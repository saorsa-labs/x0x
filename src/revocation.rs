//! Key/identity revocation records and the local grow-only revocation set
//! (issue #130).
//!
//! A [`RevocationRecord`](crate::revocation::RevocationRecord) is a signed, self-authenticating statement that a
//! specific agent or machine identity is revoked. Records are gossiped across
//! the network and enforced at every trust gate (see the enforcement points in
//! `lib.rs`, `dm_inbox.rs`, and `server/mod.rs`). Presence of a *valid*
//! revocation always fails **closed**.
//!
//! # Who may revoke — exactly two rules
//!
//! Both are verifiable from the record alone plus (for issuer-revocation) a
//! certificate already known for the subject; neither needs any trust state:
//!
//! 1. **Self-revocation** — the issuer key *is* the subject: the SHA-256 of
//!    `issuer_public_key` equals the revoked `AgentId`/`MachineId`. Always
//!    valid; an attacker "revoking" a stolen key only helps the victim.
//! 2. **Issuer-revocation** — for an `Agent` subject, the issuer key is the
//!    user key that signed that agent's [`AgentCertificate`](crate::identity::AgentCertificate). The user who
//!    vouched for an agent may un-vouch it.
//!
//! There is **no third-party revocation** and **no un-revocation**: the set is
//! grow-only (a G-Set), which removes the entire replay/rollback class —
//! replaying a revocation is idempotent and there is no "restore" message to
//! replay. Records are de-duplicated by the BLAKE3 hash of their canonical
//! bytes.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};
use ant_quic::derive_peer_id_from_public_key;
use serde::{Deserialize, Serialize};

use crate::error::IdentityError;
use crate::identity::{AgentCertificate, AgentId, MachineId, UserId};
use crate::wire_compat::{self, WireDecodeError};

/// Domain-separation prefix for the bytes a revocation signs over.
const REVOCATION_MSG_PREFIX: &[u8] = b"x0x-revocation-v1";

/// Magic marker prefixing the on-disk revocation set file.
pub(crate) const REVOCATIONS_FILE_MAGIC: &[u8; 4] = b"X0XR";

/// Magic marker prefixing the ADR-0043 ad-hoc binding-record file
/// (`revocations-v2.bin`).
pub(crate) const REVOCATIONS_FILE_MAGIC_V2: &[u8; 4] = b"X0R2";

/// Magic marker prefixing the ADR-0070 share-grant revocation file
/// (`revocations-v3.bin`). A distinct magic (and file) keeps the v1/v2
/// stores loadable by older daemons after a downgrade.
pub(crate) const REVOCATIONS_FILE_MAGIC_V3: &[u8; 4] = b"X0R3";

/// How long past the revoked grant's own expiry a share-grant revocation is
/// kept before it may be garbage-collected. A grant is dead at `expiry`
/// (evaluation never honours it after that); the slack covers clock skew
/// between the owner and the enforcing daemons.
pub const SHARE_GRANT_REVOCATION_GC_SLACK_SECS: u64 = 3_600;

/// ADR 0115 §5 (D213): the most a record's `revoked_at` may lie
/// ahead of local time. Beyond it the record is rejected at ingress and
/// dropped at load: a far-future `revoked_at` would never expire.
pub(crate) const REVOCATION_MAX_FUTURE_SKEW_SECS: u64 = 300;

/// An ADR-0070 §2 share-grant revocation: the grant id plus the owner that
/// signed the grant. Carrying the owner makes authority verifiable from the
/// record alone (the issuer key must hash to `owner`), and scopes the
/// revocation so a stranger's record for the same id revokes nothing.
///
/// `grant_expiry` is the revoked grant's own `expiry`, signed into the
/// record, so every node garbage-collects the revocation at the same point
/// (`grant_expiry + SHARE_GRANT_REVOCATION_GC_SLACK_SECS`) — once the grant
/// itself can no longer be honoured. `u64::MAX` (an unknown grant) never
/// expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareGrantRevocation {
    /// The revoked grant's random id.
    pub grant_id: [u8; 32],
    /// The grant's owner (grantor). Only this user's key may revoke it.
    pub owner: UserId,
    /// The revoked grant's `expiry` (unix seconds): the GC horizon.
    pub grant_expiry: u64,
}

impl ShareGrantRevocation {
    /// Whether this revocation may be garbage-collected at `now_unix`.
    #[must_use]
    pub fn gc_eligible_at(&self, now_unix: u64) -> bool {
        now_unix
            >= self
                .grant_expiry
                .saturating_add(SHARE_GRANT_REVOCATION_GC_SLACK_SECS)
    }
}

/// An `(agent, machine, move_epoch)` pairing retired by an ADR-0043 move
/// (or an ad-hoc owner revocation of the same pairing). Revokes the PAIR —
/// never the whole machine, never co-resident agents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentMachineBinding {
    /// The portable agent identity whose binding is retired.
    pub agent: AgentId,
    /// The machine the agent may no longer sign from.
    pub machine: MachineId,
    /// The move that retired the binding (orders tombstones against
    /// placement records).
    pub move_epoch: u64,
}

/// The identity a revocation record targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RevokedSubject {
    /// A portable agent identity.
    Agent(AgentId),
    /// A hardware-pinned machine identity.
    Machine(MachineId),
    /// An ADR-0043 agent↔machine binding: the agent may keep existing,
    /// the machine may keep hosting other agents, but THIS pairing is
    /// permanently dead. Owner-key issued only (self-revocation is
    /// structurally impossible — the issuer key hashes to one 32-byte id,
    /// the subject carries two ids plus an epoch).
    AgentMachineBinding(AgentMachineBinding),
    /// An ADR-0070 share grant. Owner-key issued only. Carried ONLY on
    /// `x0x.revocation.v3` and `revocations-v3.bin`: older daemons decode
    /// the v1/v2 batches as a whole `Vec<RevocationRecord>`, so this variant
    /// must never appear there (see [`RevocationSet::all_records`]).
    ShareGrant(ShareGrantRevocation),
}

impl From<AgentMachineBinding> for RevokedSubject {
    fn from(binding: AgentMachineBinding) -> Self {
        RevokedSubject::AgentMachineBinding(binding)
    }
}

impl RevokedSubject {
    /// Domain tag byte distinguishing the subject kind in signed bytes.
    fn tag(&self) -> u8 {
        match self {
            RevokedSubject::Agent(_) => 0x01,
            RevokedSubject::Machine(_) => 0x02,
            RevokedSubject::AgentMachineBinding(_) => 0x03,
            RevokedSubject::ShareGrant(_) => 0x04,
        }
    }

    /// The raw 32-byte identifier of the subject (Agent/Machine subjects).
    /// Binding subjects carry TWO ids plus an epoch — see
    /// [`Self::binding_subject_bytes`].
    fn id_bytes(&self) -> &[u8; 32] {
        match self {
            RevokedSubject::Agent(id) => id.as_bytes(),
            RevokedSubject::Machine(id) => id.as_bytes(),
            RevokedSubject::AgentMachineBinding(_) | RevokedSubject::ShareGrant(_) => {
                // Unreachable in canonical construction: canonical_message
                // dispatches bindings and grants to binding_subject_bytes. The
                // empty slice keeps callers that only match Agent/Machine total.
                static EMPTY: [u8; 32] = [0u8; 32];
                &EMPTY
            }
        }
    }

    /// Fixed-width subject bytes of a binding: `agent ‖ machine ‖
    /// epoch_le` — no boundary ambiguity (the §7.1 canonical form).
    fn binding_subject_bytes(&self) -> Option<Vec<u8>> {
        match self {
            RevokedSubject::AgentMachineBinding(binding) => {
                let mut out = Vec::with_capacity(32 + 32 + 8);
                out.extend_from_slice(binding.agent.as_bytes());
                out.extend_from_slice(binding.machine.as_bytes());
                out.extend_from_slice(&binding.move_epoch.to_le_bytes());
                Some(out)
            }
            // Fixed-width `grant_id ‖ owner ‖ grant_expiry_le` — no
            // boundary ambiguity; the GC horizon is signed.
            RevokedSubject::ShareGrant(grant) => {
                let mut out = Vec::with_capacity(32 + 32 + 8);
                out.extend_from_slice(&grant.grant_id);
                out.extend_from_slice(grant.owner.as_bytes());
                out.extend_from_slice(&grant.grant_expiry.to_le_bytes());
                Some(out)
            }
            _ => None,
        }
    }
}

/// A signed, self-authenticating revocation of an agent or machine identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// The identity being revoked.
    pub subject: RevokedSubject,
    /// The revoker's ML-DSA-65 public key bytes.
    pub issuer_public_key: Vec<u8>,
    /// Unix timestamp when the revocation was issued (informational only).
    pub revoked_at: u64,
    /// Optional human-readable reason.
    pub reason: Option<String>,
    /// ML-DSA-65 signature over the canonical message.
    pub signature: Vec<u8>,
}

impl RevocationRecord {
    /// Canonical bytes signed by a revocation:
    /// `prefix || subject_tag || subject_id || issuer_pubkey || revoked_at ||
    /// reason_len || reason`.
    ///
    /// `reason` is length-prefixed so two records that differ only by where a
    /// field boundary falls cannot collide. Binding subjects use the §7.1
    /// fixed-width form `prefix ‖ 0x03 ‖ agent ‖ machine ‖ epoch_le`.
    fn canonical_message(
        subject: &RevokedSubject,
        issuer_public_key: &[u8],
        revoked_at: u64,
        reason: &Option<String>,
    ) -> Vec<u8> {
        let reason_bytes = reason.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        let mut msg = Vec::with_capacity(
            REVOCATION_MSG_PREFIX.len()
                + 1
                + 32
                + 72
                + issuer_public_key.len()
                + 8
                + 8
                + reason_bytes.len(),
        );
        msg.extend_from_slice(REVOCATION_MSG_PREFIX);
        msg.push(subject.tag());
        if let Some(binding_bytes) = subject.binding_subject_bytes() {
            // §7.1: `prefix ‖ 0x03 ‖ agent ‖ machine ‖ epoch_le` — fixed
            // widths, no boundary ambiguity.
            msg.extend_from_slice(&binding_bytes);
        } else {
            msg.extend_from_slice(subject.id_bytes());
        }
        msg.extend_from_slice(issuer_public_key);
        msg.extend_from_slice(&revoked_at.to_le_bytes());
        msg.extend_from_slice(&(reason_bytes.len() as u64).to_le_bytes());
        msg.extend_from_slice(reason_bytes);
        msg
    }

    /// Sign a new revocation record.
    ///
    /// The caller supplies the issuer's public key bytes and secret key. For a
    /// **self-revocation**, pass the keypair whose id equals `subject`; for an
    /// **issuer-revocation**, pass the user keypair that signed the subject
    /// agent's certificate. Authority is (re-)checked in
    /// [`verify_authority`](Self::verify_authority) on receipt.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::CertificateVerification`] if signing fails.
    pub fn sign(
        subject: RevokedSubject,
        issuer_public_key: &MlDsaPublicKey,
        issuer_secret_key: &MlDsaSecretKey,
        revoked_at: u64,
        reason: Option<String>,
    ) -> Result<Self, IdentityError> {
        if !reason_within_limit(&reason) {
            return Err(IdentityError::Revocation(format!(
                "reason is longer than {MAX_REVOCATION_REASON_BYTES} bytes"
            )));
        }
        let issuer_pub_bytes = issuer_public_key.as_bytes().to_vec();
        let message = Self::canonical_message(&subject, &issuer_pub_bytes, revoked_at, &reason);
        let signature = sign_with_ml_dsa(issuer_secret_key, &message).map_err(|e| {
            IdentityError::CertificateVerification(format!("revocation signing failed: {e:?}"))
        })?;
        Ok(Self {
            subject,
            issuer_public_key: issuer_pub_bytes,
            revoked_at,
            reason,
            signature: signature.as_bytes().to_vec(),
        })
    }

    /// Verify the signature and the authority of this record.
    ///
    /// `subject_cert` is a certificate known for the subject agent (from the
    /// discovery cache or the same gossip batch), used only to check
    /// issuer-revocation authority; pass `None` if none is known. The
    /// signature is always checked first, so a forged record is rejected even
    /// when a certificate is supplied.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] if the signature is invalid or the
    /// issuer is neither the subject (self) nor the certifying user (issuer).
    pub fn verify_authority(
        &self,
        subject_cert: Option<&AgentCertificate>,
    ) -> Result<(), IdentityError> {
        // 1. Signature check — the record must be authentic before its claimed
        //    authority means anything.
        let issuer_pubkey = MlDsaPublicKey::from_bytes(&self.issuer_public_key)
            .map_err(|_| IdentityError::Revocation("invalid issuer public key".to_string()))?;
        let signature = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|e| IdentityError::Revocation(format!("invalid signature format: {e:?}")))?;
        let message = Self::canonical_message(
            &self.subject,
            &self.issuer_public_key,
            self.revoked_at,
            &self.reason,
        );
        verify_with_ml_dsa(&issuer_pubkey, &message, &signature)
            .map_err(|e| IdentityError::Revocation(format!("bad signature: {e:?}")))?;

        // 2. Self-revocation: the issuer key hashes to the subject id.
        //    Binding subjects never take this path (no single subject id).
        let issuer_id = derive_peer_id_from_public_key(&issuer_pubkey).0;

        // ADR-0070 §2: a share grant is revoked by its owner's key only —
        // the issuer key must hash to the grant's owner UserId. No
        // certificate is involved and no other path applies.
        if let RevokedSubject::ShareGrant(grant) = &self.subject {
            if &issuer_id == grant.owner.as_bytes() {
                return Ok(());
            }
            return Err(IdentityError::Revocation(
                "share-grant revocation issuer is not the grant owner".to_string(),
            ));
        }

        if !matches!(self.subject, RevokedSubject::AgentMachineBinding(_))
            && &issuer_id == self.subject.id_bytes()
        {
            return Ok(());
        }

        // 3. Issuer-revocation: the issuer key is the user key that signed
        //    the subject agent's certificate. For a BINDING subject
        //    (ADR-0043 §7.2) this is the ONLY legal authority path —
        //    self-revocation is structurally unreachable (the subject
        //    carries two ids plus an epoch, not one 32-byte id), so the
        //    certificate is REQUIRED, never optional.
        let subject_agent = match &self.subject {
            RevokedSubject::Agent(agent) => Some(*agent),
            RevokedSubject::AgentMachineBinding(binding) => Some(binding.agent),
            RevokedSubject::Machine(_) | RevokedSubject::ShareGrant(_) => None,
        };
        if let Some(subject_agent) = subject_agent {
            if let Some(cert) = subject_cert {
                let cert_binds_subject =
                    cert.agent_id().map(|a| a == subject_agent).unwrap_or(false);
                let cert_is_valid = cert.verify().is_ok();
                let issuer_is_certifier = cert
                    .user_id()
                    .map(|u| u.as_bytes() == &issuer_id)
                    .unwrap_or(false);
                if cert_binds_subject && cert_is_valid && issuer_is_certifier {
                    return Ok(());
                }
            }
        }

        Err(IdentityError::Revocation(
            "issuer is neither the subject nor the certifying user".to_string(),
        ))
    }

    /// ADR 0115 D214: the user whose key issued this record, read as a
    /// `UserId` (the derivation [`Self::verify_authority`] compares with
    /// a certificate's user). `None` for an unreadable key.
    #[must_use]
    pub(crate) fn issuer_user_id(&self) -> Option<UserId> {
        let key = MlDsaPublicKey::from_bytes(&self.issuer_public_key).ok()?;
        Some(UserId(derive_peer_id_from_public_key(&key).0))
    }

    /// ADR 0115 D214: whether this record's authority comes from a subject
    /// certificate: an issuer revocation of an agent, or a binding tombstone.
    #[must_use]
    pub(crate) fn needs_certificate_authority(&self) -> Option<AgentId> {
        match &self.subject {
            RevokedSubject::Agent(agent) if !self.is_self_revocation() => Some(*agent),
            RevokedSubject::AgentMachineBinding(binding) => Some(binding.agent),
            _ => None,
        }
    }

    /// ADR 0115 §5: whether `revoked_at` is within
    /// [`REVOCATION_MAX_FUTURE_SKEW_SECS`] of `now_unix`.
    #[must_use]
    pub(crate) fn revoked_at_is_credible(&self, now_unix: u64) -> bool {
        self.revoked_at <= now_unix.saturating_add(REVOCATION_MAX_FUTURE_SKEW_SECS)
    }

    /// Whether this is a self-revocation — the issuer key hashes to the
    /// subject id.
    ///
    /// A self-revocation re-verifies from the record alone (no certificate
    /// needed); an issuer-revocation requires the subject agent's certificate.
    /// A malformed issuer key yields `false` (it will fail verification anyway).
    #[must_use]
    pub fn is_self_revocation(&self) -> bool {
        match (
            &self.subject,
            MlDsaPublicKey::from_bytes(&self.issuer_public_key),
        ) {
            // Bindings and grants have no single subject id — never
            // self-revocable.
            (RevokedSubject::AgentMachineBinding(_) | RevokedSubject::ShareGrant(_), _) => false,
            (_, Ok(pk)) => &derive_peer_id_from_public_key(&pk).0 == self.subject.id_bytes(),
            (_, Err(_)) => false,
        }
    }

    /// Hex-encoded subject identifier (32 bytes → 64 hex chars).
    ///
    /// Convenience for REST responses — avoids exposing raw `[u8; 32]` in
    /// JSON. A binding subject surfaces its AGENT id (the pairing's primary
    /// identity; the machine rides in the record's REST view separately).
    #[must_use]
    pub fn subject_hex(&self) -> String {
        match &self.subject {
            RevokedSubject::AgentMachineBinding(binding) => hex::encode(binding.agent.as_bytes()),
            RevokedSubject::ShareGrant(grant) => hex::encode(grant.grant_id),
            _ => hex::encode(self.subject.id_bytes()),
        }
    }

    /// Human-readable subject kind: `"agent"`, `"machine"`, `"binding"`, or
    /// `"share_grant"`.
    #[must_use]
    pub fn subject_kind(&self) -> &'static str {
        match &self.subject {
            RevokedSubject::Agent(_) => "agent",
            RevokedSubject::Machine(_) => "machine",
            RevokedSubject::AgentMachineBinding(_) => "binding",
            RevokedSubject::ShareGrant(_) => "share_grant",
        }
    }

    /// SHA-256 of the issuer public key bytes, for compact display in REST
    /// responses. This is a plain SHA-256 with no domain separator, so it is
    /// NOT equal to the issuer's AgentId, MachineId or UserId.
    #[must_use]
    pub fn issuer_public_key_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.issuer_public_key);
        hasher.finalize().into()
    }

    /// The `(subject, issuer)` pair of this record, as one key (#1857).
    ///
    /// `None` for a share-grant subject: those records are collected when
    /// the grant ends, and the set keeps every one of them.
    pub(crate) fn pair_key(&self) -> Option<[u8; 32]> {
        if matches!(self.subject, RevokedSubject::ShareGrant(_)) {
            return None;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x-revocation-pair-v1");
        hasher.update(&[self.subject.tag()]);
        match self.subject.binding_subject_bytes() {
            Some(bytes) => hasher.update(&bytes),
            None => hasher.update(self.subject.id_bytes()),
        };
        hasher.update(&self.issuer_public_key);
        Some(*hasher.finalize().as_bytes())
    }

    /// The order between two records of one pair (#1857). The lower key
    /// is kept.
    ///
    /// 1. A record whose `revoked_at` is credible comes before one that is
    ///    far in the future. [`RevocationSet::drop_future_records`]
    ///    removes a far-future record, so such a record must never take
    ///    the place of a credible one: the subject would then have no
    ///    record at all.
    /// 2. A record whose reason is inside the limit comes before one whose
    ///    reason is over it (a legacy record), so that a node keeps, and
    ///    sends again, a record that every peer accepts.
    /// 3. The earlier `revoked_at`, and for equal times the lower record
    ///    hash.
    ///
    /// Keys 2 and 3 come from the signed bytes. Key 1 also reads the local
    /// clock; nodes agree on it except within the clock allowance of the
    /// moment a far-future time is reached.
    fn rank(&self) -> RecordRank {
        (
            !self.revoked_at_is_credible(unix_now_secs()),
            !reason_within_limit(&self.reason),
            self.revoked_at,
            self.record_hash(),
        )
    }

    /// BLAKE3 hash of the canonical (signed) message, used for de-duplication.
    ///
    /// Two records for the same `(subject, issuer, revoked_at, reason)` hash
    /// identically, so merging is idempotent.
    #[must_use]
    pub fn record_hash(&self) -> [u8; 32] {
        let message = Self::canonical_message(
            &self.subject,
            &self.issuer_public_key,
            self.revoked_at,
            &self.reason,
        );
        *blake3::hash(&message).as_bytes()
    }
}

/// A revocation record plus the subject certificate (if any) that authorizes
/// it, as stored on disk.
///
/// `subject_cert` is `Some` only for **issuer-revocations**, where the record
/// is authorized by the user key that signed the subject agent's certificate:
/// that certificate is required to re-verify authority on load. Self-revocations
/// carry `None` (they re-verify from the record alone). Persisting the cert is
/// what lets [`RevocationSet::from_bytes`] re-check authority — so a
/// tampered/forged `revocations.bin` cannot inject an unverified revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRevocation {
    record: RevocationRecord,
    subject_cert: Option<AgentCertificate>,
}

/// The order key of a record inside its pair: `(revoked_at not credible,
/// reason over the limit, revoked_at, record hash)`. The lower key is kept.
type RecordRank = (bool, bool, u64, [u8; 32]);

/// Unix seconds now; 0 when the clock is before the epoch.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// One trusted sender's carrier snapshot while a carrier waits for a
/// resync (#1116).
#[derive(Debug, Clone, Default)]
struct SnapshotCandidate {
    /// A complete snapshot: one unmarked batch, or every batch of one
    /// marked round with a matching set digest (#1857). Pair key (record
    /// hash for a share grant) → rank of the record this set would keep.
    whole: Option<HashMap<[u8; 32], RecordRank>>,
    /// The `set` of the round that gave `whole`; `None` when `whole` came
    /// from an unmarked batch. A repeat of the same round keeps `whole`.
    whole_set: Option<[u8; 32]>,
    /// The one open round of this sender for this carrier.
    round: Option<OpenRound>,
}

impl SnapshotCandidate {
    fn offers(&self, hash: &[u8; 32]) -> bool {
        self.whole
            .as_ref()
            .is_some_and(|kept| kept.values().any(|(_, _, _, held)| held == hash))
            || self
                .round
                .as_ref()
                .is_some_and(|round| round.parts.values().any(|part| part.hashes.contains(hash)))
    }
}

/// The batches seen so far of one marked round.
#[derive(Debug, Clone)]
struct OpenRound {
    set: [u8; 32],
    batches: u32,
    parts: HashMap<u32, RoundPart>,
    /// When the last part arrived. A round that gets no part for
    /// [`OPEN_ROUND_TIMEOUT`] is dropped when the next part arrives.
    last_part: std::time::Instant,
}

/// How long an open round is kept with no new part.
const OPEN_ROUND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// One batch of a marked round.
#[derive(Debug, Clone)]
struct RoundPart {
    /// Record hashes of the batch, sorted.
    hashes: Vec<[u8; 32]>,
    offered: Vec<([u8; 32], RecordRank)>,
}

/// The pair-rule view of a list of records: pair key (record hash for a
/// share grant) → rank of the record that is kept.
fn kept_of(
    offered: impl IntoIterator<Item = ([u8; 32], RecordRank)>,
) -> HashMap<[u8; 32], RecordRank> {
    let mut kept: HashMap<[u8; 32], RecordRank> = HashMap::new();
    for (key, rank) in offered {
        match kept.get(&key) {
            Some(held) if *held <= rank => {}
            _ => {
                kept.insert(key, rank);
            }
        }
    }
    kept
}

fn kept_hashes(kept: &HashMap<[u8; 32], RecordRank>) -> HashSet<[u8; 32]> {
    kept.values().map(|(_, _, _, hash)| *hash).collect()
}

/// Whether `reason` is inside [`MAX_REVOCATION_REASON_BYTES`].
fn reason_within_limit(reason: &Option<String>) -> bool {
    reason
        .as_ref()
        .is_none_or(|reason| reason.len() <= MAX_REVOCATION_REASON_BYTES)
}

/// In-memory grow-only set of verified revocations.
///
/// Maintains `HashSet`s of revoked agent/machine ids for O(1) gate checks plus
/// a hash-keyed map of the full records for rebroadcast. An agent, machine or
/// binding record is never removed because of its age (no un-revocation,
/// #1108); see [`RevocationSet::collect_dead_records`].
///
/// Every record in the set has passed [`RevocationRecord::verify_authority`] —
/// both on first receipt and again when reloaded from disk. Insertion therefore
/// only happens through [`verify_and_insert`](Self::verify_and_insert); the
/// crate-internal raw insert performs no crypto and must only ever be handed a
/// record that was just verified.
#[derive(Debug, Default, Clone)]
pub struct RevocationSet {
    revoked_agents: HashSet<AgentId>,
    revoked_machines: HashSet<MachineId>,
    records_by_hash: HashMap<[u8; 32], PersistedRevocation>,
    /// The one record held for each `(subject, issuer)` pair of an agent,
    /// machine or binding subject (#1857): pair key → record hash. Kept in
    /// step with `records_by_hash`.
    pair_index: HashMap<[u8; 32], [u8; 32]>,
    /// Makes "read the set, encode it, publish every batch" one step for
    /// the agent that owns this set (#1857). A set that needs several
    /// batches is a round, named by the digest of the set. Two publishers
    /// at once (the heartbeat and a new revocation) would send parts of
    /// two rounds mixed together, and a peer that waits for a resync
    /// would drop each round when a part of the other arrives. Not
    /// serialized.
    publish_lock: Arc<tokio::sync::Mutex<()>>,
    /// ADR-0043 tombstone epochs from ad-hoc binding `RevocationRecord`s
    /// (`x0x.revocation.v2` carrier). Grow-only; never swept.
    binding_epochs: HashMap<(AgentId, MachineId), u64>,
    /// ADR-0043 tombstone epochs unioned from VERIFIED
    /// `ActivationBundle.retired_bindings` sets (owner-covered by the
    /// bundle signature — not standalone records). Grow-only, order-
    /// independent; never swept. Both maps feed
    /// [`Self::is_binding_revoked`].
    bundle_retired_epochs: HashMap<(AgentId, MachineId), u64>,
    /// Ad-hoc binding tombstones indexed by agent (#1659). Kept in step
    /// with `binding_epochs` keys.
    binding_machines_by_agent: HashMap<AgentId, HashSet<MachineId>>,
    /// Bundle-retired tombstones indexed by agent (#1659). Kept in step
    /// with `bundle_retired_epochs` keys.
    bundle_machines_by_agent: HashMap<AgentId, HashSet<MachineId>>,
    /// ADR-0070 revoked share grants, keyed by `(grant_id, owner)`, valued
    /// by the latest signed `grant_expiry`. Collected once the grant itself is dead
    /// (`grant_expiry + SHARE_GRANT_REVOCATION_GC_SLACK_SECS`).
    revoked_share_grants: HashMap<([u8; 32], UserId), u64>,
    /// Monotonic change counter — incremented on every insert or collection.
    /// Publishers compare this to decide whether the set changed since
    /// their last full broadcast (the on-change piggyback gate), avoiding
    /// a full `all_records` comparison per heartbeat.
    change_generation: u64,
    /// Carriers whose files were present but could not be decoded (#1116).
    /// Bits: v1 = 1, v2 = 2, v3 = 4. Not serialized. Membership stays
    /// closed until each pending carrier is resynced from the group.
    /// The four `is_*_revoked` predicates stay record-only, so this state
    /// is not proof that a grant, binding or subject was revoked.
    resync_carriers: u8,
    /// Carriers whose snapshot is accepted but whose recovered records are
    /// not yet in this set (#1116). A fresh snapshot cannot clear this.
    /// It stays set when the rebuild fails. Not serialized.
    reconcile_carriers: u8,
    /// Remote snapshots offered for a waiting carrier. Index 0 is v1, 1 is
    /// v2, 2 is v3. The key is the sending agent. Ordinary ingestion does
    /// not write this map and does not open the carrier.
    resync_candidates: [HashMap<AgentId, SnapshotCandidate>; 3],
    /// Carriers whose verified resync has not been written to the live path.
    rebuild_pending: u8,
    /// Set when the quarantine rename failed. Status then says the live
    /// path still holds the bad bytes.
    status_override: Option<&'static str>,
    /// `GET /status` emits the revocation status event once per hold.
    status_event_pending: bool,
    /// Sender check for a waiting carrier. Absent means no snapshot opens.
    snapshot_authority: Option<SnapshotAuthority>,
    /// ADR-0074 §4: woken on every change so live tailnet streams are
    /// re-checked promptly. `None` (the default) wakes nothing.
    change_notify: Option<std::sync::Arc<tokio::sync::Notify>>,
}

/// v1 `revocations.bin` / `x0x.revocation.v1`.
pub(crate) const REVOCATION_CARRIER_V1: u8 = 1;
/// v2 `revocations-v2.bin` / `x0x.revocation.v2`.
pub(crate) const REVOCATION_CARRIER_V2: u8 = 2;
/// v3 `revocations-v3.bin` / `x0x.revocation.v3`.
pub(crate) const REVOCATION_CARRIER_V3: u8 = 4;

/// Text for the log line and the API/CLI status event (#1116).
pub const REVOCATION_RESYNC_STATUS: &str = "A revocation store could not be decoded. x0xd archived the bad bytes and kept running. Membership stays closed until the group resyncs revocations. A member whose non-revocation is not verified is revoked.";

/// Status text when the bad bytes could not be moved off the live path.
pub const REVOCATION_ARCHIVE_FAILED: &str = "A revocation store could not be decoded. x0xd could not archive the bad bytes. The live path still holds them. Membership stays closed until the group resyncs revocations. A member whose non-revocation is not verified is revoked.";

/// Who may reopen a waiting revocation carrier (#1116).
///
/// A free agent key is not enough. The daemon installs this check from
/// owner enrollment and the local group journal. Tests install a predicate.
type SnapshotAuthorityCheck = dyn Fn(&AgentId, &RevocationSet) -> bool + Send + Sync;

#[derive(Clone)]
pub(crate) struct SnapshotAuthority(Arc<SnapshotAuthorityCheck>);

impl std::fmt::Debug for SnapshotAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SnapshotAuthority")
    }
}

impl SnapshotAuthority {
    pub(crate) fn new(
        check: impl Fn(&AgentId, &RevocationSet) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(check))
    }

    fn allows(&self, sender: &AgentId, set: &RevocationSet) -> bool {
        (self.0)(sender, set)
    }
}

fn carrier_index(carrier: u8) -> Option<usize> {
    match carrier {
        REVOCATION_CARRIER_V1 => Some(0),
        REVOCATION_CARRIER_V2 => Some(1),
        REVOCATION_CARRIER_V3 => Some(2),
        _ => None,
    }
}

/// Whether `topic` carries revocation records that must still be delivered
/// while membership is closed (#1116).
#[must_use]
pub(crate) fn is_revocation_carrier_topic(topic: &str) -> bool {
    matches!(
        topic,
        crate::REVOCATION_TOPIC | crate::REVOCATION_V2_TOPIC | crate::REVOCATION_V3_TOPIC
    )
}

/// Topics that may flow while membership is closed (#1116).
///
/// Revocation carriers rebuild the set. Identity, machine and user
/// announcements carry the certificates an issuer revocation or a binding
/// tombstone needs. The v3 blob topic carries a certificate fetch for
/// that rebuild. Other topics stay withheld.
#[must_use]
pub(crate) fn is_revocation_recovery_topic(topic: &str) -> bool {
    is_revocation_carrier_topic(topic)
        || matches!(
            topic,
            crate::IDENTITY_ANNOUNCE_TOPIC
                | crate::MACHINE_ANNOUNCE_TOPIC
                | crate::USER_ANNOUNCE_TOPIC
                | crate::MACHINE_ANNOUNCE_V3_TOPIC
                | crate::ANNOUNCE_BLOB_V2_TOPIC
                | crate::announce_blob::ANNOUNCE_BLOB_TOPIC
        )
        || topic.starts_with("x0x.identity.shard.v2.")
        || topic.starts_with("x0x.machine.shard.v2.")
        || topic.starts_with("x0x.user.shard.v2.")
}

fn subject_carrier(subject: &RevokedSubject) -> Option<u8> {
    Some(match subject {
        RevokedSubject::Agent(_) | RevokedSubject::Machine(_) => REVOCATION_CARRIER_V1,
        RevokedSubject::AgentMachineBinding(_) => REVOCATION_CARRIER_V2,
        RevokedSubject::ShareGrant(_) => REVOCATION_CARRIER_V3,
    })
}

/// Magic prefix of the per-record revocation batch framing (#1604 G2).
///
/// A legacy batch is `bincode(Vec<RevocationRecord>)`: a `u64` LE count,
/// then the records back to back. One record with a subject variant that a
/// receiver does not know makes the whole legacy batch undecodable. The
/// framed batch is `MAGIC ‖ bincode(Vec<Vec<u8>>)`, one bincode record per
/// element, so a receiver skips (and counts) only the record it cannot
/// decode. Read as a legacy count, the magic is far above any legal batch
/// size, so the two framings cannot be confused.
pub(crate) const REVOCATION_BATCH_FRAMED_MAGIC: &[u8; 8] = b"x0xRVB02";

/// `true` when every daemon since `origin/main` @ `545b781` decodes this
/// subject. Deliberately exhaustive: a new subject variant must decide
/// here, and it gets the framed batch.
fn subject_in_legacy_batches(subject: &RevokedSubject) -> bool {
    match subject {
        RevokedSubject::Agent(_)
        | RevokedSubject::Machine(_)
        | RevokedSubject::AgentMachineBinding(_)
        | RevokedSubject::ShareGrant(_) => true,
    }
}

/// Encode a revocation batch for a carrier topic.
///
/// A batch whose subjects all predate #1604 keeps the legacy encoding,
/// byte for byte, so older daemons still decode it. A batch with a newer
/// subject uses the framed encoding ([`REVOCATION_BATCH_FRAMED_MAGIC`]).
///
/// # Errors
/// The bincode encode error.
pub(crate) fn encode_revocation_batch(
    records: &[RevocationRecord],
) -> Result<Vec<u8>, bincode::Error> {
    if records
        .iter()
        .all(|record| subject_in_legacy_batches(&record.subject))
    {
        return bincode::serialize(records);
    }
    let framed = records
        .iter()
        .map(bincode::serialize)
        .collect::<Result<Vec<Vec<u8>>, _>>()?;
    let mut out = REVOCATION_BATCH_FRAMED_MAGIC.to_vec();
    out.extend_from_slice(&bincode::serialize(&framed)?);
    Ok(out)
}

/// Decode a revocation batch in either framing, without its round marker.
///
/// In a framed batch, a record with a subject variant this node does not
/// know is skipped, counted and logged; every other record is kept, so
/// revocation stays fail-closed for the subjects this node knows. A
/// malformed record refuses the whole batch. A legacy batch decodes as a
/// whole, as before; an unknown variant in it is counted and logged.
///
/// A round-marker record (#1857) is not a revocation. It is removed here,
/// so no ingest path sees one.
///
/// # Errors
/// [`crate::wire_compat::WireDecodeError`].
pub(crate) fn decode_revocation_batch(
    payload: &[u8],
) -> Result<Vec<RevocationRecord>, WireDecodeError> {
    decode_revocation_batch_with_round(payload).map(|(records, _)| records)
}

/// [`decode_revocation_batch`], and what the batch says about its round.
///
/// # Errors
/// [`crate::wire_compat::WireDecodeError`].
pub(crate) fn decode_revocation_batch_with_round(
    payload: &[u8],
) -> Result<(Vec<RevocationRecord>, BatchRound), WireDecodeError> {
    let decoded = decode_revocation_batch_raw(payload)?;
    let (markers, records): (Vec<RevocationRecord>, Vec<RevocationRecord>) =
        decoded.into_iter().partition(is_round_marker);
    let round = match markers.as_slice() {
        [] => BatchRound::Whole,
        [marker] => parse_round_marker(marker).map_or(BatchRound::Invalid, BatchRound::Part),
        _ => BatchRound::Invalid,
    };
    Ok((records, round))
}

fn decode_revocation_batch_raw(payload: &[u8]) -> Result<Vec<RevocationRecord>, WireDecodeError> {
    let Some(framed) = payload.strip_prefix(REVOCATION_BATCH_FRAMED_MAGIC.as_slice()) else {
        return wire_compat::decode_bincode("RevocationBatch", payload);
    };
    let elements: Vec<Vec<u8>> = wire_compat::decode_bincode("RevocationBatchFramed", framed)?;
    let mut records = Vec::with_capacity(elements.len());
    for element in &elements {
        match wire_compat::decode_bincode::<RevocationRecord>("RevocationRecord", element) {
            Ok(record) => records.push(record),
            Err(WireDecodeError::UnknownVariant { .. }) => {}
            Err(malformed) => return Err(malformed),
        }
    }
    Ok(records)
}

/// The `issuer_public_key` bytes of a round-marker record (#1857). A real
/// ML-DSA-65 public key has 1952 bytes, so no real record carries this
/// value, and a marker never passes any signature check.
pub(crate) const ROUND_MARKER_ISSUER: &[u8] = b"x0x-revocation-round-marker-v1";

/// The first word of a round marker's `reason`.
const ROUND_MARKER_REASON_PREFIX: &str = "x0x-revocation-round-v1";

/// The most batches one round may have.
pub(crate) const MAX_ROUND_BATCHES: u32 = 512;

/// More than the bytes of any round-marker record (about 210).
const ROUND_MARKER_MAX_BYTES: usize = 512;

/// The most records a waiting node holds for one open round of one sender:
/// [`MAX_ROUND_BATCHES`] batches of 512 records. A full batch of real
/// records holds about 370, so a round inside the batch bound is always
/// inside this bound; the batch bound is the real limit for an honest
/// sender (about 190,000 records).
const MAX_ROUND_RECORDS: usize = MAX_ROUND_BATCHES as usize * 512;

/// What a round-marker record says: this batch is batch `index` of
/// `batches`, and `set` is the BLAKE3 digest of the sorted record hashes of
/// the sender's whole set for the carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoundMarker {
    pub(crate) batches: u32,
    pub(crate) index: u32,
    pub(crate) set: [u8; 32],
}

/// What a decoded batch says about its round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchRound {
    /// No marker: the batch is the sender's whole set, as before #1857.
    Whole,
    /// One valid marker: the batch is one part of a round.
    Part(RoundMarker),
    /// A marker that does not parse, or more than one marker. The batch is
    /// never a snapshot.
    Invalid,
}

/// Whether `record` is a round marker (#1857). The test is the exact
/// issuer tag. A marker is never a revocation: it is not verified, stored,
/// listed, counted or sent again.
#[must_use]
pub(crate) fn is_round_marker(record: &RevocationRecord) -> bool {
    record.issuer_public_key == ROUND_MARKER_ISSUER
}

/// The digest that names a round: BLAKE3 over the sorted record hashes.
fn round_set_digest(sorted_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"x0x-revocation-round-set-v1");
    for hash in sorted_hashes {
        hasher.update(hash);
    }
    *hasher.finalize().as_bytes()
}

/// The marker record that ends batch `index` of a round.
fn round_marker_record(marker: &RoundMarker) -> RevocationRecord {
    RevocationRecord {
        subject: RevokedSubject::Machine(MachineId([0u8; 32])),
        issuer_public_key: ROUND_MARKER_ISSUER.to_vec(),
        revoked_at: 0,
        reason: Some(format!(
            "{ROUND_MARKER_REASON_PREFIX} n={} i={} set={}",
            marker.batches,
            marker.index,
            hex::encode(marker.set)
        )),
        signature: Vec::new(),
    }
}

/// Read a round marker. `None` for any shape other than the exact one that
/// [`round_marker_record`] writes, and for a count or index out of range.
fn parse_round_marker(record: &RevocationRecord) -> Option<RoundMarker> {
    if record.subject != RevokedSubject::Machine(MachineId([0u8; 32]))
        || record.revoked_at != 0
        || !record.signature.is_empty()
    {
        return None;
    }
    let reason = record.reason.as_deref()?;
    let mut words = reason.split(' ');
    if words.next()? != ROUND_MARKER_REASON_PREFIX {
        return None;
    }
    let batches: u32 = words.next()?.strip_prefix("n=")?.parse().ok()?;
    let index: u32 = words.next()?.strip_prefix("i=")?.parse().ok()?;
    let set_hex = words.next()?.strip_prefix("set=")?;
    if words.next().is_some() || batches == 0 || batches > MAX_ROUND_BATCHES || index >= batches {
        return None;
    }
    let set: [u8; 32] = hex::decode(set_hex).ok()?.try_into().ok()?;
    let marker = RoundMarker {
        batches,
        index,
        set,
    };
    // Only the canonical text is a marker (no other spelling of a number).
    (round_marker_record(&marker).reason.as_deref() == Some(reason)).then_some(marker)
}

/// The most bytes one received revocation batch may have. A larger payload
/// is ignored whole. Released daemons use the same number.
pub(crate) const MAX_REVOCATION_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

/// The most bytes of records in one published batch (#1857): the receive
/// limit less 64 KiB, about 370 records. A set that fitted in one batch
/// before #1857 is still one batch, with the same bytes; only a set that
/// did not arrive at all before is sent as several batches.
pub(crate) const REVOCATION_BATCH_TARGET_BYTES: usize = MAX_REVOCATION_PAYLOAD_BYTES - 64 * 1024;

/// The longest `reason` a new record may carry (#1857). The reason is
/// inside the signed bytes, so a long one cannot be cut: the record is
/// refused when it is signed here or when it arrives from a peer. A record
/// already in the store is kept.
pub const MAX_REVOCATION_REASON_BYTES: usize = 1024;

/// Encode `records` for one carrier as one or more batches (#1857).
///
/// A set that fits in one batch is one [`encode_revocation_batch`] payload
/// with no marker: the bytes a released daemon sends and reads today. A
/// larger set is a ROUND of several batches. Each batch of a round is a
/// complete payload that ends with one round-marker record (see
/// `docs/design/revocation-batches.md`): a released daemon applies the real
/// records and rejects the marker alone; a daemon that waits for a resync
/// opens only on a complete round. One record that is larger than the
/// target goes in a batch of its own. The records are put in record-hash
/// order, so the same set gives the same batches on every node.
///
/// # Errors
/// The bincode encode error.
pub(crate) fn encode_revocation_batches(
    records: &[RevocationRecord],
) -> Result<Vec<Vec<u8>>, bincode::Error> {
    encode_revocation_batches_with_target(records, REVOCATION_BATCH_TARGET_BYTES)
}

/// [`encode_revocation_batches`] with the batch size as a parameter.
fn encode_revocation_batches_with_target(
    records: &[RevocationRecord],
    target_bytes: usize,
) -> Result<Vec<Vec<u8>>, bincode::Error> {
    let mut ordered: Vec<(&RevocationRecord, [u8; 32])> = records
        .iter()
        .filter(|record| !is_round_marker(record))
        .map(|record| (record, record.record_hash()))
        .collect();
    ordered.sort_by_key(|(_, hash)| *hash);

    let mut groups: Vec<Vec<RevocationRecord>> = Vec::new();
    let mut current: Vec<RevocationRecord> = Vec::new();
    let mut current_bytes = 0usize;
    // The round's `set` is every record hash of the carrier set, in order,
    // also the hash of a record that cannot be sent.
    let set_hashes: Vec<[u8; 32]> = ordered.iter().map(|(_, hash)| *hash).collect();
    let mut unsendable = 0usize;
    for (record, hash) in &ordered {
        // The framed encoding adds a length prefix per record.
        let size = usize::try_from(bincode::serialized_size(record)?)
            .unwrap_or(usize::MAX)
            .saturating_add(16);
        if size.saturating_add(ROUND_MARKER_MAX_BYTES) > MAX_REVOCATION_PAYLOAD_BYTES {
            // Only a stored legacy record can be this large. No receiver
            // accepts a batch that holds it, so it is not sent. Its hash
            // STAYS in the round's `set`, and every batch of this publish
            // carries a marker: the offered records then never match the
            // set, so no waiting node opens from this sender with this
            // subject not revoked.
            tracing::warn!(
                record = %hex::encode(hash),
                bytes = size,
                "revocation record is over the size a receiver accepts; it is not sent to peers, and no peer that waits for a resync can open from this daemon until a record with a short reason takes its place"
            );
            unsendable = unsendable.saturating_add(1);
            continue;
        }
        if !current.is_empty() && current_bytes.saturating_add(size) > target_bytes {
            groups.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes = current_bytes.saturating_add(size);
        current.push((*record).clone());
    }
    if !current.is_empty() {
        groups.push(current);
    }
    if groups.len() <= 1 && unsendable == 0 {
        // One batch: no marker, the bytes of before #1857.
        return groups
            .iter()
            .map(|group| encode_revocation_batch(group))
            .collect();
    }
    let batches = u32::try_from(groups.len()).unwrap_or(u32::MAX);
    if batches > MAX_ROUND_BATCHES {
        tracing::warn!(
            batches,
            "revocation set needs more batches than one round may have; a peer that waits for a resync cannot open from this daemon"
        );
    }
    let set = round_set_digest(&set_hashes);
    let mut out = Vec::with_capacity(groups.len());
    for (index, mut group) in groups.into_iter().enumerate() {
        group.push(round_marker_record(&RoundMarker {
            batches,
            index: u32::try_from(index).unwrap_or(u32::MAX),
            set,
        }));
        out.push(encode_revocation_batch(&group)?);
    }
    Ok(out)
}

/// Record one remote carrier snapshot (#1116).
///
/// A topic that is not a revocation carrier is ignored. A carrier that is
/// not waiting is ignored, so a healthy daemon does not take the write
/// lock. An empty or undecodable payload does not open membership. A
/// message from `local_agent`, or a message with no sender, is not a
/// group snapshot. Recording the snapshot does not insert records and
/// does not by itself open the carrier.
pub(crate) async fn arm_incoming_revocation_snapshot(
    set: &std::sync::Arc<tokio::sync::RwLock<RevocationSet>>,
    topic: &str,
    payload: &[u8],
    sender: Option<&crate::identity::AgentId>,
    local_agent: Option<&crate::identity::AgentId>,
) {
    let Some(sender) = sender else {
        return;
    };
    if local_agent.is_some_and(|local| local == sender) {
        return;
    }
    let carrier = match topic {
        crate::REVOCATION_TOPIC => REVOCATION_CARRIER_V1,
        crate::REVOCATION_V2_TOPIC => REVOCATION_CARRIER_V2,
        crate::REVOCATION_V3_TOPIC => REVOCATION_CARRIER_V3,
        _ => return,
    };
    if !set.read().await.carrier_resync_pending(carrier) {
        return;
    }
    let Ok((records, round)) = decode_revocation_batch_with_round(payload) else {
        return;
    };
    let trusted = {
        let guard = set.read().await;
        guard
            .snapshot_authority
            .as_ref()
            .is_some_and(|authority| authority.allows(sender, &guard))
    };
    set.write()
        .await
        .observe_remote_carrier_batch(carrier, sender, &records, round, trusted);
}

impl RevocationSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wake `notify` on every future change to the set (ADR-0074 §4 open-
    /// stream re-check). Replaces any previously installed notifier.
    pub(crate) fn set_change_notify(&mut self, notify: std::sync::Arc<tokio::sync::Notify>) {
        self.change_notify = Some(notify);
    }

    fn notify_change(&self) {
        if let Some(notify) = &self.change_notify {
            notify.notify_one();
        }
    }

    /// A revocation file was present but could not be decoded (#1116).
    ///
    /// Membership stays closed until a trusted authority publishes a
    /// verified snapshot for each pending carrier and the rebuild has
    /// installed the recovered records. A later snapshot does not clear
    /// that second hold, and a failed rebuild leaves it set. Two free
    /// agent keys are not that authority. This is not a revocation
    /// record. [`Self::is_agent_revoked`] and the other record predicates
    /// stay false for subjects that are not in the set.
    #[must_use]
    pub fn revocation_resync_required(&self) -> bool {
        self.admission_closed()
    }

    fn admission_closed(&self) -> bool {
        self.resync_carriers != 0 || self.reconcile_carriers != 0
    }

    /// Operator sentence for the log line, `warnings`, and the status event.
    #[must_use]
    pub fn revocation_status_sentence(&self) -> &'static str {
        self.status_override.unwrap_or(REVOCATION_RESYNC_STATUS)
    }

    /// One-shot status event for `GET /status` and the `/events` stream.
    ///
    /// Returns the operator text once while a resync is still required.
    #[must_use]
    pub fn take_revocation_status_event(&mut self) -> Option<&'static str> {
        if !self.admission_closed() || !self.status_event_pending {
            return None;
        }
        self.status_event_pending = false;
        Some(self.revocation_status_sentence())
    }

    /// The quarantine rename failed. Later status reads say so.
    pub(crate) fn note_archive_failed(&mut self) {
        self.status_override = Some(REVOCATION_ARCHIVE_FAILED);
    }

    /// Carriers that just opened and still need a live-file rebuild.
    ///
    /// The caller writes those bytes and leaves the quarantine file in place.
    pub(crate) fn take_rebuild_pending(&mut self) -> u8 {
        let pending = self.rebuild_pending;
        self.rebuild_pending = 0;
        pending
    }

    /// Put carrier bits back after a rebuild that failed before the rename.
    ///
    /// This does not close the carrier. A retry of a readable quarantine
    /// writes the same bytes. A failure after the rename must not call
    /// this: the live file is already in place. An unreadable quarantine
    /// is closed by [`Self::hold_carrier_until_reconciled`].
    pub(crate) fn requeue_rebuild_pending(&mut self, carriers: u8) {
        self.rebuild_pending |= carriers;
    }

    /// Close one carrier until its durable records are in this set.
    ///
    /// This is not the snapshot-resync bit. A later trusted snapshot cannot
    /// clear it. The rebuild holds it from the moment the snapshot would
    /// otherwise open admission, and a failed rebuild leaves it set.
    pub(crate) fn hold_carrier_until_reconciled(&mut self, carrier: u8) {
        let Some(index) = carrier_index(carrier) else {
            return;
        };
        self.reconcile_carriers |= carrier;
        self.resync_candidates[index].clear();
        self.status_event_pending = true;
    }

    /// Open one carrier after its durable records are in this set.
    ///
    /// A missing install, a read failure, or any rebuild error must not
    /// call this.
    pub(crate) fn release_reconciled_carrier(&mut self, carrier: u8) {
        self.reconcile_carriers &= !carrier;
    }

    /// Empty set that closes membership for one carrier (#1116).
    ///
    /// A missing file stays [`Self::new`].
    pub(crate) fn quarantined_carrier(carrier: u8) -> Self {
        Self {
            resync_carriers: carrier,
            status_event_pending: carrier != 0,
            ..Self::new()
        }
    }

    /// Whether this carrier still waits for a group snapshot (#1116).
    #[must_use]
    pub(crate) fn carrier_resync_pending(&self, carrier: u8) -> bool {
        self.resync_carriers & carrier != 0
    }

    /// Install the check that names a trusted snapshot sender (#1116).
    ///
    /// A missing check leaves every carrier closed. The daemon installs
    /// enrollment and the local group journal. An operator rebuild does
    /// not use this check.
    pub(crate) fn set_snapshot_authority(&mut self, authority: SnapshotAuthority) {
        self.snapshot_authority = Some(authority);
    }

    /// Remember one batch that a remote sender offers for a waiting carrier
    /// (#1116, #1857). `round` says whether the batch is the sender's
    /// whole set or one part of a marked round.
    pub(crate) fn observe_remote_carrier_batch(
        &mut self,
        carrier: u8,
        sender: &AgentId,
        records: &[RevocationRecord],
        round: BatchRound,
        trusted_authority: bool,
    ) {
        match round {
            BatchRound::Whole => {
                self.observe_remote_carrier_snapshot(carrier, sender, records, trusted_authority);
            }
            BatchRound::Part(marker) => {
                self.observe_remote_round_part(carrier, sender, records, marker, trusted_authority);
            }
            // A batch with a bad marker is never a snapshot. From a
            // trusted sender it still says that the sender's set is a
            // newer round now, so what the sender offered before is
            // stale (#1864).
            BatchRound::Invalid => {
                if trusted_authority {
                    self.drop_sender_candidate(carrier, sender);
                }
            }
        }
    }

    /// Forget what `sender` offered for a waiting carrier (#1864): a
    /// whole set and an open round. The carrier then cannot open on that
    /// offer. A trusted sender's batch that this node cannot use as a
    /// snapshot calls this, because the batch still shows that the
    /// sender's set has changed.
    fn drop_sender_candidate(&mut self, carrier: u8, sender: &AgentId) {
        if let Some(index) = carrier_index(carrier) {
            self.resync_candidates[index].remove(sender);
        }
    }

    /// Whether a snapshot whose kept records are `kept` covers every
    /// record this set holds for `carrier` (#1857, #1864): the snapshot
    /// has the held record, or it has a record of the same pair that this
    /// set would keep in its place. A covered record's subject is revoked
    /// in the sender's set also.
    fn snapshot_covers_held(&self, carrier: u8, kept: &HashMap<[u8; 32], RecordRank>) -> bool {
        self.records_by_hash
            .iter()
            .filter(|(_, persisted)| subject_carrier(&persisted.record.subject) == Some(carrier))
            .all(|(hash, persisted)| {
                let key = persisted.record.pair_key().unwrap_or(*hash);
                kept.get(&key)
                    .is_some_and(|rank| rank.3 == *hash || *rank <= persisted.record.rank())
            })
    }

    /// Remember one remote sender's whole-set snapshot (#1116): one batch
    /// with no round marker.
    ///
    /// This does not insert records. An untrusted sender, an empty
    /// snapshot, a record from another carrier, or a snapshot that omits
    /// a revocation already in the set is ignored. The carrier opens only
    /// when a trusted authority has offered a snapshot whose records have
    /// all verified and match the records already in the set.
    pub(crate) fn observe_remote_carrier_snapshot(
        &mut self,
        carrier: u8,
        sender: &AgentId,
        records: &[RevocationRecord],
        trusted_authority: bool,
    ) {
        if !trusted_authority || self.resync_carriers & carrier == 0 {
            return;
        }
        let Some(index) = carrier_index(carrier) else {
            return;
        };
        // This batch is the sender's set now. Whatever the sender offered
        // before (a whole set or an open round) is stale, also when this
        // batch is refused below.
        self.drop_sender_candidate(carrier, sender);
        if records.is_empty()
            || records.iter().any(|record| {
                is_round_marker(record) || subject_carrier(&record.subject) != Some(carrier)
            })
        {
            return;
        }
        // #1857: this set holds one record per (subject, issuer) pair. A
        // sender that holds more (a released daemon) is compared by the
        // records this set would keep. A record with a long reason stays
        // in the snapshot: the sender is a trusted authority, so the
        // ingest admits it (see `verify_and_insert_at`).
        let kept = kept_of(records.iter().map(|record| {
            let rank = record.rank();
            (record.pair_key().unwrap_or(rank.3), rank)
        }));
        // #1864: a held record is covered when the snapshot has it or has
        // the record that takes its place here. The offer must stay for
        // the second case: the ingest admits a long-reason record only
        // while a trusted snapshot offers it. The carrier still opens
        // only when the held records equal the snapshot's kept records
        // (`try_complete_carrier`), after each one has verified.
        if !self.snapshot_covers_held(carrier, &kept) {
            return;
        }
        self.resync_candidates[index]
            .entry(*sender)
            .or_default()
            .whole = Some(kept);
        self.try_complete_carrier(carrier);
    }

    /// Remember one part of a marked round from a remote sender (#1857).
    ///
    /// A part is never a snapshot by itself. The sender's snapshot exists
    /// only when this node has every part of ONE round (same `set`, same
    /// count) and the digest of all the offered record hashes equals
    /// `set`. Then the whole-set rule of
    /// [`Self::observe_remote_carrier_snapshot`] applies to the union. A
    /// marker from a sender that is not a trusted authority is ignored: it
    /// cannot start, extend or close a round.
    fn observe_remote_round_part(
        &mut self,
        carrier: u8,
        sender: &AgentId,
        records: &[RevocationRecord],
        marker: RoundMarker,
        trusted_authority: bool,
    ) {
        if !trusted_authority || self.resync_carriers & carrier == 0 || records.is_empty() {
            return;
        }
        let Some(index) = carrier_index(carrier) else {
            return;
        };
        if marker.batches == 0
            || marker.batches > MAX_ROUND_BATCHES
            || marker.index >= marker.batches
            || records.iter().any(|record| {
                is_round_marker(record) || subject_carrier(&record.subject) != Some(carrier)
            })
        {
            // Not a part this node can use. It still shows that the
            // sender's set has changed, so the earlier offer is stale
            // (#1864).
            self.drop_sender_candidate(carrier, sender);
            return;
        }
        let mut hashes: Vec<[u8; 32]> = records.iter().map(RevocationRecord::record_hash).collect();
        hashes.sort_unstable();
        let offered: Vec<([u8; 32], RecordRank)> = records
            .iter()
            .map(|record| {
                let rank = record.rank();
                (record.pair_key().unwrap_or(rank.3), rank)
            })
            .collect();
        let candidate = self.resync_candidates[index].entry(*sender).or_default();
        // One open round per carrier per sender: a part of another round
        // (the sender's set changed) replaces the open one. Parts of two
        // rounds are never mixed.
        if candidate.whole.is_some() && candidate.whole_set == Some(marker.set) {
            // A repeat publish of the round that this node already holds
            // complete: the snapshot is still the sender's set.
            self.try_complete_carrier(carrier);
            return;
        }
        let now = std::time::Instant::now();
        let same_round = candidate.round.as_ref().is_some_and(|round| {
            round.set == marker.set
                && round.batches == marker.batches
                && now.duration_since(round.last_part) <= OPEN_ROUND_TIMEOUT
        });
        if !same_round {
            // The sender's set is this round now. A whole-set snapshot
            // that it offered earlier is stale and must not open the
            // carrier any more.
            candidate.whole = None;
            candidate.whole_set = None;
            candidate.round = Some(OpenRound {
                set: marker.set,
                batches: marker.batches,
                parts: HashMap::new(),
                last_part: now,
            });
        }
        let Some(round) = candidate.round.as_mut() else {
            return;
        };
        round.last_part = now;
        if round
            .parts
            .get(&marker.index)
            .is_some_and(|held| held.hashes != hashes)
        {
            // The same index with other content: refuse the new part.
            return;
        }
        // The records of a part are not verified here, so bound what one
        // sender can make this node hold. Over the bound, the round is
        // dropped and the carrier stays closed.
        // A repeat of a part at the same index is not counted twice.
        let round_records: usize = round
            .parts
            .iter()
            .filter(|(index, _)| **index != marker.index)
            .map(|(_, part)| part.hashes.len())
            .sum();
        if round_records.saturating_add(hashes.len()) > MAX_ROUND_RECORDS {
            tracing::warn!(
                carrier,
                sender = %hex::encode(sender.as_bytes()),
                "revocation resync: a round offers more records than this node holds for one sender; the round is dropped"
            );
            candidate.round = None;
            return;
        }
        round
            .parts
            .insert(marker.index, RoundPart { hashes, offered });
        let parts_held = round.parts.len();
        let mut complete = None;
        if u32::try_from(parts_held).ok() == Some(round.batches) {
            let mut all: Vec<[u8; 32]> = round
                .parts
                .values()
                .flat_map(|part| part.hashes.iter().copied())
                .collect();
            all.sort_unstable();
            all.dedup();
            if round_set_digest(&all) == round.set {
                let kept = kept_of(
                    round
                        .parts
                        .values()
                        .flat_map(|part| part.offered.iter().copied()),
                );
                complete = Some((kept, round.set));
            }
        }
        if let Some((kept, set)) = complete {
            // The whole-set rule (see `observe_remote_carrier_snapshot`).
            if self.snapshot_covers_held(carrier, &kept) {
                let candidate = self.resync_candidates[index].entry(*sender).or_default();
                candidate.whole = Some(kept);
                candidate.whole_set = Some(set);
                candidate.round = None;
            }
        }
        self.try_complete_carrier(carrier);
        if self.resync_carriers & carrier != 0 {
            // An operator must be able to tell a round that is not yet
            // complete, or lost a batch, from a hang.
            tracing::warn!(
                carrier,
                sender = %hex::encode(sender.as_bytes()),
                parts_held,
                parts_in_round = marker.batches,
                held_records = self.known_carrier_hashes(carrier).len(),
                "revocation resync: the carrier stays closed. It opens when every batch of one round from a trusted sender has arrived and matches the held records. If a batch was lost, the next chance is the sender's next full publish (up to 2 hours)"
            );
        }
    }

    /// Insert a fully verified snapshot without treating it as group proof.
    ///
    /// An empty snapshot leaves membership closed. If any record fails
    /// verification, nothing is inserted and no carrier opens. Inserting
    /// records is not proof that the group snapshot is complete. A carrier
    /// opens only when a trusted authority offers one verified snapshot.
    /// Binding tombstones and issuer revocations need the subject
    /// certificate; pass it through
    /// [`Self::apply_group_revocation_resync_with_certs`].
    pub fn apply_group_revocation_resync(
        &mut self,
        records: impl IntoIterator<Item = RevocationRecord>,
        now_unix: u64,
    ) -> bool {
        self.apply_group_revocation_resync_with_certs(records, &HashMap::new(), now_unix)
    }

    /// [`Self::apply_group_revocation_resync`] with subject certificates.
    ///
    /// `certs` is keyed by the subject agent. A binding tombstone or an
    /// issuer revocation without its certificate fails the snapshot, and
    /// the hold stays closed.
    pub fn apply_group_revocation_resync_with_certs(
        &mut self,
        records: impl IntoIterator<Item = RevocationRecord>,
        certs: &HashMap<AgentId, AgentCertificate>,
        now_unix: u64,
    ) -> bool {
        if self.resync_carriers == 0 {
            return false;
        }
        let records: Vec<RevocationRecord> = records.into_iter().collect();
        if records.is_empty() {
            return false;
        }
        let mut parsed = Vec::with_capacity(records.len());
        for record in records {
            if subject_carrier(&record.subject).is_none() {
                return false;
            }
            let cert = record
                .needs_certificate_authority()
                .and_then(|agent| certs.get(&agent));
            if !record.revoked_at_is_credible(now_unix) || record.verify_authority(cert).is_err() {
                return false;
            }
            parsed.push(record);
        }
        for record in parsed {
            let cert = record
                .needs_certificate_authority()
                .and_then(|agent| certs.get(&agent));
            // The pre-check above verified every record. This path is an
            // authenticated group resync, so the reason limit of open
            // gossip does not apply: dropping a record here would open
            // the carrier with its subject not revoked.
            if self.verify_and_insert(record, cert).is_err() {
                return false;
            }
        }
        // The snapshot is accepted when its resync bit clears. Admission
        // stays closed until the rebuild releases the reconcile hold.
        self.resync_carriers == 0
    }

    fn known_carrier_hashes(&self, carrier: u8) -> HashSet<[u8; 32]> {
        self.records_by_hash
            .iter()
            .filter(|(_, persisted)| subject_carrier(&persisted.record.subject) == Some(carrier))
            .map(|(hash, _)| *hash)
            .collect()
    }

    fn try_complete_carrier(&mut self, carrier: u8) {
        if self.resync_carriers & carrier == 0 {
            return;
        }
        let Some(index) = carrier_index(carrier) else {
            return;
        };
        let known = self.known_carrier_hashes(carrier);
        if known.is_empty() {
            return;
        }
        let agreed = self.resync_candidates[index].values().any(|candidate| {
            candidate
                .whole
                .as_ref()
                .is_some_and(|kept| kept_hashes(kept) == known)
        });
        if !agreed {
            return;
        }
        // Close admission before the resync bit drops, so a member is
        // never admitted against a snapshot that has not been installed.
        self.reconcile_carriers |= carrier;
        self.status_event_pending = true;
        self.resync_carriers &= !carrier;
        self.resync_candidates[index].clear();
        self.rebuild_pending |= carrier;
    }

    /// Whether `id` must be refused as a member.
    ///
    /// True when `id` has a revocation record, or when a revocation carrier
    /// is still waiting for a group resync. In the second case the daemon
    /// cannot verify that the member is not revoked, so the member is
    /// revoked for admission. This does not write a revocation record.
    #[must_use]
    pub fn member_treated_as_revoked(&self, id: &AgentId) -> bool {
        self.admission_closed() || self.revoked_agents.contains(id)
    }

    fn absorb_quarantine(&mut self, other: &Self) {
        if other.resync_carriers == 0 {
            return;
        }
        self.resync_carriers |= other.resync_carriers;
        self.status_event_pending = true;
        if self.status_override.is_none() {
            self.status_override = other.status_override;
        }
    }

    fn note_resynced_record(&mut self, subject: &RevokedSubject, _hash: [u8; 32]) {
        let Some(carrier) = subject_carrier(subject) else {
            return;
        };
        self.try_complete_carrier(carrier);
    }

    /// Whether an agent id is revoked.
    #[must_use]
    pub fn is_agent_revoked(&self, id: &AgentId) -> bool {
        self.revoked_agents.contains(id)
    }

    /// Whether a machine id is revoked.
    #[must_use]
    pub fn is_machine_revoked(&self, id: &MachineId) -> bool {
        self.revoked_machines.contains(id)
    }

    fn note_binding_machine(&mut self, agent: AgentId, machine: MachineId) {
        self.binding_machines_by_agent
            .entry(agent)
            .or_default()
            .insert(machine);
    }

    fn note_bundle_machine(&mut self, agent: AgentId, machine: MachineId) {
        self.bundle_machines_by_agent
            .entry(agent)
            .or_default()
            .insert(machine);
    }

    /// Machines named by a binding tombstone for `agent`.
    ///
    /// The list is the union of ad-hoc binding records and bundle-retired
    /// pairings, read from the per-agent index. Callers use it to attribute
    /// a machine revocation to an agent (#1659). It does not itself mean
    /// the machine is revoked.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn binding_tombstone_machines(&self, agent: &AgentId) -> Vec<MachineId> {
        let mut machines = HashSet::new();
        if let Some(set) = self.binding_machines_by_agent.get(agent) {
            machines.extend(set.iter().copied());
        }
        if let Some(set) = self.bundle_machines_by_agent.get(agent) {
            machines.extend(set.iter().copied());
        }
        machines.into_iter().collect()
    }

    /// Whether any tombstone for `agent` names a revoked machine.
    ///
    /// Walks the two per-agent sets directly and returns on the first hit.
    /// Callers that already hold the revocation lock use this instead of
    /// building a deduplicated list.
    #[must_use]
    pub(crate) fn any_tombstone_machine_revoked(&self, agent: &AgentId) -> bool {
        self.binding_machines_by_agent
            .get(agent)
            .is_some_and(|machines| {
                machines
                    .iter()
                    .any(|machine| self.revoked_machines.contains(machine))
            })
            || self
                .bundle_machines_by_agent
                .get(agent)
                .is_some_and(|machines| {
                    machines
                        .iter()
                        .any(|machine| self.revoked_machines.contains(machine))
                })
    }

    /// Whether an `(agent, machine)` binding is retired (ADR-0043 check
    /// **B**): the grow-only union of bundle `retired_bindings` and ad-hoc
    /// v2 tombstones.
    ///
    #[must_use]
    pub fn is_binding_revoked(&self, agent: &AgentId, machine: &MachineId) -> bool {
        let key = (*agent, *machine);
        self.binding_epochs.contains_key(&key) || self.bundle_retired_epochs.contains_key(&key)
    }

    /// Whether the share grant `grant_id` signed by `owner` is revoked
    /// (ADR-0070 §2). A revocation by any other owner for the same id does
    /// not match.
    ///
    #[must_use]
    pub fn is_share_grant_revoked(&self, grant_id: &[u8; 32], owner: &UserId) -> bool {
        self.revoked_share_grants.contains_key(&(*grant_id, *owner))
    }

    /// Highest epoch of any tombstone for the agent across both carriers,
    /// ordering placement records against tombstones (§9 check **P**).
    #[must_use]
    pub fn max_revoked_binding_epoch(&self, agent: &AgentId) -> Option<u64> {
        let from_records = self
            .binding_epochs
            .iter()
            .filter(|((a, _), _)| a == agent)
            .map(|(_, epoch)| *epoch)
            .max();
        let from_bundles = self
            .bundle_retired_epochs
            .iter()
            .filter(|((a, _), _)| a == agent)
            .map(|(_, epoch)| *epoch)
            .max();
        from_records.max(from_bundles)
    }

    /// Union a VERIFIED `ActivationBundle`'s cumulative `retired_bindings`
    /// into the grow-only tombstone set (order-independent; the entries are
    /// owner-covered by the bundle's signature, not standalone records).
    /// Returns `true` when anything new was added.
    ///
    /// # Security
    ///
    /// Callers MUST have passed the bundle through
    /// [`crate::key_move::verify_bundle_mesh`] first — this method performs
    /// no cryptography.
    pub fn union_bundle_retired(&mut self, bindings: &[AgentMachineBinding]) -> bool {
        let mut changed = false;
        for binding in bindings {
            let key = (binding.agent, binding.machine);
            match self.bundle_retired_epochs.entry(key) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    let epoch = binding.move_epoch;
                    slot.insert(epoch);
                    self.note_bundle_machine(binding.agent, binding.machine);
                    if epoch > 0 {
                        changed = true;
                    }
                }
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    let epoch = slot.get_mut();
                    if *epoch < binding.move_epoch {
                        *epoch = binding.move_epoch;
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.change_generation = self.change_generation.saturating_add(1);
            self.notify_change();
        }
        changed
    }

    /// Number of distinct records held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records_by_hash.len()
    }

    /// Whether the set holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records_by_hash.is_empty()
    }

    /// Whether a record (by canonical hash) is already known.
    #[must_use]
    pub fn contains_hash(&self, hash: &[u8; 32]) -> bool {
        self.records_by_hash.contains_key(hash)
    }

    /// The lock a publisher holds while it reads this set, encodes it and
    /// sends every batch (#1857).
    #[must_use]
    pub(crate) fn publish_lock(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.publish_lock)
    }

    /// Whether the set already gives everything `record` would give
    /// (#1857): it holds this record, or it holds the record that is kept
    /// for the same `(subject, issuer)` pair. A caller can skip a covered
    /// record with no signature check. The subject of a covered record is
    /// revoked in this set.
    #[must_use]
    pub fn covers(&self, record: &RevocationRecord) -> bool {
        let hash = record.record_hash();
        if self.records_by_hash.contains_key(&hash) {
            return true;
        }
        record
            .pair_key()
            .and_then(|pair| self.pair_index.get(&pair))
            .and_then(|held| self.records_by_hash.get(held))
            .is_some_and(|held| held.record.rank() <= record.rank())
    }

    /// Whether a trusted authority offered this record in a resync
    /// snapshot for a carrier that still waits (#1116). Only a trusted
    /// sender's batch reaches the candidate store.
    fn offered_by_trusted_snapshot(&self, hash: &[u8; 32]) -> bool {
        self.resync_candidates
            .iter()
            .any(|carrier| carrier.values().any(|candidate| candidate.offers(hash)))
    }

    /// Whether the set holds a record for the `(subject, issuer)` pair
    /// with this key (#1857, #1864). The S4 store write uses it: evidence
    /// for a record that was replaced is on disk when the kept record of
    /// its pair is. S4 keeps the pair key of each record it waits for, so
    /// this set keeps no memory of replaced records and has no bound to
    /// run over.
    #[must_use]
    pub(crate) fn holds_pair(&self, pair: &[u8; 32]) -> bool {
        self.pair_index.contains_key(pair)
    }

    /// Put a verified record in the record map under the one-record-per-pair
    /// rule (#1857). Returns `false` when the set already covers it. The
    /// subject indices are not touched: both records of a pair name the
    /// same subject, so a replacement cannot un-revoke anything.
    fn admit(&mut self, persisted: PersistedRevocation) -> bool {
        if is_round_marker(&persisted.record) {
            // A round marker is never stored (#1857).
            return false;
        }
        let hash = persisted.record.record_hash();
        if self.records_by_hash.contains_key(&hash) {
            return false;
        }
        if let Some(pair) = persisted.record.pair_key() {
            if let Some(held_hash) = self.pair_index.get(&pair).copied() {
                if let Some(held) = self.records_by_hash.get(&held_hash) {
                    if held.record.rank() <= persisted.record.rank() {
                        return false;
                    }
                    self.records_by_hash.remove(&held_hash);
                }
            }
            self.pair_index.insert(pair, hash);
        }
        self.records_by_hash.insert(hash, persisted);
        true
    }

    /// Verify a record's authority, then insert it. Returns `true` if it was
    /// newly added, `false` if already present (idempotent).
    ///
    /// This is the ONLY way a record enters the set. `subject_cert` supplies
    /// the subject agent's certificate for issuer-revocations (pass `None` for
    /// self-revocations, or when no certificate is known — issuer-revocations
    /// then fail closed). The validating certificate is retained so the record
    /// re-verifies on a later [`from_bytes`](Self::from_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] if the record's signature is
    /// invalid or the issuer lacks authority over the subject.
    pub fn verify_and_insert(
        &mut self,
        record: RevocationRecord,
        subject_cert: Option<&AgentCertificate>,
    ) -> Result<bool, IdentityError> {
        if is_round_marker(&record) {
            // Never a revocation, whatever path offers it (#1857). The
            // gossip decoder removes markers, so one that reaches this
            // point came from a store file or a single-record path.
            // debug, not warn: a remote peer can send one on a
            // single-record path as often as it likes.
            tracing::debug!(
                "a revocation round-marker record was offered as a revocation; dropped"
            );
            return Err(IdentityError::Revocation(
                "a round-marker record is not a revocation".to_string(),
            ));
        }
        record.verify_authority(subject_cert)?;
        // Retain the certificate only when it was actually needed to prove
        // authority (issuer-revocation). Self-revocations re-verify without it.
        let subject = record.subject.clone();
        let hash = record.record_hash();
        let retained_cert = if record.is_self_revocation() {
            None
        } else {
            subject_cert.cloned()
        };
        let inserted = self.insert_verified(PersistedRevocation {
            record,
            subject_cert: retained_cert,
        });
        self.note_resynced_record(&subject, hash);
        Ok(inserted)
    }

    /// ADR 0115 §5: [`verify_and_insert`](Self::verify_and_insert) for a
    /// record from any ingress carrier. A `revoked_at` beyond the
    /// future-skew bound at `now_unix` is rejected and counted.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] for a far-future `revoked_at`,
    /// an invalid signature or a missing authority.
    pub(crate) fn verify_and_insert_at(
        &mut self,
        record: RevocationRecord,
        subject_cert: Option<&AgentCertificate>,
        now_unix: u64,
    ) -> Result<bool, IdentityError> {
        if !record.revoked_at_is_credible(now_unix) {
            crate::identity_authority::note_revocation_future_dropped(1);
            return Err(IdentityError::Revocation(format!(
                "revoked_at {} is more than {REVOCATION_MAX_FUTURE_SKEW_SECS} s ahead of local time {now_unix}",
                record.revoked_at
            )));
        }
        if !reason_within_limit(&record.reason)
            && !self.offered_by_trusted_snapshot(&record.record_hash())
        {
            return Err(IdentityError::Revocation(format!(
                "reason is longer than {MAX_REVOCATION_REASON_BYTES} bytes"
            )));
        }
        self.verify_and_insert(record, subject_cert)
    }

    /// ADR 0115 §5: drop every record whose `revoked_at` is beyond the
    /// future-skew bound at `now_unix` (a load-time check). Returns the
    /// number dropped and counts them.
    pub(crate) fn drop_future_records(&mut self, now_unix: u64) -> usize {
        let dropped = self
            .take_records_where(|record, _| !record.revoked_at_is_credible(now_unix))
            .len();
        if dropped > 0 {
            crate::identity_authority::note_revocation_future_dropped(dropped as u64);
        }
        dropped
    }

    /// ADR 0115 D214: every record with its retained certificate.
    pub(crate) fn records_with_certs(
        &self,
    ) -> impl Iterator<Item = (&RevocationRecord, Option<&AgentCertificate>)> {
        self.records_by_hash
            .values()
            .map(|persisted| (&persisted.record, persisted.subject_cert.as_ref()))
    }

    /// ADR 0115 D214: replace the bundle-derived tombstones with exactly
    /// `tombstones` (recomputed from the bundles that remain held).
    pub(crate) fn reset_bundle_retired(&mut self, tombstones: &[AgentMachineBinding]) {
        self.bundle_retired_epochs.clear();
        self.bundle_machines_by_agent.clear();
        self.union_bundle_retired(tombstones);
        self.change_generation = self.change_generation.saturating_add(1);
        self.notify_change();
    }

    /// Remove every record matching `take` and return it with its retained
    /// certificate. The record-derived indices are rebuilt from the records
    /// that remain; bundle-derived tombstones are untouched.
    pub(crate) fn take_records_where(
        &mut self,
        mut take: impl FnMut(&RevocationRecord, Option<&AgentCertificate>) -> bool,
    ) -> Vec<(RevocationRecord, Option<AgentCertificate>)> {
        let hashes: Vec<[u8; 32]> = self
            .records_by_hash
            .iter()
            .filter(|(_, persisted)| take(&persisted.record, persisted.subject_cert.as_ref()))
            .map(|(hash, _)| *hash)
            .collect();
        if hashes.is_empty() {
            return Vec::new();
        }
        let taken: Vec<(RevocationRecord, Option<AgentCertificate>)> = hashes
            .iter()
            .filter_map(|hash| self.records_by_hash.remove(hash))
            .map(|persisted| (persisted.record, persisted.subject_cert))
            .collect();
        self.revoked_agents.clear();
        self.revoked_machines.clear();
        self.binding_epochs.clear();
        self.binding_machines_by_agent.clear();
        self.revoked_share_grants.clear();
        self.pair_index.clear();
        let remaining: Vec<PersistedRevocation> = self
            .records_by_hash
            .drain()
            .map(|(_, persisted)| persisted)
            .collect();
        for persisted in remaining {
            self.insert_verified(persisted);
        }
        self.change_generation = self.change_generation.saturating_add(1);
        self.notify_change();
        taken
    }

    /// Monotonic generation counter — changes on every insert or collection.
    /// The heartbeat piggyback compares generations: unchanged set ⇒ skip
    /// the publish (except the periodic fallback).
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.change_generation
    }

    /// Remove the records whose revoked credential is dead. Returns the
    /// number removed.
    ///
    /// A revocation stays in force until the revoked credential can no
    /// longer be used (#1108, David's ruling of 20 Oct 2026). Record age is
    /// never a reason to remove a record:
    ///
    /// - **Agent and Machine** records are kept for good. The record names
    ///   a key, and a key has no expiry. A retained certificate does not
    ///   give a safe end date: the owner can have issued a later
    ///   certificate for the same agent key, and the key can also announce
    ///   with no certificate.
    /// - **Binding** tombstones are kept for good (ADR-0043 §7.3).
    /// - A **share-grant** record is removed when the grant itself is dead:
    ///   its signed `grant_expiry` plus the skew slack (ADR-0070).
    pub fn collect_dead_records(&mut self, now_unix: u64) -> usize {
        let dead: Vec<[u8; 32]> = self
            .records_by_hash
            .iter()
            .filter(|(_, persisted)| match &persisted.record.subject {
                RevokedSubject::ShareGrant(grant) => grant.gc_eligible_at(now_unix),
                RevokedSubject::Agent(_)
                | RevokedSubject::Machine(_)
                | RevokedSubject::AgentMachineBinding(_) => false,
            })
            .map(|(hash, _)| *hash)
            .collect();
        if dead.is_empty() {
            return 0;
        }
        for hash in &dead {
            let Some(persisted) = self.records_by_hash.remove(hash) else {
                continue;
            };
            // Only share-grant records reach this list (filter above).
            if let RevokedSubject::ShareGrant(grant) = &persisted.record.subject {
                // Drop the key only when the LATEST expiry recorded for it
                // is past the horizon — a longer-lived record for the same
                // grant keeps it revoked.
                let key = (grant.grant_id, grant.owner);
                if let Some(latest) = self.revoked_share_grants.get(&key).copied() {
                    let horizon = ShareGrantRevocation {
                        grant_expiry: latest,
                        ..*grant
                    };
                    if horizon.gc_eligible_at(now_unix) {
                        self.revoked_share_grants.remove(&key);
                    }
                }
            }
        }
        self.change_generation = self.change_generation.saturating_add(1);
        self.notify_change();
        dead.len()
    }

    /// Old name of [`Self::collect_dead_records`]. `_ttl_secs` is ignored:
    /// no record is removed because of its age (#1108).
    #[deprecated(note = "use collect_dead_records; record age no longer removes a record")]
    pub fn expire_records_older_than(&mut self, _ttl_secs: u64, now_unix: u64) -> usize {
        self.collect_dead_records(now_unix)
    }

    /// Raw insert of an already-verified record. Performs NO cryptographic
    /// checks. It is module-private and reachable only through
    /// [`verify_and_insert`](Self::verify_and_insert) (the sole path a new
    /// record enters the set) and
    /// [`take_records_where`](Self::take_records_where), which re-inserts
    /// records that were already in the set while it rebuilds the indices.
    /// Returns `true` if new.
    fn insert_verified(&mut self, persisted: PersistedRevocation) -> bool {
        if is_round_marker(&persisted.record) || self.covers(&persisted.record) {
            return false;
        }
        match &persisted.record.subject {
            RevokedSubject::Agent(id) => {
                self.revoked_agents.insert(*id);
            }
            RevokedSubject::Machine(id) => {
                self.revoked_machines.insert(*id);
            }
            RevokedSubject::AgentMachineBinding(binding) => {
                // Keep the highest epoch per pairing — the grow-only
                // tombstone set orders placement records (§9 P).
                let key = (binding.agent, binding.machine);
                match self.binding_epochs.entry(key) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(binding.move_epoch);
                        self.note_binding_machine(binding.agent, binding.machine);
                    }
                    std::collections::hash_map::Entry::Occupied(mut slot) => {
                        let epoch = slot.get_mut();
                        *epoch = (*epoch).max(binding.move_epoch);
                    }
                }
            }
            RevokedSubject::ShareGrant(grant) => {
                let entry = self
                    .revoked_share_grants
                    .entry((grant.grant_id, grant.owner))
                    .or_insert(0);
                *entry = (*entry).max(grant.grant_expiry);
            }
        }
        self.admit(persisted);
        self.change_generation = self.change_generation.saturating_add(1);
        self.notify_change();
        true
    }

    /// All held records for the V1 wire (`Agent`/`Machine` subjects only,
    /// order unspecified), for rebroadcast/anti-entropy.
    ///
    /// ADR-0043 §7.4: the v1 batch is one whole `Vec<RevocationRecord>`
    /// that legacy peers deserialize in full — an unknown variant would
    /// poison every co-resident record for old peers, so the v1
    /// publication carries legacy subjects only and stays byte-identical.
    /// ADR-0070: this is an ALLOWLIST (`Agent`/`Machine`), so a subject
    /// variant added later can never leak onto v1.
    #[must_use]
    pub fn all_records(&self) -> Vec<RevocationRecord> {
        self.records_by_hash
            .values()
            .filter(|p| is_v1_subject(&p.record.subject))
            .map(|p| p.record.clone())
            .collect()
    }

    /// All held records of every subject kind (order unspecified), for
    /// local display such as `GET /identity/revocations` (#1108).
    ///
    /// This is NOT a wire or storage view. The v1 carrier and
    /// `revocations.bin` use [`Self::all_records`], because an old daemon
    /// cannot decode a binding or share-grant subject. Tombstones that came
    /// from a move bundle are not records and are not included; see
    /// [`Self::is_binding_revoked`].
    #[must_use]
    pub fn all_subject_records(&self) -> Vec<RevocationRecord> {
        self.records_by_hash
            .values()
            .map(|p| p.record.clone())
            .collect()
    }

    /// How many held records are over the size a receiver accepts and so
    /// are never sent to peers (#1857). While this is not 0, no peer that
    /// waits for a resync can open from this daemon.
    #[must_use]
    pub fn unsendable_record_count(&self) -> usize {
        self.records_by_hash
            .values()
            .filter(|persisted| {
                bincode::serialized_size(&persisted.record).is_ok_and(|size| {
                    usize::try_from(size)
                        .unwrap_or(usize::MAX)
                        .saturating_add(16 + ROUND_MARKER_MAX_BYTES)
                        > MAX_REVOCATION_PAYLOAD_BYTES
                })
            })
            .count()
    }

    /// All held share-grant records for the `x0x.revocation.v3` carrier and
    /// the `revocations-v3.bin` store (ADR-0070 §2).
    #[must_use]
    pub fn share_grant_records(&self) -> Vec<RevocationRecord> {
        self.records_by_hash
            .values()
            .filter(|p| matches!(p.record.subject, RevokedSubject::ShareGrant(_)))
            .map(|p| p.record.clone())
            .collect()
    }

    /// All held binding-subject records (ad-hoc tombstones) for the
    /// `x0x.revocation.v2` carrier and the `revocations-v2.bin` store.
    #[must_use]
    pub fn binding_records(&self) -> Vec<RevocationRecord> {
        self.records_by_hash
            .values()
            .filter(|p| matches!(p.record.subject, RevokedSubject::AgentMachineBinding(_)))
            .map(|p| p.record.clone())
            .collect()
    }

    /// Validate the persisted layout without verifying record signatures.
    /// Load/merge callers still use the authority-verifying decoders.
    pub(crate) fn validate_persisted_bytes(
        bytes: &[u8],
        magic: &[u8; 4],
    ) -> Result<(), IdentityError> {
        use bincode::Options;

        // Keep the existing decoders' empty-file acceptance.
        if bytes.is_empty() {
            return Ok(());
        }
        let body = bytes.strip_prefix(magic).ok_or_else(|| {
            IdentityError::Serialization("revocation file magic mismatch".to_string())
        })?;
        let _: Vec<PersistedRevocation> = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .deserialize(body)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        Ok(())
    }

    /// Encode the V1 set for on-disk persistence: `X0XR` magic + bincode of
    /// the legacy-subject (`Agent`/`Machine`) record list, each record
    /// carrying the certificate that authorizes it. Binding tombstones
    /// persist via [`Self::to_bytes_v2`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        // Allowlist, like `all_records`: a downgraded daemon reads this file.
        let records: Vec<&PersistedRevocation> = self
            .records_by_hash
            .values()
            .filter(|p| is_v1_subject(&p.record.subject))
            .collect();
        let body = bincode::serialize(&records)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut out = Vec::with_capacity(REVOCATIONS_FILE_MAGIC.len() + body.len());
        out.extend_from_slice(REVOCATIONS_FILE_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Encode the ADR-0043 ad-hoc binding records for
    /// `revocations-v2.bin`: `X0R2` magic + bincode of the persisted
    /// entries (cert included — issuer authority re-verifies on load).
    /// Bundle-unioned tombstones are re-derived from `move-bundles.bin`
    /// on load and are NOT duplicated here.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn to_bytes_v2(&self) -> Result<Vec<u8>, IdentityError> {
        let records: Vec<&PersistedRevocation> = self
            .records_by_hash
            .values()
            .filter(|p| matches!(p.record.subject, RevokedSubject::AgentMachineBinding(_)))
            .collect();
        let body = bincode::serialize(&records)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut out = Vec::with_capacity(REVOCATIONS_FILE_MAGIC_V2.len() + body.len());
        out.extend_from_slice(REVOCATIONS_FILE_MAGIC_V2);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a `revocations-v2.bin` previously written by
    /// [`to_bytes_v2`](Self::to_bytes_v2), re-verifying every record's
    /// authority on load. Merge into the main set with
    /// [`merge_v2`](Self::merge_v2) — the returned set holds only the
    /// binding records.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] if the magic is missing or
    /// the body is malformed. Empty input yields an empty set.
    pub fn from_bytes_v2(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        if bytes.len() < REVOCATIONS_FILE_MAGIC_V2.len()
            || &bytes[..REVOCATIONS_FILE_MAGIC_V2.len()] != REVOCATIONS_FILE_MAGIC_V2
        {
            return Err(IdentityError::Serialization(
                "revocation v2 file missing X0R2 magic".to_string(),
            ));
        }
        let persisted: Vec<PersistedRevocation> =
            bincode::deserialize(&bytes[REVOCATIONS_FILE_MAGIC_V2.len()..])
                .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut set = Self::new();
        for entry in persisted {
            // Fail-closed load path: an entry that no longer verifies is
            // dropped, never trusted.
            let _ = set.verify_and_insert(entry.record, entry.subject_cert.as_ref());
        }
        Ok(set)
    }

    /// Encode the ADR-0070 share-grant revocations for `revocations-v3.bin`:
    /// `X0R3` magic + bincode of the persisted entries. Only
    /// [`RevokedSubject::ShareGrant`] records are written.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn to_bytes_v3(&self) -> Result<Vec<u8>, IdentityError> {
        let records: Vec<&PersistedRevocation> = self
            .records_by_hash
            .values()
            .filter(|p| matches!(p.record.subject, RevokedSubject::ShareGrant(_)))
            .collect();
        let body = bincode::serialize(&records)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut out = Vec::with_capacity(REVOCATIONS_FILE_MAGIC_V3.len() + body.len());
        out.extend_from_slice(REVOCATIONS_FILE_MAGIC_V3);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a `revocations-v3.bin` written by
    /// [`to_bytes_v3`](Self::to_bytes_v3), re-verifying every record on
    /// load. Records that are not share-grant revocations, or that no
    /// longer verify, are dropped (fail closed). Merge the result with
    /// [`merge_v3`](Self::merge_v3).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] if the magic is missing or
    /// the body is malformed. Empty input yields an empty set.
    pub fn from_bytes_v3(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        if bytes.len() < REVOCATIONS_FILE_MAGIC_V3.len()
            || &bytes[..REVOCATIONS_FILE_MAGIC_V3.len()] != REVOCATIONS_FILE_MAGIC_V3
        {
            return Err(IdentityError::Serialization(
                "revocation v3 file missing X0R3 magic".to_string(),
            ));
        }
        let persisted: Vec<PersistedRevocation> =
            bincode::deserialize(&bytes[REVOCATIONS_FILE_MAGIC_V3.len()..])
                .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut set = Self::new();
        for entry in persisted {
            if !matches!(entry.record.subject, RevokedSubject::ShareGrant(_)) {
                continue;
            }
            let _ = set.verify_and_insert(entry.record, None);
        }
        Ok(set)
    }

    /// Merge a decoded v3 set into this one (grow-only union).
    ///
    /// A quarantined source keeps those carriers closed. A readable source
    /// does not clear a carrier that is still waiting for a group resync.
    pub fn merge_v3(&mut self, other: Self) {
        self.absorb_quarantine(&other);
        let mut changed = false;
        for (key, expiry) in other.revoked_share_grants {
            let entry = self.revoked_share_grants.entry(key).or_insert(0);
            if *entry < expiry {
                *entry = expiry;
                changed = true;
            }
        }
        for persisted in other.records_by_hash.into_values() {
            if self.admit(persisted) {
                changed = true;
            }
        }
        if changed {
            self.change_generation = self.change_generation.saturating_add(1);
            self.notify_change();
        }
    }

    /// Merge a decoded v2 set into this one (grow-only union).
    ///
    /// A quarantined source keeps those carriers closed. A readable source
    /// does not clear a carrier that is still waiting for a group resync.
    pub fn merge_v2(&mut self, other: Self) {
        self.absorb_quarantine(&other);
        for ((agent, machine), epoch) in other.binding_epochs {
            let key = (agent, machine);
            match self.binding_epochs.entry(key) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(epoch);
                    self.note_binding_machine(agent, machine);
                }
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    let current = slot.get_mut();
                    *current = (*current).max(epoch);
                }
            }
        }
        for persisted in other.records_by_hash.into_values() {
            self.admit(persisted);
        }
    }

    /// Decode a set previously written by [`to_bytes`](Self::to_bytes),
    /// **re-verifying every record's authority on load**.
    ///
    /// The on-disk file is untrusted input: a record that fails re-verification
    /// (forged signature, or an issuer-revocation whose persisted certificate
    /// no longer authorizes it) is silently dropped rather than trusted, so a
    /// tampered `revocations.bin` cannot inject an unverified revocation.
    /// Legitimately-verified records — including issuer-revocations, whose
    /// authorizing certificate is persisted alongside them — are preserved.
    ///
    /// An empty input yields an empty set (a missing file is not an error).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] if the magic is missing or the
    /// body is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        if bytes.len() < REVOCATIONS_FILE_MAGIC.len()
            || &bytes[..REVOCATIONS_FILE_MAGIC.len()] != REVOCATIONS_FILE_MAGIC
        {
            return Err(IdentityError::Serialization(
                "revocation file missing X0XR magic".to_string(),
            ));
        }
        let persisted: Vec<PersistedRevocation> =
            bincode::deserialize(&bytes[REVOCATIONS_FILE_MAGIC.len()..])
                .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut set = Self::new();
        for entry in persisted {
            // Re-verify authority against the persisted certificate. A record
            // that no longer verifies is dropped (not present in the set) —
            // this is the load-path enforcement of the authority model.
            let _ = set.verify_and_insert(entry.record, entry.subject_cert.as_ref());
        }
        Ok(set)
    }
}

/// Whether a subject may ride the v1 wire and `revocations.bin`: the
/// legacy `Agent`/`Machine` subjects only (an allowlist, ADR-0070).
fn is_v1_subject(subject: &RevokedSubject) -> bool {
    matches!(
        subject,
        RevokedSubject::Agent(_) | RevokedSubject::Machine(_)
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    #[tokio::test]
    async fn trailing_bytes_block_revocation_overwrite_1116() {
        let dir = tempfile::tempdir().unwrap();
        let body = bincode::serialize(&Vec::<PersistedRevocation>::new()).unwrap();
        for (name, magic, store) in [
            (
                "revocations.bin",
                REVOCATIONS_FILE_MAGIC,
                crate::storage::RevocationStore::V1,
            ),
            (
                "revocations-v2.bin",
                REVOCATIONS_FILE_MAGIC_V2,
                crate::storage::RevocationStore::V2,
            ),
            (
                "revocations-v3.bin",
                REVOCATIONS_FILE_MAGIC_V3,
                crate::storage::RevocationStore::V3,
            ),
        ] {
            let mut valid = magic.to_vec();
            valid.extend_from_slice(&body);
            assert!(RevocationSet::validate_persisted_bytes(&valid, magic).is_ok());
            let mut garbage = valid.clone();
            garbage.extend_from_slice(b"trailing garbage");
            assert!(RevocationSet::validate_persisted_bytes(&garbage, magic).is_err());
            let path = dir.path().join(name);
            tokio::fs::write(&path, &garbage).await.unwrap();
            let loaded = crate::storage::read_revocation_store(&path, store, false)
                .await
                .expect("a present file returns a set");
            let loaded = loaded.expect("the file exists");
            assert!(
                loaded.revocation_resync_required(),
                "trailing bytes keep {name} membership closed"
            );
            assert!(loaded.is_empty(), "{name} contributes no records");
            let outcome = crate::storage::save_private_bytes_to(&path, valid).await;
            assert_ne!(
                tokio::fs::read(&path).await.ok().as_deref(),
                Some(garbage.as_slice()),
                "persist must move trailing garbage off the live path"
            );
            let refused = outcome.expect_err("trailing bytes block overwrite");
            assert!(crate::storage::revocation_persistence_is_blocked(&refused));
        }
    }

    /// #1116: the hold is in memory only. A readable merge does not clear
    /// it, and encoding still writes verified records alone.
    #[test]
    fn unreadable_store_stays_local_and_merge_keeps_it_1116() {
        let agent = AgentId([0x11; 32]);
        let machine = MachineId([0x22; 32]);
        let grant = [0x33; 32];
        let owner = UserId([0x44; 32]);
        let closed = RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1);
        assert!(closed.is_empty());
        assert!(closed.revocation_resync_required());
        assert!(closed.member_treated_as_revoked(&agent));
        assert!(!closed.is_agent_revoked(&agent));
        assert!(!closed.is_machine_revoked(&machine));
        assert!(!closed.is_binding_revoked(&agent, &machine));
        assert!(!closed.is_share_grant_revoked(&grant, &owner));
        assert!(closed.max_revoked_binding_epoch(&agent).is_none());
        assert_eq!(closed.generation(), 0);
        assert_eq!(
            closed.to_bytes().unwrap(),
            RevocationSet::new().to_bytes().unwrap()
        );
        assert_eq!(
            closed.to_bytes_v2().unwrap(),
            RevocationSet::new().to_bytes_v2().unwrap()
        );
        assert_eq!(
            closed.to_bytes_v3().unwrap(),
            RevocationSet::new().to_bytes_v3().unwrap()
        );
        let decoded = RevocationSet::from_bytes(&closed.to_bytes().unwrap()).unwrap();
        assert!(!decoded.revocation_resync_required());
        assert!(!decoded.member_treated_as_revoked(&agent));

        let mut held = RevocationSet::new();
        let generation = held.generation();
        held.merge_v2(RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V2));
        assert!(held.revocation_resync_required());
        assert!(held.member_treated_as_revoked(&agent));
        assert_eq!(held.generation(), generation);
        held.merge_v2(RevocationSet::new());
        assert!(
            held.revocation_resync_required(),
            "a readable v2 merge does not clear the hold"
        );

        let mut held = RevocationSet::new();
        held.merge_v3(RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V3));
        assert!(held.member_treated_as_revoked(&agent));
        assert!(!held.is_share_grant_revoked(&grant, &owner));
        held.merge_v3(RevocationSet::new());
        assert!(
            held.revocation_resync_required(),
            "a readable v3 merge does not clear the hold"
        );

        assert!(
            !held.apply_group_revocation_resync(Vec::new(), 1_000),
            "an empty snapshot must not re-admit members"
        );
        assert!(held.member_treated_as_revoked(&agent));
        let revoked = crate::identity::AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(revoked.agent_id()),
            revoked.public_key(),
            revoked.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let forger = crate::identity::AgentKeypair::generate().unwrap();
        let forged = RevocationRecord::sign(
            RevokedSubject::Agent(revoked.agent_id()),
            forger.public_key(),
            forger.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        assert!(
            !held.apply_group_revocation_resync(vec![record.clone(), forged], 1_000),
            "a snapshot with one failed record must not open membership"
        );
        assert!(held.revocation_resync_required());
        assert!(
            !held.apply_group_revocation_resync(vec![record], 1_000),
            "a v1 record must not open a waiting v3 carrier"
        );
        assert!(held.revocation_resync_required());
        assert!(held.member_treated_as_revoked(&agent));
        let owner_keys = crate::identity::UserKeypair::generate().unwrap();
        let grant_id = [0x33; 32];
        let grant = RevocationRecord::sign(
            RevokedSubject::ShareGrant(ShareGrantRevocation {
                grant_id,
                owner: owner_keys.user_id(),
                grant_expiry: u64::MAX,
            }),
            owner_keys.public_key(),
            owner_keys.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        assert!(
            !held.apply_group_revocation_resync(vec![grant.clone()], 1_000),
            "inserting one verified record is not a group snapshot"
        );
        assert!(held.revocation_resync_required());
        assert!(held.is_share_grant_revoked(&grant_id, &owner_keys.user_id()));
        let peer_a = AgentId([0xA1; 32]);
        let peer_b = AgentId([0xB2; 32]);
        held.observe_remote_carrier_snapshot(
            REVOCATION_CARRIER_V3,
            &peer_a,
            std::slice::from_ref(&grant),
            false,
        );
        held.observe_remote_carrier_snapshot(
            REVOCATION_CARRIER_V3,
            &peer_b,
            std::slice::from_ref(&grant),
            false,
        );
        assert!(
            held.revocation_resync_required(),
            "two free keys do not open the carrier"
        );
        held.observe_remote_carrier_snapshot(
            REVOCATION_CARRIER_V3,
            &peer_a,
            std::slice::from_ref(&grant),
            true,
        );
        assert!(
            !held.carrier_resync_pending(REVOCATION_CARRIER_V3),
            "a trusted snapshot accepts the carrier"
        );
        assert!(
            held.revocation_resync_required(),
            "a trusted snapshot does not open admission"
        );
        assert!(
            held.member_treated_as_revoked(&agent),
            "a stranger stays withheld until reconciliation releases"
        );
        held.observe_remote_carrier_snapshot(
            REVOCATION_CARRIER_V3,
            &peer_a,
            std::slice::from_ref(&grant),
            true,
        );
        held.observe_remote_carrier_snapshot(
            REVOCATION_CARRIER_V3,
            &peer_b,
            std::slice::from_ref(&grant),
            false,
        );
        assert!(
            held.revocation_resync_required(),
            "a second snapshot does not clear the reconcile hold"
        );
        assert!(held.member_treated_as_revoked(&agent));
        held.release_reconciled_carrier(REVOCATION_CARRIER_V3);
        assert!(!held.revocation_resync_required());
        assert!(
            !held.member_treated_as_revoked(&agent),
            "a stranger is admissible after reconciliation releases"
        );
    }

    /// #1116: each corrupt carrier stays closed until its own snapshot
    /// verifies. An empty payload, a local revocation, and one finished
    /// carrier do not re-admit the other carriers.
    #[tokio::test]
    async fn membership_stays_closed_until_each_carrier_resyncs_1116() {
        let stranger = AgentId([0xAB; 32]);
        let revoked = crate::identity::AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(revoked.agent_id()),
            revoked.public_key(),
            revoked.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let payload = bincode::serialize(&vec![record.clone()]).unwrap();
        let empty = bincode::serialize(&Vec::<RevocationRecord>::new()).unwrap();
        let set = std::sync::Arc::new(tokio::sync::RwLock::new(
            RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1 | REVOCATION_CARRIER_V2),
        ));
        let admin = AgentId([0xA5; 32]);
        set.write()
            .await
            .set_snapshot_authority(SnapshotAuthority::new(move |sender, _revoked| {
                *sender == admin
            }));

        let peer_a = AgentId([0xA1; 32]);
        let peer_b = AgentId([0xB2; 32]);
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &empty,
            Some(&peer_a),
            None,
        )
        .await;
        arm_incoming_revocation_snapshot(&set, "x0x.other", &payload, Some(&peer_a), None).await;
        assert!(set.read().await.member_treated_as_revoked(&stranger));

        let local = crate::identity::AgentKeypair::generate().unwrap();
        let local_record = RevocationRecord::sign(
            RevokedSubject::Agent(local.agent_id()),
            local.public_key(),
            local.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let local_for_snapshot = local_record.clone();
        assert!(set
            .write()
            .await
            .verify_and_insert(local_record, None)
            .unwrap());
        assert!(
            set.read().await.revocation_resync_required(),
            "a local revocation is not a group snapshot"
        );

        let full_payload = bincode::serialize(&vec![record.clone(), local_for_snapshot]).unwrap();
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &full_payload,
            Some(&peer_a),
            None,
        )
        .await;
        assert!(set.write().await.verify_and_insert(record, None).unwrap());
        assert!(
            set.read()
                .await
                .carrier_resync_pending(REVOCATION_CARRIER_V1),
            "one free peer's verified record does not open v1"
        );
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &full_payload,
            Some(&peer_b),
            None,
        )
        .await;
        assert!(
            set.read()
                .await
                .carrier_resync_pending(REVOCATION_CARRIER_V1),
            "two free keys do not open v1"
        );
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &full_payload,
            Some(&admin),
            None,
        )
        .await;
        {
            let guard = set.read().await;
            assert!(guard.revocation_resync_required(), "v2 is still unknown");
            assert!(guard.member_treated_as_revoked(&stranger));
            assert!(guard.member_treated_as_revoked(&revoked.agent_id()));
            assert!(!guard.carrier_resync_pending(REVOCATION_CARRIER_V1));
            assert!(guard.carrier_resync_pending(REVOCATION_CARRIER_V2));
        }

        let owner = crate::identity::UserKeypair::generate().unwrap();
        let bound = crate::identity::AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&owner, &bound).unwrap();
        let binding = RevocationRecord::sign(
            RevokedSubject::AgentMachineBinding(AgentMachineBinding {
                agent: bound.agent_id(),
                machine: MachineId([0x55; 32]),
                move_epoch: 1,
            }),
            owner.public_key(),
            owner.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let binding_payload = bincode::serialize(&vec![binding.clone()]).unwrap();
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_V2_TOPIC,
            &binding_payload,
            Some(&peer_a),
            None,
        )
        .await;
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_V2_TOPIC,
            &binding_payload,
            Some(&peer_b),
            None,
        )
        .await;
        assert!(
            !set.write()
                .await
                .apply_group_revocation_resync(vec![binding.clone()], 1_000),
            "a binding tombstone without its certificate does not verify"
        );
        assert!(set
            .read()
            .await
            .carrier_resync_pending(REVOCATION_CARRIER_V2));
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_V2_TOPIC,
            &binding_payload,
            Some(&admin),
            None,
        )
        .await;
        let mut certs = std::collections::HashMap::new();
        certs.insert(bound.agent_id(), cert);
        assert!(set.write().await.apply_group_revocation_resync_with_certs(
            vec![binding],
            &certs,
            1_000
        ));
        {
            let guard = set.read().await;
            assert!(!guard.carrier_resync_pending(REVOCATION_CARRIER_V1));
            assert!(!guard.carrier_resync_pending(REVOCATION_CARRIER_V2));
            assert!(
                guard.revocation_resync_required(),
                "accepted snapshots stay closed until reconciliation releases"
            );
            assert!(guard.member_treated_as_revoked(&revoked.agent_id()));
            assert!(
                guard.member_treated_as_revoked(&stranger),
                "a stranger stays refused until reconciliation releases"
            );
        }
        {
            let mut guard = set.write().await;
            guard.release_reconciled_carrier(REVOCATION_CARRIER_V1);
            guard.release_reconciled_carrier(REVOCATION_CARRIER_V2);
        }
        let guard = set.read().await;
        assert!(!guard.revocation_resync_required());
        assert!(guard.member_treated_as_revoked(&revoked.agent_id()));
        assert!(!guard.member_treated_as_revoked(&stranger));
    }

    /// #1116: the node's own publish is not a group snapshot, and a record
    /// that belongs to another carrier does not open the waiting one.
    #[tokio::test]
    async fn own_publish_and_wrong_carrier_keep_the_hold_1116() {
        let local = crate::identity::AgentKeypair::generate().unwrap();
        let local_record = RevocationRecord::sign(
            RevokedSubject::Agent(local.agent_id()),
            local.public_key(),
            local.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let payload = bincode::serialize(&vec![local_record.clone()]).unwrap();
        let set = std::sync::Arc::new(tokio::sync::RwLock::new(
            RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1 | REVOCATION_CARRIER_V3),
        ));
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&local.agent_id()),
            Some(&local.agent_id()),
        )
        .await;
        assert!(
            set.read().await.revocation_resync_required(),
            "the node's own publish must not open the carrier"
        );

        set.write()
            .await
            .verify_and_insert(local_record, None)
            .unwrap();
        let other = AgentId([0xC3; 32]);
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_V3_TOPIC,
            &payload,
            Some(&other),
            None,
        )
        .await;
        assert!(
            set.read()
                .await
                .carrier_resync_pending(REVOCATION_CARRIER_V3),
            "a v1 record on the v3 topic must not open v3"
        );
        assert!(set
            .read()
            .await
            .carrier_resync_pending(REVOCATION_CARRIER_V1));
    }

    /// #1116: one peer, including the revoked agent, cannot open a carrier.
    /// A snapshot that omits a known revocation cannot open it either.
    #[tokio::test]
    async fn partial_snapshot_omitting_known_revocation_keeps_the_hold_1116() {
        let revoked = crate::identity::AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(revoked.agent_id()),
            revoked.public_key(),
            revoked.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let throwaway = crate::identity::AgentKeypair::generate().unwrap();
        let unrelated = RevocationRecord::sign(
            RevokedSubject::Agent(throwaway.agent_id()),
            throwaway.public_key(),
            throwaway.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let unrelated_payload = bincode::serialize(&vec![unrelated.clone()]).unwrap();
        let full_payload = bincode::serialize(&vec![record.clone(), unrelated.clone()]).unwrap();
        let set = std::sync::Arc::new(tokio::sync::RwLock::new(
            RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1),
        ));
        let attacker = throwaway.agent_id();
        let peer = AgentId([0xD4; 32]);

        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &unrelated_payload,
            Some(&attacker),
            None,
        )
        .await;
        assert!(set
            .write()
            .await
            .verify_and_insert(unrelated.clone(), None)
            .unwrap());
        assert!(
            set.read().await.revocation_resync_required(),
            "one peer's record does not open the carrier"
        );
        assert!(
            set.read()
                .await
                .member_treated_as_revoked(&revoked.agent_id()),
            "the lost subject stays withheld"
        );

        assert!(set
            .write()
            .await
            .verify_and_insert(record.clone(), None)
            .unwrap());
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &unrelated_payload,
            Some(&attacker),
            None,
        )
        .await;
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &unrelated_payload,
            Some(&peer),
            None,
        )
        .await;
        assert!(
            set.read().await.revocation_resync_required(),
            "a snapshot that omits a known revocation does not open the carrier"
        );

        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &full_payload,
            Some(&attacker),
            None,
        )
        .await;
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &full_payload,
            Some(&peer),
            None,
        )
        .await;
        assert!(
            set.read().await.revocation_resync_required(),
            "two free keys must not open the carrier, even with a full snapshot"
        );
        set.write()
            .await
            .set_snapshot_authority(SnapshotAuthority::new(move |sender, _revoked| {
                *sender == attacker
            }));
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &unrelated_payload,
            Some(&attacker),
            None,
        )
        .await;
        assert!(
            set.read().await.revocation_resync_required(),
            "a trusted snapshot that omits a known revocation stays closed"
        );
        let admin = AgentId([0xE5; 32]);
        set.write()
            .await
            .set_snapshot_authority(SnapshotAuthority::new(move |sender, _revoked| {
                *sender == admin
            }));
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &full_payload,
            Some(&admin),
            None,
        )
        .await;
        {
            let guard = set.read().await;
            assert!(!guard.carrier_resync_pending(REVOCATION_CARRIER_V1));
            assert!(
                guard.revocation_resync_required(),
                "a complete trusted snapshot does not open admission"
            );
            assert!(guard.is_agent_revoked(&revoked.agent_id()));
            assert!(guard.member_treated_as_revoked(&AgentId([0xEE; 32])));
        }
        set.write()
            .await
            .release_reconciled_carrier(REVOCATION_CARRIER_V1);
        let guard = set.read().await;
        assert!(!guard.revocation_resync_required());
        assert!(guard.is_agent_revoked(&revoked.agent_id()));
        assert!(!guard.member_treated_as_revoked(&AgentId([0xEE; 32])));
    }

    #[test]
    fn recovery_topics_include_certificate_announcements_1116() {
        assert!(is_revocation_recovery_topic(crate::REVOCATION_TOPIC));
        assert!(is_revocation_recovery_topic(crate::IDENTITY_ANNOUNCE_TOPIC));
        assert!(is_revocation_recovery_topic("x0x.identity.shard.v2.7"));
        assert!(is_revocation_recovery_topic(
            crate::MACHINE_ANNOUNCE_V3_TOPIC
        ));
        assert!(is_revocation_recovery_topic(
            crate::announce_blob::ANNOUNCE_BLOB_TOPIC
        ));
        assert!(is_revocation_recovery_topic("x0x.user.shard.v2.9"));
        assert!(!is_revocation_recovery_topic("x0x.groups.public.example"));
        assert!(!is_revocation_recovery_topic("x0x/dm/v1/bus"));
    }

    /// #1116: two free keys that agree on a short snapshot do not write it.
    /// A restart must still withhold the subject that was never in that
    /// snapshot.
    #[tokio::test]
    async fn untrusted_free_keys_keep_incomplete_carrier_closed_across_restart_1116() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.bin");
        tokio::fs::write(&path, b"not-a-revocation-file")
            .await
            .unwrap();
        let loaded = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(loaded.revocation_resync_required());

        let lost = crate::identity::AgentKeypair::generate().unwrap();
        let throwaway = crate::identity::AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(throwaway.agent_id()),
            throwaway.public_key(),
            throwaway.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let payload = bincode::serialize(&vec![record.clone()]).unwrap();
        let set = std::sync::Arc::new(tokio::sync::RwLock::new(loaded));
        let free_a = AgentId([0x41; 32]);
        let free_b = AgentId([0x42; 32]);
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&free_a),
            None,
        )
        .await;
        assert!(set.write().await.verify_and_insert(record, None).unwrap());
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&free_b),
            None,
        )
        .await;
        assert!(
            set.read().await.revocation_resync_required(),
            "two free agent keys must not open an incomplete carrier"
        );
        assert!(set.read().await.member_treated_as_revoked(&lost.agent_id()));
        let pending = set.write().await.take_rebuild_pending();
        assert_eq!(
            pending, 0,
            "an untrusted incomplete snapshot is not a rebuild"
        );
        let again = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            again.revocation_resync_required(),
            "restart must not load the incomplete set as a rebuild"
        );
        assert!(again.member_treated_as_revoked(&lost.agent_id()));
        assert!(!again.is_agent_revoked(&lost.agent_id()));
    }

    /// #1116: a trusted authority opens the in-memory carrier. Unreadable
    /// quarantine bytes stay in place, and the shorter snapshot is not
    /// installed. The next load stays closed until the operator command.
    #[tokio::test]
    async fn unreadable_quarantine_blocks_the_shorter_rebuild_1116() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.bin");
        let garbage = b"truncated-looking-but-garbage";
        tokio::fs::write(&path, garbage).await.unwrap();
        let loaded = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(loaded.revocation_resync_required());
        let quarantine = std::fs::read_dir(dir.path())
            .unwrap()
            .find_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("revocations.bin.quarantined-")
                    .then(|| entry.path())
            })
            .expect("quarantine file");
        let quarantined_bytes = std::fs::read(&quarantine).unwrap();

        let revoked = crate::identity::AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(revoked.agent_id()),
            revoked.public_key(),
            revoked.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let payload = bincode::serialize(&vec![record.clone()]).unwrap();
        let set = std::sync::Arc::new(tokio::sync::RwLock::new(loaded));
        let free_a = AgentId([0x11; 32]);
        let free_b = AgentId([0x21; 32]);
        let authority = AgentId([0x22; 32]);
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&free_a),
            None,
        )
        .await;
        assert!(set.write().await.verify_and_insert(record, None).unwrap());
        assert!(set.read().await.revocation_resync_required());
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&free_b),
            None,
        )
        .await;
        assert!(
            set.read().await.revocation_resync_required(),
            "two free keys do not rebuild the live file"
        );
        set.write()
            .await
            .set_snapshot_authority(SnapshotAuthority::new(move |sender, _revoked| {
                *sender == authority
            }));
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&authority),
            None,
        )
        .await;
        assert!(
            set.read().await.revocation_resync_required(),
            "an accepted snapshot stays closed until the rebuild installs it"
        );
        assert!(!set
            .read()
            .await
            .carrier_resync_pending(REVOCATION_CARRIER_V1));
        let pending = set.write().await.take_rebuild_pending();
        assert_eq!(pending, REVOCATION_CARRIER_V1);
        set.write()
            .await
            .requeue_rebuild_pending(REVOCATION_CARRIER_V1);
        crate::persist_completed_revocation_rebuild(&set, Some(dir.path())).await;
        assert!(
            !path.is_file(),
            "unreadable quarantine bytes block the shorter remote set"
        );
        assert!(
            set.read().await.revocation_resync_required(),
            "unreadable quarantine keeps the running carrier closed"
        );
        assert!(set
            .read()
            .await
            .member_treated_as_revoked(&AgentId([0xEE; 32])));
        assert_ne!(set.write().await.take_rebuild_pending(), 0);
        assert_eq!(std::fs::read(&quarantine).unwrap(), quarantined_bytes);
        let again = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(again.revocation_resync_required());
        assert!(!again.is_agent_revoked(&revoked.agent_id()));
    }

    /// Open a quarantined v1 carrier from one trusted sender and return the
    /// set plus the revoked agent. No live file is written yet.
    async fn open_v1_carrier_for_rebuild(
        dir: &std::path::Path,
    ) -> (
        std::sync::Arc<tokio::sync::RwLock<RevocationSet>>,
        crate::identity::AgentId,
    ) {
        let path = dir.join("revocations.bin");
        let revoked = crate::identity::AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(revoked.agent_id()),
            revoked.public_key(),
            revoked.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let mut seeded = RevocationSet::new();
        assert!(seeded.verify_and_insert(record.clone(), None).unwrap());
        let mut stored = seeded.to_bytes().unwrap();
        stored.extend_from_slice(b"trailing");
        tokio::fs::write(&path, &stored).await.unwrap();
        let loaded = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(loaded.revocation_resync_required());
        let quarantine = std::fs::read_dir(dir)
            .unwrap()
            .find_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("revocations.bin.quarantined-")
                    .then(|| entry.path())
            })
            .expect("quarantine file");
        assert!(
            RevocationSet::from_bytes(&std::fs::read(quarantine).unwrap())
                .unwrap()
                .is_agent_revoked(&revoked.agent_id()),
            "trailing bytes quarantine still decodes the revocation"
        );
        let payload = bincode::serialize(&vec![record.clone()]).unwrap();
        let set = std::sync::Arc::new(tokio::sync::RwLock::new(loaded));
        let authority = AgentId([0x22; 32]);
        set.write()
            .await
            .set_snapshot_authority(SnapshotAuthority::new(move |sender, _revoked| {
                *sender == authority
            }));
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&authority),
            None,
        )
        .await;
        assert!(set.write().await.verify_and_insert(record, None).unwrap());
        assert!(
            set.read().await.revocation_resync_required(),
            "the snapshot is accepted and admission stays closed until the rebuild"
        );
        assert!(!set
            .read()
            .await
            .carrier_resync_pending(REVOCATION_CARRIER_V1));
        (set, revoked.agent_id())
    }

    /// #1116: a before-rename failure keeps the pending bit. Removing the
    /// fault and calling the helper again writes the same bytes. No new
    /// revocation is required.
    #[tokio::test]
    async fn rebuild_pending_retries_after_before_rename_1116() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.bin");
        let (set, revoked) = open_v1_carrier_for_rebuild(dir.path()).await;
        let records_before = set.read().await.len();
        tokio::fs::create_dir(&path).await.unwrap();
        crate::persist_completed_revocation_rebuild(&set, Some(dir.path())).await;
        assert!(path.is_dir(), "the before-rename fault leaves no live file");
        assert!(
            set.read().await.revocation_resync_required(),
            "a before-rename failure keeps admission closed"
        );
        assert!(set
            .read()
            .await
            .member_treated_as_revoked(&AgentId([0xEE; 32])));
        assert_eq!(set.read().await.len(), records_before);
        tokio::fs::remove_dir(&path).await.unwrap();
        crate::persist_completed_revocation_rebuild(&set, Some(dir.path())).await;
        assert!(path.is_file(), "the retry writes the live file");
        assert!(!set.read().await.revocation_resync_required());
        assert_eq!(set.read().await.len(), records_before);
        assert_eq!(set.write().await.take_rebuild_pending(), 0);
        let again = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!again.revocation_resync_required());
        assert!(again.is_agent_revoked(&revoked));
    }

    /// #1116: a failure after the rename leaves the new bytes in place and
    /// does not queue another rebuild.
    #[tokio::test]
    async fn rebuild_after_rename_is_not_requeued_1116() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.bin");
        let (set, revoked) = open_v1_carrier_for_rebuild(dir.path()).await;
        let _guard = crate::storage::arm_fail_parent_dir_fsync_for_testing(&path);
        crate::persist_completed_revocation_rebuild(&set, Some(dir.path())).await;
        assert!(path.is_file(), "the rename already published the live file");
        assert!(!set.read().await.revocation_resync_required());
        assert_eq!(set.write().await.take_rebuild_pending(), 0);
        let again = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!again.revocation_resync_required());
        assert!(again.is_agent_revoked(&revoked));
    }

    /// #1116: a failure after the rename that leaves bytes the node cannot
    /// install keeps admission closed and does not queue another rebuild.
    #[tokio::test]
    async fn rebuild_after_rename_failure_keeps_the_hold_1116() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.bin");
        let (set, _revoked) = open_v1_carrier_for_rebuild(dir.path()).await;
        let _fsync = crate::storage::arm_fail_parent_dir_fsync_for_testing(&path);
        let _corrupt = crate::storage::arm_corrupt_after_rename_for_testing(&path);
        crate::persist_completed_revocation_rebuild(&set, Some(dir.path())).await;
        assert_eq!(std::fs::read(&path).unwrap(), b"not-a-revocation-file");
        assert!(
            set.read().await.revocation_resync_required(),
            "a failed reconciliation keeps admission closed"
        );
        assert!(set
            .read()
            .await
            .member_treated_as_revoked(&AgentId([0xEE; 32])));
        assert_eq!(set.write().await.take_rebuild_pending(), 0);
    }

    /// #1116: admission stays closed while the rebuild is still in storage.
    /// A fresh trusted snapshot and an untrusted snapshot do not clear it.
    #[tokio::test]
    async fn rebuild_await_keeps_admission_closed_1116() {
        let kept = crate::identity::MachineKeypair::generate().unwrap();
        let snapshot_machine = crate::identity::MachineKeypair::generate().unwrap();
        let kept_record = RevocationRecord::sign(
            RevokedSubject::Machine(kept.machine_id()),
            kept.public_key(),
            kept.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let snapshot_record = RevocationRecord::sign(
            RevokedSubject::Machine(snapshot_machine.machine_id()),
            snapshot_machine.public_key(),
            snapshot_machine.secret_key(),
            1_001,
            None,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.bin");
        let mut seeded = RevocationSet::new();
        assert!(seeded.verify_and_insert(kept_record, None).unwrap());
        let mut stored = seeded.to_bytes().unwrap();
        stored.extend_from_slice(b"trailing");
        tokio::fs::write(&path, &stored).await.unwrap();
        let loaded = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        let payload = bincode::serialize(&vec![snapshot_record.clone()]).unwrap();
        let set = std::sync::Arc::new(tokio::sync::RwLock::new(loaded));
        let authority = AgentId([0x22; 32]);
        let stranger = AgentId([0xEE; 32]);
        let untrusted = AgentId([0x33; 32]);
        set.write()
            .await
            .set_snapshot_authority(SnapshotAuthority::new(move |sender, _revoked| {
                *sender == authority
            }));
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&authority),
            None,
        )
        .await;
        assert!(set
            .write()
            .await
            .verify_and_insert(snapshot_record, None)
            .unwrap());
        assert!(set.read().await.revocation_resync_required());
        assert!(!set.read().await.is_machine_revoked(&kept.machine_id()));
        assert!(set.read().await.member_treated_as_revoked(&stranger));

        let _await_guard = crate::storage::arm_rebuild_await_for_testing();
        let set_task = std::sync::Arc::clone(&set);
        let dir_path = dir.path().to_path_buf();
        let task = tokio::spawn(async move {
            crate::persist_completed_revocation_rebuild(&set_task, Some(&dir_path)).await;
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !crate::storage::rebuild_await_entered_for_testing() {
            assert!(
                std::time::Instant::now() < deadline,
                "the rebuild did not reach storage"
            );
            tokio::task::yield_now().await;
        }
        let fresh = set.read().await.all_records();
        let fresh_payload = bincode::serialize(&fresh).unwrap();
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &fresh_payload,
            Some(&authority),
            None,
        )
        .await;
        {
            let mut guard = set.write().await;
            guard.observe_remote_carrier_snapshot(REVOCATION_CARRIER_V1, &authority, &fresh, true);
            guard.observe_remote_carrier_snapshot(REVOCATION_CARRIER_V1, &untrusted, &fresh, false);
        }
        assert!(
            set.read().await.revocation_resync_required(),
            "a snapshot during the storage await does not open admission"
        );
        assert!(set.read().await.member_treated_as_revoked(&stranger));
        assert!(!set.read().await.is_machine_revoked(&kept.machine_id()));
        crate::storage::release_rebuild_await_for_testing();
        tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .expect("rebuild await")
            .expect("rebuild task");
        assert!(path.is_file());
        assert!(set.read().await.is_machine_revoked(&kept.machine_id()));
        assert!(set
            .read()
            .await
            .is_machine_revoked(&snapshot_machine.machine_id()));
        assert!(!set.read().await.revocation_resync_required());
        assert!(!set.read().await.member_treated_as_revoked(&stranger));
    }

    /// #1116: an ordinary save captured before the rebuild must not replace
    /// the rebuilt file. The captured bytes are S. Disk after the rebuild
    /// is R and S. The late save still leaves both.
    #[tokio::test]
    async fn queued_save_cannot_drop_a_rebuilt_revocation_1116() {
        let kept = crate::identity::MachineKeypair::generate().unwrap();
        let snapshot_machine = crate::identity::MachineKeypair::generate().unwrap();
        let kept_record = RevocationRecord::sign(
            RevokedSubject::Machine(kept.machine_id()),
            kept.public_key(),
            kept.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let snapshot_record = RevocationRecord::sign(
            RevokedSubject::Machine(snapshot_machine.machine_id()),
            snapshot_machine.public_key(),
            snapshot_machine.secret_key(),
            1_001,
            None,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.bin");
        let mut seeded = RevocationSet::new();
        assert!(seeded.verify_and_insert(kept_record, None).unwrap());
        let mut stored = seeded.to_bytes().unwrap();
        stored.extend_from_slice(b"trailing");
        tokio::fs::write(&path, &stored).await.unwrap();
        let loaded = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        let payload = bincode::serialize(&vec![snapshot_record.clone()]).unwrap();
        let set = std::sync::Arc::new(tokio::sync::RwLock::new(loaded));
        let authority = AgentId([0x22; 32]);
        set.write()
            .await
            .set_snapshot_authority(SnapshotAuthority::new(move |sender, _revoked| {
                *sender == authority
            }));
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&authority),
            None,
        )
        .await;
        assert!(set
            .write()
            .await
            .verify_and_insert(snapshot_record, None)
            .unwrap());
        let captured = set.read().await.to_bytes().unwrap();
        let captured_set = RevocationSet::from_bytes(&captured).unwrap();
        assert!(
            !captured_set.is_machine_revoked(&kept.machine_id()),
            "the queued save is S and does not yet contain R"
        );
        assert!(captured_set.is_machine_revoked(&snapshot_machine.machine_id()));
        crate::persist_completed_revocation_rebuild(&set, Some(dir.path())).await;
        let rebuilt = RevocationSet::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        assert!(rebuilt.is_machine_revoked(&kept.machine_id()));
        assert!(rebuilt.is_machine_revoked(&snapshot_machine.machine_id()));
        crate::storage::save_revocation_set_bytes(captured, Some(dir.path()))
            .await
            .unwrap();
        let saved = RevocationSet::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        assert!(
            saved.is_machine_revoked(&kept.machine_id()),
            "a queued save of S must not drop recovered R"
        );
        assert!(saved.is_machine_revoked(&snapshot_machine.machine_id()));
    }

    /// #1116: a delayed v3 rebuild must not erase a newer durable revocation.
    #[tokio::test]
    async fn stale_v3_rebuild_keeps_a_newer_durable_revocation_1116() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations-v3.bin");
        let owner = crate::identity::UserKeypair::generate().unwrap();
        let now = 1_700_000_000_u64;
        let older_id = [0x11_u8; 32];
        let newer_id = [0x22_u8; 32];
        let older = RevocationRecord::sign(
            RevokedSubject::ShareGrant(ShareGrantRevocation {
                grant_id: older_id,
                owner: owner.user_id(),
                grant_expiry: u64::MAX,
            }),
            owner.public_key(),
            owner.secret_key(),
            now,
            None,
        )
        .unwrap();
        let newer = RevocationRecord::sign(
            RevokedSubject::ShareGrant(ShareGrantRevocation {
                grant_id: newer_id,
                owner: owner.user_id(),
                grant_expiry: u64::MAX,
            }),
            owner.public_key(),
            owner.secret_key(),
            now + 10,
            None,
        )
        .unwrap();

        let mut stale = RevocationSet::new();
        assert!(stale.verify_and_insert(older, None).unwrap());
        stale.requeue_rebuild_pending(REVOCATION_CARRIER_V3);
        let stale = std::sync::Arc::new(tokio::sync::RwLock::new(stale));
        crate::persist_completed_revocation_rebuild(&stale, Some(dir.path())).await;
        assert!(path.is_file(), "the first rebuild writes the live file");

        let mut grown = RevocationSet::from_bytes_v3(&std::fs::read(&path).unwrap()).unwrap();
        assert!(grown.verify_and_insert(newer, None).unwrap());
        let grown = std::sync::Arc::new(tokio::sync::RwLock::new(grown));
        crate::persist_share_grant_revocations_durable(&grown, Some(dir.path()))
            .await
            .unwrap();

        stale
            .write()
            .await
            .requeue_rebuild_pending(REVOCATION_CARRIER_V3);
        crate::persist_completed_revocation_rebuild(&stale, Some(dir.path())).await;

        let loaded = RevocationSet::from_bytes_v3(&std::fs::read(&path).unwrap()).unwrap();
        assert!(
            loaded.is_share_grant_revoked(&older_id, &owner.user_id()),
            "the stale snapshot's revocation stays"
        );
        assert!(
            loaded.is_share_grant_revoked(&newer_id, &owner.user_id()),
            "a newer durable revocation survives the late rebuild"
        );
    }

    /// #1116: the first rebuild unites a revocation that the quarantine file
    /// still contains. A shorter snapshot must not drop it. Unreadable
    /// quarantine bytes are not replaced by that snapshot.
    #[tokio::test]
    async fn quarantine_file_revocation_survives_shorter_rebuild_1116() {
        let owner = crate::identity::UserKeypair::generate().unwrap();
        let now = 1_700_000_000_u64;
        let kept_id = [0x31_u8; 32];
        let snapshot_id = [0x32_u8; 32];
        let kept = RevocationRecord::sign(
            RevokedSubject::ShareGrant(ShareGrantRevocation {
                grant_id: kept_id,
                owner: owner.user_id(),
                grant_expiry: u64::MAX,
            }),
            owner.public_key(),
            owner.secret_key(),
            now,
            None,
        )
        .unwrap();
        let snapshot_record = RevocationRecord::sign(
            RevokedSubject::ShareGrant(ShareGrantRevocation {
                grant_id: snapshot_id,
                owner: owner.user_id(),
                grant_expiry: u64::MAX,
            }),
            owner.public_key(),
            owner.secret_key(),
            now,
            None,
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations-v3.bin");
        let mut seeded = RevocationSet::new();
        assert!(seeded.verify_and_insert(kept, None).unwrap());
        let mut stored = seeded.to_bytes_v3().unwrap();
        stored.extend_from_slice(b"trailing");
        tokio::fs::write(&path, &stored).await.unwrap();
        let loaded = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V3,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(loaded.revocation_resync_required());
        assert!(!path.is_file(), "quarantine removes the live file");
        let quarantine = std::fs::read_dir(dir.path())
            .unwrap()
            .find_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("revocations-v3.bin.quarantined-")
                    .then(|| entry.path())
            })
            .expect("quarantine file");
        let quarantined = std::fs::read(&quarantine).unwrap();
        assert!(
            RevocationSet::from_bytes_v3(&quarantined)
                .unwrap()
                .is_share_grant_revoked(&kept_id, &owner.user_id()),
            "the quarantine file still contains R"
        );

        let mut snapshot = RevocationSet::new();
        assert!(snapshot
            .verify_and_insert(snapshot_record.clone(), None)
            .unwrap());
        snapshot.requeue_rebuild_pending(REVOCATION_CARRIER_V3);
        let snapshot = std::sync::Arc::new(tokio::sync::RwLock::new(snapshot));
        crate::persist_completed_revocation_rebuild(&snapshot, Some(dir.path())).await;
        assert!(
            path.is_file(),
            "a readable quarantine file is united into the rebuild"
        );
        assert_eq!(snapshot.write().await.take_rebuild_pending(), 0);
        let united = RevocationSet::from_bytes_v3(&std::fs::read(&path).unwrap()).unwrap();
        assert!(
            united.is_share_grant_revoked(&kept_id, &owner.user_id()),
            "R is still revoked after the rebuild"
        );
        assert!(
            united.is_share_grant_revoked(&snapshot_id, &owner.user_id()),
            "the snapshot revocation stays"
        );
        assert_eq!(std::fs::read(&quarantine).unwrap(), quarantined);

        let operator_dir = tempfile::tempdir().unwrap();
        let operator_path = operator_dir.path().join("revocations-v3.bin");
        tokio::fs::write(&operator_path, &stored).await.unwrap();
        let operator_loaded = crate::storage::read_revocation_store(
            &operator_path,
            crate::storage::RevocationStore::V3,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(operator_loaded.revocation_resync_required());
        let candidate = {
            let mut only_snapshot = RevocationSet::new();
            assert!(only_snapshot
                .verify_and_insert(snapshot_record.clone(), None)
                .unwrap());
            only_snapshot.to_bytes_v3().unwrap()
        };
        let wrote = crate::storage::install_operator_revocation_carrier(
            operator_dir.path(),
            "v3",
            candidate,
            false,
        )
        .await
        .expect("operator install");
        assert!(wrote.kept_durable_records);
        assert!(!wrote.empty_store);
        let operator_live =
            RevocationSet::from_bytes_v3(&std::fs::read(&operator_path).unwrap()).unwrap();
        assert!(operator_live.is_share_grant_revoked(&kept_id, &owner.user_id()));
        assert!(operator_live.is_share_grant_revoked(&snapshot_id, &owner.user_id()));

        let blocked = tempfile::tempdir().unwrap();
        let blocked_path = blocked.path().join("revocations-v3.bin");
        tokio::fs::write(&blocked_path, b"not-a-v3-file")
            .await
            .unwrap();
        let blocked_load = crate::storage::read_revocation_store(
            &blocked_path,
            crate::storage::RevocationStore::V3,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(blocked_load.revocation_resync_required());
        assert!(!blocked_path.is_file());
        let mut shorter = RevocationSet::new();
        assert!(shorter.verify_and_insert(snapshot_record, None).unwrap());
        shorter.requeue_rebuild_pending(REVOCATION_CARRIER_V3);
        let shorter = std::sync::Arc::new(tokio::sync::RwLock::new(shorter));
        crate::persist_completed_revocation_rebuild(&shorter, Some(blocked.path())).await;
        assert!(
            !blocked_path.is_file(),
            "unreadable quarantine bytes block the shorter remote set"
        );
        assert_ne!(shorter.write().await.take_rebuild_pending(), 0);
        assert!(
            shorter.read().await.revocation_resync_required(),
            "unreadable quarantine keeps the running carrier closed"
        );
    }

    /// #1116: quarantine file R is a machine revocation the snapshot omits.
    /// The running set enforces R before the carrier opens. The next
    /// ordinary save of that set still contains R.
    #[tokio::test]
    async fn recovered_machine_revocation_is_enforced_through_the_next_save_1116() {
        let kept = crate::identity::MachineKeypair::generate().unwrap();
        let snapshot_machine = crate::identity::MachineKeypair::generate().unwrap();
        let later = crate::identity::MachineKeypair::generate().unwrap();
        let kept_record = RevocationRecord::sign(
            RevokedSubject::Machine(kept.machine_id()),
            kept.public_key(),
            kept.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        let snapshot_record = RevocationRecord::sign(
            RevokedSubject::Machine(snapshot_machine.machine_id()),
            snapshot_machine.public_key(),
            snapshot_machine.secret_key(),
            1_001,
            None,
        )
        .unwrap();
        let later_record = RevocationRecord::sign(
            RevokedSubject::Machine(later.machine_id()),
            later.public_key(),
            later.secret_key(),
            1_002,
            None,
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.bin");
        let mut seeded = RevocationSet::new();
        assert!(seeded.verify_and_insert(kept_record.clone(), None).unwrap());
        let mut stored = seeded.to_bytes().unwrap();
        stored.extend_from_slice(b"trailing");
        tokio::fs::write(&path, &stored).await.unwrap();
        let loaded = crate::storage::read_revocation_store(
            &path,
            crate::storage::RevocationStore::V1,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(loaded.revocation_resync_required());
        assert!(!path.is_file());

        let payload = bincode::serialize(&vec![snapshot_record.clone()]).unwrap();
        let set = std::sync::Arc::new(tokio::sync::RwLock::new(loaded));
        let authority = AgentId([0x22; 32]);
        set.write()
            .await
            .set_snapshot_authority(SnapshotAuthority::new(move |sender, _revoked| {
                *sender == authority
            }));
        arm_incoming_revocation_snapshot(
            &set,
            crate::REVOCATION_TOPIC,
            &payload,
            Some(&authority),
            None,
        )
        .await;
        assert!(set
            .write()
            .await
            .verify_and_insert(snapshot_record, None)
            .unwrap());
        assert!(
            set.read().await.revocation_resync_required(),
            "admission stays closed until the rebuild installs recovered R"
        );
        assert!(!set
            .read()
            .await
            .carrier_resync_pending(REVOCATION_CARRIER_V1));
        assert!(set
            .read()
            .await
            .is_machine_revoked(&snapshot_machine.machine_id()));
        assert!(
            !set.read().await.is_machine_revoked(&kept.machine_id()),
            "the snapshot alone does not enforce the quarantined machine"
        );

        crate::persist_completed_revocation_rebuild(&set, Some(dir.path())).await;
        assert!(path.is_file(), "the readable quarantine file is united");
        assert!(
            set.read().await.is_machine_revoked(&kept.machine_id()),
            "recovered R is enforced in the live set"
        );
        assert!(set
            .read()
            .await
            .is_machine_revoked(&snapshot_machine.machine_id()));
        assert!(!set.read().await.revocation_resync_required());
        assert!(!set
            .read()
            .await
            .member_treated_as_revoked(&AgentId([0xEE; 32])));
        assert_eq!(set.write().await.take_rebuild_pending(), 0);
        let united = RevocationSet::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        assert!(united.is_machine_revoked(&kept.machine_id()));
        assert!(united.is_machine_revoked(&snapshot_machine.machine_id()));

        assert!(set
            .write()
            .await
            .verify_and_insert(later_record, None)
            .unwrap());
        {
            let live = set.read().await;
            crate::storage::save_revocation_set(&live, Some(dir.path()))
                .await
                .unwrap();
        }
        let saved = RevocationSet::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        assert!(
            saved.is_machine_revoked(&kept.machine_id()),
            "the next ordinary save keeps recovered R"
        );
        assert!(saved.is_machine_revoked(&snapshot_machine.machine_id()));
        assert!(saved.is_machine_revoked(&later.machine_id()));
        assert!(set.read().await.is_machine_revoked(&kept.machine_id()));
    }

    #[tokio::test]
    async fn structural_validation_keeps_signature_checks_on_load_1116() {
        let owner = crate::identity::UserKeypair::generate().unwrap();
        let agent = crate::identity::AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&owner, &agent).unwrap();
        let dir = tempfile::tempdir().unwrap();
        for (name, magic, subject, subject_cert) in [
            (
                "revocations.bin",
                REVOCATIONS_FILE_MAGIC,
                RevokedSubject::Agent(agent.agent_id()),
                Some(cert.clone()),
            ),
            (
                "revocations-v2.bin",
                REVOCATIONS_FILE_MAGIC_V2,
                RevokedSubject::AgentMachineBinding(AgentMachineBinding {
                    agent: agent.agent_id(),
                    machine: crate::identity::MachineId([0x55; 32]),
                    move_epoch: 1,
                }),
                Some(cert.clone()),
            ),
            (
                "revocations-v3.bin",
                REVOCATIONS_FILE_MAGIC_V3,
                RevokedSubject::ShareGrant(ShareGrantRevocation {
                    grant_id: [0x66; 32],
                    owner: owner.user_id(),
                    grant_expiry: u64::MAX,
                }),
                None,
            ),
        ] {
            let decode = |bytes: &[u8]| match name {
                "revocations.bin" => RevocationSet::from_bytes(bytes),
                "revocations-v2.bin" => RevocationSet::from_bytes_v2(bytes),
                _ => RevocationSet::from_bytes_v3(bytes),
            };
            let record = RevocationRecord::sign(
                subject,
                owner.public_key(),
                owner.secret_key(),
                1_000,
                None,
            )
            .unwrap();
            let hash = record.record_hash();
            let mut persisted = vec![PersistedRevocation {
                record,
                subject_cert,
            }];
            let mut valid = magic.to_vec();
            valid.extend_from_slice(&bincode::serialize(&persisted).unwrap());
            assert!(RevocationSet::validate_persisted_bytes(&valid, magic).is_ok());
            assert!(
                decode(&valid).unwrap().contains_hash(&hash),
                "valid subject and authority must load from {name}"
            );
            // A native v3 subject is essential: a v1 Agent subject would
            // be filtered out before v3's signature check, hiding a defect.
            persisted[0].record.signature[0] ^= 0xff;
            let mut bytes = magic.to_vec();
            bytes.extend_from_slice(&bincode::serialize(&persisted).unwrap());
            assert!(RevocationSet::validate_persisted_bytes(&bytes, magic).is_ok());
            let loaded = decode(&bytes).unwrap();
            assert!(
                loaded.is_empty(),
                "invalid signature still rejected on load from {name}"
            );
            let path = dir.path().join(name);
            tokio::fs::write(&path, &bytes).await.unwrap();
            crate::storage::save_private_bytes_to(&path, bytes.clone())
                .await
                .unwrap();
            assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
            let mut malformed = magic.to_vec();
            malformed.push(1);
            assert!(RevocationSet::validate_persisted_bytes(&malformed, magic).is_err());
            assert!(RevocationSet::validate_persisted_bytes(b"X0RX", magic).is_err());
        }
    }

    mod revocation_cadence {
        use super::super::*;
        use crate::identity::{AgentKeypair, MachineKeypair, UserKeypair};

        /// Build a self-signed revocation record for an agent at the given
        /// timestamp. Self-revocations require no subject certificate.
        fn self_revocation(agent_kp: &AgentKeypair, revoked_at: u64) -> RevocationRecord {
            RevocationRecord::sign(
                RevokedSubject::Agent(agent_kp.agent_id()),
                agent_kp.public_key(),
                agent_kp.secret_key(),
                revoked_at,
                None,
            )
            .expect("self-revocation signs")
        }

        /// ADR 0115 §5: ingress rejects a far-future
        /// `revoked_at`, and the load-time drop removes one while the
        /// other records of the same subject keep enforcing.
        #[test]
        fn far_future_revoked_at_is_rejected_and_dropped_at_load() {
            let kp = AgentKeypair::generate().expect("agent keypair");
            let other = AgentKeypair::generate().expect("other keypair");
            let now = 1_800_000_000u64;
            let mut set = RevocationSet::new();
            assert!(set
                .verify_and_insert_at(
                    self_revocation(&kp, now + REVOCATION_MAX_FUTURE_SKEW_SECS + 1),
                    None,
                    now
                )
                .is_err());
            assert!(set
                .verify_and_insert_at(
                    self_revocation(&kp, now + REVOCATION_MAX_FUTURE_SKEW_SECS),
                    None,
                    now
                )
                .expect("at the bound is credible"));
            assert!(set.is_agent_revoked(&kp.agent_id()));

            // A persisted far-future record, as an earlier build may hold.
            let mut loaded = RevocationSet::new();
            loaded
                .verify_and_insert(self_revocation(&kp, u64::MAX), None)
                .expect("legacy insert has no bound");
            loaded
                .verify_and_insert(self_revocation(&kp, now), None)
                .expect("current record");
            loaded
                .verify_and_insert(self_revocation(&other, u64::MAX), None)
                .expect("legacy far-future record");
            // #1857: the current record for `kp` took the place of its
            // far-future record (the earlier `revoked_at` is kept), so one
            // far-future record is left to drop.
            assert_eq!(loaded.len(), 2);
            assert_eq!(loaded.drop_future_records(now), 1);
            assert_eq!(loaded.len(), 1);
            assert!(
                loaded.is_agent_revoked(&kp.agent_id()),
                "the current record still revokes its subject"
            );
            assert!(
                !loaded.is_agent_revoked(&other.agent_id()),
                "a subject revoked only by a dropped record is no longer revoked"
            );
        }

        const DAY: u64 = 24 * 3600;

        /// WHY (#1108): a revocation says "this key is not to be trusted".
        /// The old sweep removed the record 90 days after `revoked_at`, so
        /// a stolen agent key came back to life on every node. Age must
        /// never remove the record, also across a restart.
        #[test]
        fn an_old_agent_revocation_stays_in_force_across_sweep_and_restart() {
            let kp = AgentKeypair::generate().expect("agent keypair");
            let mut set = RevocationSet::new();
            let now = 1_800_000_000u64;

            set.verify_and_insert(self_revocation(&kp, now - 91 * DAY), None)
                .expect("record verifies");
            assert_eq!(set.collect_dead_records(now), 0, "91 days old: kept");
            assert!(set.is_agent_revoked(&kp.agent_id()));

            // Restart: the store round trip, then the next sweep.
            let bytes = set.to_bytes().expect("encode");
            let mut loaded = RevocationSet::from_bytes(&bytes).expect("decode");
            assert_eq!(loaded.collect_dead_records(now + 100 * 365 * DAY), 0);
            assert!(
                loaded.is_agent_revoked(&kp.agent_id()),
                "the agent stays revoked 100 years later"
            );
            assert_eq!(loaded.all_records().len(), 1);
        }

        /// WHY (#1108): a machine key has no expiry, so its revocation has
        /// no end date.
        #[test]
        fn an_old_machine_revocation_stays_in_force() {
            let kp = MachineKeypair::generate().expect("machine keypair");
            let now = 1_800_000_000u64;
            let record = RevocationRecord::sign(
                RevokedSubject::Machine(kp.machine_id()),
                kp.public_key(),
                kp.secret_key(),
                now - 91 * DAY,
                None,
            )
            .expect("sign");
            let mut set = RevocationSet::new();
            set.verify_and_insert(record, None).expect("verifies");

            assert_eq!(set.collect_dead_records(now), 0);
            assert!(set.is_machine_revoked(&kp.machine_id()));
        }

        /// WHY (#1108): the certificate that proved the owner's authority
        /// can expire, but the record names the agent KEY. The owner can
        /// have issued a later certificate for the same key, and the key
        /// can announce with no certificate. So the expiry of the retained
        /// certificate must not remove the record, in memory or on reload.
        #[test]
        fn an_owner_revocation_stays_after_the_retained_certificate_expires() {
            let owner = UserKeypair::generate().expect("owner keypair");
            let agent = AgentKeypair::generate().expect("agent keypair");
            let now = 1_800_000_000u64;
            let cert_not_after = now - 30 * DAY;
            let cert = AgentCertificate::issue_with_expiry(&owner, &agent, Some(cert_not_after))
                .expect("certificate");
            let record = RevocationRecord::sign(
                RevokedSubject::Agent(agent.agent_id()),
                owner.public_key(),
                owner.secret_key(),
                now - 91 * DAY,
                Some("stolen".to_string()),
            )
            .expect("sign");
            let mut set = RevocationSet::new();
            set.verify_and_insert(record, Some(&cert))
                .expect("owner authority verifies");

            assert_eq!(set.collect_dead_records(now), 0);
            assert!(set.is_agent_revoked(&agent.agent_id()));

            let bytes = set.to_bytes().expect("encode");
            let mut loaded = RevocationSet::from_bytes(&bytes).expect("decode");
            assert_eq!(loaded.collect_dead_records(now), 0);
            assert!(
                loaded.is_agent_revoked(&agent.agent_id()),
                "an expired retained certificate must not un-revoke the agent on reload"
            );
        }

        /// #380 cadence: the change generation advances on insert and when
        /// a dead record is collected. A sweep that removes nothing must
        /// not advance it, or every heartbeat would publish the full set.
        #[test]
        fn generation_advances_on_insert_and_collection_only() {
            let kp = AgentKeypair::generate().expect("agent keypair");
            let owner = UserKeypair::generate().expect("owner keypair");
            let mut set = RevocationSet::new();
            let now = 1_800_000_000u64;
            let gen0 = set.generation();

            set.verify_and_insert(self_revocation(&kp, now - 91 * DAY), None)
                .expect("verifies");
            let grant = RevocationRecord::sign(
                RevokedSubject::ShareGrant(ShareGrantRevocation {
                    grant_id: [7; 32],
                    owner: owner.user_id(),
                    grant_expiry: now - 91 * DAY,
                }),
                owner.public_key(),
                owner.secret_key(),
                now - 92 * DAY,
                None,
            )
            .expect("sign");
            set.verify_and_insert(grant, None).expect("verifies");
            let gen1 = set.generation();
            assert!(gen1 > gen0, "insert must advance the generation");

            // The dead grant's record goes; the old agent record stays.
            assert_eq!(set.collect_dead_records(now), 1);
            let gen2 = set.generation();
            assert!(gen2 > gen1, "collection must advance the generation");
            assert!(set.is_agent_revoked(&kp.agent_id()));

            assert_eq!(set.collect_dead_records(now), 0);
            assert_eq!(set.generation(), gen2, "no-change must not advance");
        }
    }

    use super::*;
    use crate::identity::{AgentKeypair, MachineKeypair, UserKeypair};

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn revocation_self_signed_verifies() {
        // An agent revoking its own id is always authoritative: the issuer key
        // hashes to the subject. This is the "revoke a stolen key" path and
        // must never require external state.
        let agent = AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            agent.public_key(),
            agent.secret_key(),
            now(),
            Some("compromised".to_string()),
        )
        .unwrap();
        record
            .verify_authority(None)
            .expect("self-revocation must verify with no certificate");
    }

    #[test]
    fn revocation_machine_self_signed_verifies() {
        let machine = MachineKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Machine(machine.machine_id()),
            machine.public_key(),
            machine.secret_key(),
            now(),
            None,
        )
        .unwrap();
        record
            .verify_authority(None)
            .expect("machine self-revocation must verify");
    }

    #[test]
    fn revocation_user_signed_for_certified_agent_verifies() {
        // The user who certified an agent may revoke it. Authority is proven by
        // the agent's certificate binding agent->user and the issuer being that
        // user key.
        let user = UserKeypair::generate().unwrap();
        let agent = AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user, &agent).unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            user.public_key(),
            user.secret_key(),
            now(),
            None,
        )
        .unwrap();
        record
            .verify_authority(Some(&cert))
            .expect("issuer (certifying user) revocation must verify");
    }

    #[test]
    fn revocation_user_without_cert_rejected() {
        // Without the certificate proving the agent->user binding, a user key
        // has no authority over the agent — fail closed.
        let user = UserKeypair::generate().unwrap();
        let agent = AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            user.public_key(),
            user.secret_key(),
            now(),
            None,
        )
        .unwrap();
        assert!(
            record.verify_authority(None).is_err(),
            "issuer-revocation without the binding certificate must be rejected"
        );
    }

    #[test]
    fn revocation_unrelated_key_rejected() {
        // A third party (neither the subject nor its certifier) cannot revoke,
        // even with a validly-signed record. This is the core no-third-party
        // property.
        let user = UserKeypair::generate().unwrap();
        let agent = AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user, &agent).unwrap();
        let attacker = UserKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            attacker.public_key(),
            attacker.secret_key(),
            now(),
            None,
        )
        .unwrap();
        assert!(
            record.verify_authority(Some(&cert)).is_err(),
            "an unrelated key must not be able to revoke, even with the cert"
        );
    }

    #[test]
    fn revocation_forged_signature_rejected() {
        // Tampering the record after signing must fail the signature check
        // before authority is ever considered.
        let agent = AgentKeypair::generate().unwrap();
        let mut record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            agent.public_key(),
            agent.secret_key(),
            now(),
            None,
        )
        .unwrap();
        record.revoked_at = record.revoked_at.wrapping_add(1);
        assert!(
            record.verify_authority(None).is_err(),
            "a tampered record must fail the signature check"
        );
    }

    #[test]
    fn revocation_set_merge_grow_only_idempotent() {
        // Merging the same record twice is a no-op; the set only grows. This is
        // what makes gossip replay harmless.
        let agent = AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            agent.public_key(),
            agent.secret_key(),
            now(),
            None,
        )
        .unwrap();
        let mut set = RevocationSet::new();
        assert!(
            set.verify_and_insert(record.clone(), None).unwrap(),
            "first insert is new"
        );
        assert!(
            !set.verify_and_insert(record.clone(), None).unwrap(),
            "re-inserting the same record must be idempotent"
        );
        assert_eq!(set.len(), 1);
        assert!(set.is_agent_revoked(&agent.agent_id()));
        assert!(!set.is_machine_revoked(&MachineKeypair::generate().unwrap().machine_id()));
    }

    #[test]
    fn revocation_set_persists_and_reloads() {
        // The on-disk round-trip preserves the gate state — a daemon restart
        // must not forget revocations it learned. Includes an issuer-revocation
        // (cert persisted alongside) so the reload re-verifies it via that cert.
        let agent = AgentKeypair::generate().unwrap();
        let machine = MachineKeypair::generate().unwrap();
        let user = UserKeypair::generate().unwrap();
        let issued_agent = AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user, &issued_agent).unwrap();
        let mut set = RevocationSet::new();
        // self-revocation (agent)
        set.verify_and_insert(
            RevocationRecord::sign(
                RevokedSubject::Agent(agent.agent_id()),
                agent.public_key(),
                agent.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            None,
        )
        .unwrap();
        // self-revocation (machine)
        set.verify_and_insert(
            RevocationRecord::sign(
                RevokedSubject::Machine(machine.machine_id()),
                machine.public_key(),
                machine.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            None,
        )
        .unwrap();
        // issuer-revocation (user revokes a certified agent)
        set.verify_and_insert(
            RevocationRecord::sign(
                RevokedSubject::Agent(issued_agent.agent_id()),
                user.public_key(),
                user.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            Some(&cert),
        )
        .unwrap();
        let bytes = set.to_bytes().unwrap();
        let reloaded = RevocationSet::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded.len(), 3, "all three records must survive reload");
        assert!(reloaded.is_agent_revoked(&agent.agent_id()));
        assert!(reloaded.is_machine_revoked(&machine.machine_id()));
        assert!(
            reloaded.is_agent_revoked(&issued_agent.agent_id()),
            "issuer-revocation must re-verify on load via its persisted cert"
        );
    }

    #[test]
    fn revocation_set_from_bytes_rejects_forged_and_unrelated_records() {
        // SECURITY: revocations.bin is untrusted input. A record whose signature
        // is forged (tampered after signing) and an issuer-revocation whose
        // persisted cert does not authorize it must both be DROPPED on load,
        // while a legitimately-signed self-revocation and a properly-certified
        // issuer-revocation must survive. This pins load-path authority
        // enforcement — without it a tampered file would inject revocations.
        let good_agent = AgentKeypair::generate().unwrap();
        let user = UserKeypair::generate().unwrap();
        let issued_agent = AgentKeypair::generate().unwrap();
        let good_cert = AgentCertificate::issue(&user, &issued_agent).unwrap();

        // Legit self-revocation.
        let good_self = PersistedRevocation {
            record: RevocationRecord::sign(
                RevokedSubject::Agent(good_agent.agent_id()),
                good_agent.public_key(),
                good_agent.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            subject_cert: None,
        };

        // Legit issuer-revocation, cert persisted alongside.
        let good_issuer = PersistedRevocation {
            record: RevocationRecord::sign(
                RevokedSubject::Agent(issued_agent.agent_id()),
                user.public_key(),
                user.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            subject_cert: Some(good_cert.clone()),
        };

        // Forged: a validly-signed self-revocation tampered after signing.
        let forged_agent = AgentKeypair::generate().unwrap();
        let mut forged_record = RevocationRecord::sign(
            RevokedSubject::Agent(forged_agent.agent_id()),
            forged_agent.public_key(),
            forged_agent.secret_key(),
            now(),
            None,
        )
        .unwrap();
        forged_record.revoked_at = forged_record.revoked_at.wrapping_add(1);
        let forged = PersistedRevocation {
            record: forged_record,
            subject_cert: None,
        };

        // Unrelated issuer: a third party's key with a cert that does not bind
        // them to the subject.
        let attacker = UserKeypair::generate().unwrap();
        let victim_agent = AgentKeypair::generate().unwrap();
        let unrelated = PersistedRevocation {
            record: RevocationRecord::sign(
                RevokedSubject::Agent(victim_agent.agent_id()),
                attacker.public_key(),
                attacker.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            // Attach a real cert, but it certifies issued_agent (not the
            // victim) and is signed by `user` (not the attacker).
            subject_cert: Some(good_cert),
        };

        // Craft the on-disk bytes directly (bypassing verify_and_insert) to
        // simulate a tampered file.
        let entries = vec![good_self, good_issuer, forged, unrelated];
        let mut bytes = REVOCATIONS_FILE_MAGIC.to_vec();
        bytes.extend_from_slice(&bincode::serialize(&entries).unwrap());

        let loaded = RevocationSet::from_bytes(&bytes).unwrap();
        assert_eq!(
            loaded.len(),
            2,
            "only the two authoritative records may survive load"
        );
        assert!(
            loaded.is_agent_revoked(&good_agent.agent_id()),
            "legit self-revocation must survive"
        );
        assert!(
            loaded.is_agent_revoked(&issued_agent.agent_id()),
            "legit issuer-revocation (with cert) must survive"
        );
        assert!(
            !loaded.is_agent_revoked(&forged_agent.agent_id()),
            "forged record must be rejected on load"
        );
        assert!(
            !loaded.is_agent_revoked(&victim_agent.agent_id()),
            "unrelated-issuer record must be rejected on load"
        );
    }

    #[test]
    fn revocation_set_from_empty_is_empty() {
        assert!(RevocationSet::from_bytes(&[]).unwrap().is_empty());
    }
    /// ADR-0043 §7: binding-revocation authority matrix, carrier split,
    /// and permanence. The WHY: only the owner key may retire a pairing —
    /// not the moving agent, not either machine, not a third user — and a
    /// retired binding must never resurrect via TTL or a v1 round-trip.
    #[test]
    fn binding_revocation_authority_matrix_and_carriers() {
        use crate::identity::{AgentKeypair, UserKeypair};

        let owner = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let cert = crate::identity::AgentCertificate::issue(&owner, &agent_kp).unwrap();
        let machine = crate::identity::MachineId([7u8; 32]);
        let binding = AgentMachineBinding {
            agent: agent_kp.agent_id(),
            machine,
            move_epoch: 3,
        };

        // Owner-key issued with the cert: accepted.
        let record = RevocationRecord::sign(
            RevokedSubject::AgentMachineBinding(binding.clone()),
            owner.public_key(),
            owner.secret_key(),
            1_000,
            Some("stolen machine".into()),
        )
        .unwrap();
        assert!(record.verify_authority(Some(&cert)).is_ok());
        // Without the cert: fail-closed (issuer authority unverifiable).
        assert!(record.verify_authority(None).is_err());
        assert!(!record.is_self_revocation());
        assert_eq!(record.subject_kind(), "binding");

        // The moving agent's own key cannot issue it.
        let agent_issued = RevocationRecord::sign(
            RevokedSubject::AgentMachineBinding(binding.clone()),
            agent_kp.public_key(),
            agent_kp.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        assert!(agent_issued.verify_authority(Some(&cert)).is_err());

        // A third user cannot issue it.
        let stranger = UserKeypair::generate().unwrap();
        let stranger_issued = RevocationRecord::sign(
            RevokedSubject::AgentMachineBinding(binding.clone()),
            stranger.public_key(),
            stranger.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        assert!(stranger_issued.verify_authority(Some(&cert)).is_err());

        // Insert → check B → v1 wire excludes it, v2 round-trips it →
        // TTL sweep NEVER expires it.
        let mut set = RevocationSet::new();
        assert!(set.verify_and_insert(record.clone(), Some(&cert)).unwrap());
        assert!(set.is_binding_revoked(&binding.agent, &machine));
        assert_eq!(
            set.binding_tombstone_machines(&binding.agent),
            vec![machine],
            "an inserted binding tombstone must be indexed by agent"
        );
        assert_eq!(set.max_revoked_binding_epoch(&binding.agent), Some(3));
        assert!(
            set.all_records().is_empty(),
            "v1 wire must never carry the 0x03 variant (§7.4)"
        );
        assert_eq!(set.binding_records().len(), 1);

        let v2 = set.to_bytes_v2().unwrap();
        let loaded = RevocationSet::from_bytes_v2(&v2).unwrap();
        assert!(loaded.is_binding_revoked(&binding.agent, &machine));
        let mut merged = RevocationSet::new();
        merged.merge_v2(loaded);
        assert!(merged.is_binding_revoked(&binding.agent, &machine));
        assert!(
            merged
                .binding_tombstone_machines(&binding.agent)
                .contains(&machine),
            "merge_v2 must keep the per-agent tombstone index"
        );

        // Permanence: a sweep far past any TTL keeps the tombstone.
        let expired = set.collect_dead_records(10_000_000);
        assert_eq!(expired, 0);
        assert!(set.is_binding_revoked(&binding.agent, &machine));

        // Bundle-unioned tombstones (no standalone record) feed the same
        // check and never expire.
        let mut set2 = RevocationSet::new();
        assert!(set2.union_bundle_retired(&[
            binding.clone(),
            AgentMachineBinding {
                agent: binding.agent,
                machine: crate::identity::MachineId([8u8; 32]),
                move_epoch: 1,
            }
        ]));
        assert!(set2.is_binding_revoked(&binding.agent, &machine));
        assert_eq!(set2.max_revoked_binding_epoch(&binding.agent), Some(3));
        assert!(set2.binding_records().is_empty());
        assert!(set2.collect_dead_records(u64::MAX) == 0);
        assert!(set2.is_binding_revoked(&binding.agent, &machine));
        let mut indexed = set2.binding_tombstone_machines(&binding.agent);
        indexed.sort_by_key(|id| id.0);
        assert_eq!(
            indexed,
            vec![machine, crate::identity::MachineId([8u8; 32])],
            "bundle tombstones must be indexed by agent"
        );
        set2.reset_bundle_retired(&[AgentMachineBinding {
            agent: binding.agent,
            machine: crate::identity::MachineId([9u8; 32]),
            move_epoch: 4,
        }]);
        assert_eq!(
            set2.binding_tombstone_machines(&binding.agent),
            vec![crate::identity::MachineId([9u8; 32])],
            "resetting bundle tombstones must drop machines the index still named"
        );
    }

    /// Many tombstones stay a linear short-circuit. One revoked machine among
    /// hundreds is enough. Duplicate names across the two indexes count once.
    #[test]
    fn many_tombstones_short_circuit_when_one_machine_is_revoked() {
        let agent = AgentId([0x71; 32]);
        let machine_kp = MachineKeypair::generate().unwrap();
        let revoked = machine_kp.machine_id();
        let mut bindings = Vec::with_capacity(512);
        for i in 0..511u32 {
            let mut id = [0xABu8; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            bindings.push(AgentMachineBinding {
                agent,
                machine: MachineId(id),
                move_epoch: 1,
            });
        }
        bindings.push(AgentMachineBinding {
            agent,
            machine: revoked,
            move_epoch: 2,
        });
        let mut set = RevocationSet::new();
        assert!(set.union_bundle_retired(&bindings));
        let record = RevocationRecord::sign(
            RevokedSubject::Machine(revoked),
            machine_kp.public_key(),
            machine_kp.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        assert!(set.verify_and_insert(record, None).unwrap());
        // This machine is both a tombstone and a machine revocation.
        // The answer is revoked for this agent only.
        assert!(set.any_tombstone_machine_revoked(&agent));
        assert!(!set.any_tombstone_machine_revoked(&AgentId([0x72; 32])));
        assert_eq!(set.binding_tombstone_machines(&agent).len(), 512);
        let mut listed = set.binding_tombstone_machines(&agent);
        listed.sort_by_key(|id| id.0);
        listed.dedup();
        assert_eq!(
            listed.len(),
            512,
            "the two indexes must not duplicate a machine"
        );
    }

    /// HS-A review fixture gap (seam check 2026-08-30, concern 2 / MINOR-4):
    /// the X0R2 carrier is isolated on its own topic and file today, but
    /// nothing pinned the bincode shape of `PersistedRevocation` carrying a
    /// `RevokedSubject::AgentMachineBinding` (variant 2 of the file era,
    /// enum tag 0x03). A future field INSERTED into `PersistedRevocation`,
    /// `RevocationRecord`, or before the existing `RevokedSubject` variants
    /// would silently break every older v2 decoder. Pin the exact bytes.
    #[test]
    fn revocations_v2_file_bytes_match_frozen_vector() {
        let record = RevocationRecord {
            subject: RevokedSubject::AgentMachineBinding(AgentMachineBinding {
                agent: AgentId([0xA1; 32]),
                machine: MachineId([0xA2; 32]),
                move_epoch: 7,
            }),
            issuer_public_key: vec![0xB1; 4],
            revoked_at: 1_700_000_321,
            reason: Some("key-move".to_string()),
            signature: vec![0xC1; 4],
        };
        let mut set = RevocationSet::new();
        assert!(set.insert_verified(PersistedRevocation {
            record,
            subject_cert: None,
        }));

        let bytes = set.to_bytes_v2().expect("encode v2 file");
        println!(
            "X0R2_FROZEN_HEX={}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        const FROZEN_X0R2_HEX: &str = "58305232010000000000000002000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a207000000000000000400000000000000b1b1b1b141f25365000000000108000000000000006b65792d6d6f76650400000000000000c1c1c1c100";
        let frozen = hex::decode(FROZEN_X0R2_HEX).expect("frozen hex");
        assert_eq!(
            bytes, frozen,
            "X0R2 file bytes must stay byte-identical (append-only fields/variants)"
        );
        // The pinned vector itself decodes as a v2 set (the record fails
        // authority re-verification by construction — fake keys — so the
        // decoded set is empty; the shape pin above is the contract).
        let decoded = RevocationSet::from_bytes_v2(&frozen).expect("decode v2 file");
        assert!(decoded.is_empty());
    }

    /// ADR-0070 slice 3: share-grant revocations and the old-decoder
    /// guarantees of the v1/v2 carriers.
    /// #1857: the set is not swept by age (#1108), so its size and its
    /// gossip must stay inside limits by other rules.
    mod batches_and_pairs {
        use super::super::*;
        use crate::identity::{AgentKeypair, UserKeypair};

        fn self_revocation(kp: &AgentKeypair, revoked_at: u64, reason: &str) -> RevocationRecord {
            RevocationRecord::sign(
                RevokedSubject::Agent(kp.agent_id()),
                kp.public_key(),
                kp.secret_key(),
                revoked_at,
                Some(reason.to_string()),
            )
            .expect("sign")
        }

        /// A record with the byte sizes of a real one and no valid
        /// signature (for codec tests, which do not verify).
        fn sized_fake(tag: u32) -> RevocationRecord {
            sized_fake_with_reason(tag, "r".to_string())
        }

        fn sized_fake_with_reason(tag: u32, reason: String) -> RevocationRecord {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&tag.to_le_bytes());
            RevocationRecord {
                subject: RevokedSubject::Agent(AgentId(id)),
                issuer_public_key: vec![7; 1952],
                revoked_at: 1_800_000_000,
                reason: Some(reason),
                signature: vec![9; 3309],
            }
        }

        /// Every batch is at most the target plus one record, and under
        /// the size a receiver accepts.
        fn assert_batches_fit(batches: &[Vec<u8>]) {
            for batch in batches {
                // The encoder closes a batch before its estimate passes
                // the target; the header and one round marker (under 300
                // bytes) are the only extra.
                assert!(batch.len() <= REVOCATION_BATCH_TARGET_BYTES + 512);
                assert!(batch.len() < MAX_REVOCATION_PAYLOAD_BYTES);
            }
        }

        /// A signed record with a reason over the limit, as a released
        /// daemon could have made it (`sign` refuses it now).
        fn long_reason_record(kp: &AgentKeypair, revoked_at: u64) -> RevocationRecord {
            let subject = RevokedSubject::Agent(kp.agent_id());
            let issuer = kp.public_key().as_bytes().to_vec();
            let reason = Some("x".repeat(MAX_REVOCATION_REASON_BYTES + 1));
            let message =
                RevocationRecord::canonical_message(&subject, &issuer, revoked_at, &reason);
            let signature = sign_with_ml_dsa(kp.secret_key(), &message).expect("sign");
            RevocationRecord {
                subject,
                issuer_public_key: issuer,
                revoked_at,
                reason,
                signature: signature.as_bytes().to_vec(),
            }
        }

        /// WHY: one key can sign any number of records for one subject
        /// (a new time or a new reason each). With no age sweep, each one
        /// stayed for good and was sent again every two hours. The set
        /// must hold one record for each subject and issuer.
        #[test]
        fn more_records_for_one_subject_and_issuer_do_not_grow_the_set() {
            let kp = AgentKeypair::generate().expect("keypair");
            let mut set = RevocationSet::new();
            let first = self_revocation(&kp, 1_000, "first");
            assert!(set
                .verify_and_insert(first.clone(), None)
                .expect("verifies"));

            for n in 0..20u64 {
                let later = self_revocation(&kp, 1_001 + n, &format!("again {n}"));
                assert!(
                    !set.verify_and_insert(later.clone(), None)
                        .expect("verifies"),
                    "a later record for the same pair adds nothing"
                );
                assert!(set.covers(&later), "and the set covers it");
                assert!(!set.contains_hash(&later.record_hash()));
            }
            assert_eq!(set.len(), 1);
            assert_eq!(set.all_records(), vec![first]);
            assert!(set.is_agent_revoked(&kp.agent_id()));

            // The file a restart reads holds one record too.
            let loaded =
                RevocationSet::from_bytes(&set.to_bytes().expect("encode")).expect("decode");
            assert_eq!(loaded.len(), 1);
        }

        /// WHY: every node must keep the SAME record, or two nodes never
        /// agree on the set (the #1116 resync compares record hashes). The
        /// rule is the earlier `revoked_at`, then the lower hash. A
        /// replacement must never leave the subject not revoked.
        #[test]
        fn every_arrival_order_keeps_the_same_record_and_the_subject_stays_revoked() {
            let kp = AgentKeypair::generate().expect("keypair");
            let early = self_revocation(&kp, 1_000, "early");
            let late = self_revocation(&kp, 2_000, "late");
            let same_time = self_revocation(&kp, 1_000, "same time, other reason");
            let winner_of_tie = if early.record_hash() < same_time.record_hash() {
                early.clone()
            } else {
                same_time.clone()
            };

            let mut stores = Vec::new();
            for order in [
                [&early, &late, &same_time],
                [&early, &same_time, &late],
                [&late, &early, &same_time],
                [&late, &same_time, &early],
                [&same_time, &early, &late],
                [&same_time, &late, &early],
            ] {
                let mut set = RevocationSet::new();
                for record in order {
                    set.verify_and_insert(record.clone(), None)
                        .expect("verifies");
                    assert!(
                        set.is_agent_revoked(&kp.agent_id()),
                        "the subject is revoked after every step"
                    );
                }
                assert_eq!(set.all_records(), vec![winner_of_tie.clone()]);
                // A restart reads the same record back.
                let bytes = set.to_bytes().expect("encode");
                let loaded = RevocationSet::from_bytes(&bytes).expect("decode");
                assert_eq!(loaded.all_records(), vec![winner_of_tie.clone()]);
                assert!(loaded.is_agent_revoked(&kp.agent_id()));
                stores.push(bytes);
            }
            assert!(
                stores.windows(2).all(|pair| pair[0] == pair[1]),
                "every arrival order writes the same store bytes"
            );
        }

        /// WHY: the move epoch is part of a binding subject. Tombstones for
        /// two epochs are two subjects, and both must stay: the highest
        /// epoch orders placement records. Two records for ONE epoch are
        /// one pair.
        #[test]
        fn binding_tombstones_with_different_epochs_are_separate_pairs() {
            let owner = UserKeypair::generate().expect("owner");
            let agent = AgentKeypair::generate().expect("agent");
            let cert = AgentCertificate::issue(&owner, &agent).expect("cert");
            let machine = MachineId([0x4D; 32]);
            let tombstone = |epoch: u64, revoked_at: u64| {
                RevocationRecord::sign(
                    RevokedSubject::AgentMachineBinding(AgentMachineBinding {
                        agent: agent.agent_id(),
                        machine,
                        move_epoch: epoch,
                    }),
                    owner.public_key(),
                    owner.secret_key(),
                    revoked_at,
                    None,
                )
                .expect("sign")
            };
            let mut set = RevocationSet::new();
            assert!(set
                .verify_and_insert(tombstone(1, 1_000), Some(&cert))
                .expect("ok"));
            assert!(set
                .verify_and_insert(tombstone(3, 1_000), Some(&cert))
                .expect("ok"));
            assert!(
                !set.verify_and_insert(tombstone(3, 2_000), Some(&cert))
                    .expect("ok"),
                "a second record for epoch 3 is the same pair"
            );
            assert_eq!(set.binding_records().len(), 2);
            assert_eq!(set.max_revoked_binding_epoch(&agent.agent_id()), Some(3));
            assert!(set.is_binding_revoked(&agent.agent_id(), &machine));
        }

        /// WHY: the store merges (`merge_v2`, `merge_v3`) also put records
        /// in the set. They must follow the pair rule for bindings, and
        /// must keep every share-grant record (those are exempt).
        #[test]
        fn store_merges_follow_the_pair_rule() {
            let owner = UserKeypair::generate().expect("owner");
            let agent = AgentKeypair::generate().expect("agent");
            let cert = AgentCertificate::issue(&owner, &agent).expect("cert");
            let machine = MachineId([0x4D; 32]);
            let tombstone = |revoked_at: u64| {
                RevocationRecord::sign(
                    RevokedSubject::AgentMachineBinding(AgentMachineBinding {
                        agent: agent.agent_id(),
                        machine,
                        move_epoch: 2,
                    }),
                    owner.public_key(),
                    owner.secret_key(),
                    revoked_at,
                    None,
                )
                .expect("sign")
            };
            let early = tombstone(1_000);
            let mut live = RevocationSet::new();
            live.verify_and_insert(tombstone(2_000), Some(&cert))
                .expect("ok");
            let mut disk = RevocationSet::new();
            disk.verify_and_insert(early.clone(), Some(&cert))
                .expect("ok");
            live.merge_v2(disk);
            assert_eq!(live.binding_records(), vec![early]);
            assert!(live.is_binding_revoked(&agent.agent_id(), &machine));

            let grant = |revoked_at: u64| {
                RevocationRecord::sign(
                    RevokedSubject::ShareGrant(ShareGrantRevocation {
                        grant_id: [0x61; 32],
                        owner: owner.user_id(),
                        grant_expiry: 5_000,
                    }),
                    owner.public_key(),
                    owner.secret_key(),
                    revoked_at,
                    None,
                )
                .expect("sign")
            };
            let mut live = RevocationSet::new();
            live.verify_and_insert(grant(1_000), None).expect("ok");
            let mut disk = RevocationSet::new();
            disk.verify_and_insert(grant(2_000), None).expect("ok");
            live.merge_v3(disk);
            assert_eq!(
                live.share_grant_records().len(),
                2,
                "share-grant records are exempt from the pair rule"
            );
        }

        /// WHY: a store from an earlier build can hold a record with a
        /// long reason. Peers refuse that record from gossip, so a node
        /// that kept sending it would not spread the revocation. A record
        /// for the same pair with a reason inside the limit is preferred,
        /// whatever its time. The subject stays revoked through the change.
        #[test]
        fn a_record_inside_the_limit_takes_the_place_of_a_stored_long_one() {
            let kp = AgentKeypair::generate().expect("keypair");
            let long = long_reason_record(&kp, 1_000);
            let short = self_revocation(&kp, 2_000, "short");

            let mut set = RevocationSet::new();
            assert!(set.verify_and_insert(long.clone(), None).expect("stored"));
            assert!(set
                .verify_and_insert_at(short.clone(), None, 3_000)
                .expect("accepted"));
            assert!(set.is_agent_revoked(&kp.agent_id()));
            assert_eq!(set.all_records(), vec![short.clone()]);
            let batches = encode_revocation_batches(&set.all_records()).expect("encode");
            assert_eq!(
                decode_revocation_batch(&batches[0]).expect("decode"),
                vec![short.clone()]
            );

            // The other order: the long record adds nothing.
            let mut set = RevocationSet::new();
            assert!(set.verify_and_insert(short.clone(), None).expect("ok"));
            assert!(!set.verify_and_insert(long, None).expect("verifies"));
            assert_eq!(set.all_records(), vec![short]);
        }

        /// WHY (review MAJOR): a store from a released daemon can hold two
        /// records for one subject and issuer: a credible one with a long
        /// reason, and one far in the future with a short reason. The load
        /// keeps one record per pair, and then drops far-future records.
        /// If the far-future record won the pair, the subject would have
        /// no record left and would not be revoked. It was revoked before
        /// this change, so it must stay revoked: a far-future record never
        /// wins a pair.
        #[test]
        fn a_far_future_record_never_takes_the_place_of_a_credible_one() {
            let kp = AgentKeypair::generate().expect("keypair");
            let credible_long = long_reason_record(&kp, 1_000);
            let future_short = self_revocation(&kp, u64::MAX, "short");
            let entry = |record: &RevocationRecord| PersistedRevocation {
                record: record.clone(),
                subject_cert: None,
            };

            // The store file, in both record orders.
            for order in [
                [&credible_long, &future_short],
                [&future_short, &credible_long],
            ] {
                let persisted: Vec<PersistedRevocation> = order.iter().map(|r| entry(r)).collect();
                let mut bytes = REVOCATIONS_FILE_MAGIC.to_vec();
                bytes.extend_from_slice(&bincode::serialize(&persisted).expect("encode"));
                let mut loaded = RevocationSet::from_bytes(&bytes).expect("decode");
                assert_eq!(loaded.all_records(), vec![credible_long.clone()]);
                loaded.drop_future_records(2_000);
                assert!(
                    loaded.is_agent_revoked(&kp.agent_id()),
                    "the subject stays revoked after the far-future sweep"
                );
            }

            // The store merges run the pair rule too.
            for merge_v3 in [false, true] {
                let mut live = RevocationSet::new();
                live.verify_and_insert(future_short.clone(), None)
                    .expect("ok");
                let mut disk = RevocationSet::new();
                disk.verify_and_insert(credible_long.clone(), None)
                    .expect("ok");
                if merge_v3 {
                    live.merge_v3(disk);
                } else {
                    live.merge_v2(disk);
                }
                live.drop_future_records(2_000);
                assert!(
                    live.is_agent_revoked(&kp.agent_id()),
                    "merge_v3: {merge_v3}"
                );
                assert_eq!(live.all_records(), vec![credible_long.clone()]);
            }

            // A live arrival: the far-future record adds nothing.
            let mut set = RevocationSet::new();
            set.verify_and_insert(credible_long.clone(), None)
                .expect("ok");
            assert!(!set.verify_and_insert(future_short, None).expect("verifies"));
            assert_eq!(set.all_records(), vec![credible_long]);
        }

        /// WHY: a set of one batch must have the bytes it had before
        /// #1857, so that a released daemon reads it as before. These are
        /// fixed bytes: plain bincode of the record list, no marker.
        #[test]
        fn a_one_batch_set_has_the_bytes_of_before() {
            let record = RevocationRecord {
                subject: RevokedSubject::Agent(AgentId([1; 32])),
                issuer_public_key: vec![7; 4],
                revoked_at: 1,
                reason: None,
                signature: vec![9; 4],
            };
            let golden = concat!(
                "0100000000000000", // one record
                "00000000",         // RevokedSubject::Agent
                "0101010101010101010101010101010101010101010101010101010101010101",
                "0400000000000000",
                "07070707",         // issuer_public_key
                "0100000000000000", // revoked_at
                "00",               // reason: None
                "0400000000000000",
                "09090909", // signature
            );
            let batches = encode_revocation_batches(std::slice::from_ref(&record)).expect("encode");
            assert_eq!(batches.len(), 1);
            assert_eq!(hex::encode(&batches[0]), golden);
            assert_eq!(
                decode_revocation_batch(&batches[0]).expect("decode"),
                vec![record]
            );
        }

        /// WHY: a record that no receiver accepts (it is over the receive
        /// limit by itself) cannot be sent. Its hash stays in the round's
        /// digest and every batch keeps a marker, so the batches never
        /// look like the sender's whole set.
        #[test]
        fn a_record_over_the_receive_limit_is_not_sent_but_stays_in_the_digest() {
            let mut records: Vec<RevocationRecord> = (0..800).map(sized_fake).collect();
            let giant = sized_fake_with_reason(9_999, "x".repeat(MAX_REVOCATION_PAYLOAD_BYTES));
            records.push(giant.clone());
            let batches = encode_revocation_batches(&records).expect("encode");
            assert!(batches.len() > 1);
            let mut sent = Vec::new();
            let mut sets = HashSet::new();
            for batch in &batches {
                assert!(batch.len() < MAX_REVOCATION_PAYLOAD_BYTES);
                let (part, round) = decode_revocation_batch_with_round(batch).expect("decode");
                let BatchRound::Part(marker) = round else {
                    panic!("every batch of the round has a marker");
                };
                sets.insert(marker.set);
                sent.extend(part.iter().map(RevocationRecord::record_hash));
            }
            assert!(!sent.contains(&giant.record_hash()));
            assert_eq!(sent.len(), 800);
            sent.sort_unstable();
            let mut all = sent.clone();
            all.push(giant.record_hash());
            all.sort_unstable();
            assert_eq!(sets, HashSet::from([round_set_digest(&all)]));
            assert_ne!(sets, HashSet::from([round_set_digest(&sent)]));

            // When the rest fits one batch, that batch still has a marker.
            let few = vec![sized_fake(1), sized_fake(2), giant];
            let batches = encode_revocation_batches(&few).expect("encode");
            assert_eq!(batches.len(), 1);
            let (part, round) = decode_revocation_batch_with_round(&batches[0]).expect("decode");
            assert_eq!(part.len(), 2);
            assert!(matches!(round, BatchRound::Part(marker) if marker.batches == 1));
        }

        /// WHY: a trusted resync snapshot can hold a legacy record with a
        /// long reason. If the waiting node dropped it and then opened the
        /// carrier, the subject would not be revoked there. The record is
        /// admitted when a trusted authority offered it, and only then.
        #[test]
        fn a_long_reason_record_in_a_trusted_resync_is_admitted_and_revokes() {
            let kp = AgentKeypair::generate().expect("keypair");
            let long = long_reason_record(&kp, 1_000);

            let mut open_gossip = RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1);
            open_gossip.observe_remote_carrier_snapshot(
                REVOCATION_CARRIER_V1,
                &AgentId([0xB2; 32]),
                std::slice::from_ref(&long),
                false,
            );
            assert!(
                open_gossip
                    .verify_and_insert_at(long.clone(), None, 3_000)
                    .is_err(),
                "a sender that is not a trusted authority does not lift the limit"
            );

            let mut held = RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1);
            held.observe_remote_carrier_snapshot(
                REVOCATION_CARRIER_V1,
                &AgentId([0xA1; 32]),
                std::slice::from_ref(&long),
                true,
            );
            assert!(held.carrier_resync_pending(REVOCATION_CARRIER_V1));
            assert!(held
                .verify_and_insert_at(long.clone(), None, 3_000)
                .expect("admitted from the trusted snapshot"));
            assert!(held.is_agent_revoked(&kp.agent_id()));
            assert!(!held.carrier_resync_pending(REVOCATION_CARRIER_V1));

            // The authenticated group resync path admits it too.
            let mut group = RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1);
            group.apply_group_revocation_resync(vec![long], 3_000);
            assert!(group.is_agent_revoked(&kp.agent_id()));
        }

        /// WHY: another issuer is another pair. An owner's record for an
        /// agent and the agent's own record are both kept: each one has
        /// its own authority.
        #[test]
        fn two_issuers_for_one_subject_are_both_kept() {
            let owner = UserKeypair::generate().expect("owner");
            let agent = AgentKeypair::generate().expect("agent");
            let cert = AgentCertificate::issue(&owner, &agent).expect("cert");
            let by_owner = RevocationRecord::sign(
                RevokedSubject::Agent(agent.agent_id()),
                owner.public_key(),
                owner.secret_key(),
                1_000,
                None,
            )
            .expect("sign");
            let mut set = RevocationSet::new();
            assert!(set
                .verify_and_insert(by_owner, Some(&cert))
                .expect("verifies"));
            assert!(set
                .verify_and_insert(self_revocation(&agent, 2_000, "self"), None)
                .expect("verifies"));
            assert_eq!(set.len(), 2);
        }

        /// WHY: a receiver ignores a whole batch above 2 MiB, about 380
        /// records. One batch for a larger set meant that NO revocation
        /// from that daemon reached any peer. Several batches, each one
        /// well under the limit, carry every record.
        #[test]
        fn a_large_set_is_sent_as_batches_under_the_receive_limit() {
            let records: Vec<RevocationRecord> = (0..1_000).map(sized_fake).collect();
            assert!(
                encode_revocation_batch(&records).expect("encode").len()
                    > MAX_REVOCATION_PAYLOAD_BYTES,
                "one batch of this set is over the limit a receiver accepts"
            );

            let batches = encode_revocation_batches(&records).expect("encode");
            assert!(batches.len() > 1);
            let mut seen = HashSet::new();
            assert_batches_fit(&batches);
            // A set that fitted in one batch before is still one batch,
            // with the bytes of before: plain bincode, no marker.
            let mut one: Vec<RevocationRecord> = records[..370].to_vec();
            one.sort_by_key(RevocationRecord::record_hash);
            assert_eq!(
                encode_revocation_batches(&records[..370]).expect("encode"),
                vec![bincode::serialize(&one).expect("encode")]
            );
            // Every batch of a round ends with exactly one marker, and the
            // markers name one round.
            let mut rounds = HashSet::new();
            for (index, batch) in batches.iter().enumerate() {
                let raw = decode_revocation_batch_raw(batch).expect("decode");
                assert_eq!(raw.iter().filter(|r| is_round_marker(r)).count(), 1);
                assert!(raw.last().is_some_and(is_round_marker));
                let (_, round) = decode_revocation_batch_with_round(batch).expect("decode");
                let BatchRound::Part(marker) = round else {
                    panic!("batch {index} has no valid marker");
                };
                assert_eq!(marker.index as usize, index);
                assert_eq!(marker.batches as usize, batches.len());
                rounds.insert(marker.set);
            }
            assert_eq!(rounds.len(), 1);
            for batch in &batches {
                for record in decode_revocation_batch(batch).expect("a released decoder reads it") {
                    seen.insert(record.record_hash());
                }
            }
            assert_eq!(seen.len(), 1_000, "every record is in some batch");

            // The same set gives the same batches in any input order.
            let mut reversed = records.clone();
            reversed.reverse();
            assert_eq!(
                encode_revocation_batches(&reversed).expect("encode"),
                batches
            );
            // A small set is still one batch, with the bytes of today.
            assert_eq!(
                encode_revocation_batches(&records[..2])
                    .expect("encode")
                    .len(),
                1
            );
            assert!(encode_revocation_batches(&[]).expect("encode").is_empty());

            // The longest reason a record may carry, on every record.
            let long: Vec<RevocationRecord> = (0..1_000)
                .map(|tag| sized_fake_with_reason(tag, "x".repeat(MAX_REVOCATION_REASON_BYTES)))
                .collect();
            let long_batches = encode_revocation_batches(&long).expect("encode");
            assert_batches_fit(&long_batches);
            let carried: usize = long_batches
                .iter()
                .map(|batch| decode_revocation_batch(batch).expect("decode").len())
                .sum();
            assert_eq!(carried, 1_000);
        }

        /// WHY: a store written before this change can hold more records
        /// than one batch carries. After a restart the daemon must still
        /// hold every subject as revoked and must send them all.
        #[test]
        fn an_over_limit_store_still_loads_and_goes_out_in_batches() {
            let keys: Vec<AgentKeypair> = (0..420)
                .map(|_| AgentKeypair::generate().expect("keypair"))
                .collect();
            let mut set = RevocationSet::new();
            for kp in &keys {
                set.verify_and_insert(self_revocation(kp, 1_000, "r"), None)
                    .expect("verifies");
            }
            let bytes = set.to_bytes().expect("encode");
            assert!(bytes.len() > MAX_REVOCATION_PAYLOAD_BYTES, "over one batch");

            let loaded = RevocationSet::from_bytes(&bytes).expect("decode");
            assert!(keys
                .iter()
                .all(|kp| loaded.is_agent_revoked(&kp.agent_id())));
            let batches = encode_revocation_batches(&loaded.all_records()).expect("encode");
            assert!(batches.len() > 1);
            let mut sent = 0;
            assert_batches_fit(&batches);
            for batch in &batches {
                sent += decode_revocation_batch(batch).expect("decode").len();
            }
            assert_eq!(sent, 420);
        }

        /// WHY: the reason is inside the signed bytes and had no limit, so
        /// one signature could put megabytes in every node's store. A new
        /// record with a long reason is refused where it is signed and
        /// where it arrives. A record that is already in a store is kept:
        /// refusing it at load would un-revoke its subject.
        #[test]
        fn a_long_reason_is_refused_for_new_records_and_kept_for_stored_ones() {
            let kp = AgentKeypair::generate().expect("keypair");
            let at_limit = "x".repeat(MAX_REVOCATION_REASON_BYTES);
            let over = "x".repeat(MAX_REVOCATION_REASON_BYTES + 1);
            assert!(RevocationRecord::sign(
                RevokedSubject::Agent(kp.agent_id()),
                kp.public_key(),
                kp.secret_key(),
                1_000,
                Some(over),
            )
            .is_err());

            // A record as a released daemon could have signed it.
            let long = long_reason_record(&kp, 1_000);

            let mut fresh = RevocationSet::new();
            assert!(
                fresh
                    .verify_and_insert_at(long.clone(), None, 1_000)
                    .is_err(),
                "refused when it arrives from a peer"
            );
            assert!(!fresh.is_agent_revoked(&kp.agent_id()));
            let other = AgentKeypair::generate().expect("keypair");
            assert!(fresh
                .verify_and_insert_at(self_revocation(&other, 1_000, &at_limit), None, 1_000)
                .expect("a reason at the limit is accepted"));

            // Already stored (the load path has no bound): kept.
            let mut stored = RevocationSet::new();
            assert!(stored.verify_and_insert(long, None).expect("verifies"));
            let loaded =
                RevocationSet::from_bytes(&stored.to_bytes().expect("encode")).expect("decode");
            assert!(loaded.is_agent_revoked(&kp.agent_id()));
        }

        /// WHY (#1116): a node that waits for a resync opens a carrier when
        /// a trusted snapshot matches its own records. A released daemon
        /// can hold two records for one pair; this node keeps one. The
        /// snapshot must be compared by the records this node would keep,
        /// or the carrier never opens against such a daemon.
        #[test]
        fn a_resync_snapshot_with_two_records_for_one_pair_still_opens_the_carrier() {
            let kp = AgentKeypair::generate().expect("keypair");
            let kept = self_revocation(&kp, 1_000, "kept");
            let extra = self_revocation(&kp, 2_000, "extra");
            let mut held = RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1);
            held.apply_group_revocation_resync(vec![kept.clone()], 3_000);
            assert!(
                held.carrier_resync_pending(REVOCATION_CARRIER_V1),
                "one insert is not a snapshot"
            );

            held.observe_remote_carrier_snapshot(
                REVOCATION_CARRIER_V1,
                &AgentId([0xA1; 32]),
                &[kept, extra],
                true,
            );
            assert!(
                !held.carrier_resync_pending(REVOCATION_CARRIER_V1),
                "the trusted snapshot is accepted"
            );
        }
    }

    /// #1857: a set above one batch goes out as a ROUND. A node that waits
    /// for a resync must never open on a part of a round, and a released
    /// daemon must not be worse off than before.
    mod round_marker {
        use super::super::*;
        use crate::identity::AgentKeypair;

        const SENDER: AgentId = AgentId([0xA1; 32]);
        /// Two real records fit in one batch of this size.
        const SMALL_TARGET: usize = 12 * 1024;

        fn records(count: usize) -> Vec<RevocationRecord> {
            (0..count)
                .map(|_| {
                    let kp = AgentKeypair::generate().expect("keypair");
                    RevocationRecord::sign(
                        RevokedSubject::Agent(kp.agent_id()),
                        kp.public_key(),
                        kp.secret_key(),
                        1_000,
                        None,
                    )
                    .expect("sign")
                })
                .collect()
        }

        /// The batches of one round for `set`, as the sender publishes them.
        fn round(set: &[RevocationRecord]) -> Vec<Vec<u8>> {
            let batches = encode_revocation_batches_with_target(set, SMALL_TARGET).expect("encode");
            assert!(batches.len() >= 3, "the test needs a round of 3 or more");
            batches
        }

        /// What a new waiting node does with one gossip batch: record the
        /// sender's offer, then ingest the records.
        fn receive(waiter: &mut RevocationSet, batch: &[u8], trusted: bool) {
            let (records, round) = decode_revocation_batch_with_round(batch).expect("decode");
            waiter.observe_remote_carrier_batch(
                REVOCATION_CARRIER_V1,
                &SENDER,
                &records,
                round,
                trusted,
            );
            for record in records {
                let _ = waiter.verify_and_insert_at(record, None, 2_000);
            }
        }

        fn waiting() -> RevocationSet {
            RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1)
        }

        fn pending(waiter: &RevocationSet) -> bool {
            waiter.carrier_resync_pending(REVOCATION_CARRIER_V1)
        }

        /// WHY (review blocker): the waiter starts with nothing and ingests
        /// each batch as it arrives. After batch 1 its held records equal
        /// batch 1. It must NOT open then: the other batches are not held.
        /// It opens only when the whole round is in.
        #[test]
        fn a_waiter_with_nothing_opens_only_on_the_complete_round() {
            let set = records(6);
            let batches = round(&set);
            let mut waiter = waiting();
            for (index, batch) in batches.iter().enumerate() {
                assert!(pending(&waiter), "closed before batch {index}");
                receive(&mut waiter, batch, true);
            }
            assert!(!pending(&waiter), "the complete round opens the carrier");
            assert_eq!(waiter.len(), 6, "no marker was stored");
        }

        /// WHY: a lost batch means the waiter holds a partial set. It must
        /// stay closed, whichever batch is lost.
        #[test]
        fn a_round_with_a_lost_batch_stays_closed() {
            let set = records(6);
            let batches = round(&set);
            for lost in [0, 1, batches.len() - 1] {
                let mut waiter = waiting();
                for (index, batch) in batches.iter().enumerate() {
                    if index != lost {
                        receive(&mut waiter, batch, true);
                    }
                }
                assert!(pending(&waiter), "closed with batch {lost} lost");
                // The lost batch arrives later (the next publish): open.
                receive(&mut waiter, &batches[lost], true);
                assert!(!pending(&waiter));
            }
        }

        /// WHY: the sender's set can change in the middle of a round. Parts
        /// of two rounds must never be read as one snapshot.
        #[test]
        fn parts_of_two_rounds_are_not_mixed() {
            let first = records(6);
            let mut second = first.clone();
            second.extend(records(1));
            let round_a = round(&first);
            let round_b = round(&second);

            let mut waiter = waiting();
            receive(&mut waiter, &round_a[0], true);
            for batch in &round_b[1..] {
                receive(&mut waiter, batch, true);
            }
            assert!(pending(&waiter), "round B has no batch 0 yet");
            for batch in &round_a[1..] {
                receive(&mut waiter, batch, true);
            }
            assert!(
                pending(&waiter),
                "round A parts restart round A; B is dropped"
            );
            for batch in &round_b {
                receive(&mut waiter, batch, true);
            }
            assert!(!pending(&waiter), "the complete round B opens");
            assert_eq!(waiter.len(), 7);
        }

        /// WHY: a sender offers its whole set as one batch, and later its
        /// set grows into a round. The old one-batch snapshot is stale. If
        /// the waiter kept it, it could open on that old set while it
        /// holds only part of the sender's set of now.
        #[test]
        fn an_earlier_whole_snapshot_does_not_open_after_a_round_starts() {
            let old = records(2);
            let mut grown = old.clone();
            grown.extend(records(4));
            let mut waiter = waiting();
            // The old snapshot is offered while the waiter holds nothing
            // of it yet.
            waiter.observe_remote_carrier_snapshot(REVOCATION_CARRIER_V1, &SENDER, &old, true);
            // A part of the new round arrives (not ingested: lost records).
            let batches = round(&grown);
            let (part, marker) = decode_revocation_batch_with_round(&batches[0]).expect("decode");
            waiter.observe_remote_carrier_batch(
                REVOCATION_CARRIER_V1,
                &SENDER,
                &part,
                marker,
                true,
            );
            // The waiter now comes to hold exactly the OLD set.
            for record in old {
                let _ = waiter.verify_and_insert_at(record, None, 2_000);
            }
            assert!(
                pending(&waiter),
                "the stale one-batch snapshot must not open the carrier"
            );
        }

        /// WHY: the same rule for a newer UNMARKED batch. The sender's
        /// newest batch is its set of now, also when this node refuses
        /// that batch. An older whole set from the same sender must not
        /// open the carrier after it.
        #[test]
        fn an_earlier_whole_snapshot_does_not_open_after_a_newer_one_batch_set() {
            let old = records(2);
            let newer = records(1);
            let mut waiter = waiting();
            let _ = waiter.verify_and_insert_at(old[0].clone(), None, 2_000);
            waiter.observe_remote_carrier_snapshot(REVOCATION_CARRIER_V1, &SENDER, &old, true);
            // A newer set that omits a record this node holds: refused.
            waiter.observe_remote_carrier_snapshot(REVOCATION_CARRIER_V1, &SENDER, &newer, true);
            let _ = waiter.verify_and_insert_at(old[1].clone(), None, 2_000);
            assert!(
                pending(&waiter),
                "the node holds exactly the OLD set, which is stale"
            );
        }

        /// A signed self-revocation that is over the receive limit by
        /// itself, as only an old store can hold.
        fn unsendable_record() -> RevocationRecord {
            let kp = AgentKeypair::generate().expect("keypair");
            let subject = RevokedSubject::Agent(kp.agent_id());
            let issuer = kp.public_key().as_bytes().to_vec();
            let reason = Some("x".repeat(MAX_REVOCATION_PAYLOAD_BYTES));
            let message = RevocationRecord::canonical_message(&subject, &issuer, 1_000, &reason);
            let signature = sign_with_ml_dsa(kp.secret_key(), &message).expect("sign");
            RevocationRecord {
                subject,
                issuer_public_key: issuer,
                revoked_at: 1_000,
                reason,
                signature: signature.as_bytes().to_vec(),
            }
        }

        /// WHY (review MAJOR): a sender holds a record that cannot be sent.
        /// A waiting node that opened from that sender would hold the set
        /// MINUS that record, with its subject not revoked. The node must
        /// stay closed, whether the rest needs a round or fits one batch.
        /// A released waiter must stay closed too.
        #[test]
        fn a_waiter_never_opens_from_a_sender_that_holds_an_unsendable_record() {
            // (a) The rest needs a round.
            let mut set = records(6);
            set.push(unsendable_record());
            let mut waiter = waiting();
            for batch in &round(&set) {
                receive(&mut waiter, batch, true);
            }
            assert_eq!(waiter.len(), 6);
            assert!(pending(&waiter), "the round can never match its digest");

            // (b) The rest fits one batch.
            let mut set = records(2);
            set.push(unsendable_record());
            let batches =
                encode_revocation_batches_with_target(&set, SMALL_TARGET).expect("encode");
            assert_eq!(batches.len(), 1);
            let mut waiter = waiting();
            receive(&mut waiter, &batches[0], true);
            assert_eq!(waiter.len(), 2);
            assert!(
                pending(&waiter),
                "one batch from this sender is not its whole set"
            );

            let mut released = ReleasedWaiter::new();
            assert_eq!(released.receive(&batches[0]), 2);
            assert!(!released.open, "a released waiter stays closed too");
        }

        /// WHY: the sender publishes the same set again every two hours.
        /// A waiting node that holds the complete round must keep it when
        /// a part of the SAME round arrives again, or it could never open
        /// while its own ingest is still behind.
        #[test]
        fn a_repeat_of_the_same_round_keeps_the_complete_snapshot() {
            let set = records(6);
            let batches = round(&set);
            let mut waiter = waiting();
            // Every part is offered; nothing is ingested yet.
            for batch in &batches {
                let (part, marker) = decode_revocation_batch_with_round(batch).expect("decode");
                waiter.observe_remote_carrier_batch(
                    REVOCATION_CARRIER_V1,
                    &SENDER,
                    &part,
                    marker,
                    true,
                );
            }
            assert!(pending(&waiter));
            // The sender publishes again: part 0 of the same round.
            let (part, marker) = decode_revocation_batch_with_round(&batches[0]).expect("decode");
            waiter.observe_remote_carrier_batch(
                REVOCATION_CARRIER_V1,
                &SENDER,
                &part,
                marker,
                true,
            );
            // The ingest catches up.
            for record in set {
                let _ = waiter.verify_and_insert_at(record, None, 2_000);
            }
            assert!(!pending(&waiter), "the complete round still stands");
        }

        /// WHY: only a trusted authority can offer a snapshot. A marker
        /// from any other sender must not start, extend or close a round.
        #[test]
        fn a_round_from_an_untrusted_sender_is_ignored() {
            let set = records(6);
            let mut waiter = waiting();
            for batch in &round(&set) {
                receive(&mut waiter, batch, false);
            }
            assert_eq!(waiter.len(), 6, "ordinary ingest still takes the records");
            assert!(pending(&waiter));
        }

        /// WHY: the marker is not signed by itself, so the waiter must
        /// check what it says. A wrong set digest, a wrong count, an index
        /// out of range or a changed part must never open the carrier.
        #[test]
        fn a_forged_or_bad_marker_never_opens_the_carrier() {
            let set = records(6);
            let good = round(&set);
            let parts: Vec<Vec<RevocationRecord>> = good
                .iter()
                .map(|batch| decode_revocation_batch(batch).expect("decode"))
                .collect();
            let count = parts.len() as u32;
            let batch_with = |records: &[RevocationRecord], marker: RoundMarker| {
                let mut group = records.to_vec();
                group.push(round_marker_record(&marker));
                encode_revocation_batch(&group).expect("encode")
            };

            // A wrong digest: every part arrives, the set does not match.
            let mut waiter = waiting();
            for (index, part) in parts.iter().enumerate() {
                let marker = RoundMarker {
                    batches: count,
                    index: index as u32,
                    set: [0x66; 32],
                };
                receive(&mut waiter, &batch_with(part, marker), true);
            }
            assert!(pending(&waiter), "wrong set digest");

            // A round that claims fewer batches than the set needs.
            let (_, real) = decode_revocation_batch_with_round(&good[0]).expect("decode");
            let BatchRound::Part(real) = real else {
                panic!("marker")
            };
            let mut waiter = waiting();
            let short = RoundMarker {
                batches: 1,
                index: 0,
                set: real.set,
            };
            receive(&mut waiter, &batch_with(&parts[0], short), true);
            assert!(pending(&waiter), "one part cannot be the whole set");

            // Markers that do not parse are never a snapshot.
            for reason in [
                "x0x-revocation-round-v1 n=0 i=0 set=00".to_string(),
                format!(
                    "x0x-revocation-round-v1 n=2 i=2 set={}",
                    hex::encode([1u8; 32])
                ),
                format!(
                    "x0x-revocation-round-v1 n=513 i=0 set={}",
                    hex::encode([1u8; 32])
                ),
                format!(
                    "x0x-revocation-round-v1 n=02 i=0 set={}",
                    hex::encode([1u8; 32])
                ),
                "something else".to_string(),
            ] {
                let mut bad = round_marker_record(&real);
                bad.reason = Some(reason.clone());
                assert!(is_round_marker(&bad));
                assert_eq!(parse_round_marker(&bad), None, "{reason}");
                let mut group = parts[0].clone();
                group.push(bad);
                let batch = encode_revocation_batch(&group).expect("encode");
                let (records, round) = decode_revocation_batch_with_round(&batch).expect("decode");
                assert_eq!(round, BatchRound::Invalid);
                assert_eq!(records.len(), parts[0].len(), "the marker is removed");
                let mut waiter = waiting();
                receive(&mut waiter, &batch, true);
                assert!(pending(&waiter), "a bad marker never opens: {reason}");
            }

            // The same index with other content is refused.
            let mut waiter = waiting();
            receive(&mut waiter, &good[0], true);
            let swapped = RoundMarker { index: 0, ..real };
            receive(&mut waiter, &batch_with(&parts[1], swapped), true);
            for batch in &good[1..] {
                receive(&mut waiter, batch, true);
            }
            assert!(
                !pending(&waiter),
                "the first part 0 was kept and the round is whole"
            );
        }

        /// WHY: a marker is not a revocation. No path may store, list or
        /// send it, and a store file that holds one must load without it.
        #[test]
        fn a_marker_is_never_stored_listed_or_sent() {
            let marker = round_marker_record(&RoundMarker {
                batches: 2,
                index: 0,
                set: [7; 32],
            });
            assert!(marker
                .reason
                .as_ref()
                .is_some_and(|r| r.len() < MAX_REVOCATION_REASON_BYTES));
            assert_eq!(marker.revoked_at, 0);
            assert!(
                marker.verify_authority(None).is_err(),
                "it can never verify"
            );

            let mut set = RevocationSet::new();
            assert!(set.verify_and_insert(marker.clone(), None).is_err());
            assert!(set
                .verify_and_insert_at(marker.clone(), None, 2_000)
                .is_err());
            assert!(!set.insert_verified(PersistedRevocation {
                record: marker.clone(),
                subject_cert: None,
            }));
            assert!(!set.covers(&marker));
            assert!(set.is_empty());
            assert!(set.all_subject_records().is_empty());
            assert!(!set.is_machine_revoked(&MachineId([0u8; 32])));

            // A store file with a marker in it (it should never exist).
            let real = records(1);
            let persisted = vec![
                PersistedRevocation {
                    record: real[0].clone(),
                    subject_cert: None,
                },
                PersistedRevocation {
                    record: marker.clone(),
                    subject_cert: None,
                },
            ];
            let mut bytes = REVOCATIONS_FILE_MAGIC.to_vec();
            bytes.extend_from_slice(&bincode::serialize(&persisted).expect("encode"));
            let loaded = RevocationSet::from_bytes(&bytes).expect("decode");
            assert_eq!(loaded.all_subject_records(), real);

            // The encoder drops a marker that is handed to it.
            let mut with_marker = real.clone();
            with_marker.push(marker);
            assert_eq!(
                encode_revocation_batches(&with_marker).expect("encode"),
                vec![bincode::serialize(&real).expect("encode")]
            );
        }

        /// The resync rule of a RELEASED daemon (v0.48.1,
        /// `observe_remote_carrier_snapshot` + `try_complete_carrier`),
        /// ported here: one batch is a whole snapshot, and the carrier
        /// opens when the held hashes equal a trusted snapshot's hashes.
        struct ReleasedWaiter {
            known: HashSet<[u8; 32]>,
            candidate: Option<HashSet<[u8; 32]>>,
            open: bool,
        }

        impl ReleasedWaiter {
            fn new() -> Self {
                Self {
                    known: HashSet::new(),
                    candidate: None,
                    open: false,
                }
            }

            /// A released daemon decodes the batch as a plain record list
            /// (it does not know the marker), arms the snapshot, then
            /// applies each record on its own: a record that does not
            /// verify is rejected alone.
            fn receive(&mut self, batch: &[u8]) -> usize {
                let records: Vec<RevocationRecord> =
                    bincode::deserialize(batch).expect("a released decoder reads the batch");
                // observe_remote_carrier_snapshot (trusted sender).
                if !records.is_empty()
                    && records
                        .iter()
                        .all(|r| subject_carrier(&r.subject) == Some(REVOCATION_CARRIER_V1))
                {
                    let hashes: HashSet<[u8; 32]> =
                        records.iter().map(RevocationRecord::record_hash).collect();
                    if hashes.is_superset(&self.known) {
                        self.candidate = Some(hashes);
                        self.try_complete();
                    }
                }
                // apply_legacy_revocation_records.
                let mut applied = 0;
                for record in records {
                    if record.verify_authority(None).is_ok() {
                        self.known.insert(record.record_hash());
                        applied += 1;
                        self.try_complete();
                    }
                }
                applied
            }

            fn try_complete(&mut self) {
                if !self.known.is_empty() && self.candidate.as_ref() == Some(&self.known) {
                    self.open = true;
                }
            }
        }

        /// WHY (requirement b): a released daemon must not be worse off
        /// than before. Before, a set above one batch did not arrive and
        /// its carrier stayed closed. With a round it must still stay
        /// closed (the marker never verifies, so it is never held), while
        /// ordinary ingest applies every real record. A set of one batch
        /// has no marker and opens as before.
        #[test]
        fn a_released_waiter_stays_closed_on_a_round_and_opens_on_one_batch() {
            let set = records(6);
            let mut released = ReleasedWaiter::new();
            let mut applied = 0;
            for batch in &round(&set) {
                applied += released.receive(batch);
                assert!(
                    !released.open,
                    "a marked batch never opens a released waiter"
                );
            }
            assert_eq!(
                applied, 6,
                "every real record of every marked batch is applied"
            );

            let small = records(2);
            let one = encode_revocation_batches_with_target(&small, SMALL_TARGET).expect("encode");
            assert_eq!(one.len(), 1);
            let mut released = ReleasedWaiter::new();
            assert_eq!(released.receive(&one[0]), 2);
            assert!(released.open, "one unmarked batch opens as before");

            // The same single batch opens a new waiter too.
            let mut waiter = waiting();
            receive(&mut waiter, &one[0], true);
            assert!(!pending(&waiter));
        }
    }

    /// #1864: three review findings on the batch and round code of #1857.
    mod recovery_1864 {
        use super::super::*;
        use crate::identity::AgentKeypair;

        const SENDER: AgentId = AgentId([0xA1; 32]);
        const SMALL_TARGET: usize = 12 * 1024;

        fn waiting() -> RevocationSet {
            RevocationSet::quarantined_carrier(REVOCATION_CARRIER_V1)
        }

        fn pending(waiter: &RevocationSet) -> bool {
            waiter.carrier_resync_pending(REVOCATION_CARRIER_V1)
        }

        /// A signed record with a reason over the limit, as a released
        /// daemon could have made it (`sign` refuses it now).
        fn long_reason_record(kp: &AgentKeypair, revoked_at: u64) -> RevocationRecord {
            let subject = RevokedSubject::Agent(kp.agent_id());
            let issuer = kp.public_key().as_bytes().to_vec();
            let reason = Some("x".repeat(MAX_REVOCATION_REASON_BYTES + 1));
            let message =
                RevocationRecord::canonical_message(&subject, &issuer, revoked_at, &reason);
            let signature = sign_with_ml_dsa(kp.secret_key(), &message).expect("sign");
            RevocationRecord {
                subject,
                issuer_public_key: issuer,
                revoked_at,
                reason,
                signature: signature.as_bytes().to_vec(),
            }
        }

        fn short_record(revoked_at: u64) -> RevocationRecord {
            let kp = AgentKeypair::generate().expect("keypair");
            RevocationRecord::sign(
                RevokedSubject::Agent(kp.agent_id()),
                kp.public_key(),
                kp.secret_key(),
                revoked_at,
                None,
            )
            .expect("sign")
        }

        /// What a waiting node does with one gossip batch: record the
        /// sender's offer, then ingest the records.
        fn receive(waiter: &mut RevocationSet, batch: &[u8], trusted: bool) {
            let (records, round) = decode_revocation_batch_with_round(batch).expect("decode");
            waiter.observe_remote_carrier_batch(
                REVOCATION_CARRIER_V1,
                &SENDER,
                &records,
                round,
                trusted,
            );
            for record in records {
                let _ = waiter.verify_and_insert_at(record, None, 2_000);
            }
        }

        /// A marked batch whose marker the decoder refuses (a count over
        /// the round limit, as the encoder sends above 512 batches).
        fn batch_with_invalid_marker(records: &[RevocationRecord]) -> Vec<u8> {
            let mut marker = round_marker_record(&RoundMarker {
                batches: 2,
                index: 0,
                set: [1u8; 32],
            });
            marker.reason = Some(format!(
                "x0x-revocation-round-v1 n={} i=0 set={}",
                MAX_ROUND_BATCHES + 1,
                hex::encode([1u8; 32])
            ));
            let mut group = records.to_vec();
            group.push(marker);
            let batch = encode_revocation_batch(&group).expect("encode");
            let (_, round) = decode_revocation_batch_with_round(&batch).expect("decode");
            assert_eq!(round, BatchRound::Invalid);
            batch
        }

        /// WHY (finding 1): the waiting node holds a legacy record (reason
        /// over the limit). The trusted sender holds a better record of
        /// the same pair, also with a long reason. The snapshot does not
        /// list the held record's hash, but it covers the held record:
        /// this node keeps the sender's record in its place. The offer
        /// must stay, or the long-reason replacement is refused and every
        /// repeat fails in the same way.
        #[test]
        fn a_better_legacy_record_of_a_held_pair_completes_recovery() {
            let kp = AgentKeypair::generate().expect("keypair");
            let held = long_reason_record(&kp, 1_500);
            let better = long_reason_record(&kp, 1_000);
            let mut waiter = waiting();
            assert!(waiter
                .verify_and_insert(held.clone(), None)
                .expect("insert"));
            assert!(pending(&waiter));

            let batch = encode_revocation_batch(std::slice::from_ref(&better)).expect("encode");
            receive(&mut waiter, &batch, true);
            assert!(
                waiter.contains_hash(&better.record_hash()),
                "the trusted sender's long-reason record is admitted"
            );
            assert!(!waiter.contains_hash(&held.record_hash()));
            assert!(waiter.is_agent_revoked(&kp.agent_id()));
            assert!(!pending(&waiter), "recovery completes");
        }

        /// The same case when the sender's set is a marked round.
        #[test]
        fn a_better_legacy_record_of_a_held_pair_completes_a_round() {
            let keys: Vec<AgentKeypair> = (0..6)
                .map(|_| AgentKeypair::generate().expect("keypair"))
                .collect();
            let held = long_reason_record(&keys[0], 1_500);
            let set: Vec<RevocationRecord> = keys
                .iter()
                .map(|kp| long_reason_record(kp, 1_000))
                .collect();
            let batches =
                encode_revocation_batches_with_target(&set, SMALL_TARGET).expect("encode");
            assert!(batches.len() >= 2, "the test needs a round");
            // The batch with the better record of the held pair arrives
            // last, so the round completes while the old record is held.
            let better = set[0].record_hash();
            let (last, first): (Vec<&Vec<u8>>, Vec<&Vec<u8>>) = batches.iter().partition(|batch| {
                decode_revocation_batch(batch)
                    .expect("decode")
                    .iter()
                    .any(|record| record.record_hash() == better)
            });
            assert_eq!(last.len(), 1);
            let mut waiter = waiting();
            assert!(waiter.verify_and_insert(held, None).expect("insert"));
            for batch in first.into_iter().chain(last) {
                receive(&mut waiter, batch, true);
            }
            assert_eq!(waiter.len(), set.len());
            assert!(!pending(&waiter), "recovery completes on this round");
        }

        /// The snapshot stays refused when it does not cover a held
        /// record: the sender's record of the pair is worse, so this node
        /// would keep its own record and the two sets differ.
        #[test]
        fn a_worse_record_of_a_held_pair_does_not_complete_recovery() {
            let kp = AgentKeypair::generate().expect("keypair");
            let held = long_reason_record(&kp, 1_000);
            let worse = long_reason_record(&kp, 1_500);
            let mut waiter = waiting();
            assert!(waiter
                .verify_and_insert(held.clone(), None)
                .expect("insert"));
            let batch = encode_revocation_batch(std::slice::from_ref(&worse)).expect("encode");
            receive(&mut waiter, &batch, true);
            assert!(waiter.contains_hash(&held.record_hash()));
            assert!(pending(&waiter));
        }

        /// A snapshot that covers a held record by a better record opens
        /// nothing until that better record has verified here.
        #[test]
        fn a_covering_snapshot_does_not_open_before_its_record_verifies() {
            let kp = AgentKeypair::generate().expect("keypair");
            let held = long_reason_record(&kp, 1_500);
            let mut forged = long_reason_record(&kp, 1_000);
            forged.signature = vec![0u8; forged.signature.len()];
            let mut waiter = waiting();
            assert!(waiter
                .verify_and_insert(held.clone(), None)
                .expect("insert"));
            let batch = encode_revocation_batch(std::slice::from_ref(&forged)).expect("encode");
            receive(&mut waiter, &batch, true);
            assert!(waiter.contains_hash(&held.record_hash()));
            assert!(pending(&waiter));
        }

        /// WHY (finding 2): a trusted sender offered a complete snapshot
        /// that still waits (one record is not verified yet). Then a
        /// marked batch with a marker this node cannot read arrives from
        /// the same sender: its set is a newer round now. The earlier
        /// snapshot is stale. If it stays, the late record completes it
        /// and the carrier opens with the newer batches missing.
        #[test]
        fn an_invalid_marker_drops_the_senders_earlier_snapshot() {
            let old_set = vec![short_record(1_000), short_record(1_000)];
            let mut waiter = waiting();
            waiter.observe_remote_carrier_batch(
                REVOCATION_CARRIER_V1,
                &SENDER,
                &old_set,
                BatchRound::Whole,
                true,
            );
            assert!(pending(&waiter));

            let batch = batch_with_invalid_marker(&old_set[..1]);
            receive(&mut waiter, &batch, true);
            assert!(waiter.contains_hash(&old_set[0].record_hash()));

            // The late record of the earlier snapshot verifies now.
            assert!(waiter
                .verify_and_insert_at(old_set[1].clone(), None, 2_000)
                .expect("insert"));
            assert!(
                pending(&waiter),
                "a stale snapshot must not open the carrier"
            );
        }

        /// An invalid marker from a sender that is not a trusted authority
        /// changes nothing.
        #[test]
        fn an_invalid_marker_from_an_untrusted_sender_is_ignored() {
            let set = vec![short_record(1_000), short_record(1_000)];
            let mut waiter = waiting();
            waiter.observe_remote_carrier_batch(
                REVOCATION_CARRIER_V1,
                &SENDER,
                &set,
                BatchRound::Whole,
                true,
            );
            let (records, round) =
                decode_revocation_batch_with_round(&batch_with_invalid_marker(&set[..1]))
                    .expect("decode");
            waiter.observe_remote_carrier_batch(
                REVOCATION_CARRIER_V1,
                &SENDER,
                &records,
                round,
                false,
            );
            for record in set {
                let _ = waiter.verify_and_insert_at(record, None, 2_000);
            }
            assert!(!pending(&waiter), "the trusted snapshot still stands");
        }

        /// A round part with a count or index out of range is the same
        /// case on the direct path.
        #[test]
        fn an_out_of_range_round_part_drops_the_senders_earlier_snapshot() {
            for marker in [
                RoundMarker {
                    batches: MAX_ROUND_BATCHES + 1,
                    index: 0,
                    set: [1u8; 32],
                },
                RoundMarker {
                    batches: 2,
                    index: 2,
                    set: [1u8; 32],
                },
                RoundMarker {
                    batches: 0,
                    index: 0,
                    set: [1u8; 32],
                },
            ] {
                let old_set = vec![short_record(1_000), short_record(1_000)];
                let mut waiter = waiting();
                waiter.observe_remote_carrier_batch(
                    REVOCATION_CARRIER_V1,
                    &SENDER,
                    &old_set,
                    BatchRound::Whole,
                    true,
                );
                waiter.observe_remote_carrier_batch(
                    REVOCATION_CARRIER_V1,
                    &SENDER,
                    &old_set[..1],
                    BatchRound::Part(marker),
                    true,
                );
                for record in old_set {
                    let _ = waiter.verify_and_insert_at(record, None, 2_000);
                }
                assert!(pending(&waiter), "{marker:?}");
            }
        }
    }

    mod share_grant_v3 {
        use super::super::*;
        use crate::identity::UserKeypair;

        /// Byte-for-byte replica of the subject enum an ADR-0043 daemon
        /// (pre-slice-3) decodes. Variant ORDER is the bincode tag.
        #[derive(Debug, Serialize, Deserialize)]
        enum OldRevokedSubject {
            Agent(AgentId),
            Machine(MachineId),
            AgentMachineBinding(AgentMachineBinding),
        }

        /// Replica of the pre-ADR-0043 (v1-only) subject enum.
        #[derive(Debug, Serialize, Deserialize)]
        enum V1OnlyRevokedSubject {
            Agent(AgentId),
            Machine(MachineId),
        }

        #[derive(Debug, Serialize, Deserialize)]
        struct OldRecord<S> {
            subject: S,
            issuer_public_key: Vec<u8>,
            revoked_at: u64,
            reason: Option<String>,
            signature: Vec<u8>,
        }

        fn fake(subject: RevokedSubject, tag: u8) -> RevocationRecord {
            RevocationRecord {
                subject,
                issuer_public_key: vec![tag; 4],
                revoked_at: 1_700_000_000 + u64::from(tag),
                reason: Some("r".to_string()),
                signature: vec![tag; 4],
            }
        }

        fn share_grant_fake() -> RevocationRecord {
            fake(
                RevokedSubject::ShareGrant(ShareGrantRevocation {
                    grant_id: [0x5A; 32],
                    owner: UserId([0x5B; 32]),
                    grant_expiry: 1_900_000_000,
                }),
                0x5C,
            )
        }

        fn insert(set: &mut RevocationSet, record: RevocationRecord) {
            assert!(set.insert_verified(PersistedRevocation {
                record,
                subject_cert: None,
            }));
        }

        /// WHY: only the grant's owner may revoke it. A stranger can sign a
        /// record naming someone else's grant id, but it must not verify;
        /// and a stranger's record naming *itself* as owner revokes only a
        /// grant that stranger signed — never the victim's grant with the
        /// same id.
        #[test]
        fn share_grant_revocation_authority_is_the_owner_key_only() {
            let owner = UserKeypair::generate().unwrap();
            let stranger = UserKeypair::generate().unwrap();
            let grant_id = [0x11; 32];
            let subject = RevokedSubject::ShareGrant(ShareGrantRevocation {
                grant_id,
                owner: owner.user_id(),
                grant_expiry: u64::MAX,
            });

            let by_owner = RevocationRecord::sign(
                subject.clone(),
                owner.public_key(),
                owner.secret_key(),
                1_000,
                None,
            )
            .unwrap();
            assert!(by_owner.verify_authority(None).is_ok());
            assert!(!by_owner.is_self_revocation());
            assert_eq!(by_owner.subject_kind(), "share_grant");
            assert_eq!(by_owner.subject_hex(), hex::encode(grant_id));

            let forged = RevocationRecord::sign(
                subject,
                stranger.public_key(),
                stranger.secret_key(),
                1_000,
                None,
            )
            .unwrap();
            assert!(forged.verify_authority(None).is_err());

            let own_claim = RevocationRecord::sign(
                RevokedSubject::ShareGrant(ShareGrantRevocation {
                    grant_id,
                    owner: stranger.user_id(),
                    grant_expiry: u64::MAX,
                }),
                stranger.public_key(),
                stranger.secret_key(),
                1_000,
                None,
            )
            .unwrap();
            let mut set = RevocationSet::new();
            assert!(set.verify_and_insert(own_claim, None).unwrap());
            assert!(
                !set.is_share_grant_revoked(&grant_id, &owner.user_id()),
                "a stranger's revocation must not revoke the owner's grant"
            );
            assert!(set.verify_and_insert(by_owner, None).unwrap());
            assert!(set.is_share_grant_revoked(&grant_id, &owner.user_id()));
        }

        /// WHY (golden): old daemons decode the whole v1 batch and drop it on
        /// an unknown variant, and the heartbeat republishes the full set.
        /// Holding a share-grant revocation must leave the v1 batch AND the
        /// v1 file byte-identical, and the batch must still be exactly what
        /// a pre-ADR-0043 encoder produced for the same records.
        #[test]
        fn v1_batch_and_file_bytes_unchanged_while_share_grant_held() {
            let agent = fake(RevokedSubject::Agent(AgentId([0xA1; 32])), 0xA1);
            let mut set = RevocationSet::new();
            insert(&mut set, agent.clone());
            let batch_before = bincode::serialize(&set.all_records()).unwrap();
            let file_before = set.to_bytes().unwrap();

            insert(&mut set, share_grant_fake());
            assert_eq!(
                bincode::serialize(&set.all_records()).unwrap(),
                batch_before
            );
            assert_eq!(set.to_bytes().unwrap(), file_before);

            let legacy = vec![OldRecord {
                subject: V1OnlyRevokedSubject::Agent(AgentId([0xA1; 32])),
                issuer_public_key: agent.issuer_public_key.clone(),
                revoked_at: agent.revoked_at,
                reason: agent.reason.clone(),
                signature: agent.signature.clone(),
            }];
            assert_eq!(
                bincode::serialize(&legacy).unwrap(),
                batch_before,
                "the v1 batch must match the legacy encoder byte for byte"
            );
        }

        /// WHY: ADR-0043's v2 carrier and file must also stay byte-identical
        /// when a share-grant revocation is held.
        #[test]
        fn v2_batch_and_file_bytes_unchanged_while_share_grant_held() {
            let binding = fake(
                RevokedSubject::AgentMachineBinding(AgentMachineBinding {
                    agent: AgentId([0xB1; 32]),
                    machine: MachineId([0xB2; 32]),
                    move_epoch: 4,
                }),
                0xB3,
            );
            let mut set = RevocationSet::new();
            insert(&mut set, binding);
            let batch_before = bincode::serialize(&set.binding_records()).unwrap();
            let file_before = set.to_bytes_v2().unwrap();

            insert(&mut set, share_grant_fake());
            assert_eq!(
                bincode::serialize(&set.binding_records()).unwrap(),
                batch_before
            );
            assert_eq!(set.to_bytes_v2().unwrap(), file_before);
        }

        /// WHY (old-decoder safety): a share-grant record never appears on
        /// v1 or v2, so the batches an old daemon receives still decode with
        /// its enum; and the v3 batch is exactly what such a decoder would
        /// reject — the reason it rides its own topic.
        #[test]
        fn v3_records_never_reach_old_decoders() {
            let mut set = RevocationSet::new();
            insert(&mut set, fake(RevokedSubject::Agent(AgentId([1; 32])), 1));
            insert(
                &mut set,
                fake(RevokedSubject::Machine(MachineId([2; 32])), 2),
            );
            insert(
                &mut set,
                fake(
                    RevokedSubject::AgentMachineBinding(AgentMachineBinding {
                        agent: AgentId([3; 32]),
                        machine: MachineId([4; 32]),
                        move_epoch: 1,
                    }),
                    3,
                ),
            );
            insert(&mut set, share_grant_fake());

            let v1 = set.all_records();
            let v2 = set.binding_records();
            let v3 = set.share_grant_records();
            // #1108: the display view holds every record; the v1 view
            // above must stay legacy-only.
            assert_eq!(set.all_subject_records().len(), 4);
            assert_eq!(v1.len(), 2);
            assert_eq!(v2.len(), 1);
            assert_eq!(v3.len(), 1);
            for record in v1.iter().chain(v2.iter()) {
                assert!(!matches!(record.subject, RevokedSubject::ShareGrant(_)));
            }
            assert!(v3
                .iter()
                .all(|r| matches!(r.subject, RevokedSubject::ShareGrant(_))));

            let v1_bytes = bincode::serialize(&v1).unwrap();
            assert!(
                bincode::deserialize::<Vec<OldRecord<V1OnlyRevokedSubject>>>(&v1_bytes).is_ok()
            );
            assert!(bincode::deserialize::<Vec<OldRecord<OldRevokedSubject>>>(&v1_bytes).is_ok());
            let v2_bytes = bincode::serialize(&v2).unwrap();
            assert!(bincode::deserialize::<Vec<OldRecord<OldRevokedSubject>>>(&v2_bytes).is_ok());
            let v3_bytes = bincode::serialize(&v3).unwrap();
            assert!(
                bincode::deserialize::<Vec<OldRecord<OldRevokedSubject>>>(&v3_bytes).is_err(),
                "an old decoder rejects the whole batch on the new variant"
            );
            // The v1 file (read by a downgraded daemon) never carries it
            // either: its body still decodes with the legacy subject enum.
            let file = set.to_bytes().unwrap();
            assert!(bincode::deserialize::<
                Vec<(OldRecord<V1OnlyRevokedSubject>, Option<AgentCertificate>)>,
            >(&file[4..])
            .is_ok());
        }

        /// WHY: a revoked grant must stay revoked across restart (v3 file)
        /// for as long as the grant could still be honoured — a grant may be
        /// valid for a long time, and an early
        /// collection would resurrect it. Once the grant itself is dead
        /// (expiry + slack) the record is collected, so the set stays
        /// bounded; every node computes that point from the SIGNED expiry.
        #[test]
        fn share_grant_revocation_is_kept_until_grant_expiry_then_collected() {
            let owner = UserKeypair::generate().unwrap();
            let grant_id = [0x22; 32];
            let grant_expiry = 1_000_000_000u64 + 200 * 24 * 3600;
            let record = RevocationRecord::sign(
                RevokedSubject::ShareGrant(ShareGrantRevocation {
                    grant_id,
                    owner: owner.user_id(),
                    grant_expiry,
                }),
                owner.public_key(),
                owner.secret_key(),
                1_000,
                Some("ended".to_string()),
            )
            .unwrap();
            let mut set = RevocationSet::new();
            assert!(set.verify_and_insert(record, None).unwrap());

            let bytes = set.to_bytes_v3().unwrap();
            assert_eq!(&bytes[..4], b"X0R3");
            let mut restored = RevocationSet::new();
            restored.merge_v3(RevocationSet::from_bytes_v3(&bytes).unwrap());
            assert!(restored.is_share_grant_revoked(&grant_id, &owner.user_id()));

            // Long after the revocation, but before expiry + slack: kept.
            let just_before = grant_expiry + SHARE_GRANT_REVOCATION_GC_SLACK_SECS - 1;
            assert_eq!(restored.collect_dead_records(just_before), 0);
            assert!(restored.is_share_grant_revoked(&grant_id, &owner.user_id()));
            assert_eq!(restored.share_grant_records().len(), 1);

            // At expiry + slack: collected (record and index).
            let horizon = grant_expiry + SHARE_GRANT_REVOCATION_GC_SLACK_SECS;
            assert_eq!(restored.collect_dead_records(horizon), 1);
            assert!(!restored.is_share_grant_revoked(&grant_id, &owner.user_id()));
            assert!(restored.share_grant_records().is_empty());

            // A revocation of an unknown grant (u64::MAX) is never collected.
            let unknown = ShareGrantRevocation {
                grant_id,
                owner: owner.user_id(),
                grant_expiry: u64::MAX,
            };
            assert!(!unknown.gc_eligible_at(u64::MAX - 1));

            // A v1/v2 file is not a v3 file.
            assert!(RevocationSet::from_bytes_v3(&set.to_bytes().unwrap()).is_err());
        }

        /// WHY: two signed records for one grant with different horizons —
        /// collecting the shorter one must not un-revoke the grant while the
        /// longer one is still held.
        #[test]
        fn shorter_revocation_gc_does_not_unrevoke_a_longer_one() {
            let short = fake(
                RevokedSubject::ShareGrant(ShareGrantRevocation {
                    grant_id: [0x44; 32],
                    owner: UserId([0x45; 32]),
                    grant_expiry: 1_000,
                }),
                0x46,
            );
            let long = fake(
                RevokedSubject::ShareGrant(ShareGrantRevocation {
                    grant_id: [0x44; 32],
                    owner: UserId([0x45; 32]),
                    grant_expiry: 1_000_000,
                }),
                0x47,
            );
            let mut set = RevocationSet::new();
            insert(&mut set, short);
            insert(&mut set, long);
            let now = 1_000 + SHARE_GRANT_REVOCATION_GC_SLACK_SECS;
            assert_eq!(set.collect_dead_records(now), 1);
            assert!(set.is_share_grant_revoked(&[0x44; 32], &UserId([0x45; 32])));
        }

        /// WHY: the v3 file is untrusted input. A tampered file carrying a
        /// non-grant record, or a forged grant record, must load as nothing.
        #[test]
        fn v3_file_drops_foreign_and_forged_records() {
            let mut set = RevocationSet::new();
            insert(&mut set, share_grant_fake()); // fake signature
            let tampered = set.to_bytes_v3().unwrap();
            assert!(RevocationSet::from_bytes_v3(&tampered).unwrap().is_empty());
        }
    }
}
