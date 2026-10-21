//! ADR 0109 (S3 of ADR 0088): ownerless attestation, stale-base
//! self-recovery and manual re-seat.
//!
//! This module is pure and I/O-free. It holds:
//!
//! - the admin terminal attestation ([`AdminTerminalAttestation`], §1):
//!   one admin's signed statement about one node's catch-up segment, in
//!   domain [`ATA_DOMAIN`] (`x0x.admin-terminal-attest.v1\0`);
//! - the recovery token and the re-seat basis ([`RecoveryRef`],
//!   [`ReseatBasis`], §3);
//! - the admin's signed [`ReseatAuthorisation`] (§3), in domain
//!   [`RESEAT_AUTHORISATION_DOMAIN`];
//! - the `group_attest_request` / `group_attest_response` direct messages
//!   (§5), on the typed prefix [`GROUP_RECOVERY_PREFIX`] (`X0XGRC1`) with an
//!   explicit v1 postcard body consumed exactly;
//! - the §11 limits (D83).
//!
//! The capability that gates every send is `group_terminal_attest_v1`
//! ([`crate::dm::CapabilityRegistry::GROUP_TERMINAL_ATTEST_V1`], bit 8).
//! ATAs and authorisations act only on their `subject` (D41). They are never
//! gossiped, and neither causes a commit by itself.

use std::time::Duration;

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use serde::{Deserialize, Serialize};

use crate::groups::member::{GroupMemberState, GroupRole};
use crate::groups::{ForkQuarantine, GroupInfo};
use crate::identity::{AgentId, AgentKeypair};

// ─── Domains and prefixes ──────────────────────────────────────────────────

/// The ATA signature domain (§1). It ends with a NUL byte.
pub const ATA_DOMAIN: &[u8] = b"x0x.admin-terminal-attest.v1\0";

/// The re-seat authorisation signature domain (§3).
pub const RESEAT_AUTHORISATION_DOMAIN: &[u8] = b"x0x.reseat-authorisation.v1";

/// The typed direct-message prefix of every S3 request and response (§5).
pub const GROUP_RECOVERY_PREFIX: &[u8] = b"X0XGRC1";

/// The `AnchoredGapRefusal::reason` of an admin-armed gap record (§2).
pub const ADMIN_ATTESTED_GAP_REASON: &str = "admin_attested_stale_base_gap";

/// The `AnchoredGapRefusal::reason` of an owner-armed gap record (#846).
pub const OWNER_ATTESTED_GAP_REASON: &str = "owner_attested_stale_base_gap";

// ─── Limits (§11, D83) ─────────────────────────────────────────────────────

/// Links per ATA; a longer gap takes more than one segment.
pub const ATA_MAX_LINKS: usize = 64;
/// The subject accepts an ATA only when `issued_at_ms` is this close to its
/// own clock. It applies at arming only.
pub const ATA_ARM_WINDOW: Duration = Duration::from_secs(10 * 60);
/// An armed ATA with no progress for this long is renewed.
pub const ATA_ARMED_LIFETIME: Duration = Duration::from_secs(30 * 60);
/// An armed gap record with no progress for this long asks for an ATA.
pub const GATE_STALL: Duration = Duration::from_secs(10 * 60);
/// The first request backoff.
pub const REQUEST_BACKOFF_INITIAL: Duration = Duration::from_secs(60);
/// The request backoff ceiling.
pub const REQUEST_BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);
/// One response per requester per this interval.
pub const RESPONDER_PER_REQUESTER_INTERVAL: Duration = Duration::from_secs(60);
/// Concurrent response builds per responder.
pub const RESPONDER_CONCURRENT_BUILDS: usize = 4;
/// Signatures per responder per minute.
pub const RESPONDER_SIGNATURES_PER_MINUTE: u32 = 32;
/// Response bytes per responder per minute.
pub const RESPONDER_BYTES_PER_MINUTE: usize = 1024 * 1024;
/// Entries in the admin's recovery list per group.
pub const RECOVERY_LIST_CAP: usize = 32;
/// How long a recovery-list entry is kept.
pub const RECOVERY_LIST_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Retired records kept per group.
pub const RETIRED_RECORDS_CAP: usize = 16;
/// How long a re-seat authorisation and its invite stay valid.
pub const RESEAT_AUTHORISATION_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// The backoff after `attempts` unanswered or refused requests: 60 s,
/// doubling to 1 h.
#[must_use]
pub fn request_backoff(attempts: u32) -> Duration {
    let shift = attempts.min(16);
    REQUEST_BACKOFF_INITIAL
        .saturating_mul(1_u32 << shift)
        .min(REQUEST_BACKOFF_MAX)
}

// ─── Refusals ──────────────────────────────────────────────────────────────

/// Why a frame, an ATA or an authorisation is refused. The `snake_case`
/// names are the typed reasons in logs and status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRefusal {
    /// Not an `X0XGRC1` payload.
    WrongPrefix,
    /// The body did not decode, or was not consumed exactly.
    Malformed,
    /// A signature does not verify, or the key does not derive the signer.
    BadSignature,
    /// The group does not match.
    GroupMismatch,
    /// The subject is not this node.
    SubjectMismatch,
    /// `from` is not this node's head.
    HeadMismatch,
    /// `issued_at_ms` is outside [`ATA_ARM_WINDOW`] of this node's clock.
    OutsideArmWindow,
    /// The signer is revoked.
    SignerRevoked,
    /// The segment is empty, too long, or inconsistent.
    BadSegment,
    /// The authorisation has expired.
    Expired,
}

impl RecoveryRefusal {
    /// The typed reason string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongPrefix => "wrong_prefix",
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::GroupMismatch => "group_mismatch",
            Self::SubjectMismatch => "subject_mismatch",
            Self::HeadMismatch => "head_mismatch",
            Self::OutsideArmWindow => "outside_arm_window",
            Self::SignerRevoked => "signer_revoked",
            Self::BadSegment => "bad_segment",
            Self::Expired => "expired",
        }
    }
}

impl std::fmt::Display for RecoveryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for RecoveryRefusal {}

// ─── Preimage helpers ──────────────────────────────────────────────────────

/// A length-prefixed (u32 LE) preimage builder, per the #818 hardening
/// note.
struct Preimage(Vec<u8>);

impl Preimage {
    fn new(domain: &[u8]) -> Self {
        Self(domain.to_vec())
    }

    fn bytes(&mut self, field: &[u8]) -> &mut Self {
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_le_bytes());
        self.0.extend_from_slice(field);
        self
    }

    fn str(&mut self, field: &str) -> &mut Self {
        self.bytes(field.as_bytes())
    }

    fn u64(&mut self, field: u64) -> &mut Self {
        self.bytes(&field.to_le_bytes())
    }

    fn opt_u64(&mut self, field: Option<u64>) -> &mut Self {
        match field {
            Some(value) => self.u64(value),
            None => self.bytes(&[]),
        }
    }

    fn list(&mut self, items: &[String]) -> &mut Self {
        let mut inner = Preimage(Vec::new());
        for item in items {
            inner.str(item);
        }
        self.bytes(&inner.0)
    }

    fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// Verify an ML-DSA-65 signature by the agent whose ID is `signer_hex`,
/// under the hex public key `public_key_hex`.
fn verify_agent_signature(
    signer_hex: &str,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), RecoveryRefusal> {
    let key_bytes = hex::decode(public_key_hex).map_err(|_| RecoveryRefusal::BadSignature)?;
    let key = MlDsaPublicKey::from_bytes(&key_bytes).map_err(|_| RecoveryRefusal::BadSignature)?;
    if hex::encode(AgentId::from_public_key(&key).as_bytes()) != signer_hex {
        return Err(RecoveryRefusal::BadSignature);
    }
    let signature_bytes = hex::decode(signature_hex).map_err(|_| RecoveryRefusal::BadSignature)?;
    let signature =
        MlDsaSignature::from_bytes(&signature_bytes).map_err(|_| RecoveryRefusal::BadSignature)?;
    verify_with_ml_dsa(&key, message, &signature).map_err(|_| RecoveryRefusal::BadSignature)
}

fn sign_agent(keypair: &AgentKeypair, message: &[u8]) -> Result<String, RecoveryRefusal> {
    let signature = sign_with_ml_dsa(keypair.secret_key(), message)
        .map_err(|_| RecoveryRefusal::BadSignature)?;
    Ok(hex::encode(signature.as_bytes()))
}

// ─── §1 The admin terminal attestation ─────────────────────────────────────

/// The unsigned fields of an ATA, in table order (§1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaFields {
    /// The stable group ID.
    pub group: String,
    /// The hex agent ID of the node being recovered; only it may use the ATA.
    pub subject: String,
    /// The signing admin (hex agent ID).
    pub attested_by: String,
    /// The signer's ML-DSA-65 agent public key (hex). Its SHA-256 is
    /// `attested_by`.
    pub signer_public_key: String,
    /// The subject's head revision.
    pub from_revision: u64,
    /// The subject's head state hash.
    pub from_state_hash: String,
    /// The state hash of each link after `from`, in order (1 to
    /// [`ATA_MAX_LINKS`] entries).
    pub sequence: Vec<String>,
    /// The last link's revision.
    pub segment_terminal_revision: u64,
    /// The last link's TreeKEM epoch; absent for GSS.
    pub segment_terminal_epoch: Option<u64>,
    /// The signer's clock (unix ms).
    pub issued_at_ms: u64,
}

impl AtaFields {
    fn preimage(&self) -> Vec<u8> {
        Preimage::new(ATA_DOMAIN)
            .str(&self.group)
            .str(&self.subject)
            .str(&self.attested_by)
            .str(&self.signer_public_key)
            .u64(self.from_revision)
            .str(&self.from_state_hash)
            .list(&self.sequence)
            .u64(self.segment_terminal_revision)
            .opt_u64(self.segment_terminal_epoch)
            .u64(self.issued_at_ms)
            .finish()
    }

    /// The segment's shape: 1 to [`ATA_MAX_LINKS`] links, ending at
    /// `from_revision + len`.
    fn segment_well_formed(&self) -> bool {
        let len = self.sequence.len();
        (1..=ATA_MAX_LINKS).contains(&len)
            && self
                .from_revision
                .checked_add(len as u64)
                .is_some_and(|end| end == self.segment_terminal_revision)
            && self.sequence.iter().all(|hash| !hash.is_empty())
    }
}

/// A signed admin terminal attestation (§1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminTerminalAttestation {
    /// The signed fields.
    pub fields: AtaFields,
    /// ML-DSA-65 signature (hex) over the §1 preimage.
    pub signature: String,
}

impl AdminTerminalAttestation {
    /// Sign `fields` with the admin's agent key.
    ///
    /// # Errors
    ///
    /// [`RecoveryRefusal::BadSegment`] for a malformed segment,
    /// [`RecoveryRefusal::BadSignature`] when the keypair is not
    /// `attested_by` or signing fails.
    pub fn sign(fields: AtaFields, keypair: &AgentKeypair) -> Result<Self, RecoveryRefusal> {
        if !fields.segment_well_formed() {
            return Err(RecoveryRefusal::BadSegment);
        }
        if hex::encode(keypair.agent_id().as_bytes()) != fields.attested_by
            || hex::encode(keypair.public_key().as_bytes()) != fields.signer_public_key
        {
            return Err(RecoveryRefusal::BadSignature);
        }
        let signature = sign_agent(keypair, &fields.preimage())?;
        Ok(Self { fields, signature })
    }

    /// The signature verifies under a key whose SHA-256 is `attested_by`,
    /// and the segment is well formed.
    ///
    /// # Errors
    ///
    /// The first failed check.
    pub fn verify_signature(&self) -> Result<(), RecoveryRefusal> {
        if !self.fields.segment_well_formed() {
            return Err(RecoveryRefusal::BadSegment);
        }
        verify_agent_signature(
            &self.fields.attested_by,
            &self.fields.signer_public_key,
            &self.fields.preimage(),
            &self.signature,
        )
    }

    /// The subject's §2 acceptance checks other than signer eligibility:
    /// signature, `subject` and `group`, `from` equal to its own head, and
    /// `issued_at_ms` within [`ATA_ARM_WINDOW`] of `now_ms`.
    /// `signer_revoked` is this node's agent-revocation check for
    /// `attested_by`.
    ///
    /// # Errors
    ///
    /// The first failed check.
    pub fn verify_for_subject(
        &self,
        group: &str,
        subject_hex: &str,
        head_revision: u64,
        head_state_hash: &str,
        now_ms: u64,
        signer_revoked: bool,
    ) -> Result<(), RecoveryRefusal> {
        self.verify_signature()?;
        if self.fields.group != group {
            return Err(RecoveryRefusal::GroupMismatch);
        }
        if !self.fields.subject.eq_ignore_ascii_case(subject_hex) {
            return Err(RecoveryRefusal::SubjectMismatch);
        }
        if self.fields.from_revision != head_revision
            || self.fields.from_state_hash != head_state_hash
        {
            return Err(RecoveryRefusal::HeadMismatch);
        }
        let window = u64::try_from(ATA_ARM_WINDOW.as_millis()).unwrap_or(u64::MAX);
        if self.fields.issued_at_ms.abs_diff(now_ms) > window {
            return Err(RecoveryRefusal::OutsideArmWindow);
        }
        if signer_revoked {
            return Err(RecoveryRefusal::SignerRevoked);
        }
        Ok(())
    }

    /// The signer is **verified** on `roster`: an Active admin there.
    /// Otherwise it is provisional (§2).
    #[must_use]
    pub fn signer_verified_on(&self, roster: &GroupInfo) -> bool {
        signer_is_active_admin(roster, &self.fields.attested_by)
    }

    /// The served chain's next hashes (`served`, in order from the
    /// subject's head) agree with this segment where both are known.
    #[must_use]
    pub fn agrees_with(&self, served: &[String]) -> bool {
        self.fields
            .sequence
            .iter()
            .zip(served.iter())
            .all(|(attested, served)| attested == served)
    }

    /// Two ATAs for one head conflict when their sequences diverge before
    /// either ends (§2 "Conflict").
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.fields.from_state_hash == other.fields.from_state_hash
            && !self
                .fields
                .sequence
                .iter()
                .zip(other.fields.sequence.iter())
                .all(|(a, b)| a == b)
    }
}

/// `agent_hex` is an Active admin (or higher) on `info`'s roster.
#[must_use]
pub fn signer_is_active_admin(info: &GroupInfo, agent_hex: &str) -> bool {
    info.members_v2.get(agent_hex).is_some_and(|member| {
        member.state == GroupMemberState::Active && member.role.at_least(GroupRole::Admin)
    })
}

/// What an admin answers for a subject's head on its own chain (§1
/// issuance, after the classification and admin checks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainPosition {
    /// The head is a commit on the admin's chain, behind its head: these
    /// are the next link hashes (at most [`ATA_MAX_LINKS`]) and the last
    /// one's revision.
    Behind {
        /// The next link hashes after the subject's head.
        sequence: Vec<String>,
        /// The last link's revision.
        terminal_revision: u64,
    },
    /// The head is the admin's head.
    OnChain,
    /// The head is newer than the admin's own.
    AttesterBehind,
    /// The head is older than the admin's retained log.
    BeyondRetention,
    /// The head is not on the admin's chain: the subject is forked.
    NotOnChain,
}

/// Locate `(head_revision, head_state_hash)` on `admin`'s persisted
/// `commit_log` (§1). The log is the admin's own chain.
#[must_use]
pub fn chain_position(
    admin: &GroupInfo,
    head_revision: u64,
    head_state_hash: &str,
) -> ChainPosition {
    if head_revision == admin.state_revision {
        return if head_state_hash == admin.state_hash {
            ChainPosition::OnChain
        } else {
            ChainPosition::NotOnChain
        };
    }
    if head_revision > admin.state_revision {
        return ChainPosition::AttesterBehind;
    }
    let log = &admin.commit_log;
    let Some(oldest) = log.iter().map(|entry| entry.commit.revision).min() else {
        return ChainPosition::BeyondRetention;
    };
    // The base itself must be in the log, or its successor must link from
    // it (the log keeps commits, and a base one below the oldest kept
    // commit is still provable by that commit's `prev_state_hash`).
    let anchored = log.iter().any(|entry| {
        (entry.commit.revision == head_revision && entry.commit.state_hash == head_state_hash)
            || (entry.commit.revision == head_revision.saturating_add(1)
                && entry.commit.prev_state_hash.as_deref() == Some(head_state_hash))
    });
    if !anchored {
        return if head_revision.saturating_add(1) < oldest {
            ChainPosition::BeyondRetention
        } else {
            ChainPosition::NotOnChain
        };
    }
    let mut next: Vec<&crate::groups::state_commit::RetainedCommit> = log
        .iter()
        .filter(|entry| entry.commit.revision > head_revision)
        .collect();
    next.sort_by_key(|entry| entry.commit.revision);
    let mut cursor = head_state_hash.to_string();
    let mut expected = head_revision;
    let mut sequence = Vec::new();
    for entry in next.into_iter().take(ATA_MAX_LINKS) {
        expected = expected.saturating_add(1);
        if entry.commit.revision != expected
            || entry.commit.prev_state_hash.as_deref() != Some(cursor.as_str())
        {
            break;
        }
        cursor = entry.commit.state_hash.clone();
        sequence.push(cursor.clone());
    }
    if sequence.is_empty() {
        return ChainPosition::NotOnChain;
    }
    let terminal_revision = head_revision.saturating_add(sequence.len() as u64);
    ChainPosition::Behind {
        sequence,
        terminal_revision,
    }
}

// ─── §3 Recovery token and basis ───────────────────────────────────────────

/// A node's live containment (§3 "Recovery token and basis").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryRef {
    /// A fork-quarantine marker, by its ADR 0067 identity fields.
    Marker {
        /// The evidenced revision.
        revision: u64,
        /// The evidenced state hash.
        state_hash: String,
        /// The evidenced committer (hex agent ID).
        committed_by: String,
        /// The local observation time (unix ms).
        observed_at_ms: u64,
        /// The ADR 0066 `no_anchor` flag.
        no_anchor: bool,
    },
    /// The gate-only #871 state: an armed gap record.
    Gap {
        /// The record's reason.
        reason: String,
        /// The node's head state hash.
        head_state_hash: String,
        /// The record's terminal revision.
        terminal_revision: u64,
        /// The record's terminal state hash.
        terminal_state_hash: String,
    },
}

impl RecoveryRef {
    /// The marker's recovery token.
    #[must_use]
    pub fn from_marker(marker: &ForkQuarantine) -> Self {
        Self::Marker {
            revision: marker.revision,
            state_hash: marker.state_hash.clone(),
            committed_by: marker.committed_by.clone(),
            observed_at_ms: marker.observed_at_ms,
            no_anchor: marker.no_anchor,
        }
    }

    /// The live recovery tokens of `info`: its marker, and an armed gap
    /// record whose terminal is not applied.
    #[must_use]
    pub fn live_refs(info: &GroupInfo) -> Vec<Self> {
        let mut refs = Vec::new();
        if let Some(marker) = info.fork_quarantine.as_ref() {
            refs.push(Self::from_marker(marker));
        }
        if let Some(record) = info
            .invite_lineage
            .as_ref()
            .and_then(|lineage| lineage.anchored_gap_refusal.as_ref())
            .filter(|record| {
                (record.reason == ADMIN_ATTESTED_GAP_REASON
                    || record.reason == OWNER_ATTESTED_GAP_REASON)
                    && info.state_revision < record.terminal_revision
            })
        {
            refs.push(Self::Gap {
                reason: record.reason.clone(),
                head_state_hash: info.state_hash.clone(),
                terminal_revision: record.terminal_revision,
                terminal_state_hash: record.terminal_state_hash.clone(),
            });
        }
        refs
    }

    /// The JSON view used by the API.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Marker {
                revision,
                state_hash,
                committed_by,
                observed_at_ms,
                no_anchor,
            } => serde_json::json!({
                "kind": "marker",
                "revision": revision,
                "state_hash": state_hash,
                "committed_by": committed_by,
                "observed_at_ms": observed_at_ms,
                "no_anchor": no_anchor,
            }),
            Self::Gap {
                reason,
                head_state_hash,
                terminal_revision,
                terminal_state_hash,
            } => serde_json::json!({
                "kind": "gap",
                "reason": reason,
                "head_state_hash": head_state_hash,
                "terminal_revision": terminal_revision,
                "terminal_state_hash": terminal_state_hash,
            }),
        }
    }

    fn preimage_into(&self, out: &mut Preimage) {
        match self {
            Self::Marker {
                revision,
                state_hash,
                committed_by,
                observed_at_ms,
                no_anchor,
            } => {
                out.str("marker")
                    .u64(*revision)
                    .str(state_hash)
                    .str(committed_by)
                    .u64(*observed_at_ms)
                    .u64(u64::from(*no_anchor));
            }
            Self::Gap {
                reason,
                head_state_hash,
                terminal_revision,
                terminal_state_hash,
            } => {
                out.str("gap")
                    .str(reason)
                    .str(head_state_hash)
                    .u64(*terminal_revision)
                    .str(terminal_state_hash);
            }
        }
    }
}

/// What an admin's re-seat authorisation acts on (§3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReseatBasis {
    /// One `RecoveryRef` the admin was told about.
    Ref(RecoveryRef),
    /// The subject's removal commit.
    Removal {
        /// Its state revision.
        revision: u64,
        /// Its state hash.
        state_hash: String,
    },
}

impl ReseatBasis {
    /// Parse the API form: `{"kind": "removal", "revision", "state_hash"}`,
    /// or a [`RecoveryRef::to_json`] object (`kind` `marker` or `gap`).
    #[must_use]
    pub fn from_json(value: &serde_json::Value) -> Option<Self> {
        let kind = value.get("kind")?.as_str()?;
        let text = |key: &str| value.get(key).and_then(|v| v.as_str()).map(str::to_string);
        let number = |key: &str| value.get(key).and_then(serde_json::Value::as_u64);
        match kind {
            "removal" => Some(Self::Removal {
                revision: number("revision")?,
                state_hash: text("state_hash")?,
            }),
            "marker" => Some(Self::Ref(RecoveryRef::Marker {
                revision: number("revision")?,
                state_hash: text("state_hash")?,
                committed_by: text("committed_by")?,
                observed_at_ms: number("observed_at_ms")?,
                no_anchor: value.get("no_anchor")?.as_bool()?,
            })),
            "gap" => Some(Self::Ref(RecoveryRef::Gap {
                reason: text("reason")?,
                head_state_hash: text("head_state_hash")?,
                terminal_revision: number("terminal_revision")?,
                terminal_state_hash: text("terminal_state_hash")?,
            })),
            _ => None,
        }
    }

    /// The JSON view used by the API.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Ref(recovery_ref) => recovery_ref.to_json(),
            Self::Removal {
                revision,
                state_hash,
            } => serde_json::json!({
                "kind": "removal",
                "revision": revision,
                "state_hash": state_hash,
            }),
        }
    }

    fn preimage_into(&self, out: &mut Preimage) {
        match self {
            Self::Ref(recovery_ref) => {
                out.str("ref");
                recovery_ref.preimage_into(out);
            }
            Self::Removal {
                revision,
                state_hash,
            } => {
                out.str("removal").u64(*revision).str(state_hash);
            }
        }
    }
}

/// Is the commit at `(revision, state_hash)` on `info`'s own chain a
/// removal (not a ban) of `subject_hex`? The retained roster projection
/// keeps Active and Banned seats only, so the subject is absent from the
/// commit's projection and Active in its parent's retained projection, and
/// it is not banned now.
#[must_use]
pub fn removal_commit_on_chain(
    info: &GroupInfo,
    subject_hex: &str,
    revision: u64,
    state_hash: &str,
) -> bool {
    let Some(entry) = info
        .commit_log
        .iter()
        .find(|entry| entry.commit.revision == revision && entry.commit.state_hash == state_hash)
    else {
        return false;
    };
    let removed_here = !entry.roster.contains_key(subject_hex);
    let seated_before = info
        .commit_log
        .iter()
        .find(|prior| {
            prior.commit.revision.saturating_add(1) == revision
                && entry.commit.prev_state_hash.as_deref() == Some(prior.commit.state_hash.as_str())
        })
        .is_some_and(|prior| {
            prior
                .roster
                .get(subject_hex)
                .is_some_and(|member| member.state == GroupMemberState::Active)
        });
    removed_here && seated_before && !info.is_banned(subject_hex)
}

/// The role `subject_hex` held in the parent of its removal commit (§3a
/// check 7), when that parent is retained.
#[must_use]
pub fn role_before_removal(
    info: &GroupInfo,
    subject_hex: &str,
    revision: u64,
) -> Option<GroupRole> {
    info.commit_log
        .iter()
        .find(|prior| prior.commit.revision.saturating_add(1) == revision)
        .and_then(|prior| prior.roster.get(subject_hex))
        .filter(|member| member.state == GroupMemberState::Active)
        .map(|member| member.role)
}

// ─── §3 The re-seat authorisation ──────────────────────────────────────────

/// The unsigned fields of a re-seat authorisation (§3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReseatAuthorisationFields {
    /// The stable group ID.
    pub group: String,
    /// The subject (hex agent ID).
    pub subject: String,
    /// The basis the admin acts on.
    pub basis: ReseatBasis,
    /// The BLAKE3 hash (hex) of the minted invite's secret.
    pub invite_secret_hash: String,
    /// The invite base state revision.
    pub invite_base_revision: u64,
    /// The invite base state hash.
    pub invite_base_state_hash: String,
    /// The signing admin (hex agent ID).
    pub signer: String,
    /// The signer's agent public key (hex).
    pub signer_public_key: String,
    /// The BLAKE3 hash (hex) of the operator's reason.
    pub reason_hash: String,
    /// The expiry (unix ms).
    pub expires_at_ms: u64,
}

impl ReseatAuthorisationFields {
    fn preimage(&self) -> Vec<u8> {
        let mut out = Preimage::new(RESEAT_AUTHORISATION_DOMAIN);
        out.str(&self.group).str(&self.subject);
        let mut basis = Preimage(Vec::new());
        self.basis.preimage_into(&mut basis);
        out.bytes(&basis.finish())
            .str(&self.invite_secret_hash)
            .u64(self.invite_base_revision)
            .str(&self.invite_base_state_hash)
            .str(&self.signer)
            .str(&self.signer_public_key)
            .str(&self.reason_hash)
            .u64(self.expires_at_ms)
            .finish()
    }
}

/// A signed re-seat authorisation (§3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReseatAuthorisation {
    /// The signed fields.
    pub fields: ReseatAuthorisationFields,
    /// ML-DSA-65 signature (hex) over the §3 preimage.
    pub signature: String,
}

impl ReseatAuthorisation {
    /// Sign with the admin's agent key.
    ///
    /// # Errors
    ///
    /// [`RecoveryRefusal::BadSignature`] when the keypair is not `signer`
    /// or signing fails.
    pub fn sign(
        fields: ReseatAuthorisationFields,
        keypair: &AgentKeypair,
    ) -> Result<Self, RecoveryRefusal> {
        if hex::encode(keypair.agent_id().as_bytes()) != fields.signer
            || hex::encode(keypair.public_key().as_bytes()) != fields.signer_public_key
        {
            return Err(RecoveryRefusal::BadSignature);
        }
        let signature = sign_agent(keypair, &fields.preimage())?;
        Ok(Self { fields, signature })
    }

    /// The signature verifies under a key whose SHA-256 is `signer`.
    ///
    /// # Errors
    ///
    /// [`RecoveryRefusal::BadSignature`].
    pub fn verify_signature(&self) -> Result<(), RecoveryRefusal> {
        verify_agent_signature(
            &self.fields.signer,
            &self.fields.signer_public_key,
            &self.fields.preimage(),
            &self.signature,
        )
    }

    /// The authorisation digest (BLAKE3 over the preimage and signature),
    /// bound by §3a's mandate.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.fields.preimage());
        hasher.update(self.signature.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// The subject-side causes of `authorisation_refused {cause}` that
    /// need no network state (§3): signature, subject, a basis paired with
    /// a live `RecoveryRef`, expiry. The inviter and base-roster checks run
    /// against the invite.
    ///
    /// # Errors
    ///
    /// The typed cause of the first failed check.
    pub fn check_for_subject(
        &self,
        group: &str,
        subject_hex: &str,
        live_refs: &[RecoveryRef],
        now_ms: u64,
    ) -> Result<(), &'static str> {
        self.verify_signature().map_err(|_| "signature")?;
        if self.fields.group != group {
            return Err("group_mismatch");
        }
        if !self.fields.subject.eq_ignore_ascii_case(subject_hex) {
            return Err("subject_mismatch");
        }
        let basis_live = match &self.fields.basis {
            ReseatBasis::Ref(recovery_ref) => live_refs.contains(recovery_ref),
            ReseatBasis::Removal { .. } => !live_refs.is_empty(),
        };
        if !basis_live {
            return Err("basis_not_live");
        }
        if now_ms >= self.fields.expires_at_ms {
            return Err("expired");
        }
        Ok(())
    }
}

/// The BLAKE3 hash (hex) of an invite secret, as an authorisation binds it.
#[must_use]
pub fn invite_secret_hash(secret: &str) -> String {
    blake3::hash(secret.as_bytes()).to_hex().to_string()
}

/// The BLAKE3 hash (hex) of an operator's reason.
#[must_use]
pub fn reason_hash(reason: &str) -> String {
    blake3::hash(reason.as_bytes()).to_hex().to_string()
}

// ─── §5 Wire ───────────────────────────────────────────────────────────────

/// `group_attest_request` (§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupAttestRequestV1 {
    /// The stable group ID.
    pub group: String,
    /// The requester (raw agent ID); it equals the verified DM sender.
    pub requester: [u8; 32],
    /// The requester's head revision.
    pub head_revision: u64,
    /// The requester's head state hash.
    pub head_state_hash: String,
    /// The live `RecoveryRef`s, each with its cause.
    pub refs: Vec<(RecoveryRef, String)>,
}

/// An admin's head, as a response names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminHead {
    /// Its state revision.
    pub revision: u64,
    /// Its state hash.
    pub state_hash: String,
}

/// Why a responder refuses (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestRefusalReason {
    /// The responder's own record is contained.
    AttesterQuarantined,
    /// The requester's head is newer than the responder's.
    AttesterBehind,
    /// The responder is not an active admin.
    NotAnAdmin,
    /// The requester is not an active member.
    NotAMember,
    /// The requester is banned or revoked.
    BannedOrRevoked,
    /// The requester's head is older than the responder's retained log.
    BaseBeyondRetention,
    /// The request is over a responder limit.
    RateLimited,
}

impl AttestRefusalReason {
    /// The typed reason string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AttesterQuarantined => "attester_quarantined",
            Self::AttesterBehind => "attester_behind",
            Self::NotAnAdmin => "not_an_admin",
            Self::NotAMember => "not_a_member",
            Self::BannedOrRevoked => "banned_or_revoked",
            Self::BaseBeyondRetention => "base_beyond_retention",
            Self::RateLimited => "rate_limited",
        }
    }
}

/// `group_attest_response` answers (§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestAnswer {
    /// An ATA for the requester's head.
    Attested(Box<AdminTerminalAttestation>),
    /// The requester's head is the responder's head.
    OnChain(AdminHead),
    /// The requester's head is not on the responder's chain.
    NotOnChain(AdminHead),
    /// An unconsumed re-seat authorisation names the requester.
    Reseat {
        /// The signed authorisation.
        authorisation: Box<ReseatAuthorisation>,
        /// The minted invite link.
        invite: String,
    },
    /// A typed refusal.
    Refused(AttestRefusalReason),
}

impl AttestAnswer {
    /// The answer's name, as `asked` and `last_refusal` show it.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Attested(_) => "attested",
            Self::OnChain(_) => "on_chain",
            Self::NotOnChain(_) => "not_on_chain",
            Self::Reseat { .. } => "reseat",
            Self::Refused(reason) => reason.as_str(),
        }
    }
}

/// `group_attest_response` (§5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupAttestResponseV1 {
    /// The stable group ID.
    pub group: String,
    /// The requester this answers.
    pub subject: [u8; 32],
    /// The requester head this answers.
    pub for_head_state_hash: String,
    /// The answer.
    pub answer: AttestAnswer,
}

/// One S3 direct message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupRecoveryMessageV1 {
    /// `group_attest_request`.
    Request(GroupAttestRequestV1),
    /// `group_attest_response`.
    Response(GroupAttestResponseV1),
}

/// Encode a message as a direct-message payload.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_message(message: &GroupRecoveryMessageV1) -> Result<Vec<u8>, postcard::Error> {
    let mut out = GROUP_RECOVERY_PREFIX.to_vec();
    out.extend(postcard::to_stdvec(message)?);
    Ok(out)
}

/// Decode a message with exact consumption. Signatures inside are not
/// checked here.
///
/// # Errors
///
/// [`RecoveryRefusal::WrongPrefix`] or [`RecoveryRefusal::Malformed`].
pub fn decode_message(payload: &[u8]) -> Result<GroupRecoveryMessageV1, RecoveryRefusal> {
    let body = payload
        .strip_prefix(GROUP_RECOVERY_PREFIX)
        .ok_or(RecoveryRefusal::WrongPrefix)?;
    let (message, rest) = postcard::take_from_bytes::<GroupRecoveryMessageV1>(body)
        .map_err(|_| RecoveryRefusal::Malformed)?;
    if !rest.is_empty() {
        return Err(RecoveryRefusal::Malformed);
    }
    Ok(message)
}

// ─── §3a The promoted-admin re-seat mandate ────────────────────────────────

/// The promoted-admin re-seat mandate domain (§3a). Distinct from the
/// invite-secret mandate domain, ADR 0114's repair-mandate domains and the
/// owner join domain.
pub const RESEAT_MANDATE_DOMAIN: &[u8] = b"x0x/owner-axis/reseat-mandate-admin/v1";

/// The genesis hash a mandate binds (§3a field 1): BLAKE3 over the
/// length-prefixed genesis fields, or over the stable ID alone when this
/// node holds no genesis record.
#[must_use]
pub fn genesis_hash(info: &GroupInfo) -> String {
    let mut out = Preimage::new(b"x0x.group-genesis-hash.v1");
    match info.genesis.as_ref() {
        Some(genesis) => {
            out.str(&genesis.group_id)
                .str(&genesis.creator_agent_id)
                .u64(genesis.created_at)
                .str(&genesis.creation_nonce);
        }
        None => {
            out.str(info.stable_group_id());
        }
    }
    blake3::hash(&out.finish()).to_hex().to_string()
}

/// The unsigned fields of `ReseatMandateV1`, in preimage order (§3a).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReseatMandateFields {
    /// (1) The owner user ID (hex).
    pub owner_user_id: String,
    /// (1) The stable group ID.
    pub group_id: String,
    /// (1) [`genesis_hash`] of the group.
    pub genesis_hash: String,
    /// (2) The signing admin (hex agent ID).
    pub signer: String,
    /// (2) The subject (hex agent ID).
    pub subject: String,
    /// (3) The state hash of the commit that first seated the subject.
    pub seating_commit_hash: String,
    /// (4) The state hash of the subject's removal commit (the `Removal`
    /// basis).
    pub removal_commit_hash: String,
    /// (5) The parent commit hash the re-seat `MemberAdded` links from.
    pub parent_commit_hash: String,
    /// (6) The expected terminal roster projection hash (the roster root
    /// after the add, not the enclosing state hash).
    pub terminal_roster_hash: String,
    /// (7) The re-seat invite's secret hash.
    pub invite_secret_hash: String,
    /// (7) The `ReseatAuthorisation` digest (hex).
    pub authorisation_digest: String,
    /// (8) The subject's KeyPackage hash.
    pub key_package_hash: String,
    /// (8) The native epoch the subject joins at.
    pub epoch: u64,
    /// (9) The subject's owner certificate digest.
    pub certificate_digest: String,
    /// (10) The policy hash.
    pub policy_hash: String,
    /// (11) The exact role the subject receives.
    pub role: GroupRole,
    /// The signer's agent public key (hex); its SHA-256 is `signer`.
    pub signer_public_key: String,
}

impl ReseatMandateFields {
    fn preimage(&self) -> Vec<u8> {
        let role = serde_json::to_string(&self.role).unwrap_or_default();
        Preimage::new(RESEAT_MANDATE_DOMAIN)
            .str(&self.owner_user_id)
            .str(&self.group_id)
            .str(&self.genesis_hash)
            .str(&self.signer)
            .str(&self.subject)
            .str(&self.seating_commit_hash)
            .str(&self.removal_commit_hash)
            .str(&self.parent_commit_hash)
            .str(&self.terminal_roster_hash)
            .str(&self.invite_secret_hash)
            .str(&self.authorisation_digest)
            .str(&self.key_package_hash)
            .u64(self.epoch)
            .str(&self.certificate_digest)
            .str(&self.policy_hash)
            .str(&role)
            .str(&self.signer_public_key)
            .finish()
    }
}

/// A signed promoted-admin re-seat mandate (§3a), carried in a re-seat
/// `MemberAdded` in place of the owner mandate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReseatMandateV1 {
    /// The signed fields.
    pub fields: ReseatMandateFields,
    /// ML-DSA-65 signature (hex) by the signer's agent key.
    pub signature: String,
}

impl ReseatMandateV1 {
    /// Sign with the admin's agent key.
    ///
    /// # Errors
    ///
    /// [`RecoveryRefusal::BadSignature`] when the keypair is not the signer.
    pub fn sign(
        fields: ReseatMandateFields,
        keypair: &AgentKeypair,
    ) -> Result<Self, RecoveryRefusal> {
        if hex::encode(keypair.agent_id().as_bytes()) != fields.signer
            || hex::encode(keypair.public_key().as_bytes()) != fields.signer_public_key
        {
            return Err(RecoveryRefusal::BadSignature);
        }
        let signature = sign_agent(keypair, &fields.preimage())?;
        Ok(Self { fields, signature })
    }

    /// The signature verifies under a key whose SHA-256 is the signer.
    ///
    /// # Errors
    ///
    /// [`RecoveryRefusal::BadSignature`].
    pub fn verify_signature(&self) -> Result<(), RecoveryRefusal> {
        verify_agent_signature(
            &self.fields.signer,
            &self.fields.signer_public_key,
            &self.fields.preimage(),
            &self.signature,
        )
    }
}

/// Why a receiver refuses a re-seat `MemberAdded` (§3a acceptance rule,
/// checks 1 to 8 in order): `reseat_mandate_invalid {cause}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReseatMandateCause {
    /// (1) The signature, or `committed_by` is not the signer.
    Signature,
    /// (2) The signer holds no current Admin seat at the parent commit.
    SignerNotAdmin,
    /// (3) The policy hash or the owner does not match the parent.
    PolicyMismatch,
    /// (4) The seating commit is not on the chain or did not seat the subject.
    NotPreviouslySeated,
    /// (5) The removal commit is not on the chain, did not remove the
    /// subject, was not committed by the signer, or a later commit seats,
    /// bans or revokes the subject.
    RemovalMismatch,
    /// (6) The certificate does not match the bound digest or the owner.
    CertificateInvalid,
    /// (7) The role is higher than before the removal.
    RoleRaised,
    /// (8) The parent, KeyPackage, epoch or roster binding differs from the
    /// commit.
    BindingMismatch,
}

impl ReseatMandateCause {
    /// The typed cause string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::SignerNotAdmin => "signer_not_admin",
            Self::PolicyMismatch => "policy_mismatch",
            Self::NotPreviouslySeated => "not_previously_seated",
            Self::RemovalMismatch => "removal_mismatch",
            Self::CertificateInvalid => "certificate_invalid",
            Self::RoleRaised => "role_raised",
            Self::BindingMismatch => "binding_mismatch",
        }
    }
}

/// What a receiver checks a re-seat `MemberAdded` against (§3a).
pub struct ReseatMandateCheck<'a> {
    /// The receiver's current verified record (the parent of the commit).
    pub parent: &'a GroupInfo,
    /// The signed `MemberAdded` commit.
    pub commit: &'a crate::groups::state_commit::GroupStateCommit,
    /// The added agent (hex).
    pub subject: &'a str,
    /// The event's KeyPackage hash.
    pub key_package_hash: Option<&'a str>,
    /// The event's TreeKEM epoch.
    pub epoch: Option<u64>,
    /// The role the commit seats the subject with.
    pub seated_role: GroupRole,
    /// The digest of the subject's committed certificate.
    pub certificate_digest: Option<&'a str>,
    /// The certificate verifies against the owner: valid, unexpired and
    /// unrevoked (the caller runs the owner-certificate check).
    pub certificate_valid: bool,
    /// The subject's agent is revoked on this receiver.
    pub subject_revoked: bool,
}

/// The §3a acceptance rule. Returns the first failed check.
///
/// # Errors
///
/// The [`ReseatMandateCause`] of the first failed check.
pub fn verify_reseat_mandate(
    mandate: &ReseatMandateV1,
    check: &ReseatMandateCheck<'_>,
) -> Result<(), ReseatMandateCause> {
    let fields = &mandate.fields;
    let parent = check.parent;
    // 1.
    if mandate.verify_signature().is_err()
        || !check
            .commit
            .committed_by
            .eq_ignore_ascii_case(&fields.signer)
        || !fields.subject.eq_ignore_ascii_case(check.subject)
    {
        return Err(ReseatMandateCause::Signature);
    }
    // 2.
    if !signer_is_active_admin(parent, &fields.signer) {
        return Err(ReseatMandateCause::SignerNotAdmin);
    }
    // 3.
    let owner = parent.policy.admission.owner_certified_user_id();
    if fields.policy_hash != crate::groups::compute_policy_hash(&parent.policy)
        || owner.map(|owner| hex::encode(owner.as_bytes())).as_deref()
            != Some(fields.owner_user_id.as_str())
        || fields.group_id != parent.stable_group_id()
        || fields.genesis_hash != genesis_hash(parent)
    {
        return Err(ReseatMandateCause::PolicyMismatch);
    }
    // 4.
    let log = &parent.commit_log;
    let seated_by = |entry: &crate::groups::state_commit::RetainedCommit| {
        entry
            .roster
            .get(check.subject)
            .is_some_and(|member| member.state == GroupMemberState::Active)
    };
    let seating = log
        .iter()
        .find(|entry| entry.commit.state_hash == fields.seating_commit_hash);
    let seating_ok = seating.is_some_and(|entry| {
        seated_by(entry)
            && log
                .iter()
                .find(|prior| prior.commit.revision.saturating_add(1) == entry.commit.revision)
                .is_none_or(|prior| !seated_by(prior))
    });
    if !seating_ok {
        return Err(ReseatMandateCause::NotPreviouslySeated);
    }
    // 5.
    let Some(removal) = log
        .iter()
        .find(|entry| entry.commit.state_hash == fields.removal_commit_hash)
    else {
        return Err(ReseatMandateCause::RemovalMismatch);
    };
    let removal_ok = removal_commit_on_chain(
        parent,
        check.subject,
        removal.commit.revision,
        &removal.commit.state_hash,
    ) && removal
        .commit
        .committed_by
        .eq_ignore_ascii_case(&fields.signer)
        && seating.is_some_and(|entry| entry.commit.revision < removal.commit.revision)
        && log
            .iter()
            .filter(|entry| entry.commit.revision > removal.commit.revision)
            .all(|entry| !entry.roster.contains_key(check.subject))
        && !check.subject_revoked;
    if !removal_ok {
        return Err(ReseatMandateCause::RemovalMismatch);
    }
    // 6.
    if check.certificate_digest != Some(fields.certificate_digest.as_str())
        || !check.certificate_valid
    {
        return Err(ReseatMandateCause::CertificateInvalid);
    }
    // 7.
    let before = role_before_removal(parent, check.subject, removal.commit.revision);
    let raised = before.is_none_or(|before| !before.at_least(fields.role))
        || check.seated_role != fields.role;
    if raised {
        return Err(ReseatMandateCause::RoleRaised);
    }
    // 8.
    if check.commit.prev_state_hash.as_deref() != Some(fields.parent_commit_hash.as_str())
        || parent.state_hash != fields.parent_commit_hash
        || check.key_package_hash != Some(fields.key_package_hash.as_str())
        || check.epoch != Some(fields.epoch)
        || check.commit.roster_root != fields.terminal_roster_hash
    {
        return Err(ReseatMandateCause::BindingMismatch);
    }
    Ok(())
}

// ─── §4 The S3 sidecar ─────────────────────────────────────────────────────

/// The sidecar directory under the data directory (§4).
pub const GROUP_RECOVERY_DIR: &str = "group-recovery";

/// The sidecar file extension (§4). S3 loads state only from names that end
/// exactly in `.grecov`.
pub const GROUP_RECOVERY_EXTENSION: &str = "grecov";

/// The header family prefix (§4).
pub const GROUP_RECOVERY_FAMILY: &[u8] = b"X0GRCV";

/// The version-1 header: the family prefix, `1` and a NUL terminator.
pub const GROUP_RECOVERY_HEADER_V1: &[u8] = b"X0GRCV1\0";

/// The highest sidecar version this binary reads.
pub const GROUP_RECOVERY_MAX_SUPPORTED_VERSION: u8 = b'1';

/// Why a sidecar file is not loaded (ADR 0108 §5a classes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupRecoveryDecodeError {
    /// Damage: a missing prefix, a truncated header, a bad version byte, a
    /// bad terminator, or a version-1 body that does not decode or has
    /// trailing bytes.
    Damaged(&'static str),
    /// A valid header of a higher version (the version byte).
    NewerFormat(u8),
}

impl std::fmt::Display for GroupRecoveryDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Damaged(cause) => write!(f, "damaged: {cause}"),
            Self::NewerFormat(version) => write!(f, "newer format version {}", *version as char),
        }
    }
}

impl std::error::Error for GroupRecoveryDecodeError {}

/// The phase of a subject's re-seat (§3 steps 1 to 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReseatPhase {
    /// The journal is durable; the staged join runs.
    Staging,
    /// The staged record is Active with keys; the swap is due.
    Swapping,
}

impl ReseatPhase {
    /// The typed phase name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Swapping => "swapping",
        }
    }
}

/// The subject's re-seat journal (§3 step 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReseatJournalV1 {
    /// The verified authorisation.
    pub authorisation: ReseatAuthorisation,
    /// The re-seat invite link.
    pub invite: String,
    /// BLAKE3 of the full live record (JSON) at journal time.
    pub record_digest: [u8; 32],
    /// The journal phase.
    pub phase: ReseatPhase,
    /// The live map key of the record the re-seat replaces.
    pub live_key: String,
    /// The live record (JSON) the re-seat replaces; restored on failure.
    pub live_record: Vec<u8>,
    /// The live record's TreeKEM snapshot, when it had one.
    pub live_tree: Option<Vec<u8>>,
    /// When the journal was written (unix ms).
    pub started_at_ms: u64,
}

/// One re-seat authorisation an admin issued (§3; issuer only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedReseatV1 {
    /// The signed authorisation.
    pub authorisation: ReseatAuthorisation,
    /// The minted invite link.
    pub invite: String,
    /// When it was issued (unix ms).
    pub issued_at_ms: u64,
}

/// One retired record (§3 step 3, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredRecordV1 {
    /// Why it was retired (`reseat`).
    pub cause: String,
    /// When (unix ms).
    pub retired_at_ms: u64,
    /// The retired record (JSON).
    pub record: Vec<u8>,
}

/// The S3 sidecar body (§4). Embedded `GroupInfo` records and events are
/// JSON documents carried as bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRecoveryV1 {
    /// Incremented by every transition.
    pub generation: u64,
    /// ADR 0108 §5a: the `txid`s of the files this one replaced.
    pub rebuilt_from: Vec<[u8; 16]>,
    /// The kept served chain (JSON `RetainedCommit`s).
    pub served_chain: Vec<Vec<u8>>,
    /// The active ATA.
    pub active_ata: Option<AdminTerminalAttestation>,
    /// The queued terminal (JSON metadata event).
    pub queued_terminal: Option<Vec<u8>>,
    /// The authoritative record behind an S3 placeholder (JSON).
    pub authoritative_record: Option<Vec<u8>>,
    /// The subject's re-seat journal.
    pub reseat_journal: Option<ReseatJournalV1>,
    /// The staging record (JSON).
    pub staging_record: Option<Vec<u8>>,
    /// The re-seat authorisations this node issued.
    pub issued_reseats: Vec<IssuedReseatV1>,
    /// Retired records, newest last, at most [`RETIRED_RECORDS_CAP`].
    pub retired: Vec<RetiredRecordV1>,
}

impl GroupRecoveryV1 {
    /// Nothing is stored: the file may be removed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.served_chain.is_empty()
            && self.active_ata.is_none()
            && self.queued_terminal.is_none()
            && self.authoritative_record.is_none()
            && self.reseat_journal.is_none()
            && self.staging_record.is_none()
            && self.issued_reseats.is_empty()
            && self.retired.is_empty()
    }

    /// Keep a retired record, dropping the oldest past the cap.
    pub fn retire(&mut self, record: RetiredRecordV1) {
        self.retired.push(record);
        let excess = self.retired.len().saturating_sub(RETIRED_RECORDS_CAP);
        self.retired.drain(..excess);
    }
}

/// Encode a sidecar file.
///
/// # Errors
///
/// Returns the postcard error when encoding fails.
pub fn encode_sidecar(body: &GroupRecoveryV1) -> Result<Vec<u8>, postcard::Error> {
    let mut out = GROUP_RECOVERY_HEADER_V1.to_vec();
    out.extend(postcard::to_stdvec(body)?);
    Ok(out)
}

/// Decode and classify a sidecar file (§4 header layout).
///
/// # Errors
///
/// The ADR 0108 §5a class.
pub fn decode_sidecar(bytes: &[u8]) -> Result<GroupRecoveryV1, GroupRecoveryDecodeError> {
    let family = GROUP_RECOVERY_FAMILY.len();
    let Some(prefix) = bytes.get(..family) else {
        return Err(
            if !bytes.is_empty() && GROUP_RECOVERY_FAMILY.starts_with(bytes) {
                GroupRecoveryDecodeError::Damaged("truncated_header")
            } else {
                GroupRecoveryDecodeError::Damaged("missing_prefix")
            },
        );
    };
    if prefix != GROUP_RECOVERY_FAMILY {
        return Err(GroupRecoveryDecodeError::Damaged("missing_prefix"));
    }
    let (Some(&version), Some(&terminator), Some(body)) = (
        bytes.get(family),
        bytes.get(family + 1),
        bytes.get(family + 2..),
    ) else {
        return Err(GroupRecoveryDecodeError::Damaged("truncated_header"));
    };
    if !(b'1'..=b'~').contains(&version) {
        return Err(GroupRecoveryDecodeError::Damaged("bad_version"));
    }
    if terminator != 0 {
        return Err(GroupRecoveryDecodeError::Damaged("missing_nul"));
    }
    if version > GROUP_RECOVERY_MAX_SUPPORTED_VERSION {
        return Err(GroupRecoveryDecodeError::NewerFormat(version));
    }
    let (value, rest) = postcard::take_from_bytes::<GroupRecoveryV1>(body)
        .map_err(|_| GroupRecoveryDecodeError::Damaged("body_decode"))?;
    if !rest.is_empty() {
        return Err(GroupRecoveryDecodeError::Damaged("trailing_bytes"));
    }
    Ok(value)
}

/// The sidecar file name of a group: its stable ID, sanitised, plus the
/// extension. A stable ID with characters outside `[0-9A-Za-z_-]` is
/// hashed.
#[must_use]
pub fn sidecar_file_name(stable_group_id: &str) -> String {
    let clean = !stable_group_id.is_empty()
        && stable_group_id.len() <= 128
        && stable_group_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    let stem = if clean {
        stable_group_id.to_string()
    } else {
        blake3::hash(stable_group_id.as_bytes())
            .to_hex()
            .to_string()
    };
    format!("{stem}.{GROUP_RECOVERY_EXTENSION}")
}

// ─── §2 Pre-Welcome link apply (rule (b)) ──────────────────────────────────

/// The TreeKEM epoch a commit's security binding names
/// (`treekem:epoch=<n>[:...]`), if any.
#[must_use]
pub fn treekem_epoch_of(commit: &crate::groups::state_commit::GroupStateCommit) -> Option<u64> {
    let binding = commit.security_binding.as_deref()?;
    let rest = binding.strip_prefix("treekem:epoch=")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Rule (b) (§2, D82): apply one served-chain link state-only on a
/// pre-Welcome node. The caller has checked the whole served chain with
/// `validate_alternate_chain` from this node's head, and that the link is
/// the next hash of an armed attested sequence. This applies every
/// `validate_apply` check against the current record, refuses a policy
/// change and a GSS security-binding change, and takes no tree and no
/// epoch: the TreeKEM commit is skipped.
///
/// # Errors
///
/// The refusal reason.
pub fn apply_link_state_only(
    current: &GroupInfo,
    link: &crate::groups::state_commit::RetainedCommit,
) -> Result<GroupInfo, &'static str> {
    use crate::groups::state_commit as sc;
    let commit = &link.commit;
    if commit.prev_state_hash.as_deref() != Some(current.state_hash.as_str()) {
        return Err("link does not chain from the node's head");
    }
    let ctx = sc::ApplyContext {
        current_state_hash: &current.state_hash,
        current_revision: current.state_revision,
        current_withdrawn: current.withdrawn,
        members_v2: &current.members_v2,
        group_id: current.stable_group_id(),
    };
    sc::validate_apply(&ctx, commit, sc::ActionKind::AdminOrHigher)
        .map_err(|_| "link fails validate_apply")?;
    if commit.policy_hash != crate::groups::compute_policy_hash(&current.policy) {
        return Err("link changes the policy hash");
    }
    if current.secure_plane != crate::mls::SecureGroupPlane::TreeKem
        && commit.security_binding != current.security_binding
    {
        return Err("link changes a GSS security binding");
    }
    let Some(meta) = link.meta.as_ref() else {
        return Err("link has no sealed metadata");
    };
    if sc::roster_root_of_projection(&link.roster) != commit.roster_root {
        return Err("link roster does not re-derive its signed root");
    }
    let mut next = current.clone();
    next.apply_reconstructed_roster(&link.roster);
    next.finalize_adopted_commit_reconstructed(commit, meta, &[])
        .map_err(|_| "link does not re-derive its signed state hash")?;
    Ok(next)
}

/// Where a non-joiner stands on a provisional signer's promotion path
/// (§2 "Verification and signer eligibility").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionalPath {
    /// The node has not yet applied the link that makes the signer an
    /// Active admin; every link it applied so far is the ATA's prefix.
    Pending,
    /// The applied links are the ATA's prefix and end at (or pass) the
    /// link that makes the signer an Active admin: the ATA may arm for the
    /// rest of its sequence.
    Verified,
    /// The head left the ATA's sequence, an applied hash differs from the
    /// prefix, or the whole sequence applied with no promotion: drop it.
    Unverified,
}

/// §2: a node that is not a joiner verifies a provisional signer by
/// applying the promotion path through the ordinary path, ungated. The
/// ordinary apply path checks every committer against its predecessor
/// roster; this checks that what it applied is the ATA's own prefix, in
/// order, and that the signer is now an Active admin on `info`.
#[must_use]
pub fn provisional_path(ata: &AdminTerminalAttestation, info: &GroupInfo) -> ProvisionalPath {
    let fields = &ata.fields;
    if info.state_revision == fields.from_revision && info.state_hash == fields.from_state_hash {
        return ProvisionalPath::Pending;
    }
    let Some(index) = fields
        .sequence
        .iter()
        .position(|hash| *hash == info.state_hash)
    else {
        return ProvisionalPath::Unverified;
    };
    let prefix_applied =
        fields
            .sequence
            .iter()
            .take(index + 1)
            .enumerate()
            .all(|(offset, hash)| {
                let revision = fields
                    .from_revision
                    .saturating_add(u64::try_from(offset).unwrap_or(u64::MAX))
                    .saturating_add(1);
                info.commit_log.iter().any(|entry| {
                    entry.commit.revision == revision && entry.commit.state_hash == *hash
                })
            });
    if !prefix_applied {
        return ProvisionalPath::Unverified;
    }
    if signer_is_active_admin(info, &fields.attested_by) {
        ProvisionalPath::Verified
    } else if index + 1 >= fields.sequence.len() {
        ProvisionalPath::Unverified
    } else {
        ProvisionalPath::Pending
    }
}

/// §2 "Segments": the links of a kept served chain still to apply when
/// this node's head is `(head_revision, head_state_hash)`. After an earlier
/// segment the head is inside the chain, so the links up to it are already
/// applied. `None` when the head is inside the chain's range but is not
/// its link at that revision (the chain does not continue from the head).
#[must_use]
pub fn kept_chain_remainder(
    chain: Vec<crate::groups::state_commit::RetainedCommit>,
    head_revision: u64,
    head_state_hash: &str,
) -> Option<Vec<crate::groups::state_commit::RetainedCommit>> {
    let applied = chain
        .iter()
        .take_while(|link| link.commit.revision <= head_revision)
        .count();
    if let Some(last_applied) = applied.checked_sub(1).and_then(|index| chain.get(index)) {
        if last_applied.commit.revision != head_revision
            || last_applied.commit.state_hash != head_state_hash
        {
            return None;
        }
    }
    Some(chain.into_iter().skip(applied).collect())
}

/// §2 provisional signer: the promotion path inside the served chain.
/// Returns the number of leading links (a prefix of the ATA's own
/// sequence) that end at the first link whose roster makes the signer an
/// Active admin. The caller has walked `chain` with
/// `validate_alternate_chain`, which checks every committer against its
/// predecessor roster. `None` when no such prefix exists, or the walked
/// hashes differ from the ATA's prefix.
#[must_use]
pub fn promotion_prefix(
    ata: &AdminTerminalAttestation,
    chain: &[crate::groups::state_commit::RetainedCommit],
) -> Option<usize> {
    let signer = &ata.fields.attested_by;
    for (index, link) in chain.iter().enumerate() {
        if ata.fields.sequence.get(index) != Some(&link.commit.state_hash) {
            return None;
        }
        let admin = link.roster.get(signer).is_some_and(|member| {
            member.state == GroupMemberState::Active && member.role.at_least(GroupRole::Admin)
        });
        if admin {
            return Some(index + 1);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> AgentKeypair {
        AgentKeypair::generate().expect("keypair")
    }

    fn fields(admin: &AgentKeypair) -> AtaFields {
        AtaFields {
            group: "g".to_string(),
            subject: "ab".repeat(32),
            attested_by: hex::encode(admin.agent_id().as_bytes()),
            signer_public_key: hex::encode(admin.public_key().as_bytes()),
            from_revision: 4,
            from_state_hash: "h4".to_string(),
            sequence: vec!["h5".to_string(), "h6".to_string()],
            segment_terminal_revision: 6,
            segment_terminal_epoch: Some(3),
            issued_at_ms: 1_000_000,
        }
    }

    #[test]
    fn ata_signs_and_verifies_for_its_subject_only() {
        let admin = keypair();
        let ata = AdminTerminalAttestation::sign(fields(&admin), &admin).expect("sign");
        let subject = "ab".repeat(32);
        ata.verify_for_subject("g", &subject, 4, "h4", 1_000_000, false)
            .expect("valid");
        assert_eq!(
            ata.verify_for_subject("g", &"cd".repeat(32), 4, "h4", 1_000_000, false),
            Err(RecoveryRefusal::SubjectMismatch)
        );
        assert_eq!(
            ata.verify_for_subject("g", &subject, 5, "h5", 1_000_000, false),
            Err(RecoveryRefusal::HeadMismatch)
        );
        assert_eq!(
            ata.verify_for_subject("g2", &subject, 4, "h4", 1_000_000, false),
            Err(RecoveryRefusal::GroupMismatch)
        );
        assert_eq!(
            ata.verify_for_subject("g", &subject, 4, "h4", 1_000_000 + 11 * 60_000, false),
            Err(RecoveryRefusal::OutsideArmWindow)
        );
        assert_eq!(
            ata.verify_for_subject("g", &subject, 4, "h4", 1_000_000, true),
            Err(RecoveryRefusal::SignerRevoked)
        );
    }

    #[test]
    fn tampered_ata_fails_and_other_keys_cannot_sign() {
        let admin = keypair();
        let mut ata = AdminTerminalAttestation::sign(fields(&admin), &admin).expect("sign");
        ata.fields.sequence[1] = "other".to_string();
        assert_eq!(ata.verify_signature(), Err(RecoveryRefusal::BadSignature));
        let other = keypair();
        assert_eq!(
            AdminTerminalAttestation::sign(fields(&admin), &other),
            Err(RecoveryRefusal::BadSignature)
        );
        let mut bad = fields(&admin);
        bad.segment_terminal_revision = 9;
        assert_eq!(
            AdminTerminalAttestation::sign(bad, &admin),
            Err(RecoveryRefusal::BadSegment)
        );
    }

    #[test]
    fn diverging_segments_conflict() {
        let admin = keypair();
        let a = AdminTerminalAttestation::sign(fields(&admin), &admin).expect("sign");
        let mut prefix = fields(&admin);
        prefix.sequence.truncate(1);
        prefix.segment_terminal_revision = 5;
        let b = AdminTerminalAttestation::sign(prefix, &admin).expect("sign");
        assert!(!a.conflicts_with(&b));
        let mut diverge = fields(&admin);
        diverge.sequence[1] = "x6".to_string();
        let c = AdminTerminalAttestation::sign(diverge, &admin).expect("sign");
        assert!(a.conflicts_with(&c));
        assert!(a.agrees_with(&["h5".to_string()]));
        assert!(!a.agrees_with(&["x5".to_string()]));
    }

    #[test]
    fn messages_round_trip_with_exact_consumption() {
        let admin = keypair();
        let ata = AdminTerminalAttestation::sign(fields(&admin), &admin).expect("sign");
        let message = GroupRecoveryMessageV1::Response(GroupAttestResponseV1 {
            group: "g".to_string(),
            subject: [7; 32],
            for_head_state_hash: "h4".to_string(),
            answer: AttestAnswer::Attested(Box::new(ata)),
        });
        let mut bytes = encode_message(&message).expect("encode");
        assert!(bytes.starts_with(GROUP_RECOVERY_PREFIX));
        assert_eq!(decode_message(&bytes), Ok(message));
        bytes.push(0);
        assert_eq!(decode_message(&bytes), Err(RecoveryRefusal::Malformed));
        assert_eq!(
            decode_message(b"X0XCE1rest"),
            Err(RecoveryRefusal::WrongPrefix)
        );
    }

    #[test]
    fn authorisation_binds_its_subject_basis_and_expiry() {
        let admin = keypair();
        let subject = "ab".repeat(32);
        let auth = ReseatAuthorisation::sign(
            ReseatAuthorisationFields {
                group: "g".to_string(),
                subject: subject.clone(),
                basis: ReseatBasis::Removal {
                    revision: 7,
                    state_hash: "h7".to_string(),
                },
                invite_secret_hash: invite_secret_hash("secret"),
                invite_base_revision: 7,
                invite_base_state_hash: "h7".to_string(),
                signer: hex::encode(admin.agent_id().as_bytes()),
                signer_public_key: hex::encode(admin.public_key().as_bytes()),
                reason_hash: reason_hash("forked"),
                expires_at_ms: 2_000,
            },
            &admin,
        )
        .expect("sign");
        let live = vec![RecoveryRef::Gap {
            reason: ADMIN_ATTESTED_GAP_REASON.to_string(),
            head_state_hash: "h".to_string(),
            terminal_revision: 9,
            terminal_state_hash: "t".to_string(),
        }];
        assert_eq!(auth.check_for_subject("g", &subject, &live, 1_000), Ok(()));
        assert_eq!(
            auth.check_for_subject("g", &subject, &[], 1_000),
            Err("basis_not_live")
        );
        assert_eq!(
            auth.check_for_subject("g", &subject, &live, 2_000),
            Err("expired")
        );
        assert_eq!(
            auth.check_for_subject("g", &"cd".repeat(32), &live, 1_000),
            Err("subject_mismatch")
        );
        let mut tampered = auth.clone();
        tampered.fields.expires_at_ms = 9_000;
        assert_eq!(
            tampered.check_for_subject("g", &subject, &live, 1_000),
            Err("signature")
        );
        assert_ne!(auth.digest(), tampered.digest());
    }

    #[test]
    fn basis_json_round_trips() {
        let removal = ReseatBasis::Removal {
            revision: 3,
            state_hash: "h".to_string(),
        };
        assert_eq!(ReseatBasis::from_json(&removal.to_json()), Some(removal));
        let marker = ReseatBasis::Ref(RecoveryRef::Marker {
            revision: 2,
            state_hash: "s".to_string(),
            committed_by: "c".to_string(),
            observed_at_ms: 5,
            no_anchor: true,
        });
        assert_eq!(ReseatBasis::from_json(&marker.to_json()), Some(marker));
        assert_eq!(
            ReseatBasis::from_json(&serde_json::json!({"kind": "other"})),
            None
        );
    }

    #[test]
    fn backoff_doubles_to_one_hour() {
        assert_eq!(request_backoff(0), Duration::from_secs(60));
        assert_eq!(request_backoff(1), Duration::from_secs(120));
        assert_eq!(request_backoff(6), Duration::from_secs(3600));
        assert_eq!(request_backoff(40), Duration::from_secs(3600));
    }

    fn signed_group(admin: &AgentKeypair) -> GroupInfo {
        let mut info = GroupInfo::new(
            "g".to_string(),
            "d".to_string(),
            admin.agent_id(),
            "ab".repeat(16),
        );
        for (id, by) in [("m1", true), ("m2", true)] {
            let hex_id = id.repeat(32);
            info.add_member(
                hex_id,
                GroupRole::Member,
                by.then(|| hex::encode(admin.agent_id().as_bytes())),
                None,
            );
        }
        info.seal_commit(admin, 1_000).expect("seal");
        info
    }

    #[test]
    fn chain_position_names_behind_on_chain_forked_and_newer() {
        let admin = keypair();
        let mut info = signed_group(&admin);
        let base_revision = info.state_revision;
        let base_hash = info.state_hash.clone();
        info.remove_member(&"m2".repeat(32), None);
        info.seal_commit(&admin, 2_000).expect("seal removal");
        info.name = "renamed".to_string();
        info.seal_commit(&admin, 3_000).expect("seal rename");
        match chain_position(&info, base_revision, &base_hash) {
            ChainPosition::Behind {
                sequence,
                terminal_revision,
            } => {
                assert_eq!(sequence.len(), 2);
                assert_eq!(sequence.last(), Some(&info.state_hash));
                assert_eq!(terminal_revision, info.state_revision);
            }
            other => panic!("expected Behind, got {other:?}"),
        }
        assert_eq!(
            chain_position(&info, info.state_revision, &info.state_hash),
            ChainPosition::OnChain
        );
        assert_eq!(
            chain_position(&info, info.state_revision, "sibling"),
            ChainPosition::NotOnChain
        );
        assert_eq!(
            chain_position(&info, base_revision, "sibling"),
            ChainPosition::NotOnChain
        );
        assert_eq!(
            chain_position(&info, info.state_revision + 1, "ahead"),
            ChainPosition::AttesterBehind
        );
    }

    #[test]
    fn provisional_path_verifies_only_the_applied_promotion_prefix() {
        let admin = keypair();
        let m1_keys = keypair();
        let m1 = hex::encode(m1_keys.agent_id().as_bytes());
        let mut info = signed_group(&admin);
        info.add_member(
            m1.clone(),
            GroupRole::Member,
            Some(hex::encode(admin.agent_id().as_bytes())),
            None,
        );
        info.seal_commit(&admin, 1_500).expect("seal add");
        let base = info.clone();
        // r+1: a rename; r+2: M1 promoted to admin; r+3: another rename.
        info.name = "one".to_string();
        info.seal_commit(&admin, 2_000).expect("seal rename");
        let after_rename = info.clone();
        if let Some(member) = info.members_v2.get_mut(&m1) {
            member.role = GroupRole::Admin;
        }
        info.seal_commit(&admin, 3_000).expect("seal promotion");
        let after_promotion = info.clone();
        info.name = "two".to_string();
        info.seal_commit(&admin, 4_000).expect("seal rename");
        let sequence: Vec<String> = info
            .commit_log
            .iter()
            .filter(|entry| entry.commit.revision > base.state_revision)
            .map(|entry| entry.commit.state_hash.clone())
            .collect();
        assert_eq!(sequence.len(), 3);
        let mut ata_fields = fields(&m1_keys);
        ata_fields.from_revision = base.state_revision;
        ata_fields.from_state_hash = base.state_hash.clone();
        ata_fields.segment_terminal_revision = info.state_revision;
        ata_fields.sequence = sequence;
        let ata = AdminTerminalAttestation::sign(ata_fields, &m1_keys).expect("sign");

        assert_eq!(provisional_path(&ata, &base), ProvisionalPath::Pending);
        assert_eq!(
            provisional_path(&ata, &after_rename),
            ProvisionalPath::Pending
        );
        assert_eq!(
            provisional_path(&ata, &after_promotion),
            ProvisionalPath::Verified
        );
        // A head that left the sequence is dropped.
        let mut off = after_rename.clone();
        off.state_hash = "sibling".to_string();
        assert_eq!(provisional_path(&ata, &off), ProvisionalPath::Unverified);
        // The whole sequence applied, but the signer was demoted at its end.
        let mut demoted = info.clone();
        if let Some(member) = demoted.members_v2.get_mut(&m1) {
            member.role = GroupRole::Member;
        }
        assert_eq!(
            provisional_path(&ata, &demoted),
            ProvisionalPath::Unverified
        );
    }

    #[test]
    fn kept_chain_remainder_resumes_from_the_head() {
        let admin = keypair();
        let mut info = signed_group(&admin);
        let base = info.clone();
        info.remove_member(&"m2".repeat(32), None);
        info.seal_commit(&admin, 2_000).expect("seal removal");
        info.name = "renamed".to_string();
        info.seal_commit(&admin, 3_000).expect("seal rename");
        let links: Vec<_> = info
            .commit_log
            .iter()
            .filter(|entry| entry.commit.revision > base.state_revision)
            .cloned()
            .collect();
        assert_eq!(links.len(), 2);
        // At the base: the whole chain is still to apply.
        let all = kept_chain_remainder(links.clone(), base.state_revision, &base.state_hash)
            .expect("from the base");
        assert_eq!(all.len(), 2);
        // After the first segment: only the second link.
        let first = links[0].commit.clone();
        let rest = kept_chain_remainder(links.clone(), first.revision, &first.state_hash)
            .expect("from the first link");
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].commit.state_hash, links[1].commit.state_hash);
        // At the chain's end: nothing left, the terminal follows.
        let end = kept_chain_remainder(links.clone(), info.state_revision, &info.state_hash)
            .expect("from the end");
        assert!(end.is_empty());
        // A head at a chain revision with another hash: not this chain.
        assert!(kept_chain_remainder(links, first.revision, "sibling").is_none());
    }

    #[test]
    fn served_links_apply_state_only_in_order() {
        let admin = keypair();
        let mut info = signed_group(&admin);
        let base = info.clone();
        let m2 = "m2".repeat(32);
        info.remove_member(&m2, None);
        info.seal_commit(&admin, 2_000).expect("seal removal");
        info.name = "renamed".to_string();
        info.seal_commit(&admin, 3_000).expect("seal rename");
        let links: Vec<_> = info
            .commit_log
            .iter()
            .filter(|entry| entry.commit.revision > base.state_revision)
            .cloned()
            .collect();
        assert_eq!(links.len(), 2);
        assert!(apply_link_state_only(&base, &links[1]).is_err());
        let first = apply_link_state_only(&base, &links[0]).expect("removal link");
        assert!(!first.has_active_member(&m2));
        let second = apply_link_state_only(&first, &links[1]).expect("rename link");
        assert_eq!(second.state_hash, info.state_hash);
        assert_eq!(second.name, "renamed");
        assert!(removal_commit_on_chain(
            &info,
            &m2,
            links[0].commit.revision,
            &links[0].commit.state_hash
        ));
        assert!(!removal_commit_on_chain(
            &info,
            &"m1".repeat(32),
            links[0].commit.revision,
            &links[0].commit.state_hash
        ));
    }

    #[test]
    fn link_changing_the_policy_is_refused() {
        let admin = keypair();
        let mut info = signed_group(&admin);
        let base = info.clone();
        info.policy.read_access = crate::groups::policy::GroupReadAccess::Public;
        info.seal_commit(&admin, 2_000).expect("seal policy");
        let link = info
            .commit_log
            .iter()
            .find(|entry| entry.commit.revision == info.state_revision)
            .cloned()
            .expect("link");
        assert_eq!(
            apply_link_state_only(&base, &link).map(|_| ()),
            Err("link changes the policy hash")
        );
    }

    #[test]
    fn sidecar_round_trips_and_classifies_damage() {
        let body = GroupRecoveryV1 {
            generation: 3,
            queued_terminal: Some(b"{}".to_vec()),
            ..GroupRecoveryV1::default()
        };
        let bytes = encode_sidecar(&body).expect("encode");
        assert!(bytes.starts_with(GROUP_RECOVERY_HEADER_V1));
        assert_eq!(decode_sidecar(&bytes), Ok(body));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_sidecar(&trailing),
            Err(GroupRecoveryDecodeError::Damaged("trailing_bytes"))
        );
        assert_eq!(
            decode_sidecar(b"X0GRC"),
            Err(GroupRecoveryDecodeError::Damaged("truncated_header"))
        );
        assert_eq!(
            decode_sidecar(b"nope"),
            Err(GroupRecoveryDecodeError::Damaged("missing_prefix"))
        );
        assert_eq!(
            decode_sidecar(b"X0GRCV0\0"),
            Err(GroupRecoveryDecodeError::Damaged("bad_version"))
        );
        assert_eq!(
            decode_sidecar(b"X0GRCV1x"),
            Err(GroupRecoveryDecodeError::Damaged("missing_nul"))
        );
        assert_eq!(
            decode_sidecar(b"X0GRCV2\0rest"),
            Err(GroupRecoveryDecodeError::NewerFormat(b'2'))
        );
        assert_eq!(sidecar_file_name("abc-1"), "abc-1.grecov");
        assert!(sidecar_file_name("../x").ends_with(".grecov"));
        assert!(!sidecar_file_name("../x").contains('/'));
    }

    #[test]
    fn treekem_epoch_parses_both_binding_forms() {
        let admin = keypair();
        let mut info = signed_group(&admin);
        info.security_binding = Some("treekem:epoch=7:commit=ab".to_string());
        let commit = info.seal_commit(&admin, 2_000).expect("seal");
        assert_eq!(treekem_epoch_of(&commit), Some(7));
        info.security_binding = Some("treekem:epoch=9".to_string());
        let commit = info.seal_commit(&admin, 3_000).expect("seal");
        assert_eq!(treekem_epoch_of(&commit), Some(9));
        info.security_binding = Some("gss:epoch=2".to_string());
        let commit = info.seal_commit(&admin, 4_000).expect("seal");
        assert_eq!(treekem_epoch_of(&commit), None);
    }
    struct OwnerAxis {
        admin: AgentKeypair,
        certs: Vec<(String, crate::identity::AgentCertificate)>,
        subject_hex: String,
        subject_cert_digest: String,
        info: GroupInfo,
        seating_hash: String,
        removal_hash: String,
    }

    fn sealed(
        info: &mut GroupInfo,
        admin: &AgentKeypair,
        certs: &[(String, crate::identity::AgentCertificate)],
        at: u64,
    ) -> crate::groups::state_commit::GroupStateCommit {
        let mut evidence = crate::groups::owner_cert::OwnerCertEvidence::new(
            crate::groups::owner_cert::restore_clock_now(),
        );
        for (agent, cert) in certs {
            evidence.insert_cert(agent.clone(), cert.clone());
        }
        let verdict = info.owner_cert_verdict(&evidence);
        info.seal_commit_with_owner_certs(admin, at, &verdict)
            .expect("seal")
            .0
    }

    fn owner_axis_group() -> OwnerAxis {
        let owner = crate::identity::UserKeypair::generate().expect("owner");
        let admin = keypair();
        let subject = keypair();
        let admin_cert = crate::identity::AgentCertificate::issue(&owner, &admin).expect("cert");
        let subject_cert =
            crate::identity::AgentCertificate::issue(&owner, &subject).expect("cert");
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let subject_hex = hex::encode(subject.agent_id().as_bytes());
        let mut policy = crate::groups::GroupPolicy::default();
        policy.admission = crate::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
        let mut info = GroupInfo::with_policy(
            "g".to_string(),
            String::new(),
            admin.agent_id(),
            "cd".repeat(32),
            policy,
        );
        info.set_member_certificate(&admin_hex, admin_cert.clone())
            .expect("admin cert");
        let certs = vec![
            (admin_hex.clone(), admin_cert),
            (subject_hex.clone(), subject_cert.clone()),
        ];
        info.add_member(
            subject_hex.clone(),
            GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.set_member_certificate(&subject_hex, subject_cert.clone())
            .expect("subject cert");
        sealed(&mut info, &admin, &certs, 1_000);
        let seating_hash = info.state_hash.clone();
        info.remove_member(&subject_hex, Some(admin_hex));
        sealed(&mut info, &admin, &certs, 2_000);
        let removal_hash = info.state_hash.clone();
        OwnerAxis {
            admin,
            certs,
            subject_hex,
            subject_cert_digest: crate::groups::owner_cert::certificate_digest_hex(&subject_cert),
            info,
            seating_hash,
            removal_hash,
        }
    }

    fn mandate_for(
        fixture: &OwnerAxis,
        commit: &crate::groups::state_commit::GroupStateCommit,
        role: GroupRole,
    ) -> ReseatMandateV1 {
        let owner = fixture
            .info
            .policy
            .admission
            .owner_certified_user_id()
            .map(|owner| hex::encode(owner.as_bytes()))
            .expect("owner axis");
        ReseatMandateV1::sign(
            ReseatMandateFields {
                owner_user_id: owner,
                group_id: fixture.info.stable_group_id().to_string(),
                genesis_hash: genesis_hash(&fixture.info),
                signer: hex::encode(fixture.admin.agent_id().as_bytes()),
                subject: fixture.subject_hex.clone(),
                seating_commit_hash: fixture.seating_hash.clone(),
                removal_commit_hash: fixture.removal_hash.clone(),
                parent_commit_hash: fixture.info.state_hash.clone(),
                terminal_roster_hash: commit.roster_root.clone(),
                invite_secret_hash: invite_secret_hash("s"),
                authorisation_digest: "00".repeat(32),
                key_package_hash: "kp".to_string(),
                epoch: 0,
                certificate_digest: fixture.subject_cert_digest.clone(),
                policy_hash: crate::groups::compute_policy_hash(&fixture.info.policy),
                role,
                signer_public_key: hex::encode(fixture.admin.public_key().as_bytes()),
            },
            &fixture.admin,
        )
        .expect("sign")
    }

    #[test]
    fn reseat_mandate_accepts_a_bound_readmission_and_names_each_failure() {
        let fixture = owner_axis_group();
        // The re-seat commit: the subject back as Member, sealed by the admin
        // on a clone of the parent.
        let mut next = fixture.info.clone();
        next.add_member(
            fixture.subject_hex.clone(),
            GroupRole::Member,
            Some(hex::encode(fixture.admin.agent_id().as_bytes())),
            None,
        );
        let commit = sealed(&mut next, &fixture.admin, &fixture.certs, 3_000);
        let check = ReseatMandateCheck {
            parent: &fixture.info,
            commit: &commit,
            subject: &fixture.subject_hex,
            key_package_hash: Some("kp"),
            epoch: Some(0),
            seated_role: GroupRole::Member,
            certificate_digest: Some(&fixture.subject_cert_digest),
            certificate_valid: true,
            subject_revoked: false,
        };
        let mandate = mandate_for(&fixture, &commit, GroupRole::Member);
        assert_eq!(verify_reseat_mandate(&mandate, &check), Ok(()));

        let mut tampered = mandate.clone();
        tampered.fields.epoch = 9;
        assert_eq!(
            verify_reseat_mandate(&tampered, &check),
            Err(ReseatMandateCause::Signature)
        );
        let raised = mandate_for(&fixture, &commit, GroupRole::Admin);
        let raised_check = ReseatMandateCheck {
            seated_role: GroupRole::Admin,
            ..check
        };
        assert_eq!(
            verify_reseat_mandate(&raised, &raised_check),
            Err(ReseatMandateCause::RoleRaised)
        );
        let revoked = ReseatMandateCheck {
            subject_revoked: true,
            ..check
        };
        assert_eq!(
            verify_reseat_mandate(&mandate, &revoked),
            Err(ReseatMandateCause::RemovalMismatch)
        );
        let bad_cert = ReseatMandateCheck {
            certificate_valid: false,
            ..check
        };
        assert_eq!(
            verify_reseat_mandate(&mandate, &bad_cert),
            Err(ReseatMandateCause::CertificateInvalid)
        );
        let other_kp = ReseatMandateCheck {
            key_package_hash: Some("other"),
            ..check
        };
        assert_eq!(
            verify_reseat_mandate(&mandate, &other_kp),
            Err(ReseatMandateCause::BindingMismatch)
        );
        // A replay after the subject is seated again fails check 5.
        let mut reseated = fixture.info.clone();
        reseated
            .commit_log
            .push(crate::groups::state_commit::RetainedCommit::capture(
                commit.clone(),
                &next.members_v2,
                next.public_meta(),
            ));
        let replay = ReseatMandateCheck {
            parent: &reseated,
            ..check
        };
        assert!(verify_reseat_mandate(&mandate, &replay).is_err());
    }
}
