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
/// removal (not a ban) of `subject_hex`? The commit's retained roster has
/// the subject Removed, and the previous retained roster had it seated.
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
    let removed_here = entry
        .roster
        .get(subject_hex)
        .is_some_and(|member| member.state == GroupMemberState::Removed);
    let seated_before = info
        .commit_log
        .iter()
        .find(|prior| prior.commit.revision.saturating_add(1) == revision)
        .is_none_or(|prior| {
            prior
                .roster
                .get(subject_hex)
                .is_some_and(|member| member.state == GroupMemberState::Active)
        });
    removed_here && seated_before && !info.is_banned(subject_hex)
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
}
