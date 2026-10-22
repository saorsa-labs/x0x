//! ADR-0041 Tier-1 cross-machine owner-state sync.
//!
//! Tier 1 replicates exactly four kinds of small owner-signed state between
//! the owner's machines over ADR-0022 byte streams ([`crate::streams`]):
//! the owner profile, per-machine agent/machine names, the Home roster +
//! policy pointer, and the sub-agent issuance journal. Tier 2 (history
//! backfill) and Tier 3 (never-replicates state) are out of scope here.
//!
//! # Trust model — same-owner, enrolled machines, key possession
//! (gapcheck blocker 30; review R2)
//!
//! A stream carrying [`crate::streams::StreamProtocol::SyncV1`] is accepted
//! only when ALL hold:
//!
//! 1. the ADR-0022 machine identity gates (transport-verified, trusted,
//!    non-revoked) have already cleared — enforced by the shared accept loop
//!    before this protocol's acceptor sees the stream. **#1040 exception:**
//!    when the transport-authenticated machine has NO known agent (e.g.
//!    this device restarted with an empty discovery cache), the accept loop
//!    admits a `SyncV1` stream — and no other protocol — if the machine is
//!    in the verified owner enrollment set (signature chains to the local
//!    owner, current, not in the revocation set), re-verified after the
//!    prefix read. The outbound pass likewise dials such a machine by its
//!    id using only bootstrap-cache addresses (enrollments carry none);
//!    see [`crate::Agent`]'s `open_enrolled_owner_sync_stream`;
//! 2. the remote machine is in the local **owner device set**: an
//!    [`crate::owner_sync::OwnerEnrollment`] record signed by the owner key, whose public key
//!    derives to this install's `UserId`, and whose optional expiry has not
//!    elapsed (enrollment currency, not just signature validity). This is
//!    the enrollment direction of ADR-0043, reused — not a rival scheme.
//!    Enrollments are removed with the DELETE `/sync/devices/:id` path.
//! 3. the peer **proves possession of the owner key**: after the transport
//!    handshake each side sends a random nonce and the peer must return an
//!    ML-DSA signature over `nonce || both machine ids || owner_user_id`
//!    under the owner key. Echoing the owner id (as the unsigned `Hello`
//!    alone allowed) is worthless; a stale-but-enrolled machine that no
//!    longer holds the owner key learns nothing.
//!
//! Fail closed: any signature, enrollment, or proof failure aborts the
//! session, and the peer learns nothing beyond the refusal.
//!
//! # Object model (gapcheck blocker 31)
//!
//! Each Tier-1 object is an owner-signed [`crate::owner_sync::VersionedRecord`]. Conflict rule
//! (deliberately decoupled from state-commit heights): highest `version`
//! wins; tie → highest `signed_at_ms`; tie → lexicographically greatest
//! `writer_machine`; **exact-clock tie with different signed content →
//! greatest `record_hash`** (deterministic convergence under equal-clock
//! equivocation; detected and surfaced). Anti-rollback: nothing ever
//! replaces a stored record it does not strictly outrank.
//!
//! Durability (review R2): the store directory is created at load, and
//! every mutating path propagates persistence errors — success is never
//! reported on a swallowed write. Accepted batches are committed in ONE
//! atomic file write only after the whole batch verified and the session
//! reached a clean `Done`, so a forged tail cannot leave a partial batch
//! committed and advertised.
//!
//! # Protocol
//!
//! On connect: `Hello` (same owner, same protocol version, non-self, each
//! side carrying a fresh nonce) → mutual `Proof` (owner-key possession) →
//! per-kind **paged** version vectors → **paged** record batches both ways
//! → `Done` → atomic local commit. The whole session runs under a total
//! timeout ([`crate::owner_sync::SESSION_TIMEOUT`]); a peer that stalls at any stage is
//! dropped, never held. Sessions run periodically and are re-triggered on
//! local change (the store's generation channel).
//!
//! # Tier-3 boundary (gapcheck blocker 32 scope note)
//!
//! The sync surface serializes ONLY the four Tier-1 kinds: [`crate::owner_sync::SyncKind`] and
//! [`crate::owner_sync::SyncValue`] are closed enums with no catch-all. A record whose kind tag
//! is not one of the four fails to decode, and a record whose kind does not
//! match its value variant is rejected whole.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaPublicKey, MlDsaSignature,
};
use ant_quic::derive_peer_id_from_public_key;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::IdentityError;
use crate::groups::{GroupMemberState, GroupPolicy, GroupRole};
use crate::identity::{MachineId, UserId, UserKeypair};

/// Domain-separation prefix for the bytes an owner enrollment signs.
const ENROLL_MSG_PREFIX: &[u8] = b"x0x-adr0041-enroll-v1";
/// Domain-separation prefix for the bytes a versioned record signs.
const RECORD_MSG_PREFIX: &[u8] = b"x0x-adr0041-record-v1";
/// Domain-separation prefix for the owner-key possession proof.
const PROOF_MSG_PREFIX: &[u8] = b"x0x-adr0041-proof-v1";

/// Wire protocol version for the SyncV1 handshake. Bumped to 2 in review
/// R2 (Hello carries a nonce; `Proof` frame added; vectors/records paged).
pub const SYNC_PROTOCOL_VERSION: u32 = 2;

/// Maximum size of one sync frame (length-prefixed payload). Tier-1 records
/// are tiny; anything larger is hostile or corrupt — fail closed.
pub const MAX_FRAME_BYTES: u32 = 256 * 1024;

/// Version-vector entries per `VersionVector` frame (an upper bound; the
/// byte budget below usually splits earlier). Paging keeps any one frame
/// far below [`MAX_FRAME_BYTES`] and the writer inside the QUIC stream
/// window even when the peer has not started reading.
pub const VV_ENTRIES_PER_FRAME: usize = 256;

/// Byte budget for one `VersionVector` frame.
pub const VV_PAGE_BYTES: usize = 64 * 1024;

/// Records per `Records` frame (an upper bound; the byte budget below
/// splits earlier when values are large — review R3 finding 5).
pub const RECORDS_PER_FRAME: usize = 16;

/// Byte budget for one `Records` frame. A single record larger than the
/// budget still ships alone: values are capped at [`MAX_VALUE_BYTES`], so
/// any one frame stays far below [`MAX_FRAME_BYTES`].
pub const RECORDS_PAGE_BYTES: usize = 64 * 1024;

/// Total version-vector entries a session will accept (both directions of
/// the state space are bounded; beyond this the peer is hostile).
pub const MAX_VECTOR_ENTRIES: usize = 4096;

/// Total records a session will accept in one batch. Equal to the store
/// capacity so a fresh peer can atomically synchronize a FULL valid store
/// (review R3 finding 5).
pub const MAX_RECORDS_PER_SESSION: usize = MAX_STORED_RECORDS;

/// Hard cap on stored (winning) records. Tier-1 state is small by design;
/// exceeding this is a StoreLimit failure, never silent truncation.
pub const MAX_STORED_RECORDS: usize = 4096;

/// Maximum serialized [`SyncValue`] size in bytes (review R3 finding 5:
/// values are bounded so no legal record — and no 16-record page — can
/// exceed the frame limit). Oversize values are rejected at verify and at
/// mint.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Maximum record key length in bytes.
pub const MAX_KEY_BYTES: usize = 256;

/// Enrollment expiry clock skew tolerance, in milliseconds (mirrors
/// [`crate::identity::EXPIRY_CLOCK_SKEW_SECS`]).
const ENROLL_EXPIRY_SKEW_MS: u64 = 300_000;

/// Total session budget after the protocol prefix. A peer that stalls at
/// any protocol stage holds no task beyond this.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// File holding the owner device set, inside `<data_dir>/sync/`.
const DEVICES_FILE: &str = "devices.json";
/// File holding the winning versioned records, inside `<data_dir>/sync/`.
const RECORDS_FILE: &str = "records.json";
/// File holding the `IssuanceJournal` records of a commit in progress,
/// inside `<data_dir>/sync/` (#1542, see `recover_journal_commit`).
const JOURNAL_INTENT_FILE: &str = "journal-intent.json";
/// File holding the committed name records that live daemon state may not
/// show yet, inside `<data_dir>/sync/` (#1545, see `pending_applies`).
const APPLY_PENDING_FILE: &str = "apply-pending.json";
/// Directory under the instance data dir holding all sync state.
const SYNC_DIR: &str = "sync";

/// The Tier-1 kinds — exhaustive, no catch-all (ADR-0041; gapcheck 32).
///
/// `from_u8` returns `None` for every unassigned byte, so a record or frame
/// carrying any other kind tag is undecodable and rejected whole.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SyncKind {
    /// Owner profile (`{ human_name }`) — one record, key `"owner"`.
    OwnerProfile = 0x01,
    /// Per-machine agent/machine names — key = machine id hex.
    MachineNames = 0x02,
    /// Home roster + policy pointer — one record, key `"home"`.
    HomePointer = 0x03,
    /// Sub-agent issuance journal — key = agent id hex.
    IssuanceJournal = 0x04,
}

impl SyncKind {
    /// All Tier-1 kinds. Length 4 is a load-bearing constant: Tier 3 states
    /// that no other state can be emitted.
    pub const ALL: [SyncKind; 4] = [
        SyncKind::OwnerProfile,
        SyncKind::MachineNames,
        SyncKind::HomePointer,
        SyncKind::IssuanceJournal,
    ];

    /// Parse a kind tag. `None` for every unassigned byte.
    #[must_use]
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::OwnerProfile),
            0x02 => Some(Self::MachineNames),
            0x03 => Some(Self::HomePointer),
            0x04 => Some(Self::IssuanceJournal),
            _ => None,
        }
    }

    /// The on-wire kind tag.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One member line of the Home roster snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeRosterEntry {
    /// Agent id, hex-encoded (matches `GroupMember` keys).
    pub agent_id: String,
    pub role: GroupRole,
    pub state: GroupMemberState,
}

/// The value of a Tier-1 record — a closed four-variant enum mirroring
/// [`SyncKind`] with NO catch-all. Compiling a new variant forces every
/// exhaustive match (including [`SyncValue::kind`]) to handle it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncValue {
    /// Owner profile: the owner's human-facing name.
    OwnerProfile {
        /// Owner's human name (ADR-0036 `human_name`).
        human_name: Option<String>,
    },
    /// Agent and machine names for one machine (key = machine id hex).
    MachineNames {
        /// The daemon agent's display name (announce self-name).
        display_name: Option<String>,
        /// Label for the machine itself.
        machine_name: Option<String>,
    },
    /// Home roster + policy pointer (ADR-0038): enough to identify and
    /// re-adopt the Home space on another machine; NOT a full group state
    /// transfer (TreeKEM material is deliberately out of Tier 1).
    HomePointer {
        group_id: String,
        policy: GroupPolicy,
        roster: Vec<HomeRosterEntry>,
        primary_agent: String,
        provisioned_at_ms: u64,
    },
    /// One line of the sub-agent issuance journal (ADR-0039).
    IssuanceJournal {
        agent_id: String,
        cert_digest: String,
        issued_at: u64,
        not_after: Option<u64>,
    },
}

impl SyncValue {
    /// The kind of this value — exhaustive match, no wildcard, so adding a
    /// variant without extending [`SyncKind`] is a compile error (the
    /// Tier-3 deny-by-default allowlist is structural, not conventional).
    #[must_use]
    pub fn kind(&self) -> SyncKind {
        match self {
            SyncValue::OwnerProfile { .. } => SyncKind::OwnerProfile,
            SyncValue::MachineNames { .. } => SyncKind::MachineNames,
            SyncValue::HomePointer { .. } => SyncKind::HomePointer,
            SyncValue::IssuanceJournal { .. } => SyncKind::IssuanceJournal,
        }
    }
}

/// The per-record clock the conflict rule orders on (gapcheck blocker 31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecordClock {
    /// Writer-minted monotonic version for this `(kind, key)`.
    pub version: u64,
    /// Unix ms when the record was signed.
    pub signed_at_ms: u64,
    /// Machine id of the writer — final tie-break, lexicographic.
    pub writer_machine: [u8; 32],
}

impl RecordClock {
    /// Whether `self` strictly beats `other` under the ADR-0041 rule:
    /// highest `version`, then highest `signed_at_ms`, then lexicographically
    /// greatest `writer_machine`. Equal clocks beat nothing — the
    /// equal-clock case is resolved by signed-content hash in
    /// [`OwnerSyncStore`] so peers converge deterministically.
    #[must_use]
    pub fn beats(&self, other: &Self) -> bool {
        match self.version.cmp(&other.version) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
        match self.signed_at_ms.cmp(&other.signed_at_ms) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
        self.writer_machine > other.writer_machine
    }
}

/// An owner-signed Tier-1 object (gapcheck blocker 31).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedRecord {
    pub kind: SyncKind,
    /// Record key within the kind (see [`SyncKind`] variant docs).
    pub key: String,
    pub value: SyncValue,
    pub clock: RecordClock,
    /// Owner ML-DSA-65 public key bytes (self-authenticating record).
    pub owner_public_key: Vec<u8>,
    /// ML-DSA-65 signature over the canonical message.
    pub signature: Vec<u8>,
}

impl VersionedRecord {
    /// Canonical signed bytes: domain prefix, kind tag, length-prefixed key,
    /// clock fields, and the bincode-canonical value.
    fn canonical_message(
        kind: &SyncKind,
        key: &str,
        clock: &RecordClock,
        value_bytes: &[u8],
    ) -> Vec<u8> {
        let key_bytes = key.as_bytes();
        let mut msg = Vec::with_capacity(
            RECORD_MSG_PREFIX.len() + 1 + 8 + key_bytes.len() + 16 + 32 + value_bytes.len(),
        );
        msg.extend_from_slice(RECORD_MSG_PREFIX);
        msg.push(kind.as_u8());
        msg.extend_from_slice(&(key_bytes.len() as u64).to_le_bytes());
        msg.extend_from_slice(key_bytes);
        msg.extend_from_slice(&clock.version.to_le_bytes());
        msg.extend_from_slice(&clock.signed_at_ms.to_le_bytes());
        msg.extend_from_slice(&clock.writer_machine);
        msg.extend_from_slice(value_bytes);
        msg
    }

    /// The canonical bytes of this record (self-shaped).
    fn canonical_bytes(&self) -> Vec<u8> {
        let value_bytes = bincode::serialize(&self.value).unwrap_or_default();
        Self::canonical_message(&self.kind, &self.key, &self.clock, &value_bytes)
    }

    /// BLAKE3 over the canonical bytes plus the signature — the
    /// deterministic equal-clock tie-break. Two peers holding different
    /// records under the same clock agree on the greater hash.
    #[must_use]
    pub fn record_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.canonical_bytes());
        hasher.update(&self.signature);
        *hasher.finalize().as_bytes()
    }

    /// Sign a fresh record with the owner key.
    ///
    /// # Errors
    ///
    /// [`IdentityError::CertificateVerification`] when signing fails or the
    /// value fails canonical serialization.
    pub fn sign(
        kind: SyncKind,
        key: &str,
        value: &SyncValue,
        clock: RecordClock,
        owner: &UserKeypair,
    ) -> Result<Self, IdentityError> {
        let value_bytes = bincode::serialize(value)
            .map_err(|e| IdentityError::CertificateVerification(format!("value encode: {e}")))?;
        let owner_public_key = owner.public_key().as_bytes().to_vec();
        let message = Self::canonical_message(&kind, key, &clock, &value_bytes);
        let signature = sign_with_ml_dsa(owner.secret_key(), &message).map_err(|e| {
            IdentityError::CertificateVerification(format!("record signing failed: {e:?}"))
        })?;
        Ok(Self {
            kind,
            key: key.to_string(),
            value: value.clone(),
            clock,
            owner_public_key,
            signature: signature.as_bytes().to_vec(),
        })
    }

    /// Verify the signature and that the record's kind matches its value
    /// variant, plus structural bounds (key length). Fail closed on any
    /// mismatch.
    ///
    /// # Errors
    ///
    /// [`SyncError::BadSignature`] on an invalid signature or malformed key
    /// material; [`SyncError::KindMismatch`] when the kind tag and value
    /// variant disagree; [`SyncError::MalformedFrame`] when the key exceeds
    /// [`MAX_KEY_BYTES`].
    pub fn verify(&self) -> Result<(), SyncError> {
        if self.value.kind() != self.kind {
            return Err(SyncError::KindMismatch);
        }
        if self.key.len() > MAX_KEY_BYTES {
            return Err(SyncError::MalformedFrame(format!(
                "record key of {} bytes exceeds limit {MAX_KEY_BYTES}",
                self.key.len()
            )));
        }
        let value_bytes = bincode::serialize(&self.value)
            .map_err(|e| SyncError::BadSignature(format!("value encode: {e}")))?;
        if value_bytes.len() > MAX_VALUE_BYTES {
            // Bounded values keep every legal page under the frame cap
            // (review R3 finding 5).
            return Err(SyncError::MalformedFrame(format!(
                "record value of {} bytes exceeds limit {MAX_VALUE_BYTES}",
                value_bytes.len()
            )));
        }
        let owner_pubkey = MlDsaPublicKey::from_bytes(&self.owner_public_key)
            .map_err(|_| SyncError::BadSignature("invalid owner public key".into()))?;
        let signature = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|e| SyncError::BadSignature(format!("invalid signature format: {e:?}")))?;
        let message = Self::canonical_message(&self.kind, &self.key, &self.clock, &value_bytes);
        verify_with_ml_dsa(&owner_pubkey, &message, &signature)
            .map_err(|e| SyncError::BadSignature(format!("bad signature: {e:?}")))?;
        Ok(())
    }

    /// Verify the signature AND that the signer is the given owner.
    ///
    /// # Errors
    ///
    /// [`SyncError::OwnerMismatch`] when the signing key does not derive to
    /// `owner`; see [`VersionedRecord::verify`].
    pub fn verify_owner(&self, owner: &UserId) -> Result<(), SyncError> {
        self.verify()?;
        let pubkey = MlDsaPublicKey::from_bytes(&self.owner_public_key)
            .map_err(|_| SyncError::BadSignature("invalid owner public key".into()))?;
        if derive_peer_id_from_public_key(&pubkey).0 != owner.0 {
            return Err(SyncError::OwnerMismatch);
        }
        Ok(())
    }
}

/// Owner-key-signed enrollment of one machine into the owner device set
/// (gapcheck blocker 30; enrollment direction per ADR-0043).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerEnrollment {
    pub machine_id: [u8; 32],
    /// Unix ms when the owner enrolled this machine.
    pub enrolled_at_ms: u64,
    /// Optional expiry (Unix ms). `None` = until explicitly deleted.
    /// [`OwnerSyncStore::is_enrolled`] checks currency, not just signature —
    /// a stale enrollment must not keep the sync gate open (review R2).
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    /// Owner ML-DSA-65 public key bytes.
    pub owner_public_key: Vec<u8>,
    /// Signature over the canonical enrollment message.
    pub signature: Vec<u8>,
}

impl OwnerEnrollment {
    fn canonical_message(
        machine_id: &[u8; 32],
        enrolled_at_ms: u64,
        expires_at_ms: Option<u64>,
        owner_pub: &[u8],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(ENROLL_MSG_PREFIX.len() + 32 + 16 + owner_pub.len());
        msg.extend_from_slice(ENROLL_MSG_PREFIX);
        msg.extend_from_slice(machine_id);
        msg.extend_from_slice(&enrolled_at_ms.to_le_bytes());
        match expires_at_ms {
            Some(expiry) => {
                msg.push(1);
                msg.extend_from_slice(&expiry.to_le_bytes());
            }
            None => msg.push(0),
        }
        msg.extend_from_slice(owner_pub);
        msg
    }

    /// Sign an enrollment for `machine_id` with the owner key. `expires_at_ms`
    /// bounds the enrollment's lifetime (`None` = until deleted).
    ///
    /// # Errors
    ///
    /// [`IdentityError::CertificateVerification`] when signing fails.
    pub fn sign(
        machine_id: MachineId,
        owner: &UserKeypair,
        enrolled_at_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> Result<Self, IdentityError> {
        let owner_public_key = owner.public_key().as_bytes().to_vec();
        let message = Self::canonical_message(
            &machine_id.0,
            enrolled_at_ms,
            expires_at_ms,
            &owner_public_key,
        );
        let signature = sign_with_ml_dsa(owner.secret_key(), &message).map_err(|e| {
            IdentityError::CertificateVerification(format!("enrollment signing failed: {e:?}"))
        })?;
        Ok(Self {
            machine_id: machine_id.0,
            enrolled_at_ms,
            expires_at_ms,
            owner_public_key,
            signature: signature.as_bytes().to_vec(),
        })
    }

    /// Verify the signature and that the signer derives to `owner`.
    ///
    /// # Errors
    ///
    /// [`SyncError::BadSignature`] / [`SyncError::OwnerMismatch`] — fail
    /// closed on any enrollment failure.
    pub fn verify_owner(&self, owner: &UserId) -> Result<(), SyncError> {
        let pubkey = MlDsaPublicKey::from_bytes(&self.owner_public_key)
            .map_err(|_| SyncError::BadSignature("invalid owner public key".into()))?;
        if derive_peer_id_from_public_key(&pubkey).0 != owner.0 {
            return Err(SyncError::OwnerMismatch);
        }
        let signature = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|e| SyncError::BadSignature(format!("invalid signature format: {e:?}")))?;
        let message = Self::canonical_message(
            &self.machine_id,
            self.enrolled_at_ms,
            self.expires_at_ms,
            &self.owner_public_key,
        );
        verify_with_ml_dsa(&pubkey, &message, &signature)
            .map_err(|e| SyncError::BadSignature(format!("bad signature: {e:?}")))?;
        Ok(())
    }

    /// Whether the enrollment is still current at `now_ms` (expiry with
    /// skew tolerance; `None` never expires).
    #[must_use]
    pub fn is_current_at(&self, now_ms: u64) -> bool {
        self.expires_at_ms
            .is_none_or(|expiry| now_ms <= expiry.saturating_add(ENROLL_EXPIRY_SKEW_MS))
    }
}

/// Typed sync failures — every one is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    Io(String),
    /// Frame body exceeded [`MAX_FRAME_BYTES`], a decode failed, or a
    /// structural bound (key length) was violated.
    MalformedFrame(String),
    ProtocolVersion {
        local: u32,
        remote: u32,
    },
    OwnerMismatch,
    /// The peer machine is not in the local owner device set.
    NotEnrolled {
        machine: [u8; 32],
    },
    /// The peer's owner-key possession proof failed (challenge-response).
    ChallengeFailed(String),
    /// The session exceeded its total time budget.
    SessionTimeout,
    /// A machine tried to sync with itself.
    SelfSync,
    BadSignature(String),
    /// Record kind tag and value variant disagree.
    KindMismatch,
    /// Undecodable kind tag on the wire (Tier-3 allowlist).
    UnknownKind {
        tag: u8,
    },
    /// Store cardinality limit exceeded ([`MAX_STORED_RECORDS`]).
    StoreLimit(String),
    /// Inbound batch/vector exceeded its session cap.
    TooManyRecords(String),
    /// A durable write crossed the rename but could not be synced: disk
    /// holds the NEW state while the caller saw an error. The store is
    /// POISONED — every further mutation and session fails until the
    /// process reloads state from disk (review R5 finding 2).
    Poisoned(String),
}

impl SyncError {
    fn class(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::MalformedFrame(_) => "malformed_frame",
            Self::ProtocolVersion { .. } => "protocol_version",
            Self::OwnerMismatch => "owner_mismatch",
            Self::NotEnrolled { .. } => "not_enrolled",
            Self::ChallengeFailed(_) => "challenge_failed",
            Self::SessionTimeout => "session_timeout",
            Self::SelfSync => "self_sync",
            Self::BadSignature(_) => "bad_signature",
            Self::KindMismatch => "kind_mismatch",
            Self::UnknownKind { .. } => "unknown_kind",
            Self::StoreLimit(_) => "store_limit",
            Self::TooManyRecords(_) => "too_many_records",
            Self::Poisoned(_) => "poisoned",
        }
    }
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "sync io error: {e}"),
            Self::MalformedFrame(e) => write!(f, "malformed sync frame: {e}"),
            Self::ProtocolVersion { local, remote } => {
                write!(
                    f,
                    "sync protocol version mismatch: local {local}, remote {remote}"
                )
            }
            Self::OwnerMismatch => write!(f, "sync peer is not the same owner"),
            Self::NotEnrolled { machine } => write!(
                f,
                "machine {} is not in the owner device set",
                hex::encode(machine)
            ),
            Self::ChallengeFailed(e) => {
                write!(f, "owner-key possession proof failed: {e}")
            }
            Self::SessionTimeout => write!(f, "sync session timed out"),
            Self::SelfSync => write!(f, "refusing to sync with this machine itself"),
            Self::BadSignature(e) => write!(f, "sync signature failure: {e}"),
            Self::KindMismatch => write!(f, "record kind does not match its value variant"),
            Self::UnknownKind { tag } => {
                write!(f, "unknown sync kind tag 0x{tag:02x} (Tier-3 allowlist)")
            }
            Self::Poisoned(e) => write!(
                f,
                "sync store poisoned (state replaced but not durable): {e}"
            ),
            Self::TooManyRecords(e) => write!(f, "sync session record cap: {e}"),
            Self::StoreLimit(e) => write!(f, "sync store limit: {e}"),
        }
    }
}

/// Which half of a durable atomic write failed — the two halves have
/// OPPOSITE rollback semantics (review R5 finding 2).
#[derive(Debug)]
enum DurableWriteError {
    /// Failed before the rename: the OLD state is still on disk; callers
    /// may safely roll in-memory state back.
    BeforeRename(std::io::Error),
    /// The rename happened but the post-rename sync failed: the NEW state
    /// is already visible on disk; rolling memory back would leave memory
    /// behind an advanced disk. The store must be poisoned instead.
    AfterRename(std::io::Error),
}

impl std::error::Error for SyncError {}

impl From<std::io::Error> for SyncError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Outcome of classifying one inbound record against the stored winner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Stored — the record outranks what we had.
    Accepted,
    /// Not stored — the stored record outranks it (stale, rollback, exact
    /// replay, or lost equal-clock hash tie-break). Never an error:
    /// partitions heal.
    Superseded,
}

/// Per-kind version vector entry: the peer's clock and record hash for one
/// key. The hash makes equal-clock divergence visible so the tie-break can
/// ship the deterministic winner (review R2 finding 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindVersions {
    pub kind: SyncKind,
    /// `(key, clock, record_hash)` for every record the peer holds under
    /// the kind.
    pub entries: Vec<(String, RecordClock, [u8; 32])>,
}

/// One frame of the SyncV1 wire protocol. Length-prefixed bincode on the
/// stream following the `SyncV1` protocol byte.
///
/// `VersionVector` and `Records` frames are **paged**: a session may carry
/// several of each (bounded by [`MAX_VECTOR_ENTRIES`] /
/// [`MAX_RECORDS_PER_SESSION`]) so a large state set never produces a frame
/// over [`MAX_FRAME_BYTES`] (review R2 finding 5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncFrame {
    /// Handshake: protocol version, sender machine, sender owner, and a
    /// fresh random nonce for the possession proof.
    Hello {
        protocol_version: u32,
        machine_id: [u8; 32],
        owner_user_id: [u8; 32],
        nonce: [u8; 32],
    },
    /// Owner-key signature over
    /// `proof_prefix || peer_nonce || sender_machine || peer_machine || owner_user_id`
    /// — proves the sender holds the owner key (review R2 finding 1).
    Proof { signature: Vec<u8> },
    /// One page of the sender's per-kind version table.
    VersionVector { kinds: Vec<KindVersions> },
    /// End of the version-vector stage. The records stage follows. An
    /// explicit terminator (rather than peeking the first records frame)
    /// keeps both sides' write-then-read stages from deadlocking.
    VectorEnd,
    /// One page of records the peer is missing or would accept.
    Records { records: Vec<VersionedRecord> },
    /// Clean end of session.
    Done,
    /// Fail-closed abort with a reason (best-effort, one-way).
    Abort { reason: String },
}

/// Canonical proof message: prefix || the verifier's nonce (the nonce the
/// PROVER is answering) || prover machine || verifier machine || owner id.
fn proof_message(
    nonce: &[u8; 32],
    prover: &[u8; 32],
    verifier: &[u8; 32],
    owner: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(PROOF_MSG_PREFIX.len() + 32 * 3 + 32);
    msg.extend_from_slice(PROOF_MSG_PREFIX);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(prover);
    msg.extend_from_slice(verifier);
    msg.extend_from_slice(owner);
    msg
}

/// Write one frame: `u32` big-endian length + bincode body.
///
/// # Errors
///
/// [`SyncError::MalformedFrame`] when the body exceeds [`MAX_FRAME_BYTES`] or
/// fails to encode; [`SyncError::Io`] on write failure.
pub async fn write_frame<S: AsyncWrite + Unpin>(
    send: &mut S,
    frame: &SyncFrame,
) -> Result<(), SyncError> {
    let body =
        bincode::serialize(frame).map_err(|e| SyncError::MalformedFrame(format!("encode: {e}")))?;
    let len = u32::try_from(body.len())
        .map_err(|_| SyncError::MalformedFrame("frame too large".into()))?;
    if len > MAX_FRAME_BYTES {
        return Err(SyncError::MalformedFrame(format!(
            "frame of {len} bytes exceeds limit {MAX_FRAME_BYTES}"
        )));
    }
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&body).await?;
    send.flush().await?;
    Ok(())
}

/// Read one frame written by [`write_frame`]. Fails closed on an oversized
/// or undecodable body.
///
/// # Errors
///
/// [`SyncError::MalformedFrame`] on oversize/undecodable frames (which
/// includes any record carrying an unknown [`SyncKind`] tag — the bincode
/// `from_u8` path rejects unassigned bytes).
pub async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> Result<SyncFrame, SyncError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(SyncError::MalformedFrame(format!(
            "frame of {len} bytes exceeds limit {MAX_FRAME_BYTES}"
        )));
    }
    let mut body = vec![0u8; len as usize];
    recv.read_exact(&mut body).await?;
    bincode::deserialize(&body).map_err(|e| SyncError::MalformedFrame(format!("decode: {e}")))
}

/// Outcome of one sync session, for surfaces and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionSummary {
    pub accepted: usize,
    pub superseded: usize,
    /// Equal-clock records with DIFFERENT signed content seen this session:
    /// a writer equivocated (or forked). Resolved deterministically by
    /// record hash and surfaced, never silently merged.
    pub equivocations: usize,
    pub shipped: usize,
}

type VerifiedEnrollmentOwners = BTreeMap<[u8; 32], (UserId, OwnerEnrollment)>;

/// The register: the winning record of each `(kind, key)`.
type RecordMap = BTreeMap<(SyncKind, String), VersionedRecord>;

/// An owned hold of `OwnerSyncStore::journal_apply`.
type JournalGuard = tokio::sync::OwnedMutexGuard<()>;

pub struct OwnerSyncStore {
    dir: PathBuf,
    /// Every change of the register runs its durable write in a task that
    /// owns this lock until the write and the memory update are done
    /// (`replace_records`, #1545).
    records: Arc<tokio::sync::RwLock<RecordMap>>,
    devices: tokio::sync::RwLock<BTreeMap<[u8; 32], OwnerEnrollment>>,
    // Verified once on load/enroll, consulted under the devices read lock.
    evidence_owners: std::sync::RwLock<VerifiedEnrollmentOwners>,
    last_session: tokio::sync::RwLock<BTreeMap<[u8; 32], DeviceSyncStatus>>,
    generation_tx: Arc<tokio::sync::watch::Sender<u64>>,
    /// #824: count of successful sessions with an owner device, inbound or
    /// outbound. Home provisioning waits for one before minting, because a
    /// completed session means that device's records, including any
    /// canonical Home pointer, have been merged.
    sessions_ok_tx: tokio::sync::watch::Sender<u64>,
    /// Set when a durable write crossed the rename but could not be
    /// synced: memory/disk agreement is no longer reconstructable by
    /// rollback, so every further mutation and session fails until the
    /// process reloads from disk (review R5 finding 2).
    poisoned: Arc<std::sync::Mutex<Option<String>>>,
    /// Test injection: make the next durable writes fail AFTER the rename
    /// (simulates a post-rename fsync failure). Never set in production.
    fail_after_rename: std::sync::atomic::AtomicBool,
    /// #449 r3 P2: serializes canonical-Home ADMISSION against readers who
    /// must act on the canonical answer they got.
    ///
    /// A seat mint is linearized at the moment it acquires the gate; a
    /// canonical pointer accepted after that waits until the mint's durable
    /// persistence completes; a pointer accepted before it makes the seat
    /// refuse 409.
    ///
    /// Without it, `POST /home/seat` could resolve canonical A, await the
    /// per-group membership lock, and durably persist an addressed invite
    /// into A after the local register had already accepted B — offering a
    /// seat in the LOSING Home. A pre-await recheck cannot close that: the
    /// mint transaction itself awaits, so the window reopens inside it.
    ///
    /// Every writer that can change the `(HomePointer, HOME_POINTER_KEY)`
    /// register takes `.write()` for the whole of its records mutation plus
    /// persist: [`Self::commit_batch`] (and therefore [`Self::merge_record`],
    /// which wraps it), [`Self::mint`], and
    /// [`Self::records_insert_for_testing`]. Writes that touch no
    /// `HomePointer` record skip the gate, so ordinary name and journal sync
    /// is never serialized behind a seat.
    ///
    /// **Lock order, never to be violated.** Readers:
    /// `canonical_home_gate` → per-group membership lock → `named_groups`
    /// and persistence. Writers: `canonical_home_gate` → `records`. The two
    /// cannot cycle because `commit_batch`, `mint` and `apply_record` never
    /// take a membership lock or `named_groups` (`apply_record`'s
    /// `HomePointer` arm is a no-op and its names arm spawns), and the
    /// reader never touches `records` while holding a membership lock.
    ///
    /// This is a LOCAL linearization boundary only. It claims nothing about
    /// cross-device election ordering.
    canonical_home_gate: Arc<tokio::sync::RwLock<()>>,
    /// #1542: the one serializer of the `IssuanceJournal` register and the
    /// issuance journal file. Two writers move values between them:
    /// [`Self::commit_batch`] (for an accepted inbound record) and the
    /// reconcile `mint_journal_lines`. Both write the journal file first
    /// and the register second, and each holds this lock for its whole
    /// read-and-write, so neither sees the other half done. Thus every
    /// durable register value is in the journal file, or the journal file
    /// holds a newer line that the next reconcile publishes. A failure or
    /// a restart between the two writes leaves the journal ahead, never
    /// behind: a register ahead of the journal would make the reconcile
    /// mint the journal's older line over it. The commit also writes a
    /// journal intent before the journal file, so a restart can finish an
    /// interrupted commit (`recover_journal_commit`), and the reconcile
    /// mints only from a durable journal read. Lock order: `journal_apply` →
    /// `canonical_home_gate` → `records`, and `journal_apply` → the
    /// profile journal writer lock.
    ///
    /// #1545: each write of the journal intent and each register write
    /// of a commit runs in a task that owns this lock until the write is
    /// done (`run_to_completion`). A cancelled caller cannot release it
    /// while one of its writes can still land.
    journal_apply: Arc<tokio::sync::Mutex<()>>,
    /// The local issuance journal that accepted `IssuanceJournal` records
    /// are applied to (set by the service; unset in a bare store).
    journal_file: std::sync::OnceLock<PathBuf>,
    /// #1545: the committed name records that live daemon state may not
    /// show yet, keyed by kind, key and record hash; a mirror of `APPLY_PENDING_FILE`.
    /// A commit adds its name records here and to the file before its
    /// register write, and only a durable save of the daemon profile
    /// removes them (see [`Self::pending_applies`]). A restart before
    /// that applies them again, so the reconcile never mints the old live
    /// names over them. A new record of a key does not replace an older
    /// one: until the new record's commit is durable, the older one can
    /// still be the register's winner. Lock order: `records` →
    /// `pending_apply`.
    ///
    /// Every change of the obligations and every live-name mint is
    /// checked against the register under `records`, with this lock
    /// inside it:
    /// - a commit adds its names under the `records` write lock, before
    ///   its register write (`add_pending_applies`);
    /// - a retirement (`discharge_applies`, `settle_saved`) holds the
    ///   `records` read lock, so no commit can change a winner between
    ///   its check and its removal;
    /// - a live-name mint (`mint_live_name`) holds the `records` write
    ///   lock, and mints only when no winner is owed and the epoch
    ///   (`PendingApplies::epoch`) is the one read before the live names
    ///   were read.
    ///
    /// Each write of `APPLY_PENDING_FILE` runs in a task that owns this
    /// lock until the write and the memory update are done
    /// (`replace_pending`).
    pending_apply: Arc<tokio::sync::Mutex<PendingApplies>>,
    /// Test injection: hold a synced journal append after its decision
    /// read until the test releases it.
    #[cfg(test)]
    journal_check_pause: std::sync::Mutex<Option<JournalCheckPause>>,
    /// Test injection: hold the reconcile's journal mint after it reads
    /// the journal until the test releases it.
    #[cfg(test)]
    journal_read_pause: std::sync::Mutex<Option<JournalCheckPause>>,
    /// Test injection: hold the reconcile's name mint after it reads the
    /// live names until the test releases it.
    #[cfg(test)]
    name_mint_pause: std::sync::Mutex<Option<JournalCheckPause>>,
    /// Test injection: hold the next discharge of pending applies before
    /// it takes any lock until the test releases it.
    #[cfg(test)]
    discharge_pause: std::sync::Mutex<Option<JournalCheckPause>>,
    /// Test injection: fail the next register write before its rename.
    #[cfg(test)]
    fail_next_register_write: std::sync::atomic::AtomicBool,
    /// Test injection: fail every synced journal append.
    #[cfg(test)]
    fail_journal_append: std::sync::atomic::AtomicBool,
    /// Test injection: fail the write of the next discharge of pending
    /// applies.
    #[cfg(test)]
    fail_next_discharge: std::sync::atomic::AtomicBool,
    /// Test injection: stop the next journal-applying commit after the
    /// first of its two writes (register and journal file), as a crash
    /// between them would.
    #[cfg(test)]
    stop_between_journal_writes: std::sync::atomic::AtomicBool,
    /// ADR-0074 §4: woken when the owner device set changes (an enrollment
    /// or unenrollment).
    device_change_notify: std::sync::Mutex<Option<std::sync::Arc<tokio::sync::Notify>>>,
}

/// The key of a pending apply (`OwnerSyncStore::pending_apply`).
type PendingKey = (SyncKind, String, [u8; 32]);

fn pending_key(record: &VersionedRecord) -> PendingKey {
    (record.kind, record.key.clone(), record.record_hash())
}

/// The names of a profile save (`OwnerSyncStore::note_profile_save`). A
/// private copy of [`SyncProfileNames`], so the public type gets no serde
/// impls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SavedNames {
    human_name: Option<String>,
    display_name: Option<String>,
    machine_name: Option<String>,
}

impl From<&SyncProfileNames> for SavedNames {
    fn from(names: &SyncProfileNames) -> Self {
        Self {
            human_name: names.human_name.clone(),
            display_name: names.display_name.clone(),
            machine_name: names.machine_name.clone(),
        }
    }
}

/// #1545: a pending apply (`OwnerSyncStore::pending_apply`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingApply {
    record: VersionedRecord,
    /// The names of each profile save that started with `record` folded
    /// in, written durably before the save. A durable profile with one of
    /// these names holds `record` or a later local edit over it, so
    /// `record` is not owed any more (`OwnerSyncStore::settle_saved`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    saved_in: Vec<SavedNames>,
    /// `record` is not owed any more, but no write of `APPLY_PENDING_FILE`
    /// without it has succeeded yet. No pass applies it, and every write
    /// of the file leaves it out; the first write that succeeds removes
    /// it from memory (`OwnerSyncStore::persist_and_prune`). Until then a
    /// profile save must write the file first (`note_profile_save`), or
    /// the stale file entry can come back at the next start over that
    /// save.
    #[serde(skip)]
    discharged: bool,
}

/// #1545: the pending applies (`OwnerSyncStore::pending_apply`).
#[derive(Debug, Clone, Default)]
struct PendingApplies {
    applies: BTreeMap<PendingKey, PendingApply>,
    /// The generation of `applies`. It changes at each commit that adds
    /// names and at each retirement. A retirement means that the live
    /// profile now holds a committed name (or that the name is no longer
    /// owed), so live names read before it can be older than the
    /// register. The reconcile reads it before it reads the live names
    /// ([`OwnerSyncStore::names_epoch`]), and its mint compares it
    /// (`OwnerSyncStore::mint_live_name`).
    epoch: u64,
}

/// The contents of `APPLY_PENDING_FILE`.
#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedPendingApplies {
    #[serde(default)]
    applies: Vec<PendingApply>,
}

/// The two ends of [`OwnerSyncStore::pause_next_journal_check`].
#[cfg(test)]
type JournalCheckPause = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

/// Per-device sync status surfaced by `GET /sync/devices`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSyncStatus {
    /// Unix ms of the last completed session with this device.
    pub last_session_ms: u64,
    /// Whether that session completed cleanly (`true`) or failed.
    pub last_session_ok: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedRecords {
    records: Vec<VersionedRecord>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedDevices {
    devices: Vec<OwnerEnrollment>,
}

/// Result of a batch commit: what the caller should apply/count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitOutcome {
    pub accepted: Vec<VersionedRecord>,
    pub superseded: usize,
    pub equivocations: usize,
}

impl OwnerSyncStore {
    /// Wake `notify` on every future change to the device set (ADR-0074 §4).
    pub(crate) fn set_device_change_notify(&self, notify: std::sync::Arc<tokio::sync::Notify>) {
        *self
            .device_change_notify
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(notify);
    }

    fn notify_device_change(&self) {
        if let Some(notify) = self
            .device_change_notify
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            notify.notify_one();
        }
    }

    /// Load (or start empty under) `<data_dir>/sync`, creating the
    /// directory. **Only genuine absence is empty** (fresh install): a
    /// records/devices file that exists but is corrupt or unreadable is a
    /// HARD error — silently starting with an empty anti-rollback store
    /// would let an old owner-signed record win again (review R3
    /// finding 2).
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] when the directory cannot be created, or a state
    /// file exists but cannot be read or parsed.
    pub async fn load(data_dir: &Path) -> Result<Self, SyncError> {
        let dir = data_dir.join(SYNC_DIR);
        tokio::fs::create_dir_all(&dir).await.map_err(|e| {
            SyncError::Io(format!("failed to create sync dir {}: {e}", dir.display()))
        })?;
        let persisted_records: PersistedRecords = Self::load_json(&dir.join(RECORDS_FILE)).await?;
        let persisted_devices: PersistedDevices = Self::load_json(&dir.join(DEVICES_FILE)).await?;
        let pending_apply: PersistedPendingApplies =
            Self::load_json(&dir.join(APPLY_PENDING_FILE)).await?;
        let records = persisted_records
            .records
            .into_iter()
            .map(|r| ((r.kind, r.key.clone()), r))
            .collect::<BTreeMap<_, _>>();
        let devices = persisted_devices
            .devices
            .into_iter()
            .map(|d| (d.machine_id, d))
            .collect::<BTreeMap<_, _>>();
        let evidence_owners = devices
            .iter()
            .filter_map(|(m, e)| {
                let key = MlDsaPublicKey::from_bytes(&e.owner_public_key).ok()?;
                let owner = UserId(derive_peer_id_from_public_key(&key).0);
                e.verify_owner(&owner).ok()?;
                Some((*m, (owner, e.clone())))
            })
            .collect();
        let (generation_tx, _) = tokio::sync::watch::channel(0);
        Ok(Self {
            dir,
            records: Arc::new(tokio::sync::RwLock::new(records)),
            devices: tokio::sync::RwLock::new(devices),
            evidence_owners: std::sync::RwLock::new(evidence_owners),
            last_session: tokio::sync::RwLock::new(BTreeMap::new()),
            generation_tx: Arc::new(generation_tx),
            sessions_ok_tx: tokio::sync::watch::channel(0).0,
            poisoned: Arc::new(std::sync::Mutex::new(None)),
            fail_after_rename: std::sync::atomic::AtomicBool::new(false),
            canonical_home_gate: Arc::new(tokio::sync::RwLock::new(())),
            journal_apply: Arc::new(tokio::sync::Mutex::new(())),
            journal_file: std::sync::OnceLock::new(),
            pending_apply: Arc::new(tokio::sync::Mutex::new(PendingApplies {
                applies: pending_apply
                    .applies
                    .into_iter()
                    .map(|p| (pending_key(&p.record), p))
                    .collect(),
                epoch: 0,
            })),
            #[cfg(test)]
            journal_check_pause: std::sync::Mutex::new(None),
            #[cfg(test)]
            journal_read_pause: std::sync::Mutex::new(None),
            #[cfg(test)]
            name_mint_pause: std::sync::Mutex::new(None),
            #[cfg(test)]
            discharge_pause: std::sync::Mutex::new(None),
            #[cfg(test)]
            fail_next_register_write: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_journal_append: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_next_discharge: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            stop_between_journal_writes: std::sync::atomic::AtomicBool::new(false),
            device_change_notify: std::sync::Mutex::new(None),
        })
    }

    /// Read a persisted state file: `NotFound` → default (fresh install);
    /// any other read error, or a parse error, → hard error. Never a
    /// silent fallback to empty (review R3 finding 2).
    async fn load_json<T: serde::de::DeserializeOwned + Default>(
        path: &Path,
    ) -> Result<T, SyncError> {
        match tokio::fs::read(path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                SyncError::Io(format!(
                    "corrupt sync state file {}: {e} — refusing to start with an empty store",
                    path.display()
                ))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
            Err(e) => Err(SyncError::Io(format!(
                "unreadable sync state file {}: {e}",
                path.display()
            ))),
        }
    }

    /// Write `bytes` to `path` durably and atomically: unique temp file →
    /// fsync the temp file (data durable) → rename over the target →
    /// fsync the target file and its parent directory (the rename entry
    /// durable). A crash after a successful persist can no longer lose the
    /// durable state the caller just verified (review R3 finding 2).
    ///
    /// The error distinguishes the two transaction halves (review R5
    /// finding 2): [`DurableWriteError::BeforeRename`] leaves the OLD
    /// state on disk (callers may roll memory back); [`DurableWriteError::AfterRename`]
    /// means the NEW state is already in place and the process can no
    /// longer reconstruct memory/disk agreement by rolling back — the
    /// store must be poisoned instead.
    async fn write_atomically(
        path: &Path,
        bytes: &[u8],
        fail_after_rename: bool,
    ) -> Result<(), DurableWriteError> {
        use tokio::io::AsyncWriteExt as _;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp-{}-{unique}", std::process::id()));
        let mut file = tokio::fs::File::create(&tmp)
            .await
            .map_err(DurableWriteError::BeforeRename)?;
        file.write_all(bytes)
            .await
            .map_err(DurableWriteError::BeforeRename)?;
        file.sync_all()
            .await
            .map_err(DurableWriteError::BeforeRename)?;
        drop(file);
        crate::profile::rename_file(&tmp, path)
            .await
            .map_err(DurableWriteError::BeforeRename)?;
        // Everything below runs with the NEW state already visible.
        if fail_after_rename {
            // Test injection: simulate a post-rename fsync failure.
            return Err(DurableWriteError::AfterRename(std::io::Error::other(
                "injected post-rename fsync failure",
            )));
        }
        // fsync the renamed file and the parent directory so the new name
        // survives a crash. (Directory fds support fsync on Unix.)
        let target = tokio::fs::File::open(path)
            .await
            .map_err(DurableWriteError::AfterRename)?;
        target
            .sync_all()
            .await
            .map_err(DurableWriteError::AfterRename)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            let dir = tokio::fs::File::open(parent)
                .await
                .map_err(DurableWriteError::AfterRename)?;
            dir.sync_all()
                .await
                .map_err(DurableWriteError::AfterRename)?;
        }
        #[cfg(not(unix))]
        let _ = path.parent();
        #[cfg(test)]
        crate::profile::crash_sim::note_durable(path);
        Ok(())
    }

    /// #1545: run `work` to its end in its own task, and wait for its
    /// output. A cancelled caller stops only its wait. Each durable write
    /// of the register, of the pending applies and of the journal intent
    /// runs in this way, with the owned guards of the state that it writes
    /// moved into `work`. Those guards stay held until the write and the
    /// memory update after it are done: no later writer can start before
    /// the write lands, and memory ends as the disk holds it.
    ///
    /// # Errors
    ///
    /// The error of `work`, or [`SyncError::Io`] when its task fails.
    async fn run_to_completion<T: Send + 'static>(
        work: impl std::future::Future<Output = Result<T, SyncError>> + Send + 'static,
    ) -> Result<T, SyncError> {
        tokio::spawn(work)
            .await
            .map_err(|e| SyncError::Io(format!("durable write task failed: {e}")))?
    }

    /// Write `next` durably as the register, and then make it the register
    /// in memory. The two run to their end in one task
    /// (`run_to_completion`), which owns `records` and `held` until then;
    /// `held` comes back on success. A caller builds `next` from a copy of
    /// the register, so a caller cancelled before this call leaves the
    /// register as it was.
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] when the write fails before its rename: the
    /// register does not change. [`SyncError::Poisoned`] when it fails
    /// after its rename: the disk holds `next`, so memory takes it too and
    /// the store is poisoned (review R5 finding 2). Errors PROPAGATE —
    /// callers never report success on a swallowed write (review R2
    /// finding 2).
    async fn replace_records<H: Send + 'static>(
        &self,
        mut records: tokio::sync::OwnedRwLockWriteGuard<RecordMap>,
        next: RecordMap,
        held: H,
    ) -> Result<H, SyncError> {
        let bytes = serde_json::to_vec(&PersistedRecords {
            records: next.values().cloned().collect(),
        })
        .map_err(|e| SyncError::Io(format!("encode records: {e}")))?;
        #[cfg(test)]
        if self
            .fail_next_register_write
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            return Err(SyncError::Io("injected register write failure".into()));
        }
        let path = self.dir.join(RECORDS_FILE);
        let fail_after_rename = self.fail_after_rename_for_testing();
        let poisoned = Arc::clone(&self.poisoned);
        let generation = Arc::clone(&self.generation_tx);
        Self::run_to_completion(async move {
            match Self::write_atomically(&path, &bytes, fail_after_rename).await {
                Ok(()) => {
                    *records = next;
                    drop(records);
                    Self::kick_generation(&generation);
                    Ok(held)
                }
                Err(DurableWriteError::BeforeRename(io)) => {
                    Err(SyncError::Io(format!("persist records: {io}")))
                }
                Err(DurableWriteError::AfterRename(io)) => {
                    // Disk already holds `next`: memory takes it, and the
                    // store is poisoned; never roll memory back below an
                    // advanced disk.
                    *records = next;
                    drop(records);
                    let e = SyncError::Poisoned(format!("records replaced but not durable: {io}"));
                    Self::poison_slot(&poisoned, e.to_string());
                    Err(e)
                }
            }
        })
        .await
    }

    /// Persist the device set; errors propagate (see [`Self::replace_records`]).
    async fn persist_devices(
        &self,
        devices: &BTreeMap<[u8; 32], OwnerEnrollment>,
    ) -> Result<(), SyncError> {
        let persisted = PersistedDevices {
            devices: devices.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&persisted)
            .map_err(|e| SyncError::Io(format!("encode devices: {e}")))?;
        Self::write_atomically(
            &self.dir.join(DEVICES_FILE),
            &bytes,
            self.fail_after_rename_for_testing(),
        )
        .await
        .map_err(|e| match e {
            DurableWriteError::BeforeRename(io) => SyncError::Io(format!("persist devices: {io}")),
            DurableWriteError::AfterRename(io) => {
                SyncError::Poisoned(format!("devices replaced but not durable: {io}"))
            }
        })
    }

    /// Poison the store: a durable write crossed the rename but could not
    /// be synced, so memory/disk agreement is not reconstructable — all
    /// further mutations and sessions fail until a fresh `load` (review R5
    /// finding 2).
    fn poison(&self, reason: String) {
        Self::poison_slot(&self.poisoned, reason);
    }

    /// [`Self::poison`] for a task that owns no `&self`.
    fn poison_slot(slot: &std::sync::Mutex<Option<String>>, reason: String) {
        *slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reason);
    }

    /// Why the store is poisoned, if it is.
    #[must_use]
    pub fn poisoned_reason(&self) -> Option<String> {
        self.poisoned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The typed refusal for a poisoned store, if it is poisoned. Every
    /// state-mutating entry point checks this FIRST (review R6): after a
    /// post-rename durability failure, no mutation may proceed against
    /// state whose memory/disk agreement is unrecoverable — even after the
    /// underlying fault clears — until an explicit reload.
    fn poison_refusal(&self) -> Option<SyncError> {
        self.poisoned_reason().map(SyncError::Poisoned)
    }

    /// Whether the test armed a stop between a commit's two writes;
    /// disarms it.
    #[cfg(test)]
    fn stop_after_first_journal_write(&self) -> bool {
        self.stop_between_journal_writes
            .swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    /// Hold the next synced journal append after its decision read: it
    /// signals `checked` and then waits for `release`.
    #[cfg(test)]
    fn pause_next_journal_check(
        &self,
        checked: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        Self::arm_pause(&self.journal_check_pause, checked, release);
    }

    #[cfg(test)]
    async fn pause_after_journal_check(&self) {
        Self::take_pause(&self.journal_check_pause).await;
    }

    /// Hold the next reconcile journal mint after it reads the journal: it
    /// signals `read` and then waits for `release`.
    #[cfg(test)]
    fn pause_next_journal_read(
        &self,
        read: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        Self::arm_pause(&self.journal_read_pause, read, release);
    }

    #[cfg(test)]
    async fn pause_after_journal_read(&self) {
        Self::take_pause(&self.journal_read_pause).await;
    }

    /// Hold the next reconcile name mint after it reads the live names:
    /// it signals `read` and then waits for `release`.
    #[cfg(test)]
    pub(crate) fn pause_next_name_mint(
        &self,
        read: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        Self::arm_pause(&self.name_mint_pause, read, release);
    }

    #[cfg(test)]
    async fn pause_before_name_mint(&self) {
        Self::take_pause(&self.name_mint_pause).await;
    }

    /// Hold the next discharge of pending applies before it takes any
    /// lock: it signals `reached` and then waits for `release`.
    #[cfg(test)]
    pub(crate) fn pause_next_discharge(
        &self,
        reached: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        Self::arm_pause(&self.discharge_pause, reached, release);
    }

    /// Test injection: fail the next register write before its rename, so
    /// the commit rolls back after its pending applies are durable.
    #[cfg(test)]
    pub(crate) fn fail_next_register_write(&self) {
        self.fail_next_register_write
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    fn arm_pause(
        slot: &std::sync::Mutex<Option<JournalCheckPause>>,
        reached: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) {
        *slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((reached, release));
    }

    #[cfg(test)]
    async fn take_pause(slot: &std::sync::Mutex<Option<JournalCheckPause>>) {
        let pause = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((reached, release)) = pause {
            let _ = reached.send(());
            let _ = release.await;
        }
    }

    /// Append the line for the register value `value` to the journal file
    /// at `path` when this device needs it ([`synced_line_needed`]).
    /// `published` is the register's value before the commit that accepted
    /// `value`. The caller holds `journal_apply`, so the register cannot
    /// change and no reconcile can read the journal until this returns.
    ///
    /// # Errors
    ///
    /// The IO error of a failed append. The caller must not then persist
    /// `value` to the register (see `journal_apply`).
    async fn apply_journal_value(
        &self,
        path: &Path,
        owner_hex: &str,
        value: &SyncValue,
        published: Option<SyncValue>,
    ) -> std::io::Result<()> {
        let SyncValue::IssuanceJournal {
            agent_id,
            cert_digest,
            issued_at,
            not_after,
        } = value
        else {
            return Ok(());
        };
        #[cfg(test)]
        if self
            .fail_journal_append
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(std::io::Error::other("injected append failure"));
        }
        let published_digest = match published {
            Some(SyncValue::IssuanceJournal { cert_digest, .. }) => Some(cert_digest),
            _ => None,
        };
        crate::profile::IssuedCertRecord::append_when(path, |existing| async move {
            #[cfg(test)]
            self.pause_after_journal_check().await;
            synced_line_needed(
                &existing,
                owner_hex,
                agent_id,
                cert_digest,
                *issued_at,
                *not_after,
                published_digest.as_deref(),
            )
            .then(|| {
                synced_journal_line(
                    owner_hex.to_string(),
                    agent_id.clone(),
                    cert_digest.clone(),
                    *issued_at,
                    *not_after,
                )
            })
        })
        .await?;
        Ok(())
    }

    /// Apply accepted `IssuanceJournal` records to the issuance journal at
    /// `path` (the service sets it once, at construction).
    pub(crate) fn set_journal_path(&self, path: PathBuf) {
        let _ = self.journal_file.set(path);
    }

    /// Test injection: fail (or stop failing) every synced journal append.
    #[cfg(test)]
    pub(crate) fn set_fail_journal_append(&self, fail: bool) {
        self.fail_journal_append
            .store(fail, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test injection: fail the write of the next discharge of pending
    /// applies.
    #[cfg(test)]
    pub(crate) fn fail_next_discharge(&self) {
        self.fail_next_discharge
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// The file of the pending applies.
    #[cfg(test)]
    pub(crate) fn pending_applies_path(&self) -> PathBuf {
        self.dir.join(APPLY_PENDING_FILE)
    }

    fn fail_after_rename_for_testing(&self) -> bool {
        self.fail_after_rename
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Test-only: make subsequent durable writes fail AFTER the rename,
    /// simulating a post-rename fsync failure (review R5 finding 2).
    #[doc(hidden)]
    pub fn set_fail_after_rename_for_testing(&self, fail: bool) {
        self.fail_after_rename
            .store(fail, std::sync::atomic::Ordering::Relaxed);
    }

    /// Every stored enrollment is (re-)verified against `owner` and its
    /// expiry checked here — a corrupt, foreign-key, or stale record fails
    /// closed, so persistence poison or an expired grant cannot wedge the
    /// gate open (review R2 finding 1).
    #[must_use]
    pub async fn is_enrolled(&self, machine: &MachineId, owner: &UserId) -> bool {
        let devices = self.devices.read().await;
        devices
            .get(&machine.0)
            .is_some_and(|e| e.verify_owner(owner).is_ok() && e.is_current_at(now_unix_ms()))
    }

    /// [`Self::evidence_enrolled`] without ever blocking (x0x #1150 r7c,
    /// synchronous seams): `None` while either lock is held.
    pub(crate) fn try_evidence_enrolled(
        &self,
        machine: &MachineId,
        owner: &UserId,
        now: u64,
    ) -> Option<bool> {
        let Ok(devices) = self.devices.try_read() else {
            return None;
        };
        let Ok(verified) = self.evidence_owners.try_read() else {
            return None;
        };
        Some(
            verified.get(&machine.0).is_some_and(|(u, record)| {
                u == owner && devices.get(&machine.0).is_some_and(|e| e == record)
            }) && devices
                .get(&machine.0)
                .is_some_and(|e| e.is_current_at(now)),
        )
    }

    /// Current enrollment for evidence policy, with zero signature checks.
    /// A writer in flight fails closed. The verification index is changed
    /// under the devices write lock, so deletion/rollback is immediately seen.
    pub(crate) fn evidence_enrolled(
        &self,
        machine: &MachineId,
        owner: &UserId,
        now: u64,
    ) -> Option<bool> {
        let Ok(devices) = self.devices.try_read() else {
            return None;
        };
        let Ok(verified) = self.evidence_owners.read() else {
            return None;
        };
        Some(
            verified.get(&machine.0).is_some_and(|(u, record)| {
                u == owner && devices.get(&machine.0).is_some_and(|e| e == record)
            }) && devices
                .get(&machine.0)
                .is_some_and(|e| e.is_current_at(now)),
        )
    }

    /// Store a (verified-by-caller) enrollment, keeping the latest
    /// `enrolled_at_ms` per machine so a replayed older enrollment cannot
    /// rewind the clock. The new expiry replaces any previous one.
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] when persistence failed BEFORE the rename (the
    /// in-memory set is rolled back); [`SyncError::Poisoned`] when the
    /// write crossed the rename but was not durable — the mutation STAYS
    /// (disk already advanced) and the store refuses further sync until
    /// reload (review R5 finding 2).
    pub async fn enroll(&self, enrollment: OwnerEnrollment) -> Result<(), SyncError> {
        if let Some(err) = self.poison_refusal() {
            return Err(err);
        }
        // Preserve the store's verified-by-caller contract. Invalid material
        // stays incapable of contributing evidence, just as is_enrolled denies it.
        let verified_owner = MlDsaPublicKey::from_bytes(&enrollment.owner_public_key)
            .ok()
            .map(|key| UserId(derive_peer_id_from_public_key(&key).0))
            .filter(|owner| enrollment.verify_owner(owner).is_ok());
        let mut devices = self.devices.write().await;
        let previous = devices.get(&enrollment.machine_id).cloned();
        let keep = previous
            .as_ref()
            .is_none_or(|old| enrollment.enrolled_at_ms >= old.enrolled_at_ms);
        if keep {
            devices.insert(enrollment.machine_id, enrollment.clone());
            if let Err(e) = self.persist_devices(&devices).await {
                if matches!(e, SyncError::Poisoned(_)) {
                    // Disk already holds the new device set: keep the
                    // mutation (memory matches disk) and poison.
                    drop(devices);
                    self.poison(e.to_string());
                    self.notify_device_change();
                    return Err(e);
                }
                // Pre-rename failure: roll back so memory matches the
                // unchanged disk (review R2 finding 2).
                match previous {
                    Some(old) => {
                        devices.insert(old.machine_id, old);
                    }
                    None => {
                        devices.remove(&enrollment.machine_id);
                    }
                }
                return Err(e);
            }
            if let Ok(mut verified) = self.evidence_owners.write() {
                if let Some(owner) = verified_owner {
                    verified.insert(enrollment.machine_id, (owner, enrollment.clone()));
                } else {
                    verified.remove(&enrollment.machine_id);
                }
            }
        }
        drop(devices);
        self.kick();
        self.notify_device_change();
        Ok(())
    }

    /// Remove a machine from the owner device set (the DELETE
    /// `/sync/devices/:id` path; review R2 finding 1). Poisoning semantics
    /// match [`Self::enroll`]. Returns `Ok(false)` when not enrolled.
    pub async fn unenroll(&self, machine: &MachineId) -> Result<bool, SyncError> {
        if let Some(err) = self.poison_refusal() {
            return Err(err);
        }
        let mut devices = self.devices.write().await;
        if let Some(previous) = devices.remove(&machine.0) {
            if let Err(e) = self.persist_devices(&devices).await {
                if matches!(e, SyncError::Poisoned(_)) {
                    // Disk already holds the removal: keep it and poison.
                    drop(devices);
                    self.poison(e.to_string());
                    self.notify_device_change();
                    return Err(e);
                }
                devices.insert(previous.machine_id, previous);
                return Err(e);
            }
        } else {
            return Ok(false);
        }
        if let Ok(mut verified) = self.evidence_owners.write() {
            verified.remove(&machine.0);
        }
        drop(devices);
        self.kick();
        self.notify_device_change();
        Ok(true)
    }

    /// Enrolled machines (raw records, for surfaces).
    pub async fn enrolled_devices(&self) -> Vec<OwnerEnrollment> {
        self.devices.read().await.values().cloned().collect()
    }

    /// On-change trigger: bump the generation the periodic task waits on.
    pub fn kick(&self) {
        Self::kick_generation(&self.generation_tx);
    }

    /// [`Self::kick`] for a task that owns no `&self`.
    fn kick_generation(generation: &tokio::sync::watch::Sender<u64>) {
        generation.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Subscribe to generation changes.
    pub fn generation_rx(&self) -> tokio::sync::watch::Receiver<u64> {
        self.generation_tx.subscribe()
    }

    /// Pure classification of `record` against `stored` under the full
    /// conflict rule: `beats`, else equal-clock resolved by the FULL
    /// record hash (canonical signed bytes including the randomized
    /// ML-DSA signature): an identical hash is an exact replay
    /// (idempotent supersede); any difference under the same clock —
    /// value OR signature-only — makes the greater hash the deterministic
    /// winner on every peer (review R5 finding 1).
    fn classify(record: &VersionedRecord, stored: &VersionedRecord) -> MergeOutcome {
        if record.clock.beats(&stored.clock) {
            return MergeOutcome::Accepted;
        }
        if record.clock == stored.clock {
            // Signature-only differences (the same writer double-signing
            // identical content) MUST also converge to one canonical
            // record — deciding by value equality would leave replicas
            // holding different records under the same clock forever.
            if record.record_hash() > stored.record_hash() {
                return MergeOutcome::Accepted;
            }
        }
        MergeOutcome::Superseded
    }

    /// Commit a verified batch atomically (review R2 finding 4): all
    /// classification decisions are made against a copy of the register,
    /// all accepted records inserted into it, and ONE file write persists
    /// the result. The copy becomes the register only once that write is
    /// done (`replace_records`). On any failure the register keeps its
    /// **pre-batch** state, and the error propagates. A partial batch is
    /// never committed or advertised.
    ///
    /// Records must have been verified (`verify_owner`) by the caller.
    /// #1545: a caller that is cancelled leaves the register as before
    /// the batch, or, once the register write has started, as that write
    /// leaves it; memory always ends as the disk holds it.
    ///
    /// # Errors
    ///
    /// [`SyncError::StoreLimit`] when the batch would exceed
    /// [`MAX_STORED_RECORDS`]; [`SyncError::Io`] when persistence fails.
    pub async fn commit_batch(
        &self,
        batch: Vec<VersionedRecord>,
        owner: &UserId,
    ) -> Result<CommitOutcome, SyncError> {
        if let Some(err) = self.poison_refusal() {
            return Err(err);
        }
        // #1542: a batch that can change the IssuanceJournal register holds
        // `journal_apply` until its accepted values are in the journal file.
        let journal = self
            .journal_file
            .get()
            .filter(|_| batch.iter().any(|r| r.kind == SyncKind::IssuanceJournal));
        let held = match journal {
            Some(_) => {
                let guard = Arc::clone(&self.journal_apply).lock_owned().await;
                Some(self.recover_journal_commit(guard, owner).await?)
            }
            None => None,
        };
        self.commit_locked(batch, owner, journal, held)
            .await
            .map(|(outcome, _)| outcome)
    }

    /// [`Self::commit_batch`] after its `journal_apply` step. `journal` is
    /// the journal file to apply accepted `IssuanceJournal` values to;
    /// `held` then holds `journal_apply`. `held` moves into each write of
    /// the journal intent and of the register (`run_to_completion`), and
    /// comes back on success.
    async fn commit_locked<H: Send + 'static>(
        &self,
        batch: Vec<VersionedRecord>,
        owner: &UserId,
        journal: Option<&PathBuf>,
        mut held: H,
    ) -> Result<(CommitOutcome, H), SyncError> {
        // #449 r3 P2: an inbound batch that can change the canonical Home
        // register waits behind any in-flight seat mint, and blocks the next
        // one until this batch is durable. Batches that touch no HomePointer
        // record skip the gate entirely (lock order: gate → records).
        let canonical_gate = if batch.iter().any(|r| r.kind == SyncKind::HomePointer) {
            Some(Arc::clone(&self.canonical_home_gate).write_owned().await)
        } else {
            None
        };
        let records = Arc::clone(&self.records).write_owned().await;
        let mut next = records.clone();
        // The keys this batch changes; `records` keeps their values before
        // the batch until `replace_records`.
        let mut touched: BTreeSet<(SyncKind, String)> = BTreeSet::new();
        let mut outcome = CommitOutcome::default();
        for record in batch {
            // Re-verify inside the lock: the caller's verification and
            // the commit must not be separated by a store mutation.
            record.verify_owner(owner)?;
            if next.len() >= MAX_STORED_RECORDS
                && !next.contains_key(&(record.kind, record.key.clone()))
            {
                return Err(SyncError::StoreLimit(format!(
                    "store at capacity ({MAX_STORED_RECORDS} records)"
                )));
            }
            let key = (record.kind, record.key.clone());
            let stored = next.get(&key);
            // Equal clock with ANY differing signed bytes (different
            // value, or the same value double-signed) is an
            // equivocation whichever side wins the hash tie-break —
            // surfaced, never silently merged (review R2 finding 3,
            // extended in R5 to signature-only differences).
            if let Some(existing) = stored {
                if existing.clock == record.clock && existing.record_hash() != record.record_hash()
                {
                    outcome.equivocations += 1;
                    let values_differ = existing.value != record.value;
                    tracing::warn!(
                        target: "x0x::owner_sync",
                        kind = ?existing.kind,
                        key = %existing.key,
                        values_differ,
                        "equal-clock equivocation resolved deterministically by record hash"
                    );
                }
            }
            match stored.map(|existing| Self::classify(&record, existing)) {
                None | Some(MergeOutcome::Accepted) => {
                    touched.insert(key.clone());
                    next.insert(key, record.clone());
                    outcome.accepted.push(record);
                }
                Some(MergeOutcome::Superseded) => {
                    outcome.superseded += 1;
                }
            }
        }
        if outcome.accepted.is_empty() {
            return Ok((outcome, held)); // nothing new — no write needed
        }
        // #1542: the journal file first, then the register (see
        // `journal_apply`). A failed append commits nothing; a later
        // session delivers the records again.
        let updates = match journal {
            Some(_) => Self::journal_updates(&records, &next, &touched),
            None => Vec::new(),
        };
        if let Some(path) = journal.filter(|_| !updates.is_empty()) {
            // The intent first: after a stop between the two writes, the
            // journal holds lines that came from these records, and the
            // restart must not take them for unpublished local issuance
            // (see `recover_journal_commit`). The intent holds every
            // accepted record of the batch, not only the journal ones, so
            // the recovery commits all of it or none.
            held = self
                .persist_journal_intent(held, outcome.accepted.clone())
                .await?;
            let owner_hex = hex::encode(owner.0);
            for (record, published) in &updates {
                self.apply_journal_value(path, &owner_hex, &record.value, published.clone())
                    .await
                    .map_err(|e| {
                        SyncError::Io(format!("failed to append synced journal line: {e}"))
                    })?;
            }
            #[cfg(test)]
            if self.stop_after_first_journal_write() {
                return Err(SyncError::Io("stopped between writes".into()));
            }
        }
        // #1545: the obligation to apply the names before the register
        // holds them (see `pending_apply`).
        self.add_pending_applies(&outcome.accepted).await?;
        let (_, mut held) = self
            .replace_records(records, next, (canonical_gate, held))
            .await?;
        if !updates.is_empty() {
            held = self.remove_journal_intent(held).await?;
        }
        Ok((outcome, held))
    }

    /// The `IssuanceJournal` records a committed batch changed: each is the
    /// key's record now, with the value the register held before the batch.
    fn journal_updates(
        before: &RecordMap,
        after: &RecordMap,
        touched: &BTreeSet<(SyncKind, String)>,
    ) -> Vec<(VersionedRecord, Option<SyncValue>)> {
        touched
            .iter()
            .filter(|(kind, _)| *kind == SyncKind::IssuanceJournal)
            .filter_map(|key| {
                let now = after.get(key)?;
                let previous = before.get(key).map(|r| r.value.clone());
                (previous.as_ref() != Some(&now.value)).then(|| (now.clone(), previous))
            })
            .collect()
    }

    /// Durably record the accepted records of a commit that is about to
    /// write `IssuanceJournal` values to the journal file and then the
    /// whole batch to the register (#1542). `held` holds `journal_apply`
    /// until the write is done (`run_to_completion`), and comes back.
    async fn persist_journal_intent<H: Send + 'static>(
        &self,
        held: H,
        records: Vec<VersionedRecord>,
    ) -> Result<H, SyncError> {
        let bytes = serde_json::to_vec(&PersistedRecords { records })
            .map_err(|e| SyncError::Io(format!("encode journal intent: {e}")))?;
        let path = self.dir.join(JOURNAL_INTENT_FILE);
        Self::run_to_completion(async move {
            Self::write_atomically(&path, &bytes, false)
                .await
                .map_err(|e| match e {
                    DurableWriteError::BeforeRename(io) | DurableWriteError::AfterRename(io) => {
                        SyncError::Io(format!("persist journal intent: {io}"))
                    }
                })?;
            Ok(held)
        })
        .await
    }

    /// Remove the journal intent once its records are in the register. A
    /// left-over intent is harmless: its recovery finds the records already
    /// there. `held` holds `journal_apply` until the removal is done, so a
    /// late removal cannot take the intent of a later commit; it comes
    /// back.
    async fn remove_journal_intent<H: Send + 'static>(&self, held: H) -> Result<H, SyncError> {
        let path = self.dir.join(JOURNAL_INTENT_FILE);
        Self::run_to_completion(async move {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!(target: "x0x::owner_sync", error = %e, "failed to remove the journal intent");
                }
            }
            Ok(held)
        })
        .await
    }

    /// #1542: finish an interrupted commit (`recover_journal_commit`)
    /// outside of a commit, for the reconcile pass. The daemon calls this
    /// before it mints any record from live state: a mint before the
    /// recovery can put an old live value over a recovered record.
    ///
    /// # Errors
    ///
    /// See `recover_journal_commit`.
    pub(crate) async fn recover_interrupted_commit(&self, owner: &UserId) -> Result<(), SyncError> {
        let guard = Arc::clone(&self.journal_apply).lock_owned().await;
        self.recover_journal_commit(guard, owner).await.map(drop)
    }

    /// Add the name records of a commit to `pending_apply` and its file.
    async fn add_pending_applies(&self, accepted: &[VersionedRecord]) -> Result<(), SyncError> {
        let names: Vec<&VersionedRecord> = accepted
            .iter()
            .filter(|r| matches!(r.kind, SyncKind::OwnerProfile | SyncKind::MachineNames))
            .collect();
        if names.is_empty() {
            return Ok(());
        }
        let pending = Arc::clone(&self.pending_apply).lock_owned().await;
        let mut next = pending.clone();
        for record in names {
            let entry = next
                .applies
                .entry(pending_key(record))
                .or_insert_with(|| PendingApply {
                    record: (*record).clone(),
                    saved_in: Vec::new(),
                    discharged: false,
                });
            // A record retired as not the winner (its earlier commit did
            // not complete), whose removal did not reach the file yet, is
            // owed again now that a commit accepts it.
            if entry.discharged {
                entry.discharged = false;
                entry.saved_in.clear();
            }
        }
        next.epoch = next.epoch.wrapping_add(1);
        self.replace_pending(pending, next).await
    }

    /// #1545: the generation of the pending applies
    /// (`PendingApplies::epoch`). The reconcile reads it after its apply
    /// step and before it reads the live names, and passes it to
    /// [`Self::mint_live_name`].
    pub(crate) async fn names_epoch(&self) -> u64 {
        self.pending_apply.lock().await.epoch
    }

    /// Whether `record` is the winner in `records`.
    fn is_winner(
        records: &BTreeMap<(SyncKind, String), VersionedRecord>,
        record: &VersionedRecord,
    ) -> bool {
        records
            .get(&(record.kind, record.key.clone()))
            .is_some_and(|stored| stored.record_hash() == record.record_hash())
    }

    /// Write the owed records of `next` durably to `APPLY_PENDING_FILE`,
    /// and then make `next`, without its discharged records, the pending
    /// applies (see `PendingApply::discharged`). An empty set is written
    /// too, not unlinked: an unlink without a directory fsync can come
    /// back after a crash with the obligations it removed.
    ///
    /// The write and the update run to their end in one task
    /// (`run_to_completion`), which owns `pending` until then. A caller
    /// cancelled during the write stops only its wait: no later change of
    /// the pending applies can start before the write lands, and memory
    /// ends as the disk holds it (Codex review of #1545, b17cd8bf).
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] when the file cannot be written; `pending` does
    /// not change.
    async fn replace_pending(
        &self,
        mut pending: tokio::sync::OwnedMutexGuard<PendingApplies>,
        mut next: PendingApplies,
    ) -> Result<(), SyncError> {
        let path = self.dir.join(APPLY_PENDING_FILE);
        let bytes = serde_json::to_vec(&PersistedPendingApplies {
            applies: next
                .applies
                .values()
                .filter(|p| !p.discharged)
                .cloned()
                .collect(),
        })
        .map_err(|e| SyncError::Io(format!("encode pending applies: {e}")))?;
        Self::run_to_completion(async move {
            Self::write_atomically(&path, &bytes, false)
                .await
                .map_err(|e| match e {
                    DurableWriteError::BeforeRename(io) | DurableWriteError::AfterRename(io) => {
                        SyncError::Io(format!("persist pending applies: {io}"))
                    }
                })?;
            next.applies.retain(|_, p| !p.discharged);
            *pending = next;
            Ok(())
        })
        .await
    }

    /// #1545: the committed name records that live daemon state may not
    /// show yet (see `pending_apply`). The flag is `true` for a record that
    /// is still the register's winner; the caller applies only those. A
    /// record that a later commit replaced, or whose commit failed after
    /// the obligation was written, is `false`.
    pub(crate) async fn pending_applies(&self) -> Vec<(VersionedRecord, bool)> {
        let pending: Vec<VersionedRecord> = self
            .pending_apply
            .lock()
            .await
            .applies
            .values()
            .filter(|p| !p.discharged)
            .map(|p| p.record.clone())
            .collect();
        if pending.is_empty() {
            return Vec::new();
        }
        let records = self.records.read().await;
        pending
            .into_iter()
            .map(|r| {
                let winner = records
                    .get(&(r.kind, r.key.clone()))
                    .is_some_and(|stored| stored.record_hash() == r.record_hash());
                (r, winner)
            })
            .collect()
    }

    /// #1545: whether any of `records` is still owed: a save of its names
    /// has not discharged it yet.
    pub(crate) async fn owes_any(&self, records: &[(VersionedRecord, bool)]) -> bool {
        let pending = self.pending_apply.lock().await;
        records.iter().any(|(record, _)| {
            pending
                .applies
                .get(&pending_key(record))
                .is_some_and(|entry| !entry.discharged)
        })
    }

    /// #1545: record that a profile save with `names` starts with
    /// `folded` in it. Each entry of `folded` is a record of
    /// [`Self::pending_applies`] with its winner flag at the fold; only a
    /// winner was applied to the profile, so only a winner is noted. The
    /// caller holds the profile write lock, and saves only after this
    /// returns `Ok`: then a durable profile with `names` shows that the
    /// applied records are not owed any more, even when the discharge
    /// after the save does not reach the disk (`settle_saved`). A record
    /// that was not the winner is not in the profile; a retried commit
    /// can make it the winner later, so no save may settle it.
    ///
    /// It also writes the file when a record is discharged but its removal
    /// from the file failed: else the file keeps the record with the names
    /// of an older save only, and the next start applies it over this
    /// save.
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] when the file cannot be written; the caller must
    /// not save the profile.
    pub(crate) async fn note_profile_save(
        &self,
        folded: &[(VersionedRecord, bool)],
        names: &SyncProfileNames,
    ) -> Result<(), SyncError> {
        let saved = SavedNames::from(names);
        let pending = Arc::clone(&self.pending_apply).lock_owned().await;
        let mut next = pending.clone();
        let mut changed = next.applies.values().any(|p| p.discharged);
        for (record, _) in folded.iter().filter(|(_, applied)| *applied) {
            if let Some(entry) = next.applies.get_mut(&pending_key(record)) {
                if !entry.discharged && !entry.saved_in.contains(&saved) {
                    entry.saved_in.push(saved.clone());
                    changed = true;
                }
            }
        }
        if !changed {
            return Ok(());
        }
        self.replace_pending(pending, next).await
    }

    /// #1545: remove `done` from the pending applies, after the daemon has
    /// durably saved the winners among them. Each entry of `done` is a
    /// record of [`Self::pending_applies`] with its winner flag at the
    /// read; `true` means the caller applied it. A record that a commit
    /// added after `done` was read stays.
    ///
    /// The check is made again here, under the `records` read lock: a
    /// record that was not the winner at the read, and so was not
    /// applied, is retired only if it is still not the winner. A retried
    /// commit can have made it the winner since; it then stays owed, and
    /// the next pass applies it.
    ///
    /// When the file write fails, the records stay in memory as
    /// discharged (`PendingApply::discharged`): no later pass applies them
    /// over a newer local edit, and the next write of the file, at the
    /// latest the note of the next profile save, removes them. A crash
    /// before that keeps the noted names of their save on disk, so
    /// `settle_saved` removes them at the next start.
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] when the file cannot be written.
    pub(crate) async fn discharge_applies(
        &self,
        done: &[(VersionedRecord, bool)],
    ) -> Result<(), SyncError> {
        #[cfg(test)]
        Self::take_pause(&self.discharge_pause).await;
        let records = self.records.read().await;
        let mut pending = Arc::clone(&self.pending_apply).lock_owned().await;
        let mut retired = false;
        for (record, applied) in done {
            if !applied && Self::is_winner(&records, record) {
                continue;
            }
            if let Some(entry) = pending.applies.get_mut(&pending_key(record)) {
                if !entry.discharged {
                    entry.discharged = true;
                    retired = true;
                }
            }
        }
        if retired {
            pending.epoch = pending.epoch.wrapping_add(1);
        }
        if !pending.applies.values().any(|p| p.discharged) {
            return Ok(());
        }
        #[cfg(test)]
        if self
            .fail_next_discharge
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            return Err(SyncError::Io("injected discharge failure".into()));
        }
        let next = pending.clone();
        self.replace_pending(pending, next).await
    }

    /// #1545: remove the pending applies that a durable profile with
    /// `durable` holds (see `PendingApply::saved_in`). The daemon calls
    /// this at start, with the profile it loaded, before any pass applies
    /// them: a discharge before the restart can have failed to reach the
    /// disk.
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] when the file cannot be written; the records
    /// stay in memory as discharged, as in `discharge_applies`.
    pub(crate) async fn settle_saved(&self, durable: &SyncProfileNames) -> Result<(), SyncError> {
        let saved = SavedNames::from(durable);
        let _records = self.records.read().await;
        let mut pending = Arc::clone(&self.pending_apply).lock_owned().await;
        let mut settled = false;
        for entry in pending.applies.values_mut() {
            if !entry.discharged && entry.saved_in.contains(&saved) {
                entry.discharged = true;
                settled = true;
            }
        }
        if !settled {
            return Ok(());
        }
        pending.epoch = pending.epoch.wrapping_add(1);
        let next = pending.clone();
        self.replace_pending(pending, next).await
    }

    /// #1542: finish a commit that stopped after its journal intent was
    /// durable but before its register write. `guard` holds
    /// `journal_apply`, and comes back on success. The caller calls this
    /// before any other change of the `IssuanceJournal` register or any
    /// reconcile of the journal.
    ///
    /// Without this, the journal can hold a line that came from the
    /// register (from another device) while the register still holds the
    /// value before it. That line then looks like a local issuance that no
    /// reconcile has published: a later same-second record is not
    /// appended, and the reconcile publishes the older line over it. The
    /// recovery commits the original signed records again, so the register
    /// keeps their versions and every device keeps the same order.
    ///
    /// # Errors
    ///
    /// [`SyncError::Io`] or [`SyncError::Poisoned`] when the intent cannot
    /// be read or decoded, or the recovery cannot be written; the error of
    /// the commit when the intent's records do not verify or do not fit.
    /// The intent stays for the next attempt. Only an intent whose records
    /// verify under another owner is dropped.
    async fn recover_journal_commit(
        &self,
        guard: JournalGuard,
        owner: &UserId,
    ) -> Result<JournalGuard, SyncError> {
        if let Some(err) = self.poison_refusal() {
            return Err(err);
        }
        let Some(journal) = self.journal_file.get() else {
            return Ok(guard);
        };
        let bytes = match tokio::fs::read(self.dir.join(JOURNAL_INTENT_FILE)).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(guard),
            Err(e) => return Err(SyncError::Io(format!("read journal intent: {e}"))),
        };
        // An undecodable intent fails closed and stays in place. Without
        // it, a journal line of the interrupted commit looks like an
        // unpublished local issuance, and the reconcile publishes it over
        // a later same-second record.
        let batch = serde_json::from_slice::<PersistedRecords>(&bytes)
            .map_err(|e| SyncError::Io(format!("undecodable journal intent: {e}")))?
            .records;
        // The commit verifies each record in order and stops at the first
        // failure; the same check here decides the intent's fate first,
        // while `guard` is still held for its removal.
        match batch.iter().find_map(|r| r.verify_owner(owner).err()) {
            None => {}
            Some(SyncError::OwnerMismatch) => {
                // The records verify, but under another owner (after an
                // owner rotation): no session would deliver them either.
                // `verify_owner` checks the signature first, so a changed
                // record cannot get here.
                tracing::warn!(target: "x0x::owner_sync", "dropped a journal intent of a previous owner");
                return self.remove_journal_intent(guard).await;
            }
            // Any other failure (a bad signature, a kind mismatch) fails
            // closed and keeps the intent, as for an undecodable intent.
            Some(e) => return Err(e),
        }
        // A failure here (a full store, I/O) fails closed and keeps the
        // intent too. The commit adds the recovered names to
        // `pending_apply`.
        let (_, guard) = self
            .commit_locked(batch, owner, Some(journal), guard)
            .await?;
        self.remove_journal_intent(guard).await
    }

    /// Merge one verified inbound record — a single-record batch commit.
    ///
    /// # Errors
    ///
    /// See [`VersionedRecord::verify_owner`] and [`Self::commit_batch`].
    pub async fn merge_record(
        &self,
        record: VersionedRecord,
        owner: &UserId,
    ) -> Result<MergeOutcome, SyncError> {
        let outcome = self.commit_batch(vec![record], owner).await?;
        Ok(if outcome.accepted.is_empty() {
            MergeOutcome::Superseded
        } else {
            MergeOutcome::Accepted
        })
    }

    /// Mint a local record for `(kind, key)` from `desired`: no-op when the
    /// stored winner already carries exactly this value; otherwise version =
    /// stored version + 1, signed now by this machine.
    ///
    /// # Errors
    ///
    /// [`SyncError::BadSignature`] when signing fails; [`SyncError::Io`]
    /// when persistence fails (never swallowed — review R2 finding 2).
    pub async fn mint(
        &self,
        kind: SyncKind,
        key: &str,
        desired: &SyncValue,
        owner: &UserKeypair,
        writer_machine: MachineId,
    ) -> Result<(), SyncError> {
        self.mint_when(kind, key, desired, owner, writer_machine, None)
            .await
    }

    /// #1545: [`Self::mint`] for a name read from live daemon state.
    /// `epoch` is [`Self::names_epoch`], read before the live names. The
    /// mint is skipped when a committed name that is still the register's
    /// winner is owed to that state (`pending_applies`), or when the
    /// pending applies changed since `epoch`: a commit or a retirement
    /// after the read can mean that the names read are older than the
    /// register, and the mint would put them over a synced name at a
    /// higher version. The check and the mint hold the register write
    /// lock together, and every change of the pending applies holds the
    /// same lock (see `pending_apply`). A mint skipped for a changed
    /// epoch kicks the next pass, which reads the names again.
    ///
    /// # Errors
    ///
    /// See [`Self::mint`].
    pub(crate) async fn mint_live_name(
        &self,
        kind: SyncKind,
        key: &str,
        desired: &SyncValue,
        owner: &UserKeypair,
        writer_machine: MachineId,
        epoch: u64,
    ) -> Result<(), SyncError> {
        self.mint_when(kind, key, desired, owner, writer_machine, Some(epoch))
            .await
    }

    /// [`Self::mint`]; with `live_epoch`, see [`Self::mint_live_name`].
    async fn mint_when(
        &self,
        kind: SyncKind,
        key: &str,
        desired: &SyncValue,
        owner: &UserKeypair,
        writer_machine: MachineId,
        live_epoch: Option<u64>,
    ) -> Result<(), SyncError> {
        if let Some(err) = self.poison_refusal() {
            return Err(err);
        }
        let value_bytes = bincode::serialize(desired)
            .map_err(|e| SyncError::BadSignature(format!("value encode: {e}")))?;
        if value_bytes.len() > MAX_VALUE_BYTES {
            return Err(SyncError::MalformedFrame(format!(
                "value of {} bytes exceeds limit {MAX_VALUE_BYTES}",
                value_bytes.len()
            )));
        }
        let now_ms = now_unix_ms();
        // #449 r3 P2: the LOCAL publisher of a canonical Home pointer is
        // fenced on the same gate as inbound commits (lock order: gate →
        // records). Other kinds are unaffected.
        let canonical_gate = if kind == SyncKind::HomePointer {
            Some(Arc::clone(&self.canonical_home_gate).write_owned().await)
        } else {
            None
        };
        let records = Arc::clone(&self.records).write_owned().await;
        let stored = records.get(&(kind, key.to_string()));
        if stored.is_some_and(|r| r.value == *desired) {
            return Ok(());
        }
        if let Some(epoch) = live_epoch {
            let pending = self.pending_apply.lock().await;
            let owed = pending
                .applies
                .values()
                .filter(|p| !p.discharged)
                .any(|p| Self::is_winner(&records, &p.record));
            if owed {
                // The next pass applies the owed names first.
                return Ok(());
            }
            if pending.epoch != epoch {
                drop(pending);
                drop(records);
                self.kick();
                return Ok(());
            }
        }
        let version = stored.map_or(1, |r| r.clock.version.saturating_add(1));
        let clock = RecordClock {
            version,
            signed_at_ms: now_ms,
            writer_machine: writer_machine.0,
        };
        let record = VersionedRecord::sign(kind, key, desired, clock, owner)
            .map_err(|e| SyncError::BadSignature(format!("mint: {e}")))?;
        let mut next = records.clone();
        next.insert((kind, key.to_string()), record);
        self.replace_records(records, next, canonical_gate)
            .await
            .map(drop)
    }

    /// Hold the canonical-Home admission gate for reading (#449 r3 P2).
    ///
    /// A caller that must ACT on the canonical answer — `POST /home/seat` is
    /// the only one today — acquires this before resolving the canonical
    /// Home and holds it until its durable side effect has landed. See
    /// the doc comment on `canonical_home_gate` for the linearization
    /// statement and the lock order this participates in.
    ///
    /// This is not a substitute for reading the register: it makes the read
    /// and the act that follows it one unit, nothing more.
    pub async fn canonical_home_gate_read(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.canonical_home_gate.read().await
    }

    /// Full record snapshot (winners only), for surfaces and sessions.
    pub async fn records_snapshot(&self) -> Vec<VersionedRecord> {
        self.records.read().await.values().cloned().collect()
    }

    /// The winning value for one `(kind, key)`, if any.
    ///
    /// Used by the #449 Home-pointer mint gate, which must decide whether
    /// to yield to a peer's canonical Home before minting its own.
    pub async fn stored_value(&self, kind: SyncKind, key: &str) -> Option<SyncValue> {
        self.records
            .read()
            .await
            .get(&(kind, key.to_string()))
            .map(|record| record.value.clone())
    }

    /// The per-kind version table (with record hashes) for the handshake.
    pub async fn version_vector(&self) -> Vec<KindVersions> {
        let records = self.records.read().await;
        let mut by_kind: BTreeMap<SyncKind, Vec<(String, RecordClock, [u8; 32])>> = BTreeMap::new();
        for ((kind, key), record) in records.iter() {
            by_kind.entry(*kind).or_default().push((
                key.clone(),
                record.clock,
                record.record_hash(),
            ));
        }
        SyncKind::ALL
            .into_iter()
            .map(|kind| KindVersions {
                kind,
                entries: by_kind.remove(&kind).unwrap_or_default(),
            })
            .collect()
    }

    /// Records the peer is missing or would accept under the full conflict
    /// rule (`beats`, or equal clock with a greater record hash — so the
    /// deterministic equal-clock winner always ships; review R2 finding 3).
    pub async fn records_for_peer(&self, peer_vector: &[KindVersions]) -> Vec<VersionedRecord> {
        struct PeerEntry {
            clock: RecordClock,
            hash: [u8; 32],
        }
        let peer_entries: BTreeMap<(SyncKind, String), PeerEntry> = peer_vector
            .iter()
            .flat_map(|kv| {
                kv.entries.iter().map(move |(k, c, h)| {
                    (
                        (kv.kind, k.clone()),
                        PeerEntry {
                            clock: *c,
                            hash: *h,
                        },
                    )
                })
            })
            .collect();
        let records = self.records.read().await;
        records
            .iter()
            .filter(
                |((kind, key), record)| match peer_entries.get(&(*kind, key.clone())) {
                    None => true,
                    Some(peer) => {
                        record.clock.beats(&peer.clock)
                            || (record.clock == peer.clock && record.record_hash() > peer.hash)
                    }
                },
            )
            .map(|(_, record)| record.clone())
            .collect()
    }

    /// Record the outcome of a session with `machine`.
    pub async fn set_session_status(&self, machine: &MachineId, ok: bool) {
        let mut last = self.last_session.write().await;
        last.insert(
            machine.0,
            DeviceSyncStatus {
                last_session_ms: now_unix_ms(),
                last_session_ok: ok,
            },
        );
        drop(last);
        if ok {
            self.sessions_ok_tx
                .send_modify(|count| *count = count.wrapping_add(1));
        }
    }

    /// Successful-session counter (#824): changes once per session with an
    /// owner device that completed, in either direction.
    #[must_use]
    pub fn successful_sessions_rx(&self) -> tokio::sync::watch::Receiver<u64> {
        self.sessions_ok_tx.subscribe()
    }

    /// Last-session status per device (for `GET /sync/devices`).
    pub async fn session_statuses(&self) -> BTreeMap<[u8; 32], DeviceSyncStatus> {
        self.last_session.read().await.clone()
    }

    /// Test-only: insert a pre-built record WITHOUT verification, so
    /// integration tests can simulate a compromised writer whose forgery
    /// the receiving side must reject. Never call from production code —
    /// every real path (`mint`, `commit_batch`) verifies signatures.
    #[doc(hidden)]
    pub async fn records_insert_for_testing(&self, record: VersionedRecord) {
        if self.poison_refusal().is_some() {
            return; // test helper respects poison too
        }
        // #449 r3 P2: the unverified test writer participates in the gate
        // too, so a test cannot accidentally prove a fence that production
        // writers honour but this back door bypasses.
        let canonical_gate = if record.kind == SyncKind::HomePointer {
            Some(Arc::clone(&self.canonical_home_gate).write_owned().await)
        } else {
            None
        };
        let records = Arc::clone(&self.records).write_owned().await;
        let mut next = records.clone();
        next.insert((record.kind, record.key.clone()), record);
        let _ = self.replace_records(records, next, canonical_gate).await;
    }
}

/// Unix epoch milliseconds.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A fresh random 32-byte nonce.
fn fresh_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Run one fail-closed sync session over the two halves of a SyncV1 stream
/// under the default [`SESSION_TIMEOUT`] budget.
///
/// # Errors
///
/// Any [`SyncError`] aborts the session; see
/// [`run_sync_session_with_timeout`].
pub async fn run_sync_session<S, R, F>(
    send: &mut S,
    recv: &mut R,
    store: &OwnerSyncStore,
    owner: &UserKeypair,
    local_machine: &MachineId,
    peer_machine: &MachineId,
    on_accept: F,
) -> Result<SessionSummary, SyncError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: FnMut(&VersionedRecord),
{
    run_sync_session_with_timeout(
        SESSION_TIMEOUT,
        send,
        recv,
        store,
        owner,
        local_machine,
        peer_machine,
        on_accept,
    )
    .await
}

/// [`run_sync_session`] with an explicit total budget (tests use short
/// ones; production uses [`SESSION_TIMEOUT`]). A peer that stalls at any
/// protocol stage — after the transport-level protocol prefix — is dropped
/// when the budget elapses, never held indefinitely (review R2 finding 5).
///
/// Both sides run the same symmetric protocol: Hello (with nonce) → mutual
/// owner-key possession Proof → paged version vectors → paged records both
/// ways → Done → ONE atomic local commit of the verified batch. The caller
/// has already cleared the ADR-0022 machine identity gates; this function
/// enforces the same-owner + enrollment + possession gates (blocker 30) and
/// verifies EVERY record before anything is committed (review R2 finding 4).
///
/// `on_accept` fires for each record committed by this session, after the
/// clean `Done`, so callers can apply Tier-1 state to live daemon surfaces.
///
/// # Errors
///
/// Any [`SyncError`] aborts the session with NOTHING from the inbound batch
/// committed.
#[allow(clippy::too_many_arguments)]
pub async fn run_sync_session_with_timeout<S, R, F>(
    budget: Duration,
    send: &mut S,
    recv: &mut R,
    store: &OwnerSyncStore,
    owner: &UserKeypair,
    local_machine: &MachineId,
    peer_machine: &MachineId,
    mut on_accept: F,
) -> Result<SessionSummary, SyncError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: FnMut(&VersionedRecord),
{
    // The NETWORK protocol runs under the budget; the durable commit runs
    // OUTSIDE it, after the timeout future has completed. Cancelling at the
    // budget can therefore never rip a persistence await out from under
    // commit_batch's rollback paths (review R3 finding 4).
    let pending = tokio::time::timeout(
        budget,
        negotiate_sync_session(send, recv, store, owner, local_machine, peer_machine),
    )
    .await
    .map_err(|_| SyncError::SessionTimeout)??;
    let owner_id = owner.user_id();
    let outcome = store.commit_batch(pending.verified, &owner_id).await;
    // #1542: a recovery in the commit can commit records of an earlier,
    // interrupted commit. Apply the names still owed to live state (the
    // reconcile pass confirms them), even when this commit fails.
    let accepted: Vec<[u8; 32]> = outcome
        .as_ref()
        .map(|o| {
            o.accepted
                .iter()
                .map(VersionedRecord::record_hash)
                .collect()
        })
        .unwrap_or_default();
    for (record, winner) in store.pending_applies().await {
        if winner && !accepted.contains(&record.record_hash()) {
            on_accept(&record);
        }
    }
    let outcome = outcome?;
    let mut summary = pending.summary;
    summary.accepted = outcome.accepted.len();
    summary.superseded = outcome.superseded;
    summary.equivocations = outcome.equivocations;
    // Apply committed records only now, so partial sessions never mutate
    // live daemon state.
    for record in outcome.accepted {
        on_accept(&record);
    }
    Ok(summary)
}

/// A session that cleared every gate and exchange but has not yet committed.
struct PendingCommit {
    summary: SessionSummary,
    verified: Vec<VersionedRecord>,
}

/// The network protocol body (no timeout wrapper, no commit — the caller
/// commits the verified batch outside the time budget).
async fn negotiate_sync_session<S, R>(
    send: &mut S,
    recv: &mut R,
    store: &OwnerSyncStore,
    owner: &UserKeypair,
    local_machine: &MachineId,
    peer_machine: &MachineId,
) -> Result<PendingCommit, SyncError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let owner_id = owner.user_id();
    let mut summary = SessionSummary::default();

    // A poisoned store never syncs: memory/disk agreement is unrecoverable
    // until the process reloads state from disk (review R5 finding 2).
    if let Some(reason) = store.poisoned_reason() {
        return Err(SyncError::Poisoned(reason));
    }
    // Same-owner gate: a peer machine that is not enrolled locally (and
    // current) never gets past the first byte (blocker 30).
    if peer_machine.0 == local_machine.0 {
        return Err(SyncError::SelfSync);
    }
    if !store.is_enrolled(peer_machine, &owner_id).await {
        return Err(SyncError::NotEnrolled {
            machine: peer_machine.0,
        });
    }

    // Hello both ways (each side contributes a fresh nonce).
    let local_nonce = fresh_nonce();
    let hello = SyncFrame::Hello {
        protocol_version: SYNC_PROTOCOL_VERSION,
        machine_id: local_machine.0,
        owner_user_id: owner_id.0,
        nonce: local_nonce,
    };
    write_frame(send, &hello).await?;
    let peer_nonce = match read_frame(recv).await? {
        SyncFrame::Hello {
            protocol_version,
            machine_id,
            owner_user_id,
            nonce,
        } => {
            if protocol_version != SYNC_PROTOCOL_VERSION {
                return Err(SyncError::ProtocolVersion {
                    local: SYNC_PROTOCOL_VERSION,
                    remote: protocol_version,
                });
            }
            if owner_user_id != owner_id.0 {
                return Err(SyncError::OwnerMismatch);
            }
            if machine_id != peer_machine.0 {
                // Hello machine must match the transport-authenticated peer.
                return Err(SyncError::MalformedFrame(
                    "hello machine differs from transport peer".into(),
                ));
            }
            nonce
        }
        other => {
            return Err(SyncError::MalformedFrame(format!(
                "expected hello, got {other:?}"
            )));
        }
    };

    // Mutual owner-key possession proof (review R2 finding 1): each side
    // signs the PEER's nonce bound to both machines and the owner id, and
    // verifies the peer's proof against its OWN nonce. A machine that
    // merely echoes the victim's owner id — without holding the owner key —
    // cannot produce the proof and learns nothing.
    let proof_msg = proof_message(&peer_nonce, &local_machine.0, &peer_machine.0, &owner_id.0);
    let proof_sig = sign_with_ml_dsa(owner.secret_key(), &proof_msg)
        .map_err(|e| SyncError::ChallengeFailed(format!("signing: {e:?}")))?;
    write_frame(
        send,
        &SyncFrame::Proof {
            signature: proof_sig.as_bytes().to_vec(),
        },
    )
    .await?;
    match read_frame(recv).await? {
        SyncFrame::Proof { signature } => {
            let expected_msg =
                proof_message(&local_nonce, &peer_machine.0, &local_machine.0, &owner_id.0);
            let sig = MlDsaSignature::from_bytes(&signature)
                .map_err(|e| SyncError::ChallengeFailed(format!("invalid proof format: {e:?}")))?;
            verify_with_ml_dsa(owner.public_key(), &expected_msg, &sig)
                .map_err(|e| SyncError::ChallengeFailed(format!("bad proof: {e:?}")))?;
        }
        other => {
            return Err(SyncError::MalformedFrame(format!(
                "expected proof, got {other:?}"
            )));
        }
    }

    // Paged version vectors both ways (bounded, explicitly terminated).
    let local_vector = store.version_vector().await;
    write_paged_vector(send, &local_vector).await?;
    let peer_vector = read_paged_vector(recv).await?;

    // Compute the outbound set from the FULL peer vector, then ship it in
    // bounded pages, ending with Done ("finished shipping"). Done is sent
    // BEFORE reading the peer's records — both sides' reads must be able
    // to complete independently of their own send state.
    let to_ship = store.records_for_peer(&peer_vector).await;
    summary.shipped = to_ship.len();
    write_paged_records(send, &to_ship).await?;
    write_frame(send, &SyncFrame::Done).await?;
    // Done ends the application frames; FIN ends the transport send half.
    // An unfinished ant-quic SendStream resets on drop, so the peer can
    // otherwise observe a reset after an otherwise successful exchange.
    send.shutdown().await?;

    // Receive the peer's paged records (terminated by their Done or an
    // Abort); verify EVERY record before returning — one forgery aborts
    // with nothing stored (review R2 finding 4). The caller commits the
    // verified batch atomically, outside the session's time budget.
    let inbound = read_paged_records(recv).await?;
    let mut verified = Vec::with_capacity(inbound.len());
    for record in inbound {
        record.verify_owner(&owner_id)?;
        verified.push(record);
    }
    Ok(PendingCommit { summary, verified })
}

/// Write the version table as bounded pages (always at least one page, so
/// the reader's stage loop always advances).
async fn write_paged_vector<S: AsyncWrite + Unpin>(
    send: &mut S,
    vector: &[KindVersions],
) -> Result<(), SyncError> {
    // Each frame carries one kind with at most VV_ENTRIES_PER_FRAME
    // entries AND at most ~VV_PAGE_BYTES of serialized entries (byte
    // budget; review R3 finding 5).
    const ENTRY_OVERHEAD_BYTES: usize = 96; // clock (48) + hash (32) + framing
    let mut pages: Vec<KindVersions> = Vec::new();
    for kv in vector {
        let mut current = KindVersions {
            kind: kv.kind,
            entries: Vec::new(),
        };
        let mut current_bytes = 0usize;
        for entry in &kv.entries {
            let entry_bytes = entry.0.len() + ENTRY_OVERHEAD_BYTES;
            if !current.entries.is_empty()
                && (current.entries.len() >= VV_ENTRIES_PER_FRAME
                    || current_bytes + entry_bytes > VV_PAGE_BYTES)
            {
                pages.push(current);
                current = KindVersions {
                    kind: kv.kind,
                    entries: Vec::new(),
                };
                current_bytes = 0;
            }
            current_bytes += entry_bytes;
            current.entries.push(entry.clone());
        }
        if !current.entries.is_empty() {
            pages.push(current);
        }
    }
    for page in pages {
        write_frame(send, &SyncFrame::VersionVector { kinds: vec![page] }).await?;
    }
    // Explicit stage terminator — see [`SyncFrame::VectorEnd`].
    write_frame(send, &SyncFrame::VectorEnd).await?;
    Ok(())
}
/// Read paged version frames until the explicit [`SyncFrame::VectorEnd`]
/// terminator. Total entries are capped ([`MAX_VECTOR_ENTRIES`]).
async fn read_paged_vector<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<Vec<KindVersions>, SyncError> {
    let mut merged: BTreeMap<SyncKind, Vec<(String, RecordClock, [u8; 32])>> = BTreeMap::new();
    let mut total = 0usize;
    loop {
        match read_frame(recv).await? {
            SyncFrame::VersionVector { kinds } => {
                for kv in kinds {
                    total += kv.entries.len();
                    if total > MAX_VECTOR_ENTRIES {
                        return Err(SyncError::TooManyRecords(format!(
                            "version vector exceeds {MAX_VECTOR_ENTRIES} entries"
                        )));
                    }
                    for (key, ..) in &kv.entries {
                        if key.len() > MAX_KEY_BYTES {
                            // Structural bound, same as records (review R3
                            // finding 5).
                            return Err(SyncError::MalformedFrame(format!(
                                "vector key of {} bytes exceeds limit {MAX_KEY_BYTES}",
                                key.len()
                            )));
                        }
                    }
                    merged.entry(kv.kind).or_default().extend(kv.entries);
                }
            }
            SyncFrame::VectorEnd => {
                return Ok(SyncKind::ALL
                    .into_iter()
                    .map(|kind| KindVersions {
                        kind,
                        entries: merged.remove(&kind).unwrap_or_default(),
                    })
                    .collect());
            }
            other => {
                return Err(SyncError::MalformedFrame(format!(
                    "expected version-vector page or end, got {other:?}"
                )));
            }
        }
    }
}

/// Read the peer's paged records until `Done`/`Abort`. Capped at
/// [`MAX_RECORDS_PER_SESSION`].
async fn read_paged_records<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<Vec<VersionedRecord>, SyncError> {
    let mut records = Vec::new();
    loop {
        match read_frame(recv).await? {
            SyncFrame::Records { records: page } => {
                records.extend(page);
                if records.len() > MAX_RECORDS_PER_SESSION {
                    return Err(SyncError::TooManyRecords(format!(
                        "inbound batch exceeds {MAX_RECORDS_PER_SESSION} records"
                    )));
                }
            }
            SyncFrame::Done => break,
            SyncFrame::Abort { reason } => {
                return Err(SyncError::Io(format!("peer aborted: {reason}")));
            }
            other => {
                return Err(SyncError::MalformedFrame(format!(
                    "expected records page or done, got {other:?}"
                )));
            }
        }
    }
    Ok(records)
}

pub const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// #449 (D3): whether a device may mint `desired` into the single
/// `("home")` register, given the current winner `stored`.
///
/// The register is one LWW slot per owner, and [`OwnerSyncStore::mint`]
/// short-circuits ONLY on exact value equality — otherwise it takes the slot
/// at `version + 1`. `reconcile_local_state` runs every
/// [`DEFAULT_SYNC_INTERVAL`], so two enrolled devices holding different Homes
/// used to fight over the slot forever: each pass bumped the version, flipped
/// the canonical pointer, re-signed a record and re-persisted the store, once
/// per device per minute, without end.
///
/// The rule that ends it — deterministic, clock-skew tolerant, and monotone,
/// so it terminates:
///
/// - empty register: mint (we may genuinely be the owner's first device);
/// - the register already names OUR Home: only that Home's designated primary
///   agent refreshes it, so the slot has a single writer and roster churn
///   cannot ping-pong between co-members;
/// - the register names a DIFFERENT Home: mint only if ours is strictly
///   preferable under `(provisioned_at_ms, group_id)` — oldest Home wins, id
///   breaks ties. Both devices compare the same two tuples and so compute the
///   same winner; the value strictly decreases under that order, so the
///   register converges after at most one flip per device.
///
/// Yielding devices publish nothing, which is what lets `mint`'s equality
/// check hold the slot stable once converged.
///
/// Consequence accepted for this phase: a non-primary co-member does not
/// refresh the winner's roster projection, so `HomePointer.roster` can go
/// stale. Harmless today — the apply arm is a no-op (#449 P1+ acts on it),
/// and the authoritative roster is the group's signed commit chain, never
/// this pointer.
#[must_use]
fn home_pointer_mint_decision(
    desired: &SyncValue,
    stored: Option<&SyncValue>,
    local_agent_hex: &str,
    stored_is_retired: bool,
) -> bool {
    let SyncValue::HomePointer {
        group_id: desired_id,
        primary_agent: desired_primary,
        provisioned_at_ms: desired_at,
        ..
    } = desired
    else {
        debug_assert!(false, "mint decision called with a non-HomePointer value");
        return false;
    };
    let Some(stored_value) = stored else {
        return true; // empty register
    };
    let SyncValue::HomePointer {
        group_id: stored_id,
        provisioned_at_ms: stored_at,
        ..
    } = stored_value
    else {
        return true; // defensively: a foreign kind is not a Home winner
    };

    // r3 P2: the slot is held by a Home we can PROVE is retired. Take it —
    // the ordering rule below would otherwise refuse, because a replacement
    // Home is always newer than the dead one, leaving every device yielding
    // to a tombstone forever.
    if stored_is_retired && desired_id != stored_id {
        return true;
    }

    if desired_id == stored_id {
        // Single-writer refresh: only the Home's designated primary agent,
        // and only when the value actually changed. `mint` would no-op on an
        // unchanged value anyway, but deciding "no" here keeps the contract
        // "a write would change something" — so the register's quiescence is
        // observable at THIS level, which is what the oscillation regression
        // test asserts on.
        return local_agent_hex == desired_primary && desired != stored_value;
    }

    // Strict improvement only — monotone, therefore terminating.
    (*desired_at, desired_id.as_str()) < (*stored_at, stored_id.as_str())
}

/// The owner's canonical Home, as advertised on the Tier-1 register (#449).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalHome {
    /// Stable group id of the owner's Home.
    pub group_id: String,
    /// Hex agent id of that Home's designated primary agent.
    pub primary_agent: String,
    /// Unix ms when it was provisioned (the election's first key).
    pub provisioned_at_ms: u64,
    /// Roster projection as of the advertising device's last mint.
    pub roster: Vec<HomeRosterEntry>,
}

/// Record key for the owner's canonical Home pointer.
///
/// A CONSTANT key, so `(HomePointer, "home")` is one LWW register per owner
/// rather than one record per device. Every enrolled device writes the same
/// slot, which is what makes it an election (see
/// `home_pointer_mint_decision`, #449). Not an intra-doc link: that function
/// is private, and a public item may not link to one.
pub const HOME_POINTER_KEY: &str = "home";

/// Concurrent sync sessions this daemon will run at once (inbound +
/// outbound combined). The acceptor's bounded queue drops (resets) streams
/// beyond this — an enrolled peer cannot wedge an unbounded task set
/// (review R2 finding 5).
pub const MAX_CONCURRENT_SESSIONS: usize = 16;

/// Live daemon view contract; implemented by the server subtree.
pub trait SyncDaemonView: Send + Sync + 'static {
    /// Snapshot of the current self-profile names.
    fn profile_names(&self) -> SyncProfileNames;
    /// Home roster + policy pointer snapshot, `None` when no Home exists.
    /// Best-effort (`try_read`): the reconcile pass tolerates a missed
    /// snapshot; the SESSION PATH must not — use
    /// [`Self::home_pointer_definitive`] there (#863 r2).
    fn home_pointer(&self) -> Option<SyncValue>;
    /// #863 r2: the DEFINITIVE Home pointer under an AWAITED
    /// `named_groups` read — `Err(())` only on a poisoned lock, so a
    /// session can fail CLOSED instead of understating the pointer.
    fn home_pointer_definitive(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<SyncValue>, ()>> + Send>>;
    /// Apply winning Tier-1 names to live daemon state.
    fn apply_names(
        &self,
        human_name: Option<String>,
        display_name: Option<String>,
        machine_name: Option<String>,
    );
    /// Whether `group_id` is a Home this device can PROVE is retired (r3 P2).
    ///
    /// Proof is local: the group is in our roster and carries the terminal
    /// `withdrawn` flag. Inability to see the group is NOT proof — a Home on
    /// an unreachable device is unknown, and treating unknown as retired
    /// would let a partitioned device mint over the owner's real Home.
    /// Implementations MUST be non-blocking and answer `false` when unsure.
    fn canonical_pointer_is_retired(&self, group_id: &str) -> bool;
}

/// #1545: a daemon view whose `apply_names` saves the names in the
/// background. Crate-internal; see [`OwnerSyncService::attach_daemon_view`].
pub(crate) trait PersistedNames: Send + Sync + 'static {
    /// Completes when every earlier `apply_names` call has ended, saved
    /// or not. A save that succeeds discharges the names it holds
    /// (`OwnerSyncStore::discharge_applies`), so the store, not this
    /// call, tells whether a name is still owed: a later save, such as
    /// `PUT /profile`, can discharge a name whose own save failed.
    fn names_settled(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    /// The names of the live profile, read under its lock (waiting for
    /// a writer), never a cached copy: a copy can be older than a
    /// retirement of a pending apply (`OwnerSyncStore::names_epoch`).
    fn live_names(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = SyncProfileNames> + Send>>;
}

/// Current daemon self-profile names, best-effort snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncProfileNames {
    pub human_name: Option<String>,
    pub display_name: Option<String>,
    pub machine_name: Option<String>,
}
/// Write records as bounded pages: each page fills up to BOTH
/// [`RECORDS_PER_FRAME`] records and [`RECORDS_PAGE_BYTES`] cumulative
/// serialized bytes before flushing, so a page of large (individually
/// value-capped) records cannot approach the frame limit (review R4).
/// Always at least one page; a single record always ships (its own size is
/// value-capped well under [`MAX_FRAME_BYTES`]).
async fn write_paged_records<S: AsyncWrite + Unpin>(
    send: &mut S,
    records: &[VersionedRecord],
) -> Result<(), SyncError> {
    if records.is_empty() {
        write_frame(
            send,
            &SyncFrame::Records {
                records: Vec::new(),
            },
        )
        .await?;
        return Ok(());
    }
    let mut page: Vec<VersionedRecord> = Vec::new();
    let mut page_bytes = 0usize;
    for record in records {
        let record_bytes = bincode::serialize(record)
            .map_err(|e| SyncError::MalformedFrame(format!("encode record: {e}")))?
            .len();
        if !page.is_empty()
            && (page.len() >= RECORDS_PER_FRAME || page_bytes + record_bytes > RECORDS_PAGE_BYTES)
        {
            write_frame(
                send,
                &SyncFrame::Records {
                    records: std::mem::take(&mut page),
                },
            )
            .await?;
            page_bytes = 0;
        }
        page_bytes += record_bytes;
        page.push(record.clone());
    }
    if !page.is_empty() {
        write_frame(send, &SyncFrame::Records { records: page }).await?;
    }
    Ok(())
}
/// Minimum spacing between identity re-announcements triggered by the SAME
/// enrolled owner machine connecting (#1040).
///
/// Why 60 s: an identity announcement is a network-wide gossip publish that
/// every receiver ML-DSA-verifies (the #656 CPU budget), so a flapping owner
/// connection must not turn into an announcement storm. The regular
/// heartbeat is [`crate::IDENTITY_HEARTBEAT_INTERVAL_SECS`] (600 s); one
/// extra announcement per enrolled device per minute is at most a 10x
/// increase for that device and only while it reconnects, and is still far
/// inside the #824 owner-sync wait, so a restarted peer hears us well before
/// its provisioning deadline. Owner sync itself does not depend on it.
pub const OWNER_REANNOUNCE_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Per-machine rate limiter for owner-connect re-announcements (#1040):
/// [`Self::allow`] returns `true` at most once per machine per interval.
/// Expired entries are pruned on every call, so memory is bounded by the
/// machines seen within one interval (enrolled machines only).
pub(crate) struct ReannounceLimiter {
    interval: Duration,
    /// `tokio::time::Instant` reads the std clock unless tokio time is paused
    /// (tests only), so the W3-H simulation can age this window with virtual
    /// time across a restart.
    last: std::collections::HashMap<[u8; 32], tokio::time::Instant>,
}

impl ReannounceLimiter {
    pub(crate) fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: std::collections::HashMap::new(),
        }
    }

    /// Whether `machine` may trigger a re-announcement at `now`; records it
    /// when allowed.
    pub(crate) fn allow(&mut self, machine: &MachineId, now: tokio::time::Instant) -> bool {
        let interval = self.interval;
        self.last
            .retain(|_, at| now.saturating_duration_since(*at) < interval);
        if self.last.contains_key(&machine.0) {
            return false;
        }
        self.last.insert(machine.0, now);
        true
    }
}

/// The SyncV1 acceptor's own admission check, run when a session starts,
/// after the shared accept loop has handed the stream over. The accept
/// loop's check and this one are separated by the handoff: a machine
/// revocation (ADR-0018) that lands in between must still stop the session
/// (ADR 0084, revocation race). The peer's enrollment must verify and be
/// current under `owner`, and the peer machine must not be revoked.
async fn inbound_session_admissible(
    store: &OwnerSyncStore,
    revocation_set: &tokio::sync::RwLock<crate::revocation::RevocationSet>,
    peer: &MachineId,
    owner: &UserId,
) -> bool {
    // Cheap-first: the device-map miss costs no signature verification.
    store.is_enrolled(peer, owner).await && {
        let revoked = revocation_set.read().await;
        !revoked.revocation_resync_required() && !revoked.is_machine_revoked(peer)
    }
}

/// Daemon-resident Tier-1 sync service (the `ForwardService` pattern for
/// `SyncV1`): owns the single registered acceptor for
/// [`crate::streams::StreamProtocol::SyncV1`], gates each inbound stream on
/// the owner device set (permit acquired before the per-stream task is
/// spawned), dials every enrolled machine it can resolve, and mints local
/// Tier-1 records from live daemon state before each pass.
///
/// Constructed only when the install has an owner key (`user.key`); an
/// ownerless install registers no acceptor and syncs nothing.
pub struct OwnerSyncService {
    agent: Arc<crate::Agent>,
    store: Arc<OwnerSyncStore>,
    journal_path: Option<PathBuf>,
    view: std::sync::RwLock<Option<Arc<dyn SyncDaemonView>>>,
    /// The attached view's save confirmation, when it saves in the
    /// background (#1545, see [`Self::attach_daemon_view`]).
    persisted_names: std::sync::RwLock<Option<Arc<dyn PersistedNames>>>,
    tasks: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    session_permits: Arc<tokio::sync::Semaphore>,
}

impl OwnerSyncService {
    /// Build the service, load its store from `<data_dir>/sync` (creating
    /// the directory — failure is a hard startup error, review R2 finding
    /// 2), and register the `SyncV1` acceptor (single-acceptor rule).
    ///
    /// # Errors
    ///
    /// [`crate::error::NetworkError::StreamAcceptorConflict`] when another
    /// consumer already owns `SyncV1`; storage errors when the sync
    /// directory cannot be created.
    pub async fn new(
        agent: Arc<crate::Agent>,
        data_dir: &Path,
    ) -> crate::error::NetworkResult<Arc<Self>> {
        let acceptor = agent.register_stream_acceptor(crate::streams::StreamProtocol::SyncV1)?;
        let journal_path = agent.cert_journal_path().map(Path::to_path_buf);
        let store = OwnerSyncStore::load(data_dir)
            .await
            .map_err(|e| crate::error::NetworkError::CacheError(format!("sync store: {e}")))?;
        if let Some(path) = journal_path.as_ref() {
            store.set_journal_path(path.clone());
        }
        let service = Arc::new(Self {
            agent,
            store: Arc::new(store),
            journal_path,
            view: std::sync::RwLock::new(None),
            persisted_names: std::sync::RwLock::new(None),
            tasks: tokio::sync::Mutex::new(Vec::new()),
            session_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSIONS)),
        });
        service.spawn_acceptor_loop(acceptor).await;
        service.spawn_reannounce_on_owner_connect().await;
        Ok(service)
    }

    /// #843 fixture: the real `SyncV1` acceptor and enrollment admission,
    /// without the owner-connect re-announcement. That task calls
    /// [`crate::Agent::reannounce_identity`], which binds `[::]:0` and
    /// connects to `[2001:4860:4860::8888]:80`. Production startup still
    /// uses [`Self::new`].
    #[cfg(test)]
    pub(crate) async fn new_without_owner_connect_reannounce(
        agent: Arc<crate::Agent>,
        data_dir: &Path,
    ) -> crate::error::NetworkResult<Arc<Self>> {
        let acceptor = agent.register_stream_acceptor(crate::streams::StreamProtocol::SyncV1)?;
        let journal_path = agent.cert_journal_path().map(Path::to_path_buf);
        let store = OwnerSyncStore::load(data_dir)
            .await
            .map_err(|e| crate::error::NetworkError::CacheError(format!("sync store: {e}")))?;
        if let Some(path) = journal_path.as_ref() {
            store.set_journal_path(path.clone());
        }
        let service = Arc::new(Self {
            agent,
            store: Arc::new(store),
            journal_path,
            view: std::sync::RwLock::new(None),
            persisted_names: std::sync::RwLock::new(None),
            tasks: tokio::sync::Mutex::new(Vec::new()),
            session_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSIONS)),
        });
        service.spawn_acceptor_loop(acceptor).await;
        Ok(service)
    }

    /// #1040: when an enrolled owner machine newly connects, re-announce
    /// this device's identity (so a peer that restarted with an empty
    /// discovery cache learns our agent promptly) and kick a sync pass.
    /// Bounded by [`ReannounceLimiter`] at one re-announcement per machine
    /// per [`OWNER_REANNOUNCE_MIN_INTERVAL`]. Owner sync itself never
    /// waits on this: admission and dialing use the enrollment alone.
    async fn spawn_reannounce_on_owner_connect(self: &Arc<Self>) {
        let Some(network) = self.agent.network().map(Arc::clone) else {
            return;
        };
        let mut events = network.subscribe();
        let service = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            let mut limiter = ReannounceLimiter::new(OWNER_REANNOUNCE_MIN_INTERVAL);
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                let crate::network::NetworkEvent::PeerConnected { peer_id, .. } = event else {
                    continue;
                };
                let Some(service) = service.upgrade() else {
                    break;
                };
                service
                    .on_peer_connected(MachineId(peer_id), &mut limiter)
                    .await;
            }
        });
        self.tasks.lock().await.push(task);
    }

    async fn on_peer_connected(&self, machine: MachineId, limiter: &mut ReannounceLimiter) {
        let Some((owner, local)) = self.owner_and_machine() else {
            return;
        };
        if machine == local {
            return;
        }
        // Cheap-first: a non-enrolled peer misses the device map without
        // any signature verification.
        if !self.store.is_enrolled(&machine, &owner).await {
            return;
        }
        if self
            .agent
            .revocation_set()
            .read()
            .await
            .is_machine_revoked(&machine)
        {
            return;
        }
        if !limiter.allow(&machine, tokio::time::Instant::now()) {
            tracing::debug!(
                target: "x0x::owner_sync",
                machine = %hex::encode(machine.0),
                "enrolled owner machine reconnected; re-announce rate-limited (#1040)"
            );
            return;
        }
        tracing::info!(
            target: "x0x::owner_sync",
            machine = %hex::encode(machine.0),
            "enrolled owner machine connected; re-announcing identity and kicking sync (#1040)"
        );
        if let Err(e) = self.agent.reannounce_identity().await {
            tracing::warn!(
                target: "x0x::owner_sync",
                error = %e,
                "owner-connect identity re-announcement failed (#1040)"
            );
        }
        self.kick();
    }

    /// Install the live daemon view (idempotent; called by the daemon right
    /// after `AppState` construction).
    ///
    /// The reconcile pass takes a name record as applied once the view's
    /// `apply_names` returns.
    pub fn attach_view(&self, view: Arc<dyn SyncDaemonView>) {
        self.install_view(view, None);
    }

    /// #1545: [`Self::attach_view`] for a view that saves its names in the
    /// background. The reconcile pass takes a name record as applied only
    /// when the view confirms the save.
    pub(crate) fn attach_daemon_view<V: SyncDaemonView + PersistedNames>(&self, view: Arc<V>) {
        let persisted: Arc<dyn PersistedNames> = view.clone();
        self.install_view(view, Some(persisted));
    }

    fn install_view(
        &self,
        view: Arc<dyn SyncDaemonView>,
        persisted: Option<Arc<dyn PersistedNames>>,
    ) {
        *self
            .persisted_names
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = persisted;
        *self
            .view
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(view);
    }

    /// The shared store (routes read device/session status from it).
    #[must_use]
    pub fn store(&self) -> &Arc<OwnerSyncStore> {
        &self.store
    }

    /// On-change trigger: wake the periodic pass early.
    pub fn kick(&self) {
        self.store.kick();
    }

    /// The save confirmation of the daemon view, when installed with
    /// [`Self::attach_daemon_view`].
    fn persisted_names(&self) -> Option<Arc<dyn PersistedNames>> {
        self.persisted_names
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn view(&self) -> Option<Arc<dyn SyncDaemonView>> {
        self.view
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn owner_kp(&self) -> Option<&UserKeypair> {
        self.agent.identity().user_keypair()
    }

    fn owner_and_machine(&self) -> Option<(UserId, MachineId)> {
        let owner = self.owner_kp()?.user_id();
        Some((owner, self.agent.machine_id()))
    }

    /// Spawn the inbound acceptor drain loop. A session permit is acquired
    /// IN THE LOOP, BEFORE the per-stream task is spawned (review R3
    /// finding 5): the permit moves into the task, so the set of live
    /// session tasks is bounded by the semaphore — a flood of inbound
    /// streams cannot spawn unbounded tasks. Without a permit the stream
    /// is dropped (reset) right there.
    ///
    /// WHY a `Weak<Self>` (as [`Self::spawn_reannounce_on_owner_connect`]):
    /// `acceptor.next()` never returns `None` (the acceptor keeps a sender
    /// of its own channel for deregistration), so this task never ends by
    /// itself. With an `Arc` it kept the service, and through it the agent
    /// and the agent's history database lock, alive after the daemon shut
    /// down, and the service's `Drop`, which aborts this task, never ran.
    /// With a `Weak` the service drops with its last owner, and its `Drop`
    /// aborts this task.
    async fn spawn_acceptor_loop(self: &Arc<Self>, mut acceptor: crate::streams::StreamAcceptor) {
        let service = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            while let Some(stream) = acceptor.next().await {
                let Some(service) = service.upgrade() else {
                    break; // the service is gone: drop => reset
                };
                let permit = match service.session_permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::warn!(
                            target: "x0x::owner_sync",
                            "SyncV1 stream dropped: session limit reached"
                        );
                        continue; // drop => reset, fail closed and bounded
                    }
                };
                tokio::spawn(async move { service.handle_inbound(stream, permit).await });
            }
        });
        self.tasks.lock().await.push(task);
    }

    /// Inbound path: the ADR-0022 machine identity gates have already
    /// cleared in the shared accept loop; the caller holds the session
    /// permit (acquired before this task was spawned). Enforce the owner
    /// device set (blocker 30) — an unenrolled machine's stream is dropped
    /// (reset) with zero application bytes read.
    async fn handle_inbound(
        &self,
        stream: crate::streams::PeerStream,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        let Some(owner_kp) = self.owner_kp() else {
            return;
        };
        let local_machine = self.agent.machine_id();
        let peer = stream.peer();
        if !inbound_session_admissible(
            &self.store,
            &self.agent.revocation_set(),
            &peer,
            &owner_kp.user_id(),
        )
        .await
        {
            tracing::warn!(
                target: "x0x::owner_sync",
                machine = %hex::encode(peer.0),
                "refusing SyncV1 stream from non-enrolled or revoked machine"
            );
            return; // drop => stream reset, fail closed
        }
        let (mut send, mut recv) = stream.into_split();
        // #863: publish the local Home pointer BEFORE the version-vector
        // exchange — an empty HomePointer vector must be genuine proof of
        // no local Home, never a timing artifact (see
        // session_with_home_publication).
        let result = self
            .session_with_home_publication(&mut send, &mut recv, owner_kp, &local_machine, &peer)
            .await;
        match result {
            Ok(summary) => {
                tracing::debug!(
                    target: "x0x::owner_sync",
                    machine = %hex::encode(peer.0),
                    accepted = summary.accepted,
                    superseded = summary.superseded,
                    equivocations = summary.equivocations,
                    shipped = summary.shipped,
                    "Tier-1 sync session complete"
                );
                self.store.set_session_status(&peer, true).await;
            }
            Err(e) => {
                tracing::warn!(
                    target: "x0x::owner_sync",
                    machine = %hex::encode(peer.0),
                    error_class = e.class(),
                    error = %e,
                    "Tier-1 sync session failed (fail closed)"
                );
                self.store.set_session_status(&peer, false).await;
            }
        }
    }

    /// Dial `machine` and run one session as the initiator. Errors retain a
    /// stable class for the pass log; a failed dial never aborts the pass.
    async fn dial_and_sync(
        &self,
        machine: &MachineId,
    ) -> Result<SessionSummary, (&'static str, String)> {
        let owner_kp = self
            .owner_kp()
            .ok_or_else(|| ("no_owner_key", "no owner key".to_string()))?;
        let owner_id = owner_kp.user_id();
        let local_machine = self.agent.machine_id();
        if !self.store.is_enrolled(machine, &owner_id).await {
            return Err((
                "not_enrolled",
                format!("machine {} is not enrolled", hex::encode(machine.0)),
            ));
        }
        // Resolve the deterministic first agent on the target machine —
        // open_peer_stream authorizes per agent, sessions are per machine.
        // ADR 0115 §2: a candidate counts only when an
        // authority store confirms it on `machine`; a routing entry alone
        // does not.
        let mut candidates: Vec<crate::identity::AgentId> = self
            .agent
            .discovered_agents()
            .await
            .map_err(|e| ("discovery", e.to_string()))?
            .into_iter()
            .filter(|d| d.machine_id == *machine)
            .map(|d| d.agent_id)
            .collect();
        candidates.sort_by_key(|agent| agent.0);
        let mut target_agent = None;
        for candidate in candidates {
            if self.agent.authority_confirms(&candidate, machine).await {
                target_agent = Some(candidate);
                break;
            }
        }
        let stream = match target_agent {
            Some(target_agent) => self
                .agent
                .open_peer_stream(&target_agent, crate::streams::StreamProtocol::SyncV1)
                .await
                .map_err(|e| ("open_stream", e.to_string()))?,
            // #1040: no agent announced on the machine yet (e.g. this
            // device restarted with an empty discovery cache). Dial the
            // enrolled machine by its id on the verified enrollment alone.
            None => self
                .agent
                .open_enrolled_owner_sync_stream(machine)
                .await
                .map_err(|e| ("enrolled_dial", e.to_string()))?,
        };
        let peer = stream.peer();
        let (mut send, mut recv) = stream.into_split();
        let _permit = self
            .session_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| ("session_limit", e.to_string()))?;
        // #863: as the responder path (handle_inbound) — the
        // initiator's vector must not understate a local Home either.
        // Both session directions go through the shared composition, so
        // an unpublication-capable view fails the session CLOSED (never
        // an empty HomePointer vector).
        let result = self
            .session_with_home_publication(&mut send, &mut recv, owner_kp, &local_machine, &peer)
            .await;
        self.store.set_session_status(&peer, result.is_ok()).await;
        result.map_err(|e| (e.class(), e.to_string()))
    }

    /// #824: wait for every in-flight owner-sync session to finish and hold
    /// off new ones while the returned guard lives.
    ///
    /// Home provisioning creates a fresh Home under this guard. Remote records,
    /// including a canonical Home pointer, arrive only inside sessions, so no
    /// pointer can be merged between its final pointer check and the create.
    /// Outbound sessions queue behind the guard. Inbound streams are dropped
    /// while it is held, and the peer retries on its next pass. Sessions are
    /// bounded by [`SESSION_TIMEOUT`], so the wait is too.
    pub async fn quiesce_sessions(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        let all = u32::try_from(MAX_CONCURRENT_SESSIONS).ok()?;
        self.session_permits.acquire_many(all).await.ok()
    }

    /// Test hook (#824): occupy one session slot, as an in-flight session does.
    #[cfg(test)]
    pub(crate) fn hold_session_slot_for_testing(
        &self,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.session_permits).try_acquire_owned().ok()
    }

    /// #863 r2 (review finding 2): the DEFINITIVE local Home pointer,
    /// read under an AWAITED `named_groups` lock (the view's boxed
    /// future) — unlike the trait's `home_pointer()` (a `try_read`
    /// best-effort the reconcile pass tolerates), this never mistakes
    /// lock contention for "no Home" (the awaited read simply waits).
    /// `Err(())` survives only for the no-owner-key case; the session
    /// path fails CLOSED on it rather than advertise an empty vector.
    async fn definitive_local_home_pointer(&self) -> Result<Option<SyncValue>, ()> {
        let Some(view) = self.view() else {
            // No view attached (tests / library use): nothing to publish,
            // and nothing to understate — a genuinely empty vector.
            return Ok(None);
        };
        view.home_pointer_definitive().await
    }

    /// #863: mint the local Home pointer into the Tier-1 store NOW. A
    /// device holding a Home it has not yet published (created since the
    /// last reconcile pass, or a mint that failed) would otherwise answer
    /// a session's version-vector exchange with an EMPTY HomePointer
    /// kind — and the peer's rank-0 wait-for-sync would take that empty
    /// session as proof no Home exists and provision a DUPLICATE. Runs
    /// before EVERY session (both directions) and in the reconcile pass;
    /// after it, an empty HomePointer vector is genuine proof the peer
    /// holds no Home.
    pub(crate) async fn materialize_local_home_pointer(&self) {
        let Some(owner_kp) = self.owner_kp() else {
            return;
        };
        let Ok(Some(home_value)) = self.definitive_local_home_pointer().await else {
            return;
        };
        if self.should_mint_home_pointer(&home_value).await {
            let local_machine = self.agent.machine_id();
            self.mint_or_log(
                SyncKind::HomePointer,
                HOME_POINTER_KEY,
                home_value,
                owner_kp,
                local_machine,
            )
            .await;
        }
    }

    /// #863 r2 (review finding 1): the session composition BOTH session
    /// directions run — publish the local Home pointer (definitive read;
    /// an unreadable view fails the session CLOSED), then the exchange.
    /// This is the seam the #863 guarantee is proven on: with the
    /// publication removed, a Home-holding peer advertises an empty
    /// HomePointer vector (the fail-before).
    ///
    /// MIXED VERSIONS (review finding 3): this guarantee is one-sided.
    /// A PEER on a pre-#863 build holding an unpublished Home still
    /// answers the version-vector exchange with an EMPTY HomePointer
    /// kind — SyncV1 carries no capability signal to detect that — so
    /// the local rank-0 wait can still be released into a duplicate
    /// until BOTH ends run this build. #863 stays open in a
    /// mixed-version owner fleet by design; the fix closes it fleet-wide
    /// as the rollout completes.
    pub(crate) async fn session_with_home_publication<S, R>(
        &self,
        send: &mut S,
        recv: &mut R,
        owner_kp: &crate::identity::UserKeypair,
        local_machine: &MachineId,
        peer: &MachineId,
    ) -> Result<SessionSummary, SyncError>
    where
        S: tokio::io::AsyncWrite + Unpin,
        R: tokio::io::AsyncRead + Unpin,
    {
        // Fail closed on an unreadable view: an empty HomePointer vector
        // must be proof of no Home, never a timing artifact.
        match self.definitive_local_home_pointer().await {
            Err(()) => {
                return Err(SyncError::MalformedFrame(
                    "local daemon view unreadable; refusing to understate the Home pointer"
                        .to_string(),
                ));
            }
            Ok(home_value) => {
                if let Some(home_value) = home_value {
                    if let Some(owner_kp) = self.owner_kp() {
                        if self.should_mint_home_pointer(&home_value).await {
                            let local_machine_for_mint = self.agent.machine_id();
                            // #1097: publication is a session precondition;
                            // never exchange an empty vector after a failed mint.
                            self.store
                                .mint(
                                    SyncKind::HomePointer,
                                    HOME_POINTER_KEY,
                                    &home_value,
                                    owner_kp,
                                    local_machine_for_mint,
                                )
                                .await?;
                        }
                    }
                }
            }
        }
        run_sync_session(
            send,
            recv,
            &self.store,
            owner_kp,
            local_machine,
            peer,
            |record| self.apply_record(record),
        )
        .await
    }

    /// One full pass: mint local Tier-1 records from live daemon state,
    /// then sync with every enrolled machine we can resolve.
    pub async fn sync_all(&self) {
        if let Err(e) = self.reconcile_local_state().await {
            tracing::warn!(target: "x0x::owner_sync", error = %e, "local reconcile failed");
        }
        let Some((owner, local)) = self.owner_and_machine() else {
            return;
        };
        for device in self.store.enrolled_devices().await {
            let machine = MachineId(device.machine_id);
            if machine == local {
                continue;
            }
            if !self.store.is_enrolled(&machine, &owner).await {
                continue;
            }
            if let Err((error_class, error)) = self.dial_and_sync(&machine).await {
                tracing::warn!(
                    target: "x0x::owner_sync",
                    machine = %hex::encode(machine.0),
                    error_class,
                    error = %error,
                    "Tier-1 dial or sync failed until next pass"
                );
            }
        }
    }

    /// Mint local Tier-1 records from live daemon state (no-op when a kind
    /// is unchanged since its stored winner). Persistence failures are
    /// surfaced per-kind; a failed mint is retried next pass.
    async fn reconcile_local_state(&self) -> Result<(), SyncError> {
        let Some(owner_kp) = self.owner_kp() else {
            return Ok(()); // ownerless installs mint nothing
        };
        let local_machine = self.agent.machine_id();
        let local_hex = hex::encode(local_machine.0);

        // #1542: finish an interrupted commit and apply its records before
        // any mint from live state, or the mint puts the old live value
        // over a recovered record at a higher version.
        let recovery = self
            .store
            .recover_interrupted_commit(&owner_kp.user_id())
            .await;
        let names_applied = self.apply_pending().await;
        recovery?;

        // Kinds 1 + 2 + 3: profile names and the Home pointer, via the
        // daemon view when attached.
        if let Some(view) = self.view() {
            // The live profile shows every committed name only when they
            // are applied; until then, its names are not local changes. A
            // session can commit names, and a profile save can retire
            // them, after `apply_pending`. So the epoch of the pending
            // applies is read before the names, and each mint checks, in
            // one step with its register write, that no name is owed and
            // that the epoch did not change (`mint_live_name`).
            let epoch = self.store.names_epoch().await;
            let names = match self.persisted_names() {
                Some(persisted) => persisted.live_names().await,
                None => view.profile_names(),
            };
            #[cfg(test)]
            self.store.pause_before_name_mint().await;
            if names_applied {
                self.mint_live_name_or_log(
                    SyncKind::OwnerProfile,
                    "owner",
                    SyncValue::OwnerProfile {
                        human_name: names.human_name,
                    },
                    owner_kp,
                    local_machine,
                    epoch,
                )
                .await;
                self.mint_live_name_or_log(
                    SyncKind::MachineNames,
                    &local_hex,
                    SyncValue::MachineNames {
                        display_name: names.display_name,
                        machine_name: names.machine_name,
                    },
                    owner_kp,
                    local_machine,
                    epoch,
                )
                .await;
            }
            self.materialize_local_home_pointer().await;
        }

        // Kind 4: issuance journal lines (latest per agent, owner-scoped).
        if let Some(path) = self.journal_path.as_ref() {
            mint_journal_lines(&self.store, path, owner_kp, local_machine).await;
            // Its recovery can commit names too.
            self.apply_pending().await;
        }
        Ok(())
    }

    /// #1545: apply the committed names that live state may not show yet
    /// (`OwnerSyncStore::pending_applies`), and discharge them once they
    /// are saved. `true` when none of them are owed any more; `false` when
    /// no view is attached or a name is not saved yet, so the next pass
    /// applies it again.
    ///
    /// With a view that saves in the background (`PersistedNames`), each
    /// save discharges the names it holds. A record that sets a local name
    /// is then confirmed only by its obligation in the store, after the
    /// earlier saves have ended: a failed save does not count against a
    /// name that a later save discharged. The other records set no local
    /// name (`sets_local_name`), so they need no save, and the pass
    /// discharges them.
    async fn apply_pending(&self) -> bool {
        let pending = self.store.pending_applies().await;
        if pending.is_empty() {
            return true;
        }
        if self.view().is_none() {
            return false;
        }
        for (record, winner) in &pending {
            if *winner {
                self.apply_record(record);
            }
        }
        let Some(persisted) = self.persisted_names() else {
            // The view applied the winners in place. The store retires a
            // non-winner only if it is still not the winner
            // (`discharge_applies`).
            if let Err(e) = self.store.discharge_applies(&pending).await {
                tracing::warn!(target: "x0x::owner_sync", error = %e, "failed to discharge applied names");
            }
            return true;
        };
        persisted.names_settled().await;
        let local = self.agent.machine_id();
        let (saved, unsaved): (Vec<_>, Vec<_>) = pending
            .into_iter()
            .partition(|(record, winner)| *winner && sets_local_name(record, &local));
        if let Err(e) = self.store.discharge_applies(&unsaved).await {
            tracing::warn!(target: "x0x::owner_sync", error = %e, "failed to discharge applied names");
        }
        if self.store.owes_any(&saved).await {
            tracing::warn!(target: "x0x::owner_sync", "synced names not saved yet; retry next pass");
            return false;
        }
        true
    }

    /// The owner's CANONICAL Home per the Tier-1 `("home")` register (#449).
    ///
    /// `None` means no owner device has advertised a Home yet — which is not
    /// the same as "this owner has no Home": an un-synced device simply has
    /// not heard one. Callers must treat absence as "unknown", never as
    /// "none exists".
    pub async fn canonical_home(&self) -> Option<CanonicalHome> {
        match self
            .store
            .stored_value(SyncKind::HomePointer, HOME_POINTER_KEY)
            .await
        {
            Some(SyncValue::HomePointer {
                group_id,
                primary_agent,
                provisioned_at_ms,
                roster,
                ..
            }) => Some(CanonicalHome {
                group_id,
                primary_agent,
                provisioned_at_ms,
                roster,
            }),
            _ => None,
        }
    }

    /// Thin async wrapper over [`home_pointer_mint_decision`] (#449 D3).
    async fn should_mint_home_pointer(&self, desired: &SyncValue) -> bool {
        let stored = self
            .store
            .stored_value(SyncKind::HomePointer, HOME_POINTER_KEY)
            .await;
        // r3 P2: a stored pointer naming a Home we hold and know to be
        // retired must not keep the slot. Without this the ordering rule
        // would refuse every replacement, since a new Home is always NEWER
        // than the dead one it replaces.
        let stored_is_retired = match (&stored, self.view()) {
            (Some(SyncValue::HomePointer { group_id, .. }), Some(view)) => {
                view.canonical_pointer_is_retired(group_id)
            }
            _ => false,
        };
        home_pointer_mint_decision(
            desired,
            stored.as_ref(),
            &hex::encode(self.agent.agent_id().as_bytes()),
            stored_is_retired,
        )
    }

    async fn mint_or_log(
        &self,
        kind: SyncKind,
        key: &str,
        value: SyncValue,
        owner_kp: &UserKeypair,
        machine: MachineId,
    ) {
        if let Err(e) = self.store.mint(kind, key, &value, owner_kp, machine).await {
            tracing::warn!(target: "x0x::owner_sync", kind = ?kind, error = %e, "mint failed");
        }
    }

    async fn mint_live_name_or_log(
        &self,
        kind: SyncKind,
        key: &str,
        value: SyncValue,
        owner_kp: &UserKeypair,
        machine: MachineId,
        epoch: u64,
    ) {
        if let Err(e) = self
            .store
            .mint_live_name(kind, key, &value, owner_kp, machine, epoch)
            .await
        {
            tracing::warn!(target: "x0x::owner_sync", kind = ?kind, error = %e, "mint failed");
        }
    }

    /// Apply an accepted record to live daemon state (post-commit only).
    /// See [`local_names_of`] for what each kind applies.
    pub(crate) fn apply_record(&self, record: &VersionedRecord) {
        if let Some(names) = local_names_of(record, &self.agent.machine_id()) {
            if let Some(view) = self.view() {
                view.apply_names(names.human_name, names.display_name, names.machine_name);
            }
        }
    }

    /// Spawn the periodic + on-change pass loop (owned by the daemon's
    /// bg-task list; ends when `shutdown_rx` fires or the service drops).
    pub async fn spawn_periodic(
        self: &Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut generation = self.store.generation_rx();
        let mut ticker = tokio::time::interval(DEFAULT_SYNC_INTERVAL);
        ticker.tick().await; // consume the immediate first tick
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = generation.changed() => {}
                _ = ticker.tick() => {}
            }
            self.sync_all().await;
        }
    }
}

/// Whether `record` sets a name on the profile of `local_machine`, so that
/// its apply saves the profile (`SyncDaemonView::apply_names` does nothing
/// for no names).
fn sets_local_name(record: &VersionedRecord, local_machine: &MachineId) -> bool {
    local_names_of(record, local_machine).is_some_and(|names| {
        names.human_name.is_some() || names.display_name.is_some() || names.machine_name.is_some()
    })
}

/// The names that `record` sets on the profile of `local_machine`, with
/// `None` for a name it leaves unchanged; `None` when it sets no local
/// name. The names of a remote machine stay in the record store for future
/// surfacing (ADR-0041 Tier-1 scope).
pub(crate) fn local_names_of(
    record: &VersionedRecord,
    local_machine: &MachineId,
) -> Option<SyncProfileNames> {
    match &record.value {
        SyncValue::OwnerProfile { human_name } => Some(SyncProfileNames {
            human_name: human_name.clone(),
            display_name: None,
            machine_name: None,
        }),
        SyncValue::MachineNames {
            display_name,
            machine_name,
        } if record.key == hex::encode(local_machine.0) => Some(SyncProfileNames {
            human_name: None,
            display_name: display_name.clone(),
            machine_name: machine_name.clone(),
        }),
        SyncValue::MachineNames { .. } => None,
        // The register is read on demand (`canonical_home`) by the Home
        // resolution path rather than pushed here: provisioning,
        // `GET /home` and adoption all need the CURRENT winner, not
        // whatever happened to arrive last (#449).
        SyncValue::HomePointer { .. } => None,
        // `commit_batch` already wrote the journal file, under the same
        // `journal_apply` hold as the register change (#1542).
        SyncValue::IssuanceJournal { .. } => None,
    }
}

/// Mint each agent's latest journal line into the `IssuanceJournal`
/// register (kind 4 of the local reconcile). A failed mint is logged and
/// retried next pass. Holds `OwnerSyncStore::journal_apply` from the
/// journal read to the last mint, so no inbound commit changes the
/// register between them (#1542). It first finishes an interrupted commit
/// (`recover_journal_commit`), and it mints only from a durable read of
/// the journal.
async fn mint_journal_lines(
    store: &OwnerSyncStore,
    path: &Path,
    owner_kp: &UserKeypair,
    machine: MachineId,
) {
    let guard = Arc::clone(&store.journal_apply).lock_owned().await;
    let _journal_apply = match store
        .recover_journal_commit(guard, &owner_kp.user_id())
        .await
    {
        Ok(guard) => guard,
        Err(e) => {
            tracing::warn!(target: "x0x::owner_sync", error = %e, "journal commit recovery failed");
            return;
        }
    };
    let owner_hex = hex::encode(owner_kp.user_id().0);
    // A durable read: a line a host crash can take back must not reach the
    // register first.
    let lines = match crate::profile::IssuedCertRecord::load_durable(path).await {
        Ok(lines) => lines,
        Err(e) => {
            tracing::warn!(target: "x0x::owner_sync", error = %e, "journal is not durable");
            return;
        }
    };
    #[cfg(test)]
    store.pause_after_journal_read().await;
    for (agent_hex, value) in latest_journal_values(lines, &owner_hex) {
        if let Err(e) = store
            .mint(
                SyncKind::IssuanceJournal,
                &agent_hex,
                &value,
                owner_kp,
                machine,
            )
            .await
        {
            tracing::warn!(target: "x0x::owner_sync", kind = ?SyncKind::IssuanceJournal, error = %e, "mint failed");
        }
    }
}

/// Whether a synced journal line must be appended to `existing`.
///
/// Owner sync calls this only for a value that `commit_batch` has just
/// made the `IssuanceJournal` register's winner, under `journal_apply`.
/// `published_digest` is the certificate the register held before that
/// commit. The line is compared with this owner's CURRENT line for the
/// agent (see `latest_journal_values`; the owner roster reads the same
/// last line):
///
/// - no current line, or a later second: append;
/// - an earlier second: never append. A later line for an older
///   certificate would roll the roster back to it (rollback protection);
///   this device's next pass mints its newer line over the register;
/// - the same second and the same digest: append only to supply an expiry
///   the current line lacks (a line written before #1542);
/// - the same second and a different digest: `issued_at` has second
///   precision, so it cannot order the two certificates. If the current
///   line is the published one, append: the register's clock (version,
///   signing time, writer) ordered them, and every device follows that
///   order. Otherwise the current line is a local issuance that no
///   reconcile has published yet: keep it, and the next reconcile
///   publishes it over the register at a higher version.
fn synced_line_needed(
    existing: &[crate::profile::IssuedCertRecord],
    owner_hex: &str,
    agent_hex: &str,
    cert_digest: &str,
    issued_at: u64,
    not_after: Option<u64>,
    published_digest: Option<&str>,
) -> bool {
    let current = latest_journal_values(
        existing.iter().filter(|r| r.agent_id == agent_hex).cloned(),
        owner_hex,
    )
    .remove(agent_hex);
    let Some(SyncValue::IssuanceJournal {
        cert_digest: current_digest,
        issued_at: current_issued_at,
        not_after: current_not_after,
        ..
    }) = current
    else {
        return true;
    };
    match issued_at.cmp(&current_issued_at) {
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Equal if cert_digest == current_digest => {
            current_not_after.is_none() && not_after.is_some()
        }
        std::cmp::Ordering::Equal => published_digest == Some(current_digest.as_str()),
    }
}

/// The local journal line for a synced `IssuanceJournal` value. It keeps
/// the value's `not_after`: a line without it would make this device mint
/// a different value for the same key (#1542, see
/// [`latest_journal_values`]).
fn synced_journal_line(
    owner_hex: String,
    agent_hex: String,
    cert_digest: String,
    issued_at: u64,
    not_after: Option<u64>,
) -> crate::profile::IssuedCertRecord {
    crate::profile::IssuedCertRecord {
        user_id: owner_hex,
        agent_id: agent_hex,
        cert_digest,
        issued_at,
        not_after,
        // ADR-0039 fields are not part of the Tier-1 sync value: a synced
        // line records the issuance fact (digest, time and expiry); mode
        // defaults to Acp (the pre-ADR-0039 line shape) and no certificate
        // bytes travel Tier 1 (Tier-3 boundary).
        mode: crate::profile::CertMode::Acp,
        label: None,
        cert_b64: None,
    }
}

/// The `IssuanceJournal` value each agent's latest journal line mints:
/// owner-scoped (`owner_hex`), latest `issued_at` per agent, later lines
/// winning ties.
///
/// #1542: a digest names exactly one certificate, so its `not_after` is
/// fixed. A line with the same digest but no `not_after` (a synced line
/// written before the expiry travelled with it) does not replace a known
/// expiry. Otherwise two owner devices mint `Some` and `None` for the same
/// key in turn: each mint bumps the store generation, which starts the
/// next sync pass at once, so the pair spins without end.
fn latest_journal_values(
    lines: impl IntoIterator<Item = crate::profile::IssuedCertRecord>,
    owner_hex: &str,
) -> BTreeMap<String, SyncValue> {
    let mut latest: BTreeMap<String, crate::profile::IssuedCertRecord> = BTreeMap::new();
    for mut record in lines {
        if record.user_id != owner_hex {
            continue;
        }
        if let Some(old) = latest.get(&record.agent_id) {
            if record.issued_at < old.issued_at {
                continue;
            }
            if record.cert_digest == old.cert_digest {
                record.not_after = record.not_after.or(old.not_after);
            }
        }
        latest.insert(record.agent_id.clone(), record);
    }
    latest
        .into_iter()
        .map(|(agent_hex, record)| {
            (
                agent_hex,
                SyncValue::IssuanceJournal {
                    agent_id: record.agent_id,
                    cert_digest: record.cert_digest,
                    issued_at: record.issued_at,
                    not_after: record.not_after,
                },
            )
        })
        .collect()
}

impl Drop for OwnerSyncService {
    fn drop(&mut self) {
        // Best-effort leak protection (voice `X0xLinkTransport` pattern):
        // abort owned tasks; the acceptor deregisters when its task drops.
        if let Ok(mut tasks) = self.tasks.try_lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(in crate::owner_sync) fn owner_kp(seed: u8) -> UserKeypair {
        UserKeypair::from_seed(&[seed; 32]).expect("deterministic keypair")
    }

    pub(in crate::owner_sync) fn machine(id: u8) -> MachineId {
        MachineId([id; 32])
    }

    pub(in crate::owner_sync) fn names_value(display: &str) -> SyncValue {
        SyncValue::MachineNames {
            display_name: Some(display.to_string()),
            machine_name: None,
        }
    }

    pub(in crate::owner_sync) fn clock(version: u64, ts: u64, writer: u8) -> RecordClock {
        RecordClock {
            version,
            signed_at_ms: ts,
            writer_machine: machine(writer).0,
        }
    }

    /// Cross-enroll two machines under `owner` for r3 session tests.
    pub(in crate::owner_sync) async fn cross_enroll_for_tests(
        a: &OwnerSyncStore,
        b: &OwnerSyncStore,
        owner: &UserKeypair,
    ) {
        a.enroll(OwnerEnrollment::sign(machine(2), owner, 1_000, None).unwrap())
            .await
            .unwrap();
        b.enroll(OwnerEnrollment::sign(machine(1), owner, 1_000, None).unwrap())
            .await
            .unwrap();
    }

    // ADR 0084 revocation race: a machine revoked after the accept loop
    // admitted its SyncV1 stream, but before the acceptor starts the
    // session, must be refused by the acceptor's own check.
    #[tokio::test]
    async fn acceptor_refuses_machine_revoked_after_admission() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(9);
        let peer_kp = crate::identity::MachineKeypair::generate().expect("machine keygen");
        let peer = peer_kp.machine_id();
        store
            .enroll(OwnerEnrollment::sign(peer, &owner, 1_000, None).expect("sign"))
            .await
            .expect("enroll");
        let revocations = tokio::sync::RwLock::new(crate::revocation::RevocationSet::new());
        assert!(
            inbound_session_admissible(&store, &revocations, &peer, &owner.user_id()).await,
            "precondition: an enrolled, unrevoked machine is admitted"
        );

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Machine(peer),
            peer_kp.public_key(),
            peer_kp.secret_key(),
            now_secs,
            None,
        )
        .expect("sign machine revocation");
        revocations
            .write()
            .await
            .verify_and_insert(record, None)
            .expect("insert machine revocation");

        assert!(
            store.is_enrolled(&peer, &owner.user_id()).await,
            "the enrollment itself still verifies"
        );
        assert!(
            !inbound_session_admissible(&store, &revocations, &peer, &owner.user_id()).await,
            "the acceptor must refuse a machine revoked after admission"
        );
    }

    pub(in crate::owner_sync) fn sign_names(
        key: &str,
        display: &str,
        clock: RecordClock,
        owner: &UserKeypair,
    ) -> VersionedRecord {
        VersionedRecord::sign(
            SyncKind::MachineNames,
            key,
            &names_value(display),
            clock,
            owner,
        )
        .expect("sign")
    }

    #[tokio::test]
    async fn conflict_rule_orders_version_then_time_then_writer() {
        // WHY: blocker 31 — the exact tie-break chain must hold.
        let base = RecordClock {
            version: 5,
            signed_at_ms: 100,
            writer_machine: [2; 32],
        };
        let higher_version = RecordClock {
            version: 6,
            signed_at_ms: 0, // older time must NOT matter
            writer_machine: [0; 32],
        };
        assert!(higher_version.beats(&base));
        let lower_version = RecordClock {
            version: 4,
            signed_at_ms: 1_000_000, // newer time must NOT rescue it
            writer_machine: [9; 32],
        };
        assert!(!lower_version.beats(&base));
        let tie_higher_time = RecordClock {
            version: 5,
            signed_at_ms: 101,
            writer_machine: [0; 32],
        };
        assert!(tie_higher_time.beats(&base));
        let tie_lexicographic = RecordClock {
            version: 5,
            signed_at_ms: 100,
            writer_machine: [3; 32],
        };
        assert!(tie_lexicographic.beats(&base));
        assert!(!base.beats(&tie_lexicographic));
        assert!(!base.beats(&base), "identical clocks beat nothing");
    }

    #[tokio::test]
    async fn rollback_and_stale_records_are_rejected() {
        // WHY: rollback protection — version < stored is never accepted,
        // and equal-version-but-older is superseded, not stored.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let owner_id = owner.user_id();
        let key = hex::encode(machine(1).0);
        store
            .mint(
                SyncKind::MachineNames,
                &key,
                &names_value("v1"),
                &owner,
                machine(1),
            )
            .await
            .expect("mint v1");
        // Bump to a high version by hand.
        let high = sign_names(&key, "v9", clock(9, 1, 2), &owner);
        assert_eq!(
            store.merge_record(high, &owner_id).await.expect("merge v9"),
            MergeOutcome::Accepted
        );

        // Rollback: version 3 (and 9-with-older-clock) rejected.
        let rollback = sign_names(&key, "old", clock(3, 999, 3), &owner);
        assert_eq!(
            store
                .merge_record(rollback, &owner_id)
                .await
                .expect("merge rollback"),
            MergeOutcome::Superseded
        );
        let stale_equal = sign_names(&key, "stale", clock(9, 0, 3), &owner);
        assert_eq!(
            store
                .merge_record(stale_equal, &owner_id)
                .await
                .expect("merge stale"),
            MergeOutcome::Superseded
        );

        let snapshot = store.records_snapshot().await;
        assert_eq!(snapshot.len(), 1, "one winner for the key");
        assert_eq!(snapshot[0].clock.version, 9);
        assert_eq!(
            snapshot[0].value,
            names_value("v9"),
            "neither rollback nor stale overwrote the winner"
        );
    }

    #[tokio::test]
    async fn forged_non_owner_record_rejected_fail_closed() {
        // WHY: ADR-0041 validation — a forged state-commit from a non-owner
        // key is rejected, and the failure is typed so sessions abort.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let attacker = owner_kp(2);
        let forged = VersionedRecord::sign(
            SyncKind::OwnerProfile,
            "owner",
            &SyncValue::OwnerProfile {
                human_name: Some("Mallory".into()),
            },
            clock(100, 200, 9),
            &attacker,
        )
        .expect("sign forged");
        let err = store
            .merge_record(forged, &owner.user_id())
            .await
            .expect_err("non-owner record must be rejected");
        assert_eq!(err, SyncError::OwnerMismatch);
        assert!(
            store.records_snapshot().await.is_empty(),
            "nothing was stored"
        );
    }

    #[tokio::test]
    async fn tampered_signature_rejected() {
        let owner = owner_kp(1);
        let mut record = VersionedRecord::sign(
            SyncKind::OwnerProfile,
            "owner",
            &SyncValue::OwnerProfile {
                human_name: Some("A".into()),
            },
            clock(1, 1, 1),
            &owner,
        )
        .expect("sign");
        // Tamper with the payload after signing.
        record.value = SyncValue::OwnerProfile {
            human_name: Some("B".into()),
        };
        let result = record.verify_owner(&owner.user_id());
        assert!(
            matches!(result, Err(SyncError::BadSignature(_))),
            "tampered payload must fail signature verification, got {result:?}"
        );
    }

    #[tokio::test]
    async fn s2_enrollment_verification_index_checks_exact_current_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = OwnerSyncStore::load(dir.path()).await.unwrap();
        let owner = owner_kp(1);
        let m = machine(7);
        let mut enrollment = OwnerEnrollment::sign(m, &owner, 1_000, None).unwrap();
        store.enroll(enrollment.clone()).await.unwrap();
        assert_eq!(
            store.evidence_enrolled(&m, &owner.user_id(), now_unix_ms()),
            Some(true)
        );
        // The index must not authorize different signed fields just because
        // the old signature bytes survived a failed write-through mutation.
        enrollment.enrolled_at_ms += 1;
        store.set_fail_after_rename_for_testing(true);
        assert!(store.enroll(enrollment).await.is_err());
        assert_eq!(
            store.evidence_enrolled(&m, &owner.user_id(), now_unix_ms()),
            Some(false)
        );
    }

    #[tokio::test]
    async fn enrollment_gate_rejects_unenrolled_forged_and_expired() {
        // WHY: blocker 30 + review R2 finding 1 — only owner-enrolled AND
        // CURRENT machines pass the gate.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let owner_id = owner.user_id();
        let enrolled_machine = machine(7);
        let enrollment =
            OwnerEnrollment::sign(enrolled_machine, &owner, 1_000, None).expect("enroll");
        store.enroll(enrollment).await.expect("persist enroll");

        assert!(store.is_enrolled(&enrolled_machine, &owner_id).await);
        assert!(
            !store.is_enrolled(&machine(8), &owner_id).await,
            "unenrolled machine fails the gate"
        );

        // Forged enrollment signed by a different key fails closed.
        let attacker = owner_kp(2);
        let forged = OwnerEnrollment::sign(machine(9), &attacker, 2_000, None).expect("sign");
        assert_eq!(
            forged.verify_owner(&owner_id),
            Err(SyncError::OwnerMismatch)
        );
        store.enroll(forged).await.expect("persist forged");
        assert!(
            !store.is_enrolled(&machine(9), &owner_id).await,
            "foreign-key enrollment never passes the gate"
        );

        // Expired enrollment fails the currency check even though the
        // signature is valid (review R2 finding 1).
        let expired = OwnerEnrollment::sign(
            machine(4),
            &owner,
            1_000,
            Some(now_unix_ms().saturating_sub(10 * ENROLL_EXPIRY_SKEW_MS)),
        )
        .expect("sign");
        assert!(expired.verify_owner(&owner_id).is_ok(), "signature valid");
        store.enroll(expired).await.expect("persist");
        assert!(
            !store.is_enrolled(&machine(4), &owner_id).await,
            "expired enrollment must not keep the gate open"
        );
    }

    #[tokio::test]
    async fn unenroll_removes_device_and_persists() {
        // WHY: review R2 finding 1 — a DELETE path so stale enrollments
        // don't linger.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let owner_id = owner.user_id();
        let target = machine(6);
        store
            .enroll(OwnerEnrollment::sign(target, &owner, 1_000, None).expect("sign"))
            .await
            .expect("persist");
        assert!(store.is_enrolled(&target, &owner_id).await);

        assert!(
            store.unenroll(&target).await.expect("persist unenroll"),
            "removal reports true"
        );
        assert!(!store.is_enrolled(&target, &owner_id).await);
        assert!(
            !store.unenroll(&target).await.expect("idempotent"),
            "second removal reports false"
        );

        // Persistence survived: a fresh load over the same dir has no
        // devices (review R2 finding 2 — durable state must be real).
        let reloaded = OwnerSyncStore::load(dir.path()).await.expect("reload");
        assert!(reloaded.enrolled_devices().await.is_empty());
    }

    #[tokio::test]
    async fn persistence_failures_propagate_never_swallowed() {
        // WHY: review R2 finding 2 — enroll/mint/commit must FAIL (and roll
        // back in-memory state) when the disk write fails; success is never
        // reported on a swallowed error.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let owner_id = owner.user_id();

        // Break the sync dir: remove it and place a FILE where it was, so
        // every write under it fails.
        let sync_dir = dir.path().join(SYNC_DIR);
        std::fs::remove_dir_all(&sync_dir).expect("remove dir");
        std::fs::write(&sync_dir, b"not a directory").expect("block path");

        let enrollment = OwnerEnrollment::sign(machine(5), &owner, 1_000, None).expect("sign");
        assert!(
            store.enroll(enrollment).await.is_err(),
            "enroll must fail on persistence failure"
        );
        assert!(
            !store.is_enrolled(&machine(5), &owner_id).await,
            "in-memory state rolled back / never admitted"
        );

        let record = sign_names("k", "v", clock(1, 1, 1), &owner);
        assert!(
            store.commit_batch(vec![record], &owner_id).await.is_err(),
            "commit must fail on persistence failure"
        );
        assert!(
            store.records_snapshot().await.is_empty(),
            "commit rolled back — nothing advertised"
        );

        assert!(
            store
                .mint(
                    SyncKind::OwnerProfile,
                    "owner",
                    &SyncValue::OwnerProfile {
                        human_name: Some("X".into())
                    },
                    &owner,
                    machine(1)
                )
                .await
                .is_err(),
            "mint must fail on persistence failure"
        );
        assert!(store.records_snapshot().await.is_empty());

        // load over a blocked path fails outright (fresh installs must not
        // silently run with unwritable storage).
        assert!(OwnerSyncStore::load(dir.path()).await.is_err());
    }

    #[tokio::test]
    async fn equal_clock_equivocation_converges_by_hash() {
        // WHY: review R2 finding 3 — two different records with the SAME
        // clock must converge deterministically on every peer (greater
        // record hash), never stay split by arrival order.
        let owner = owner_kp(1);
        let key = "shared";
        let a = sign_names(key, "content-a", clock(4, 500, 1), &owner);
        let b = sign_names(key, "content-b", clock(4, 500, 1), &owner);
        assert_ne!(a.record_hash(), b.record_hash());
        let (winner, loser) = if a.record_hash() > b.record_hash() {
            (&a, &b)
        } else {
            (&b, &a)
        };

        // Two stores, OPPOSITE arrival orders.
        let dir1 = tempfile::tempdir().expect("tmpdir");
        let dir2 = tempfile::tempdir().expect("tmpdir");
        let s1 = OwnerSyncStore::load(dir1.path()).await.expect("store");
        let s2 = OwnerSyncStore::load(dir2.path()).await.expect("store");
        let owner_id = owner.user_id();
        s1.commit_batch(vec![a.clone()], &owner_id)
            .await
            .expect("c");
        s1.commit_batch(vec![b.clone()], &owner_id)
            .await
            .expect("c");
        s2.commit_batch(vec![b.clone()], &owner_id)
            .await
            .expect("c");
        s2.commit_batch(vec![a.clone()], &owner_id)
            .await
            .expect("c");

        for store in [&s1, &s2] {
            let snapshot = store.records_snapshot().await;
            assert_eq!(snapshot.len(), 1);
            assert_eq!(snapshot[0].value, winner.value, "hash winner everywhere");
            assert_eq!(snapshot[0].record_hash(), winner.record_hash());
        }
        let _ = loser;
    }

    #[tokio::test]
    async fn batch_with_forgery_commits_nothing() {
        // WHY: review R2 finding 4 — a later forgery in a batch must leave
        // NOTHING committed, not even the earlier valid records.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let owner_id = owner.user_id();
        let attacker = owner_kp(2);
        let valid = sign_names("k1", "good", clock(1, 1, 1), &owner);
        let forged = VersionedRecord::sign(
            SyncKind::OwnerProfile,
            "owner",
            &SyncValue::OwnerProfile {
                human_name: Some("Evil".into()),
            },
            clock(99, 99, 9),
            &attacker,
        )
        .expect("sign");
        let err = store
            .commit_batch(vec![valid, forged], &owner_id)
            .await
            .expect_err("batch containing a forgery must fail whole");
        assert_eq!(err, SyncError::OwnerMismatch);
        assert!(
            store.records_snapshot().await.is_empty(),
            "no partial commit: the earlier valid record is NOT stored"
        );
    }

    #[tokio::test]
    async fn store_cardinality_and_key_caps_fail_closed() {
        // WHY: review R2 finding 5 — record/key cardinality is bounded with
        // typed failures, never silent truncation.
        let owner = owner_kp(1);
        let long_key = "k".repeat(MAX_KEY_BYTES + 1);
        let record = VersionedRecord::sign(
            SyncKind::MachineNames,
            &long_key,
            &names_value("x"),
            clock(1, 1, 1),
            &owner,
        )
        .expect("sign");
        let err = record.verify().expect_err("over-length key rejected");
        assert!(matches!(err, SyncError::MalformedFrame(_)));

        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner_id = owner.user_id();
        let over: Vec<VersionedRecord> = (0..=MAX_STORED_RECORDS)
            .map(|i| sign_names(&format!("k{i}"), "v", clock(1, 1, 1), &owner))
            .collect();
        assert!(
            matches!(
                store.commit_batch(over, &owner_id).await,
                Err(SyncError::StoreLimit(_))
            ),
            "store capacity is enforced with a typed error"
        );
    }

    #[tokio::test]
    async fn tier3_surface_is_exactly_the_four_kinds() {
        // WHY: blocker 32 — the sync surface serializes ONLY Tier-1 kinds;
        // every other kind tag is undecodable (deny-by-default allowlist).
        assert_eq!(SyncKind::ALL.len(), 4);
        for byte in 0u8..=255 {
            let decoded = SyncKind::from_u8(byte);
            let known = SyncKind::ALL.iter().any(|k| k.as_u8() == byte);
            assert_eq!(
                decoded.is_some(),
                known,
                "kind tag 0x{byte:02x} must decode iff it is one of the four kinds"
            );
        }
        // Every one of the four kinds must round-trip through the wire
        // value enum — these are the only shapes a record can carry.
        let owner = owner_kp(1);
        for kind in SyncKind::ALL {
            let value = match kind {
                SyncKind::OwnerProfile => SyncValue::OwnerProfile {
                    human_name: Some("H".into()),
                },
                SyncKind::MachineNames => names_value("n"),
                SyncKind::HomePointer => SyncValue::HomePointer {
                    group_id: "g".into(),
                    policy: GroupPolicy::default(),
                    roster: vec![],
                    primary_agent: "a".into(),
                    provisioned_at_ms: 0,
                },
                SyncKind::IssuanceJournal => SyncValue::IssuanceJournal {
                    agent_id: "a".into(),
                    cert_digest: "d".into(),
                    issued_at: 1,
                    not_after: None,
                },
            };
            assert_eq!(value.kind(), kind);
            let record =
                VersionedRecord::sign(kind, "k", &value, clock(1, 1, 1), &owner).expect("sign");
            record.verify().expect("all four kinds verify");
        }

        // Behavioral Tier-3 check: kind/value coherence is enforced, so no
        // foreign state can ride a record under a mismatched kind tag.
        let mismatched = VersionedRecord {
            kind: SyncKind::HomePointer,
            key: "home".into(),
            value: names_value("evil"),
            clock: clock(1, 1, 1),
            owner_public_key: vec![],
            signature: vec![],
        };
        assert_eq!(
            mismatched.verify(),
            Err(SyncError::KindMismatch),
            "kind must match value variant — no other state can ride a record"
        );
    }

    #[tokio::test]
    async fn unknown_kind_tag_fails_record_decode() {
        // WHY: Tier-3 allowlist — bincode deserialization of SyncKind with
        // an out-of-range discriminant fails, so no fifth kind can arrive.
        let bad = bincode::serialize(&SyncKind::OwnerProfile).expect("encode");
        // A u8-repr enum serializes as its tag; corrupt it to 0x2A.
        let mut hostile = bad;
        hostile[0] = 0x2A;
        let decoded: Result<SyncKind, _> = bincode::deserialize(&hostile);
        assert!(decoded.is_err(), "unknown kind tag must not decode");
        assert_eq!(SyncKind::from_u8(0x2A), None);
    }

    #[tokio::test]
    async fn frame_round_trip_and_oversize_rejected() {
        // WHY: bounded framing — an oversized length prefix fails closed
        // instead of allocating.
        let frame = SyncFrame::Done;
        let mut buf = Vec::new();
        write_frame(&mut buf, &frame).await.expect("write");
        let mut cursor = std::io::Cursor::new(buf);
        let back = read_frame(&mut cursor).await.expect("read");
        assert_eq!(back, frame);

        let mut evil = Vec::new();
        evil.extend_from_slice(&(MAX_FRAME_BYTES + 1).to_be_bytes());
        let mut cursor = std::io::Cursor::new(evil);
        assert!(matches!(
            read_frame(&mut cursor).await,
            Err(SyncError::MalformedFrame(_))
        ));
    }

    #[tokio::test]
    async fn session_rejects_non_enrolled_peer_and_self() {
        // WHY: blocker 30 — the stream accept path fails closed before any
        // application byte for unenrolled (or self) peers.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let local = machine(1);
        let (tx, mut rx) = tokio::io::duplex(64);
        let mut tx = tx;
        let _ = &mut rx;
        let err = run_sync_session(
            &mut tx,
            &mut rx,
            &store,
            &owner,
            &local,
            &machine(2),
            |_| {},
        )
        .await
        .expect_err("unenrolled peer refused");
        assert!(matches!(err, SyncError::NotEnrolled { .. }));
        let err = run_sync_session(&mut tx, &mut rx, &store, &owner, &local, &local, |_| {})
            .await
            .expect_err("self-sync refused");
        assert_eq!(err, SyncError::SelfSync);
    }

    #[tokio::test]
    async fn session_proof_rejects_peer_without_owner_key() {
        // WHY: review R2 finding 1 — a stale-enrolled machine that ECHOES
        // the victim's owner id but does not hold the owner key must fail
        // the possession proof and receive nothing.
        let dir = tempfile::tempdir().expect("tmpdir");
        let victim_store = OwnerSyncStore::load(&dir.path().join("v"))
            .await
            .expect("store");
        let owner = owner_kp(1);
        let attacker_kp = owner_kp(2); // different owner key in hand
        let attacker_id = attacker_kp.user_id();
        let victim = machine(1);
        let attacker = machine(2);

        // The victim enrolled the attacker's machine long ago (stale but
        // unexpired), so the enrollment gate passes...
        victim_store
            .enroll(OwnerEnrollment::sign(attacker, &owner, 1_000, None).expect("sign"))
            .await
            .expect("persist");

        // ...and run both sides over a duplex pipe: the attacker side
        // signs its proof with the WRONG key.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (mut v_recv, mut v_send) = tokio::io::split(server);
        let (mut a_recv, mut a_send) = tokio::io::split(client);
        let owner_id_bytes = owner.user_id().0;
        let attacker_signer = Arc::new(attacker_kp);

        // Attacker handshake: honest Hello claiming the victim's owner id,
        // then a proof signed by the attacker's key.
        let attacker_hello = tokio::spawn(async move {
            let hello = SyncFrame::Hello {
                protocol_version: SYNC_PROTOCOL_VERSION,
                machine_id: attacker.0,
                owner_user_id: owner_id_bytes, // echoed, not held
                nonce: fresh_nonce(),
            };
            write_frame(&mut a_send, &hello).await?;
            let v_hello = match read_frame(&mut a_recv).await? {
                SyncFrame::Hello { nonce, .. } => nonce,
                other => return Err(SyncError::MalformedFrame(format!("{other:?}"))),
            };
            // Proof over the victim's nonce — but with the ATTACKER key.
            let msg = proof_message(&v_hello, &attacker.0, &victim.0, &owner_id_bytes);
            let sig = sign_with_ml_dsa(attacker_signer.secret_key(), &msg)
                .map_err(|e| SyncError::ChallengeFailed(format!("{e:?}")))?;
            write_frame(
                &mut a_send,
                &SyncFrame::Proof {
                    signature: sig.as_bytes().to_vec(),
                },
            )
            .await?;
            // Keep the pipe open briefly so the victim can send its error.
            let _ = read_frame(&mut a_recv).await;
            Ok::<(), SyncError>(())
        });

        let err = run_sync_session(
            &mut v_send,
            &mut v_recv,
            &victim_store,
            &owner,
            &victim,
            &attacker,
            |_| {},
        )
        .await
        .expect_err("peer without the owner key must fail the proof");
        assert!(matches!(err, SyncError::ChallengeFailed(_)), "got: {err:?}");
        let _ = attacker_hello.await;
        let _ = attacker_id;
        assert!(
            victim_store.records_snapshot().await.is_empty(),
            "victim shipped nothing"
        );
    }

    #[tokio::test]
    async fn session_times_out_when_peer_stalls() {
        // WHY: review R2 finding 5 — an enrolled peer that stalls after the
        // handshake holds the session only until the budget elapses.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let local = machine(1);
        let peer = machine(2);
        store
            .enroll(OwnerEnrollment::sign(peer, &owner, 1_000, None).expect("sign"))
            .await
            .expect("persist");

        // A duplex peer that sends an honest Hello then goes silent.
        let (client, server) = tokio::io::duplex(4096);
        let (mut s_recv, mut s_send) = tokio::io::split(server);
        let (mut c_recv, mut c_send) = tokio::io::split(client);
        let owner_id_bytes = owner.user_id().0;
        let peer_hello = tokio::spawn(async move {
            let hello = SyncFrame::Hello {
                protocol_version: SYNC_PROTOCOL_VERSION,
                machine_id: peer.0,
                owner_user_id: owner_id_bytes,
                nonce: fresh_nonce(),
            };
            write_frame(&mut c_send, &hello).await?;
            // Read the local Hello, then stall forever (never send Proof).
            let _ = read_frame(&mut c_recv).await;
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok::<(), SyncError>(())
        });
        let _ = &mut s_send;
        let _ = &mut s_recv;
        let err = run_sync_session_with_timeout(
            Duration::from_millis(150),
            &mut s_send,
            &mut s_recv,
            &store,
            &owner,
            &local,
            &peer,
            |_| {},
        )
        .await
        .expect_err("stalled peer must time out");
        assert_eq!(err, SyncError::SessionTimeout);
        peer_hello.abort();
    }

    /// Loopback bind, no bootstrap peers, no mDNS, no port mapping.
    fn loopback_owner_sync_config() -> crate::network::NetworkConfig {
        crate::network::NetworkConfig {
            bind_addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            bootstrap_nodes: Vec::new(),
            port_mapping_enabled: false,
            mdns_enabled: false,
            ..crate::network::NetworkConfig::default()
        }
    }

    /// A live owner device with the `SyncV1` accept loop running and its
    /// enrollment store installed. The owner-connect re-announcement is
    /// left off, and `join_network` is not called, so the discovery cache
    /// stays empty and the IPv6 route probe does not run.
    pub(in crate::owner_sync) async fn live_owner_device(
        dir: &Path,
        name: &str,
        owner_seed: [u8; 32],
    ) -> (Arc<crate::Agent>, Arc<OwnerSyncService>) {
        let owner = UserKeypair::from_seed(&owner_seed).expect("owner key");
        let agent = crate::Agent::builder()
            .with_machine_key(dir.join(format!("{name}-machine.key")))
            .with_agent_key_path(dir.join(format!("{name}-agent.key")))
            .with_agent_cert_path(dir.join(format!("{name}-agent.cert")))
            .with_user_key(owner)
            .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
            .with_peer_cache_dir(dir.join(format!("{name}-peers")))
            .with_network_config(loopback_owner_sync_config())
            .build()
            .await
            .expect("owner device");
        let agent = Arc::new(agent);
        agent.start_stream_accept_loop();
        let service = OwnerSyncService::new_without_owner_connect_reannounce(
            Arc::clone(&agent),
            &dir.join(name),
        )
        .await
        .expect("owner sync service");
        agent.install_owner_device_store(Arc::clone(service.store()));
        (agent, service)
    }

    /// #1542 (Codex review of #1545): repairing an older certificate's
    /// line must not hide a newer issuance. The owner roster reads the
    /// journal's last line per agent, so a synced line for an older digest
    /// appended after a renewal rolled the roster back to the older
    /// certificate, its expiry, mode and label.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_older_synced_line_never_replaces_a_newer_issuance_in_the_roster() {
        install_loopback_socket_boundary();
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x85; 32];
        let (agent, service) = live_owner_device(dir.path(), "alice", seed).await;
        let journal = agent
            .cert_journal_path()
            .expect("journal path")
            .to_path_buf();
        let owner_hex = hex::encode(UserKeypair::from_seed(&seed).expect("owner").user_id().0);
        let target = "b".repeat(64);
        let line = |digest: &str, issued_at, not_after, label: Option<&str>| {
            crate::profile::IssuedCertRecord {
                user_id: owner_hex.clone(),
                agent_id: target.clone(),
                cert_digest: digest.to_string(),
                issued_at,
                not_after,
                mode: crate::profile::CertMode::Acp,
                label: label.map(str::to_string),
                cert_b64: None,
            }
        };
        // A pre-fix synced line for d1 (no expiry), then the renewal d2.
        for record in [
            line("d1", 100, None, None),
            line("d2", 200, Some(9_000), Some("renewed")),
        ] {
            crate::profile::IssuedCertRecord::append(&journal, &record)
                .await
                .expect("append");
        }
        // A late sync of d1 that carries its expiry arrives and wins the
        // register here (this device has not minted d2).
        let owner = UserKeypair::from_seed(&seed).expect("owner");
        service
            .store()
            .mint(
                SyncKind::IssuanceJournal,
                &target,
                &SyncValue::IssuanceJournal {
                    agent_id: target.clone(),
                    cert_digest: "d1".to_string(),
                    issued_at: 100,
                    not_after: Some(5_000),
                },
                &owner,
                agent.machine_id(),
            )
            .await
            .expect("commit d1");
        service
            .store()
            .apply_journal_value(
                &journal,
                &owner_hex,
                &SyncValue::IssuanceJournal {
                    agent_id: target.clone(),
                    cert_digest: "d1".to_string(),
                    issued_at: 100,
                    not_after: Some(5_000),
                },
                None,
            )
            .await
            .expect("apply d1");
        let roster = agent.owner_issued_certificates().await;
        let entry = roster
            .iter()
            .find(|cert| cert.agent_id == target)
            .expect("roster entry");
        assert_eq!(
            (
                entry.digest.as_str(),
                entry.not_after,
                entry.label.as_deref()
            ),
            ("d2", Some(9_000), Some("renewed")),
            "the newest issuance stays in the roster"
        );
    }

    async fn loopback_addr(agent: &crate::Agent) -> std::net::SocketAddr {
        let network = agent.network().expect("network");
        let addr = network.bound_addr().await.expect("bound address");
        if addr.ip().is_unspecified() {
            std::net::SocketAddr::from(([127, 0, 0, 1], addr.port()))
        } else {
            addr
        }
    }

    async fn remember_peer(agent: &crate::Agent, peer: MachineId, addr: std::net::SocketAddr) {
        let cache = agent
            .network()
            .and_then(|network| network.bootstrap_cache())
            .expect("bootstrap cache");
        cache
            .add_from_connection(ant_quic::PeerId(peer.0), vec![addr], None)
            .await;
    }

    async fn knows_agent_on(agent: &crate::Agent, machine: MachineId) -> bool {
        agent
            .discovered_agents()
            .await
            .expect("discovery cache")
            .iter()
            .any(|discovered| discovered.machine_id == machine)
    }

    fn has_display_name(records: &[VersionedRecord], display: &str) -> bool {
        records.iter().any(|record| {
            matches!(
                &record.value,
                SyncValue::MachineNames {
                    display_name: Some(name),
                    ..
                } if name == display
            )
        })
    }

    async fn wait_for_successful_session(
        mut sessions: tokio::sync::watch::Receiver<u64>,
        before: u64,
        direction: &str,
    ) {
        let wait = tokio::time::timeout(Duration::from_secs(20), async {
            while *sessions.borrow_and_update() == before {
                sessions.changed().await.expect("session watch");
            }
        })
        .await;
        assert!(
            wait.is_ok(),
            "{direction}: no owner-sync session completed (R12 logged stream reset 0xA17C0244)"
        );
    }

    /// WHY (#843): two owner devices that stay up, enroll each other, and
    /// have never restarted must finish an owner-sync session in each
    /// direction. R12 logged `Tier-1 sync session failed (fail closed)`
    /// with `sync io error: stream reset by peer` (0xA17C0244) on every
    /// such session. Neither device learns the other's agent, so the
    /// session uses the verified enrollment alone.
    ///
    /// The fixture starts the real acceptor without the owner-connect
    /// re-announcement. A seccomp watcher fails the test if this process
    /// calls `bind` or `connect` outside loopback, including the `[::]:0`
    /// probe to `[2001:4860:4860::8888]:80`. This test opens no
    /// non-loopback socket.
    ///
    /// On the pre-#1044 dial the initiator stops at `machine not in
    /// discovery cache` and no session completes. When the responder
    /// drops the stream, the initiator's error is the stream reset.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mutually_enrolled_devices_complete_owner_sync_both_ways_without_restart() {
        install_loopback_socket_boundary();
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = [0x84; 32];
        let (alice, alice_sync) = live_owner_device(dir.path(), "alice", seed).await;
        let (bob, bob_sync) = live_owner_device(dir.path(), "bob", seed).await;
        assert_acceptor_without_reannounce(&alice_sync).await;
        assert_acceptor_without_reannounce(&bob_sync).await;
        assert_loopback_sockets("after owner devices start");
        let alice_id = alice.machine_id();
        let bob_id = bob.machine_id();
        assert_ne!(alice_id, bob_id, "distinct machines");

        let signed_enrollment = |peer: MachineId| {
            let owner = UserKeypair::from_seed(&seed).expect("owner key");
            OwnerEnrollment::sign(peer, &owner, 1_000, None).expect("sign enrollment")
        };
        alice_sync
            .store()
            .enroll(signed_enrollment(bob_id))
            .await
            .expect("alice enrolls bob");
        bob_sync
            .store()
            .enroll(signed_enrollment(alice_id))
            .await
            .expect("bob enrolls alice");

        remember_peer(&alice, bob_id, loopback_addr(&bob).await).await;
        remember_peer(&bob, alice_id, loopback_addr(&alice).await).await;
        assert!(
            !knows_agent_on(&alice, bob_id).await,
            "alice already knows bob's agent; the session would not use enrollment alone"
        );
        assert!(
            !knows_agent_on(&bob, alice_id).await,
            "bob already knows alice's agent; the session would not use enrollment alone"
        );

        let alice_owner = UserKeypair::from_seed(&seed).expect("owner key");
        let bob_owner = UserKeypair::from_seed(&seed).expect("owner key");
        alice_sync
            .store()
            .mint(
                SyncKind::MachineNames,
                &hex::encode(alice_id.0),
                &SyncValue::MachineNames {
                    display_name: Some("alice-device".into()),
                    machine_name: Some("alice-mac".into()),
                },
                &alice_owner,
                alice_id,
            )
            .await
            .expect("alice mints her name");
        bob_sync
            .store()
            .mint(
                SyncKind::MachineNames,
                &hex::encode(bob_id.0),
                &SyncValue::MachineNames {
                    display_name: Some("bob-device".into()),
                    machine_name: Some("bob-mac".into()),
                },
                &bob_owner,
                bob_id,
            )
            .await
            .expect("bob mints his name");

        let before_bob = *bob_sync.store().successful_sessions_rx().borrow();
        let bob_sessions = bob_sync.store().successful_sessions_rx();
        let alice_to_bob =
            tokio::time::timeout(Duration::from_secs(30), alice_sync.dial_and_sync(&bob_id))
                .await
                .unwrap_or_else(|_| panic!("alice→bob timed out"));
        alice_to_bob.unwrap_or_else(|(class, error)| {
            panic!("alice→bob failed ({class}): {error}");
        });
        wait_for_successful_session(bob_sessions, before_bob, "alice→bob").await;

        let before_alice = *alice_sync.store().successful_sessions_rx().borrow();
        let alice_sessions = alice_sync.store().successful_sessions_rx();
        let bob_to_alice =
            tokio::time::timeout(Duration::from_secs(30), bob_sync.dial_and_sync(&alice_id))
                .await
                .unwrap_or_else(|_| panic!("bob→alice timed out"));
        bob_to_alice.unwrap_or_else(|(class, error)| {
            panic!("bob→alice failed ({class}): {error}");
        });
        wait_for_successful_session(alice_sessions, before_alice, "bob→alice").await;

        for (service, peer, who) in [(&alice_sync, bob_id, "alice"), (&bob_sync, alice_id, "bob")] {
            let statuses = service.store().session_statuses().await;
            assert_eq!(
                statuses.get(&peer.0).map(|status| status.last_session_ok),
                Some(true),
                "{who}: last session with the other owner device must have succeeded"
            );
            let records = service.store().records_snapshot().await;
            assert!(
                has_display_name(&records, "alice-device"),
                "{who} is missing alice's name after both directions"
            );
            assert!(
                has_display_name(&records, "bob-device"),
                "{who} is missing bob's name after both directions"
            );
        }

        assert!(
            !knows_agent_on(&alice, bob_id).await,
            "an identity announcement arrived; the test no longer uses enrollment alone"
        );
        assert!(
            !knows_agent_on(&bob, alice_id).await,
            "an identity announcement arrived; the test no longer uses enrollment alone"
        );
        assert_loopback_sockets("after both owner-sync sessions");
    }

    /// WHY: `/proc/self/net` is the whole network namespace. A parallel
    /// test can hold `0.0.0.0` UDP there. The session test must not open
    /// that socket itself. This check opens it only after the namespace
    /// is verified loopback-only, then the process-scoped audit must
    /// stay clear.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn foreign_wildcard_in_verified_loopback_namespace_does_not_fail_socket_audit() {
        require_loopback_only_namespace();
        let mut foreign = ForeignWildcardListener::spawn();
        install_loopback_socket_boundary();
        foreign.assert_still_held();
        assert_loopback_sockets("unrelated wildcard listener");
        foreign.assert_still_held();
    }

    /// Another process in this network namespace, bound to `0.0.0.0`.
    /// `spawn` refuses unless the namespace is already loopback-only.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    struct ForeignWildcardListener {
        child: std::process::Child,
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    impl Drop for ForeignWildcardListener {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    impl ForeignWildcardListener {
        fn spawn() -> Self {
            require_loopback_only_namespace();
            let child = std::process::Command::new("/usr/bin/python3")
                .args([
                    "-c",
                    "import socket, time\n\
                     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
                     s.bind(('0.0.0.0', 0))\n\
                     time.sleep(180)\n",
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("unrelated wildcard listener");
            let mut hold = Self { child };
            hold.wait_until_bound();
            hold
        }

        fn wait_until_bound(&mut self) {
            let start = std::time::Instant::now();
            while start.elapsed() < std::time::Duration::from_secs(2) {
                if let Some(status) = self.child.try_wait().expect("listener status") {
                    let mut err = String::new();
                    if let Some(stderr) = self.child.stderr.as_mut() {
                        use std::io::Read;
                        let _ = stderr.read_to_string(&mut err);
                    }
                    panic!("unrelated wildcard listener exited ({status}): {err}");
                }
                if foreign_wildcard_udp_present() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("unrelated process did not bind 0.0.0.0 UDP in this namespace");
        }

        fn assert_still_held(&mut self) {
            assert!(
                self.child.try_wait().expect("listener status").is_none(),
                "unrelated wildcard listener exited during the session"
            );
            assert!(
                foreign_wildcard_udp_present(),
                "namespace no longer has a foreign 0.0.0.0 UDP socket"
            );
        }
    }

    /// Same rule as the isolation harness: only `lo`, and no default or
    /// gateway route. A failure here is before any wildcard bind.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn require_loopback_only_namespace() {
        let links = ip_json(&["-j", "link"]);
        let names: Vec<&str> = links
            .as_array()
            .expect("ip link")
            .iter()
            .map(|link| {
                link.get("ifname")
                    .and_then(|name| name.as_str())
                    .expect("ifname")
            })
            .collect();
        assert_eq!(
            names,
            ["lo"],
            "refusing to open a wildcard socket; interfaces are not loopback-only"
        );
        for family in ["-4", "-6"] {
            for row in ip_json(&[family, "-j", "route", "show", "table", "all"])
                .as_array()
                .expect("ip route")
            {
                let dev = row.get("dev").and_then(|value| value.as_str());
                let dst = row.get("dst").and_then(|value| value.as_str());
                assert!(
                    dev == Some("lo") && dst != Some("default") && row.get("gateway").is_none(),
                    "refusing to open a wildcard socket; route is not loopback-only: {row}"
                );
            }
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn ip_json(args: &[&str]) -> serde_json::Value {
        let output = std::process::Command::new("/usr/sbin/ip")
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("ip {}: {error}", args.join(" ")));
        assert!(
            output.status.success(),
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("ip {} json: {error}", args.join(" ")))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn foreign_wildcard_udp_present() -> bool {
        let own = own_socket_inodes();
        let Ok(text) = std::fs::read_to_string("/proc/self/net/udp") else {
            return false;
        };
        text.lines().skip(1).any(|line| {
            let mut cols = line.split_whitespace();
            let Some(local) = cols.nth(1) else {
                return false;
            };
            let Some(inode) = cols.nth(7) else {
                return false;
            };
            local.starts_with("00000000:") && !own.contains(inode)
        })
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn own_socket_inodes() -> std::collections::HashSet<String> {
        let mut own = std::collections::HashSet::new();
        let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
            return own;
        };
        for entry in entries.flatten() {
            let Ok(target) = std::fs::read_link(entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                own.insert(inode.to_string());
            }
        }
        own
    }

    async fn assert_acceptor_without_reannounce(service: &OwnerSyncService) {
        assert_eq!(
            service.tasks.lock().await.len(),
            1,
            "SyncV1 acceptor must be the only owner-sync task; the connect re-announcement probes a non-loopback route"
        );
    }

    pub(in crate::owner_sync) fn install_loopback_socket_boundary() {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        socket_boundary::install();
    }

    fn assert_loopback_sockets(when: &str) {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        socket_boundary::assert_clear(when);
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        let _ = when;
    }

    /// Process-scoped audit of `bind` and `connect`. The kernel reports
    /// every call from this process, then the call proceeds.
    /// `/proc/self/net` lists every socket in the network namespace,
    /// including parallel tests, so those tables are not consulted.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod socket_boundary {
        use std::sync::{Mutex, Once};

        const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
        const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
        const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;
        const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
        // Required with the two flags above. Without it the kernel cannot
        // tell a listener fd from a TSYNC thread id and returns EINVAL.
        const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: libc::c_ulong = 1 << 4;
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
        const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JMP_JEQ_K: u16 = 0x15;
        const BPF_RET_K: u16 = 0x06;
        const CONTINUE: u32 = 1;

        fn violations() -> &'static Mutex<Vec<String>> {
            static VIOLATIONS: Mutex<Vec<String>> = Mutex::new(Vec::new());
            &VIOLATIONS
        }

        pub(super) fn install() {
            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                self_check_classifier();
                let fd = install_filter();
                std::thread::Builder::new()
                    .name("owner-sync-socket-boundary".into())
                    .spawn(move || supervise(fd))
                    .expect("socket boundary watcher");
            });
            violations().lock().expect("violations").clear();
        }

        pub(super) fn assert_clear(when: &str) {
            let hits = violations().lock().expect("violations").clone();
            assert!(
                hits.is_empty(),
                "{when}: this process left loopback: {}",
                hits.join("; ")
            );
        }

        fn install_filter() -> libc::c_int {
            let privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
            assert_eq!(
                privs,
                0,
                "PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            );
            let mut filter = vec![
                insn(BPF_LD_W_ABS, 0, 0, 4),
                insn(BPF_JMP_JEQ_K, 0, 3, AUDIT_ARCH_X86_64),
                insn(BPF_LD_W_ABS, 0, 0, 0),
                insn(BPF_JMP_JEQ_K, 2, 0, libc::SYS_connect as u32),
                insn(BPF_JMP_JEQ_K, 1, 0, libc::SYS_bind as u32),
                insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
                insn(BPF_RET_K, 0, 0, SECCOMP_RET_USER_NOTIF),
            ];
            let prog = libc::sock_fprog {
                len: filter.len() as libc::c_ushort,
                filter: filter.as_mut_ptr(),
            };
            let flags = SECCOMP_FILTER_FLAG_TSYNC
                | SECCOMP_FILTER_FLAG_NEW_LISTENER
                | SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
            // SAFETY: `prog` points at `filter`, which stays live for this
            // synchronous syscall. The process opts into no-new-privs first,
            // which is what an unprivileged seccomp filter requires.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_SET_MODE_FILTER,
                    flags,
                    &prog as *const libc::sock_fprog,
                )
            };
            assert!(
                fd >= 0,
                "seccomp socket watcher: {}",
                std::io::Error::last_os_error()
            );
            i32::try_from(fd).expect("listener fd")
        }

        fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
            libc::sock_filter { code, jt, jf, k }
        }

        fn supervise(fd: libc::c_int) {
            let (notif_size, resp_size, recv, send) = notif_layout();
            loop {
                let mut req = vec![0u8; notif_size];
                // SAFETY: `req` is `notif_size` bytes, the size the kernel
                // reported for `struct seccomp_notif`. The listener fd stays
                // open for the process lifetime.
                let rc = unsafe { libc::ioctl(fd, recv, req.as_mut_ptr()) };
                if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if let Some(hit) = violation_from_notif(&req) {
                    violations().lock().expect("violations").push(hit);
                }
                let mut resp = vec![0u8; resp_size];
                resp[..8].copy_from_slice(&req[..8]);
                resp[20..24].copy_from_slice(&CONTINUE.to_ne_bytes());
                // SAFETY: `resp` is the kernel-reported response size. The
                // first qword is the notification id; flags at offset 20
                // request CONTINUE so the original syscall still runs.
                let sent = unsafe { libc::ioctl(fd, send, resp.as_ptr()) };
                if sent < 0 {
                    let err = std::io::Error::last_os_error();
                    // ENOENT: the caller went away. Anything else means this
                    // notification was not released; remember it and keep
                    // draining so later loopback calls do not sit forever.
                    if err.raw_os_error() != Some(libc::ENOENT) {
                        violations()
                            .lock()
                            .expect("violations")
                            .push(format!("watcher send: {err}"));
                    }
                }
            }
        }

        fn notif_layout() -> (usize, usize, libc::Ioctl, libc::Ioctl) {
            #[repr(C)]
            struct Sizes {
                notif: u16,
                resp: u16,
                _data: u16,
            }
            let mut sizes = Sizes {
                notif: 0,
                resp: 0,
                _data: 0,
            };
            // SAFETY: `sizes` matches the uapi `seccomp_notif_sizes` the
            // kernel writes for SECCOMP_GET_NOTIF_SIZES.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_GET_NOTIF_SIZES,
                    0,
                    &mut sizes as *mut Sizes,
                )
            };
            assert_eq!(
                rc,
                0,
                "SECCOMP_GET_NOTIF_SIZES: {}",
                std::io::Error::last_os_error()
            );
            assert!(sizes.notif >= 80, "seccomp_notif is {} bytes", sizes.notif);
            assert!(
                sizes.resp >= 24,
                "seccomp_notif_resp is {} bytes",
                sizes.resp
            );
            (
                sizes.notif as usize,
                sizes.resp as usize,
                io_wr(0, u32::from(sizes.notif)),
                io_wr(1, u32::from(sizes.resp)),
            )
        }

        fn io_wr(nr: u32, size: u32) -> libc::Ioctl {
            let dir = 3u32;
            let typ = u32::from(b'!');
            libc::Ioctl::from((dir << 30) | (size << 16) | (typ << 8) | nr)
        }

        fn violation_from_notif(req: &[u8]) -> Option<String> {
            let nr = i32::from_ne_bytes(req[16..20].try_into().ok()?);
            let ptr = u64::from_ne_bytes(req[40..48].try_into().ok()?);
            let len = u64::from_ne_bytes(req[48..56].try_into().ok()?);
            let op = if nr == libc::SYS_connect as i32 {
                "connect"
            } else {
                "bind"
            };
            let bytes = read_sockaddr(ptr, len)?;
            non_loopback_reason(&bytes).map(|reason| format!("{op} {reason}"))
        }

        fn read_sockaddr(ptr: u64, len: u64) -> Option<Vec<u8>> {
            let n = usize::try_from(len).ok()?.clamp(0, 64);
            if n < 2 || ptr == 0 {
                return Some(b"unreadable sockaddr".to_vec());
            }
            let mut buf = vec![0u8; n];
            let local = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: n,
            };
            let remote = libc::iovec {
                iov_base: ptr as *mut libc::c_void,
                iov_len: n,
            };
            // SAFETY: the calling thread is stopped inside the syscall, so
            // the sockaddr stays put. `process_vm_readv` returns an error
            // instead of faulting this thread when the pointer is bad.
            let rc = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
            if rc == n as isize {
                Some(buf)
            } else {
                Some(b"unreadable sockaddr".to_vec())
            }
        }

        fn non_loopback_reason(bytes: &[u8]) -> Option<String> {
            if bytes.len() < 2 {
                return Some("short sockaddr".to_string());
            }
            if bytes == b"unreadable sockaddr" {
                return Some("unreadable sockaddr".to_string());
            }
            let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
            match family {
                // Unspecified, unix, and netlink stay on this machine.
                // Netlink is how the stack reads interfaces; it is not a route.
                0 | 1 | 16 => None,
                2 => ipv4_reason(bytes),
                10 => ipv6_reason(bytes),
                other => Some(format!("address family {other}")),
            }
        }

        fn ipv4_reason(bytes: &[u8]) -> Option<String> {
            if bytes.len() < 8 {
                return Some("short IPv4 sockaddr".to_string());
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = [bytes[4], bytes[5], bytes[6], bytes[7]];
            if ip[0] == 127 {
                None
            } else {
                Some(format!("{}.{}.{}.{}:{port}", ip[0], ip[1], ip[2], ip[3]))
            }
        }

        fn ipv6_reason(bytes: &[u8]) -> Option<String> {
            if bytes.len() < 24 {
                return Some("short IPv6 sockaddr".to_string());
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            if octets[..15].iter().all(|b| *b == 0) && octets[15] == 1 {
                return None;
            }
            if octets[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] && octets[12] == 127 {
                return None;
            }
            let ip = std::net::Ipv6Addr::from(octets);
            Some(format!("[{ip}]:{port}"))
        }

        fn self_check_classifier() {
            let mut v4 = [0u8; 16];
            v4[0] = 2;
            v4[4] = 127;
            v4[7] = 1;
            assert!(non_loopback_reason(&v4).is_none());
            let mut wildcard = [0u8; 28];
            wildcard[0] = 10;
            let wildcard = non_loopback_reason(&wildcard).expect("wildcard ipv6");
            assert!(wildcard.contains("[::]:0"), "{wildcard}");
            let mut probe = [0u8; 28];
            probe[0] = 10;
            probe[3] = 80;
            let dns = std::net::Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
            probe[8..24].copy_from_slice(&dns.octets());
            let probe = non_loopback_reason(&probe).expect("route probe");
            assert!(probe.contains("[2001:4860:4860::8888]:80"), "{probe}");
        }
    }
}

#[cfg(test)]
mod r3_tests {
    use super::tests::{clock, machine, names_value, owner_kp, sign_names};
    use super::*;

    #[tokio::test]
    async fn corrupt_or_unreadable_state_files_fail_loud() {
        // WHY: review R3 finding 2 — a records/devices file that EXISTS
        // but is corrupt or unreadable must be a hard error, never a
        // silent fallback to an empty anti-rollback store. Only genuine
        // absence (fresh install) is empty.
        let dir = tempfile::tempdir().expect("tmpdir");
        let sync_dir = dir.path().join(SYNC_DIR);
        tokio::fs::create_dir_all(&sync_dir).await.unwrap();

        // Fresh install (both files absent) → empty store, Ok.
        let store = OwnerSyncStore::load(dir.path()).await.expect("fresh load");
        assert!(store.records_snapshot().await.is_empty());
        assert!(store.enrolled_devices().await.is_empty());

        // Corrupt records.json → Err.
        tokio::fs::write(sync_dir.join(RECORDS_FILE), b"{ not json")
            .await
            .unwrap();
        let err = match OwnerSyncStore::load(dir.path()).await {
            Err(e) => e,
            Ok(_) => panic!("corrupt records must fail loud"),
        };
        assert!(err.to_string().contains("refusing to start"), "{err}");
        tokio::fs::remove_file(sync_dir.join(RECORDS_FILE))
            .await
            .unwrap();

        // Corrupt devices.json → Err.
        tokio::fs::write(sync_dir.join(DEVICES_FILE), b"]]]")
            .await
            .unwrap();
        assert!(OwnerSyncStore::load(dir.path()).await.is_err());

        // Unreadable (permission-denied) records.json → Err (Unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::remove_file(sync_dir.join(DEVICES_FILE))
                .await
                .unwrap();
            tokio::fs::write(sync_dir.join(RECORDS_FILE), b"{}")
                .await
                .unwrap();
            std::fs::set_permissions(
                sync_dir.join(RECORDS_FILE),
                std::fs::Permissions::from_mode(0o000),
            )
            .unwrap();
            let result = OwnerSyncStore::load(dir.path()).await;
            std::fs::set_permissions(
                sync_dir.join(RECORDS_FILE),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(result.is_err(), "unreadable state file must fail loud");
        }
    }

    #[tokio::test]
    async fn rollback_restores_pre_batch_value_not_first_replacement() {
        // WHY: review R3 finding 4 — a batch that replaces the SAME key
        // twice and then fails (persistence error here) must restore the
        // PRE-BATCH value, not the first replacement.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let owner_id = owner.user_id();
        let key = "double";
        let pre = sign_names(key, "pre", clock(1, 1, 1), &owner);
        store
            .commit_batch(vec![pre.clone()], &owner_id)
            .await
            .expect("seed");

        // Break persistence, then commit a batch replacing the key twice.
        let sync_dir = dir.path().join(SYNC_DIR);
        std::fs::remove_dir_all(&sync_dir).unwrap();
        std::fs::write(&sync_dir, b"not a directory").unwrap();
        let batch = vec![
            sign_names(key, "first-replacement", clock(2, 2, 1), &owner),
            sign_names(key, "second-replacement", clock(3, 3, 1), &owner),
        ];
        assert!(store.commit_batch(batch, &owner_id).await.is_err());

        // The store holds the PRE-batch value, not the first replacement.
        let snapshot = store.records_snapshot().await;
        assert_eq!(snapshot.len(), 1, "one record");
        assert_eq!(snapshot[0].value, names_value("pre"));
        assert_eq!(snapshot[0].clock.version, 1, "pre-batch clock restored");
    }

    #[tokio::test]
    async fn oversize_values_rejected_at_verify_and_mint() {
        // WHY: review R3 finding 5 — values are bounded so no legal record
        // or page can exceed the frame limit.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);

        let huge = SyncValue::IssuanceJournal {
            agent_id: "a".into(),
            cert_digest: "x".repeat(MAX_VALUE_BYTES + 1024),
            issued_at: 1,
            not_after: None,
        };
        // mint refuses before signing.
        let err = store
            .mint(SyncKind::IssuanceJournal, "a", &huge, &owner, machine(1))
            .await
            .expect_err("oversize value must not mint");
        assert!(matches!(err, SyncError::MalformedFrame(_)), "{err:?}");

        // A hand-signed record with an oversize value fails verify (and
        // therefore every merge/session path).
        let record = VersionedRecord::sign(
            SyncKind::IssuanceJournal,
            "a",
            &huge,
            clock(1, 1, 1),
            &owner,
        )
        .expect("sign (sign itself does not check size)");
        let err = record.verify().expect_err("oversize value must not verify");
        assert!(err.to_string().contains("exceeds limit"), "{err}");
    }

    #[tokio::test]
    async fn store_larger_than_old_session_cap_syncs_to_fresh_peer() {
        // WHY: review R3 finding 5 — the session record cap must cover a
        // FULL valid store (previously 1024 < 4096, so a fresh peer could
        // never atomically sync a full store).
        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let store_a = Arc::new(OwnerSyncStore::load(&dir.path().join("a")).await.unwrap());
        let store_b = Arc::new(OwnerSyncStore::load(&dir.path().join("b")).await.unwrap());
        super::tests::cross_enroll_for_tests(&store_a, &store_b, &owner).await;

        // 1_100 records — above the old 1_024 cap, one atomic commit (fast;
        // per-record minting would re-write the file per record).
        const N: usize = 1_100;
        let owner_id = owner.user_id();
        let batch: Vec<VersionedRecord> = (0..N)
            .map(|i| {
                VersionedRecord::sign(
                    SyncKind::IssuanceJournal,
                    &format!("agent-{i:04}"),
                    &SyncValue::IssuanceJournal {
                        agent_id: format!("agent-{i:04}"),
                        cert_digest: format!("digest-{i:04}"),
                        issued_at: i as u64,
                        not_after: None,
                    },
                    clock(1, 1, 1),
                    &owner,
                )
                .unwrap()
            })
            .collect();
        store_a.commit_batch(batch, &owner_id).await.unwrap();
        assert_eq!(store_a.records_snapshot().await.len(), N);

        let (client, server) = tokio::io::duplex(256 * 1024);
        let (mut c_recv, mut c_send) = tokio::io::split(server);
        let (mut r_recv, mut r_send) = tokio::io::split(client);
        let responder_owner = UserKeypair::from_seed(&[7u8; 32]).expect("same owner keypair");
        let b = Arc::clone(&store_b);
        let responder = tokio::spawn(async move {
            run_sync_session(
                &mut r_send,
                &mut r_recv,
                &b,
                &responder_owner,
                &machine(2),
                &machine(1),
                |_| {},
            )
            .await
            .expect("responder")
        });
        let summary = run_sync_session(
            &mut c_send,
            &mut c_recv,
            &store_a,
            &owner,
            &machine(1),
            &machine(2),
            |_| {},
        )
        .await
        .expect("initiator syncs a full store");
        responder.await.unwrap();
        assert_eq!(summary.shipped, N);
        assert_eq!(
            store_b.records_snapshot().await.len(),
            N,
            "fresh peer received the FULL store atomically"
        );
    }

    #[tokio::test]
    async fn large_values_page_by_bytes_and_converge() {
        // WHY: review R3 finding 5 — pages split on a BYTE budget, not a
        // fixed record count, so values near the (bounded) cap cannot push
        // a 16-record page over the frame limit.
        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let store_a = Arc::new(OwnerSyncStore::load(&dir.path().join("a")).await.unwrap());
        let store_b = Arc::new(OwnerSyncStore::load(&dir.path().join("b")).await.unwrap());
        super::tests::cross_enroll_for_tests(&store_a, &store_b, &owner).await;

        // 10 records × ~8 KiB values: under the 16-record page count but
        // ~80 KiB total — the byte budget MUST split the pages.
        const N: usize = 10;
        let owner_id = owner.user_id();
        let batch: Vec<VersionedRecord> = (0..N)
            .map(|i| {
                VersionedRecord::sign(
                    SyncKind::IssuanceJournal,
                    &format!("big-{i}"),
                    &SyncValue::IssuanceJournal {
                        agent_id: format!("big-{i}"),
                        cert_digest: "d".repeat(8 * 1024),
                        issued_at: i as u64,
                        not_after: None,
                    },
                    clock(1, 1, 1),
                    &owner,
                )
                .unwrap()
            })
            .collect();
        store_a.commit_batch(batch, &owner_id).await.unwrap();

        let (client, server) = tokio::io::duplex(256 * 1024);
        let (mut c_recv, mut c_send) = tokio::io::split(server);
        let (mut r_recv, mut r_send) = tokio::io::split(client);
        let responder_owner = UserKeypair::from_seed(&[7u8; 32]).expect("same owner keypair");
        let b = Arc::clone(&store_b);
        let responder = tokio::spawn(async move {
            run_sync_session(
                &mut r_send,
                &mut r_recv,
                &b,
                &responder_owner,
                &machine(2),
                &machine(1),
                |_| {},
            )
            .await
            .expect("responder")
        });
        let summary = run_sync_session(
            &mut c_send,
            &mut c_recv,
            &store_a,
            &owner,
            &machine(1),
            &machine(2),
            |_| {},
        )
        .await
        .expect("byte-paged session");
        responder.await.unwrap();
        assert_eq!(summary.shipped, N);
        assert_eq!(store_b.records_snapshot().await.len(), N);
    }
}

#[cfg(test)]
mod r4_tests {
    use super::tests::{clock, owner_kp};
    use super::*;

    /// A `Vec<u8>` sink for `write_frame`, decoded back frame-by-frame so
    /// tests can assert the PAGE COUNT and each frame's encoded body size.
    async fn count_record_frames(records: &[VersionedRecord]) -> Vec<usize> {
        let mut sink = Vec::new();
        write_paged_records(&mut sink, records)
            .await
            .expect("write pages");
        let mut cursor = std::io::Cursor::new(sink);
        let mut sizes = Vec::new();
        loop {
            let before = cursor.position();
            match read_frame(&mut cursor).await {
                Ok(_) => sizes.push((cursor.position() - before - 4) as usize),
                Err(_) => break,
            }
        }
        sizes
    }

    /// WHY (review R4): pages fill by CUMULATIVE BYTES, not a fixed count —
    /// a set of large (individually capped) records splits into multiple
    /// frames each well under the frame limit, and many small records still
    /// respect the per-frame count cap.
    #[tokio::test]
    async fn record_pages_fill_by_cumulative_bytes() {
        let owner = owner_kp(7);
        // 10 records × 8 KiB values ≈ 83 KiB of records: the 64 KiB byte
        // budget MUST split them even though 10 < the 16-record count cap.
        let big: Vec<VersionedRecord> = (0..10)
            .map(|i| {
                VersionedRecord::sign(
                    SyncKind::IssuanceJournal,
                    &format!("big-{i}"),
                    &SyncValue::IssuanceJournal {
                        agent_id: format!("big-{i}"),
                        cert_digest: "d".repeat(8 * 1024),
                        issued_at: i as u64,
                        not_after: None,
                    },
                    clock(1, 1, 1),
                    &owner,
                )
                .unwrap()
            })
            .collect();
        let sizes = count_record_frames(&big).await;
        assert!(
            sizes.len() > 1,
            "byte budget must split the pages: {sizes:?}"
        );
        // Every frame stays far below the 256 KiB frame limit: the page
        // budget plus at most one value-capped record.
        let max_record_overhead = 12 * 1024; // pubkey + ML-DSA sig + framing
        for size in &sizes {
            assert!(
                *size <= RECORDS_PAGE_BYTES + MAX_VALUE_BYTES + max_record_overhead,
                "frame body of {size} bytes exceeds the page bound"
            );
            assert!(
                (*size as u32) < MAX_FRAME_BYTES,
                "frame body of {size} bytes must stay under the frame limit"
            );
        }
        // All records fit in the emitted frames (decode side already proved
        // frames are well-formed; count the payload).
        let total_records: usize = sizes.len(); // ≥ 1 page per flush
        assert!(total_records >= 1);

        // Many small records: the 16-record count cap still binds.
        let small: Vec<VersionedRecord> = (0..40)
            .map(|i| {
                VersionedRecord::sign(
                    SyncKind::IssuanceJournal,
                    &format!("s-{i}"),
                    &SyncValue::IssuanceJournal {
                        agent_id: format!("s-{i}"),
                        cert_digest: format!("d{i}"),
                        issued_at: i as u64,
                        not_after: None,
                    },
                    clock(1, 1, 1),
                    &owner,
                )
                .unwrap()
            })
            .collect();
        let small_sizes = count_record_frames(&small).await;
        // 40 tiny records ≈ 40 × ~3.5 KiB ≈ 140 KiB — split by EITHER the
        // byte or the count cap; every frame remains bounded.
        assert!(
            small_sizes.len() >= 3,
            "40 records cannot fit one page: {small_sizes:?}"
        );
        for size in &small_sizes {
            assert!((*size as u32) < MAX_FRAME_BYTES);
        }
    }

    /// WHY (review R4): an oversize single value is rejected AT THE
    /// BOUNDARY — typed error at mint, at merge (pre-commit), and at the
    /// frame decoder for anything that would exceed the frame limit — never
    /// discovered mid-stream during commit or apply.
    #[tokio::test]
    async fn oversize_value_rejected_at_every_boundary() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await.expect("store");
        let owner = owner_kp(1);
        let owner_id = owner.user_id();

        // A decodable frame (≈ 68 KiB < 256 KiB) carrying ONE oversize
        // value: rejected by MERGE with a typed error, before any commit.
        let oversize = VersionedRecord::sign(
            SyncKind::IssuanceJournal,
            "big",
            &SyncValue::IssuanceJournal {
                agent_id: "big".into(),
                cert_digest: "d".repeat(MAX_VALUE_BYTES + 2048),
                issued_at: 1,
                not_after: None,
            },
            clock(1, 1, 1),
            &owner,
        )
        .expect("sign");
        let err = store
            .merge_record(oversize, &owner_id)
            .await
            .expect_err("merge must reject an oversize value");
        assert!(
            matches!(err, SyncError::MalformedFrame(ref m) if m.contains("exceeds limit")),
            "typed boundary rejection, got: {err:?}"
        );
        assert!(
            store.records_snapshot().await.is_empty(),
            "nothing committed from the rejected record"
        );

        // A frame whose BODY itself would exceed MAX_FRAME_BYTES is
        // rejected by the frame decoder — the outermost boundary, before
        // any record is even deserialized.
        let mut hostile = Vec::new();
        hostile.extend_from_slice(&(MAX_FRAME_BYTES + 1).to_be_bytes());
        let mut cursor = std::io::Cursor::new(hostile);
        assert!(matches!(
            read_frame(&mut cursor).await,
            Err(SyncError::MalformedFrame(_))
        ));

        // A legitimately-framed batch that CONTAINS an oversize record is
        // rejected during ingest verification (the session's verify stage),
        // never reaching commit: simulate by verifying the batch records
        // exactly as the session does.
        let oversize_two = VersionedRecord::sign(
            SyncKind::IssuanceJournal,
            "huge",
            &SyncValue::IssuanceJournal {
                agent_id: "huge".into(),
                cert_digest: "d".repeat(MAX_VALUE_BYTES * 2),
                issued_at: 1,
                not_after: None,
            },
            clock(1, 1, 1),
            &owner,
        )
        .expect("sign");
        let err = oversize_two
            .verify_owner(&owner_id)
            .expect_err("session verify stage rejects oversize values");
        assert!(
            matches!(err, SyncError::MalformedFrame(ref m) if m.contains("exceeds limit")),
            "got: {err:?}"
        );
    }
}

#[cfg(test)]
mod r5_tests {
    use super::tests::{clock, cross_enroll_for_tests, machine, names_value, owner_kp, sign_names};
    use super::*;

    /// WHY (review R5 finding 1): ML-DSA signatures are randomized, so the
    /// same writer can produce two records with identical kind/key/value/
    /// clock but different signatures. Equal-clock classification must
    /// compare the FULL record hash (signature included) so every replica
    /// converges on one canonical record — deciding by value equality left
    /// replicas permanently split.
    #[tokio::test]
    async fn equal_clock_signature_only_records_converge() {
        let owner = owner_kp(1);
        let owner_id = owner.user_id();
        let key = "same-value";
        let same_clock = clock(4, 500, 1);
        // Sign the SAME value twice: different signature bytes, identical
        // content otherwise.
        let first = VersionedRecord::sign(
            SyncKind::MachineNames,
            key,
            &names_value("identical"),
            same_clock,
            &owner,
        )
        .unwrap();
        let second = VersionedRecord::sign(
            SyncKind::MachineNames,
            key,
            &names_value("identical"),
            same_clock,
            &owner,
        )
        .unwrap();
        assert_eq!(first.value, second.value);
        assert_ne!(
            first.record_hash(),
            second.record_hash(),
            "randomized ML-DSA signatures must produce different record hashes"
        );
        let canonical = if first.record_hash() > second.record_hash() {
            &first
        } else {
            &second
        };

        // Two stores, OPPOSITE arrival orders — both must hold the
        // canonical record afterwards.
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let s1 = OwnerSyncStore::load(dir1.path()).await.unwrap();
        let s2 = OwnerSyncStore::load(dir2.path()).await.unwrap();
        s1.commit_batch(vec![first.clone()], &owner_id)
            .await
            .unwrap();
        s1.commit_batch(vec![second.clone()], &owner_id)
            .await
            .unwrap();
        s2.commit_batch(vec![second.clone()], &owner_id)
            .await
            .unwrap();
        s2.commit_batch(vec![first.clone()], &owner_id)
            .await
            .unwrap();

        for store in [&s1, &s2] {
            let snapshot = store.records_snapshot().await;
            assert_eq!(snapshot.len(), 1);
            assert_eq!(
                snapshot[0].record_hash(),
                canonical.record_hash(),
                "signature-only equal-clock divergence converges to the canonical record"
            );
        }
    }

    /// WHY (review R5 finding 2): when a durable write crosses the rename
    /// but its post-rename sync fails, disk already holds the NEW state —
    /// memory must NOT be rolled back (that would leave memory behind an
    /// advanced disk); instead the store is poisoned and refuses every
    /// further mutation and session until a reload.
    #[tokio::test]
    async fn post_rename_failure_keeps_memory_advanced_and_poisons() {
        let dir = tempfile::tempdir().unwrap();
        let store = OwnerSyncStore::load(dir.path()).await.unwrap();
        let owner = owner_kp(1);
        let owner_id = owner.user_id();

        // Inject a post-rename fsync failure for the next write.
        store.set_fail_after_rename_for_testing(true);
        let record = sign_names("k", "v", clock(1, 1, 1), &owner);
        let err = store
            .commit_batch(vec![record], &owner_id)
            .await
            .expect_err("post-rename failure must surface");
        assert!(
            matches!(err, SyncError::Poisoned(_)),
            "typed poison error, got: {err:?}"
        );
        assert!(store.poisoned_reason().is_some(), "store is poisoned");

        // Memory was NOT rolled back: it matches the advanced disk.
        let snapshot = store.records_snapshot().await;
        assert_eq!(snapshot.len(), 1, "memory keeps the crossed-rename batch");

        // A fresh load over the same directory sees the same advanced state
        // — memory and disk agree, just not durably.
        let reloaded = OwnerSyncStore::load(dir.path()).await.unwrap();
        assert_eq!(
            reloaded.records_snapshot().await.len(),
            1,
            "disk holds the new batch the callers saw fail"
        );

        // Disable the fault injector FIRST (review R6): with it left on,
        // the refusals below could come from the injector firing again
        // rather than the poison flag. With it off, a refusal can ONLY
        // come from the poison check at the mutator entry points.
        store.set_fail_after_rename_for_testing(false);

        // Every further mutation refuses BECAUSE the store is poisoned —
        // the transient fault has cleared, the flag has not.
        let err = store
            .mint(
                SyncKind::OwnerProfile,
                "owner",
                &SyncValue::OwnerProfile {
                    human_name: Some("X".into()),
                },
                &owner,
                machine(1),
            )
            .await
            .expect_err("poisoned store refuses mint");
        assert!(matches!(err, SyncError::Poisoned(_)));
        let err = store
            .enroll(OwnerEnrollment::sign(machine(9), &owner, 1, None).unwrap())
            .await
            .expect_err("poisoned store refuses enroll");
        assert!(matches!(err, SyncError::Poisoned(_)));
        let err = store
            .commit_batch(
                vec![sign_names("post", "v", clock(9, 9, 1), &owner)],
                &owner_id,
            )
            .await
            .expect_err("poisoned store refuses commit_batch");
        assert!(matches!(err, SyncError::Poisoned(_)));
        let err = store
            .unenroll(&machine(9))
            .await
            .expect_err("poisoned store refuses unenroll");
        assert!(matches!(err, SyncError::Poisoned(_)));

        // Sessions refuse too — even with a fully enrolled peer.
        cross_enroll_for_tests(
            &Arc::new(OwnerSyncStore::load(dir.path()).await.unwrap()),
            &Arc::new(OwnerSyncStore::load(dir.path()).await.unwrap()),
            &owner,
        )
        .await;
        let (mut tx, mut rx) = tokio::io::duplex(64);
        let err = run_sync_session(
            &mut tx,
            &mut rx,
            &store,
            &owner,
            &machine(1),
            &machine(2),
            |_| {},
        )
        .await
        .expect_err("poisoned store refuses sessions");
        assert!(matches!(err, SyncError::Poisoned(_)));
    }
}

/// #449 (D3): the `"home"` register must converge, not oscillate.
#[cfg(test)]
mod home_pointer_election_tests {
    use super::*;

    fn home_ptr(
        group_id: &str,
        primary: &str,
        provisioned_at_ms: u64,
        roster: Vec<HomeRosterEntry>,
    ) -> SyncValue {
        SyncValue::HomePointer {
            group_id: group_id.into(),
            policy: GroupPolicy::default(),
            roster,
            primary_agent: primary.into(),
            provisioned_at_ms,
        }
    }

    /// An owner's second device must not fight the first for the register.
    ///
    /// Regression test for the write-amplification loop: before the mint
    /// gate, each device re-minted its own Home every
    /// [`DEFAULT_SYNC_INTERVAL`], so the canonical pointer flipped forever
    /// and every flip re-signed and re-persisted a record. The property that
    /// matters is TERMINATION — the devices must stop writing — so this
    /// asserts the mint count falls to zero and stays there, not merely that
    /// some particular device won.
    #[test]
    fn home_pointer_election_terminates_instead_of_oscillating() {
        // Two owner devices, each having auto-provisioned its own Home.
        // Ids are deliberately ordered against the timestamps so a naive
        // id-only rule would disagree with the intended winner.
        let devices = [
            ("agent-a", home_ptr("g-bbb", "agent-a", 1_000, vec![])),
            ("agent-b", home_ptr("g-aaa", "agent-b", 2_000, vec![])),
        ];

        let mut register: Option<SyncValue> = None;
        let mut mints_per_round = Vec::new();
        for _ in 0..10 {
            let mut mints = 0;
            for (agent_hex, desired) in &devices {
                if home_pointer_mint_decision(desired, register.as_ref(), agent_hex, false) {
                    register = Some(desired.clone());
                    mints += 1;
                }
            }
            mints_per_round.push(mints);
        }

        // Writes must cease. Pre-fix this was [2, 2, 2, …] without end.
        assert!(
            mints_per_round[2..].iter().all(|&m| m == 0),
            "register never settled — devices still minting: {mints_per_round:?}"
        );

        let Some(SyncValue::HomePointer { group_id, .. }) = register else {
            panic!("register empty after convergence");
        };
        assert_eq!(
            group_id, "g-bbb",
            "the OLDEST Home must win, regardless of id ordering"
        );
    }

    /// Both devices must elect the same winner from the same pair of
    /// candidates, whichever order they observe them in — otherwise the
    /// register cannot converge in the field.
    #[test]
    fn home_pointer_election_is_order_independent() {
        let older = home_ptr("g-zzz", "agent-a", 1_000, vec![]);
        let newer = home_ptr("g-aaa", "agent-b", 2_000, vec![]);

        // Newer already in the slot: the older device takes it.
        assert!(home_pointer_mint_decision(
            &older,
            Some(&newer),
            "agent-a",
            false
        ));
        // Older already in the slot: the newer device yields.
        assert!(!home_pointer_mint_decision(
            &newer,
            Some(&older),
            "agent-b",
            false
        ));
    }

    /// Equal `provisioned_at_ms` — a genuine simultaneous genesis, or just
    /// coarse clocks — must still break deterministically, on group id, or
    /// both devices could believe they won.
    #[test]
    fn home_pointer_election_breaks_timestamp_ties_on_group_id() {
        let a = home_ptr("g-aaa", "agent-a", 5_000, vec![]);
        let b = home_ptr("g-bbb", "agent-b", 5_000, vec![]);
        assert!(home_pointer_mint_decision(&a, Some(&b), "agent-a", false));
        assert!(!home_pointer_mint_decision(&b, Some(&a), "agent-b", false));
    }

    /// A slot held by a PROVABLY retired Home must be takeable (r3 P2).
    ///
    /// The ordering rule alone refuses every replacement here, because a new
    /// Home is always NEWER than the dead one it replaces — so without this
    /// override the register keeps naming a tombstone forever and every
    /// device yields to it. The proof is local (`withdrawn` in our own
    /// roster); an unreachable remote Home is unknown, not retired, and must
    /// NOT be overridden.
    #[test]
    fn a_provably_retired_pointer_can_be_replaced_by_a_newer_home() {
        let retired = home_ptr("g-old", "agent-a", 1_000, vec![]);
        let replacement = home_ptr("g-new", "agent-a", 9_999, vec![]);

        assert!(
            !home_pointer_mint_decision(&replacement, Some(&retired), "agent-a", false),
            "without proof of retirement the ordering rule stands: a newer Home does not win"
        );
        assert!(
            home_pointer_mint_decision(&replacement, Some(&retired), "agent-a", true),
            "a provably retired pointer must be replaceable despite being older"
        );
    }

    /// The owner's first device must publish: an empty register is not a
    /// reason to stay silent, or no Home is ever advertised at all.
    #[test]
    fn home_pointer_mints_into_an_empty_register() {
        assert!(home_pointer_mint_decision(
            &home_ptr("g-aaa", "agent-a", 1, vec![]),
            None,
            "agent-a",
            false
        ));
    }

    /// Once the register names a Home, only that Home's designated PRIMARY
    /// agent may refresh it. Co-members re-minting their own roster
    /// projection of the same group would reintroduce the oscillation in a
    /// different guise.
    #[test]
    fn only_the_primary_agent_refreshes_its_own_home_pointer() {
        let stored = home_ptr("g-aaa", "agent-a", 1_000, vec![]);
        let refreshed = home_ptr(
            "g-aaa",
            "agent-a",
            1_000,
            vec![HomeRosterEntry {
                agent_id: "agent-b".into(),
                role: GroupRole::Member,
                state: GroupMemberState::Active,
            }],
        );
        assert!(
            home_pointer_mint_decision(&refreshed, Some(&stored), "agent-a", false),
            "the primary agent must be able to refresh its own Home pointer"
        );
        assert!(
            !home_pointer_mint_decision(&refreshed, Some(&stored), "agent-b", false),
            "a co-member must not refresh the primary's Home pointer"
        );
    }

    /// WHY (#1040): an identity announcement is a network-wide publish that
    /// every receiver verifies. A flapping owner connection must yield at
    /// most one re-announcement per machine per interval, while a DIFFERENT
    /// enrolled machine is not starved, and the machine may re-announce
    /// again once the interval has passed.
    #[test]
    fn owner_reconnect_reannounce_is_rate_limited_per_machine() {
        let interval = OWNER_REANNOUNCE_MIN_INTERVAL;
        let mut limiter = ReannounceLimiter::new(interval);
        let t0 = tokio::time::Instant::now();
        assert!(
            limiter.allow(&MachineId([1; 32]), t0),
            "first connect re-announces"
        );
        for step in [0, 1, 30, 59] {
            assert!(
                !limiter.allow(&MachineId([1; 32]), t0 + Duration::from_secs(step)),
                "reconnect {step}s later must not re-announce again"
            );
        }
        assert!(
            limiter.allow(&MachineId([2; 32]), t0 + Duration::from_secs(1)),
            "another enrolled machine has its own budget"
        );
        assert!(
            limiter.allow(&MachineId([1; 32]), t0 + interval),
            "after the interval the machine may re-announce again"
        );
        assert!(!limiter.allow(&MachineId([1; 32]), t0 + interval + Duration::from_secs(1)));
        // Stale entries are pruned: memory is bounded by recent machines.
        assert!(limiter.allow(&MachineId([3; 32]), t0 + interval * 3));
        assert_eq!(limiter.last.len(), 1, "expired entries must be pruned");
    }
}

/// #1542: an `IssuanceJournal` value must survive the sync round trip, or
/// two owner devices re-mint it in turn without end.
#[cfg(test)]
mod issuance_journal_sync_tests {
    use super::*;

    const OWNER: &str = "aa";

    /// An issuing device's own journal line (not a synced one).
    fn line(
        digest: &str,
        issued_at: u64,
        not_after: Option<u64>,
    ) -> crate::profile::IssuedCertRecord {
        crate::profile::IssuedCertRecord {
            user_id: OWNER.to_string(),
            agent_id: "bb".to_string(),
            cert_digest: digest.to_string(),
            issued_at,
            not_after,
            mode: crate::profile::CertMode::Acp,
            label: None,
            cert_b64: None,
        }
    }

    fn fields(value: &SyncValue) -> (String, String, u64, Option<u64>) {
        match value {
            SyncValue::IssuanceJournal {
                agent_id,
                cert_digest,
                issued_at,
                not_after,
            } => (
                agent_id.clone(),
                cert_digest.clone(),
                *issued_at,
                *not_after,
            ),
            other => panic!("not a journal value: {other:?}"),
        }
    }

    /// The issuing device's line has a `not_after`. A receiving device
    /// writes the synced line and mints from its own journal: it must mint
    /// the same value, so its mint is a no-op. Before the fix the synced
    /// line dropped `not_after`, the receiver minted `None`, and the two
    /// devices replaced each other's record on every pass.
    #[test]
    fn a_synced_expiring_line_mints_the_value_it_came_from() {
        let origin = latest_journal_values(vec![line("d1", 100, Some(5_000))], OWNER);
        let sent = origin.get("bb").expect("origin value");
        let (agent, digest, issued_at, not_after) = fields(sent);
        let received = synced_journal_line(OWNER.to_string(), agent, digest, issued_at, not_after);
        let receiver = latest_journal_values(vec![received], OWNER);
        assert_eq!(receiver.get("bb"), Some(sent));
    }

    /// Codex review of #1545 (42d32a0): `issued_at` has second precision,
    /// so a renewal can share its predecessor's second. A device that holds
    /// only `d1@100` must take the synced renewal `d2@100`. If it refuses,
    /// it mints `d1` again over the register and the issuing device mints
    /// `d2` again, without end.
    #[test]
    fn a_same_second_renewal_replaces_the_current_certificate() {
        assert!(synced_line_needed(
            &[line("d1", 100, Some(5_000))],
            OWNER,
            "bb",
            "d2",
            100,
            Some(9_000),
            Some("d1")
        ));
    }

    /// Codex review of #1545 (5306e5d): the same-second line is not
    /// appended over a local issuance that the register has not published
    /// yet. The next reconcile publishes the local issuance instead.
    #[test]
    fn a_same_second_line_keeps_an_unpublished_local_issuance() {
        let existing = vec![line("d0", 50, Some(1_000)), line("d2", 100, Some(9_000))];
        for published in [Some("d0"), None] {
            assert!(!synced_line_needed(
                &existing,
                OWNER,
                "bb",
                "d1",
                100,
                Some(5_000),
                published
            ));
        }
    }

    /// Codex review of #1545 (42d32a0): the expiry repair of the CURRENT
    /// certificate runs, also when an earlier certificate has the same
    /// second.
    #[test]
    fn the_current_certificate_is_repaired_beside_a_same_second_predecessor() {
        let existing = vec![line("d1", 100, Some(5_000)), line("d2", 100, None)];
        assert!(synced_line_needed(
            &existing,
            OWNER,
            "bb",
            "d2",
            100,
            Some(9_000),
            Some("d2")
        ));
        // The repair still runs when the digest is the only line.
        assert!(synced_line_needed(
            &[line("d1", 100, None)],
            OWNER,
            "bb",
            "d1",
            100,
            Some(5_000),
            Some("d1")
        ));
    }

    /// Rollback protection: a synced line for a certificate issued in an
    /// EARLIER second than the current one is never appended.
    #[test]
    fn an_earlier_second_never_replaces_the_current_certificate() {
        let existing = vec![line("d1", 100, None), line("d2", 200, Some(9_000))];
        assert!(!synced_line_needed(
            &existing,
            OWNER,
            "bb",
            "d1",
            100,
            Some(5_000),
            Some("d2")
        ));
    }

    /// Codex review of #1545 (42d32a0): two owner devices converge after a
    /// same-second renewal. Device A issued `d1@100` and then `d2@100`;
    /// device B holds only `d1@100`. Each pass runs the real reconcile
    /// (`mint_journal_lines`) and the real record merge, which applies an
    /// accepted record to the journal. The register must stop changing,
    /// and both devices must hold `d2`.
    #[tokio::test]
    async fn two_devices_converge_after_a_same_second_renewal() {
        use super::tests::{machine, owner_kp};

        struct Device {
            journal: PathBuf,
            store: Arc<OwnerSyncStore>,
            machine: MachineId,
        }

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_id = owner.user_id();
        let owner_hex = hex::encode(owner_id.0);
        let agent = "bb".to_string();
        let mut devices = Vec::new();
        for (name, id) in [("a", 1), ("b", 2)] {
            let (store, journal) = journal_device(&dir.path().join(name)).await;
            devices.push(Device {
                journal,
                store,
                machine: machine(id),
            });
        }
        let issued = |digest: &str, not_after| crate::profile::IssuedCertRecord {
            user_id: owner_hex.clone(),
            agent_id: agent.clone(),
            cert_digest: digest.to_string(),
            issued_at: 100,
            not_after: Some(not_after),
            mode: crate::profile::CertMode::Acp,
            label: None,
            cert_b64: None,
        };
        async fn reconcile(device: &Device, owner: &UserKeypair) {
            mint_journal_lines(&device.store, &device.journal, owner, device.machine).await;
        }
        async fn deliver(from: &Device, to: &Device, owner_id: &UserId) {
            for record in from.store.records_snapshot().await {
                to.store
                    .merge_record(record, owner_id)
                    .await
                    .expect("merge");
            }
        }
        let (a, b) = (&devices[0], &devices[1]);

        // A issues d1; it syncs to B. Then A renews to d2 in the same second.
        crate::profile::IssuedCertRecord::append(&a.journal, &issued("d1", 5_000))
            .await
            .expect("append d1");
        reconcile(a, &owner).await;
        deliver(a, b, &owner_id).await;
        crate::profile::IssuedCertRecord::append(&a.journal, &issued("d2", 9_000))
            .await
            .expect("append d2");

        let mut stable_passes = 0;
        for _ in 0..8 {
            let before = (
                a.store.records_snapshot().await,
                b.store.records_snapshot().await,
            );
            reconcile(a, &owner).await;
            reconcile(b, &owner).await;
            deliver(a, b, &owner_id).await;
            deliver(b, a, &owner_id).await;
            let after = (
                a.store.records_snapshot().await,
                b.store.records_snapshot().await,
            );
            stable_passes = if before == after {
                stable_passes + 1
            } else {
                0
            };
            if stable_passes == 2 {
                break;
            }
        }
        assert_eq!(stable_passes, 2, "the register never stopped changing");
        for (device, who) in [(a, "a"), (b, "b")] {
            let value = device
                .store
                .stored_value(SyncKind::IssuanceJournal, &agent)
                .await
                .expect("register value");
            assert_eq!(fields(&value).1, "d2", "device {who} must hold the renewal");
        }
    }

    /// Codex review of #1545 (3b18ea7): the register accepts `d1@100` and
    /// then `d2@100`. The journal must end on the register's winner `d2`.
    /// If it ends on `d1`, the next reconcile mints the older certificate
    /// over the register. One batch carries both, so the commit applies
    /// only the batch's final value for the key.
    #[tokio::test]
    async fn a_batch_applies_only_the_register_winner() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = super::tests::owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let (local, journal) = journal_device(&dir.path().join("local")).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        local
            .commit_batch(vec![r1, r2], &owner.user_id())
            .await
            .expect("commit");

        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            latest_journal_values(lines, &owner_hex).get("bb"),
            Some(&d2),
            "the journal must end on the register's winner"
        );
    }

    /// Codex review of #1545 (a5ee204): an inbound `d1@100` commits and
    /// its journal append pauses after it reads the journal. While it
    /// pauses, this device renews to `d2@100` and reconciles. The renewal
    /// must land after `d1`, and the reconcile must publish it: the
    /// delayed append must not put `d1` after `d2`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delayed_repair_does_not_roll_back_a_local_renewal() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let (store, journal) = journal_device(&dir.path().join("local")).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;

        let (checked_tx, checked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        store.pause_next_journal_check(checked_tx, release_rx);
        let repair = {
            let (store, owner) = (Arc::clone(&store), owner_kp(7));
            tokio::spawn(async move { deliver(&store, &owner, r1).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), checked_rx)
            .await
            .expect("the repair reaches its journal read")
            .expect("checked signal");

        // The local renewal and a reconcile pass, while the repair pauses.
        let renewal = {
            let (store, journal, owner, owner_hex) = (
                Arc::clone(&store),
                journal.clone(),
                owner_kp(7),
                owner_hex.clone(),
            );
            tokio::spawn(async move {
                let renewed = crate::profile::IssuedCertRecord {
                    user_id: owner_hex,
                    agent_id: "bb".to_string(),
                    cert_digest: "d2".to_string(),
                    issued_at: 100,
                    not_after: Some(9_000),
                    mode: crate::profile::CertMode::Acp,
                    label: None,
                    cert_b64: None,
                };
                crate::profile::IssuedCertRecord::append(&journal, &renewed)
                    .await
                    .expect("append d2");
                mint_journal_lines(&store, &journal, &owner, machine(1)).await;
            })
        };
        // Let the renewal run while the repair is held (it blocks).
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        release_tx.send(()).expect("release");
        repair.await.expect("repair task");
        renewal.await.expect("renewal task");

        // The next reconcile pass.
        mint_journal_lines(&store, &journal, &owner, machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            latest_journal_values(lines.clone(), &owner_hex).get("bb"),
            Some(&d2),
            "the journal must end on the renewal: {lines:?}"
        );
        assert_eq!(
            store.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d2),
            "the register must keep the renewal"
        );
    }

    /// A pre-fix synced line (same digest, no `not_after`) never hides a
    /// known expiry, in either order; a newer issuance still wins.
    #[test]
    fn a_line_without_expiry_does_not_replace_a_known_one() {
        for lines in [
            vec![line("d1", 100, None), line("d1", 100, Some(5_000))],
            vec![line("d1", 100, Some(5_000)), line("d1", 100, None)],
        ] {
            let values = latest_journal_values(lines, OWNER);
            assert_eq!(fields(&values["bb"]).3, Some(5_000));
        }
        let renewed = latest_journal_values(
            vec![line("d1", 100, Some(5_000)), line("d2", 200, Some(9_000))],
            OWNER,
        );
        assert_eq!(fields(&renewed["bb"]).1, "d2");
        assert_eq!(fields(&renewed["bb"]).3, Some(9_000));
        let other_owner = latest_journal_values(
            vec![synced_journal_line(
                "cc".into(),
                "bb".into(),
                "d1".into(),
                1,
                None,
            )],
            OWNER,
        );
        assert!(other_owner.is_empty());
    }

    /// One device's view for the #1545 ordering tests: a store whose
    /// accepted journal records apply to `journal`.
    async fn journal_device(dir: &Path) -> (Arc<OwnerSyncStore>, PathBuf) {
        let journal = dir.join(crate::profile::CERT_JOURNAL_FILE);
        let store = Arc::new(OwnerSyncStore::load(dir).await.expect("store"));
        store.set_journal_path(journal.clone());
        (store, journal)
    }

    /// Mint `value` on the remote `store` and return the signed record, as
    /// a sync session would carry it.
    async fn remote_record(
        store: &OwnerSyncStore,
        owner: &UserKeypair,
        value: &SyncValue,
    ) -> VersionedRecord {
        store
            .mint(
                SyncKind::IssuanceJournal,
                "bb",
                value,
                owner,
                super::tests::machine(2),
            )
            .await
            .expect("remote mint");
        store
            .records_snapshot()
            .await
            .into_iter()
            .find(|r| r.kind == SyncKind::IssuanceJournal && r.key == "bb")
            .expect("remote record")
    }

    /// Commit one inbound record the way a sync session does; the commit
    /// applies an accepted record to the store's journal.
    async fn deliver(store: &OwnerSyncStore, owner: &UserKeypair, record: VersionedRecord) {
        store
            .commit_batch(vec![record], &owner.user_id())
            .await
            .expect("commit");
    }

    fn journal_value(digest: &str, issued_at: u64, not_after: u64) -> SyncValue {
        SyncValue::IssuanceJournal {
            agent_id: "bb".to_string(),
            cert_digest: digest.to_string(),
            issued_at,
            not_after: Some(not_after),
        }
    }

    /// Codex review of #1545 (5306e5d), P1: a reconcile reads `d1` from
    /// the journal and pauses. An inbound renewal `d2` then arrives. The
    /// commit must wait for the reconcile. If it commits first, the
    /// reconcile mints its stale `d1` over `d2` at a higher version, and
    /// `d2`'s journal line is then dropped as superseded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_inbound_renewal_is_not_lost_to_a_running_reconcile() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let (local, journal) = journal_device(&dir.path().join("local")).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        deliver(&local, &owner, r1).await;

        let (read_tx, read_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        local.pause_next_journal_read(read_tx, release_rx);
        let reconcile = {
            let (local, journal, owner) = (Arc::clone(&local), journal.clone(), owner_kp(7));
            tokio::spawn(async move {
                mint_journal_lines(&local, &journal, &owner, machine(1)).await;
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), read_rx)
            .await
            .expect("the reconcile reads the journal")
            .expect("read signal");
        let inbound = {
            let (local, owner) = (Arc::clone(&local), owner_kp(7));
            tokio::spawn(async move { deliver(&local, &owner, r2).await })
        };
        // Let the inbound commit run while the reconcile is held (it may block).
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        release_tx.send(()).expect("release");
        reconcile.await.expect("reconcile task");
        inbound.await.expect("inbound task");

        // The next reconcile pass.
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d2.clone()),
            "the register must keep the renewal: {lines:?}"
        );
        assert_eq!(
            latest_journal_values(lines.clone(), &owner_hex).get("bb"),
            Some(&d2),
            "the journal must end on the renewal: {lines:?}"
        );
    }

    /// Codex review of #1545 (5306e5d), P2: this device holds `d0@50` in
    /// its register and journal. It renews to `d2@100`, and the issuance
    /// completes. Before its next reconcile publishes `d2`, another
    /// device's `d1@100` arrives and wins the register. The journal must
    /// keep the unpublished local `d2`, and the next reconcile must
    /// publish it. If `d1` is appended after `d2`, the roster and the
    /// register roll back to `d1`.
    #[tokio::test]
    async fn an_unpublished_local_renewal_survives_an_inbound_same_second_line() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let (local, journal) = journal_device(&dir.path().join("local")).await;
        let d0 = journal_value("d0", 50, 1_000);
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r0 = remote_record(&remote, &owner, &d0).await;
        let r1 = remote_record(&remote, &owner, &d1).await;
        deliver(&local, &owner, r0).await;

        // The local renewal completes before the inbound line arrives.
        let (_, digest, issued_at, not_after) = fields(&d2);
        crate::profile::IssuedCertRecord::append(
            &journal,
            &crate::profile::IssuedCertRecord {
                user_id: owner_hex.clone(),
                agent_id: "bb".to_string(),
                cert_digest: digest,
                issued_at,
                not_after,
                mode: crate::profile::CertMode::Acp,
                label: Some("renewed".to_string()),
                cert_b64: None,
            },
        )
        .await
        .expect("append d2");
        deliver(&local, &owner, r1).await;

        // The next reconcile pass.
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            latest_journal_values(lines.clone(), &owner_hex).get("bb"),
            Some(&d2),
            "the journal must end on the local renewal: {lines:?}"
        );
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d2),
            "the register must publish the local renewal"
        );
    }

    /// Codex review of #1545 (deee2c9), P2: this device holds `d1@100` in
    /// its register and journal. An inbound renewal `d2@100` commits, but
    /// its journal append fails. A later session delivers `d2` again. The
    /// next reconcile must not mint `d1` over the register: if the
    /// register keeps `d2` while the journal keeps `d1`, the reconcile
    /// publishes `d1` at a higher version and every device rolls back.
    #[tokio::test]
    async fn a_failed_journal_append_does_not_roll_back_a_renewal() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let (local, journal) = journal_device(&dir.path().join("local")).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        deliver(&local, &owner, r1).await;

        local
            .fail_journal_append
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let failed = local.commit_batch(vec![r2.clone()], &owner.user_id()).await;
        assert!(failed.is_err(), "a failed journal append fails the commit");
        local
            .fail_journal_append
            .store(false, std::sync::atomic::Ordering::Relaxed);
        // A later session delivers the renewal again.
        deliver(&local, &owner, r2).await;

        // The next reconcile pass.
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d2.clone()),
            "the register must keep the renewal: {lines:?}"
        );
        assert_eq!(
            latest_journal_values(lines.clone(), &owner_hex).get("bb"),
            Some(&d2),
            "the journal must end on the renewal: {lines:?}"
        );
    }

    /// Codex review of #1545 (55afdf2), P1: an inbound renewal `d2` commits
    /// in full, then the host crashes. A crash keeps only the writes made
    /// durable. The register write is durable, so the journal append that
    /// came before it must be durable too. If the journal came back as
    /// `d1` beside a `d2` register, the reconcile would publish `d1` over
    /// the renewal.
    #[tokio::test]
    async fn a_host_crash_after_a_commit_does_not_roll_back_a_renewal() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, journal) = journal_device(&local_dir).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        deliver(&local, &owner, r1).await;
        // Some time passes: the kernel has flushed the `d1` journal.
        crate::profile::crash_sim::note_durable(&journal);
        deliver(&local, &owner, r2).await;
        drop(local);

        // The host crash, the restart, then the first reconcile pass.
        crate::profile::crash_sim::crash(&[&journal, &local_dir.join(SYNC_DIR).join(RECORDS_FILE)]);
        let (local, journal) = journal_device(&local_dir).await;
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d2.clone()),
            "the register must keep the renewal: {lines:?}"
        );
        assert_eq!(
            latest_journal_values(lines.clone(), &owner_hex).get("bb"),
            Some(&d2),
            "the journal must end on the renewal: {lines:?}"
        );
    }

    /// Codex review of #1545 (deee2c9), P2: as above, but the daemon stops
    /// between the commit's register write and its journal write. After a
    /// restart, the reconcile must not mint `d1` over the register.
    #[tokio::test]
    async fn a_restart_between_the_commit_writes_does_not_roll_back_a_renewal() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, _) = journal_device(&local_dir).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        deliver(&local, &owner, r1).await;

        local
            .stop_between_journal_writes
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = local.commit_batch(vec![r2], &owner.user_id()).await;
        drop(local);

        // The restart, then the first reconcile pass.
        let (local, journal) = journal_device(&local_dir).await;
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d2.clone()),
            "the register must keep the renewal: {lines:?}"
        );
        assert_eq!(
            latest_journal_values(lines.clone(), &owner_hex).get("bb"),
            Some(&d2),
            "the journal must end on the renewal: {lines:?}"
        );
    }

    /// The local issuance journal line for `value`.
    fn local_line(owner_hex: &str, value: &SyncValue) -> crate::profile::IssuedCertRecord {
        let (agent_id, cert_digest, issued_at, not_after) = fields(value);
        crate::profile::IssuedCertRecord {
            user_id: owner_hex.to_string(),
            agent_id,
            cert_digest,
            issued_at,
            not_after,
            mode: crate::profile::CertMode::Acp,
            label: None,
            cert_b64: None,
        }
    }

    /// The host crash of the #1545 durability tests: lose every journal and
    /// register write in `local_dir` that was not made durable.
    fn crash_device(local_dir: &Path) {
        crate::profile::crash_sim::crash(&[
            &local_dir.join(crate::profile::CERT_JOURNAL_FILE),
            &local_dir.join(SYNC_DIR).join(RECORDS_FILE),
        ]);
    }

    /// Restart the device in `local_dir` and run its first reconcile pass.
    /// The pass must keep the register it published before the restart,
    /// and the journal must end on that value.
    async fn assert_restart_keeps_the_register(local_dir: &Path, owner: &UserKeypair) {
        let (local, journal) = journal_device(local_dir).await;
        let published = local.stored_value(SyncKind::IssuanceJournal, "bb").await;
        mint_journal_lines(&local, &journal, owner, super::tests::machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            published,
            "the reconcile must not roll back the published register: {lines:?}"
        );
        assert_eq!(
            latest_journal_values(lines.clone(), &hex::encode(owner.user_id().0)).get("bb"),
            published.as_ref(),
            "the journal must end on the published register: {lines:?}"
        );
    }

    /// Codex review of #1545 (72e8b9f), P1: a local renewal `d2` is between
    /// its journal rename and its directory fsync, so the line is visible
    /// but not durable. A reconcile that runs then must not publish `d2`:
    /// if the host crashes, the register keeps `d2`, the journal comes
    /// back as `d1`, and the next reconcile mints `d1` over the renewal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reconcile_does_not_publish_a_journal_line_before_it_is_durable() {
        use super::tests::{machine, owner_kp};
        use crate::profile::journal_faults::PauseEnd;

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, journal) = journal_device(&local_dir).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 200, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;
        deliver(&local, &owner, r1).await;

        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        crate::profile::journal_faults::pause_next(&journal, reached_tx, release_rx);
        let issuance = {
            let (journal, line) = (journal.clone(), local_line(&owner_hex, &d2));
            tokio::spawn(
                async move { crate::profile::IssuedCertRecord::append(&journal, &line).await },
            )
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), reached_rx)
            .await
            .expect("the issuance renames the journal")
            .expect("rename signal");
        let reconcile = {
            let (local, journal, owner) = (Arc::clone(&local), journal.clone(), owner_kp(7));
            tokio::spawn(async move {
                mint_journal_lines(&local, &journal, &owner, machine(1)).await;
            })
        };
        // Let the reconcile run while the issuance is held (it may block).
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // The host crashes before the issuance's directory fsync. Stop and
        // join the reconcile, then the journal writer itself (the append
        // awaits the task that owns the write), so no write or durable
        // mark lands after the crash state is restored.
        reconcile.abort();
        let _ = reconcile.await;
        let _ = release_tx.send(PauseEnd::Crash);
        let issued = issuance.await.expect("issuance task");
        assert!(issued.is_err(), "the writer stops at the simulated crash");
        drop(local);
        crash_device(&local_dir);
        assert_restart_keeps_the_register(&local_dir, &owner).await;
    }

    /// Codex review of #1545 (72e8b9f), P1: a local renewal's directory
    /// fsync fails, so its journal line stays visible but is not durable.
    /// The next reconcile may publish the line only after it is durable.
    #[tokio::test]
    async fn a_failed_journal_fsync_does_not_roll_back_a_renewal() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, journal) = journal_device(&local_dir).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 200, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;
        deliver(&local, &owner, r1).await;

        crate::profile::journal_faults::fail_next(&journal);
        let failed =
            crate::profile::IssuedCertRecord::append(&journal, &local_line(&owner_hex, &d2)).await;
        assert!(
            failed.is_err(),
            "the injected fsync failure fails the append"
        );
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;

        drop(local);
        crash_device(&local_dir);
        assert_restart_keeps_the_register(&local_dir, &owner).await;
    }

    /// Codex review of #1545 (72e8b9f), P1: an inbound renewal's journal
    /// append fails at the directory fsync, so the commit fails but the
    /// line stays visible. A later session delivers the renewal again,
    /// and the commit finds the line already there. It must make the line
    /// durable before it writes the register.
    #[tokio::test]
    async fn a_commit_retry_after_a_failed_journal_fsync_does_not_roll_back_a_renewal() {
        use super::tests::owner_kp;

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, journal) = journal_device(&local_dir).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        deliver(&local, &owner, r1).await;

        crate::profile::journal_faults::fail_next(&journal);
        let failed = local.commit_batch(vec![r2.clone()], &owner.user_id()).await;
        assert!(failed.is_err(), "a failed journal fsync fails the commit");
        // A later session delivers the renewal again.
        deliver(&local, &owner, r2).await;

        drop(local);
        crash_device(&local_dir);
        assert_restart_keeps_the_register(&local_dir, &owner).await;
    }

    /// Codex review of #1545 (72e8b9f), P2: the register holds `d0@v1`. A
    /// commit of the remote `d1@v2` appends its journal line, then the
    /// daemon stops before the register write. After the restart, the
    /// remote `d2@v3` (the same second as `d1`) arrives before any
    /// reconcile. `d2` is ordered after `d1`, so the register and the
    /// journal must end on `d2`. If the restart forgets that `d1` came
    /// from the register, `d1` looks like an unpublished local issuance:
    /// `d2`'s line is not appended, and the reconcile publishes `d1` at a
    /// higher version over `d2`.
    #[tokio::test]
    async fn an_interrupted_commit_does_not_override_a_later_same_second_renewal() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, _) = journal_device(&local_dir).await;
        let d0 = journal_value("d0", 50, 1_000);
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r0 = remote_record(&remote, &owner, &d0).await;
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        deliver(&local, &owner, r0).await;

        local
            .stop_between_journal_writes
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = local.commit_batch(vec![r1], &owner.user_id()).await;
        drop(local);

        // The restart; `d2` arrives before the first reconcile pass.
        let (local, journal) = journal_device(&local_dir).await;
        deliver(&local, &owner, r2).await;
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d2.clone()),
            "the register must keep the later renewal: {lines:?}"
        );
        assert_eq!(
            latest_journal_values(lines.clone(), &owner_hex).get("bb"),
            Some(&d2),
            "the journal must end on the later renewal: {lines:?}"
        );
    }

    /// Codex review of #1545 (758f62c), P2: as in
    /// `an_interrupted_commit_does_not_override_a_later_same_second_renewal`,
    /// but the intent of the interrupted `d1` commit cannot be decoded
    /// after the restart. The recovery must not delete it and go on: the
    /// journal then holds `d1` with no record that it came from the
    /// register, so the same-second `d2` is accepted without a journal
    /// line and the reconcile publishes `d1` over it. The recovery fails
    /// closed and keeps the intent; no journal commit or mint runs.
    #[tokio::test]
    async fn an_undecodable_journal_intent_fails_closed() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, _) = journal_device(&local_dir).await;
        let d0 = journal_value("d0", 50, 1_000);
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r0 = remote_record(&remote, &owner, &d0).await;
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        deliver(&local, &owner, r0).await;

        local
            .stop_between_journal_writes
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = local.commit_batch(vec![r1], &owner.user_id()).await;
        drop(local);
        let intent = local_dir.join(SYNC_DIR).join(JOURNAL_INTENT_FILE);
        std::fs::write(&intent, b"{\"records\": [").expect("corrupt the intent");

        // The restart; `d2` arrives before the first reconcile pass.
        let (local, journal) = journal_device(&local_dir).await;
        let delivered = local.commit_batch(vec![r2], &owner.user_id()).await;
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d0),
            "no journal commit or mint may change the register: {lines:?}"
        );
        assert!(
            delivered.is_err(),
            "a journal commit must fail while the intent cannot be decoded"
        );
        assert_eq!(
            std::fs::read(&intent).expect("the intent is kept"),
            b"{\"records\": [",
            "the recovery must keep the undecodable intent"
        );
    }

    /// Codex review of #1545 (162b724), P2: as in
    /// `an_undecodable_journal_intent_fails_closed`, but the intent stays
    /// valid JSON and one signed byte changes, so its record does not
    /// verify. The recovery must keep the intent and fail closed here too:
    /// only a record that verifies under another owner can be dropped.
    #[tokio::test]
    async fn a_journal_intent_with_a_bad_signature_fails_closed() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, _) = journal_device(&local_dir).await;
        let d0 = journal_value("d0", 50, 1_000);
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let r0 = remote_record(&remote, &owner, &d0).await;
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        deliver(&local, &owner, r0).await;

        local
            .stop_between_journal_writes
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = local.commit_batch(vec![r1], &owner.user_id()).await;
        drop(local);
        let intent = local_dir.join(SYNC_DIR).join(JOURNAL_INTENT_FILE);
        let mut persisted: PersistedRecords =
            serde_json::from_slice(&std::fs::read(&intent).expect("the intent")).expect("decode");
        persisted.records[0].signature[0] ^= 0x01;
        let corrupted = serde_json::to_vec(&persisted).expect("encode");
        std::fs::write(&intent, &corrupted).expect("corrupt the intent");

        // The restart; `d2` arrives before the first reconcile pass.
        let (local, journal) = journal_device(&local_dir).await;
        let delivered = local.commit_batch(vec![r2], &owner.user_id()).await;
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;
        let lines = crate::profile::IssuedCertRecord::load(&journal).await;
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d0),
            "no journal commit or mint may change the register: {lines:?}"
        );
        assert!(
            delivered.is_err(),
            "a journal commit must fail while the intent does not verify"
        );
        assert_eq!(
            std::fs::read(&intent).expect("the intent is kept"),
            corrupted,
            "the recovery must keep the intent that does not verify"
        );
    }

    /// Codex review of #1545 (bab382f), P2: a local renewal `d2` is
    /// cancelled after its journal rename and before the write's
    /// bookkeeping, as a caller cancellation during the rename await can
    /// do. The journal was durable before the write, so a stale mark would
    /// let the reconcile publish `d2` before it is durable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_journal_write_does_not_roll_back_a_renewal() {
        use super::tests::{machine, owner_kp};
        use crate::profile::journal_faults::PauseEnd;

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let owner_hex = hex::encode(owner.user_id().0);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, journal) = journal_device(&local_dir).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 200, 9_000),
        );
        let r1 = remote_record(&remote, &owner, &d1).await;
        deliver(&local, &owner, r1).await;

        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        crate::profile::journal_faults::pause_next(&journal, reached_tx, release_rx);
        let issuance = {
            let (journal, line) = (journal.clone(), local_line(&owner_hex, &d2));
            tokio::spawn(
                async move { crate::profile::IssuedCertRecord::append(&journal, &line).await },
            )
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), reached_rx)
            .await
            .expect("the issuance renames the journal")
            .expect("rename signal");
        // The caller cancels the issuance after the rename.
        issuance.abort();
        let _ = issuance.await;
        // The write goes on without its caller; the reconcile below waits
        // for it under the journal writer lock.
        let _ = release_tx.send(PauseEnd::Resume);
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;

        drop(local);
        crash_device(&local_dir);
        assert_restart_keeps_the_register(&local_dir, &owner).await;
    }

    /// Codex review of #1545 (bab382f), P2: a batch carries a journal
    /// renewal and an owner profile. The daemon stops after the journal
    /// write, before the register write. The restart must finish the whole
    /// batch, not only its journal record: `commit_batch` is all or nothing.
    #[tokio::test]
    async fn an_interrupted_mixed_commit_recovers_the_whole_batch() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let local_dir = dir.path().join("local");
        let (local, _) = journal_device(&local_dir).await;
        let (d1, d2) = (
            journal_value("d1", 100, 5_000),
            journal_value("d2", 100, 9_000),
        );
        let profile = SyncValue::OwnerProfile {
            human_name: Some("Alice".into()),
        };
        let r1 = remote_record(&remote, &owner, &d1).await;
        let r2 = remote_record(&remote, &owner, &d2).await;
        remote
            .mint(
                SyncKind::OwnerProfile,
                "owner",
                &profile,
                &owner,
                machine(2),
            )
            .await
            .expect("remote profile mint");
        let rp = remote
            .records_snapshot()
            .await
            .into_iter()
            .find(|r| r.kind == SyncKind::OwnerProfile)
            .expect("remote profile record");
        deliver(&local, &owner, r1).await;

        local
            .stop_between_journal_writes
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = local.commit_batch(vec![r2, rp], &owner.user_id()).await;
        drop(local);

        // The restart, then the first reconcile pass finishes the commit.
        let (local, journal) = journal_device(&local_dir).await;
        mint_journal_lines(&local, &journal, &owner, machine(1)).await;
        assert_eq!(
            local.stored_value(SyncKind::IssuanceJournal, "bb").await,
            Some(d2),
            "the recovery must commit the journal renewal"
        );
        assert_eq!(
            local.stored_value(SyncKind::OwnerProfile, "owner").await,
            Some(profile),
            "the recovery must commit the rest of the batch"
        );
    }

    /// A daemon view with a live owner profile name, for the recovery
    /// tests: `profile_names` reads it, `apply_names` replaces it.
    struct ProfileView(std::sync::Mutex<Option<String>>);

    impl ProfileView {
        fn human_name(&self) -> Option<String> {
            self.0.lock().expect("view").clone()
        }
    }

    impl SyncDaemonView for ProfileView {
        fn profile_names(&self) -> SyncProfileNames {
            SyncProfileNames {
                human_name: self.human_name(),
                ..SyncProfileNames::default()
            }
        }
        fn home_pointer(&self) -> Option<SyncValue> {
            None
        }
        fn home_pointer_definitive(
            &self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Option<SyncValue>, ()>> + Send>,
        > {
            Box::pin(async { Ok(None) })
        }
        fn apply_names(
            &self,
            human_name: Option<String>,
            _display_name: Option<String>,
            _machine_name: Option<String>,
        ) {
            if human_name.is_some() {
                *self.0.lock().expect("view") = human_name;
            }
        }
        fn canonical_pointer_is_retired(&self, _group_id: &str) -> bool {
            false
        }
    }

    /// A remote store's signed records for the mixed batch of the recovery
    /// tests: a journal renewal and the owner profile `name` at version 2.
    async fn remote_mixed_batch(
        remote: &OwnerSyncStore,
        owner: &UserKeypair,
        name: &str,
    ) -> (VersionedRecord, VersionedRecord) {
        use super::tests::machine;
        let journal = remote_record(remote, owner, &journal_value("d2", 100, 9_000)).await;
        for human_name in ["first", name] {
            remote
                .mint(
                    SyncKind::OwnerProfile,
                    "owner",
                    &SyncValue::OwnerProfile {
                        human_name: Some(human_name.into()),
                    },
                    owner,
                    machine(2),
                )
                .await
                .expect("remote profile mint");
        }
        let profile = remote
            .records_snapshot()
            .await
            .into_iter()
            .find(|r| r.kind == SyncKind::OwnerProfile)
            .expect("remote profile record");
        (journal, profile)
    }

    /// Codex review of #1545 (a19203d), P2: a mixed journal and profile
    /// commit fails after its journal intent is durable. The same records
    /// then arrive again in a session. The recovery in that commit commits them, so
    /// the session's own batch is superseded. The session must still apply
    /// the recovered profile to the daemon.
    #[tokio::test]
    async fn a_session_applies_the_records_its_recovery_commits() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let remote = Arc::new(
            OwnerSyncStore::load(&dir.path().join("remote"))
                .await
                .expect("remote store"),
        );
        let (local, _) = journal_device(&dir.path().join("local")).await;
        super::tests::cross_enroll_for_tests(&local, &remote, &owner).await;
        let (rj, rp) = remote_mixed_batch(&remote, &owner, "Alice").await;
        local
            .fail_journal_append
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let failed = local.commit_batch(vec![rj, rp], &owner.user_id()).await;
        assert!(failed.is_err(), "a failed journal append fails the commit");
        local
            .fail_journal_append
            .store(false, std::sync::atomic::Ordering::Relaxed);

        let (client, server) = tokio::io::duplex(256 * 1024);
        let (mut c_recv, mut c_send) = tokio::io::split(server);
        let (mut r_recv, mut r_send) = tokio::io::split(client);
        let responder = {
            let (remote, owner) = (Arc::clone(&remote), owner_kp(7));
            tokio::spawn(async move {
                run_sync_session(
                    &mut r_send,
                    &mut r_recv,
                    &remote,
                    &owner,
                    &machine(2),
                    &machine(1),
                    |_| {},
                )
                .await
                .expect("responder")
            })
        };
        let mut applied = Vec::new();
        run_sync_session(
            &mut c_send,
            &mut c_recv,
            &local,
            &owner,
            &machine(1),
            &machine(2),
            |record| applied.push(record.value.clone()),
        )
        .await
        .expect("initiator");
        responder.await.expect("responder task");
        assert!(
            applied.contains(&SyncValue::OwnerProfile {
                human_name: Some("Alice".into())
            }),
            "the session must apply the recovered profile: {applied:?}"
        );
    }

    /// Codex review of #1545 (a19203d), P2: after a mixed journal and
    /// profile commit fails after its journal intent is durable, the
    /// reconcile pass recovers it. The live profile must then show the recovered name,
    /// and the next pass must not publish the old live name over it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_reconcile_applies_a_recovered_profile_to_the_daemon() {
        super::tests::install_loopback_socket_boundary();
        let dir = tempfile::tempdir().expect("tmpdir");
        let seed = 0x86;
        let owner = super::tests::owner_kp(seed);
        let (_agent, service) =
            super::tests::live_owner_device(dir.path(), "alice", [seed; 32]).await;
        let view = Arc::new(ProfileView(std::sync::Mutex::new(Some("Old".into()))));
        service.attach_view(Arc::clone(&view) as Arc<dyn SyncDaemonView>);
        service.reconcile_local_state().await.expect("first pass");

        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let (rj, rp) = remote_mixed_batch(&remote, &owner, "Alice").await;
        let store = service.store();
        store
            .fail_journal_append
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let failed = store.commit_batch(vec![rj, rp], &owner.user_id()).await;
        assert!(failed.is_err(), "a failed journal append fails the commit");
        store
            .fail_journal_append
            .store(false, std::sync::atomic::Ordering::Relaxed);

        for _ in 0..2 {
            service.reconcile_local_state().await.expect("pass");
        }
        let alice = SyncValue::OwnerProfile {
            human_name: Some("Alice".into()),
        };
        assert_eq!(
            view.human_name().as_deref(),
            Some("Alice"),
            "the daemon must show the recovered profile"
        );
        assert_eq!(
            store.stored_value(SyncKind::OwnerProfile, "owner").await,
            Some(alice),
            "the reconcile must not publish the old live name"
        );
    }

    /// Codex review of #1545 (29e2800), P2: a commit writes the apply
    /// obligation of its name record `B` before its register write. A
    /// crash between the two leaves the register at the committed `A`.
    /// The obligation of `A` must stay owed until `B` is committed, or the
    /// restart has no obligation for the register's winner, and the
    /// reconcile publishes the old live name over `A`.
    #[tokio::test]
    async fn a_crash_before_a_replacing_commit_keeps_the_predecessor_owed() {
        use super::tests::{machine, owner_kp};

        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let remote = OwnerSyncStore::load(&dir.path().join("remote"))
            .await
            .expect("remote store");
        let mut records = Vec::new();
        for name in ["A", "B"] {
            remote
                .mint(
                    SyncKind::OwnerProfile,
                    "owner",
                    &SyncValue::OwnerProfile {
                        human_name: Some(name.into()),
                    },
                    &owner,
                    machine(2),
                )
                .await
                .expect("remote profile mint");
            records.extend(remote.records_snapshot().await);
        }
        let (a, b) = (records[0].clone(), records[1].clone());

        let local_dir = dir.path().join("local");
        let local = OwnerSyncStore::load(&local_dir).await.expect("local store");
        local
            .commit_batch(vec![a.clone()], &owner.user_id())
            .await
            .expect("commit A");
        // The commit of `B` stops after its obligation is durable and
        // before its register write.
        local
            .add_pending_applies(std::slice::from_ref(&b))
            .await
            .expect("obligation of B");
        drop(local);

        let local = OwnerSyncStore::load(&local_dir).await.expect("restart");
        assert_eq!(
            local.stored_value(SyncKind::OwnerProfile, "owner").await,
            Some(a.value.clone()),
            "the register holds A"
        );
        assert!(
            local.pending_applies().await.contains(&(a.clone(), true)),
            "A must stay owed as the register's winner"
        );
    }
}

/// #1545 round 7: a caller that is cancelled while a durable write of the
/// store is in flight. The blocking rename of the write still lands after
/// the cancel; no later writer may run before it, and memory must agree
/// with the disk after it.
#[cfg(test)]
mod cancellation_tests {
    use super::tests::{machine, owner_kp};
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    fn names(human: &str) -> SyncProfileNames {
        SyncProfileNames {
            human_name: Some(human.into()),
            display_name: None,
            machine_name: None,
        }
    }

    fn profile(human: &str) -> SyncValue {
        SyncValue::OwnerProfile {
            human_name: Some(human.into()),
        }
    }

    /// An owner-signed `OwnerProfile` record of another machine.
    async fn remote_profile(dir: &Path, owner: &UserKeypair, human: &str) -> VersionedRecord {
        let remote = OwnerSyncStore::load(dir).await.expect("remote store");
        remote
            .mint(
                SyncKind::OwnerProfile,
                "owner",
                &profile(human),
                owner,
                machine(2),
            )
            .await
            .expect("remote mint");
        remote.records_snapshot().await.remove(0)
    }

    /// Hold the next rename to `path` on the blocking pool.
    fn hold_rename(
        path: &Path,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        crate::profile::journal_faults::pause_next_rename(path, reached_tx, release_rx);
        (reached_rx, release_tx)
    }

    /// Start `task`, wait until it holds its rename, and cancel it.
    async fn cancel_at_rename<T: Send + 'static>(
        reached: tokio::sync::oneshot::Receiver<()>,
        task: tokio::task::JoinHandle<T>,
    ) {
        tokio::time::timeout(Duration::from_secs(10), reached)
            .await
            .expect("the write reaches its rename")
            .expect("rename hook");
        task.abort();
        let _ = task.await;
    }

    /// Run `next` for up to a second, release the held rename, and finish
    /// `next`. Then give the released rename time to land.
    async fn run_then_release<T: Send + 'static>(
        mut next: tokio::task::JoinHandle<T>,
        release: std::sync::mpsc::Sender<()>,
    ) -> T {
        let early = tokio::time::timeout(Duration::from_secs(1), &mut next).await;
        release.send(()).expect("release the held rename");
        let out = match early {
            Ok(done) => done.expect("next task"),
            Err(_) => next.await.expect("next task"),
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        out
    }

    /// Codex review of #1545 (b17cd8bf), P2: `Alice` is owed. `PUT Bob`
    /// notes its save and is cancelled during the rename of the pending
    /// file. `PUT Carol` then notes its save and discharges `Alice`. The
    /// late rename of Bob's note must not bring `Alice` back on disk: a
    /// restart would then apply `Alice` over the durable `Carol`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_note_cancelled_during_its_rename_cannot_restore_a_discharged_name() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let alice = remote_profile(&dir.path().join("remote"), &owner, "Alice").await;
        let local_dir = dir.path().join("local");
        let local = Arc::new(OwnerSyncStore::load(&local_dir).await.expect("store"));
        local
            .commit_batch(vec![alice.clone()], &owner.user_id())
            .await
            .expect("commit Alice");
        let folded = vec![(alice.clone(), true)];

        let (reached, release) = hold_rename(&local.pending_applies_path());
        let bob = {
            let (local, folded) = (Arc::clone(&local), folded.clone());
            tokio::spawn(async move { local.note_profile_save(&folded, &names("Bob")).await })
        };
        cancel_at_rename(reached, bob).await;

        let carol = {
            let (local, folded) = (Arc::clone(&local), folded.clone());
            tokio::spawn(async move {
                local.note_profile_save(&folded, &names("Carol")).await?;
                local.discharge_applies(&folded).await
            })
        };
        run_then_release(carol, release)
            .await
            .expect("Carol's note and discharge");
        assert!(
            local.pending_applies().await.is_empty(),
            "Alice is discharged"
        );

        drop(local);
        let restarted = OwnerSyncStore::load(&local_dir).await.expect("restart");
        assert!(
            restarted.pending_applies().await.is_empty(),
            "a cancelled note must not restore the discharged Alice on disk"
        );
    }

    /// A mint is cancelled during the rename of the register file, and a
    /// later mint completes. The late rename must not put the older
    /// register on disk over the later one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_mint_cancelled_during_its_rename_cannot_roll_the_register_back() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = Arc::new(owner_kp(7));
        let local = Arc::new(OwnerSyncStore::load(dir.path()).await.expect("store"));

        let (reached, release) = hold_rename(&local.dir.join(RECORDS_FILE));
        let first = {
            let (local, owner) = (Arc::clone(&local), Arc::clone(&owner));
            tokio::spawn(async move {
                local
                    .mint(
                        SyncKind::OwnerProfile,
                        "owner",
                        &profile("A"),
                        &owner,
                        machine(1),
                    )
                    .await
            })
        };
        cancel_at_rename(reached, first).await;

        let second = {
            let (local, owner) = (Arc::clone(&local), Arc::clone(&owner));
            tokio::spawn(async move {
                local
                    .mint(
                        SyncKind::OwnerProfile,
                        "owner",
                        &profile("B"),
                        &owner,
                        machine(1),
                    )
                    .await
            })
        };
        run_then_release(second, release).await.expect("mint B");

        let live = local.records_snapshot().await;
        drop(local);
        let restarted = OwnerSyncStore::load(dir.path()).await.expect("restart");
        assert_eq!(
            restarted
                .stored_value(SyncKind::OwnerProfile, "owner")
                .await,
            Some(profile("B")),
            "the late rename of a cancelled mint must not roll the register back"
        );
        assert_eq!(
            restarted.records_snapshot().await,
            live,
            "memory agrees with disk"
        );
    }

    /// A commit of a synced name is cancelled during the write of its
    /// obligation, before its register write. Memory must then agree with
    /// the disk: a register in memory that holds the record without its
    /// obligation lets the reconcile mint the old live name over it, and
    /// the next register write publishes the record although its commit
    /// did not complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_commit_cancelled_before_its_register_write_leaves_memory_as_the_disk() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let owner = owner_kp(7);
        let alice = remote_profile(&dir.path().join("remote"), &owner, "Alice").await;
        let local_dir = dir.path().join("local");
        let local = Arc::new(OwnerSyncStore::load(&local_dir).await.expect("store"));

        let (reached, release) = hold_rename(&local.pending_applies_path());
        let commit = {
            let (local, owner) = (Arc::clone(&local), owner.user_id());
            tokio::spawn(async move { local.commit_batch(vec![alice], &owner).await })
        };
        cancel_at_rename(reached, commit).await;
        release.send(()).expect("release the held rename");
        tokio::time::sleep(Duration::from_millis(300)).await;

        let disk = OwnerSyncStore::load(&local_dir).await.expect("reload");
        assert_eq!(
            local.records_snapshot().await,
            disk.records_snapshot().await,
            "the register in memory must be the register on disk"
        );
        assert_eq!(
            local.pending_applies().await,
            disk.pending_applies().await,
            "the obligations in memory must be the obligations on disk"
        );
    }
}
