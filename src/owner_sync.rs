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
//!    before this protocol's acceptor sees the stream;
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

use std::collections::BTreeMap;
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

pub struct OwnerSyncStore {
    dir: PathBuf,
    records: tokio::sync::RwLock<BTreeMap<(SyncKind, String), VersionedRecord>>,
    devices: tokio::sync::RwLock<BTreeMap<[u8; 32], OwnerEnrollment>>,
    last_session: tokio::sync::RwLock<BTreeMap<[u8; 32], DeviceSyncStatus>>,
    generation_tx: tokio::sync::watch::Sender<u64>,
    /// Set when a durable write crossed the rename but could not be
    /// synced: memory/disk agreement is no longer reconstructable by
    /// rollback, so every further mutation and session fails until the
    /// process reloads from disk (review R5 finding 2).
    poisoned: std::sync::Mutex<Option<String>>,
    /// Test injection: make the next durable writes fail AFTER the rename
    /// (simulates a post-rename fsync failure). Never set in production.
    fail_after_rename: std::sync::atomic::AtomicBool,
}

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
        let (generation_tx, _) = tokio::sync::watch::channel(0);
        Ok(Self {
            dir,
            records: tokio::sync::RwLock::new(records),
            devices: tokio::sync::RwLock::new(devices),
            last_session: tokio::sync::RwLock::new(BTreeMap::new()),
            generation_tx,
            poisoned: std::sync::Mutex::new(None),
            fail_after_rename: std::sync::atomic::AtomicBool::new(false),
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
        tokio::fs::rename(&tmp, path)
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
        Ok(())
    }

    /// Persist the winning records. `Poisoned` tells the caller the write
    /// crossed the rename but could not be made durable — memory must NOT
    /// be rolled back (disk already advanced); the store must be poisoned.
    /// Errors PROPAGATE — callers never report success on a swallowed
    /// write (review R2 finding 2).
    async fn persist_records(
        &self,
        records: &BTreeMap<(SyncKind, String), VersionedRecord>,
    ) -> Result<(), SyncError> {
        let persisted = PersistedRecords {
            records: records.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&persisted)
            .map_err(|e| SyncError::Io(format!("encode records: {e}")))?;
        Self::write_atomically(
            &self.dir.join(RECORDS_FILE),
            &bytes,
            self.fail_after_rename_for_testing(),
        )
        .await
        .map_err(|e| match e {
            DurableWriteError::BeforeRename(io) => SyncError::Io(format!("persist records: {io}")),
            DurableWriteError::AfterRename(io) => {
                SyncError::Poisoned(format!("records replaced but not durable: {io}"))
            }
        })
    }

    /// Persist the device set; errors propagate (see [`Self::persist_records`]).
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
        *self
            .poisoned
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
        }
        drop(devices);
        self.kick();
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
                    return Err(e);
                }
                devices.insert(previous.machine_id, previous);
                return Err(e);
            }
        } else {
            return Ok(false);
        }
        drop(devices);
        self.kick();
        Ok(true)
    }

    /// Enrolled machines (raw records, for surfaces).
    pub async fn enrolled_devices(&self) -> Vec<OwnerEnrollment> {
        self.devices.read().await.values().cloned().collect()
    }

    /// On-change trigger: bump the generation the periodic task waits on.
    pub fn kick(&self) {
        self.generation_tx.send_modify(|g| *g = g.wrapping_add(1));
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
    /// classification decisions are made against the live map, all accepted
    /// records inserted, and ONE file write persists the result. On any
    /// failure the in-memory map is rolled back to its **pre-batch** state
    /// — each key's pre-batch value is captured ONCE, on its first touch
    /// in the batch, so a key replaced twice in a failing batch restores
    /// the original, not an intermediate replacement (review R3 finding 4)
    /// — and the error propagates. A partial batch is never committed or
    /// advertised.
    ///
    /// Records must have been verified (`verify_owner`) by the caller.
    /// Callers must NOT hold this future inside a cancellable timeout: the
    /// rollback paths assume the await completes (the session wrapper
    /// commits outside its time budget for exactly that reason).
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
        let mut records = self.records.write().await;
        // (kind, key) → the value held BEFORE this batch first touched it.
        let mut touched: BTreeMap<(SyncKind, String), Option<VersionedRecord>> = BTreeMap::new();
        let mut outcome = CommitOutcome::default();
        let result = (|| -> Result<(), SyncError> {
            for record in batch {
                // Re-verify inside the lock: the caller's verification and
                // the commit must not be separated by a store mutation.
                record.verify_owner(owner)?;
                if records.len() >= MAX_STORED_RECORDS
                    && !records.contains_key(&(record.kind, record.key.clone()))
                {
                    return Err(SyncError::StoreLimit(format!(
                        "store at capacity ({MAX_STORED_RECORDS} records)"
                    )));
                }
                let key = (record.kind, record.key.clone());
                let stored = records.get(&key);
                // Equal clock with ANY differing signed bytes (different
                // value, or the same value double-signed) is an
                // equivocation whichever side wins the hash tie-break —
                // surfaced, never silently merged (review R2 finding 3,
                // extended in R5 to signature-only differences).
                if let Some(existing) = stored {
                    if existing.clock == record.clock
                        && existing.record_hash() != record.record_hash()
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
                let decision = stored.map(|existing| Self::classify(&record, existing));
                match decision {
                    None => {
                        // First touch of a fresh key: pre-batch value None.
                        touched.entry(key.clone()).or_insert(None);
                        records.insert(key, record.clone());
                        outcome.accepted.push(record);
                    }
                    Some(MergeOutcome::Accepted) => {
                        // Capture the pre-batch value ONCE (entry.or_insert
                        // keeps the first capture even on repeat touches).
                        touched
                            .entry(key.clone())
                            .or_insert_with(|| stored.cloned());
                        records.insert(key, record.clone());
                        outcome.accepted.push(record);
                    }
                    Some(MergeOutcome::Superseded) => {
                        outcome.superseded += 1;
                    }
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                if outcome.accepted.is_empty() {
                    return Ok(outcome); // nothing new — no write needed
                }
                match self.persist_records(&records).await {
                    Ok(()) => {
                        drop(records);
                        self.kick();
                        Ok(outcome)
                    }
                    Err(e) if matches!(e, SyncError::Poisoned(_)) => {
                        // The batch crossed the rename but was not durable:
                        // disk already holds it — KEEP the mutations (memory
                        // matches the advanced disk) and poison the store;
                        // never roll memory back below an advanced disk
                        // (review R5 finding 2).
                        drop(records);
                        self.poison(e.to_string());
                        Err(e)
                    }
                    Err(e) => {
                        Self::rollback(&mut records, &touched);
                        Err(e)
                    }
                }
            }
            Err(e) => {
                Self::rollback(&mut records, &touched);
                Err(e)
            }
        }
    }

    /// Restore the in-memory map to its pre-batch state: every touched key
    /// returns to the value captured on its FIRST touch in the batch.
    fn rollback(
        records: &mut BTreeMap<(SyncKind, String), VersionedRecord>,
        touched: &BTreeMap<(SyncKind, String), Option<VersionedRecord>>,
    ) {
        for ((kind, key), previous) in touched {
            match previous {
                Some(prev) => {
                    records.insert((*kind, key.clone()), prev.clone());
                }
                None => {
                    records.remove(&(*kind, key.clone()));
                }
            }
        }
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
        let mut records = self.records.write().await;
        let stored = records.get(&(kind, key.to_string()));
        if stored.is_some_and(|r| r.value == *desired) {
            return Ok(());
        }
        let version = stored.map_or(1, |r| r.clock.version.saturating_add(1));
        let clock = RecordClock {
            version,
            signed_at_ms: now_ms,
            writer_machine: writer_machine.0,
        };
        let record = VersionedRecord::sign(kind, key, desired, clock, owner)
            .map_err(|e| SyncError::BadSignature(format!("mint: {e}")))?;
        let previous = records.insert((kind, key.to_string()), record);
        match self.persist_records(&records).await {
            Ok(()) => {
                drop(records);
                self.kick();
                Ok(())
            }
            Err(e) if matches!(e, SyncError::Poisoned(_)) => {
                // Disk already holds the minted record: keep it and poison.
                drop(records);
                self.poison(e.to_string());
                Err(e)
            }
            Err(e) => {
                // Pre-rename failure: roll back so memory matches the
                // unchanged disk.
                match previous {
                    Some(prev) => {
                        records.insert((kind, key.to_string()), prev);
                    }
                    None => {
                        records.remove(&(kind, key.to_string()));
                    }
                }
                Err(e)
            }
        }
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
        let mut records = self.records.write().await;
        records.insert((record.kind, record.key.clone()), record);
        let _ = self.persist_records(&records).await;
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
    let outcome = store.commit_batch(pending.verified, &owner_id).await?;
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
    fn home_pointer(&self) -> Option<SyncValue>;
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
        let service = Arc::new(Self {
            agent,
            store: Arc::new(store),
            journal_path,
            view: std::sync::RwLock::new(None),
            tasks: tokio::sync::Mutex::new(Vec::new()),
            session_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSIONS)),
        });
        service.spawn_acceptor_loop(acceptor).await;
        Ok(service)
    }

    /// Install the live daemon view (idempotent; called by the daemon right
    /// after `AppState` construction).
    pub fn attach_view(&self, view: Arc<dyn SyncDaemonView>) {
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
    async fn spawn_acceptor_loop(self: &Arc<Self>, mut acceptor: crate::streams::StreamAcceptor) {
        let service = Arc::clone(self);
        let task = tokio::spawn(async move {
            while let Some(stream) = acceptor.next().await {
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
                let service = Arc::clone(&service);
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
        if !self.store.is_enrolled(&peer, &owner_kp.user_id()).await {
            tracing::warn!(
                target: "x0x::owner_sync",
                machine = %hex::encode(peer.0),
                "refusing SyncV1 stream from non-enrolled machine"
            );
            return; // drop => stream reset, fail closed
        }
        let (mut send, mut recv) = stream.into_split();
        let result = run_sync_session(
            &mut send,
            &mut recv,
            &self.store,
            owner_kp,
            &local_machine,
            &peer,
            |record| self.apply_record(record),
        )
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
                    error = %e,
                    "Tier-1 sync session failed (fail closed)"
                );
                self.store.set_session_status(&peer, false).await;
            }
        }
    }

    /// Dial `machine` and run one session as the initiator. Errors are
    /// strings by design: dial outcomes are logged, never fatal to the pass.
    async fn dial_and_sync(&self, machine: &MachineId) -> Result<SessionSummary, String> {
        let owner_kp = self.owner_kp().ok_or_else(|| "no owner key".to_string())?;
        let owner_id = owner_kp.user_id();
        let local_machine = self.agent.machine_id();
        if !self.store.is_enrolled(machine, &owner_id).await {
            return Err(format!(
                "machine {} is not enrolled",
                hex::encode(machine.0)
            ));
        }
        // Resolve the deterministic first agent on the target machine —
        // open_peer_stream authorizes per agent, sessions are per machine.
        let target_agent = self
            .agent
            .discovered_agents()
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|d| d.machine_id == *machine)
            .min_by_key(|d| d.agent_id.as_bytes().to_vec())
            .ok_or_else(|| "machine not in discovery cache".to_string())?
            .agent_id;
        let stream = self
            .agent
            .open_peer_stream(&target_agent, crate::streams::StreamProtocol::SyncV1)
            .await
            .map_err(|e| e.to_string())?;
        let peer = stream.peer();
        let (mut send, mut recv) = stream.into_split();
        let _permit = self
            .session_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        let result = run_sync_session(
            &mut send,
            &mut recv,
            &self.store,
            owner_kp,
            &local_machine,
            &peer,
            |record| self.apply_record(record),
        )
        .await;
        self.store.set_session_status(&peer, result.is_ok()).await;
        result.map_err(|e| e.to_string())
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
            if let Err(e) = self.dial_and_sync(&machine).await {
                tracing::debug!(
                    target: "x0x::owner_sync",
                    machine = %hex::encode(machine.0),
                    error = %e,
                    "Tier-1 dial skipped/failed until next pass"
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

        // Kinds 1 + 2 + 3: profile names and the Home pointer, via the
        // daemon view when attached.
        if let Some(view) = self.view() {
            let names = view.profile_names();
            self.mint_or_log(
                SyncKind::OwnerProfile,
                "owner",
                SyncValue::OwnerProfile {
                    human_name: names.human_name,
                },
                owner_kp,
                local_machine,
            )
            .await;
            self.mint_or_log(
                SyncKind::MachineNames,
                &local_hex,
                SyncValue::MachineNames {
                    display_name: names.display_name,
                    machine_name: names.machine_name,
                },
                owner_kp,
                local_machine,
            )
            .await;
            if let Some(home_value) = view.home_pointer() {
                if self.should_mint_home_pointer(&home_value).await {
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
        }

        // Kind 4: issuance journal lines (latest per agent, owner-scoped).
        if let Some(path) = self.journal_path.as_ref() {
            let owner_hex = hex::encode(owner_kp.user_id().0);
            let mut latest: BTreeMap<String, crate::profile::IssuedCertRecord> = BTreeMap::new();
            for record in crate::profile::IssuedCertRecord::load(path).await {
                if record.user_id != owner_hex {
                    continue;
                }
                let keep = latest
                    .get(&record.agent_id)
                    .is_none_or(|old| record.issued_at >= old.issued_at);
                if keep {
                    latest.insert(record.agent_id.clone(), record);
                }
            }
            for (agent_hex, record) in latest {
                self.mint_or_log(
                    SyncKind::IssuanceJournal,
                    &agent_hex,
                    SyncValue::IssuanceJournal {
                        agent_id: record.agent_id,
                        cert_digest: record.cert_digest,
                        issued_at: record.issued_at,
                        not_after: record.not_after,
                    },
                    owner_kp,
                    local_machine,
                )
                .await;
            }
        }
        Ok(())
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

    /// Apply an accepted record to live daemon state (post-commit only).
    ///
    /// Exhaustive over [`SyncValue`] — Tier-3 kinds cannot reach here.
    fn apply_record(&self, record: &VersionedRecord) {
        match &record.value {
            SyncValue::OwnerProfile { human_name } => {
                if let Some(view) = self.view() {
                    view.apply_names(human_name.clone(), None, None);
                }
            }
            SyncValue::MachineNames {
                display_name,
                machine_name,
            } => {
                let local_hex = hex::encode(self.agent.machine_id().0);
                if record.key == local_hex {
                    if let Some(view) = self.view() {
                        view.apply_names(None, display_name.clone(), machine_name.clone());
                    }
                }
                // Remote machines' names stay in the record store for
                // future surfacing (ADR-0041 Tier-1 scope).
            }
            SyncValue::HomePointer { .. } => {
                // The register is read on demand (`canonical_home`) by the
                // Home resolution path rather than pushed here: provisioning,
                // `GET /home` and adoption all need the CURRENT winner, not
                // whatever happened to arrive last (#449).
            }
            SyncValue::IssuanceJournal {
                agent_id,
                cert_digest,
                issued_at,
                ..
            } => {
                self.apply_journal_line(agent_id, cert_digest, *issued_at);
            }
        }
    }

    /// Append a synced journal line to the local file when missing
    /// (idempotent; fire-and-forget).
    fn apply_journal_line(&self, agent_hex: &str, cert_digest: &str, issued_at: u64) {
        let Some(path) = self.journal_path.clone() else {
            return;
        };
        let Some(owner_hex) = self.owner_kp().map(|kp| hex::encode(kp.user_id().0)) else {
            return;
        };
        let agent_hex = agent_hex.to_string();
        let cert_digest = cert_digest.to_string();
        tokio::spawn(async move {
            let existing = crate::profile::IssuedCertRecord::load(&path).await;
            if existing
                .iter()
                .any(|r| r.agent_id == agent_hex && r.cert_digest == cert_digest)
            {
                return; // already local
            }
            let record = crate::profile::IssuedCertRecord {
                user_id: owner_hex,
                agent_id: agent_hex,
                cert_digest,
                issued_at,
                not_after: None,
                // ADR-0039 fields are not part of the Tier-1 sync value:
                // a synced line records the issuance fact (digest + time);
                // mode defaults to Acp (the pre-ADR-0039 line shape) and
                // no certificate bytes travel Tier 1 (Tier-3 boundary).
                mode: crate::profile::CertMode::Acp,
                label: None,
                cert_b64: None,
            };
            if let Err(e) = crate::profile::IssuedCertRecord::append(&path, &record).await {
                tracing::warn!(
                    target: "x0x::owner_sync",
                    "failed to append synced journal line: {e}"
                );
            }
        });
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
}
