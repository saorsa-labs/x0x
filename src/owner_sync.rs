//! ADR-0041 Tier-1 cross-machine owner-state sync.
//!
//! Tier 1 replicates exactly four kinds of small owner-signed state between
//! the owner's machines over ADR-0022 byte streams ([`crate::streams`]):
//! the owner profile, per-machine agent/machine names, the Home roster +
//! policy pointer, and the sub-agent issuance journal. Tier 2 (history
//! backfill) and Tier 3 (never-replicates state) are out of scope here.
//!
//! # Trust model — same-owner, enrolled machines only (gapcheck blocker 30)
//!
//! A stream carrying [`crate::streams::StreamProtocol::SyncV1`] is accepted
//! only when BOTH hold:
//!
//! 1. the ADR-0022 machine identity gates (transport-verified, trusted,
//!    non-revoked) have already cleared — enforced by the shared accept loop
//!    before this protocol's acceptor sees the stream;
//! 2. the remote machine is in the local **owner device set**: an
//!    [`OwnerEnrollment`] record signed by the owner key, whose public key
//!    derives to this install's `UserId`. This is the enrollment direction
//!    of ADR-0043 (owner-key-signed, machine-scoped), reused — not a rival
//!    scheme.
//!
//! Fail closed: any signature or enrollment failure aborts the session and
//! the peer learns nothing beyond the refusal.
//!
//! # Object model (gapcheck blocker 31)
//!
//! Each Tier-1 object is an owner-signed [`VersionedRecord`]. Conflict rule
//! (deliberately decoupled from state-commit heights): highest `version`
//! wins; tie → highest `signed_at_ms`; tie → lexicographically greatest
//! `writer_machine`. Anti-rollback: a record is accepted only when it
//! *strictly beats* the stored clock under that ordering, so a replayed or
//! stale record can never overwrite a newer one.
//!
//! # Protocol
//!
//! On connect the two sides exchange a [`SyncFrame::Hello`] (same owner,
//! same protocol version, non-self), then per-kind version vectors, then
//! ship exactly the records the other side is missing or would accept.
//! Sessions run periodically and are re-triggered on local change (the
//! store's generation channel) — "periodic + on-change".
//!
//! # Tier-3 boundary (gapcheck blocker 32 scope note)
//!
//! The sync surface serializes ONLY the four Tier-1 kinds: [`SyncKind`] and
//! [`SyncValue`] are closed enums with no catch-all. A record whose kind tag
//! is not one of the four fails to decode, and a record whose kind does not
//! match its value variant is rejected whole.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

/// Wire protocol version for the SyncV1 handshake.
pub const SYNC_PROTOCOL_VERSION: u32 = 1;

/// Maximum size of one sync frame (length-prefixed payload). Tier-1 records
/// are tiny; anything larger is hostile or corrupt — fail closed.
pub const MAX_FRAME_BYTES: u32 = 256 * 1024;

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
    /// greatest `writer_machine`. Equal clocks beat nothing (idempotent
    /// re-delivery), and a lower `version` never wins — rollback protection.
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
    /// ML-DSA-65 signature over [`VersionedRecord::canonical_message`].
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
    /// variant. Fail closed on any mismatch.
    ///
    /// # Errors
    ///
    /// [`SyncError::BadSignature`] on an invalid signature or malformed key
    /// material; [`SyncError::KindMismatch`] when the kind tag and value
    /// variant disagree.
    pub fn verify(&self) -> Result<(), SyncError> {
        if self.value.kind() != self.kind {
            return Err(SyncError::KindMismatch);
        }
        let owner_pubkey = MlDsaPublicKey::from_bytes(&self.owner_public_key)
            .map_err(|_| SyncError::BadSignature("invalid owner public key".into()))?;
        let signature = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|e| SyncError::BadSignature(format!("invalid signature format: {e:?}")))?;
        let value_bytes = bincode::serialize(&self.value)
            .map_err(|e| SyncError::BadSignature(format!("value encode: {e}")))?;
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
    /// Owner ML-DSA-65 public key bytes.
    pub owner_public_key: Vec<u8>,
    /// Signature over the canonical enrollment message.
    pub signature: Vec<u8>,
}

impl OwnerEnrollment {
    fn canonical_message(machine_id: &[u8; 32], enrolled_at_ms: u64, owner_pub: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(ENROLL_MSG_PREFIX.len() + 32 + 8 + owner_pub.len());
        msg.extend_from_slice(ENROLL_MSG_PREFIX);
        msg.extend_from_slice(machine_id);
        msg.extend_from_slice(&enrolled_at_ms.to_le_bytes());
        msg.extend_from_slice(owner_pub);
        msg
    }

    /// Sign an enrollment for `machine_id` with the owner key.
    ///
    /// # Errors
    ///
    /// [`IdentityError::CertificateVerification`] when signing fails.
    pub fn sign(
        machine_id: MachineId,
        owner: &UserKeypair,
        enrolled_at_ms: u64,
    ) -> Result<Self, IdentityError> {
        let owner_public_key = owner.public_key().as_bytes().to_vec();
        let message = Self::canonical_message(&machine_id.0, enrolled_at_ms, &owner_public_key);
        let signature = sign_with_ml_dsa(owner.secret_key(), &message).map_err(|e| {
            IdentityError::CertificateVerification(format!("enrollment signing failed: {e:?}"))
        })?;
        Ok(Self {
            machine_id: machine_id.0,
            enrolled_at_ms,
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
            &self.owner_public_key,
        );
        verify_with_ml_dsa(&pubkey, &message, &signature)
            .map_err(|e| SyncError::BadSignature(format!("bad signature: {e:?}")))?;
        Ok(())
    }
}

/// Typed sync failures — every one is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    Io(String),
    /// Frame body exceeded [`MAX_FRAME_BYTES`] or a decode failed.
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
    /// A machine tried to sync with itself.
    SelfSync,
    BadSignature(String),
    /// Record kind tag and value variant disagree.
    KindMismatch,
    /// Undecodable kind tag on the wire (Tier-3 allowlist).
    UnknownKind {
        tag: u8,
    },
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
            Self::NotEnrolled { machine } => {
                write!(
                    f,
                    "machine {} is not in the owner device set",
                    hex::encode(machine)
                )
            }
            Self::SelfSync => write!(f, "refusing to sync with this machine itself"),
            Self::BadSignature(e) => write!(f, "sync signature failure: {e}"),
            Self::KindMismatch => write!(f, "record kind does not match its value variant"),
            Self::UnknownKind { tag } => {
                write!(f, "unknown sync kind tag 0x{tag:02x} (Tier-3 allowlist)")
            }
        }
    }
}

impl std::error::Error for SyncError {}

impl From<std::io::Error> for SyncError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Outcome of merging one inbound record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Stored — the record beat what we had.
    Accepted,
    /// Not stored — did not beat the stored clock (stale, rollback, or
    /// identical re-delivery). Never an error: partitions heal.
    Superseded,
}

/// Per-kind version vector entry: the peer's clock for one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindVersions {
    pub kind: SyncKind,
    /// `(key, clock)` for every record the peer holds under the kind.
    pub entries: Vec<(String, RecordClock)>,
}

/// One frame of the SyncV1 wire protocol. Length-prefixed bincode on the
/// stream following the `SyncV1` protocol byte.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncFrame {
    /// Handshake: protocol version, sender machine, sender owner.
    Hello {
        protocol_version: u32,
        machine_id: [u8; 32],
        owner_user_id: [u8; 32],
    },
    /// Per-kind version vectors (the sender's full Tier-1 clock table).
    VersionVector { kinds: Vec<KindVersions> },
    /// Records the peer is missing or would accept.
    Records { records: Vec<VersionedRecord> },
    /// Clean end of session.
    Done,
    /// Fail-closed abort with a reason (best-effort, one-way).
    Abort { reason: String },
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
    pub shipped: usize,
}

/// The local Tier-1 store: the owner device set plus the winning record for
/// every `(kind, key)` this machine holds. Persisted as two small JSON files
/// under `<data_dir>/sync/`, written atomically (temp file + rename).
pub struct OwnerSyncStore {
    dir: PathBuf,
    records: tokio::sync::RwLock<BTreeMap<(SyncKind, String), VersionedRecord>>,
    devices: tokio::sync::RwLock<BTreeMap<[u8; 32], OwnerEnrollment>>,
    last_session: tokio::sync::RwLock<BTreeMap<[u8; 32], DeviceSyncStatus>>,
    generation_tx: tokio::sync::watch::Sender<u64>,
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

impl OwnerSyncStore {
    /// Load (or start empty under) `<data_dir>/sync`. Corrupt or missing
    /// files start empty — the next session re-derives Tier-1 state from a
    /// live peer, and records are owner-signed so poison dies at verify.
    #[must_use]
    pub async fn load(data_dir: &Path) -> Self {
        let dir = data_dir.join(SYNC_DIR);
        let records = match tokio::fs::read(dir.join(RECORDS_FILE)).await {
            Ok(bytes) => serde_json::from_slice::<PersistedRecords>(&bytes)
                .map(|p| {
                    p.records
                        .into_iter()
                        .map(|r| ((r.kind, r.key.clone()), r))
                        .collect::<BTreeMap<_, _>>()
                })
                .unwrap_or_default(),
            Err(_) => BTreeMap::new(),
        };
        let devices = match tokio::fs::read(dir.join(DEVICES_FILE)).await {
            Ok(bytes) => serde_json::from_slice::<PersistedDevices>(&bytes)
                .map(|p| {
                    p.devices
                        .into_iter()
                        .map(|d| (d.machine_id, d))
                        .collect::<BTreeMap<_, _>>()
                })
                .unwrap_or_default(),
            Err(_) => BTreeMap::new(),
        };
        let (generation_tx, _) = tokio::sync::watch::channel(0);
        Self {
            dir,
            records: tokio::sync::RwLock::new(records),
            devices: tokio::sync::RwLock::new(devices),
            last_session: tokio::sync::RwLock::new(BTreeMap::new()),
            generation_tx,
        }
    }

    /// Write `bytes` to `path` via a unique temp file + rename (atomic for
    /// same-directory renames; mirrors `src/profile.rs`).
    async fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp-{}-{unique}", std::process::id()));
        tokio::fs::write(&tmp, bytes).await?;
        tokio::fs::rename(&tmp, path).await
    }

    async fn persist_records(records: &BTreeMap<(SyncKind, String), VersionedRecord>, dir: &Path) {
        let persisted = PersistedRecords {
            records: records.values().cloned().collect(),
        };
        if let Ok(bytes) = serde_json::to_vec(&persisted) {
            if let Err(e) = Self::write_atomically(&dir.join(RECORDS_FILE), &bytes).await {
                tracing::warn!("failed to persist sync records: {e}");
            }
        }
    }

    async fn persist_devices(devices: &BTreeMap<[u8; 32], OwnerEnrollment>, dir: &Path) {
        let persisted = PersistedDevices {
            devices: devices.values().cloned().collect(),
        };
        if let Ok(bytes) = serde_json::to_vec(&persisted) {
            if let Err(e) = Self::write_atomically(&dir.join(DEVICES_FILE), &bytes).await {
                tracing::warn!("failed to persist sync device set: {e}");
            }
        }
    }

    /// The enrollment gate (blocker 30): is `machine` enrolled for `owner`?
    ///
    /// Every stored enrollment is (re-)verified against `owner` here — a
    /// corrupt or foreign-key record fails closed, so persistence poison
    /// cannot wedge the gate open.
    #[must_use]
    pub async fn is_enrolled(&self, machine: &MachineId, owner: &UserId) -> bool {
        let devices = self.devices.read().await;
        devices
            .get(&machine.0)
            .is_some_and(|e| e.verify_owner(owner).is_ok())
    }

    /// Store a (verified-by-caller) enrollment, keeping the latest
    /// `enrolled_at_ms` per machine so a replayed older enrollment cannot
    /// rewind the clock.
    pub async fn enroll(&self, enrollment: OwnerEnrollment) {
        let mut devices = self.devices.write().await;
        let keep = devices
            .get(&enrollment.machine_id)
            .is_none_or(|old| enrollment.enrolled_at_ms >= old.enrolled_at_ms);
        if keep {
            devices.insert(enrollment.machine_id, enrollment.clone());
            Self::persist_devices(&devices, &self.dir).await;
        }
        self.kick();
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

    /// Merge one verified inbound record under the conflict rule.
    ///
    /// Verifies the owner signature first — fail closed (error, session
    /// aborts) on any signature failure; a merely stale or replayed record is
    /// [`MergeOutcome::Superseded`] (anti-rollback, not an error).
    pub async fn merge_record(
        &self,
        record: VersionedRecord,
        owner: &UserId,
    ) -> Result<MergeOutcome, SyncError> {
        record.verify_owner(owner)?;
        let mut records = self.records.write().await;
        let stored = records.get(&(record.kind, record.key.clone()));
        match stored {
            Some(existing) if !record.clock.beats(&existing.clock) => Ok(MergeOutcome::Superseded),
            _ => {
                records.insert((record.kind, record.key.clone()), record);
                Self::persist_records(&records, &self.dir).await;
                Ok(MergeOutcome::Accepted)
            }
        }
    }

    /// Mint a local record for `(kind, key)` from `desired`: no-op when the
    /// stored winner already carries exactly this value; otherwise version =
    /// stored version + 1, signed now by this machine.
    ///
    /// # Errors
    ///
    /// Propagates signing failures from [`VersionedRecord::sign`].
    pub async fn mint(
        &self,
        kind: SyncKind,
        key: &str,
        desired: &SyncValue,
        owner: &UserKeypair,
        writer_machine: MachineId,
    ) -> Result<(), IdentityError> {
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
        let record = VersionedRecord::sign(kind, key, desired, clock, owner)?;
        records.insert((kind, key.to_string()), record);
        Self::persist_records(&records, &self.dir).await;
        drop(records);
        self.kick();
        Ok(())
    }

    /// Test-only: insert a pre-built record WITHOUT verification, so
    /// integration tests can simulate a compromised writer whose forgery
    /// the receiving side must reject. Never call from production code —
    /// every real path (`mint`, `merge_record`) verifies signatures.
    #[doc(hidden)]
    pub async fn records_insert_for_testing(&self, record: VersionedRecord) {
        let mut records = self.records.write().await;
        records.insert((record.kind, record.key.clone()), record);
        Self::persist_records(&records, &self.dir).await;
    }

    /// Full record snapshot (winners only), for surfaces and sessions.
    pub async fn records_snapshot(&self) -> Vec<VersionedRecord> {
        self.records.read().await.values().cloned().collect()
    }

    /// The per-kind version vectors for the handshake.
    pub async fn version_vector(&self) -> Vec<KindVersions> {
        let records = self.records.read().await;
        let mut by_kind: BTreeMap<SyncKind, Vec<(String, RecordClock)>> = BTreeMap::new();
        for ((kind, key), record) in records.iter() {
            by_kind
                .entry(*kind)
                .or_default()
                .push((key.clone(), record.clock));
        }
        SyncKind::ALL
            .into_iter()
            .map(|kind| KindVersions {
                kind,
                entries: by_kind.remove(&kind).unwrap_or_default(),
            })
            .collect()
    }

    /// Records the peer is missing or would accept under [`RecordClock`].
    pub async fn records_for_peer(&self, peer_vector: &[KindVersions]) -> Vec<VersionedRecord> {
        let peer_clocks: BTreeMap<(SyncKind, String), RecordClock> = peer_vector
            .iter()
            .flat_map(|kv| {
                kv.entries
                    .iter()
                    .map(move |(k, c)| ((kv.kind, k.clone()), *c))
            })
            .collect();
        let records = self.records.read().await;
        records
            .iter()
            .filter(
                |((kind, key), record)| match peer_clocks.get(&(*kind, key.clone())) {
                    None => true,
                    Some(peer_clock) => record.clock.beats(peer_clock),
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
}

/// Unix epoch milliseconds.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Run one fail-closed sync session over the two halves of a SyncV1 stream.
///
/// Both sides run this same symmetric protocol: Hello → version vectors →
/// records both ways → Done. The caller has already cleared the ADR-0022
/// machine identity gates; this function enforces the same-owner +
/// enrollment gates (blocker 30) and verifies EVERY record's owner signature
/// (fail closed on any failure).
///
/// `on_accept` fires for each record this side stored, so callers can apply
/// Tier-1 state to live daemon surfaces.
///
/// # Errors
///
/// Any [`SyncError`] aborts the session; the store keeps whatever verified
/// records preceded the failure.
pub async fn run_sync_session<S, R, F>(
    send: &mut S,
    recv: &mut R,
    store: &OwnerSyncStore,
    owner: &UserId,
    local_machine: &MachineId,
    peer_machine: &MachineId,
    mut on_accept: F,
) -> Result<SessionSummary, SyncError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: FnMut(&VersionedRecord),
{
    let mut summary = SessionSummary::default();

    // Same-owner gate: a peer machine that is not enrolled locally never
    // gets past the first byte (blocker 30).
    if peer_machine.0 == local_machine.0 {
        return Err(SyncError::SelfSync);
    }
    if !store.is_enrolled(peer_machine, owner).await {
        return Err(SyncError::NotEnrolled {
            machine: peer_machine.0,
        });
    }

    // Hello both ways.
    let hello = SyncFrame::Hello {
        protocol_version: SYNC_PROTOCOL_VERSION,
        machine_id: local_machine.0,
        owner_user_id: owner.0,
    };
    write_frame(send, &hello).await?;
    match read_frame(recv).await? {
        SyncFrame::Hello {
            protocol_version,
            machine_id,
            owner_user_id,
        } => {
            if protocol_version != SYNC_PROTOCOL_VERSION {
                return Err(SyncError::ProtocolVersion {
                    local: SYNC_PROTOCOL_VERSION,
                    remote: protocol_version,
                });
            }
            if owner_user_id != owner.0 {
                return Err(SyncError::OwnerMismatch);
            }
            if machine_id != peer_machine.0 {
                // Hello machine must match the transport-authenticated peer.
                return Err(SyncError::MalformedFrame(
                    "hello machine differs from transport peer".into(),
                ));
            }
        }
        other => {
            return Err(SyncError::MalformedFrame(format!(
                "expected hello, got {other:?}"
            )));
        }
    }

    // Version vectors both ways.
    let local_vector = store.version_vector().await;
    write_frame(
        send,
        &SyncFrame::VersionVector {
            kinds: local_vector,
        },
    )
    .await?;
    let peer_vector = match read_frame(recv).await? {
        SyncFrame::VersionVector { kinds } => kinds,
        other => {
            return Err(SyncError::MalformedFrame(format!(
                "expected version vector, got {other:?}"
            )));
        }
    };

    // Ship what the peer lacks; receive what we lack. Every inbound record
    // is owner-verified — one forgery aborts the whole session.
    let to_ship = store.records_for_peer(&peer_vector).await;
    summary.shipped = to_ship.len();
    write_frame(send, &SyncFrame::Records { records: to_ship }).await?;
    let accepted: Vec<VersionedRecord> = match read_frame(recv).await? {
        SyncFrame::Records { records } => {
            let mut accepted = Vec::new();
            for record in records {
                match store.merge_record(record.clone(), owner).await {
                    Ok(MergeOutcome::Accepted) => {
                        summary.accepted += 1;
                        accepted.push(store_last_winner(store, &record).await);
                    }
                    Ok(MergeOutcome::Superseded) => {
                        summary.superseded += 1;
                    }
                    Err(e) => {
                        let _ = write_frame(
                            send,
                            &SyncFrame::Abort {
                                reason: e.to_string(),
                            },
                        )
                        .await;
                        return Err(e);
                    }
                }
            }
            accepted
        }
        other => {
            return Err(SyncError::MalformedFrame(format!(
                "expected records, got {other:?}"
            )));
        }
    };

    // Done both ways.
    write_frame(send, &SyncFrame::Done).await?;
    match read_frame(recv).await? {
        SyncFrame::Done => {}
        SyncFrame::Abort { reason } => {
            return Err(SyncError::MalformedFrame(format!("peer aborted: {reason}")));
        }
        other => {
            return Err(SyncError::MalformedFrame(format!(
                "expected done, got {other:?}"
            )));
        }
    }

    // Apply accepted records only after the clean Done, so an aborted
    // session never mutates live daemon state. (The stored winner is
    // re-read: a later record in the same batch may have superseded it.)
    for record in accepted {
        on_accept(&record);
    }
    Ok(summary)
}

/// The stored winner for a freshly merged record's `(kind, key)`.
async fn store_last_winner(store: &OwnerSyncStore, merged: &VersionedRecord) -> VersionedRecord {
    store
        .records_snapshot()
        .await
        .into_iter()
        .find(|r| r.kind == merged.kind && r.key == merged.key)
        .unwrap_or_else(|| merged.clone())
}
/// Default period between automatic sync passes (also wakes on any local
/// Tier-1 change via the store's generation channel).
pub const DEFAULT_SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Current daemon self-profile names, best-effort snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncProfileNames {
    pub human_name: Option<String>,
    pub display_name: Option<String>,
    pub machine_name: Option<String>,
}

/// Live daemon view the server installs into [`OwnerSyncService`] after
/// `AppState` exists. Keeps this module decoupled from server internals:
/// reads are best-effort (a contended lock reads as "unchanged" and the
/// next pass retries), applies are fire-and-forget (the implementation
/// owns locking and persistence).
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
}

/// Daemon-resident Tier-1 sync service (the `ForwardService` pattern for
/// `SyncV1`): owns the single registered acceptor for
/// [`crate::streams::StreamProtocol::SyncV1`], gates each inbound stream on
/// the owner device set, dials every enrolled machine it can resolve, and
/// mints local Tier-1 records from live daemon state before each pass.
///
/// Constructed only when the install has an owner key (`user.key`); an
/// ownerless install registers no acceptor and syncs nothing.
pub struct OwnerSyncService {
    agent: Arc<crate::Agent>,
    store: Arc<OwnerSyncStore>,
    journal_path: Option<PathBuf>,
    view: std::sync::RwLock<Option<Arc<dyn SyncDaemonView>>>,
    tasks: tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl OwnerSyncService {
    /// Build the service, load its store from `<data_dir>/sync`, and
    /// register the `SyncV1` acceptor (single-acceptor rule — a conflict is
    /// a hard startup error). The acceptor is moved into its drain task,
    /// which deregisters it when the task ends.
    ///
    /// # Errors
    ///
    /// [`crate::error::NetworkError::StreamAcceptorConflict`] when another
    /// consumer already owns `SyncV1`.
    pub async fn new(
        agent: Arc<crate::Agent>,
        data_dir: &Path,
    ) -> crate::error::NetworkResult<Arc<Self>> {
        let acceptor = agent.register_stream_acceptor(crate::streams::StreamProtocol::SyncV1)?;
        let journal_path = agent.cert_journal_path().map(Path::to_path_buf);
        let service = Arc::new(Self {
            agent,
            store: Arc::new(OwnerSyncStore::load(data_dir).await),
            journal_path,
            view: std::sync::RwLock::new(None),
            tasks: tokio::sync::Mutex::new(Vec::new()),
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

    /// Spawn the inbound acceptor drain loop. Each accepted stream is
    /// enrollment-gated, then runs one session.
    async fn spawn_acceptor_loop(self: &Arc<Self>, mut acceptor: crate::streams::StreamAcceptor) {
        let service = Arc::clone(self);
        let task = tokio::spawn(async move {
            while let Some(stream) = acceptor.next().await {
                let service = Arc::clone(&service);
                tokio::spawn(async move { service.handle_inbound(stream).await });
            }
        });
        self.tasks.lock().await.push(task);
    }

    /// Inbound path: the ADR-0022 machine identity gates have already
    /// cleared in the shared accept loop; enforce the owner device set
    /// (blocker 30) — an unenrolled machine's stream is dropped (reset)
    /// with zero application bytes read.
    async fn handle_inbound(&self, stream: crate::streams::PeerStream) {
        let Some((owner, local_machine)) = self.owner_and_machine() else {
            return;
        };
        let peer = stream.peer();
        if !self.store.is_enrolled(&peer, &owner).await {
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
            &owner,
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
        let (owner, local_machine) = self
            .owner_and_machine()
            .ok_or_else(|| "no owner key".to_string())?;
        if !self.store.is_enrolled(machine, &owner).await {
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
        let result = run_sync_session(
            &mut send,
            &mut recv,
            &self.store,
            &owner,
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
    /// is unchanged since its stored winner).
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
                self.mint_or_log(
                    SyncKind::HomePointer,
                    "home",
                    home_value,
                    owner_kp,
                    local_machine,
                )
                .await;
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

    /// Apply an accepted record to live daemon state (post-Done only).
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
                // Stored in the record map for adoption by future Home
                // provisioning; cross-machine Home adoption (TreeKEM
                // re-key, key packages) is deliberately out of Tier-1
                // scope (gapcheck blocker 32).
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

    fn owner_kp(seed: u8) -> UserKeypair {
        UserKeypair::from_seed(&[seed; 32]).expect("deterministic keypair")
    }

    fn machine(id: u8) -> MachineId {
        MachineId([id; 32])
    }

    fn names_value(display: &str) -> SyncValue {
        SyncValue::MachineNames {
            display_name: Some(display.to_string()),
            machine_name: None,
        }
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
        let store = OwnerSyncStore::load(dir.path()).await;
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
        let high = VersionedRecord::sign(
            SyncKind::MachineNames,
            &key,
            &names_value("v9"),
            RecordClock {
                version: 9,
                signed_at_ms: 1,
                writer_machine: machine(2).0,
            },
            &owner,
        )
        .expect("sign v9");
        assert_eq!(
            store.merge_record(high, &owner_id).await.expect("merge v9"),
            MergeOutcome::Accepted
        );

        // Rollback: version 3 (and 9-with-older-clock) rejected.
        let rollback = VersionedRecord::sign(
            SyncKind::MachineNames,
            &key,
            &names_value("old"),
            RecordClock {
                version: 3,
                signed_at_ms: 999,
                writer_machine: machine(3).0,
            },
            &owner,
        )
        .expect("sign rollback");
        assert_eq!(
            store
                .merge_record(rollback, &owner_id)
                .await
                .expect("merge rollback"),
            MergeOutcome::Superseded
        );
        let stale_equal = VersionedRecord::sign(
            SyncKind::MachineNames,
            &key,
            &names_value("stale"),
            RecordClock {
                version: 9,
                signed_at_ms: 0,
                writer_machine: machine(3).0,
            },
            &owner,
        )
        .expect("sign stale");
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
        let store = OwnerSyncStore::load(dir.path()).await;
        let owner = owner_kp(1);
        let attacker = owner_kp(2);
        let forged = VersionedRecord::sign(
            SyncKind::OwnerProfile,
            "owner",
            &SyncValue::OwnerProfile {
                human_name: Some("Mallory".into()),
            },
            RecordClock {
                version: 100,
                signed_at_ms: 200,
                writer_machine: machine(9).0,
            },
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
            RecordClock {
                version: 1,
                signed_at_ms: 1,
                writer_machine: machine(1).0,
            },
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
    async fn enrollment_gate_rejects_unenrolled_and_forged_machines() {
        // WHY: blocker 30 — only owner-enrolled machines pass the gate.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = OwnerSyncStore::load(dir.path()).await;
        let owner = owner_kp(1);
        let owner_id = owner.user_id();
        let enrolled_machine = machine(7);
        let enrollment = OwnerEnrollment::sign(enrolled_machine, &owner, 1_000).expect("enroll");
        store.enroll(enrollment).await;

        assert!(store.is_enrolled(&enrolled_machine, &owner_id).await);
        assert!(
            !store.is_enrolled(&machine(8), &owner_id).await,
            "unenrolled machine fails the gate"
        );

        // Forged enrollment signed by a different key fails closed.
        let attacker = owner_kp(2);
        let forged = OwnerEnrollment::sign(machine(9), &attacker, 2_000).expect("sign");
        assert_eq!(
            forged.verify_owner(&owner_id),
            Err(SyncError::OwnerMismatch)
        );
        // Directly planted in the file, it still fails verification at the gate.
        store.enroll(forged).await;
        assert!(
            !store.is_enrolled(&machine(9), &owner_id).await,
            "foreign-key enrollment never passes the gate"
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
            let record = VersionedRecord::sign(
                kind,
                "k",
                &value,
                RecordClock {
                    version: 1,
                    signed_at_ms: 1,
                    writer_machine: machine(1).0,
                },
                &owner,
            )
            .expect("sign");
            record.verify().expect("all four kinds verify");
        }

        // Behavioral Tier-3 check: kind/value coherence is enforced, so no
        // foreign state can ride a record under a mismatched kind tag.
        let mismatched = VersionedRecord {
            kind: SyncKind::HomePointer,
            key: "home".into(),
            value: names_value("evil"),
            clock: RecordClock {
                version: 1,
                signed_at_ms: 1,
                writer_machine: machine(1).0,
            },
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
        let store = OwnerSyncStore::load(dir.path()).await;
        let owner = owner_kp(1);
        let owner_id = owner.user_id();
        let local = machine(1);
        let (mut tx, mut rx) = tokio::io::duplex(64);
        let err = run_sync_session(
            &mut tx,
            &mut rx,
            &store,
            &owner_id,
            &local,
            &machine(2),
            |_| {},
        )
        .await
        .expect_err("unenrolled peer refused");
        assert!(matches!(err, SyncError::NotEnrolled { .. }));
        let err = run_sync_session(&mut tx, &mut rx, &store, &owner_id, &local, &local, |_| {})
            .await
            .expect_err("self-sync refused");
        assert_eq!(err, SyncError::SelfSync);
    }
}
