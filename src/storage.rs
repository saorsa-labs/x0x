//! Key storage utilities for x0x identity persistence.
//!
//! This module provides serialization and storage functionality for
//! MachineKeypair, AgentKeypair, UserKeypair, and AgentCertificate types,
//! enabling persistence of identities across application restarts.

#[cfg(test)]
use self::w3h_fs as fs;
use crate::error::{IdentityError, Result};
use crate::identity::{AgentCertificate, AgentKeypair, MachineKeypair, UserKeypair};
use crate::revocation::{
    RevocationSet, REVOCATIONS_FILE_MAGIC, REVOCATIONS_FILE_MAGIC_V2, REVOCATIONS_FILE_MAGIC_V3,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(test))]
use tokio::fs;

/// Test-only FS layer for W3-H (#1245): when the entropy/wall-clock shim is
/// active, read/write/exists/remove/metadata run on the current-thread
/// runtime instead of `tokio::fs`'s blocking pool, so same-instant task
/// order is not scrambled by remote wakeups. `read_dir` stays on tokio
/// (rare on the join path; wrapping its stream type is not worth the
/// surface). Production builds use `tokio::fs` unchanged.
#[cfg(test)]
mod w3h_fs {
    use std::io;
    use std::path::Path;

    fn inline() -> bool {
        std::env::var_os("W3H_SHIM_ACTIVE").as_deref() == Some(std::ffi::OsStr::new("1"))
    }

    pub async fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        if inline() {
            std::fs::read(path)
        } else {
            tokio::fs::read(path).await
        }
    }

    pub async fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
        if inline() {
            std::fs::write(path, contents)
        } else {
            tokio::fs::write(path, contents).await
        }
    }

    pub async fn try_exists(path: impl AsRef<Path>) -> io::Result<bool> {
        if inline() {
            Ok(path.as_ref().exists())
        } else {
            tokio::fs::try_exists(path).await
        }
    }

    pub async fn remove_file(path: impl AsRef<Path>) -> io::Result<()> {
        if inline() {
            std::fs::remove_file(path)
        } else {
            tokio::fs::remove_file(path).await
        }
    }

    pub async fn metadata(path: impl AsRef<Path>) -> io::Result<std::fs::Metadata> {
        if inline() {
            std::fs::metadata(path)
        } else {
            tokio::fs::metadata(path).await
        }
    }

    pub async fn create_dir(path: impl AsRef<Path>) -> io::Result<()> {
        if inline() {
            std::fs::create_dir(path)
        } else {
            tokio::fs::create_dir(path).await
        }
    }

    pub async fn create_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
        if inline() {
            std::fs::create_dir_all(path)
        } else {
            tokio::fs::create_dir_all(path).await
        }
    }

    pub async fn remove_dir(path: impl AsRef<Path>) -> io::Result<()> {
        if inline() {
            std::fs::remove_dir(path)
        } else {
            tokio::fs::remove_dir(path).await
        }
    }

    pub async fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
        if inline() {
            std::fs::rename(from, to)
        } else {
            tokio::fs::rename(from, to).await
        }
    }

    pub async fn set_permissions(
        path: impl AsRef<Path>,
        perms: std::fs::Permissions,
    ) -> io::Result<()> {
        if inline() {
            std::fs::set_permissions(path, perms)
        } else {
            tokio::fs::set_permissions(path, perms).await
        }
    }

    pub use tokio::fs::{read_dir, File};
}

/// Serialized keypair representation for storage (legacy v1 format).
///
/// Uses raw bytes for efficiency rather than base64 encoding. This is the
/// on-disk shape produced by every x0x release to date: a bare
/// `bincode(public_key, secret_key)` with no version marker. New code keeps
/// writing exactly these bytes whenever no expiry is recorded, so existing
/// `~/.x0x/*.key` files stay byte-for-byte compatible.
#[derive(Serialize, Deserialize)]
struct SerializedKeypair {
    /// Raw public key bytes
    public_key: Vec<u8>,
    /// Raw secret key bytes
    secret_key: Vec<u8>,
}

/// Serialized keypair representation carrying a local expiry (v2 format).
///
/// Only written when a `not_after` is recorded. The on-disk encoding is
/// [`KEYFILE_V2_MAGIC`] followed by `bincode(public_key, secret_key,
/// not_after)`. The magic marker lets the loader distinguish this from the
/// legacy format without ambiguity.
#[derive(Serialize, Deserialize)]
struct SerializedKeypairV2 {
    /// Raw public key bytes
    public_key: Vec<u8>,
    /// Raw secret key bytes
    secret_key: Vec<u8>,
    /// Unix timestamp after which this key material is considered expired.
    ///
    /// This is a **local record only** — key-file expiry is never enforced
    /// over the network (only [`crate::identity::AgentCertificate`] expiry is).
    not_after: u64,
}

/// Magic marker prefixing a v2 (expiry-carrying) key file.
///
/// A legacy v1 file begins with the bincode length prefix of the ML-DSA-65
/// public key (`0xA0 0x07 …`), so it can never collide with this marker; a
/// missing marker therefore unambiguously means "legacy, no expiry".
const KEYFILE_V2_MAGIC: &[u8; 4] = b"X0K2";

/// Encode raw key material with an optional local expiry.
///
/// `None` produces the legacy v1 bytes verbatim (no marker, no extra bytes)
/// so existing deployments' files are unchanged. `Some` produces the v2
/// format ([`KEYFILE_V2_MAGIC`] + bincode with the trailing `not_after`).
fn encode_keypair_bytes(
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    not_after: Option<u64>,
) -> Result<Vec<u8>> {
    match not_after {
        None => {
            let data = SerializedKeypair {
                public_key,
                secret_key,
            };
            bincode::serialize(&data).map_err(|e| IdentityError::Serialization(e.to_string()))
        }
        Some(not_after) => {
            let data = SerializedKeypairV2 {
                public_key,
                secret_key,
                not_after,
            };
            let body = bincode::serialize(&data)
                .map_err(|e| IdentityError::Serialization(e.to_string()))?;
            let mut out = Vec::with_capacity(KEYFILE_V2_MAGIC.len() + body.len());
            out.extend_from_slice(KEYFILE_V2_MAGIC);
            out.extend_from_slice(&body);
            Ok(out)
        }
    }
}

/// Decode key-file bytes into raw key material plus an optional local expiry.
///
/// Detects the v2 magic marker; when absent the bytes are the legacy v1
/// format and `not_after` is `None` (absence of expiry ⇒ never expires).
fn decode_keypair_bytes(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Option<u64>)> {
    if bytes.len() >= KEYFILE_V2_MAGIC.len() && &bytes[..KEYFILE_V2_MAGIC.len()] == KEYFILE_V2_MAGIC
    {
        let data: SerializedKeypairV2 = bincode::deserialize(&bytes[KEYFILE_V2_MAGIC.len()..])
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        Ok((data.public_key, data.secret_key, Some(data.not_after)))
    } else {
        let data: SerializedKeypair =
            bincode::deserialize(bytes).map_err(|e| IdentityError::Serialization(e.to_string()))?;
        Ok((data.public_key, data.secret_key, None))
    }
}

/// Serialize a MachineKeypair to bytes for storage.
///
/// # Arguments
///
/// * `kp` - The MachineKeypair to serialize
///
/// # Returns
///
/// A vector containing the serialized keypair data
pub fn serialize_machine_keypair(kp: &MachineKeypair) -> Result<Vec<u8>> {
    encode_keypair_bytes(
        kp.public_key().as_bytes().to_vec(),
        kp.secret_key().as_bytes().to_vec(),
        None,
    )
}

/// Deserialize a MachineKeypair from bytes.
///
/// # Arguments
///
/// * `bytes` - The serialized keypair data
///
/// # Returns
///
/// A deserialized MachineKeypair
pub fn deserialize_machine_keypair(bytes: &[u8]) -> Result<MachineKeypair> {
    let (public_key, secret_key, _not_after) = decode_keypair_bytes(bytes)?;
    MachineKeypair::from_bytes(&public_key, &secret_key)
}

/// Deserialize a MachineKeypair along with its optional local expiry.
///
/// Returns `(keypair, not_after)` where `not_after` is `None` for legacy
/// (v1) key files — absence of expiry means the key never expires.
///
/// # Errors
///
/// Returns [`IdentityError::Serialization`] if the bytes are not a valid
/// key file, or a key-material error if the embedded bytes are malformed.
pub fn deserialize_machine_keypair_with_expiry(
    bytes: &[u8],
) -> Result<(MachineKeypair, Option<u64>)> {
    let (public_key, secret_key, not_after) = decode_keypair_bytes(bytes)?;
    Ok((
        MachineKeypair::from_bytes(&public_key, &secret_key)?,
        not_after,
    ))
}

/// Serialize a MachineKeypair recording an optional local expiry.
///
/// `None` writes the legacy v1 format byte-for-byte; `Some` writes the v2
/// format carrying `not_after`.
///
/// # Errors
///
/// Returns [`IdentityError::Serialization`] if encoding fails.
pub fn serialize_machine_keypair_with_expiry(
    kp: &MachineKeypair,
    not_after: Option<u64>,
) -> Result<Vec<u8>> {
    encode_keypair_bytes(
        kp.public_key().as_bytes().to_vec(),
        kp.secret_key().as_bytes().to_vec(),
        not_after,
    )
}

/// Serialize an AgentKeypair to bytes for storage.
///
/// # Arguments
///
/// * `kp` - The AgentKeypair to serialize
///
/// # Returns
///
/// A vector containing the serialized keypair data
pub fn serialize_agent_keypair(kp: &AgentKeypair) -> Result<Vec<u8>> {
    encode_keypair_bytes(
        kp.public_key().as_bytes().to_vec(),
        kp.secret_key().as_bytes().to_vec(),
        None,
    )
}

/// Serialize an AgentKeypair recording an optional local expiry.
///
/// `None` writes the legacy v1 format byte-for-byte; `Some` writes the v2
/// format carrying `not_after`.
///
/// # Errors
///
/// Returns [`IdentityError::Serialization`] if encoding fails.
pub fn serialize_agent_keypair_with_expiry(
    kp: &AgentKeypair,
    not_after: Option<u64>,
) -> Result<Vec<u8>> {
    encode_keypair_bytes(
        kp.public_key().as_bytes().to_vec(),
        kp.secret_key().as_bytes().to_vec(),
        not_after,
    )
}

/// Deserialize an AgentKeypair from bytes.
///
/// # Arguments
///
/// * `bytes` - The serialized keypair data
///
/// # Returns
///
/// A deserialized AgentKeypair
pub fn deserialize_agent_keypair(bytes: &[u8]) -> Result<AgentKeypair> {
    let (public_key, secret_key, _not_after) = decode_keypair_bytes(bytes)?;
    AgentKeypair::from_bytes(&public_key, &secret_key)
}

/// Deserialize an AgentKeypair along with its optional local expiry.
///
/// Returns `(keypair, not_after)` where `not_after` is `None` for legacy
/// (v1) key files — absence of expiry means the key never expires.
///
/// # Errors
///
/// Returns [`IdentityError::Serialization`] if the bytes are not a valid
/// key file, or a key-material error if the embedded bytes are malformed.
pub fn deserialize_agent_keypair_with_expiry(bytes: &[u8]) -> Result<(AgentKeypair, Option<u64>)> {
    let (public_key, secret_key, not_after) = decode_keypair_bytes(bytes)?;
    Ok((
        AgentKeypair::from_bytes(&public_key, &secret_key)?,
        not_after,
    ))
}

/// x0x configuration directory path.
const X0X_DIR: &str = ".x0x";

/// Machine keypair file name.
const MACHINE_KEY_FILE: &str = "machine.key";

/// Agent keypair file name.
const AGENT_KEY_FILE: &str = "agent.key";

/// User keypair file name.
const USER_KEY_FILE: &str = "user.key";

/// Agent certificate file name.
const AGENT_CERT_FILE: &str = "agent.cert";

/// Revocation set file name.
const REVOCATION_FILE: &str = "revocations.bin";

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

async fn write_private_file(path: &Path, bytes: Vec<u8>) -> Result<()> {
    let _revocation_guard = revocation_write_guard(path).await?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .await
        .map_err(IdentityError::from)?;

    let file_name = path.file_name().ok_or_else(|| {
        IdentityError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid path: missing file name",
        ))
    })?;
    let unique = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        unique
    ));

    fs::write(&tmp_path, bytes)
        .await
        .map_err(IdentityError::from)?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&tmp_path)
            .await
            .map_err(IdentityError::from)?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&tmp_path, perms)
            .await
            .map_err(IdentityError::from)?;
    }

    if let Err(err) = fs::rename(&tmp_path, path).await {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(IdentityError::from(err));
    }

    Ok(())
}

/// Which half of a durable atomic write failed — the two halves have
/// OPPOSITE rollback semantics (issue #1101; the same split
/// `OwnerSyncStore` introduced for its `write_atomically`, review R5
/// finding 2).
#[derive(Debug)]
#[non_exhaustive]
pub enum DurableWriteError {
    /// Failed before the rename: the OLD bytes are still on disk and no
    /// new bytes are visible; callers may safely roll in-memory state
    /// back.
    BeforeRename(std::io::Error),
    /// The rename happened but the post-rename parent-directory open or
    /// fsync failed: the NEW bytes are already in place on disk; rolling
    /// memory back would leave it behind an advanced disk. Callers must
    /// align memory with the new disk instead (and fail-stop where the
    /// durability contract demands it).
    AfterRename(std::io::Error),
}

impl std::fmt::Display for DurableWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeRename(e) => {
                write!(f, "durable write failed before the rename (disk unchanged): {e}")
            }
            Self::AfterRename(e) => write!(
                f,
                "durable write failed after the rename (new bytes are in place, durability unconfirmed): {e}"
            ),
        }
    }
}

impl std::error::Error for DurableWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BeforeRename(e) | Self::AfterRename(e) => Some(e),
        }
    }
}

impl DurableWriteError {
    /// Whether the failure arrived AFTER the atomic rename — the NEW
    /// bytes are already visible on disk and memory must not be rolled
    /// back below them (issue #1101).
    #[must_use]
    pub fn crossed_rename(&self) -> bool {
        matches!(self, Self::AfterRename(_))
    }

    /// A remote rebuild refused because a quarantine sibling could not be read.
    ///
    /// The live file was not replaced. Callers keep that carrier closed.
    #[must_use]
    pub(crate) fn quarantine_unreadable(&self) -> bool {
        let Self::BeforeRename(error) = self else {
            return false;
        };
        error.to_string().contains(QUARANTINE_UNREADABLE_REBUILD)
    }

    /// Prefix the carried message with `path` context without changing
    /// which half failed (the variant is the contract; the message is for
    /// logs).
    #[must_use]
    pub fn with_path(self, path: &Path) -> Self {
        let contextual =
            |e: &std::io::Error| std::io::Error::other(format!("{}: {e}", path.display()));
        match self {
            Self::BeforeRename(e) => Self::BeforeRename(contextual(&e)),
            Self::AfterRename(e) => Self::AfterRename(contextual(&e)),
        }
    }
}

/// Test-only fault injection for [`write_private_bytes_durable`]
/// (issue #1101): while a target path is armed, the parent-directory
/// fsync — durable point 2, AFTER the atomic rename — fails for writes
/// to exactly that path, so tests can prove each caller keeps memory
/// aligned with the already-advanced disk. Mirrors
/// `OwnerSyncStore::set_fail_after_rename_for_testing`; compiled only
/// for this crate's own test builds (`cfg(test)` — no env var, no cargo
/// feature). Path-scoped, not process-global: threaded `cargo test`
/// runs the whole suite in one process, where a global flag armed by
/// any test would fail every concurrent durable write in the others.
#[cfg(test)]
static FAIL_PARENT_DIR_FSYNC_FOR_TESTING: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

/// Disarms only the path this guard armed, on drop, so a panicking
/// assertion cannot leak the injected fault — not even to other tests'
/// writes in the same process.
#[cfg(test)]
pub(crate) struct FailParentDirFsyncGuard {
    path: std::path::PathBuf,
}

/// Arm the parent-directory fsync failure seam for writes to `path`
/// (issue #1101): until the returned guard is dropped, durable writes
/// to exactly this path fail AFTER the atomic rename; writes to every
/// other path are unaffected. A directory path arms every file under it.
#[cfg(test)]
pub(crate) fn arm_fail_parent_dir_fsync_for_testing(path: &Path) -> FailParentDirFsyncGuard {
    FAIL_PARENT_DIR_FSYNC_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(path.to_path_buf());
    FailParentDirFsyncGuard {
        path: path.to_path_buf(),
    }
}

/// Whether `path` is armed in [`FAIL_PARENT_DIR_FSYNC_FOR_TESTING`].
#[cfg(test)]
fn fails_parent_dir_fsync_for_testing(path: &Path) -> bool {
    FAIL_PARENT_DIR_FSYNC_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|armed| armed == path || path.starts_with(armed))
}

/// With the parent-directory fsync seam, replace the renamed bytes so the
/// caller cannot install them. The hold must stay closed.
#[cfg(test)]
static CORRUPT_AFTER_RENAME_FOR_TESTING: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) struct CorruptAfterRenameGuard {
    path: std::path::PathBuf,
}

#[cfg(test)]
pub(crate) fn arm_corrupt_after_rename_for_testing(path: &Path) -> CorruptAfterRenameGuard {
    CORRUPT_AFTER_RENAME_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(path.to_path_buf());
    CorruptAfterRenameGuard {
        path: path.to_path_buf(),
    }
}

#[cfg(test)]
fn corrupts_after_rename_for_testing(path: &Path) -> bool {
    CORRUPT_AFTER_RENAME_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|armed| armed == path)
}

#[cfg(test)]
impl Drop for CorruptAfterRenameGuard {
    fn drop(&mut self) {
        let mut armed = CORRUPT_AFTER_RENAME_FOR_TESTING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(idx) = armed.iter().position(|p| *p == self.path) {
            armed.swap_remove(idx);
        }
    }
}

/// Pause inside a preserving rebuild so a test can observe admission.
#[cfg(test)]
static REBUILD_AWAIT_ARMED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
static REBUILD_AWAIT_ENTERED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) struct RebuildAwaitGuard;

#[cfg(test)]
pub(crate) fn arm_rebuild_await_for_testing() -> RebuildAwaitGuard {
    REBUILD_AWAIT_ENTERED.store(false, std::sync::atomic::Ordering::SeqCst);
    REBUILD_AWAIT_ARMED.store(true, std::sync::atomic::Ordering::SeqCst);
    RebuildAwaitGuard
}

#[cfg(test)]
pub(crate) fn rebuild_await_entered_for_testing() -> bool {
    REBUILD_AWAIT_ENTERED.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
pub(crate) fn release_rebuild_await_for_testing() {
    REBUILD_AWAIT_ARMED.store(false, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
impl Drop for RebuildAwaitGuard {
    fn drop(&mut self) {
        release_rebuild_await_for_testing();
    }
}

#[cfg(test)]
async fn pause_rebuild_await_for_testing() {
    if !REBUILD_AWAIT_ARMED.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    REBUILD_AWAIT_ENTERED.store(true, std::sync::atomic::Ordering::SeqCst);
    while REBUILD_AWAIT_ARMED.load(std::sync::atomic::Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
impl Drop for FailParentDirFsyncGuard {
    fn drop(&mut self) {
        let mut armed = FAIL_PARENT_DIR_FSYNC_FOR_TESTING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(idx) = armed.iter().position(|p| *p == self.path) {
            armed.swap_remove(idx);
        }
    }
}

/// Fail a durable write before its rename. Arm a file path, or a directory
/// to fail every durable publish under it. The temp file is removed and the
/// destination stays unchanged.
#[cfg(test)]
static FAIL_DURABLE_BEFORE_RENAME_FOR_TESTING: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) struct FailDurableBeforeRenameGuard {
    path: std::path::PathBuf,
}

#[cfg(test)]
pub(crate) fn arm_fail_durable_before_rename_for_testing(
    path: &Path,
) -> FailDurableBeforeRenameGuard {
    FAIL_DURABLE_BEFORE_RENAME_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(path.to_path_buf());
    FailDurableBeforeRenameGuard {
        path: path.to_path_buf(),
    }
}

#[cfg(test)]
fn fails_durable_before_rename_for_testing(path: &Path) -> bool {
    FAIL_DURABLE_BEFORE_RENAME_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|armed| armed == path || path.starts_with(armed))
}

#[cfg(test)]
impl Drop for FailDurableBeforeRenameGuard {
    fn drop(&mut self) {
        let mut armed = FAIL_DURABLE_BEFORE_RENAME_FOR_TESTING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(idx) = armed.iter().position(|candidate| *candidate == self.path) {
            armed.swap_remove(idx);
        }
    }
}

/// Crash-atomic durable write for secret bytes (review r3, PR #465 item 1):
/// temp file (0600) → `sync_all` the file → atomic rename into place →
/// `sync_all` the parent directory. Unlike [`write_private_bytes`], a power
/// loss can never leave a torn/half-written destination or a rename the
/// directory does not remember — required for the persistence journals
/// that must be durable BEFORE the live state they protect changes.
///
/// # Errors
/// Returns an error if the directory cannot be created, the write, the
/// file sync, the rename, or the parent-directory sync fails. This error
/// does not say whether the rename happened. A caller that rolls memory
/// back on failure must use [`write_private_bytes_durable_typed`]
/// instead (issue #1101).
pub async fn write_private_bytes_durable(path: &Path, bytes: Vec<u8>) -> Result<()> {
    // The guard's own error passes through unchanged, as before #1101.
    let guard = revocation_write_guard(path).await?;
    let bytes = monotonic_v1_v2_bytes(path, bytes)
        .await
        .map_err(durable_write_identity_error)?;
    write_private_bytes_durable_guarded(path, bytes, guard)
        .await
        .map_err(durable_write_identity_error)
}

/// [`write_private_bytes_durable`], with a typed error that says which
/// half of the write failed (issue #1101). The write itself is the same:
/// temp file (0600), file fsync, atomic rename, parent-directory fsync.
///
/// # Errors
/// [`DurableWriteError::BeforeRename`] when the failure precedes the
/// rename (the revocation-store guard, directory creation, the write,
/// the file sync, the chmod or the rename itself): the destination still
/// holds its OLD bytes, so callers may roll in-memory state back.
/// [`DurableWriteError::AfterRename`] when the parent-directory open or
/// fsync fails: the NEW bytes are already in place and callers must NOT
/// roll memory back below the advanced disk.
pub async fn write_private_bytes_durable_typed(
    path: &Path,
    bytes: Vec<u8>,
) -> std::result::Result<(), DurableWriteError> {
    let guard = revocation_write_guard(path)
        .await
        .map_err(guard_refusal_before_rename)?;
    let bytes = monotonic_v1_v2_bytes(path, bytes).await?;
    write_private_bytes_durable_guarded(path, bytes, guard).await
}

/// Unite `incoming` with verified records in a readable v1 or v2 file.
///
/// A queued save captured before a rebuild must not replace recovered
/// records. A file whose records all fail verification has nothing to
/// preserve, so the write keeps `incoming` byte for byte. v3 keeps its
/// own merge writer. A missing live file is written as `incoming`.
async fn monotonic_v1_v2_bytes(
    path: &Path,
    incoming: Vec<u8>,
) -> std::result::Result<Vec<u8>, DurableWriteError> {
    let Some(store) = RevocationStore::at_path(path) else {
        return Ok(incoming);
    };
    if matches!(store, RevocationStore::V3) {
        return Ok(incoming);
    }
    let disk = match read_revocation_store_locked(path, store, true).await {
        Ok(Some(bytes)) if !bytes.is_empty() => bytes,
        Ok(_) => return Ok(incoming),
        Err(error) => {
            return Err(match error {
                IdentityError::Storage(io) => DurableWriteError::BeforeRename(io),
                other => DurableWriteError::BeforeRename(std::io::Error::other(other.to_string())),
            });
        }
    };
    let disk_set = decode_revocation_bytes(store, &disk)?;
    let incoming_set = decode_revocation_bytes(store, &incoming)?;
    if disk_set.is_empty() {
        return Ok(incoming);
    }
    let mut merged = disk_set;
    unite_revocation_store(store, &mut merged, incoming_set);
    encode_revocation_store(store, &merged)
}

async fn clear_revocation_block_async(path: &Path) {
    let mut states = revocation_store_states().lock().await;
    if let Some(state) = states.get_mut(path) {
        state.unreadable = None;
        state.last_persist_warning = None;
        state.archive_failed = false;
    }
}

/// Revocations recovered from `<name>.quarantined-*` siblings.
struct QuarantineSiblingLoad {
    records: RevocationSet,
    /// A sibling could not be read or decoded.
    unreadable: bool,
}

/// Read every quarantine sibling under the caller's lock.
///
/// `decode` accepts the trailing bytes that `validate` rejects, so a
/// quarantined file can still yield its records. A read or decode failure
/// sets `unreadable` and keeps any siblings that did decode. This does not
/// delete the quarantine files.
async fn quarantine_sibling_records(path: &Path, store: RevocationStore) -> QuarantineSiblingLoad {
    let readable_empty = QuarantineSiblingLoad {
        records: RevocationSet::new(),
        unreadable: false,
    };
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return readable_empty;
    };
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return QuarantineSiblingLoad {
            records: RevocationSet::new(),
            unreadable: true,
        };
    };
    let prefix = format!("{name}.quarantined-");
    let mut entries = match fs::read_dir(parent).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return readable_empty,
        Err(_) => {
            return QuarantineSiblingLoad {
                records: RevocationSet::new(),
                unreadable: true,
            };
        }
    };
    let mut records = RevocationSet::new();
    let mut unreadable = false;
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                let file_name = entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    continue;
                };
                if !file_name.starts_with(&prefix) {
                    continue;
                }
                match fs::read(entry.path()).await {
                    Ok(bytes) => match store.decode(&bytes) {
                        Ok(decoded) => unite_revocation_store(store, &mut records, decoded),
                        Err(_) => unreadable = true,
                    },
                    Err(_) => unreadable = true,
                }
            }
            Ok(None) => break,
            Err(_) => {
                unreadable = true;
                break;
            }
        }
    }
    QuarantineSiblingLoad {
        records,
        unreadable,
    }
}

fn unite_revocation_store(
    store: RevocationStore,
    merged: &mut RevocationSet,
    mut extra: RevocationSet,
) {
    match store {
        RevocationStore::V1 | RevocationStore::V2 => {
            for (record, cert) in extra.take_records_where(|_, _| true) {
                let _ = merged.verify_and_insert(record, cert.as_ref());
            }
        }
        RevocationStore::V3 => merged.merge_v3(extra),
    }
}

fn expire_merged_v3(store: RevocationStore, merged: &mut RevocationSet) {
    if !matches!(store, RevocationStore::V3) {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    if now != 0 {
        merged.expire_records_older_than(crate::SHARE_GRANT_REVOCATIONS_TTL_SECS, now);
    }
}

fn decode_revocation_bytes(
    store: RevocationStore,
    bytes: &[u8],
) -> std::result::Result<RevocationSet, DurableWriteError> {
    store
        .decode(bytes)
        .map_err(|error| DurableWriteError::BeforeRename(std::io::Error::other(error.to_string())))
}

fn encode_revocation_store(
    store: RevocationStore,
    merged: &RevocationSet,
) -> std::result::Result<Vec<u8>, DurableWriteError> {
    match store {
        RevocationStore::V1 => merged.to_bytes(),
        RevocationStore::V2 => merged.to_bytes_v2(),
        RevocationStore::V3 => merged.to_bytes_v3(),
    }
    .map_err(|error| DurableWriteError::BeforeRename(std::io::Error::other(error.to_string())))
}

/// Remote rebuild refusal when a quarantine sibling cannot be decoded.
const QUARANTINE_UNREADABLE_REBUILD: &str = "quarantine revocation bytes could not be read";

/// Bytes written by a preserving rebuild.
pub(crate) struct PreservedRevocationWrite {
    /// A live file or a quarantine sibling contributed records.
    pub kept_durable_records: bool,
    /// The bytes now on the live path.
    pub bytes: Vec<u8>,
}

/// Copy `bytes` into the running set.
///
/// v1 and v2 re-verify each record with the certificate the file retained.
/// v3 copies the decoded records. The caller holds the set and decides
/// when the carrier may open.
pub(crate) fn install_preserved_revocations(
    set: &mut RevocationSet,
    store: RevocationStore,
    bytes: &[u8],
) -> std::result::Result<(), DurableWriteError> {
    let mut decoded = decode_revocation_bytes(store, bytes)?;
    match store {
        RevocationStore::V1 | RevocationStore::V2 => {
            for (record, cert) in decoded.take_records_where(|_, _| true) {
                set.verify_and_insert(record, cert.as_ref())
                    .map_err(|error| {
                        DurableWriteError::BeforeRename(std::io::Error::other(error.to_string()))
                    })?;
            }
        }
        RevocationStore::V3 => set.merge_v3(decoded),
    }
    Ok(())
}

/// Write `snapshot` without erasing a revocation that is already durable.
///
/// The caller holds `guard`. A readable live file is decoded and united
/// with `snapshot`. Revocations still readable in a quarantine sibling are
/// united too. The quarantine file stays. When `remote` is set and a
/// quarantine sibling cannot be read, the snapshot is not installed.
/// Bad bytes that are still on the live path are not replaced.
///
/// The `bool` is true when a live file or a quarantine sibling contributed
/// records.
async fn write_union_or_initial_revocation(
    path: &Path,
    store: RevocationStore,
    snapshot: Vec<u8>,
    guard: RevocationWriteGuard,
    remote: bool,
) -> std::result::Result<PreservedRevocationWrite, DurableWriteError> {
    #[cfg(test)]
    pause_rebuild_await_for_testing().await;
    let live = match read_revocation_store_locked(path, store, true).await {
        Ok(bytes) => bytes,
        Err(error) => {
            if fs::metadata(path).await.is_ok() {
                return Err(match error {
                    IdentityError::Storage(io) => DurableWriteError::BeforeRename(io),
                    other => DurableWriteError::BeforeRename(std::io::Error::other(other)),
                });
            }
            None
        }
    };
    let quarantine = quarantine_sibling_records(path, store).await;
    if remote && quarantine.unreadable {
        return Err(DurableWriteError::BeforeRename(std::io::Error::other(
            QUARANTINE_UNREADABLE_REBUILD,
        )));
    }
    let kept_durable_records =
        live.as_ref().is_some_and(|bytes| !bytes.is_empty()) || !quarantine.records.is_empty();
    let bytes = if live.is_none() && quarantine.records.is_empty() {
        snapshot
    } else {
        let mut merged = match live.as_deref() {
            Some(disk) => decode_revocation_bytes(store, disk)?,
            None => RevocationSet::new(),
        };
        unite_revocation_store(
            store,
            &mut merged,
            decode_revocation_bytes(store, &snapshot)?,
        );
        if !quarantine.records.is_empty() {
            unite_revocation_store(store, &mut merged, quarantine.records);
        }
        expire_merged_v3(store, &mut merged);
        encode_revocation_store(store, &merged)?
    };
    let result = write_private_bytes_durable_guarded(path, bytes.clone(), Some(guard)).await;
    if result.is_ok() {
        clear_revocation_block_async(path).await;
    }
    result.map(|()| PreservedRevocationWrite {
        kept_durable_records,
        bytes,
    })
}

/// Rebuild one carrier without dropping a revocation the quarantine file
/// still contains.
///
/// v3 takes the in-process mutex, the OS lock, and the per-path mutex.
/// v1 and v2 take the per-path mutex. Under that lock the live file and
/// every readable quarantine sibling are united with `snapshot`. When
/// `remote` is set and a quarantine sibling cannot be read, `snapshot` is
/// not installed. The returned bytes are the file now on the live path.
pub(crate) async fn rebuild_carrier_preserving_durable(
    path: &Path,
    store: RevocationStore,
    snapshot: Vec<u8>,
    remote: bool,
) -> std::result::Result<PreservedRevocationWrite, DurableWriteError> {
    if matches!(store, RevocationStore::V3) {
        return rebuild_v3_preserving_durable(path, snapshot, remote).await;
    }
    let guard = lock_revocation_path(path).await;
    write_union_or_initial_revocation(path, store, snapshot, guard, remote).await
}

/// Rebuild `revocations-v3.bin` without dropping a newer durable revocation.
///
/// Takes the same locks as the ordinary v3 writer: the in-process mutex,
/// then the OS lock, then the per-path mutex. Under those locks it re-reads
/// the live file and unions it with `snapshot` and with every revocation
/// still readable in the quarantine file. If those quarantine bytes cannot
/// be read and `remote` is set, `snapshot` is not installed. The quarantine
/// file stays.
pub(crate) async fn rebuild_v3_preserving_durable(
    path: &Path,
    snapshot: Vec<u8>,
    remote: bool,
) -> std::result::Result<PreservedRevocationWrite, DurableWriteError> {
    let _in_process = crate::SHARE_GRANT_REVOCATIONS_WRITE_LOCK.lock().await;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .await
            .map_err(DurableWriteError::BeforeRename)?;
    }
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let _cross_process = crate::file_lock::lock_exclusive_with_retry(
        Path::new(&lock_path),
        std::time::Duration::from_millis(20),
        crate::SHARE_GRANT_REVOCATIONS_LOCK_TIMEOUT,
        || {},
    )
    .await
    .map_err(DurableWriteError::BeforeRename)?;
    let guard = lock_revocation_path(path).await;
    write_union_or_initial_revocation(path, RevocationStore::V3, snapshot, guard, remote).await
}

/// What [`install_operator_revocation_carrier`] wrote.
#[derive(Debug)]
pub struct OperatorRevocationWrite {
    /// Live file name, such as `revocations-v3.bin`.
    pub file_name: String,
    /// The installed candidate had no records, and neither the live file nor a readable quarantine file contributed records.
    pub empty_store: bool,
    /// A readable live file or a readable quarantine file was united with the candidate. Its records stayed.
    pub kept_durable_records: bool,
}

/// Validate `bytes` and install them as one revocation carrier (#1116).
///
/// This is the operator command. A remote peer cannot call it. An empty
/// candidate is installed only when `confirm_empty` is set. A readable
/// live file is united with the candidate, so a newer durable revocation
/// stays. A readable quarantine file is united too, so the candidate cannot
/// drop a revocation that file still contains. Unreadable quarantine bytes
/// do not block this command. A zero-byte candidate is rejected. The
/// quarantine file is not deleted.
///
/// # Errors
/// The carrier name, the bytes, or the durable write failed. An empty
/// candidate without `confirm_empty` is an error.
pub async fn install_operator_revocation_carrier(
    identity_dir: &Path,
    carrier: &str,
    bytes: Vec<u8>,
    confirm_empty: bool,
) -> Result<OperatorRevocationWrite> {
    let (file_name, store) = match carrier {
        "v1" => ("revocations.bin", RevocationStore::V1),
        "v2" => ("revocations-v2.bin", RevocationStore::V2),
        "v3" => ("revocations-v3.bin", RevocationStore::V3),
        _ => {
            return Err(IdentityError::Serialization(
                "carrier must be v1, v2, or v3".to_string(),
            ));
        }
    };
    if bytes.is_empty() || store.validate(&bytes).is_err() {
        return Err(IdentityError::Serialization(
            "revocation file did not validate".to_string(),
        ));
    }
    let decoded = store.decode(&bytes)?;
    if decoded.is_empty() && !confirm_empty {
        return Err(IdentityError::Serialization(
            "an empty revocation store needs --confirm-empty".to_string(),
        ));
    }
    let path = identity_dir.join(file_name);
    let preserved = rebuild_carrier_preserving_durable(&path, store, bytes, false)
        .await
        .map_err(durable_write_identity_error)?;
    Ok(OperatorRevocationWrite {
        file_name: file_name.to_string(),
        empty_store: decoded.is_empty() && !preserved.kept_durable_records,
        kept_durable_records: preserved.kept_durable_records,
    })
}

pub(crate) async fn write_revocation_bytes_durable(
    bytes: Vec<u8>,
    guard: RevocationWriteGuard,
) -> Result<()> {
    let path = guard.path.clone();
    write_private_bytes_durable_guarded(&path, bytes, Some(guard))
        .await
        .map_err(durable_write_identity_error)
}

/// The revocation-store guard runs before any byte is written, so its
/// refusal is a [`DurableWriteError::BeforeRename`]. The `io::Error` is
/// moved, not re-wrapped: its [`RevocationPersistenceBlocked`] source
/// stays in place for [`revocation_persistence_is_blocked`].
fn guard_refusal_before_rename(error: IdentityError) -> DurableWriteError {
    match error {
        IdentityError::Storage(io) => DurableWriteError::BeforeRename(io),
        other => DurableWriteError::BeforeRename(std::io::Error::other(other)),
    }
}

/// The untyped writers' historical error: `IdentityError::Storage` with
/// the original `io::Error` (and its source) for either half.
fn durable_write_identity_error(error: DurableWriteError) -> IdentityError {
    match error {
        DurableWriteError::BeforeRename(io) | DurableWriteError::AfterRename(io) => {
            IdentityError::Storage(io)
        }
    }
}

async fn write_private_bytes_durable_guarded(
    path: &Path,
    bytes: Vec<u8>,
    _revocation_guard: Option<RevocationWriteGuard>,
) -> std::result::Result<(), DurableWriteError> {
    use tokio::io::AsyncWriteExt;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .await
        .map_err(DurableWriteError::BeforeRename)?;

    let file_name = path.file_name().ok_or_else(|| {
        DurableWriteError::BeforeRename(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid path: missing file name",
        ))
    })?;
    let unique = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        unique
    ));

    let mut file = fs::File::create(&tmp_path)
        .await
        .map_err(DurableWriteError::BeforeRename)?;
    if let Err(err) = file.write_all(&bytes).await {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(DurableWriteError::BeforeRename(err));
    }
    // Durable point 1: the journal bytes reach stable storage BEFORE the
    // rename makes them visible.
    if let Err(err) = file.sync_all().await {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(DurableWriteError::BeforeRename(err));
    }
    drop(file);

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&tmp_path)
            .await
            .map_err(DurableWriteError::BeforeRename)?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&tmp_path, perms)
            .await
            .map_err(DurableWriteError::BeforeRename)?;
    }

    #[cfg(test)]
    if fails_durable_before_rename_for_testing(path) {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(DurableWriteError::BeforeRename(std::io::Error::other(
            "injected durable failure before rename (test seam)",
        )));
    }

    if let Err(err) = fs::rename(&tmp_path, path).await {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(DurableWriteError::BeforeRename(err));
    }

    // Everything below runs with the NEW bytes already visible on disk.
    sync_published_file(path).await
}

/// Fsync a file that is already visible, then fsync its parent directory.
///
/// The quarantine retry uses this before it removes the live file. A power
/// loss after the rename, and before this returns, can still drop the name.
/// [`DurableWriteError::AfterRename`] means the bytes are visible and the
/// caller must not treat the name as durable.
async fn sync_published_file(path: &Path) -> std::result::Result<(), DurableWriteError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file = fs::File::open(path)
        .await
        .map_err(DurableWriteError::AfterRename)?;
    file.sync_all()
        .await
        .map_err(DurableWriteError::AfterRename)?;
    drop(file);

    // Test seam (issue #1101): fail the parent-directory fsync here for
    // the armed path only, so PostRename callers can be exercised
    // without a real fsync fault and without breaking concurrent
    // durable writes to other paths in the same test process.
    #[cfg(test)]
    if fails_parent_dir_fsync_for_testing(path) {
        if corrupts_after_rename_for_testing(path) {
            let _ = fs::write(path, b"not-a-revocation-file").await;
        }
        return Err(DurableWriteError::AfterRename(std::io::Error::other(
            "injected parent-directory fsync failure (test seam)",
        )));
    }

    // Durable point 2: the rename itself survives power loss.
    let dir = fs::File::open(parent)
        .await
        .map_err(DurableWriteError::AfterRename)?;
    dir.sync_all()
        .await
        .map_err(DurableWriteError::AfterRename)?;
    Ok(())
}

/// Write arbitrary secret bytes to `path` with the same protection x0x gives
/// key material: an atomic write (temp file + rename) with Unix mode `0600`.
///
/// Used to persist TreeKEM group snapshots at rest (ADR-0012 §6 / Phase 4) —
/// they contain private key material and are no more sensitive than
/// `machine.key` / `agent.key` / `agent_kem.key`, which use this same model.
/// At-rest encryption of the whole identity dir is tracked separately
/// (ADR-0012 open question #4).
///
/// # Errors
/// Returns an error if the directory cannot be created or the write/rename
/// fails.
pub async fn write_private_bytes(path: &Path, bytes: Vec<u8>) -> Result<()> {
    write_private_file(path, bytes).await
}

/// Pure resolution core for [`x0x_home_dir`] (issue #456): the default x0x
/// identity directory is `$X0X_HOME` when set, else `<home>/.x0x`.
///
/// Split out so tests can exercise precedence without racing the process
/// environment (unit tests run multi-threaded; `std::env::set_var` is
/// process-global).
#[must_use]
pub fn resolve_x0x_home(
    env_override: Option<&str>,
    home: Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    let overridden = env_override
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    overridden.or_else(|| home.map(|h| h.join(X0X_DIR)))
}

/// The process-wide default x0x identity directory (issue #456).
///
/// Every `~/.x0x` fallback in the codebase resolves through here:
/// - precedence: `$X0X_HOME` (if set and non-empty) > `$HOME/.x0x`;
/// - the test harness sets `X0X_HOME` (`.config/nextest.toml` wrapper), so
///   the workspace suite never writes Home-Suite state (owner-cert journal,
///   `agent.cert`, move/placement files, history, contacts) into a
///   developer's real `~/.x0x`;
/// - in UNIT-TEST builds only (`#[cfg(test)]`, compiled out of every
///   shipped target — review r4: the production resolver must never
///   panic), a test reaching the real-home fallback without an override
///   PANICS by design: that is exactly the #456 pollution bug, so it
///   fails loudly instead of silently dirtying the maintainer's node.
///   Integration binaries are covered by the harness env (the wrapper
///   sets `X0X_HOME` for every test process, so their fallbacks redirect
///   rather than reach the real home).
///
/// # Panics
/// In `#[cfg(test)]` builds when no override is active — never in debug
/// or release binaries shipped to users.
pub fn x0x_home_dir() -> Option<std::path::PathBuf> {
    let env_override = std::env::var("X0X_HOME").ok();
    if env_override.as_deref().is_some_and(|s| !s.is_empty()) {
        return env_override.map(std::path::PathBuf::from);
    }
    #[cfg(test)]
    {
        panic!(
            "#456 test-home guard: a test reached the real ~/.x0x fallback. \
             Set X0X_HOME (the nextest harness does), or give the builder \
             explicit paths (identity_dir / key / cert / store paths)."
        );
    }
    #[cfg(not(test))]
    {
        let home = dirs::home_dir();
        resolve_x0x_home(None, home)
    }
}

/// The identity directory of a NAMED daemon instance (issue #456): a
/// sibling of the default x0x home named `.x0x-<name>`. With `X0X_HOME`
/// set, instances live beside the override's parent — the same "instances
/// sit next to the default dir" rule as `~/.x0x-<name>` on a real home.
#[must_use]
pub fn resolve_x0x_instance_dir(
    home: Option<std::path::PathBuf>,
    name: &str,
) -> Option<std::path::PathBuf> {
    let home = home?;
    let parent = home.parent().map(std::path::Path::to_path_buf)?;
    Some(parent.join(format!(".x0x-{name}")))
}

/// See [`resolve_x0x_instance_dir`]; resolves the default home first.
#[must_use]
pub fn x0x_instance_dir(name: &str) -> Option<std::path::PathBuf> {
    resolve_x0x_instance_dir(x0x_home_dir(), name)
}

/// Get the x0x configuration directory path.
///
/// Honours `X0X_HOME` (issue #456) via [`x0x_home_dir`].
///
/// # Returns
///
/// The path to the .x0x directory (default identity directory)
pub(crate) async fn x0x_dir() -> Result<std::path::PathBuf> {
    x0x_home_dir().ok_or_else(|| {
        IdentityError::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no home directory and no X0X_HOME override",
        ))
    })
}

/// Save a MachineKeypair to the default storage location.
///
/// Stores the keypair in ~/.x0x/machine.key with appropriate
/// file permissions. The directory will be created if it doesn't exist.
///
/// # Arguments
///
/// * `kp` - The MachineKeypair to save
///
/// # Returns
///
/// Ok(()) on success, or an error if the operation fails
pub async fn save_machine_keypair(kp: &MachineKeypair) -> Result<()> {
    let dir = x0x_dir().await?;
    let path = dir.join(MACHINE_KEY_FILE);
    let bytes = serialize_machine_keypair(kp)?;
    write_private_file(&path, bytes).await
}

/// Load a MachineKeypair from the default storage location.
///
/// # Returns
///
/// The loaded MachineKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_machine_keypair() -> Result<MachineKeypair> {
    let path = x0x_dir().await?.join(MACHINE_KEY_FILE);
    let bytes = fs::read(&path).await.map_err(IdentityError::from)?;
    deserialize_machine_keypair(&bytes)
}

/// Check if a machine keypair exists in the default storage location.
///
/// # Returns
///
/// true if the machine key file exists, false otherwise
pub async fn machine_keypair_exists() -> bool {
    let Ok(path) = x0x_dir().await else {
        return false;
    };
    fs::try_exists(path.join(MACHINE_KEY_FILE))
        .await
        .unwrap_or(false)
}

/// Save an AgentKeypair to the specified file path.
///
/// # Arguments
///
/// * `kp` - The AgentKeypair to save
/// * `path` - The file path to save to
///
/// # Returns
///
/// Ok(()) on success, or an error if the operation fails
pub async fn save_agent_keypair<P: AsRef<Path>>(kp: &AgentKeypair, path: P) -> Result<()> {
    let bytes = serialize_agent_keypair(kp)?;
    write_private_file(path.as_ref(), bytes).await
}

/// Save a MachineKeypair to the specified file path.
///
/// Creates the parent directory if it doesn't exist.
///
/// # Arguments
///
/// * `kp` - The MachineKeypair to save
/// * `path` - The file path to save to
///
/// # Returns
///
/// `Ok(())` on success, or an error if file I/O fails
pub async fn save_machine_keypair_to<P: AsRef<Path> + Clone>(
    kp: &MachineKeypair,
    path: P,
) -> Result<()> {
    let bytes = serialize_machine_keypair(kp)?;
    write_private_file(path.as_ref(), bytes).await
}

/// Load a MachineKeypair from the specified file path.
///
/// # Arguments
///
/// * `path` - The file path to load from
///
/// # Returns
///
/// The loaded MachineKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_machine_keypair_from<P: AsRef<Path>>(path: P) -> Result<MachineKeypair> {
    let bytes = fs::read(path).await.map_err(IdentityError::from)?;
    deserialize_machine_keypair(&bytes)
}

/// Load an AgentKeypair from the specified file path.
///
/// # Arguments
///
/// * `path` - The file path to load from
///
/// # Returns
///
/// The loaded AgentKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_agent_keypair<P: AsRef<Path>>(path: P) -> Result<AgentKeypair> {
    let bytes = fs::read(path).await.map_err(IdentityError::from)?;
    deserialize_agent_keypair(&bytes)
}

/// Save an AgentKeypair to the default storage location.
///
/// Stores the keypair in `~/.x0x/agent.key` with appropriate
/// file permissions. The directory will be created if it doesn't exist.
///
/// # Arguments
///
/// * `kp` - The AgentKeypair to save
///
/// # Returns
///
/// `Ok(())` on success, or an error if the operation fails
pub async fn save_agent_keypair_default(kp: &AgentKeypair) -> Result<()> {
    let dir = x0x_dir().await?;
    let path = dir.join(AGENT_KEY_FILE);
    let bytes = serialize_agent_keypair(kp)?;
    write_private_file(&path, bytes).await
}

/// Load an AgentKeypair from the default storage location.
///
/// # Returns
///
/// The loaded AgentKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_agent_keypair_default() -> Result<AgentKeypair> {
    let path = x0x_dir().await?.join(AGENT_KEY_FILE);
    let bytes = fs::read(&path).await.map_err(IdentityError::from)?;
    deserialize_agent_keypair(&bytes)
}

/// Check if an agent keypair exists in the default storage location.
///
/// # Returns
///
/// true if the agent key file exists, false otherwise
pub async fn agent_keypair_exists() -> bool {
    let Ok(path) = x0x_dir().await else {
        return false;
    };
    fs::try_exists(path.join(AGENT_KEY_FILE))
        .await
        .unwrap_or(false)
}

/// Save an AgentKeypair to the specified file path.
///
/// Creates the parent directory if it doesn't exist. Sets file
/// permissions to 0o600 on Unix systems.
///
/// # Arguments
///
/// * `kp` - The AgentKeypair to save
/// * `path` - The file path to save to
///
/// # Returns
///
/// `Ok(())` on success, or an error if file I/O fails
pub async fn save_agent_keypair_to<P: AsRef<Path> + Clone>(
    kp: &AgentKeypair,
    path: P,
) -> Result<()> {
    let bytes = serialize_agent_keypair(kp)?;
    write_private_file(path.as_ref(), bytes).await
}

/// Load an AgentKeypair from the specified file path.
///
/// # Arguments
///
/// * `path` - The file path to load from
///
/// # Returns
///
/// The loaded AgentKeypair, or an error if the file doesn't exist or is invalid
pub async fn load_agent_keypair_from<P: AsRef<Path>>(path: P) -> Result<AgentKeypair> {
    let bytes = fs::read(path).await.map_err(IdentityError::from)?;
    deserialize_agent_keypair(&bytes)
}

// ── UserKeypair storage ──

/// Serialize a UserKeypair to bytes for storage.
///
/// # Arguments
///
/// * `kp` - The UserKeypair to serialize
///
/// # Returns
///
/// A vector containing the serialized keypair data
pub fn serialize_user_keypair(kp: &UserKeypair) -> Result<Vec<u8>> {
    encode_keypair_bytes(
        kp.public_key().as_bytes().to_vec(),
        kp.secret_key().as_bytes().to_vec(),
        None,
    )
}

/// Deserialize a UserKeypair from bytes.
///
/// # Arguments
///
/// * `bytes` - The serialized keypair data
///
/// # Returns
///
/// A deserialized UserKeypair
pub fn deserialize_user_keypair(bytes: &[u8]) -> Result<UserKeypair> {
    let (public_key, secret_key, _not_after) = decode_keypair_bytes(bytes)?;
    UserKeypair::from_bytes(&public_key, &secret_key)
}

/// Save a UserKeypair to the default storage location (`~/.x0x/user.key`).
///
/// # Arguments
///
/// * `kp` - The UserKeypair to save
pub async fn save_user_keypair(kp: &UserKeypair) -> Result<()> {
    let dir = x0x_dir().await?;
    let path = dir.join(USER_KEY_FILE);
    let bytes = serialize_user_keypair(kp)?;
    write_private_file(&path, bytes).await
}

/// Load a UserKeypair from the default storage location (`~/.x0x/user.key`).
pub async fn load_user_keypair() -> Result<UserKeypair> {
    let path = x0x_dir().await?.join(USER_KEY_FILE);
    let bytes = fs::read(&path).await.map_err(IdentityError::from)?;
    deserialize_user_keypair(&bytes)
}

/// Check if a user keypair exists in the default storage location.
pub async fn user_keypair_exists() -> bool {
    let Ok(path) = x0x_dir().await else {
        return false;
    };
    fs::try_exists(path.join(USER_KEY_FILE))
        .await
        .unwrap_or(false)
}

/// Save a UserKeypair to the specified file path.
///
/// Creates the parent directory if it doesn't exist. Sets file
/// permissions to 0o600 on Unix systems.
pub async fn save_user_keypair_to<P: AsRef<Path> + Clone>(kp: &UserKeypair, path: P) -> Result<()> {
    let bytes = serialize_user_keypair(kp)?;
    write_private_file(path.as_ref(), bytes).await
}

/// Load a UserKeypair from the specified file path.
pub async fn load_user_keypair_from<P: AsRef<Path>>(path: P) -> Result<UserKeypair> {
    let bytes = fs::read(path).await.map_err(IdentityError::from)?;
    deserialize_user_keypair(&bytes)
}

// ── AgentCertificate storage ──

/// Save an AgentCertificate to the default storage location (`~/.x0x/agent.cert`).
pub async fn save_agent_certificate(cert: &AgentCertificate) -> Result<()> {
    let dir = x0x_dir().await?;
    let path = dir.join(AGENT_CERT_FILE);
    let bytes = cert.to_storage_bytes()?;
    write_private_file(&path, bytes).await
}

/// Load an AgentCertificate from the default storage location (`~/.x0x/agent.cert`).
pub async fn load_agent_certificate() -> Result<AgentCertificate> {
    let path = x0x_dir().await?.join(AGENT_CERT_FILE);
    let bytes = fs::read(&path).await.map_err(IdentityError::from)?;
    AgentCertificate::from_storage_bytes(&bytes)
}

/// Check if an agent certificate exists in the default storage location.
pub async fn agent_certificate_exists() -> bool {
    let Ok(path) = x0x_dir().await else {
        return false;
    };
    fs::try_exists(path.join(AGENT_CERT_FILE))
        .await
        .unwrap_or(false)
}

/// Save an AgentCertificate to the specified file path.
pub async fn save_agent_certificate_to<P: AsRef<Path> + Clone>(
    cert: &AgentCertificate,
    path: P,
) -> Result<()> {
    let bytes = cert.to_storage_bytes()?;
    write_private_file(path.as_ref(), bytes).await
}

/// Load an AgentCertificate from the specified file path.
pub async fn load_agent_certificate_from<P: AsRef<Path>>(path: P) -> Result<AgentCertificate> {
    let bytes = fs::read(path).await.map_err(IdentityError::from)?;
    AgentCertificate::from_storage_bytes(&bytes)
}

/// Default path for the revocation set file.
///
/// When `identity_dir` is provided (multi-instance daemons), the file is
/// stored there instead of the global `~/.x0x/` directory.
pub(crate) fn revocation_path(identity_dir: Option<&Path>) -> Option<std::path::PathBuf> {
    match identity_dir {
        Some(dir) => Some(dir.join(REVOCATION_FILE)),
        // Issue #456: honor X0X_HOME (tests relocate this; never the real
        // home under the test harness).
        None => x0x_home_dir().map(|dir| dir.join(REVOCATION_FILE)),
    }
}

/// Each store keeps its existing decoder and load acceptance rules.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RevocationStore {
    V1,
    V2,
    V3,
}

impl RevocationStore {
    fn name(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::V3 => "v3",
        }
    }

    fn carrier_bit(self) -> u8 {
        match self {
            Self::V1 => crate::revocation::REVOCATION_CARRIER_V1,
            Self::V2 => crate::revocation::REVOCATION_CARRIER_V2,
            Self::V3 => crate::revocation::REVOCATION_CARRIER_V3,
        }
    }

    fn at_path(path: &Path) -> Option<Self> {
        match path.file_name()?.to_str()? {
            "revocations.bin" => Some(Self::V1),
            "revocations-v2.bin" => Some(Self::V2),
            "revocations-v3.bin" => Some(Self::V3),
            _ => None,
        }
    }

    fn validate(self, bytes: &[u8]) -> Result<()> {
        let magic = match self {
            Self::V1 => REVOCATIONS_FILE_MAGIC,
            Self::V2 => REVOCATIONS_FILE_MAGIC_V2,
            Self::V3 => REVOCATIONS_FILE_MAGIC_V3,
        };
        RevocationSet::validate_persisted_bytes(bytes, magic)
    }

    fn decode(self, bytes: &[u8]) -> Result<RevocationSet> {
        match self {
            Self::V1 => RevocationSet::from_bytes(bytes),
            Self::V2 => RevocationSet::from_bytes_v2(bytes),
            Self::V3 => RevocationSet::from_bytes_v3(bytes),
        }
    }
}

/// Private typed refusal, retained as the source of IdentityError::Storage.
/// No public error variant or persisted format is added.
#[derive(Debug, thiserror::Error)]
#[error("revocations-{store} persistence blocked at {path}: {error}")]
pub(crate) struct RevocationPersistenceBlocked {
    store: &'static str,
    path: std::path::PathBuf,
    error: String,
}

pub(crate) fn revocation_persistence_is_blocked(error: &IdentityError) -> bool {
    matches!(error, IdentityError::Storage(io) if io.get_ref().is_some_and(|source| source.is::<RevocationPersistenceBlocked>()))
}

#[derive(Default)]
struct RevocationStoreState {
    write_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    unreadable: Option<String>,
    last_persist_warning: Option<std::time::Instant>,
    archive_failed: bool,
}

type RevocationStoreStates = std::collections::HashMap<std::path::PathBuf, RevocationStoreState>;

fn revocation_store_states() -> &'static tokio::sync::Mutex<RevocationStoreStates> {
    static STATES: std::sync::OnceLock<tokio::sync::Mutex<RevocationStoreStates>> =
        std::sync::OnceLock::new();
    STATES.get_or_init(|| tokio::sync::Mutex::new(RevocationStoreStates::new()))
}

/// Caller holds write serialization (and, for v3 merge, the OS file lock).
/// Re-read even a previously blocked store: an operator repair clears the
/// refusal without restart. Missing files permit first-run creation.
async fn read_revocation_store_locked(
    path: &Path,
    store: RevocationStore,
    persist_attempt: bool,
) -> Result<Option<Vec<u8>>> {
    let result = match fs::read(path).await {
        Ok(bytes) if bytes.is_empty() => {
            archive_corrupt_revocation_bytes(path, &bytes, persist_attempt).await;
            Err(IdentityError::Serialization(
                "revocation store is empty".to_string(),
            ))
        }
        Ok(bytes) => match store.validate(&bytes) {
            Ok(()) => Ok(Some(bytes)),
            Err(error) => {
                archive_corrupt_revocation_bytes(path, &bytes, persist_attempt).await;
                Err(error)
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if quarantine_sibling_exists(path).await {
                // The bad bytes already live under a quarantine name. Do not
                // read them again. Membership stays closed until resync.
                if !persist_attempt {
                    tracing::error!(
                        path = %path.display(),
                        "{}",
                        crate::revocation::REVOCATION_RESYNC_STATUS
                    );
                }
                Err(IdentityError::Serialization(
                    "revocation store was quarantined".to_string(),
                ))
            } else {
                Ok(None)
            }
        }
        Err(e) => Err(IdentityError::Storage(e)),
    };
    let mut states = revocation_store_states().lock().await;
    let state = states.entry(path.to_path_buf()).or_default();
    match result {
        Ok(set) => {
            state.unreadable = None;
            state.last_persist_warning = None;
            Ok(set)
        }
        Err(e) => {
            state.unreadable = Some(e.to_string());
            // Startup warnings must not consume the first persist-attempt
            // window. Repeated persists warn at most once every 30 seconds.
            let now = std::time::Instant::now();
            if !persist_attempt
                || state.last_persist_warning.is_none_or(|last| {
                    now.duration_since(last) >= std::time::Duration::from_secs(30)
                })
            {
                tracing::warn!(
                    store = store.name(),
                    path = %path.display(),
                    error = %e,
                    persistence_blocked = true,
                    "revocation store unreadable; persistence refused until repaired"
                );
                if persist_attempt {
                    state.last_persist_warning = Some(now);
                }
            }
            Err(IdentityError::Storage(std::io::Error::other(
                RevocationPersistenceBlocked {
                    store: store.name(),
                    path: path.to_path_buf(),
                    error: state.unreadable.clone().unwrap_or_default(),
                },
            )))
        }
    }
}

/// Serialization is per store path. The global map mutex only protects
/// warning state/lock lookup, never disk I/O or record signature checks.
pub(crate) struct RevocationWriteGuard {
    path: std::path::PathBuf,
    _lock: tokio::sync::OwnedMutexGuard<()>,
}

async fn lock_revocation_path(path: &Path) -> RevocationWriteGuard {
    // Path spelling is stable: all in-process revocation writers derive
    // these filenames from the same identity_dir (or x0x_home_dir fallback).
    // They do not independently resolve relative paths or symlink aliases,
    // so load, probe and persist share this key, even before the file exists.
    let lock = {
        let mut states = revocation_store_states().lock().await;
        std::sync::Arc::clone(&states.entry(path.to_path_buf()).or_default().write_lock)
    };
    RevocationWriteGuard {
        path: path.to_path_buf(),
        _lock: lock.lock_owned().await,
    }
}

/// Load one revocation file.
///
/// A missing file with no quarantine sibling is `Ok(None)`. A file that
/// exists but cannot be decoded is moved to
/// `<name>.quarantined-<timestamp>` and returned as `Ok(Some)` of an empty
/// set whose membership stays closed until that carrier is resynced
/// (#1116). The next start sees the quarantine name, does not read those
/// bytes, and stays closed. x0xd keeps running.
pub(crate) async fn read_revocation_store(
    path: &Path,
    store: RevocationStore,
    persist_attempt: bool,
) -> Result<Option<RevocationSet>> {
    let bytes = {
        let _guard = lock_revocation_path(path).await;
        match read_revocation_store_locked(path, store, persist_attempt).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(Some(quarantined_load(
                    store.carrier_bit(),
                    archive_failed(path).await,
                )));
            }
        }
    };
    let Some(raw) = bytes else {
        return Ok(None);
    };
    match store.decode(&raw) {
        Ok(set) => Ok(Some(set)),
        Err(error) => {
            // Structural validation passed and cleared the block. The
            // authority decoder then rejected the same bytes. Move them
            // off the live path and restore the block so a writer cannot
            // replace the store with an empty set.
            archive_corrupt_revocation_bytes(path, &raw, persist_attempt).await;
            remember_unreadable_store(path, error.to_string()).await;
            Ok(Some(quarantined_load(
                store.carrier_bit(),
                archive_failed(path).await,
            )))
        }
    }
}

/// True when `<name>.quarantined-<timestamp>` is already beside `path`.
///
/// This looks at file names only. It does not read the quarantined bytes.
async fn quarantine_sibling_exists(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let prefix = format!("{name}.quarantined-");
    let Ok(mut entries) = fs::read_dir(parent).await else {
        return false;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if file_name.starts_with(&prefix) {
            return true;
        }
    }
    false
}

#[cfg(test)]
fn fails_revocation_archive_for_testing(path: &Path) -> bool {
    FAIL_REVOCATION_ARCHIVE_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|armed| armed == path)
}

#[cfg(test)]
static FAIL_REVOCATION_ARCHIVE_FOR_TESTING: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

/// Arm archive failure for `path` until the guard drops.
#[cfg(test)]
pub(crate) struct FailRevocationArchiveGuard {
    path: std::path::PathBuf,
}

#[cfg(test)]
pub(crate) fn arm_fail_revocation_archive_for_testing(path: &Path) -> FailRevocationArchiveGuard {
    FAIL_REVOCATION_ARCHIVE_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(path.to_path_buf());
    FailRevocationArchiveGuard {
        path: path.to_path_buf(),
    }
}

#[cfg(test)]
impl Drop for FailRevocationArchiveGuard {
    fn drop(&mut self) {
        let mut armed = FAIL_REVOCATION_ARCHIVE_FOR_TESTING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(idx) = armed.iter().position(|candidate| *candidate == self.path) {
            armed.swap_remove(idx);
        }
    }
}

/// Move the live file onto its quarantine name.
///
/// A test can force this rename to fail so the copy fallback runs while the
/// live file is still present.
async fn rename_onto_quarantine(path: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if fails_quarantine_rename_for_testing(path) {
        return Err(std::io::Error::other("injected quarantine rename failure"));
    }
    fs::rename(path, dest).await
}

#[cfg(test)]
static FAIL_QUARANTINE_RENAME_FOR_TESTING: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
struct FailQuarantineRenameGuard {
    path: std::path::PathBuf,
}

#[cfg(test)]
fn arm_fail_quarantine_rename_for_testing(path: &Path) -> FailQuarantineRenameGuard {
    FAIL_QUARANTINE_RENAME_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(path.to_path_buf());
    FailQuarantineRenameGuard {
        path: path.to_path_buf(),
    }
}

#[cfg(test)]
fn fails_quarantine_rename_for_testing(path: &Path) -> bool {
    FAIL_QUARANTINE_RENAME_FOR_TESTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|armed| armed == path)
}

#[cfg(test)]
impl Drop for FailQuarantineRenameGuard {
    fn drop(&mut self) {
        let mut armed = FAIL_QUARANTINE_RENAME_FOR_TESTING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(idx) = armed.iter().position(|candidate| *candidate == self.path) {
            armed.swap_remove(idx);
        }
    }
}

/// Move corrupt revocation bytes to `<name>.quarantined-<unix-ms>`.
///
/// Returns whether the live path no longer holds the payload. An existing
/// quarantine file with the same bytes is kept and the live path is removed.
/// When that rename fails, the bytes are published with the durable private
/// write before the live path is removed. That write fsyncs the file and
/// the parent directory. It does not take the revocation-store guard, so
/// this archive does not call itself. The public durable writer and
/// `write_private_file` do take that guard and would recurse. A failure
/// before the publish leaves the quarantine name unchanged and the live
/// file in place. A later attempt that finds the same bytes syncs that
/// file and its directory again before it removes the live file. If that
/// sync fails, the live file and the failure flag stay. Startup
/// (`persist_attempt == false`) logs the operator message. A failed archive
/// logs that the bytes are still on the live path.
async fn archive_corrupt_revocation_bytes(
    path: &Path,
    bytes: &[u8],
    persist_attempt: bool,
) -> bool {
    #[cfg(test)]
    if fails_revocation_archive_for_testing(path) {
        note_archive_failed(path).await;
        if !persist_attempt {
            tracing::error!(
                path = %path.display(),
                "{}",
                crate::revocation::REVOCATION_ARCHIVE_FAILED
            );
        }
        return false;
    }
    let Some(parent) = path.parent() else {
        note_archive_failed(path).await;
        return false;
    };
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        note_archive_failed(path).await;
        return false;
    };
    let prefix = format!("{name}.quarantined-");
    let mut existing = None;
    if let Ok(mut entries) = fs::read_dir(parent).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            if !file_name.starts_with(&prefix) {
                continue;
            }
            if fs::read(entry.path()).await.ok().as_deref() == Some(bytes) {
                existing = Some(entry.path());
                break;
            }
        }
    }
    let quarantine = if let Some(dest) = existing {
        // The previous attempt may have published these bytes and then
        // failed the directory sync. Prove the name is durable again
        // before removing the live file.
        if let Err(error) = sync_published_file(&dest).await {
            tracing::error!(
                path = %path.display(),
                quarantine = %dest.display(),
                error = %error,
                "{}",
                crate::revocation::REVOCATION_ARCHIVE_FAILED
            );
            note_archive_failed(path).await;
            return false;
        }
        if let Err(error) = fs::remove_file(path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::error!(
                    path = %path.display(),
                    error = %error,
                    "{}",
                    crate::revocation::REVOCATION_ARCHIVE_FAILED
                );
                note_archive_failed(path).await;
                return false;
            }
        }
        dest
    } else {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0);
        let mut dest = parent.join(format!("{prefix}{millis}"));
        let mut seq = 0u32;
        while fs::try_exists(&dest).await.unwrap_or(false) {
            seq = seq.saturating_add(1);
            dest = parent.join(format!("{prefix}{millis}-{seq}"));
        }
        if let Err(rename_error) = rename_onto_quarantine(path, &dest).await {
            // Publish the full bytes, and fsync them, before the live file
            // is removed. A failure before that publish leaves `dest` absent.
            if let Err(error) =
                write_private_bytes_durable_guarded(&dest, bytes.to_vec(), None).await
            {
                tracing::error!(
                    path = %path.display(),
                    rename_error = %rename_error,
                    error = %error,
                    "{}",
                    crate::revocation::REVOCATION_ARCHIVE_FAILED
                );
                note_archive_failed(path).await;
                return false;
            }
            if let Err(error) = fs::remove_file(path).await {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::error!(
                        path = %path.display(),
                        error = %error,
                        "{}",
                        crate::revocation::REVOCATION_ARCHIVE_FAILED
                    );
                    note_archive_failed(path).await;
                    return false;
                }
            }
        }
        dest
    };
    clear_archive_failed(path).await;
    if !persist_attempt {
        tracing::error!(
            path = %path.display(),
            quarantine = %quarantine.display(),
            "{}",
            crate::revocation::REVOCATION_RESYNC_STATUS
        );
    }
    true
}

async fn note_archive_failed(path: &Path) {
    let mut states = revocation_store_states().lock().await;
    states.entry(path.to_path_buf()).or_default().archive_failed = true;
}

async fn clear_archive_failed(path: &Path) {
    let mut states = revocation_store_states().lock().await;
    if let Some(state) = states.get_mut(path) {
        state.archive_failed = false;
    }
}

fn quarantined_load(carrier: u8, archive_failed: bool) -> RevocationSet {
    let mut set = RevocationSet::quarantined_carrier(carrier);
    if archive_failed {
        set.note_archive_failed();
    }
    set
}

async fn archive_failed(path: &Path) -> bool {
    revocation_store_states()
        .lock()
        .await
        .get(path)
        .is_some_and(|state| state.archive_failed)
}

/// Record a decode failure after structural validation cleared the block.
async fn remember_unreadable_store(path: &Path, error: String) {
    let mut states = revocation_store_states().lock().await;
    let state = states.entry(path.to_path_buf()).or_default();
    state.unreadable = Some(error);
    tracing::warn!(
        path = %path.display(),
        persistence_blocked = true,
        "revocation store failed to decode; gates fail closed and persistence stays refused"
    );
}

/// V3 merge keeps this guard through the final durable write, and reads
/// only once under its OS lock. Signature verification happens without
/// holding the global bookkeeping mutex.
pub(crate) async fn read_revocation_store_for_write(
    path: &Path,
    store: RevocationStore,
) -> Result<(Option<RevocationSet>, RevocationWriteGuard)> {
    let guard = lock_revocation_path(path).await;
    let bytes = read_revocation_store_locked(path, store, true).await?;
    let set = bytes.map(|bytes| store.decode(&bytes)).transpose()?;
    Ok((set, guard))
}

/// Check an unchanged store for a rate-limited blocked-store warning.
pub(crate) async fn probe_revocation_store(path: &Path, store: RevocationStore) -> Result<()> {
    let _guard = lock_revocation_path(path).await;
    read_revocation_store_locked(path, store, true).await?;
    Ok(())
}

/// Both atomic writers use this guard, covering ordinary, pre-encoded and
/// generic saves. It stays held from structural validation through fsync.
async fn revocation_write_guard(path: &Path) -> Result<Option<RevocationWriteGuard>> {
    let Some(store) = RevocationStore::at_path(path) else {
        return Ok(None);
    };
    let guard = lock_revocation_path(path).await;
    read_revocation_store_locked(path, store, true).await?;
    Ok(Some(guard))
}

/// Load the local v1 revocation set from disk.
///
/// A missing file with no quarantine sibling is an empty set: no
/// revocations are known yet. A file that exists but cannot be read or
/// decoded is moved to a quarantine file. The live path no longer holds
/// those bytes. Membership stays closed until the group resyncs that
/// carrier, including on the next start (#1116). x0xd keeps running. A
/// record that decodes but fails authority verification is still dropped
/// on its own; that does not close membership.
pub async fn load_revocation_set(identity_dir: Option<&Path>) -> RevocationSet {
    let Some(path) = revocation_path(identity_dir) else {
        return RevocationSet::new();
    };
    match read_revocation_store(&path, RevocationStore::V1, false).await {
        Ok(Some(set)) => set,
        Ok(None) | Err(_) => RevocationSet::new(),
    }
}

/// Persist the revocation set to disk.
///
/// Uses the same atomic-rename strategy as other private files so a crash
/// during write never leaves a truncated revocation file.
pub async fn save_revocation_set(set: &RevocationSet, identity_dir: Option<&Path>) -> Result<()> {
    let Some(path) = revocation_path(identity_dir) else {
        return Err(IdentityError::Storage(std::io::Error::other(
            "no home directory and no identity_dir — cannot persist revocations",
        )));
    };
    let bytes = set.to_bytes()?;
    write_private_bytes_durable(&path, bytes).await
}

/// Persist pre-encoded revocation-set bytes to disk (issue #191).
///
/// Companion to [`save_revocation_set`] for the gossip-receive path, which
/// snapshots the live set's [`to_bytes`](RevocationSet::to_bytes) output under
/// a brief read lock and writes it off-lock. This preserves issuer-
/// revocations' authorizing certificates (carried in `PersistedRevocation`)
/// — the previous rebuild re-inserted records with `None` cert and silently
/// dropped every issuer-revocation on save.
pub async fn save_revocation_set_bytes(bytes: Vec<u8>, identity_dir: Option<&Path>) -> Result<()> {
    let Some(path) = revocation_path(identity_dir) else {
        return Err(IdentityError::Storage(std::io::Error::other(
            "no home directory and no identity_dir — cannot persist revocations",
        )));
    };
    write_private_bytes_durable(&path, bytes).await
}

/// Write private bytes to an explicit path (atomic rename, mode 0600 on
/// Unix). ADR-0043 callers persist move-log/bundle/placement/v2 files
/// through this — same guarantees as the revocation set.
///
/// v1 and v2 revocation files also fsync the file and the parent directory,
/// as v3 already does. Other callers keep the rename-only writer.
///
/// # Errors
///
/// Returns [`IdentityError::Storage`] on any filesystem failure.
pub async fn save_private_bytes_to(path: &std::path::Path, bytes: Vec<u8>) -> Result<()> {
    if RevocationStore::at_path(path).is_some() {
        write_private_bytes_durable(path, bytes).await
    } else {
        write_private_file(path, bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AgentKeypair, MachineKeypair};

    async fn quarantine_files(dir: &Path, stem: &str) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let mut entries = fs::read_dir(dir).await.expect("read dir");
        let prefix = format!("{stem}.quarantined-");
        while let Some(entry) = entries.next_entry().await.expect("entry") {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(&prefix) {
                continue;
            }
            let stamp = name[prefix.len()..].split('-').next().unwrap_or("");
            assert!(
                !stamp.is_empty() && stamp.chars().all(|ch| ch.is_ascii_digit()),
                "quarantine name has a timestamp: {name}"
            );
            found.push(entry.path());
        }
        found
    }

    /// The rename fallback must publish the quarantine file whole. A missing
    /// live path forces that copy. The direct write used to leave `dest`
    /// visible before the bytes were complete.
    #[tokio::test]
    async fn fallback_quarantine_copy_publishes_whole_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REVOCATION_FILE);
        let bytes = b"corrupt-bytes-must-land-whole";
        let archived = archive_corrupt_revocation_bytes(&path, bytes, true).await;
        assert!(
            archived,
            "a failed rename still archives when the copy completes"
        );
        assert!(
            fs::read(&path).await.is_err(),
            "the live path does not hold the payload"
        );
        let quarantine = quarantine_files(dir.path(), REVOCATION_FILE).await;
        assert_eq!(quarantine.len(), 1, "one quarantine file");
        assert_eq!(
            std::fs::read(&quarantine[0]).expect("quarantine bytes"),
            bytes,
            "the quarantine file holds the full payload"
        );
        let mut entries = fs::read_dir(dir.path()).await.expect("read dir");
        while let Some(entry) = entries.next_entry().await.expect("entry") {
            let name = entry.file_name();
            assert!(
                !name.to_string_lossy().contains(".tmp"),
                "no temp debris: {}",
                name.to_string_lossy()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&quarantine[0])
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "quarantine copy is private");
        }
    }

    /// An interrupted copy must not publish the quarantine name and must not
    /// remove the live file. The failure is injected before the durable
    /// rename, after the bytes have been written to the temp file.
    #[tokio::test]
    async fn fallback_quarantine_copy_keeps_live_file_when_publish_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REVOCATION_FILE);
        let bytes = b"corrupt-bytes-must-stay-on-the-live-path";
        fs::write(&path, bytes).await.expect("seed live file");
        let _rename = arm_fail_quarantine_rename_for_testing(&path);
        let _publish = arm_fail_durable_before_rename_for_testing(dir.path());
        let archived = archive_corrupt_revocation_bytes(&path, bytes, true).await;
        assert!(
            !archived,
            "a copy that fails before publish must not count as archived"
        );
        assert_eq!(
            fs::read(&path).await.expect("live file remains"),
            bytes,
            "the live file stays until the quarantine copy is durable"
        );
        assert!(
            quarantine_files(dir.path(), REVOCATION_FILE)
                .await
                .is_empty(),
            "the quarantine name is not published"
        );
        let mut entries = fs::read_dir(dir.path()).await.expect("read dir");
        while let Some(entry) = entries.next_entry().await.expect("entry") {
            let name = entry.file_name();
            assert!(
                !name.to_string_lossy().contains(".tmp"),
                "no temp debris: {}",
                name.to_string_lossy()
            );
        }
    }

    /// A directory sync that fails after the quarantine rename must keep the
    /// live file. The next attempt, with that fault still armed, must sync
    /// again and still keep the live file. After the fault clears, the retry
    /// removes the live file.
    #[tokio::test]
    async fn fallback_quarantine_retry_resyncs_before_removing_the_live_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REVOCATION_FILE);
        let bytes = b"corrupt-bytes-need-a-durable-directory-entry";
        fs::write(&path, bytes).await.expect("seed live file");
        let _rename = arm_fail_quarantine_rename_for_testing(&path);
        let sync_fault = arm_fail_parent_dir_fsync_for_testing(dir.path());

        let first = archive_corrupt_revocation_bytes(&path, bytes, true).await;
        assert!(!first, "a failed directory sync must not count as archived");
        assert_eq!(
            fs::read(&path)
                .await
                .expect("live file after first attempt"),
            bytes,
            "the first attempt keeps the live file"
        );
        let quarantine = quarantine_files(dir.path(), REVOCATION_FILE).await;
        assert_eq!(quarantine.len(), 1, "the copy is visible");
        assert_eq!(
            std::fs::read(&quarantine[0]).expect("quarantine bytes"),
            bytes
        );
        assert!(
            archive_failed(&path).await,
            "the first failure stays recorded"
        );

        let second = archive_corrupt_revocation_bytes(&path, bytes, true).await;
        assert!(
            !second,
            "a retry with the directory sync still failing must not succeed"
        );
        assert_eq!(
            fs::read(&path).await.expect("live file after retry"),
            bytes,
            "the retry must not remove the live file"
        );
        assert_eq!(
            quarantine_files(dir.path(), REVOCATION_FILE).await.len(),
            1,
            "the retry does not add another quarantine file"
        );
        assert!(
            archive_failed(&path).await,
            "the failure flag stays set while the sync fault is active"
        );

        drop(sync_fault);
        let third = archive_corrupt_revocation_bytes(&path, bytes, true).await;
        assert!(third, "a retry after the fault clears archives");
        assert!(
            fs::read(&path).await.is_err(),
            "the successful retry removes the live file"
        );
        assert_eq!(
            std::fs::read(&quarantine[0]).expect("quarantine bytes remain"),
            bytes
        );
        assert!(
            !archive_failed(&path).await,
            "the failure flag clears only after the durable retry"
        );
    }

    /// #1116: the operator command validates, rejects an unconfirmed empty
    /// store, and does not delete the quarantine file.
    #[tokio::test]
    async fn operator_rebuild_validates_and_reopens_with_confirm_1116() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("revocations-v3.bin");
        fs::write(&path, b"corrupt-v3").await.unwrap();
        let loaded = read_revocation_store(&path, RevocationStore::V3, false)
            .await
            .unwrap()
            .unwrap();
        assert!(loaded.revocation_resync_required());
        let quarantine = quarantine_files(dir.path(), "revocations-v3.bin").await;
        assert_eq!(quarantine.len(), 1);
        let kept = std::fs::read(&quarantine[0]).unwrap();

        let empty = RevocationSet::new().to_bytes_v3().unwrap();
        assert!(
            install_operator_revocation_carrier(dir.path(), "v3", empty.clone(), false)
                .await
                .is_err(),
            "an empty store needs confirmation"
        );
        assert!(
            install_operator_revocation_carrier(dir.path(), "v3", Vec::new(), true)
                .await
                .is_err(),
            "zero bytes do not validate"
        );
        let still = read_revocation_store(&path, RevocationStore::V3, false)
            .await
            .unwrap()
            .unwrap();
        assert!(still.revocation_resync_required());

        let wrote = install_operator_revocation_carrier(dir.path(), "v3", empty, true)
            .await
            .expect("confirmed empty install");
        assert!(wrote.empty_store);
        assert!(!wrote.kept_durable_records);
        let opened = read_revocation_store(&path, RevocationStore::V3, false)
            .await
            .unwrap()
            .unwrap();
        assert!(!opened.revocation_resync_required());
        assert_eq!(std::fs::read(&quarantine[0]).unwrap(), kept);
        assert!(fs::read(&path).await.unwrap().len() > 1);
    }

    /// #1116 / ADR 0085 rule 4: a fail-closed load must not authorize
    /// overwriting an unreadable v1 file on the next ordinary persist.
    #[tokio::test]
    async fn unreadable_v1_revocations_survive_persist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REVOCATION_FILE);
        let garbage = b"unreadable v1 revocations\x00\xff";
        fs::write(&path, garbage).await.expect("seed garbage");

        let mut set = load_revocation_set(Some(dir.path())).await;
        assert!(set.is_empty(), "undecodable bytes contribute no records");
        assert!(
            set.revocation_resync_required(),
            "a present but undecodable v1 file closes membership"
        );
        let stranger = AgentKeypair::generate().expect("stranger");
        assert!(
            set.member_treated_as_revoked(&stranger.agent_id()),
            "an unknown agent is refused while revocations.bin is unreadable"
        );
        assert!(
            !set.is_agent_revoked(&stranger.agent_id()),
            "the hold is not a revocation record"
        );
        assert!(
            quarantine_files(dir.path(), REVOCATION_FILE)
                .await
                .iter()
                .any(|path| std::fs::read(path).ok().as_deref() == Some(garbage.as_slice())),
            "startup moves the bad v1 bytes to a quarantine file"
        );
        assert_ne!(
            fs::read(&path).await.ok().as_deref(),
            Some(garbage.as_slice()),
            "the live path no longer holds the corrupt payload"
        );
        let issuer = AgentKeypair::generate().expect("issuer key");
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(issuer.agent_id()),
            issuer.public_key(),
            issuer.secret_key(),
            1_000,
            None,
        )
        .expect("sign self-revocation");
        assert!(set.verify_and_insert(record, None).expect("insert"));

        // Persistence stays refused so an empty rewrite cannot re-admit.
        // The live path must still not hold the corrupt payload.
        let refused = save_revocation_set(&set, Some(dir.path()))
            .await
            .expect_err("v1 write refused");
        assert!(revocation_persistence_is_blocked(&refused));
        assert!(set.is_agent_revoked(&issuer.agent_id()));
        assert_ne!(
            fs::read(&path).await.ok().as_deref(),
            Some(garbage.as_slice()),
            "persist must not put the corrupt payload back on the live path"
        );
        let again = load_revocation_set(Some(dir.path())).await;
        assert!(
            again.revocation_resync_required(),
            "the next start stays closed without reading the quarantined payload"
        );
        assert!(again.member_treated_as_revoked(&stranger.agent_id()));
        fs::write(&path, RevocationSet::new().to_bytes().unwrap())
            .await
            .expect("operator repair");
        save_revocation_set(&set, Some(dir.path()))
            .await
            .expect("repair unblocks v1");
        let repaired = load_revocation_set(Some(dir.path())).await;
        assert!(repaired.is_agent_revoked(&issuer.agent_id()));
        assert!(
            !repaired.revocation_resync_required(),
            "a readable file loads without the hold"
        );
        assert!(
            !repaired.member_treated_as_revoked(&stranger.agent_id()),
            "a repaired file does not refuse an unknown agent"
        );
    }

    /// #1116: the next start must not read the quarantined payload, and the
    /// live path must not hold it. Membership stays closed.
    #[tokio::test]
    async fn next_start_leaves_the_live_path_and_does_not_reread_1116() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REVOCATION_FILE);
        let garbage = b"corrupt payload must leave the live path";
        fs::write(&path, garbage).await.expect("seed garbage");
        let stranger = AgentKeypair::generate().expect("stranger");
        let first = load_revocation_set(Some(dir.path())).await;
        assert!(first.revocation_resync_required());
        assert!(first.member_treated_as_revoked(&stranger.agent_id()));
        assert_ne!(
            fs::read(&path).await.ok().as_deref(),
            Some(garbage.as_slice()),
            "the original path is no longer the corrupt payload"
        );
        let quarantined = quarantine_files(dir.path(), REVOCATION_FILE).await;
        assert_eq!(quarantined.len(), 1, "one timestamped quarantine file");
        assert_eq!(std::fs::read(&quarantined[0]).expect("quarantine"), garbage);
        // A decodable replacement must not be loaded. The next start looks
        // at the quarantine name only.
        let readable = RevocationSet::new().to_bytes().expect("empty store");
        fs::write(&quarantined[0], &readable)
            .await
            .expect("replace quarantined payload");
        let second = load_revocation_set(Some(dir.path())).await;
        assert!(
            second.revocation_resync_required(),
            "the next start stays closed without reading the quarantined bytes"
        );
        assert!(second.member_treated_as_revoked(&stranger.agent_id()));
        assert_ne!(
            fs::read(&path).await.ok().as_deref(),
            Some(garbage.as_slice()),
            "the next start does not put the corrupt payload back"
        );
    }

    /// #1116: startup load of a present but undecodable v1, v2 or v3 file
    /// fails the gates closed and moves the payload off the live path. A
    /// missing file does not.
    #[tokio::test]
    async fn corrupt_revocation_files_fail_closed_on_load_1116() {
        use crate::identity::{AgentId, MachineId, UserId};

        let agent = AgentId([0x11; 32]);
        let machine = MachineId([0x22; 32]);
        let grant = [0x33; 32];
        let owner = UserId([0x44; 32]);
        let assert_closed = |set: &RevocationSet, label: &str| {
            assert!(
                set.revocation_resync_required(),
                "{label} closes membership"
            );
            assert!(set.is_empty(), "{label} contributes no records");
            assert!(
                set.member_treated_as_revoked(&agent),
                "{label} refuses an unverified member"
            );
            assert!(
                !set.is_agent_revoked(&agent),
                "{label} writes no revocation record"
            );
            assert!(
                !set.is_share_grant_revoked(&grant, &owner),
                "{label} does not mark share grants revoked"
            );
            assert!(
                !set.is_binding_revoked(&agent, &machine),
                "{label} does not mark bindings revoked"
            );
            assert!(
                set.max_revoked_binding_epoch(&agent).is_none(),
                "{label} does not invent a binding epoch"
            );
        };
        let assert_open = |set: &RevocationSet, label: &str| {
            assert!(!set.revocation_resync_required(), "{label} has no hold");
            assert!(
                !set.member_treated_as_revoked(&agent),
                "{label} accepts a member"
            );
            assert!(
                !set.is_machine_revoked(&machine),
                "{label} accepts a machine"
            );
            assert!(
                !set.is_binding_revoked(&agent, &machine),
                "{label} accepts a binding"
            );
            assert!(
                !set.is_share_grant_revoked(&grant, &owner),
                "{label} accepts a share grant"
            );
        };

        let dir = tempfile::tempdir().expect("tempdir");
        assert_open(
            &load_revocation_set(Some(dir.path())).await,
            "missing files",
        );

        let garbage = b"not a revocation store";
        let names = [
            "revocations.bin",
            "revocations-v2.bin",
            "revocations-v3.bin",
        ];
        for name in names {
            fs::write(dir.path().join(name), garbage)
                .await
                .expect("seed garbage");
        }

        // Same order as daemon startup: v1 load, then v2 merge, then v3 merge.
        let mut set = load_revocation_set(Some(dir.path())).await;
        assert_closed(&set, "corrupt v1");
        let v2 = read_revocation_store(
            &dir.path().join("revocations-v2.bin"),
            RevocationStore::V2,
            false,
        )
        .await
        .expect("v2 load")
        .expect("v2 file exists");
        set.merge_v2(v2);
        let v3 = read_revocation_store(
            &dir.path().join("revocations-v3.bin"),
            RevocationStore::V3,
            false,
        )
        .await
        .expect("v3 load")
        .expect("v3 file exists");
        set.merge_v3(v3);
        assert_closed(&set, "corrupt v1 v2 and v3");
        for name in names {
            assert!(
                quarantine_files(dir.path(), name)
                    .await
                    .iter()
                    .any(|path| std::fs::read(path).ok().as_deref() == Some(garbage.as_slice())),
                "{name} is moved to a timestamped quarantine file"
            );
            assert_ne!(
                fs::read(dir.path().join(name)).await.ok().as_deref(),
                Some(garbage.as_slice()),
                "{name} live path no longer holds the corrupt payload"
            );
        }

        let empty = RevocationSet::new();
        for name in names {
            let path = dir.path().join(name);
            let refused = save_private_bytes_to(&path, empty.to_bytes().expect("encode"))
                .await
                .expect_err("overwrite refused");
            assert!(revocation_persistence_is_blocked(&refused));
            assert_ne!(
                fs::read(&path).await.ok().as_deref(),
                Some(garbage.as_slice()),
                "{name} stays off the live path after a refused write"
            );
        }

        fs::write(
            dir.path().join("revocations.bin"),
            empty.to_bytes().unwrap(),
        )
        .await
        .unwrap();
        fs::write(
            dir.path().join("revocations-v2.bin"),
            empty.to_bytes_v2().unwrap(),
        )
        .await
        .unwrap();
        fs::write(
            dir.path().join("revocations-v3.bin"),
            empty.to_bytes_v3().unwrap(),
        )
        .await
        .unwrap();
        let mut repaired = load_revocation_set(Some(dir.path())).await;
        let v2 = read_revocation_store(
            &dir.path().join("revocations-v2.bin"),
            RevocationStore::V2,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        repaired.merge_v2(v2);
        let v3 = read_revocation_store(
            &dir.path().join("revocations-v3.bin"),
            RevocationStore::V3,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        repaired.merge_v3(v3);
        assert_open(&repaired, "repaired files");

        // One corrupt carrier is enough. A readable sibling does not clear it.
        fs::write(dir.path().join("revocations-v2.bin"), garbage)
            .await
            .unwrap();
        let mut mixed = load_revocation_set(Some(dir.path())).await;
        assert_open(&mixed, "readable v1 before the v2 merge");
        let v2 = read_revocation_store(
            &dir.path().join("revocations-v2.bin"),
            RevocationStore::V2,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        mixed.merge_v2(v2);
        assert_closed(&mixed, "corrupt v2");
        let v3 = read_revocation_store(
            &dir.path().join("revocations-v3.bin"),
            RevocationStore::V3,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        mixed.merge_v3(v3);
        assert_closed(&mixed, "corrupt v2 with a readable v3");
    }

    /// #1116: a present 0-byte file and a truncated valid file are corrupt.
    /// Each is moved off the live path and membership stays closed.
    /// The v2 truncation is a shortened v2 encoding, not a v1 header.
    #[tokio::test]
    async fn zero_byte_and_truncated_revocation_files_fail_closed_1116() {
        let empty = RevocationSet::new();
        let v1 = empty.to_bytes().expect("v1");
        let v2 = empty.to_bytes_v2().expect("v2");
        let v3 = empty.to_bytes_v3().expect("v3");
        assert!(v1.len() > 1 && v2.len() > 1 && v3.len() > 1);
        let cases: [(&str, &[u8]); 6] = [
            ("revocations.bin", &[]),
            ("revocations.bin", &v1[..v1.len() - 1]),
            ("revocations-v2.bin", &[]),
            ("revocations-v2.bin", &v2[..v2.len() - 1]),
            ("revocations-v3.bin", &[]),
            ("revocations-v3.bin", &v3[..v3.len() - 1]),
        ];
        for (name, bytes) in cases {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join(name);
            fs::write(&path, bytes).await.expect("seed");
            let store = match name {
                "revocations.bin" => RevocationStore::V1,
                "revocations-v2.bin" => RevocationStore::V2,
                _ => RevocationStore::V3,
            };
            let loaded = read_revocation_store(&path, store, false)
                .await
                .expect("load")
                .expect("present file");
            assert!(
                loaded.revocation_resync_required(),
                "{name} closes membership"
            );
            assert!(loaded.is_empty(), "{name} contributes no records");
            assert_ne!(
                fs::read(&path).await.ok().as_deref(),
                Some(bytes),
                "{name} no longer holds the bad payload"
            );
            assert!(
                quarantine_files(dir.path(), name)
                    .await
                    .iter()
                    .any(|quarantine| std::fs::read(quarantine).ok().as_deref() == Some(bytes)),
                "{name} quarantine holds the bad payload"
            );
        }
    }

    /// #1116: a failed archive must not claim the bytes were moved.
    #[tokio::test]
    async fn archive_failure_keeps_the_bad_bytes_and_says_so_1116() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REVOCATION_FILE);
        let garbage = b"cannot-archive";
        fs::write(&path, garbage).await.expect("seed");
        let _guard = arm_fail_revocation_archive_for_testing(&path);
        let loaded = read_revocation_store(&path, RevocationStore::V1, false)
            .await
            .expect("load")
            .expect("present");
        assert!(loaded.revocation_resync_required());
        assert_eq!(
            loaded.revocation_status_sentence(),
            crate::revocation::REVOCATION_ARCHIVE_FAILED
        );
        assert_eq!(fs::read(&path).await.expect("live bytes"), garbage);
        assert!(
            quarantine_files(dir.path(), REVOCATION_FILE)
                .await
                .is_empty(),
            "a failed archive leaves no quarantine sibling"
        );
    }

    /// Missing stores are healthy, independent, and may be created by every
    /// writer, including the pre-encoded v1 gossip path and generic v2 path.
    #[tokio::test]
    async fn missing_revocation_stores_allow_first_run_creation_1116() {
        let dir = tempfile::tempdir().unwrap();
        let set = RevocationSet::new();
        assert!(load_revocation_set(Some(dir.path())).await.is_empty());
        save_revocation_set(&set, Some(dir.path())).await.unwrap();
        assert!(RevocationSet::from_bytes(
            &fs::read(dir.path().join(REVOCATION_FILE)).await.unwrap()
        )
        .is_ok());
        fs::remove_file(dir.path().join(REVOCATION_FILE))
            .await
            .unwrap();
        save_revocation_set_bytes(set.to_bytes().unwrap(), Some(dir.path()))
            .await
            .unwrap();

        // A blocked v1 must not prevent first-run v2/v3 creation.
        fs::write(dir.path().join(REVOCATION_FILE), b"garbage")
            .await
            .unwrap();
        assert!(save_revocation_set(&set, Some(dir.path())).await.is_err());
        let v2 = dir.path().join("revocations-v2.bin");
        save_private_bytes_to(&v2, set.to_bytes_v2().unwrap())
            .await
            .unwrap();
        assert!(RevocationSet::from_bytes_v2(&fs::read(v2).await.unwrap()).is_ok());
        let v3 = dir.path().join("revocations-v3.bin");
        crate::persist_share_grant_revocations_durable(
            &tokio::sync::RwLock::new(set),
            Some(dir.path()),
        )
        .await
        .unwrap();
        assert!(RevocationSet::from_bytes_v3(&fs::read(v3).await.unwrap()).is_ok());
    }

    /// Re-validation is required even when startup read healthy bytes.
    /// Both raw writers must guard every store, and the pre-encoded v1
    /// gossip writer must not bypass the ordinary save's refusal.
    #[tokio::test]
    async fn all_revocation_writers_refuse_post_load_corruption_1116() {
        let dir = tempfile::tempdir().unwrap();
        let set = RevocationSet::new();
        for (name, store, bytes) in [
            (
                "revocations.bin",
                RevocationStore::V1,
                set.to_bytes().unwrap(),
            ),
            (
                "revocations-v2.bin",
                RevocationStore::V2,
                set.to_bytes_v2().unwrap(),
            ),
            (
                "revocations-v3.bin",
                RevocationStore::V3,
                set.to_bytes_v3().unwrap(),
            ),
        ] {
            let path = dir.path().join(name);
            fs::write(&path, &bytes).await.unwrap();
            assert!(read_revocation_store(&path, store, false)
                .await
                .unwrap()
                .is_some());
            fs::write(&path, b"corruption after load").await.unwrap();
            let err = save_private_bytes_to(&path, bytes.clone())
                .await
                .unwrap_err();
            assert!(revocation_persistence_is_blocked(&err));
            let err = write_private_bytes_durable(&path, bytes.clone())
                .await
                .unwrap_err();
            assert!(revocation_persistence_is_blocked(&err));
            // #1101: the typed writer refuses BEFORE the rename (the
            // guard runs before any byte is written), and the blocked
            // source survives the typed error and the mapping back.
            let err = write_private_bytes_durable_typed(&path, bytes.clone())
                .await
                .unwrap_err();
            assert!(!err.crossed_rename(), "guard refusal is BeforeRename");
            assert!(revocation_persistence_is_blocked(
                &durable_write_identity_error(err)
            ));
            if matches!(store, RevocationStore::V1) {
                let err = save_revocation_set_bytes(bytes.clone(), Some(dir.path()))
                    .await
                    .unwrap_err();
                assert!(revocation_persistence_is_blocked(&err));
            }
            assert_ne!(
                fs::read(&path).await.ok().as_deref(),
                Some(b"corruption after load".as_slice()),
                "{name} live path no longer holds the corrupt payload"
            );
            fs::write(&path, &bytes).await.unwrap();
            save_private_bytes_to(&path, bytes.clone()).await.unwrap();
            write_private_bytes_durable(&path, bytes.clone())
                .await
                .unwrap();
            write_private_bytes_durable_typed(&path, bytes)
                .await
                .unwrap();
        }
    }

    /// Read I/O failures are recorded too. Startup does not consume the
    /// first persist warning; retries warn again in each 30-second window.
    #[tokio::test]
    async fn unreadable_store_warning_windows_and_io_errors_1116() {
        let dir = tempfile::tempdir().unwrap();
        for (name, store, bytes) in [
            (
                "revocations.bin",
                RevocationStore::V1,
                RevocationSet::new().to_bytes().unwrap(),
            ),
            (
                "revocations-v2.bin",
                RevocationStore::V2,
                RevocationSet::new().to_bytes_v2().unwrap(),
            ),
            (
                "revocations-v3.bin",
                RevocationStore::V3,
                RevocationSet::new().to_bytes_v3().unwrap(),
            ),
        ] {
            let path = dir.path().join(name);
            fs::create_dir(&path).await.unwrap();
            let loaded = read_revocation_store(&path, store, false)
                .await
                .expect("an unreadable path returns a quarantined set");
            assert!(
                loaded
                    .expect("the path exists")
                    .revocation_resync_required(),
                "{name} io failure closes membership"
            );
            {
                let states = revocation_store_states().lock().await;
                assert!(states[&path].unreadable.is_some());
                assert!(states[&path].last_persist_warning.is_none());
            }
            assert!(save_private_bytes_to(&path, bytes.clone()).await.is_err());
            let first = revocation_store_states().lock().await[&path]
                .last_persist_warning
                .unwrap();
            assert!(save_private_bytes_to(&path, bytes.clone()).await.is_err());
            assert_eq!(
                revocation_store_states().lock().await[&path].last_persist_warning,
                Some(first)
            );
            revocation_store_states()
                .lock()
                .await
                .get_mut(&path)
                .unwrap()
                .last_persist_warning = first.checked_sub(std::time::Duration::from_secs(31));
            assert!(save_private_bytes_to(&path, bytes.clone()).await.is_err());
            assert!(
                revocation_store_states().lock().await[&path]
                    .last_persist_warning
                    .unwrap()
                    >= first
            );
            fs::remove_dir(&path).await.unwrap();
            save_private_bytes_to(&path, bytes).await.unwrap();
            let states = revocation_store_states().lock().await;
            assert!(states[&path].unreadable.is_none());
            assert!(states[&path].last_persist_warning.is_none());
        }
    }

    #[tokio::test]
    async fn test_keypair_serialization_roundtrip() {
        // Test MachineKeypair
        let original = MachineKeypair::generate().unwrap();
        let serialized = serialize_machine_keypair(&original).unwrap();
        let deserialized = deserialize_machine_keypair(&serialized).unwrap();

        assert_eq!(original.machine_id(), deserialized.machine_id());
        assert_eq!(
            original.public_key().as_bytes(),
            deserialized.public_key().as_bytes()
        );

        // Test AgentKeypair
        let original_agent = AgentKeypair::generate().unwrap();
        let serialized_agent = serialize_agent_keypair(&original_agent).unwrap();
        let deserialized_agent = deserialize_agent_keypair(&serialized_agent).unwrap();

        assert_eq!(original_agent.agent_id(), deserialized_agent.agent_id());
        assert_eq!(
            original_agent.public_key().as_bytes(),
            deserialized_agent.public_key().as_bytes()
        );
    }

    #[tokio::test]
    async fn test_save_and_load_machine_keypair() {
        let keypair = MachineKeypair::generate().unwrap();

        // Save to temp file
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test_machine.key");
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        // Load and verify
        let loaded = load_machine_keypair_from_path(&path).await.unwrap();
        assert_eq!(keypair.machine_id(), loaded.machine_id());
    }

    #[tokio::test]
    async fn test_machine_keypair_exists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join(MACHINE_KEY_FILE);

        // Initially should not exist
        assert!(!machine_keypair_exists_in_dir(temp_dir.path()).await);

        // Create a key file
        let keypair = MachineKeypair::generate().unwrap();
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        // Should now exist
        assert!(machine_keypair_exists_in_dir(temp_dir.path()).await);
    }

    #[tokio::test]
    async fn test_invalid_deserialization() {
        // Test with invalid bytes
        let result = deserialize_machine_keypair(&[1u8, 2u8, 3u8]).unwrap_err();
        assert!(matches!(result, IdentityError::Serialization(_)));
    }

    // ── File permission tests (Unix only) ─────────────────────────────

    #[cfg(unix)]
    #[tokio::test]
    async fn test_key_file_has_restrictive_permissions() {
        let keypair = MachineKeypair::generate().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test_machine.key");
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "key file must have 0600 permissions, got {:o}",
            mode
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_agent_key_file_has_restrictive_permissions() {
        let keypair = AgentKeypair::generate().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test_agent.key");
        save_agent_keypair_to_path(&keypair, &path).await.unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "agent key file must have 0600 permissions, got {:o}",
            mode
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_key_file_not_world_readable() {
        let keypair = MachineKeypair::generate().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.key");
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        // World-readable bit (others read) must not be set
        assert_eq!(mode & 0o004, 0, "key file must not be world-readable");
        // Group-readable bit must not be set
        assert_eq!(mode & 0o040, 0, "key file must not be group-readable");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_key_file_not_world_writable() {
        let keypair = MachineKeypair::generate().unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.key");
        save_machine_keypair_to_path(&keypair, &path).await.unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        // World-writable bit must not be set
        assert_eq!(mode & 0o002, 0, "key file must not be world-writable");
    }

    #[cfg(unix)]
    async fn save_agent_keypair_to_path(kp: &AgentKeypair, path: &Path) -> Result<()> {
        let bytes = serialize_agent_keypair(kp)?;
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent)
            .await
            .map_err(IdentityError::from)?;
        fs::write(path, bytes).await.map_err(IdentityError::from)?;

        // Apply restrictive permissions (mirrors production code)
        let mut perms = fs::metadata(path)
            .await
            .map_err(IdentityError::from)?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)
            .await
            .map_err(IdentityError::from)?;

        Ok(())
    }

    // Helper functions for testing (since the main functions use ~/.x0x)
    async fn save_machine_keypair_to_path(kp: &MachineKeypair, path: &Path) -> Result<()> {
        let bytes = serialize_machine_keypair(kp)?;
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent)
            .await
            .map_err(IdentityError::from)?;
        fs::write(path, bytes).await.map_err(IdentityError::from)?;

        // Apply restrictive permissions (mirrors production code path)
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(path)
                .await
                .map_err(IdentityError::from)?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)
                .await
                .map_err(IdentityError::from)?;
        }

        Ok(())
    }

    async fn load_machine_keypair_from_path(path: &Path) -> Result<MachineKeypair> {
        let bytes = fs::read(path).await.map_err(IdentityError::from)?;
        deserialize_machine_keypair(&bytes)
    }

    async fn machine_keypair_exists_in_dir(dir: &Path) -> bool {
        dir.join(MACHINE_KEY_FILE).exists()
    }

    // ========================================================================
    // #124 / WS1.3 tranche 3 — storage / identity error paths.
    //
    // Key material is the root of trust. These pin the failure modes that
    // matter for a security daemon: a corrupt/truncated/wrong-size keyfile
    // must surface as a STRUCTURED `IdentityError` (never a panic), and the
    // atomic write must fail cleanly when the destination is unwritable.
    // Round-trip coverage is extended to agent + user keypairs (machine was
    // already covered above).
    // ========================================================================

    #[tokio::test]
    async fn write_private_bytes_fails_when_parent_is_a_file_not_a_dir() {
        // `write_private_file` begins with `create_dir_all(parent)`; if the
        // parent path is an existing regular file, that must fail and surface
        // as a structured Storage error — never a panic, never a silent ok.
        let tmp = tempfile::tempdir().expect("tmpdir");
        let blocker = tmp.path().join("blocker");
        fs::write(&blocker, b"x")
            .await
            .expect("create blocker file");
        let target = blocker.join("sub").join("secret.key");
        let result = write_private_bytes(&target, b"secret".to_vec()).await;
        let err = result.expect_err("must fail when parent is a regular file");
        assert!(
            matches!(err, IdentityError::Storage(_)),
            "unwritable destination must surface as IdentityError::Storage, got {err:?}"
        );
    }

    #[tokio::test]
    async fn write_private_bytes_leaves_no_final_file_on_failure() {
        // On the failure path above the final target must NOT exist (the
        // atomic write is temp-then-rename; a failure before rename leaves
        // no committed file). This guards against a half-written keyfile
        // being trusted on a later load.
        let tmp = tempfile::tempdir().expect("tmpdir");
        let blocker = tmp.path().join("blocker");
        fs::write(&blocker, b"x")
            .await
            .expect("create blocker file");
        let target = blocker.join("sub").join("secret.key");
        let _ = write_private_bytes(&target, b"secret".to_vec()).await;
        assert!(
            !target.exists(),
            "no committed file must remain after a failed atomic write"
        );
    }

    #[test]
    fn deserialize_rejects_truncated_and_garbage_bytes_for_every_keypair_type() {
        // Corrupt / truncated keyfiles must surface as a structured
        // `Serialization` error (bincode fails) — never a panic. Machine's
        // `[1,2,3]` case exists above; this extends the matrix to all three
        // keypair types AND includes empty + larger garbage.
        let bad_inputs: &[&[u8]] = &[&[], &[1, 2, 3], &[0xA5; 64], &[0xFF; 4096]];
        for bytes in bad_inputs {
            let err = deserialize_machine_keypair(bytes)
                .err()
                .unwrap_or_else(|| panic!("machine: garbage must error: {bytes:?}"));
            assert!(
                matches!(err, IdentityError::Serialization(_)),
                "machine {bytes:?} must be Serialization, got {err:?}"
            );
            let err = deserialize_agent_keypair(bytes)
                .err()
                .unwrap_or_else(|| panic!("agent: garbage must error: {bytes:?}"));
            assert!(
                matches!(err, IdentityError::Serialization(_)),
                "agent {bytes:?} must be Serialization, got {err:?}"
            );
            let err = deserialize_user_keypair(bytes)
                .err()
                .unwrap_or_else(|| panic!("user: garbage must error: {bytes:?}"));
            assert!(
                matches!(err, IdentityError::Serialization(_)),
                "user {bytes:?} must be Serialization, got {err:?}"
            );
        }
    }

    #[test]
    fn deserialize_rejects_valid_bincode_with_wrong_size_key_material() {
        // A subtler corruption: the bincode frame is well-formed (so bincode
        // does NOT fail), but the embedded key bytes are the wrong size for
        // an ML-DSA-65 key. `from_bytes` must reject these as a structured
        // `InvalidPublicKey`/`InvalidSecretKey` — again, never a panic.
        let malformed = SerializedKeypair {
            public_key: vec![0u8; 10], // wrong size (not 1952 bytes)
            secret_key: vec![0u8; 10],
        };
        let bytes = bincode::serialize(&malformed).expect("serialize malformed pair");

        let err = deserialize_machine_keypair(&bytes).expect_err("must reject wrong-size key");
        assert!(
            matches!(
                err,
                IdentityError::InvalidPublicKey(_) | IdentityError::InvalidSecretKey(_)
            ),
            "wrong-size machine key must be InvalidPublicKey/InvalidSecretKey, got {err:?}"
        );
        let err = deserialize_agent_keypair(&bytes).expect_err("must reject wrong-size key");
        assert!(
            matches!(
                err,
                IdentityError::InvalidPublicKey(_) | IdentityError::InvalidSecretKey(_)
            ),
            "wrong-size agent key must be InvalidPublicKey/InvalidSecretKey, got {err:?}"
        );
        let err = deserialize_user_keypair(&bytes).expect_err("must reject wrong-size key");
        assert!(
            matches!(
                err,
                IdentityError::InvalidPublicKey(_) | IdentityError::InvalidSecretKey(_)
            ),
            "wrong-size user key must be InvalidPublicKey/InvalidSecretKey, got {err:?}"
        );
    }

    #[tokio::test]
    async fn agent_keypair_round_trips_through_file_storage() {
        // End-to-end file round-trip for the agent keypair (machine is
        // covered above): save -> load -> identity preserved, file 0600.
        let kp = AgentKeypair::generate().expect("generate agent keypair");
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("agent.key");
        save_agent_keypair(&kp, &path).await.expect("save");
        let loaded = load_agent_keypair(&path).await.expect("load");
        assert_eq!(
            kp.public_key().as_bytes(),
            loaded.public_key().as_bytes(),
            "agent public key must survive a save/load round-trip"
        );
        assert_eq!(
            kp.agent_id(),
            loaded.agent_id(),
            "agent_id must survive a save/load round-trip"
        );
    }

    #[tokio::test]
    async fn user_keypair_round_trips_through_file_storage() {
        // End-to-end file round-trip for the user keypair: save -> load ->
        // identity + user_id preserved.
        let kp = UserKeypair::generate().expect("generate user keypair");
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("user.key");
        save_user_keypair_to(&kp, &path).await.expect("save");
        let loaded = load_user_keypair_from(&path).await.expect("load");
        assert_eq!(
            kp.public_key().as_bytes(),
            loaded.public_key().as_bytes(),
            "user public key must survive a save/load round-trip"
        );
        assert_eq!(
            kp.user_id(),
            loaded.user_id(),
            "user_id must survive a save/load round-trip"
        );
    }

    // ── Key-file expiry format versioning (issue #130) ──

    #[test]
    fn keyfile_without_expiry_writes_legacy_format() {
        // The no-break guarantee: when no expiry is recorded, the bytes must
        // be identical to the legacy `bincode(public_key, secret_key)` shape
        // an older x0x would write and read. A regression here silently
        // rewrites every user's key file into a format old daemons reject.
        let kp = MachineKeypair::generate().unwrap();
        let modern = serialize_machine_keypair(&kp).unwrap();
        let legacy = bincode::serialize(&SerializedKeypair {
            public_key: kp.public_key().as_bytes().to_vec(),
            secret_key: kp.secret_key().as_bytes().to_vec(),
        })
        .unwrap();
        assert_eq!(
            modern, legacy,
            "a no-expiry key file must be byte-for-byte the legacy format"
        );
        // And must NOT carry the v2 marker.
        assert_ne!(
            &modern[..KEYFILE_V2_MAGIC.len()],
            KEYFILE_V2_MAGIC,
            "legacy bytes must not begin with the v2 magic marker"
        );
    }

    #[test]
    fn legacy_keyfile_bytes_load_via_new_loader() {
        // Bytes written by a pre-#130 x0x (bare bincode, no marker) must load
        // through the new versioned loader unchanged, reporting no expiry.
        let kp = AgentKeypair::generate().unwrap();
        let legacy = bincode::serialize(&SerializedKeypair {
            public_key: kp.public_key().as_bytes().to_vec(),
            secret_key: kp.secret_key().as_bytes().to_vec(),
        })
        .unwrap();
        let (loaded, not_after) = deserialize_agent_keypair_with_expiry(&legacy).unwrap();
        assert_eq!(
            loaded.public_key().as_bytes(),
            kp.public_key().as_bytes(),
            "legacy key bytes must decode to the same public key"
        );
        assert_eq!(
            not_after, None,
            "absence of an expiry field must decode as None (never expires)"
        );
    }

    #[test]
    fn v2_keyfile_roundtrip_preserves_not_after() {
        // The v2 format must round-trip the recorded expiry exactly, and the
        // v1 loader must still recover the key material from a v2 file.
        let kp = MachineKeypair::generate().unwrap();
        let expiry = 1_900_000_000u64;
        let bytes = serialize_machine_keypair_with_expiry(&kp, Some(expiry)).unwrap();
        assert_eq!(
            &bytes[..KEYFILE_V2_MAGIC.len()],
            KEYFILE_V2_MAGIC,
            "a v2 key file must begin with the magic marker"
        );
        let (loaded, not_after) = deserialize_machine_keypair_with_expiry(&bytes).unwrap();
        assert_eq!(
            not_after,
            Some(expiry),
            "the recorded expiry must survive a v2 round-trip"
        );
        assert_eq!(
            loaded.public_key().as_bytes(),
            kp.public_key().as_bytes(),
            "v2 key material must survive a round-trip"
        );
        // The plain (non-expiry) loader must also cope with a v2 file.
        let plain = deserialize_machine_keypair(&bytes).unwrap();
        assert_eq!(
            plain.public_key().as_bytes(),
            kp.public_key().as_bytes(),
            "the plain loader must recover key material from a v2 file"
        );
    }

    // ── Default-dir resolution (issue #456) ──

    #[test]
    fn resolve_x0x_home_prefers_override_over_real_home() {
        let real_home = std::path::PathBuf::from("/home/developer");
        // Override wins.
        assert_eq!(
            super::resolve_x0x_home(Some("/tmp/xt"), Some(real_home.clone())),
            Some(std::path::PathBuf::from("/tmp/xt"))
        );
        // An EMPTY override is ignored (unset semantics), never a
        // resolve-to-empty-dir footgun.
        assert_eq!(
            super::resolve_x0x_home(Some(""), Some(real_home.clone())),
            Some(real_home.join(".x0x"))
        );
        // Default: <home>/.x0x.
        assert_eq!(
            super::resolve_x0x_home(None, Some(real_home)),
            Some(std::path::PathBuf::from("/home/developer/.x0x"))
        );
        // Nothing resolvable at all.
        assert_eq!(super::resolve_x0x_home(None, None), None);
    }

    #[test]
    fn instance_dir_is_sibling_of_default_home() {
        let home = std::path::PathBuf::from("/home/developer/.x0x");
        assert_eq!(
            super::resolve_x0x_instance_dir(Some(home.clone()), "alice"),
            Some(std::path::PathBuf::from("/home/developer/.x0x-alice"))
        );
        // An override home relocates instances beside the override.
        let override_home = std::path::PathBuf::from("/tmp/xt");
        assert_eq!(
            super::resolve_x0x_instance_dir(Some(override_home), "alice"),
            Some(std::path::PathBuf::from("/tmp/.x0x-alice"))
        );
        assert_eq!(super::resolve_x0x_instance_dir(None, "alice"), None);
    }

    /// #456 tripwire proof: outside the harness env (`X0X_HOME` unset, as
    /// with a bare `cargo test`), the resolver REFUSES to hand back the
    /// real `~/.x0x` in test builds — it panics, so a polluting test fails
    /// loudly instead of dirtying the maintainer's node. Self-skipping
    /// under the nextest harness (which sets X0X_HOME).
    #[test]
    fn x0x_home_dir_test_guard_panics_without_override() {
        if std::env::var_os("X0X_HOME").is_some_and(|v| !v.is_empty()) {
            // Harness env active: the guard cannot fire; nothing to prove.
            return;
        }
        let result = std::panic::catch_unwind(super::x0x_home_dir);
        assert!(
            result.is_err(),
            "#456 guard must panic when a test would touch the real ~/.x0x"
        );
    }

    /// Review r3 (PR #465 item 1): the durable journal write is
    /// content-correct, 0600, and leaves no temp debris.
    #[tokio::test]
    async fn write_private_bytes_durable_is_atomic_and_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sub").join("journal.bin");
        super::write_private_bytes_durable(&path, vec![1, 2, 3, 4])
            .await
            .expect("durable write");
        let bytes = fs::read(&path).await.expect("read back");
        assert_eq!(bytes, vec![1, 2, 3, 4]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path)
                .await
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "journal bytes are private");
        }
        let mut entries = fs::read_dir(dir.path().join("sub"))
            .await
            .expect("read_dir");
        while let Some(entry) = entries.next_entry().await.expect("entry") {
            let name = entry.file_name();
            assert!(
                !name.to_string_lossy().contains(".tmp"),
                "no temp debris: {}",
                name.to_string_lossy()
            );
        }
        // Overwrite in place stays clean too (the rename path).
        super::write_private_bytes_durable(&path, vec![9])
            .await
            .expect("rewrite");
        let bytes = fs::read(&path).await.expect("reread");
        assert_eq!(bytes, vec![9]);
    }

    /// Issue #1101 seam proof: an injected failure at the parent-directory
    /// fsync (durable point 2, AFTER the rename) is typed `AfterRename`
    /// and the NEW bytes are already in place — the contract every
    /// PostRename caller relies on.
    #[tokio::test]
    async fn durable_write_injected_post_rename_failure_leaves_new_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("journal.bin");
        super::write_private_bytes_durable(&path, vec![1, 2, 3])
            .await
            .expect("seed write");
        let _seam = super::arm_fail_parent_dir_fsync_for_testing(&path);
        let err = super::write_private_bytes_durable_typed(&path, vec![9, 9])
            .await
            .expect_err("injected post-rename failure");
        assert!(
            matches!(err, super::DurableWriteError::AfterRename(_)),
            "typed AfterRename, got: {err:?}"
        );
        let bytes = fs::read(&path).await.expect("read back");
        assert_eq!(bytes, vec![9, 9], "the NEW bytes are already in place");
        let mut entries = fs::read_dir(dir.path()).await.expect("read_dir");
        while let Some(entry) = entries.next_entry().await.expect("entry") {
            assert!(
                !entry.file_name().to_string_lossy().contains(".tmp"),
                "no temp debris: {}",
                entry.file_name().to_string_lossy()
            );
        }

        // The untyped public writer keeps its historical error: the same
        // fault is `IdentityError::Storage` carrying the original
        // `io::Error`, so existing callers see no change (additive API).
        let err = super::write_private_bytes_durable(&path, vec![7])
            .await
            .expect_err("same injected failure through the untyped writer");
        match err {
            IdentityError::Storage(io) => assert_eq!(
                io.to_string(),
                "injected parent-directory fsync failure (test seam)"
            ),
            other => panic!("untyped writer must keep IdentityError::Storage, got: {other:?}"),
        }
        assert_eq!(fs::read(&path).await.expect("read back"), vec![7]);
    }

    /// Issue #1101 seam scoping (round 2): threaded `cargo test` runs the
    /// whole suite in ONE process, so the seam must fail only the armed
    /// path — with path A armed, a concurrent durable write to path B
    /// still succeeds (a process-global flag would have failed B too).
    #[tokio::test]
    async fn post_rename_seam_only_fails_the_armed_path() {
        let dir_a = tempfile::tempdir().expect("tempdir a");
        let path_a = dir_a.path().join("a.bin");
        let dir_b = tempfile::tempdir().expect("tempdir b");
        let path_b = dir_b.path().join("b.bin");

        let _seam = super::arm_fail_parent_dir_fsync_for_testing(&path_a);
        let (a, b) = tokio::join!(
            super::write_private_bytes_durable_typed(&path_a, vec![1]),
            super::write_private_bytes_durable_typed(&path_b, vec![2]),
        );
        assert!(a.is_err(), "the armed path fails after its rename");
        b.expect("a concurrent durable write to another path succeeds");
        assert_eq!(
            fs::read(&path_b).await.expect("read b"),
            vec![2],
            "path B's bytes are in place and its directory was synced"
        );
    }
}
