//! Key storage utilities for x0x identity persistence.
//!
//! This module provides serialization and storage functionality for
//! MachineKeypair, AgentKeypair, UserKeypair, and AgentCertificate types,
//! enabling persistence of identities across application restarts.

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
use tokio::fs;

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
/// other path are unaffected.
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
        .any(|armed| armed == path)
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
    write_private_bytes_durable_guarded(path, bytes, guard).await
}

/// V3's read/merge already validated the file and holds its write guard.
/// Consume that guard through fsync rather than reading the file twice.
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

    if let Err(err) = fs::rename(&tmp_path, path).await {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(DurableWriteError::BeforeRename(err));
    }

    // Everything below runs with the NEW bytes already visible on disk.

    // Test seam (issue #1101): fail the parent-directory fsync here for
    // the armed path only, so PostRename callers can be exercised
    // without a real fsync fault and without breaking concurrent
    // durable writes to other paths in the same test process.
    #[cfg(test)]
    if fails_parent_dir_fsync_for_testing(path) {
        return Err(DurableWriteError::AfterRename(std::io::Error::other(
            "injected parent-directory fsync failure (test seam)",
        )));
    }

    // Durable point 2: the rename itself survives power loss.
    let dir = fs::File::open(parent)
        .await
        .map_err(DurableWriteError::AfterRename)?;
    if let Err(err) = dir.sync_all().await {
        return Err(DurableWriteError::AfterRename(err));
    }
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
    tokio::fs::try_exists(path.join(MACHINE_KEY_FILE))
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
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
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
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
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
    tokio::fs::try_exists(path.join(AGENT_KEY_FILE))
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
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
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
    tokio::fs::try_exists(path.join(USER_KEY_FILE))
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
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
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
    tokio::fs::try_exists(path.join(AGENT_CERT_FILE))
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
    let bytes = tokio::fs::read(path).await.map_err(IdentityError::from)?;
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
                return Ok(Some(RevocationSet::quarantined_carrier(
                    store.carrier_bit(),
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
            Ok(Some(RevocationSet::quarantined_carrier(
                store.carrier_bit(),
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
    let Ok(mut entries) = tokio::fs::read_dir(parent).await else {
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

/// Move corrupt revocation bytes to `<name>.quarantined-<unix-ms>`.
///
/// The live path no longer holds the payload. An existing quarantine file
/// with the same bytes is kept and the live path is removed. Startup
/// (`persist_attempt == false`) logs the operator message.
async fn archive_corrupt_revocation_bytes(path: &Path, bytes: &[u8], persist_attempt: bool) {
    let Some(parent) = path.parent() else {
        return;
    };
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let prefix = format!("{name}.quarantined-");
    let mut existing = None;
    if let Ok(mut entries) = tokio::fs::read_dir(parent).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            if !file_name.starts_with(&prefix) {
                continue;
            }
            if tokio::fs::read(entry.path()).await.ok().as_deref() == Some(bytes) {
                existing = Some(entry.path());
                break;
            }
        }
    }
    let quarantine = if let Some(dest) = existing {
        if let Err(error) = tokio::fs::remove_file(path).await {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::error!(
                    path = %path.display(),
                    error = %error,
                    "{}",
                    crate::revocation::REVOCATION_RESYNC_STATUS
                );
                return;
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
        while tokio::fs::try_exists(&dest).await.unwrap_or(false) {
            seq = seq.saturating_add(1);
            dest = parent.join(format!("{prefix}{millis}-{seq}"));
        }
        if let Err(rename_error) = tokio::fs::rename(path, &dest).await {
            if tokio::fs::write(&dest, bytes).await.is_err() {
                tracing::error!(
                    path = %path.display(),
                    error = %rename_error,
                    "{}",
                    crate::revocation::REVOCATION_RESYNC_STATUS
                );
                return;
            }
            if let Err(error) = tokio::fs::remove_file(path).await {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::error!(
                        path = %path.display(),
                        error = %error,
                        "{}",
                        crate::revocation::REVOCATION_RESYNC_STATUS
                    );
                    return;
                }
            }
        }
        dest
    };
    if !persist_attempt {
        tracing::error!(
            path = %path.display(),
            quarantine = %quarantine.display(),
            "{}",
            crate::revocation::REVOCATION_RESYNC_STATUS
        );
    }
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
        let mut entries = tokio::fs::read_dir(dir).await.expect("read dir");
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

    /// #1116 / ADR 0085 rule 4: a fail-closed load must not authorize
    /// overwriting an unreadable v1 file on the next ordinary persist.
    #[tokio::test]
    async fn unreadable_v1_revocations_survive_persist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(REVOCATION_FILE);
        let garbage = b"unreadable v1 revocations\x00\xff";
        tokio::fs::write(&path, garbage)
            .await
            .expect("seed garbage");

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
            tokio::fs::read(&path).await.ok().as_deref(),
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
            tokio::fs::read(&path).await.ok().as_deref(),
            Some(garbage.as_slice()),
            "persist must not put the corrupt payload back on the live path"
        );
        let again = load_revocation_set(Some(dir.path())).await;
        assert!(
            again.revocation_resync_required(),
            "the next start stays closed without reading the quarantined payload"
        );
        assert!(again.member_treated_as_revoked(&stranger.agent_id()));
        tokio::fs::write(&path, RevocationSet::new().to_bytes().unwrap())
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
        tokio::fs::write(&path, garbage)
            .await
            .expect("seed garbage");
        let stranger = AgentKeypair::generate().expect("stranger");
        let first = load_revocation_set(Some(dir.path())).await;
        assert!(first.revocation_resync_required());
        assert!(first.member_treated_as_revoked(&stranger.agent_id()));
        assert_ne!(
            tokio::fs::read(&path).await.ok().as_deref(),
            Some(garbage.as_slice()),
            "the original path is no longer the corrupt payload"
        );
        let quarantined = quarantine_files(dir.path(), REVOCATION_FILE).await;
        assert_eq!(quarantined.len(), 1, "one timestamped quarantine file");
        assert_eq!(std::fs::read(&quarantined[0]).expect("quarantine"), garbage);
        // A decodable replacement must not be loaded. The next start looks
        // at the quarantine name only.
        let readable = RevocationSet::new().to_bytes().expect("empty store");
        tokio::fs::write(&quarantined[0], &readable)
            .await
            .expect("replace quarantined payload");
        let second = load_revocation_set(Some(dir.path())).await;
        assert!(
            second.revocation_resync_required(),
            "the next start stays closed without reading the quarantined bytes"
        );
        assert!(second.member_treated_as_revoked(&stranger.agent_id()));
        assert_ne!(
            tokio::fs::read(&path).await.ok().as_deref(),
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
            tokio::fs::write(dir.path().join(name), garbage)
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
                tokio::fs::read(dir.path().join(name)).await.ok().as_deref(),
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
                tokio::fs::read(&path).await.ok().as_deref(),
                Some(garbage.as_slice()),
                "{name} stays off the live path after a refused write"
            );
        }

        tokio::fs::write(
            dir.path().join("revocations.bin"),
            empty.to_bytes().unwrap(),
        )
        .await
        .unwrap();
        tokio::fs::write(
            dir.path().join("revocations-v2.bin"),
            empty.to_bytes_v2().unwrap(),
        )
        .await
        .unwrap();
        tokio::fs::write(
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
        tokio::fs::write(dir.path().join("revocations-v2.bin"), garbage)
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
    #[tokio::test]
    async fn zero_byte_and_truncated_revocation_files_fail_closed_1116() {
        let valid = RevocationSet::new().to_bytes().expect("empty store");
        assert!(valid.len() > 1, "a revocation file has a header");
        let truncated = &valid[..valid.len() - 1];
        for (name, bytes) in [
            ("revocations.bin", &[][..]),
            ("revocations-v2.bin", truncated),
            ("revocations-v3.bin", &[][..]),
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join(name);
            tokio::fs::write(&path, bytes).await.expect("seed");
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
                tokio::fs::read(&path).await.ok().as_deref(),
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
        tokio::fs::write(&blocker, b"x")
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
        tokio::fs::write(&blocker, b"x")
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
        let bytes = tokio::fs::read(&path).await.expect("read back");
        assert_eq!(bytes, vec![1, 2, 3, 4]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = tokio::fs::metadata(&path)
                .await
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "journal bytes are private");
        }
        let mut entries = tokio::fs::read_dir(dir.path().join("sub"))
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
        let bytes = tokio::fs::read(&path).await.expect("reread");
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
        let bytes = tokio::fs::read(&path).await.expect("read back");
        assert_eq!(bytes, vec![9, 9], "the NEW bytes are already in place");
        let mut entries = tokio::fs::read_dir(dir.path()).await.expect("read_dir");
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
        assert_eq!(tokio::fs::read(&path).await.expect("read back"), vec![7]);
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
            tokio::fs::read(&path_b).await.expect("read b"),
            vec![2],
            "path B's bytes are in place and its directory was synced"
        );
    }
}
