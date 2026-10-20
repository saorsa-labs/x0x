//! Decentralized self-update system for x0x binaries.
//!
//! Manifest-based upgrade flow: GitHub releases are checked for new versions,
//! verified with ML-DSA-65 signatures, and propagated symmetrically via gossip.
//! Nodes download, verify, and atomically replace their own binary with rollback
//! support.

pub mod apply;
#[cfg(unix)]
pub(crate) mod fleet_policy;
#[cfg(unix)]
mod inventory_accounts;
pub(crate) mod journal;
pub mod manifest;
pub mod monitor;
pub(crate) mod pair;
pub(crate) mod probe;
pub(crate) mod probe_retry;
pub mod restart;
pub mod rollout;
pub mod signature;
pub(crate) mod staging;
pub(crate) mod staging_runtime;
pub mod verification_probe;

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use semver::Version;
use tracing::{debug, info, warn};

/// Maximum binary size we'll accept (200 MiB).
pub const MAX_BINARY_SIZE_BYTES: u64 = 200 * 1024 * 1024;

/// Result of an upgrade attempt.
#[derive(Debug)]
pub enum UpgradeResult {
    /// Upgrade completed successfully.
    Success { version: String },
    /// Upgrade failed and was rolled back.
    RolledBack { reason: String },
    /// No upgrade was needed.
    NoUpgrade,
}

/// Manages binary backup, replacement, and rollback.
pub struct Upgrader {
    /// Path to the binary being upgraded.
    target_path: PathBuf,
    /// Current version of the binary.
    current_version: Version,
}

impl Upgrader {
    pub fn new(target_path: PathBuf, current_version: Version) -> Self {
        Self {
            target_path,
            current_version,
        }
    }

    /// Prevent downgrades — target must be strictly newer.
    pub fn validate_upgrade(&self, target_version: &Version) -> Result<(), UpgradeError> {
        if target_version <= &self.current_version {
            warn!(
                current_version = %self.current_version,
                target_version = %target_version,
                "Ignoring downgrade attempt: {} -> {}",
                self.current_version,
                target_version
            );
            return Err(UpgradeError::DowngradeAttempt {
                current: self.current_version.to_string(),
                target: target_version.to_string(),
            });
        }
        Ok(())
    }

    /// Create a backup of the current binary.
    pub fn create_backup(&self) -> Result<PathBuf, UpgradeError> {
        let backup_path = self.target_path.with_extension("backup");
        debug!(backup_path = %backup_path.display(), "Creating backup at: {}", backup_path.display());
        std::fs::copy(&self.target_path, &backup_path).map_err(|e| UpgradeError::BackupFailed {
            path: backup_path.clone(),
            source: e,
        })?;
        Ok(backup_path)
    }

    /// Restore from a backup file.
    pub fn restore_from_backup(&self, backup_path: &Path) -> Result<(), UpgradeError> {
        info!(backup_path = %backup_path.display(), "Restoring from backup: {}", backup_path.display());
        std::fs::rename(backup_path, &self.target_path).map_err(|e| UpgradeError::RestoreFailed {
            backup_path: backup_path.to_path_buf(),
            target_path: self.target_path.clone(),
            source: e,
        })
    }

    /// Atomically replace the target binary with the new one.
    ///
    /// On Unix, this uses `fs::rename` which is atomic on the same filesystem
    /// — including when the target is the currently-running executable. The
    /// `new_binary` path should be on the same filesystem as the target.
    ///
    /// On Windows a running executable is locked and cannot be renamed over in
    /// place, so this falls back to [`replace_via_sideline`]: the live binary
    /// is moved aside (it stays locked until this process exits and is then
    /// reclaimed by [`sweep_stale_upgrade_artifacts`] on the next launch) and
    /// the new binary is moved into its place.
    pub fn atomic_replace(&self, new_binary: &Path) -> Result<(), UpgradeError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Preserve executable permissions
            std::fs::set_permissions(new_binary, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| UpgradeError::ReplaceFailed { source: e })?;
            std::fs::rename(new_binary, &self.target_path)
                .map_err(|e| UpgradeError::ReplaceFailed { source: e })?;
        }

        #[cfg(not(unix))]
        {
            replace_via_sideline(&self.target_path, new_binary)?;
        }

        debug!("Atomic replacement complete");
        Ok(())
    }

    /// Create a temp directory on the same filesystem as the target binary,
    /// ensuring atomic rename will work. Uses a unique suffix per invocation
    /// to prevent collisions between concurrent upgrade tasks.
    pub fn create_temp_dir(&self) -> Result<PathBuf, UpgradeError> {
        let parent = self.target_path.parent().unwrap_or_else(|| Path::new("."));
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_dir = parent.join(format!(".x0x-upgrade-{}-{}", std::process::id(), unique_id));
        std::fs::create_dir_all(&temp_dir).map_err(|e| UpgradeError::TempDirFailed {
            path: temp_dir.clone(),
            source: e,
        })?;
        Ok(temp_dir)
    }

    /// Path of the binary this upgrader replaces.
    pub(super) fn target_path(&self) -> &Path {
        &self.target_path
    }

    /// Full upgrade workflow: host lock -> compare -> backup -> replace.
    ///
    /// The caller is responsible for downloading and verifying the new binary
    /// before calling this method.
    ///
    /// Under a host-wide exclusive lock beside this target
    /// (`<target-file-name>.upgrade.lock`), if the on-disk target already
    /// matches the incoming bytes, backup and replace are skipped (the
    /// preserved backup is not rewritten). On Unix the target is still made
    /// executable (`0o755`) before Success — the same postcondition as
    /// [`Self::atomic_replace`]. Permission repair failure is an error, never
    /// Success. The public result is otherwise [`UpgradeResult::Success`] with
    /// the requested version so auto-apply can still restart an old-running
    /// process into those bytes (T-self-update-host-backup-guard / #1447).
    /// Companion binaries (e.g. `x0x` next to `x0xd`) take their own lock file
    /// beside that path via the same mechanism.
    pub fn perform_upgrade(
        &self,
        new_binary_path: &Path,
        target_version: &Version,
    ) -> Result<UpgradeResult, UpgradeError> {
        self.validate_upgrade(target_version)?;

        // Hold for the whole compare / backup / replace critical section.
        // Dropping the guard releases the OS lock; the lock file is never
        // unlinked, so reclaim cannot remove a file another process still holds.
        let _host_lock = acquire_host_upgrade_lock(&self.target_path)?;
        self.finish_upgrade_under_host_lock(new_binary_path, target_version)
    }

    /// Compare / backup / replace while the caller already holds this target's
    /// host lock. Used by the offloaded multi-target apply so every lock can
    /// be taken before any mutation (cancel must not install bytes without a
    /// restart owner).
    ///
    /// When disk already matches the incoming bytes, backup and replace are
    /// skipped and [`UpgradeResult::Success`] is returned so public
    /// `perform_upgrade` matches main and auto-apply can still own restart.
    /// On Unix, Success still requires the installed target to be executable
    /// (`0o755`), matching `atomic_replace`; a permission repair failure is
    /// an error, never Success. The preserved backup is not rewritten.
    pub(super) fn finish_upgrade_under_host_lock(
        &self,
        new_binary_path: &Path,
        target_version: &Version,
    ) -> Result<UpgradeResult, UpgradeError> {
        if on_disk_matches_incoming(&self.target_path, new_binary_path)? {
            // Host lock is held: repair execute bits without clobbering backup.
            ensure_target_executable(&self.target_path)?;
            info!(
                version = %target_version,
                target = %self.target_path.display(),
                "On-disk target already matches incoming binary; skipping backup and replace"
            );
            return Ok(UpgradeResult::Success {
                version: target_version.to_string(),
            });
        }

        let backup_path = self.create_backup()?;

        info!(
            replace_target = %self.target_path.display(),
            "Replacing binary..."
        );
        match self.atomic_replace(new_binary_path) {
            Ok(()) => {
                info!(version = %target_version, "Successfully upgraded to version {}", target_version);
                Ok(UpgradeResult::Success {
                    version: target_version.to_string(),
                })
            }
            Err(replace_err) => {
                warn!(error = %replace_err, "Binary replacement failed: {}", replace_err);
                match self.restore_from_backup(&backup_path) {
                    Ok(()) => Ok(UpgradeResult::RolledBack {
                        reason: format!("Replacement failed: {replace_err}"),
                    }),
                    Err(restore_err) => {
                        tracing::error!(
                            error = %replace_err,
                            rollback_error = %restore_err,
                            "CRITICAL: Replacement failed ({}) AND rollback failed ({})",
                            replace_err,
                            restore_err
                        );
                        Err(UpgradeError::CriticalFailure {
                            replace_error: replace_err.to_string(),
                            rollback_error: restore_err.to_string(),
                        })
                    }
                }
            }
        }
    }
}

/// Persistent lock file beside `target`: `<file-name>.upgrade.lock`.
///
/// Never unlinked on release or reclaim — only the OS advisory lock is dropped
/// when the holder process dies or the returned file is closed.
fn host_upgrade_lock_path(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".upgrade.lock");
    target.with_file_name(name)
}

/// Exclusive OS lock (`std::fs::File::lock`: flock/fcntl on Unix, LockFileEx
/// on Windows). Created if missing; never truncated or unlinked.
pub(super) fn acquire_host_upgrade_lock(target: &Path) -> Result<File, UpgradeError> {
    let lock_path = host_upgrade_lock_path(target);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| {
            UpgradeError::Other(format!(
                "failed to take host upgrade lock at {}: {source}",
                lock_path.display()
            ))
        })?;
    file.lock().map_err(|source| {
        UpgradeError::Other(format!(
            "failed to take host upgrade lock at {}: {source}",
            lock_path.display()
        ))
    })?;
    Ok(file)
}

/// Unix postcondition shared with [`Upgrader::atomic_replace`]: Success means
/// the installed target is executable (`0o755`). Runs under the host lock on
/// the equal-bytes shortcut so a `0644` target is repaired without rewriting
/// the preserved backup. Permission failure must not become Success.
#[cfg(unix)]
fn ensure_target_executable(target: &Path) -> Result<(), UpgradeError> {
    use std::os::unix::fs::PermissionsExt;

    #[cfg(test)]
    if exec_postcondition_seam::should_fail() {
        return Err(UpgradeError::ReplaceFailed {
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected executable-postcondition failure",
            ),
        });
    }

    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755))
        .map_err(|source| UpgradeError::ReplaceFailed { source })
}

#[cfg(not(unix))]
fn ensure_target_executable(_target: &Path) -> Result<(), UpgradeError> {
    Ok(())
}

/// cfg(test) only: force [`ensure_target_executable`] to fail on this thread so
/// equal-bytes Success cannot be claimed when the execute-bit repair fails.
#[cfg(all(test, unix))]
pub(crate) mod exec_postcondition_seam {
    use std::cell::Cell;

    thread_local! {
        static FAIL: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) struct Guard {
        _private: (),
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL.with(|f| f.set(false));
        }
    }

    pub(crate) fn force_fail() -> Guard {
        FAIL.with(|f| f.set(true));
        Guard { _private: () }
    }

    pub(crate) fn should_fail() -> bool {
        FAIL.with(|f| f.get())
    }
}

/// True when the installed target exists and its bytes equal `incoming`.
fn on_disk_matches_incoming(target: &Path, incoming: &Path) -> Result<bool, UpgradeError> {
    if !target.exists() {
        return Ok(false);
    }
    let target_meta = std::fs::metadata(target).map_err(|source| {
        UpgradeError::Other(format!(
            "failed to stat target {}: {source}",
            target.display()
        ))
    })?;
    let incoming_meta = std::fs::metadata(incoming).map_err(|source| {
        UpgradeError::Other(format!(
            "failed to stat incoming {}: {source}",
            incoming.display()
        ))
    })?;
    if target_meta.len() != incoming_meta.len() {
        return Ok(false);
    }
    let mut target_file = File::open(target).map_err(|source| {
        UpgradeError::Other(format!(
            "failed to open target {}: {source}",
            target.display()
        ))
    })?;
    let mut incoming_file = File::open(incoming).map_err(|source| {
        UpgradeError::Other(format!(
            "failed to open incoming {}: {source}",
            incoming.display()
        ))
    })?;
    let mut target_buf = [0u8; 64 * 1024];
    let mut incoming_buf = [0u8; 64 * 1024];
    loop {
        let n_t = target_file.read(&mut target_buf).map_err(|source| {
            UpgradeError::Other(format!(
                "failed to read target {}: {source}",
                target.display()
            ))
        })?;
        let n_i = incoming_file.read(&mut incoming_buf).map_err(|source| {
            UpgradeError::Other(format!(
                "failed to read incoming {}: {source}",
                incoming.display()
            ))
        })?;
        if n_t != n_i || target_buf[..n_t] != incoming_buf[..n_i] {
            return Ok(false);
        }
        if n_t == 0 {
            return Ok(true);
        }
    }
}

/// Replace `target` with `new_binary` by moving the existing file aside first.
///
/// Required on Windows, where a running executable is locked and cannot be
/// renamed over in place — but a locked file *can* be moved aside. The moved
/// file (`<name>.x0xold-<nanos>`) stays locked until the old process exits and
/// is reclaimed by [`sweep_stale_upgrade_artifacts`] on the next launch. On any
/// failure the sideline is rolled back so the original binary is never lost.
///
/// Used by [`Upgrader::atomic_replace`] on non-Unix targets; defined for all
/// platforms so its logic is exercised by tests on Unix CI.
pub fn replace_via_sideline(target: &Path, new_binary: &Path) -> Result<(), UpgradeError> {
    let sidelined = sideline_path_for(target);
    std::fs::rename(target, &sidelined).map_err(|e| UpgradeError::ReplaceFailed { source: e })?;
    if let Err(e) = std::fs::rename(new_binary, target) {
        // Restore the original so a failed replace can't leave us binaryless.
        let _ = std::fs::rename(&sidelined, target);
        return Err(UpgradeError::ReplaceFailed { source: e });
    }
    Ok(())
}

/// Compute the move-aside path for `target`, using the `.x0xold-<nanos>` marker
/// that [`sweep_stale_upgrade_artifacts`] recognises and reclaims.
fn sideline_path_for(target: &Path) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = target
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".x0xold-{unique}"));
    target.with_file_name(name)
}

/// Reclaim leftover upgrade artifacts from interrupted or failed attempts.
///
/// Two kinds of debris accumulate in the binary's directory:
/// - `.x0x-upgrade-*` temp dirs (each holds a downloaded archive plus the
///   extracted binary, tens of MB). A failed binary replace used to leave one
///   behind on every attempt — the cause of the Windows disk-fill loop.
/// - `*.x0xold-*` binaries sidelined by [`replace_via_sideline`], which stay
///   locked until the old process exits and so can only be reclaimed later.
///
/// Temp dirs younger than `dir_min_age` are left untouched so a concurrent
/// in-flight apply (this process's, or a co-located instance's) is never
/// disturbed. Sidelined binaries are age-gated the same way (issue #261 I4b):
/// a handoff still in flight — including a manual relaunch of a crashing new
/// binary — must not lose its rollback bytes to the startup sweep.
///
/// Returns the number of entries removed. All removal is best-effort.
pub fn sweep_stale_upgrade_artifacts(dir: &Path, dir_min_age: std::time::Duration) -> usize {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!(dir = %dir.display(), error = %e, "Cannot scan for stale upgrade artifacts");
            return 0;
        }
    };
    let now = std::time::SystemTime::now();
    let entry_is_aged = |entry: &std::fs::DirEntry| {
        entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_none_or(|age| age >= dir_min_age)
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let path = entry.path();
        if name.starts_with(".x0x-upgrade-") {
            // Age-gate temp dirs so an in-flight apply is never deleted.
            if entry_is_aged(&entry) && std::fs::remove_dir_all(&path).is_ok() {
                info!(path = %path.display(), "Removed stale upgrade temp dir");
                removed += 1;
            }
        } else if name.contains(".x0xold-")
            && entry_is_aged(&entry)
            && std::fs::remove_file(&path).is_ok()
        {
            info!(path = %path.display(), "Removed sidelined binary from prior upgrade");
            removed += 1;
        }
    }
    removed
}

#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("downgrade not allowed: current {current} -> target {target}")]
    DowngradeAttempt { current: String, target: String },

    #[error("failed to create backup at {path}: {source}")]
    BackupFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to restore backup from {backup_path} to {target_path}: {source}")]
    RestoreFailed {
        backup_path: PathBuf,
        target_path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to replace binary: {source}")]
    ReplaceFailed { source: std::io::Error },

    #[error("failed to create temp dir at {path}: {source}")]
    TempDirFailed {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error(
        "CRITICAL: replacement failed ({replace_error}) AND rollback failed ({rollback_error})"
    )]
    CriticalFailure {
        replace_error: String,
        rollback_error: String,
    },

    #[error("signature verification failed: {0}")]
    SignatureError(#[from] signature::SignatureError),

    #[error("download failed: {0}")]
    DownloadError(String),

    #[error("extraction failed: {0}")]
    ExtractionError(String),

    #[error("binary too large: {size} bytes exceeds limit of {limit} bytes")]
    BinaryTooLarge { size: u64, limit: u64 },

    #[error("unsupported platform")]
    UnsupportedPlatform,

    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("manifest signature verification failed")]
    ManifestSignatureInvalid,

    #[error("archive SHA-256 hash mismatch")]
    HashMismatch,

    #[error("no platform asset in manifest for current platform")]
    NoPlatformAsset,

    #[error("failed to fetch manifest: {0}")]
    ManifestFetchFailed(String),

    /// The restart contract could not be resolved, or names two restart
    /// owners, so the apply was refused before any binary was replaced
    /// (ADR-0061 §1/§2).
    #[error(transparent)]
    RestartOwnership(#[from] restart::RestartOwnershipError),

    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_binary(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    #[test]
    fn test_backup_creation_and_restore() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"original content");
        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));

        let backup_path = upgrader.create_backup().unwrap();
        assert!(backup_path.exists());
        assert_eq!(fs::read(&backup_path).unwrap(), b"original content");

        // Simulate replacement
        fs::write(&binary_path, b"new content").unwrap();
        assert_eq!(fs::read(&binary_path).unwrap(), b"new content");

        // Restore
        upgrader.restore_from_backup(&backup_path).unwrap();
        assert_eq!(fs::read(&binary_path).unwrap(), b"original content");
    }

    #[test]
    fn test_atomic_replacement() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"old");
        let new_binary_path = create_test_binary(&dir, "new-binary", b"new");
        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));

        upgrader.atomic_replace(&new_binary_path).unwrap();
        assert_eq!(fs::read(&binary_path).unwrap(), b"new");
        assert!(!new_binary_path.exists()); // rename moves the file
    }

    #[test]
    fn test_downgrade_prevention() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"content");
        let upgrader = Upgrader::new(binary_path, Version::new(2, 0, 0));

        let result = upgrader.validate_upgrade(&Version::new(1, 0, 0));
        assert!(matches!(result, Err(UpgradeError::DowngradeAttempt { .. })));
    }

    #[test]
    fn test_same_version_prevention() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"content");
        let upgrader = Upgrader::new(binary_path, Version::new(1, 0, 0));

        let result = upgrader.validate_upgrade(&Version::new(1, 0, 0));
        assert!(matches!(result, Err(UpgradeError::DowngradeAttempt { .. })));
    }

    #[test]
    fn test_valid_upgrade_accepted() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"content");
        let upgrader = Upgrader::new(binary_path, Version::new(1, 0, 0));

        upgrader.validate_upgrade(&Version::new(2, 0, 0)).unwrap();
    }

    #[test]
    fn test_perform_upgrade_success() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"old binary");
        let new_binary = create_test_binary(&dir, "new-binary", b"new binary");
        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));

        let result = upgrader
            .perform_upgrade(&new_binary, &Version::new(2, 0, 0))
            .unwrap();
        assert!(matches!(result, UpgradeResult::Success { .. }));
        assert_eq!(fs::read(&binary_path).unwrap(), b"new binary");
        assert!(
            host_upgrade_lock_path(&binary_path).exists(),
            "perform_upgrade must create the host lock file beside the target"
        );
    }

    #[test]
    fn test_perform_upgrade_skips_when_disk_already_matches() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"same bytes");
        let first = create_test_binary(&dir, "new-binary-1", b"same bytes");
        let second = create_test_binary(&dir, "new-binary-2", b"same bytes");
        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));

        // Seed a good backup of a prior version, then install matching bytes.
        fs::write(binary_path.with_extension("backup"), b"prior version").unwrap();
        fs::write(&binary_path, b"same bytes").unwrap();

        let result = upgrader
            .perform_upgrade(&first, &Version::new(2, 0, 0))
            .unwrap();
        // Public result matches main 4b0f927e: Success for older current /
        // newer requested / equal disk+incoming bytes (RC4 wrongly returned
        // NoUpgrade; main has no matching-byte skip branch and returns Success).
        assert!(
            matches!(
                result,
                UpgradeResult::Success {
                    ref version
                } if version == "2.0.0"
            ),
            "public perform_upgrade must match main Success on equal bytes: {result:?}"
        );
        // Skip leaves incoming in place; backup untouched.
        assert!(first.exists(), "skip must not consume the incoming path");
        assert_eq!(
            fs::read(binary_path.with_extension("backup")).unwrap(),
            b"prior version"
        );

        let result2 = upgrader
            .perform_upgrade(&second, &Version::new(2, 0, 0))
            .unwrap();
        assert!(
            matches!(
                result2,
                UpgradeResult::Success {
                    ref version
                } if version == "2.0.0"
            ),
            "second matching-bytes call must still be public Success: {result2:?}"
        );
        assert!(second.exists());
        assert_eq!(
            fs::read(binary_path.with_extension("backup")).unwrap(),
            b"prior version",
            "a second skip must never rewrite the backup"
        );

        // finish_* under an already-held lock is the same Success result so
        // auto-apply can arm restart for an old-running process.
        let _lock = acquire_host_upgrade_lock(&binary_path).unwrap();
        let restart_owner = upgrader
            .finish_upgrade_under_host_lock(&second, &Version::new(2, 0, 0))
            .unwrap();
        assert!(
            matches!(restart_owner, UpgradeResult::Success { .. }),
            "finish on match must stay Success for restart ownership: {restart_owner:?}"
        );
    }

    /// Equal bytes + non-executable target must still leave a runnable binary
    /// (main's atomic_replace sets 0755). Backup must stay untouched.
    #[cfg(unix)]
    #[test]
    fn matching_bytes_repairs_0644_target_to_0755_without_touching_backup() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let binary_path = dir.path().join("test-binary");
        let incoming = dir.path().join("incoming");
        let bytes = b"same bytes";
        fs::write(&binary_path, bytes).unwrap();
        fs::write(&incoming, bytes).unwrap();
        fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(binary_path.with_extension("backup"), b"prior version").unwrap();

        assert_eq!(
            fs::metadata(&binary_path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));
        let result = upgrader
            .perform_upgrade(&incoming, &Version::new(2, 0, 0))
            .expect("equal-bytes upgrade must succeed after execute repair");
        assert!(
            matches!(
                result,
                UpgradeResult::Success {
                    ref version
                } if version == "2.0.0"
            ),
            "Success required when bytes match and execute bits can be repaired: {result:?}"
        );
        assert_eq!(
            fs::metadata(&binary_path).unwrap().permissions().mode() & 0o777,
            0o755,
            "Success must mean the installed target is executable"
        );
        assert_eq!(fs::read(&binary_path).unwrap(), bytes);
        assert!(
            incoming.exists(),
            "equal-bytes path must not consume incoming"
        );
        assert_eq!(
            fs::read(binary_path.with_extension("backup")).unwrap(),
            b"prior version",
            "execute-bit repair must not rewrite the preserved backup"
        );
    }

    /// Permission-repair failure under the equal-bytes shortcut must not report
    /// Success (restart must not be armed into a non-executable target).
    #[cfg(unix)]
    #[test]
    fn matching_bytes_permission_repair_failure_is_not_success() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let binary_path = dir.path().join("test-binary");
        let incoming = dir.path().join("incoming");
        let bytes = b"same bytes";
        fs::write(&binary_path, bytes).unwrap();
        fs::write(&incoming, bytes).unwrap();
        fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(binary_path.with_extension("backup"), b"prior version").unwrap();

        let _fail = exec_postcondition_seam::force_fail();
        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));
        let result = upgrader.perform_upgrade(&incoming, &Version::new(2, 0, 0));
        assert!(
            matches!(result, Err(UpgradeError::ReplaceFailed { .. })),
            "permission repair failure must be Err, never Success: {result:?}"
        );
        assert_eq!(
            fs::metadata(&binary_path).unwrap().permissions().mode() & 0o777,
            0o644,
            "failed repair must leave the target mode unchanged"
        );
        assert_eq!(
            fs::read(binary_path.with_extension("backup")).unwrap(),
            b"prior version",
            "failed repair must not rewrite the preserved backup"
        );
    }

    #[test]
    fn test_temp_dir_in_target_directory() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"content");
        let upgrader = Upgrader::new(binary_path, Version::new(1, 0, 0));

        let temp_dir = upgrader.create_temp_dir().unwrap();
        assert!(temp_dir.starts_with(dir.path()));
        assert!(temp_dir.exists());
        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_permissions_preserved_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"old");
        let new_binary = create_test_binary(&dir, "new-binary", b"new");
        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));

        upgrader.atomic_replace(&new_binary).unwrap();
        let perms = fs::metadata(&binary_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o755);
    }

    #[test]
    fn test_max_binary_size_constant() {
        assert_eq!(MAX_BINARY_SIZE_BYTES, 200 * 1024 * 1024);
    }

    #[test]
    fn replace_via_sideline_swaps_binary_and_keeps_old_aside() {
        // Encodes the Windows self-replace contract: the new binary lands at the
        // target path and the old one is preserved under a sweepable marker, so a
        // crash mid-restart can never leave the install without a working binary.
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("x0xd.exe");
        fs::write(&target, b"old binary").unwrap();
        let new_binary = create_test_binary(&dir, "extracted-binary", b"new binary");

        replace_via_sideline(&target, &new_binary).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new binary");
        let sidelined: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".x0xold-"))
            .collect();
        assert_eq!(sidelined.len(), 1, "exactly one sidelined binary expected");
        assert_eq!(fs::read(sidelined[0].path()).unwrap(), b"old binary");
    }

    #[test]
    fn sweep_reclaims_sidelined_binaries_but_spares_fresh_temp_dirs() {
        // A successful upgrade leaves both a fresh temp dir (about to be cleaned
        // by the caller) and a sidelined binary (locked until restart). The sweep
        // must reclaim the latter without nuking an in-flight apply's temp dir.
        let dir = TempDir::new().unwrap();
        let fresh_temp = dir.path().join(".x0x-upgrade-123-456");
        fs::create_dir_all(&fresh_temp).unwrap();
        let sidelined = dir.path().join("x0xd.exe.x0xold-789");
        fs::write(&sidelined, b"old").unwrap();
        // #261 I4b: a sideline younger than the age gate is an in-flight
        // handoff's rollback bytes and must survive the same way a fresh
        // temp dir does.
        let in_flight_sideline = dir.path().join("x0xd.exe.x0xold-111");
        fs::write(&in_flight_sideline, b"in-flight").unwrap();
        age_file(&sidelined, std::time::Duration::from_secs(7200));
        let backup = dir.path().join("x0xd.exe.backup");
        fs::write(&backup, b"backup").unwrap();

        let removed =
            sweep_stale_upgrade_artifacts(dir.path(), std::time::Duration::from_secs(3600));

        assert_eq!(
            removed, 1,
            "only the aged sidelined binary should be removed"
        );
        assert!(
            fresh_temp.exists(),
            "fresh temp dir must survive the age gate"
        );
        assert!(
            !sidelined.exists(),
            "aged sidelined binary must be reclaimed"
        );
        assert!(
            in_flight_sideline.exists(),
            "in-flight handoff sideline must survive the age gate"
        );
        assert!(backup.exists(), "unrelated .backup file must be left alone");
    }

    /// Backdate a file's mtime so the sweep's age gate sees it as old.
    fn age_file(path: &Path, age: std::time::Duration) {
        let file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_modified(
            std::time::SystemTime::now()
                .checked_sub(age)
                .expect("age must not overflow the clock"),
        )
        .unwrap();
    }

    #[test]
    fn sweep_reclaims_aged_temp_dirs() {
        // Orphaned temp dirs from a previous run are the disk-fill debris; with a
        // zero min-age every such dir qualifies and must be removed.
        let dir = TempDir::new().unwrap();
        let stale = dir.path().join(".x0x-upgrade-1-1");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("archive"), vec![0u8; 1024]).unwrap();
        fs::write(stale.join("extracted-binary"), vec![0u8; 1024]).unwrap();

        let removed = sweep_stale_upgrade_artifacts(dir.path(), std::time::Duration::from_secs(0));

        assert_eq!(removed, 1);
        assert!(!stale.exists());
    }
}
