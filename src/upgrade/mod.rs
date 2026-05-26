//! Decentralized self-update system for x0x binaries.
//!
//! Manifest-based upgrade flow: GitHub releases are checked for new versions,
//! verified with ML-DSA-65 signatures, and propagated symmetrically via gossip.
//! Nodes download, verify, and atomically replace their own binary with rollback
//! support.

pub mod apply;
pub mod manifest;
pub mod monitor;
pub mod rollout;
pub mod signature;

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

    /// Full upgrade workflow: validate -> backup -> replace.
    ///
    /// The caller is responsible for downloading and verifying the new binary
    /// before calling this method.
    pub fn perform_upgrade(
        &self,
        new_binary_path: &Path,
        target_version: &Version,
    ) -> Result<UpgradeResult, UpgradeError> {
        self.validate_upgrade(target_version)?;

        let backup_path = self.create_backup()?;

        info!("Replacing binary...");
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
/// disturbed. Sidelined binaries are always best-effort removed — the process
/// that locked one has, by definition, exited before this runs (a delete of a
/// still-locked file simply fails and is retried on a future launch).
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
    let mut removed = 0;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        let path = entry.path();
        if name.starts_with(".x0x-upgrade-") {
            // Age-gate temp dirs so an in-flight apply is never deleted.
            let old_enough = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_none_or(|age| age >= dir_min_age);
            if old_enough && std::fs::remove_dir_all(&path).is_ok() {
                info!(path = %path.display(), "Removed stale upgrade temp dir");
                removed += 1;
            }
        } else if name.contains(".x0xold-") && std::fs::remove_file(&path).is_ok() {
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
        let backup = dir.path().join("x0xd.exe.backup");
        fs::write(&backup, b"backup").unwrap();

        let removed =
            sweep_stale_upgrade_artifacts(dir.path(), std::time::Duration::from_secs(3600));

        assert_eq!(removed, 1, "only the sidelined binary should be removed");
        assert!(
            fresh_temp.exists(),
            "fresh temp dir must survive the age gate"
        );
        assert!(!sidelined.exists(), "sidelined binary must be reclaimed");
        assert!(backup.exists(), "unrelated .backup file must be left alone");
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
