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
    /// On Unix, this uses `fs::rename` which is atomic on the same filesystem.
    /// The `new_binary` path should be on the same filesystem as the target.
    pub fn atomic_replace(&self, new_binary: &Path) -> Result<(), UpgradeError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Preserve executable permissions
            std::fs::set_permissions(new_binary, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| UpgradeError::ReplaceFailed { source: e })?;
        }

        std::fs::rename(new_binary, &self.target_path)
            .map_err(|e| UpgradeError::ReplaceFailed { source: e })?;

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
        let temp_dir = parent.join(format!(
            ".x0x-upgrade-{}-{}",
            std::process::id(),
            unique_id
        ));
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
}
