//! Decentralized self-update system for x0x binaries.
//!
//! Manifest-based upgrade flow: GitHub releases are checked for new versions,
//! verified with ML-DSA-65 signatures, and propagated symmetrically via gossip.
//! Nodes download, verify, and atomically replace their own binary with rollback
//! support.

pub mod apply;
pub mod manifest;
pub mod monitor;
pub mod participants;
pub mod restart;
pub mod rollout;
pub mod signature;
pub mod verification_probe;

use std::path::{Path, PathBuf};

use semver::Version;
use tracing::{debug, info, warn};

/// Maximum binary size we'll accept (200 MiB).
pub const MAX_BINARY_SIZE_BYTES: u64 = 200 * 1024 * 1024;

/// How long an apply waits for another writer's host upgrade lock (#1106).
/// The holder releases the lock when its apply returns or its process exits.
pub const HOST_UPGRADE_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Free space that staging must leave on the install filesystem (D194:
/// 1 GiB).
pub const DISK_RESERVE_BYTES: u64 = 1024 * 1024 * 1024;

/// Versioned backups kept per binary besides the known-good pair (review S3).
pub const NEWEST_BACKUPS_KEPT: usize = 3;

/// Refuse staging when `available` minus the peak space an apply needs
/// would leave less than [`DISK_RESERVE_BYTES`] (D194, review S3).
pub fn check_disk_reserve(_available: u64, _needed: u64) -> Result<(), UpgradeError> {
    Ok(())
}

/// Free bytes available to this process on the filesystem holding `path`.
pub fn free_space_bytes(_path: &Path) -> Option<u64> {
    None
}

/// Outcome of a host-locked binary swap (#1106).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapOutcome {
    /// This writer replaced the installed bytes. `backup_path` holds the
    /// previous bytes under a versioned name.
    Swapped {
        /// The versioned backup of the previous bytes.
        backup_path: PathBuf,
    },
    /// Another writer on this host already installed exactly these bytes.
    /// Nothing was copied or replaced.
    AlreadyInstalled,
    /// The replacement failed and the previous bytes are in place.
    RolledBack {
        /// Why the replacement failed.
        reason: String,
    },
}

/// Host-level upgrade lock: one binary writer per install (#1106, ADR 0094
/// §2/§3).
///
/// An OS file lock on `<install dir>/.<binary>.upgrade-lock`. Two daemons
/// that share one executable (for example `x0xd` and `x0xd-443`) take the
/// same lock, so only one of them downloads, backs up and swaps at a time.
/// The OS releases the lock when the holder drops it or its process exits.
/// The lock file itself is never deleted.
#[derive(Debug)]
pub struct HostUpgradeLock {
    _file: std::fs::File,
    path: PathBuf,
}

impl HostUpgradeLock {
    /// The lock file for the binary at `target`.
    pub fn lock_path_for(target: &Path) -> PathBuf {
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "x0xd".to_string());
        let dir = target.parent().unwrap_or_else(|| Path::new("."));
        dir.join(format!(".{name}.upgrade-lock"))
    }

    /// Take the lock without waiting. `Ok(None)` means another writer holds it.
    pub fn try_acquire(target: &Path) -> Result<Option<Self>, UpgradeError> {
        let path = Self::lock_path_for(target);
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path);
        // Review R1: another service account on a shared install may only
        // read a lock file the first account created. flock needs no write
        // access, so a read-only descriptor locks the same file.
        let opened = match opened {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                std::fs::OpenOptions::new().read(true).open(&path)
            }
            other => other,
        };
        let file = opened.map_err(|source| UpgradeError::HostLock {
            path: path.clone(),
            source,
        })?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file, path })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(source)) => {
                Err(UpgradeError::HostLock { path, source })
            }
        }
    }

    /// Take the lock, waiting at most `timeout` for another writer.
    pub async fn acquire(
        target: &Path,
        timeout: std::time::Duration,
    ) -> Result<Self, UpgradeError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(lock) = Self::try_acquire(target)? {
                return Ok(lock);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(UpgradeError::HostLockBusy {
                    path: Self::lock_path_for(target),
                    waited_secs: timeout.as_secs(),
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    /// Path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// SHA-256 of a file, streamed.
pub fn sha256_file(path: &Path) -> Result<[u8; 32], UpgradeError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|e| UpgradeError::Other(format!("cannot read {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| UpgradeError::Other(format!("cannot read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// The newest versioned backup of `target` that `from_version` made, if any.
///
/// The transactional handoff and the supervised-exit intent record name this
/// path as `backup_path`. When this process did not swap (another writer on
/// the host did), the other writer's backup of the same running version is
/// the previous bytes.
pub fn latest_versioned_backup(target: &Path, from_version: &str) -> Option<PathBuf> {
    let name = target.file_name()?.to_string_lossy().into_owned();
    let prefix = format!("{name}.backup-{from_version}-");
    let dir = target.parent()?;
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|entry| {
            entry.file_name().to_string_lossy().starts_with(&prefix)
                && entry.file_type().is_ok_and(|t| t.is_file())
        })
        .filter_map(|entry| {
            let modified = entry.metadata().and_then(|m| m.modified()).ok()?;
            Some((modified, entry.path()))
        })
        .max()
        .map(|(_, path)| path)
}

/// fsync the directory that holds `path`, so a rename in it is durable.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

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
    /// SHA-256 of the bytes this process runs, when the target is this
    /// process's own executable (#1106 F1 version evidence).
    running_sha256: Option<[u8; 32]>,
    /// The release this daemon ran before the current one (its last
    /// known-good predecessor), kept by retention (D194, review S3).
    previous_release: Option<Version>,
}

/// What a host-locked swap does, decided under the lock before any binary
/// changes (#1106 F1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockedSwapPlan {
    /// The installed bytes already equal the verified binary.
    AlreadyInstalled,
    /// Replace the installed release, which is older than the target.
    Replace {
        /// The release now installed, from verified evidence.
        installed_release: Version,
        /// SHA-256 of the installed bytes.
        installed_sha256: [u8; 32],
    },
}

/// Verified evidence of the release installed at a target (#1106 F1):
/// `<install dir>/.<binary>.installed.json`, written under the host lock
/// after each swap. It counts only while its hash matches the installed bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstallRecord {
    /// Always [`INSTALL_RECORD_FORMAT`].
    pub format: String,
    /// Always [`INSTALL_RECORD_VERSION`].
    pub version: u32,
    /// The installed release (semver).
    pub release: String,
    /// Hex SHA-256 of the installed bytes.
    pub sha256: String,
}

/// `format` marker of [`InstallRecord`].
pub const INSTALL_RECORD_FORMAT: &str = "x0x.upgrade-install";
/// Current `version` of [`InstallRecord`].
pub const INSTALL_RECORD_VERSION: u32 = 1;

impl InstallRecord {
    /// The record file for the binary at `target`.
    pub fn path_for(target: &Path) -> PathBuf {
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "x0xd".to_string());
        let dir = target.parent().unwrap_or_else(|| Path::new("."));
        dir.join(format!(".{name}.installed.json"))
    }

    /// Read the record for `target`. `None` when missing, unparseable or of
    /// another format: then it is no evidence, and the swap fails closed.
    pub fn read(target: &Path) -> Option<Self> {
        let bytes = std::fs::read(Self::path_for(target)).ok()?;
        serde_json::from_slice::<Self>(&bytes)
            .ok()
            .filter(|r| r.format == INSTALL_RECORD_FORMAT && r.version == INSTALL_RECORD_VERSION)
    }

    /// The installed release this record proves for bytes with `sha256`.
    pub fn release_for(&self, sha256: &[u8; 32]) -> Option<Version> {
        if self.sha256 != hex::encode(sha256) {
            return None;
        }
        Version::parse(&self.release).ok()
    }

    /// Write the record for `target` with a record barrier (temp file,
    /// fsync, rename, directory fsync).
    pub fn write(target: &Path, release: &Version, sha256: &[u8; 32]) -> std::io::Result<()> {
        use std::io::Write;
        let record = Self {
            format: INSTALL_RECORD_FORMAT.to_string(),
            version: INSTALL_RECORD_VERSION,
            release: release.to_string(),
            sha256: hex::encode(sha256),
        };
        let json = serde_json::to_vec_pretty(&record).map_err(std::io::Error::other)?;
        let path = Self::path_for(target);
        let mut tmp_name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        tmp_name.push(format!(".tmp-{}", std::process::id()));
        let tmp = path.with_file_name(tmp_name);
        let written = std::fs::File::create(&tmp).and_then(|mut file| {
            file.write_all(&json)?;
            file.sync_all()
        });
        if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, &path)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        sync_parent_dir(&path)
    }
}

/// Release marker embedded in every x0x binary built from this crate
/// (#1106 review R2/R3): `X0X-RELEASE-MARKER:<version>:END` in read-only
/// data. Both `x0xd` and `x0x` reference it at start, so the linker keeps it.
/// It lets a writer read the release of installed bytes from the bytes.
pub const RELEASE_MARKER: &str = concat!("X0X-RELEASE-MARKER:", env!("CARGO_PKG_VERSION"), ":END");

/// The release embedded in the bytes at `path`: `Some` when the bytes carry
/// exactly one marker release, `None` when they carry none (a binary from
/// before 0.48.1) or markers of different releases.
pub fn embedded_release(path: &Path) -> Result<Option<Version>, UpgradeError> {
    // The needle is built at run time, so this function's own bytes do not
    // add a second copy of the prefix to the binary.
    let prefix: Vec<u8> = MARKER_PREFIX_REVERSED.iter().rev().copied().collect();
    let bytes = std::fs::read(path)
        .map_err(|e| UpgradeError::Other(format!("cannot read {}: {e}", path.display())))?;
    let mut found: Option<Version> = None;
    let mut at = 0;
    while let Some(offset) = find_subslice(&bytes[at..], &prefix) {
        let start = at + offset + prefix.len();
        at = start;
        let window = &bytes[start..bytes.len().min(start + 64)];
        let Some(end) = find_subslice(window, b":END") else {
            continue;
        };
        let Some(release) = std::str::from_utf8(&window[..end])
            .ok()
            .and_then(|v| Version::parse(v).ok())
        else {
            continue;
        };
        match &found {
            None => found = Some(release),
            Some(seen) if *seen == release => {}
            Some(_) => return Ok(None), // two releases: no evidence
        }
    }
    Ok(found)
}

/// `"X0X-RELEASE-MARKER:"` reversed.
const MARKER_PREFIX_REVERSED: &[u8] = b":REKRAM-ESAELER-X0X";

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        match haystack[i..].iter().position(|b| *b == first) {
            Some(p) => i += p,
            None => return None,
        }
        if haystack.get(i..i + needle.len()) == Some(needle) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The upgrader for the companion `x0x` CLI beside the daemon.
///
/// Review R3: the CLI needs its own version evidence (the marker in its
/// bytes or its own matching install record). The daemon's release is never
/// assumed for unknown CLI bytes, so an interrupted pair swap or a separate
/// CLI install cannot be downgraded. The daemon's swap plan is decided
/// first and is not used as CLI evidence.
pub fn companion_upgrader(
    cli_path: PathBuf,
    current_version: Version,
    _daemon_plan: &LockedSwapPlan,
    _target_version: &Version,
) -> Upgrader {
    Upgrader::new(cli_path, current_version)
}

/// SHA-256 of the bytes this process runs, computed once (#1106 F1).
///
/// Linux only: `/proc/self/exe` names the running image even after a rename
/// replaced the installed file, so the hash is bound to the running image.
/// Elsewhere a pathname hash could be the hash of bytes another daemon
/// installed later (review R2), so there is no such evidence (`None`) and
/// the swap relies on the release marker in the installed bytes or a
/// matching install record.
pub fn running_binary_sha256() -> Option<[u8; 32]> {
    #[cfg(target_os = "linux")]
    {
        static RUNNING: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();
        *RUNNING.get_or_init(|| sha256_file(Path::new("/proc/self/exe")).ok())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

impl Upgrader {
    pub fn new(target_path: PathBuf, current_version: Version) -> Self {
        Self {
            target_path,
            current_version,
            running_sha256: None,
            previous_release: None,
        }
    }

    /// Supply the SHA-256 of the bytes this process runs (#1106 F1). When it
    /// equals the installed bytes, the installed release is this process's
    /// version.
    pub fn with_running_sha256(mut self, running_sha256: Option<[u8; 32]>) -> Self {
        self.running_sha256 = running_sha256;
        self
    }

    /// The release this daemon ran before the current one (D194, review S3):
    /// retention never deletes its backup.
    pub fn with_previous_release(mut self, previous_release: Option<Version>) -> Self {
        self.previous_release = previous_release;
        self
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

    /// The versioned backup name for the bytes now at the target:
    /// `<binary>.backup-<their release>-<first 8 hex of their SHA-256>`.
    /// The release is the installed release from verified evidence, not
    /// the running version (#1106 F1).
    pub fn versioned_backup_path(&self, release: &Version, previous_sha256: &[u8; 32]) -> PathBuf {
        let name = self
            .target_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "x0xd".to_string());
        self.target_path.with_file_name(format!(
            "{name}.backup-{release}-{}",
            hex::encode(&previous_sha256[..4])
        ))
    }

    /// Copy the bytes now at the target to their versioned backup name.
    ///
    /// The copy is staged in `staging_dir`, fsynced, renamed into place and
    /// the directory fsynced. An existing backup with the same name and
    /// the same bytes is reused. A different file under that name is never
    /// overwritten (ADR 0094 §3): the apply is refused before any swap.
    fn create_versioned_backup(
        &self,
        release: &Version,
        previous_sha256: &[u8; 32],
        staging_dir: &Path,
    ) -> Result<PathBuf, UpgradeError> {
        let backup_path = self.versioned_backup_path(release, previous_sha256);
        let backup_failed = |source: std::io::Error| UpgradeError::BackupFailed {
            path: backup_path.clone(),
            source,
        };
        if backup_path.exists() {
            if sha256_file(&backup_path)? == *previous_sha256 {
                debug!(backup_path = %backup_path.display(), "Versioned backup already holds these bytes");
                return Ok(backup_path);
            }
            return Err(backup_failed(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "a different file already holds this versioned backup name; \
                 refusing to overwrite a rollback copy",
            )));
        }
        let staged = staging_dir.join("previous-binary");
        std::fs::copy(&self.target_path, &staged).map_err(backup_failed)?;
        std::fs::File::open(&staged)
            .and_then(|f| f.sync_all())
            .map_err(backup_failed)?;
        if sha256_file(&staged)? != *previous_sha256 {
            let _ = std::fs::remove_file(&staged);
            return Err(backup_failed(std::io::Error::other(
                "the installed binary changed while it was copied",
            )));
        }
        std::fs::rename(&staged, &backup_path).map_err(backup_failed)?;
        sync_parent_dir(&backup_path).map_err(backup_failed)?;
        Ok(backup_path)
    }

    /// Host-locked swap (#1106): one writer per install.
    ///
    /// The caller holds the [`HostUpgradeLock`] for `target_path` and has
    /// verified `new_binary`. When the installed bytes already equal
    /// `new_binary`, another writer on this host has installed them: nothing
    /// is copied or replaced. Otherwise the previous bytes go to a versioned
    /// backup that no later writer overwrites, and then the new bytes replace
    /// the target. `staging_dir` must be on the target's filesystem.
    /// The installed release for bytes with `installed_sha256`, from
    /// verified evidence only.
    ///
    /// Evidence order (review R2): the release marker in the installed bytes
    /// themselves, then an install record whose hash matches, then (Linux
    /// only) the hash of the running image.
    fn installed_release(&self, installed_sha256: &[u8; 32]) -> Option<Version> {
        if let Ok(Some(release)) = embedded_release(&self.target_path) {
            return Some(release);
        }
        if let Some(release) =
            InstallRecord::read(&self.target_path).and_then(|r| r.release_for(installed_sha256))
        {
            return Some(release);
        }
        if self.running_sha256.as_ref() == Some(installed_sha256) {
            return Some(self.current_version.clone());
        }
        None
    }

    /// Decide the swap under the lock, before any binary changes (#1106 F1).
    ///
    /// The installed bytes and their release are checked under the lock.
    /// Equal bytes need no swap. Otherwise the installed release must be
    /// known from verified evidence and older than the target; a newer or
    /// equal installed release (another writer on this host installed it)
    /// and unknown bytes are refused.
    pub fn plan_locked_swap(
        &self,
        _lock: &HostUpgradeLock,
        new_binary_path: &Path,
        target_version: &Version,
    ) -> Result<LockedSwapPlan, UpgradeError> {
        self.validate_upgrade(target_version)?;
        let new_sha256 = sha256_file(new_binary_path)?;
        let installed_sha256 = sha256_file(&self.target_path)?;
        if new_sha256 == installed_sha256 {
            return Ok(LockedSwapPlan::AlreadyInstalled);
        }
        let installed_release = self.installed_release(&installed_sha256).ok_or_else(|| {
            UpgradeError::InstalledReleaseUnknown {
                path: self.target_path.clone(),
            }
        })?;
        if &installed_release >= target_version {
            warn!(
                target = %self.target_path.display(),
                installed = %installed_release,
                requested = %target_version,
                "Refusing to replace an installed release that is not older than the target"
            );
            return Err(UpgradeError::InstalledReleaseNotOlder {
                installed: installed_release.to_string(),
                target: target_version.to_string(),
            });
        }
        Ok(LockedSwapPlan::Replace {
            installed_release,
            installed_sha256,
        })
    }

    pub fn perform_locked_upgrade(
        &self,
        lock: &HostUpgradeLock,
        new_binary_path: &Path,
        target_version: &Version,
        staging_dir: &Path,
    ) -> Result<SwapOutcome, UpgradeError> {
        let (installed_release, installed_sha256) =
            match self.plan_locked_swap(lock, new_binary_path, target_version)? {
                LockedSwapPlan::AlreadyInstalled => {
                    info!(
                        target = %self.target_path.display(),
                        version = %target_version,
                        "Installed binary already matches the verified release; another \
                         writer on this host swapped it, so this writer skips the swap"
                    );
                    if let Err(e) = InstallRecord::write(
                        &self.target_path,
                        target_version,
                        &sha256_file(new_binary_path)?,
                    ) {
                        debug!(error = %e, "Failed to refresh the install record");
                    }
                    return Ok(SwapOutcome::AlreadyInstalled);
                }
                LockedSwapPlan::Replace {
                    installed_release,
                    installed_sha256,
                } => (installed_release, installed_sha256),
            };
        let new_sha256 = sha256_file(new_binary_path)?;

        let backup_path =
            self.create_versioned_backup(&installed_release, &installed_sha256, staging_dir)?;
        info!(backup_path = %backup_path.display(), "Previous binary kept as a versioned backup");

        info!("Replacing binary...");
        match self.atomic_replace(new_binary_path) {
            Ok(()) => {
                if let Err(e) = sync_parent_dir(&self.target_path) {
                    debug!(error = %e, "Directory fsync after the binary swap failed");
                }
                // Evidence for the next writer on this host: these bytes are
                // this release (#1106 F1).
                if let Err(e) = InstallRecord::write(&self.target_path, target_version, &new_sha256)
                {
                    warn!(error = %e, "Failed to write the install record after the swap");
                }
                info!(version = %target_version, "Successfully upgraded to version {}", target_version);
                // No automatic pruning (review R4): before ADR 0094 M2 there
                // is no host-commit evidence for the last known-good pair
                // (D194), so every versioned backup stays until an operator
                // removes it.
                Ok(SwapOutcome::Swapped { backup_path })
            }
            Err(replace_err) => {
                warn!(error = %replace_err, "Binary replacement failed: {}", replace_err);
                // A failed rename leaves the target as it was. Put the
                // previous bytes back only if the target changed anyway.
                if sha256_file(&self.target_path).ok() == Some(installed_sha256) {
                    return Ok(SwapOutcome::RolledBack {
                        reason: format!("Replacement failed: {replace_err}"),
                    });
                }
                // Copy, then rename over the target: a rename is valid even
                // when the target is a running executable, and the backup
                // stays in place for the next attempt.
                let restoring = staging_dir.join("restore-binary");
                let restore = std::fs::copy(&backup_path, &restoring)
                    .and_then(|_| std::fs::rename(&restoring, &self.target_path))
                    .map_err(|source| UpgradeError::RestoreFailed {
                        backup_path: backup_path.clone(),
                        target_path: self.target_path.clone(),
                        source,
                    });
                match restore {
                    Ok(()) => Ok(SwapOutcome::RolledBack {
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

    /// The host upgrade lock file could not be opened or locked (#1106).
    #[error("host upgrade lock {path} failed: {source}")]
    HostLock {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The installed release is the target or newer (#1106 F1): another
    /// writer on this host installed it. Nothing was replaced.
    #[error(
        "installed release {installed} is not older than target {target}; refusing to replace it"
    )]
    InstalledReleaseNotOlder { installed: String, target: String },

    /// No verified evidence names the installed bytes (#1106 F1): they are
    /// not this process's bytes and no install record matches them.
    #[error("the release installed at {path} is unknown (not this process's bytes, no matching install record); refusing to replace it")]
    InstalledReleaseUnknown { path: PathBuf },

    /// A shared install still has participants whose wait is not served
    /// (#1106 review F2, ADR 0094 §1). Nothing was replaced; this is a wait,
    /// not a failure.
    #[error("shared install: participants are not yet due for {release}: {}", pending.join("; "))]
    ParticipantsNotDue {
        release: String,
        pending: Vec<String>,
    },

    /// The participants of a shared install cannot be established (#1106
    /// review F2). The swap is refused.
    #[error("shared install: participants cannot be established: {reason}")]
    ParticipantsUnknown { reason: String },

    /// Staging would leave less than the 1 GiB disk reserve (D194, review
    /// S3). Nothing was downloaded; this is not counted as a failure.
    #[error("insufficient_disk: {available} bytes free, an apply needs {needed} plus a {reserve}-byte reserve")]
    InsufficientDisk {
        available: u64,
        needed: u64,
        reserve: u64,
    },

    /// Another writer on this host held the upgrade lock for the whole wait
    /// (#1106). Nothing was replaced.
    #[error("host upgrade lock {path} still held by another writer after {waited_secs}s")]
    HostLockBusy { path: PathBuf, waited_secs: u64 },

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

    // ------------------------------------------------------------------
    // #1106: one binary writer per host, versioned backups.
    // ------------------------------------------------------------------

    const OLD_BYTES: &[u8] = b"x0xd 0.48.0 bytes that serve today";
    const NEW_BYTES: &[u8] = b"x0xd 0.48.1 bytes from the verified archive";

    fn expected_backup_name(previous: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(previous).into();
        format!("x0xd.backup-0.48.0-{}", hex::encode(&digest[..4]))
    }

    fn backup_files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("x0xd.backup"))
            .collect();
        names.sort();
        names
    }

    /// One writer: take the host lock (bounded spin), swap, release.
    fn locked_writer(target: &Path, staging: &Path, new_binary: &Path) -> SwapOutcome {
        locked_writer_for(target, staging, new_binary, &Version::new(0, 48, 1)).unwrap()
    }

    fn sha(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }

    fn take_lock(target: &Path) -> HostUpgradeLock {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(lock) = HostUpgradeLock::try_acquire(target).unwrap() {
                return lock;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the other writer must release the host lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// One writer that runs 0.48.0 (its running bytes are `OLD_BYTES`) and
    /// applies `target_version` from `new_binary` under the host lock.
    fn locked_writer_for(
        target: &Path,
        staging: &Path,
        new_binary: &Path,
        target_version: &Version,
    ) -> Result<SwapOutcome, UpgradeError> {
        let lock = take_lock(target);
        let upgrader = Upgrader::new(target.to_path_buf(), Version::new(0, 48, 0))
            .with_running_sha256(Some(sha(OLD_BYTES)));
        let outcome = upgrader.perform_locked_upgrade(&lock, new_binary, target_version, staging);
        drop(lock);
        outcome
    }

    fn staged_binary(dir: &Path, tag: &str, bytes: &[u8]) -> (PathBuf, PathBuf) {
        let staging = dir.join(format!(".x0x-upgrade-{tag}"));
        fs::create_dir_all(&staging).unwrap();
        let new_binary = staging.join("extracted-binary");
        fs::write(&new_binary, bytes).unwrap();
        (staging, new_binary)
    }

    const NEW_0482: &[u8] = b"x0xd 0.48.2 bytes from a later verified archive";
    const NEW_0483: &[u8] = b"x0xd 0.48.3 bytes from the next verified archive";

    #[test]
    fn a_late_writer_with_an_older_release_never_downgrades_the_install() {
        // Codex F1: A and B both run 0.48.0. A installs 0.48.2. B holds a
        // valid 0.48.1 manifest and gets the lock later. B must refuse
        // before any binary changes.
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        let (staging_a, new_a) = staged_binary(dir.path(), "a", NEW_0482);
        let a = locked_writer_for(&target, &staging_a, &new_a, &Version::new(0, 48, 2)).unwrap();
        assert!(matches!(a, SwapOutcome::Swapped { .. }), "{a:?}");

        let (staging_b, new_b) = staged_binary(dir.path(), "b", NEW_BYTES);
        let b = locked_writer_for(&target, &staging_b, &new_b, &Version::new(0, 48, 1));
        assert!(
            matches!(b, Err(UpgradeError::InstalledReleaseNotOlder { ref installed, ref target })
                if installed == "0.48.2" && target == "0.48.1"),
            "an older target must be refused: {b:?}"
        );
        assert_eq!(
            fs::read(&target).unwrap(),
            NEW_0482,
            "0.48.2 stays installed"
        );
        assert_eq!(
            backup_files(dir.path()),
            vec![expected_backup_name(OLD_BYTES)],
            "the refused writer saved nothing"
        );
    }

    #[test]
    fn the_backup_is_named_from_the_bytes_being_saved() {
        // The process runs 0.48.0, but another writer installed 0.48.2. The
        // backup of the 0.48.2 bytes must say 0.48.2, not 0.48.0.
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        let (staging_a, new_a) = staged_binary(dir.path(), "a", NEW_0482);
        locked_writer_for(&target, &staging_a, &new_a, &Version::new(0, 48, 2)).unwrap();
        let (staging_c, new_c) = staged_binary(dir.path(), "c", NEW_0483);
        let c = locked_writer_for(&target, &staging_c, &new_c, &Version::new(0, 48, 3)).unwrap();
        let SwapOutcome::Swapped { backup_path } = c else {
            panic!("0.48.3 replaces 0.48.2: {c:?}");
        };
        assert_eq!(
            backup_path.file_name().unwrap().to_string_lossy(),
            format!("x0xd.backup-0.48.2-{}", hex::encode(&sha(NEW_0482)[..4]))
        );
        assert_eq!(fs::read(&backup_path).unwrap(), NEW_0482);
        assert_eq!(fs::read(&target).unwrap(), NEW_0483);
    }

    #[test]
    fn unknown_installed_bytes_are_never_replaced() {
        // The installed bytes are not this process's bytes and no install
        // record names them (for example a hand copy without a restart).
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", b"bytes from an unknown copy");
        let (staging, new_binary) = staged_binary(dir.path(), "u", NEW_BYTES);
        let outcome = locked_writer_for(&target, &staging, &new_binary, &Version::new(0, 48, 1));
        assert!(
            matches!(outcome, Err(UpgradeError::InstalledReleaseUnknown { .. })),
            "{outcome:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), b"bytes from an unknown copy");
        assert!(backup_files(dir.path()).is_empty());
    }

    #[test]
    fn pruning_keeps_the_running_known_good_backup_after_an_uncommitted_swap() {
        // Codex F6: 0.48.0 serves; an earlier swap installed 0.48.1 but its
        // restart failed, so 0.48.0 still runs. Hours later the same process
        // applies 0.48.2. The 0.48.0 copy is the last known-good release and
        // must survive; only releases older than it may go.
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        let (staging_a, new_a) = staged_binary(dir.path(), "a", NEW_BYTES);
        locked_writer_for(&target, &staging_a, &new_a, &Version::new(0, 48, 1)).unwrap();
        let known_good = dir.path().join(expected_backup_name(OLD_BYTES));
        age_file(&known_good, std::time::Duration::from_secs(7200));
        let ancient = dir.path().join("x0xd.backup-0.47.1-0badc0de");
        fs::write(&ancient, b"0.47.1").unwrap();
        age_file(&ancient, std::time::Duration::from_secs(7200));

        let (staging_b, new_b) = staged_binary(dir.path(), "b", NEW_0482);
        let b = locked_writer_for(&target, &staging_b, &new_b, &Version::new(0, 48, 2)).unwrap();
        assert!(matches!(b, SwapOutcome::Swapped { .. }), "{b:?}");
        assert!(
            known_good.exists(),
            "the running release's backup is the last known-good copy"
        );
        assert_eq!(fs::read(&known_good).unwrap(), OLD_BYTES);
        // Review R4: without host-commit evidence nothing is pruned, so the
        // older copy stays too.
        assert!(
            ancient.exists(),
            "no backup is deleted without commit evidence"
        );
    }

    // A real two-process case (#1106 acceptance): the test binary re-runs
    // itself twice as plain processes. No socket, no daemon.
    const CHILD_TARGET: &str = "X0X_1106_CHILD_TARGET";
    const CHILD_STAGING: &str = "X0X_1106_CHILD_STAGING";
    const CHILD_GO: &str = "X0X_1106_CHILD_GO";
    const CHILD_OUT: &str = "X0X_1106_CHILD_OUT";

    #[test]
    fn two_process_writer_child() {
        // A no-op unless the two-process test below started this process.
        let (Ok(target), Ok(staging), Ok(go), Ok(out)) = (
            std::env::var(CHILD_TARGET),
            std::env::var(CHILD_STAGING),
            std::env::var(CHILD_GO),
            std::env::var(CHILD_OUT),
        ) else {
            return;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !Path::new(&go).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "start signal never came"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let staging = PathBuf::from(staging);
        let outcome = locked_writer(
            Path::new(&target),
            &staging,
            &staging.join("extracted-binary"),
        );
        fs::write(out, format!("{outcome:?}")).unwrap();
    }

    #[test]
    fn two_processes_on_one_install_swap_once_and_keep_a_versioned_backup() {
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        let go = dir.path().join("go");
        let exe = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..2)
            .map(|i| {
                let (staging, _) = staged_binary(dir.path(), &format!("p{i}"), NEW_BYTES);
                let out = dir.path().join(format!("outcome-{i}"));
                let child = std::process::Command::new(&exe)
                    .args([
                        "--exact",
                        "upgrade::tests::two_process_writer_child",
                        "--test-threads=1",
                        "--quiet",
                    ])
                    .env(CHILD_TARGET, &target)
                    .env(CHILD_STAGING, &staging)
                    .env(CHILD_GO, &go)
                    .env(CHILD_OUT, &out)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                (child, out)
            })
            .collect();
        fs::write(&go, b"go").unwrap();
        let mut outcomes = Vec::new();
        for (mut child, out) in children {
            assert!(child.wait().unwrap().success(), "a writer process failed");
            outcomes.push(fs::read_to_string(out).unwrap());
        }
        outcomes.sort();
        assert_eq!(
            outcomes.iter().filter(|o| o.starts_with("Swapped")).count(),
            1,
            "exactly one process swaps: {outcomes:?}"
        );
        assert!(
            outcomes.iter().any(|o| o == "AlreadyInstalled"),
            "the other process finds the bytes installed: {outcomes:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), NEW_BYTES);
        assert_eq!(
            fs::read(dir.path().join(expected_backup_name(OLD_BYTES))).unwrap(),
            OLD_BYTES,
            "a valid previous-version backup survives"
        );
        assert_eq!(
            backup_files(dir.path()),
            vec![expected_backup_name(OLD_BYTES)]
        );
    }

    #[test]
    fn the_host_lock_admits_one_holder_at_a_time() {
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        let first = HostUpgradeLock::try_acquire(&target)
            .unwrap()
            .expect("the first writer takes the lock");
        assert!(
            HostUpgradeLock::try_acquire(&target).unwrap().is_none(),
            "a second writer must wait while the first holds the lock"
        );
        drop(first);
        assert!(
            HostUpgradeLock::try_acquire(&target).unwrap().is_some(),
            "the lock is free again once its holder drops it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_host_lock_works_on_a_read_only_lock_file() {
        // Codex R1: a second service account may only read a lock file the
        // first account created; flock needs no write access.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        drop(HostUpgradeLock::try_acquire(&target).unwrap().unwrap());
        let lock_path = HostUpgradeLock::lock_path_for(&target);
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o444)).unwrap();
        let held = HostUpgradeLock::try_acquire(&target)
            .unwrap()
            .expect("a read-only lock file still locks");
        assert!(HostUpgradeLock::try_acquire(&target).unwrap().is_none());
        drop(held);
    }

    #[test]
    fn two_writers_on_one_install_swap_once_and_keep_a_versioned_backup() {
        // x0xd and x0xd-443 share /opt/x0x/x0xd and apply the same release
        // at about the same moment (the 2026-10-14 prod event).
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|i| {
                let staging = dir.path().join(format!(".x0x-upgrade-test-{i}"));
                fs::create_dir_all(&staging).unwrap();
                let new_binary = staging.join("extracted-binary");
                fs::write(&new_binary, NEW_BYTES).unwrap();
                let target = target.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    locked_writer(&target, &staging, &new_binary)
                })
            })
            .collect();
        let outcomes: Vec<SwapOutcome> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let swapped: Vec<&SwapOutcome> = outcomes
            .iter()
            .filter(|o| matches!(o, SwapOutcome::Swapped { .. }))
            .collect();
        assert_eq!(swapped.len(), 1, "exactly one swap per host: {outcomes:?}");
        assert!(
            outcomes.contains(&SwapOutcome::AlreadyInstalled),
            "the second writer sees the bytes installed and skips: {outcomes:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), NEW_BYTES);

        let SwapOutcome::Swapped { backup_path } = swapped[0] else {
            unreachable!("filtered above");
        };
        assert_eq!(
            backup_path.file_name().unwrap().to_string_lossy(),
            expected_backup_name(OLD_BYTES)
        );
        assert_eq!(
            fs::read(backup_path).unwrap(),
            OLD_BYTES,
            "the backup holds the bytes that served before the swap"
        );
        assert_eq!(
            backup_files(dir.path()),
            vec![expected_backup_name(OLD_BYTES)],
            "one versioned backup and no legacy single-slot x0xd.backup"
        );
    }

    #[test]
    fn a_late_second_writer_never_overwrites_the_backup_with_new_bytes() {
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        let mut outcomes = Vec::new();
        for i in 0..2 {
            let staging = dir.path().join(format!(".x0x-upgrade-late-{i}"));
            fs::create_dir_all(&staging).unwrap();
            let new_binary = staging.join("extracted-binary");
            fs::write(&new_binary, NEW_BYTES).unwrap();
            outcomes.push(locked_writer(&target, &staging, &new_binary));
        }
        assert!(matches!(outcomes[0], SwapOutcome::Swapped { .. }));
        assert_eq!(outcomes[1], SwapOutcome::AlreadyInstalled);
        let backup = dir.path().join(expected_backup_name(OLD_BYTES));
        assert_eq!(fs::read(&backup).unwrap(), OLD_BYTES);
        assert_eq!(
            backup_files(dir.path()),
            vec![expected_backup_name(OLD_BYTES)]
        );
        assert_eq!(
            latest_versioned_backup(&target, "0.48.0"),
            Some(backup),
            "the handoff record can name this transaction's backup"
        );
    }

    #[test]
    fn a_swap_deletes_no_backup_without_host_commit_evidence() {
        // Codex R4: no host-commit state exists before ADR 0094 M2, so no
        // backup has the evidence D194 needs before deletion. A swap keeps
        // every versioned backup, the legacy one and operator copies.
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        let older = dir.path().join("x0xd.backup-0.47.1-0badc0de");
        fs::write(&older, b"0.47.1").unwrap();
        age_file(&older, std::time::Duration::from_secs(7200));
        let fresh = dir.path().join("x0xd.backup-0.47.2-0123abcd");
        fs::write(&fresh, b"0.47.2").unwrap();
        let legacy = dir.path().join("x0xd.backup");
        fs::write(&legacy, b"legacy").unwrap();
        let companion = dir.path().join("x0x.backup-0.47.1-0badc0de");
        fs::write(&companion, b"cli").unwrap();
        age_file(&companion, std::time::Duration::from_secs(7200));
        let ops_copy = dir.path().join("x0xd.v0480-pre0481");
        fs::write(&ops_copy, b"ops").unwrap();

        let staging = dir.path().join(".x0x-upgrade-prune");
        fs::create_dir_all(&staging).unwrap();
        let new_binary = staging.join("extracted-binary");
        fs::write(&new_binary, NEW_BYTES).unwrap();
        let outcome = locked_writer(&target, &staging, &new_binary);

        let SwapOutcome::Swapped { backup_path } = outcome else {
            panic!("expected a swap, got {outcome:?}");
        };
        assert!(backup_path.exists());
        for kept in [&older, &fresh, &legacy, &companion, &ops_copy] {
            assert!(kept.exists(), "{} must be kept", kept.display());
        }
    }

    #[test]
    fn a_marker_alone_is_not_version_evidence() {
        // Codex S2: a hand copy or partial file can keep a whole marker. With
        // no hash-bound evidence the bytes are unknown.
        let dir = TempDir::new().unwrap();
        let installed = marked("0.48.0", b"hand copy, maybe partial");
        let target = create_test_binary(&dir, "x0xd", &installed);
        let (staging, new_binary) = staged_binary(dir.path(), "s2a", &marked("0.48.1", b"new"));
        let lock = take_lock(&target);
        let outcome = Upgrader::new(target.clone(), Version::new(0, 48, 0)).perform_locked_upgrade(
            &lock,
            &new_binary,
            &Version::new(0, 48, 1),
            &staging,
        );
        assert!(
            matches!(outcome, Err(UpgradeError::InstalledReleaseUnknown { .. })),
            "{outcome:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), installed);
    }

    #[test]
    fn a_marker_that_disagrees_with_hash_bound_evidence_is_unknown() {
        // Codex S2: a false low marker must not defeat the version guard.
        let dir = TempDir::new().unwrap();
        let installed = marked("0.48.0", b"bytes the updater recorded as 0.48.2");
        let target = create_test_binary(&dir, "x0xd", &installed);
        InstallRecord::write(&target, &Version::new(0, 48, 2), &sha(&installed)).unwrap();
        let (staging, new_binary) = staged_binary(dir.path(), "s2b", &marked("0.48.1", b"new"));
        let lock = take_lock(&target);
        let outcome = Upgrader::new(target.clone(), Version::new(0, 48, 0)).perform_locked_upgrade(
            &lock,
            &new_binary,
            &Version::new(0, 48, 1),
            &staging,
        );
        assert!(
            matches!(outcome, Err(UpgradeError::InstalledReleaseUnknown { .. })),
            "{outcome:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), installed);
    }

    #[test]
    fn a_marker_that_agrees_with_the_install_record_counts() {
        let dir = TempDir::new().unwrap();
        let installed = marked("0.48.2", b"recorded bytes");
        let target = create_test_binary(&dir, "x0xd", &installed);
        InstallRecord::write(&target, &Version::new(0, 48, 2), &sha(&installed)).unwrap();
        let (staging, new_binary) = staged_binary(dir.path(), "s2c", &marked("0.48.1", b"new"));
        let lock = take_lock(&target);
        let outcome = Upgrader::new(target.clone(), Version::new(0, 48, 0)).perform_locked_upgrade(
            &lock,
            &new_binary,
            &Version::new(0, 48, 1),
            &staging,
        );
        assert!(
            matches!(outcome, Err(UpgradeError::InstalledReleaseNotOlder { ref installed, .. })
                if installed == "0.48.2"),
            "{outcome:?}"
        );
    }

    #[test]
    fn retention_keeps_the_known_good_pair_and_the_newest_three() {
        // Codex S3 / D194 (controller ruling): never delete the backup of
        // the release this daemon runs or of the one it ran before; keep the
        // newest three versioned backups; delete only older ones.
        let dir = TempDir::new().unwrap();
        let target = create_test_binary(&dir, "x0xd", OLD_BYTES);
        let backup = |release: &str| dir.path().join(format!("x0xd.backup-{release}-0badc0de"));
        for release in ["0.46.0", "0.47.0", "0.47.1", "0.47.2", "0.47.3"] {
            fs::write(backup(release), release.as_bytes()).unwrap();
        }
        let companion = dir.path().join("x0x.backup-0.46.0-0badc0de");
        fs::write(&companion, b"cli").unwrap();
        let (staging, new_binary) = staged_binary(dir.path(), "s3", NEW_BYTES);
        let lock = take_lock(&target);
        let outcome = Upgrader::new(target.clone(), Version::new(0, 48, 0))
            .with_running_sha256(Some(sha(OLD_BYTES)))
            .with_previous_release(Some(Version::new(0, 47, 1)))
            .perform_locked_upgrade(&lock, &new_binary, &Version::new(0, 48, 1), &staging)
            .unwrap();
        let SwapOutcome::Swapped { backup_path } = outcome else {
            panic!("expected a swap");
        };
        assert!(
            backup_path.exists(),
            "the backup of the running release stays"
        );
        assert!(
            backup("0.47.1").exists(),
            "the previous known-good release stays"
        );
        assert!(
            backup("0.47.3").exists() && backup("0.47.2").exists(),
            "newest three stay"
        );
        assert!(!backup("0.47.0").exists(), "older backups go");
        assert!(!backup("0.46.0").exists(), "older backups go");
        assert!(
            companion.exists(),
            "another binary's backups are not touched"
        );
    }

    #[test]
    fn the_disk_reserve_refuses_staging_below_one_gib() {
        // D194 (review S3): refuse staging when it would leave less than
        // 1 GiB free; report insufficient_disk.
        let gib = DISK_RESERVE_BYTES;
        assert!(check_disk_reserve(10 * gib, gib).is_ok());
        let refused = check_disk_reserve(gib + 100, 200).unwrap_err();
        assert!(matches!(refused, UpgradeError::InsufficientDisk { .. }));
        assert!(
            refused.to_string().starts_with("insufficient_disk"),
            "{refused}"
        );
        assert!(check_disk_reserve(100, 200).is_err());
        assert!(free_space_bytes(std::env::temp_dir().as_path()).is_some_and(|b| b > 0));
    }

    fn marked(release: &str, filler: &[u8]) -> Vec<u8> {
        let mut bytes = filler.to_vec();
        bytes.extend_from_slice(b"\0\x7f padding ");
        bytes.extend_from_slice(format!("X0X-RELEASE-MARKER:{release}:END").as_bytes());
        bytes.extend_from_slice(b" more data\0");
        bytes
    }

    #[test]
    fn embedded_release_reads_the_one_marker_in_the_bytes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("x0xd");
        fs::write(&path, marked("0.48.2", b"elf")).unwrap();
        assert_eq!(
            embedded_release(&path).unwrap(),
            Some(Version::new(0, 48, 2))
        );
        // A fat binary carries the same marker twice: still one release.
        let mut twice = marked("0.48.2", b"a");
        twice.extend(marked("0.48.2", b"b"));
        fs::write(&path, &twice).unwrap();
        assert_eq!(
            embedded_release(&path).unwrap(),
            Some(Version::new(0, 48, 2))
        );
        // A binary from before 0.48.1 has no marker.
        fs::write(&path, b"plain bytes").unwrap();
        assert_eq!(embedded_release(&path).unwrap(), None);
        // Two different releases: no evidence.
        let mut mixed = marked("0.48.2", b"a");
        mixed.extend(marked("0.48.3", b"b"));
        fs::write(&path, &mixed).unwrap();
        assert_eq!(embedded_release(&path).unwrap(), None);
        // A truncated marker is no evidence either.
        fs::write(&path, b"X0X-RELEASE-MARKER:0.48.2").unwrap();
        assert_eq!(embedded_release(&path).unwrap(), None);
    }

    #[test]
    fn the_embedded_release_of_installed_bytes_wins_over_the_running_hash() {
        // Codex R2: on macOS the running hash was taken from the pathname,
        // so it could be the hash of bytes another daemon installed later.
        // Bytes that say 0.48.2 must not be called 0.48.0.
        let dir = TempDir::new().unwrap();
        let installed = marked("0.48.2", b"new bytes");
        let target = create_test_binary(&dir, "x0xd", &installed);
        let (staging, new_binary) = staged_binary(dir.path(), "r2", &marked("0.48.1", b"older"));
        let lock = take_lock(&target);
        let upgrader = Upgrader::new(target.clone(), Version::new(0, 48, 0))
            .with_running_sha256(Some(sha(&installed)));
        let outcome =
            upgrader.perform_locked_upgrade(&lock, &new_binary, &Version::new(0, 48, 1), &staging);
        // Review S2: the marker disagrees with the hash-bound evidence (the
        // running hash says 0.48.0): the bytes are unknown and refused.
        assert!(
            matches!(outcome, Err(UpgradeError::InstalledReleaseUnknown { .. })),
            "{outcome:?}"
        );
        assert_eq!(fs::read(&target).unwrap(), installed);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_running_hash_is_not_version_evidence_off_linux() {
        // Codex R2: off Linux the running image cannot be read after a
        // rename, so a pathname hash cannot prove the binding.
        assert_eq!(running_binary_sha256(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_running_hash_reads_the_running_image_on_linux() {
        assert!(running_binary_sha256().is_some());
    }

    #[test]
    fn a_companion_cli_with_newer_or_unknown_bytes_is_never_replaced() {
        // Codex R3: A replaced the CLI with 0.48.2 and died before its
        // record and the daemon swap. B (0.48.0, due 0.48.1) must not
        // downgrade the CLI, and must not guess unknown CLI bytes.
        let dir = TempDir::new().unwrap();
        let daemon_plan = LockedSwapPlan::Replace {
            installed_release: Version::new(0, 48, 0),
            installed_sha256: sha(OLD_BYTES),
        };
        let target_version = Version::new(0, 48, 1);
        let cli_new = marked("0.48.2", b"cli");
        let cli = create_test_binary(&dir, "x0x", &cli_new);
        let (staging, new_cli) = staged_binary(dir.path(), "cli", &marked("0.48.1", b"cli-old"));
        let lock = take_lock(&cli);
        let upgrader = companion_upgrader(
            cli.clone(),
            Version::new(0, 48, 0),
            &daemon_plan,
            &target_version,
        );
        let outcome = upgrader.perform_locked_upgrade(&lock, &new_cli, &target_version, &staging);
        // Review S2: a marker with no hash-bound evidence is no evidence.
        assert!(
            matches!(outcome, Err(UpgradeError::InstalledReleaseUnknown { .. })),
            "{outcome:?}"
        );
        assert_eq!(fs::read(&cli).unwrap(), cli_new, "no CLI downgrade");

        // Unknown CLI bytes (no marker, no record) are refused too.
        fs::write(&cli, b"unknown cli bytes").unwrap();
        let outcome = upgrader.perform_locked_upgrade(&lock, &new_cli, &target_version, &staging);
        assert!(
            matches!(outcome, Err(UpgradeError::InstalledReleaseUnknown { .. })),
            "{outcome:?}"
        );
        drop(lock);
    }
}

/// Test-only capture of `tracing` output at WARN and above.
#[cfg(test)]
pub(crate) mod log_capture {
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("capture buffer poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `f` and return every line it logged at WARN or above.
    pub(crate) fn capture_warn<F: FnOnce() -> R, R>(f: F) -> (String, R) {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let result = tracing::subscriber::with_default(subscriber, f);
        let bytes = captured.0.lock().expect("capture buffer poisoned").clone();
        (String::from_utf8_lossy(&bytes).into_owned(), result)
    }
}
