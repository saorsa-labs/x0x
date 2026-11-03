//! Decentralized self-update system for x0x binaries.
//!
//! Manifest-based upgrade flow: GitHub releases are checked for new versions,
//! verified with ML-DSA-65 signatures, and propagated symmetrically via gossip.
//! Nodes download, verify, and atomically replace their own binary with rollback
//! support.
//! Upgrade parsers must not derive Debug for values that can hold argv, environment or credentials.

pub mod apply;
#[cfg(unix)]
pub(crate) mod fleet_policy;
#[cfg(unix)]
mod inventory_accounts;
#[cfg(unix)]
mod inventory_procfs;
#[cfg(unix)]
mod inventory_systemd_context;
#[cfg(unix)]
mod inventory_systemd_environment;
#[cfg(unix)]
mod inventory_systemd_exec;
#[cfg(unix)]
mod inventory_systemd_lists;
pub(crate) mod journal;
pub(crate) mod log_flush;
pub mod manifest;
pub mod monitor;
pub(crate) mod pair;
pub(crate) mod probe;
pub(crate) mod probe_retry;
pub mod restart;
pub mod rollout;
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) mod shutdown_flush;
pub mod signature;
pub(crate) mod staging;
pub(crate) mod staging_runtime;
pub(crate) mod staging_selection;
pub mod verification_probe;

#[cfg(unix)]
mod inventory_argv;
#[cfg(unix)]
mod inventory_commands;
#[cfg(unix)]
mod inventory_roots;

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
    ///
    /// The backup file is per-swap: `<file>.backup-<running-version>-<pid>-<nanos>`
    /// (issue #1106 M2, "a per-instance `<exe>.backup-<ver>`"). One fixed name
    /// let a second daemon sharing this executable destroy or consume the
    /// first one's rollback copy — its swap overwrote the shared file, and a
    /// late restore (HTTP deferred-restart owner, transactional-handoff
    /// helper) renamed away a backup another live transaction owned. Each
    /// transaction now restores only the file its own swap created, so a
    /// concurrent transaction never destroys or consumes another
    /// transaction's rollback copy. The *installed bytes* are still
    /// unserialised across processes: restores rename without the host lock
    /// (as on main), so a late restore can overwrite a later transaction's
    /// installed release — #1106's lock-or-handoff question for restores,
    /// flagged in the PR body.
    ///
    /// The canonical `<file>.backup` name is refreshed to the same bytes as a
    /// separate copy so path-deriving consumers (an equal-bytes-skip restart,
    /// which has no fresh backup of its own, and operators) keep seeing the
    /// latest preserved bytes under the documented name. Never an alias: a
    /// hard link to the per-swap file would let a post-restore state share
    /// one inode between the canonical name and the target, so a pre-#1106
    /// swapper's copy onto the canonical name would truncate the running
    /// binary (review finding on the first draft).
    pub fn create_backup(&self) -> Result<PathBuf, UpgradeError> {
        let backup_path = per_swap_backup_path(&self.target_path, &self.current_version);
        debug!(backup_path = %backup_path.display(), "Creating backup at: {}", backup_path.display());
        std::fs::copy(&self.target_path, &backup_path).map_err(|e| UpgradeError::BackupFailed {
            path: backup_path.clone(),
            source: e,
        })?;
        refresh_mtime(&backup_path);
        sync_file_best_effort(&backup_path);
        refresh_canonical_backup(&self.target_path, &backup_path);
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
        let (result, _fresh_backup) =
            self.finish_upgrade_under_host_lock(new_binary_path, target_version)?;
        Ok(result)
    }

    /// Compare / backup / replace while the caller already holds this target's
    /// host lock. Used by the offloaded multi-target apply so every lock can
    /// be taken before any mutation (cancel must not install bytes without a
    /// restart owner).
    ///
    /// When disk already matches the incoming bytes, backup and replace are
    /// skipped and [`UpgradeResult::Success`] is returned (with no backup
    /// path) so public `perform_upgrade` matches main and auto-apply can
    /// still own restart. On a real swap the returned backup path is the
    /// fresh backup of the bytes that were serving; a failed flush restores
    /// exactly the artifacts that report one, never a stale backup. A
    /// [`UpgradeResult::RolledBack`] result reports no backup path: its
    /// rollback already consumed the backup. On Unix, Success still
    /// requires the installed target to be executable (`0o755`), matching
    /// `atomic_replace`; a permission repair failure is an error, never
    /// Success.
    pub(super) fn finish_upgrade_under_host_lock(
        &self,
        new_binary_path: &Path,
        target_version: &Version,
    ) -> Result<(UpgradeResult, Option<PathBuf>), UpgradeError> {
        if on_disk_matches_incoming(&self.target_path, new_binary_path)? {
            // Host lock is held: repair execute bits without clobbering backup.
            ensure_target_executable(&self.target_path)?;
            info!(
                version = %target_version,
                target = %self.target_path.display(),
                "On-disk target already matches incoming binary; skipping backup and replace"
            );
            return Ok((
                UpgradeResult::Success {
                    version: target_version.to_string(),
                },
                None,
            ));
        }

        let backup_path = self.create_backup()?;

        info!(
            replace_target = %self.target_path.display(),
            "Replacing binary..."
        );
        match self.atomic_replace(new_binary_path) {
            Ok(()) => {
                info!(version = %target_version, "Successfully upgraded to version {}", target_version);
                Ok((
                    UpgradeResult::Success {
                        version: target_version.to_string(),
                    },
                    Some(backup_path),
                ))
            }
            Err(replace_err) => {
                warn!(error = %replace_err, "Binary replacement failed: {}", replace_err);
                match self.restore_from_backup(&backup_path) {
                    // No backup path on RolledBack: the restore above already
                    // consumed it, so a caller must not be handed a path it
                    // could try to restore again later.
                    Ok(()) => Ok((
                        UpgradeResult::RolledBack {
                            reason: format!("Replacement failed: {replace_err}"),
                        },
                        None,
                    )),
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

/// Per-swap backup path for `target`: `<file>.backup-<version>-<pid>-<nanos>`.
///
/// The version label is the swapper's running version — a diagnostic label,
/// not a claim about the bytes on disk (a second daemon still running v1 can
/// preserve v2 bytes a first swapper already installed, #1106). The
/// pid-nanos pair (the [`Upgrader::create_temp_dir`] idiom) makes the name
/// unique per transaction, which is what concurrent swappers on one shared
/// executable actually need — two same-version daemons applying different
/// releases would otherwise collide on a version-only name.
fn per_swap_backup_path(target: &Path, running_version: &Version) -> PathBuf {
    let mut unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    loop {
        let mut name = target
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(format!(
            ".backup-{running_version}-{}-{unique}",
            std::process::id()
        ));
        let path = target.with_file_name(name);
        // `fs::copy` onto an existing name would silently destroy another
        // transaction's rollback bytes — the exact #1106 bug class — so a
        // collision (coarse clock tick, backward NTP step) re-derives instead.
        if !path.exists() {
            return path;
        }
        unique += 1;
    }
}

/// Refresh the canonical `<file>.backup` name to hold this transaction's
/// preserved bytes as a separate copy. A separate inode is required: an
/// alias of the per-swap file would let a post-restore rename leave the
/// canonical name and the target sharing one inode, and `fs::copy` onto the
/// canonical name (a pre-#1106 swapper, or this fallback) truncates its
/// destination before writing — emptying the running binary. A separate
/// copy also survives the per-swap file being renamed onto the target by a
/// restore. The copy stages under a `.backup-partial-` name and renames, so
/// a mid-copy failure (full disk) never leaves a truncated canonical file
/// for a later skip-restart fallback to restore. Best-effort: the per-swap
/// file is the rollback token; the canonical name only serves
/// path-deriving consumers. Called under the host lock, so the swap cannot
/// interleave with another swapper.
fn refresh_canonical_backup(target: &Path, per_swap: &Path) {
    let canonical = target.with_extension("backup");
    let staging = target.with_file_name(format!(
        "{}.backup-partial-{}",
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        std::process::id()
    ));
    if let Err(error) = std::fs::copy(per_swap, &staging).and_then(|_| {
        sync_file_best_effort(&staging);
        std::fs::rename(&staging, &canonical).inspect_err(|_| {
            // The staged copy is complete; only the atomic swap failed.
            let _ = std::fs::remove_file(&staging);
        })
    }) {
        let _ = std::fs::remove_file(&staging);
        warn!(
            canonical = %canonical.display(),
            error = %error,
            "cannot refresh the canonical backup name; the per-swap backup is unaffected"
        );
        return;
    }
    refresh_mtime(&canonical);
    if let Some(parent) = canonical.parent() {
        if let Err(error) = journal::open_for_sync(parent, true).and_then(|dir| dir.sync_all()) {
            warn!(
                dir = %parent.display(),
                error = %error,
                "cannot sync the install directory after the canonical backup rename"
            );
        }
    }
}

/// Reset a freshly written backup's mtime to now. `fs::copy` may preserve
/// the source's timestamps (macOS `fcopyfile`, Windows `CopyFileExW`), and
/// the bytes being preserved usually carry an install-date mtime; without
/// this reset the startup sweep's age gate could reclaim a live
/// transaction's backup the moment it is written (#1106 review finding).
/// `fs::copy` also copies the source's permission bits, so a `0o555`
/// install cannot be opened for writing — but this process created the
/// backup and owns it, and `futimens` with explicit times needs only
/// ownership, so a read-only open is the fallback. Best-effort: a failure
/// is logged because the sweep's age gate is then the only protection.
fn refresh_mtime(path: &Path) {
    let file = File::options()
        .write(true)
        .open(path)
        .or_else(|_| File::options().read(true).open(path));
    match file {
        Ok(file) => {
            if let Err(error) = file.set_modified(std::time::SystemTime::now()) {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "cannot reset the backup mtime; the sweep's age gate may see it as old"
                );
            }
        }
        Err(error) => {
            warn!(
                path = %path.display(),
                error = %error,
                "cannot open the backup to reset its mtime; the sweep's age gate may see it as old"
            );
        }
    }
}

/// Flush a freshly written backup file to storage, matching the durability
/// the restore side already provides (#1595): a rollback token that a power
/// cut can tear is no rollback token. Any fd syncs the file's data.
/// Best-effort and logged — a sync error must not fail the upgrade that
/// already holds the host lock, and the pre-#1106 `.backup` was never
/// synced either.
fn sync_file_best_effort(path: &Path) {
    match File::options().read(true).open(path) {
        Ok(file) => {
            if let Err(error) = file.sync_all() {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "cannot sync the backup file; a power cut may tear it"
                );
            }
        }
        Err(error) => {
            warn!(path = %path.display(), error = %error, "cannot open the backup file to sync it");
        }
    }
}

/// True for per-swap backup files this module creates:
/// `<file>.backup-<version>-<pid>-<nanos>`.
///
/// The version must parse as semver and the two trailing groups must be all
/// digits, which keeps date-like operator files (`notes.backup-2026-01-15`,
/// read as version `2026`) out of the sweep. Still deliberately narrower
/// than a bare `.backup-` substring so the dormant pair engine's
/// `.backup-<version>-<transaction>` names (uuid transaction ids, not
/// pid-nanos pairs) are never matched. Residual false positive: a uuid
/// whose last two dash groups are all digits (~0.05% per artifact) would
/// match; the cost is only a skipped cleanup of that dormant artifact.
fn is_per_swap_backup_name(name: &str) -> bool {
    let Some((_, rest)) = name.split_once(".backup-") else {
        return false;
    };
    // `<version>-<pid>-<nanos>`: the two trailing dash segments are all
    // digits and a valid semver label precedes them. A version may carry
    // dashes (prerelease), so only the tail is split off first.
    let mut tail = rest.rsplitn(3, '-');
    let nanos = tail.next().unwrap_or_default();
    let pid = tail.next().unwrap_or_default();
    let version = tail.next().unwrap_or_default();
    !nanos.is_empty()
        && !pid.is_empty()
        && !version.is_empty()
        && nanos.bytes().all(|b| b.is_ascii_digit())
        && pid.bytes().all(|b| b.is_ascii_digit())
        && Version::parse(version).is_ok()
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

/// Put the pre-upgrade binary back at `target` from `backup` (engineer
/// ruling 23 Oct 2026: a failed or overrunning acknowledged shutdown flush
/// keeps the old binary so the service manager's restart lands on the old
/// version). A missing backup means no swap happened or the backup was
/// already consumed; the error names that state so the caller can log it
/// and still exit `EX_TEMPFAIL`.
pub(crate) fn restore_backup_binary(target: &Path, backup: &Path) -> std::io::Result<()> {
    if !backup.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no backup binary at {} to restore", backup.display()),
        ));
    }
    std::fs::rename(backup, target)
}

/// Restore the artifacts this transaction swapped (engineer ruling,
/// 23 Oct 2026). Each entry is `(target, fresh_backup)` — exactly the
/// pairs the swap step under `Upgrader`\'s host-locked finish reported
/// as real swaps. Every backup is checked before the first rename, and a
/// missing backup restores nothing. A rename that fails after an earlier
/// rename succeeded can still leave a daemon/CLI pair on mixed versions;
/// the caller logs that state for manual recovery and still exits
/// `EX_TEMPFAIL`. After the renames, every directory that received one is
/// synced, so the restore survives a power loss immediately after the
/// caller's `EX_TEMPFAIL` exit (issue #1595, Claude #1565 finding 1).
pub(crate) fn restore_swapped_binaries(artifacts: &[(PathBuf, PathBuf)]) -> std::io::Result<()> {
    for (target, backup) in artifacts {
        if !backup.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "no backup binary at {} for target {}; nothing is restored",
                    backup.display(),
                    target.display()
                ),
            ));
        }
    }
    for (target, backup) in artifacts {
        restore_backup_binary(target, backup)?;
    }
    let mut synced = Vec::new();
    for (target, _) in artifacts {
        let Some(parent) = target.parent() else {
            continue;
        };
        if parent.as_os_str().is_empty() || synced.contains(&parent) {
            continue;
        }
        journal::open_for_sync(parent, true)?.sync_all()?;
        synced.push(parent);
    }
    Ok(())
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
/// Per-swap backups (`<file>.backup-<version>-<pid>-<nanos>`, issue #1106)
/// and interrupted canonical refreshes (`<file>.backup-partial-<pid>`) are
/// age-gated identically for the same reason: a live handoff helper may
/// still need its transaction's rollback bytes.
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
        } else if (is_per_swap_backup_name(&name) || name.contains(".backup-partial-"))
            && entry_is_aged(&entry)
            && std::fs::remove_file(&path).is_ok()
        {
            info!(path = %path.display(), "Removed per-swap backup from a completed upgrade");
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

    /// D182: distinguish future-clock skew from stale or malformed manifests.
    #[error("manifest timestamp {timestamp} exceeds local time {now} by more than {max_future_skew_secs} seconds")]
    ManifestTimestampInFuture {
        timestamp: u64,
        now: u64,
        max_future_skew_secs: u64,
    },

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

    /// #1106: each swap writes its own per-swap backup file, and the canonical
    /// `<target>.backup` name keeps pointing at the latest preserved bytes.
    #[test]
    fn create_backup_writes_per_swap_file_and_refreshes_canonical() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"original content");
        let canonical = binary_path.with_extension("backup");
        fs::write(&canonical, b"stale prior backup").unwrap();
        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));

        let backup_path = upgrader.create_backup().unwrap();

        assert_ne!(
            backup_path, canonical,
            "the rollback token must be a per-swap file, not the shared canonical name"
        );
        assert_eq!(fs::read(&backup_path).unwrap(), b"original content");
        assert_eq!(
            fs::read(&canonical).unwrap(),
            b"original content",
            "the canonical name must be refreshed to this swap's preserved bytes"
        );

        // A restore that consumes the per-swap file by rename leaves the
        // canonical name holding the same preserved bytes: it is an
        // independent copy, never an alias of the per-swap or target inode,
        // so it is neither emptied by the restore nor able to alias the
        // running binary.
        fs::write(&binary_path, b"new content").unwrap();
        upgrader.restore_from_backup(&backup_path).unwrap();
        assert_eq!(fs::read(&binary_path).unwrap(), b"original content");
        assert_eq!(fs::read(&canonical).unwrap(), b"original content");
        // The staged refresh name is consumed by the rename, never left
        // behind for a later restore to mistake for complete bytes.
        assert!(
            !dir.path().read_dir().unwrap().flatten().any(|entry| entry
                .file_name()
                .to_string_lossy()
                .contains(".backup-partial-")),
            "no partial-refresh staging file may survive a successful backup"
        );
    }

    /// #1106 review finding: `fs::copy` may preserve the source binary's
    /// install-date mtime (macOS `fcopyfile`, Windows `CopyFileExW`), so a
    /// freshly written backup must have its mtime reset or the startup
    /// sweep's age gate can reclaim a live transaction's backup immediately.
    #[test]
    fn create_backup_resets_mtime_so_a_fresh_backup_is_never_swept() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"original content");
        age_file(&binary_path, std::time::Duration::from_secs(7200));
        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));

        let backup_path = upgrader.create_backup().unwrap();
        let canonical = binary_path.with_extension("backup");

        // The production startup sweep's one-hour gate must spare both names.
        let removed =
            sweep_stale_upgrade_artifacts(dir.path(), std::time::Duration::from_secs(3600));
        assert_eq!(removed, 0, "a just-written backup must not look aged");
        assert!(backup_path.is_file(), "the per-swap backup must survive");
        assert!(canonical.is_file(), "the canonical backup must survive");
    }

    /// `fs::copy` also copies the source's permission bits (#1106 review
    /// round 3): a `0o555` install produces a `0o555` backup, whose mtime
    /// must still be resettable — this process owns the fresh file, so the
    /// reset falls back to a read-only open.
    #[test]
    fn create_backup_resets_mtime_on_a_read_only_mode_backup() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"original content");
        // Age first, while the mode still allows the write-open that
        // backdates the mtime; then make the install read-only.
        age_file(&binary_path, std::time::Duration::from_secs(7200));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        let upgrader = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));

        let backup_path = upgrader.create_backup().unwrap();

        let removed =
            sweep_stale_upgrade_artifacts(dir.path(), std::time::Duration::from_secs(3600));
        assert_eq!(removed, 0, "a mode-inheriting backup must not look aged");
        assert!(backup_path.is_file(), "the per-swap backup must survive");
    }

    /// #1106 regression: two transactions on one shared executable applying
    /// different releases must each keep their own rollback copy, and a late
    /// restore of the first transaction must not consume the second's backup.
    /// On a single fixed `.backup` name the second swap overwrote the first
    /// rollback copy and the late restore renamed the second's backup away.
    #[test]
    fn second_release_keeps_first_transactions_rollback_copy() {
        let dir = TempDir::new().unwrap();
        let binary_path = create_test_binary(&dir, "test-binary", b"v1-original");
        let candidate_v2 = create_test_binary(&dir, "new-v2", b"v2-bytes");
        let candidate_v3 = create_test_binary(&dir, "new-v3", b"v3-bytes");

        // Transaction 1: a daemon running v1 applies v2.
        let first = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));
        let lock1 = acquire_host_upgrade_lock(&binary_path).unwrap();
        let (result1, backup1) = first
            .finish_upgrade_under_host_lock(&candidate_v2, &Version::new(2, 0, 0))
            .unwrap();
        drop(lock1);
        assert!(matches!(result1, UpgradeResult::Success { .. }));
        let backup1 = backup1.expect("a real swap reports its fresh backup");

        // Transaction 2: a second daemon still running v1 from the same
        // shared executable applies a different release; disk now holds v2.
        let second = Upgrader::new(binary_path.clone(), Version::new(1, 0, 0));
        let lock2 = acquire_host_upgrade_lock(&binary_path).unwrap();
        let (result2, backup2) = second
            .finish_upgrade_under_host_lock(&candidate_v3, &Version::new(3, 0, 0))
            .unwrap();
        drop(lock2);
        assert!(matches!(result2, UpgradeResult::Success { .. }));
        let backup2 = backup2.expect("a real swap reports its fresh backup");

        assert_ne!(backup1, backup2, "each swap owns its own backup file");
        assert_eq!(
            fs::read(&backup1).unwrap(),
            b"v1-original",
            "the second transaction must not destroy the first rollback copy"
        );
        assert_eq!(fs::read(&backup2).unwrap(), b"v2-bytes");

        // A late restore of transaction 1 (handoff helper, deferred restart
        // owner) restores exactly its own bytes and leaves transaction 2's
        // backup untouched.
        restore_swapped_binaries(&[(binary_path.clone(), backup1.clone())]).unwrap();
        assert_eq!(fs::read(&binary_path).unwrap(), b"v1-original");
        assert!(
            backup2.is_file(),
            "a late restore must not consume another transaction's backup"
        );
    }

    /// The sweep's per-swap matcher: this module's pid-nanos names match; the
    /// canonical name, the dormant pair engine's uuid-transaction names, and
    /// date-like operator files do not.
    #[test]
    fn per_swap_backup_name_matcher_is_precise() {
        assert!(is_per_swap_backup_name(
            "x0xd.backup-1.2.3-4212-99887766554433221100"
        ));
        assert!(is_per_swap_backup_name("x0xd.backup-1.0.0-rc.1-42-7"));
        assert!(!is_per_swap_backup_name("x0xd.backup"));
        assert!(!is_per_swap_backup_name("x0xd.backup-1.0.0"));
        assert!(!is_per_swap_backup_name(
            "x0xd.backup-1.0.0-3f2a8c1e-9d4b-4c6e-8a2f-1b0d5e7a9c31"
        ));
        assert!(!is_per_swap_backup_name("x0xd.exe.x0xold-17"));
        // Date-like operator files in the install directory must never be
        // swept as upgrade debris (review round-2 finding: `2026` etc. parse
        // as pid/nanos groups but not as a semver version label).
        assert!(!is_per_swap_backup_name("notes.backup-2026-01-15"));
        assert!(!is_per_swap_backup_name("x0xd.backup-2024-01-15"));
        assert!(!is_per_swap_backup_name("x0xd.backup-partial-123"));
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
        let (restart_owner, fresh_backup) = upgrader
            .finish_upgrade_under_host_lock(&second, &Version::new(2, 0, 0))
            .unwrap();
        assert!(
            matches!(restart_owner, UpgradeResult::Success { .. }),
            "finish on match must stay Success for restart ownership: {restart_owner:?}"
        );
        assert!(
            fresh_backup.is_none(),
            "an already-matching target has no fresh backup to restore"
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

    /// Per-swap backups (#1106) are reclaimed by the startup sweep only past
    /// the age gate, so a live handoff keeps its rollback bytes while
    /// completed upgrades do not accumulate one ≤200 MiB file per swap.
    /// Interrupted canonical refreshes (`*.backup-partial-*`) are reclaimed
    /// the same way, and date-like operator files are never touched.
    #[test]
    fn sweep_reclaims_aged_per_swap_backups_but_spares_live_ones() {
        let dir = TempDir::new().unwrap();
        let aged = dir.path().join("x0xd.backup-1.0.0-123-456");
        fs::write(&aged, b"old").unwrap();
        let fresh = dir.path().join("x0xd.backup-2.0.0-789-101");
        fs::write(&fresh, b"fresh").unwrap();
        let canonical = dir.path().join("x0xd.backup");
        fs::write(&canonical, b"canonical").unwrap();
        // A dormant pair-engine artifact (uuid transaction id) is not this
        // module's debris and must survive the sweep.
        let pair_artifact = dir
            .path()
            .join("x0xd.backup-1.0.0-3f2a8c1e-9d4b-4c6e-8a2f-1b0d5e7a9c31");
        fs::write(&pair_artifact, b"pair").unwrap();
        // An operator's date-named backup beside the binary is not upgrade
        // debris and must survive the sweep (review round-2 finding).
        let operator_file = dir.path().join("notes.backup-2026-01-15");
        fs::write(&operator_file, b"operator notes").unwrap();
        // A canonical refresh interrupted mid-copy stages under this name;
        // an aged leftover is debris, a live one is an in-flight refresh.
        let aged_partial = dir.path().join("x0xd.backup-partial-321");
        fs::write(&aged_partial, b"partial").unwrap();
        age_file(&aged, std::time::Duration::from_secs(7200));
        age_file(&aged_partial, std::time::Duration::from_secs(7200));

        let removed =
            sweep_stale_upgrade_artifacts(dir.path(), std::time::Duration::from_secs(3600));

        assert_eq!(
            removed, 2,
            "only the aged per-swap backup and aged partial staging should be removed"
        );
        assert!(!aged.exists(), "aged per-swap backup must be reclaimed");
        assert!(
            fresh.exists(),
            "a live transaction's per-swap backup must survive the age gate"
        );
        assert!(
            canonical.exists(),
            "the canonical backup name is never swept"
        );
        assert!(
            pair_artifact.exists(),
            "pair-engine artifact names are not this module's debris"
        );
        assert!(
            operator_file.exists(),
            "date-like operator files are not this module's debris"
        );
        assert!(!aged_partial.exists(), "aged partial staging is debris");
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
