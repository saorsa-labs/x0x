//! The record of a sibling `x0x` that made an apply fail (#2012 review).
//!
//! Since the pair fails together, a companion that fails the same way
//! every time would otherwise fail every update cycle silently. Recorded
//! are the failures of the apply worker's companion lock and swap (an
//! unreadable `x0x`, a foreign-owned `x0x.backup` or `x0x.upgrade.lock`)
//! and, on Windows, an archive without a usable `x0x.exe`. (On Unix an
//! archive without `x0x` fails earlier, at the candidate probe extraction,
//! and is not recorded here.)
//!
//! The apply writes `<data_root>/upgrade-companion-failure.json` (mode 0600,
//! file and directory synced). `/health`, `GET /diagnostics/upgrade` and
//! `x0x doctor` show it while its release is newer than the running daemon.
//! The same release is not applied again, by any apply including an
//! operator's `POST /upgrade/apply`, until a bounded backoff has passed; a
//! newer release is tried at once, and removing the file allows a retry at
//! once. A successful apply removes it. A record that cannot be read is
//! logged and reported, and never blocks an apply.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The record's file name in the data root.
pub(crate) const RECORD: &str = "upgrade-companion-failure.json";

/// First wait after a failure; it doubles per further failure of the same
/// release, up to [`MAX_BACKOFF_SECS`].
pub(crate) const FIRST_BACKOFF_SECS: u64 = 30 * 60;
pub(crate) const MAX_BACKOFF_SECS: u64 = 24 * 60 * 60;

/// The text a backed-off apply fails with.
pub(crate) const BACKOFF: &str = "companion backoff";

/// The text of an error that left the installed pair mixed.
pub(crate) const MIXED: &str = "the installed pair is mixed and needs manual recovery";

const MAX_RECORD_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionFailure {
    /// The release whose apply failed.
    pub version: String,
    /// The apply's error, which names the companion path and the outcome.
    pub detail: String,
    /// How many applies of this release failed this way in a row.
    pub failures: u32,
    /// When the last one failed (Unix seconds).
    pub last_unix: u64,
    /// The failure left a new daemon beside the old CLI (the daemon's
    /// restore failed); otherwise the installed binaries are unchanged.
    #[serde(default)]
    pub pair_mixed: bool,
}

impl CompanionFailure {
    /// When the same release may be tried again (Unix seconds).
    pub fn retry_at_unix(&self) -> u64 {
        self.last_unix.saturating_add(backoff_secs(self.failures))
    }
}

/// What reading the record found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    Missing,
    Record(CompanionFailure),
    /// A file that is not a readable record: reported, never blocking.
    Unreadable,
}

/// The wait after `failures` failures in a row: 30 min, doubled per
/// further failure, at most 24 h.
pub(crate) fn backoff_secs(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    FIRST_BACKOFF_SECS
        .saturating_mul(1u64 << doublings)
        .min(MAX_BACKOFF_SECS)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The record in `data_root`.
pub fn read(data_root: &Path) -> Read {
    use std::io::Read as _;
    let file = match std::fs::File::open(data_root.join(RECORD)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Read::Missing,
        Err(_) => return Read::Unreadable,
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_RECORD_BYTES
    {
        return Read::Unreadable;
    }
    serde_json::from_slice(&bytes).map_or(Read::Unreadable, Read::Record)
}

fn record_of(data_root: &Path) -> Option<CompanionFailure> {
    match read(data_root) {
        Read::Record(record) => Some(record),
        _ => None,
    }
}

/// Whether `version` is newer than `running` (semver). An unparseable
/// version is not newer.
fn newer(version: &str, running: &str) -> bool {
    match (
        semver::Version::parse(version),
        semver::Version::parse(running),
    ) {
        (Ok(version), Ok(running)) => version > running,
        _ => false,
    }
}

/// What `/health`, `/diagnostics/upgrade` and `x0x doctor` show: the
/// record while its release is newer than the running daemon, or
/// `Unreadable`. A record for this or an older release is stale.
pub fn current(data_root: &Path) -> Read {
    current_for(data_root, crate::VERSION)
}

pub(crate) fn current_for(data_root: &Path, running: &str) -> Read {
    match read(data_root) {
        Read::Record(record) if !newer(&record.version, running) => Read::Missing,
        other => other,
    }
}

/// Outcome of writing the companion failure record. When `dir_sync_error` is
/// `Some`, the atomic rename succeeded and the record is in place on disk,
/// while syncing the parent directory failed.
pub(crate) struct RecordWrite {
    pub record: CompanionFailure,
    pub dir_sync_error: Option<io::Error>,
}

/// Record a failed apply of `version`: mode 0600, the file synced, renamed
/// over the record, the directory synced. A failure of the same release
/// counts up; another release starts at 1.
#[cfg(test)]
pub(crate) fn record(
    data_root: &Path,
    version: &str,
    detail: &str,
) -> io::Result<CompanionFailure> {
    let outcome = record_at_with_sync(data_root, version, detail, now_unix())?;
    if let Some(err) = outcome.dir_sync_error {
        return Err(err);
    }
    Ok(outcome.record)
}

pub(crate) fn record_with_sync_status(
    data_root: &Path,
    version: &str,
    detail: &str,
) -> io::Result<RecordWrite> {
    record_at_with_sync(data_root, version, detail, now_unix())
}

#[cfg(test)]
pub(crate) fn record_at(
    data_root: &Path,
    version: &str,
    detail: &str,
    now: u64,
) -> io::Result<CompanionFailure> {
    let outcome = record_at_with_sync(data_root, version, detail, now)?;
    if let Some(err) = outcome.dir_sync_error {
        return Err(err);
    }
    Ok(outcome.record)
}

fn record_at_with_sync(
    data_root: &Path,
    version: &str,
    detail: &str,
    now: u64,
) -> io::Result<RecordWrite> {
    use std::io::Write;
    let failures = record_of(data_root)
        .filter(|record| record.version == version)
        .map_or(1, |record| record.failures.saturating_add(1));
    let record = CompanionFailure {
        version: version.to_string(),
        detail: detail.to_string(),
        failures,
        last_unix: now,
        pair_mixed: detail.contains(MIXED),
    };
    let path = data_root.join(RECORD);
    let temporary = data_root.join(format!(".{RECORD}.{}.tmp", uuid::Uuid::new_v4()));
    let renamed = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec(&record).map_err(io::Error::other)?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &path)
    })();
    if let Err(err) = renamed {
        let _ = std::fs::remove_file(&temporary);
        return Err(err);
    }
    let dir_sync_error = super::journal::open_for_sync(data_root, true)
        .and_then(|dir| dir.sync_all())
        .err();
    Ok(RecordWrite {
        record,
        dir_sync_error,
    })
}

/// Remove the record after a successful apply. A missing record is fine.
pub(crate) fn clear(data_root: &Path) {
    match std::fs::remove_file(data_root.join(RECORD)) {
        Ok(()) => {
            tracing::info!("the companion failure record is removed after a successful apply")
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(%error, "cannot remove the companion failure record"),
    }
}

/// `Some(record)` while `version` is backed off after an earlier failure.
pub(crate) fn backed_off(data_root: &Path, version: &str) -> Option<CompanionFailure> {
    backed_off_at(data_root, version, now_unix())
}

/// A wait longer than [`MAX_BACKOFF_SECS`] from now (the clock stepped
/// back, or a record written ahead) is ignored, so it cannot hold a
/// release for longer than the bound.
pub(crate) fn backed_off_at(data_root: &Path, version: &str, now: u64) -> Option<CompanionFailure> {
    match read(data_root) {
        Read::Record(record) => {
            let retry_at = record.retry_at_unix();
            (record.version == version && now < retry_at && retry_at - now <= MAX_BACKOFF_SECS)
                .then_some(record)
        }
        Read::Unreadable => {
            tracing::warn!(
                "the companion failure record {RECORD} cannot be read; it is ignored and the \
                 apply goes on"
            );
            None
        }
        Read::Missing => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2012 review: the same failing release is backed off (30 min,
    /// doubling, at most 24 h); a newer release is not; a wait more than
    /// 24 h ahead (a clock stepped back) is ignored.
    #[test]
    fn a_repeated_companion_failure_backs_off_the_same_release() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(backed_off_at(root, "9.0.0", 0).is_none());
        let first = record_at(root, "9.0.0", "x0x companion failed at /opt/x0x", 1_000).unwrap();
        assert_eq!(first.failures, 1);
        assert!(backed_off_at(root, "9.0.0", 1_000 + FIRST_BACKOFF_SECS - 1).is_some());
        assert!(backed_off_at(root, "9.0.0", 1_000 + FIRST_BACKOFF_SECS).is_none());
        assert!(
            backed_off_at(root, "9.0.1", 1_001).is_none(),
            "a newer release"
        );
        let second = record_at(root, "9.0.0", "again", 5_000).unwrap();
        assert_eq!(second.failures, 2);
        assert_eq!(second.retry_at_unix(), 5_000 + 2 * FIRST_BACKOFF_SECS);
        assert_eq!(backoff_secs(40), MAX_BACKOFF_SECS);
        // The clock stepped back two days: the wait is ignored.
        record_at(root, "9.0.2", "later", 1_000_000).unwrap();
        assert!(backed_off_at(root, "9.0.2", 1_000_000).is_some());
        assert!(backed_off_at(root, "9.0.2", 1_000_000 - 2 * MAX_BACKOFF_SECS).is_none());
        assert_eq!(
            record_at(root, "9.0.1", "other", 6_000).unwrap().failures,
            1
        );
        // Removing the file allows the retry at once.
        std::fs::remove_file(root.join(RECORD)).unwrap();
        assert!(backed_off_at(root, "9.0.1", 6_001).is_none());
    }

    /// #2012 review: a record shows only while its release is newer than
    /// the running daemon; 0.50.0 failed, a host on 0.50.0, 0.50.1 or
    /// 0.51.0 does not show it. A successful apply removes it.
    #[test]
    fn a_record_shows_only_for_a_newer_release_and_a_success_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        record_at(root, "0.50.0", "x0x companion failed at /opt/x0x/x0x", 1).unwrap();
        assert!(matches!(current_for(root, "0.49.1"), Read::Record(_)));
        for running in ["0.50.0", "0.50.1", "0.51.0"] {
            assert_eq!(current_for(root, running), Read::Missing, "{running}");
        }
        clear(root);
        assert_eq!(read(root), Read::Missing);
        clear(root);
    }

    /// The record is written 0600; a corrupt one is reported as unreadable
    /// and does not hold any release.
    #[test]
    fn the_record_is_private_and_a_corrupt_one_never_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mixed = record_at(root, "9.0.0", &format!("x0x companion failed; {MIXED}"), 1).unwrap();
        assert!(mixed.pair_mixed);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join(RECORD))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(root.join(RECORD), b"{not json").unwrap();
        assert_eq!(current_for(root, "0.1.0"), Read::Unreadable);
        assert!(backed_off_at(root, "9.0.0", 2).is_none());
        assert_eq!(record_at(root, "9.0.0", "again", 3).unwrap().failures, 1);
    }
}
