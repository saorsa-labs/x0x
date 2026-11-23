//! The record of a sibling `x0x` that made an apply fail (#2012 review).
//!
//! Since the pair fails together, a companion that fails the same way
//! every time (an unreadable `x0x`, a foreign-owned `x0x.backup` or
//! `x0x.upgrade.lock`, an archive without a usable `x0x`) would otherwise
//! fail every update cycle silently. The apply writes
//! `<data_root>/upgrade-companion-failure.json`; `/health`,
//! `GET /diagnostics/upgrade` and `x0x doctor` show it, and the same
//! release is not downloaded again until a bounded backoff has passed. A
//! newer release is tried at once. A record for the version this daemon
//! runs is stale (that apply later succeeded) and is not shown.

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
}

impl CompanionFailure {
    /// When the same release may be tried again (Unix seconds).
    pub fn retry_at_unix(&self) -> u64 {
        self.last_unix.saturating_add(backoff_secs(self.failures))
    }
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

/// The record in `data_root`, if one can be read.
pub fn read(data_root: &Path) -> Option<CompanionFailure> {
    use std::io::Read;
    let file = std::fs::File::open(data_root.join(RECORD)).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES).read_to_end(&mut bytes).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The record, unless it is for the version this daemon runs.
pub fn current(data_root: &Path) -> Option<CompanionFailure> {
    read(data_root).filter(|record| record.version != crate::VERSION)
}

/// Record a failed apply of `version` (a temporary file, then a rename).
/// A failure of the same release counts up; another release starts at 1.
pub(crate) fn record(
    data_root: &Path,
    version: &str,
    detail: &str,
) -> io::Result<CompanionFailure> {
    record_at(data_root, version, detail, now_unix())
}

pub(crate) fn record_at(
    data_root: &Path,
    version: &str,
    detail: &str,
    now: u64,
) -> io::Result<CompanionFailure> {
    let failures = read(data_root)
        .filter(|record| record.version == version)
        .map_or(1, |record| record.failures.saturating_add(1));
    let record = CompanionFailure {
        version: version.to_string(),
        detail: detail.to_string(),
        failures,
        last_unix: now,
    };
    let path = data_root.join(RECORD);
    let temporary = data_root.join(format!(".{RECORD}.{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(
        &temporary,
        serde_json::to_vec(&record).map_err(io::Error::other)?,
    )?;
    if let Err(error) = std::fs::rename(&temporary, &path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(record)
}

/// `Some(record)` while `version` is backed off after an earlier failure.
pub(crate) fn backed_off(data_root: &Path, version: &str) -> Option<CompanionFailure> {
    backed_off_at(data_root, version, now_unix())
}

pub(crate) fn backed_off_at(data_root: &Path, version: &str, now: u64) -> Option<CompanionFailure> {
    read(data_root).filter(|record| record.version == version && now < record.retry_at_unix())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2012 review: the same failing release is backed off (30 min,
    /// doubling, at most 24 h); a newer release is not; a record for the
    /// running version is stale and not shown.
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
        assert_eq!(
            record_at(root, "9.0.1", "other", 6_000).unwrap().failures,
            1
        );
        assert!(current(root).is_some());
        record_at(root, crate::VERSION, "stale", 7_000).unwrap();
        assert!(read(root).is_some() && current(root).is_none());
    }
}
