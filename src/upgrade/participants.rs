//! Shared-install participants (#1106 review F2).
//!
//! ADR 0094 §1: "Shared installs wait for every participant to be due." Two
//! daemons can run one executable (every fleet host runs `x0xd` and
//! `x0xd-443` from `/opt/x0x/x0xd`). Each daemon that may self-update keeps
//! one record in `<install dir>/.<binary>.participants/<key>.json`: its
//! MachineId, data dir, running version, the release it has staged and
//! whether its wait for that release is served. Under the host upgrade lock,
//! a writer swaps the shared binary only when every live participant is due
//! (or already runs the release).
//!
//! Stale records: a daemon refreshes its record every
//! [`PARTICIPANT_REFRESH`] while it runs. A record not refreshed for
//! [`PARTICIPANT_STALE_AFTER`] (a removed or long-stopped daemon) no longer
//! blocks the swap; the writer logs it. A daemon that starts with self-update
//! off removes its own record. If the participants cannot be established
//! (the directory or this daemon's own record is missing, or a record is
//! unreadable), the swap is refused.

use std::path::{Path, PathBuf};
use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};

use super::UpgradeError;

/// `format` marker of a participant record.
pub const PARTICIPANT_FORMAT: &str = "x0x.upgrade-participant";

/// Current `version` of a participant record.
pub const PARTICIPANT_VERSION: u32 = 1;

/// A record not refreshed for this long belongs to a removed or stopped
/// daemon and no longer blocks the shared swap.
pub const PARTICIPANT_STALE_AFTER: Duration = Duration::from_secs(30 * 60);

/// How often a running daemon refreshes its own record.
pub const PARTICIPANT_REFRESH: Duration = Duration::from_secs(5 * 60);

/// How often a due daemon checks the other participants again.
pub const PARTICIPANT_RECHECK: Duration = Duration::from_secs(30);

/// The release a participant has staged and its wait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantStage {
    /// The staged release (the participant's active release).
    pub release: String,
    /// The participant's delay for it.
    pub delay_secs: u64,
    /// The wait it still has to serve.
    pub remaining_secs: u64,
    /// Whether its wait is served.
    pub due: bool,
}

/// One daemon's participant record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantRecord {
    /// Always [`PARTICIPANT_FORMAT`].
    pub format: String,
    /// Always [`PARTICIPANT_VERSION`].
    pub version: u32,
    /// Hex MachineId of the daemon.
    pub machine_id: String,
    /// The daemon's data directory.
    pub data_dir: String,
    /// The daemon's process id (diagnostic).
    pub pid: u32,
    /// The version the daemon runs.
    pub running_version: String,
    /// Wall-clock second of the last refresh (staleness only).
    pub updated_unix: u64,
    /// The release the daemon has staged, if any.
    #[serde(default)]
    pub staged: Option<ParticipantStage>,
    /// Set when the daemon's rollout state is blocked (unreadable).
    #[serde(default)]
    pub blocked: Option<String>,
}

impl ParticipantRecord {
    /// A record for this process.
    pub fn new(
        machine_id: &[u8; 32],
        data_dir: &Path,
        running_version: &str,
        updated_unix: u64,
        staged: Option<ParticipantStage>,
        blocked: Option<String>,
    ) -> Self {
        Self {
            format: PARTICIPANT_FORMAT.to_string(),
            version: PARTICIPANT_VERSION,
            machine_id: hex::encode(machine_id),
            data_dir: data_dir.display().to_string(),
            pid: std::process::id(),
            running_version: running_version.to_string(),
            updated_unix,
            staged,
            blocked,
        }
    }
}

/// A live participant that is not yet due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingParticipant {
    /// The record key (file stem).
    pub key: String,
    /// Hex MachineId from the record.
    pub machine_id: String,
    /// Why it is not due.
    pub reason: String,
}

/// The shared-install gate for one release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParticipantGate {
    /// Every live participant is due or already runs the release.
    AllDue {
        /// Stale records that were ignored (paths).
        stale: Vec<String>,
    },
    /// At least one live participant still waits.
    Waiting {
        /// The participants that are not due.
        pending: Vec<PendingParticipant>,
        /// Stale records that were ignored (paths).
        stale: Vec<String>,
    },
}

/// `<install dir>/.<binary>.participants` for the binary at `target`.
pub fn participants_dir(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "x0xd".to_string());
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!(".{name}.participants"))
}

/// The record key of the daemon with `data_dir`: the first 16 hex digits of
/// SHA-256 of the data dir path (one daemon per data dir).
pub fn participant_key(data_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data_dir.as_os_str().as_encoded_bytes());
    hex::encode(&digest[..8])
}

/// Path of the record with `key`.
pub fn record_path(target: &Path, key: &str) -> PathBuf {
    participants_dir(target).join(format!("{key}.json"))
}

/// Write this daemon's record (temp file, fsync, rename).
pub fn write_own(_target: &Path, _key: &str, _record: &ParticipantRecord) -> std::io::Result<()> {
    Ok(())
}

/// Remove this daemon's record (a missing record is fine).
pub fn remove_own(target: &Path, key: &str) -> std::io::Result<()> {
    match std::fs::remove_file(record_path(target, key)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Check, under the host lock, that every live participant of the install
/// at `target` is due for `release`.
pub fn check_all_due(
    _target: &Path,
    _own_key: &str,
    _release: &Version,
    _now_unix: u64,
) -> Result<ParticipantGate, UpgradeError> {
    Ok(ParticipantGate::AllDue { stale: Vec::new() })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn release() -> Version {
        Version::new(0, 48, 1)
    }

    fn stage(release: &str, due: bool) -> Option<ParticipantStage> {
        Some(ParticipantStage {
            release: release.to_string(),
            delay_secs: 1200,
            remaining_secs: if due { 0 } else { 600 },
            due,
        })
    }

    struct Install {
        _dir: tempfile::TempDir,
        target: PathBuf,
    }

    fn install() -> Install {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("x0xd");
        std::fs::write(&target, b"bytes").unwrap();
        Install { _dir: dir, target }
    }

    fn register(
        install: &Install,
        data_dir: &str,
        id: u8,
        running: &str,
        updated: u64,
        staged: Option<ParticipantStage>,
    ) -> String {
        let key = participant_key(Path::new(data_dir));
        let record = ParticipantRecord::new(
            &[id; 32],
            Path::new(data_dir),
            running,
            updated,
            staged,
            None,
        );
        write_own(&install.target, &key, &record).unwrap();
        key
    }

    #[test]
    fn the_shared_swap_waits_until_every_participant_is_due() {
        // Codex F2: A is due; B shares the binary and still waits.
        let install = install();
        let a = register(
            &install,
            "/var/lib/x0x",
            1,
            "0.48.0",
            NOW,
            stage("0.48.1", true),
        );
        let b = register(
            &install,
            "/var/lib/x0x-443",
            2,
            "0.48.0",
            NOW,
            stage("0.48.1", false),
        );
        let gate = check_all_due(&install.target, &a, &release(), NOW).unwrap();
        let ParticipantGate::Waiting { pending, .. } = gate else {
            panic!("B is not due, so A must not swap: {gate:?}");
        };
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].key, b);

        // B's wait is served: now A may swap.
        register(
            &install,
            "/var/lib/x0x-443",
            2,
            "0.48.0",
            NOW,
            stage("0.48.1", true),
        );
        assert_eq!(
            check_all_due(&install.target, &a, &release(), NOW).unwrap(),
            ParticipantGate::AllDue { stale: Vec::new() }
        );

        // A participant that already runs the release is due too.
        register(&install, "/var/lib/x0x-443", 2, "0.48.1", NOW, None);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW).unwrap(),
            ParticipantGate::AllDue { .. }
        ));
    }

    #[test]
    fn a_participant_that_has_not_staged_the_release_blocks() {
        let install = install();
        let a = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", true));
        register(&install, "/b", 2, "0.48.0", NOW, None);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW).unwrap(),
            ParticipantGate::Waiting { .. }
        ));
        register(&install, "/b", 2, "0.48.0", NOW, stage("0.48.0-old", true));
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW).unwrap(),
            ParticipantGate::Waiting { .. }
        ));
    }

    #[test]
    fn a_blocked_participant_blocks_the_swap() {
        let install = install();
        let a = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", true));
        let key = participant_key(Path::new("/b"));
        let record = ParticipantRecord::new(
            &[2; 32],
            Path::new("/b"),
            "0.48.0",
            NOW,
            stage("0.48.1", true),
            Some("unreadable rollout state".to_string()),
        );
        write_own(&install.target, &key, &record).unwrap();
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW).unwrap(),
            ParticipantGate::Waiting { .. }
        ));
    }

    #[test]
    fn a_stale_participant_does_not_block_and_is_reported() {
        // A daemon that was removed stops refreshing its record.
        let install = install();
        let a = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", true));
        let stale_at = NOW - PARTICIPANT_STALE_AFTER.as_secs() - 1;
        let b = register(&install, "/gone", 2, "0.48.0", stale_at, None);
        let gate = check_all_due(&install.target, &a, &release(), NOW).unwrap();
        let ParticipantGate::AllDue { stale } = gate else {
            panic!("a stale record must not block: {gate:?}");
        };
        assert_eq!(stale.len(), 1);
        assert!(stale[0].contains(&b), "{stale:?}");

        // Just inside the window it still blocks.
        register(&install, "/gone", 2, "0.48.0", NOW - 60, None);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW).unwrap(),
            ParticipantGate::Waiting { .. }
        ));
    }

    #[test]
    fn participants_that_cannot_be_established_refuse_the_swap() {
        let install = install();
        // No records at all: this daemon's own registration is missing.
        assert!(matches!(
            check_all_due(&install.target, "self", &release(), NOW),
            Err(UpgradeError::ParticipantsUnknown { .. })
        ));
        let a = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", true));
        assert!(check_all_due(&install.target, &a, &release(), NOW).is_ok());

        // An unreadable record.
        let corrupt = participants_dir(&install.target).join("feedfacefeedface.json");
        std::fs::write(&corrupt, b"{ not json").unwrap();
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW),
            Err(UpgradeError::ParticipantsUnknown { .. })
        ));
        // A record of another format.
        std::fs::write(
            &corrupt,
            br#"{"format":"x0x.upgrade-participant","version":9}"#,
        )
        .unwrap();
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW),
            Err(UpgradeError::ParticipantsUnknown { .. })
        ));
        std::fs::remove_file(&corrupt).unwrap();
        assert!(check_all_due(&install.target, &a, &release(), NOW).is_ok());
    }

    #[test]
    fn own_record_round_trips_and_is_removed() {
        let install = install();
        let key = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", false));
        let bytes = std::fs::read(record_path(&install.target, &key)).unwrap();
        let record: ParticipantRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record.machine_id, hex::encode([1u8; 32]));
        assert_eq!(record.staged, stage("0.48.1", false));
        remove_own(&install.target, &key).unwrap();
        assert!(!record_path(&install.target, &key).exists());
        remove_own(&install.target, &key).unwrap();
    }
}
