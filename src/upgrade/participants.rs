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
    /// `false` for a daemon that runs from this install with self-update
    /// off: it never becomes due on its own (review R1).
    #[serde(default = "default_true")]
    pub updates_enabled: bool,
}

fn default_true() -> bool {
    true
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
            updates_enabled: true,
        }
    }

    /// Mark the daemon's self-update as on or off.
    pub fn with_updates_enabled(mut self, updates_enabled: bool) -> Self {
        self.updates_enabled = updates_enabled;
        self
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

/// `<install dir>/.<binary>.unregistered-lock` (review S1). A daemon that
/// runs from the install holds a shared lock on it until its participant
/// record is written; a writer that cannot take it exclusively knows that a
/// live daemon is not registered.
pub fn unregistered_signal_path(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "x0xd".to_string());
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!(".{name}.unregistered-lock"))
}

/// A held "not yet registered" signal (review S1). Dropping it releases it.
#[derive(Debug)]
pub struct UnregisteredSignal {
    _file: std::fs::File,
}

impl UnregisteredSignal {
    /// Take the shared signal lock for the install at `target`. The signal
    /// file is created (with the install's sharing) when this account may,
    /// else opened read-only. `None` when it cannot be opened or a writer
    /// holds it right now; the caller tries again.
    pub fn hold(target: &Path) -> Option<Self> {
        let path = unregistered_signal_path(target);
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
        {
            Ok(file) => {
                super::share_like_install(&path, target, false);
                file
            }
            Err(_) => std::fs::File::open(&path).ok()?,
        };
        file.try_lock_shared().ok()?;
        Some(Self { _file: file })
    }
}

/// Path of the record with `key`.
pub fn record_path(target: &Path, key: &str) -> PathBuf {
    participants_dir(target).join(format!("{key}.json"))
}

/// Write this daemon's record under the host upgrade lock (review R1): a
/// writer that holds the lock sees a participant set that cannot change.
///
/// Each daemon writes only its own file: temp file, fsync, rename, then a
/// directory fsync. The participants directory is created on first use with
/// the install directory's group-write bit (setgid on a group-writable
/// install), so a second service account on a group-shared install can add
/// its record.
pub fn write_own(
    _lock: &super::HostUpgradeLock,
    target: &Path,
    key: &str,
    record: &ParticipantRecord,
) -> std::io::Result<()> {
    use std::io::Write;
    let dir = participants_dir(target);
    if !dir.is_dir() {
        std::fs::create_dir_all(&dir)?;
        sync_dir_of(&dir)?;
    }
    // Review S1: also an existing directory (older code, an interrupted
    // creation) gets the install's sharing, so every account can register.
    super::share_like_install(&dir, target, true);
    let path = record_path(target, key);
    let tmp = dir.join(format!("{key}.json.tmp-{}", std::process::id()));
    let json = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
    let written = std::fs::File::create(&tmp).and_then(|mut file| {
        file.write_all(&json)?;
        super::share_like_install(&tmp, target, false);
        file.sync_all()
    });
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, &path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir_of(&path)
}

/// Remove this daemon's record under the host lock (a missing record is
/// fine).
pub fn remove_own(_lock: &super::HostUpgradeLock, target: &Path, key: &str) -> std::io::Result<()> {
    let path = record_path(target, key);
    match std::fs::remove_file(&path) {
        Ok(()) => sync_dir_of(&path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// fsync the directory that holds `path`.
fn sync_dir_of(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Check, under the host lock, that every live participant of the install
/// at `target` is due for `release`.
///
/// A live participant is due when it already runs `release` or newer, or
/// when it has staged `release` or newer and its wait is served. A record
/// older than [`PARTICIPANT_STALE_AFTER`] is stale: it is ignored and
/// reported. A daemon with self-update off never becomes due. With
/// `skip_waits` (D185 `now=true`), other participants' waits are skipped,
/// but their holds (a blocked rollout state) still stop the swap. In every
/// mode the swap is refused when the participants cannot be established:
/// this daemon's own record is missing (pending), or the directory cannot
/// be read or a record is unreadable or of another format (error).
pub fn check_all_due(
    target: &Path,
    own_key: &str,
    release: &Version,
    now_unix: u64,
    skip_waits: bool,
) -> Result<ParticipantGate, UpgradeError> {
    let dir = participants_dir(target);
    let unknown = |reason: String| UpgradeError::ParticipantsUnknown { reason };
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        // Nothing registered yet, this daemon included: not established.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ParticipantGate::Waiting {
                pending: vec![own_record_missing(own_key, &dir)],
                stale: Vec::new(),
            });
        }
        Err(e) => return Err(unknown(format!("cannot read {}: {e}", dir.display()))),
    };
    let mut own_seen = false;
    let mut pending = Vec::new();
    let mut stale = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| unknown(format!("cannot list {}: {e}", dir.display())))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(key) = name.strip_suffix(".json") else {
            continue; // temp files and anything else
        };
        let path = entry.path();
        let record: ParticipantRecord = std::fs::read(&path)
            .map_err(|e| unknown(format!("cannot read {}: {e}", path.display())))
            .and_then(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|e| unknown(format!("unreadable record {}: {e}", path.display())))
            })?;
        if record.format != PARTICIPANT_FORMAT || record.version != PARTICIPANT_VERSION {
            return Err(unknown(format!(
                "record {} has format {:?} version {}",
                path.display(),
                record.format,
                record.version
            )));
        }
        if key == own_key {
            own_seen = true;
            continue;
        }
        if record
            .updated_unix
            .saturating_add(PARTICIPANT_STALE_AFTER.as_secs())
            < now_unix
        {
            stale.push(format!(
                "{} (machine {}, data dir {}, last refreshed {}s ago)",
                path.display(),
                short(&record.machine_id),
                record.data_dir,
                now_unix.saturating_sub(record.updated_unix)
            ));
            continue;
        }
        match participant_not_due(&record, release) {
            None => {}
            // D185 now=true skips other participants' waits, not their holds.
            Some(NotDue::Wait(_)) if skip_waits => {}
            Some(NotDue::Wait(reason) | NotDue::Hold(reason)) => pending.push(PendingParticipant {
                key: key.to_string(),
                machine_id: record.machine_id.clone(),
                reason,
            }),
        }
    }
    if !own_seen {
        // Registration is pending or failed (logged by that daemon at
        // WARN). The set is not established: no swap, in any mode.
        pending.push(own_record_missing(own_key, &dir));
    }
    // Review S1: a live daemon that runs from this install but has no
    // record (it cannot write one) holds the shared "unregistered" signal.
    // Then no writer may swap, in any mode.
    let signal = unregistered_signal_path(target);
    match std::fs::File::open(&signal) {
        Ok(file) => match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => pending.push(PendingParticipant {
                key: String::new(),
                machine_id: String::new(),
                reason: format!(
                    "a daemon that runs from this install is not registered (it holds {}; \
                     registration pending or failed)",
                    signal.display()
                ),
            }),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(unknown(format!("cannot probe {}: {e}", signal.display())))
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(unknown(format!("cannot open {}: {e}", signal.display()))),
    }
    if pending.is_empty() {
        Ok(ParticipantGate::AllDue { stale })
    } else {
        Ok(ParticipantGate::Waiting { pending, stale })
    }
}

fn own_record_missing(own_key: &str, dir: &Path) -> PendingParticipant {
    PendingParticipant {
        key: own_key.to_string(),
        machine_id: String::new(),
        reason: format!(
            "this daemon's own record {own_key}.json is missing from {} (registration pending \
             or failed)",
            dir.display()
        ),
    }
}

/// Why a live participant is not due: a wait (time; D185 `now=true` may
/// skip it) or a hold (a blocked rollout state or self-update off; it never
/// ends by waiting, and now=true does not skip it).
enum NotDue {
    Wait(String),
    Hold(String),
}

/// `None` when the live participant is due for `release`, else why not.
fn participant_not_due(record: &ParticipantRecord, release: &Version) -> Option<NotDue> {
    let label = format!(
        "machine {} ({})",
        short(&record.machine_id),
        record.data_dir
    );
    if let Some(reason) = &record.blocked {
        return Some(NotDue::Hold(format!(
            "{label}: rollout state blocked: {reason}"
        )));
    }
    if Version::parse(&record.running_version).is_ok_and(|running| &running >= release) {
        return None;
    }
    // Review S4 (controller ruling): a configured hold, [update] enabled =
    // false, always wins, also over now=true.
    if !record.updates_enabled {
        return Some(NotDue::Hold(format!(
            "{label}: self-update is off for this daemon (a configured hold)"
        )));
    }
    let reason = match &record.staged {
        None => format!("{label}: has not staged v{release}"),
        Some(stage) => match Version::parse(&stage.release) {
            Ok(staged) if &staged >= release && stage.due => return None,
            Ok(staged) if &staged >= release => format!(
                "{label}: due for v{} in {}s",
                stage.release, stage.remaining_secs
            ),
            _ => format!("{label}: waits for v{}, not v{release}", stage.release),
        },
    };
    Some(NotDue::Wait(reason))
}

fn short(machine_id: &str) -> &str {
    machine_id.get(..16).unwrap_or(machine_id)
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
        write_record(install, &key, &record);
        key
    }

    fn write_record(install: &Install, key: &str, record: &ParticipantRecord) {
        let lock = super::super::HostUpgradeLock::try_acquire(&install.target)
            .unwrap()
            .expect("the test takes the host lock");
        write_own(&lock, &install.target, key, record).unwrap();
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
        let gate = check_all_due(&install.target, &a, &release(), NOW, false).unwrap();
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
            check_all_due(&install.target, &a, &release(), NOW, false).unwrap(),
            ParticipantGate::AllDue { stale: Vec::new() }
        );

        // A participant that already runs the release is due too.
        register(&install, "/var/lib/x0x-443", 2, "0.48.1", NOW, None);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, false).unwrap(),
            ParticipantGate::AllDue { .. }
        ));
    }

    #[test]
    fn a_participant_that_has_not_staged_the_release_blocks() {
        let install = install();
        let a = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", true));
        register(&install, "/b", 2, "0.48.0", NOW, None);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, false).unwrap(),
            ParticipantGate::Waiting { .. }
        ));
        register(&install, "/b", 2, "0.48.0", NOW, stage("0.48.0-old", true));
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, false).unwrap(),
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
        write_record(&install, &key, &record);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, false).unwrap(),
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
        let gate = check_all_due(&install.target, &a, &release(), NOW, false).unwrap();
        let ParticipantGate::AllDue { stale } = gate else {
            panic!("a stale record must not block: {gate:?}");
        };
        assert_eq!(stale.len(), 1);
        assert!(stale[0].contains(&b), "{stale:?}");

        // Just inside the window it still blocks.
        register(&install, "/gone", 2, "0.48.0", NOW - 60, None);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, false).unwrap(),
            ParticipantGate::Waiting { .. }
        ));
    }

    #[test]
    fn participants_that_cannot_be_established_refuse_the_swap() {
        let install = install();
        // No records at all: this daemon's own registration is missing, so
        // the participants are not established and the swap must not run.
        assert!(!matches!(
            check_all_due(&install.target, "self", &release(), NOW, false),
            Ok(ParticipantGate::AllDue { .. })
        ));
        let a = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", true));
        assert!(check_all_due(&install.target, &a, &release(), NOW, false).is_ok());

        // An unreadable record.
        let corrupt = participants_dir(&install.target).join("feedfacefeedface.json");
        std::fs::write(&corrupt, b"{ not json").unwrap();
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, false),
            Err(UpgradeError::ParticipantsUnknown { .. })
        ));
        // A record of another format.
        std::fs::write(
            &corrupt,
            br#"{"format":"x0x.upgrade-participant","version":9}"#,
        )
        .unwrap();
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, false),
            Err(UpgradeError::ParticipantsUnknown { .. })
        ));
        std::fs::remove_file(&corrupt).unwrap();
        assert!(check_all_due(&install.target, &a, &release(), NOW, false).is_ok());
    }

    #[test]
    fn a_daemon_with_updates_off_is_a_participant_that_waits() {
        // Codex R1: a daemon that runs from the install with self-update off
        // must not vanish from the participant set.
        let install = install();
        let a = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", true));
        let key = participant_key(Path::new("/off"));
        let record = ParticipantRecord::new(&[2; 32], Path::new("/off"), "0.48.0", NOW, None, None)
            .with_updates_enabled(false);
        write_record(&install, &key, &record);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, false).unwrap(),
            ParticipantGate::Waiting { .. }
        ));
    }

    #[test]
    fn a_now_bypass_skips_waits_but_keeps_holds() {
        // Codex R5 / D185: now=true skips the WAIT only. Other
        // participants' remaining waits do not stop the swap; their holds
        // and the transaction checks still do.
        let install = install();
        let a = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", true));
        register(&install, "/b", 2, "0.48.0", NOW, stage("0.48.1", false));
        assert!(
            matches!(
                check_all_due(&install.target, &a, &release(), NOW, true).unwrap(),
                ParticipantGate::AllDue { .. }
            ),
            "waits do not stop a now=true swap"
        );

        // Codex S4 / controller ruling: a configured hold ([update] enabled
        // = false) always wins over now=true.
        let key = participant_key(Path::new("/off"));
        let off = ParticipantRecord::new(&[3; 32], Path::new("/off"), "0.48.0", NOW, None, None)
            .with_updates_enabled(false);
        write_record(&install, &key, &off);
        assert!(
            matches!(
                check_all_due(&install.target, &a, &release(), NOW, true).unwrap(),
                ParticipantGate::Waiting { .. }
            ),
            "a daemon with updates off holds the shared install"
        );
        std::fs::remove_file(record_path(&install.target, &key)).unwrap();

        // A blocked (held) participant still stops it.
        let held_key = participant_key(Path::new("/held"));
        let held = ParticipantRecord::new(
            &[4; 32],
            Path::new("/held"),
            "0.48.0",
            NOW,
            stage("0.48.1", true),
            Some("unreadable rollout state".to_string()),
        );
        write_record(&install, &held_key, &held);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, true).unwrap(),
            ParticipantGate::Waiting { .. }
        ));

        // An unreadable record still refuses it.
        std::fs::remove_file(record_path(&install.target, &held_key)).unwrap();
        let corrupt = participants_dir(&install.target).join("feedfacefeedface.json");
        std::fs::write(&corrupt, b"{ not json").unwrap();
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, true),
            Err(UpgradeError::ParticipantsUnknown { .. })
        ));
        std::fs::remove_file(&corrupt).unwrap();

        // This daemon's own missing record still refuses it.
        assert!(!matches!(
            check_all_due(&install.target, "unregistered", &release(), NOW, true),
            Ok(ParticipantGate::AllDue { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_group_writable_install_gets_a_group_writable_participants_dir() {
        // Codex R1: on a group-shared install a second service account must
        // be able to add its record.
        use std::os::unix::fs::PermissionsExt;
        let install = install();
        let dir = install.target.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
        register(&install, "/a", 1, "0.48.0", NOW, None);
        let mode = std::fs::metadata(participants_dir(&install.target))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(
            mode & 0o020,
            0,
            "group write follows the install dir: {mode:o}"
        );
    }

    #[test]
    fn an_unregistered_live_daemon_blocks_every_writer() {
        // Codex S1: B runs from the install but could not write its record.
        // It holds the shared "unregistered" signal, so A must not swap.
        let install = install();
        let a = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", true));
        let signal = std::fs::File::create(unregistered_signal_path(&install.target)).unwrap();
        signal.try_lock_shared().unwrap();
        for skip_waits in [false, true] {
            assert!(
                matches!(
                    check_all_due(&install.target, &a, &release(), NOW, skip_waits).unwrap(),
                    ParticipantGate::Waiting { .. }
                ),
                "skip_waits={skip_waits}"
            );
        }
        drop(signal);
        assert!(matches!(
            check_all_due(&install.target, &a, &release(), NOW, false).unwrap(),
            ParticipantGate::AllDue { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_registration_fixes_an_existing_owner_only_participants_dir() {
        // Codex S1: a participants dir left at 0755 (older code, an
        // interrupted creation) must become group-writable on a shared install.
        use std::os::unix::fs::PermissionsExt;
        let install = install();
        let dir = install.target.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
        let participants = participants_dir(&install.target);
        std::fs::create_dir_all(&participants).unwrap();
        std::fs::set_permissions(&participants, std::fs::Permissions::from_mode(0o755)).unwrap();
        register(&install, "/a", 1, "0.48.0", NOW, None);
        let mode = std::fs::metadata(&participants)
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o020, 0, "group write is restored: {mode:o}");
    }

    // Two-account control (review S1), as two processes: a child registers
    // under umask 077; every registry file must stay usable by the install
    // group. (A real second account needs a host; this is the inert proxy.)
    const UMASK_TARGET: &str = "X0X_1106_UMASK_TARGET";

    #[test]
    fn umask_writer_child() {
        let Ok(target) = std::env::var(UMASK_TARGET) else {
            return; // a no-op unless the test below started this process
        };
        let target = PathBuf::from(target);
        let lock = super::super::HostUpgradeLock::try_acquire(&target)
            .unwrap()
            .expect("the child takes the host lock");
        let key = participant_key(Path::new("/umask"));
        let record =
            ParticipantRecord::new(&[7; 32], Path::new("/umask"), "0.48.0", NOW, None, None);
        write_own(&lock, &target, &key, &record).unwrap();
        drop(lock);
        drop(UnregisteredSignal::hold(&target));
    }

    #[cfg(unix)]
    #[test]
    fn registry_files_stay_group_usable_under_umask_077() {
        use std::os::unix::fs::PermissionsExt;
        let install = install();
        let dir = install.target.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg("umask 077 && exec \"$0\" --exact upgrade::participants::tests::umask_writer_child --test-threads=1 --quiet")
            .arg(&exe)
            .env(UMASK_TARGET, &install.target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "the umask 077 writer ran");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let participants = participants_dir(&install.target);
        assert_eq!(mode(&participants) & 0o070, 0o070, "group can add records");
        let record = record_path(&install.target, &participant_key(Path::new("/umask")));
        assert_ne!(mode(&record) & 0o040, 0, "group can read the record");
        let lock = super::super::HostUpgradeLock::lock_path_for(&install.target);
        assert_ne!(mode(&lock) & 0o040, 0, "group can open the host lock");
        let signal = unregistered_signal_path(&install.target);
        assert_ne!(
            mode(&signal) & 0o040,
            0,
            "group can hold the unregistered signal"
        );
    }

    #[test]
    fn own_record_round_trips_and_is_removed() {
        let install = install();
        let key = register(&install, "/a", 1, "0.48.0", NOW, stage("0.48.1", false));
        let bytes = std::fs::read(record_path(&install.target, &key)).unwrap();
        let record: ParticipantRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record.machine_id, hex::encode([1u8; 32]));
        assert_eq!(record.staged, stage("0.48.1", false));
        let lock = super::super::HostUpgradeLock::try_acquire(&install.target)
            .unwrap()
            .unwrap();
        remove_own(&lock, &install.target, &key).unwrap();
        assert!(!record_path(&install.target, &key).exists());
        remove_own(&lock, &install.target, &key).unwrap();
    }
}
