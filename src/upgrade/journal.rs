//! Durable, versioned M2 records (ADR 0094 sections 3 and 6).
//!
//! These records are diagnostic until S3 supplies the launcher, host lock,
//! trusted install inventory and hash reconciliation. Parsing a record never
//! grants permission to apply, restore, spawn a recorded path or commit health.
//! In particular, a readable replacement does not prove that its writer
//! completed the parent-directory sync.

// S2a defines the records that later M2 slices consume.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const JOURNAL_FILE_NAME: &str = "upgrade-journal.json";
pub(crate) const HANDOFF_FILE_NAME: &str = "upgrade-handoff.json";
pub(crate) const BOOT_FILE_NAME: &str = "upgrade-boot.json";
pub(crate) const SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// Frozen paths and hashes are evidence, not trusted recovery destinations.
/// Recovery must compare them with independent install inventory under the
/// host lock and hash the actual files before taking any action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactPlan {
    pub target_path: PathBuf,
    pub staged_path: PathBuf,
    pub backup_path: PathBuf,
    pub previous_sha256: [u8; 32],
    pub candidate_sha256: [u8; 32],
}

/// Names match the released restart-plan modes. LauncherChild is reserved
/// for S3; reading it does not establish a loaded launcher binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RestartOwner {
    TransactionalHandoff,
    SupervisedExit,
    LauncherChild,
}

/// These fields match the existing launchd diagnostic record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LaunchdBinding {
    pub label: String,
    pub domain: String,
}

/// These fields match the existing systemd diagnostic record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdBinding {
    pub unit: String,
    pub user_manager: bool,
    pub restart: String,
    pub template_version: Option<u32>,
}

/// Captured launcher identity, distinct from the participant child identity.
/// Stopped jobs may have no live launcher PID/start-time pair. A later
/// coordinator must verify this binding against the actual loaded job.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LauncherBinding {
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub pid: Option<u32>,
    pub process_start: Option<u64>,
    pub boot_id: String,
    /// The manager's launcher-exit policy is separate from child upgrade exit.
    pub manager_exit_code: i32,
}

// Captured arguments, environment and legacy payloads can contain credentials.
// Redact the complete value, including nested and alternate Debug formatting.
impl fmt::Debug for LauncherBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LauncherBinding(<redacted>)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestartBinding {
    pub mode: RestartOwner,
    pub supervised_exit_code: Option<i32>,
    pub supervision_signal: Option<String>,
    pub launchd_verified: Option<LaunchdBinding>,
    pub systemd_verified: Option<SystemdBinding>,
    pub launcher: Option<LauncherBinding>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Participant {
    pub instance_id: String,
    pub executable: PathBuf,
    pub data_root: PathBuf,
    pub identity_root: PathBuf,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    /// Captured approved environment, not a new read of process state.
    pub env: BTreeMap<String, String>,
    pub restart: RestartBinding,
    pub old_pid: Option<u32>,
    pub process_start: Option<u64>,
    pub boot_id: String,
    pub was_running: bool,
}

// Captured arguments, environment and legacy payloads can contain credentials.
// Redact the complete value, including nested and alternate Debug formatting.
impl fmt::Debug for Participant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Participant(<redacted>)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenPlan {
    pub previous_version: String,
    pub candidate_version: String,
    pub manifest_sha256: [u8; 32],
    pub daemon: ArtifactPlan,
    pub cli: ArtifactPlan,
    pub participants: Vec<Participant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Staged,
    Probed,
    Prepared,
    SwappedDaemon,
    SwappedCli,
    HandoffArmed,
    Booting,
    HealthCommitted,
    HostCommitted,
    RollingBack,
    FailedReleaseHold,
    Restored,
    RecoveryFailed,
    Idle,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CauseClass {
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cause {
    pub class: CauseClass,
    pub reason: String,
}

/// Swap and restore progress stay separate for the two executable files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactProgress {
    pub swapped: bool,
    pub restored: bool,
    pub observed_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalRecord {
    pub schema_version: u32,
    pub record_kind: String,
    pub transaction_id: String,
    pub sequence: u64,
    pub generation: u64,
    pub plan: FrozenPlan,
    pub phase: Phase,
    pub cause: Option<Cause>,
    pub daemon_progress: ArtifactProgress,
    pub cli_progress: ArtifactProgress,
}

/// Legacy fields remain top-level so released readers can diagnose them.
/// A versioned M2 handoff is distinct from the legacy helper's intent.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct M2HandoffRecord {
    pub schema_version: u32,
    pub record_kind: String,
    pub transaction_id: String,
    pub generation: u64,
    pub instance_id: String,
    #[serde(flatten)]
    pub legacy: BTreeMap<String, Value>,
}

// Captured arguments, environment and legacy payloads can contain credentials.
// Redact the complete value, including nested and alternate Debug formatting.
impl fmt::Debug for M2HandoffRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("M2HandoffRecord(<redacted>)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootRecord {
    pub schema_version: u32,
    pub record_kind: String,
    pub transaction_id: String,
    pub generation: u64,
    pub instance_id: String,
    pub attempt: u32,
    pub pid: u32,
    pub process_start: u64,
    pub boot_id: String,
    /// Suspend-inclusive monotonic times in nanoseconds, in this boot.
    pub started_at_ns: u64,
    pub deadline_ns: u64,
}

pub(crate) enum RecordRead {
    Missing,
    Journal(Box<JournalRecord>),
    Handoff(M2HandoffRecord),
    Boot(BootRecord),
    LegacyHandoff(Value),
    Refused(String),
}

// Captured arguments, environment and legacy payloads can contain credentials.
// Redact the complete value, including nested and alternate Debug formatting.
impl fmt::Debug for RecordRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordRead(<redacted>)")
    }
}

#[derive(Debug)]
pub(crate) struct BootRecords {
    pub journal: RecordRead,
    pub handoff: RecordRead,
    pub boot: RecordRead,
}

impl BootRecords {
    pub(crate) fn configured_start_allowed(&self) -> bool {
        true
    }

    pub(crate) fn may_apply(&self) -> bool {
        false
    }

    pub(crate) fn may_recover(&self) -> bool {
        false
    }

    pub(crate) fn has_records(&self) -> bool {
        [&self.journal, &self.handoff, &self.boot]
            .iter()
            .any(|record| !matches!(record, RecordRead::Missing))
    }

    /// Existing legacy intent is diagnostic and keeps the pre-M2 planner
    /// contract. Any M2, unknown or corrupt record prevents a new apply.
    pub(crate) fn blocks_apply(&self) -> bool {
        [&self.journal, &self.handoff, &self.boot]
            .iter()
            .any(|record| !matches!(record, RecordRead::Missing | RecordRead::LegacyHandoff(_)))
    }

    pub(crate) fn diagnostic(&self) -> Option<String> {
        let refused: Vec<_> = [
            (JOURNAL_FILE_NAME, &self.journal),
            (HANDOFF_FILE_NAME, &self.handoff),
            (BOOT_FILE_NAME, &self.boot),
        ]
        .into_iter()
        .filter_map(|(name, record)| match record {
            // Parser errors can quote credentials from a malformed record.
            // Name the fixed record, but do not expose its refusal text.
            RecordRead::Refused(_) => Some(format!("{name}: record refused (details redacted)")),
            _ => None,
        })
        .collect();
        if !refused.is_empty() {
            Some(format!(
                "upgrade protection is unprotected/degraded; records preserved; \
                 no apply or recovery action: {}",
                refused.join("; ")
            ))
        } else if self.has_records() {
            Some(
                "upgrade protection is unprotected/degraded; diagnostic records preserved; \
                 M2 recovery is not active"
                    .into(),
            )
        } else {
            None
        }
    }
}

/// Read only the three fixed record names. Never follow paths from records,
/// remove records or temporary files, or turn a read failure into startup failure.
pub(crate) fn read_boot_records(data_dir: &Path) -> BootRecords {
    BootRecords {
        journal: read_record(&data_dir.join(JOURNAL_FILE_NAME), "journal"),
        handoff: read_record(&data_dir.join(HANDOFF_FILE_NAME), "handoff"),
        boot: read_record(&data_dir.join(BOOT_FILE_NAME), "boot"),
    }
}

/// Pending or unreadable M2 records have no safe cleanup reference set.
/// Ordinary released legacy intent permits unrelated debris cleanup. If its
/// recorded target or backup can match the sweep patterns, preserve candidates
/// conservatively instead. No path taken from a record is followed.
pub(crate) fn sweep_if_no_pending_records(data_dir: &Path, sweep: impl FnOnce() -> usize) -> usize {
    let records = read_boot_records(data_dir);
    let legacy_references_candidates = match &records.handoff {
        RecordRead::LegacyHandoff(value) => ["target_path", "backup_path"].iter().any(|name| {
            value.get(name).and_then(Value::as_str).is_none_or(|path| {
                Path::new(path).components().any(|component| {
                    let name = component.as_os_str().to_string_lossy();
                    name.starts_with(".x0x-upgrade-") || name.contains(".x0xold-")
                })
            })
        }),
        _ => false,
    };
    if records.blocks_apply() || legacy_references_candidates {
        0
    } else {
        sweep()
    }
}

fn read_record(path: &Path, expected: &str) -> RecordRead {
    match read_bytes(path) {
        Ok(bytes) => match classify(&bytes, expected) {
            Ok(record) => record,
            Err(error) => RecordRead::Refused(error.to_string()),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => RecordRead::Missing,
        Err(error) => RecordRead::Refused(error.to_string()),
    }
}

fn read_bytes(path: &Path) -> io::Result<Vec<u8>> {
    // A symlink must not redirect a fixed record name outside its directory.
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("record is not a regular file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("record is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid("record exceeds the size limit"));
    }
    Ok(bytes)
}

/// Read an auxiliary upgrade record through the journal's bounded,
/// regular-file, no-symlink reader. The caller validates its schema.
pub(crate) fn read_auxiliary_record(path: &Path) -> io::Result<Vec<u8>> {
    read_bytes(path)
}

fn classify(bytes: &[u8], expected: &str) -> io::Result<RecordRead> {
    let value: Value = serde_json::from_slice(bytes).map_err(invalid)?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("record must be a JSON object"))?;
    if !object.contains_key("schema_version") {
        if expected != "handoff" || object.contains_key("record_kind") {
            return Err(invalid("record has no schema_version"));
        }
        validate_legacy(&value)?;
        return Ok(RecordRead::LegacyHandoff(value));
    }
    if object.get("schema_version").and_then(Value::as_u64) != Some(SCHEMA_VERSION.into()) {
        return Err(invalid("unknown or invalid schema_version"));
    }
    let kind = object
        .get("record_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("record has no record_kind"))?;
    match (expected, kind) {
        ("journal", "journal") => {
            let record: JournalRecord = serde_json::from_value(value).map_err(invalid)?;
            validate_journal(&record)?;
            Ok(RecordRead::Journal(Box::new(record)))
        }
        ("boot", "boot") => {
            let record: BootRecord = serde_json::from_value(value).map_err(invalid)?;
            nonempty(&record.transaction_id)?;
            nonempty(&record.instance_id)?;
            nonempty(&record.boot_id)?;
            if record.attempt == 0 || record.pid == 0 || record.deadline_ns < record.started_at_ns {
                return Err(invalid("invalid boot attempt, process or deadline"));
            }
            Ok(RecordRead::Boot(record))
        }
        ("handoff", "handoff") => {
            let record: M2HandoffRecord = serde_json::from_value(value).map_err(invalid)?;
            nonempty(&record.transaction_id)?;
            nonempty(&record.instance_id)?;
            validate_legacy(&serde_json::to_value(&record.legacy).map_err(invalid)?)?;
            Ok(RecordRead::Handoff(record))
        }
        ("handoff", "legacy_handoff") => {
            validate_legacy(&value)?;
            Ok(RecordRead::LegacyHandoff(value))
        }
        _ => Err(invalid("unknown record_kind or wrong record location")),
    }
}

fn validate_journal(record: &JournalRecord) -> io::Result<()> {
    nonempty(&record.transaction_id)?;
    semver::Version::parse(&record.plan.previous_version).map_err(invalid)?;
    semver::Version::parse(&record.plan.candidate_version).map_err(invalid)?;
    if record.plan.participants.is_empty() {
        return Err(invalid("journal has no frozen participants"));
    }
    let mut paths = std::collections::BTreeSet::new();
    for artifact in [&record.plan.daemon, &record.plan.cli] {
        for path in [
            &artifact.target_path,
            &artifact.staged_path,
            &artifact.backup_path,
        ] {
            absolute_path(path)?;
            if !paths.insert(path) {
                return Err(invalid("artifact paths overlap"));
            }
        }
    }
    let mut instances = std::collections::BTreeSet::new();
    for participant in &record.plan.participants {
        nonempty(&participant.instance_id)?;
        nonempty(&participant.boot_id)?;
        if !instances.insert(&participant.instance_id) {
            return Err(invalid("duplicate participant"));
        }
        absolute_path(&participant.executable)?;
        for directory in [
            &participant.data_root,
            &participant.identity_root,
            &participant.cwd,
        ] {
            absolute_directory(directory)?;
        }
        validate_restart_binding(&participant.restart)?;
        if participant.executable != record.plan.daemon.target_path {
            return Err(invalid(
                "participant executable differs from frozen install",
            ));
        }
        if participant.argv.is_empty()
            || (participant.was_running
                && (participant.old_pid.is_none_or(|pid| pid == 0)
                    || participant.process_start.is_none()))
        {
            return Err(invalid("participant process identity is incomplete"));
        }
    }
    Ok(())
}

fn validate_restart_binding(binding: &RestartBinding) -> io::Result<()> {
    if let Some(signal) = &binding.supervision_signal {
        nonempty(signal)?;
    }
    if let Some(launchd) = &binding.launchd_verified {
        nonempty(&launchd.label)?;
        nonempty(&launchd.domain)?;
    }
    if let Some(systemd) = &binding.systemd_verified {
        nonempty(&systemd.unit)?;
        nonempty(&systemd.restart)?;
    }
    if let Some(launcher) = &binding.launcher {
        absolute_path(&launcher.executable)?;
        nonempty(&launcher.boot_id)?;
        if launcher.argv.is_empty()
            || launcher.pid == Some(0)
            || launcher.pid.is_some() != launcher.process_start.is_some()
        {
            return Err(invalid("launcher process identity is incomplete"));
        }
    }
    // Optional observations remain optional for direct jobs. Complete loaded
    // binding, ownership and policy checks belong to the future coordinator.
    if binding.mode == RestartOwner::LauncherChild && binding.launcher.is_none() {
        return Err(invalid("launcher-owned participant has no launcher record"));
    }
    Ok(())
}

fn absolute_path(path: &Path) -> io::Result<()> {
    absolute_directory(path)?;
    if path.file_name().is_none() {
        return Err(invalid("record file path has no file name"));
    }
    Ok(())
}

fn absolute_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("record path is not an absolute normalized path"));
    }
    Ok(())
}

fn nonempty(value: &str) -> io::Result<()> {
    if value.trim().is_empty() {
        Err(invalid("record identifier is empty"))
    } else {
        Ok(())
    }
}

fn validate_legacy(value: &Value) -> io::Result<()> {
    // Match the released required fields without depending on restart.rs.
    // Additional legacy diagnostics remain byte-for-byte values in the map.
    for name in [
        "from_version",
        "to_version",
        "target_path",
        "backup_path",
        "cwd",
        "api_addr",
    ] {
        value
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("legacy handoff has invalid {name}")))?;
    }
    let argv = value
        .get("argv")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("legacy handoff has invalid argv"))?;
    if argv.iter().any(|arg| !arg.is_string()) {
        return Err(invalid("legacy handoff has non-string argv"));
    }
    let env = value
        .get("env")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("legacy handoff has invalid env"))?;
    if env.values().any(|entry| !entry.is_string()) {
        return Err(invalid("legacy handoff has non-string environment"));
    }
    for name in ["old_pid", "started_at"] {
        let number = value
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid(format!("legacy handoff has invalid {name}")))?;
        if name == "old_pid" && number > u32::MAX.into() {
            return Err(invalid("legacy handoff pid is out of range"));
        }
    }
    let mode = value.get("mode").and_then(Value::as_str);
    if !matches!(mode, Some("SupervisedExit" | "TransactionalHandoff")) {
        return Err(invalid("legacy handoff has invalid mode"));
    }
    value["api_addr"]
        .as_str()
        .ok_or_else(|| invalid("legacy handoff has invalid api_addr"))?
        .parse::<std::net::SocketAddr>()
        .map_err(invalid)?;
    if let Some(job) = value
        .get("launchd_verified")
        .filter(|value| !value.is_null())
    {
        for name in ["label", "domain"] {
            if job.get(name).and_then(Value::as_str).is_none() {
                return Err(invalid("legacy handoff has invalid launchd diagnostics"));
            }
        }
    }
    if let Some(unit) = value
        .get("systemd_verified")
        .filter(|value| !value.is_null())
    {
        if unit.get("unit").and_then(Value::as_str).is_none()
            || unit.get("restart").and_then(Value::as_str).is_none()
            || unit.get("user_manager").and_then(Value::as_bool).is_none()
            || unit
                .get("template_version")
                .filter(|value| !value.is_null())
                .is_some_and(|value| {
                    value
                        .as_u64()
                        .is_none_or(|version| version > u32::MAX.into())
                })
        {
            return Err(invalid("legacy handoff has invalid systemd diagnostics"));
        }
    }
    Ok(())
}

/// Decode only released helper intent. An M2 handoff cannot be accidentally
/// consumed by the old helper; it needs the future coordinator's checks.
pub(crate) fn decode_handoff(bytes: &[u8]) -> io::Result<Value> {
    match classify(bytes, "handoff")? {
        RecordRead::LegacyHandoff(value) => Ok(value),
        _ => Err(invalid("M2 handoff requires its launcher recovery owner")),
    }
}

pub(crate) fn read_handoff(path: &Path) -> io::Result<Value> {
    decode_handoff(&read_bytes(path)?)
}

/// Unix uses the durable versioned diagnostic writer. Windows retains the
/// released unmanaged helper's unversioned intent, without an M2 durability
/// claim; typed M2 writes still require the directory barrier.
pub(crate) fn write_handoff(path: &Path, handoff: &impl Serialize) -> io::Result<()> {
    #[cfg(windows)]
    {
        write_legacy_handoff(path, handoff)
    }
    #[cfg(not(windows))]
    {
        let mut value = serde_json::to_value(handoff).map_err(invalid)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| invalid("handoff must be an object"))?;
        object.insert("schema_version".into(), Value::from(SCHEMA_VERSION));
        object.insert("record_kind".into(), Value::from("legacy_handoff"));
        write_record(path, &value)
    }
}

/// Compatibility writer for the unmanaged Windows helper. Rename avoids
/// truncating the previous record while its replacement is written. There is
/// no supported directory-sync barrier here, so this is never M2 armed intent.
#[cfg(any(windows, test))]
pub(crate) fn write_legacy_handoff(path: &Path, handoff: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(handoff).map_err(invalid)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid("record exceeds the size limit"));
    }
    let value = decode_handoff(&bytes)?;
    if value.get("schema_version").is_some() || value.get("record_kind").is_some() {
        return Err(invalid(
            "legacy compatibility writes require unversioned helper intent",
        ));
    }
    match read_handoff(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Released Windows writes create a missing data directory. This remains
    // compatibility behavior and does not claim a durable ancestor barrier.
    std::fs::create_dir_all(parent)?;
    let (temporary_path, mut temporary) = create_replacement(parent)?;
    let result = (|| {
        temporary.write_all(&bytes)?;
        temporary.sync_all()?;
        drop(temporary);
        std::fs::rename(&temporary_path, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

/// Complete the record barrier before acknowledging success. The caller must
/// hold the host lock for transaction changes. A failure grants no next step.
/// The parent directory must already exist; creating the data root is outside
/// this record operation.
pub(crate) fn write_record(path: &Path, record: &impl Serialize) -> io::Result<()> {
    write_record_inner(path, record, |_| Ok(()))
}

/// Check the platform and filesystem barrier before staging or binary swap.
/// This opens and syncs an existing directory; it creates no record or root.
/// A passing preflight cannot predict later I/O failure, so the writer still
/// checks every barrier and never acknowledges a failed operation.
pub(crate) fn check_record_barrier_support(data_dir: &Path) -> io::Result<()> {
    #[cfg(any(unix, windows))]
    {
        let directory = open_for_sync(data_dir, true).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot open upgrade record directory: {error}"),
            )
        })?;
        if !directory.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upgrade record parent must be an existing directory",
            ));
        }
        directory.sync_all().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("upgrade record directory sync is unavailable: {error}"),
            )
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = data_dir;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable upgrade record directory sync is unsupported on this platform; \
             apply must be refused before replacing binaries",
        ))
    }
}

/// Open a file or directory for a `sync_all` barrier. Unix opens it
/// read-only. Windows `FlushFileBuffers` needs write access, and a directory
/// handle needs `FILE_FLAG_BACKUP_SEMANTICS`; NTFS then flushes the directory
/// entries, the Windows equivalent of a Unix directory fsync (#1588). A file
/// system that refuses the flush fails the barrier, and the caller refuses.
pub(crate) fn open_for_sync(path: &Path, directory: bool) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let mut options = OpenOptions::new();
        options.write(true);
        if directory {
            options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        }
        options.open(path)
    }
    #[cfg(not(windows))]
    {
        let _ = directory;
        File::open(path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BarrierStep {
    Write,
    FileSync,
    Rename,
    DirectorySync,
}

/// Deterministic faults immediately before the real barrier operation.
#[cfg(test)]
pub(crate) fn write_record_with_failure(
    path: &Path,
    record: &impl Serialize,
    failure: BarrierStep,
) -> io::Result<()> {
    write_record_inner(path, record, |step| {
        if step == failure {
            Err(io::Error::other(format!("injected {step:?} failure")))
        } else {
            Ok(())
        }
    })
}

fn write_record_inner(
    path: &Path,
    record: &impl Serialize,
    before: impl FnMut(BarrierStep) -> io::Result<()>,
) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(record).map_err(invalid)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid("record exceeds the size limit"));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(invalid)?;
    let kind = value
        .get("record_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("new record has no record_kind"))?;
    let expected = match kind {
        "legacy_handoff" | "handoff" => "handoff",
        "journal" => "journal",
        "boot" => "boot",
        _ => return Err(invalid("new record has unknown record_kind")),
    };
    classify(&bytes, expected)?;
    match read_bytes(path) {
        Ok(existing) => {
            // Unknown or corrupt records are retained for operator diagnosis.
            classify(&existing, expected)?;
            let prior: Value = serde_json::from_slice(&existing).map_err(invalid)?;
            if prior
                .get("record_kind")
                .and_then(Value::as_str)
                .is_some_and(|prior_kind| prior_kind != kind)
                || (!prior
                    .as_object()
                    .is_some_and(|object| object.contains_key("schema_version"))
                    && kind != "legacy_handoff")
            {
                return Err(invalid("cannot replace a different recovery record kind"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    replace_record_bytes(path, &bytes, before)
}

/// A slice may define a smaller record than the complete transaction plan.
/// Both old and new bytes must pass its strict decoder before replacement.
pub(crate) fn write_auxiliary_record(
    path: &Path,
    record: &impl Serialize,
    validate: fn(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    write_auxiliary_record_inner(path, record, validate, |_| Ok(()))
}

#[cfg(test)]
pub(crate) fn write_auxiliary_record_with_failure(
    path: &Path,
    record: &impl Serialize,
    validate: fn(&[u8]) -> io::Result<()>,
    fail: BarrierStep,
) -> io::Result<()> {
    write_auxiliary_record_inner(path, record, validate, |step| {
        if step == fail {
            Err(io::Error::other(
                "injected auxiliary record barrier failure",
            ))
        } else {
            Ok(())
        }
    })
}

fn write_auxiliary_record_inner(
    path: &Path,
    record: &impl Serialize,
    validate: fn(&[u8]) -> io::Result<()>,
    before: impl FnMut(BarrierStep) -> io::Result<()>,
) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(record).map_err(invalid)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid("record exceeds the size limit"));
    }
    validate(&bytes)?;
    match read_bytes(path) {
        Ok(existing) => validate(&existing)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    replace_record_bytes(path, &bytes, before)
}

fn replace_record_bytes(
    path: &Path,
    bytes: &[u8],
    mut before: impl FnMut(BarrierStep) -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    check_record_barrier_support(parent)?;
    let directory = open_for_sync(parent, true)?;
    let (temporary_path, mut temporary) = create_replacement(parent)?;
    let result = (|| {
        before(BarrierStep::Write)?;
        temporary.write_all(bytes)?;
        before(BarrierStep::FileSync)?;
        temporary.sync_all()?;
        before(BarrierStep::Rename)?;
        std::fs::rename(&temporary_path, path)?;
        before(BarrierStep::DirectorySync)?;
        directory.sync_all()
    })();
    // Only this invocation's uninstalled replacement is removed. Never sweep
    // crash remnants or referenced files; the installed record is preserved
    // even when the final directory sync fails.
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

fn create_replacement(parent: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..16 {
        let path = parent.join(format!(
            ".x0x-upgrade-record-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not reserve an upgrade record replacement",
    ))
}

fn invalid(reason: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.to_string())
}

#[cfg(test)]
mod debug_tests {
    use super::*;
    use serde_json::json;

    const ARGUMENT: &str = "journal-argument-secret";
    const ENVIRONMENT: &str = "journal-environment-secret";

    fn assert_redacted(value: &impl std::fmt::Debug, label: &str) {
        let expected = format!("{label}(<redacted>)");
        assert_eq!(format!("{value:?}"), expected);
        assert_eq!(format!("{value:#?}"), expected);
        assert_eq!(format!("{:?}", Some(value)), format!("Some({expected})"));
        assert_eq!(format!("{:#?}", [value]), format!("[\n    {expected},\n]"));
    }

    fn assert_no_credentials(value: &impl std::fmt::Debug) {
        for output in [format!("{value:?}"), format!("{value:#?}")] {
            assert!(!output.contains(ARGUMENT));
            assert!(!output.contains(ENVIRONMENT));
        }
    }

    fn launcher() -> LauncherBinding {
        LauncherBinding {
            executable: "/owned/bin/launcher".into(),
            argv: vec!["launcher".into(), ARGUMENT.into()],
            pid: Some(23),
            process_start: Some(42),
            boot_id: "boot-a".into(),
            manager_exit_code: 75,
        }
    }

    fn participant() -> Participant {
        Participant {
            instance_id: "alice".into(),
            executable: "/owned/bin/x0xd".into(),
            data_root: "/owned/data".into(),
            identity_root: "/owned/identity".into(),
            argv: vec!["x0xd".into(), ARGUMENT.into()],
            cwd: "/owned".into(),
            env: BTreeMap::from([("TOKEN".into(), ENVIRONMENT.into())]),
            restart: RestartBinding {
                mode: RestartOwner::LauncherChild,
                supervised_exit_code: None,
                supervision_signal: None,
                launchd_verified: None,
                systemd_verified: None,
                launcher: Some(launcher()),
            },
            old_pid: Some(24),
            process_start: Some(43),
            boot_id: "boot-a".into(),
            was_running: true,
        }
    }

    fn legacy() -> Value {
        json!({
            "from_version": "0.48.1", "to_version": "0.48.2",
            "target_path": "/owned/bin/x0xd", "backup_path": "/owned/bin/x0xd.backup",
            "argv": ["x0xd", ARGUMENT], "cwd": "/owned",
            "env": {"TOKEN": ENVIRONMENT}, "old_pid": 24,
            "api_addr": "127.0.0.1:12700", "started_at": 1_792_500_000,
            "mode": "TransactionalHandoff", "launchd_verified": null,
            "systemd_verified": null
        })
    }

    #[test]
    fn launcher_debug_redacts_arguments_without_changing_serialization() {
        let record = launcher();
        let before = serde_json::to_value(&record).unwrap();
        assert_eq!(before["argv"][1], ARGUMENT);
        assert_redacted(&record, "LauncherBinding");
        let decoded: LauncherBinding = serde_json::from_value(before.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), before);
    }

    #[test]
    fn participant_debug_redacts_arguments_and_environment_without_changing_serialization() {
        let record = participant();
        let before = serde_json::to_value(&record).unwrap();
        assert_eq!(before["argv"][1], ARGUMENT);
        assert_eq!(before["env"]["TOKEN"], ENVIRONMENT);
        assert_redacted(&record, "Participant");
        let decoded: Participant = serde_json::from_value(before.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), before);
    }

    #[test]
    fn restart_binding_debug_does_not_reveal_nested_launcher_arguments() {
        let record = participant().restart;
        assert_no_credentials(&record);
        assert!(format!("{record:?}").contains("LauncherBinding(<redacted>)"));
    }

    #[test]
    fn frozen_plan_debug_does_not_reveal_nested_participant_credentials() {
        let artifact = ArtifactPlan {
            target_path: "/owned/bin/x0xd".into(),
            staged_path: "/owned/staged".into(),
            backup_path: "/owned/backup".into(),
            previous_sha256: [1; 32],
            candidate_sha256: [2; 32],
        };
        let record = FrozenPlan {
            previous_version: "0.48.1".into(),
            candidate_version: "0.48.2".into(),
            manifest_sha256: [3; 32],
            daemon: artifact.clone(),
            cli: artifact,
            participants: vec![participant()],
        };
        assert_no_credentials(&record);
        assert!(format!("{record:?}").contains("Participant(<redacted>)"));
    }

    #[test]
    fn m2_handoff_debug_redacts_flattened_legacy_credentials_without_changing_serialization() {
        let mut value = legacy();
        value["schema_version"] = json!(SCHEMA_VERSION);
        value["record_kind"] = json!("handoff");
        value["transaction_id"] = json!("transaction-a");
        value["generation"] = json!(3);
        value["instance_id"] = json!("alice");
        let record: M2HandoffRecord = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(record.legacy["argv"][1], ARGUMENT);
        assert_eq!(record.legacy["env"]["TOKEN"], ENVIRONMENT);
        assert_redacted(&record, "M2HandoffRecord");
        assert_eq!(serde_json::to_value(&record).unwrap(), value);
        assert_no_credentials(&RecordRead::Handoff(record));
    }

    #[test]
    fn record_read_debug_redacts_legacy_credentials_and_refusal_details() {
        let value = legacy();
        let record = classify(&serde_json::to_vec(&value).unwrap(), "handoff").unwrap();
        assert_redacted(&record, "RecordRead");
        match &record {
            RecordRead::LegacyHandoff(decoded) => assert_eq!(decoded, &value),
            _ => panic!("expected legacy handoff"),
        }
        let records = BootRecords {
            journal: RecordRead::Missing,
            handoff: record,
            boot: RecordRead::Refused(format!("invalid credential: {ENVIRONMENT}")),
        };
        assert_no_credentials(&records);
        assert_redacted(&records.boot, "RecordRead");
    }
}

#[cfg(test)]
mod refusal_diagnostics_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn refusal_diagnostics_omit_all_record_reasons() {
        let records = BootRecords {
            journal: RecordRead::Refused("journal-argument-secret".into()),
            handoff: RecordRead::Refused("handoff-environment-secret".into()),
            boot: RecordRead::Refused("boot-credential-secret".into()),
        };
        let diagnostic = records.diagnostic().expect("refusal diagnostic");
        for name in [JOURNAL_FILE_NAME, HANDOFF_FILE_NAME, BOOT_FILE_NAME] {
            assert!(diagnostic.contains(name));
        }
        assert!(!diagnostic.contains("secret"));
        assert!(diagnostic.contains("records preserved"));
        assert!(records.blocks_apply());
        assert!(records.configured_start_allowed());
        assert!(!records.may_apply());
        assert!(!records.may_recover());
    }

    #[test]
    fn refusal_diagnostics_redact_real_parser_failure_without_rewriting_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(BOOT_FILE_NAME);
        let value = json!({
            "schema_version": SCHEMA_VERSION, "record_kind": "boot",
            "attempt": "record-parser-secret", "transaction_id": "tx",
            "generation": 1, "instance_id": "alice", "pid": 23,
            "process_start": 1, "boot_id": "boot-a",
            "started_at_ns": 1, "deadline_ns": 2
        });
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let records = read_boot_records(dir.path());
        match &records.boot {
            RecordRead::Refused(reason) => assert!(reason.contains("record-parser-secret")),
            _ => panic!("fixture must reach the real parser refusal"),
        }
        let diagnostic = records.diagnostic().unwrap();
        assert!(!diagnostic.contains("record-parser-secret"));
        assert!(diagnostic.contains(BOOT_FILE_NAME));
        assert!(records.blocks_apply());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn refusal_diagnostics_keep_missing_and_valid_boot_controls() {
        let dir = tempfile::tempdir().unwrap();
        let empty = read_boot_records(dir.path());
        assert!(empty.diagnostic().is_none());
        assert!(!empty.blocks_apply());
        let value = json!({
            "schema_version": SCHEMA_VERSION, "record_kind": "boot",
            "attempt": 1, "transaction_id": "tx", "generation": 1,
            "instance_id": "alice", "pid": 23, "process_start": 1,
            "boot_id": "boot-a", "started_at_ns": 1, "deadline_ns": 2
        });
        let path = dir.path().join(BOOT_FILE_NAME);
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let records = read_boot_records(dir.path());
        assert!(matches!(records.boot, RecordRead::Boot(_)));
        assert!(records.blocks_apply());
        assert!(records.configured_start_allowed());
        assert!(!records.may_apply());
        assert!(!records.may_recover());
        assert!(records
            .diagnostic()
            .unwrap()
            .contains("M2 recovery is not active"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}
