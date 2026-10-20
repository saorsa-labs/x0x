//! Pre-swap execution probes and install-scoped holds (ADR 0094 section 2).
//!
//! The caller owns the canonical install lock through admission and replacement.
//! A probe receipt is execution evidence, never recovery or restart authority.
//! Windows retains the released unmanaged apply path until its record barriers
//! have a supported implementation; the inert flag itself is cross-platform.
#![cfg(unix)]

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::journal;

pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(90);
const OUTPUT_LIMIT: usize = 8192;
const MAX_CANDIDATE_BYTES: u64 = 200 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);
const RETRY_DELAYS_MS: [u64; 3] = [30 * 60_000, 60 * 60_000, 120 * 60_000];

/// Captured with the carried restart plan, before any await or mutation.
/// The child inherits the old process's effective account and groups.
#[derive(Clone)]
pub(crate) struct ProbeLaunch {
    pub cwd: PathBuf,
    pub env: Vec<(OsString, OsString)>,
}

impl std::fmt::Debug for ProbeLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProbeLaunch")
            .field("cwd", &self.cwd)
            .field("environment_entries", &self.env.len())
            .finish()
    }
}

impl ProbeLaunch {
    pub(crate) fn capture(cwd: &Path) -> Self {
        Self {
            cwd: cwd.to_path_buf(),
            env: std::env::vars_os().collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProbeRequest {
    /// Existing installed daemon, not its parent directory.
    pub install: PathBuf,
    pub version: String,
    pub platform: String,
    /// The digest already authenticated by the release manifest.
    pub archive_sha256: [u8; 32],
    pub daemon: PathBuf,
    pub cli: PathBuf,
    pub launch: ProbeLaunch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeClock {
    pub boot_id: String,
    pub monotonic_ms: u64,
}

impl ProbeClock {
    fn now() -> io::Result<Self> {
        Ok(Self {
            boot_id: boot_id()?,
            monotonic_ms: monotonic_ms()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbePhase {
    Running,
    Passed,
    InterruptedWait,
    FailedHold,
    RecoveryFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbeCause {
    ExecFailed,
    NonzeroExit,
    InvalidOutput,
    VersionMismatch,
    PlatformMismatch,
    OutputLimit,
    Timeout,
    HostIo,
    Cancelled,
    CandidateChanged,
    RetriesExhausted,
    HoldWriteFailed,
    StateWriteFailed,
    CleanupFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeState {
    pub schema_version: u32,
    pub record_kind: String,
    pub install: PathBuf,
    pub version: String,
    pub platform: String,
    pub archive_sha256: [u8; 32],
    pub transaction_id: String,
    /// One initial attempt and at most three fresh retry transactions.
    pub attempt: u32,
    pub phase: ProbePhase,
    pub cause: Option<ProbeCause>,
    pub last_pid: Option<u32>,
    pub boot_id: String,
    pub retry_remaining_ms: u64,
    pub retry_deadline_ms: u64,
    pub daemon_sha256: Option<[u8; 32]>,
    pub cli_sha256: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminalization {
    schema_version: u32,
    record_kind: String,
    install: PathBuf,
    transaction_id: String,
    /// Retain the exact prior record, including Running, across replacement.
    previous_record: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Admission {
    Ready,
    Waiting { retry_after: Duration },
}

#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum ProbeRefusal {
    #[error("candidate probe failed; release held: {reason}")]
    Failed { reason: String },
    #[error("candidate probe interrupted: {reason}; retry after {retry_after:?}")]
    Interrupted {
        reason: String,
        retry_after: Duration,
    },
    #[error("release probe hold: {reason}")]
    Held { reason: String },
    #[error("candidate probe retry waits {retry_after:?}")]
    Waiting { retry_after: Duration },
    #[error("upgrade probe recovery-failed: {reason}")]
    RecoveryFailed { reason: String },
    #[error("upgrade cancelled before the probe attempt")]
    Cancelled,
}

/// S3 may retain these hashes with its complete immutable transaction plan.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct ProbeReceipt {
    pub transaction_id: String,
    pub daemon_sha256: [u8; 32],
    pub cli_sha256: [u8; 32],
    pub daemon_pid: u32,
    pub cli_pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordWrite {
    Attempt,
    Outcome,
    Hold,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct WriteFailure {
    pub phase: RecordWrite,
    pub step: journal::BarrierStep,
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct ProbeOptions {
    pub clock: ProbeClock,
    pub timeout: Duration,
    pub fail_write: Option<WriteFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Each fault point names the exact file or directory durability operation.
#[allow(clippy::enum_variant_names)]
pub(crate) enum StageBarrierStep {
    DaemonFileSync,
    DaemonDirectorySync,
    CliFileSync,
    CliDirectorySync,
}

struct RunOptions {
    clock: ProbeClock,
    started: Instant,
    timeout: Duration,
    live_clock: bool,
    #[cfg(test)]
    fail_write: Option<WriteFailure>,
    #[cfg(test)]
    fail_stage: Option<StageBarrierStep>,
    #[cfg(test)]
    fail_terminal_and_recovery: bool,
    #[cfg(test)]
    before_reap: Option<Box<dyn Fn(u32)>>,
}

impl RunOptions {
    fn now(&self) -> io::Result<ProbeClock> {
        Ok(ProbeClock {
            boot_id: self.clock.boot_id.clone(),
            monotonic_ms: if self.live_clock {
                monotonic_ms()?
            } else {
                self.clock
                    .monotonic_ms
                    .saturating_add(duration_ms(self.started.elapsed()))
            },
        })
    }
}

fn recovery_latches() -> &'static Mutex<HashSet<PathBuf>> {
    static LATCHES: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    LATCHES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn latch(path: &Path) {
    recovery_latches()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path.to_path_buf());
}

fn is_latched(path: &Path) -> bool {
    recovery_latches()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(path)
}

/// Fixed basename beside the independently canonicalized installed daemon.
/// It never matches the candidate/debris sweep patterns.
pub(crate) fn state_path(install: &Path) -> io::Result<PathBuf> {
    let canonical = std::fs::canonicalize(install)?;
    let mut name = canonical
        .file_name()
        .ok_or_else(|| invalid("install has no filename"))?
        .to_os_string();
    name.push(".upgrade-probe.json");
    Ok(canonical.with_file_name(name))
}

fn sidecar_path(state: &Path) -> PathBuf {
    let mut name = state.as_os_str().to_os_string();
    name.push(".pending");
    PathBuf::from(name)
}

pub(crate) fn uncertainty_path(install: &Path) -> io::Result<PathBuf> {
    state_path(install).map(|path| sidecar_path(&path))
}

fn decode_terminalization(bytes: &[u8]) -> io::Result<Terminalization> {
    let marker: Terminalization = serde_json::from_slice(bytes).map_err(invalid)?;
    let previous = decode_state(marker.previous_record.as_bytes())?;
    if marker.schema_version != 1
        || marker.record_kind != "probe_terminalizing"
        || marker.install != previous.install
        || marker.transaction_id != previous.transaction_id
    {
        return Err(invalid("invalid probe terminalization record"));
    }
    Ok(marker)
}

fn validate_terminalization(bytes: &[u8]) -> io::Result<()> {
    decode_terminalization(bytes).map(|_| ())
}

fn begin_terminalization(path: &Path, state: &ProbeState) -> io::Result<PathBuf> {
    let marker_path = sidecar_path(path);
    match journal::read_auxiliary_record(&marker_path) {
        Ok(_) => return Err(invalid("probe terminalization is already unresolved")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let previous_record =
        String::from_utf8(journal::read_auxiliary_record(path)?).map_err(invalid)?;
    let previous = decode_state(previous_record.as_bytes())?;
    if previous.install != state.install || previous.transaction_id != state.transaction_id {
        return Err(invalid("probe terminalization transaction changed"));
    }
    let marker = Terminalization {
        schema_version: 1,
        record_kind: "probe_terminalizing".into(),
        install: state.install.clone(),
        transaction_id: state.transaction_id.clone(),
        previous_record,
    };
    journal::write_auxiliary_record(&marker_path, &marker, validate_terminalization)?;
    Ok(marker_path)
}

fn finish_terminalization(path: &Path, state: &ProbeState) -> io::Result<()> {
    let marker = decode_terminalization(&journal::read_auxiliary_record(path)?)?;
    if marker.install != state.install || marker.transaction_id != state.transaction_id {
        return Err(invalid("probe terminalization transaction changed"));
    }
    std::fs::remove_file(path)?;
    // The terminal record barrier has already succeeded. Removal is only
    // conservative bookkeeping: if a crash restores this marker, admission
    // refuses. Its absence proves that the acknowledged record came first.
    // A failed directory sync must not invent a failed HOLD barrier here.
    if let Some(parent) = path.parent() {
        let _ = std::fs::File::open(parent).and_then(|directory| directory.sync_all());
    }
    Ok(())
}

fn decode_state(bytes: &[u8]) -> io::Result<ProbeState> {
    let state: ProbeState = serde_json::from_slice(bytes).map_err(invalid)?;
    if state.schema_version != 1
        || state.record_kind != "probe"
        || !state.install.is_absolute()
        || state.install.file_name().is_none()
        || state.install.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || state.platform.is_empty()
        || state.boot_id.is_empty()
        || state.boot_id.len() > 128
        || !(1..=4).contains(&state.attempt)
        || state.last_pid == Some(0)
        || state.retry_remaining_ms > RETRY_DELAYS_MS[2]
    {
        return Err(invalid("unsupported or invalid probe record"));
    }
    uuid::Uuid::parse_str(&state.transaction_id).map_err(invalid)?;
    semver::Version::parse(&state.version).map_err(invalid)?;
    if state.phase == ProbePhase::InterruptedWait {
        if !matches!(
            state.cause,
            Some(ProbeCause::Timeout | ProbeCause::HostIo | ProbeCause::Cancelled)
        ) || state.retry_remaining_ms == 0
            || state.retry_deadline_ms == 0
            || state.attempt > 3
        {
            return Err(invalid("invalid interrupted probe wait"));
        }
    } else if state.retry_remaining_ms != 0 || state.retry_deadline_ms != 0 {
        return Err(invalid("non-waiting probe record has a retry deadline"));
    }
    match state.phase {
        ProbePhase::Running | ProbePhase::Passed if state.cause.is_some() => {
            return Err(invalid("non-failed probe record has a cause"));
        }
        ProbePhase::FailedHold
            if !matches!(
                state.cause,
                Some(
                    ProbeCause::ExecFailed
                        | ProbeCause::NonzeroExit
                        | ProbeCause::InvalidOutput
                        | ProbeCause::VersionMismatch
                        | ProbeCause::PlatformMismatch
                        | ProbeCause::OutputLimit
                        | ProbeCause::CandidateChanged
                        | ProbeCause::RetriesExhausted
                )
            ) =>
        {
            return Err(invalid("failed probe hold has an invalid cause"));
        }
        ProbePhase::RecoveryFailed
            if !matches!(
                state.cause,
                Some(
                    ProbeCause::HoldWriteFailed
                        | ProbeCause::StateWriteFailed
                        | ProbeCause::CleanupFailed
                )
            ) =>
        {
            return Err(invalid("probe recovery failure has an invalid cause"));
        }
        _ => {}
    }
    if state.phase == ProbePhase::Passed
        && (state.daemon_sha256.is_none() || state.cli_sha256.is_none())
    {
        return Err(invalid("passed probe has no pair hashes"));
    }
    Ok(state)
}

fn validate_state(bytes: &[u8]) -> io::Result<()> {
    decode_state(bytes).map(|_| ())
}

pub(crate) fn read_state(install: &Path) -> io::Result<Option<ProbeState>> {
    let canonical = std::fs::canonicalize(install)?;
    let path = state_path(&canonical)?;
    match journal::read_auxiliary_record(&path) {
        Ok(bytes) => {
            let state = decode_state(&bytes)?;
            if state.install != canonical {
                return Err(invalid("probe record belongs to another install"));
            }
            Ok(Some(state))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn write_state(
    path: &Path,
    state: &ProbeState,
    write: RecordWrite,
    options: Option<&RunOptions>,
) -> Result<(), ProbeRefusal> {
    let marker = if write == RecordWrite::Attempt {
        None
    } else {
        match begin_terminalization(path, state) {
            Ok(marker) => Some(marker),
            Err(error) => {
                latch(path);
                // The prior Running record remains untouched. If no new
                // marker became visible, Running still refuses fresh readers.
                return Err(ProbeRefusal::RecoveryFailed {
                    reason: format!("probe terminalization barrier failed: {error}"),
                });
            }
        }
    };
    #[cfg(test)]
    let result = {
        let failure = options.and_then(|options| {
            if options.fail_terminal_and_recovery && write != RecordWrite::Attempt {
                Some(journal::BarrierStep::DirectorySync)
            } else {
                options
                    .fail_write
                    .filter(|failure| failure.phase == write)
                    .map(|failure| failure.step)
            }
        });
        match failure {
            Some(step) => {
                journal::write_auxiliary_record_with_failure(path, state, validate_state, step)
            }
            None => journal::write_auxiliary_record(path, state, validate_state),
        }
    };
    #[cfg(not(test))]
    let result = {
        let _ = options;
        journal::write_auxiliary_record(path, state, validate_state)
    };
    result.map_err(|error| record_write_failed(path, state, write, options, error))?;
    if let Some(marker) = marker {
        if let Err(error) = finish_terminalization(&marker, state) {
            latch(path);
            return Err(ProbeRefusal::RecoveryFailed {
                reason: format!("probe terminalization cleanup failed: {error}"),
            });
        }
    }
    Ok(())
}

fn record_write_failed(
    path: &Path,
    state: &ProbeState,
    write: RecordWrite,
    options: Option<&RunOptions>,
    error: io::Error,
) -> ProbeRefusal {
    latch(path);
    // Keep the sidecar even when the final record is visible after a failed
    // directory sync. It preserves the prior bytes and blocks fresh readers
    // if this best-effort recovery-failed write also fails.
    let mut failed = state.clone();
    failed.phase = ProbePhase::RecoveryFailed;
    failed.cause = Some(if write == RecordWrite::Hold {
        ProbeCause::HoldWriteFailed
    } else {
        ProbeCause::StateWriteFailed
    });
    failed.retry_remaining_ms = 0;
    failed.retry_deadline_ms = 0;
    #[cfg(test)]
    if options.is_some_and(|options| options.fail_terminal_and_recovery) {
        let _ = journal::write_auxiliary_record_with_failure(
            path,
            &failed,
            validate_state,
            journal::BarrierStep::FileSync,
        );
    } else {
        let _ = journal::write_auxiliary_record(path, &failed, validate_state);
    }
    #[cfg(not(test))]
    {
        let _ = options;
        let _ = journal::write_auxiliary_record(path, &failed, validate_state);
    }
    ProbeRefusal::RecoveryFailed {
        reason: format!("probe record barrier failed: {error}"),
    }
}

/// Caller holds the install lock. This pre-download check advances only a
/// durably observed interrupted wait; it never follows a recorded path.
pub(crate) fn inspect_admission(install: &Path, version: &str) -> Result<Admission, ProbeRefusal> {
    let clock = ProbeClock::now().map_err(recovery_error)?;
    inspect_admission_inner(install, version, &clock)
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn inspect_admission_at(
    install: &Path,
    version: &str,
    clock: &ProbeClock,
) -> Result<Admission, ProbeRefusal> {
    inspect_admission_inner(install, version, clock)
}

fn inspect_admission_inner(
    install: &Path,
    version: &str,
    clock: &ProbeClock,
) -> Result<Admission, ProbeRefusal> {
    let requested = semver::Version::parse(version).map_err(recovery_error)?;
    let path = state_path(install).map_err(recovery_error)?;
    match journal::read_auxiliary_record(&uncertainty_path(install).map_err(recovery_error)?) {
        Ok(_) => {
            return Err(ProbeRefusal::RecoveryFailed {
                reason: "probe terminalization is unresolved; records preserved".into(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(recovery_error(error)),
    }
    if is_latched(&path) {
        return Err(ProbeRefusal::RecoveryFailed {
            reason: "a probe record barrier failed in this process".into(),
        });
    }
    let Some(mut state) = read_state(install).map_err(recovery_error)? else {
        return Ok(Admission::Ready);
    };
    if state.phase == ProbePhase::RecoveryFailed {
        return Err(ProbeRefusal::RecoveryFailed {
            reason: format!("{:?}", state.cause),
        });
    }
    if state.phase == ProbePhase::Running {
        // A missing terminal outcome is ambiguous: the process may have died
        // during execution, OR it may have observed a failed probe and then
        // lost both the hold write and the recovery-failed write. No reader
        // can distinguish those histories on a broken filesystem. Preserve
        // the record and require inspection; neither a reboot nor a newer
        // release can turn absent durability evidence into permission.
        return Err(ProbeRefusal::RecoveryFailed {
            reason: "probe outcome is unresolved; a failed hold barrier cannot be excluded; \
                     record preserved for manual inspection"
                .into(),
        });
    }
    let recorded = semver::Version::parse(&state.version).map_err(recovery_error)?;
    if requested < recorded {
        return Err(ProbeRefusal::Held {
            reason: format!(
                "newer release {} owns this install's probe state",
                state.version
            ),
        });
    }
    if requested > recorded {
        // D190: a newer release clears a failed-release hold. It never clears
        // recovery-failed, which was checked above.
        return Ok(Admission::Ready);
    }
    match state.phase {
        ProbePhase::FailedHold => Err(ProbeRefusal::Held {
            reason: format!("{:?}", state.cause),
        }),
        ProbePhase::InterruptedWait => {
            if state.boot_id != clock.boot_id {
                // Across reboot keep the last durable remaining wait. Elapsed
                // downtime and a wall-clock step cannot shorten it.
                state.boot_id.clone_from(&clock.boot_id);
                state.retry_deadline_ms =
                    clock.monotonic_ms.saturating_add(state.retry_remaining_ms);
                write_state(&path, &state, RecordWrite::Outcome, None)?;
            }
            let remaining = state.retry_deadline_ms.saturating_sub(clock.monotonic_ms);
            if remaining == 0 {
                Ok(Admission::Ready)
            } else {
                // Persist only progress, never reset a wait on duplicate
                // receipt or same-boot daemon restart.
                if remaining < state.retry_remaining_ms {
                    state.retry_remaining_ms = remaining;
                    write_state(&path, &state, RecordWrite::Outcome, None)?;
                }
                Ok(Admission::Waiting {
                    retry_after: Duration::from_millis(remaining),
                })
            }
        }
        ProbePhase::Passed => Ok(Admission::Ready),
        ProbePhase::Running | ProbePhase::RecoveryFailed => Err(ProbeRefusal::RecoveryFailed {
            reason: "unresolved probe state".into(),
        }),
    }
}

fn interrupt_state(state: &mut ProbeState, cause: ProbeCause, clock: &ProbeClock) {
    state.cause = Some(cause);
    state.boot_id.clone_from(&clock.boot_id);
    let delay = state
        .attempt
        .checked_sub(1)
        .and_then(|index| RETRY_DELAYS_MS.get(index as usize))
        .copied();
    if let Some(delay) = delay {
        state.phase = ProbePhase::InterruptedWait;
        state.retry_remaining_ms = delay;
        state.retry_deadline_ms = clock.monotonic_ms.saturating_add(delay);
    } else {
        state.phase = ProbePhase::FailedHold;
        state.cause = Some(ProbeCause::RetriesExhausted);
        state.retry_remaining_ms = 0;
        state.retry_deadline_ms = 0;
    }
}

/// Run synchronously on the existing blocking replacement worker while it
/// holds the canonical install lock. No backup, rename or restart occurs here.
pub(crate) fn run_before_swap(
    request: &ProbeRequest,
    caller_alive: &AtomicBool,
) -> Result<ProbeReceipt, ProbeRefusal> {
    let options = RunOptions {
        clock: ProbeClock::now().map_err(recovery_error)?,
        started: Instant::now(),
        timeout: PROBE_TIMEOUT,
        live_clock: true,
        #[cfg(test)]
        fail_write: None,
        #[cfg(test)]
        fail_stage: None,
        #[cfg(test)]
        fail_terminal_and_recovery: false,
        #[cfg(test)]
        before_reap: None,
    };
    run_before_swap_inner(request, caller_alive, &options)
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn run_before_swap_with_options(
    request: &ProbeRequest,
    caller_alive: &AtomicBool,
    options: &ProbeOptions,
) -> Result<ProbeReceipt, ProbeRefusal> {
    run_before_swap_inner(
        request,
        caller_alive,
        &RunOptions {
            clock: options.clock.clone(),
            started: Instant::now(),
            timeout: options.timeout,
            live_clock: false,
            fail_write: options.fail_write,
            fail_stage: None,
            fail_terminal_and_recovery: false,
            before_reap: None,
        },
    )
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn run_before_swap_with_stage_failure(
    request: &ProbeRequest,
    caller_alive: &AtomicBool,
    options: &ProbeOptions,
    step: StageBarrierStep,
) -> Result<ProbeReceipt, ProbeRefusal> {
    run_before_swap_inner(
        request,
        caller_alive,
        &RunOptions {
            clock: options.clock.clone(),
            started: Instant::now(),
            timeout: options.timeout,
            live_clock: false,
            fail_write: options.fail_write,
            fail_stage: Some(step),
            fail_terminal_and_recovery: false,
            before_reap: None,
        },
    )
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn run_before_swap_with_terminal_failure(
    request: &ProbeRequest,
    caller_alive: &AtomicBool,
    options: &ProbeOptions,
) -> Result<ProbeReceipt, ProbeRefusal> {
    run_before_swap_inner(
        request,
        caller_alive,
        &RunOptions {
            clock: options.clock.clone(),
            started: Instant::now(),
            timeout: options.timeout,
            live_clock: false,
            fail_write: options.fail_write,
            fail_stage: None,
            fail_terminal_and_recovery: true,
            before_reap: None,
        },
    )
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn run_before_swap_with_cleanup_observer(
    request: &ProbeRequest,
    caller_alive: &AtomicBool,
    options: &ProbeOptions,
    before_reap: impl Fn(u32) + 'static,
) -> Result<ProbeReceipt, ProbeRefusal> {
    run_before_swap_inner(
        request,
        caller_alive,
        &RunOptions {
            clock: options.clock.clone(),
            started: Instant::now(),
            timeout: options.timeout,
            live_clock: false,
            fail_write: options.fail_write,
            fail_stage: None,
            fail_terminal_and_recovery: false,
            before_reap: Some(Box::new(before_reap)),
        },
    )
}

fn run_before_swap_inner(
    request: &ProbeRequest,
    caller_alive: &AtomicBool,
    options: &RunOptions,
) -> Result<ProbeReceipt, ProbeRefusal> {
    if !caller_alive.load(Ordering::Acquire) {
        return Err(ProbeRefusal::Cancelled);
    }
    let clock = options.now().map_err(recovery_error)?;
    if let Admission::Waiting { retry_after } =
        inspect_admission_inner(&request.install, &request.version, &clock)?
    {
        return Err(ProbeRefusal::Waiting { retry_after });
    }
    let canonical = std::fs::canonicalize(&request.install).map_err(recovery_error)?;
    let path = state_path(&canonical).map_err(recovery_error)?;
    let previous = read_state(&canonical).map_err(recovery_error)?;
    let attempt = previous
        .filter(|state| {
            state.version == request.version && state.phase == ProbePhase::InterruptedWait
        })
        .map_or(1, |state| state.attempt.saturating_add(1));
    let mut state = ProbeState {
        schema_version: 1,
        record_kind: "probe".into(),
        install: canonical,
        version: request.version.clone(),
        platform: request.platform.clone(),
        archive_sha256: request.archive_sha256,
        transaction_id: uuid::Uuid::new_v4().to_string(),
        attempt,
        phase: ProbePhase::Running,
        cause: None,
        last_pid: None,
        boot_id: clock.boot_id,
        retry_remaining_ms: 0,
        retry_deadline_ms: 0,
        daemon_sha256: None,
        cli_sha256: None,
    };
    write_state(&path, &state, RecordWrite::Attempt, Some(options))?;
    let result = (|| {
        if !request.launch.cwd.is_absolute()
            || !request.launch.cwd.is_dir()
            || !request.daemon.is_absolute()
            || !request.cli.is_absolute()
        {
            return Err(CandidateFailure::interrupted(
                ProbeCause::HostIo,
                "candidate paths must be absolute and the captured launch directory must exist",
                None,
            ));
        }
        // Extraction's copy/chmod alone does not establish the staged-file
        // barrier. Finish both file and directory barriers before ANY child.
        stage_barrier(
            &request.daemon,
            StageBarrierStep::DaemonFileSync,
            StageBarrierStep::DaemonDirectorySync,
            options,
        )
        .map_err(host_failure)?;
        stage_barrier(
            &request.cli,
            StageBarrierStep::CliFileSync,
            StageBarrierStep::CliDirectorySync,
            options,
        )
        .map_err(host_failure)?;
        // Freeze BOTH verified extraction results before running either image:
        // the first probe cannot silently replace the second candidate.
        let daemon_hash = hash_candidate(&request.daemon).map_err(host_failure)?;
        let cli_hash = hash_candidate(&request.cli).map_err(host_failure)?;
        let daemon = run_candidate(&request.daemon, daemon_hash, request, caller_alive, options)?;
        state.daemon_sha256 = Some(daemon.sha256);
        state.last_pid = Some(daemon.pid);
        let cli = run_candidate(&request.cli, cli_hash, request, caller_alive, options)?;
        state.cli_sha256 = Some(cli.sha256);
        state.last_pid = Some(cli.pid);
        // A later probe must not change the first binary after it passed.
        if hash_candidate(&request.daemon).map_err(host_failure)? != daemon.sha256
            || hash_candidate(&request.cli).map_err(host_failure)? != cli.sha256
        {
            return Err(CandidateFailure::failed(
                ProbeCause::CandidateChanged,
                "candidate bytes changed after probing",
                None,
            ));
        }
        if !caller_alive.load(Ordering::Acquire) {
            return Err(CandidateFailure::interrupted(
                ProbeCause::Cancelled,
                "apply caller cancelled during probe",
                None,
            ));
        }
        Ok(ProbeReceipt {
            transaction_id: state.transaction_id.clone(),
            daemon_sha256: daemon.sha256,
            cli_sha256: cli.sha256,
            daemon_pid: daemon.pid,
            cli_pid: cli.pid,
        })
    })();
    match result {
        Ok(receipt) => {
            state.phase = ProbePhase::Passed;
            write_state(&path, &state, RecordWrite::Outcome, Some(options))?;
            Ok(receipt)
        }
        Err(failure) => {
            if failure.pid.is_some() {
                state.last_pid = failure.pid;
            }
            state.cause = Some(failure.cause);
            if failure.recovery_failed {
                state.phase = ProbePhase::RecoveryFailed;
            } else if failure.interrupted {
                let now = options.now().map_err(recovery_error)?;
                interrupt_state(&mut state, failure.cause, &now);
            } else {
                state.phase = ProbePhase::FailedHold;
            }
            let write = if state.phase == ProbePhase::FailedHold {
                RecordWrite::Hold
            } else {
                RecordWrite::Outcome
            };
            write_state(&path, &state, write, Some(options))?;
            match state.phase {
                ProbePhase::RecoveryFailed => Err(ProbeRefusal::RecoveryFailed {
                    reason: failure.reason,
                }),
                ProbePhase::InterruptedWait => Err(ProbeRefusal::Interrupted {
                    reason: failure.reason,
                    retry_after: Duration::from_millis(state.retry_remaining_ms),
                }),
                _ => Err(ProbeRefusal::Failed {
                    reason: if state.cause == Some(ProbeCause::RetriesExhausted) {
                        "retries_exhausted".into()
                    } else {
                        failure.reason
                    },
                }),
            }
        }
    }
}

struct CandidateReceipt {
    sha256: [u8; 32],
    pid: u32,
}

struct CandidateFailure {
    cause: ProbeCause,
    reason: String,
    pid: Option<u32>,
    interrupted: bool,
    recovery_failed: bool,
}

impl CandidateFailure {
    fn failed(cause: ProbeCause, reason: impl Into<String>, pid: Option<u32>) -> Self {
        Self {
            cause,
            reason: reason.into(),
            pid,
            interrupted: false,
            recovery_failed: false,
        }
    }

    fn interrupted(cause: ProbeCause, reason: impl Into<String>, pid: Option<u32>) -> Self {
        Self {
            interrupted: true,
            ..Self::failed(cause, reason, pid)
        }
    }
}

fn host_failure(error: io::Error) -> CandidateFailure {
    CandidateFailure::interrupted(ProbeCause::HostIo, error.to_string(), None)
}

fn open_candidate(path: &Path) -> io::Result<std::fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_CANDIDATE_BYTES {
        return Err(invalid("candidate is not a bounded regular file"));
    }
    Ok(file)
}

fn stage_barrier(
    path: &Path,
    file_step: StageBarrierStep,
    directory_step: StageBarrierStep,
    options: &RunOptions,
) -> io::Result<()> {
    let file = open_candidate(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("candidate has no parent directory"))?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    stage_barrier_fault(options, file_step)?;
    file.sync_all()?;
    stage_barrier_fault(options, directory_step)?;
    directory.sync_all()
}

fn stage_barrier_fault(options: &RunOptions, step: StageBarrierStep) -> io::Result<()> {
    #[cfg(test)]
    if options.fail_stage == Some(step) {
        return Err(io::Error::other(
            "injected staged candidate barrier failure",
        ));
    }
    let _ = (options, step);
    Ok(())
}

fn hash_candidate(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = open_candidate(path)?;
    let mut hash = Sha256::new();
    let mut remaining = MAX_CANDIDATE_BYTES;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            return Ok(hash.finalize().into());
        }
        remaining = remaining
            .checked_sub(n as u64)
            .ok_or_else(|| invalid("candidate grew beyond the binary size limit"))?;
        hash.update(&chunk[..n]);
    }
}

fn run_candidate(
    binary: &Path,
    expected_hash: [u8; 32],
    request: &ProbeRequest,
    caller_alive: &AtomicBool,
    options: &RunOptions,
) -> Result<CandidateReceipt, CandidateFailure> {
    if !caller_alive.load(Ordering::Acquire) {
        return Err(CandidateFailure::interrupted(
            ProbeCause::Cancelled,
            "apply caller cancelled before candidate execution",
            None,
        ));
    }
    if hash_candidate(binary).map_err(host_failure)? != expected_hash {
        return Err(CandidateFailure::failed(
            ProbeCause::CandidateChanged,
            "candidate bytes changed before execution",
            None,
        ));
    }
    let mut command = Command::new(binary);
    command
        .arg("--upgrade-probe")
        .current_dir(&request.launch.cwd)
        .env_clear()
        .envs(request.launch.env.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn().map_err(|error| {
        // Invalid image/loader and permission refusals are candidate execution
        // failures. Resource exhaustion and other OS faults are Interrupted.
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOEXEC | libc::ENOENT | libc::EACCES | libc::EPERM | libc::EISDIR)
        ) {
            CandidateFailure::failed(
                ProbeCause::ExecFailed,
                format!("candidate could not execute: {error}"),
                None,
            )
        } else {
            host_failure(error)
        }
    })?;
    let pid = child.id();
    let result = collect_probe_output(&mut child, caller_alive, options)
        .and_then(|bytes| {
            #[derive(Deserialize)]
            struct ProbeOutput {
                version: String,
                platform: String,
            }
            let output: ProbeOutput = serde_json::from_slice(&bytes).map_err(|_| {
                CandidateFailure::failed(
                    ProbeCause::InvalidOutput,
                    "candidate emitted an invalid probe response",
                    Some(pid),
                )
            })?;
            if output.version != request.version {
                return Err(CandidateFailure::failed(
                    ProbeCause::VersionMismatch,
                    "candidate probe version does not match the release",
                    Some(pid),
                ));
            }
            if output.platform != request.platform {
                return Err(CandidateFailure::failed(
                    ProbeCause::PlatformMismatch,
                    "candidate probe platform does not match the release",
                    Some(pid),
                ));
            }
            if hash_candidate(binary).map_err(host_failure)? != expected_hash {
                return Err(CandidateFailure::failed(
                    ProbeCause::CandidateChanged,
                    "candidate modified its executable during probe",
                    Some(pid),
                ));
            }
            Ok(CandidateReceipt {
                sha256: expected_hash,
                pid,
            })
        })
        .map_err(|mut failure| {
            failure.pid = Some(pid);
            failure
        });
    #[cfg(test)]
    if let Some(before_reap) = options.before_reap.as_ref() {
        before_reap(pid);
    }
    // The direct child remains waitable through validation. Its reserved PID
    // anchors group cleanup even when malformed output is detected after exit.
    // Clean up descendants on success too, before granting a probe receipt.
    if let Err(error) = kill_and_reap(&mut child) {
        return Err(CandidateFailure {
            cause: ProbeCause::CleanupFailed,
            reason: format!("probe child cleanup failed: {error}"),
            pid: Some(pid),
            interrupted: false,
            recovery_failed: true,
        });
    }
    result
}

fn collect_probe_output(
    child: &mut Child,
    caller_alive: &AtomicBool,
    options: &RunOptions,
) -> Result<Vec<u8>, CandidateFailure> {
    let pid = child.id();
    let mut stdout = child.stdout.take().ok_or_else(|| {
        CandidateFailure::interrupted(ProbeCause::HostIo, "probe stdout unavailable", Some(pid))
    })?;
    let fd = stdout.as_raw_fd();
    // SAFETY: this stdout descriptor belongs exclusively to this child handle;
    // nonblocking reads keep descendants holding the pipe inside the deadline.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(host_failure(io::Error::last_os_error()));
    }
    let start_ms = options.now().map_err(host_failure)?.monotonic_ms;
    let mut bytes = Vec::new();
    let mut eof = false;
    let mut status = None;
    loop {
        if !caller_alive.load(Ordering::Acquire) {
            return Err(CandidateFailure::interrupted(
                ProbeCause::Cancelled,
                "apply caller cancelled during probe",
                Some(pid),
            ));
        }
        let now_ms = options.now().map_err(host_failure)?.monotonic_ms;
        if now_ms.saturating_sub(start_ms) >= duration_ms(options.timeout) {
            return Err(CandidateFailure::interrupted(
                ProbeCause::Timeout,
                "candidate probe timed out",
                Some(pid),
            ));
        }
        if !eof {
            let mut chunk = [0_u8; 1024];
            match stdout.read(&mut chunk) {
                Ok(0) => eof = true,
                Ok(n) => {
                    if bytes.len() + n > OUTPUT_LIMIT {
                        return Err(CandidateFailure::failed(
                            ProbeCause::OutputLimit,
                            "candidate probe exceeded the output limit",
                            Some(pid),
                        ));
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(host_failure(error)),
            }
        }
        if status.is_none() {
            status = observe_exit(child).map_err(host_failure)?;
        }
        if let Some(success) = status {
            if !success {
                return Err(CandidateFailure::failed(
                    ProbeCause::NonzeroExit,
                    "candidate probe exited unsuccessfully",
                    Some(pid),
                ));
            }
            if eof {
                return Ok(bytes);
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn observe_exit(child: &Child) -> io::Result<Option<bool>> {
    let pid = i32::try_from(child.id()).map_err(invalid)?;
    if pid <= 0 {
        return Err(invalid("invalid probe child identity"));
    }
    // SAFETY: zero is a valid initial siginfo_t. waitid owns the writable
    // buffer for this call; WNOWAIT observes only our direct child's exit and
    // retains its identity until the later explicit reap.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::Interrupted {
            Ok(None)
        } else {
            Err(error)
        };
    }
    // SAFETY: waitid initialized the child-status union, or left its zero
    // value when WNOHANG found no exited child.
    let observed = unsafe { info.si_pid() };
    if observed == 0 {
        return Ok(None);
    }
    if observed != pid {
        return Err(invalid("probe exit observation belongs to another child"));
    }
    Ok(Some(
        info.si_code == libc::CLD_EXITED && unsafe { info.si_status() } == 0,
    ))
}

fn kill_and_reap(child: &mut Child) -> io::Result<()> {
    // Refuse to signal if another owner has already reaped the child. A
    // waitable child (running or exited) keeps this PID from being reused.
    let exited = observe_exit(child)?.is_some();
    let pid = i32::try_from(child.id()).map_err(invalid)?;
    // SAFETY: Command created a fresh process group whose ID is this child's
    // PID. Signal the group so a fixture/failed image cannot leave a descendant
    // holding stdout and escaping the bounded probe.
    let killed = unsafe { libc::kill(-pid, libc::SIGKILL) };
    let group_error = if killed == 0 {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    if group_error.is_some() && !exited {
        // A candidate may have left its original group. Its direct PID is
        // still reserved, so killing that child cannot hit a reused PID.
        child.kill()?;
    }
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return match group_error {
                Some(error) if error.raw_os_error() != Some(libc::ESRCH) => Err(error),
                _ => Ok(()),
            };
        }
        if start.elapsed() >= REAP_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "candidate did not reap after SIGKILL",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn boot_id() -> io::Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    if value.is_empty() || value.len() > 128 {
        return Err(invalid("invalid Linux boot identity"));
    }
    Ok(value.to_string())
}

#[cfg(target_os = "linux")]
fn monotonic_ms() -> io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes to this owned timespec; BOOTTIME includes
    // suspended time and is independent of wall-clock adjustments.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(time.tv_sec).map_err(invalid)?;
    let nanos = u64::try_from(time.tv_nsec).map_err(invalid)?;
    seconds
        .checked_mul(1000)
        .and_then(|millis| millis.checked_add(nanos / 1_000_000))
        .ok_or_else(|| invalid("monotonic clock overflow"))
}

#[cfg(target_os = "macos")]
fn boot_id() -> io::Result<String> {
    let mut bytes = [0_u8; 128];
    let mut len = bytes.len();
    // SAFETY: constant nul-terminated name; writable buffer and length remain
    // alive through sysctlbyname. No value is written to the kernel.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = std::str::from_utf8(
        bytes
            .get(..len)
            .ok_or_else(|| invalid("boot ID too large"))?,
    )
    .map_err(invalid)?
    .trim_end_matches('\0');
    if value.is_empty() {
        return Err(invalid("empty macOS boot identity"));
    }
    Ok(value.to_string())
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn monotonic_ms() -> io::Result<u64> {
    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
    }
    #[allow(deprecated)]
    let mut scale = libc::mach_timebase_info { numer: 0, denom: 0 };
    // SAFETY: the kernel fills this owned timebase record; the continuous
    // clock has no arguments, and includes sleep as required by ADR 0094.
    #[allow(deprecated)]
    let result = unsafe { libc::mach_timebase_info(&mut scale) };
    if result != 0 || scale.denom == 0 {
        return Err(io::Error::other("macOS monotonic timebase unavailable"));
    }
    let ticks = unsafe { mach_continuous_time() };
    u64::try_from(u128::from(ticks) * u128::from(scale.numer) / u128::from(scale.denom) / 1_000_000)
        .map_err(invalid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn boot_id() -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "M2 boot clock unsupported",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn monotonic_ms() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "M2 monotonic clock unsupported",
    ))
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn recovery_error(error: impl std::fmt::Display) -> ProbeRefusal {
    ProbeRefusal::RecoveryFailed {
        reason: error.to_string(),
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
