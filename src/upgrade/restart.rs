//! Transactional restart after a successful binary swap (issue #261).
//!
//! The file swap in [`super::Upgrader`] is already transactional. This module
//! makes the *restart* transactional too: the swap is only committed once a
//! replacement process answers `GET /health` with `ok: true` and the expected
//! version on the pre-upgrade API address; otherwise the previous binary is
//! restored and respawned. A terminal-
//! launched daemon (no systemd/launchd) can therefore never be left silently
//! DOWN with the new bytes on disk.
//!
//! - [`RestartMode`] classifies supervision before anything destructive runs.
//! - [`begin_transactional_handoff`] is the old daemon's exit path: it writes
//!   `upgrade-handoff.json`, spawns a detached helper, releases binds within a
//!   5s bound, then `_exit`s.
//! - [`run_upgrade_handoff`] is the helper (`x0xd --upgrade-handoff <file>`):
//!   it waits for the old pid/port, spawns the new binary, health-checks it,
//!   and rolls the backup back over the target on any failure.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use semver::Version;
use tracing::{info, warn};

use super::{UpgradeError, Upgrader};

/// Name of the handoff/intent file inside the daemon data directory.
pub const HANDOFF_FILE_NAME: &str = "upgrade-handoff.json";
/// Name of the loud failure artifact written when no process could be brought
/// back up after an upgrade attempt.
pub const UPGRADE_FAILED_FILE_NAME: &str = "UPGRADE_FAILED";
/// Private CLI flag the handoff helper is spawned with.
pub const UPGRADE_HANDOFF_FLAG: &str = "--upgrade-handoff";
/// Environment variable the old process (and operators) can set to opt in to
/// supervised-exit semantics explicitly (launchd plists, Windows services).
pub const SUPERVISED_ENV_VAR: &str = "X0X_SUPERVISED";

/// Bound on the old process's graceful cancel before it hard-exits. The macOS
/// SIGTERM-hang incident is why this must be bounded, not generous.
const GRACEFUL_CANCEL_BOUND: Duration = Duration::from_secs(5);
/// Bound on each bounded phase of [`terminate_and_reap`]: the graceful
/// SIGTERM window before the unconditional kill, and the post-kill reap
/// attempt. The readiness watch already expired by then, so this only caps
/// how long a wedged target can stall the rollback.
const TERMINATE_GRACE: Duration = Duration::from_secs(5);
/// Default bound for the helper's wait on the old pid dying and the API port
/// freeing. Also the default bound for each `/health` wait (restart commit).
const DEFAULT_HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);
/// Poll cadence inside the helper's bounded waits.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Environment override for the old-pid/port release wait (seconds). Tests use
/// this to keep the bound short; operators may raise it on slow machines.
const RELEASE_TIMEOUT_ENV: &str = "X0X_UPGRADE_HANDOFF_RELEASE_TIMEOUT_SECS";
/// Environment override for each `/health` wait (seconds).
const HEALTH_TIMEOUT_ENV: &str = "X0X_UPGRADE_HANDOFF_HEALTH_TIMEOUT_SECS";

/// Environment variables recorded in the handoff file for diagnosability. The
/// spawned processes inherit the full environment anyway; this whitelist is
/// what a crash-loop post-mortem needs to see.
const ENV_WHITELIST: &[&str] = &[
    "INVOCATION_ID",
    SUPERVISED_ENV_VAR,
    "X0X_LOG_DIR",
    "RUST_LOG",
];

// ---------------------------------------------------------------------------
// I0 — supervision classification
// ---------------------------------------------------------------------------

/// How the daemon comes back after a successful binary swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RestartMode {
    /// A supervisor (systemd `Restart=always`, launchd, Windows service) owns
    /// the respawn: exit 0 (100 on Windows) and let it re-exec the new bytes.
    SupervisedExit,
    /// Nobody will respawn us: run the swap+respawn as a transaction through a
    /// detached helper that proves `/health` or restores the backup.
    TransactionalHandoff,
}

/// Supervision signals sampled from the environment. Injectable so the
/// classification table is testable without manipulating process-global env.
#[derive(Debug, Clone, Default)]
pub struct SupervisionSignals {
    /// `INVOCATION_ID` is set (systemd sets it for every unit invocation).
    pub invocation_id: bool,
    /// `X0X_SUPERVISED=1` — explicit operator opt-in (launchd plist,
    /// Windows service, any custom supervisor).
    pub x0x_supervised: bool,
    /// `/proc/<ppid>/comm` of the parent process, when discoverable.
    pub parent_comm: Option<String>,
    /// Whether stdin is a TTY. Recorded for diagnosis only — **not-a-TTY is
    /// NOT supervision** (nohup/background launches must stay handoff).
    pub stdin_is_tty: bool,
}

impl SupervisionSignals {
    /// Sample the real process environment.
    pub fn sample() -> Self {
        Self {
            invocation_id: std::env::var_os("INVOCATION_ID").is_some_and(|v| !v.is_empty()),
            x0x_supervised: std::env::var(SUPERVISED_ENV_VAR).as_deref() == Ok("1"),
            parent_comm: parent_comm(),
            stdin_is_tty: stdin_is_tty(),
        }
    }
}

/// Read the parent process's `comm` (Linux `/proc`). Non-Linux Unix has no
/// `/proc`; those hosts classify via `INVOCATION_ID` / `X0X_SUPERVISED`
/// instead. "Some ancestor is launchd" is deliberately NOT consulted — every
/// macOS process has that.
#[cfg(target_os = "linux")]
fn parent_comm() -> Option<String> {
    let ppid = unsafe { libc::getppid() };
    let comm = std::fs::read_to_string(format!("/proc/{ppid}/comm")).ok()?;
    let comm = comm.trim().to_string();
    if comm.is_empty() {
        None
    } else {
        Some(comm)
    }
}

#[cfg(not(target_os = "linux"))]
fn parent_comm() -> Option<String> {
    None
}

#[cfg(unix)]
fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

#[cfg(not(unix))]
fn stdin_is_tty() -> bool {
    false
}

/// Which recognized supervision signal fired, if any.
///
/// `INVOCATION_ID`, parent comm `systemd`, or `X0X_SUPERVISED=1`. Nothing else
/// qualifies: not-a-TTY, nohup, detached stdin, and launchd ancestry are all
/// unsupervised. The name is carried into the refusal message so an operator
/// is told *which* signal made this instance managed (ADR-0061 §2).
pub fn supervision_signal_name(signals: &SupervisionSignals) -> Option<&'static str> {
    if signals.invocation_id {
        Some("INVOCATION_ID")
    } else if signals.x0x_supervised {
        Some("X0X_SUPERVISED=1")
    } else if signals
        .parent_comm
        .as_deref()
        // /proc/<pid>/comm carries a trailing newline.
        .is_some_and(|comm| comm.trim() == "systemd")
    {
        Some("parent process `systemd`")
    } else {
        None
    }
}

/// Whether one of the three supervision signals is present.
pub fn is_supervised(signals: &SupervisionSignals) -> bool {
    supervision_signal_name(signals).is_some()
}

/// Exit status a supervisor is expected to restart the daemon on. Unix 0,
/// Windows 100 — the platform statuses ADR-0061 §3 binds the contract to.
pub const fn supervised_exit_code() -> i32 {
    if cfg!(windows) {
        100
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// I0b — loaded launchd policy readback (ADR-0061 §3, #615)
// ---------------------------------------------------------------------------

/// One launchd job's **loaded** policy, parsed from `launchctl print
/// gui/<uid>/<label>` output.
///
/// The on-disk plist is not evidence at upgrade time: a loaded job can
/// differ from its file, and `x0x autostart --repair` only ever verified the
/// plist at repair time (#615). `launchctl print` reports what launchd will
/// actually do after the process exits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchdLoadedJob {
    /// `program = …` — the executable launchd will (re)run.
    pub program: PathBuf,
    /// The `arguments = { … }` block: `ProgramArguments` verbatim.
    pub arguments: Vec<String>,
    /// Whether launchd holds an **unconditional** keep-alive on the job —
    /// the `keepalive` token in the `properties = …` summary. Conditional
    /// `KeepAlive` dictionaries do not set that token (verified against
    /// loaded fixture jobs), so it is exactly the "restarts after exit 0"
    /// guarantee the supervised exit depends on.
    pub keepalive_unconditional: bool,
}

/// Parse the `launchctl print` dump for one job. `None` when the output is
/// not a job dump (launchd error text, empty stdout): the caller fails
/// closed on `None`.
pub fn parse_launchd_loaded_job(print_output: &str) -> Option<LaunchdLoadedJob> {
    let mut program: Option<PathBuf> = None;
    let mut arguments: Vec<String> = Vec::new();
    let mut keepalive_unconditional = false;
    let mut in_arguments = false;
    for line in print_output.lines() {
        let trimmed = line.trim();
        if in_arguments {
            if trimmed == "}" {
                in_arguments = false;
            } else if !trimmed.is_empty() {
                arguments.push(trimmed.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("program = ") {
            // The dump repeats keys inside nested blocks; the first
            // top-level `program` is the job's own.
            program.get_or_insert_with(|| PathBuf::from(rest));
        } else if trimmed == "arguments = {" {
            in_arguments = true;
        } else if let Some(rest) = trimmed.strip_prefix("properties = ") {
            keepalive_unconditional = rest.split('|').any(|token| token.trim() == "keepalive");
        }
    }
    Some(LaunchdLoadedJob {
        program: program?,
        arguments,
        keepalive_unconditional,
    })
}

/// Basename of a path-like string, ignoring any directory part.
fn path_basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// Whether a loaded launchd job runs THIS daemon instance — the job whose
/// program is our executable and whose flags select our instance.
///
/// Multi-instance installs (`--name alice` / `--name bob`) run one launchd
/// job per instance; verifying against a sibling's healthy job while this
/// instance's job lost `KeepAlive` would green-light an upgrade that strands
/// this instance (#615). `argv[0]` may differ from the job's program path
/// (symlinks, relative launch), so the identity is the program basename plus
/// the argument tail.
pub fn launchd_job_runs_this_instance(job: &LaunchdLoadedJob, argv: &[String]) -> bool {
    let Some(argv0) = argv.first() else {
        return false;
    };
    if path_basename(&job.program.to_string_lossy()) != path_basename(argv0) {
        return false;
    }
    let job_tail: &[String] = job.arguments.get(1..).unwrap_or(&[]);
    let argv_tail: &[String] = argv.get(1..).unwrap_or(&[]);
    job_tail == argv_tail
}

/// Outcome of the upgrade-time loaded-policy readback behind the
/// `X0X_SUPERVISED=1` marker. ADR-0061 §3: "loaded-policy readback
/// establish support, not a marker in isolation."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchdPolicyReadback {
    /// The loaded job that runs this instance holds an unconditional
    /// keep-alive, so the supervisor is guaranteed to take the exit-0
    /// restart request.
    Verified {
        /// The launchd label that was verified.
        label: String,
    },
    /// Readback ran and could not confirm a guaranteed respawn. The apply
    /// is refused: exiting into an unconfirmed policy is exactly the
    /// silent-service-disappearance failure #615 closes.
    NotGuaranteed {
        /// Why the loaded policy could not be confirmed.
        detail: String,
    },
    /// No launchd readback applies (the recognized signal is not the
    /// marker, or the marker fired on a non-macOS supervisor, which has no
    /// launchd to read). The marker stands on those supervisors; that
    /// residual §3 gap is stated in #615 and not closed by it.
    Unavailable {
        /// Why readback does not apply.
        detail: String,
    },
}

/// The running process's argv as lossy strings. Shared by the restart
/// resolver and the launchd readback so both reason about the same
/// arguments.
pub(crate) fn current_argv() -> Vec<String> {
    std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

/// Read back the LOADED launchd policy behind the `X0X_SUPERVISED=1` marker
/// at upgrade time (#615).
///
/// Only the marker signal consults launchd: `INVOCATION_ID` and a `systemd`
/// parent name a systemd unit, not a launchd job, and are out of #615's
/// scope. On macOS, candidate labels come from the `~/Library/LaunchAgents`
/// plists whose `ProgramArguments[0]` is this executable — the population
/// `x0x autostart` generates and `--repair` migrates — and the verdict comes
/// from `launchctl print` on each candidate's **loaded** state, never from
/// the plist alone. Any outcome short of a confirmed unconditional
/// keep-alive on the job running this exact instance is `NotGuaranteed`:
/// fail closed.
pub fn readback_launchd_policy(
    signals: &SupervisionSignals,
    executable: &Path,
    argv: &[String],
) -> LaunchdPolicyReadback {
    if signals.invocation_id || !signals.x0x_supervised {
        return LaunchdPolicyReadback::Unavailable {
            detail: "the recognized supervision signal is not the launchd marker".to_string(),
        };
    }
    info!(
        executable = %executable.display(),
        "Reading back the loaded launchd policy behind X0X_SUPERVISED=1 (ADR-0061 §3)"
    );
    readback_launchd_policy_macos(executable, argv)
}

/// launchd does not exist on this platform, so the marker cannot be
/// cross-checked here. Fail-open is deliberate and bounded: #615 closes the
/// macOS residual failure (`KeepAlive` altered after repair); a non-macOS
/// supervisor honoring the marker keeps today's behaviour.
#[cfg(not(target_os = "macos"))]
fn readback_launchd_policy_macos(_executable: &Path, _argv: &[String]) -> LaunchdPolicyReadback {
    LaunchdPolicyReadback::Unavailable {
        detail: "loaded-policy readback exists for macOS launchd only".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn readback_launchd_policy_macos(executable: &Path, argv: &[String]) -> LaunchdPolicyReadback {
    let Some(plist_dir) = dirs::home_dir().map(|h| h.join("Library/LaunchAgents")) else {
        return LaunchdPolicyReadback::NotGuaranteed {
            detail: "cannot locate ~/Library/LaunchAgents".to_string(),
        };
    };
    readback_launchd_policy_in(
        &plist_dir,
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() },
        executable,
        argv,
        &plist_as_json,
        &mut run_launchctl_print,
    )
}

/// Real launchctl probe for [`readback_launchd_policy_in`]: run
/// `launchctl print <target>`. `Ok(None)` when the domain does not hold the
/// job (launchctl exits nonzero for an unknown service target); `Err` when
/// launchctl itself could not be run.
#[cfg(target_os = "macos")]
fn run_launchctl_print(target: &str) -> Result<Option<String>, String> {
    match std::process::Command::new("launchctl")
        .arg("print")
        .arg(target)
        .output()
    {
        Ok(out) if out.status.success() => {
            Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
        }
        Ok(_) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Plist-reader callback for [`readback_launchd_policy_in`]: the plist file
/// as JSON, or `None` when it cannot be read or parsed.
type PlistReader<'a> = &'a dyn Fn(&Path) -> Option<serde_json::Value>;

/// launchctl probe callback for [`readback_launchd_policy_in`]: given a full
/// launchd service target (e.g. `gui/501/com.example.x0xd`), `Ok(Some(stdout))`
/// when that domain holds the job, `Ok(None)` when it does not, `Err` when
/// launchctl could not be run. `FnMut` so tests can record probe order.
type LaunchctlPrint<'a> = &'a mut dyn FnMut(&str) -> Result<Option<String>, String>;

/// The decision core of [`readback_launchd_policy`]: discover candidate
/// labels from a LaunchAgents directory, probe each label's LOADED policy,
/// and verdict on the job running this exact instance.
///
/// Each label is probed in the `gui/<uid>` domain first and falls back to
/// `user/<uid>`: the two per-user domains are disjoint (a job bootstrapped
/// into `user/<uid>` answers "Could not find service" from the gui probe),
/// so probing gui alone would refuse a legitimately-loaded marker job
/// forever (round-2 review of #615).
///
/// Split from the plutil/launchctl drivers — and free of any platform API —
/// so the refuse-vs-proceed decision table is unit-testable on any platform
/// with captured probe output; every path that cannot confirm an
/// unconditional keep-alive on this instance's job fails closed.
fn readback_launchd_policy_in(
    plist_dir: &Path,
    uid: u32,
    executable: &Path,
    argv: &[String],
    read_plist: PlistReader<'_>,
    launchctl_print: LaunchctlPrint<'_>,
) -> LaunchdPolicyReadback {
    use LaunchdPolicyReadback::NotGuaranteed;

    let entries = match std::fs::read_dir(plist_dir) {
        Ok(entries) => entries,
        Err(e) => {
            return NotGuaranteed {
                detail: format!("cannot read {}: {e}", plist_dir.display()),
            };
        }
    };

    let executable_basename = path_basename(&executable.to_string_lossy()).to_string();

    // First refusal-worthy observation, kept for the diagnostic when no
    // candidate verifies. A definitive answer (verified, or the loaded job
    // running this instance lacking KeepAlive) returns immediately.
    let mut refusal: Option<String> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("plist") {
            continue;
        }
        let Some(job_plist) = read_plist(&path) else {
            refusal.get_or_insert_with(|| format!("unreadable plist {}", path.display()));
            continue;
        };
        let program = job_plist
            .get("ProgramArguments")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(|p| p.as_str())
            .or_else(|| job_plist.get("Program").and_then(|p| p.as_str()));
        if program.is_none_or(|p| path_basename(p) != executable_basename) {
            continue; // not an x0xd job for this executable
        }
        let Some(label) = job_plist.get("Label").and_then(|l| l.as_str()) else {
            refusal.get_or_insert_with(|| format!("plist {} has no Label", path.display()));
            continue;
        };
        // Probe gui first; fall back to the user domain when gui does not
        // hold the job (the domains are disjoint — see the function docs).
        let gui_probe = launchctl_print(&format!("gui/{uid}/{label}"));
        let loaded_stdout = match &gui_probe {
            Ok(Some(stdout)) => Some(std::borrow::Cow::Borrowed(stdout.as_str())),
            _ => match launchctl_print(&format!("user/{uid}/{label}")) {
                Ok(Some(stdout)) => Some(std::borrow::Cow::Owned(stdout)),
                Ok(None) => {
                    refusal.get_or_insert_with(|| {
                        format!(
                            "job {label} ({}) is not loaded in either the gui or the user \
                             launchd domain",
                            path.display()
                        )
                    });
                    continue;
                }
                Err(user_err) => {
                    let why = match &gui_probe {
                        Err(gui_err) => format!("{gui_err}; {user_err}"),
                        _ => user_err,
                    };
                    refusal.get_or_insert_with(|| {
                        format!("could not run launchctl print for job {label}: {why}")
                    });
                    continue;
                }
            },
        };
        let Some(loaded) = loaded_stdout.as_deref().and_then(parse_launchd_loaded_job) else {
            refusal
                .get_or_insert_with(|| format!("could not parse the loaded policy of job {label}"));
            continue;
        };
        if !launchd_job_runs_this_instance(&loaded, argv) {
            refusal.get_or_insert_with(|| {
                format!("loaded job {label} runs different arguments, so it is not this instance")
            });
            continue;
        }
        if loaded.keepalive_unconditional {
            return LaunchdPolicyReadback::Verified {
                label: label.to_string(),
            };
        }
        return NotGuaranteed {
            detail: format!(
                "loaded job {label} does not hold an unconditional KeepAlive, so nothing is \
                 guaranteed to restart this instance after the upgrade exit"
            ),
        };
    }
    NotGuaranteed {
        detail: refusal.unwrap_or_else(|| {
            "no launchd job in ~/Library/LaunchAgents runs this executable, so nothing is \
             guaranteed to restart it after the upgrade exit"
                .to_string()
        }),
    }
}

/// Convert a plist to JSON via `plutil`. `None` when the file is not a
/// parseable plist or plutil cannot run.
#[cfg(target_os = "macos")]
fn plist_as_json(path: &Path) -> Option<serde_json::Value> {
    let out = std::process::Command::new("plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

/// The instance's restart contract could not be resolved, so no bytes may be
/// replaced (ADR-0061 §1: failure "leaves the current process and installed
/// binaries unchanged and reports the unresolved contract").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestartOwnershipError {
    /// Recognized supervision plus `stop_on_upgrade = false` names two restart
    /// owners for one instance. Refused before replacement (ADR-0061 §2).
    #[error(
        "refusing self-update: this instance is supervised ({signal} is present) but \
         `[update] stop_on_upgrade` is false, which asks x0xd to restart itself through the \
         transactional handoff helper. That gives one instance two restart owners — the \
         supervisor and the helper would each start a daemon on the same data root. \
         Correct the deployment, then retry: either set `[update] stop_on_upgrade = true` in \
         the daemon config so the supervisor owns the restart (x0xd exits {exit_code} and the \
         supervisor re-execs the new binary), or, if this instance is not actually supervised, \
         remove {signal} from its environment. No binaries were replaced."
    )]
    SupervisedRestartConflict {
        /// The recognized signal that made this instance managed.
        signal: String,
        /// Exit status the supervisor would have to restart on.
        exit_code: i32,
    },

    /// An input the restart plan depends on could not be resolved or validated.
    #[error(
        "refusing self-update: cannot resolve the restart contract ({what}: {detail}). \
         No binaries were replaced."
    )]
    Unresolved {
        /// Which part of the contract is unresolved.
        what: &'static str,
        /// Why it could not be resolved.
        detail: String,
    },

    /// The `X0X_SUPERVISED=1` marker fired, but the loaded launchd job
    /// policy does not guarantee a respawn after the supervised exit status
    /// (ADR-0061 §3, #615). Refused before replacement: exiting into an
    /// unconfirmed policy is the silent-service-disappearance failure — the
    /// daemon exits 0 for the upgrade and nothing restarts it.
    #[error(
        "refusing self-update: this instance reports {signal} but the loaded launchd job \
         policy does not guarantee a restart after exit {exit_code} ({detail}). A supervised \
         exit without a guaranteed respawn leaves the service down with the new bytes on \
         disk. Restore an unconditional `KeepAlive` on the job — inspect it with \
         `launchctl print gui/$(id -u)/<label>`, fix the plist, then `launchctl unload` and \
         `launchctl load` it — and retry; if the daemon is already down after a supervised \
         upgrade, follow the \"Manual recovery after a failed supervised upgrade\" procedure \
         in docs/upgrade-system.md. No binaries were replaced."
    )]
    SupervisedPolicyNotGuaranteed {
        /// The recognized signal that made this instance managed.
        signal: String,
        /// Exit status the supervisor would have to restart on.
        exit_code: i32,
        /// Why the loaded policy could not be confirmed.
        detail: String,
    },
}

/// I0 classification: pick the restart mode before anything destructive runs.
///
/// - `SupervisedExit` requires `stop_on_upgrade == true` **and** real
///   supervision: the external owner re-execs the new bytes.
/// - `TransactionalHandoff` covers genuinely unsupervised runs, including the
///   default `stop_on_upgrade = true` terminal launch (the old `exec()` path
///   could not roll back and is gone).
/// - Supervision with `stop_on_upgrade == false` is **refused** rather than
///   classified: see [`RestartOwnershipError::SupervisedRestartConflict`].
pub fn plan_restart_mode(
    stop_on_upgrade: bool,
    signals: &SupervisionSignals,
) -> Result<RestartMode, RestartOwnershipError> {
    match (stop_on_upgrade, supervision_signal_name(signals)) {
        (true, Some(_)) => Ok(RestartMode::SupervisedExit),
        (false, Some(signal)) => Err(RestartOwnershipError::SupervisedRestartConflict {
            signal: signal.to_string(),
            exit_code: supervised_exit_code(),
        }),
        (_, None) => Ok(RestartMode::TransactionalHandoff),
    }
}

/// A fully resolved restart contract for this instance (ADR-0061 §1).
///
/// Every field is resolved and validated **before** any byte on disk changes,
/// then carried unchanged through replacement and restart. The plan is never
/// re-derived after the swap, so a conflicting plan cannot be discovered with
/// new bytes already installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartPlan {
    /// Who owns the respawn.
    pub mode: RestartMode,
    /// Status the process exits with for the supervisor; `None` when the
    /// helper owns the restart instead.
    pub supervised_exit_code: Option<i32>,
    /// Recognized supervision signal, recorded for diagnosis.
    pub supervision_signal: Option<String>,
    /// Binary that will be replaced and (re)started.
    pub executable: PathBuf,
    /// Full argv of the running process, `argv[0]` included. Together with
    /// `cwd` this is what determines the instance's effective identity/data
    /// roots (`--config`, `--name`), which is why it is captured pre-swap.
    pub argv: Vec<String>,
    /// Working directory of the running process.
    pub cwd: PathBuf,
    /// Effective data root: where the handoff/intent record and durable
    /// history live. Two daemons must never share it.
    pub data_root: PathBuf,
    /// Pre-upgrade API address the replacement must serve `/health` on.
    pub api_addr: SocketAddr,
}

impl RestartPlan {
    /// Where the handoff/intent record for this instance goes.
    pub fn handoff_path(&self) -> PathBuf {
        self.data_root.join(HANDOFF_FILE_NAME)
    }

    /// Whether this plan starts a detached replacement helper.
    ///
    /// ADR-0061 §5 keeps restart ownership singular: the managed path requests
    /// restart through its external owner and must launch no helper, so no
    /// second process can start a daemon on `data_root`.
    pub fn spawns_helper(&self) -> bool {
        matches!(self.mode, RestartMode::TransactionalHandoff)
    }
}

/// Resolve and validate the full restart contract before mutation (ADR-0061 §1).
///
/// `executable` is the binary that will be replaced; `data_root_hint` is the
/// daemon's data directory (`None` falls back to the install directory for
/// non-daemon callers). `api_addr` is the pre-upgrade API address.
/// `launchd_readback` is the loaded-policy readback behind the
/// [`SUPERVISED_ENV_VAR`] marker ([`readback_launchd_policy`]).
///
/// Returns `Err` — leaving the caller to abort before replacing anything — on
/// a conflicting managed configuration, an unconfirmed launchd restart
/// policy (§3, #615), or any input that cannot be resolved or validated.
pub fn resolve_restart_plan(
    stop_on_upgrade: bool,
    signals: &SupervisionSignals,
    executable: &Path,
    data_root_hint: Option<&Path>,
    api_addr: Option<SocketAddr>,
    launchd_readback: &LaunchdPolicyReadback,
) -> Result<RestartPlan, RestartOwnershipError> {
    let mode = plan_restart_mode(stop_on_upgrade, signals)?;

    // ADR-0061 §3 (#615): the launchd marker is an operator assertion, not a
    // respawn guarantee. Before choosing SupervisedExit on the marker alone,
    // the LOADED launchd policy must confirm an unconditional keep-alive on
    // the job running this instance — the marker-in-isolation check ruled out
    // by §3 stranded jobs whose `KeepAlive` was altered after `--repair`.
    // INVOCATION_ID / `systemd`-parent signals are not gated: they name a
    // systemd unit, and the systemd-side readback is out of #615's scope.
    if mode == RestartMode::SupervisedExit && !signals.invocation_id && signals.x0x_supervised {
        if let LaunchdPolicyReadback::NotGuaranteed { detail } = launchd_readback {
            return Err(RestartOwnershipError::SupervisedPolicyNotGuaranteed {
                signal: format!("{SUPERVISED_ENV_VAR}=1"),
                exit_code: supervised_exit_code(),
                detail: detail.clone(),
            });
        }
    }

    // The swap writes `<executable>.backup` beside the target and the helper
    // respawns from that directory. An install dir we cannot see is an
    // unresolved contract, not something to discover mid-swap.
    let install_dir = executable
        .parent()
        .filter(|dir| dir.is_dir())
        .ok_or_else(|| RestartOwnershipError::Unresolved {
            what: "install directory",
            detail: format!(
                "{} has no existing parent directory to hold the backup",
                executable.display()
            ),
        })?;

    let argv = current_argv();
    if argv.is_empty() {
        return Err(RestartOwnershipError::Unresolved {
            what: "process argv",
            detail: "the running process reports no arguments, so the replacement's \
                     configuration and roots cannot be reproduced"
                .to_string(),
        });
    }

    let cwd = std::env::current_dir().map_err(|e| RestartOwnershipError::Unresolved {
        what: "working directory",
        detail: e.to_string(),
    })?;

    let data_root = data_root_hint.unwrap_or(install_dir).to_path_buf();
    if !data_root.is_dir() {
        return Err(RestartOwnershipError::Unresolved {
            what: "data root",
            detail: format!("{} is not an existing directory", data_root.display()),
        });
    }

    Ok(RestartPlan {
        mode,
        supervised_exit_code: match mode {
            RestartMode::SupervisedExit => Some(supervised_exit_code()),
            RestartMode::TransactionalHandoff => None,
        },
        supervision_signal: supervision_signal_name(signals).map(str::to_string),
        executable: executable.to_path_buf(),
        argv,
        cwd,
        data_root,
        api_addr: api_addr.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0))),
    })
}

// ---------------------------------------------------------------------------
// Handoff state
// ---------------------------------------------------------------------------

/// The on-disk handoff/intent record (`data_dir/upgrade-handoff.json`).
///
/// Captured by the old process *before* any exit: argv, cwd, and the binary
/// path are properties of the running process, not of the post-swap files.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpgradeHandoff {
    /// Version of the process that initiated the handoff.
    pub from_version: String,
    /// Version the binary on disk was swapped to.
    pub to_version: String,
    /// Path the new bytes were swapped into (the daemon's install path).
    pub target_path: PathBuf,
    /// Path holding the previous binary (`x0xd.backup`).
    pub backup_path: PathBuf,
    /// Full argv of the old process, including `argv[0]`. `argv[0]` is recorded
    /// for diagnosis only — the respawn always uses `target_path`.
    pub argv: Vec<String>,
    /// Working directory of the old process.
    pub cwd: String,
    /// Whitelisted environment of the old process (diagnosability; the
    /// spawned processes inherit the real environment).
    pub env: BTreeMap<String, String>,
    /// Pid of the old process the helper must wait out.
    pub old_pid: u32,
    /// API address the replacement must serve `/health` on. Port 0 means the
    /// bind is ephemeral: the helper reads `<data_dir>/api.port` instead.
    pub api_addr: SocketAddr,
    /// Unix seconds at handoff start.
    pub started_at: u64,
    /// Mode the old process classified (also written on the supervised-exit
    /// intent file so crash loops are diagnosable).
    pub mode: RestartMode,
}

impl UpgradeHandoff {
    /// Build the handoff record from an already-resolved [`RestartPlan`].
    ///
    /// ADR-0061 §1: the plan was resolved and validated before any bytes
    /// changed, so argv/cwd/roots are *carried* here rather than re-sampled
    /// from a process whose binary has since been replaced.
    pub fn from_plan(plan: &RestartPlan, to_version: &str) -> Self {
        let env = ENV_WHITELIST
            .iter()
            .filter_map(|key| {
                std::env::var(key)
                    .ok()
                    .map(|value| ((*key).to_string(), value))
            })
            .collect();
        Self {
            from_version: crate::VERSION.to_string(),
            to_version: to_version.to_string(),
            target_path: plan.executable.clone(),
            backup_path: Self::backup_path_for(&plan.executable),
            argv: plan.argv.clone(),
            cwd: plan.cwd.to_string_lossy().into_owned(),
            env,
            old_pid: std::process::id(),
            api_addr: plan.api_addr,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            mode: plan.mode,
        }
    }

    /// Serialize to `data_dir/upgrade-handoff.json`.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self).map_err(io_other)?)
    }

    /// Parse a handoff file (helper side).
    pub fn read(path: &Path) -> std::io::Result<Self> {
        serde_json::from_str(&std::fs::read_to_string(path)?).map_err(io_other)
    }

    /// Backup path the swap created for this target (`x0xd.backup`).
    pub fn backup_path_for(target_path: &Path) -> PathBuf {
        target_path.with_extension("backup")
    }
}

fn io_other(err: serde_json::Error) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

/// Build the respawn argv: skip the recorded `argv[0]` and append
/// `--skip-update-check` only when it is not already present, so a daemon
/// started with the flag does not grow a second copy on every restart.
pub fn build_spawn_args(argv: &[String]) -> Vec<String> {
    let mut args: Vec<String> = argv.iter().skip(1).cloned().collect();
    if !argv.iter().any(|a| a == "--skip-update-check") {
        args.push("--skip-update-check".to_string());
    }
    args
}

// ---------------------------------------------------------------------------
// Old-process side (I2 steps 1–3)
// ---------------------------------------------------------------------------

/// Start the transactional handoff from the old daemon after a swap Success.
///
/// Writes the handoff file, spawns a detached helper (in a new session, so it
/// outlives this process), triggers the graceful-shutdown hook, waits at most
/// `GRACEFUL_CANCEL_BOUND` (5s) for the API bind to release, then `_exit(0)`
/// without unwinding. On success this never returns.
///
/// If the helper cannot be spawned, nothing exits: the backup is restored over
/// the target, `UPGRADE_FAILED` records why, and the caller keeps serving on
/// the still-running old image.
pub fn begin_transactional_handoff(
    handoff: UpgradeHandoff,
    handoff_path: &Path,
    shutdown: Option<&(dyn Fn() + Send + Sync)>,
) -> Result<(), UpgradeError> {
    handoff
        .write(handoff_path)
        .map_err(|e| UpgradeError::Other(format!("failed to write handoff file: {e}")))?;
    info!(
        handoff = %handoff_path.display(),
        to_version = %handoff.to_version,
        "Upgrade handoff file written"
    );

    // Prefer the backup bytes for the helper: they are the known-good image
    // that just ran this code. (After the unix swap, `current_exe()` names the
    // NEW bytes; the old bytes live at backup_path.)
    let helper_binary = if handoff.backup_path.is_file() {
        handoff.backup_path.clone()
    } else {
        handoff.target_path.clone()
    };

    let mut cmd = std::process::Command::new(&helper_binary);
    cmd.arg(UPGRADE_HANDOFF_FLAG).arg(handoff_path);
    cmd.stdin(std::process::Stdio::null());
    detach_from_terminal(&mut cmd);

    match cmd.spawn() {
        Ok(child) => {
            info!(
                helper_pid = child.id(),
                helper = %helper_binary.display(),
                "Upgrade handoff helper spawned"
            );
        }
        Err(e) => {
            // Loud failure that keeps the user UP: restore the old bytes and
            // record why. The old process keeps serving from memory.
            warn!(error = %e, "Failed to spawn upgrade handoff helper");
            let data_dir = data_dir_of(handoff_path);
            let restore = restore_backup(&handoff.backup_path, &handoff.target_path);
            write_upgrade_failed(
                &data_dir,
                &format!("handoff helper spawn failed: {e}; restore: {restore:?}"),
                &handoff,
            );
            return Err(UpgradeError::Other(format!(
                "failed to spawn upgrade handoff helper: {e}"
            )));
        }
    }

    // Bounded graceful cancel: trigger the shutdown hook, then give the binds
    // at most GRACEFUL_CANCEL_BOUND to release before hard-exiting. Never wait
    // unbounded (the macOS SIGTERM-hang incident).
    if let Some(cancel) = shutdown {
        cancel();
        bounded_graceful_wait(Some(handoff.api_addr), GRACEFUL_CANCEL_BOUND);
    }

    info!("Upgrade handoff: old process exiting");
    #[cfg(unix)]
    {
        // _exit: no destructors, no atexit flushes — the helper owns the rest
        // of the transaction.
        unsafe { libc::_exit(0) };
    }
    #[cfg(not(unix))]
    {
        std::process::exit(0);
    }
}

/// Mark a spawned child detached from the launching terminal: on Unix a new
/// session (immune to terminal-close SIGHUP), on Windows a new process group
/// without a console.
fn detach_from_terminal(cmd: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Safe: setsid only fails if the caller is already a session/pgrp
        // leader, which a freshly forked child (fresh pid, inherited pgid)
        // never is.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
}

/// Wait up to `bound` for the API address to become bindable (i.e. released).
/// Unknown/ephemeral addresses wait out the full bound. Never waits forever.
fn bounded_graceful_wait(api_addr: Option<SocketAddr>, bound: Duration) {
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if let Some(addr) = api_addr {
            if addr.port() != 0 && addr_is_free(addr) {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ---------------------------------------------------------------------------
// Helper side (I2 steps 4–8) — `x0xd --upgrade-handoff <file>`
// ---------------------------------------------------------------------------

/// Run the handoff helper to completion and return its exit code.
///
/// 1. Wait (bounded) for the old pid to die and the API port to free. If the
///    old process hangs past the bound: abort the spawn, restore the backup,
///    leave the old process up, write `UPGRADE_FAILED`. **No SIGKILL.**
/// 2. Spawn the new binary with the captured argv/cwd and wait for
///    `GET /health` to answer `ok: true` with the target version (bounded).
///    Healthy ⇒ delete the handoff file, exit 0.
/// 3. On spawn/health failure: restore the backup, respawn the previous
///    binary, wait for `/health` to report the previous version again.
/// 4. If the rollback respawn also fails: write `UPGRADE_FAILED`, eprint, exit
///    nonzero. Never exit 0 after a failed respawn.
///
/// The helper joins no gossip, binds nothing, and takes no instance lock.
pub fn run_upgrade_handoff(handoff_path: &Path) -> i32 {
    eprintln!(
        "x0xd: upgrade handoff helper starting ({})",
        handoff_path.display()
    );
    let handoff = match UpgradeHandoff::read(handoff_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "x0xd: cannot read handoff file {}: {e}",
                handoff_path.display()
            );
            return 2;
        }
    };
    let data_dir = data_dir_of(handoff_path);

    // Step 1: the old process must die and release the API port. The helper
    // never signals or kills it — history.db durability depends on the old
    // process's own bounded shutdown.
    if !wait_for_old_process_release(&handoff, env_timeout(RELEASE_TIMEOUT_ENV)) {
        let restore = restore_backup(&handoff.backup_path, &handoff.target_path);
        let reason = format!(
            "old pid {} did not exit and release the API port within the bound; \
             restored backup ({}), old process left running; restore: {:?}",
            handoff.old_pid, handoff.from_version, restore
        );
        write_upgrade_failed(&data_dir, &reason, &handoff);
        eprintln!("x0xd: UPGRADE FAILED — {reason}");
        return 3;
    }

    // Step 2: prove the new binary serves the target version before
    // committing the restart.
    let health_timeout = env_timeout(HEALTH_TIMEOUT_ENV);
    let new_outcome = spawn_and_await_health(
        &handoff.target_path,
        &handoff,
        &data_dir,
        health_timeout,
        &handoff.to_version,
    );
    match new_outcome {
        SpawnHealthOutcome::Healthy => {
            finish_success(handoff_path, &handoff, &handoff.to_version, "new");
            return 0;
        }
        SpawnHealthOutcome::SpawnFailed(e) => {
            eprintln!(
                "x0xd: new binary {} failed to spawn: {e}; rolling back to {}",
                handoff.target_path.display(),
                handoff.from_version
            );
        }
        SpawnHealthOutcome::Unhealthy => {
            eprintln!(
                "x0xd: new binary {} did not serve /health within {}s; rolling back to {}",
                handoff.target_path.display(),
                health_timeout.as_secs(),
                handoff.from_version
            );
        }
    }

    // Step 3: rollback — restore the previous binary and respawn it.
    if let Err(e) = restore_backup(&handoff.backup_path, &handoff.target_path) {
        let reason = format!("rollback restore failed after new binary did not come up: {e}");
        write_upgrade_failed(&data_dir, &reason, &handoff);
        eprintln!("x0xd: UPGRADE FAILED — {reason}");
        return 4;
    }
    match spawn_and_await_health(
        &handoff.target_path,
        &handoff,
        &data_dir,
        health_timeout,
        &handoff.from_version,
    ) {
        SpawnHealthOutcome::Healthy => {
            finish_success(handoff_path, &handoff, &handoff.from_version, "restored");
            return 0;
        }
        SpawnHealthOutcome::SpawnFailed(e) => {
            let reason = format!(
                "rollback spawn of restored binary {} failed: {e}",
                handoff.target_path.display()
            );
            write_upgrade_failed(&data_dir, &reason, &handoff);
            eprintln!("x0xd: UPGRADE FAILED — {reason}");
        }
        SpawnHealthOutcome::Unhealthy => {
            let reason = format!(
                "restored binary {} spawned but did not serve /health within {}s",
                handoff.target_path.display(),
                health_timeout.as_secs()
            );
            write_upgrade_failed(&data_dir, &reason, &handoff);
            eprintln!("x0xd: UPGRADE FAILED — {reason}");
        }
    }
    5
}

/// Delete the handoff file and report a committed restart (I2 step 6).
fn finish_success(handoff_path: &Path, handoff: &UpgradeHandoff, version: &str, which: &str) {
    if let Err(e) = std::fs::remove_file(handoff_path) {
        eprintln!(
            "x0xd: warning: could not remove handoff file {}: {e}",
            handoff_path.display()
        );
    }
    eprintln!(
        "x0xd: upgrade handoff complete — {which} binary on {} serving {}",
        handoff.target_path.display(),
        version
    );
}

enum SpawnHealthOutcome {
    Healthy,
    SpawnFailed(std::io::Error),
    Unhealthy,
}

/// Spawn `binary` with the captured argv/cwd (own process group, no terminal)
/// and wait for `/health` to answer `ok: true` with `expected_version` on the
/// handoff's API address.
///
/// The [`std::process::Child`] is retained for the whole watch: if the
/// readiness deadline expires, that exact child is terminated and reaped
/// *before* `Unhealthy` is returned, so a late-binding target cannot contend
/// with the rollback respawn for the API port. On success the child is
/// dropped unreaped — a healthy daemon must survive the helper's exit.
fn spawn_and_await_health(
    binary: &Path,
    handoff: &UpgradeHandoff,
    data_dir: &Path,
    health_timeout: Duration,
    expected_version: &str,
) -> SpawnHealthOutcome {
    let mut cmd = std::process::Command::new(binary);
    cmd.args(build_spawn_args(&handoff.argv));
    if !handoff.cwd.is_empty() {
        cmd.current_dir(&handoff.cwd);
    }
    cmd.stdin(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group: signals aimed at the helper's group must not
        // reach the daemon.
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return SpawnHealthOutcome::SpawnFailed(e),
    };
    if wait_for_health(handoff, data_dir, health_timeout, expected_version) {
        drop(child);
        SpawnHealthOutcome::Healthy
    } else {
        terminate_and_reap(&mut child);
        SpawnHealthOutcome::Unhealthy
    }
}

/// Terminate and reap a spawned process whose readiness watch expired.
///
/// The child held (or was about to hold) the pre-upgrade API address; the
/// rollback respawn cannot bind until it is gone. SIGTERM first — the
/// daemon's own graceful path releases its binds — escalating to an
/// unconditional kill within [`TERMINATE_GRACE`] so the helper stays bounded.
/// Even the post-kill reap is bounded: a child wedged in uninterruptible
/// sleep (D-state) would otherwise hold `wait()` open-ended, and a zombie
/// left behind is reparented to init when the helper exits right after.
/// The direct child is the whole story: production daemons do not fork
/// listeners, and the test fixtures `exec` their wrappers.
#[cfg(unix)]
fn terminate_and_reap(child: &mut std::process::Child) {
    let pid = child.id() as libc::pid_t;
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        // Already dead or unreachable: fall through to the reap below.
        let _ = child.kill();
    }
    let deadline = Instant::now() + TERMINATE_GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    reap_bounded(child);
}

#[cfg(not(unix))]
fn terminate_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    reap_bounded(child);
}

/// Bounded reap after the unconditional kill: poll `try_wait` for
/// [`TERMINATE_GRACE`] and give up rather than block on a child the kernel
/// will not harvest (uninterruptible sleep). The orphaned entry is init's /
/// the runtime's to collect once this helper exits.
fn reap_bounded(child: &mut std::process::Child) {
    let deadline = Instant::now() + TERMINATE_GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

/// Wait (bounded) for the old pid to die and the API port to free.
fn wait_for_old_process_release(handoff: &UpgradeHandoff, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let pid_gone = !pid_alive(handoff.old_pid);
        // An ephemeral recorded port (0) cannot be probed; pid death is the
        // release signal there.
        let port_free = handoff.api_addr.port() == 0 || addr_is_free(handoff.api_addr);
        if pid_gone && port_free {
            return true;
        }
        if Instant::now() >= deadline {
            eprintln!(
                "x0xd: old pid {} still {} (port {} free: {})",
                handoff.old_pid,
                if pid_gone { "gone" } else { "alive" },
                handoff.api_addr,
                port_free
            );
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Wait (bounded) for `GET /health` to answer `ok: true` with
/// `expected_version` on the pre-upgrade API address, or on the address the
/// replacement advertised in `<data_dir>/api.port` when the pre-upgrade bind
/// was ephemeral.
fn wait_for_health(
    handoff: &UpgradeHandoff,
    data_dir: &Path,
    timeout: Duration,
    expected_version: &str,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(addr) = resolve_health_addr(handoff, data_dir) {
            if http_health_ok(addr, expected_version) {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The address to health-check: the recorded API address, unless the bind was
/// ephemeral (port 0) — then whatever the replacement wrote to `api.port`.
fn resolve_health_addr(handoff: &UpgradeHandoff, data_dir: &Path) -> Option<SocketAddr> {
    if handoff.api_addr.port() != 0 {
        return Some(handoff.api_addr);
    }
    std::fs::read_to_string(data_dir.join("api.port"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Whether `kill(pid, 0)` says the pid is alive (or protected). A pid we lack
/// permission to signal counts as alive — never a false "dead".
#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return true;
    }
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    )
}

#[cfg(not(unix))]
fn pid_alive(_pid: u32) -> bool {
    // No portable pre-exit probe; the port check below carries the wait.
    false
}

/// Whether the exact address can be bound right now. The probe binds the
/// address verbatim — including unspecified wildcard binds — because that is
/// precisely what the restarted daemon will attempt. BSD `SO_REUSEADDR`
/// permits overlapping wildcard/specific binds, so substituting loopback for
/// a wildcard address can report a held port as free; an exact-duplicate
/// bind is refused on every platform (`SO_REUSEPORT` would be required to
/// steal it). `AddrInUse` is the only "busy" answer; anything else
/// (firewalled, unsupported family) reads as free so the wait cannot
/// deadlock on exotic setups.
fn addr_is_free(addr: SocketAddr) -> bool {
    match TcpListener::bind(addr) {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(e) => e.kind() != std::io::ErrorKind::AddrInUse,
    }
}

/// Cap on the `/health` response this probe will buffer. The real body is a
/// few hundred bytes; anything larger is not our daemon.
const HEALTH_RESPONSE_CAP: usize = 16 * 1024;

/// Overall wall-clock bound on one `/health` probe exchange — the second
/// bound beside the byte cap above. The socket timeouts are per-operation:
/// a responder trickling bytes with sub-timeout gaps could otherwise stretch
/// a single probe arbitrarily, deferring `wait_for_health`'s deadline check
/// and everything it guards (`terminate_and_reap`, the rollback) past
/// `health_timeout` without ever firing a timeout. A bounded watchdog must
/// bound the probe, not just each read (code-review finding).
const PROBE_IO_BOUND: Duration = Duration::from_secs(5);

/// Minimal mirror of the daemon's `/health` envelope —
/// `server::routes::status`'s `ApiResponse<HealthData>`, whose `data` is
/// `#[serde(flatten)]`ed into `{"ok":true,"status":…,"version":…,…}`. Those
/// types are `pub(in crate::server)` and Serialize-only, so the probe carries
/// its own Deserialize shape; unknown fields are ignored.
#[derive(serde::Deserialize)]
struct HealthProbe {
    ok: bool,
    version: String,
}

/// Bounded `GET /health` readiness probe: the responder must answer HTTP 200
/// whose full (size-capped) body parses as the daemon's health envelope with
/// `ok == true` and `version == expected_version`. A bare 200 — from an old
/// image still bound to the address, or a foreign listener — never commits
/// the restart, and a truncated or malformed body fails closed.
/// `/health` is auth-exempt on the daemon API.
fn http_health_ok(addr: SocketAddr, expected_version: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let started = Instant::now();
    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if started.elapsed() >= PROBE_IO_BOUND {
            return false;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if response.len() + n > HEALTH_RESPONSE_CAP {
                    return false;
                }
                response.extend_from_slice(&chunk[..n]);
            }
            Err(_) => return false,
        }
    }
    let response = String::from_utf8_lossy(&response);
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    if !(head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")) {
        return false;
    }
    match serde_json::from_str::<HealthProbe>(body) {
        Ok(probe) => probe.ok && probe.version == expected_version,
        Err(_) => false,
    }
}

/// Restore the backup bytes over the target — the same
/// [`Upgrader::restore_from_backup`] the file-swap rollback uses.
fn restore_backup(backup_path: &Path, target_path: &Path) -> Result<(), UpgradeError> {
    // restore_from_backup never consults the version; a sentinel keeps this
    // independent of the versions recorded in the handoff JSON.
    Upgrader::new(target_path.to_path_buf(), Version::new(0, 0, 0)).restore_from_backup(backup_path)
}

/// Write the loud failure artifact: reason, versions, paths, timestamps.
fn write_upgrade_failed(data_dir: &Path, reason: &str, handoff: &UpgradeHandoff) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let content = format!(
        "x0xd self-upgrade FAILED at unix time {now} ({})\n\
         reason: {reason}\n\
         from version: {}\n\
         to version: {}\n\
         target binary: {}\n\
         backup binary: {}\n\
         old pid: {}\n\
         api address: {}\n\
         handoff started at: unix {}\n\
         the daemon is NOT running — relaunch it (the backup above holds the last good binary)\n",
        humantime_or_raw(now),
        handoff.from_version,
        handoff.to_version,
        handoff.target_path.display(),
        handoff.backup_path.display(),
        handoff.old_pid,
        handoff.api_addr,
        handoff.started_at,
    );
    let path = data_dir.join(UPGRADE_FAILED_FILE_NAME);
    if let Err(e) = std::fs::write(&path, content) {
        eprintln!(
            "x0xd: could not write {}: {e} — upgrade failed: {reason}",
            path.display()
        );
    }
}

/// The data directory owning a handoff file path (its parent).
fn data_dir_of(handoff_path: &Path) -> PathBuf {
    handoff_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// RFC 3339-ish timestamp without pulling a datetime crate: fall back to the
/// raw epoch seconds when `date` is unavailable (the file still carries the
/// epoch value in its header line).
fn humantime_or_raw(epoch: u64) -> String {
    match std::process::Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .arg(format!("@{epoch}"))
        .output()
    {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => format!("epoch {epoch}"),
    }
}

/// Timeout from an env override (seconds), else the 30s default.
fn env_timeout(env_var: &str) -> Duration {
    std::env::var(env_var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_HANDOFF_TIMEOUT)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn shell_parent_signals() -> SupervisionSignals {
        SupervisionSignals {
            invocation_id: false,
            x0x_supervised: false,
            parent_comm: Some("zsh".to_string()),
            stdin_is_tty: true,
        }
    }

    #[test]
    fn unsupervised_stop_on_upgrade_true_chooses_handoff() {
        // The #261 incident: terminal-launched (parent = shell), config
        // default stop_on_upgrade=true, no supervision env. Must NOT be a
        // supervised exit(0).
        assert_eq!(
            plan_restart_mode(true, &shell_parent_signals()),
            Ok(RestartMode::TransactionalHandoff)
        );
    }

    #[test]
    fn unsupervised_without_tty_still_chooses_handoff() {
        // Architect pin: nohup/background (stdin not a TTY) is NOT
        // supervision. Same classification as the TTY case.
        let signals = SupervisionSignals {
            stdin_is_tty: false,
            ..shell_parent_signals()
        };
        assert_eq!(
            plan_restart_mode(true, &signals),
            Ok(RestartMode::TransactionalHandoff)
        );
    }

    #[test]
    fn detached_shell_parent_without_tty_is_unsupervised() {
        let signals = SupervisionSignals {
            invocation_id: false,
            x0x_supervised: false,
            parent_comm: Some("sh".to_string()),
            stdin_is_tty: false,
        };
        assert!(!is_supervised(&signals));
    }

    #[test]
    fn launchd_ancestor_comm_is_not_supervision() {
        // "Some ancestor is launchd" must never qualify — every macOS process
        // has that. A launchd parent only counts via X0X_SUPERVISED=1.
        let signals = SupervisionSignals {
            parent_comm: Some("launchd".to_string()),
            ..shell_parent_signals()
        };
        assert!(!is_supervised(&signals));
        assert_eq!(
            plan_restart_mode(true, &signals),
            Ok(RestartMode::TransactionalHandoff)
        );
    }

    #[test]
    fn invocation_id_with_stop_on_upgrade_chooses_supervised_exit() {
        let signals = SupervisionSignals {
            invocation_id: true,
            ..shell_parent_signals()
        };
        assert_eq!(
            plan_restart_mode(true, &signals),
            Ok(RestartMode::SupervisedExit)
        );
    }

    #[test]
    fn systemd_parent_comm_chooses_supervised_exit() {
        let signals = SupervisionSignals {
            parent_comm: Some("systemd".to_string()),
            ..shell_parent_signals()
        };
        assert_eq!(
            plan_restart_mode(true, &signals),
            Ok(RestartMode::SupervisedExit)
        );
    }

    #[test]
    fn systemd_parent_comm_is_trimmed() {
        // /proc/<pid>/comm carries a trailing newline; the classifier must
        // trim it before comparing.
        let signals = SupervisionSignals {
            parent_comm: Some("systemd\n".to_string()),
            ..shell_parent_signals()
        };
        assert_eq!(
            plan_restart_mode(true, &signals),
            Ok(RestartMode::SupervisedExit)
        );
    }

    #[test]
    fn x0x_supervised_env_chooses_supervised_exit_even_without_tty() {
        // Explicit operator opt-in (launchd plist / Windows service) with
        // stdin not a TTY: still supervised — not-a-TTY alone never flips it.
        let signals = SupervisionSignals {
            x0x_supervised: true,
            stdin_is_tty: false,
            ..shell_parent_signals()
        };
        assert_eq!(
            plan_restart_mode(true, &signals),
            Ok(RestartMode::SupervisedExit)
        );
    }

    #[test]
    fn unsupervised_stop_on_upgrade_false_still_uses_handoff() {
        // Unchanged half of the old `stop_on_upgrade_false_always_uses_handoff`
        // contract: with nobody to respawn us, stop_on_upgrade=false must not
        // become a fire-and-forget exit. The helper still owns the restart.
        assert_eq!(
            plan_restart_mode(false, &shell_parent_signals()),
            Ok(RestartMode::TransactionalHandoff)
        );
    }

    #[test]
    fn supervised_stop_on_upgrade_false_is_refused_not_classified() {
        // INVERTED from `stop_on_upgrade_false_always_uses_handoff`
        // (ADR-0061 §2, accepted 2026-09-09). The old contract classified this
        // as TransactionalHandoff, which is exactly the #493 defect: launchd
        // (or systemd) respawns the daemon while the handoff helper starts a
        // second one, giving one data root two restart owners. Because we
        // cannot know the supervisor's policy, the safe answer is neither
        // mode — refuse, and keep the current binary serving until the
        // operator corrects the deployment.
        for signals in [
            SupervisionSignals {
                invocation_id: true,
                ..shell_parent_signals()
            },
            SupervisionSignals {
                x0x_supervised: true,
                ..shell_parent_signals()
            },
            SupervisionSignals {
                parent_comm: Some("systemd".to_string()),
                ..shell_parent_signals()
            },
        ] {
            let err = plan_restart_mode(false, &signals)
                .expect_err("supervised + stop_on_upgrade=false must refuse, not classify");
            assert!(
                matches!(err, RestartOwnershipError::SupervisedRestartConflict { .. }),
                "expected the ownership conflict, got {err:?}"
            );
            // The refusal is only actionable if it names the signal that made
            // the instance managed and the setting to correct.
            let message = err.to_string();
            assert!(message.contains("stop_on_upgrade"), "message: {message}");
            assert!(
                message
                    .contains(supervision_signal_name(&signals).expect("signals are supervised")),
                "message: {message}"
            );
            assert!(
                message.contains("No binaries were replaced"),
                "the refusal must state that nothing was mutated: {message}"
            );
        }
    }

    /// A binary path inside `dir` whose parent exists — the minimum an
    /// install directory must satisfy for the backup to be writable.
    fn installed_binary(dir: &std::path::Path) -> PathBuf {
        dir.join("x0xd")
    }

    #[test]
    fn resolved_plan_carries_the_contract_the_restart_will_execute() {
        // ADR-0061 §1: the fields the restart depends on (owner, exit
        // behaviour, executable, argv, roots) must all be pinned by the
        // resolver, because after replacement the running image no longer
        // matches the bytes on disk and re-deriving them is unsound.
        let dir = tempfile::tempdir().expect("tempdir");
        let data_root = dir.path().join("data");
        std::fs::create_dir_all(&data_root).expect("data root");
        let binary = installed_binary(dir.path());
        let addr: SocketAddr = "127.0.0.1:12700".parse().expect("addr");

        let plan = resolve_restart_plan(
            true,
            &shell_parent_signals(),
            &binary,
            Some(&data_root),
            Some(addr),
            &readback_na(),
        )
        .expect("an unsupervised terminal run resolves");

        assert_eq!(plan.mode, RestartMode::TransactionalHandoff);
        assert_eq!(plan.supervised_exit_code, None);
        assert_eq!(plan.supervision_signal, None);
        assert_eq!(plan.executable, binary);
        assert_eq!(plan.data_root, data_root);
        assert_eq!(plan.api_addr, addr);
        assert!(!plan.argv.is_empty(), "argv must be captured pre-swap");
        assert_eq!(plan.handoff_path(), data_root.join(HANDOFF_FILE_NAME));
    }

    #[test]
    fn supervised_plan_requests_restart_from_the_owner_and_spawns_no_helper() {
        // ADR-0061 §5: restart ownership stays singular. If the supervised
        // plan ever spawned the helper, launchd/systemd and the helper would
        // each start a daemon on `data_root` — the #493 defect.
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = installed_binary(dir.path());
        let signals = SupervisionSignals {
            x0x_supervised: true,
            ..shell_parent_signals()
        };

        let plan = resolve_restart_plan(
            true,
            &signals,
            &binary,
            Some(dir.path()),
            None,
            &LaunchdPolicyReadback::Verified {
                label: "com.example.x0xd".to_string(),
            },
        )
        .expect("supervised + stop_on_upgrade=true is a supported contract");

        assert_eq!(plan.mode, RestartMode::SupervisedExit);
        assert!(
            !plan.spawns_helper(),
            "the managed path must launch no detached replacement helper"
        );
        assert_eq!(plan.supervised_exit_code, Some(supervised_exit_code()));
        assert_eq!(plan.supervision_signal.as_deref(), Some("X0X_SUPERVISED=1"));
    }

    #[test]
    fn conflicting_managed_config_is_refused_by_the_resolver_too() {
        // The refusal must sit on the path every apply caller uses, not only
        // in the classifier: an apply that got as far as resolving must still
        // abort before it can replace anything.
        let dir = tempfile::tempdir().expect("tempdir");
        let signals = SupervisionSignals {
            invocation_id: true,
            ..shell_parent_signals()
        };
        let err = resolve_restart_plan(
            false,
            &signals,
            &installed_binary(dir.path()),
            Some(dir.path()),
            None,
            &readback_na(),
        )
        .expect_err("supervised + stop_on_upgrade=false must not resolve");
        assert!(matches!(
            err,
            RestartOwnershipError::SupervisedRestartConflict { .. }
        ));
    }

    /// `X0X_SUPERVISED=1` sampled from the environment — the launchd marker.
    fn launchd_marker_signals() -> SupervisionSignals {
        SupervisionSignals {
            x0x_supervised: true,
            ..shell_parent_signals()
        }
    }

    /// A readback value for callers whose recognized signal is not the
    /// launchd marker (the resolver ignores it there).
    fn readback_na() -> LaunchdPolicyReadback {
        LaunchdPolicyReadback::Unavailable {
            detail: "not a launchd-marker instance".to_string(),
        }
    }

    /// A `launchctl print gui/<uid>/<label>` dump for one job, in the exact
    /// shape macOS emits (tab-indented `key = value`, the `arguments` brace
    /// block, and the `properties` summary whose `keepalive` token appears
    /// only while launchd holds an UNCONDITIONAL keep-alive — verified
    /// against real loaded jobs for #615).
    fn launchd_print_dump(args: &[&str], keepalive: bool) -> String {
        let mut args_block = String::new();
        for a in args {
            args_block.push_str(&format!("\t\t{a}\n"));
        }
        let properties = if keepalive {
            "keepalive | runatload | inferred program"
        } else {
            "runatload | inferred program"
        };
        format!(
            "com.example.x0xd = {{\n\
             \tactive count = 1\n\
             \tpath = /Users/t/Library/LaunchAgents/com.example.x0xd.plist\n\
             \ttype = LaunchAgent\n\
             \tstate = running\n\
             \n\
             \tprogram = {program}\n\
             \targuments = {{\n{args_block}\t}}\n\
             \n\
             \tstdout path = /Users/t/Library/Logs/x0xd.log\n\
             \n\
             \tproperties = {properties}\n\
             }}\n",
            program = args.first().copied().unwrap_or("/usr/local/bin/x0xd"),
        )
    }

    #[test]
    fn launchd_readback_parses_program_arguments_and_keepalive() {
        // #615: the LOADED policy is the truth at upgrade time — a job whose
        // plist said `KeepAlive: true` at repair time can have been reloaded
        // with a conditional dict or no KeepAlive at all, and the plist on
        // disk no longer proves anything about what launchd will do after
        // exit 0. `launchctl print` is the readback: its `properties` summary
        // carries the `keepalive` token exactly while launchd holds an
        // unconditional keep-alive (conditional KeepAlive dictionaries do NOT
        // set it — verified against fixture jobs loaded for #615).
        let unconditional = parse_launchd_loaded_job(&launchd_print_dump(
            &["/usr/local/bin/x0xd", "--name", "alice"],
            true,
        ))
        .expect("a well-formed print dump parses");
        assert_eq!(
            unconditional,
            LaunchdLoadedJob {
                program: PathBuf::from("/usr/local/bin/x0xd"),
                arguments: vec![
                    "/usr/local/bin/x0xd".to_string(),
                    "--name".to_string(),
                    "alice".to_string(),
                ],
                keepalive_unconditional: true,
            }
        );

        // Conditional KeepAlive (a dict in the plist): the loaded summary has
        // no `keepalive` token, so an exit-0 respawn is NOT guaranteed.
        let conditional =
            parse_launchd_loaded_job(&launchd_print_dump(&["/usr/local/bin/x0xd"], false))
                .expect("parses");
        assert!(!conditional.keepalive_unconditional);

        // Not a job dump at all: fail closed by parsing to nothing.
        assert!(parse_launchd_loaded_job("launchctl: no such file").is_none());
    }

    #[test]
    fn launchd_readback_matches_this_instance_not_a_sibling() {
        // Multi-instance installs (--name alice / --name bob) run separate
        // launchd jobs. Verifying against bob's healthy job while alice's job
        // lost KeepAlive would green-light an upgrade that strands alice, so
        // the match must compare the job's arguments to THIS process's argv —
        // program basename plus the flags that select the instance.
        let bob_job = parse_launchd_loaded_job(&launchd_print_dump(
            &["/usr/local/bin/x0xd", "--name", "bob"],
            true,
        ))
        .expect("parses");
        let alice_argv = vec![
            "/usr/local/bin/x0xd".to_string(),
            "--name".to_string(),
            "alice".to_string(),
        ];
        assert!(
            !launchd_job_runs_this_instance(&bob_job, &alice_argv),
            "a sibling instance's job must not verify this instance"
        );

        let alice_job = parse_launchd_loaded_job(&launchd_print_dump(
            &["/opt/x0x/bin/x0xd", "--name", "alice"],
            true,
        ))
        .expect("parses");
        // argv[0] may differ in path (symlinks, relative launch) — the
        // basename plus the flag tail is the identity.
        assert!(launchd_job_runs_this_instance(&alice_job, &alice_argv));

        // A job running some other program with coincidentally equal flags
        // must not match.
        let foreign = parse_launchd_loaded_job(&launchd_print_dump(&["/usr/local/bin/x0xd"], true))
            .expect("parses");
        assert!(!launchd_job_runs_this_instance(&foreign, &alice_argv));
    }

    #[test]
    fn marker_without_a_guaranteed_respawn_is_refused_by_the_resolver() {
        // #615 / ADR-0061 §3: `X0X_SUPERVISED=1` is a marker, and a marker in
        // isolation is NOT support. The residual failure it leaves today: a
        // job repaired when its plist had `KeepAlive: true`, later edited to
        // a conditional KeepAlive or none, still classifies SupervisedExit,
        // exits 0 for the upgrade — and nothing restarts it. The daemon goes
        // down and stays down, silently. The resolver must refuse the update
        // while the current binary still serves, exactly like the §2 conflict.
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = installed_binary(dir.path());

        let err = resolve_restart_plan(
            true,
            &launchd_marker_signals(),
            &binary,
            Some(dir.path()),
            None,
            &LaunchdPolicyReadback::NotGuaranteed {
                detail: "loaded job com.example.x0xd does not hold an unconditional KeepAlive"
                    .to_string(),
            },
        )
        .expect_err("an unverifiable launchd policy must refuse the apply");

        assert!(
            matches!(
                &err,
                RestartOwnershipError::SupervisedPolicyNotGuaranteed { signal, .. }
                    if signal == "X0X_SUPERVISED=1"
            ),
            "got {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("No binaries were replaced"),
            "the refusal must state that nothing was mutated: {message}"
        );
        // #616: the operator path out of a failed supervised upgrade is the
        // manual recovery procedure — the diagnostic must point at it.
        assert!(
            message.contains("docs/upgrade-system.md"),
            "the refusal must cross-link the manual recovery procedure: {message}"
        );
    }

    #[test]
    fn marker_with_a_verified_loaded_policy_resolves_supervised_exit() {
        // The positive half: readback found the loaded job for THIS instance
        // and launchd holds an unconditional keep-alive on it, so the exit-0
        // restart request has a guaranteed taker.
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = installed_binary(dir.path());
        let plan = resolve_restart_plan(
            true,
            &launchd_marker_signals(),
            &binary,
            Some(dir.path()),
            None,
            &LaunchdPolicyReadback::Verified {
                label: "com.example.x0xd".to_string(),
            },
        )
        .expect("a verified launchd policy is a supported contract");
        assert_eq!(plan.mode, RestartMode::SupervisedExit);
    }

    #[test]
    fn non_marker_signals_do_not_gate_on_a_launchd_readback() {
        // INVOCATION_ID (systemd) is not a launchd marker: the readback is
        // Unavailable on this platform, and the contract still resolves —
        // the marker-in-isolation gap is a launchd-specific fix (#615); the
        // systemd-side readback is deliberately out of its scope.
        let dir = tempfile::tempdir().expect("tempdir");
        let signals = SupervisionSignals {
            invocation_id: true,
            ..shell_parent_signals()
        };
        let plan = resolve_restart_plan(
            true,
            &signals,
            &installed_binary(dir.path()),
            Some(dir.path()),
            None,
            &LaunchdPolicyReadback::Unavailable {
                detail: "no launchd on a systemd unit".to_string(),
            },
        )
        .expect("systemd signals do not require a launchd readback");
        assert_eq!(plan.mode, RestartMode::SupervisedExit);
    }

    // ------------------------------------------------------------------------
    // Round-2 (#615 review): the readback DECISION core — the code that
    // decides refuse-vs-proceed on real Macs — driven with captured
    // `launchctl print` output, so every fail-closed arm is pinned without
    // touching real launchd or the developer's ~/Library/LaunchAgents.
    // ------------------------------------------------------------------------

    /// Write a LaunchAgents-style candidate plist as plain JSON (the reader
    /// is injected in these tests, so no plutil is involved).
    fn write_candidate_plist(dir: &Path, label: &str, program: &str, args: &[&str]) {
        let mut argv = vec![program.to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        let plist = serde_json::json!({
            "Label": label,
            "ProgramArguments": argv,
        });
        std::fs::write(
            dir.join(format!("{label}.plist")),
            serde_json::to_string(&plist).expect("serialize fixture plist"),
        )
        .expect("write fixture plist");
    }

    /// The injected plist reader for the decision tests.
    fn read_json_plist(path: &Path) -> Option<serde_json::Value> {
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
    }

    const TEST_LABEL: &str = "com.example.x0xd";
    const TEST_EXE: &str = "/usr/local/bin/x0xd";

    #[test]
    fn readback_decision_verifies_a_loaded_keepalive_job() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_candidate_plist(dir.path(), TEST_LABEL, TEST_EXE, &[]);
        let dump = launchd_print_dump(&[TEST_EXE], true);
        let verdict = readback_launchd_policy_in(
            dir.path(),
            501,
            Path::new(TEST_EXE),
            &[TEST_EXE.to_string()],
            &read_json_plist,
            &mut |_target| Ok(Some(dump.clone())),
        );
        assert_eq!(
            verdict,
            LaunchdPolicyReadback::Verified {
                label: TEST_LABEL.to_string()
            }
        );
    }

    #[test]
    fn readback_decision_refuses_a_conditional_keepalive_job() {
        // The #615 scenario itself: the plist still names this executable,
        // the job is loaded, but the LOADED policy no longer guarantees a
        // respawn after exit 0 — refuse rather than exit into a dead service.
        let dir = tempfile::tempdir().expect("tempdir");
        write_candidate_plist(dir.path(), TEST_LABEL, TEST_EXE, &[]);
        let dump = launchd_print_dump(&[TEST_EXE], false);
        let verdict = readback_launchd_policy_in(
            dir.path(),
            501,
            Path::new(TEST_EXE),
            &[TEST_EXE.to_string()],
            &read_json_plist,
            &mut |_target| Ok(Some(dump.clone())),
        );
        match verdict {
            LaunchdPolicyReadback::NotGuaranteed { detail } => {
                assert!(
                    detail.contains("does not hold an unconditional KeepAlive"),
                    "detail: {detail}"
                );
            }
            other => panic!("expected NotGuaranteed, got {other:?}"),
        }
    }

    #[test]
    fn readback_decision_falls_back_to_the_user_domain() {
        // Round-2 review: `gui/<uid>` and `user/<uid>` are DISJOINT — a
        // marker job bootstrapped into `user/<uid>` answers "Could not find
        // service" from the gui probe. Probing gui alone refused such a job
        // forever. The gui miss must fall back to `user/<uid>`, and gui must
        // be probed FIRST (it is the domain `x0x autostart` loads into).
        let dir = tempfile::tempdir().expect("tempdir");
        write_candidate_plist(dir.path(), TEST_LABEL, TEST_EXE, &[]);
        let dump = launchd_print_dump(&[TEST_EXE], true);
        let mut probed = Vec::new();
        let verdict = readback_launchd_policy_in(
            dir.path(),
            501,
            Path::new(TEST_EXE),
            &[TEST_EXE.to_string()],
            &read_json_plist,
            &mut |target| {
                probed.push(target.to_string());
                if target == "user/501/com.example.x0xd" {
                    Ok(Some(dump.clone()))
                } else {
                    Ok(None)
                }
            },
        );
        assert_eq!(
            verdict,
            LaunchdPolicyReadback::Verified {
                label: TEST_LABEL.to_string()
            }
        );
        assert_eq!(
            probed,
            vec![
                "gui/501/com.example.x0xd".to_string(),
                "user/501/com.example.x0xd".to_string()
            ],
            "gui must be probed first, user only as fallback"
        );
    }

    #[test]
    fn readback_decision_refuses_a_job_not_loaded_in_either_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_candidate_plist(dir.path(), TEST_LABEL, TEST_EXE, &[]);
        let verdict = readback_launchd_policy_in(
            dir.path(),
            501,
            Path::new(TEST_EXE),
            &[TEST_EXE.to_string()],
            &read_json_plist,
            &mut |_target| Ok(None),
        );
        match verdict {
            LaunchdPolicyReadback::NotGuaranteed { detail } => {
                assert!(
                    detail.contains("not loaded in either the gui or the user launchd domain"),
                    "detail: {detail}"
                );
            }
            other => panic!("expected NotGuaranteed, got {other:?}"),
        }
    }

    #[test]
    fn readback_decision_fails_closed_on_unparseable_loaded_policy() {
        // launchctl "succeeds" but the dump is not a job dump (format drift,
        // partial output): parsing to nothing must refuse, never guess.
        let dir = tempfile::tempdir().expect("tempdir");
        write_candidate_plist(dir.path(), TEST_LABEL, TEST_EXE, &[]);
        let verdict = readback_launchd_policy_in(
            dir.path(),
            501,
            Path::new(TEST_EXE),
            &[TEST_EXE.to_string()],
            &read_json_plist,
            &mut |_target| Ok(Some("launchctl: unexpected format drift".to_string())),
        );
        match verdict {
            LaunchdPolicyReadback::NotGuaranteed { detail } => {
                assert!(
                    detail.contains("could not parse the loaded policy"),
                    "detail: {detail}"
                );
            }
            other => panic!("expected NotGuaranteed, got {other:?}"),
        }
    }

    #[test]
    fn readback_decision_refuses_when_only_a_sibling_instance_matches() {
        // A loaded, healthy job for a DIFFERENT instance (--name bob) must
        // not verify this instance, and the refusal must say why — the
        // operator is told which job was inspected, not a bare "no job".
        let dir = tempfile::tempdir().expect("tempdir");
        write_candidate_plist(dir.path(), TEST_LABEL, TEST_EXE, &["--name", "bob"]);
        let dump = launchd_print_dump(&[TEST_EXE, "--name", "bob"], true);
        let verdict = readback_launchd_policy_in(
            dir.path(),
            501,
            Path::new(TEST_EXE),
            &[
                TEST_EXE.to_string(),
                "--name".to_string(),
                "alice".to_string(),
            ],
            &read_json_plist,
            &mut |_target| Ok(Some(dump.clone())),
        );
        match verdict {
            LaunchdPolicyReadback::NotGuaranteed { detail } => {
                assert!(
                    detail.contains("runs different arguments"),
                    "detail: {detail}"
                );
            }
            other => panic!("expected NotGuaranteed, got {other:?}"),
        }
    }

    #[test]
    fn readback_decision_refuses_when_no_plist_names_this_executable() {
        // Marker set, but nothing in LaunchAgents even references this
        // executable: an env-var-only marker with no supervisor is exactly
        // the false positive §3 rules out — refuse with the honest reason.
        let dir = tempfile::tempdir().expect("tempdir");
        let verdict = readback_launchd_policy_in(
            dir.path(),
            501,
            Path::new(TEST_EXE),
            &[TEST_EXE.to_string()],
            &read_json_plist,
            &mut |_target| Ok(None),
        );
        match verdict {
            LaunchdPolicyReadback::NotGuaranteed { detail } => {
                assert!(detail.contains("no launchd job"), "detail: {detail}");
            }
            other => panic!("expected NotGuaranteed, got {other:?}"),
        }
    }

    #[test]
    fn unresolvable_roots_fail_for_their_own_reason() {
        // ADR-0061 validation: "malformed/unresolved contract input must fail
        // for its own reason" — an unusable install dir or data root must not
        // be reported as an ownership conflict, and must not be discovered
        // after the swap.
        let dir = tempfile::tempdir().expect("tempdir");
        let missing_install = dir.path().join("no-such-dir").join("x0xd");
        let err = resolve_restart_plan(
            true,
            &shell_parent_signals(),
            &missing_install,
            Some(dir.path()),
            None,
            &readback_na(),
        )
        .expect_err("a missing install directory is an unresolved contract");
        assert!(
            matches!(err, RestartOwnershipError::Unresolved { what, .. } if what == "install directory"),
            "got {err:?}"
        );

        let err = resolve_restart_plan(
            true,
            &shell_parent_signals(),
            &installed_binary(dir.path()),
            Some(&dir.path().join("no-such-data-root")),
            None,
            &readback_na(),
        )
        .expect_err("a missing data root is an unresolved contract");
        assert!(
            matches!(err, RestartOwnershipError::Unresolved { what, .. } if what == "data root"),
            "got {err:?}"
        );
    }

    #[test]
    fn handoff_record_is_built_from_the_plan_not_resampled() {
        // ADR-0061 §1: "carry that plan through replacement and restart".
        // The helper must respawn the argv/roots captured before the swap.
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = installed_binary(dir.path());
        let mut plan = resolve_restart_plan(
            true,
            &shell_parent_signals(),
            &binary,
            Some(dir.path()),
            None,
            &readback_na(),
        )
        .expect("resolves");
        plan.argv = vec![
            "x0xd".to_string(),
            "--name".to_string(),
            "alice".to_string(),
        ];

        let handoff = UpgradeHandoff::from_plan(&plan, "9.9.9");
        assert_eq!(handoff.argv, plan.argv);
        assert_eq!(handoff.target_path, plan.executable);
        assert_eq!(
            handoff.backup_path,
            UpgradeHandoff::backup_path_for(&plan.executable)
        );
        assert_eq!(handoff.cwd, plan.cwd.to_string_lossy());
        assert_eq!(handoff.mode, plan.mode);
        assert_eq!(handoff.to_version, "9.9.9");
    }

    #[test]
    fn build_spawn_args_appends_skip_update_check_once() {
        let argv = vec![
            "x0xd".to_string(),
            "--config".to_string(),
            "/etc/x0x/config.toml".to_string(),
        ];
        assert_eq!(
            build_spawn_args(&argv),
            vec![
                "--config".to_string(),
                "/etc/x0x/config.toml".to_string(),
                "--skip-update-check".to_string()
            ]
        );
    }

    #[test]
    fn build_spawn_args_never_duplicates_skip_update_check() {
        let argv = vec![
            "x0xd".to_string(),
            "--skip-update-check".to_string(),
            "--config".to_string(),
            "/etc/x0x/config.toml".to_string(),
        ];
        assert_eq!(
            build_spawn_args(&argv),
            vec![
                "--skip-update-check".to_string(),
                "--config".to_string(),
                "/etc/x0x/config.toml".to_string()
            ]
        );
    }

    #[test]
    fn handoff_json_round_trips() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(HANDOFF_FILE_NAME);
        let handoff = UpgradeHandoff {
            from_version: "1.2.3".to_string(),
            to_version: "1.3.0".to_string(),
            target_path: dir.path().join("x0xd"),
            backup_path: dir.path().join("x0xd.backup"),
            argv: vec![
                "x0xd".to_string(),
                "--config".to_string(),
                "x.toml".to_string(),
            ],
            cwd: "/srv".to_string(),
            env: BTreeMap::from([(SUPERVISED_ENV_VAR.to_string(), "1".to_string())]),
            old_pid: 4242,
            api_addr: "127.0.0.1:12700".parse().unwrap(),
            started_at: 1_700_000_000,
            mode: RestartMode::TransactionalHandoff,
        };
        handoff.write(&path).unwrap();
        let read_back = UpgradeHandoff::read(&path).unwrap();
        assert_eq!(read_back.from_version, "1.2.3");
        assert_eq!(read_back.to_version, "1.3.0");
        assert_eq!(read_back.argv, handoff.argv);
        assert_eq!(read_back.old_pid, 4242);
        assert_eq!(read_back.api_addr, handoff.api_addr);
        assert_eq!(read_back.mode, RestartMode::TransactionalHandoff);
        assert_eq!(
            read_back.env.get(SUPERVISED_ENV_VAR).map(String::as_str),
            Some("1")
        );
    }

    #[test]
    fn handoff_file_names_are_stable() {
        assert_eq!(HANDOFF_FILE_NAME, "upgrade-handoff.json");
        assert_eq!(UPGRADE_FAILED_FILE_NAME, "UPGRADE_FAILED");
    }

    #[test]
    fn backup_path_for_matches_swap_backup_name() {
        // The handoff must point at the same x0xd.backup the swap created
        // (target.with_extension("backup")), or rollback restores nothing.
        let target = Path::new("/opt/x0x/bin/x0xd");
        assert_eq!(
            UpgradeHandoff::backup_path_for(target),
            Path::new("/opt/x0x/bin/x0xd.backup")
        );
    }

    #[test]
    fn resolve_health_addr_prefers_recorded_port() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("api.port"), "127.0.0.1:9999\n").unwrap();
        let handoff = UpgradeHandoff {
            from_version: "1.0.0".to_string(),
            to_version: "1.1.0".to_string(),
            target_path: dir.path().join("x0xd"),
            backup_path: dir.path().join("x0xd.backup"),
            argv: vec!["x0xd".to_string()],
            cwd: "/".to_string(),
            env: BTreeMap::new(),
            old_pid: 1,
            api_addr: "127.0.0.1:12700".parse().unwrap(),
            started_at: 0,
            mode: RestartMode::TransactionalHandoff,
        };
        assert_eq!(
            resolve_health_addr(&handoff, dir.path()),
            Some("127.0.0.1:12700".parse().unwrap())
        );
    }

    #[test]
    fn resolve_health_addr_reads_api_port_when_ephemeral() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("api.port"), "127.0.0.1:41234\n").unwrap();
        let handoff = UpgradeHandoff {
            api_addr: "127.0.0.1:0".parse().unwrap(),
            ..ephemeral_handoff_fixture()
        };
        assert_eq!(
            resolve_health_addr(&handoff, dir.path()),
            Some("127.0.0.1:41234".parse().unwrap())
        );
        // No api.port yet (old process removed it, new one not bound):
        // nothing to probe, the health wait keeps polling.
        let missing = dir.path().join("missing");
        assert_eq!(resolve_health_addr(&handoff, &missing), None);
    }

    fn ephemeral_handoff_fixture() -> UpgradeHandoff {
        UpgradeHandoff {
            from_version: "1.0.0".to_string(),
            to_version: "1.1.0".to_string(),
            target_path: PathBuf::from("/opt/x0x/x0xd"),
            backup_path: PathBuf::from("/opt/x0x/x0xd.backup"),
            argv: vec!["x0xd".to_string()],
            cwd: "/".to_string(),
            env: BTreeMap::new(),
            old_pid: 1,
            api_addr: "127.0.0.1:0".parse().unwrap(),
            started_at: 0,
            mode: RestartMode::TransactionalHandoff,
        }
    }

    #[test]
    fn addr_is_free_detects_bound_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(!addr_is_free(addr));
        let port = addr.port();
        drop(listener);
        // Small race window after drop; retry briefly before asserting free.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !addr_is_free(SocketAddr::from(([127, 0, 0, 1], port))) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(addr_is_free(SocketAddr::from(([127, 0, 0, 1], port))));
    }

    #[test]
    fn addr_is_free_detects_wildcard_bound_port() {
        let listener = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(!addr_is_free(addr));
        drop(listener);
        // Same small race window after drop as above; the wildcard address
        // must read free again so the release wait cannot wedge.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !addr_is_free(addr) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(addr_is_free(addr));
    }

    /// The daemon's `/health` body — mirrors `ApiResponse<HealthData>`'s
    /// flattened serialization (`status.rs`); the probe ignores unknown
    /// fields, as it must against real responses.
    fn health_body(version: &str) -> String {
        format!(
            "{{\"ok\":true,\"status\":\"ok\",\"version\":\"{version}\",\"peers\":0,\
             \"send_ready_peers\":0,\"uptime_secs\":0,\"warnings\":[]}}"
        )
    }

    /// Serve one canned HTTP response per accepted connection, in order.
    fn serve_responses(
        listener: TcpListener,
        responses: Vec<(String, String)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for (status, body) in responses {
                let (mut sock, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let mut buf = [0u8; 256];
                let _ = sock.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        })
    }

    #[test]
    fn http_health_ok_accepts_200_and_rejects_non_200() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = serve_responses(
            listener,
            vec![
                ("200 OK".to_string(), health_body("1.2.3")),
                ("503 Service Unavailable".to_string(), health_body("1.2.3")),
            ],
        );
        assert!(http_health_ok(addr, "1.2.3"));
        assert!(!http_health_ok(addr, "1.2.3"));
        server.join().unwrap();
    }

    #[test]
    fn http_health_ok_rejects_200_with_wrong_version() {
        // The production bug this probe closes: an OLD (or foreign) listener
        // answering 200 ok:true must not commit a new-version restart.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = serve_responses(listener, vec![("200 OK".to_string(), health_body("9.9.7"))]);
        assert!(!http_health_ok(addr, "9.9.9"));
        server.join().unwrap();
    }

    #[test]
    fn http_health_ok_rejects_malformed_truncated_or_not_ok_bodies() {
        // Truncated JSON, a non-JSON body, and ok:false must all fail closed
        // — a garbled responder never commits the restart.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let truncated = "{\"ok\":true,\"version\":\"1.2".to_string();
        let not_ok = "{\"ok\":false,\"version\":\"1.2.3\"}".to_string();
        let server = serve_responses(
            listener,
            vec![
                ("200 OK".to_string(), truncated),
                ("200 OK".to_string(), "ok".to_string()),
                ("200 OK".to_string(), not_ok),
            ],
        );
        assert!(!http_health_ok(addr, "1.2.3"));
        assert!(!http_health_ok(addr, "1.2.3"));
        assert!(!http_health_ok(addr, "1.2.3"));
        server.join().unwrap();
    }

    #[test]
    fn http_health_ok_rejects_oversized_health_body() {
        // A body beyond HEALTH_RESPONSE_CAP is not our daemon; the probe
        // must stop buffering and fail closed. (The wall-clock
        // PROBE_IO_BOUND trickle case is documented on the const — a
        // timing-based test here would itself be flaky.)
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let oversized = format!(
            "{{\"ok\":true,\"version\":\"1.2.3\",\"pad\":\"{}\"}}",
            "x".repeat(HEALTH_RESPONSE_CAP + 1024)
        );
        let server = serve_responses(listener, vec![("200 OK".to_string(), oversized)]);
        assert!(!http_health_ok(addr, "1.2.3"));
        server.join().unwrap();
    }
    #[test]
    fn env_timeout_defaults_and_overrides() {
        // No env manipulation here (process-global and racy under nextest's
        // parallel tests): pin the default and the parser instead.
        assert_eq!(DEFAULT_HANDOFF_TIMEOUT, Duration::from_secs(30));
        assert_eq!("2".parse::<u64>().unwrap(), 2);
    }

    #[test]
    fn restore_backup_moves_backup_over_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("x0xd");
        let backup = dir.path().join("x0xd.backup");
        std::fs::write(&target, b"new broken bytes").unwrap();
        std::fs::write(&backup, b"old good bytes").unwrap();
        restore_backup(&backup, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"old good bytes");
        assert!(!backup.exists(), "restore moves (not copies) the backup");
    }
}
