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
        /// The per-user launchd session domain whose loaded state answered
        /// the probe: `gui` or `user`. The two domains are disjoint, so a
        /// job verified in one is invisible to the other — surfacing which
        /// one matched keeps an operator's `launchctl print` follow-up from
        /// answering "Could not find service" (#671).
        domain: &'static str,
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

/// The launchd job whose loaded policy guaranteed the supervised restart
/// (ADR-0061 §3, #671): the label plus the per-user session domain that held
/// it. Carried into [`RestartPlan`] and the `upgrade-handoff.json` intent
/// record so an operator's follow-up `launchctl print` targets the domain
/// that actually answered, not the one `x0x autostart` usually loads into.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LaunchdVerifiedJob {
    /// launchd label of the verified job.
    pub label: String,
    /// Per-user session domain that held the job: `gui` or `user`.
    pub domain: String,
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

/// [`readback_launchd_policy`] run off the async runtime (#671).
///
/// The readback shells out to `plutil` and `launchctl print` synchronously
/// (`[`readback_launchd_policy_macos`]`), and the upgrade path awaits it from
/// async code. Run inline, a slow `launchctl` would stall the runtime worker
/// for the whole subprocess exchange; [`tokio::task::spawn_blocking`] moves
/// the entire readback — plist discovery plus both domain probes — onto the
/// blocking pool, so the runtime keeps serving while launchd answers.
///
/// Fails closed: a join failure (the readback task panicked or was torn down
/// with the runtime) maps to `NotGuaranteed`, so the apply is refused rather
/// than green-lit by a policy that was never read.
pub async fn readback_launchd_policy_offloaded(
    signals: &SupervisionSignals,
    executable: &Path,
    argv: &[String],
) -> LaunchdPolicyReadback {
    let signals = signals.clone();
    let executable = executable.to_path_buf();
    let argv = argv.to_vec();
    spawn_readback_offloaded(move || readback_launchd_policy(&signals, &executable, &argv)).await
}

/// spawn_blocking core of [`readback_launchd_policy_offloaded`], split so the
/// offload itself is testable with a stand-in readback closure instead of the
/// real plutil/launchctl subprocesses.
async fn spawn_readback_offloaded(
    readback: impl FnOnce() -> LaunchdPolicyReadback + Send + 'static,
) -> LaunchdPolicyReadback {
    match tokio::task::spawn_blocking(readback).await {
        Ok(verdict) => verdict,
        Err(join_err) => LaunchdPolicyReadback::NotGuaranteed {
            detail: format!("launchd policy readback task failed: {join_err}"),
        },
    }
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
#[cfg(any(test, target_os = "macos"))]
type PlistReader<'a> = &'a dyn Fn(&Path) -> Option<serde_json::Value>;

/// launchctl probe callback for [`readback_launchd_policy_in`]: given a full
/// launchd service target (e.g. `gui/501/com.example.x0xd`), `Ok(Some(stdout))`
/// when that domain holds the job, `Ok(None)` when it does not, `Err` when
/// launchctl could not be run. `FnMut` so tests can record probe order.
#[cfg(any(test, target_os = "macos"))]
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
#[cfg(any(test, target_os = "macos"))]
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
            Ok(Some(stdout)) => Some((std::borrow::Cow::Borrowed(stdout.as_str()), "gui")),
            _ => match launchctl_print(&format!("user/{uid}/{label}")) {
                Ok(Some(stdout)) => Some((std::borrow::Cow::Owned(stdout), "user")),
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
        let Some((stdout, domain)) = loaded_stdout else {
            refusal
                .get_or_insert_with(|| format!("could not parse the loaded policy of job {label}"));
            continue;
        };
        let Some(loaded) = parse_launchd_loaded_job(&stdout) else {
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
                domain,
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
// ---------------------------------------------------------------------------
// systemd loaded-policy readback (ADR-0061 §3, #690)
// ---------------------------------------------------------------------------

/// `Environment=` key the versioned systemd template stamps into generated
/// units (see `x0x autostart`): it makes the template generation the job
/// was created from observable in the LOADED policy (`systemctl show -p
/// Environment`), so upgrade-time drift detection does not have to trust a
/// file on disk.
pub const SYSTEMD_TEMPLATE_ENV_KEY: &str = "X0X_TEMPLATE_VERSION";

/// The launchd plist key carrying the same template-version identity.
pub const LAUNCHD_TEMPLATE_VERSION_KEY: &str = "X0XTemplateVersion";

/// Upper bound for every `systemctl` subprocess the readback runs
/// (`systemctl show` on one unit; bounded so a wedged dbus/manager cannot
/// hang an upgrade decision — the refusal side of the bound is fail-closed).
#[cfg(target_os = "linux")]
const SYSTEMCTL_SHOW_BOUND: Duration = Duration::from_secs(5);

/// Output cap for the bounded `systemctl show` collection: far above any
/// realistic property payload, small enough that a runaway `show` (e.g. a
/// unit with a pathological Environment) cannot balloon memory.
#[cfg(target_os = "linux")]
const SYSTEMCTL_OUTPUT_CAP: usize = 256 * 1024;

/// `Restart=` values that guarantee a respawn after the supervised exit
/// status (exit 0), per `man systemd.service` (table 2): `always`
/// restarts on every exit including clean ones; `on-success` restarts on
/// exit 0/success specifically. Every other value (`no`, `on-failure`,
/// `on-abnormal`, `on-watchdog`, `on-abort`) leaves a clean exit
/// un-restarted and may NOT back a `SupervisedExit` plan — the daemon
/// would exit 0 for the upgrade and stay down.
#[cfg(any(test, target_os = "linux"))]
const RESTART_POLICIES_GUARANTEEING_CLEAN_EXIT_RESTART: &[&str] = &["always", "on-success"];

/// The systemd unit whose loaded policy guaranteed the restart (ADR-0061
/// §3, #690): the unit name, which manager holds it, the confirmed
/// `Restart=` value, and the template version stamped in the unit's loaded
/// environment when the deployment was created from a versioned template
/// (`None` = pre-template legacy unit — recorded for drift visibility, not a
/// refusal; the readback's accept/reject rests on policy and instance
/// binding, not on the version marker).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SystemdVerifiedUnit {
    /// Unit name as systemd knows it (instance suffix included, e.g.
    /// `x0xd.service` or `x0xd@foo.service`).
    pub unit: String,
    /// `true` when the unit lives in the user's manager (`systemctl
    /// --user`), `false` for the system manager. The two managers hold
    /// disjoint unit sets, so the follow-up `systemctl` commands an operator
    /// runs must target the same one.
    pub user_manager: bool,
    /// The confirmed `Restart=` value (one of
    /// `RESTART_POLICIES_GUARANTEEING_CLEAN_EXIT_RESTART`).
    pub restart: String,
    /// present and parseable.
    pub template_version: Option<u32>,
}

/// Outcome of the systemd loaded-policy readback — the systemd-side twin of
/// [`LaunchdPolicyReadback`] (#615), closing ADR-0061 §3's Linux half
/// (#690).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemdPolicyReadback {
    /// No systemd signal classified this instance (or the readback is not
    /// applicable on this platform) — nothing to gate.
    NotApplicable,
    /// The loaded unit policy for THIS exact running instance was read back
    /// and guarantees a respawn after the supervised exit status.
    Verified(Box<SystemdVerifiedUnit>),
    /// Every path that cannot confirm the guarantee. Fail-closed: choosing
    /// `SupervisedExit` on any of these is the silent-service-disappearance
    /// failure §3 exists to prevent.
    NotGuaranteed { detail: String },
}

/// Whether the recognized supervision signal names a systemd unit (either
/// `INVOCATION_ID` or a `systemd` parent) — those are the signals whose
/// `SupervisedExit` plan the systemd readback must gate.
fn systemd_signal_name(signals: &SupervisionSignals) -> Option<&'static str> {
    if signals.invocation_id {
        Some("INVOCATION_ID")
    } else if signals
        .parent_comm
        .as_deref()
        .is_some_and(|c| c.trim() == "systemd")
    {
        Some("parent process `systemd`")
    } else {
        None
    }
}

/// Extract `(unit, user_manager)` from a `/proc/<pid>/cgroup` read.
///
/// The cgroup path is systemd's own name for the unit holding the process
/// (`man systemd.cgroup`): system units live under `/system.slice/…`, user
/// units under `/user.slice/user-<uid>.slice/user@<uid>.service/…` — the
/// `user@` component is what distinguishes the user manager. The unit is
/// the LAST `.service` path component; anything else (a bare slice/scope
/// tail, an empty path) cannot name this daemon's service and fails closed.
#[cfg(any(test, target_os = "linux"))]
fn unit_from_cgroup(cgroup: &str) -> Option<(String, bool)> {
    // Lines are `<hierarchy-id>:<controllers>:<path>` (cgroup v1) or
    // `0::<path>` (unified v2); the last non-empty line is the most
    // specific. Split on ':' taking everything after the second colon.
    let path = cgroup
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|line| {
            let mut parts = line.splitn(3, ':');
            let _hierarchy = parts.next()?;
            let _controllers = parts.next()?;
            parts.next()
        })?
        .trim();
    let user_manager = path.contains("/user@");
    let unit = path.rsplit('/').find(|c| c.ends_with(".service"))?;
    Some((unit.to_string(), user_manager))
}

/// One `key=value` line from `systemctl show` output, if present.
#[cfg(any(test, target_os = "linux"))]
fn show_property<'a>(show: &'a str, key: &str) -> Option<&'a str> {
    show.lines()
        .map(|l| l.trim())
        .find(|l| l.starts_with(key) && l[key.len()..].starts_with('='))
        .map(|l| &l[key.len() + 1..])
}

/// Tokenize one raw systemd command-line (the `argv[]=` rendering of
/// `systemctl show -p ExecStart`) into its argument list, preserving
/// argument boundaries per `man systemd.service` (COMMAND LINES): tokens
/// are whitespace-separated; double quotes keep whitespace inside a token;
/// backslash escapes the next character.
///
/// Conservative by contract: returns `None` for anything it cannot decode
/// with certainty (unterminated quote, trailing backslash, quoting in the
/// middle of a token). Raw `%` (specifier) and `$` (variable) sequences are
/// also refused — the shown ExecStart is the RAW configured line, and
/// comparing it against the running process's EXPANDED argv would require
/// reimplementing specifier/variable expansion; refusing is the fail-closed
/// side of that trade.
#[cfg(any(test, target_os = "linux"))]
fn parse_systemd_argv_tokens(raw: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quoted_token = false;
    let mut chars = raw.trim().chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(escaped) => current.push(escaped),
                None => return None, // trailing backslash
            },
            '"' => {
                if in_quotes || current.is_empty() {
                    in_quotes = !in_quotes;
                    quoted_token = true;
                } else {
                    // `"a"b` — quoting glued onto a token this parser
                    // cannot reproduce faithfully.
                    return None;
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() || quoted_token {
                    tokens.push(std::mem::take(&mut current));
                    quoted_token = false;
                }
            }
            c => current.push(c),
        }
    }
    if in_quotes {
        return None; // unterminated quote
    }
    if !current.is_empty() || quoted_token {
        tokens.push(current);
    }
    if tokens.is_empty() {
        return None;
    }
    for token in &tokens {
        if token.contains('%') || token.contains('$') {
            return None;
        }
    }
    Some(tokens)
}

/// `ExecStart={ path=/x/y ; argv[]=a b ; … }` → `(path, argv_tokens)`.
#[cfg(any(test, target_os = "linux"))]
fn parse_exec_start(value: &str) -> Option<(String, Vec<String>)> {
    let path = value
        .split("path=")
        .nth(1)?
        .split(" ; ")
        .next()?
        .trim()
        .to_string();
    let argv_raw = value.split("argv[]=").nth(1)?.split(" ; ").next()?.trim();
    let tokens = parse_systemd_argv_tokens(argv_raw)?;
    Some((path, tokens))
}

/// The decision core of [`readback_systemd_policy`]: resolve the unit from
/// the cgroup read, query the correct manager's LOADED policy, and verify —
/// for THIS exact running instance — the PID binding (`MainPID`), the
/// invocation binding (`InvocationID`), the executable/argv binding
/// (`ExecStart`, compared by canonical absolute path through
/// `same_executable` and by exact argv boundaries), and a `Restart=`
/// policy that respawns after exit 0.
///
/// `same_executable` decides whether a loaded `ExecStart` path IS this
/// executable — the production implementation canonicalizes both paths
/// (never basename equality: different directories may contain `x0xd`);
/// tests inject fixture logic. Split from the systemctl driver so the
/// refuse-vs-proceed decision table is unit-testable on any platform with
/// captured show output; every path that cannot confirm the guarantee
/// fails closed.
#[cfg(any(test, target_os = "linux"))]
type SystemctlShow<'a> = dyn FnMut(bool, &str) -> Result<Option<String>, String> + 'a;

#[cfg(any(test, target_os = "linux"))]
type SameExecutable<'a> = dyn Fn(&str, &Path) -> bool + 'a;

#[cfg(any(test, target_os = "linux"))]
struct SystemdReadbackInput<'a> {
    cgroup: &'a str,
    pid: u32,
    invocation_id: Option<&'a str>,
    executable: &'a Path,
    argv: &'a [String],
    monotonic_now_us: Option<u64>,
}

#[cfg(any(test, target_os = "linux"))]
fn readback_systemd_policy_in(
    input: SystemdReadbackInput<'_>,
    show: &mut SystemctlShow<'_>,
    same_executable: &SameExecutable<'_>,
) -> SystemdPolicyReadback {
    let SystemdReadbackInput {
        cgroup,
        pid,
        invocation_id,
        executable,
        argv,
        monotonic_now_us,
    } = input;
    let refuse = |detail: String| SystemdPolicyReadback::NotGuaranteed { detail };
    let Some((unit, user_manager)) = unit_from_cgroup(cgroup) else {
        return refuse(format!(
            "the process cgroup ({}) does not name a service unit for this instance",
            cgroup.trim()
        ));
    };
    let show_output = match show(user_manager, &unit) {
        Ok(Some(out)) => out,
        Ok(None) => {
            return refuse(format!(
                "systemctl show reported no loaded unit `{unit}` ({} manager)",
                if user_manager { "user" } else { "system" }
            ))
        }
        Err(e) => return refuse(format!("`systemctl show {unit}` failed: {e}")),
    };

    // PID binding: the unit's MainPID must be THIS process. A child of the
    // real service (or a unit that is not running) fails here — exactly the
    // "not merely INVOCATION_ID presence" requirement.
    let main_pid = show_property(&show_output, "MainPID")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(0);
    if main_pid != pid {
        return refuse(format!(
            "unit `{unit}` reports MainPID {main_pid}, not this process ({pid}); \
             INVOCATION_ID presence alone does not bind the unit to this instance"
        ));
    }

    // Invocation binding: when systemd gave us an invocation id, the loaded
    // unit's must match it.
    if let Some(invocation) = invocation_id {
        match show_property(&show_output, "InvocationID") {
            Some(loaded) if loaded.trim() == invocation => {}
            other => {
                return refuse(format!(
                    "unit `{unit}` reports InvocationID {} but this process runs under {}",
                    other.unwrap_or("<absent>"),
                    invocation
                ))
            }
        }
    }

    // Executable/argv binding: canonical-absolute-path identity for the
    // executable (never basename equality) and exact argv boundaries —
    // unparseable or ambiguous ExecStart quoting fails closed.
    let exec = show_property(&show_output, "ExecStart").and_then(parse_exec_start);
    let exec_ok = exec.is_some_and(|(loaded_path, tokens)| {
        if !same_executable(&loaded_path, executable) {
            return false;
        }
        // argv[0] in the loaded line: either the path itself or an
        // `argv[0]=` override, which must still be this executable.
        let first = tokens.first().map(String::as_str).unwrap_or_default();
        if first != loaded_path && !same_executable(first, executable) {
            return false;
        }
        tokens.len() == argv.len()
            && tokens
                .iter()
                .zip(argv.iter())
                .skip(1)
                .all(|(loaded, ours)| loaded == ours)
    });
    if !exec_ok {
        return refuse(format!(
            "unit `{unit}` does not run this executable/argv (ExecStart {})",
            show_property(&show_output, "ExecStart").unwrap_or("<absent>")
        ));
    }

    // Restart policy: only the clean-exit-covering values may back a
    // SupervisedExit (see RESTART_POLICIES_GUARANTEEING_CLEAN_EXIT_RESTART).
    let restart = show_property(&show_output, "Restart").unwrap_or("").trim();
    if !RESTART_POLICIES_GUARANTEEING_CLEAN_EXIT_RESTART.contains(&restart) {
        return refuse(format!(
            "unit `{unit}` has Restart={restart:?}, which does not guarantee a respawn \
             after exit {}; `always` or `on-success` is required (man systemd.service)",
            supervised_exit_code()
        ));
    }

    /// What one `RestartPreventExitStatus=` entry says about the clean exit
    /// status (exit 0). Entries are numeric statuses, `low-high` ranges, or
    /// signal names (man systemd.service); a signal never covers a clean exit,
    /// and anything this parser cannot decode is [`PreventCoverage::Unparseable`]
    /// so the caller fails closed.
    enum PreventCoverage {
        CoversCleanExit,
        CleanExitNotCovered,
        Unparseable,
    }

    #[cfg(any(test, target_os = "linux"))]
    fn prevent_token_covers_clean_exit(token: &str) -> PreventCoverage {
        let token = token.trim();
        if token.is_empty() {
            return PreventCoverage::Unparseable;
        }
        if let Ok(status) = token.parse::<i64>() {
            return if status == 0 {
                PreventCoverage::CoversCleanExit
            } else {
                PreventCoverage::CleanExitNotCovered
            };
        }
        if let Some((low, high)) = token.split_once('-') {
            if let (Ok(low), Ok(high)) = (low.trim().parse::<i64>(), high.trim().parse::<i64>()) {
                return if low <= 0 && 0 <= high {
                    PreventCoverage::CoversCleanExit
                } else {
                    PreventCoverage::CleanExitNotCovered
                };
            }
        }
        // Signal names (SIGTERM, SIGKILL, …) name terminations, not clean
        // exits; systemd renders them with the SIG prefix.
        if token.to_ascii_uppercase().starts_with("SIG") {
            return PreventCoverage::CleanExitNotCovered;
        }
        PreventCoverage::Unparseable
    }

    // RestartPreventExitStatus (man systemd.service): a matching exit
    // status prevents the restart REGARDLESS of Restart= — a unit with
    // Restart=always and `0` (or a range covering 0) listed here still
    // leaves the daemon down after exit 0. Fail closed when the property
    match show_property(&show_output, "RestartPreventExitStatus") {
        None => {
            return refuse(
                "RestartPreventExitStatus was not reported for the unit; whether exit 0 \
                 is restart-prevented cannot be proven"
                    .to_string(),
            )
        }
        Some(v) if v.trim().is_empty() => {}
        Some(v) => {
            for token in v.split_whitespace() {
                match prevent_token_covers_clean_exit(token) {
                    PreventCoverage::CoversCleanExit => {
                        return refuse(format!(
                            "RestartPreventExitStatus lists `{token}`, which covers the \
                             clean exit status and prevents the restart regardless of \
                             Restart={restart}"
                        ))
                    }
                    PreventCoverage::Unparseable => {
                        return refuse(format!(
                            "RestartPreventExitStatus entry `{token}` cannot be parsed; \
                             coverage of the clean exit status cannot be proven"
                        ))
                    }
                    PreventCoverage::CleanExitNotCovered => {}
                }
            }
        }
    }

    // RemainAfterExit=yes / Type=oneshot: a clean exit leaves the unit
    // `active (exited)` and systemd does not respawn it (man systemd.service,
    // Restart= and Type= semantics) — not a restart guarantee. Both
    // properties are always emitted by `systemctl show`; absence is
    // unprovable and fails closed.
    let remain_after_exit = show_property(&show_output, "RemainAfterExit")
        .unwrap_or("")
        .trim();
    let unit_type = show_property(&show_output, "Type").unwrap_or("").trim();
    if remain_after_exit.is_empty() || unit_type.is_empty() {
        return refuse(
            "RemainAfterExit/Type were not reported for the unit; the clean-exit restart \
             semantics cannot be proven"
                .to_string(),
        );
    }
    if remain_after_exit.eq_ignore_ascii_case("yes") {
        return refuse(
            "RemainAfterExit=yes leaves the unit active(exited) after a clean exit — \
             systemd does not respawn it"
                .to_string(),
        );
    }
    if unit_type.eq_ignore_ascii_case("oneshot") {
        return refuse(
            "Type=oneshot units are not restarted on clean exit — the supervised exit \
             would leave the service down"
                .to_string(),
        );
    }

    // Start-rate limiting (man systemd.service, StartLimitIntervalSec=/
    // StartLimitBurst=): restarts are subject to a rate limit — a unit at
    // the limit does NOT respawn even with Restart=always. Bound the claim
    // to ONE clean-exit restart: either limiting is disabled (interval 0 or
    // burst 0), or the CURRENT activation has outlived the loaded interval,
    // so every earlier start attempt has slid out of the window and this
    // activation's own start has too — the next start is the only one the
    // window could count. Anything ambiguous (property absent, unparseable,
    // no monotonic clock, or a window that may still hold prior attempts)
    // fails closed before mutation. Host limits are never weakened and no
    // competing restart owner is introduced: an exhausted unit is an
    // operator problem, not one the upgrade path papers over.
    let Some(interval_us) =
        show_property(&show_output, "StartLimitIntervalUSec").and_then(parse_systemd_timespan_us)
    else {
        return refuse(
            "StartLimitIntervalUSec is absent or unparseable; the start-rate window \
             cannot be proven"
                .to_string(),
        );
    };
    let Some(burst) =
        show_property(&show_output, "StartLimitBurst").and_then(|v| v.trim().parse::<u64>().ok())
    else {
        return refuse(
            "StartLimitBurst is absent or unparseable; the start-rate limit cannot be \
             proven"
                .to_string(),
        );
    };
    if interval_us != 0 && burst != 0 {
        let Some(active_enter_us) = show_property(&show_output, "ActiveEnterTimestampMonotonic")
            .and_then(|v| v.trim().parse::<u64>().ok())
        else {
            return refuse(
                "ActiveEnterTimestampMonotonic is absent or unparseable; whether the \
                 start-rate window has aged out cannot be proven"
                    .to_string(),
            );
        };
        match monotonic_now_us {
            Some(now_us) if now_us > active_enter_us && now_us - active_enter_us > interval_us => {
                // Stable old service: the window has aged out completely.
            }
            Some(_) => {
                return refuse(
                    "the unit's current activation has not outlived StartLimitIntervalUSec; \
                     a restart now could hit the start-rate limit and leave the service \
                     down (man systemd.service)"
                        .to_string(),
                )
            }
            None => {
                return refuse(
                    "the monotonic clock is unavailable; whether the start-rate window \
                     has aged out cannot be proven"
                        .to_string(),
                )
            }
        }
    }

    // Template identity for drift detection — recorded, never required (a
    // pre-template unit is legacy, not unsupported; the policy+binding
    // checks above are what establish support). Unparseable versions stay
    // `None` rather than guessing.
    let template_version = show_property(&show_output, "Environment").and_then(|env| {
        env.split(&[',', ' '][..])
            .find_map(|tok| {
                tok.strip_prefix(SYSTEMD_TEMPLATE_ENV_KEY)?
                    .strip_prefix('=')
            })
            .and_then(|v| v.trim().parse::<u32>().ok())
    });

    SystemdPolicyReadback::Verified(Box::new(SystemdVerifiedUnit {
        unit,
        user_manager,
        restart: restart.to_string(),
        template_version,
    }))
}

/// Executable identity for the readback: canonical absolute paths on both
/// sides (a directory difference is a DIFFERENT binary, never a match);
/// anything that cannot be canonicalized is unproven and fails closed.
/// (Device/inode comparison would be equally acceptable evidence; canonical
/// paths are what `std` provides portably here.)
#[cfg(target_os = "linux")]
fn same_executable_canonical(loaded: &str, ours: &Path) -> bool {
    matches!(
        (
            std::fs::canonicalize(std::path::Path::new(loaded)),
            std::fs::canonicalize(ours)
        ),
        (Ok(a), Ok(b)) if a == b
    )
}
/// Parse a systemd timespan (`systemctl show` renders `StartLimitIntervalUSec`
/// as e.g. `10s`, `1min 30s`, `500ms`, `0`, or `infinity`) into microseconds.
/// `infinity` is not a finite window this readback can reason about and fails
/// closed (`None`), as does any token that does not parse.
#[cfg(any(test, target_os = "linux"))]
fn parse_systemd_timespan_us(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None; // empty is unparseable, not zero — fail closed
    }
    // "0" (no unit) is how systemctl renders a disabled limit.
    if trimmed == "0" {
        return Some(0);
    }
    let mut total_us: u64 = 0;
    for token in trimmed.split_whitespace() {
        if token.eq_ignore_ascii_case("infinity") {
            return None;
        }
        let end = token
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(token.len());
        let (digits, unit) = token.split_at(end);
        if digits.is_empty() {
            return None; // no numeric part
        }
        let value: u64 = digits.parse().ok()?;
        // Integer microseconds only: sub-second units (usec/ms) below 1 µs
        // cannot be represented and fail closed rather than truncating.
        let multiplier_us = match unit.to_ascii_lowercase().as_str() {
            "s" => 1_000_000u64.checked_mul(1)?,
            "us" | "\u{b5}s" | "usec" => 1,
            "ms" | "msec" => 1_000,
            "m" | "min" => 60_000_000,
            "h" => 3_600_000_000,
            "d" => 86_400_000_000,
            "w" => 604_800_000_000,
            _ => return None,
        };
        total_us = total_us.checked_add(value.checked_mul(multiplier_us)?)?;
    }
    Some(total_us)
}

/// Collect a spawned child's stdout under a hard wall-clock bound and byte
/// cap using `poll(2)` on a genuinely non-blocking descriptor — NOT a
/// blocking `read` behind a stop flag (a flag cannot wake a parked read,
/// and a silent DESCENDANT inheriting the write end keeps the pipe open
/// forever after the direct child exits).
///
/// Mechanics: the piped stdout is duplicated into a raw fd set
/// `O_NONBLOCK`, then `poll(POLLIN, deadline-remaining)` drives every
/// read. Three exits, all bounded: (1) poll/read reports EOF or a child
/// error — pipe drained, done; (2) the wall deadline passes — the child is
/// killed and reaped, the loop makes one final drain pass with a short
/// grace so buffered-but-unread final properties are still collected, then
/// returns; (3) the byte cap is exceeded — fail closed, never accept
/// truncated property data. Every post-spawn error path kills and reaps
/// the child so no `systemctl` is ever left running. I/O read errors are
/// returned as errors, never silently treated as EOF.
///
/// # Safety
/// The `unsafe` blocks call `libc::fcntl`/`libc::poll`/`libc::read`/`libc::close`
/// on a raw fd this function owns for its lifetime (duplicated from the
/// child's piped stdout, closed before returning on every path); the
/// descriptor is not shared with any other thread, so no aliasing is
/// possible (same pattern as the existing `unsafe` blocks in this module:
/// `getppid`, `isatty`, `_exit`).
#[cfg(unix)]
#[cfg(any(test, target_os = "linux"))]
fn collect_child_output_bounded(
    child: std::process::Child,
    bound: Duration,
    cap: usize,
) -> Result<Option<String>, String> {
    collect_child_output_bounded_inner(child, bound, cap, false)
}

#[cfg(unix)]
#[cfg(any(test, target_os = "linux"))]
fn collect_child_output_bounded_inner(
    mut child: std::process::Child,
    bound: Duration,
    cap: usize,
    fail_after_dup_for_test: bool,
) -> Result<Option<String>, String> {
    use std::os::unix::io::AsRawFd;

    // Cleanup guard: every fallible SETUP step below (stdout take, fd
    // duplicate, flag reads) that fails must kill and reap the child before
    // returning — no spawned process is ever leaked past a setup error
    // (Sol292 review). The closure captures nothing; it borrows the child.
    let fail_setup = |child: &mut std::process::Child, what: &str| -> String {
        let _ = child.kill();
        let _ = child.wait();
        what.to_string()
    };

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fail_setup(&mut child, "child stdout was not piped"))?;
    let raw_fd = stdout.as_raw_fd();

    // SAFETY: fcntl(F_DUPFD) on a live fd we own; the duplicate is a fresh
    // descriptor number with no other holders.
    let dup_fd = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD, 0) };
    if dup_fd < 0 {
        return Err(fail_setup(&mut child, "cannot duplicate child stdout fd"));
    }
    if fail_after_dup_for_test {
        // SAFETY: close the private duplicate before exercising the common
        // post-spawn cleanup path.
        unsafe { libc::close(dup_fd) };
        return Err(fail_setup(&mut child, "injected collector setup failure"));
    }
    // SAFETY: fcntl(F_GETFL)/fcntl(F_SETFL) toggling O_NONBLOCK on our
    // private duplicate.
    let flags = unsafe { libc::fcntl(dup_fd, libc::F_GETFL, 0) };
    if flags < 0 {
        // SAFETY: close on the error path.
        unsafe { libc::close(dup_fd) };
        return Err(fail_setup(&mut child, "cannot read child stdout fd flags"));
    }
    if unsafe { libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        // SAFETY: close on the error path.
        unsafe { libc::close(dup_fd) };
        return Err(fail_setup(
            &mut child,
            "cannot set child stdout non-blocking",
        ));
    }

    let deadline = Instant::now() + bound;
    let mut buf: Vec<u8> = Vec::new();
    let mut read_error: Option<String> = None;
    let mut over_cap = false;
    let mut timed_out = false;

    let kill_and_reap = |child: &mut std::process::Child| {
        let _ = child.kill();
        child.wait().ok()
    };

    // Main bounded loop: poll + read until EOF, error, over-cap, or the
    // wall deadline. Each iteration's poll timeout is the deadline
    // remainder, so a silent pipe still returns at the wall bound.
    let final_status;
    'collect: loop {
        let now = Instant::now();
        if now >= deadline {
            timed_out = true;
            let reaped_status = kill_and_reap(&mut child);
            // One bounded grace drain: the kill closed the direct child's
            // descriptors; anything the pipe already buffered is readable
            // as EOF-or-data within this grace. A silent DESCENDANT still
            // holding the write end keeps POLLIN off (no EOF), so the
            // grace deadline — not the descendant — ends the wait.
            let grace = Instant::now() + Duration::from_millis(500);
            while Instant::now() < grace {
                match poll_read_once(dup_fd, &mut buf, cap, grace) {
                    PollRead::Data { cap_exceeded: true } => {
                        over_cap = true;
                        break;
                    }
                    PollRead::Data {
                        cap_exceeded: false,
                    } => continue,
                    PollRead::Eof | PollRead::Timeout => break,
                    PollRead::Error(e) => {
                        read_error = Some(e);
                        break;
                    }
                }
            }
            final_status = reaped_status;
            break;
        }
        match poll_read_once(dup_fd, &mut buf, cap, deadline) {
            PollRead::Data { cap_exceeded } => {
                if cap_exceeded {
                    over_cap = true;
                    final_status = kill_and_reap(&mut child);
                    break;
                }
            }
            PollRead::Eof => {
                // EOF only proves every stdout writer closed. The child may
                // remain alive indefinitely, so wait via try_wait under the
                // same wall deadline rather than calling blocking wait().
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            final_status = Some(status);
                            break 'collect;
                        }
                        Ok(None) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Ok(None) => {
                            timed_out = true;
                            final_status = kill_and_reap(&mut child);
                            break 'collect;
                        }
                        Err(error) => {
                            read_error = Some(format!("checking child status failed: {error}"));
                            final_status = kill_and_reap(&mut child);
                            break 'collect;
                        }
                    }
                }
            }
            PollRead::Error(e) => {
                read_error = Some(e);
                final_status = kill_and_reap(&mut child);
                break;
            }
            PollRead::Timeout => {
                // No data within the remaining wall bound; loop re-checks
                // the deadline and takes the kill path above.
            }
        }
    }
    // SAFETY: close our private duplicate on every exit path.
    unsafe { libc::close(dup_fd) };

    if let Some(e) = read_error {
        return Err(format!("reading child output failed: {e}"));
    }
    if over_cap || buf.len() > cap {
        return Err(format!(
            "child output exceeded the {} byte cap; the property payload is \
             incomplete and cannot be verified",
            cap
        ));
    }
    if timed_out {
        // Grace draining is cleanup only. Expiry means the property stream
        // was never proven complete, even if the direct child exited zero.
        return Ok(None);
    }
    let status = final_status.ok_or("child was not reaped")?;
    if status.success() {
        Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
#[cfg(any(test, target_os = "linux"))]
enum PollRead {
    Data { cap_exceeded: bool },
    Eof,
    Error(String),
    Timeout,
}

/// One `poll(POLLIN, until)` + non-blocking `read` cycle on `fd`.
/// Appends to `buf` up to `cap` (never beyond).
///
/// # Safety
/// Called only with the private duplicate fd owned by
/// [`collect_child_output_bounded`]; no aliasing, no other threads.
#[cfg(unix)]
#[cfg(any(test, target_os = "linux"))]
fn poll_read_once(fd: i32, buf: &mut Vec<u8>, cap: usize, until: Instant) -> PollRead {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let remaining = until.saturating_duration_since(Instant::now());
    let timeout_ms: i32 = remaining.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: poll(2) on a private fd; the pfd is stack-local.
    let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if ready < 0 {
        let errno = std::io::Error::last_os_error();
        if errno.kind() == std::io::ErrorKind::Interrupted {
            return PollRead::Timeout;
        }
        return PollRead::Error(errno.to_string());
    }
    if ready == 0 {
        return PollRead::Timeout;
    }
    if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return PollRead::Error("poll reported POLLERR/POLLNVAL".to_string());
    }
    if pfd.revents & libc::POLLHUP != 0 && pfd.revents & libc::POLLIN == 0 {
        return PollRead::Eof;
    }
    let mut chunk = [0u8; 8192];
    // SAFETY: read(2) into a stack buffer we own; the fd is non-blocking.
    let n = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
    if n < 0 {
        let errno = std::io::Error::last_os_error();
        if errno.kind() == std::io::ErrorKind::WouldBlock
            || errno.kind() == std::io::ErrorKind::Interrupted
        {
            return PollRead::Data {
                cap_exceeded: false,
            }; // spurious wakeup; poll again
        }
        return PollRead::Error(errno.to_string());
    }
    if n == 0 {
        return PollRead::Eof;
    }
    let n = n as usize;
    let room = cap.saturating_sub(buf.len());
    buf.extend_from_slice(&chunk[..n.min(room)]);
    PollRead::Data {
        cap_exceeded: n > room,
    }
}
/// Run `systemctl [--user] show <unit>` with every property the decision
/// core verifies, under a hard wall-clock bound and output cap: on expiry
/// the child is killed and the caller fails closed. Off the async runtime
/// by construction (the driver is called from
/// [`readback_systemd_policy_offloaded`]'s blocking task), so the poll loop
/// cannot stall a runtime worker. Output is capped well above any realistic
/// property payload and error messages never include the `Environment=`
/// line (it may carry deployment secrets — only the parsed template
/// version ever leaves the readback).
#[cfg(target_os = "linux")]
fn run_systemctl_show(user_manager: bool, unit: &str) -> Result<Option<String>, String> {
    let mut cmd = std::process::Command::new("systemctl");
    if user_manager {
        cmd.arg("--user");
    }
    cmd.arg("show")
        .arg(unit)
        .args([
            "--property",
            "MainPID,InvocationID,Restart,RestartPreventExitStatus,RemainAfterExit,Type,StartLimitIntervalUSec,StartLimitBurst,ActiveEnterTimestampMonotonic,ExecStart,Environment",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let child = cmd
        .spawn()
        .map_err(|e| format!("cannot run systemctl: {e}"))?;
    collect_child_output_bounded(child, SYSTEMCTL_SHOW_BOUND, SYSTEMCTL_OUTPUT_CAP)
}

/// Linux `CLOCK_MONOTONIC` microseconds, matching systemd's
/// `ActiveEnterTimestampMonotonic`. `/proc/uptime` includes suspend time on
/// Linux and would make a resumed host appear older than this clock.
/// Errors and conversion overflow fail closed.
#[cfg(target_os = "linux")]
fn monotonic_now_us() -> Option<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a valid writable timespec and CLOCK_MONOTONIC takes
    // no borrowed resources.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return None;
    }
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let nanos = u64::try_from(value.tv_nsec).ok()?;
    if nanos >= 1_000_000_000 {
        return None;
    }
    seconds.checked_mul(1_000_000)?.checked_add(nanos / 1_000)
}

/// Driver half of the systemd readback (Linux): read this process's cgroup
/// and `INVOCATION_ID`, then verify the loaded policy through
/// `readback_systemd_policy_in`. Returns
/// [`SystemdPolicyReadback::NotApplicable`] unless a systemd signal
/// classified this instance, so non-systemd applies shell out to nothing.
#[cfg(target_os = "linux")]
pub fn readback_systemd_policy(
    signals: &SupervisionSignals,
    executable: &Path,
    argv: &[String],
) -> SystemdPolicyReadback {
    if systemd_signal_name(signals).is_none() {
        return SystemdPolicyReadback::NotApplicable;
    }
    let cgroup = match std::fs::read_to_string("/proc/self/cgroup") {
        Ok(c) => c,
        Err(e) => {
            return SystemdPolicyReadback::NotGuaranteed {
                detail: format!("cannot read /proc/self/cgroup: {e}"),
            }
        }
    };
    let invocation = std::env::var("INVOCATION_ID")
        .ok()
        .filter(|v| !v.is_empty());
    readback_systemd_policy_in(
        SystemdReadbackInput {
            cgroup: &cgroup,
            pid: std::process::id(),
            invocation_id: invocation.as_deref(),
            executable,
            argv,
            monotonic_now_us: monotonic_now_us(),
        },
        &mut run_systemctl_show,
        &same_executable_canonical,
    )
}

/// Non-Linux: there is no systemd to read back.
#[cfg(not(target_os = "linux"))]
pub fn readback_systemd_policy(
    _signals: &SupervisionSignals,
    _executable: &Path,
    _argv: &[String],
) -> SystemdPolicyReadback {
    SystemdPolicyReadback::NotApplicable
}

/// [`readback_systemd_policy`] on the blocking pool (the twin of
/// [`readback_launchd_policy_offloaded`]): the bounded `systemctl`
/// subprocesses must not stall the runtime worker mid-upgrade (#671 rule).
pub async fn readback_systemd_policy_offloaded(
    signals: &SupervisionSignals,
    executable: &Path,
    argv: &[String],
) -> SystemdPolicyReadback {
    let signals = signals.clone();
    let executable = executable.to_path_buf();
    let argv = argv.to_vec();
    tokio::task::spawn_blocking(move || readback_systemd_policy(&signals, &executable, &argv))
        .await
        .unwrap_or_else(|e| SystemdPolicyReadback::NotGuaranteed {
            detail: format!("systemd readback task failed: {e}"),
        })
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

    /// A systemd signal fired (INVOCATION_ID / systemd parent), but the
    /// loaded unit policy for this exact instance does not guarantee a
    /// respawn after the supervised exit status (ADR-0061 §3, #690).
    /// Refused before replacement: exiting into an unconfirmed policy is
    /// the silent-service-disappearance failure — the daemon exits 0 for
    /// the upgrade and nothing restarts it.
    #[error(
        "refusing self-update: this instance reports {signal} but the loaded systemd unit \
         policy does not guarantee a restart after exit {exit_code} ({detail}). A supervised \
         exit without a guaranteed respawn leaves the service down with the new bytes on \
         disk. Inspect the unit with `systemctl show <unit> -p Restart -p RestartPreventExitStatus -p MainPID` \
         (add `--user` for user-manager units), set `Restart=always` (or `on-success`) with no \
         exit-0 entry in `RestartPreventExitStatus`, no `RemainAfterExit=yes`, not `Type=oneshot`, \
         and a start-rate window that has aged out, then `daemon-reload` and restart the unit — \
         and retry; if the daemon is already down after a supervised upgrade, follow the \"Manual \
         recovery after a failed supervised upgrade\" procedure in docs/upgrade-system.md. No \
         binaries were replaced."
    )]
    SupervisedSystemdPolicyNotGuaranteed {
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
    /// The launchd job whose loaded policy guaranteed the restart, when the
    /// recognized signal is the `X0X_SUPERVISED=1` marker and the readback
    /// verified it (ADR-0061 §3, #671). Carried into the intent record so
    /// diagnostics name the domain that actually answered.
    pub launchd_verified: Option<LaunchdVerifiedJob>,
    /// The systemd unit whose loaded policy guaranteed the restart
    /// (ADR-0061 §3, #690), with the manager scope, confirmed `Restart=`
    /// value and stamped template version. `None` on every non-systemd
    /// path. Carried into the intent record the same way
    /// `launchd_verified` is (#671).
    pub systemd_verified: Option<SystemdVerifiedUnit>,
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
    systemd_readback: &SystemdPolicyReadback,
) -> Result<RestartPlan, RestartOwnershipError> {
    let mode = plan_restart_mode(stop_on_upgrade, signals)?;

    // ADR-0061 §3 (#615): the launchd marker is an operator assertion, not a
    // respawn guarantee. Before choosing SupervisedExit on the marker alone,
    // the LOADED launchd policy must confirm an unconditional keep-alive on
    // the job running this instance — the marker-in-isolation check ruled out
    // by §3 stranded jobs whose `KeepAlive` was altered after `--repair`.
    // INVOCATION_ID / `systemd`-parent signals are not gated: they name a
    // systemd unit, and the systemd-side readback is out of #615's scope.
    let launchd_verified = match launchd_readback {
        LaunchdPolicyReadback::Verified { label, domain } => Some(LaunchdVerifiedJob {
            label: label.clone(),
            domain: domain.to_string(),
        }),
        _ => None,
    };
    // ADR-0061 §3 (#690): the systemd signals name a unit, and the unit's
    // LOADED policy must guarantee a respawn after the supervised exit —
    // MainPID/InvocationID/ExecStart binding plus Restart=/prevent-status/
    // rate-limit semantics verified by the readback. Refused before any
    // mutation on every NotGuaranteed path.
    let systemd_verified = match systemd_readback {
        SystemdPolicyReadback::Verified(unit) => Some((**unit).clone()),
        _ => None,
    };
    if mode == RestartMode::SupervisedExit {
        if let Some(signal) = systemd_signal_name(signals) {
            if !matches!(systemd_readback, SystemdPolicyReadback::Verified(_)) {
                let detail = match systemd_readback {
                SystemdPolicyReadback::NotGuaranteed { detail } => detail.clone(),
                _ => "the systemd readback did not run for a systemd-signalled                       instance"
                    .to_string(),
            };
                return Err(
                    RestartOwnershipError::SupervisedSystemdPolicyNotGuaranteed {
                        signal: signal.to_string(),
                        exit_code: supervised_exit_code(),
                        detail,
                    },
                );
            }
        }
    }
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
        launchd_verified,
        systemd_verified,
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
    /// The launchd job whose loaded policy guaranteed the supervised
    /// restart, with the session domain (`gui`/`user`) that held it — #671:
    /// the domains are disjoint, so the intent record must name the one that
    /// actually answered or an operator's `launchctl print` follow-up misses.
    /// `None` on every non-launchd-marker path. `#[serde(default)]` keeps
    /// intent files written before the field existed parseable.
    #[serde(default)]
    pub launchd_verified: Option<LaunchdVerifiedJob>,
    /// The systemd unit whose loaded policy guaranteed the supervised
    /// restart (#690) — unit, manager scope, `Restart=`, template version.
    /// `None` on every non-systemd path. `#[serde(default)]` keeps intent
    /// files written before the field existed parseable.
    #[serde(default)]
    pub systemd_verified: Option<SystemdVerifiedUnit>,
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
            launchd_verified: plan.launchd_verified.clone(),
            systemd_verified: plan.systemd_verified.clone(),
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
            &SystemdPolicyReadback::NotApplicable,
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
                domain: "gui",
            },
            &SystemdPolicyReadback::NotApplicable,
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
            &SystemdPolicyReadback::NotApplicable,
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
            &SystemdPolicyReadback::NotApplicable,
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
                domain: "gui",
            },
            &SystemdPolicyReadback::NotApplicable,
        )
        .expect("a verified launchd policy is a supported contract");
        assert_eq!(plan.mode, RestartMode::SupervisedExit);
    }

    #[test]
    fn non_marker_signals_do_not_gate_on_a_launchd_readback() {
        // INVOCATION_ID (systemd) is not a launchd marker: the launchd
        // readback is unavailable on this platform, while the independently
        // verified systemd policy still supports the supervised exit.
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
            &SystemdPolicyReadback::Verified(Box::new(SystemdVerifiedUnit {
                unit: "x0xd.service".to_string(),
                user_manager: false,
                restart: "always".to_string(),
                template_version: Some(1),
            })),
        )
        .expect("verified systemd policy does not require a launchd readback");
        assert_eq!(plan.mode, RestartMode::SupervisedExit);
        assert_eq!(
            plan.systemd_verified,
            Some(SystemdVerifiedUnit {
                unit: "x0xd.service".to_string(),
                user_manager: false,
                restart: "always".to_string(),
                template_version: Some(1),
            })
        );
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
                label: TEST_LABEL.to_string(),
                domain: "gui",
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
                label: TEST_LABEL.to_string(),
                domain: "user",
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

    #[tokio::test(flavor = "current_thread")]
    async fn readback_offload_runs_the_subprocess_work_off_the_runtime_thread() {
        // #671: the plutil/launchctl subprocesses behind the launchd
        // readback are blocking, and the upgrade path awaits them from async
        // code. If they ever run inline on the runtime worker again, a slow
        // `launchctl` stalls the whole runtime mid-upgrade — exactly what
        // spawn_blocking exists to prevent. Thread identity is the directly
        // observable property: on a current_thread runtime the polling thread
        // IS the only runtime worker, so the closure must never see it.
        let runtime_thread = std::thread::current().id();
        let verdict = spawn_readback_offloaded(move || {
            assert_ne!(
                std::thread::current().id(),
                runtime_thread,
                "the launchd readback must not run on the async runtime thread"
            );
            LaunchdPolicyReadback::Verified {
                label: TEST_LABEL.to_string(),
                domain: "gui",
            }
        })
        .await;
        assert_eq!(
            verdict,
            LaunchdPolicyReadback::Verified {
                label: TEST_LABEL.to_string(),
                domain: "gui",
            },
            "the offloaded verdict must be passed through unchanged"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn readback_offload_fails_closed_when_the_readback_task_panics() {
        // A panicking readback must refuse the apply, not crash the upgrade
        // path or — worse — verify by accident: the JoinError arm maps to
        // NotGuaranteed, the same fail-closed verdict as every other
        // unread-policy outcome.
        let verdict =
            spawn_readback_offloaded(|| panic!("launchctl hung in an unexpected way")).await;
        match verdict {
            LaunchdPolicyReadback::NotGuaranteed { detail } => {
                assert!(
                    detail.contains("launchd policy readback task failed"),
                    "detail: {detail}"
                );
            }
            other => panic!("expected NotGuaranteed, got {other:?}"),
        }
    }

    #[test]
    fn supervised_intent_json_records_the_verified_launchd_domain() {
        // #671: `gui/<uid>` and `user/<uid>` are disjoint, so the intent
        // record must name the domain that actually answered. Without it, an
        // operator following the recovery doc probes the gui domain first
        // and reads "Could not find service" for a job verified in `user`.
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = resolve_restart_plan(
            true,
            &launchd_marker_signals(),
            &installed_binary(dir.path()),
            Some(dir.path()),
            None,
            &LaunchdPolicyReadback::Verified {
                label: TEST_LABEL.to_string(),
                domain: "user",
            },
            &SystemdPolicyReadback::NotApplicable,
        )
        .expect("a verified launchd policy is a supported contract");
        assert_eq!(
            plan.launchd_verified,
            Some(LaunchdVerifiedJob {
                label: TEST_LABEL.to_string(),
                domain: "user".to_string(),
            }),
            "the plan must carry which domain matched, not just the label"
        );

        let handoff = UpgradeHandoff::from_plan(&plan, "9.9.9");
        assert_eq!(handoff.launchd_verified, plan.launchd_verified);
        let path = dir.path().join(HANDOFF_FILE_NAME);
        handoff.write(&path).expect("write intent record");
        let raw = std::fs::read_to_string(&path).expect("read intent record");
        assert!(
            raw.contains("\"launchd_verified\"") && raw.contains("\"domain\": \"user\""),
            "the intent JSON must name the matched domain: {raw}"
        );
        let read_back = UpgradeHandoff::read(&path).expect("intent record parses");
        assert_eq!(read_back.launchd_verified, plan.launchd_verified);

        // Intent files written before the field existed must still parse.
        let mut old_shape =
            serde_json::from_str::<serde_json::Value>(&raw).expect("intent record is JSON");
        old_shape
            .as_object_mut()
            .expect("intent record is an object")
            .remove("launchd_verified");
        let legacy: UpgradeHandoff = serde_json::from_value(old_shape)
            .expect("a pre-#671 intent file must remain parseable");
        assert_eq!(legacy.launchd_verified, None);
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
            &SystemdPolicyReadback::NotApplicable,
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
            &SystemdPolicyReadback::NotApplicable,
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
            &SystemdPolicyReadback::NotApplicable,
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
            launchd_verified: None,
            systemd_verified: None,
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
            launchd_verified: None,
            systemd_verified: None,
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
            launchd_verified: None,
            systemd_verified: None,
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
    // ===================================================================
    // #690: systemd loaded-policy readback decision table
    // ===================================================================

    /// A realistic full `systemctl show` output — exact property set and
    /// rendering observed on the real systemd 255 VPS fixture (NYC,
    /// 2026-09-14, omp-reports/recovery-20260914/690-real-systemd-show.txt):
    /// ExecStart carries ` ; `-separated fields with `[n/a]` timestamps;
    /// ActiveEnterTimestampMonotonic is plain integer microseconds.
    fn healthy_show(pid: u32, invocation: &str, exec: &str, restart: &str) -> String {
        format!(
            "Type=simple\n\
             Restart={restart}\n\
             RemainAfterExit=no\n\
             RestartPreventExitStatus=\n\
             MainPID={pid}\n\
             ExecStart={{ path={exec} ; argv[]={exec} --name testnet ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}\n\
             ActiveEnterTimestampMonotonic=1000000\n\
             StartLimitIntervalUSec=10s\n\
             StartLimitBurst=5\n\
             InvocationID={invocation}\n\
             Environment=X0X_TEMPLATE_VERSION=1\n"
        )
    }

    fn real_fixture_argv(exec: &str) -> Vec<String> {
        vec![
            exec.to_string(),
            "--name".to_string(),
            "testnet".to_string(),
        ]
    }

    fn run_readback(
        cgroup: &str,
        pid: u32,
        invocation: Option<&str>,
        argv: &[String],
        show_output: Result<Option<String>, String>,
        monotonic_now: Option<u64>,
    ) -> SystemdPolicyReadback {
        let exec = Path::new("/opt/x0x/x0xd");
        readback_systemd_policy_in(
            SystemdReadbackInput {
                cgroup,
                pid,
                invocation_id: invocation,
                executable: exec,
                argv,
                monotonic_now_us: monotonic_now,
            },
            &mut |_user, _unit| show_output.clone(),
            &|loaded, ours| loaded == "/opt/x0x/x0xd" && ours == Path::new("/opt/x0x/x0xd"),
        )
    }

    const SYSTEM_CGROUP: &str = "0::/system.slice/x0xd.service";

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_executable_identity_uses_canonical_paths() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir()?;
        let executable = dir.path().join("x0xd");
        let alias = dir.path().join("x0xd-alias");
        let other = dir.path().join("other-x0xd");
        std::fs::write(&executable, b"fixture executable")?;
        std::fs::write(&other, b"different fixture executable")?;
        symlink(&executable, &alias)?;

        assert!(same_executable_canonical(
            alias
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF-8 alias"))?,
            &executable,
        ));
        assert!(!same_executable_canonical(
            other
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF-8 other path"))?,
            &executable,
        ));
        assert!(!same_executable_canonical(
            dir.path()
                .join("missing")
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF-8 missing path"))?,
            &executable,
        ));
        Ok(())
    }

    #[test]
    fn systemd_readback_verifies_healthy_unit_both_restart_values() {
        for restart in ["always", "on-success"] {
            let out = healthy_show(
                4242,
                "0851a8fdc1cf4ab38316f9e4e2e1eaa0",
                "/opt/x0x/x0xd",
                restart,
            );
            let verdict = run_readback(
                SYSTEM_CGROUP,
                4242,
                Some("0851a8fdc1cf4ab38316f9e4e2e1eaa0"),
                &real_fixture_argv("/opt/x0x/x0xd"),
                Ok(Some(out)),
                // 100 s monotonic > 10 s interval past activation: stable.
                Some(101_000_000),
            );
            match verdict {
                SystemdPolicyReadback::Verified(unit) => {
                    assert_eq!(unit.unit, "x0xd.service");
                    assert!(!unit.user_manager, "system.slice is the system manager");
                    assert_eq!(unit.restart, restart);
                    assert_eq!(unit.template_version, Some(1));
                }
                other => panic!("expected Verified for Restart={restart}, got {other:?}"),
            }
        }
    }

    #[test]
    fn systemd_readback_resolves_user_manager_from_cgroup() {
        let out = healthy_show(4242, "inv-1", "/opt/x0x/x0xd", "always");
        let verdict = run_readback(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x0xd.service",
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(out)),
            Some(101_000_000),
        );
        match verdict {
            SystemdPolicyReadback::Verified(unit) => {
                assert!(unit.user_manager, "user@ cgroup is the user manager");
                assert_eq!(unit.unit, "x0xd.service");
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn systemd_readback_rejects_wrong_pid_and_invocation() {
        let out = healthy_show(9999, "inv-1", "/opt/x0x/x0xd", "always");
        let verdict = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(out)),
            Some(101_000_000),
        );
        assert!(
            matches!(verdict, SystemdPolicyReadback::NotGuaranteed { ref detail } if detail.contains("MainPID 9999"))
        );

        let out = healthy_show(4242, "inv-OTHER", "/opt/x0x/x0xd", "always");
        let verdict = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(out)),
            Some(101_000_000),
        );
        assert!(
            matches!(verdict, SystemdPolicyReadback::NotGuaranteed { ref detail } if detail.contains("InvocationID"))
        );
    }

    #[test]
    fn systemd_readback_rejects_wrong_executable_by_canonical_identity() {
        // Different directory, same basename: basename equality would
        // accept; canonical identity must not.
        let out = healthy_show(4242, "inv-1", "/other/dir/x0xd", "always");
        let verdict = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/other/dir/x0xd"),
            Ok(Some(out)),
            Some(101_000_000),
        );
        assert!(
            matches!(verdict, SystemdPolicyReadback::NotGuaranteed { ref detail } if detail.contains("does not run this executable"))
        );

        // Argv boundary: a different argument list must not pass.
        let out = healthy_show(4242, "inv-1", "/opt/x0x/x0xd", "always");
        let verdict = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &[
                "/opt/x0x/x0xd".to_string(),
                "--name".to_string(),
                "a b".to_string(),
            ],
            Ok(Some(out)),
            Some(101_000_000),
        );
        assert!(matches!(
            verdict,
            SystemdPolicyReadback::NotGuaranteed { .. }
        ));
    }

    #[test]
    fn systemd_readback_rejects_clean_exit_unsafe_policies() {
        for restart in ["on-failure", "no", "on-abnormal", "on-watchdog", ""] {
            let out = healthy_show(4242, "inv-1", "/opt/x0x/x0xd", restart);
            let verdict = run_readback(
                SYSTEM_CGROUP,
                4242,
                Some("inv-1"),
                &real_fixture_argv("/opt/x0x/x0xd"),
                Ok(Some(out)),
                Some(101_000_000),
            );
            assert!(
                matches!(verdict, SystemdPolicyReadback::NotGuaranteed { ref detail } if detail.contains("Restart=")),
                "Restart={restart:?} must refuse"
            );
        }
    }

    #[test]
    fn systemd_readback_rejects_restart_prevent_exit_status_covering_zero() {
        for prevent in ["0", "0-3", "0 5", "SIGTERM 0", "garbage"] {
            let out = healthy_show(4242, "inv-1", "/opt/x0x/x0xd", "always").replace(
                "RestartPreventExitStatus=\n",
                &format!("RestartPreventExitStatus={prevent}\n"),
            );
            let verdict = run_readback(
                SYSTEM_CGROUP,
                4242,
                Some("inv-1"),
                &real_fixture_argv("/opt/x0x/x0xd"),
                Ok(Some(out)),
                Some(101_000_000),
            );
            assert!(
                matches!(verdict, SystemdPolicyReadback::NotGuaranteed { .. }),
                "RestartPreventExitStatus={prevent:?} must refuse"
            );
        }
        // A non-zero, non-zero-covering, parseable list passes; SIGTERM does
        // not cover a clean exit.
        let out = healthy_show(4242, "inv-1", "/opt/x0x/x0xd", "always").replace(
            "RestartPreventExitStatus=\n",
            "RestartPreventExitStatus=5 SIGTERM\n",
        );
        let verdict = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(out)),
            Some(101_000_000),
        );
        assert!(matches!(verdict, SystemdPolicyReadback::Verified(_)));
    }

    #[test]
    fn systemd_readback_rejects_missing_restart_prevent_property() {
        let out: String = healthy_show(4242, "inv-1", "/opt/x0x/x0xd", "always")
            .lines()
            .filter(|l| !l.starts_with("RestartPreventExitStatus="))
            .collect::<Vec<_>>()
            .join("\n");
        let verdict = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(out)),
            Some(101_000_000),
        );
        assert!(
            matches!(verdict, SystemdPolicyReadback::NotGuaranteed { ref detail } if detail.contains("RestartPreventExitStatus")),
            "absent property must fail closed"
        );
    }

    #[test]
    fn systemd_readback_rejects_remain_after_exit_and_oneshot() {
        for (prop, value) in [("RemainAfterExit", "yes"), ("Type", "oneshot")] {
            let out = healthy_show(4242, "inv-1", "/opt/x0x/x0xd", "always")
                .replace(&format!("{prop}=no\n"), &format!("{prop}={value}\n"))
                .replace(&format!("{prop}=simple\n"), &format!("{prop}={value}\n"));
            let verdict = run_readback(
                SYSTEM_CGROUP,
                4242,
                Some("inv-1"),
                &real_fixture_argv("/opt/x0x/x0xd"),
                Ok(Some(out)),
                Some(101_000_000),
            );
            assert!(
                matches!(verdict, SystemdPolicyReadback::NotGuaranteed { .. }),
                "{prop}={value} must refuse"
            );
        }
    }

    #[test]
    fn systemd_readback_start_rate_limit_table() {
        let mk = |interval: &str, burst: &str, active: &str| {
            healthy_show(4242, "inv-1", "/opt/x0x/x0xd", "always")
                .replace(
                    "StartLimitIntervalUSec=10s\n",
                    &format!("StartLimitIntervalUSec={interval}\n"),
                )
                .replace("StartLimitBurst=5\n", &format!("StartLimitBurst={burst}\n"))
                .replace(
                    "ActiveEnterTimestampMonotonic=1000000\n",
                    &format!("ActiveEnterTimestampMonotonic={active}\n"),
                )
        };
        // Disabled (interval 0): passes without any clock.
        let v = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(mk("0", "5", "1000000"))),
            None,
        );
        assert!(
            matches!(v, SystemdPolicyReadback::Verified(_)),
            "interval 0 disables"
        );
        // Disabled (burst 0): passes without any clock.
        let v = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(mk("10s", "0", "1000000"))),
            None,
        );
        assert!(
            matches!(v, SystemdPolicyReadback::Verified(_)),
            "burst 0 disables"
        );
        // Stable old service: activation 20 s ago > 10 s interval.
        let v = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(mk("10s", "5", "1000000"))),
            Some(21_000_000),
        );
        assert!(
            matches!(v, SystemdPolicyReadback::Verified(_)),
            "aged-out window"
        );
        // Fresh activation (2 s ago < 10 s): refuse — the window may still
        // count prior attempts.
        let v = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(mk("10s", "5", "1000000"))),
            Some(3_000_000),
        );
        assert!(
            matches!(v, SystemdPolicyReadback::NotGuaranteed { detail: ref d } if d.contains("start-rate")),
            "fresh activation refuses"
        );
        // Ambiguous: no monotonic clock with a live limit.
        let v = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(mk("10s", "5", "1000000"))),
            None,
        );
        assert!(
            matches!(v, SystemdPolicyReadback::NotGuaranteed { detail: ref d } if d.contains("monotonic clock")),
            "no clock refuses"
        );
        // Unparseable interval.
        let v = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(mk("infinity", "5", "1000000"))),
            Some(21_000_000),
        );
        assert!(
            matches!(v, SystemdPolicyReadback::NotGuaranteed { detail: ref d } if d.contains("StartLimitIntervalUSec")),
            "infinity refuses"
        );
        // Absent interval property.
        let out: String = healthy_show(4242, "inv-1", "/opt/x0x/x0xd", "always")
            .lines()
            .filter(|l| !l.starts_with("StartLimitIntervalUSec="))
            .collect::<Vec<_>>()
            .join("\n");
        let v = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &real_fixture_argv("/opt/x0x/x0xd"),
            Ok(Some(out)),
            Some(21_000_000),
        );
        assert!(
            matches!(v, SystemdPolicyReadback::NotGuaranteed { detail: ref d } if d.contains("StartLimitIntervalUSec")),
            "absent interval refuses"
        );
    }

    #[test]
    fn systemd_readback_rejects_command_failure_and_absent_unit() {
        let argv = real_fixture_argv("/opt/x0x/x0xd");
        let v = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &argv,
            Err("spawn failed".into()),
            Some(101_000_000),
        );
        assert!(
            matches!(v, SystemdPolicyReadback::NotGuaranteed { detail: ref d } if d.contains("failed"))
        );
        let v = run_readback(
            SYSTEM_CGROUP,
            4242,
            Some("inv-1"),
            &argv,
            Ok(None),
            Some(101_000_000),
        );
        assert!(
            matches!(v, SystemdPolicyReadback::NotGuaranteed { detail: ref d } if d.contains("no loaded unit"))
        );
        let v = run_readback(
            "0::/system.slice/foo.scope",
            4242,
            Some("inv-1"),
            &argv,
            Ok(Some(healthy_show(4242, "inv-1", "/opt/x0x/x0xd", "always"))),
            Some(101_000_000),
        );
        assert!(
            matches!(v, SystemdPolicyReadback::NotGuaranteed { detail: ref d } if d.contains("does not name a service unit"))
        );
    }

    #[test]
    fn resolve_restart_plan_gates_systemd_signals_on_readback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("x0xd");
        std::fs::write(&bin, b"stub").expect("stub binary");
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).expect("data root");
        let mk = |systemd: SystemdPolicyReadback| {
            let signals = SupervisionSignals {
                invocation_id: true,
                ..Default::default()
            };
            resolve_restart_plan(
                true,
                &signals,
                &bin,
                Some(&data),
                Some(SocketAddr::from(([127, 0, 0, 1], 9))),
                &LaunchdPolicyReadback::Unavailable {
                    detail: "test".to_string(),
                },
                &systemd,
            )
        };
        // Verified → SupervisedExit plan carrying the verified unit.
        let plan = mk(SystemdPolicyReadback::Verified(Box::new(
            SystemdVerifiedUnit {
                unit: "x0xd.service".into(),
                user_manager: false,
                restart: "always".into(),
                template_version: Some(1),
            },
        )))
        .expect("verified readback admits SupervisedExit");
        assert_eq!(plan.mode, RestartMode::SupervisedExit);
        let unit = plan.systemd_verified.expect("plan carries the unit");
        assert_eq!(unit.unit, "x0xd.service");
        assert_eq!(unit.restart, "always");
        // NotGuaranteed → refusal naming the systemd policy.
        let err = mk(SystemdPolicyReadback::NotGuaranteed {
            detail: "unit `x0xd.service` has Restart=\"no\"".into(),
        })
        .expect_err("not-guaranteed readback refuses");
        assert!(matches!(
            err,
            RestartOwnershipError::SupervisedSystemdPolicyNotGuaranteed { .. }
        ));
        // NotApplicable while the signal IS systemd → refusal.
        let err = mk(SystemdPolicyReadback::NotApplicable).expect_err("missing readback refuses");
        assert!(matches!(
            err,
            RestartOwnershipError::SupervisedSystemdPolicyNotGuaranteed { .. }
        ));
        // Non-systemd instance: NotApplicable is fine (handoff path).
        let signals = SupervisionSignals::default();
        let plan = resolve_restart_plan(
            true,
            &signals,
            &bin,
            Some(&data),
            None,
            &LaunchdPolicyReadback::Unavailable {
                detail: "test".to_string(),
            },
            &SystemdPolicyReadback::NotApplicable,
        )
        .expect("unsupervised instance unaffected");
        assert_eq!(plan.mode, RestartMode::TransactionalHandoff);
        assert!(plan.systemd_verified.is_none());
    }

    #[test]
    fn handoff_roundtrips_systemd_verified_unit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("x0xd");
        std::fs::write(&bin, b"stub").expect("stub binary");
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).expect("data root");
        let plan = resolve_restart_plan(
            true,
            &SupervisionSignals {
                invocation_id: true,
                ..Default::default()
            },
            &bin,
            Some(&data),
            None,
            &LaunchdPolicyReadback::Unavailable {
                detail: "test".to_string(),
            },
            &SystemdPolicyReadback::Verified(Box::new(SystemdVerifiedUnit {
                unit: "x0xd.service".into(),
                user_manager: true,
                restart: "on-success".into(),
                template_version: None,
            })),
        )
        .expect("plan resolves");
        let handoff = UpgradeHandoff::from_plan(&plan, "9.9.9");
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join(HANDOFF_FILE_NAME);
        handoff.write(&path).expect("write");
        let raw = std::fs::read_to_string(&path).expect("read");
        assert!(raw.contains("\"systemd_verified\"") && raw.contains("\"user_manager\": true"));
        let back = UpgradeHandoff::read(&path).expect("parse");
        assert_eq!(back.systemd_verified, plan.systemd_verified);
    }

    #[test]
    fn systemd_timespan_parser_table() {
        assert_eq!(parse_systemd_timespan_us("0"), Some(0));
        assert_eq!(parse_systemd_timespan_us("10s"), Some(10_000_000));
        assert_eq!(parse_systemd_timespan_us("1min 30s"), Some(90_000_000));
        assert_eq!(parse_systemd_timespan_us("500ms"), Some(500_000));
        assert_eq!(parse_systemd_timespan_us(""), None, "empty is unparseable");
        assert_eq!(parse_systemd_timespan_us("infinity"), None);
        assert_eq!(parse_systemd_timespan_us("garbage"), None);
        assert_eq!(
            parse_systemd_timespan_us("1.5s"),
            None,
            "fractional digits fail closed"
        );
        assert_eq!(
            parse_systemd_timespan_us("18446744073709551615w"),
            None,
            "overflow fails closed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_collector_kills_a_hung_child() {
        use std::process::Command;
        let child = Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let started = Instant::now();
        let result = collect_child_output_bounded(child, Duration::from_secs(1), 1024);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "bound is enforced"
        );
        assert!(
            matches!(result, Ok(None)),
            "killed child is not success: {result:?}"
        );
    }

    #[cfg(unix)]
    fn assert_process_reaped(pid: u32) {
        // SAFETY: signal 0 performs existence/permission checking only.
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        assert_eq!(result, -1, "child {pid} still exists after collector error");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "child {pid} was not reaped"
        );
    }

    #[cfg(unix)]
    struct FixtureProcessGuard(libc::pid_t);

    #[cfg(unix)]
    impl Drop for FixtureProcessGuard {
        fn drop(&mut self) {
            // SAFETY: the fixture records the PID of the process it forked;
            // the guard exists solely to terminate that owned process.
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
            }
        }
    }

    #[cfg(unix)]
    fn wait_for_fixture_pid(
        child: &mut std::process::Child,
        path: &std::path::Path,
    ) -> FixtureProcessGuard {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(pid) = contents.parse::<libc::pid_t>() {
                    if pid > 0 {
                        return FixtureProcessGuard(pid);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("fixture did not report readiness before its setup deadline");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_collector_reaps_child_when_stdout_is_missing() {
        use std::process::Command;
        let mut child = Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        drop(child.stdout.take());
        let result = collect_child_output_bounded(child, Duration::from_secs(1), 1024);
        assert!(matches!(result, Err(ref error) if error.contains("not piped")));
        assert_process_reaped(pid);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_collector_reaps_child_on_setup_failure_after_dup() {
        use std::process::Command;
        let child = Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let result = collect_child_output_bounded_inner(child, Duration::from_secs(1), 1024, true);
        assert!(matches!(result, Err(ref error) if error.contains("injected")));
        assert_process_reaped(pid);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_collector_returns_output_and_fails_closed_on_cap() {
        use std::process::Command;
        let child = Command::new("echo")
            .arg("MainPID=1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn echo");
        let result = collect_child_output_bounded(child, Duration::from_secs(5), 4096);
        assert!(
            matches!(result, Ok(Some(ref s)) if s.contains("MainPID=1")),
            "{result:?}"
        );
        let child = Command::new("head")
            .arg("-c")
            .arg("4096")
            .arg("/dev/zero")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn exact-cap head");
        let result = collect_child_output_bounded(child, Duration::from_secs(5), 4096);
        assert!(
            matches!(result, Ok(Some(ref bytes)) if bytes.len() == 4096),
            "exactly-at-cap output remains complete: {result:?}"
        );
        let child = Command::new("head")
            .arg("-c")
            .arg("8192")
            .arg("/dev/zero")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn head");
        let result = collect_child_output_bounded(child, Duration::from_secs(5), 4096);
        assert!(
            matches!(result, Err(ref e) if e.contains("cap")),
            "over-cap must fail closed: {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_collector_reaps_child_that_closes_stdout_then_sleeps() {
        use std::process::Command;
        let child = Command::new("python3")
            .args(["-c", "import os,time; os.close(1); time.sleep(30)"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn close-stdout child");
        let pid = child.id();
        let started = Instant::now();
        let result = collect_child_output_bounded(child, Duration::from_millis(250), 1024);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(
            matches!(result, Ok(None)),
            "sleeping child is killed: {result:?}"
        );
        assert_process_reaped(pid);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_collector_returns_when_descendant_holds_pipe() {
        use std::process::Command;
        let dir = tempfile::tempdir().expect("fixture dir");
        let pid_path = dir.path().join("descendant.pid");
        // The direct child exits immediately after recording the descendant
        // PID; the forked descendant alone retains the pipe's write end.
        let mut child = Command::new("python3")
            .args([
                "-c",
                "import os,time,pathlib\npid=os.fork()\nif pid==0:\n time.sleep(30)\n os._exit(0)\npathlib.Path(os.environ['DESC_PID_FILE']).write_text(str(pid))\nos._exit(0)",
            ])
            .env("DESC_PID_FILE", &pid_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn sh");
        let descendant = wait_for_fixture_pid(&mut child, &pid_path);
        let started = Instant::now();
        let result = collect_child_output_bounded(child, Duration::from_millis(250), 65536);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "silent descendant must not hang the collector past the bound"
        );
        assert!(
            matches!(result, Ok(None)),
            "expired collection fails closed: {result:?}"
        );
        drop(descendant);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_collector_rejects_overflow_arriving_during_grace() {
        use std::process::Command;
        let dir = tempfile::tempdir().expect("fixture dir");
        let ready_path = dir.path().join("overflow-ready.pid");
        let mut child = Command::new("python3")
            .args([
                "-c",
                "import os,time,pathlib\npid=os.fork()\nif pid==0:\n os.write(1,b'x'*2048)\n pathlib.Path(os.environ['READY_FILE']).write_text(str(os.getpid()))\n os._exit(0)\ntime.sleep(30)",
            ])
            .env("READY_FILE", &ready_path)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn buffered overflow fixture");
        let writer = wait_for_fixture_pid(&mut child, &ready_path);
        let result = collect_child_output_bounded(child, Duration::ZERO, 1024);
        assert!(
            matches!(result, Err(ref error) if error.contains("cap")),
            "{result:?}"
        );
        drop(writer);
    }

    #[cfg(target_os = "macos")]
    const LAUNCHD_FIXTURE_ENV: &str = "X0X_690_LAUNCHD_FIXTURE_DIR";

    #[cfg(target_os = "macos")]
    fn wait_for_fixture_file(path: &Path) -> String {
        // launchd's default service throttle is commonly ten seconds. Keep a
        // platform-fixture-only margin so a real clean-exit respawn is not
        // raced by the assertion deadline.
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(value) = std::fs::read_to_string(path) {
                if !value.trim().is_empty() {
                    return value;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("launchd fixture did not produce {}", path.display());
    }

    #[cfg(target_os = "macos")]
    fn xml_fixture_value(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    #[cfg(target_os = "macos")]
    fn write_fixture_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let temp = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = std::fs::rename(&temp, path) {
            let _ = std::fs::remove_file(temp);
            return Err(error);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    struct BoundedCommandOutput {
        status: std::process::ExitStatus,
        stdout: String,
        stderr: String,
    }

    #[cfg(target_os = "macos")]
    fn launchctl_output_bounded(args: &[&str]) -> Result<BoundedCommandOutput, String> {
        let stdout_file = tempfile::NamedTempFile::new()
            .map_err(|error| format!("create launchctl stdout capture: {error}"))?;
        let stderr_file = tempfile::NamedTempFile::new()
            .map_err(|error| format!("create launchctl stderr capture: {error}"))?;
        let mut child = std::process::Command::new("launchctl")
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(stdout_file.reopen().map_err(
                |error| format!("open launchctl stdout capture: {error}"),
            )?))
            .stderr(std::process::Stdio::from(stderr_file.reopen().map_err(
                |error| format!("open launchctl stderr capture: {error}"),
            )?))
            .spawn()
            .map_err(|error| format!("spawn launchctl: {error}"))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("launchctl {} timed out", args.join(" ")));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("poll launchctl {}: {error}", args.join(" ")));
                }
            }
        };
        let stdout = std::fs::read_to_string(stdout_file.path())
            .map_err(|error| format!("read launchctl stdout capture: {error}"))?;
        let stderr = std::fs::read_to_string(stderr_file.path())
            .map_err(|error| format!("read launchctl stderr capture: {error}"))?;
        Ok(BoundedCommandOutput {
            status,
            stdout,
            stderr,
        })
    }

    #[cfg(target_os = "macos")]
    struct LaunchdFixtureGuard {
        target: String,
        dir: PathBuf,
        active: bool,
    }

    #[cfg(target_os = "macos")]
    impl LaunchdFixtureGuard {
        fn run_recorded(&self, label: &str, args: &[&str]) -> Result<BoundedCommandOutput, String> {
            let result = launchctl_output_bounded(args);
            let record = match &result {
                Ok(output) => serde_json::json!({
                    "args": args,
                    "status": output.status.code(),
                    "success": output.status.success(),
                    "stdout": output.stdout,
                    "stderr": output.stderr,
                }),
                Err(error) => serde_json::json!({"args": args, "error": error}),
            };
            write_fixture_atomic(
                &self.dir.join(format!("launchctl-{label}.json")),
                &serde_json::to_vec_pretty(&record)
                    .map_err(|error| format!("serialize launchctl evidence: {error}"))?,
            )
            .map_err(|error| format!("preserve launchctl {label} evidence: {error}"))?;
            result
        }

        fn cleanup(&mut self) -> Result<(), String> {
            let _ = write_fixture_atomic(&self.dir.join("stop"), b"stop");
            let bootout = self.run_recorded("bootout", &["bootout", &self.target])?;
            let print = self.run_recorded("cleanup-print", &["print", &self.target])?;
            if print.status.success() {
                return Err(format!(
                    "fixture remained loaded after bootout (bootout status {}; print stdout {:?}; stderr {:?})",
                    bootout.status, print.stdout, print.stderr
                ));
            }
            if !print.stdout.contains("Could not find service")
                && !print.stderr.contains("Could not find service")
            {
                return Err(format!(
                    "launchctl did not prove fixture absence (status {}; stdout {:?}; stderr {:?})",
                    print.status, print.stdout, print.stderr
                ));
            }
            write_fixture_atomic(&self.dir.join("cleanup-proved"), b"missing-target")
                .map_err(|error| format!("preserve cleanup proof: {error}"))?;
            self.active = false;
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for LaunchdFixtureGuard {
        fn drop(&mut self) {
            if self.active {
                let _ = self.cleanup();
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn bootstrap_launchd_fixture(keepalive: bool) -> (PathBuf, LaunchdFixtureGuard, String) {
        use std::fmt::Write as _;
        use std::os::unix::fs::DirBuilderExt as _;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock after epoch")
            .as_nanos();
        let unique = format!(
            "com.saorsalabs.x0x.test.{}.{}.{}",
            std::process::id(),
            nonce,
            if keepalive { "positive" } else { "negative" }
        );
        let dir = std::env::temp_dir().join(format!("x0x-690-launchd-{unique}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("create retained launchd artifact directory");
        eprintln!("X0X690 launchd artifacts={}", dir.display());
        let executable = std::env::current_exe().expect("current test executable");
        // libtest's exact selector omits the library crate prefix (`x0x::`).
        let fixture_test = "upgrade::restart::tests::platform_launchd_fixture_role".to_string();
        let arguments = [
            executable.to_string_lossy().into_owned(),
            fixture_test,
            "--exact".to_string(),
            "--ignored".to_string(),
            "--nocapture".to_string(),
        ];
        let mut argument_xml = String::new();
        for argument in &arguments {
            writeln!(
                argument_xml,
                "        <string>{}</string>",
                xml_fixture_value(argument)
            )
            .expect("render argument");
        }
        let keepalive_xml = if keepalive {
            "    <key>KeepAlive</key>\n    <true/>\n"
        } else {
            ""
        };
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n\
             <key>Label</key><string>{}</string>\n\
             <key>ProgramArguments</key><array>\n{}    </array>\n\
             <key>EnvironmentVariables</key><dict>\n\
             <key>{}</key><string>{}</string>\n\
             </dict>\n{}\
             <key>RunAtLoad</key><true/>\n\
             <key>StandardOutPath</key><string>{}</string>\n\
             <key>StandardErrorPath</key><string>{}</string>\n\
             </dict></plist>\n",
            xml_fixture_value(&unique),
            argument_xml,
            LAUNCHD_FIXTURE_ENV,
            xml_fixture_value(&dir.to_string_lossy()),
            keepalive_xml,
            xml_fixture_value(&dir.join("stdout.log").to_string_lossy()),
            xml_fixture_value(&dir.join("stderr.log").to_string_lossy()),
        );
        let plist_path = dir.join(format!("{unique}.plist"));
        write_fixture_atomic(&plist_path, plist.as_bytes()).expect("write isolated fixture plist");
        let uid = unsafe { libc::getuid() };
        let domain = format!("gui/{uid}");
        let target = format!("{domain}/{unique}");
        let plist_arg = plist_path.to_string_lossy();
        // Install cleanup ownership before bootstrap: launchctl can register
        // the job and still return late/nonzero, and that partial state must
        // never escape a failing fixture setup.
        let guard = LaunchdFixtureGuard {
            target,
            dir: dir.clone(),
            active: true,
        };
        let bootstrap = guard
            .run_recorded("bootstrap", &["bootstrap", &domain, &plist_arg])
            .expect("run bounded launchctl bootstrap");
        assert!(
            bootstrap.status.success(),
            "the current user GUI launchd domain is unavailable; this platform gate is unsupported: {}",
            bootstrap.stderr
        );
        (dir, guard, unique)
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "loads a uniquely labelled temporary launchd fixture"]
    fn platform_launchd_fixture_role() {
        let Some(dir) = std::env::var_os(LAUNCHD_FIXTURE_ENV).map(PathBuf::from) else {
            return;
        };
        let slot = [1_u8, 2]
            .into_iter()
            .find(|slot| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(dir.join(format!("invocation-{slot}.claim")))
                    .is_ok()
            })
            .expect("at most two fixture invocations");
        write_fixture_atomic(
            &dir.join(format!("invocation-{slot}.pid")),
            std::process::id().to_string().as_bytes(),
        )
        .expect("publish invocation pid");
        if slot == 1 {
            let executable = std::env::current_exe().expect("fixture executable");
            let argv = current_argv();
            let uid = unsafe { libc::getuid() };
            let verdict = readback_launchd_policy_in(
                &dir,
                uid,
                &executable,
                &argv,
                &plist_as_json,
                &mut run_launchctl_print,
            );
            let verdict = match verdict {
                LaunchdPolicyReadback::Verified { label, domain } => serde_json::json!({
                    "status": "verified",
                    "label": label,
                    "domain": domain,
                }),
                LaunchdPolicyReadback::NotGuaranteed { detail } => serde_json::json!({
                    "status": "not_guaranteed",
                    "detail": detail,
                }),
                LaunchdPolicyReadback::Unavailable { detail } => serde_json::json!({
                    "status": "unavailable",
                    "detail": detail,
                }),
            };
            write_fixture_atomic(
                &dir.join("verdict.json"),
                &serde_json::to_vec(&verdict).expect("serialize loaded-policy verdict"),
            )
            .expect("write loaded-policy verdict");
            let _ = wait_for_fixture_file(&dir.join("release-first"));
            write_fixture_atomic(&dir.join("clean-exit-intent"), b"0")
                .expect("record controlled clean exit");
        } else {
            let _ = wait_for_fixture_file(&dir.join("stop"));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "loads isolated launchd jobs and proves real loaded policy/respawn"]
    fn platform_launchd_loaded_policy_and_clean_exit_restart() {
        let (positive_dir, mut positive_guard, positive_label) = bootstrap_launchd_fixture(true);
        let first_pid = wait_for_fixture_file(&positive_dir.join("invocation-1.pid"));
        let verdict: serde_json::Value =
            serde_json::from_str(&wait_for_fixture_file(&positive_dir.join("verdict.json")))
                .expect("typed positive verdict");
        assert_eq!(verdict["status"], "verified");
        assert_eq!(verdict["label"], positive_label);
        assert_eq!(verdict["domain"], "gui");
        write_fixture_atomic(&positive_dir.join("release-first"), b"release")
            .expect("release first clean exit");
        let second_pid = wait_for_fixture_file(&positive_dir.join("invocation-2.pid"));
        assert_eq!(
            wait_for_fixture_file(&positive_dir.join("clean-exit-intent")).trim(),
            "0"
        );
        assert_ne!(
            first_pid.trim(),
            second_pid.trim(),
            "exit zero must produce a new launchd-owned process"
        );
        let loaded = positive_guard
            .run_recorded("loaded-positive", &["print", &positive_guard.target])
            .expect("capture loaded positive job");
        assert!(
            loaded.status.success() && loaded.stdout.contains("last exit code = 0"),
            "launchd did not report the controlled clean exit (stdout {:?}; stderr {:?})",
            loaded.stdout,
            loaded.stderr
        );
        write_fixture_atomic(
            &positive_dir.join("launchctl-print.txt"),
            loaded.stdout.as_bytes(),
        )
        .expect("preserve loaded launchd evidence");
        positive_guard.cleanup().expect("clean positive fixture");

        let (negative_dir, mut negative_guard, _) = bootstrap_launchd_fixture(false);
        let _ = wait_for_fixture_file(&negative_dir.join("invocation-1.pid"));
        let verdict: serde_json::Value =
            serde_json::from_str(&wait_for_fixture_file(&negative_dir.join("verdict.json")))
                .expect("typed negative verdict");
        assert_eq!(verdict["status"], "not_guaranteed");
        assert!(
            verdict["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("KeepAlive")),
            "loaded job without KeepAlive must fail closed: {verdict}"
        );
        negative_guard.cleanup().expect("clean negative fixture");
    }
}
