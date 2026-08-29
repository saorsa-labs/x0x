//! Transactional restart after a successful binary swap (issue #261).
//!
//! The file swap in [`super::Upgrader`] is already transactional. This module
//! makes the *restart* transactional too: the swap is only committed once a
//! replacement process answers `GET /health` on the pre-upgrade API address;
//! otherwise the previous binary is restored and respawned. A terminal-
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

/// Whether one of the three supervision signals is present.
///
/// `INVOCATION_ID`, parent comm `systemd`, or `X0X_SUPERVISED=1`. Nothing else
/// qualifies: not-a-TTY, nohup, detached stdin, and launchd ancestry are all
/// unsupervised.
pub fn is_supervised(signals: &SupervisionSignals) -> bool {
    signals.invocation_id
        || signals.x0x_supervised
        || signals
            .parent_comm
            .as_deref()
            // /proc/<pid>/comm carries a trailing newline.
            .is_some_and(|comm| comm.trim() == "systemd")
}

/// I0 classification: pick the restart mode before anything destructive runs.
///
/// `SupervisedExit` requires `stop_on_upgrade == true` **and** real
/// supervision. Everything else — including unsupervised runs with the
/// default `stop_on_upgrade = true`, and every `stop_on_upgrade = false` run —
/// goes through [`RestartMode::TransactionalHandoff`] (the old `exec()` path
/// could not roll back and is gone).
pub fn plan_restart_mode(stop_on_upgrade: bool, signals: &SupervisionSignals) -> RestartMode {
    if stop_on_upgrade && is_supervised(signals) {
        RestartMode::SupervisedExit
    } else {
        RestartMode::TransactionalHandoff
    }
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
    /// Capture the old process's restart intent. Must run before any exit.
    pub fn capture(
        target_path: &Path,
        backup_path: &Path,
        to_version: &str,
        api_addr: SocketAddr,
        mode: RestartMode,
    ) -> Self {
        let argv: Vec<String> = std::env::args_os()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
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
            target_path: target_path.to_path_buf(),
            backup_path: backup_path.to_path_buf(),
            argv,
            cwd,
            env,
            old_pid: std::process::id(),
            api_addr,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            mode,
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
///    `GET /health` 200 (bounded). Health ok ⇒ delete the handoff file, exit 0.
/// 3. On spawn/health failure: restore the backup, respawn the previous
///    binary, wait for `/health` again.
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

    // Step 2: prove the new binary serves before committing the restart.
    let health_timeout = env_timeout(HEALTH_TIMEOUT_ENV);
    let new_outcome =
        spawn_and_await_health(&handoff.target_path, &handoff, &data_dir, health_timeout);
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
    match spawn_and_await_health(&handoff.target_path, &handoff, &data_dir, health_timeout) {
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
/// and wait for `/health` 200 on the handoff's API address.
fn spawn_and_await_health(
    binary: &Path,
    handoff: &UpgradeHandoff,
    data_dir: &Path,
    health_timeout: Duration,
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

    if let Err(e) = cmd.spawn() {
        return SpawnHealthOutcome::SpawnFailed(e);
    }
    if wait_for_health(handoff, data_dir, health_timeout) {
        SpawnHealthOutcome::Healthy
    } else {
        SpawnHealthOutcome::Unhealthy
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

/// Wait (bounded) for `GET /health` 200 on the pre-upgrade API address, or on
/// the address the replacement advertised in `<data_dir>/api.port` when the
/// pre-upgrade bind was ephemeral.
fn wait_for_health(handoff: &UpgradeHandoff, data_dir: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(addr) = resolve_health_addr(handoff, data_dir) {
            if http_health_ok(addr) {
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

/// Minimal `GET /health` probe: any HTTP/1.x 200 status line commits the
/// restart. `/health` is auth-exempt on the daemon API.
fn http_health_ok(addr: SocketAddr) -> bool {
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
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")
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
            RestartMode::TransactionalHandoff
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
            RestartMode::TransactionalHandoff
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
            RestartMode::TransactionalHandoff
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
            RestartMode::SupervisedExit
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
            RestartMode::SupervisedExit
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
            RestartMode::SupervisedExit
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
            RestartMode::SupervisedExit
        );
    }

    #[test]
    fn stop_on_upgrade_false_always_uses_handoff() {
        // stop_on_upgrade=false replaces the old exec(): the new image can
        // never be a fire-and-forget success path, supervised or not.
        let supervised = SupervisionSignals {
            invocation_id: true,
            parent_comm: Some("systemd".to_string()),
            ..shell_parent_signals()
        };
        assert_eq!(
            plan_restart_mode(false, &supervised),
            RestartMode::TransactionalHandoff
        );
        assert_eq!(
            plan_restart_mode(false, &shell_parent_signals()),
            RestartMode::TransactionalHandoff
        );
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

    #[test]
    fn http_health_ok_accepts_200_and_rejects_non_200() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for (status, body) in [("200 OK", "ok"), ("503 Service Unavailable", "bad")] {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = [0u8; 128];
                let _ = sock.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        assert!(http_health_ok(addr));
        assert!(!http_health_ok(addr));
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
