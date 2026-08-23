//! API-unserved watchdog (issue #384).
//!
//! The #384 wedge shape: the process stays "active" under systemd, the API
//! listener accepts TCP connections, but `/health` is never answered — a
//! tokio worker parked in a blocking `futex_wait` starves the tasks that
//! serve the API and feed the PubSub dispatcher. Monitors that treat a
//! timeout as "slow" keep such a daemon in rotation indefinitely.
//!
//! This watchdog runs on a **dedicated std thread** (not a tokio task) so it
//! survives a fully wedged async runtime: every `probe_interval_secs` it
//! opens a loopback TCP connection to the daemon's own API listener and
//! issues a bare `GET /health HTTP/1.0` (the one auth-exempt route). After
//! `miss_threshold` consecutive unserved probes past the startup grace it
//! logs the runtime state it can reach without the async runtime
//! (PubSub dispatcher counters, platform thread list) and — when
//! `abort_on_stall` resolves true — calls [`std::process::abort`] so a
//! supervisor restarts the daemon and a core/backtrace exists.
//!
//! It must never fire during startup grace or shutdown: failures inside the
//! grace window do not count, and the thread disarms itself as soon as the
//! shutdown watch flips.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::upgrade::restart::{is_supervised, SupervisionSignals};
use crate::Agent;

/// Configuration for the API-unserved watchdog (TOML: `[api_watchdog]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiWatchdogConfig {
    /// Master switch. Default `true`: the probe is a loopback GET every
    /// `probe_interval_secs` on its own thread — cheap enough to always run,
    /// and without it the #384 wedge shape is undetectable from inside.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Seconds between `/health` self-probes. Default 10 (issue #384's
    /// "every N s" with a ~30 s detection budget at the default threshold).
    #[serde(default = "default_probe_interval_secs")]
    pub probe_interval_secs: u64,

    /// Per-probe connect+read timeout in seconds. Default 3 — well under the
    /// interval so a wedged listener counts at most one miss per tick.
    #[serde(default = "default_probe_timeout_secs")]
    pub probe_timeout_secs: u64,

    /// Consecutive missed probes (past the startup grace) required to trip.
    /// Default 3 → ~30 s from wedge to trip at the default interval.
    #[serde(default = "default_miss_threshold")]
    pub miss_threshold: u32,

    /// Seconds after startup before a miss can count. Default 90: covers
    /// binary start, identity load, gossip join, and first connections.
    #[serde(default = "default_startup_grace_secs")]
    pub startup_grace_secs: u64,

    /// Whether a trip aborts the process for a supervisor restart.
    ///
    /// `None` (the default) resolves at arm time from the same supervision
    /// detection the upgrade path uses ([`is_supervised`]): supervised runs
    /// (systemd `INVOCATION_ID`, parent comm `systemd`, `X0X_SUPERVISED=1`)
    /// abort by default so `Restart=always` heals the wedge; unsupervised
    /// (terminal-launched) runs stay up and only log. Set `true`/`false`
    /// explicitly to override.
    #[serde(default)]
    pub abort_on_stall: Option<bool>,
}

impl Default for ApiWatchdogConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            probe_interval_secs: default_probe_interval_secs(),
            probe_timeout_secs: default_probe_timeout_secs(),
            miss_threshold: default_miss_threshold(),
            startup_grace_secs: default_startup_grace_secs(),
            abort_on_stall: None,
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_probe_interval_secs() -> u64 {
    10
}

fn default_probe_timeout_secs() -> u64 {
    3
}

fn default_miss_threshold() -> u32 {
    3
}

fn default_startup_grace_secs() -> u64 {
    90
}

/// One watchdog observation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchdogAction {
    /// Nothing to do (probe ok, still under grace, or below threshold).
    None,
    /// Threshold reached: caller must dump state and (if resolved) abort.
    Trip { misses: u32 },
}

/// Pure trip-state machine for consecutive-miss counting.
///
/// Kept free of I/O so the counting rules (grace, reset-on-success,
/// one-shot trip) are unit-testable in isolation.
#[derive(Debug)]
pub(crate) struct ApiWatchdogMachine {
    threshold: u32,
    misses: u32,
    grace_end: Instant,
    tripped: bool,
    disarmed: bool,
}

impl ApiWatchdogMachine {
    pub(crate) fn new(threshold: u32, grace: Duration, started_at: Instant) -> Self {
        Self {
            // A threshold below 1 would trip on the first miss past grace —
            // clamp so a misconfig cannot turn the watchdog into a
            // startup race.
            threshold: threshold.max(1),
            misses: 0,
            grace_end: started_at + grace,
            tripped: false,
            disarmed: false,
        }
    }

    /// Record one probe outcome at time `now`.
    pub(crate) fn observe(&mut self, probe_ok: bool, now: Instant) -> WatchdogAction {
        if self.disarmed || self.tripped {
            return WatchdogAction::None;
        }
        if probe_ok {
            self.misses = 0;
            return WatchdogAction::None;
        }
        // Failures during the startup grace never count: the daemon may not
        // have bound its final listener yet (self-update handoff, restart).
        if now < self.grace_end {
            return WatchdogAction::None;
        }
        self.misses += 1;
        if self.misses >= self.threshold {
            self.tripped = true;
            WatchdogAction::Trip {
                misses: self.misses,
            }
        } else {
            WatchdogAction::None
        }
    }

    /// Current consecutive-miss count (post-grace; reset on success).
    pub(crate) fn miss_count(&self) -> u32 {
        self.misses
    }

    /// Disarm permanently (shutdown in progress). Late probes are ignored.
    pub(crate) fn disarm(&mut self) {
        self.disarmed = true;
    }
}

/// Distinguish probe failures in the trip log: the #384 signature is
/// `Timeout` (TCP accepted, HTTP never answered), not `Refused`.
#[derive(Debug)]
enum ProbeOutcome {
    /// Response bytes received; latency measured.
    Served(Duration),
    /// TCP connect refused/reset — the listener is gone, not wedged.
    Refused,
    /// Connect or read timed out — the listener accepted but never answered.
    Timeout,
    /// Any other I/O error.
    Io(String),
}

impl ProbeOutcome {
    /// Human-readable one-liner for logs; keeps the `Served` latency and
    /// `Io` error text (otherwise unread) in the operator's face.
    fn describe(&self) -> String {
        match self {
            ProbeOutcome::Served(latency) => format!("served in {latency:?}"),
            ProbeOutcome::Refused => "connect refused (listener gone)".to_string(),
            ProbeOutcome::Timeout => {
                "timeout: TCP accepted but HTTP never answered (issue #384 signature)".to_string()
            }
            ProbeOutcome::Io(err) => format!("io error: {err}"),
        }
    }
}

/// Bare `GET /health HTTP/1.0` over loopback. No auth needed: `/health` is
/// auth-exempt (`src/server/auth.rs`). Returns once any response bytes
/// arrive (a served `/health` is always `200`; the watchdog only cares that
/// the HTTP task was polled at all).
fn probe_health(api_addr: SocketAddr, timeout: Duration) -> ProbeOutcome {
    // Bind-address sanity: probe the loopback side of an unspecified bind.
    let addr = if api_addr.ip().is_unspecified() {
        SocketAddr::from((Ipv4Addr::LOCALHOST, api_addr.port()))
    } else {
        api_addr
    };
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            return ProbeOutcome::Refused;
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return ProbeOutcome::Timeout,
        Err(e) => return ProbeOutcome::Io(e.to_string()),
    };
    let started = Instant::now();
    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        return ProbeOutcome::Io(e.to_string());
    }
    if let Err(e) = stream.set_write_timeout(Some(timeout)) {
        return ProbeOutcome::Io(e.to_string());
    }
    let request = b"GET /health HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if let Err(e) = stream.write_all(request) {
        return match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ProbeOutcome::Timeout,
            _ => ProbeOutcome::Io(e.to_string()),
        };
    }
    let mut buf = [0u8; 128];
    match stream.read(&mut buf) {
        Ok(0) => ProbeOutcome::Io("connection closed before any response bytes".to_string()),
        Ok(_) => ProbeOutcome::Served(started.elapsed()),
        Err(e) => match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ProbeOutcome::Timeout,
            _ => ProbeOutcome::Io(e.to_string()),
        },
    }
}

/// Launch the watchdog thread. Called once from `serve_with_options` after
/// the API listener is bound; owns its probe loop for the process lifetime
/// (or until shutdown).
pub(crate) fn spawn_api_watchdog(
    config: &ApiWatchdogConfig,
    api_addr: SocketAddr,
    agent: Arc<Agent>,
    shutdown: watch::Receiver<bool>,
) -> std::thread::JoinHandle<()> {
    let interval = Duration::from_secs(config.probe_interval_secs.max(1));
    let timeout = Duration::from_secs(config.probe_timeout_secs.max(1));
    let threshold = config.miss_threshold;
    let grace = Duration::from_secs(config.startup_grace_secs);
    let abort_on_stall = config
        .abort_on_stall
        .unwrap_or_else(|| is_supervised(&SupervisionSignals::sample()));

    std::thread::Builder::new()
        .name("x0x-api-watchdog".to_string())
        .spawn(move || {
            let started_at = Instant::now();
            let mut machine = ApiWatchdogMachine::new(threshold, grace, started_at);
            tracing::info!(
                target: "x0x::api_watchdog",
                api_address = %api_addr,
                interval_secs = interval.as_secs(),
                miss_threshold = threshold,
                grace_secs = grace.as_secs(),
                abort_on_stall,
                "API-unserved watchdog armed (issue #384)"
            );
            loop {
                std::thread::sleep(interval);
                // Shutdown disarm: the listener is intentionally going away;
                // a probe failure here is the shutdown, not a wedge.
                if *shutdown.borrow() {
                    machine.disarm();
                    tracing::debug!(
                        target: "x0x::api_watchdog",
                        "shutdown observed — watchdog disarmed"
                    );
                    return;
                }
                let outcome = probe_health(api_addr, timeout);
                let ok = matches!(outcome, ProbeOutcome::Served(_));
                if !ok {
                    tracing::warn!(
                        target: "x0x::api_watchdog",
                        consecutive_misses = machine.miss_count(),
                        probe = %outcome.describe(),
                        "/health self-probe missed"
                    );
                }
                if let WatchdogAction::Trip { misses } = machine.observe(ok, Instant::now()) {
                    // Re-check shutdown between the probe and the abort: a
                    // graceful shutdown racing the trip must not abort.
                    if *shutdown.borrow() {
                        return;
                    }
                    trip(
                        &agent,
                        api_addr,
                        misses,
                        interval,
                        timeout,
                        &outcome,
                        abort_on_stall,
                    );
                    return;
                }
            }
        })
        .unwrap_or_else(|e| {
            // A failed thread spawn must never take the daemon down; the
            // watchdog is best-effort by construction.
            tracing::warn!(
                target: "x0x::api_watchdog",
                error = %e,
                "failed to spawn API-unserved watchdog thread — running without it"
            );
            // A dummy handle: the thread never existed.
            std::thread::spawn(|| ())
        })
}

/// The trip path: log everything reachable without the async runtime, then
/// abort if resolved to do so.
///
/// Everything here is synchronous **by design**: the wedged state is
/// "tokio tasks not being polled", so any `.await` (or `block_on`) would
/// hang the diagnostics with the same wedge it is trying to report.
fn trip(
    agent: &Agent,
    api_addr: SocketAddr,
    misses: u32,
    interval: Duration,
    timeout: Duration,
    outcome: &ProbeOutcome,
    abort_on_stall: bool,
) {
    tracing::error!(
        target: "x0x::api_watchdog",
        consecutive_misses = misses,
        probe_interval_secs = interval.as_secs(),
        probe_timeout_secs = timeout.as_secs(),
        probe_outcome = %outcome.describe(),
        api_address = %api_addr,
        agent_id = %agent.agent_id(),
        machine_id = %agent.machine_id(),
        pubsub_stats = ?agent.gossip_stats(),
        thread_dump = thread_dump_summary(),
        "API-unserved watchdog tripped (issue #384): /health unserved past the \
         grace window — async runtime presumed wedged (TCP accepted, HTTP \
         never answered)"
    );
    if abort_on_stall {
        tracing::error!(
            target: "x0x::api_watchdog",
            "abort_on_stall=true (supervised run or explicit override): calling \
             std::process::abort() for supervisor restart + core dump"
        );
        std::process::abort();
    }
}

/// Best-effort platform thread list. Linux: `/proc/self/task/*/comm`.
/// Other platforms have no stable userspace enumeration — say so instead of
/// pretending.
fn thread_dump_summary() -> String {
    #[cfg(target_os = "linux")]
    {
        let mut names: Vec<String> = std::fs::read_dir("/proc/self/task")
            .map(|entries| {
                entries
                    .filter_map(|e| {
                        let comm = std::fs::read_to_string(e.ok()?.path().join("comm")).ok()?;
                        Some(comm.trim().to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        if names.is_empty() {
            return "unavailable (/proc/self/task unreadable)".to_string();
        }
        names.sort();
        format!("{} threads: {}", names.len(), names.join(", "))
    }
    #[cfg(not(target_os = "linux"))]
    {
        "unavailable on this platform (Linux /proc only)".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(threshold: u32, grace: Duration) -> ApiWatchdogMachine {
        ApiWatchdogMachine::new(threshold, grace, Instant::now())
    }

    #[test]
    fn success_resets_miss_count() {
        let mut m = machine(3, Duration::ZERO);
        let t = Instant::now();
        assert_eq!(m.observe(false, t), WatchdogAction::None);
        assert_eq!(m.observe(false, t), WatchdogAction::None);
        // A single success clears the run of misses.
        assert_eq!(m.observe(true, t), WatchdogAction::None);
        assert_eq!(m.observe(false, t), WatchdogAction::None);
        // Only 2 misses since the reset — must not trip yet. (The 3rd miss
        // past a reset trips, which trips_after_threshold_consecutive_misses
        // already covers.)
        assert_eq!(m.observe(false, t), WatchdogAction::None);
    }

    #[test]
    fn trips_after_threshold_consecutive_misses() {
        let mut m = machine(3, Duration::ZERO);
        let t = Instant::now();
        assert_eq!(m.observe(false, t), WatchdogAction::None);
        assert_eq!(m.observe(false, t), WatchdogAction::None);
        assert_eq!(m.observe(false, t), WatchdogAction::Trip { misses: 3 });
    }

    #[test]
    fn trip_is_one_shot() {
        let mut m = machine(1, Duration::ZERO);
        let t = Instant::now();
        assert_eq!(m.observe(false, t), WatchdogAction::Trip { misses: 1 });
        // After tripping, further observations never re-trip (the trip path
        // already aborted or returned).
        assert_eq!(m.observe(false, t), WatchdogAction::None);
    }

    #[test]
    fn misses_inside_startup_grace_do_not_count() {
        let mut m = machine(3, Duration::from_secs(90));
        let t0 = Instant::now();
        // Ten consecutive failures entirely inside the grace window.
        for _ in 0..10 {
            assert_eq!(
                m.observe(false, t0 + Duration::from_secs(5)),
                WatchdogAction::None
            );
        }
        // Grace ends; the first 2 misses past it still do not trip…
        let past = t0 + Duration::from_secs(91);
        assert_eq!(m.observe(false, past), WatchdogAction::None);
        assert_eq!(m.observe(false, past), WatchdogAction::None);
        // …the 3rd does.
        assert_eq!(m.observe(false, past), WatchdogAction::Trip { misses: 3 });
    }

    #[test]
    fn success_during_grace_keeps_machine_armed() {
        let mut m = machine(2, Duration::from_secs(60));
        let t0 = Instant::now();
        assert_eq!(m.observe(true, t0), WatchdogAction::None);
        let past = t0 + Duration::from_secs(61);
        assert_eq!(m.observe(false, past), WatchdogAction::None);
        assert_eq!(m.observe(false, past), WatchdogAction::Trip { misses: 2 });
    }

    #[test]
    fn disarm_swallows_all_future_observations() {
        let mut m = machine(1, Duration::ZERO);
        m.disarm();
        let t = Instant::now();
        assert_eq!(m.observe(false, t), WatchdogAction::None);
        assert_eq!(m.observe(true, t), WatchdogAction::None);
    }

    #[test]
    fn threshold_below_one_is_clamped_to_one() {
        let mut m = machine(0, Duration::ZERO);
        let t = Instant::now();
        assert_eq!(m.observe(false, t), WatchdogAction::Trip { misses: 1 });
    }

    #[test]
    fn defaults_match_issue_budget() {
        let c = ApiWatchdogConfig::default();
        assert!(c.enabled);
        assert_eq!(c.probe_interval_secs, 10);
        assert_eq!(c.probe_timeout_secs, 3);
        assert_eq!(c.miss_threshold, 3);
        assert_eq!(c.startup_grace_secs, 90);
        assert_eq!(c.abort_on_stall, None);
    }

    #[test]
    fn config_parses_from_toml_section() {
        let c: ApiWatchdogConfig = toml::from_str(
            r#"
            enabled = true
            probe_interval_secs = 5
            probe_timeout_secs = 2
            miss_threshold = 6
            startup_grace_secs = 120
            abort_on_stall = false
            "#,
        )
        .expect("watchdog config parses");
        assert_eq!(c.probe_interval_secs, 5);
        assert_eq!(c.probe_timeout_secs, 2);
        assert_eq!(c.miss_threshold, 6);
        assert_eq!(c.startup_grace_secs, 120);
        assert_eq!(c.abort_on_stall, Some(false));
    }

    #[test]
    fn probe_health_detects_served_listener() {
        // A real loopback listener answering HTTP must read as Served.
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            // One connection: the probe returns as soon as response bytes
            // arrive, so a second accept() would block join() forever.
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 128];
            use std::io::{Read as _, Write as _};
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });
        assert!(matches!(
            probe_health(addr, Duration::from_secs(2)),
            ProbeOutcome::Served(_)
        ));
        server.join().unwrap();
    }

    #[test]
    fn probe_health_reports_refused_when_no_listener() {
        // Bind then drop to get a (very likely) free port.
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let outcome = probe_health(addr, Duration::from_secs(2));
        assert!(
            matches!(outcome, ProbeOutcome::Refused | ProbeOutcome::Io(_)),
            "expected refused/io, got {outcome:?}"
        );
    }

    #[test]
    fn probe_health_unspecified_bind_probes_loopback() {
        // Regression guard for the unspecified-bind path: the rewrite must
        // not panic on 0.0.0.0 addresses (it rewrites to 127.0.0.1 before
        // connecting). Connect will fail — that's fine, it must not panic.
        let outcome = probe_health(
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1)),
            Duration::from_millis(200),
        );
        assert!(matches!(
            outcome,
            ProbeOutcome::Refused | ProbeOutcome::Io(_)
        ));
    }
}
