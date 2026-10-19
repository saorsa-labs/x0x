//! M1 structured `/health` verdict v1 (issue #1380, #1119 M1 row, ADR 0096
//! §6: health truth does not wait for R12).
//!
//! `GET /health` historically answers a liveness question (`status:
//! healthy|degraded` from peer counts, #262/#1419). That is not a health
//! *verdict*: a node can serve HTTP while its delivery pipeline is wedged
//! (the closed #288), its disk is filling, or its upgrade attempt failed.
//! This module adds the verdict — `ok|degraded|error` over the ten M1
//! inputs (plane, peers, seed reachable, send-failure rate, delivery
//! probe, recv-pump shed, disk, log, identity, upgrade state).
//!
//! Two invariants shape the design:
//!
//! - **The handler stays O(1) and lock-free over transport state (#600).**
//!   The watchdog probes `/health` every 10 s with a 3 s budget and aborts
//!   after 3 misses; the handler must never walk ant-quic's peer table.
//!   Every expensive input (seed counts, recv-pump counters, disk stats,
//!   upgrade artifacts, identity presence) is therefore sampled off-path
//!   by the 5 s background refresher in `serve_with_options` into a
//!   `VerdictSample`; the handler clones that sample, merges the live
//!   peer atomics and uptime, and runs `classify` — a pure function.
//!
//! - **`/health` is auth-exempt (ADR-0038 review fix, issue #600).** The
//!   verdict reports counts, booleans and classifications only: no agent
//!   or machine ids, no custom plane id, no seed addresses, no upgrade
//!   repo. The existing `status`/`degraded_reason` fields keep their exact
//!   legacy semantics (additive JSON only); the new information lives in
//!   the `verdict` object.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::watch;

use super::routes::status::{classify_health, HealthSnapshot, CONNECTIVITY_GRACE_SECS};
use super::state::{AppState, PROD_PLANE_ID};

/// Topic the delivery probe publishes on. A real (non-`local:`) topic so
/// the probe exercises the full same-node path a gossip publish takes:
/// sign → encode → PlumTree admission → decode → subscriber handoff.
pub(in crate::server) const DELIVERY_PROBE_TOPIC: &str = "x0x.health.probe.v1";
/// Probe cadence. Every 30 s one tiny signed frame per daemon — far below
/// presence-beacon traffic.
pub(in crate::server) const DELIVERY_PROBE_INTERVAL_SECS: u64 = 30;
/// How long a probe waits for its own payload to come back before the
/// delivery input is degraded.
pub(in crate::server) const DELIVERY_PROBE_TIMEOUT_SECS: u64 = 5;
/// Delay before the first probe so a freshly started daemon is not flagged
/// while gossip is still joining.
pub(in crate::server) const DELIVERY_PROBE_STARTUP_DELAY_SECS: u64 = 10;
/// Magic prefix distinguishing probe frames from any other traffic on the
/// shared topic (each daemon's probe carries a random nonce after it).
const PROBE_MAGIC: &[u8] = b"x0x-health-probe-v1:";

/// Window duration every rolling counter measures. The refresher's 5 s
/// cadence makes that roughly 12 ticks, but expiry is by elapsed time, not
/// tick count: quiet ticks record no entry, so a count-only window would
/// keep the last nonzero deltas alive for as long as the node stays idle
/// (RC1 review of #1380).
pub(in crate::server) const WINDOW_SECS: u64 = 60;

/// Publish attempts below this in the window make the rate statistically
/// meaningless (idle nodes publish a handful of beacons per minute); the
/// input stays `ok` with `rate: null` instead of paging on 1/1.
const SEND_FAILURE_MIN_ATTEMPTS: u64 = 5;
/// Fraction of failed publishes (over the window, with enough attempts)
/// that degrades the send-failure-rate input.
const SEND_FAILURE_RATE_DEGRADED: f64 = 0.5;

/// Error-level log events in the window that degrade the log input. Well
/// below a storm (thousands/min), well above routine connection churn.
const LOG_ERROR_DEGRADED_THRESHOLD: u64 = 50;

/// Free space under which the disk input is `degraded` (warning).
const DISK_DEGRADED_FREE_BYTES: u64 = 1024 * 1024 * 1024;
/// Free space under which the disk input is `error`: durable writes are
/// about to fail outright, so the node cannot do its job.
const DISK_CRITICAL_FREE_BYTES: u64 = 64 * 1024 * 1024;

/// Process-lifetime count of ERROR-level tracing events. Incremented by
/// [`ErrorCountLayer`], which the `x0xd` binary installs in its tracing
/// registry. Embedders that bring their own subscriber without the layer
/// read a permanent 0 — the log input then reports `ok` with `errors: 0`;
/// the field is a lower bound, not a claim of silence.
static ERROR_LOG_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Counting layer for ERROR-level tracing events (M1 "log" input).
///
/// Cheap by construction: one relaxed atomic increment per ERROR event,
/// no formatting, no I/O — safe to keep on the #600-sensitive logging
/// path.
pub struct ErrorCountLayer;

impl<S> tracing_subscriber::Layer<S> for ErrorCountLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() == tracing::Level::ERROR {
            ERROR_LOG_EVENTS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Total ERROR-level events counted this process. Monotonic; the verdict
/// reads the delta over the rolling window.
pub(in crate::server) fn error_log_events_total() -> u64 {
    ERROR_LOG_EVENTS.load(Ordering::Relaxed)
}

/// Effective-plane classification for the plane input. The *value* of a
/// custom plane is deliberately not reported on the auth-exempt endpoint —
/// a custom id can name a private deployment; `prod`/`custom`/`open` is
/// the whole answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::server) enum PlaneSample {
    /// Not yet sampled (first refresher tick has not run).
    #[default]
    NotSampled,
    /// The well-known prod plane (`x0x.prod`, the unset-`network_id`
    /// default).
    Prod,
    /// Any other declared plane id.
    Custom,
    /// Explicit opt-out (`network_id = ""`): no plane isolation at all.
    Open,
}

impl PlaneSample {
    fn as_str(self) -> &'static str {
        match self {
            PlaneSample::NotSampled => "not_sampled",
            PlaneSample::Prod => "prod",
            PlaneSample::Custom => "custom",
            PlaneSample::Open => "open",
        }
    }
}

impl From<Option<&str>> for PlaneSample {
    fn from(resolved: Option<&str>) -> Self {
        match resolved {
            None => PlaneSample::Open,
            Some(PROD_PLANE_ID) => PlaneSample::Prod,
            Some(_) => PlaneSample::Custom,
        }
    }
}

/// Everything [`classify`] needs, gathered off-path by the refresher and
/// merged with live peer counts/uptime by the handler. `Default` is the
/// unsampled-but-benign state: before the first 5 s refresh the verdict
/// must read `ok`, not a transient error from absent data. The default
/// carries identity presence because a serving daemon cannot lack its
/// auto-generated keys — a derived default would flip those booleans to
/// `false` and classify a never-refreshed snapshot as `error` (RC1 review
/// of #1380).
#[derive(Debug, Clone)]
pub(in crate::server) struct VerdictSample {
    /// Effective gossip plane (handler-irrelevant, refresher-sampled).
    pub plane: PlaneSample,
    // Handler-filled live values (fresh, from the health atomics).
    pub peers: usize,
    pub send_ready_peers: usize,
    pub one_sided_peers: usize,
    pub uptime_secs: u64,
    // Refresher-sampled values (up to HEALTH_SNAPSHOT_REFRESH_SECS old).
    pub seeds_configured: u64,
    pub seeds_connected: u64,
    pub send_attempts_window: u64,
    pub send_failed_window: u64,
    pub probes_run: u64,
    pub last_probe_ok: Option<bool>,
    pub last_probe_latency_ms: Option<u64>,
    pub shed_window: u64,
    pub dropped_full_window: u64,
    pub disk_free_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub log_errors_window: u64,
    pub identity_agent: bool,
    pub identity_machine: bool,
    pub identity_user: bool,
    pub upgrade_checks_enabled: bool,
    pub upgrade_update_available: Option<bool>,
    pub upgrade_latest_version: Option<String>,
    pub upgrade_checked_age_secs: Option<u64>,
    pub upgrade_handoff_pending: bool,
    pub upgrade_failed_artifact: bool,
}

impl Default for VerdictSample {
    fn default() -> Self {
        Self {
            plane: PlaneSample::NotSampled,
            peers: 0,
            send_ready_peers: 0,
            one_sided_peers: 0,
            uptime_secs: 0,
            seeds_configured: 0,
            seeds_connected: 0,
            send_attempts_window: 0,
            send_failed_window: 0,
            probes_run: 0,
            last_probe_ok: None,
            last_probe_latency_ms: None,
            shed_window: 0,
            dropped_full_window: 0,
            disk_free_bytes: None,
            disk_total_bytes: None,
            log_errors_window: 0,
            identity_agent: true,
            identity_machine: true,
            identity_user: false,
            upgrade_checks_enabled: false,
            upgrade_update_available: None,
            upgrade_latest_version: None,
            upgrade_checked_age_secs: None,
            upgrade_handoff_pending: false,
            upgrade_failed_artifact: false,
        }
    }
}

impl VerdictSample {
    /// The unsampled baseline: every input `ok` by absence of contrary
    /// data (identity presence is assumed — a serving daemon cannot lack
    /// its auto-generated keys — and unknown disk/log/upgrade read `ok`).
    pub(in crate::server) fn unsampled() -> Self {
        Self::default()
    }
}

/// Rolling sum of per-tick counter deltas over the last [`WINDOW_SECS`]
/// seconds. Fed by the refresher from monotonic counters (publish totals,
/// recv-pump shed totals, the ERROR-event count); each push records the
/// delta since the previous push.
///
/// Expiry runs on the runtime clock so every window measures the same
/// elapsed [`WINDOW_SECS`], including across quiet periods where no delta
/// is recorded: a burst ages out 60 s after it happened, not the next time
/// enough newer entries arrive. Timestamps therefore come from
/// `tokio::time::Instant` (testable under a paused clock); production
/// callers only ever run inside the refresher task's runtime.
#[derive(Debug, Default)]
pub(in crate::server) struct CounterWindow {
    entries: VecDeque<(tokio::time::Instant, u64)>,
    last_total: Option<u64>,
}

impl CounterWindow {
    /// Record a new monotonic total; returns this tick's delta.
    fn push_total(&mut self, total: u64) -> u64 {
        let delta = self.last_total.map_or(0, |prev| total.saturating_sub(prev));
        self.last_total = Some(total);
        if delta > 0 {
            self.entries.push_back((tokio::time::Instant::now(), delta));
        }
        self.prune();
        delta
    }

    /// Sum of deltas recorded within the last [`WINDOW_SECS`]. Reading
    /// filters by age as well, so the answer stays true to the window even
    /// between pushes.
    fn window_sum(&self) -> u64 {
        match recent_cutoff() {
            Some(cutoff) => self
                .entries
                .iter()
                .take_while(|(at, _)| *at > cutoff)
                .map(|(_, delta)| *delta)
                .sum(),
            // The runtime clock is younger than the window: nothing
            // recorded can be stale yet.
            None => self.entries.iter().map(|(_, delta)| *delta).sum(),
        }
    }

    /// Drop entries older than [`WINDOW_SECS`] — on quiet ticks too, so an
    /// idle node's last burst cannot outlive its window.
    fn prune(&mut self) {
        let Some(cutoff) = recent_cutoff() else {
            return;
        };
        while self.entries.front().is_some_and(|(at, _)| *at <= cutoff) {
            self.entries.pop_front();
        }
    }
}

/// The instant before which window entries are stale: [`WINDOW_SECS`] ago.
/// `None` when the runtime clock cannot look that far back (a clock younger
/// than the window has no stale entries at all).
fn recent_cutoff() -> Option<tokio::time::Instant> {
    tokio::time::Instant::now().checked_sub(Duration::from_secs(WINDOW_SECS))
}

/// Per-daemon rolling-window state owned by the refresher task.
#[derive(Debug, Default)]
pub(in crate::server) struct VerdictWindows {
    send_attempts: CounterWindow,
    send_failed: CounterWindow,
    shed: CounterWindow,
    dropped_full: CounterWindow,
    log_errors: CounterWindow,
}

/// Gather every off-path verdict input. Runs on the 5 s refresher tick
/// where blocking is survivable (#600); never call this from a handler.
pub(in crate::server) async fn sample_verdict_inputs(
    state: &AppState,
    resolved_plane: Option<String>,
    windows: &mut VerdictWindows,
) -> VerdictSample {
    let mut sample = VerdictSample::unsampled();
    sample.plane = PlaneSample::from(resolved_plane.as_deref());

    // Identity: presence only — ids stay on the authed /agent endpoint.
    sample.identity_agent = true; // Agent cannot serve without one.
    sample.identity_machine = true; // Auto-generated at startup.
    sample.identity_user = state.agent.user_id().is_some();

    // Send-failure rate over the rolling window.
    if let Some(stats) = state.agent.gossip_stats() {
        let successes = stats.publish_total;
        let failed = stats.publish_failed;
        windows.send_attempts.push_total(successes + failed);
        windows.send_failed.push_total(failed);
        sample.send_attempts_window = windows.send_attempts.window_sum();
        sample.send_failed_window = windows.send_failed.window_sum();
    }

    // Seed reachability + recv-pump shed/drop counters need the transport.
    if let Some(network) = state.agent.network() {
        let transport = network.transport_diagnostics().await;
        sample.seeds_configured = transport.total_bootstrap_nodes;
        sample.seeds_connected = transport.connected_bootstrap_nodes;

        let pump = network.recv_pump_diagnostics();
        let shed_total =
            pump.pubsub.shed_priority + pump.membership.shed_priority + pump.bulk.shed_priority;
        let dropped_total =
            pump.pubsub.dropped_full + pump.membership.dropped_full + pump.bulk.dropped_full;
        windows.shed.push_total(shed_total);
        windows.dropped_full.push_total(dropped_total);
        sample.shed_window = windows.shed.window_sum();
        sample.dropped_full_window = windows.dropped_full.window_sum();
    }

    // Disk: the data-dir filesystem is where every durable write lands.
    if let Some(bytes) = filesystem_bytes(&state.data_dir) {
        sample.disk_free_bytes = Some(bytes.free_bytes);
        sample.disk_total_bytes = Some(bytes.total_bytes);
    }

    // Log: delta of the ERROR-event counter over the window.
    windows.log_errors.push_total(error_log_events_total());
    sample.log_errors_window = windows.log_errors.window_sum();

    // Upgrade state, read only through existing accessors/artifacts (#1380
    // fence: no edits to src/upgrade). `update_available` alone stays `ok`
    // — matching `x0x doctor`, an available release is info, not illness.
    sample.upgrade_checks_enabled = state.update_config.enabled;
    {
        let cache = state.upgrade_check_cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            sample.upgrade_checked_age_secs = Some(cached.checked_at.elapsed().as_secs());
            sample.upgrade_update_available = cached
                .body
                .get("update_available")
                .and_then(serde_json::Value::as_bool);
            sample.upgrade_latest_version = cached
                .body
                .get("version")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
        }
    }
    sample.upgrade_handoff_pending = state
        .data_dir
        .join(crate::upgrade::restart::HANDOFF_FILE_NAME)
        .exists();
    sample.upgrade_failed_artifact = state
        .data_dir
        .join(crate::upgrade::restart::UPGRADE_FAILED_FILE_NAME)
        .exists();

    // Delivery probe results are published to the health snapshot by the
    // probe task; read them back for the sample.
    let (probes_run, last_ok, latency) = state.health_snapshot.probe_results();
    sample.probes_run = probes_run;
    sample.last_probe_ok = last_ok;
    sample.last_probe_latency_ms = latency;

    sample
}

/// Filesystem capacity for the given path, or `None` where unsupported
/// (non-unix) or unstatable.
#[derive(Debug, Clone, Copy)]
struct FilesystemBytes {
    free_bytes: u64,
    total_bytes: u64,
}

#[cfg(unix)]
fn filesystem_bytes(path: &Path) -> Option<FilesystemBytes> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c_path` is a valid NUL-terminated path and `statvfs` only
    // writes into the zeroed struct we pass; no pointers are retained.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    // POSIX: f_frsize is the fundamental block size; older filesystems
    // report 0 there, f_bsize always holds a usable size.
    let block = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };
    Some(FilesystemBytes {
        free_bytes: stat.f_bavail as u64 * block,
        total_bytes: stat.f_blocks as u64 * block,
    })
}

#[cfg(not(unix))]
fn filesystem_bytes(_path: &Path) -> Option<FilesystemBytes> {
    None
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Per-input state badge. `error` is reserved for inputs whose failure
/// means the node cannot do its job (identity gone, disk at a critical
/// floor); everything else degrades at most — the process is still alive
/// and serving, which is what the watchdog's `ok: true` keeps saying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum InputState {
    Ok,
    Degraded,
    Error,
}

impl InputState {
    fn as_str(self) -> &'static str {
        match self {
            InputState::Ok => "ok",
            InputState::Degraded => "degraded",
            InputState::Error => "error",
        }
    }

    fn severity(self) -> u8 {
        match self {
            InputState::Ok => 0,
            InputState::Degraded => 1,
            InputState::Error => 2,
        }
    }
}

macro_rules! input_report {
    (struct $name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Serialize)]
        pub(in crate::server) struct $name {
            state: &'static str,
            $(pub(in crate::server) $field: $ty,)*
        }
    };
}

input_report! {
    struct PlaneReport {
        plane: &'static str,
    }
}

input_report! {
    struct PeersReport {
        peers: usize,
        send_ready_peers: usize,
        one_sided_peers: usize,
    }
}

input_report! {
    struct SeedReachableReport {
        configured: u64,
        connected: u64,
    }
}

input_report! {
    struct SendFailureRateReport {
        window_secs: u64,
        attempts: u64,
        failed: u64,
        rate: Option<f64>,
    }
}

input_report! {
    struct DeliveryProbeReport {
        probes_run: u64,
        last_ok: Option<bool>,
        last_latency_ms: Option<u64>,
    }
}

input_report! {
    struct RecvPumpShedReport {
        window_secs: u64,
        shed: u64,
        dropped_full: u64,
    }
}

input_report! {
    struct DiskReport {
        free_bytes: Option<u64>,
        total_bytes: Option<u64>,
    }
}

input_report! {
    struct LogReport {
        window_secs: u64,
        errors: u64,
    }
}

input_report! {
    struct IdentityReport {
        agent: bool,
        machine: bool,
        user_present: bool,
    }
}

input_report! {
    struct UpgradeReport {
        checks_enabled: bool,
        update_available: Option<bool>,
        latest_version: Option<String>,
        checked_age_secs: Option<u64>,
        handoff_pending: bool,
        failed_artifact: bool,
    }
}

/// The ten M1 inputs, each with its own `state` badge.
#[derive(Debug, Serialize)]
pub(in crate::server) struct InputsReport {
    pub(in crate::server) plane: PlaneReport,
    pub(in crate::server) peers: PeersReport,
    pub(in crate::server) seed_reachable: SeedReachableReport,
    pub(in crate::server) send_failure_rate: SendFailureRateReport,
    pub(in crate::server) delivery_probe: DeliveryProbeReport,
    pub(in crate::server) recv_pump_shed: RecvPumpShedReport,
    pub(in crate::server) disk: DiskReport,
    pub(in crate::server) log: LogReport,
    pub(in crate::server) identity: IdentityReport,
    pub(in crate::server) upgrade: UpgradeReport,
}

/// The structured verdict served as `GET /health`'s additive `verdict`
/// field. `verdict` is the worst input state; `reasons` collects one
/// sentence per non-`ok` input.
#[derive(Debug, Serialize)]
pub(in crate::server) struct HealthVerdict {
    pub(in crate::server) verdict: &'static str,
    pub(in crate::server) reasons: Vec<String>,
    pub(in crate::server) inputs: InputsReport,
}

/// Classify the M1 verdict over a sample. Pure: no I/O, no locks beyond
/// the caller's — safe to run inside the handler.
pub(in crate::server) fn classify(sample: &VerdictSample) -> HealthVerdict {
    let mut reasons: Vec<String> = Vec::new();
    let mut worst: u8 = 0;
    let mut bump = |state: InputState| worst = worst.max(state.severity());

    // Plane: an open plane (`network_id = ""`) is an explicit operator
    // opt-out from isolation — gossip traffic from every plane is admitted
    // (#206). Surfacing it as degraded is the verdict doing its job; the
    // operator who meant it can read the reason and move on.
    let plane_state = match sample.plane {
        PlaneSample::Open => {
            bump(InputState::Degraded);
            reasons.push(
                "open plane (network_id = \"\"): no plane isolation, gossip is admitted \
                 from every plane"
                    .to_string(),
            );
            InputState::Degraded
        }
        PlaneSample::NotSampled | PlaneSample::Prod | PlaneSample::Custom => InputState::Ok,
    };

    // Peers: the legacy #262/#1419 classification, verbatim.
    let (peers_status, peers_degraded_reason) = classify_health(
        sample.peers,
        sample.send_ready_peers,
        sample.uptime_secs,
        sample.one_sided_peers,
    );
    let peers_state = if peers_status == "degraded" {
        bump(InputState::Degraded);
        if let Some(reason) = peers_degraded_reason {
            reasons.push(reason);
        }
        InputState::Degraded
    } else {
        InputState::Ok
    };

    // Seeds: hints only (ADR 0001), so an unreachable seed with a working
    // mesh is not fatal — but a daemon that configured seeds, is past the
    // bootstrap grace and reaches none of them has lost its join path.
    let seed_state = if sample.seeds_configured > 0
        && sample.seeds_connected == 0
        && sample.uptime_secs >= CONNECTIVITY_GRACE_SECS
    {
        bump(InputState::Degraded);
        reasons.push(format!(
            "0 of {} configured bootstrap seeds reachable past the \
                 {CONNECTIVITY_GRACE_SECS}s grace; the join path is down",
            sample.seeds_configured
        ));
        InputState::Degraded
    } else {
        InputState::Ok
    };

    // Send-failure rate over the rolling window.
    let attempts = sample.send_attempts_window;
    let failed = sample.send_failed_window;
    let rate = if attempts >= SEND_FAILURE_MIN_ATTEMPTS {
        Some(failed as f64 / attempts as f64)
    } else {
        None
    };
    let send_state = match rate {
        Some(rate) if rate >= SEND_FAILURE_RATE_DEGRADED => {
            bump(InputState::Degraded);
            reasons.push(format!(
                "{failed}/{attempts} publishes failed in the last {WINDOW_SECS}s \
                 (rate {rate:.0} ≥ {SEND_FAILURE_RATE_DEGRADED:.0})"
            ));
            InputState::Degraded
        }
        _ => InputState::Ok,
    };

    // Delivery probe: the last completed probe decides. No probe yet (or
    // no gossip runtime — embed path) is `ok`, not degraded.
    let probe_state = match (sample.probes_run, sample.last_probe_ok) {
        (0, _) | (_, Some(true)) => InputState::Ok,
        (_, Some(false)) => {
            bump(InputState::Degraded);
            reasons.push(format!(
                "delivery probe did not return within \
                 {DELIVERY_PROBE_TIMEOUT_SECS}s (#288: serving but not delivering)"
            ));
            InputState::Degraded
        }
        (_, None) => InputState::Ok,
    };

    // Recv-pump shed: ADR 0013 shedding is recoverable by design, but any
    // recent shed or full-queue drop says the pump ran into near-overload.
    let shed = sample.shed_window;
    let dropped = sample.dropped_full_window;
    let shed_state = if shed + dropped > 0 {
        bump(InputState::Degraded);
        reasons.push(format!(
            "recv pump shed {shed} recoverable control frames (ADR 0013) and \
             dropped {dropped} frames at a full queue in the last {WINDOW_SECS}s"
        ));
        InputState::Degraded
    } else {
        InputState::Ok
    };

    // Disk: `error` at the critical floor — durable writes are about to
    // fail, which is beyond "degraded".
    let disk_state = match sample.disk_free_bytes {
        None => InputState::Ok,
        Some(free) if free < DISK_CRITICAL_FREE_BYTES => {
            bump(InputState::Error);
            reasons.push(format!(
                "data-dir filesystem has {free} bytes free (< {DISK_CRITICAL_FREE_BYTES}); \
                 durable writes are failing or about to"
            ));
            InputState::Error
        }
        Some(free) if free < DISK_DEGRADED_FREE_BYTES => {
            bump(InputState::Degraded);
            reasons.push(format!(
                "data-dir filesystem has {free} bytes free (< {DISK_DEGRADED_FREE_BYTES})"
            ));
            InputState::Degraded
        }
        Some(_) => InputState::Ok,
    };

    // Log: an error-level storm, not individual errors (a failed dial
    // logs ERROR; that is routine).
    let log_state = if sample.log_errors_window >= LOG_ERROR_DEGRADED_THRESHOLD {
        bump(InputState::Degraded);
        reasons.push(format!(
            "{} error-level log events in the last {WINDOW_SECS}s",
            sample.log_errors_window
        ));
        InputState::Degraded
    } else {
        InputState::Ok
    };

    // Identity: a serving daemon cannot actually lack its auto-generated
    // machine/agent keys — this arm is defensive depth and keeps the
    // input honest for embedders. The optional user key is info, never a
    // verdict mover.
    let identity_state = if !sample.identity_agent || !sample.identity_machine {
        bump(InputState::Error);
        reasons.push("agent or machine identity missing; the node cannot sign".to_string());
        InputState::Error
    } else {
        InputState::Ok
    };

    // Upgrade: read through existing accessors only. A staged handoff or
    // the loud UPGRADE_FAILED artifact is a real maintenance state. An
    // available update or a failed lookup stays `ok` (matches doctor).
    let upgrade_state = if sample.upgrade_handoff_pending {
        bump(InputState::Degraded);
        reasons.push(format!(
            "upgrade handoff staged ({} present); restart pending",
            crate::upgrade::restart::HANDOFF_FILE_NAME
        ));
        InputState::Degraded
    } else if sample.upgrade_failed_artifact {
        bump(InputState::Degraded);
        reasons.push(format!(
            "last upgrade attempt failed ({} artifact present)",
            crate::upgrade::restart::UPGRADE_FAILED_FILE_NAME
        ));
        InputState::Degraded
    } else {
        InputState::Ok
    };

    let verdict = match worst {
        2 => "error",
        1 => "degraded",
        _ => "ok",
    };

    HealthVerdict {
        verdict,
        reasons,
        inputs: InputsReport {
            plane: PlaneReport {
                state: plane_state.as_str(),
                plane: sample.plane.as_str(),
            },
            peers: PeersReport {
                state: peers_state.as_str(),
                peers: sample.peers,
                send_ready_peers: sample.send_ready_peers,
                one_sided_peers: sample.one_sided_peers,
            },
            seed_reachable: SeedReachableReport {
                state: seed_state.as_str(),
                configured: sample.seeds_configured,
                connected: sample.seeds_connected,
            },
            send_failure_rate: SendFailureRateReport {
                state: send_state.as_str(),
                window_secs: WINDOW_SECS,
                attempts,
                failed,
                rate,
            },
            delivery_probe: DeliveryProbeReport {
                state: probe_state.as_str(),
                probes_run: sample.probes_run,
                last_ok: sample.last_probe_ok,
                last_latency_ms: sample.last_probe_latency_ms,
            },
            recv_pump_shed: RecvPumpShedReport {
                state: shed_state.as_str(),
                window_secs: WINDOW_SECS,
                shed,
                dropped_full: dropped,
            },
            disk: DiskReport {
                state: disk_state.as_str(),
                free_bytes: sample.disk_free_bytes,
                total_bytes: sample.disk_total_bytes,
            },
            log: LogReport {
                state: log_state.as_str(),
                window_secs: WINDOW_SECS,
                errors: sample.log_errors_window,
            },
            identity: IdentityReport {
                state: identity_state.as_str(),
                agent: sample.identity_agent,
                machine: sample.identity_machine,
                user_present: sample.identity_user,
            },
            upgrade: UpgradeReport {
                state: upgrade_state.as_str(),
                checks_enabled: sample.upgrade_checks_enabled,
                update_available: sample.upgrade_update_available,
                latest_version: sample.upgrade_latest_version.clone(),
                checked_age_secs: sample.upgrade_checked_age_secs,
                handoff_pending: sample.upgrade_handoff_pending,
                failed_artifact: sample.upgrade_failed_artifact,
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Delivery probe
// ---------------------------------------------------------------------------

/// Background delivery probe (#288's blind spot): publish a nonce to
/// [`DELIVERY_PROBE_TOPIC`] and wait for our own payload to come back
/// through subscribe → decode → subscriber handoff. Other daemons'
/// probes on the same topic are ignored — only the nonce match counts.
///
/// Schedule: the first probe runs at the documented
/// [`DELIVERY_PROBE_STARTUP_DELAY_SECS`] boundary (10 s, see
/// `docs/api-reference.md`), then every [`DELIVERY_PROBE_INTERVAL_SECS`].
pub(in crate::server) async fn run_delivery_probe(
    agent: Arc<crate::Agent>,
    snapshot: Arc<HealthSnapshot>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    // Startup delay, bounded by shutdown: gossip is still joining on a
    // freshly started daemon.
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(DELIVERY_PROBE_STARTUP_DELAY_SECS)) => {}
        _ = shutdown_rx.changed() => return,
    }
    if *shutdown_rx.borrow() {
        return;
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(DELIVERY_PROBE_INTERVAL_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut subscription: Option<crate::gossip::Subscription> = None;
    loop {
        // The interval's first tick fires immediately, so the first probe
        // runs at the 10 s boundary above — not one interval later.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown_rx.changed() => return,
        }
        if *shutdown_rx.borrow() {
            return;
        }
        // Subscribe lazily, under the same deadline as the probe itself:
        // an unbounded initial subscribe would park this task (and leave
        // the delivery input `ok`) exactly when the path is wedged. A
        // subscribe that fails outright means no gossip runtime (embed
        // path): `probes_run: 0`, the input stays `ok`, and the task ends.
        // A subscribe that stalls is a delivery failure — recorded, then
        // retried on the next tick.
        let subscription = match subscription.as_mut() {
            Some(subscription) => subscription,
            None => {
                match tokio::time::timeout(
                    Duration::from_secs(DELIVERY_PROBE_TIMEOUT_SECS),
                    agent.subscribe(DELIVERY_PROBE_TOPIC),
                )
                .await
                {
                    Ok(Ok(fresh)) => subscription.insert(fresh),
                    Ok(Err(err)) => {
                        tracing::debug!(
                            error = %err,
                            "health delivery probe: no gossip runtime, not probing"
                        );
                        return;
                    }
                    Err(_) => {
                        tracing::warn!(
                            "health delivery probe: subscribe did not complete \
                             within {DELIVERY_PROBE_TIMEOUT_SECS}s"
                        );
                        snapshot.record_probe(false, None);
                        continue;
                    }
                }
            }
        };
        let started = Instant::now();
        match probe_once(&agent, subscription).await {
            Ok(()) => {
                snapshot.record_probe(true, Some(started.elapsed().as_millis() as u64));
            }
            Err(err) => {
                // Rate-limited by the 30 s cadence: one warn per failed
                // probe, never a storm.
                tracing::warn!("health delivery probe failed: {err}");
                snapshot.record_probe(false, None);
            }
        }
    }
}

/// One probe round-trip. `Ok(())` only when this daemon's exact payload
/// came back on the subscription within the timeout.
async fn probe_once(
    agent: &crate::Agent,
    subscription: &mut crate::gossip::Subscription,
) -> Result<(), String> {
    let mut channel = AgentChannel {
        agent,
        subscription,
    };
    probe_exchange(&mut channel, probe_payload()).await
}

/// The transport-facing half of one probe, as an injectable seam: the
/// production pair is [`Agent::publish`] plus the subscription's recv,
/// and tests substitute channels that block, echo or stall.
trait ProbeChannel {
    async fn publish(&mut self, payload: Vec<u8>) -> Result<(), String>;
    async fn recv(&mut self) -> Option<Vec<u8>>;
}

/// [`ProbeChannel`] over the real delivery path: a signed publish on the
/// probe topic and this daemon's own subscription on it.
struct AgentChannel<'a> {
    agent: &'a crate::Agent,
    subscription: &'a mut crate::gossip::Subscription,
}

impl ProbeChannel for AgentChannel<'_> {
    async fn publish(&mut self, payload: Vec<u8>) -> Result<(), String> {
        self.agent
            .publish(DELIVERY_PROBE_TOPIC, payload)
            .await
            .map_err(|err| format!("probe publish failed: {err}"))
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.subscription
            .recv()
            .await
            .map(|message| message.payload.to_vec())
    }
}

/// The payload one probe publishes and must hear back: the probe magic
/// plus 16 random bytes, unique per round, so other daemons' probes on
/// the shared topic never satisfy ours.
fn probe_payload() -> Vec<u8> {
    use rand::RngCore;

    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut payload = PROBE_MAGIC.to_vec();
    payload.extend_from_slice(&nonce);
    payload
}

/// One bounded probe exchange: publish the nonce, then wait for the exact
/// payload to come back — publish included, all under a single
/// [`DELIVERY_PROBE_TIMEOUT_SECS`] deadline. A publish that never
/// completes is precisely the #288 serving-but-not-delivering wedge this
/// probe exists to expose, so it must fail the probe, not outlive the cap.
async fn probe_exchange<C: ProbeChannel>(channel: &mut C, payload: Vec<u8>) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(DELIVERY_PROBE_TIMEOUT_SECS), async {
        channel.publish(payload.clone()).await?;
        loop {
            match channel.recv().await {
                Some(echo) if echo == payload => return Ok(()),
                // Another daemon's probe on the shared topic — keep waiting.
                Some(_) => {}
                // Subscription dropped (shutdown): the outer loop exits on
                // the shutdown watch right after.
                None => return Err("probe subscription closed".to_string()),
            }
        }
    })
    .await
    .map_err(|_| format!("probe did not complete within {DELIVERY_PROBE_TIMEOUT_SECS}s"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VerdictSample {
        VerdictSample {
            plane: PlaneSample::Prod,
            peers: 4,
            send_ready_peers: 4,
            one_sided_peers: 0,
            uptime_secs: 600,
            identity_agent: true,
            identity_machine: true,
            ..VerdictSample::unsampled()
        }
    }

    fn assert_ok(verdict: &HealthVerdict) {
        assert_eq!(verdict.verdict, "ok", "reasons: {:?}", verdict.reasons);
    }

    // Plane ------------------------------------------------------------

    /// #1380: an open plane must be able to move the verdict — the daemon
    /// deliberately disabled plane isolation.
    #[test]
    fn open_plane_degrades_the_verdict() {
        let mut sample = sample();
        sample.plane = PlaneSample::Open;
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.plane.state, "degraded");
        assert!(verdict.reasons.iter().any(|r| r.contains("open plane")));
    }

    #[test]
    fn prod_and_custom_planes_are_ok() {
        for plane in [PlaneSample::Prod, PlaneSample::Custom] {
            let mut sample = sample();
            sample.plane = plane;
            let verdict = classify(&sample);
            assert_eq!(verdict.inputs.plane.state, "ok");
            assert_eq!(verdict.inputs.plane.plane, plane.as_str());
            assert_ok(&verdict);
        }
    }

    #[test]
    fn unsampled_plane_is_ok_not_degraded() {
        // Before the first refresher tick the verdict must not flag.
        let mut sample = sample();
        sample.plane = PlaneSample::NotSampled;
        assert_ok(&classify(&sample));
    }

    // Peers ------------------------------------------------------------

    /// The peers input reuses the #262 wedged-transport classification.
    #[test]
    fn zero_peers_past_grace_degrades_the_verdict() {
        let mut sample = sample();
        sample.peers = 0;
        sample.send_ready_peers = 0;
        sample.uptime_secs = CONNECTIVITY_GRACE_SECS + 1;
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.peers.state, "degraded");
        assert!(verdict.reasons.iter().any(|r| r.contains("zero peers")));
    }

    /// The #1419 one-sided link signal also moves the peers input.
    #[test]
    fn one_sided_peers_degrade_the_verdict() {
        let mut sample = sample();
        sample.one_sided_peers = 1;
        let verdict = classify(&sample);
        assert_eq!(verdict.inputs.peers.state, "degraded");
        assert!(verdict.reasons.iter().any(|r| r.contains("one-sided")));
    }

    #[test]
    fn healthy_peers_input_is_ok() {
        let verdict = classify(&sample());
        assert_eq!(verdict.inputs.peers.state, "ok");
        assert_ok(&verdict);
    }

    // Seeds ------------------------------------------------------------

    #[test]
    fn seeds_configured_but_none_reachable_past_grace_degrades() {
        let mut sample = sample();
        sample.seeds_configured = 3;
        sample.seeds_connected = 0;
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.seed_reachable.state, "degraded");
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("0 of 3 configured bootstrap seeds")));
    }

    #[test]
    fn seeds_unreachable_within_grace_is_ok() {
        let mut sample = sample();
        sample.seeds_configured = 3;
        sample.seeds_connected = 0;
        sample.uptime_secs = CONNECTIVITY_GRACE_SECS - 1;
        assert_ok(&classify(&sample));
    }

    #[test]
    fn no_configured_seeds_and_reachable_seeds_are_ok() {
        let mut no_seeds = sample();
        no_seeds.seeds_configured = 0;
        no_seeds.seeds_connected = 0;
        assert_ok(&classify(&no_seeds));

        let mut reachable = sample();
        reachable.seeds_configured = 3;
        reachable.seeds_connected = 1;
        let verdict = classify(&reachable);
        assert_eq!(verdict.inputs.seed_reachable.state, "ok");
        assert_ok(&verdict);
    }

    // Send-failure rate -------------------------------------------------

    #[test]
    fn high_send_failure_rate_degrades() {
        let mut sample = sample();
        sample.send_attempts_window = 100;
        sample.send_failed_window = 60;
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.send_failure_rate.state, "degraded");
        assert_eq!(verdict.inputs.send_failure_rate.rate, Some(0.6));
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("publishes failed")));
    }

    #[test]
    fn too_few_attempts_keeps_the_rate_null_and_ok() {
        let mut sample = sample();
        sample.send_attempts_window = 2;
        sample.send_failed_window = 2;
        let verdict = classify(&sample);
        assert_eq!(verdict.inputs.send_failure_rate.rate, None);
        assert_ok(&verdict);
    }

    #[test]
    fn low_send_failure_rate_is_ok() {
        let mut sample = sample();
        sample.send_attempts_window = 100;
        sample.send_failed_window = 5;
        assert_ok(&classify(&sample));
    }

    // Delivery probe ----------------------------------------------------

    #[test]
    fn failed_delivery_probe_degrades() {
        let mut sample = sample();
        sample.probes_run = 7;
        sample.last_probe_ok = Some(false);
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.delivery_probe.state, "degraded");
        assert!(verdict.reasons.iter().any(|r| r.contains("delivery probe")));
    }

    #[test]
    fn successful_probe_and_no_probe_yet_are_ok() {
        let mut probed = sample();
        probed.probes_run = 7;
        probed.last_probe_ok = Some(true);
        probed.last_probe_latency_ms = Some(12);
        let verdict = classify(&probed);
        assert_eq!(verdict.inputs.delivery_probe.state, "ok");
        assert_eq!(verdict.inputs.delivery_probe.last_latency_ms, Some(12));
        assert_ok(&verdict);

        // Never probed (no gossip runtime, or before the first probe).
        let unprobed = sample();
        assert_eq!(classify(&unprobed).inputs.delivery_probe.probes_run, 0);
        assert_ok(&classify(&unprobed));
    }

    // Recv-pump shed ----------------------------------------------------

    #[test]
    fn recent_shed_or_dropped_frames_degrade() {
        let mut sample = sample();
        sample.shed_window = 40;
        sample.dropped_full_window = 2;
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.recv_pump_shed.state, "degraded");
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("shed 40 recoverable")));
    }

    #[test]
    fn clean_pump_window_is_ok() {
        assert_ok(&classify(&sample()));
    }

    // Disk --------------------------------------------------------------

    #[test]
    fn critically_full_disk_is_an_error_verdict() {
        let mut sample = sample();
        sample.disk_free_bytes = Some(1024);
        sample.disk_total_bytes = Some(1024 * 1024);
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "error");
        assert_eq!(verdict.inputs.disk.state, "error");
        assert!(verdict.reasons.iter().any(|r| r.contains("durable writes")));
    }

    #[test]
    fn low_disk_degrades_and_healthy_disk_is_ok() {
        let mut low = sample();
        low.disk_free_bytes = Some(512 * 1024 * 1024);
        low.disk_total_bytes = Some(64 * 1024 * 1024 * 1024);
        let verdict = classify(&low);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.disk.state, "degraded");

        let mut healthy = sample();
        healthy.disk_free_bytes = Some(100 * 1024 * 1024 * 1024);
        healthy.disk_total_bytes = Some(256 * 1024 * 1024 * 1024);
        assert_ok(&classify(&healthy));
    }

    #[test]
    fn unknown_disk_is_ok() {
        let mut sample = sample();
        sample.disk_free_bytes = None;
        sample.disk_total_bytes = None;
        assert_ok(&classify(&sample));
    }

    // Log ---------------------------------------------------------------

    #[test]
    fn error_log_storm_degrades() {
        let mut sample = sample();
        sample.log_errors_window = LOG_ERROR_DEGRADED_THRESHOLD;
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.log.state, "degraded");
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("error-level log events")));
    }

    #[test]
    fn routine_error_count_is_ok() {
        let mut sample = sample();
        sample.log_errors_window = LOG_ERROR_DEGRADED_THRESHOLD - 1;
        assert_ok(&classify(&sample));
    }

    // Identity ----------------------------------------------------------

    #[test]
    fn missing_machine_or_agent_identity_is_an_error_verdict() {
        let mut no_machine = sample();
        no_machine.identity_machine = false;
        let verdict = classify(&no_machine);
        assert_eq!(verdict.verdict, "error");
        assert_eq!(verdict.inputs.identity.state, "error");

        let mut no_agent = sample();
        no_agent.identity_agent = false;
        assert_eq!(classify(&no_agent).verdict, "error");
    }

    #[test]
    fn absent_optional_user_identity_is_ok() {
        let mut sample = sample();
        sample.identity_user = false;
        let verdict = classify(&sample);
        assert!(!verdict.inputs.identity.user_present);
        assert_ok(&verdict);
    }

    // Upgrade -----------------------------------------------------------

    #[test]
    fn staged_upgrade_handoff_degrades() {
        let mut sample = sample();
        sample.upgrade_handoff_pending = true;
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.upgrade.state, "degraded");
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains(crate::upgrade::restart::HANDOFF_FILE_NAME)));
    }

    #[test]
    fn failed_upgrade_artifact_degrades() {
        let mut sample = sample();
        sample.upgrade_failed_artifact = true;
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "degraded");
        assert_eq!(verdict.inputs.upgrade.state, "degraded");
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains(crate::upgrade::restart::UPGRADE_FAILED_FILE_NAME)));
    }

    #[test]
    fn available_update_and_disabled_checks_stay_ok() {
        // An available release is info, matching `x0x doctor` (#1382).
        let mut update = sample();
        update.upgrade_checks_enabled = true;
        update.upgrade_update_available = Some(true);
        update.upgrade_latest_version = Some("9.9.9".to_string());
        update.upgrade_checked_age_secs = Some(30);
        let verdict = classify(&update);
        assert_eq!(
            verdict.inputs.upgrade.update_available,
            Some(true),
            "the field is still reported"
        );
        assert_ok(&verdict);

        let mut disabled = sample();
        disabled.upgrade_checks_enabled = false;
        assert_ok(&classify(&disabled));
    }

    // Aggregation -------------------------------------------------------

    #[test]
    fn error_dominates_degraded_in_the_overall_verdict() {
        let mut sample = sample();
        sample.plane = PlaneSample::Open; // degraded
        sample.disk_free_bytes = Some(1024); // error
        let verdict = classify(&sample);
        assert_eq!(verdict.verdict, "error");
        assert_eq!(verdict.reasons.len(), 2, "both inputs carry a reason");
    }

    #[test]
    fn all_good_inputs_produce_an_ok_verdict() {
        let verdict = classify(&sample());
        assert_ok(&verdict);
        assert!(verdict.reasons.is_empty());
    }

    // Windows ------------------------------------------------------------

    /// RC1 #1380 (P1): expiry is by elapsed time, not entry count. Quiet
    /// ticks record no entry, so a count-only window kept the last nonzero
    /// deltas alive for as long as the node stayed idle — a 61 s-old error
    /// burst still degraded the verdict after 12 unchanged-total pushes.
    /// Fails at 8646cc84, where the window ignored the runtime clock.
    #[tokio::test(start_paused = true)]
    async fn counter_window_expires_an_old_burst_by_time_not_ticks() {
        let mut window = CounterWindow::default();
        window.push_total(0); // baseline
        assert_eq!(window.push_total(50), 50); // the error burst
        tokio::time::advance(Duration::from_secs(WINDOW_SECS + 1)).await;
        // Twelve quiet pushes: unchanged totals record nothing, but must
        // still age the burst out of the window.
        for _ in 0..12 {
            assert_eq!(window.push_total(50), 0);
        }
        assert_eq!(window.window_sum(), 0, "a 61 s-old burst must age out");
    }

    /// RC1 #1380 (P1): the attempt and failure windows must measure the
    /// same elapsed 60 s. Count-based eviction retired them on different
    /// activity schedules, so the rate divided mismatched windows.
    /// Fails at 8646cc84, where both sums stayed at their burst values.
    #[tokio::test(start_paused = true)]
    async fn attempt_and_failure_windows_expire_on_the_same_clock() {
        let mut attempts = CounterWindow::default();
        let mut failed = CounterWindow::default();
        attempts.push_total(0); // baselines
        failed.push_total(0);
        attempts.push_total(100);
        failed.push_total(60);
        assert_eq!(attempts.window_sum(), 100, "fresh bursts still count");
        assert_eq!(failed.window_sum(), 60);
        tokio::time::advance(Duration::from_secs(WINDOW_SECS + 1)).await;
        attempts.push_total(100); // quiet: unchanged total
        failed.push_total(60);
        assert_eq!(attempts.window_sum(), 0);
        assert_eq!(failed.window_sum(), 0);
    }

    /// RC1 #1380 (P1): a recovered pump — one shed burst, then quiet —
    /// must stop feeding the recv-pump input once its window passes. The
    /// shed/dropped counters run through the same time-based windows.
    /// Fails at 8646cc84, where the shed burst never aged out.
    #[tokio::test(start_paused = true)]
    async fn recovered_pump_shed_ages_out_of_the_window() {
        let mut windows = VerdictWindows::default();
        windows.shed.push_total(0); // baseline
        windows.shed.push_total(40); // the near-overload burst
        assert_eq!(windows.shed.window_sum(), 40);
        tokio::time::advance(Duration::from_secs(WINDOW_SECS + 1)).await;
        windows.shed.push_total(40); // quiet: the pump recovered
        assert_eq!(
            windows.shed.window_sum(),
            0,
            "a 61 s-old shed burst must age out"
        );
    }

    /// A burst inside the window still counts, whatever the tick count.
    #[tokio::test(start_paused = true)]
    async fn counter_window_keeps_fresh_bursts_regardless_of_entry_count() {
        let mut window = CounterWindow::default();
        window.push_total(0); // baseline
        for i in 0..17 {
            window.push_total((i + 1) as u64 * 10);
        }
        // 17 nonzero pushes within the window: all 17 count, not "the last 12".
        assert_eq!(window.window_sum(), 17 * 10);
    }

    /// The window reads the runtime clock, so this runs under tokio; an
    /// impossible total reset must not fabricate drops.
    #[tokio::test(start_paused = true)]
    async fn counter_window_ignores_zero_and_negative_deltas() {
        let mut window = CounterWindow::default();
        window.push_total(100);
        window.push_total(100);
        window.push_total(50); // impossible reset must not fabricate drops
        assert_eq!(window.window_sum(), 0);
    }

    // Log layer -----------------------------------------------------------

    #[test]
    fn error_count_layer_counts_only_error_events() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let before = error_log_events_total();
        tracing::subscriber::with_default(
            tracing_subscriber::registry().with(ErrorCountLayer),
            || {
                tracing::error!("counted");
                tracing::warn!("not counted");
                tracing::info!("not counted");
            },
        );
        assert_eq!(error_log_events_total(), before + 1);
    }

    // Disk helper ---------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn filesystem_bytes_reads_the_tempdir_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = filesystem_bytes(dir.path()).expect("statvfs on a tempdir");
        assert!(bytes.free_bytes > 0);
        assert!(bytes.total_bytes >= bytes.free_bytes);
    }

    // Delivery probe ------------------------------------------------------

    /// A loopback-only, bootstrap-free, mDNS-off agent: inert for test
    /// purposes, and the same shape the daemon runs in production.
    async fn loopback_agent() -> crate::Agent {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir = Box::leak(Box::new(dir)); // lives as long as the agent
        crate::Agent::builder()
            .with_identity_dir(dir.path())
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            // Explicit (absent) user key: skips the default ~/.x0x probe
            // (#456 test-home guard) — the user layer is opt-in.
            .with_user_key_path(dir.path().join("user.key"))
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_peer_cache_disabled()
            .with_peer_cache_dir(dir.path().join("peers"))
            .with_network_config(crate::network::NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr")),
                bootstrap_nodes: Vec::new(),
                port_mapping_enabled: false,
                mdns_enabled: false,
                ..crate::network::NetworkConfig::default()
            })
            .build()
            .await
            .expect("loopback agent")
    }

    /// Step the paused clock forward until `started.elapsed()` reaches
    /// `target`, in small hops so timer-driven tasks (probe rounds, their
    /// deadlines) actually run between hops. Auto-advance may already have
    /// moved the clock past `target`; the callers' checkpoints are one-sided.
    async fn advance_past(started: tokio::time::Instant, target: Duration) {
        while started.elapsed() < target {
            tokio::time::advance(Duration::from_millis(200)).await;
        }
    }

    /// RC1 #1380 (P1): the deadline must bound the whole probe, publish
    /// included. At 8646cc84 the publish was awaited before the deadline
    /// existed, so a stalled publish left the probe pending forever and
    /// the delivery input kept its previous verdict. This test targets the
    /// bounded exchange seam introduced by the fix; the paused-clock
    /// harness in the RC1 evidence reproduces the old unbounded shape.
    #[tokio::test(start_paused = true)]
    async fn a_blocked_publish_fails_within_the_probe_deadline() {
        struct BlockedPublish;

        impl ProbeChannel for BlockedPublish {
            async fn publish(&mut self, _payload: Vec<u8>) -> Result<(), String> {
                std::future::pending().await
            }

            async fn recv(&mut self) -> Option<Vec<u8>> {
                std::future::pending().await
            }
        }

        let started = tokio::time::Instant::now();
        let mut channel = BlockedPublish;
        let result = probe_exchange(&mut channel, probe_payload()).await;
        let Err(err) = result else {
            panic!("a publish that never completes must fail the probe");
        };
        assert!(
            err.contains(&format!("within {DELIVERY_PROBE_TIMEOUT_SECS}s")),
            "error names the deadline: {err}"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(DELIVERY_PROBE_TIMEOUT_SECS),
            "probe failed before its deadline: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(DELIVERY_PROBE_TIMEOUT_SECS + 1),
            "probe outlived its deadline: {elapsed:?}"
        );
    }

    /// A healthy exchange: the publish completes, a foreign probe's echo
    /// is skipped, and this daemon's own payload completes the probe.
    #[tokio::test(start_paused = true)]
    async fn an_immediate_echo_after_a_foreign_one_succeeds() {
        struct Echo {
            queued: VecDeque<Vec<u8>>,
        }

        impl ProbeChannel for Echo {
            async fn publish(&mut self, _payload: Vec<u8>) -> Result<(), String> {
                Ok(())
            }

            async fn recv(&mut self) -> Option<Vec<u8>> {
                self.queued.pop_front()
            }
        }

        let payload = probe_payload();
        let mut foreign = PROBE_MAGIC.to_vec();
        foreign.extend_from_slice(&[0xAA; 16]);
        let mut channel = Echo {
            queued: VecDeque::from(vec![foreign, payload.clone()]),
        };
        let result = probe_exchange(&mut channel, payload).await;
        assert_eq!(result, Ok(()));
    }

    /// A publish that completes but never echoes still fails at the
    /// deadline — the recv side of the exchange stays bounded too.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_receive_fails_at_the_deadline() {
        struct StalledRecv;

        impl ProbeChannel for StalledRecv {
            async fn publish(&mut self, _payload: Vec<u8>) -> Result<(), String> {
                Ok(())
            }

            async fn recv(&mut self) -> Option<Vec<u8>> {
                std::future::pending().await
            }
        }

        let started = tokio::time::Instant::now();
        let mut channel = StalledRecv;
        let result = probe_exchange(&mut channel, probe_payload()).await;
        assert!(result.is_err(), "a never-echoing exchange must fail");
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(DELIVERY_PROBE_TIMEOUT_SECS + 1));
    }

    /// The probe round-trips through a real (loopback-only, bootstrap-free,
    /// mDNS-off) agent: publish → PlumTree → decode → subscriber. This is
    /// the #288 scenario — serving fine, delivering nothing — caught.
    #[tokio::test]
    async fn delivery_probe_round_trips_on_a_loopback_agent() {
        let agent = loopback_agent().await;

        let snapshot = Arc::new(HealthSnapshot::default());
        let mut subscription = agent
            .subscribe(DELIVERY_PROBE_TOPIC)
            .await
            .expect("subscribe");
        probe_once(&agent, &mut subscription)
            .await
            .expect("probe round-trip within timeout");
        snapshot.record_probe(true, Some(1));
        assert_eq!(snapshot.probe_results(), (1, Some(true), Some(1)));
    }

    /// RC1 #1380 (P2): the first probe must run at the documented 10 s
    /// boundary (`docs/api-reference.md`), not at 10 + 30 s. At 8646cc84
    /// the startup sleep was followed by discarding the interval's
    /// immediate tick, so the first publish happened at 40 s. Checkpoints
    /// are one-sided (at least N probes by T) so a probe that wedges under
    /// the paused clock still resolves via its own deadline.
    #[tokio::test(start_paused = true)]
    async fn first_probe_runs_at_the_documented_10s_boundary() {
        let agent = Arc::new(loopback_agent().await);
        let snapshot = Arc::new(HealthSnapshot::default());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(run_delivery_probe(
            Arc::clone(&agent),
            Arc::clone(&snapshot),
            shutdown_rx,
        ));
        let started = tokio::time::Instant::now();

        // Before the startup delay: no probe.
        advance_past(
            started,
            Duration::from_secs(DELIVERY_PROBE_STARTUP_DELAY_SECS - 2),
        )
        .await;
        assert_eq!(
            snapshot.probe_results().0,
            0,
            "no probe before the startup delay"
        );

        // First probe at 10 s: even a wedged round trip resolves (success
        // or failure) once its 5 s deadline expires, so by 16 s exactly
        // one probe has been recorded. Fails at 8646cc84, where the first
        // probe only fires at 40 s.
        advance_past(
            started,
            Duration::from_secs(
                DELIVERY_PROBE_STARTUP_DELAY_SECS + DELIVERY_PROBE_TIMEOUT_SECS + 1,
            ),
        )
        .await;
        assert_eq!(
            snapshot.probe_results().0,
            1,
            "first probe must run at the 10 s boundary, not 10 s + one interval"
        );

        // 30 s cadence afterwards: the second probe fires at 40 s and
        // resolves by 45 s.
        advance_past(
            started,
            Duration::from_secs(
                DELIVERY_PROBE_STARTUP_DELAY_SECS
                    + DELIVERY_PROBE_INTERVAL_SECS
                    + DELIVERY_PROBE_TIMEOUT_SECS
                    + 1,
            ),
        )
        .await;
        assert_eq!(
            snapshot.probe_results().0,
            2,
            "30 s cadence after the first probe"
        );

        shutdown_tx.send(true).expect("shutdown send");
        tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("probe task exits on shutdown")
            .expect("probe task join");
    }
}
