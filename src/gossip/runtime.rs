//! Gossip runtime orchestration.

use super::config::GossipConfig;
use super::pubsub::{PubSubManager, SigningContext};
use crate::error::NetworkResult;
use crate::network::NetworkNode;
use crate::presence::PresenceWrapper;
use saorsa_gossip_membership::{HyParViewMembership, MembershipConfig};
use saorsa_gossip_transport::GossipStreamType;
use saorsa_gossip_types::PeerId;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// X0X-0009 prototype: how often the adaptive worker supervisor samples
/// recv_pump telemetry and decides whether to scale workers up or down.
const PUBSUB_WORKER_SUPERVISOR_INTERVAL: Duration = Duration::from_secs(30);
/// X0X-0009 prototype: producer-rate-over-consumer-rate ratio above which
/// the supervisor considers the dispatcher saturated and scales up.
const PUBSUB_WORKER_SCALE_UP_RATIO: f64 = 1.10;
/// X0X-0009 prototype: queue depth fraction above which scale-up fires
/// regardless of producer/consumer ratio.
const PUBSUB_WORKER_SCALE_UP_DEPTH_FRAC: f64 = 0.50;
/// X0X-0009 prototype: queue depth fraction below which scale-down candidates
/// accumulate. Workers scale back after this is sustained for several intervals.
const PUBSUB_WORKER_SCALE_DOWN_DEPTH_FRAC: f64 = 0.05;
/// X0X-0009 prototype: number of consecutive idle supervisor intervals required
/// before a scale-down (hysteresis to prevent flapping).
const PUBSUB_WORKER_SCALE_DOWN_INTERVALS: u64 = 10;
/// X0X-0009 prototype: hard ceiling for adaptive scaling regardless of config.
const PUBSUB_WORKER_MAX: usize = 16;
/// X0X-0009 prototype: hard floor — at least one worker must always run.
const PUBSUB_WORKER_MIN: usize = 1;
/// X0X-0009 prototype: parked worker slots also poll the target at this
/// interval so a lost Notify wake cannot strand a reusable worker slot.
const PUBSUB_WORKER_PARK_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// X0X-0009 prototype: average per-message dispatch time (over the window)
/// above which the dispatcher is "slow" and we should scale up — even if the
/// queue has not filled yet. Catches the long-RTT case where each republish
/// is bounded at 750 ms by the per-peer timeout but workers spend most of
/// their time waiting on those timeouts.
const PUBSUB_WORKER_SCALE_UP_AVG_DISPATCH_MS: f64 = 1_000.0;
/// X0X-0009 prototype: dispatcher 30 s watchdog timeout rate above which we
/// scale up immediately. Even one event per 10 s is operationally significant.
const PUBSUB_WORKER_SCALE_UP_TIMEOUT_RATE: f64 = 0.10;
/// X0X-0009 prototype: per-peer republish timeout rate above which an
/// effective-worker calculation argues for more workers. Each timeout pins
/// one worker for `PER_PEER_REPUBLISH_TIMEOUT` (750 ms). At 3/s on 4 workers
/// that is ~56% of worker-time lost to timeouts.
const PUBSUB_WORKER_PER_PEER_TIMEOUT_BUDGET: f64 = 0.30;
/// X0X-0009 prototype: average per-message dispatch time below which the
/// supervisor considers the dispatcher comfortable and accumulates idle
/// intervals toward a scale-down.
const PUBSUB_WORKER_SCALE_DOWN_AVG_DISPATCH_MS: f64 = 200.0;

/// Maximum time to spend handling one inbound presence Bulk message.
///
/// Bulk has its own dispatcher, but a wedged presence handler must still be
/// bounded so future Bulk presence beacons continue to drain from the dedicated
/// Bulk receive queue.
const PRESENCE_MESSAGE_HANDLE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time to spend handling one inbound PubSub message.
///
/// This is a watchdog against a wedged handler, not a per-message latency
/// budget. The soak on 2026-04-30 (8h, 100 msg/s) produced ~5% of messages
/// hitting the previous 10 s cap exactly (max_elapsed_ms = 10004 ms). Those
/// are not stuck handlers — they are slow under cumulative load (ML-DSA-65
/// verification + subscriber fan-out under scheduler pressure with 8 peers).
/// `decode_to_delivery_drops` stayed at 0 across the soak, confirming the
/// timeouts did not lose messages, only marked them late. Raising the cap to
/// 30 s converts those false-positive watchdog fires into successful
/// completions; a real wedged handler still gets cancelled, just later.
const PUBSUB_MESSAGE_HANDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum time to spend handling one inbound membership message.
const MEMBERSHIP_MESSAGE_HANDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-stream dispatcher counters.
#[derive(Debug, Default)]
pub struct DispatchStreamStats {
    received: AtomicU64,
    completed: AtomicU64,
    timed_out: AtomicU64,
    max_elapsed_ms: AtomicU64,
    total_elapsed_ns: AtomicU64,
    over_1s_count: AtomicU64,
    over_5s_count: AtomicU64,
    over_30s_count: AtomicU64,
}

/// JSON-friendly snapshot of per-stream dispatcher counters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DispatchStreamStatsSnapshot {
    pub received: u64,
    pub completed: u64,
    pub timed_out: u64,
    pub max_elapsed_ms: u64,
    /// Cumulative handler wall-clock time, in nanoseconds.
    pub total_elapsed_ns: u64,
    /// Handler invocations that took at least 1 second.
    pub over_1s_count: u64,
    /// Handler invocations that took at least 5 seconds.
    pub over_5s_count: u64,
    /// Handler invocations that took at least 30 seconds.
    pub over_30s_count: u64,
}

impl DispatchStreamStats {
    fn record_received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }

    fn record_completed(&self, elapsed: Duration) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        self.record_elapsed(elapsed);
    }

    fn record_timed_out(&self, elapsed: Duration) {
        self.timed_out.fetch_add(1, Ordering::Relaxed);
        self.record_elapsed(elapsed);
    }

    fn record_elapsed(&self, elapsed: Duration) {
        self.max_elapsed_ms
            .fetch_max(duration_ms(elapsed), Ordering::Relaxed);
        self.total_elapsed_ns
            .fetch_add(duration_ns(elapsed), Ordering::Relaxed);
        if elapsed >= Duration::from_secs(1) {
            self.over_1s_count.fetch_add(1, Ordering::Relaxed);
        }
        if elapsed >= Duration::from_secs(5) {
            self.over_5s_count.fetch_add(1, Ordering::Relaxed);
        }
        if elapsed >= Duration::from_secs(30) {
            self.over_30s_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> DispatchStreamStatsSnapshot {
        DispatchStreamStatsSnapshot {
            received: self.received.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            timed_out: self.timed_out.load(Ordering::Relaxed),
            max_elapsed_ms: self.max_elapsed_ms.load(Ordering::Relaxed),
            total_elapsed_ns: self.total_elapsed_ns.load(Ordering::Relaxed),
            over_1s_count: self.over_1s_count.load(Ordering::Relaxed),
            over_5s_count: self.over_5s_count.load(Ordering::Relaxed),
            over_30s_count: self.over_30s_count.load(Ordering::Relaxed),
        }
    }
}

/// Per-stream receive queue depth counters.
#[derive(Debug, Default)]
struct DispatchQueueStats {
    latest: AtomicU64,
    max: AtomicU64,
    capacity: AtomicU64,
}

/// JSON-friendly snapshot of receive queue depth counters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DispatchQueueStatsSnapshot {
    pub latest: u64,
    pub max: u64,
    pub capacity: u64,
}

impl DispatchQueueStats {
    fn record(&self, depth: usize, capacity: usize) {
        let depth = usize_to_u64(depth);
        let capacity = usize_to_u64(capacity);
        self.latest.store(depth, Ordering::Relaxed);
        self.max.fetch_max(depth, Ordering::Relaxed);
        self.capacity.store(capacity, Ordering::Relaxed);
    }

    fn snapshot(&self) -> DispatchQueueStatsSnapshot {
        DispatchQueueStatsSnapshot {
            latest: self.latest.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
            capacity: self.capacity.load(Ordering::Relaxed),
        }
    }
}

/// Dispatcher counters for the inbound gossip receive pipeline.
#[derive(Debug, Default)]
pub struct GossipDispatchStats {
    pubsub: DispatchStreamStats,
    membership: DispatchStreamStats,
    bulk: DispatchStreamStats,
    pubsub_queue: DispatchQueueStats,
    membership_queue: DispatchQueueStats,
    bulk_queue: DispatchQueueStats,
    pubsub_workers: AtomicU64,
}

/// JSON-friendly snapshot of [`GossipDispatchStats`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct GossipDispatchStatsSnapshot {
    pub pubsub: DispatchStreamStatsSnapshot,
    pub membership: DispatchStreamStatsSnapshot,
    pub bulk: DispatchStreamStatsSnapshot,
    pub recv_depth: DispatchQueueDepthSnapshot,
    /// Configured number of concurrent PubSub workers draining recv_pubsub_rx.
    pub pubsub_workers: u64,
}

/// JSON-friendly snapshot of per-stream receive queue depths.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DispatchQueueDepthSnapshot {
    pub pubsub: DispatchQueueStatsSnapshot,
    pub membership: DispatchQueueStatsSnapshot,
    pub bulk: DispatchQueueStatsSnapshot,
}

impl GossipDispatchStats {
    fn new(pubsub_workers: usize) -> Self {
        Self {
            pubsub_workers: AtomicU64::new(usize_to_u64(pubsub_workers)),
            ..Default::default()
        }
    }

    fn record_dequeue(&self, stream_type: GossipStreamType, depth: usize, capacity: usize) {
        match stream_type {
            GossipStreamType::PubSub => self.pubsub_queue.record(depth, capacity),
            GossipStreamType::Membership => self.membership_queue.record(depth, capacity),
            GossipStreamType::Bulk => self.bulk_queue.record(depth, capacity),
        }
    }

    /// Snapshot dispatcher counters.
    #[must_use]
    pub fn snapshot(&self) -> GossipDispatchStatsSnapshot {
        GossipDispatchStatsSnapshot {
            pubsub: self.pubsub.snapshot(),
            membership: self.membership.snapshot(),
            bulk: self.bulk.snapshot(),
            recv_depth: DispatchQueueDepthSnapshot {
                pubsub: self.pubsub_queue.snapshot(),
                membership: self.membership_queue.snapshot(),
                bulk: self.bulk_queue.snapshot(),
            },
            pubsub_workers: self.pubsub_workers.load(Ordering::Relaxed),
        }
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .ok()
        .map_or(u64::MAX, |ms| ms)
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos())
        .ok()
        .map_or(u64::MAX, |ns| ns)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).ok().map_or(u64::MAX, |v| v)
}

/// The gossip runtime that manages all gossip components.
///
/// This orchestrates HyParView membership, SWIM failure detection,
/// and pub/sub messaging via the saorsa-gossip stack.
pub struct GossipRuntime {
    config: GossipConfig,
    network: Arc<NetworkNode>,
    membership: Arc<HyParViewMembership<NetworkNode>>,
    pubsub: Arc<PubSubManager>,
    peer_id: PeerId,
    presence: std::sync::Mutex<Option<Arc<PresenceWrapper>>>,
    dispatcher_handles: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    peer_sync_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    keepalive_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    dispatch_stats: Arc<GossipDispatchStats>,
}

impl std::fmt::Debug for GossipRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipRuntime")
            .field("config", &self.config)
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

async fn run_pubsub_dispatcher(
    worker_id: usize,
    target_count: Arc<AtomicUsize>,
    worker_notify: Arc<Notify>,
    network: Arc<NetworkNode>,
    pubsub: Arc<PubSubManager>,
    dispatch_stats: Arc<GossipDispatchStats>,
) {
    loop {
        // X0X-0009: every worker slot is spawned once and tracked for
        // shutdown. Slots above the current target park here, then wake when
        // the supervisor changes the target. Keeping stable worker IDs avoids
        // the scale-down/scale-up hole where a monotonic new id can be
        // immediately outside the target again.
        let worker_count = target_count.load(Ordering::Relaxed);
        if worker_id >= worker_count {
            tracing::debug!(
                worker_id,
                worker_count,
                "X0X-0009 PubSub dispatcher worker parked above target"
            );
            tokio::select! {
                _ = worker_notify.notified() => {}
                _ = tokio::time::sleep(PUBSUB_WORKER_PARK_POLL_INTERVAL) => {}
            }
            continue;
        }
        match network.receive_pubsub_message().await {
            Ok((peer, data)) => {
                let (recv_depth, recv_capacity) =
                    network.gossip_recv_queue_depth(GossipStreamType::PubSub);
                dispatch_stats.record_dequeue(GossipStreamType::PubSub, recv_depth, recv_capacity);
                dispatch_stats.pubsub.record_received();
                let bytes = data.len();
                let started = Instant::now();
                tracing::debug!(
                    from = %peer,
                    bytes,
                    recv_depth,
                    recv_capacity,
                    stream_type = "PubSub",
                    worker_id,
                    worker_count,
                    "[2/6 runtime] dispatching gossip message"
                );
                match tokio::time::timeout(
                    PUBSUB_MESSAGE_HANDLE_TIMEOUT,
                    pubsub.handle_incoming(peer, data),
                )
                .await
                {
                    Ok(()) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.pubsub.record_completed(elapsed);
                        tracing::debug!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            stream_type = "PubSub",
                            worker_id,
                            worker_count,
                            "[2/6 runtime] completed gossip message dispatch"
                        );
                    }
                    Err(_) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.pubsub.record_timed_out(elapsed);
                        tracing::warn!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            timeout_secs = PUBSUB_MESSAGE_HANDLE_TIMEOUT.as_secs(),
                            stream_type = "PubSub",
                            worker_id,
                            worker_count,
                            "Timed out handling gossip message"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!("PubSub message receive failed: {}", e);
                break;
            }
        }
    }
    tracing::info!(
        worker_id,
        target_count = target_count.load(Ordering::Relaxed),
        "Gossip PubSub dispatcher shut down"
    );
}

/// X0X-0009 prototype: a single sample of dispatcher health passed to the
/// supervisor decision function. Combines the cumulative `recv_pump` /
/// `dispatcher` / `pubsub_stages` snapshots into the windowed signals the
/// policy actually needs: depth fraction, producer/consumer ratio, and the
/// rates of slow-stage events over the supervisor interval (deltas computed
/// by the supervisor task from one tick to the next).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SupervisorSample {
    /// Producer rate over the supervisor interval (msg/s into the recv_pump).
    pub producer_per_sec: f64,
    /// Consumer rate over the supervisor interval (msg/s drained by the dispatcher).
    pub consumer_per_sec: f64,
    /// Most recent recv_pump queue depth.
    pub latest_depth: u64,
    /// recv_pump queue capacity.
    pub capacity: u64,
    /// Average per-message dispatch time over the supervisor interval (ms).
    /// Computed as `delta(total_elapsed_ns) / max(delta(completed), 1)`.
    pub recent_avg_dispatch_ms: f64,
    /// Dispatcher 30 s watchdog timeouts per second over the interval.
    pub recent_timeout_rate_per_sec: f64,
    /// `pubsub_stages.republish_per_peer_timeout` events per second over the
    /// interval. Each event represents one worker pinned for ~750 ms by a
    /// slow remote peer. The supervisor treats this as effective-worker loss.
    pub recent_per_peer_timeout_rate_per_sec: f64,
}

/// X0X-0009 prototype: pure decision function (no I/O, no time) that the
/// supervisor calls every interval. Returns `(next_target, next_idle_intervals)`.
///
/// Scale-up signals (any one triggers +1, capped at `PUBSUB_WORKER_MAX`):
/// 1. Queue depth ≥ 50% of capacity.
/// 2. Producer / consumer rate ≥ `PUBSUB_WORKER_SCALE_UP_RATIO` (1.10).
/// 3. Average dispatch time ≥ `PUBSUB_WORKER_SCALE_UP_AVG_DISPATCH_MS` (1 s).
/// 4. Dispatcher watchdog timeout rate ≥ `PUBSUB_WORKER_SCALE_UP_TIMEOUT_RATE`
///    (0.10/s; one event per 10 s).
/// 5. Effective-worker fraction lost to per-peer timeouts ≥
///    `PUBSUB_WORKER_PER_PEER_TIMEOUT_BUDGET` (30%).
///
/// Scale-down requires ALL of:
/// - depth < 5% of capacity
/// - producer ≤ consumer (or zero traffic)
/// - average dispatch time < `PUBSUB_WORKER_SCALE_DOWN_AVG_DISPATCH_MS` (200 ms)
/// - no recent dispatcher or per-peer timeouts
/// - sustained for `PUBSUB_WORKER_SCALE_DOWN_INTERVALS` (10) consecutive
///   supervisor intervals
///
/// Caller is responsible for applying the target change and notifying parked
/// worker slots. Worker tasks are stable and tracked for the runtime lifetime.
fn supervisor_decide_target(
    sample: SupervisorSample,
    current_target: usize,
    idle_intervals: u64,
) -> (usize, u64) {
    let depth_frac = if sample.capacity == 0 {
        0.0
    } else {
        (sample.latest_depth as f64) / (sample.capacity as f64)
    };
    let producer_over_consumer = if sample.consumer_per_sec > 0.0 {
        sample.producer_per_sec / sample.consumer_per_sec
    } else {
        0.0
    };
    // Effective-worker fraction lost to per-peer timeouts. Each per-peer
    // timeout pins one worker for `PER_PEER_REPUBLISH_TIMEOUT` (750 ms);
    // dividing by current_target gives the fraction of total worker-time
    // the slow-peer path is consuming.
    let per_peer_timeout_load = if current_target > 0 {
        sample.recent_per_peer_timeout_rate_per_sec * 0.75 / (current_target as f64)
    } else {
        0.0
    };

    let saturated = depth_frac >= PUBSUB_WORKER_SCALE_UP_DEPTH_FRAC
        || producer_over_consumer >= PUBSUB_WORKER_SCALE_UP_RATIO
        || sample.recent_avg_dispatch_ms >= PUBSUB_WORKER_SCALE_UP_AVG_DISPATCH_MS
        || sample.recent_timeout_rate_per_sec >= PUBSUB_WORKER_SCALE_UP_TIMEOUT_RATE
        || per_peer_timeout_load >= PUBSUB_WORKER_PER_PEER_TIMEOUT_BUDGET;
    if saturated {
        let next = (current_target + 1).min(PUBSUB_WORKER_MAX);
        return (next, 0);
    }
    let healthy = depth_frac < PUBSUB_WORKER_SCALE_DOWN_DEPTH_FRAC
        && (sample.consumer_per_sec == 0.0 || producer_over_consumer <= 1.0)
        && sample.recent_avg_dispatch_ms < PUBSUB_WORKER_SCALE_DOWN_AVG_DISPATCH_MS
        && sample.recent_timeout_rate_per_sec == 0.0
        && sample.recent_per_peer_timeout_rate_per_sec == 0.0;
    if healthy && current_target > PUBSUB_WORKER_MIN {
        let next_idle = idle_intervals + 1;
        if next_idle >= PUBSUB_WORKER_SCALE_DOWN_INTERVALS {
            return (current_target - 1, 0);
        }
        return (current_target, next_idle);
    }
    (current_target, idle_intervals)
}

/// X0X-0009 prototype: cumulative counters captured at the previous
/// supervisor tick so the next tick can compute deltas. All values come
/// from `network.recv_pump_diagnostics()`, `dispatch_stats.snapshot()`,
/// and `pubsub.stage_stats()` — no direct counter access needed here.
#[derive(Debug, Clone, Copy, Default)]
struct SupervisorPrevious {
    produced: u64,
    dequeued: u64,
    completed: u64,
    timed_out: u64,
    total_elapsed_ns: u64,
    per_peer_timeout: u64,
}

fn window_rate(current: u64, previous: u64, interval_secs: f64) -> f64 {
    let interval_secs = interval_secs.max(1.0);
    (current.saturating_sub(previous) as f64) / interval_secs
}

async fn run_pubsub_worker_supervisor(
    target_count: Arc<AtomicUsize>,
    worker_notify: Arc<Notify>,
    network: Arc<NetworkNode>,
    pubsub: Arc<PubSubManager>,
    dispatch_stats: Arc<GossipDispatchStats>,
) {
    let mut idle_intervals: u64 = 0;
    let mut previous = SupervisorPrevious::default();
    let interval_secs = PUBSUB_WORKER_SUPERVISOR_INTERVAL.as_secs_f64().max(1.0);
    let mut interval = tokio::time::interval(PUBSUB_WORKER_SUPERVISOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let recv_pump = network.recv_pump_diagnostics();
        let ps = &recv_pump.pubsub;
        let dispatcher = dispatch_stats.snapshot();
        let stages = pubsub.stage_stats();

        let cur_produced = ps.produced_total;
        let cur_dequeued = ps.dequeued_total;
        let cur_completed = dispatcher.pubsub.completed;
        let cur_timed_out = dispatcher.pubsub.timed_out;
        let cur_total_elapsed_ns = dispatcher.pubsub.total_elapsed_ns;
        let cur_per_peer_timeout = stages.republish_per_peer_timeout;

        let delta_completed = cur_completed.saturating_sub(previous.completed);
        let delta_timed_out = cur_timed_out.saturating_sub(previous.timed_out);
        let delta_total_elapsed_ns = cur_total_elapsed_ns.saturating_sub(previous.total_elapsed_ns);
        let delta_per_peer_timeout = cur_per_peer_timeout.saturating_sub(previous.per_peer_timeout);

        // Average dispatch time over the window: total elapsed ns divided by
        // messages completed in the window. If nothing completed (idle), the
        // metric is 0.0 — supervisor treats absence of work as healthy.
        let recent_avg_dispatch_ms = if delta_completed > 0 {
            (delta_total_elapsed_ns as f64 / delta_completed as f64) / 1_000_000.0
        } else {
            0.0
        };
        let recent_timeout_rate = (delta_timed_out as f64) / interval_secs;
        let recent_per_peer_timeout_rate = (delta_per_peer_timeout as f64) / interval_secs;

        let sample = SupervisorSample {
            producer_per_sec: window_rate(cur_produced, previous.produced, interval_secs),
            consumer_per_sec: window_rate(cur_dequeued, previous.dequeued, interval_secs),
            latest_depth: ps.latest_depth,
            capacity: ps.capacity,
            recent_avg_dispatch_ms,
            recent_timeout_rate_per_sec: recent_timeout_rate,
            recent_per_peer_timeout_rate_per_sec: recent_per_peer_timeout_rate,
        };

        previous = SupervisorPrevious {
            produced: cur_produced,
            dequeued: cur_dequeued,
            completed: cur_completed,
            timed_out: cur_timed_out,
            total_elapsed_ns: cur_total_elapsed_ns,
            per_peer_timeout: cur_per_peer_timeout,
        };

        let current_target = target_count.load(Ordering::Relaxed);
        let (next_target, next_idle) =
            supervisor_decide_target(sample, current_target, idle_intervals);
        idle_intervals = next_idle;
        if next_target == current_target {
            continue;
        }
        target_count.store(next_target, Ordering::Relaxed);
        worker_notify.notify_waiters();
        dispatch_stats
            .pubsub_workers
            .store(usize_to_u64(next_target), Ordering::Relaxed);
        tracing::info!(
            previous_target = current_target,
            next_target,
            producer_per_sec = sample.producer_per_sec,
            consumer_per_sec = sample.consumer_per_sec,
            latest_depth = sample.latest_depth,
            capacity = sample.capacity,
            recent_avg_dispatch_ms = sample.recent_avg_dispatch_ms,
            recent_timeout_rate_per_sec = sample.recent_timeout_rate_per_sec,
            recent_per_peer_timeout_rate_per_sec = sample.recent_per_peer_timeout_rate_per_sec,
            "X0X-0009 supervisor adjusted PubSub dispatcher target"
        );
    }
}

async fn run_membership_dispatcher(
    network: Arc<NetworkNode>,
    membership: Arc<HyParViewMembership<NetworkNode>>,
    dispatch_stats: Arc<GossipDispatchStats>,
) {
    loop {
        match network.receive_membership_message().await {
            Ok((peer, data)) => {
                let (recv_depth, recv_capacity) =
                    network.gossip_recv_queue_depth(GossipStreamType::Membership);
                dispatch_stats.record_dequeue(
                    GossipStreamType::Membership,
                    recv_depth,
                    recv_capacity,
                );
                dispatch_stats.membership.record_received();
                let bytes = data.len();
                let started = Instant::now();
                tracing::debug!(
                    from = %peer,
                    bytes,
                    recv_depth,
                    recv_capacity,
                    stream_type = "Membership",
                    "[2/6 runtime] dispatching gossip message"
                );
                match tokio::time::timeout(
                    MEMBERSHIP_MESSAGE_HANDLE_TIMEOUT,
                    membership.dispatch_message(peer, &data),
                )
                .await
                {
                    Ok(Ok(())) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.membership.record_completed(elapsed);
                        tracing::debug!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            stream_type = "Membership",
                            "[2/6 runtime] completed gossip message dispatch"
                        );
                    }
                    Ok(Err(e)) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.membership.record_completed(elapsed);
                        tracing::debug!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            stream_type = "Membership",
                            "Failed to handle membership message: {e}"
                        );
                    }
                    Err(_) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.membership.record_timed_out(elapsed);
                        tracing::warn!(
                            from = %peer,
                            bytes,
                            elapsed_ms = duration_ms(elapsed),
                            timeout_secs = MEMBERSHIP_MESSAGE_HANDLE_TIMEOUT.as_secs(),
                            stream_type = "Membership",
                            "Timed out handling gossip message"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::error!("Membership message receive failed: {}", e);
                break;
            }
        }
    }
    tracing::info!("Gossip Membership dispatcher shut down");
}

async fn run_bulk_dispatcher(
    network: Arc<NetworkNode>,
    presence: Option<Arc<PresenceWrapper>>,
    dispatch_stats: Arc<GossipDispatchStats>,
) {
    loop {
        match network.receive_bulk_message().await {
            Ok((peer, data)) => {
                let (recv_depth, recv_capacity) =
                    network.gossip_recv_queue_depth(GossipStreamType::Bulk);
                dispatch_stats.record_dequeue(GossipStreamType::Bulk, recv_depth, recv_capacity);
                dispatch_stats.bulk.record_received();
                let bytes = data.len();
                let started = Instant::now();
                tracing::debug!(
                    from = %peer,
                    bytes,
                    recv_depth,
                    recv_capacity,
                    stream_type = "Bulk",
                    "[2/6 runtime] dispatching gossip message"
                );
                if let Some(ref pm) = presence {
                    match tokio::time::timeout(
                        PRESENCE_MESSAGE_HANDLE_TIMEOUT,
                        pm.manager().handle_presence_message(&data),
                    )
                    .await
                    {
                        Ok(Ok(Some(source))) => {
                            let elapsed = started.elapsed();
                            dispatch_stats.bulk.record_completed(elapsed);
                            tracing::debug!(
                                from = %source,
                                peer = %peer,
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                stream_type = "Bulk",
                                "Handled presence beacon"
                            );
                        }
                        Ok(Ok(None)) => {
                            let elapsed = started.elapsed();
                            dispatch_stats.bulk.record_completed(elapsed);
                            tracing::debug!(
                                from = %peer,
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                stream_type = "Bulk",
                                "Presence message processed (no source)"
                            );
                        }
                        Ok(Err(e)) => {
                            let elapsed = started.elapsed();
                            dispatch_stats.bulk.record_completed(elapsed);
                            tracing::debug!(
                                from = %peer,
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                stream_type = "Bulk",
                                "Failed to handle presence message: {e}"
                            );
                        }
                        Err(_) => {
                            let elapsed = started.elapsed();
                            dispatch_stats.bulk.record_timed_out(elapsed);
                            tracing::warn!(
                                from = %peer,
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                timeout_secs = PRESENCE_MESSAGE_HANDLE_TIMEOUT.as_secs(),
                                stream_type = "Bulk",
                                "Timed out handling gossip message"
                            );
                        }
                    }
                } else {
                    let elapsed = started.elapsed();
                    dispatch_stats.bulk.record_completed(elapsed);
                    tracing::debug!(
                        from = %peer,
                        bytes,
                        elapsed_ms = duration_ms(elapsed),
                        stream_type = "Bulk",
                        "Ignoring Bulk stream (presence not configured)"
                    );
                }
            }
            Err(e) => {
                tracing::error!("Bulk message receive failed: {}", e);
                break;
            }
        }
    }
    tracing::info!("Gossip Bulk dispatcher shut down");
}

impl GossipRuntime {
    /// Create a new gossip runtime with the given configuration and network node.
    ///
    /// This initializes HyParView membership, SWIM failure detection, and
    /// pub/sub messaging. Call `start()` to begin gossip protocol operations.
    ///
    /// # Arguments
    ///
    /// * `config` - The gossip configuration
    /// * `network` - The network node (implements GossipTransport)
    ///
    /// # Returns
    ///
    /// A new `GossipRuntime` instance
    ///
    /// # Errors
    ///
    /// Returns an error if configuration validation fails.
    pub async fn new(
        config: GossipConfig,
        network: Arc<NetworkNode>,
        signing: Option<Arc<SigningContext>>,
    ) -> NetworkResult<Self> {
        config.validate().map_err(|e| {
            crate::error::NetworkError::NodeCreation(format!("invalid gossip config: {e}"))
        })?;

        let peer_id = saorsa_gossip_transport::GossipTransport::local_peer_id(network.as_ref());
        let membership_config = MembershipConfig::default();
        let membership = Arc::new(HyParViewMembership::new(
            peer_id,
            membership_config,
            Arc::clone(&network),
        ));
        let pubsub = Arc::new(PubSubManager::new(Arc::clone(&network), signing)?);
        let dispatch_workers = config.dispatch_workers;

        Ok(Self {
            config,
            network,
            membership,
            pubsub,
            peer_id,
            presence: std::sync::Mutex::new(None),
            dispatcher_handles: std::sync::Mutex::new(Vec::new()),
            peer_sync_handle: std::sync::Mutex::new(None),
            keepalive_handle: std::sync::Mutex::new(None),
            dispatch_stats: Arc::new(GossipDispatchStats::new(dispatch_workers)),
        })
    }

    /// Get the PubSubManager for this runtime.
    ///
    /// # Returns
    ///
    /// A reference to the `PubSubManager`.
    #[must_use]
    pub fn pubsub(&self) -> &Arc<PubSubManager> {
        &self.pubsub
    }

    /// Get the HyParView membership manager.
    ///
    /// # Returns
    ///
    /// A reference to the `HyParViewMembership`.
    #[must_use]
    pub fn membership(&self) -> &Arc<HyParViewMembership<NetworkNode>> {
        &self.membership
    }

    /// Get the local peer ID.
    ///
    /// # Returns
    ///
    /// The `PeerId` for this node.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Set the presence wrapper for Bulk stream dispatch.
    ///
    /// Must be called before `start()` so that the Bulk dispatcher can route
    /// `GossipStreamType::Bulk` messages to the presence manager.
    pub fn set_presence(&self, presence: Arc<PresenceWrapper>) {
        if let Ok(mut guard) = self.presence.lock() {
            *guard = Some(presence);
        }
    }

    /// Get the presence wrapper, if configured.
    #[must_use]
    pub fn presence(&self) -> Option<Arc<PresenceWrapper>> {
        self.presence.lock().ok().and_then(|guard| guard.clone())
    }

    /// Snapshot inbound dispatcher counters.
    #[must_use]
    pub fn dispatch_stats(&self) -> GossipDispatchStatsSnapshot {
        self.dispatch_stats.snapshot()
    }

    /// Start the gossip runtime.
    ///
    /// This initializes all gossip components and begins protocol operations.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub async fn start(&self) -> NetworkResult<()> {
        let network = Arc::clone(&self.network);
        let membership = Arc::clone(&self.membership);
        let pubsub = Arc::clone(&self.pubsub);
        let presence = self.presence();
        let dispatch_stats = Arc::clone(&self.dispatch_stats);

        // X0X-0009: spawn the full worker-slot ceiling once so every worker
        // is tracked by `dispatcher_handles` and can be aborted on shutdown.
        // `target_count` controls how many slots actively drain PubSub; the
        // rest park until the supervisor raises the target.
        let pubsub_worker_count = self.config.dispatch_workers;
        let target_count = Arc::new(AtomicUsize::new(pubsub_worker_count));
        let worker_notify = Arc::new(Notify::new());
        let mut pubsub_handles = Vec::with_capacity(PUBSUB_WORKER_MAX + 1);
        for worker_id in 0..PUBSUB_WORKER_MAX {
            pubsub_handles.push(tokio::spawn(run_pubsub_dispatcher(
                worker_id,
                Arc::clone(&target_count),
                Arc::clone(&worker_notify),
                Arc::clone(&network),
                Arc::clone(&pubsub),
                Arc::clone(&dispatch_stats),
            )));
        }
        let supervisor_handle = tokio::spawn(run_pubsub_worker_supervisor(
            Arc::clone(&target_count),
            Arc::clone(&worker_notify),
            Arc::clone(&network),
            Arc::clone(&pubsub),
            Arc::clone(&dispatch_stats),
        ));
        pubsub_handles.push(supervisor_handle);
        let membership_handle = tokio::spawn(run_membership_dispatcher(
            Arc::clone(&network),
            membership,
            Arc::clone(&dispatch_stats),
        ));
        let bulk_handle = tokio::spawn(run_bulk_dispatcher(
            Arc::clone(&network),
            presence,
            Arc::clone(&dispatch_stats),
        ));

        // Periodically refresh PlumTree topic peers with current connections.
        // This ensures newly connected peers (discovered via HyParView or
        // direct connection) are added to the eager set for existing topics.
        // Using 1-second interval to minimize the window where a newly-connected
        // peer could miss a published message (e.g. release manifest broadcast).
        let pubsub_refresh = Arc::clone(&self.pubsub);
        let peer_sync_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                pubsub_refresh.refresh_topic_peers().await;
            }
        });

        if let Ok(mut guard) = self.peer_sync_handle.lock() {
            *guard = Some(peer_sync_handle);
        }

        // Keepalive: send a SWIM Ping to every connected peer every 15 seconds.
        // This prevents QUIC idle timeout (30s) from dropping direct connections
        // that were established via auto-connect. Without this, connections with
        // no application traffic are closed by QUIC after 30s of inactivity.
        // See ADR-0002 for rationale.
        let keepalive_membership = Arc::clone(&self.membership);
        let keepalive_network = Arc::clone(&self.network);
        let keepalive_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;

                let peers = keepalive_network.connected_peers().await;
                for peer in peers {
                    let gossip_peer = PeerId::new(peer.0);
                    if let Err(e) = keepalive_membership.send_ping(gossip_peer).await {
                        tracing::debug!(
                            peer = %gossip_peer,
                            "Keepalive ping failed: {e}"
                        );
                    }
                }
            }
        });

        if let Ok(mut guard) = self.keepalive_handle.lock() {
            *guard = Some(keepalive_handle);
        }

        match self.dispatcher_handles.lock() {
            Ok(mut guard) => {
                guard.extend(pubsub_handles);
                guard.push(membership_handle);
                guard.push(bulk_handle);
            }
            Err(_) => {
                return Err(crate::error::NetworkError::NodeCreation(
                    "dispatcher handles lock poisoned".into(),
                ));
            }
        }
        Ok(())
    }

    /// Shutdown the gossip runtime.
    ///
    /// This gracefully stops all gossip components and cleans up resources.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&self) -> NetworkResult<()> {
        if let Ok(mut guard) = self.keepalive_handle.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.peer_sync_handle.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.dispatcher_handles.lock() {
            for handle in guard.drain(..) {
                handle.abort();
            }
        }
        Ok(())
    }

    /// Get the runtime configuration.
    #[must_use]
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// Get the network node.
    #[must_use]
    pub fn network(&self) -> &Arc<NetworkNode> {
        &self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkConfig;

    #[tokio::test]
    async fn test_runtime_creation() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(config, Arc::new(network), None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(
            runtime.config().active_view_size,
            GossipConfig::default().active_view_size
        );
    }

    #[tokio::test]
    async fn test_runtime_start_stop() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(config, Arc::new(network), None)
            .await
            .expect("Failed to create runtime");

        assert!(runtime.start().await.is_ok());
        assert!(runtime.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_accessors() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let network_arc = Arc::new(network);
        let runtime = GossipRuntime::new(config.clone(), network_arc.clone(), None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(runtime.config().active_view_size, config.active_view_size);
        assert!(Arc::ptr_eq(runtime.network(), &network_arc));
    }

    #[tokio::test]
    async fn test_runtime_peer_id() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let network_arc = Arc::new(network);
        let expected_peer_id =
            saorsa_gossip_transport::GossipTransport::local_peer_id(network_arc.as_ref());
        let runtime = GossipRuntime::new(config, network_arc, None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(runtime.peer_id(), expected_peer_id);
    }

    #[tokio::test]
    async fn test_runtime_invalid_config() {
        let config = GossipConfig {
            active_view_size: 0,
            ..Default::default()
        };
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let result = GossipRuntime::new(config, Arc::new(network), None).await;

        assert!(result.is_err());
    }

    #[test]
    fn test_dispatch_stats_record_per_stream_queue_depth() {
        let stats = GossipDispatchStats::default();

        stats.record_dequeue(GossipStreamType::PubSub, 42, 10_000);
        stats.record_dequeue(GossipStreamType::Membership, 7, 4_000);
        stats.record_dequeue(GossipStreamType::Bulk, 3, 4_000);
        stats.record_dequeue(GossipStreamType::PubSub, 4, 10_000);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.recv_depth.pubsub.latest, 4);
        assert_eq!(snapshot.recv_depth.pubsub.max, 42);
        assert_eq!(snapshot.recv_depth.pubsub.capacity, 10_000);
        assert_eq!(snapshot.recv_depth.membership.latest, 7);
        assert_eq!(snapshot.recv_depth.membership.max, 7);
        assert_eq!(snapshot.recv_depth.membership.capacity, 4_000);
        assert_eq!(snapshot.recv_depth.bulk.latest, 3);
        assert_eq!(snapshot.recv_depth.bulk.max, 3);
        assert_eq!(snapshot.recv_depth.bulk.capacity, 4_000);
    }

    #[test]
    fn test_dispatch_stats_record_elapsed_buckets_for_all_streams() {
        let stats = GossipDispatchStats::default();

        stats.pubsub.record_completed(Duration::from_millis(25));
        stats.membership.record_timed_out(Duration::from_secs(6));
        stats.bulk.record_timed_out(Duration::from_secs(31));

        let snapshot = stats.snapshot();
        assert!(snapshot.pubsub.total_elapsed_ns >= 25_000_000);
        assert_eq!(snapshot.pubsub.over_1s_count, 0);
        assert_eq!(snapshot.membership.over_1s_count, 1);
        assert_eq!(snapshot.membership.over_5s_count, 1);
        assert_eq!(snapshot.membership.over_30s_count, 0);
        assert_eq!(snapshot.bulk.over_1s_count, 1);
        assert_eq!(snapshot.bulk.over_5s_count, 1);
        assert_eq!(snapshot.bulk.over_30s_count, 1);
    }

    #[tokio::test]
    async fn test_runtime_records_configured_pubsub_workers() {
        let config = GossipConfig {
            dispatch_workers: 2,
            ..Default::default()
        };
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(config, Arc::new(network), None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(runtime.dispatch_stats().pubsub_workers, 2);
    }

    // ── X0X-0009 supervisor decision tests ──────────────────────────────
    // These exercise the pure decision function with synthetic telemetry
    // so we can prove the scale-up / scale-down / hysteresis logic without
    // spinning up a real network. The supervisor task itself only does
    // (a) sample telemetry, (b) compute deltas, (c) call this function,
    // (d) update the active-worker target and notify parked worker slots —
    // all the policy is here.

    /// Build a SupervisorSample with the given depth-related signals and
    /// "stage signals all zero" defaults. Used by older tests written before
    /// the per-stage windowed signals were added; the dispatch_avg/timeout
    /// values are 0.0 so those gates never fire.
    fn sample_depth_only(
        producer: f64,
        consumer: f64,
        depth: u64,
        capacity: u64,
    ) -> SupervisorSample {
        SupervisorSample {
            producer_per_sec: producer,
            consumer_per_sec: consumer,
            latest_depth: depth,
            capacity,
            recent_avg_dispatch_ms: 0.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.0,
        }
    }

    #[test]
    fn supervisor_window_rate_uses_counter_deltas_not_lifetime_rates() {
        assert_eq!(window_rate(1_300, 1_000, 30.0), 10.0);
        assert_eq!(window_rate(1_300, 1_300, 30.0), 0.0);
        assert_eq!(window_rate(1_000, 1_300, 30.0), 0.0);
    }

    #[test]
    fn supervisor_decide_target_scales_up_on_high_depth() {
        let (next, idle) =
            supervisor_decide_target(sample_depth_only(50.0, 50.0, 6_000, 10_000), 1, 0);
        assert_eq!(next, 2);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_scales_up_on_producer_overshoot() {
        let (next, idle) =
            supervisor_decide_target(sample_depth_only(80.0, 50.0, 100, 10_000), 2, 5);
        assert_eq!(next, 3);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_holds_when_balanced() {
        let (next, idle) =
            supervisor_decide_target(sample_depth_only(50.0, 50.0, 200, 10_000), 4, 3);
        assert_eq!(next, 4);
        assert_eq!(idle, 4);
    }

    #[test]
    fn supervisor_decide_target_scales_down_after_sustained_idle() {
        let (next, idle) =
            supervisor_decide_target(sample_depth_only(50.0, 50.0, 200, 10_000), 4, 9);
        assert_eq!(next, 3);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_never_drops_below_floor() {
        let (next, idle) = supervisor_decide_target(sample_depth_only(0.0, 0.0, 0, 10_000), 1, 9);
        assert_eq!(next, 1);
        assert_eq!(idle, 9);
    }

    #[test]
    fn supervisor_decide_target_caps_at_ceiling() {
        let (next, idle) =
            supervisor_decide_target(sample_depth_only(500.0, 50.0, 9_999, 10_000), 16, 0);
        assert_eq!(next, 16);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_handles_cold_start_zero_consumer() {
        let (next, _idle) =
            supervisor_decide_target(sample_depth_only(50.0, 0.0, 6_000, 10_000), 1, 0);
        assert_eq!(next, 2);
    }

    #[test]
    fn supervisor_decide_target_hysteresis_resets_on_resaturation() {
        let (next, idle) =
            supervisor_decide_target(sample_depth_only(80.0, 50.0, 100, 10_000), 4, 8);
        assert_eq!(next, 5);
        assert_eq!(idle, 0);
    }

    // ── New per-stage windowed-signal tests (the X0X-0009 iteration b
    //    additions: react to dispatcher slowness predictively, not just
    //    after the queue fills) ────────────────────────────────────────

    #[test]
    fn supervisor_decide_target_scales_up_on_slow_average_dispatch() {
        // Queue is empty, prod==cons — but each message is taking 1.2 s on
        // average. That's a clear sign the dispatcher is sweating. Scale up.
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 50,
            capacity: 10_000,
            recent_avg_dispatch_ms: 1_200.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 2, 4);
        assert_eq!(next, 3);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_scales_up_on_dispatcher_timeout_rate() {
        // Even one watchdog timeout per 10 s is operationally significant.
        let sample = SupervisorSample {
            producer_per_sec: 30.0,
            consumer_per_sec: 30.0,
            latest_depth: 100,
            capacity: 10_000,
            recent_avg_dispatch_ms: 50.0,
            recent_timeout_rate_per_sec: 0.10,
            recent_per_peer_timeout_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 1, 0);
        assert_eq!(next, 2);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_scales_up_on_per_peer_timeout_load() {
        // The long-RTT scenario: dispatcher looks fine on every other axis,
        // but per-peer timeouts are draining ~30% of worker-time. The
        // effective-worker calculation says we need more workers to keep
        // up. With 4 workers and 1.6/s timeouts × 0.75 s = 1.2 s of
        // worker-time per second = 30% load — exactly at the threshold.
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 200,
            capacity: 10_000,
            recent_avg_dispatch_ms: 100.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 1.6,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 5);
        assert_eq!(next, 5);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_low_per_peer_timeout_load_does_not_scale() {
        // Same shape as the per_peer_timeout_load test but only 0.2/s on 4
        // workers = ~3.75% effective load. Below the 30% scale-up budget.
        // No scale-up. The idle counter does NOT advance either, because
        // ANY per-peer timeout breaks the "healthy" predicate — the
        // supervisor refuses to shrink while peers are even occasionally
        // slow. This is the conservative default; users can lower it
        // explicitly if they want eager scale-down.
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 200,
            capacity: 10_000,
            recent_avg_dispatch_ms: 100.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.2,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 5);
        assert_eq!(next, 4);
        assert_eq!(
            idle, 5,
            "any per-peer timeout in the window blocks scale-down accumulation"
        );
    }

    #[test]
    fn supervisor_decide_target_scale_down_blocked_by_recent_per_peer_timeout() {
        // Depth low, prod==cons, dispatch fast — but ANY per-peer timeout
        // in the window is enough to block the scale-down. The supervisor
        // refuses to lose a worker while peers are even occasionally slow.
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 50,
            capacity: 10_000,
            recent_avg_dispatch_ms: 50.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.05,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 9);
        // No scale-down; idle counter does NOT advance because the
        // per-peer-timeout rate broke the "healthy" predicate.
        assert_eq!(next, 4);
        assert_eq!(idle, 9);
    }

    #[test]
    fn supervisor_decide_target_scale_down_blocked_by_slow_dispatch() {
        // Depth low, no timeouts, but average dispatch time is 250 ms (above
        // the 200 ms scale-down ceiling). Don't shrink — workers are working.
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 50,
            capacity: 10_000,
            recent_avg_dispatch_ms: 250.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 9);
        assert_eq!(next, 4);
        assert_eq!(idle, 9);
    }

    #[test]
    fn supervisor_decide_target_scale_down_after_sustained_full_health() {
        // All four "healthy" conditions hold for 10 consecutive intervals →
        // scale down by one. This is the precise inverse of the new gates.
        let sample = SupervisorSample {
            producer_per_sec: 30.0,
            consumer_per_sec: 30.0,
            latest_depth: 50,
            capacity: 10_000,
            recent_avg_dispatch_ms: 50.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 9);
        assert_eq!(next, 3);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_long_rtt_simulation_converges() {
        // Walk a 10-tick simulation that mimics the X0X-0008 sydney evidence:
        // producer 80/s, dispatch ~150 ms, per-peer timeouts at 2/s (= 50%
        // load on 4 workers, drops to 25% on 8). Start at 1, observe the
        // supervisor scale up monotonically until per_peer_timeout_load
        // falls below the 30% budget. Verifies the loop converges and does
        // not over-shoot.
        let mut target = 1usize;
        let mut idle = 0u64;
        for _ in 0..10 {
            // Per-peer timeout load = 2.0 * 0.75 / target = 1.5 / target.
            // At target=1: 1.50 > 0.30 → scale up
            // At target=2: 0.75 > 0.30 → scale up
            // At target=4: 0.375 > 0.30 → scale up
            // At target=5: 0.30 == 0.30 → scale up (>= threshold)
            // At target=6: 0.25 < 0.30 → no further scale
            let sample = SupervisorSample {
                producer_per_sec: 80.0,
                consumer_per_sec: 80.0,
                latest_depth: 100,
                capacity: 10_000,
                recent_avg_dispatch_ms: 150.0,
                recent_timeout_rate_per_sec: 0.0,
                recent_per_peer_timeout_rate_per_sec: 2.0,
            };
            let (next, next_idle) = supervisor_decide_target(sample, target, idle);
            target = next;
            idle = next_idle;
        }
        assert_eq!(
            target, 6,
            "supervisor should converge at target=6 where per-peer timeout load drops below 30%"
        );
    }

    #[tokio::test]
    async fn parked_worker_slot_reactivates_after_downscale_then_upscale() {
        // Regression for the monotonic-id bug: workers are stable slots now,
        // not disposable tasks. A slot above target parks, then the same slot
        // must become active again when the target rises back above its id.
        let target = Arc::new(AtomicUsize::new(2));
        let target_clone = Arc::clone(&target);
        let notify = Arc::new(Notify::new());
        let notify_clone = Arc::clone(&notify);
        let worker_id = 1usize;
        let active_count = Arc::new(AtomicUsize::new(0));
        let active_count_clone = Arc::clone(&active_count);
        let parked_count = Arc::new(AtomicUsize::new(0));
        let parked_count_clone = Arc::clone(&parked_count);
        let handle = tokio::spawn(async move {
            loop {
                let count = target_clone.load(Ordering::Relaxed);
                if worker_id >= count {
                    parked_count_clone.fetch_add(1, Ordering::Relaxed);
                    notify_clone.notified().await;
                    continue;
                }
                let active = active_count_clone.fetch_add(1, Ordering::Relaxed) + 1;
                if active >= 2 {
                    break;
                }
                notify_clone.notified().await;
            }
        });

        // Worker starts at id=1, target=2 and records one active pass.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(active_count.load(Ordering::Relaxed), 1);

        // Downscale to target=1 parks slot 1 instead of terminating it.
        target.store(1, Ordering::Relaxed);
        notify.notify_waiters();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(parked_count.load(Ordering::Relaxed), 1);
        assert!(
            !handle.is_finished(),
            "parked worker slot should stay tracked"
        );

        // Upscale to target=2 wakes and reuses slot 1.
        target.store(2, Ordering::Relaxed);
        notify.notify_waiters();
        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            result.is_ok(),
            "parked worker slot should reactivate within 200 ms after target rises"
        );
        assert_eq!(active_count.load(Ordering::Relaxed), 2);
    }
}
