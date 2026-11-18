//! Gossip runtime orchestration.

use super::config::GossipConfig;
use super::pubsub::{PubSubManager, SigningContext};
use crate::error::NetworkResult;
use crate::network::{NetworkNode, PubsubTopicPriorityResolver};
use crate::presence::PresenceWrapper;
use saorsa_gossip_membership::{HyParViewMembership, MembershipConfig};
use saorsa_gossip_transport::GossipStreamType;
use saorsa_gossip_types::PeerId;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

const PUBSUB_WORKER_SUPERVISOR_INTERVAL: Duration = Duration::from_secs(5);
const PUBSUB_WORKER_SCALE_UP_RATIO: f64 = 1.10;
const PUBSUB_WORKER_SCALE_UP_DEPTH_FRAC: f64 = 0.50;
const PUBSUB_WORKER_SCALE_DOWN_DEPTH_FRAC: f64 = 0.05;
const PUBSUB_WORKER_SCALE_DOWN_INTERVALS: u64 = 60;
const PUBSUB_WORKER_MAX: usize = 32;
const PUBSUB_WORKER_MIN: usize = 1;
const PUBSUB_WORKER_STARTUP_TARGET: usize = 8;
const PUBSUB_WORKER_SCALE_UP_HEADROOM: f64 = 1.25;
const PUBSUB_WORKER_PARK_POLL_INTERVAL: Duration = Duration::from_millis(100);
const PUBSUB_WORKER_SCALE_UP_AVG_DISPATCH_MS: f64 = 1_000.0;
const PUBSUB_WORKER_SCALE_UP_TIMEOUT_RATE: f64 = 0.10;
const PUBSUB_WORKER_PER_PEER_TIMEOUT_BUDGET: f64 = 0.30;
const PUBSUB_WORKER_SCALE_DOWN_AVG_DISPATCH_MS: f64 = 200.0;

const PRESENCE_MESSAGE_HANDLE_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const PUBSUB_MESSAGE_HANDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MEMBERSHIP_MESSAGE_HANDLE_TIMEOUT: Duration = Duration::from_secs(5);
const MEMBERSHIP_DISPATCH_WORKERS: usize = 4;

const DISPATCH_TIMEOUT_WARN_WINDOW: Duration = Duration::from_secs(30);

struct TimeoutWarnLimiter {
    window: Duration,
    last_emit: Option<Instant>,
    suppressed: u64,
}

impl TimeoutWarnLimiter {
    fn new(window: Duration) -> Self {
        Self {
            window,
            last_emit: None,
            suppressed: 0,
        }
    }

    fn observe(&mut self, now: Instant) -> Option<u64> {
        let due = match self.last_emit {
            None => true,
            Some(last) => now.duration_since(last) >= self.window,
        };
        if due {
            self.last_emit = Some(now);
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed += 1;
            None
        }
    }
}

/// Per-stream dispatcher counters.
#[derive(Debug, Default)]
pub struct DispatchStreamStats {
    received: AtomicU64,
    completed: AtomicU64,
    timed_out: AtomicU64,
    max_elapsed_ms: AtomicU64,
    total_elapsed_ns: AtomicU64,
    over_100ms_count: AtomicU64,
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
    /// Handler invocations that took at least 100 milliseconds.
    pub over_100ms_count: u64,
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
        if elapsed >= Duration::from_millis(100) {
            self.over_100ms_count.fetch_add(1, Ordering::Relaxed);
        }
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
            over_100ms_count: self.over_100ms_count.load(Ordering::Relaxed),
            over_1s_count: self.over_1s_count.load(Ordering::Relaxed),
            over_5s_count: self.over_5s_count.load(Ordering::Relaxed),
            over_30s_count: self.over_30s_count.load(Ordering::Relaxed),
        }
    }
}

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
    membership_workers: AtomicU64,
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
    /// Fixed number of concurrent membership workers draining recv_membership_rx.
    pub membership_workers: u64,
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
            membership_workers: AtomicU64::new(usize_to_u64(MEMBERSHIP_DISPATCH_WORKERS)),
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
            membership_workers: self.membership_workers.load(Ordering::Relaxed),
        }
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).ok().unwrap_or(u64::MAX)
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).ok().unwrap_or(u64::MAX)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).ok().unwrap_or(u64::MAX)
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
    let mut timeout_warns = TimeoutWarnLimiter::new(DISPATCH_TIMEOUT_WARN_WINDOW);
    loop {
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
        match network.receive_pubsub_message_with_session().await {
            Ok((peer, data, session)) => {
                let session = match session {
                    Some(session) if session.peer == peer => Some(session),
                    Some(mismatched) => {
                        tracing::warn!(
                            dequeued_peer = %peer,
                            token_peer = %mismatched.peer,
                            "dropping PubSub frame with peer-mismatched session token"
                        );
                        continue;
                    }
                    None => None,
                };
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
                    pubsub.handle_incoming(peer, session, data),
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
                        if let Some(suppressed) = timeout_warns.observe(Instant::now()) {
                            tracing::warn!(
                                from = %crate::logging::LogPeerId::from(peer),
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                timeout_secs = PUBSUB_MESSAGE_HANDLE_TIMEOUT.as_secs(),
                                stream_type = "PubSub",
                                worker_id,
                                worker_count,
                                suppressed_since_last_warn = suppressed,
                                "Timed out handling gossip message"
                            );
                        }
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

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SupervisorSample {
    pub producer_per_sec: f64,
    pub consumer_per_sec: f64,
    pub latest_depth: u64,
    pub capacity: u64,
    pub recent_avg_dispatch_ms: f64,
    pub recent_timeout_rate_per_sec: f64,
    pub recent_per_peer_timeout_rate_per_sec: f64,
    pub recent_drop_rate_per_sec: f64,
}

fn supervisor_decide_target(
    sample: SupervisorSample,
    current_target: usize,
    idle_intervals: u64,
) -> (usize, u64) {
    let current_target = current_target.clamp(PUBSUB_WORKER_MIN, PUBSUB_WORKER_MAX);
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
    let per_peer_timeout_load = if current_target > 0 {
        sample.recent_per_peer_timeout_rate_per_sec * 0.75 / (current_target as f64)
    } else {
        0.0
    };

    if sample.recent_drop_rate_per_sec > 0.0 || depth_frac >= PUBSUB_WORKER_SCALE_UP_DEPTH_FRAC {
        return (PUBSUB_WORKER_MAX, 0);
    }

    let mut next = current_target;
    if producer_over_consumer >= PUBSUB_WORKER_SCALE_UP_RATIO {
        let needed = ceil_worker_count(
            (current_target as f64) * producer_over_consumer * PUBSUB_WORKER_SCALE_UP_HEADROOM,
        );
        next = next.max(needed).max(current_target.saturating_add(1));
    }
    if sample.recent_avg_dispatch_ms >= PUBSUB_WORKER_SCALE_UP_AVG_DISPATCH_MS {
        next = next.max(current_target.saturating_add(1));
    }
    if sample.recent_timeout_rate_per_sec >= PUBSUB_WORKER_SCALE_UP_TIMEOUT_RATE {
        next = next.max(current_target.saturating_add(1));
    }
    if per_peer_timeout_load >= PUBSUB_WORKER_PER_PEER_TIMEOUT_BUDGET {
        let needed = ceil_worker_count(
            sample.recent_per_peer_timeout_rate_per_sec * 0.75
                / PUBSUB_WORKER_PER_PEER_TIMEOUT_BUDGET,
        );
        next = next.max(needed).max(current_target.saturating_add(1));
    }

    let next = next.min(PUBSUB_WORKER_MAX);
    if next > current_target {
        return (next, 0);
    }
    let healthy = depth_frac < PUBSUB_WORKER_SCALE_DOWN_DEPTH_FRAC
        && (sample.consumer_per_sec == 0.0 || producer_over_consumer <= 1.0)
        && sample.recent_avg_dispatch_ms < PUBSUB_WORKER_SCALE_DOWN_AVG_DISPATCH_MS
        && sample.recent_timeout_rate_per_sec == 0.0
        && sample.recent_per_peer_timeout_rate_per_sec == 0.0
        && sample.recent_drop_rate_per_sec == 0.0;
    if healthy && current_target > PUBSUB_WORKER_MIN {
        let next_idle = idle_intervals + 1;
        if next_idle >= PUBSUB_WORKER_SCALE_DOWN_INTERVALS {
            return (current_target - 1, 0);
        }
        return (current_target, next_idle);
    }
    (current_target, idle_intervals)
}

fn ceil_worker_count(value: f64) -> usize {
    if !value.is_finite() || value <= 0.0 {
        return PUBSUB_WORKER_MIN;
    }
    if value >= PUBSUB_WORKER_MAX as f64 {
        return PUBSUB_WORKER_MAX;
    }
    value.ceil() as usize
}

#[derive(Debug, Clone, Copy, Default)]
struct SupervisorPrevious {
    produced: u64,
    dequeued: u64,
    completed: u64,
    timed_out: u64,
    total_elapsed_ns: u64,
    per_peer_timeout: u64,
    dropped_full: u64,
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
        let cur_dropped_full = ps.dropped_full;

        let delta_completed = cur_completed.saturating_sub(previous.completed);
        let delta_timed_out = cur_timed_out.saturating_sub(previous.timed_out);
        let delta_total_elapsed_ns = cur_total_elapsed_ns.saturating_sub(previous.total_elapsed_ns);
        let delta_per_peer_timeout = cur_per_peer_timeout.saturating_sub(previous.per_peer_timeout);
        let delta_dropped_full = cur_dropped_full.saturating_sub(previous.dropped_full);

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
            recent_drop_rate_per_sec: (delta_dropped_full as f64) / interval_secs,
        };

        previous = SupervisorPrevious {
            produced: cur_produced,
            dequeued: cur_dequeued,
            completed: cur_completed,
            timed_out: cur_timed_out,
            total_elapsed_ns: cur_total_elapsed_ns,
            per_peer_timeout: cur_per_peer_timeout,
            dropped_full: cur_dropped_full,
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
            recent_drop_rate_per_sec = sample.recent_drop_rate_per_sec,
            "X0X-0009 supervisor adjusted PubSub dispatcher target"
        );
    }
}

async fn run_membership_dispatcher(
    worker_id: usize,
    network: Arc<NetworkNode>,
    membership: Arc<HyParViewMembership<NetworkNode>>,
    dispatch_stats: Arc<GossipDispatchStats>,
) {
    let mut timeout_warns = TimeoutWarnLimiter::new(DISPATCH_TIMEOUT_WARN_WINDOW);
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
                    worker_id,
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
                            worker_id,
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
                            worker_id,
                            "Failed to handle membership message: {e}"
                        );
                    }
                    Err(_) => {
                        let elapsed = started.elapsed();
                        dispatch_stats.membership.record_timed_out(elapsed);
                        if let Some(suppressed) = timeout_warns.observe(Instant::now()) {
                            tracing::warn!(
                                from = %crate::logging::LogPeerId::from(peer),
                                bytes,
                                elapsed_ms = duration_ms(elapsed),
                                timeout_secs = MEMBERSHIP_MESSAGE_HANDLE_TIMEOUT.as_secs(),
                                stream_type = "Membership",
                                worker_id,
                                suppressed_since_last_warn = suppressed,
                                "Timed out handling gossip message"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Membership message receive failed: {}", e);
                break;
            }
        }
    }
    tracing::info!(worker_id, "Gossip Membership dispatcher shut down");
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
                                from = %crate::logging::LogPeerId::from(peer),
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
    /// * `signing` - Required author signing context for pub/sub messages
    ///
    /// # Returns
    ///
    /// A new `GossipRuntime` instance
    ///
    /// # Errors
    ///
    /// Returns an error if configuration validation fails.
    ///
    /// An absent signer is rejected before any runtime can start:
    ///
    /// ```compile_fail,E0308
    /// # use std::sync::Arc;
    /// # use x0x::{gossip::{GossipConfig, GossipRuntime}, network::NetworkNode};
    /// # async fn without_signer(network: Arc<NetworkNode>) {
    /// let _ = GossipRuntime::new(GossipConfig::default(), network, None).await;
    /// # }
    /// ```
    pub async fn new(
        mut config: GossipConfig,
        network: Arc<NetworkNode>,
        signing: Arc<SigningContext>,
    ) -> NetworkResult<Self> {
        if let Some(warning) = config.normalize_egress_budget() {
            tracing::warn!("{warning}");
        }
        for warning in config.deprecation_warnings() {
            tracing::warn!("{warning}");
        }
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
        let oracle: Arc<dyn saorsa_gossip_types::PeerHealthOracle> = membership.swim_arc();
        let mut pubsub = PubSubManager::new_with_participation(
            Arc::clone(&network),
            signing,
            Some(oracle),
            config.resolved_participation(),
            config.resolved_participation_reason().to_string(),
        )?;
        pubsub.configure_egress(&config).await?;
        let pubsub = Arc::new(pubsub);
        let weak_pubsub = Arc::downgrade(&pubsub);
        network.set_pubsub_topic_priority_resolver(PubsubTopicPriorityResolver::new(
            move |topic| {
                weak_pubsub
                    .upgrade()
                    .map_or(saorsa_gossip_types::TopicPriority::Normal, |manager| {
                        manager.topic_priority_for(topic)
                    })
            },
        ));
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

        let pubsub_worker_count = self
            .config
            .dispatch_workers
            .clamp(PUBSUB_WORKER_STARTUP_TARGET, PUBSUB_WORKER_MAX);
        dispatch_stats
            .pubsub_workers
            .store(usize_to_u64(pubsub_worker_count), Ordering::Relaxed);
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
        let mut membership_handles = Vec::with_capacity(MEMBERSHIP_DISPATCH_WORKERS);
        for worker_id in 0..MEMBERSHIP_DISPATCH_WORKERS {
            membership_handles.push(tokio::spawn(run_membership_dispatcher(
                worker_id,
                Arc::clone(&network),
                Arc::clone(&membership),
                Arc::clone(&dispatch_stats),
            )));
        }
        let bulk_handle = tokio::spawn(run_bulk_dispatcher(
            Arc::clone(&network),
            presence,
            Arc::clone(&dispatch_stats),
        ));

        let pubsub_refresh = Arc::clone(&self.pubsub);
        let peer_sync_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                pubsub_refresh.sample_egress();
                pubsub_refresh.refresh_topic_peers().await;
            }
        });

        if let Ok(mut guard) = self.peer_sync_handle.lock() {
            *guard = Some(peer_sync_handle);
        }

        let keepalive_membership = Arc::clone(&self.membership);
        let keepalive_network = Arc::clone(&self.network);
        let keepalive_handle = tokio::spawn(async move {
            // saorsa-gossip admits never-connected peers to the HyParView active
            // view and never prunes them (x0x#1036).
            let mut stale_targets = super::stale_targets::StaleTargetTracker::default();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;

                let connected: std::collections::HashSet<PeerId> = keepalive_network
                    .send_ready_peers()
                    .await
                    .into_iter()
                    .map(|peer| PeerId::new(peer.0))
                    .collect();
                super::stale_targets::maintain_active_view(
                    keepalive_membership.as_ref(),
                    &mut stale_targets,
                    &connected,
                    Instant::now(),
                )
                .await;

                let peers = keepalive_network.gossip_plane_peers().await;
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
                guard.extend(membership_handles);
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
        let mut handles = Vec::new();
        for slot in [&self.keepalive_handle, &self.peer_sync_handle] {
            if let Some(handle) = slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                handles.push(handle);
            }
        }
        handles.extend(
            self.dispatcher_handles
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drain(..),
        );
        for handle in &handles {
            handle.abort();
        }
        // Abort only requests cancellation. Join before reporting completion
        // so dispatcher futures have dropped their in-flight transport sends.
        for handle in handles {
            let _ = handle.await;
        }
        self.pubsub.shutdown().await;
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

    #[test]
    fn first_timeout_always_warns_and_the_burst_is_folded() {
        let window = Duration::from_secs(30);
        let mut limiter = TimeoutWarnLimiter::new(window);
        let t0 = Instant::now();

        assert_eq!(
            limiter.observe(t0),
            Some(0),
            "an isolated timeout must warn immediately, with nothing suppressed"
        );
        for _ in 0..999 {
            assert_eq!(
                limiter.observe(t0),
                None,
                "the rest of the burst inside the window is suppressed"
            );
        }
        assert_eq!(
            limiter.observe(t0 + window),
            Some(999),
            "the next warn must report how many lines it stood in for, so the \
             storm stays visible without the write amplification"
        );
        assert_eq!(
            limiter.observe(t0 + window * 2),
            Some(0),
            "the suppressed tally resets after it is reported"
        );
    }

    fn test_network_config() -> NetworkConfig {
        NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..NetworkConfig::default()
        }
    }

    #[tokio::test]
    async fn test_runtime_creation() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(test_network_config(), None, None)
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(
            config,
            Arc::new(network),
            crate::gossip::pubsub::test_support::signing_context(),
        )
        .await
        .expect("Failed to create runtime");

        assert_eq!(
            runtime.config().leaf_max_eager_degree,
            GossipConfig::default().leaf_max_eager_degree
        );
    }

    #[tokio::test]
    async fn test_runtime_start_stop() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(test_network_config(), None, None)
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(
            config,
            Arc::new(network),
            crate::gossip::pubsub::test_support::signing_context(),
        )
        .await
        .expect("Failed to create runtime");

        assert!(runtime.start().await.is_ok());
        assert!(runtime.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_accessors() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(test_network_config(), None, None)
            .await
            .expect("Failed to create network");
        let network_arc = Arc::new(network);
        let runtime = GossipRuntime::new(
            config.clone(),
            network_arc.clone(),
            crate::gossip::pubsub::test_support::signing_context(),
        )
        .await
        .expect("Failed to create runtime");

        assert_eq!(
            runtime.config().leaf_max_eager_degree,
            config.leaf_max_eager_degree
        );
        assert!(Arc::ptr_eq(runtime.network(), &network_arc));
    }

    #[tokio::test]
    async fn test_runtime_peer_id() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(test_network_config(), None, None)
            .await
            .expect("Failed to create network");
        let network_arc = Arc::new(network);
        let expected_peer_id =
            saorsa_gossip_transport::GossipTransport::local_peer_id(network_arc.as_ref());
        let runtime = GossipRuntime::new(
            config,
            network_arc,
            crate::gossip::pubsub::test_support::signing_context(),
        )
        .await
        .expect("Failed to create runtime");

        assert_eq!(runtime.peer_id(), expected_peer_id);
    }

    #[tokio::test]
    async fn test_runtime_invalid_config() {
        let config = GossipConfig {
            dispatch_workers: 0,
            ..Default::default()
        };
        let network = NetworkNode::new(test_network_config(), None, None)
            .await
            .expect("Failed to create network");
        let result = GossipRuntime::new(
            config,
            Arc::new(network),
            crate::gossip::pubsub::test_support::signing_context(),
        )
        .await;

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
        stats
            .membership
            .record_completed(Duration::from_millis(100));

        let snapshot = stats.snapshot();
        assert!(snapshot.pubsub.total_elapsed_ns >= 25_000_000);
        assert_eq!(snapshot.pubsub.over_100ms_count, 0);
        assert_eq!(snapshot.membership.over_100ms_count, 2);
        assert_eq!(snapshot.bulk.over_100ms_count, 1);
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
        let network = NetworkNode::new(test_network_config(), None, None)
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(
            config,
            Arc::new(network),
            crate::gossip::pubsub::test_support::signing_context(),
        )
        .await
        .expect("Failed to create runtime");

        assert_eq!(runtime.dispatch_stats().pubsub_workers, 2);
        assert_eq!(
            runtime.dispatch_stats().membership_workers,
            usize_to_u64(MEMBERSHIP_DISPATCH_WORKERS)
        );
    }

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
            recent_drop_rate_per_sec: 0.0,
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
        assert_eq!(next, 32);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_scales_up_on_producer_overshoot() {
        let (next, idle) =
            supervisor_decide_target(sample_depth_only(80.0, 50.0, 100, 10_000), 2, 5);
        assert_eq!(next, 4);
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
            supervisor_decide_target(sample_depth_only(50.0, 50.0, 200, 10_000), 4, 59);
        assert_eq!(next, 3);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_never_drops_below_floor() {
        let (next, idle) = supervisor_decide_target(sample_depth_only(0.0, 0.0, 0, 10_000), 1, 59);
        assert_eq!(next, 1);
        assert_eq!(idle, 59);
    }

    #[test]
    fn supervisor_decide_target_caps_at_ceiling() {
        let (next, idle) =
            supervisor_decide_target(sample_depth_only(500.0, 50.0, 9_999, 10_000), 32, 0);
        assert_eq!(next, 32);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_handles_cold_start_zero_consumer() {
        let (next, _idle) =
            supervisor_decide_target(sample_depth_only(50.0, 0.0, 6_000, 10_000), 1, 0);
        assert_eq!(next, 32);
    }

    #[test]
    fn supervisor_decide_target_hysteresis_resets_on_resaturation() {
        let (next, idle) =
            supervisor_decide_target(sample_depth_only(80.0, 50.0, 100, 10_000), 4, 8);
        assert_eq!(next, 8);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_scales_up_on_slow_average_dispatch() {
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 50,
            capacity: 10_000,
            recent_avg_dispatch_ms: 1_200.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.0,
            recent_drop_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 2, 4);
        assert_eq!(next, 3);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_scales_up_on_dispatcher_timeout_rate() {
        let sample = SupervisorSample {
            producer_per_sec: 30.0,
            consumer_per_sec: 30.0,
            latest_depth: 100,
            capacity: 10_000,
            recent_avg_dispatch_ms: 50.0,
            recent_timeout_rate_per_sec: 0.10,
            recent_per_peer_timeout_rate_per_sec: 0.0,
            recent_drop_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 1, 0);
        assert_eq!(next, 2);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_scales_up_on_per_peer_timeout_load() {
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 200,
            capacity: 10_000,
            recent_avg_dispatch_ms: 100.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 1.6,
            recent_drop_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 5);
        assert_eq!(next, 5);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_low_per_peer_timeout_load_does_not_scale() {
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 200,
            capacity: 10_000,
            recent_avg_dispatch_ms: 100.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.2,
            recent_drop_rate_per_sec: 0.0,
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
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 50,
            capacity: 10_000,
            recent_avg_dispatch_ms: 50.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.05,
            recent_drop_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 9);
        assert_eq!(next, 4);
        assert_eq!(idle, 9);
    }

    #[test]
    fn supervisor_decide_target_scale_down_blocked_by_slow_dispatch() {
        let sample = SupervisorSample {
            producer_per_sec: 50.0,
            consumer_per_sec: 50.0,
            latest_depth: 50,
            capacity: 10_000,
            recent_avg_dispatch_ms: 250.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.0,
            recent_drop_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 9);
        assert_eq!(next, 4);
        assert_eq!(idle, 9);
    }

    #[test]
    fn supervisor_decide_target_scale_down_after_sustained_full_health() {
        let sample = SupervisorSample {
            producer_per_sec: 30.0,
            consumer_per_sec: 30.0,
            latest_depth: 50,
            capacity: 10_000,
            recent_avg_dispatch_ms: 50.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.0,
            recent_drop_rate_per_sec: 0.0,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 59);
        assert_eq!(next, 3);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_jumps_to_ceiling_on_recv_pump_drops() {
        let sample = SupervisorSample {
            producer_per_sec: 30.0,
            consumer_per_sec: 30.0,
            latest_depth: 50,
            capacity: 10_000,
            recent_avg_dispatch_ms: 50.0,
            recent_timeout_rate_per_sec: 0.0,
            recent_per_peer_timeout_rate_per_sec: 0.0,
            recent_drop_rate_per_sec: 0.1,
        };
        let (next, idle) = supervisor_decide_target(sample, 4, 12);
        assert_eq!(next, 32);
        assert_eq!(idle, 0);
    }

    #[test]
    fn supervisor_decide_target_long_rtt_simulation_converges() {
        let mut target = 1usize;
        let mut idle = 0u64;
        for _ in 0..10 {
            let sample = SupervisorSample {
                producer_per_sec: 80.0,
                consumer_per_sec: 80.0,
                latest_depth: 100,
                capacity: 10_000,
                recent_avg_dispatch_ms: 150.0,
                recent_timeout_rate_per_sec: 0.0,
                recent_per_peer_timeout_rate_per_sec: 2.0,
                recent_drop_rate_per_sec: 0.0,
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

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(active_count.load(Ordering::Relaxed), 1);

        target.store(1, Ordering::Relaxed);
        notify.notify_waiters();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(parked_count.load(Ordering::Relaxed), 1);
        assert!(
            !handle.is_finished(),
            "parked worker slot should stay tracked"
        );

        target.store(2, Ordering::Relaxed);
        notify.notify_waiters();
        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            result.is_ok(),
            "parked worker slot should reactivate within 200 ms after target rises"
        );
        assert_eq!(active_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn duration_ms_converts_correctly() {
        assert_eq!(duration_ms(Duration::from_secs(1)), 1000);
        assert_eq!(duration_ms(Duration::from_millis(500)), 500);
        assert_eq!(duration_ms(Duration::from_nanos(1_000_000)), 1);
        assert_eq!(duration_ms(Duration::ZERO), 0);
    }

    #[test]
    fn duration_ns_converts_correctly() {
        assert_eq!(duration_ns(Duration::from_secs(1)), 1_000_000_000);
        assert_eq!(duration_ns(Duration::from_millis(1)), 1_000_000);
        assert_eq!(duration_ns(Duration::from_nanos(500)), 500);
        assert_eq!(duration_ns(Duration::ZERO), 0);
    }

    #[test]
    fn usize_to_u64_converts_correctly() {
        assert_eq!(usize_to_u64(0), 0);
        assert_eq!(usize_to_u64(42), 42);
        assert_eq!(usize_to_u64(usize::MAX), u64::MAX);
    }

    #[test]
    fn ceil_worker_count_rounds_up() {
        assert_eq!(ceil_worker_count(0.0), 1, "clamped to PUBSUB_WORKER_MIN");
        assert_eq!(ceil_worker_count(0.5), 1);
        assert_eq!(ceil_worker_count(1.0), 1);
        assert_eq!(ceil_worker_count(1.5), 2);
        assert_eq!(ceil_worker_count(10.1), 11);
    }

    #[test]
    fn window_rate_computes_correctly() {
        assert!((window_rate(100u64, 0u64, 10.0) - 10.0).abs() < 0.001);
        assert_eq!(window_rate(0u64, 0u64, 10.0), 0.0);
        assert!((window_rate(50u64, 0u64, 5.0) - 10.0).abs() < 0.001);
    }

    #[test]
    fn window_rate_handles_zero_interval() {
        let rate = window_rate(100u64, 0u64, 0.0);
        assert!(rate.is_finite());
    }

    #[test]
    fn window_rate_handles_no_previous() {
        assert_eq!(window_rate(50u64, 50u64, 10.0), 0.0);
    }

    const STALL_PEER_DATA_CHANNEL_CAPACITY: usize = 64;
    const STALL_PEER_UNI_CREDIT: u32 = 8;
    const STALL_BURST_PINGS: usize = 400;
    const STALL_WINDOW: Duration = Duration::from_secs(12);

    fn membership_swim_ping_frame() -> Vec<u8> {
        let wrapped = saorsa_gossip_membership::MembershipProtocolMessage::Swim(
            saorsa_gossip_membership::SwimMessage::Ping,
        );
        let mut frame = vec![GossipStreamType::Membership.to_byte()];
        frame.extend_from_slice(&postcard::to_allocvec(&wrapped).expect("serialize SWIM Ping"));
        frame
    }

    async fn spawn_stalled_peer() -> (ant_quic::Node, std::net::SocketAddr) {
        let config = ant_quic::NodeConfig::builder()
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("loopback addr literal"),
            )
            .mdns_enabled(false)
            .port_mapping_enabled(false)
            .data_channel_capacity(STALL_PEER_DATA_CHANNEL_CAPACITY)
            .max_concurrent_uni_streams(STALL_PEER_UNI_CREDIT)
            .build();
        let node = ant_quic::Node::with_config(config)
            .await
            .expect("stalled peer node");
        let addr = node.local_addr().expect("stalled peer bound addr");
        // A raw ant-quic node registers inbound connections only when the
        // application drives `accept()`.
        let accept_driver = node.clone();
        tokio::spawn(async move { while accept_driver.accept().await.is_some() {} });
        (node, addr)
    }

    async fn stalled_peer_view_of_sut(stalled: &ant_quic::Node) -> ant_quic::PeerId {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(conn) = stalled.connected_peers().await.into_iter().next() {
                return conn.peer_id;
            }
            assert!(Instant::now() < deadline, "stalled peer never saw the SUT");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stalled_remote_peer_cannot_pin_membership_dispatch() {
        let measure_only = std::env::var("X0X_1395_MEASURE_ONLY").is_ok();

        let network = Arc::new(
            NetworkNode::new(test_network_config(), None, None)
                .await
                .expect("SUT network node"),
        );
        let runtime = GossipRuntime::new(
            GossipConfig::default(),
            Arc::clone(&network),
            crate::gossip::pubsub::test_support::signing_context(),
        )
        .await
        .expect("SUT runtime");
        runtime.start().await.expect("SUT runtime started");

        let (stalled, stalled_addr) = spawn_stalled_peer().await;
        network
            .connect_addr(stalled_addr)
            .await
            .expect("dial the stalled peer");
        let sut_peer_on_stalled = stalled_peer_view_of_sut(&stalled).await;
        let ping = membership_swim_ping_frame();

        for _ in 0..10 {
            let _ = stalled.send(&sut_peer_on_stalled, &ping).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let m = &runtime.dispatch_stats().membership;
            if m.received >= 10 && m.completed + m.timed_out >= 10 {
                break;
            }
            assert!(Instant::now() < deadline, "warm-up pings never dispatched");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let warm = runtime.dispatch_stats().membership;
        assert_eq!(warm.timed_out, 0, "warm-up must be timeout-free");
        println!(
            "[1395] warmup received={} completed={} timed_out={} max_elapsed_ms={}",
            warm.received, warm.completed, warm.timed_out, warm.max_elapsed_ms
        );

        for _ in 0..STALL_BURST_PINGS {
            let _ = stalled.send(&sut_peer_on_stalled, &ping).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let window_start = runtime.dispatch_stats().membership;
        println!(
            "[1395] window_start received={} completed={} timed_out={} max_elapsed_ms={}",
            window_start.received,
            window_start.completed,
            window_start.timed_out,
            window_start.max_elapsed_ms
        );

        let started = Instant::now();
        let mut next_sample = started;
        let mut next_ping = started;
        while started.elapsed() < STALL_WINDOW {
            let now = Instant::now();
            if now >= next_ping {
                let _ = stalled.send(&sut_peer_on_stalled, &ping).await;
                next_ping += Duration::from_millis(100);
            }
            if now >= next_sample {
                let m = runtime.dispatch_stats().membership;
                println!("[1395] t={:>2}s received={} completed={} timed_out={} over_1s={} max_elapsed_ms={}",
                    started.elapsed().as_secs(), m.received, m.completed, m.timed_out, m.over_1s_count, m.max_elapsed_ms);
                next_sample += Duration::from_secs(1);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;

        let window_end = runtime.dispatch_stats().membership;
        let d_received = window_end.received.saturating_sub(window_start.received);
        let d_timed_out = window_end.timed_out.saturating_sub(window_start.timed_out);
        let d_over_100ms = window_end
            .over_100ms_count
            .saturating_sub(window_start.over_100ms_count);
        let ratio = if d_received > 0 {
            d_timed_out as f64 / d_received as f64
        } else {
            f64::INFINITY
        };
        println!("[1395] SUMMARY d_received={} d_timed_out={} d_over_100ms={} ratio={:.4} max_elapsed_ms={}",
            d_received, d_timed_out, d_over_100ms, ratio, window_end.max_elapsed_ms);

        if !measure_only {
            assert!(
                d_received >= 8,
                "stall window dispatched only {d_received} messages; the harness did not exercise the lane"
            );
            assert!(
                d_over_100ms * 2 >= d_received,
                "stall never engaged: {d_received} dispatched but only {d_over_100ms} took the slow egress path"
            );
            assert!(
                ratio < 0.005,
                "membership-lane timeout ratio {ratio:.4} exceeds the 0.5% #1395 bar ({d_timed_out}/{d_received})"
            );
        }

        runtime.shutdown().await.expect("SUT runtime shutdown");
        stalled.shutdown().await;
    }
}
