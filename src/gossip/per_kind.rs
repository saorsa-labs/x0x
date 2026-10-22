//! Per-message-kind gossip efficiency counters (#1170 / Track E M1).
//!
//! This slice counts recv-pump bus pressure, local PlumTree delivery, and
//! outbound publish. Counters are cumulative for the process lifetime.
//! Diagnostics expose the open interval as `current` and the previous
//! finished interval as `last_completed`. A read stores that finished
//! interval and returns the same value to every later reader until the next
//! rotation replaces it.
//!
//! `delivered` and `published` are Eager PlumTree traffic only. Same-daemon
//! `local:` hand-offs never enter PlumTree and are not counted. Per-kind
//! verify CPU is not in this slice: the pinned saorsa-gossip 0.5.90 crate
//! has no per-kind verify meter, and x0x does not sample `stage_stats()`.
//!
//! The reporting clock starts when the meter is created, with a zero
//! baseline taken at that same moment. `window_secs` is the elapsed seconds
//! of that interval, including a fraction of a second. A non-empty interval
//! never reports `0`. Rotation and the baseline update share one lock.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use saorsa_gossip_types::MessageKind;
use serde::Serialize;

/// Default rolling window length.
pub const PER_KIND_ROLLING_WINDOW: Duration = Duration::from_secs(60);

/// Kind share of bus events (dispatched + dropped) that flags the verdict.
pub const PER_KIND_BUS_SHARE_THRESHOLD: f64 = 0.40;

/// Stable kind keys — same lowercase set as `inbound_by_topic` / `outbound_by_kind`.
pub const PER_KIND_NAMES: [&str; 9] = [
    "eager",
    "ihave",
    "iwant",
    "ping",
    "ack",
    "find",
    "presence",
    "anti_entropy",
    "shuffle",
];

fn kind_index(kind: MessageKind) -> usize {
    match kind {
        MessageKind::Eager => 0,
        MessageKind::IHave => 1,
        MessageKind::IWant => 2,
        MessageKind::Ping => 3,
        MessageKind::Ack => 4,
        MessageKind::Find => 5,
        MessageKind::Presence => 6,
        MessageKind::AntiEntropy => 7,
        MessageKind::Shuffle => 8,
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Elapsed seconds for a rate denominator.
///
/// Whole-second truncation made a non-empty sample inside the first second
/// report `0`, so Δcount / `window_secs` was undefined. A non-empty sample
/// uses sub-second precision and, if the clock delta is still zero, one
/// nanosecond.
fn reported_window_secs(elapsed: Duration, nonempty: bool) -> f64 {
    let secs = elapsed.as_secs_f64();
    if nonempty && secs == 0.0 {
        1e-9
    } else {
        secs
    }
}

/// x0x-owned cumulative counters (bus / delivered / published). Never cleared
/// on a diagnostics read.
#[derive(Debug, Default)]
struct KindSlot {
    bus_dispatched: AtomicU64,
    bus_dropped: AtomicU64,
    delivered: AtomicU64,
    published: AtomicU64,
}

impl KindSlot {
    fn load(&self) -> LocalKindCumulative {
        LocalKindCumulative {
            bus_dispatched: self.bus_dispatched.load(Ordering::Relaxed),
            bus_dropped: self.bus_dropped.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            published: self.published.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LocalKindCumulative {
    bus_dispatched: u64,
    bus_dropped: u64,
    delivered: u64,
    published: u64,
}

/// Clock, baseline, and the last finished interval. One lock covers all three
/// so two readers cannot both rotate, and neither reader consumes the
/// finished interval.
#[derive(Debug)]
struct WindowState {
    started: Instant,
    since_ts_ms: u64,
    local: [LocalKindCumulative; PER_KIND_NAMES.len()],
    last_completed: Option<PerKindInterval>,
}

/// Per-kind counter row for JSON.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct KindCountersSnapshot {
    pub bus_dispatched: u64,
    pub bus_dropped: u64,
    pub delivered: u64,
    pub published: u64,
}

impl KindCountersSnapshot {
    fn bus_events(self) -> u64 {
        self.bus_dispatched.saturating_add(self.bus_dropped)
    }

    fn is_empty(self) -> bool {
        self.bus_dispatched == 0
            && self.bus_dropped == 0
            && self.delivered == 0
            && self.published == 0
    }
}

/// M1 health verdict over one reporting interval.
///
/// The list is a share of bus events. A kind that carries most of the
/// traffic, commonly `eager`, is listed when its share is above the
/// threshold. That is a share signal, not a fault by itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PerKindHealthVerdict {
    /// Kinds whose bus-event share exceeds [`PER_KIND_BUS_SHARE_THRESHOLD`].
    pub bus_pressure_kinds: Vec<&'static str>,
    pub bus_share_threshold: f64,
}

/// One reporting interval: the open window, or a finished window kept for
/// every reader.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PerKindInterval {
    /// Unix milliseconds when this interval started.
    pub since_ts: u64,
    /// Elapsed seconds of this interval, including a fraction.
    ///
    /// A non-empty interval is never `0`, so Δcount / `window_secs` stays
    /// defined. An empty interval may be `0` when it has just opened.
    pub window_secs: f64,
    /// Non-empty kind rows only.
    pub kinds: BTreeMap<&'static str, KindCountersSnapshot>,
    pub health: PerKindHealthVerdict,
}

/// JSON snapshot of the rolling per-kind meter.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PerKindGossipSnapshot {
    /// Interval open at the time of this read. Counts are the delta since
    /// `current.since_ts`.
    pub current: PerKindInterval,
    /// Previous finished interval. Every reader receives this same value
    /// until the next rotation replaces it. `None` until the first rotation.
    pub last_completed: Option<PerKindInterval>,
}

fn saturating_local_delta(
    cur: LocalKindCumulative,
    base: LocalKindCumulative,
) -> LocalKindCumulative {
    LocalKindCumulative {
        bus_dispatched: cur.bus_dispatched.saturating_sub(base.bus_dispatched),
        bus_dropped: cur.bus_dropped.saturating_sub(base.bus_dropped),
        delivered: cur.delivered.saturating_sub(base.delivered),
        published: cur.published.saturating_sub(base.published),
    }
}

fn rows_from_delta(
    local: &[LocalKindCumulative; PER_KIND_NAMES.len()],
    baseline: &WindowState,
) -> [KindCountersSnapshot; PER_KIND_NAMES.len()] {
    let mut rows = [KindCountersSnapshot::default(); PER_KIND_NAMES.len()];
    for (index, row) in rows.iter_mut().enumerate() {
        let delta = saturating_local_delta(local[index], baseline.local[index]);
        *row = KindCountersSnapshot {
            bus_dispatched: delta.bus_dispatched,
            bus_dropped: delta.bus_dropped,
            delivered: delta.delivered,
            published: delta.published,
        };
    }
    rows
}

fn interval_from_rows(
    rows: &[KindCountersSnapshot; PER_KIND_NAMES.len()],
    since_ts: u64,
    elapsed: Duration,
    bus_share_threshold: f64,
) -> PerKindInterval {
    let mut kinds = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        if !row.is_empty() {
            kinds.insert(PER_KIND_NAMES[index], *row);
        }
    }
    let health = health_verdict(rows, bus_share_threshold);
    PerKindInterval {
        since_ts,
        window_secs: reported_window_secs(elapsed, !kinds.is_empty()),
        kinds,
        health,
    }
}

/// Process-wide per-kind efficiency meter.
#[derive(Debug)]
pub struct PerKindGossipCounters {
    slots: [KindSlot; PER_KIND_NAMES.len()],
    window_state: Mutex<WindowState>,
    window: Duration,
    bus_share_threshold: f64,
}

impl Default for PerKindGossipCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl PerKindGossipCounters {
    /// Build a meter with the shipped defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::with_window(PER_KIND_ROLLING_WINDOW)
    }

    /// Build a meter with a custom window (tests).
    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            slots: std::array::from_fn(|_| KindSlot::default()),
            window_state: Mutex::new(WindowState {
                started: Instant::now(),
                since_ts_ms: unix_ms_now().max(1),
                local: [LocalKindCumulative::default(); PER_KIND_NAMES.len()],
                last_completed: None,
            }),
            window,
            bus_share_threshold: PER_KIND_BUS_SHARE_THRESHOLD,
        }
    }

    fn load_local(&self) -> [LocalKindCumulative; PER_KIND_NAMES.len()] {
        std::array::from_fn(|i| self.slots[i].load())
    }

    fn lock_window(&self) -> MutexGuard<'_, WindowState> {
        self.window_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Move the open interval's start into the past. Tests use this to
    /// exercise a delayed first read and a slow poll without sleeping.
    #[cfg(test)]
    fn backdate(&self, by: Duration) {
        let mut state = self.lock_window();
        if let Some(started) = state.started.checked_sub(by) {
            state.started = started;
        }
        let millis = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        state.since_ts_ms = state.since_ts_ms.saturating_sub(millis).max(1);
    }

    /// Re-baseline the open interval at the current local cumulatives.
    ///
    /// Does not clear process-lifetime counters and does not drop
    /// `last_completed`.
    #[cfg(test)]
    fn rolling_reset(&self) {
        let local = self.load_local();
        let mut state = self.lock_window();
        state.local = local;
        state.since_ts_ms = unix_ms_now().max(1);
        state.started = Instant::now();
    }

    /// Process-lifetime bus dispatches. Does not read or rotate the window.
    ///
    /// Test-only. A rolling-window snapshot can rotate between two reads
    /// under plain `cargo test`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn lifetime_bus_dispatched(&self, kind: MessageKind) -> u64 {
        self.slots[kind_index(kind)]
            .bus_dispatched
            .load(Ordering::Relaxed)
    }

    /// Process-lifetime deliveries. Does not read or rotate the window.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn lifetime_delivered(&self, kind: MessageKind) -> u64 {
        self.slots[kind_index(kind)]
            .delivered
            .load(Ordering::Relaxed)
    }

    /// Process-lifetime publishes. Does not read or rotate the window.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn lifetime_published(&self, kind: MessageKind) -> u64 {
        self.slots[kind_index(kind)]
            .published
            .load(Ordering::Relaxed)
    }

    pub fn record_bus_dispatched(&self, kind: MessageKind) {
        self.slots[kind_index(kind)]
            .bus_dispatched
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bus_dropped(&self, kind: MessageKind) {
        self.slots[kind_index(kind)]
            .bus_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delivered(&self, kind: MessageKind) {
        self.slots[kind_index(kind)]
            .delivered
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_published(&self, kind: MessageKind) {
        self.slots[kind_index(kind)]
            .published
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the open interval and the retained finished interval.
    ///
    /// When the open interval has already run for at least the rotation
    /// target, this stores that whole interval in `last_completed` and opens
    /// a new `current`. Every later reader receives the same
    /// `last_completed` until the next rotation. `window_secs` is the elapsed
    /// time of each interval, which is longer than the rotation target when
    /// the reader was late. Reads never clear cumulative counters. The check
    /// and the baseline update hold one lock.
    #[must_use]
    pub fn snapshot(&self) -> PerKindGossipSnapshot {
        let mut state = self.lock_window();
        let local = self.load_local();
        let elapsed = state.started.elapsed();
        if elapsed >= self.window {
            let rows = rows_from_delta(&local, &state);
            let completed =
                interval_from_rows(&rows, state.since_ts_ms, elapsed, self.bus_share_threshold);
            state.local = local;
            state.since_ts_ms = unix_ms_now().max(1);
            state.started = Instant::now();
            state.last_completed = Some(completed);
            let current_elapsed = state.started.elapsed();
            let since_ts = state.since_ts_ms;
            let last_completed = state.last_completed.clone();
            drop(state);
            return PerKindGossipSnapshot {
                current: interval_from_rows(
                    &[KindCountersSnapshot::default(); PER_KIND_NAMES.len()],
                    since_ts,
                    current_elapsed,
                    self.bus_share_threshold,
                ),
                last_completed,
            };
        }
        let rows = rows_from_delta(&local, &state);
        let since_ts = state.since_ts_ms;
        let last_completed = state.last_completed.clone();
        drop(state);
        PerKindGossipSnapshot {
            current: interval_from_rows(&rows, since_ts, elapsed, self.bus_share_threshold),
            last_completed,
        }
    }
}

fn health_verdict(
    rows: &[KindCountersSnapshot; PER_KIND_NAMES.len()],
    bus_threshold: f64,
) -> PerKindHealthVerdict {
    let total_bus: u64 = rows.iter().map(|r| r.bus_events()).sum();
    let mut bus_pressure_kinds = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if total_bus > 0 {
            let share = row.bus_events() as f64 / total_bus as f64;
            if share > bus_threshold {
                bus_pressure_kinds.push(PER_KIND_NAMES[index]);
            }
        }
    }
    PerKindHealthVerdict {
        bus_pressure_kinds,
        bus_share_threshold: bus_threshold,
    }
}

/// Process-wide meter shared by the recv pump, pubsub delivery, and publish.
static PER_KIND_COUNTERS: LazyLock<PerKindGossipCounters> =
    LazyLock::new(PerKindGossipCounters::new);

/// Snapshot of the process-wide per-kind efficiency counters.
#[must_use]
pub fn per_kind_gossip_stats() -> PerKindGossipSnapshot {
    PER_KIND_COUNTERS.snapshot()
}

/// Process-wide meter for instrumentation call sites.
#[must_use]
pub fn per_kind_counters() -> &'static PerKindGossipCounters {
    &PER_KIND_COUNTERS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn rolling_reset_rebases_window_without_clearing_cumulatives() {
        let meter = PerKindGossipCounters::new();
        meter.record_bus_dispatched(MessageKind::IHave);
        meter.record_delivered(MessageKind::Eager);
        meter.record_published(MessageKind::Eager);
        let before = meter.snapshot();
        assert!(before.current.kinds.contains_key("eager"));
        assert!(before.current.since_ts > 0);
        assert_eq!(before.current.kinds["eager"].delivered, 1);
        assert!(before.last_completed.is_none());

        thread::sleep(Duration::from_millis(2));
        meter.rolling_reset();
        let after = meter.snapshot();
        assert!(
            after.current.kinds.is_empty(),
            "re-baseline at the current cumulatives must zero the delta: {after:?}"
        );
        assert!(
            after.current.since_ts >= before.current.since_ts,
            "since_ts must not go backwards"
        );
        meter.record_bus_dropped(MessageKind::IWant);
        let again = meter.snapshot();
        assert_eq!(again.current.kinds["iwant"].bus_dropped, 1);
        assert!(!again.current.kinds.contains_key("eager"));
        assert_eq!(meter.lifetime_delivered(MessageKind::Eager), 1);
    }

    #[test]
    fn independent_readers_both_see_the_completed_interval() {
        let meter = PerKindGossipCounters::with_window(Duration::from_millis(40));
        meter.record_bus_dispatched(MessageKind::Eager);
        let mid = meter.snapshot();
        assert!(mid.last_completed.is_none());
        assert_eq!(mid.current.kinds["eager"].bus_dispatched, 1);

        thread::sleep(Duration::from_millis(50));
        let first = meter.snapshot();
        let second = meter.snapshot();
        let finished = first
            .last_completed
            .as_ref()
            .expect("rotation retains the finished interval");
        assert_eq!(finished.kinds["eager"].bus_dispatched, 1);
        assert_eq!(finished.since_ts, mid.current.since_ts);
        assert!(
            finished.window_secs > 0.0,
            "a non-empty finished interval must keep a defined rate: {finished:?}"
        );
        assert_eq!(
            first.last_completed, second.last_completed,
            "a second reader must see the same finished interval: {second:?}"
        );
        assert!(
            first.current.kinds.is_empty() && second.current.kinds.is_empty(),
            "the open interval starts empty after rotation"
        );
    }

    #[test]
    fn health_verdict_flags_kind_over_bus_share() {
        let meter = PerKindGossipCounters::new();
        for _ in 0..9 {
            meter.record_bus_dispatched(MessageKind::Eager);
        }
        meter.record_bus_dropped(MessageKind::IWant);
        let snap = meter.snapshot();
        assert_eq!(snap.current.health.bus_pressure_kinds, vec!["eager"]);
    }

    #[test]
    fn concurrent_attribution_sums_exactly() {
        let meter = Arc::new(PerKindGossipCounters::new());
        let threads = 8usize;
        let per_thread = 100usize;
        let mut handles = Vec::new();
        for t in 0..threads {
            let m = Arc::clone(&meter);
            handles.push(thread::spawn(move || {
                for i in 0..per_thread {
                    if (t + i) % 2 == 0 {
                        m.record_bus_dispatched(MessageKind::Eager);
                    } else {
                        m.record_bus_dropped(MessageKind::IHave);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("join");
        }
        let total = (threads * per_thread) as u64;
        let snap = meter.snapshot();
        let eager_bus = snap
            .current
            .kinds
            .get("eager")
            .map(|r| r.bus_dispatched)
            .unwrap_or(0);
        let ihave_bus = snap
            .current
            .kinds
            .get("ihave")
            .map(|r| r.bus_dropped)
            .unwrap_or(0);
        assert_eq!(eager_bus + ihave_bus, total);
    }

    #[test]
    fn issue1170_snapshot_exposes_bus_delivery_and_publish() {
        let meter = PerKindGossipCounters::new();
        meter.record_bus_dispatched(MessageKind::Eager);
        meter.record_bus_dropped(MessageKind::IWant);
        meter.record_delivered(MessageKind::Eager);
        meter.record_published(MessageKind::Eager);
        let snap = meter.snapshot();
        assert!(snap.current.since_ts > 0);
        assert!(snap.last_completed.is_none());
        let eager = &snap.current.kinds["eager"];
        assert_eq!(eager.bus_dispatched, 1);
        assert_eq!(eager.delivered, 1);
        assert_eq!(eager.published, 1);
        assert_eq!(snap.current.kinds["iwant"].bus_dropped, 1);
        let json = serde_json::to_value(&snap).expect("serialize");
        assert!(json["current"]["since_ts"].as_u64().unwrap() > 0);
        assert!(json["current"]["window_secs"].as_f64().unwrap() > 0.0);
        assert!(json["last_completed"].is_null());
        for field in ["bus_dispatched", "bus_dropped", "delivered", "published"] {
            assert!(json["current"]["kinds"]["eager"][field].is_u64(), "{field}");
        }
        assert!(json["current"]["kinds"]["eager"].get("verify_ok").is_none());
        assert!(json["current"]["kinds"]["eager"]
            .get("verify_err")
            .is_none());
        assert!(json["current"]["health"]["bus_share_threshold"].is_f64());
        assert!(json["current"]["health"]
            .get("cpu_pressure_kinds")
            .is_none());
        assert!(json["current"]["health"]["bus_pressure_kinds"].is_array());
    }

    #[test]
    fn nonempty_sample_never_reports_zero_window() {
        assert_eq!(reported_window_secs(Duration::ZERO, false), 0.0);
        let sub_second = reported_window_secs(Duration::from_millis(1), true);
        assert!(sub_second > 0.0 && sub_second < 1.0);
        assert!(reported_window_secs(Duration::ZERO, true) > 0.0);

        let meter = PerKindGossipCounters::new();
        meter.record_bus_dispatched(MessageKind::Ping);
        let snap = meter.snapshot();
        assert!(snap.current.kinds.contains_key("ping"));
        assert!(
            snap.current.window_secs > 0.0,
            "events inside the first second must keep a defined rate: {snap:?}"
        );
    }

    #[test]
    fn delayed_first_read_aligns_timestamp_with_counts() {
        let meter = PerKindGossipCounters::new();
        meter.record_bus_dispatched(MessageKind::Eager);
        meter.backdate(Duration::from_secs(2 * 60 * 60));
        let snap = meter.snapshot();
        let finished = snap
            .last_completed
            .as_ref()
            .expect("a late first read rotates and retains the interval");
        assert_eq!(finished.kinds["eager"].bus_dispatched, 1);
        assert!(
            finished.window_secs >= 2.0 * 60.0 * 60.0,
            "a late first read must report the real elapsed seconds: {finished:?}"
        );
        let now = unix_ms_now();
        assert!(
            finished.since_ts + 60_000 < now,
            "since_ts must stay at the interval start: since={} now={now}",
            finished.since_ts
        );
        assert!(snap.current.kinds.is_empty());
    }

    #[test]
    fn slow_poll_retains_elapsed_interval_for_the_next_reader() {
        let meter = PerKindGossipCounters::with_window(Duration::from_secs(60));
        meter.record_bus_dropped(MessageKind::IWant);
        meter.backdate(Duration::from_secs(5 * 60));
        let completed = meter.snapshot();
        let finished = completed
            .last_completed
            .as_ref()
            .expect("slow poll retains the gap");
        assert_eq!(finished.kinds["iwant"].bus_dropped, 1);
        assert!(
            finished.window_secs >= 5.0 * 60.0,
            "slow poll must label the real gap: {finished:?}"
        );
        let next = meter.snapshot();
        assert_eq!(next.last_completed, completed.last_completed);
        assert!(
            next.current.kinds.is_empty(),
            "the open interval after the late read is new: {next:?}"
        );
        assert!(next.current.since_ts > finished.since_ts);
        assert!(next.current.window_secs < 60.0);
    }

    #[test]
    fn concurrent_readers_all_see_one_completed_interval() {
        let meter = Arc::new(PerKindGossipCounters::with_window(Duration::from_secs(60)));
        for _ in 0..100 {
            meter.record_bus_dispatched(MessageKind::Eager);
        }
        meter.backdate(Duration::from_secs(120));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = Arc::clone(&meter);
            handles.push(thread::spawn(move || m.snapshot()));
        }
        let snaps: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect();
        let finished = snaps[0].last_completed.clone().expect("retained");
        assert_eq!(finished.kinds["eager"].bus_dispatched, 100);
        assert!(
            snaps
                .iter()
                .all(|snap| snap.last_completed.as_ref() == Some(&finished)),
            "every reader must see the same finished interval: {snaps:?}"
        );
        assert!(snaps.iter().all(|snap| snap.current.kinds.is_empty()));
    }
}
