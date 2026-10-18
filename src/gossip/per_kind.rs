//! Per-message-kind gossip efficiency counters (#1170 / Track E M1).
//!
//! Four signals per [`MessageKind`]: verify cost, recv-pump bus pressure,
//! local delivery, and outbound publish. Counters are cumulative for the
//! process lifetime; diagnostics expose a rolling window as a delta of those
//! cumulatives. When the window elapses, the previous completed interval is
//! retained so a slow poller still sees the measurement.
//!
//! Outer-frame verify ok/err comes from saorsa-gossip's native
//! [`saorsa_gossip_pubsub::PlumtreePubSub::verify_by_kind_stats`] (cumulative,
//! never reset by a read). x0x does not re-count verifies on the receive path.
//! `delivered` and `published` are Eager-only (local subscriber hand-off and
//! local mesh publish). The gossip `failures` counter counts ML-DSA signature
//! verify failures only; it excludes ADR-012 payload-hash mismatches and
//! RejectV1 policy rejections.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use saorsa_gossip_pubsub::{KindVerifyCounters, PerKindVerifyMeterSnapshot};
use saorsa_gossip_types::MessageKind;
use serde::Serialize;

/// Default rolling window length.
pub const PER_KIND_ROLLING_WINDOW: Duration = Duration::from_secs(60);

/// Kind share of verify CPU (total_ns) that flags the M1 health verdict.
pub const PER_KIND_CPU_SHARE_THRESHOLD: f64 = 0.40;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WindowBaseline {
    verify: [KindVerifyCounters; PER_KIND_NAMES.len()],
    local: [LocalKindCumulative; PER_KIND_NAMES.len()],
    since_ts_ms: u64,
}

/// Count plus cumulative nanoseconds (verify paths).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CountAndNs {
    pub count: u64,
    pub total_ns: u64,
}

/// Per-kind counter row for JSON.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct KindCountersSnapshot {
    pub verify_ok: CountAndNs,
    pub verify_err: CountAndNs,
    pub bus_dispatched: u64,
    pub bus_dropped: u64,
    pub delivered: u64,
    pub published: u64,
}

impl KindCountersSnapshot {
    fn verify_cpu_ns(self) -> u64 {
        self.verify_ok
            .total_ns
            .saturating_add(self.verify_err.total_ns)
    }

    fn bus_events(self) -> u64 {
        self.bus_dispatched.saturating_add(self.bus_dropped)
    }

    fn is_empty(self) -> bool {
        self.verify_ok.count == 0
            && self.verify_err.count == 0
            && self.bus_dispatched == 0
            && self.bus_dropped == 0
            && self.delivered == 0
            && self.published == 0
    }
}

/// M1 health verdict over the reporting window.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PerKindHealthVerdict {
    /// Kinds whose verify CPU share exceeds [`PER_KIND_CPU_SHARE_THRESHOLD`].
    pub cpu_pressure_kinds: Vec<&'static str>,
    /// Kinds whose bus-event share exceeds [`PER_KIND_BUS_SHARE_THRESHOLD`].
    pub bus_pressure_kinds: Vec<&'static str>,
    pub cpu_share_threshold: f64,
    pub bus_share_threshold: f64,
}

/// JSON snapshot of the rolling per-kind meter.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PerKindGossipSnapshot {
    /// Unix milliseconds when the reporting window started.
    pub since_ts: u64,
    /// Rolling window length in seconds.
    pub window_secs: u64,
    /// Non-empty kind rows only.
    pub kinds: BTreeMap<&'static str, KindCountersSnapshot>,
    pub health: PerKindHealthVerdict,
}

/// Map native verify counters into the diagnostics `verify_ok` / `verify_err`
/// shape. Time is not split by outcome upstream (`total_ns` covers all
/// attempts); failure count comes from the native `failures` field.
fn kind_row_from_parts(
    verify: KindVerifyCounters,
    local: LocalKindCumulative,
) -> KindCountersSnapshot {
    let ok = verify.attempts.saturating_sub(verify.failures);
    KindCountersSnapshot {
        verify_ok: CountAndNs {
            count: ok,
            // All verify wall time; native meter does not split ok vs err ns.
            total_ns: verify.total_ns,
        },
        verify_err: CountAndNs {
            count: verify.failures,
            total_ns: 0,
        },
        bus_dispatched: local.bus_dispatched,
        bus_dropped: local.bus_dropped,
        delivered: local.delivered,
        published: local.published,
    }
}

fn saturating_verify_delta(
    cur: KindVerifyCounters,
    base: KindVerifyCounters,
) -> KindVerifyCounters {
    KindVerifyCounters {
        attempts: cur.attempts.saturating_sub(base.attempts),
        failures: cur.failures.saturating_sub(base.failures),
        total_ns: cur.total_ns.saturating_sub(base.total_ns),
    }
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
    verify: &PerKindVerifyMeterSnapshot,
    local: &[LocalKindCumulative; PER_KIND_NAMES.len()],
    baseline: &WindowBaseline,
) -> [KindCountersSnapshot; PER_KIND_NAMES.len()] {
    let mut rows = [KindCountersSnapshot::default(); PER_KIND_NAMES.len()];
    for (index, row) in rows.iter_mut().enumerate() {
        let v = saturating_verify_delta(verify.by_kind[index], baseline.verify[index]);
        let l = saturating_local_delta(local[index], baseline.local[index]);
        *row = kind_row_from_parts(v, l);
    }
    rows
}

fn snapshot_from_rows(
    rows: &[KindCountersSnapshot; PER_KIND_NAMES.len()],
    since_ts: u64,
    window_secs: u64,
    cpu_share_threshold: f64,
    bus_share_threshold: f64,
) -> PerKindGossipSnapshot {
    let mut kinds = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        if !row.is_empty() {
            kinds.insert(PER_KIND_NAMES[index], *row);
        }
    }
    let health = health_verdict(rows, cpu_share_threshold, bus_share_threshold);
    PerKindGossipSnapshot {
        since_ts,
        window_secs,
        kinds,
        health,
    }
}

/// Process-wide per-kind efficiency meter.
#[derive(Debug)]
pub struct PerKindGossipCounters {
    slots: [KindSlot; PER_KIND_NAMES.len()],
    window_started: Mutex<Instant>,
    baseline: Mutex<WindowBaseline>,
    /// Last fully completed window (retained across reads after rotation).
    last_completed: Mutex<Option<(u64, [KindCountersSnapshot; PER_KIND_NAMES.len()])>>,
    window: Duration,
    cpu_share_threshold: f64,
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
            window_started: Mutex::new(Instant::now()),
            baseline: Mutex::new(WindowBaseline::default()),
            last_completed: Mutex::new(None),
            window,
            cpu_share_threshold: PER_KIND_CPU_SHARE_THRESHOLD,
            bus_share_threshold: PER_KIND_BUS_SHARE_THRESHOLD,
        }
    }

    fn load_local(&self) -> [LocalKindCumulative; PER_KIND_NAMES.len()] {
        std::array::from_fn(|i| self.slots[i].load())
    }

    /// Ensure the window clock is running. Baseline counters stay at zero so
    /// the first snapshot reports absolute cumulatives since process start.
    fn ensure_started(&self) {
        let Ok(mut baseline) = self.baseline.lock() else {
            return;
        };
        if baseline.since_ts_ms != 0 {
            return;
        }
        baseline.since_ts_ms = unix_ms_now().max(1);
        if let Ok(mut started) = self.window_started.lock() {
            *started = Instant::now();
        }
    }

    /// Advance the window when elapsed. Preserves the completed interval in
    /// `last_completed` instead of discarding it. Cumulative counters are
    /// never cleared.
    fn maybe_rotate(
        &self,
        verify: &PerKindVerifyMeterSnapshot,
        local: &[LocalKindCumulative; PER_KIND_NAMES.len()],
    ) -> bool {
        self.ensure_started();
        let Ok(started) = self.window_started.lock() else {
            return false;
        };
        if started.elapsed() < self.window {
            return false;
        }
        drop(started);

        let Ok(mut baseline) = self.baseline.lock() else {
            return false;
        };
        // A zero since_ts means ensure_started lost the race; do not rotate.
        if baseline.since_ts_ms == 0 {
            return false;
        }
        let completed = rows_from_delta(verify, local, &baseline);
        let completed_since = baseline.since_ts_ms;
        if let Ok(mut last) = self.last_completed.lock() {
            *last = Some((completed_since, completed));
        }
        baseline.verify = verify.by_kind;
        baseline.local = *local;
        baseline.since_ts_ms = unix_ms_now().max(1);
        if let Ok(mut started) = self.window_started.lock() {
            *started = Instant::now();
        }
        true
    }

    /// Zero the reporting window by re-baselining at the current cumulatives.
    /// Does not clear process-lifetime counters. Used by tests.
    pub fn rolling_reset(&self) {
        let verify = PerKindVerifyMeterSnapshot::default();
        let local = self.load_local();
        if let Ok(mut baseline) = self.baseline.lock() {
            baseline.verify = verify.by_kind;
            baseline.local = local;
            baseline.since_ts_ms = unix_ms_now().max(1);
        }
        if let Ok(mut started) = self.window_started.lock() {
            *started = Instant::now();
        }
        if let Ok(mut last) = self.last_completed.lock() {
            *last = None;
        }
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

    /// Snapshot using an empty native verify meter (x0x-local signals only).
    #[must_use]
    pub fn snapshot(&self) -> PerKindGossipSnapshot {
        self.snapshot_with_verify(PerKindVerifyMeterSnapshot::default())
    }

    /// Snapshot merging cumulative native per-kind verify stats.
    ///
    /// When the rolling window has elapsed, returns the **previous completed
    /// interval** (not an empty in-progress window). Otherwise returns the
    /// in-progress delta since the current window start. Reads never clear
    /// cumulative counters.
    #[must_use]
    pub fn snapshot_with_verify(
        &self,
        verify: PerKindVerifyMeterSnapshot,
    ) -> PerKindGossipSnapshot {
        let local = self.load_local();
        let rotated = self.maybe_rotate(&verify, &local);
        if rotated {
            if let Ok(last) = self.last_completed.lock() {
                if let Some((since_ts, rows)) = last.as_ref() {
                    return snapshot_from_rows(
                        rows,
                        *since_ts,
                        self.window.as_secs(),
                        self.cpu_share_threshold,
                        self.bus_share_threshold,
                    );
                }
            }
        }

        self.ensure_started();
        let baseline = self.baseline.lock().map(|b| *b).unwrap_or_default();
        let rows = rows_from_delta(&verify, &local, &baseline);
        snapshot_from_rows(
            &rows,
            baseline.since_ts_ms,
            self.window.as_secs(),
            self.cpu_share_threshold,
            self.bus_share_threshold,
        )
    }
}

fn health_verdict(
    rows: &[KindCountersSnapshot; PER_KIND_NAMES.len()],
    cpu_threshold: f64,
    bus_threshold: f64,
) -> PerKindHealthVerdict {
    let total_cpu: u64 = rows.iter().map(|r| r.verify_cpu_ns()).sum();
    let total_bus: u64 = rows.iter().map(|r| r.bus_events()).sum();
    let mut cpu_pressure_kinds = Vec::new();
    let mut bus_pressure_kinds = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if total_cpu > 0 {
            let share = row.verify_cpu_ns() as f64 / total_cpu as f64;
            if share > cpu_threshold {
                cpu_pressure_kinds.push(PER_KIND_NAMES[index]);
            }
        }
        if total_bus > 0 {
            let share = row.bus_events() as f64 / total_bus as f64;
            if share > bus_threshold {
                bus_pressure_kinds.push(PER_KIND_NAMES[index]);
            }
        }
    }
    PerKindHealthVerdict {
        cpu_pressure_kinds,
        bus_pressure_kinds,
        cpu_share_threshold: cpu_threshold,
        bus_share_threshold: bus_threshold,
    }
}

/// Process-wide meter shared by the recv pump, pubsub delivery, and publish.
static PER_KIND_COUNTERS: LazyLock<PerKindGossipCounters> =
    LazyLock::new(PerKindGossipCounters::new);

/// Snapshot of the process-wide per-kind efficiency counters (no verify merge).
#[must_use]
pub fn per_kind_gossip_stats() -> PerKindGossipSnapshot {
    PER_KIND_COUNTERS.snapshot()
}

/// Snapshot merging saorsa-gossip native per-kind verify meters.
#[must_use]
pub fn per_kind_gossip_stats_with_verify(
    verify: PerKindVerifyMeterSnapshot,
) -> PerKindGossipSnapshot {
    PER_KIND_COUNTERS.snapshot_with_verify(verify)
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

    fn verify_snap(by_kind: [KindVerifyCounters; 9]) -> PerKindVerifyMeterSnapshot {
        PerKindVerifyMeterSnapshot { by_kind }
    }

    fn v(attempts: u64, failures: u64, total_ns: u64) -> KindVerifyCounters {
        KindVerifyCounters {
            attempts,
            failures,
            total_ns,
        }
    }

    #[test]
    fn rolling_reset_rebases_window_without_clearing_cumulatives() {
        let meter = PerKindGossipCounters::new();
        meter.record_bus_dispatched(MessageKind::IHave);
        meter.record_delivered(MessageKind::Eager);
        meter.record_published(MessageKind::Eager);
        let before = meter.snapshot_with_verify(verify_snap({
            let mut a = [KindVerifyCounters::default(); 9];
            a[0] = v(1, 0, 1_000);
            a
        }));
        assert!(before.kinds.contains_key("eager"));
        assert!(before.since_ts > 0);

        thread::sleep(Duration::from_millis(2));
        meter.rolling_reset();
        let after = meter.snapshot();
        assert!(
            after.kinds.is_empty(),
            "re-baseline must zero the window delta: {after:?}"
        );
        assert!(
            after.since_ts >= before.since_ts,
            "since_ts must not go backwards"
        );
        meter.record_bus_dropped(MessageKind::IWant);
        let again = meter.snapshot();
        assert_eq!(again.kinds["iwant"].bus_dropped, 1);
    }

    #[test]
    fn elapsed_window_preserves_previous_completed_interval() {
        let meter = PerKindGossipCounters::with_window(Duration::from_millis(40));
        meter.record_bus_dispatched(MessageKind::Eager);
        let verify1 = verify_snap({
            let mut a = [KindVerifyCounters::default(); 9];
            a[1] = v(2, 1, 500);
            a
        });
        let mid = meter.snapshot_with_verify(verify1);
        assert_eq!(mid.kinds["eager"].bus_dispatched, 1);
        assert_eq!(mid.kinds["ihave"].verify_ok.count, 1);
        assert_eq!(mid.kinds["ihave"].verify_err.count, 1);
        assert_eq!(mid.kinds["ihave"].verify_ok.total_ns, 500);

        thread::sleep(Duration::from_millis(50));
        // No new traffic — a slow poller must still see the completed window.
        let completed = meter.snapshot_with_verify(verify1);
        assert_eq!(
            completed.kinds["eager"].bus_dispatched, 1,
            "elapsed-window read must not discard the measurement: {completed:?}"
        );
        assert_eq!(completed.kinds["ihave"].verify_err.count, 1);
        assert_eq!(completed.since_ts, mid.since_ts);

        // Next read is a fresh in-progress window (empty until new events).
        let next = meter.snapshot_with_verify(verify1);
        assert!(
            next.kinds.is_empty(),
            "new window starts empty after reporting completed: {next:?}"
        );
        assert!(next.since_ts >= completed.since_ts);
    }

    #[test]
    fn health_verdict_flags_kind_over_cpu_share() {
        let meter = PerKindGossipCounters::new();
        let snap = meter.snapshot_with_verify(verify_snap({
            let mut a = [KindVerifyCounters::default(); 9];
            a[1] = v(1, 0, 900);
            a[0] = v(1, 0, 100);
            a
        }));
        assert_eq!(snap.health.cpu_pressure_kinds, vec!["ihave"]);
        assert!(snap.health.bus_pressure_kinds.is_empty());
    }

    #[test]
    fn health_verdict_flags_kind_over_bus_share() {
        let meter = PerKindGossipCounters::new();
        for _ in 0..9 {
            meter.record_bus_dispatched(MessageKind::Eager);
        }
        meter.record_bus_dropped(MessageKind::IWant);
        let snap = meter.snapshot();
        assert_eq!(snap.health.bus_pressure_kinds, vec!["eager"]);
    }

    #[test]
    fn verify_err_uses_native_failures_counter() {
        let meter = PerKindGossipCounters::new();
        let row = meter
            .snapshot_with_verify(verify_snap({
                let mut a = [KindVerifyCounters::default(); 9];
                a[0] = v(3, 1, 75);
                a
            }))
            .kinds["eager"];
        assert_eq!(row.verify_ok.count, 2);
        assert_eq!(row.verify_ok.total_ns, 75);
        assert_eq!(row.verify_err.count, 1);
        assert_eq!(row.verify_err.total_ns, 0);
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
        // Simulate native verify totals that concurrent workers would record
        // under their own kinds (no cross-kind bleed in the snapshot math).
        let total = (threads * per_thread) as u64;
        let verify = verify_snap({
            let mut a = [KindVerifyCounters::default(); 9];
            a[0] = v(total / 2, 0, total * 10);
            a[1] = v(total - total / 2, 3, total * 5);
            a
        });
        let snap = meter.snapshot_with_verify(verify);
        let eager_bus = snap
            .kinds
            .get("eager")
            .map(|r| r.bus_dispatched)
            .unwrap_or(0);
        let ihave_bus = snap.kinds.get("ihave").map(|r| r.bus_dropped).unwrap_or(0);
        assert_eq!(eager_bus + ihave_bus, total);
        assert_eq!(snap.kinds["eager"].verify_ok.count, total / 2);
        assert_eq!(
            snap.kinds["ihave"].verify_ok.count + snap.kinds["ihave"].verify_err.count,
            total - total / 2
        );
        assert_eq!(snap.kinds["ihave"].verify_err.count, 3);
    }

    #[test]
    fn issue1170_done_when_snapshot_exposes_required_fields() {
        let meter = PerKindGossipCounters::new();
        meter.record_bus_dispatched(MessageKind::Eager);
        meter.record_bus_dropped(MessageKind::IWant);
        meter.record_delivered(MessageKind::Eager);
        meter.record_published(MessageKind::Eager);
        let snap = meter.snapshot_with_verify(verify_snap({
            let mut a = [KindVerifyCounters::default(); 9];
            a[0] = v(1, 0, 10);
            a[1] = v(1, 1, 5);
            a
        }));
        assert!(snap.since_ts > 0);
        let eager = &snap.kinds["eager"];
        assert_eq!(eager.verify_ok.count, 1);
        assert_eq!(eager.verify_ok.total_ns, 10);
        assert_eq!(eager.bus_dispatched, 1);
        assert_eq!(eager.delivered, 1);
        assert_eq!(eager.published, 1);
        let ihave = &snap.kinds["ihave"];
        assert_eq!(ihave.verify_err.count, 1);
        assert_eq!(ihave.verify_ok.total_ns, 5);
        let iwant = &snap.kinds["iwant"];
        assert_eq!(iwant.bus_dropped, 1);
        let json = serde_json::to_value(&snap).expect("serialize");
        assert!(json["since_ts"].as_u64().unwrap() > 0);
        assert!(json["kinds"]["eager"]["verify_ok"]["count"].is_u64());
        assert!(json["kinds"]["eager"]["verify_err"]["count"].is_u64());
        assert!(json["kinds"]["eager"]["bus_dispatched"].is_u64());
        assert!(json["kinds"]["eager"]["bus_dropped"].is_u64());
        assert!(json["kinds"]["eager"]["delivered"].is_u64());
        assert!(json["kinds"]["eager"]["published"].is_u64());
        assert!(json["health"]["cpu_share_threshold"].is_f64());
    }
}
