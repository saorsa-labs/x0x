//! Per-message-kind gossip efficiency counters (#1170 / Track E M1).
//!
//! Four signals per [`MessageKind`]: verify cost, recv-pump bus pressure,
//! local delivery, and outbound publish. Counters live in a rolling window
//! with `since_ts` so consumers can compute rates after a reset.
//!
//! Outer-frame verify ok/err attribution uses the saorsa-gossip verify stage
//! delta around `handle_incoming`, plus signature-failure errors. Soft verify
//! failures on non-pubsub kinds that return `Ok` may land under `verify_ok`
//! until saorsa-gossip exposes a native per-kind verify meter (Cargo bump
//! fenced for this issue).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use saorsa_gossip_types::MessageKind;
use serde::Serialize;

/// Default rolling window. Survives a reset: counters zero and `since_ts`
/// advances; the meter keeps accepting observations.
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

#[derive(Debug, Default)]
struct KindSlot {
    verify_ok: AtomicU64,
    verify_ok_ns: AtomicU64,
    verify_err: AtomicU64,
    verify_err_ns: AtomicU64,
    bus_dispatched: AtomicU64,
    bus_dropped: AtomicU64,
    delivered: AtomicU64,
    published: AtomicU64,
}

impl KindSlot {
    fn reset(&self) {
        self.verify_ok.store(0, Ordering::Relaxed);
        self.verify_ok_ns.store(0, Ordering::Relaxed);
        self.verify_err.store(0, Ordering::Relaxed);
        self.verify_err_ns.store(0, Ordering::Relaxed);
        self.bus_dispatched.store(0, Ordering::Relaxed);
        self.bus_dropped.store(0, Ordering::Relaxed);
        self.delivered.store(0, Ordering::Relaxed);
        self.published.store(0, Ordering::Relaxed);
    }

    fn snapshot(&self) -> KindCountersSnapshot {
        KindCountersSnapshot {
            verify_ok: CountAndNs {
                count: self.verify_ok.load(Ordering::Relaxed),
                total_ns: self.verify_ok_ns.load(Ordering::Relaxed),
            },
            verify_err: CountAndNs {
                count: self.verify_err.load(Ordering::Relaxed),
                total_ns: self.verify_err_ns.load(Ordering::Relaxed),
            },
            bus_dispatched: self.bus_dispatched.load(Ordering::Relaxed),
            bus_dropped: self.bus_dropped.load(Ordering::Relaxed),
            delivered: self.delivered.load(Ordering::Relaxed),
            published: self.published.load(Ordering::Relaxed),
        }
    }
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

/// M1 health verdict over the current window.
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
    /// Unix milliseconds when the current window started.
    pub since_ts: u64,
    /// Rolling window length in seconds.
    pub window_secs: u64,
    /// Non-empty kind rows only.
    pub kinds: BTreeMap<&'static str, KindCountersSnapshot>,
    pub health: PerKindHealthVerdict,
}

/// Process-wide per-kind efficiency meter.
#[derive(Debug)]
pub struct PerKindGossipCounters {
    slots: [KindSlot; PER_KIND_NAMES.len()],
    since_ts_ms: AtomicU64,
    window_started: Mutex<Instant>,
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
        Self {
            slots: std::array::from_fn(|_| KindSlot::default()),
            since_ts_ms: AtomicU64::new(0),
            window_started: Mutex::new(Instant::now()),
            window: PER_KIND_ROLLING_WINDOW,
            cpu_share_threshold: PER_KIND_CPU_SHARE_THRESHOLD,
            bus_share_threshold: PER_KIND_BUS_SHARE_THRESHOLD,
        }
    }

    /// Ensure `since_ts` is set on first use (const `new` cannot call time APIs).
    fn ensure_started(&self) {
        if self.since_ts_ms.load(Ordering::Relaxed) == 0 {
            let _ = self.since_ts_ms.compare_exchange(
                0,
                unix_ms_now().max(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    /// Zero every slot and advance `since_ts`. Concurrent increments during
    /// the reset may land in the new window (best-effort).
    pub fn rolling_reset(&self) {
        for slot in &self.slots {
            slot.reset();
        }
        self.since_ts_ms
            .store(unix_ms_now().max(1), Ordering::Relaxed);
        if let Ok(mut started) = self.window_started.lock() {
            *started = Instant::now();
        }
    }

    /// Reset when the window has elapsed. Returns true when a reset ran.
    pub fn maybe_rolling_reset(&self) -> bool {
        self.ensure_started();
        let Ok(started) = self.window_started.lock() else {
            return false;
        };
        if started.elapsed() < self.window {
            return false;
        }
        drop(started);
        self.rolling_reset();
        true
    }

    pub fn record_verify_ok(&self, kind: MessageKind, elapsed_ns: u64) {
        self.ensure_started();
        let slot = &self.slots[kind_index(kind)];
        slot.verify_ok.fetch_add(1, Ordering::Relaxed);
        slot.verify_ok_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
    }

    pub fn record_verify_err(&self, kind: MessageKind, elapsed_ns: u64) {
        self.ensure_started();
        let slot = &self.slots[kind_index(kind)];
        slot.verify_err.fetch_add(1, Ordering::Relaxed);
        slot.verify_err_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
    }

    pub fn record_bus_dispatched(&self, kind: MessageKind) {
        self.ensure_started();
        self.slots[kind_index(kind)]
            .bus_dispatched
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bus_dropped(&self, kind: MessageKind) {
        self.ensure_started();
        self.slots[kind_index(kind)]
            .bus_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delivered(&self, kind: MessageKind) {
        self.ensure_started();
        self.slots[kind_index(kind)]
            .delivered
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_published(&self, kind: MessageKind) {
        self.ensure_started();
        self.slots[kind_index(kind)]
            .published
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Attribute one outer-frame verify observation from a stage-stats delta.
    ///
    /// `signature_error` is true when the handler returned a signature
    /// verification failure.
    pub fn record_verify_delta(&self, kind: MessageKind, elapsed_ns: u64, signature_error: bool) {
        if signature_error {
            self.record_verify_err(kind, elapsed_ns);
        } else {
            self.record_verify_ok(kind, elapsed_ns);
        }
    }

    /// Snapshot after applying a due rolling reset.
    #[must_use]
    pub fn snapshot(&self) -> PerKindGossipSnapshot {
        self.maybe_rolling_reset();
        self.ensure_started();
        let mut kinds = BTreeMap::new();
        let mut rows = [KindCountersSnapshot::default(); PER_KIND_NAMES.len()];
        for (index, slot) in self.slots.iter().enumerate() {
            let row = slot.snapshot();
            rows[index] = row;
            if !row.is_empty() {
                kinds.insert(PER_KIND_NAMES[index], row);
            }
        }
        let health = health_verdict(&rows, self.cpu_share_threshold, self.bus_share_threshold);
        PerKindGossipSnapshot {
            since_ts: self.since_ts_ms.load(Ordering::Relaxed),
            window_secs: self.window.as_secs(),
            kinds,
            health,
        }
    }
}

/// True when an error string names a signature verification failure.
#[must_use]
pub fn is_signature_verify_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("invalid signature") || lower.contains("invalid key-cache control signature")
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

    #[test]
    fn rolling_reset_zeros_counters_and_advances_since_ts() {
        let meter = PerKindGossipCounters::new();
        meter.record_verify_ok(MessageKind::Eager, 1_000);
        meter.record_bus_dispatched(MessageKind::IHave);
        meter.record_delivered(MessageKind::Eager);
        meter.record_published(MessageKind::Eager);
        let before = meter.snapshot();
        assert!(before.kinds.contains_key("eager"));
        assert!(before.since_ts > 0);

        std::thread::sleep(Duration::from_millis(2));
        meter.rolling_reset();
        let after = meter.snapshot();
        assert!(after.kinds.is_empty(), "reset must clear rows: {after:?}");
        assert!(
            after.since_ts >= before.since_ts,
            "since_ts must not go backwards"
        );
        // Meter still accepts observations after the reset.
        meter.record_bus_dropped(MessageKind::IWant);
        let again = meter.snapshot();
        assert_eq!(again.kinds["iwant"].bus_dropped, 1);
    }

    #[test]
    fn health_verdict_flags_kind_over_cpu_share() {
        let meter = PerKindGossipCounters::new();
        meter.record_verify_ok(MessageKind::IHave, 900);
        meter.record_verify_ok(MessageKind::Eager, 100);
        let snap = meter.snapshot();
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
    fn verify_err_and_ok_track_count_and_ns() {
        let meter = PerKindGossipCounters::new();
        meter.record_verify_ok(MessageKind::Eager, 50);
        meter.record_verify_err(MessageKind::Eager, 25);
        let row = meter.snapshot().kinds["eager"];
        assert_eq!(row.verify_ok.count, 1);
        assert_eq!(row.verify_ok.total_ns, 50);
        assert_eq!(row.verify_err.count, 1);
        assert_eq!(row.verify_err.total_ns, 25);
    }

    #[test]
    fn signature_error_helper_matches_sg_strings() {
        assert!(is_signature_verify_error(
            "Invalid signature on IHAVE message"
        ));
        assert!(is_signature_verify_error(
            "invalid key-cache control signature"
        ));
        assert!(!is_signature_verify_error(
            "Failed to deserialize IHAVE payload"
        ));
    }

    #[test]
    fn issue1170_done_when_snapshot_exposes_required_fields() {
        let meter = PerKindGossipCounters::new();
        meter.record_verify_ok(MessageKind::Eager, 10);
        meter.record_verify_err(MessageKind::IHave, 5);
        meter.record_bus_dispatched(MessageKind::Eager);
        meter.record_bus_dropped(MessageKind::IWant);
        meter.record_delivered(MessageKind::Eager);
        meter.record_published(MessageKind::Eager);
        let snap = meter.snapshot();
        assert!(snap.since_ts > 0);
        let eager = &snap.kinds["eager"];
        assert_eq!(eager.verify_ok.count, 1);
        assert_eq!(eager.verify_ok.total_ns, 10);
        assert_eq!(eager.bus_dispatched, 1);
        assert_eq!(eager.delivered, 1);
        assert_eq!(eager.published, 1);
        let ihave = &snap.kinds["ihave"];
        assert_eq!(ihave.verify_err.count, 1);
        assert_eq!(ihave.verify_err.total_ns, 5);
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
