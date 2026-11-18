//! #1964 request 5 (slice 1): transport bandwidth visibility.
//!
//! What this counts: every application frame that crosses x0x's own
//! transport edge — the send funnels and the single receive-pump demux in
//! [`crate::network`] — split into the kinds the wire can tell apart with
//! zero extra decoding: `gossip` (the three saorsa-gossip lanes: pub/sub,
//! membership, bulk), `direct` (`0x10` DM frames), `relay` (`0x11`
//! relayed-DM frames plus the relay-side forward of them) and `other`
//! (plane hellos and anything unrecognised).
//!
//! What this deliberately does NOT count: QUIC/UDP framing and crypto
//! overhead (the true wire cost is somewhat higher), ADR-0022 streams
//! (forward/voice; they do not pass the datagram funnels) and the evidence
//! wire, which keeps its own `evidence_bytes_in`/`evidence_bytes_out`
//! counters. CRDT/KV state-sync (`…/state-sync` topics) and DM-inbox
//! publishes ride the gossip lanes, so their bytes land in `gossip`;
//! per-topic gossip egress detail is already available from
//! `/diagnostics/gossip` (`outbound_by_topic`).
//!
//! Counters are `AtomicU64` adds on the hot path — monotonic for the
//! process lifetime, never cleared by a read. Rates are computed on read
//! over a rolling window: a snapshot stores a `(instant, counters)`
//! sample (at most one per second for the shipped window, so the sample
//! count stays bounded under any poll rate) and the rate spans the window between the oldest retained
//! sample and now. Retention keeps the newest sample at least
//! [`BANDWIDTH_RATE_WINDOW`](crate::network::bandwidth::BANDWIDTH_RATE_WINDOW)
//! old as the baseline (so a steady poller sees
//! roughly that window), and the construction-time zero baseline before
//! that — so the first read of a long-idle process reports the lifetime
//! average rather than an undefined rate. `window_secs` always reports
//! the span actually used.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

/// Rolling window the read-side rate calculation keeps between samples.
pub const BANDWIDTH_RATE_WINDOW: Duration = Duration::from_secs(60);

/// A read stores a rate sample only when the newest stored one is at least
/// `rate_window / RATE_SAMPLE_SLOTS` old (1 s for the shipped window), so
/// the window holds at most about this many samples plus the baseline.
const RATE_SAMPLE_SLOTS: u32 = 60;

/// The traffic kinds the transport edge can tell apart without decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthKind {
    /// The saorsa-gossip lanes (pub/sub, membership, bulk), including
    /// CRDT/KV state-sync and DM-inbox publishes, which ride those lanes.
    Gossip,
    /// `0x10` direct-message frames.
    Direct,
    /// `0x11` relayed-DM frames and the relay-side forward of them
    /// (a forward exits as `0x10`, but only the relay sends it).
    Relay,
    /// Plane hellos and any frame the demux does not recognise.
    Other,
}

const KIND_COUNT: usize = 4;

/// Per-kind byte totals for one direction. `total` is the sum of the four
/// kinds: every counted frame is classified exactly once.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BandwidthTotals {
    pub total: u64,
    pub gossip: u64,
    pub direct: u64,
    pub relay: u64,
    pub other: u64,
}

impl BandwidthTotals {
    fn from_kinds(kinds: [u64; KIND_COUNT]) -> Self {
        let [gossip, direct, relay, other] = kinds;
        Self {
            total: gossip
                .saturating_add(direct)
                .saturating_add(relay)
                .saturating_add(other),
            gossip,
            direct,
            relay,
            other,
        }
    }
}

/// Per-kind rates in bits per second over the snapshot's rate window.
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize)]
pub struct BandwidthRates {
    pub total: f64,
    pub gossip: f64,
    pub direct: f64,
    pub relay: f64,
    pub other: f64,
}

impl BandwidthRates {
    fn from_deltas(now: [u64; KIND_COUNT], baseline: [u64; KIND_COUNT], secs: f64) -> Self {
        let delta = |i: usize| now[i].saturating_sub(baseline[i]);
        let bits_per_sec = |bytes: u64| {
            if secs > 0.0 {
                bytes as f64 * 8.0 / secs
            } else {
                0.0
            }
        };
        Self {
            total: bits_per_sec(
                delta(0)
                    .saturating_add(delta(1))
                    .saturating_add(delta(2))
                    .saturating_add(delta(3)),
            ),
            gossip: bits_per_sec(delta(0)),
            direct: bits_per_sec(delta(1)),
            relay: bits_per_sec(delta(2)),
            other: bits_per_sec(delta(3)),
        }
    }
}

/// Read-only bandwidth snapshot surfaced by `GET /status` and the CLI.
#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize)]
pub struct BandwidthUsage {
    /// Application bytes handed to the transport, by kind.
    pub sent_bytes: BandwidthTotals,
    /// Application bytes taken off the transport by the receive pump.
    pub received_bytes: BandwidthTotals,
    /// Outbound bits per second over `window_secs`.
    pub up_bps: BandwidthRates,
    /// Inbound bits per second over `window_secs`.
    pub down_bps: BandwidthRates,
    /// The span the rates were computed over (see the module docs).
    pub window_secs: f64,
}

/// Clock and samples for the read-side rate window. One lock covers both
/// so two concurrent readers cannot interleave a trim with a push.
#[derive(Debug)]
struct RateWindow {
    /// Construction-time baseline. Seeded as the first sample on the first
    /// read so that read reports the lifetime average, never `0/0`.
    birth: Instant,
    samples: VecDeque<(Instant, [u64; KIND_COUNT], [u64; KIND_COUNT])>,
}

/// Process-lifetime byte counters plus the read-side rate window.
///
/// Owned by [`crate::network::NetworkNode`] behind an `Arc` (the node is
/// `Clone`; clones share the counters, and the spawned receive pump keeps
/// its own handle).
#[derive(Debug)]
pub struct BandwidthCounters {
    tx: [AtomicU64; KIND_COUNT],
    rx: [AtomicU64; KIND_COUNT],
    rate_window: Duration,
    window: Mutex<RateWindow>,
}

impl Default for BandwidthCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl BandwidthCounters {
    /// Build the counters with the shipped rate window.
    #[must_use]
    pub fn new() -> Self {
        Self::with_rate_window(BANDWIDTH_RATE_WINDOW)
    }

    /// Build with a custom rate window (tests).
    #[must_use]
    pub fn with_rate_window(rate_window: Duration) -> Self {
        Self {
            tx: std::array::from_fn(|_| AtomicU64::new(0)),
            rx: std::array::from_fn(|_| AtomicU64::new(0)),
            rate_window,
            window: Mutex::new(RateWindow {
                birth: Instant::now(),
                samples: VecDeque::new(),
            }),
        }
    }

    /// Record `bytes` handed to the transport for `kind`.
    pub fn record_sent(&self, kind: BandwidthKind, bytes: u64) {
        self.tx[kind as usize].fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record `bytes` received from the transport for `kind`.
    pub fn record_received(&self, kind: BandwidthKind, bytes: u64) {
        self.rx[kind as usize].fetch_add(bytes, Ordering::Relaxed);
    }

    /// Load the totals, sample the rate window, compute the rates.
    ///
    /// The read never clears the process-lifetime counters; it stores at
    /// most one window sample (see the module docs for the retention rule).
    #[must_use]
    pub fn snapshot(&self) -> BandwidthUsage {
        let tx = load_kinds(&self.tx);
        let rx = load_kinds(&self.rx);
        let now = Instant::now();
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if window.samples.is_empty() {
            let birth = window.birth;
            window
                .samples
                .push_back((birth, [0; KIND_COUNT], [0; KIND_COUNT]));
        }
        // Store at most one read sample per `rate_window / RATE_SAMPLE_SLOTS`
        // so a fast poller cannot grow the window without bound (#2000
        // review). A skipped read still reports exact totals and a rate
        // against the retained baseline; it only stores nothing.
        let spacing = self.rate_window / RATE_SAMPLE_SLOTS;
        let store = window.samples.len() == 1
            || window
                .samples
                .back()
                .is_some_and(|(at, _, _)| now.duration_since(*at) >= spacing);
        if store {
            window.samples.push_back((now, tx, rx));
        }
        // Retain the newest sample at least one window old as the rate
        // baseline plus every sample newer than it; drop older baselines.
        while window.samples.len() > 1
            && now.duration_since(window.samples[1].0) >= self.rate_window
        {
            window.samples.pop_front();
        }
        let (start, tx0, rx0) = window.samples[0];
        let secs = now.duration_since(start).as_secs_f64();
        BandwidthUsage {
            sent_bytes: BandwidthTotals::from_kinds(tx),
            received_bytes: BandwidthTotals::from_kinds(rx),
            up_bps: BandwidthRates::from_deltas(tx, tx0, secs),
            down_bps: BandwidthRates::from_deltas(rx, rx0, secs),
            window_secs: secs,
        }
    }

    /// Move the birth baseline and every stored sample into the past so a
    /// test can exercise a delayed read or a window roll without sleeping
    /// (the same seam `PerKindGossipCounters::backdate` gives the
    /// per-kind meter).
    #[cfg(test)]
    fn backdate(&self, by: Duration) {
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(birth) = window.birth.checked_sub(by) {
            window.birth = birth;
        }
        for (at, _, _) in &mut window.samples {
            if let Some(shifted) = at.checked_sub(by) {
                *at = shifted;
            }
        }
    }
}

fn load_kinds(counters: &[AtomicU64; KIND_COUNT]) -> [u64; KIND_COUNT] {
    std::array::from_fn(|i| counters[i].load(Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn totals_split_by_kind_and_sum_to_the_total() {
        let counters = BandwidthCounters::new();
        counters.record_sent(BandwidthKind::Gossip, 1_000);
        counters.record_sent(BandwidthKind::Direct, 100);
        counters.record_sent(BandwidthKind::Relay, 10);
        counters.record_sent(BandwidthKind::Other, 1);
        counters.record_received(BandwidthKind::Gossip, 2_000);
        let usage = counters.snapshot();
        assert_eq!(usage.sent_bytes.gossip, 1_000);
        assert_eq!(usage.sent_bytes.direct, 100);
        assert_eq!(usage.sent_bytes.relay, 10);
        assert_eq!(usage.sent_bytes.other, 1);
        assert_eq!(usage.sent_bytes.total, 1_111);
        assert_eq!(usage.received_bytes.total, 2_000);
    }

    #[test]
    fn counters_are_monotonic_across_reads() {
        let counters = BandwidthCounters::new();
        let first = counters.snapshot();
        counters.record_sent(BandwidthKind::Gossip, 5);
        let second = counters.snapshot();
        assert!(second.sent_bytes.gossip > first.sent_bytes.gossip);
        assert!(second.sent_bytes.total >= first.sent_bytes.total);
        // A read never clears anything: the third read keeps the counts.
        let third = counters.snapshot();
        assert_eq!(third.sent_bytes.gossip, second.sent_bytes.gossip);
    }

    #[test]
    fn first_read_of_a_long_idle_process_reports_the_lifetime_average() {
        let counters = BandwidthCounters::new();
        counters.backdate(Duration::from_secs(10));
        counters.record_sent(BandwidthKind::Gossip, 100);
        let usage = counters.snapshot();
        // 100 B over ~10 s = 80 bps; tolerate scheduler jitter.
        assert!(
            (usage.up_bps.gossip - 80.0).abs() < 1.0,
            "lifetime average expected: {:?}",
            usage.up_bps
        );
        assert!(usage.window_secs >= 9.0, "window {:?}", usage.window_secs);
        assert_eq!(usage.down_bps.total, 0.0);
    }

    #[test]
    fn rate_window_rolls_past_the_baseline_under_a_steady_poller() {
        let counters = BandwidthCounters::with_rate_window(Duration::from_secs(60));
        counters.record_sent(BandwidthKind::Direct, 1_000);
        let first = counters.snapshot();
        // First read: the baseline is birth, so the rate covers everything.
        assert_eq!(first.sent_bytes.direct, 1_000);
        // Age the stored samples a full window, then send more. The next
        // read must re-baseline on the newest out-of-window sample, so the
        // reported span stays ~one window, not the whole process lifetime.
        counters.backdate(Duration::from_secs(120));
        counters.record_sent(BandwidthKind::Direct, 3_000);
        let second = counters.snapshot();
        assert_eq!(second.sent_bytes.direct, 4_000);
        // 3_000 B over the ~120 s between the two reads = ~200 bps.
        assert!(
            (second.up_bps.direct - 200.0).abs() < 10.0,
            "window rate expected: {:?}",
            second.up_bps
        );
        assert!(
            second.window_secs < 121.0 && second.window_secs >= 119.0,
            "span must track the retained baseline, not birth: {}",
            second.window_secs
        );
    }

    fn stored_samples(counters: &BandwidthCounters) -> usize {
        counters
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .samples
            .len()
    }

    /// #2000 review: a fast poller must not grow the sample window without
    /// bound. Reads closer together than the sample spacing store nothing
    /// but still report exact totals; spaced reads are kept up to one
    /// window, then old baselines are dropped.
    #[test]
    fn sample_window_stays_bounded_under_fast_polling() {
        let counters = BandwidthCounters::with_rate_window(Duration::from_secs(60));
        for i in 0..10_000u64 {
            counters.record_sent(BandwidthKind::Gossip, 1);
            let usage = counters.snapshot();
            assert_eq!(usage.sent_bytes.gossip, i + 1, "totals stay exact");
        }
        // Birth plus the first read; every later read was within 1 s.
        assert!(
            stored_samples(&counters) <= 2,
            "fast reads stored {} samples",
            stored_samples(&counters)
        );

        // One read per spacing over three windows: the window keeps about
        // one window of samples plus the baseline, never all 180.
        for _ in 0..180 {
            counters.backdate(Duration::from_secs(1));
            let _ = counters.snapshot();
        }
        let kept = stored_samples(&counters);
        assert!(
            kept <= usize::try_from(RATE_SAMPLE_SLOTS).unwrap_or(usize::MAX) + 2,
            "kept {kept} samples"
        );
        let usage = counters.snapshot();
        assert!(
            usage.window_secs >= 59.0 && usage.window_secs < 62.0,
            "a steady poller sees about one window: {}",
            usage.window_secs
        );
    }

    #[test]
    fn concurrent_attribution_sums_exactly() {
        let counters = Arc::new(BandwidthCounters::new());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let counters = Arc::clone(&counters);
                std::thread::spawn(move || {
                    for _ in 0..250 {
                        counters.record_sent(BandwidthKind::Gossip, 1);
                        counters.record_received(BandwidthKind::Direct, 1);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("join");
        }
        let usage = counters.snapshot();
        assert_eq!(usage.sent_bytes.gossip, 1_000);
        assert_eq!(usage.received_bytes.direct, 1_000);
        // The snapshot serializes the documented shape (the /status layer
        // asserts the same keys additively in
        // `status_json_is_additive_with_bandwidth`).
        let json = serde_json::to_value(usage).expect("serializes");
        assert!(json["sent_bytes"]["total"].is_u64());
        assert!(json["up_bps"]["relay"].is_f64());
        assert!(json["window_secs"].as_f64().unwrap() >= 0.0);
    }
}
