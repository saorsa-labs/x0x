//! X0X-0066 — request hedging for cross-region tail-latency on
//! `send_ack_racing_replaced`.
//!
//! Per-peer EWMA tracker that decides when to fire a hedged duplicate
//! `send_with_receive_ack`. Receiver-side dedupe is guaranteed by the
//! X0X-0060 `RecentDeliveryCache`: both sends share the same encoded
//! `wire` bytes and therefore the same `request_id`, so the receiver
//! collapses the second arrival and republishes the cached ACK
//! outcome on the second stream. Whichever ACK arrives first wins; the
//! losing future is dropped (Quinn streams are drop-safe — same
//! contract X0X-0053 already relies on).
//!
//! Trigger derivation (see `HedgeRttTracker::hedge_trigger`):
//!
//! - Cold start (no samples): `HEDGE_COLD_START_TRIGGER`.
//! - Warm: `ewma * HEDGE_TRIGGER_MULTIPLIER`.
//! - Always clamped to `[HEDGE_MIN_TRIGGER, timeout * HEDGE_MAX_TRIGGER_FRACTION]`
//!   so the hedge cannot fire so early that intra-continent paths see
//!   spurious duplicates, and cannot fire so late that the hedged send
//!   has no time to complete before the overall ACK timeout.
//!
//! Intent: a peer with ~50 ms EWMA never triggers the hedge (trigger
//! clamps to the 250 ms floor and the original send completes first);
//! a peer with ~700 ms EWMA (helsinki↔singapore class) triggers at
//! ~1050 ms which still leaves several seconds of the 6 s ACK budget
//! for the hedge to land.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// Minimum trigger floor — paths faster than this never hedge.
pub const HEDGE_MIN_TRIGGER: Duration = Duration::from_millis(250);

/// Hedge timer cannot fire after this fraction of the overall timeout
/// — leaves headroom for the hedged send to complete.
pub const HEDGE_MAX_TRIGGER_FRACTION_NUM: u32 = 2;
pub const HEDGE_MAX_TRIGGER_FRACTION_DEN: u32 = 3;

/// EWMA multiplier — approximates p95 from observed mean.
pub const HEDGE_TRIGGER_MULTIPLIER: f64 = 1.5;

/// EWMA decay factor for new samples (0.0–1.0).
pub const HEDGE_EWMA_ALPHA: f64 = 0.25;

/// Number of samples before the EWMA is used in place of the cold-start trigger.
pub const HEDGE_MIN_SAMPLES_FOR_EWMA: u32 = 3;

/// Trigger to use when no observed samples exist for a peer.
pub const HEDGE_COLD_START_TRIGGER: Duration = Duration::from_millis(750);

/// Per-peer EWMA tracker keyed by peer identifier.
///
/// The key type is left generic so callers can use whichever peer
/// identifier suits their layer (e.g. `ant_quic::PeerId` or
/// `identity::AgentId`). The tracker holds no transport state and
/// has no async surface; it is purely a cache of observed durations.
#[derive(Debug)]
pub struct HedgeRttTracker<K> {
    inner: Mutex<HashMap<K, HedgeRttEntry>>,
}

#[derive(Debug, Clone, Copy)]
struct HedgeRttEntry {
    ewma_ms: f64,
    samples: u32,
}

impl<K> Default for HedgeRttTracker<K>
where
    K: Eq + std::hash::Hash,
{
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl<K> HedgeRttTracker<K>
where
    K: Eq + std::hash::Hash + Clone,
{
    /// Construct an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute the hedge trigger for one send to `peer` with the given
    /// overall ACK timeout. The trigger is the duration to wait before
    /// firing the hedged duplicate `send_with_receive_ack`.
    ///
    /// The trigger is `HEDGE_COLD_START_TRIGGER` until `HEDGE_MIN_SAMPLES_FOR_EWMA`
    /// successful observations exist, then `ewma * HEDGE_TRIGGER_MULTIPLIER`.
    /// Always clamped to `[HEDGE_MIN_TRIGGER, timeout * 2 / 3]`.
    pub fn hedge_trigger(&self, peer: &K, timeout: Duration) -> Duration {
        let base = match self.inner.lock() {
            Ok(map) => map.get(peer).copied(),
            Err(poisoned) => poisoned.into_inner().get(peer).copied(),
        };
        let trigger_ms = match base {
            Some(entry) if entry.samples >= HEDGE_MIN_SAMPLES_FOR_EWMA => {
                (entry.ewma_ms * HEDGE_TRIGGER_MULTIPLIER) as u64
            }
            _ => HEDGE_COLD_START_TRIGGER.as_millis() as u64,
        };
        let trigger = Duration::from_millis(trigger_ms);
        let upper = timeout
            .checked_mul(HEDGE_MAX_TRIGGER_FRACTION_NUM)
            .and_then(|t| t.checked_div(HEDGE_MAX_TRIGGER_FRACTION_DEN))
            .unwrap_or(timeout);
        let lower = HEDGE_MIN_TRIGGER;
        let clamped = if trigger < lower { lower } else { trigger };
        if clamped > upper {
            upper
        } else {
            clamped
        }
    }

    /// Record one successful `send_with_receive_ack` duration for the
    /// peer. Updates the EWMA used by future trigger computations.
    pub fn record_success(&self, peer: K, observed: Duration) {
        let observed_ms = observed.as_millis() as f64;
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = guard.entry(peer).or_insert(HedgeRttEntry {
            ewma_ms: 0.0,
            samples: 0,
        });
        if entry.samples == 0 {
            entry.ewma_ms = observed_ms;
        } else {
            entry.ewma_ms =
                HEDGE_EWMA_ALPHA * observed_ms + (1.0 - HEDGE_EWMA_ALPHA) * entry.ewma_ms;
        }
        entry.samples = entry.samples.saturating_add(1);
    }

    /// Best-effort snapshot of the EWMA for a peer in milliseconds,
    /// or `None` if no samples have been recorded.
    pub fn ewma_ms(&self, peer: &K) -> Option<f64> {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.get(peer).map(|e| e.ewma_ms)
    }

    /// Sample count for a peer (useful for diagnostics).
    pub fn samples(&self, peer: &K) -> u32 {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.get(peer).map(|e| e.samples).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type K = u32;

    #[test]
    fn cold_start_trigger_returns_cold_start_value_clamped_to_timeout_ceiling() {
        let tracker: HedgeRttTracker<K> = HedgeRttTracker::new();
        let timeout = Duration::from_secs(6);
        let trigger = tracker.hedge_trigger(&1, timeout);
        assert_eq!(trigger, HEDGE_COLD_START_TRIGGER);
    }

    #[test]
    fn cold_start_is_floored_at_min_when_small_timeout() {
        // timeout * 2/3 = 600ms * 2/3 = 400ms which is > HEDGE_MIN_TRIGGER (250ms).
        // Cold start is 750ms but gets clamped down to the timeout ceiling (400ms).
        let tracker: HedgeRttTracker<K> = HedgeRttTracker::new();
        let timeout = Duration::from_millis(600);
        let trigger = tracker.hedge_trigger(&1, timeout);
        assert_eq!(trigger, Duration::from_millis(400));
    }

    #[test]
    fn ewma_takes_over_after_minimum_samples() {
        let tracker: HedgeRttTracker<K> = HedgeRttTracker::new();
        for _ in 0..HEDGE_MIN_SAMPLES_FOR_EWMA {
            tracker.record_success(7, Duration::from_millis(700));
        }
        let trigger = tracker.hedge_trigger(&7, Duration::from_secs(6));
        // EWMA stays at ~700 (all samples identical), so trigger = 700 * 1.5 = 1050.
        assert_eq!(trigger, Duration::from_millis(1050));
    }

    #[test]
    fn ewma_under_min_trigger_clamps_to_floor() {
        let tracker: HedgeRttTracker<K> = HedgeRttTracker::new();
        for _ in 0..10 {
            tracker.record_success(2, Duration::from_millis(40));
        }
        let trigger = tracker.hedge_trigger(&2, Duration::from_secs(6));
        // 40 * 1.5 = 60ms which is below 250ms floor.
        assert_eq!(trigger, HEDGE_MIN_TRIGGER);
    }

    #[test]
    fn ewma_over_timeout_ceiling_clamps_to_two_thirds_of_timeout() {
        let tracker: HedgeRttTracker<K> = HedgeRttTracker::new();
        for _ in 0..10 {
            tracker.record_success(3, Duration::from_secs(10));
        }
        let timeout = Duration::from_secs(6);
        let trigger = tracker.hedge_trigger(&3, timeout);
        // 10s * 1.5 = 15s which exceeds 6s * 2/3 = 4s ceiling.
        assert_eq!(trigger, Duration::from_secs(4));
    }

    #[test]
    fn ewma_decays_toward_new_observations() {
        let tracker: HedgeRttTracker<K> = HedgeRttTracker::new();
        tracker.record_success(5, Duration::from_millis(1000));
        // After 1 sample, EWMA = 1000.
        assert_eq!(tracker.ewma_ms(&5).unwrap() as u64, 1000);
        tracker.record_success(5, Duration::from_millis(500));
        // After 2nd sample at 500: EWMA = 0.25 * 500 + 0.75 * 1000 = 875.
        assert_eq!(tracker.ewma_ms(&5).unwrap() as u64, 875);
        tracker.record_success(5, Duration::from_millis(500));
        // After 3rd sample at 500: EWMA = 0.25 * 500 + 0.75 * 875 ≈ 781.
        let observed = tracker.ewma_ms(&5).unwrap() as u64;
        assert!((780..=782).contains(&observed), "got {observed}");
    }

    #[test]
    fn samples_count_advances_with_each_record() {
        let tracker: HedgeRttTracker<K> = HedgeRttTracker::new();
        assert_eq!(tracker.samples(&1), 0);
        tracker.record_success(1, Duration::from_millis(100));
        assert_eq!(tracker.samples(&1), 1);
        tracker.record_success(1, Duration::from_millis(100));
        assert_eq!(tracker.samples(&1), 2);
    }

    #[test]
    fn empty_tracker_returns_none_for_ewma_and_zero_for_samples() {
        let tracker: HedgeRttTracker<K> = HedgeRttTracker::new();
        assert_eq!(tracker.ewma_ms(&99), None);
        assert_eq!(tracker.samples(&99), 0);
    }

    #[test]
    fn cold_start_with_few_samples_still_uses_cold_start_trigger() {
        let tracker: HedgeRttTracker<K> = HedgeRttTracker::new();
        // Only HEDGE_MIN_SAMPLES_FOR_EWMA - 1 samples — should still use cold start.
        for _ in 0..(HEDGE_MIN_SAMPLES_FOR_EWMA.saturating_sub(1)) {
            tracker.record_success(8, Duration::from_millis(40));
        }
        let trigger = tracker.hedge_trigger(&8, Duration::from_secs(6));
        assert_eq!(trigger, HEDGE_COLD_START_TRIGGER);
    }
}
