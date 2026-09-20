//! Retention reaper (ADR-0023 §6) — the `discovery_cache_reaper` pattern:
//! a periodic tokio task, shutdown-race-guarded start, abort on shutdown.
//! The synchronous `Store::retain` runs under `spawn_blocking`.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::store::{RetentionPolicy, Store};
use super::writer::HistoryCounters;

/// Interval between retention passes.
pub const HISTORY_REAPER_INTERVAL_SECS: u64 = 300;

/// Spawn the reaper loop. The returned handle is aborted at shutdown by
/// [`super::HistoryService::shutdown`].
pub(super) fn spawn(
    store: Arc<Store>,
    policy: RetentionPolicy,
    counters: Arc<HistoryCounters>,
    interval_secs: u64,
    pins: Arc<super::QuarantinePinSlot>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(interval_secs.max(1));
        loop {
            tokio::time::sleep(interval).await;
            let store = Arc::clone(&store);
            let policy = policy.clone();
            // ADR-0068 D1: the pinned set is derived live from the marker
            // state, once per pass and BEFORE the blocking retain — so the
            // async read the source takes is never held across the
            // `spawn_blocking`, and a marker installed mid-pass is honoured by
            // the next pass (accepted residual: ≤ one interval).
            let pinned = pins.pinned().await;
            counters
                .quarantine_pinned_scopes
                .store(pinned.len() as u64, Ordering::Relaxed);
            let result =
                tokio::task::spawn_blocking(move || store.retain_with_pins(&policy, &pinned)).await;
            match result {
                Ok(Ok(outcome)) => {
                    if outcome.pinned_evicted > 0 {
                        counters
                            .quarantine_pinned_evictions
                            .fetch_add(outcome.pinned_evicted, Ordering::Relaxed);
                        tracing::warn!(
                            pinned_evicted = outcome.pinned_evicted,
                            pinned_scopes = outcome.pinned_scopes,
                            "[history] a fork-quarantined scope exceeded its pinned ceiling and \
                             shed its OWN oldest rows (ADR-0068 D1)"
                        );
                    }
                    let evicted = outcome.evicted;
                    if evicted > 0 {
                        counters
                            .reaper_evicted_total
                            .fetch_add(evicted, Ordering::Relaxed);
                        tracing::debug!(evicted, "[history] retention pass evicted rows");
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "[history] retention pass failed");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "[history] retention task join failed");
                }
            }
        }
    })
}
