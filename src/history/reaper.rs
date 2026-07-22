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
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(interval_secs.max(1));
        loop {
            tokio::time::sleep(interval).await;
            let store = Arc::clone(&store);
            let policy = policy.clone();
            let result = tokio::task::spawn_blocking(move || store.retain(&policy)).await;
            match result {
                Ok(Ok(evicted)) => {
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
