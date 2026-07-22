//! Bounded, shed-on-full history writer (ADR-0023 §5).
//!
//! Producers `try_send` into a bounded channel; a **dedicated OS thread**
//! (rusqlite is synchronous — no async executor involvement) drains it in
//! batches of ≤`BATCH_MAX` records or `BATCH_WINDOW`, whichever comes
//! first. On a full channel the record is dropped and counted
//! (`dropped_full`) — the receive pump and DM/group hot paths never block
//! on disk.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use super::record::HistoryRecord;
use super::store::Store;

/// Channel capacity (records) between producers and the writer thread.
pub const WRITER_QUEUE_CAPACITY: usize = 4096;

/// Maximum records per write transaction.
const BATCH_MAX: usize = 64;

/// Maximum time the writer waits to fill a batch.
const BATCH_WINDOW: Duration = Duration::from_millis(50);

/// Grace period for draining queued records at shutdown.
const SHUTDOWN_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Shared, lock-free counters surfaced by `/diagnostics/history`.
#[derive(Debug, Default)]
pub struct HistoryCounters {
    /// Records committed to SQLite.
    pub written_total: AtomicU64,
    /// Records dropped because the channel was full.
    pub dropped_full: AtomicU64,
    /// Duplicate/stale records collapsed by `msg_id`/replaceable dedupe.
    pub dedup_hits: AtomicU64,
    /// Records abandoned at shutdown after the drain grace expired.
    pub abandoned_at_shutdown: AtomicU64,
    /// Rows evicted by the retention reaper.
    pub reaper_evicted_total: AtomicU64,
    /// Write-transaction failures (batch lost, logged).
    pub write_errors: AtomicU64,
}

/// Producer-side handle: cheap to clone, never blocks.
#[derive(Clone, Debug)]
pub struct WriterHandle {
    tx: mpsc::SyncSender<HistoryRecord>,
    counters: Arc<HistoryCounters>,
}

impl WriterHandle {
    /// Enqueue a record; drops (and counts) when the queue is full or the
    /// writer has shut down. Never blocks.
    pub fn record(&self, record: HistoryRecord) {
        match self.tx.try_send(record) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => {
                self.counters.dropped_full.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Shared counters.
    #[must_use]
    pub fn counters(&self) -> Arc<HistoryCounters> {
        Arc::clone(&self.counters)
    }
}

/// The writer thread plus its shutdown control.
pub struct Writer {
    handle: WriterHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    shutdown_tx: mpsc::Sender<()>,
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer").finish_non_exhaustive()
    }
}

impl Writer {
    /// Spawn the writer thread over `store`.
    #[must_use]
    pub fn spawn(store: Arc<Store>) -> Self {
        let (tx, rx) = mpsc::sync_channel::<HistoryRecord>(WRITER_QUEUE_CAPACITY);
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let counters = Arc::new(HistoryCounters::default());
        let thread_counters = Arc::clone(&counters);
        let thread = std::thread::Builder::new()
            .name("x0x-history-writer".into())
            .spawn(move || writer_loop(&store, &rx, &shutdown_rx, &thread_counters))
            .ok();
        if thread.is_none() {
            // Thread spawn failure: every record will count as dropped via
            // the disconnected channel; loud but non-fatal (ADR-0023 §5).
            tracing::error!("[history] failed to spawn writer thread — history disabled");
        }
        Self {
            handle: WriterHandle { tx, counters },
            thread,
            shutdown_tx,
        }
    }

    /// Producer handle.
    #[must_use]
    pub fn handle(&self) -> WriterHandle {
        self.handle.clone()
    }

    /// Drain-then-stop. Bounded by `SHUTDOWN_DRAIN_GRACE`; queued records
    /// beyond the grace are abandoned and counted — never `abort()`.
    pub fn shutdown(mut self) {
        // Signal the loop; it drains what it can within the grace window.
        let _ = self.shutdown_tx.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn writer_loop(
    store: &Store,
    rx: &mpsc::Receiver<HistoryRecord>,
    shutdown_rx: &mpsc::Receiver<()>,
    counters: &HistoryCounters,
) {
    let mut batch: Vec<HistoryRecord> = Vec::with_capacity(BATCH_MAX);
    loop {
        let shutting_down = shutdown_rx.try_recv().is_ok();

        // Fill a batch: block briefly for the first record, then drain
        // whatever is immediately available up to BATCH_MAX.
        match rx.recv_timeout(BATCH_WINDOW) {
            Ok(rec) => {
                batch.push(rec);
                while batch.len() < BATCH_MAX {
                    match rx.try_recv() {
                        Ok(r) => batch.push(r),
                        Err(_) => break,
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                flush(store, &mut batch, counters);
                return;
            }
        }

        flush(store, &mut batch, counters);

        if shutting_down {
            drain_at_shutdown(store, rx, counters);
            return;
        }
    }
}

fn drain_at_shutdown(
    store: &Store,
    rx: &mpsc::Receiver<HistoryRecord>,
    counters: &HistoryCounters,
) {
    let deadline = std::time::Instant::now() + SHUTDOWN_DRAIN_GRACE;
    let mut batch: Vec<HistoryRecord> = Vec::with_capacity(BATCH_MAX);
    loop {
        if std::time::Instant::now() >= deadline {
            // Count what we are abandoning, then stop.
            let mut abandoned = 0u64;
            while rx.try_recv().is_ok() {
                abandoned += 1;
            }
            if abandoned > 0 {
                counters
                    .abandoned_at_shutdown
                    .fetch_add(abandoned, Ordering::Relaxed);
                tracing::warn!(
                    abandoned,
                    "[history] shutdown drain grace expired; records abandoned"
                );
            }
            return;
        }
        match rx.try_recv() {
            Ok(rec) => {
                batch.push(rec);
                if batch.len() >= BATCH_MAX {
                    flush(store, &mut batch, counters);
                }
            }
            Err(_) => {
                flush(store, &mut batch, counters);
                return;
            }
        }
    }
}

fn flush(store: &Store, batch: &mut Vec<HistoryRecord>, counters: &HistoryCounters) {
    if batch.is_empty() {
        return;
    }
    match store.insert_batch(batch) {
        Ok((written, dups)) => {
            counters.written_total.fetch_add(written, Ordering::Relaxed);
            counters.dedup_hits.fetch_add(dups, Ordering::Relaxed);
        }
        Err(e) => {
            counters
                .write_errors
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            tracing::error!(error = %e, lost = batch.len(), "[history] batch write failed");
        }
    }
    batch.clear();
}
