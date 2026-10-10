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
use super::store::{InsertOutcome, Store};
use crate::error::{HistoryError, HistoryResult};

enum WriteCommand {
    BestEffort(HistoryRecord),
    Commit {
        record: HistoryRecord,
        reply: tokio::sync::oneshot::Sender<HistoryResult<InsertOutcome>>,
    },
}

/// Channel capacity (records) between producers and the writer thread.
pub const WRITER_QUEUE_CAPACITY: usize = 4096;

/// Maximum records per write transaction.
const BATCH_MAX: usize = 64;

/// Maximum time the writer waits to fill a batch.
const BATCH_WINDOW: Duration = Duration::from_millis(50);

/// Grace period for draining queued records at shutdown.
///
/// The clock starts when shutdown is submitted, including time spent queued
/// on the Tokio blocking pool. It does not start again when a worker runs.
pub(super) const SHUTDOWN_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// How long past [`SHUTDOWN_DRAIN_GRACE`] the submitter waits so a worker
/// already inside [`Writer::shutdown_until`] can retain its thread before
/// the wait gives up. This is timer slop, not a second grace: the closure
/// still uses the original deadline.
pub(super) const SHUTDOWN_SUBMIT_SLACK: Duration = Duration::from_millis(200);

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
    /// ADR-0068 D1: rows evicted from INSIDE a fork-quarantine-pinned scope
    /// because that scope exceeded its own ceiling. Cumulative. A non-zero
    /// value tells the operator a pinned group is at its ceiling and shedding
    /// its oldest rows — no other scope ever pays for that overshoot.
    pub quarantine_pinned_evictions: AtomicU64,
    /// ADR-0068 D1: scopes pinned by the most recent retention pass (`G` in
    /// the ADR's `max_bytes * (1 + G/16)` disk bound). A GAUGE overwritten
    /// each pass, not a total.
    pub quarantine_pinned_scopes: AtomicU64,
    /// Write-transaction failures (batch lost, logged).
    pub write_errors: AtomicU64,
    /// ADR 0116 §3: ordinary DM records the local `dm_recording =
    /// "ephemeral"` policy kept out of history. Cumulative; no label.
    pub policy_suppressed_dm_total: AtomicU64,
    /// ADR 0116 §3: topic records a winning `recording = "ephemeral"` topic
    /// rule kept out of history. Cumulative; never labelled with a topic.
    pub policy_suppressed_topic_total: AtomicU64,
    /// ADR 0116 §3 / ADR 0030: generic durable DM receipts withheld because
    /// the local policy suppresses their commit. The local reason is
    /// recorded here only; nothing is sent to the peer. Cumulative.
    pub policy_durable_receipt_withheld_total: AtomicU64,
}

/// Producer-side handle: cheap to clone, never blocks.
#[derive(Clone, Debug)]
pub struct WriterHandle {
    tx: mpsc::SyncSender<WriteCommand>,
    counters: Arc<HistoryCounters>,
    /// Set when [`Writer::shutdown`] returns while the thread is still in
    /// SQLite. Clones of this handle, including the agent's history handle,
    /// observe the same flag.
    shutdown_incomplete: Arc<std::sync::atomic::AtomicBool>,
}

impl WriterHandle {
    /// Enqueue a record; drops (and counts) when the queue is full or the
    /// writer has shut down. Never blocks.
    pub fn record(&self, record: HistoryRecord) {
        match self.tx.try_send(WriteCommand::BestEffort(record)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => {
                self.counters.dropped_full.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Enqueue a record and wait until its SQLite transaction has committed.
    ///
    /// Unlike [`Self::record`], this never sheds silently: a full or closed
    /// writer queue is returned to the caller so an application-level ACK
    /// cannot get ahead of durable history.
    pub async fn record_committed(&self, record: HistoryRecord) -> HistoryResult<InsertOutcome> {
        let (reply, receipt) = tokio::sync::oneshot::channel();
        match self.tx.try_send(WriteCommand::Commit { record, reply }) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => return Err(HistoryError::WriterBackpressured),
            Err(mpsc::TrySendError::Disconnected(_)) => return Err(HistoryError::WriterClosed),
        }
        match receipt.await {
            Ok(result) => result,
            Err(_) => Err(HistoryError::WriterClosed),
        }
    }

    /// Shared counters.
    #[must_use]
    pub fn counters(&self) -> Arc<HistoryCounters> {
        Arc::clone(&self.counters)
    }

    /// Whether shutdown left this writer running past the drain grace.
    ///
    /// The thread is still in custody and still holds the store. A caller
    /// that sees `true` must not report a finished shutdown.
    #[must_use]
    pub fn shutdown_incomplete(&self) -> bool {
        self.shutdown_incomplete.load(Ordering::SeqCst)
    }

    pub(super) fn mark_shutdown_incomplete(&self) {
        self.shutdown_incomplete.store(true, Ordering::SeqCst);
    }
}

/// The writer thread plus its shutdown control.
pub struct Writer {
    handle: WriterHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    shutdown_tx: mpsc::Sender<()>,
    /// Set when the writer thread returns, including after a panic.
    finished: Arc<std::sync::atomic::AtomicBool>,
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
        let (tx, rx) = mpsc::sync_channel::<WriteCommand>(WRITER_QUEUE_CAPACITY);
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let counters = Arc::new(HistoryCounters::default());
        let thread_counters = Arc::clone(&counters);
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_finished = Arc::clone(&finished);
        let shutdown_incomplete = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = std::thread::Builder::new()
            .name("x0x-history-writer".into())
            .spawn(move || {
                let _done = WriterFinished(thread_finished);
                writer_loop(&store, &rx, &shutdown_rx, &thread_counters);
            })
            .ok();
        if thread.is_none() {
            // Thread spawn failure: every record will count as dropped via
            // the disconnected channel; loud but non-fatal (ADR-0023 §5).
            tracing::error!("[history] failed to spawn writer thread — history disabled");
        }
        Self {
            handle: WriterHandle {
                tx,
                counters,
                shutdown_incomplete,
            },
            thread,
            shutdown_tx,
            finished,
        }
    }

    /// Producer handle.
    #[must_use]
    pub fn handle(&self) -> WriterHandle {
        self.handle.clone()
    }

    /// Drain-then-stop. Bounded by `SHUTDOWN_DRAIN_GRACE` from this call;
    /// queued records beyond the grace are abandoned and counted — never
    /// `abort()`.
    ///
    /// The join uses that same grace. A thread blocked in SQLite past that
    /// grace is left running: the `JoinHandle` stays owned and the in-flight
    /// write is not cancelled. This call still returns. `false` means the
    /// writer is incomplete and [`WriterHandle::shutdown_incomplete`] is set,
    /// so the caller must not report a finished shutdown.
    #[must_use]
    pub fn shutdown(self) -> bool {
        self.shutdown_until(std::time::Instant::now() + SHUTDOWN_DRAIN_GRACE)
    }

    /// [`Self::shutdown`] against a deadline chosen by the caller.
    ///
    /// `HistoryService::shutdown` captures the deadline when it submits the
    /// blocking job, so time spent queued on the pool counts. A worker that
    /// starts after `deadline` retains the thread and returns without waiting
    /// another grace.
    #[must_use]
    pub(super) fn shutdown_until(mut self, deadline: std::time::Instant) -> bool {
        // Signal the loop; it drains what it can within the grace window.
        let _ = self.shutdown_tx.send(());
        if self.thread.is_none() {
            return true;
        }
        // Leave the thread in `self` until join or retain. A panic or a
        // dropped queued job then hits `Drop`, which retains without waiting.
        loop {
            if self.finished.load(Ordering::SeqCst) {
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                self.handle.mark_shutdown_incomplete();
                if let Some(thread) = self.thread.take() {
                    retain_unfinished_writer(thread);
                }
                return false;
            }
            std::thread::sleep((deadline - now).min(Duration::from_millis(20)));
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // A queued `spawn_blocking` shutdown can be dropped by later pool
        // cleanup before it runs. Retain the thread here and do not join it:
        // joining would wait out whatever is still inside SQLite.
        let Some(thread) = self.thread.take() else {
            return;
        };
        let _ = self.shutdown_tx.send(());
        self.handle.mark_shutdown_incomplete();
        if thread.is_finished() {
            let _ = thread.join();
        } else {
            retain_unfinished_writer(thread);
        }
    }
}

/// Marks the writer thread finished on every return path, including panic.
struct WriterFinished(Arc<std::sync::atomic::AtomicBool>);

impl Drop for WriterFinished {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn unfinished_writers() -> &'static std::sync::Mutex<Vec<std::thread::JoinHandle<()>>> {
    static WRITERS: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>> =
        std::sync::Mutex::new(Vec::new());
    &WRITERS
}

/// Keep a writer that did not exit within the drain grace. Finished handles
/// already in the registry are joined here. The stuck thread is not detached
/// and its write is not aborted.
fn retain_unfinished_writer(thread: std::thread::JoinHandle<()>) {
    let finished = {
        let mut guard = unfinished_writers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending = std::mem::take(&mut *guard);
        let (finished, mut pending): (Vec<_>, Vec<_>) = pending
            .into_iter()
            .partition(std::thread::JoinHandle::is_finished);
        pending.push(thread);
        *guard = pending;
        finished
    };
    for thread in finished {
        let _ = thread.join();
    }
}

/// Join writer threads that have finished since a bounded shutdown retained
/// them. Returns how many are still running.
#[cfg(test)]
pub fn reap_finished_writer_threads() -> usize {
    let mut guard = unfinished_writers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pending = std::mem::take(&mut *guard);
    let (finished, pending): (Vec<_>, Vec<_>) = pending
        .into_iter()
        .partition(std::thread::JoinHandle::is_finished);
    *guard = pending;
    let running = guard.len();
    drop(guard);
    for thread in finished {
        let _ = thread.join();
    }
    running
}

fn writer_loop(
    store: &Store,
    rx: &mpsc::Receiver<WriteCommand>,
    shutdown_rx: &mpsc::Receiver<()>,
    counters: &HistoryCounters,
) {
    let mut batch: Vec<HistoryRecord> = Vec::with_capacity(BATCH_MAX);
    loop {
        let shutting_down = shutdown_rx.try_recv().is_ok();

        // Fill a batch: block briefly for the first record, then drain
        // whatever is immediately available up to BATCH_MAX.
        match rx.recv_timeout(BATCH_WINDOW) {
            Ok(command) => {
                process_command(store, command, &mut batch, counters);
                let mut commands_processed = 1;
                while commands_processed < BATCH_MAX {
                    match rx.try_recv() {
                        Ok(command) => {
                            process_command(store, command, &mut batch, counters);
                            commands_processed += 1;
                        }
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

fn drain_at_shutdown(store: &Store, rx: &mpsc::Receiver<WriteCommand>, counters: &HistoryCounters) {
    let deadline = std::time::Instant::now() + SHUTDOWN_DRAIN_GRACE;
    let mut batch: Vec<HistoryRecord> = Vec::with_capacity(BATCH_MAX);
    loop {
        if std::time::Instant::now() >= deadline {
            // Count what we are abandoning, then stop.
            let mut abandoned = 0u64;
            while let Ok(command) = rx.try_recv() {
                abandon_command(command);
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
            Ok(command) => {
                process_command(store, command, &mut batch, counters);
            }
            Err(_) => {
                flush(store, &mut batch, counters);
                return;
            }
        }
    }
}

fn process_command(
    store: &Store,
    command: WriteCommand,
    batch: &mut Vec<HistoryRecord>,
    counters: &HistoryCounters,
) {
    match command {
        WriteCommand::BestEffort(record) => {
            batch.push(record);
            if batch.len() >= BATCH_MAX {
                flush(store, batch, counters);
            }
        }
        WriteCommand::Commit { record, reply } => {
            // Preserve producer order: everything queued before this receipt
            // is committed before the receipt-bearing record.
            flush(store, batch, counters);
            let result = store.insert(&record);
            match &result {
                Ok(InsertOutcome::Inserted | InsertOutcome::Replaced) => {
                    counters.written_total.fetch_add(1, Ordering::Relaxed);
                }
                Ok(InsertOutcome::Duplicate | InsertOutcome::StaleRejected) => {
                    counters.dedup_hits.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    counters.write_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(%error, "[history] receipt-bearing write failed");
                }
            }
            let _ = reply.send(result);
        }
    }
}

fn abandon_command(command: WriteCommand) {
    if let WriteCommand::Commit { reply, .. } = command {
        let _ = reply.send(Err(HistoryError::WriterClosed));
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::{reap_finished_writer_threads, Writer, SHUTDOWN_DRAIN_GRACE};
    use crate::history::record::{Direction, HistoryRecord, Provenance};
    use crate::history::store::{
        arm_query_lock_park, prepare_query_lock_park, HistoryQuery, QueryLockHold, Store,
    };
    use crate::history::Scope;

    struct Release(Arc<QueryLockHold>);

    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    fn waiting_record() -> HistoryRecord {
        HistoryRecord {
            msg_id: [9u8; 32],
            scope: Scope::Topic("x0x.test.1288.writer-wait".to_string()),
            author_agent: None,
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: 1,
            seen_at_ms: 1,
            direction: Direction::Inbound,
            content_type: "text/plain".to_string(),
            payload: b"writer-wait".to_vec(),
            signed_artifact: None,
            signature: None,
            sig_context: None,
            provenance: Provenance::LocalSend,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        }
    }

    /// A query holds the connection mutex and the writer is blocked in
    /// `insert`. `Writer::shutdown` returns within the drain grace, and the
    /// admitted write commits after the query releases the lock.
    #[test]
    fn issue1288_writer_shutdown_bounded_while_query_holds_lock() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("history.db")).unwrap());
        let hold = arm_query_lock_park(&store);
        let release = Release(Arc::clone(&hold));
        let query_store = Arc::clone(&store);
        let query = std::thread::spawn(move || {
            prepare_query_lock_park();
            let _ = query_store.query(&HistoryQuery {
                limit: 1,
                ..HistoryQuery::default()
            });
        });
        let park_deadline = Instant::now() + Duration::from_secs(2);
        while hold.parked() < 1 {
            assert!(
                Instant::now() < park_deadline,
                "the query did not park inside the connection lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let writer = Writer::spawn(Arc::clone(&store));
        let probe = writer.handle();
        let counters = writer.handle().counters();
        let entered = hold.writer_entered();
        writer.handle().record(waiting_record());
        let wait_deadline = Instant::now() + Duration::from_secs(2);
        while hold.writer_entered() <= entered {
            assert!(
                Instant::now() < wait_deadline,
                "the writer did not reach the connection lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let written = counters.written_total.load(Ordering::Relaxed);

        let (done_tx, done_rx) = mpsc::channel();
        let started = Instant::now();
        let shutdown = std::thread::spawn(move || {
            let completed = writer.shutdown();
            let _ = done_tx.send((started.elapsed(), completed));
        });
        let outcome = done_rx.recv_timeout(SHUTDOWN_DRAIN_GRACE + Duration::from_secs(3));
        if outcome.is_err() {
            drop(release);
            let _ = query.join();
            let _ = shutdown.join();
            panic!("writer shutdown did not return while the query held the connection");
        }
        let (elapsed, completed) = outcome.unwrap();
        assert!(
            !completed,
            "a writer still blocked in SQLite must not report a completed shutdown"
        );
        assert!(
            probe.shutdown_incomplete(),
            "the unfinished writer must stay visible to the caller"
        );
        assert!(
            elapsed + Duration::from_secs(1) >= SHUTDOWN_DRAIN_GRACE,
            "shutdown returned before the join bound ({elapsed:?})"
        );
        assert!(
            elapsed < SHUTDOWN_DRAIN_GRACE + Duration::from_secs(2),
            "shutdown exceeded the drain grace ({elapsed:?})"
        );
        assert_eq!(
            counters.written_total.load(Ordering::Relaxed),
            written,
            "the admitted write must still be waiting"
        );
        assert!(!hold.is_released());

        drop(release);
        let cleanup = Instant::now() + Duration::from_secs(2);
        while !query.is_finished() || reap_finished_writer_threads() > 0 {
            assert!(
                Instant::now() < cleanup,
                "the writer did not finish after the query released the lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            counters.written_total.load(Ordering::Relaxed) > written,
            "the admitted write must commit after the lock is released"
        );
        let _ = query.join();
        let _ = shutdown.join();
    }

    /// A worker that starts after the shutdown deadline retains the thread
    /// and returns. It does not open a second grace while the read is held.
    #[test]
    fn issue1288_writer_shutdown_past_deadline_retains_without_another_grace() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("history.db")).unwrap());
        let hold = arm_query_lock_park(&store);
        let release = Release(Arc::clone(&hold));
        let query_store = Arc::clone(&store);
        let query = std::thread::spawn(move || {
            prepare_query_lock_park();
            let _ = query_store.query(&HistoryQuery {
                limit: 1,
                ..HistoryQuery::default()
            });
        });
        let park_deadline = Instant::now() + Duration::from_secs(2);
        while hold.parked() < 1 {
            assert!(
                Instant::now() < park_deadline,
                "the query did not park inside the connection lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let writer = Writer::spawn(Arc::clone(&store));
        let probe = writer.handle();
        let counters = writer.handle().counters();
        let entered = hold.writer_entered();
        writer.handle().record(waiting_record());
        let wait_deadline = Instant::now() + Duration::from_secs(2);
        while hold.writer_entered() <= entered {
            assert!(
                Instant::now() < wait_deadline,
                "the writer did not reach the connection lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let written = counters.written_total.load(Ordering::Relaxed);

        let started = Instant::now();
        let completed = writer.shutdown_until(Instant::now());
        let elapsed = started.elapsed();
        assert!(
            !completed,
            "a writer still blocked after the deadline must not report completion"
        );
        assert!(
            probe.shutdown_incomplete(),
            "the unfinished writer must stay visible to the caller"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "a missed deadline must not wait another grace ({elapsed:?})"
        );
        assert_eq!(
            counters.written_total.load(Ordering::Relaxed),
            written,
            "the admitted write must still be waiting"
        );
        assert!(!hold.is_released());
        assert!(
            reap_finished_writer_threads() >= 1,
            "the writer thread must still be in custody"
        );

        drop(release);
        let cleanup = Instant::now() + Duration::from_secs(2);
        while !query.is_finished() || reap_finished_writer_threads() > 0 {
            assert!(
                Instant::now() < cleanup,
                "the writer did not finish after the query released the lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            counters.written_total.load(Ordering::Relaxed) > written,
            "the admitted write must commit after the lock is released"
        );
        let _ = query.join();
    }

    struct PoolGate(Option<mpsc::Sender<()>>);

    impl Drop for PoolGate {
        fn drop(&mut self) {
            if let Some(gate) = self.0.take() {
                let _ = gate.send(());
            }
        }
    }

    /// One blocking thread is stuck, and a read still holds the store past
    /// the drain grace. Shutdown returns an incomplete result inside that
    /// grace. Freeing the pool afterwards must not wait another grace.
    #[test]
    fn issue1288_saturated_blocking_pool_returns_incomplete_writer_shutdown() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let service = crate::history::HistoryService::start(
                &crate::history::HistoryConfig {
                    enabled: true,
                    db_path: Some(dir.path().join("history.db")),
                    ..crate::history::HistoryConfig::default()
                },
                dir.path(),
            )
            .unwrap();
            let handle = service.handle();
            let hold = arm_query_lock_park(handle.store());
            let release = Release(Arc::clone(&hold));
            let query_store = Arc::clone(handle.store());
            let query = std::thread::spawn(move || {
                prepare_query_lock_park();
                let _ = query_store.query(&HistoryQuery {
                    limit: 1,
                    ..HistoryQuery::default()
                });
            });
            let park_deadline = Instant::now() + Duration::from_secs(2);
            while hold.parked() < 1 {
                assert!(
                    Instant::now() < park_deadline,
                    "the read did not park inside the connection lock"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            let (started_tx, started_rx) = mpsc::channel();
            let (gate_tx, gate_rx) = mpsc::channel();
            let pool_gate = PoolGate(Some(gate_tx));
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                let _ = gate_rx.recv();
            });
            started_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("the blocking worker did not start");

            let counters = handle.counters();
            let entered = hold.writer_entered();
            handle.record(waiting_record());
            let wait_deadline = Instant::now() + Duration::from_secs(2);
            while hold.writer_entered() <= entered {
                assert!(
                    Instant::now() < wait_deadline,
                    "the writer did not reach the connection lock"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let written = counters.written_total.load(Ordering::Relaxed);

            let started = Instant::now();
            let outcome = tokio::time::timeout(
                SHUTDOWN_DRAIN_GRACE + Duration::from_secs(3),
                service.shutdown(),
            )
            .await;
            let elapsed = started.elapsed();
            assert!(
                outcome.is_ok(),
                "shutdown waited for a blocking worker ({elapsed:?})"
            );
            assert!(
                elapsed + Duration::from_secs(1) >= SHUTDOWN_DRAIN_GRACE,
                "shutdown returned before the grace that covers queueing ({elapsed:?})"
            );
            assert!(
                elapsed < SHUTDOWN_DRAIN_GRACE + Duration::from_secs(2),
                "shutdown exceeded the grace that covers queueing ({elapsed:?})"
            );
            assert!(
                handle.writer_shutdown_incomplete(),
                "a queued writer shutdown must be an incomplete result"
            );
            assert!(
                hold.parked() >= 1 && !hold.is_released(),
                "the read must still be held past the budget"
            );
            assert!(
                !blocker.is_finished(),
                "the blocking pool must stay saturated past the budget"
            );
            assert_eq!(
                counters.written_total.load(Ordering::Relaxed),
                written,
                "the admitted write must still be waiting"
            );

            // The queued shutdown runs once the pool frees. The read still
            // holds the writer in SQLite, so a second grace would be visible.
            let running_before = reap_finished_writer_threads();
            let cleanup_started = Instant::now();
            drop(pool_gate);
            let cleanup_deadline = Instant::now() + Duration::from_secs(2);
            while reap_finished_writer_threads() <= running_before {
                assert!(
                    Instant::now() < cleanup_deadline,
                    "pool cleanup waited another grace after the budget ({:?})",
                    cleanup_started.elapsed()
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(
                hold.parked() >= 1 && !hold.is_released(),
                "the read must stay held while the queued shutdown is cleaned up"
            );

            drop(release);
            let finished = Instant::now() + Duration::from_secs(2);
            while !query.is_finished()
                || !blocker.is_finished()
                || reap_finished_writer_threads() > 0
                || counters.written_total.load(Ordering::Relaxed) <= written
            {
                assert!(
                    Instant::now() < finished,
                    "the admitted write did not finish after the read released the lock"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let _ = query.join();
            drop(blocker);
        });
    }
}
