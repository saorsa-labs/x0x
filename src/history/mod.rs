//! Durable local history (ADR-0023).
//!
//! Default-on in `x0xd`, opt-in for library embedders
//! (`AgentBuilder::with_history`). The store is SQLite (bundled rusqlite)
//! in the instance data directory; writes go through a bounded,
//! shed-on-full writer thread so hot paths never block on disk; a periodic
//! reaper enforces retention. History is **local-only** — it is never
//! served to the network (ADR-0023 non-goal).
//!
//! `history.db` must live on local disk: WAL requires working file locks
//! (no NFS/SMB). The store holds SQLite's `EXCLUSIVE` locking mode so a
//! second process opening the same database fails loud at open.

pub mod classify;
pub mod record;
pub mod store;
pub mod writer;

mod reaper;

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::HistoryResult;

pub use record::{Direction, HistoryRecord, MessageClass, Provenance, Scope};
pub use store::{
    HistoryQuery, HistoryStats, InsertOutcome, PinnedScopes, RetainOutcome, RetentionPolicy,
    ScopeLimit, ScopeSummary, Store, StoredRecord, HISTORY_QUARANTINE_PIN_ABSOLUTE_DIVISOR,
    HISTORY_QUARANTINE_PIN_BASE_DIVISOR, HISTORY_QUARANTINE_PIN_MULTIPLIER, MAX_QUERY_LIMIT,
};
pub use writer::{HistoryCounters, WriterHandle, WRITER_QUEUE_CAPACITY};

pub use reaper::HISTORY_REAPER_INTERVAL_SECS;

/// Default whole-database byte budget: 1 GiB (ADR-0023 §6).
pub const DEFAULT_MAX_BYTES: u64 = 1_073_741_824;

/// History configuration (TOML `[history]` in the daemon; builder option in
/// the library).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryConfig {
    /// Master switch. Library default **off**; the daemon defaults this to
    /// **on** (ADR-0023: core capability, `enabled = false` is the escape
    /// hatch).
    #[serde(default)]
    pub enabled: bool,
    /// Whole-database byte budget (default 1 GiB).
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    /// Age bound in days; 0 (default) disables age eviction.
    #[serde(default)]
    pub max_age_days: u64,
    /// Per-scope byte overrides.
    #[serde(default)]
    pub scope_limits: Vec<ScopeLimit>,
    /// Explicit database path. `None` ⇒ `<data_dir>/history.db`.
    #[serde(default)]
    pub db_path: Option<PathBuf>,
    /// Pub/sub topics this daemon records (ADR-0023 §4 "Durable opt-in").
    /// A **local ingest option**: it never obliges any other daemon, and a
    /// publisher cannot force recording on a receiver.
    #[serde(default)]
    pub record_topics: Vec<String>,
}

fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}

impl Default for HistoryConfig {
    /// Library default: disabled (zero-footprint embedding).
    fn default() -> Self {
        Self {
            enabled: false,
            max_bytes: DEFAULT_MAX_BYTES,
            max_age_days: 0,
            scope_limits: Vec::new(),
            db_path: None,
            record_topics: Vec::new(),
        }
    }
}

impl HistoryConfig {
    /// The daemon default: enabled, 1 GiB budget (ADR-0023 default-on).
    #[must_use]
    pub fn daemon_default() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    fn retention_policy(&self) -> RetentionPolicy {
        RetentionPolicy {
            max_bytes: self.max_bytes,
            max_age_days: self.max_age_days,
            scope_limits: self.scope_limits.clone(),
        }
    }
}

/// ADR-0068 D1: where the retention reaper learns which scopes are
/// fork-quarantined.
///
/// The history module deliberately knows nothing about named groups, so the
/// marker lookup stays in the daemon (one resolver, both spellings) and is
/// injected through [`QuarantinePinSlot`]. Called once per retention pass,
/// BEFORE the blocking `retain`, so an implementation may take async locks —
/// but it must not hold one across the return.
pub trait QuarantinePins: Send + Sync + 'static {
    /// Canonical scope strings (`group:<id>`) that currently hold a live
    /// fork-quarantine marker, in both spellings where a group's map key
    /// differs from its stable id. An empty vector pins nothing.
    fn pinned_scopes(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + '_>>;
}

/// Set-once slot holding the [`QuarantinePins`] source for this store's
/// reaper.
///
/// Set-once because the daemon installs exactly one source, after `AppState`
/// exists (the store is created by the `Agent`, which `AppState` owns). Never
/// set ⇒ nothing is pinned and retention behaves exactly as it did before
/// ADR-0068, which is the library-embedding contract: an embedder has no
/// marker to honour.
#[derive(Default)]
pub struct QuarantinePinSlot(std::sync::OnceLock<Arc<dyn QuarantinePins>>);

impl std::fmt::Debug for QuarantinePinSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuarantinePinSlot")
            .field("installed", &self.0.get().is_some())
            .finish()
    }
}

impl QuarantinePinSlot {
    /// Install the pin source. Returns `false` if one was already installed
    /// (the existing source is kept).
    pub fn install(&self, pins: Arc<dyn QuarantinePins>) -> bool {
        self.0.set(pins).is_ok()
    }

    /// The pinned scopes for the pass about to run, or none when no source is
    /// installed.
    pub async fn pinned(&self) -> store::PinnedScopes {
        match self.0.get() {
            Some(pins) => store::PinnedScopes::from_canonical(pins.pinned_scopes().await),
            None => store::PinnedScopes::none(),
        }
    }
}

/// Cheap-to-clone handle producers and readers hold.
#[derive(Clone, Debug)]
pub struct HistoryHandle {
    writer: WriterHandle,
    store: Arc<Store>,
    /// ADR-0068 D1: shared with the reaper, so the daemon can install the
    /// pin source through any handle after `AppState` is built.
    quarantine_pins: Arc<QuarantinePinSlot>,
}

impl HistoryHandle {
    /// Enqueue a record (never blocks; sheds on full — ADR-0023 §5).
    pub fn record(&self, record: HistoryRecord) {
        self.writer.record(record);
    }

    /// Enqueue a record and wait for its SQLite transaction to commit.
    ///
    /// This is reserved for protocol surfaces whose success receipt promises
    /// durable local history. Hot paths should continue using [`Self::record`].
    pub async fn record_committed(&self, record: HistoryRecord) -> HistoryResult<InsertOutcome> {
        self.writer.record_committed(record).await
    }

    /// Read access to the store. Synchronous — call from `spawn_blocking`
    /// on async paths.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Writer/reaper counters for `/diagnostics/history`.
    #[must_use]
    pub fn counters(&self) -> Arc<HistoryCounters> {
        self.writer.counters()
    }

    /// ADR-0068 D1: install the fork-quarantine pin source the reaper
    /// consults. Returns `false` if one is already installed.
    pub fn install_quarantine_pins(&self, pins: Arc<dyn QuarantinePins>) -> bool {
        self.quarantine_pins.install(pins)
    }
}

/// Owns the store, the writer thread, and the reaper task.
#[derive(Debug)]
pub struct HistoryService {
    handle: HistoryHandle,
    writer: Option<writer::Writer>,
    reaper: tokio::task::JoinHandle<()>,
}

/// What [`HistoryService::open`] produced: the opened store plus everything
/// the service's tasks need, with **no tasks spawned yet**. Dropping it
/// closes the store and releases the exclusive database lock. This is the
/// cancellation-safe unit the blocking-pool boot path moves across the
/// `await` (review round 2, R2-E): if the builder future is dropped while
/// the blocking `Store::open` is still running, the runtime drops this value
/// when the task completes — instead of leaking an unowned writer thread and
/// reaper that hold the database forever.
pub(crate) struct OpenedHistory {
    store: Arc<Store>,
    policy: RetentionPolicy,
    quarantine_pins: Arc<QuarantinePinSlot>,
}

impl HistoryService {
    /// Open the store at `config.db_path` (or `<data_dir>/history.db`) and
    /// start the writer thread + retention reaper.
    ///
    /// The constructor itself is SYNCHRONOUS and blocking — migrations plus
    /// the canonical-id backfill can take minutes on a large history — and
    /// must be called from within a tokio runtime (the reaper is a tokio
    /// task). An async caller runs it on the blocking pool:
    /// `tokio::task::spawn_blocking(move || HistoryService::start(&cfg, &dir))`
    /// with owned config/path values. `AgentBuilder::build` does exactly
    /// that, through the cancellation-safe open/start-tasks split this
    /// method is a shorthand for.
    pub fn start(config: &HistoryConfig, data_dir: &std::path::Path) -> HistoryResult<Self> {
        Ok(Self::start_tasks(Self::open(config, data_dir)?))
    }

    /// Open (migrate + canonical backfill) WITHOUT spawning any tasks.
    ///
    /// Blocking; run inside `spawn_blocking` on async paths. The builder
    /// calls this in the blocking closure and defers [`Self::start_tasks`]
    /// to after the `await`: a cancelled build future can therefore never
    /// leave an unowned writer/reaper running — the runtime drops the
    /// returned value, closing the store.
    pub(crate) fn open(
        config: &HistoryConfig,
        data_dir: &std::path::Path,
    ) -> HistoryResult<OpenedHistory> {
        let db_path = config
            .db_path
            .clone()
            .unwrap_or_else(|| data_dir.join("history.db"));
        Ok(OpenedHistory {
            store: Arc::new(Store::open(&db_path)?),
            policy: config.retention_policy(),
            quarantine_pins: Arc::new(QuarantinePinSlot::default()),
        })
    }

    /// Spawn the writer thread + retention reaper over an [`Self::open`]ed
    /// store. Only ever called by an owner that survived the open — the
    /// public [`Self::start`], or the builder after its `await` resolved.
    pub(crate) fn start_tasks(opened: OpenedHistory) -> Self {
        let OpenedHistory {
            store,
            policy,
            quarantine_pins,
        } = opened;
        let writer = writer::Writer::spawn(Arc::clone(&store));
        let handle = HistoryHandle {
            writer: writer.handle(),
            store: Arc::clone(&store),
            quarantine_pins: Arc::clone(&quarantine_pins),
        };
        let reaper = reaper::spawn(
            store,
            policy,
            handle.counters(),
            HISTORY_REAPER_INTERVAL_SECS,
            quarantine_pins,
        );
        Self {
            handle,
            writer: Some(writer),
            reaper,
        }
    }

    /// The shared handle.
    #[must_use]
    pub fn handle(&self) -> HistoryHandle {
        self.handle.clone()
    }

    /// Stop the reaper and drain the writer (bounded grace, then abandon
    /// with count — ADR-0023 §5 shutdown semantics).
    ///
    /// The reaper task owns an `Arc<Store>` for its whole life, so an
    /// aborted-but-unawaited reaper keeps the SQLite connection open until
    /// the runtime happens to drop the cancelled task — potentially after
    /// the server supervisor has finished and released `instance.lock`
    /// (#661 item 2). Awaiting the abort parks that release deterministically
    /// *inside* `shutdown`, before the drain that precedes lock release.
    /// Residual, accepted: a `retain` already inside its `spawn_blocking`
    /// runs to completion holding the connection — blocking code cannot be
    /// cancelled — which is bounded by one retention pass and covered by the
    /// restart-side retry in `tests/f2_public_group_bootstrap_wiring.rs`.
    pub async fn shutdown(mut self) {
        self.reaper.abort();
        // Awaits the cancelled task's reaping: returns promptly with a
        // cancelled JoinError once the runtime drops the aborted future.
        let _ = self.reaper.await;
        if let Some(writer) = self.writer.take() {
            // Writer drain is blocking (joins an OS thread).
            let _ = tokio::task::spawn_blocking(move || writer.shutdown()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review round 2 (R2-E): cancelling the builder while its blocking
    /// `Store::open` runs must not leak an unowned writer/reaper that holds
    /// the exclusive database lock forever. The builder moves only the
    /// NOT-YET-STARTED opened store ([`OpenedHistory`]) across the `await`;
    /// when the build future is dropped, the runtime drops that value when
    /// the blocking task completes — closing the store — because no tasks
    /// were ever spawned. This test reproduces the builder's exact shape:
    /// the join handle is dropped mid-flight (the cancelled `await`), the
    /// closure still finishes, and the history file must become openable
    /// again. `Store` holds `PRAGMA locking_mode = EXCLUSIVE`, so a leaked
    /// owner would fail every reopen here.
    #[tokio::test]
    async fn cancelled_boot_open_leaves_no_orphan_owner() {
        let dir = tempfile::tempdir().unwrap();
        let config = HistoryConfig {
            enabled: true,
            db_path: Some(dir.path().join("history.db")),
            ..HistoryConfig::default()
        };
        // Seed a database so the blocking open does real work.
        drop(Store::open(config.db_path.as_ref().unwrap()).unwrap());

        // The builder's blocking closure: open WITHOUT starting tasks.
        let opened_cfg = config.clone();
        let opened_dir = dir.path().to_path_buf();
        // 0 = running, 1 = the closure's open succeeded, 2 = it failed.
        let finished = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let finished_in_closure = Arc::clone(&finished);
        let join = tokio::task::spawn_blocking(move || {
            let opened = HistoryService::open(&opened_cfg, &opened_dir);
            // Signals the test the closure is done; the task harness then
            // drops the returned (unclaimed, un-started) value.
            let outcome = if opened.is_ok() { 1 } else { 2 };
            finished_in_closure.store(outcome, std::sync::atomic::Ordering::Release);
            opened
        });
        // The cancelled build: nobody awaits the open.
        drop(join);

        // Wait until the closure has really opened the store, so the probe
        // below cannot win the lock before the cancelled open takes it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while finished.load(std::sync::atomic::Ordering::Acquire) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the cancelled boot open never finished"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(
            finished.load(std::sync::atomic::Ordering::Acquire),
            1,
            "the cancelled boot open itself must succeed"
        );

        // Then wait for the runtime to drop its unclaimed output, and prove
        // the lock came back: a fresh open must succeed. Under the round-2
        // shape (tasks started inside the closure) the reaper would hold the
        // store forever and every probe would fail until the deadline.
        loop {
            if HistoryService::open(&config, dir.path()).is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "history.db stayed exclusively locked after a cancelled boot open: \
                 an unowned service is holding the store"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}
