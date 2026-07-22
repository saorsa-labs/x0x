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
    HistoryQuery, HistoryStats, InsertOutcome, RetentionPolicy, ScopeLimit, Store, StoredRecord,
    MAX_QUERY_LIMIT,
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

/// Cheap-to-clone handle producers and readers hold.
#[derive(Clone, Debug)]
pub struct HistoryHandle {
    writer: WriterHandle,
    store: Arc<Store>,
}

impl HistoryHandle {
    /// Enqueue a record (never blocks; sheds on full — ADR-0023 §5).
    pub fn record(&self, record: HistoryRecord) {
        self.writer.record(record);
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
}

/// Owns the store, the writer thread, and the reaper task.
#[derive(Debug)]
pub struct HistoryService {
    handle: HistoryHandle,
    writer: Option<writer::Writer>,
    reaper: tokio::task::JoinHandle<()>,
}

impl HistoryService {
    /// Open the store at `config.db_path` (or `<data_dir>/history.db`) and
    /// start the writer thread + retention reaper.
    ///
    /// Must be called from within a tokio runtime (the reaper is a tokio
    /// task).
    pub fn start(config: &HistoryConfig, data_dir: &std::path::Path) -> HistoryResult<Self> {
        let db_path = config
            .db_path
            .clone()
            .unwrap_or_else(|| data_dir.join("history.db"));
        let store = Arc::new(Store::open(&db_path)?);
        let writer = writer::Writer::spawn(Arc::clone(&store));
        let handle = HistoryHandle {
            writer: writer.handle(),
            store: Arc::clone(&store),
        };
        let reaper = reaper::spawn(
            store,
            config.retention_policy(),
            handle.counters(),
            HISTORY_REAPER_INTERVAL_SECS,
        );
        Ok(Self {
            handle,
            writer: Some(writer),
            reaper,
        })
    }

    /// The shared handle.
    #[must_use]
    pub fn handle(&self) -> HistoryHandle {
        self.handle.clone()
    }

    /// Stop the reaper and drain the writer (bounded grace, then abandon
    /// with count — ADR-0023 §5 shutdown semantics).
    pub async fn shutdown(mut self) {
        self.reaper.abort();
        if let Some(writer) = self.writer.take() {
            // Writer drain is blocking (joins an OS thread).
            let _ = tokio::task::spawn_blocking(move || writer.shutdown()).await;
        }
    }
}
