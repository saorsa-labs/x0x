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
pub mod policy;
pub mod record;
pub mod store;
pub mod trim;
pub mod writer;

mod reaper;

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::{HistoryError, HistoryResult};

pub use policy::{
    ClassLimit, CompiledBounds, CompiledTopicRule, DmRecording, HistoryPolicy, RetainedClass,
    TopicRecording, TopicRule, MAX_POLICY_RULES, MAX_TOPIC_PREFIX_BYTES,
};
pub use record::{Direction, HistoryRecord, MessageClass, Provenance, Scope};
pub use store::{
    HistoryQuery, HistoryStats, InsertOutcome, PinnedScopes, RetainOutcome, RetentionPolicy,
    ScopeLimit, ScopeSummary, Store, StoredRecord, HISTORY_QUARANTINE_PIN_ABSOLUTE_DIVISOR,
    HISTORY_QUARANTINE_PIN_BASE_DIVISOR, HISTORY_QUARANTINE_PIN_MULTIPLIER, MAX_QUERY_LIMIT,
};
pub use trim::{
    RetainDeleted, RetainError, RetainOptions, RetainReport, RetainState, RetainStop,
    RETAIN_DEFAULT_BUDGET_MS, RETAIN_DEFAULT_MAX_ROWS, RETAIN_MAX_BUDGET_MS, RETAIN_MAX_ROWS,
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
    /// ADR 0116 §1: how this node records ordinary inbound and outbound
    /// DMs. Default `inherit` (record as ADR 0023 classifies them).
    /// Omitted from serialized output while it is the default.
    #[serde(default, skip_serializing_if = "DmRecording::is_inherit")]
    pub dm_recording: DmRecording,
    /// ADR 0116 §1: per-class retention bounds (`[[history.class_limits]]`).
    /// Default empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub class_limits: Vec<ClassLimit>,
    /// ADR 0116 §1: topic-prefix recording and retention rules
    /// (`[[history.topic_rules]]`). They only filter topics that
    /// `record_topics` already selects. Default empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topic_rules: Vec<TopicRule>,
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
            dm_recording: DmRecording::Inherit,
            class_limits: Vec::new(),
            topic_rules: Vec::new(),
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

    /// Validate and compile the ADR 0116 rules (`dm_recording`,
    /// `class_limits`, `topic_rules`). This is the ADR 0116 §1 check only;
    /// [`Self::validate`] also refuses rules this build cannot enforce.
    ///
    /// # Errors
    /// [`crate::error::HistoryError::InvalidConfig`] names the rule that
    /// fails validation.
    pub fn compile_policy(&self) -> HistoryResult<HistoryPolicy> {
        HistoryPolicy::compile(self.dm_recording, &self.class_limits, &self.topic_rules)
    }

    /// The check history runs before it opens, and the daemon runs at
    /// config load whatever `enabled` says (ADR 0116 §1).
    ///
    /// # Errors
    /// [`crate::error::HistoryError::InvalidConfig`] names the first rule
    /// refused.
    pub fn validate(&self) -> HistoryResult<HistoryPolicy> {
        self.compile_policy()
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
    /// ADR 0116 §1: the compiled local recording and retention policy,
    /// fixed at open. A policy change needs a restart (ADR 0116 §4).
    policy: Arc<HistoryPolicy>,
    /// The global and exact-scope retention bounds the reaper enforces,
    /// fixed at open (reported by `GET /history/policy`).
    retention: Arc<RetentionPolicy>,
}

impl HistoryHandle {
    /// ADR 0116 §3: the typed local history policy this store was opened
    /// with. [`HistoryPolicy::is_unset`] when no ADR 0116 key is set.
    #[must_use]
    pub fn policy(&self) -> &HistoryPolicy {
        &self.policy
    }

    /// The global and exact-scope retention bounds this store's reaper
    /// enforces, as fixed at open.
    #[must_use]
    pub fn retention_policy(&self) -> &RetentionPolicy {
        &self.retention
    }

    /// Enqueue a record (never blocks; sheds on full — ADR-0023 §5).
    ///
    /// ADR 0116 §3: a record the local policy suppresses is dropped here,
    /// before it is enqueued, and counted. That is an ordinary DM under
    /// `dm_recording = "ephemeral"`, or a message on a topic whose winning
    /// rule is `ephemeral`. It writes no row, payload, artifact, FTS entry,
    /// canonical projection or replay source.
    pub fn record(&self, record: HistoryRecord) {
        if self.suppressed_by_policy(&record) {
            return;
        }
        self.writer.record(record);
    }

    /// Enqueue a record and wait for its SQLite transaction to commit.
    ///
    /// This is reserved for protocol surfaces whose success receipt promises
    /// durable local history. Hot paths should continue using [`Self::record`].
    ///
    /// ADR 0116 §3: a record the local policy suppresses is not written,
    /// and the call returns [`HistoryError::PolicySuppressed`], never a
    /// success, so a durable receipt can never be built on it.
    pub async fn record_committed(&self, record: HistoryRecord) -> HistoryResult<InsertOutcome> {
        if self.suppressed_by_policy(&record) {
            return Err(HistoryError::PolicySuppressed);
        }
        self.writer.record_committed(record).await
    }

    /// ADR 0116 §3, the shared write boundary: does the local policy keep
    /// `record` out of history? Counts it when it does.
    ///
    /// - Ordinary DM: `Scope::Dm` with no `replace_key` (ruling Q5). That
    ///   covers every DM producer: the gossip inbox, the raw-QUIC path and
    ///   the outbound DM record. A Replaceable row in DM scope, such as an
    ///   imported agent card, is not a DM and is kept.
    /// - Topic message: `Scope::Topic` whose winning rule is `ephemeral`.
    /// - Group rows are never suppressed (quarantine ingest stays
    ///   tag-and-retain).
    ///
    /// The counters carry no topic or payload.
    fn suppressed_by_policy(&self, record: &HistoryRecord) -> bool {
        let dm = matches!(record.scope, Scope::Dm(_))
            && record.replace_key.is_none()
            && self.policy.suppresses_ordinary_dms();
        let topic = !dm
            && matches!(&record.scope, Scope::Topic(name) if self.policy.suppresses_topic(name));
        if !(dm || topic) {
            return false;
        }
        let counters = self.writer.counters();
        let counter = if dm {
            &counters.policy_suppressed_dm_total
        } else {
            &counters.policy_suppressed_topic_total
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
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

    /// ADR 0116 §4: one bounded runtime trim of this store under its own
    /// startup policy, the same service `POST /history/retain` and
    /// `x0x history retain` use.
    ///
    /// - It refreshes the fork-quarantine pins from the installed pin source
    ///   for this call. A library with no pin source pins nothing (ADR
    ///   0068's no-pin contract).
    /// - It shares admission with the reaper: while a reaper pass or another
    ///   trim holds the store it returns [`RetainError::Busy`] at once,
    ///   rather than queueing.
    /// - The SQLite work runs on the blocking pool. Dropping the returned
    ///   future cancels the trim at its next committed boundary.
    /// - Use it before `serve()` to trim without opening SQLite yourself.
    ///
    /// # Errors
    /// [`RetainError::InvalidOptions`] for an out-of-range budget,
    /// [`RetainError::Busy`], or [`RetainError::Failed`] with the counts of
    /// the batches committed before an SQLite failure.
    pub async fn retain(&self, options: RetainOptions) -> Result<RetainReport, RetainError> {
        options.validate()?;
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_millis(u64::from(options.budget_ms));
        let pinned = self.quarantine_pins.pinned().await;
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _cancel_on_drop = trim::CancelOnDrop(Arc::clone(&cancel));
        let store = Arc::clone(&self.store);
        let retention = Arc::clone(&self.retention);
        let rules = Arc::clone(&self.policy);
        let max_rows = u64::from(options.max_rows);
        let joined = tokio::task::spawn_blocking(move || {
            store.trim(
                &retention,
                &rules,
                &pinned,
                &trim::TrimBudget {
                    max_rows,
                    started,
                    deadline,
                    cancel: &cancel,
                },
            )
        })
        .await;
        match joined {
            Ok(result) => result,
            Err(join) => Err(RetainError::Failed {
                error: HistoryError::Database(format!("history trim task did not finish: {join}")),
                committed: RetainReport::new(
                    RetainState::MoreWork,
                    RetainDeleted::default(),
                    started.elapsed(),
                    None,
                ),
            }),
        }
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
    /// ADR 0116 §1: validated before the store opened.
    rules: Arc<HistoryPolicy>,
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
        // ADR 0116 §1: refuse a bad rule before history opens: no database
        // file is created or migrated for a config that will not run.
        let rules = Arc::new(config.validate()?);
        let db_path = config
            .db_path
            .clone()
            .unwrap_or_else(|| data_dir.join("history.db"));
        let store = Store::open(&db_path)?;
        // Codex review of slice B, round 2 (controller decision): topic-rule
        // limits match topic names in SQL as UTF-8 bytes, so they need a
        // UTF-8 database. On a database created with another text encoding
        // they are refused here, after `Store::open` and with no other file
        // change. Everything else still opens there, as before.
        if rules.bounded_topic_rule_count() > 0 && !store.text_encoding_is_utf8() {
            return Err(HistoryError::InvalidConfig(format!(
                "[[history.topic_rules]] max_bytes / max_age_days need a UTF-8 history \
                 database, but {} uses {}. Remove the topic limits, or use a UTF-8 history \
                 database",
                db_path.display(),
                store.text_encoding()
            )));
        }
        Ok(OpenedHistory {
            store: Arc::new(store),
            policy: config.retention_policy(),
            quarantine_pins: Arc::new(QuarantinePinSlot::default()),
            rules,
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
            rules,
        } = opened;
        let writer = writer::Writer::spawn(Arc::clone(&store));
        let handle = HistoryHandle {
            writer: writer.handle(),
            store: Arc::clone(&store),
            quarantine_pins: Arc::clone(&quarantine_pins),
            policy: Arc::clone(&rules),
            retention: Arc::new(policy.clone()),
        };
        let reaper = reaper::spawn(
            store,
            policy,
            rules,
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

    // ── ADR 0116 §1: `[history]` rule configuration and validation ──────
    //
    // Each case decodes a `[history]` table the way the daemon does (TOML)
    // and then opens history, the library's path. Validation must refuse a
    // bad rule at one of those two steps, before any history is open.

    /// Decode `body` as a `[history]` table, then open history in `dir`.
    /// `Err` names the step that refused and carries its message.
    fn open_history_toml(dir: &std::path::Path, body: &str) -> Result<(), String> {
        let decoded: HistoryConfig = toml::from_str(body).map_err(|e| format!("decode: {e}"))?;
        let config = HistoryConfig {
            enabled: true,
            db_path: Some(dir.join("history.db")),
            ..decoded
        };
        HistoryService::open(&config, dir)
            .map(drop)
            .map_err(|e| format!("open: {e}"))
    }

    /// Assert that `body` is refused with a message containing `needle`.
    fn assert_refused(body: &str, needle: &str) {
        let dir = tempfile::tempdir().unwrap();
        match open_history_toml(dir.path(), body) {
            Ok(()) => panic!("history opened, but this config must be refused ({needle}):\n{body}"),
            Err(message) => assert!(
                message.contains(needle),
                "refused for the wrong reason; wanted {needle:?}, got {message:?}\n{body}"
            ),
        }
    }

    /// Assert that `body` decodes and history opens.
    fn assert_opens(body: &str) {
        let dir = tempfile::tempdir().unwrap();
        if let Err(message) = open_history_toml(dir.path(), body) {
            panic!("history must open with this config, got {message:?}\n{body}");
        }
    }

    #[test]
    fn adr0116_rejects_a_duplicate_class_limit() {
        assert_refused(
            "[[class_limits]]\nclass = \"durable\"\nmax_bytes = 1\n\n\
             [[class_limits]]\nclass = \"durable\"\nmax_age_days = 7\n",
            "more than one entry for class \"durable\"",
        );
    }

    #[test]
    fn adr0116_rejects_unknown_keys_in_new_rule_objects() {
        assert_refused(
            "[[class_limits]]\nclass = \"durable\"\nmax_bytez = 1\n",
            "unknown field `max_bytez`",
        );
        assert_refused(
            "[[topic_rules]]\nprefix = \"app.\"\nrecord = \"ephemeral\"\n",
            "unknown field `record`",
        );
    }

    #[test]
    fn adr0116_rejects_unknown_values() {
        // `ephemeral` is not a retained class: it cannot carry a budget.
        assert_refused(
            "[[class_limits]]\nclass = \"ephemeral\"\nmax_bytes = 1\n",
            "unknown variant `ephemeral`",
        );
        assert_refused("dm_recording = \"never\"\n", "unknown variant `never`");
        assert_refused(
            "[[topic_rules]]\nprefix = \"app.\"\nrecording = \"drop\"\n",
            "unknown variant `drop`",
        );
    }

    /// Q8: a class entry must set `max_bytes` or a positive age. A zero or
    /// omitted age adds no bound, so it does not count.
    #[test]
    fn adr0116_rejects_a_class_limit_without_a_bound() {
        for body in [
            "[[class_limits]]\nclass = \"durable\"\n",
            "[[class_limits]]\nclass = \"replaceable\"\nmax_age_days = 0\n",
        ] {
            assert_refused(body, "sets neither max_bytes nor a positive max_age_days");
        }
    }

    /// Zero and omitted are different for bytes and the same for age.
    /// `max_bytes = 0` is a real bound (retain no eligible rows), so it is
    /// accepted; a zero age alone bounds nothing and is refused.
    #[test]
    fn adr0116_zero_bytes_is_a_bound_but_zero_age_is_not() {
        assert_opens("[[class_limits]]\nclass = \"durable\"\nmax_bytes = 0\n");
        assert_refused(
            "[[class_limits]]\nclass = \"durable\"\nmax_age_days = 0\n",
            "sets neither max_bytes nor a positive max_age_days",
        );
    }

    #[test]
    fn adr0116_rejects_duplicate_and_empty_topic_prefixes() {
        assert_refused(
            "[[topic_rules]]\nprefix = \"app.chat\"\n\n[[topic_rules]]\nprefix = \"app.chat\"\n",
            "more than one rule for prefix \"app.chat\"",
        );
        assert_refused(
            "[[topic_rules]]\nprefix = \"\"\n",
            "prefix must not be empty",
        );
    }

    /// The prefix bound is 256 UTF-8 BYTES, not characters: `é` is two.
    #[test]
    fn adr0116_prefix_length_is_bounded_in_bytes() {
        let at_limit = format!("{}é", "a".repeat(254)); // 256 bytes
        let over_limit = format!("{}é", "a".repeat(255)); // 257 bytes, 256 chars
        assert_opens(&format!("[[topic_rules]]\nprefix = \"{at_limit}\"\n"));
        assert_refused(
            &format!("[[topic_rules]]\nprefix = \"{over_limit}\"\n"),
            "at most 256 UTF-8 bytes",
        );
    }

    /// At most 256 new rules in total, class entries included.
    #[test]
    fn adr0116_rule_count_is_bounded() {
        let rules = |n: usize| {
            (0..n)
                .map(|i| format!("[[topic_rules]]\nprefix = \"t{i}.\"\n"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_opens(&rules(256));
        assert_refused(&rules(257), "at most 256 are allowed");
        assert_refused(
            &format!(
                "[[class_limits]]\nclass = \"durable\"\nmax_bytes = 1\n\n{}",
                rules(256)
            ),
            "at most 256 are allowed",
        );
    }

    /// A positive age must fit `i64` milliseconds. (A byte budget above
    /// `i64::MAX` cannot be written in TOML at all; the library-side check
    /// is covered in `policy.rs`.)
    #[test]
    fn adr0116_rejects_an_overflowing_age() {
        assert_refused(
            "[[class_limits]]\nclass = \"durable\"\nmax_age_days = 106751991168\n",
            "overflows",
        );
    }

    /// Slice C enforces the `ephemeral` recording modes, so every valid rule
    /// opens; none is refused for being unenforced.
    #[test]
    fn adr0116_every_valid_rule_opens() {
        for body in [
            "dm_recording = \"ephemeral\"\n",
            "[[topic_rules]]\nprefix = \"app.sync.\"\nrecording = \"ephemeral\"\n",
            "[[topic_rules]]\nprefix = \"app.sync.\"\nrecording = \"ephemeral\"\nmax_bytes = 1\n",
            "[[class_limits]]\nclass = \"durable\"\nmax_age_days = 7\n",
            "[[class_limits]]\nclass = \"replaceable\"\nmax_bytes = 8388608\n",
            "[[topic_rules]]\nprefix = \"app.chat\"\nmax_bytes = 16777216\n",
            "[[topic_rules]]\nprefix = \"app.chat\"\nmax_age_days = 3\n",
        ] {
            assert_opens(body);
        }
        assert_opens("dm_recording = \"inherit\"\n");
        assert_opens("[[topic_rules]]\nprefix = \"app.chat\"\nrecording = \"inherit\"\n");
        assert_opens("[[topic_rules]]\nprefix = \"app.chat\"\nmax_age_days = 0\n");
    }

    /// Validation row 1 (defaults): a `[history]` table written before ADR
    /// 0116 decodes to the same config and opens as before.
    #[test]
    fn adr0116_pre_existing_history_config_is_unchanged() {
        let body = "enabled = true\nmax_bytes = 1073741824\nmax_age_days = 0\n\
                    record_topics = [\"app.chat\"]\n\n\
                    [[scope_limits]]\nscope = \"group:example\"\nmax_bytes = 268435456\n";
        let decoded: HistoryConfig = toml::from_str(body).unwrap();
        assert_eq!(
            decoded,
            HistoryConfig {
                enabled: true,
                max_bytes: 1_073_741_824,
                max_age_days: 0,
                scope_limits: vec![ScopeLimit {
                    scope: "group:example".into(),
                    max_bytes: 268_435_456,
                }],
                record_topics: vec!["app.chat".into()],
                ..HistoryConfig::default()
            }
        );
        assert_opens(body);
    }

    /// Validation runs before the store opens: a refused config creates no
    /// database file.
    #[test]
    fn adr0116_refused_config_creates_no_database() {
        let dir = tempfile::tempdir().unwrap();
        let refused = open_history_toml(dir.path(), "[[topic_rules]]\nprefix = \"\"\n");
        assert!(refused.is_err(), "an empty prefix is refused");
        assert!(
            !dir.path().join("history.db").exists(),
            "no history.db is created for a refused config"
        );
    }

    /// ADR 0116 §3: the typed policy is reachable from the handle, and an
    /// unconfigured store reports an unset policy.
    #[tokio::test]
    async fn adr0116_handle_exposes_the_compiled_policy() {
        let dir = tempfile::tempdir().unwrap();
        let config = HistoryConfig {
            enabled: true,
            db_path: Some(dir.path().join("history.db")),
            topic_rules: vec![TopicRule {
                prefix: "app.chat".into(),
                recording: TopicRecording::Inherit,
                max_bytes: None,
                max_age_days: None,
            }],
            ..HistoryConfig::default()
        };
        let service = HistoryService::start(&config, dir.path()).unwrap();
        let handle = service.handle();
        assert!(!handle.policy().is_unset());
        assert_eq!(
            handle
                .policy()
                .winning_topic_rule("app.chat.room")
                .map(|rule| rule.prefix.as_str()),
            Some("app.chat")
        );
        service.shutdown().await;

        let plain_dir = tempfile::tempdir().unwrap();
        let plain = HistoryService::start(
            &HistoryConfig {
                enabled: true,
                db_path: Some(plain_dir.path().join("history.db")),
                ..HistoryConfig::default()
            },
            plain_dir.path(),
        )
        .unwrap();
        assert!(plain.handle().policy().is_unset());
        plain.shutdown().await;
    }

    /// ADR 0116 slice B: the periodic reaper applies the compiled class and
    /// topic rules (here a 1-day Durable age), not only the global bounds.
    #[tokio::test]
    async fn adr0116_reaper_applies_the_compiled_rules() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("history.db")).unwrap());
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        for (payload, seen_at_ms) in [(&b"old row"[..], now - 5 * 86_400_000), (b"new row", now)] {
            store
                .insert(&HistoryRecord {
                    msg_id: HistoryRecord::compute_msg_id(None, payload),
                    scope: Scope::Dm("ab".repeat(32)),
                    author_agent: None,
                    author_machine: None,
                    author_pubkey: None,
                    sent_at_ms: seen_at_ms,
                    seen_at_ms,
                    direction: Direction::Inbound,
                    content_type: "text/plain".into(),
                    payload: payload.to_vec(),
                    signed_artifact: None,
                    signature: None,
                    sig_context: None,
                    provenance: Provenance::LocalAppDecrypt,
                    replace_key: None,
                    thread_root: None,
                    thread_parent: None,
                    ingress_sender_agent: None,
                    logical_request_id: None,
                })
                .unwrap();
        }
        let config = HistoryConfig {
            class_limits: vec![ClassLimit {
                class: RetainedClass::Durable,
                max_bytes: None,
                max_age_days: Some(1),
            }],
            ..HistoryConfig::default()
        };
        let rules = Arc::new(config.validate().unwrap());
        let reaper = reaper::spawn(
            Arc::clone(&store),
            config.retention_policy(),
            rules,
            Arc::new(HistoryCounters::default()),
            1,
            Arc::new(QuarantinePinSlot::default()),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if store.stats().unwrap().rows == 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the reaper never applied the class age"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        reaper.abort();
        let _ = reaper.await;
    }

    /// Codex B review r2 (controller decision): bounded topic rules need a
    /// UTF-8 database, so `open` refuses them on a database created with
    /// another text encoding, after `Store::open` and with no other file
    /// change. Everything else still opens there: no rule, a class limit, a
    /// prefix-only topic rule.
    #[test]
    fn adr0116_open_refuses_topic_limits_on_a_non_utf8_database() {
        for encoding in ["UTF-16le", "UTF-16be"] {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("history.db");
            {
                let conn = rusqlite::Connection::open(&db).unwrap();
                conn.execute_batch(&format!(
                    "PRAGMA encoding = '{encoding}'; CREATE TABLE seed(x);"
                ))
                .unwrap();
            }
            let open = |config: HistoryConfig| {
                HistoryService::open(
                    &HistoryConfig {
                        enabled: true,
                        db_path: Some(db.clone()),
                        ..config
                    },
                    dir.path(),
                )
                .map(drop)
            };
            let bounded = HistoryConfig {
                topic_rules: vec![TopicRule {
                    prefix: "app.".into(),
                    recording: TopicRecording::Inherit,
                    max_bytes: None,
                    max_age_days: Some(3),
                }],
                ..HistoryConfig::default()
            };
            match open(bounded) {
                Err(crate::error::HistoryError::InvalidConfig(message)) => assert!(
                    message.contains("UTF-8"),
                    "{encoding}: the refusal names the encoding need: {message}"
                ),
                other => panic!("{encoding}: topic limits must be refused, got {other:?}"),
            }
            open(HistoryConfig::default()).unwrap();
            open(HistoryConfig {
                class_limits: vec![ClassLimit {
                    class: RetainedClass::Durable,
                    max_bytes: None,
                    max_age_days: Some(7),
                }],
                ..HistoryConfig::default()
            })
            .unwrap();
            open(HistoryConfig {
                topic_rules: vec![TopicRule {
                    prefix: "app.".into(),
                    recording: TopicRecording::Inherit,
                    max_bytes: None,
                    max_age_days: None,
                }],
                ..HistoryConfig::default()
            })
            .unwrap();
        }
    }

    // ── ADR 0116 slice C: Ephemeral at the shared write boundary ─────────
    //
    // Every history producer (raw-QUIC and gossip-inbox DMs, outbound DMs,
    // topic subscriptions, the durable-commit path) goes through
    // `HistoryHandle::record` / `record_committed`, so the gate is tested
    // there, with records shaped exactly as each producer builds them.

    fn c_row(
        scope: Scope,
        text: &str,
        direction: Direction,
        provenance: Provenance,
        replace_key: Option<&str>,
    ) -> HistoryRecord {
        let payload = text.as_bytes().to_vec();
        HistoryRecord {
            msg_id: HistoryRecord::compute_msg_id(None, &payload),
            scope,
            author_agent: None,
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: 1_000,
            seen_at_ms: 1_000,
            direction,
            content_type: "text/plain".into(),
            payload,
            signed_artifact: None,
            signature: None,
            sig_context: None,
            provenance,
            replace_key: replace_key.map(str::to_string),
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        }
    }

    /// An inbound DM as the gossip inbox and the raw-QUIC path record it.
    fn c_inbound_dm(text: &str) -> HistoryRecord {
        c_row(
            Scope::Dm("ab".repeat(32)),
            text,
            Direction::Inbound,
            Provenance::VerifiedEnvelope,
            None,
        )
    }

    /// An outbound DM as `record_dm_outbound` records it.
    fn c_outbound_dm(text: &str) -> HistoryRecord {
        c_row(
            Scope::Dm("cd".repeat(32)),
            text,
            Direction::Outbound,
            Provenance::LocalSend,
            None,
        )
    }

    fn c_group(id: &str, text: &str) -> HistoryRecord {
        c_row(
            Scope::Group(id.into()),
            text,
            Direction::Inbound,
            Provenance::LocalAppDecrypt,
            None,
        )
    }

    fn c_topic(name: &str, text: &str) -> HistoryRecord {
        c_row(
            Scope::Topic(name.into()),
            text,
            Direction::Inbound,
            Provenance::VerifiedEnvelope,
            None,
        )
    }

    fn c_start(dir: &std::path::Path, config: HistoryConfig) -> HistoryService {
        HistoryService::start(
            &HistoryConfig {
                enabled: true,
                db_path: Some(dir.join("history.db")),
                ..config
            },
            dir,
        )
        .unwrap()
    }

    /// Commit a group barrier row through the same writer queue (so every
    /// earlier `record` has been processed), shut the service down, reopen
    /// the database as a restart would, and return it.
    async fn c_restart(dir: &std::path::Path, service: HistoryService) -> Store {
        service
            .handle()
            .record_committed(c_group("barrier", "group barrier row"))
            .await
            .unwrap();
        service.shutdown().await;
        Store::open(&dir.join("history.db")).unwrap()
    }

    fn c_search(store: &Store, needle: &str) -> usize {
        store
            .search(needle, &HistoryQuery::default())
            .unwrap()
            .len()
    }

    fn c_dm_ephemeral() -> HistoryConfig {
        HistoryConfig {
            dm_recording: DmRecording::Ephemeral,
            ..HistoryConfig::default()
        }
    }

    /// Validation row 4: under `dm_recording = "ephemeral"` an ordinary DM,
    /// inbound or outbound, writes no history row, no FTS document and no
    /// canonical projection; after a restart only the group barrier row is
    /// there. The suppression is counted, without a label.
    #[tokio::test]
    async fn adr0116_c_dm_ephemeral_writes_no_dm_row_fts_or_projection() {
        let dir = tempfile::tempdir().unwrap();
        let service = c_start(dir.path(), c_dm_ephemeral());
        let handle = service.handle();
        handle.record(c_inbound_dm("inbound secret words"));
        handle.record(c_outbound_dm("outbound secret words"));
        let counters = handle.counters();
        drop(handle);
        let store = c_restart(dir.path(), service).await;
        assert_eq!(
            store.table_counts_for_tests(),
            (1, 1, 0),
            "(history rows, FTS documents, canonical rows): only the barrier"
        );
        assert_eq!(c_search(&store, "secret"), 0, "no FTS entry for a DM");
        assert_eq!(c_search(&store, "barrier"), 1);
        assert_eq!(
            counters
                .policy_suppressed_dm_total
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    /// Validation row 4, negative control: the same records with the
    /// policy unset are stored and indexed.
    #[tokio::test]
    async fn adr0116_c_negative_control_dm_rows_are_stored_without_the_policy() {
        let dir = tempfile::tempdir().unwrap();
        let service = c_start(dir.path(), HistoryConfig::default());
        let handle = service.handle();
        handle.record(c_inbound_dm("inbound secret words"));
        handle.record(c_outbound_dm("outbound secret words"));
        drop(handle);
        let store = c_restart(dir.path(), service).await;
        assert_eq!(store.table_counts_for_tests(), (3, 3, 0));
        assert_eq!(c_search(&store, "secret"), 2);
    }

    /// Ruling Q5: only ORDINARY DMs (`Scope::Dm` with no `replace_key`) are
    /// suppressed. An imported agent card is a Replaceable row in DM scope
    /// (`routes/identity.rs`) and is still stored.
    #[tokio::test]
    async fn adr0116_c_agent_card_in_dm_scope_is_still_stored() {
        let dir = tempfile::tempdir().unwrap();
        let service = c_start(dir.path(), c_dm_ephemeral());
        let handle = service.handle();
        handle.record(c_row(
            Scope::Dm("ef".repeat(32)),
            "agent card body",
            Direction::Inbound,
            Provenance::VerifiedEnvelope,
            Some("agent-card:ef"),
        ));
        drop(handle);
        let store = c_restart(dir.path(), service).await;
        assert_eq!(store.table_counts_for_tests().0, 2, "card + barrier");
        assert_eq!(c_search(&store, "card"), 1);
    }

    /// ADR 0116 §3: group history has no Ephemeral opt-out. Neither the DM
    /// policy nor a topic rule whose prefix happens to match a group id
    /// suppresses a group row.
    #[tokio::test]
    async fn adr0116_c_group_rows_are_never_suppressed() {
        let dir = tempfile::tempdir().unwrap();
        let config = HistoryConfig {
            topic_rules: vec![TopicRule {
                prefix: "app.".into(),
                recording: TopicRecording::Ephemeral,
                max_bytes: None,
                max_age_days: None,
            }],
            ..c_dm_ephemeral()
        };
        let service = c_start(dir.path(), config);
        let handle = service.handle();
        handle.record(c_group("app.x", "group message words"));
        handle
            .record_committed(c_group("app.y", "committed group words"))
            .await
            .unwrap();
        drop(handle);
        let store = c_restart(dir.path(), service).await;
        assert_eq!(store.table_counts_for_tests().0, 3);
    }

    /// Validation row 4, topic path: the winning `ephemeral` rule keeps a
    /// topic's messages out of history; a longer `inherit` rule carves its
    /// topics back in, and a topic no rule matches is recorded as before.
    #[tokio::test]
    async fn adr0116_c_topic_rule_ephemeral_keeps_its_topics_out() {
        let dir = tempfile::tempdir().unwrap();
        let config = HistoryConfig {
            topic_rules: vec![
                TopicRule {
                    prefix: "app.".into(),
                    recording: TopicRecording::Ephemeral,
                    max_bytes: None,
                    max_age_days: None,
                },
                TopicRule {
                    prefix: "app.chat".into(),
                    recording: TopicRecording::Inherit,
                    max_bytes: None,
                    max_age_days: None,
                },
            ],
            ..HistoryConfig::default()
        };
        let service = c_start(dir.path(), config);
        let handle = service.handle();
        handle.record(c_topic("app.sync", "sync presence words"));
        handle.record(c_topic("app.chat.room", "chat room words"));
        handle.record(c_topic("other", "other topic words"));
        let counters = handle.counters();
        drop(handle);
        let store = c_restart(dir.path(), service).await;
        assert_eq!(c_search(&store, "presence"), 0, "app.sync is ephemeral");
        assert_eq!(c_search(&store, "room"), 1, "app.chat carves back in");
        assert_eq!(c_search(&store, "other"), 1, "no rule: recorded");
        assert_eq!(
            counters
                .policy_suppressed_topic_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// Validation row 4, committed-write path: a suppressed record is never
    /// reported as committed. `record_committed` returns `PolicySuppressed`
    /// and writes nothing, so no caller can turn it into a durable receipt.
    #[tokio::test]
    async fn adr0116_c_suppressed_committed_write_is_an_error_never_a_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let service = c_start(dir.path(), c_dm_ephemeral());
        let handle = service.handle();
        let result = handle
            .record_committed(c_inbound_dm("must not commit"))
            .await;
        assert!(
            matches!(result, Err(crate::error::HistoryError::PolicySuppressed)),
            "got {result:?}"
        );
        drop(handle);
        let store = c_restart(dir.path(), service).await;
        assert_eq!(c_search(&store, "commit"), 0);
        assert_eq!(store.table_counts_for_tests().0, 1, "only the barrier");
    }

    /// Validation row 1 (defaults): the new keys are omitted from a
    /// serialized default config, so its bytes do not change.
    #[test]
    fn adr0116_default_config_serializes_unchanged() {
        assert_eq!(
            serde_json::to_string(&HistoryConfig::daemon_default()).unwrap(),
            "{\"enabled\":true,\"max_bytes\":1073741824,\"max_age_days\":0,\
             \"scope_limits\":[],\"db_path\":null,\"record_topics\":[]}"
        );
        assert_eq!(
            serde_json::to_string(&HistoryConfig::default()).unwrap(),
            "{\"enabled\":false,\"max_bytes\":1073741824,\"max_age_days\":0,\
             \"scope_limits\":[],\"db_path\":null,\"record_topics\":[]}"
        );
    }

    // ── ADR 0116 slice D: HistoryHandle::retain (§4) ────────────────────

    fn d_old_rows(store: &Store, scope: &Scope, n: usize) {
        let rows: Vec<HistoryRecord> = (0..n)
            .map(|i| {
                c_row(
                    scope.clone(),
                    &format!("old row {i} in {}", scope.canonical()),
                    Direction::Inbound,
                    Provenance::LocalAppDecrypt,
                    None,
                )
            })
            .collect();
        store.insert_batch(&rows).unwrap();
    }

    fn d_aged() -> HistoryConfig {
        HistoryConfig {
            max_age_days: 1,
            ..HistoryConfig::default()
        }
    }

    /// §4: the body knobs are `max_rows` 1–65 536 (default 4 096) and
    /// `budget_ms` 1–10 000 (default 2 000); anything else is refused
    /// before any work.
    #[tokio::test]
    async fn adr0116_d_handle_retain_validates_its_options() {
        let dir = tempfile::tempdir().unwrap();
        let service = c_start(dir.path(), HistoryConfig::default());
        let handle = service.handle();
        for (max_rows, budget_ms) in [(0, 2_000), (65_537, 2_000), (4_096, 0), (4_096, 10_001)] {
            let result = handle
                .retain(RetainOptions {
                    max_rows,
                    budget_ms,
                })
                .await;
            assert!(
                matches!(result, Err(RetainError::InvalidOptions(_))),
                "{max_rows}/{budget_ms}: {result:?}"
            );
        }
        for options in [
            RetainOptions {
                max_rows: 1,
                budget_ms: 1,
            },
            RetainOptions {
                max_rows: 65_536,
                budget_ms: 10_000,
            },
            RetainOptions::default(),
        ] {
            assert!(handle.retain(options).await.is_ok(), "{options:?}");
        }
        assert_eq!(
            RetainOptions::default(),
            RetainOptions {
                max_rows: 4_096,
                budget_ms: 2_000
            }
        );
        service.shutdown().await;
    }

    /// §4: the SQLite work runs off the async executor. On a single-thread
    /// runtime the test's own polling loop keeps running while the trim is
    /// parked holding the store, which it could not do if the trim ran on
    /// that thread.
    #[tokio::test(flavor = "current_thread")]
    async fn adr0116_d_handle_retain_runs_its_sqlite_work_off_the_executor() {
        let dir = tempfile::tempdir().unwrap();
        let service = c_start(dir.path(), d_aged());
        let handle = service.handle();
        let store = Arc::clone(handle.store());
        d_old_rows(&store, &Scope::Topic("old".into()), 300);
        store.pause_trim_for_tests(true);
        let task = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.retain(RetainOptions::default()).await })
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !store.trim_parked_for_tests() {
            assert!(
                std::time::Instant::now() < deadline,
                "the trim never parked"
            );
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!task.is_finished());
        store.pause_trim_for_tests(false);
        let report = task.await.unwrap().unwrap();
        assert_eq!(report.deleted, 300);
        assert_eq!(report.state, RetainState::Complete);
        service.shutdown().await;
    }

    /// §4: caller cancellation. Dropping the `retain` future stops the trim
    /// at its next committed boundary; the batch in flight completes.
    #[tokio::test]
    async fn adr0116_d_dropping_the_retain_future_cancels_at_the_next_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let service = c_start(dir.path(), d_aged());
        let handle = service.handle();
        let store = Arc::clone(handle.store());
        d_old_rows(&store, &Scope::Topic("old".into()), 2_000);
        store.slow_next_trim_delete_for_tests(300);
        let dropped = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            handle.retain(RetainOptions {
                max_rows: 65_536,
                budget_ms: 10_000,
            }),
        )
        .await;
        assert!(dropped.is_err(), "the caller left before the trim finished");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let probe = Arc::clone(&store);
        let rows = tokio::task::spawn_blocking(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !probe.retention_admission_free_for_tests() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the trim never stopped"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            probe.table_counts_for_tests().0
        })
        .await
        .unwrap();
        assert_eq!(rows, 1_744, "only the batch in flight completed");
        service.shutdown().await;
    }

    struct DPins(std::sync::Mutex<Vec<String>>);

    impl QuarantinePins for DPins {
        fn pinned_scopes(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + '_>> {
            let scopes = self.0.lock().unwrap().clone();
            Box::pin(async move { scopes })
        }
    }

    /// §4 pins: a library with no pin source pins nothing (ADR 0068's
    /// contract). With a source installed the pins are read on every call,
    /// so a pinned group survives and, once its marker clears, the next call
    /// trims it.
    #[tokio::test]
    async fn adr0116_d_handle_retain_reads_the_live_pin_source_on_every_call() {
        let dir = tempfile::tempdir().unwrap();
        let service = c_start(dir.path(), d_aged());
        let handle = service.handle();
        let store = Arc::clone(handle.store());
        d_old_rows(&store, &Scope::Group("g".into()), 3);
        let report = handle.retain(RetainOptions::default()).await.unwrap();
        assert_eq!(report.deleted, 3, "no pin source: nothing is pinned");
        service.shutdown().await;

        let dir = tempfile::tempdir().unwrap();
        let service = c_start(dir.path(), d_aged());
        let handle = service.handle();
        let store = Arc::clone(handle.store());
        let pins = Arc::new(DPins(std::sync::Mutex::new(vec!["group:g".into()])));
        assert!(handle.install_quarantine_pins(Arc::clone(&pins) as Arc<dyn QuarantinePins>));
        d_old_rows(&store, &Scope::Group("g".into()), 3);
        let report = handle.retain(RetainOptions::default()).await.unwrap();
        assert_eq!(report.deleted, 0, "the pinned group survives");
        assert_eq!(store.table_counts_for_tests().0, 3);
        pins.0.lock().unwrap().clear();
        let report = handle.retain(RetainOptions::default()).await.unwrap();
        assert_eq!(
            report.deleted, 3,
            "the marker cleared: the next call trims it"
        );
        service.shutdown().await;
    }
}
