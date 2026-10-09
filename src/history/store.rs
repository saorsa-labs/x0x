//! SQLite history store (ADR-0023 §3) — adapted from the x0x-nostr-bridge
//! spike's store (parameterized SQL throughout, FTS5 external-content table,
//! WAL). All operations are synchronous; async callers must go through the
//! writer thread ([`super::writer`]) or `tokio::task::spawn_blocking`.
//!
//! Exclusivity: the connection runs `PRAGMA locking_mode = EXCLUSIVE` and
//! acquires the lock at open, so a second process opening the same
//! `history.db` fails loud instead of silently interleaving (ADR-0023 §6
//! shared-data-dir posture).

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension};

use crate::error::{HistoryError, HistoryResult};

use super::record::{Direction, HistoryRecord, Provenance, Scope};

/// Current schema version (forward-only migrations).
const SCHEMA_VERSION: i64 = 4;

/// Maximum rows a single query may return.
pub const MAX_QUERY_LIMIT: usize = 500;

/// Rows evicted per retention round-trip while over budget.
const RETAIN_EVICT_BATCH: usize = 256;

/// ADR-0068 D1: a pinned (fork-quarantined) scope may hold this multiple of
/// its normal per-scope bound before the reaper evicts inside it.
///
/// Four retention windows' worth of the group's own history, so the forensic
/// record spans the incident rather than its last few minutes.
pub const HISTORY_QUARANTINE_PIN_MULTIPLIER: u64 = 4;

/// ADR-0068 D1: the synthetic per-scope bound for a pinned scope the operator
/// configured no [`ScopeLimit`] for, as a divisor of
/// [`RetentionPolicy::max_bytes`].
///
/// Such a scope has no per-scope bound in the code at all — its only bound is
/// the whole-database budget — so one has to be synthesised. `1/64` of the
/// budget (16 MiB at the 1 GiB default) makes the resulting pinned ceiling
/// `1/16` of the budget.
pub const HISTORY_QUARANTINE_PIN_BASE_DIVISOR: u64 = 64;

/// ADR-0068 D1: hard cap on one pinned scope's ceiling, as a divisor of
/// [`RetentionPolicy::max_bytes`].
///
/// A cap, not a second policy: it bites only when an operator configured a
/// per-scope limit larger than `max_bytes / 64`, and stops `4 ×` a large
/// explicit limit from swallowing the whole store. At the defaults this arm
/// and the multiplier arm coincide at 64 MiB.
pub const HISTORY_QUARANTINE_PIN_ABSOLUTE_DIVISOR: u64 = 16;

/// FTS5 index output pages one maintenance merge statement may write
/// (issue #1264 part 1). Applied as the rank of an FTS5 `'merge'` command:
/// the POSITIVE rank resumes an in-progress merge or merges a level with
/// enough segments; the NEGATIVE rank `-N` starts a fresh optimize-shaped
/// merge. [`Store::maintain_until_settled`] sequences them: positive-rank
/// slices drive all routine merging, and the negative rank is issued only
/// after a positive no-op, as the second half of the settled certificate
/// (round 4, C-1264-1: nothing writes mid-pass, so the only thing a
/// positive no-op fails to resume is a merge the engine's bottom-up level
/// selector declines to pick — the negative merge re-flattens that state
/// instead of leaving it stranded).
///
/// HONEST bound (review rounds 2–3, R2-A/R3-E): the budget counts OUTPUT
/// leaf pages, and the bundled engine checks it only when the term changes
/// (`fts5IndexMergeLevel`, sqlite3.c ~245313), so a term whose posting
/// list exceeds the budget is processed entirely within one statement,
/// and tombstone-annihilated input is read without producing budgeted
/// output. One statement is therefore bounded by this many output pages
/// PLUS the largest posting list it must cross — on a flooded term that
/// is not a small number, and nothing can interrupt a statement in
/// flight. What is actually guaranteed: how many statements run per pass
/// ([`RETENTION_PASS_BUDGET`] is checked between every statement) and how
/// many output pages each one writes.
const FTS_MERGE_PAGES_PER_SLICE: i64 = 64;

/// Upper bound on `incremental_vacuum` statements per maintenance slice.
/// Measured on the bundled SQLite 3.46.0: ONE page moves per statement
/// whatever the argument says (the argument caps newer builds that honor
/// it), so the loop of statements is the real bound here. Each statement
/// is deadline-checked; the loop stops early once `page_count` stops
/// falling, so a settled store costs one no-op pragma per slice.
const VACUUM_PAGES_PER_SLICE: i64 = 512;

/// Vacuum statements between truncating checkpoints inside one vacuum
/// slice (round 4): each one-page move costs ~5 pages of WAL (measured on
/// the bundled engine — the moved page plus pointer-map and freelist
/// bookkeeping), so this keeps a slice's WAL to a small multiple of the
/// per-statement cost instead of letting 512 moves park ~10 MiB before
/// the slice's trailing checkpoint (R3-E).
const VACUUM_CHECKPOINT_EVERY: i64 = 8;

/// Wall-clock budget for the RECLAMATION work this fix adds to one
/// retention pass (controller decision C-1264-2, narrowing C-1264-1):
/// the FTS merge slices, the incremental-vacuum steps and the truncating
/// checkpoints. The deadline is checked before EVERY such statement —
/// each merge statement and its leading and trailing structure reads,
/// the vacuum mode probe, the page-count reads around every vacuum step,
/// every cadence checkpoint, and the pass's teardown checkpoint — so
/// once the budget is spent, no new reclamation statement starts. The
/// one exception is the statement already in flight when the deadline
/// passes: a statement cannot be interrupted, and a single merge
/// statement can overrun on one huge posting list (see
/// [`FTS_MERGE_PAGES_PER_SLICE`] for the honest bound).
///
/// Eviction is NOT bounded by this budget (C-1264-2): the retention
/// phases that exist on main — the age bound, pinned ceilings,
/// per-scope limits, the global-cap batches and the forced path — run
/// to completion in every pass, in bounded batches (at most
/// [`RETAIN_EVICT_BATCH`] rows per transaction; the age bound is one
/// statement, exactly as on main), and their cost is unchanged from
/// main. A pass whose reclamation budget runs out therefore still
/// reaches every eviction phase — the round-5/6 starvation class
/// (R5-B/R6-A) cannot occur — while the global phase's settled
/// certificate can only complete from reclamation statements that
/// actually ran: a statement skipped by the deadline counts as "not
/// settled", and eviction then waits for a settled pass or the forced
/// path after [`UNSETTLED_PASSES_BEFORE_FORCED_EVICT`] unsettled ones.
const RETENTION_PASS_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// C-1264-1 §3, the progress guarantee (review round 3, R3-C): how many
/// consecutive passes may end by budget-out with the index still
/// unsettled while the store sits over its cap before the next pass
/// evicts by estimate anyway — see [`Store::forced_evict_over_cap`] for
/// the bounded over-deletion that buys. Maintenance alone must not defer
/// global eviction forever.
const UNSETTLED_PASSES_BEFORE_FORCED_EVICT: usize = 3;

/// Outcome of an insert (mirrors the donor's `InsertOutcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// New row written.
    Inserted,
    /// `msg_id` already present — no-op.
    Duplicate,
    /// Replaceable slot superseded an older row.
    Replaced,
    /// Replaceable row lost to a newer (or equal-time, lower-id) holder.
    StaleRejected,
}

/// Filter for [`Store::query`].
#[derive(Debug, Clone, Default)]
pub struct HistoryQuery {
    /// Restrict to one scope.
    pub scope: Option<Scope>,
    /// Restrict to one scope *kind* (all DMs / all groups / all topics)
    /// without naming a scope id. Ignored when `scope` is set.
    pub scope_kind: Option<i64>,
    /// Inclusive lower bound on `seen_at_ms`.
    pub since_ms: Option<i64>,
    /// Inclusive upper bound on `seen_at_ms`.
    pub until_ms: Option<i64>,
    /// Rows to return (clamped to [`MAX_QUERY_LIMIT`]). 0 ⇒ default 100.
    pub limit: usize,
    /// Keyset cursor: only rows with rowid strictly below this.
    pub before_id: Option<i64>,
}

/// A queried row: the record plus its rowid cursor.
#[derive(Debug, Clone)]
pub struct StoredRecord {
    /// Rowid — the `before_id` cursor for the next page.
    pub id: i64,
    /// The record itself.
    pub record: HistoryRecord,
}

/// Aggregate stats for `/history/stats`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryStats {
    /// Total rows.
    pub rows: i64,
    /// Durable (non-replaceable) rows.
    pub durable_rows: i64,
    /// Replaceable rows.
    pub replaceable_rows: i64,
    /// Database size in bytes (page_count × page_size).
    pub db_bytes: i64,
    /// Oldest `seen_at_ms` present, if any.
    pub oldest_ms: Option<i64>,
    /// Newest `seen_at_ms` present, if any.
    pub newest_ms: Option<i64>,
}

/// One row of the scope-discovery enumeration ([`Store::scopes`]).
///
/// Aggregated from the CURRENT `history` rows, so a scope disappears from
/// the enumeration as soon as retention or [`Store::purge`] removes its
/// last retained row — there is no separate scope registry to go stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSummary {
    /// The scope itself (reconstructed from `scope_kind`/`scope_id`).
    pub scope: Scope,
    /// Retained rows in this scope.
    pub rows: i64,
    /// Newest `seen_at_ms` among the retained rows.
    pub newest_seen_at_ms: i64,
}

/// Per-scope retention override (ADR-0023 §6).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ScopeLimit {
    /// Canonical scope string (`group:<id>`, `dm:<agent>`, `topic:<name>`).
    pub scope: String,
    /// Byte budget for this scope (payload + signed_artifact lengths).
    pub max_bytes: u64,
}

/// Retention bounds passed to [`Store::retain`].
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Whole-database byte budget.
    pub max_bytes: u64,
    /// Age bound in days; 0 disables age eviction.
    pub max_age_days: u64,
    /// Per-scope byte overrides.
    pub scope_limits: Vec<ScopeLimit>,
}

/// ADR-0068 D1: the scopes one retention pass must not evict from freely
/// because they hold a live fork-quarantine marker.
///
/// Built from canonical scope strings (`group:<id>`) — the spelling
/// `/history/scopes` and the marker surfaces already use — and deliberately
/// accepts BOTH spellings of an alias-keyed group (map key and
/// `stable_group_id()`): rows live under the stable id, and the alias costs one
/// extra set member rather than leaving the group unprotected.
///
/// Unparseable entries are ignored rather than failing the pass: a pin source
/// that hands over one bad string must not stop retention for everyone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinnedScopes {
    /// Parsed `(scope_kind, scope_id)` pairs, deduplicated and ordered.
    scopes: std::collections::BTreeSet<(i64, String)>,
}

impl PinnedScopes {
    /// Nothing is pinned — the pre-ADR-0068 behaviour, and what a library
    /// embedding with no pin source installed gets.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Parse canonical scope strings (`group:<id>`); unparseable ones are
    /// skipped.
    pub fn from_canonical<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            scopes: scopes
                .into_iter()
                .filter_map(|raw| {
                    Scope::parse(raw.as_ref())
                        .ok()
                        .map(|scope| (scope.kind(), scope.id().to_string()))
                })
                .collect(),
        }
    }

    /// Is nothing pinned? The hot path: a node with no quarantine anywhere
    /// runs the original retention statements untouched.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    /// How many scopes are pinned (`G` in the ADR's disk bound).
    #[must_use]
    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    /// Is this scope pinned? Compared on the stored `(kind, id)` columns, so
    /// the answer does not depend on the spelling the caller parsed from.
    #[must_use]
    pub fn contains(&self, scope: &Scope) -> bool {
        self.scopes
            .iter()
            .any(|(kind, id)| *kind == scope.kind() && id == scope.id())
    }
}

/// ADR-0068 D1: what one retention pass did, split so the reaper can report
/// pinned-scope pressure separately from ordinary eviction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetainOutcome {
    /// Rows evicted in total (pinned ceiling evictions included).
    pub evicted: u64,
    /// Rows evicted from INSIDE a pinned scope because that scope exceeded
    /// its own ceiling. Never includes another scope's rows: a flooder can
    /// burn only its own group's ceiling.
    pub pinned_evicted: u64,
    /// Scopes pinned during this pass (`G`), reported so an operator can see
    /// the disk bound `max_bytes * (1 + G/16)` they are running under.
    pub pinned_scopes: u64,
}

/// Synchronous SQLite-backed history store.
pub struct Store {
    /// Dropped first: in test builds it runs an optional hook while the
    /// connection is still open; zero-sized and inert otherwise
    /// ([`close_watch`]).
    _before_close: BeforeClose,
    conn: Mutex<Connection>,
    /// Serialises whole retention passes (review round 2, R2-D): the
    /// reaper and any embedder call on one shared `Arc<Store>` must not
    /// interleave phases. A pass holds this lock AND the connection for
    /// its whole duration (C-1264-1); the lock guards no SQL itself.
    /// Zero-sized.
    retention: Mutex<()>,
    /// C-1264-1 §3 progress counter: consecutive passes that ended by
    /// budget-out with the index still unsettled while the store was over
    /// its cap. In memory only (a restarted process re-earns the counts),
    /// set once from each pass's FINAL state (R4-B: reset when the pass
    /// ends settled OR at/under the cap — never on an intermediate
    /// certificate), read by the forced-eviction escape hatch in
    /// [`Store::enforce_global_budget`].
    unsettled_passes: AtomicU32,
    /// Issue #1286: how many `scope_limits` entries the most recent pass
    /// skipped because their scope string does not parse. A gauge,
    /// overwritten by each pass. The retention policy is fixed for the
    /// store's life, so a non-zero value means "this many configured
    /// limits are not in force". Read through
    /// [`Store::skipped_scope_limits`].
    skipped_scope_limits: AtomicU64,
    /// Issue #1286: the skip is logged once per store, not once per pass.
    skipped_scope_limits_logged: AtomicBool,
    /// Round-4 test hook: [`Store::maintain_until_settled`] reports
    /// "budget ran out before the index settled" without running
    /// statements, making the forced-eviction path deterministically
    /// reachable. Absent in production builds.
    #[cfg(test)]
    test_never_settles: std::sync::atomic::AtomicBool,
    /// Round-4 test hook: a pass parks at the top of its held connection
    /// until cleared — the writer-blocked-during-a-pass fixture. Absent
    /// in production builds.
    #[cfg(test)]
    test_pause_pass: std::sync::atomic::AtomicBool,
    /// Round-5 test hook (R4-B): after the first settled eviction batch
    /// of a pass, report the fold as budget-expired — the round-4
    /// scenario "settles, deletes a batch, then times out folding it".
    /// Absent in production builds.
    #[cfg(test)]
    test_timeout_fold: std::sync::atomic::AtomicBool,
    /// Round-5 test hook (R4-C): while set, the pass records this WAL
    /// file's size after every merge/vacuum statement and every
    /// checkpoint, and counts merge slices — the deterministic in-pass
    /// peak observation that replaces the racy external poller. Absent
    /// in production builds.
    #[cfg(test)]
    test_wal_path: Mutex<Option<std::path::PathBuf>>,
    #[cfg(test)]
    test_wal_peak: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    test_merge_slices: std::sync::atomic::AtomicU64,
    /// Round-6 test hook (R4-A/R5-B fixtures): pass-budget override in
    /// whole milliseconds; 0 keeps [`RETENTION_PASS_BUDGET`]. Lets a
    /// fixture prove a scope's SUM scan outlasts the budget without a
    /// multi-gigabyte fixture. Absent in production builds.
    #[cfg(test)]
    test_pass_budget_ms: std::sync::atomic::AtomicU64,
    /// Dropped after `conn` (fields drop in declaration order, and rusqlite
    /// closes the connection, closing checkpoint included, synchronously in
    /// its `Drop`): in test builds it marks the close complete; zero-sized
    /// and inert otherwise.
    _after_close: AfterClose,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

fn lock_conn(conn: &Mutex<Connection>) -> HistoryResult<std::sync::MutexGuard<'_, Connection>> {
    conn.lock()
        .map_err(|_| HistoryError::Database("history store mutex poisoned".into()))
}

impl Store {
    /// Open (creating if absent) the history database at `path`.
    pub fn open(path: &Path) -> HistoryResult<Self> {
        Self::open_with_busy_timeout(path, std::time::Duration::from_millis(5000))
    }

    /// Open with an explicit busy timeout (tests use a short one so the
    /// exclusivity probe fails fast).
    pub fn open_with_busy_timeout(path: &Path, busy: std::time::Duration) -> HistoryResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                // Surface the resolved db path (the operator's `<data_dir>`
                // or an explicit `history.db_path`) so a permission/ENOENT
                // failure names the path actually attempted, not just the
                // raw io message.
                HistoryError::Io(std::io::Error::new(
                    e.kind(),
                    format!("create parent dir for history db {}: {e}", path.display()),
                ))
            })?;
        }
        let conn = Connection::open(path).map_err(|e| {
            HistoryError::Database(format!("open history db {}: {e}", path.display()))
        })?;
        conn.busy_timeout(busy)?;
        // auto_vacuum must be decided before the first table exists; on an
        // already-populated db this pragma is a no-op (the setting is baked
        // into the file header).
        conn.execute_batch(
            "PRAGMA auto_vacuum = INCREMENTAL;\n             PRAGMA locking_mode = EXCLUSIVE;\n             PRAGMA journal_mode = WAL;\n             PRAGMA synchronous = NORMAL;",
        )
        .map_err(|e| {
            HistoryError::Database(format!("pragma setup history db {}: {e}", path.display()))
        })?;
        // Acquire the exclusive lock NOW so a second process fails at open,
        // not at first write.
        if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE; COMMIT;") {
            return Err(HistoryError::Locked(format!("{} ({e})", path.display())));
        }
        migrate(&conn)?;
        ensure_indexes(&conn)?;
        backfill_canonical_ids(&conn)?;
        let (before_close, after_close) = close_watch::signals();
        Ok(Self {
            _before_close: before_close,
            conn: Mutex::new(conn),
            retention: Mutex::new(()),
            unsettled_passes: AtomicU32::new(0),
            skipped_scope_limits: AtomicU64::new(0),
            skipped_scope_limits_logged: AtomicBool::new(false),
            #[cfg(test)]
            test_never_settles: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            test_pause_pass: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            test_timeout_fold: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            test_wal_path: Mutex::new(None),
            #[cfg(test)]
            test_wal_peak: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            test_merge_slices: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            test_pass_budget_ms: std::sync::atomic::AtomicU64::new(0),
            _after_close: after_close,
        })
    }

    /// Insert a record. Dedupe on `msg_id`; replaceable slots supersede.
    pub fn insert(&self, record: &HistoryRecord) -> HistoryResult<InsertOutcome> {
        record.validate()?;
        let mut guard = lock_conn(&self.conn)?;
        let tx = guard
            .transaction()
            .map_err(|e| HistoryError::Database(format!("begin failed: {e}")))?;

        let msg_id: &[u8] = &record.msg_id;
        let dup: Option<i64> = tx
            .query_row(
                "SELECT id FROM history WHERE msg_id = ?1",
                rusqlite::params![msg_id],
                |r| r.get(0),
            )
            .optional()?;
        if dup.is_some() {
            tx.commit()?;
            return Ok(InsertOutcome::Duplicate);
        }

        let outcome = if let Some(key) = &record.replace_key {
            let prev: Option<(i64, i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT id, sent_at_ms, msg_id FROM history WHERE replace_key = ?1",
                    rusqlite::params![key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            match prev {
                // Stored wins if strictly newer, or equal-timestamp with a
                // lower msg_id (lowest-id tie-break, donor semantics).
                Some((_, prev_sent, prev_msg))
                    if prev_sent > record.sent_at_ms
                        || (prev_sent == record.sent_at_ms
                            && prev_msg.as_slice() < record.msg_id.as_slice()) =>
                {
                    InsertOutcome::StaleRejected
                }
                Some((prev_id, _, prev_msg)) => {
                    tx.execute(
                        "DELETE FROM history_canonical_ids WHERE history_msg_id = ?1",
                        rusqlite::params![prev_msg],
                    )?;
                    tx.execute(
                        "DELETE FROM history WHERE id = ?1",
                        rusqlite::params![prev_id],
                    )?;
                    insert_row(&tx, record)?;
                    InsertOutcome::Replaced
                }
                None => {
                    insert_row(&tx, record)?;
                    InsertOutcome::Inserted
                }
            }
        } else {
            insert_row(&tx, record)?;
            InsertOutcome::Inserted
        };

        tx.commit()
            .map_err(|e| HistoryError::Database(format!("commit failed: {e}")))?;
        Ok(outcome)
    }

    /// Query rows newest-first with a keyset cursor.
    pub fn query(&self, q: &HistoryQuery) -> HistoryResult<Vec<StoredRecord>> {
        let limit = effective_limit(q.limit);
        let mut sql = String::from(
            "SELECT id, msg_id, scope_kind, scope_id, author_agent, author_machine, \
             author_pubkey, sent_at_ms, seen_at_ms, direction, content_type, payload, \
             signed_artifact, signature, sig_context, provenance, replace_key, \
             thread_root, thread_parent, ingress_sender_agent, logical_request_id \
             FROM history",
        );
        let mut parts: Vec<String> = Vec::new();
        let mut params: Vec<rusqlite::types::Value> = Vec::new();
        push_common_filters(q, &mut parts, &mut params);
        if !parts.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&parts.join(" AND "));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        params.push(rusqlite::types::Value::from(limit as i64));

        let guard = lock_conn(&self.conn)?;
        collect_rows(&guard, &sql, params)
    }

    /// Point lookup of a single row by canonical `msg_id` (issue #319,
    /// ADR-0023 completeness). `msg_id` is the store dedupe key, so at most
    /// one row matches; newest wins defensively if that invariant ever bends.
    pub fn get_by_msg_id(&self, msg_id: [u8; 32]) -> HistoryResult<Option<StoredRecord>> {
        let sql = "SELECT id, msg_id, scope_kind, scope_id, author_agent, author_machine, \
             author_pubkey, sent_at_ms, seen_at_ms, direction, content_type, payload, \
             signed_artifact, signature, sig_context, provenance, replace_key, \
             thread_root, thread_parent, ingress_sender_agent, logical_request_id \
             FROM history WHERE msg_id = ?1 ORDER BY id DESC LIMIT 1";
        let params = vec![rusqlite::types::Value::from(msg_id.to_vec())];
        let guard = lock_conn(&self.conn)?;
        Ok(collect_rows(&guard, sql, params)?.into_iter().next())
    }

    /// Point lookup of a canonical ADR-0029 group-message id.
    ///
    /// The canonical id is maintained in a derived auxiliary table so older
    /// binaries can continue to open and write the v4 `history` schema. The
    /// store's `msg_id` dedupe key remains unchanged.
    pub fn get_by_canonical_group_msg_id(
        &self,
        canonical_msg_id: [u8; 32],
        group_id: &str,
    ) -> HistoryResult<Option<StoredRecord>> {
        let sql =
            "SELECT h.id, h.msg_id, h.scope_kind, h.scope_id, h.author_agent, h.author_machine, \
             h.author_pubkey, h.sent_at_ms, h.seen_at_ms, h.direction, h.content_type, h.payload, \
             h.signed_artifact, h.signature, h.sig_context, h.provenance, h.replace_key, \
             h.thread_root, h.thread_parent, h.ingress_sender_agent, h.logical_request_id \
             FROM history h JOIN history_canonical_ids c ON c.history_msg_id = h.msg_id \
             WHERE c.canonical_msg_id = ?1 AND c.scope_kind = 1 AND c.scope_id = ?2 \
             ORDER BY h.id DESC LIMIT 1";
        let params = vec![
            rusqlite::types::Value::from(canonical_msg_id.to_vec()),
            rusqlite::types::Value::from(group_id.to_string()),
        ];
        let guard = lock_conn(&self.conn)?;
        Ok(collect_rows(&guard, sql, params)?.into_iter().next())
    }

    /// Look up the durable rows a logical request has already committed.
    ///
    /// Keyed on the schema v4 columns the DM inbox writes
    /// (`ingress_sender_agent`, `logical_request_id`), so the receiver durable
    /// path can answer "did this logical request already commit, and with
    /// which bytes?" without scanning and decoding an entire DM scope
    /// (ADR 0030 §1). Ordinarily at most one row matches; the query returns
    /// all of them so a caller can detect a binding conflict rather than
    /// silently trusting the newest.
    pub fn find_by_logical_request(
        &self,
        ingress_sender_agent: &str,
        logical_request_id: [u8; 16],
    ) -> HistoryResult<Vec<StoredRecord>> {
        let sql = "SELECT id, msg_id, scope_kind, scope_id, author_agent, author_machine, \
             author_pubkey, sent_at_ms, seen_at_ms, direction, content_type, payload, \
             signed_artifact, signature, sig_context, provenance, replace_key, \
             thread_root, thread_parent, ingress_sender_agent, logical_request_id \
             FROM history WHERE ingress_sender_agent = ?1 AND logical_request_id = ?2 \
             ORDER BY id ASC";
        let params = vec![
            rusqlite::types::Value::from(ingress_sender_agent.to_string()),
            rusqlite::types::Value::from(logical_request_id.to_vec()),
        ];
        let guard = lock_conn(&self.conn)?;
        collect_rows(&guard, sql, params)
    }

    /// Full-text search over searchable payload text. Tokens are quoted so
    /// user input is literal terms, never FTS operators (donor
    /// `fts_match_expr`).
    pub fn search(&self, needle: &str, q: &HistoryQuery) -> HistoryResult<Vec<StoredRecord>> {
        let fts = fts_match_expr(needle);
        if fts.is_empty() {
            return Ok(Vec::new());
        }
        let limit = effective_limit(q.limit);
        let mut sql = String::from(
            "SELECT h.id, h.msg_id, h.scope_kind, h.scope_id, h.author_agent, \
             h.author_machine, h.author_pubkey, h.sent_at_ms, h.seen_at_ms, h.direction, \
             h.content_type, h.payload, h.signed_artifact, h.signature, h.sig_context, \
             h.provenance, h.replace_key, h.thread_root, h.thread_parent, \
             h.ingress_sender_agent, h.logical_request_id FROM history h \
             WHERE h.id IN (SELECT rowid FROM history_fts WHERE history_fts MATCH ?)",
        );
        let mut params: Vec<rusqlite::types::Value> = vec![rusqlite::types::Value::from(fts)];
        let mut parts: Vec<String> = Vec::new();
        {
            // Re-use the common filters, prefixing columns with `h.`.
            let mut inner_params: Vec<rusqlite::types::Value> = Vec::new();
            push_common_filters(q, &mut parts, &mut inner_params);
            for p in &mut parts {
                *p = p
                    .replace("scope_kind", "h.scope_kind")
                    .replace("scope_id", "h.scope_id")
                    .replace("seen_at_ms", "h.seen_at_ms")
                    .replace("id <", "h.id <");
            }
            params.extend(inner_params);
        }
        for part in &parts {
            sql.push_str(" AND ");
            sql.push_str(part);
        }
        sql.push_str(" ORDER BY h.id DESC LIMIT ?");
        params.push(rusqlite::types::Value::from(limit as i64));

        let guard = lock_conn(&self.conn)?;
        collect_rows(&guard, &sql, params)
    }

    /// Aggregate stats.
    pub fn stats(&self) -> HistoryResult<HistoryStats> {
        let guard = lock_conn(&self.conn)?;
        let rows: i64 = guard.query_row("SELECT COUNT(*) FROM history", [], |r| r.get(0))?;
        let replaceable_rows: i64 = guard.query_row(
            "SELECT COUNT(*) FROM history WHERE replace_key IS NOT NULL",
            [],
            |r| r.get(0),
        )?;
        let db_bytes = db_bytes(&guard)?;
        let (oldest_ms, newest_ms): (Option<i64>, Option<i64>) = guard.query_row(
            "SELECT MIN(seen_at_ms), MAX(seen_at_ms) FROM history",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(HistoryStats {
            rows,
            durable_rows: rows - replaceable_rows,
            replaceable_rows,
            db_bytes,
            oldest_ms,
            newest_ms,
        })
    }

    /// Enumerate the scopes that still hold retained rows, ascending by
    /// `(scope_kind, scope_id)` with a keyset cursor.
    ///
    /// The ordering key is the `GROUP BY` key itself, so it is total and
    /// stable: two scopes with the same `scope_id` under different kinds are
    /// distinct rows, and equal timestamps cannot perturb the order (time is
    /// reported, never ordered on). Paging is therefore live — a later page
    /// reflects the store as it is then, and no row is skipped or repeated
    /// because of concurrent writes to an already-passed scope.
    ///
    /// `after` is the exclusive lower bound (the last scope of the previous
    /// page). `limit` follows the history convention: 0 ⇒ 100, clamped to
    /// [`MAX_QUERY_LIMIT`].
    pub fn scopes(&self, after: Option<&Scope>, limit: usize) -> HistoryResult<Vec<ScopeSummary>> {
        let limit = effective_limit(limit);
        let mut sql =
            String::from("SELECT scope_kind, scope_id, COUNT(*), MAX(seen_at_ms) FROM history");
        let mut params: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(after) = after {
            // Explicit two-column keyset (not a row-value comparison) so the
            // `(scope_kind, scope_id, seen_at_ms)` index drives the scan.
            sql.push_str(" WHERE scope_kind > ?1 OR (scope_kind = ?1 AND scope_id > ?2)");
            params.push(rusqlite::types::Value::from(after.kind()));
            params.push(rusqlite::types::Value::from(after.id().to_string()));
        }
        sql.push_str(
            " GROUP BY scope_kind, scope_id ORDER BY scope_kind ASC, scope_id ASC LIMIT ?",
        );
        params.push(rusqlite::types::Value::from(limit as i64));

        let guard = lock_conn(&self.conn)?;
        let mut stmt = guard
            .prepare(&sql)
            .map_err(|e| HistoryError::Database(format!("prepare failed: {e}")))?;
        let rows = stmt
            .query_map(
                rusqlite::params_from_iter(params),
                |r| -> std::result::Result<(i64, String, i64, i64), rusqlite::Error> {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                },
            )
            .map_err(|e| HistoryError::Database(format!("query failed: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, id, count, newest) =
                row.map_err(|e| HistoryError::Database(format!("row read failed: {e}")))?;
            out.push(ScopeSummary {
                scope: Scope::from_columns(kind, id)?,
                rows: count,
                newest_seen_at_ms: newest,
            });
        }
        Ok(out)
    }

    /// Enforce retention (ADR-0023 §6) with nothing pinned. Returns rows
    /// evicted.
    ///
    /// Replaceable rows are exempt from age eviction and from byte-pressure
    /// eviction (they are current state) but their size counts toward the
    /// byte measure.
    pub fn retain(&self, policy: &RetentionPolicy) -> HistoryResult<u64> {
        self.retain_with_pins(policy, &PinnedScopes::none())
            .map(|outcome| outcome.evicted)
    }

    /// Enforce retention (ADR-0023 §6), pinning fork-quarantined scopes
    /// (ADR-0068 D1).
    ///
    /// A pinned scope is excluded from all three ordinary eviction phases —
    /// the age bound, the per-scope byte budgets and the whole-database byte
    /// budget — so a quarantined group's forensic record survives pressure
    /// that a flooder can manufacture, which is the destruction ADR-0066 R3
    /// and row 14 already forbid through the ingest and purge doors.
    ///
    /// Pinning is not unbounded. Each pinned scope carries its own ceiling
    /// ([`Self::pinned_ceiling`]); above it, the oldest rows **inside that
    /// scope only** are evicted and reported in
    /// [`RetainOutcome::pinned_evicted`]. No other scope's rows are ever
    /// chosen to pay for a pinned scope's overshoot, and every unpinned scope
    /// keeps its bounds exactly as before.
    ///
    /// ONE PASS, ONE CONNECTION (controller decision C-1264-1, round 4 —
    /// fixes R3-A/R3-B/R3-C/R3-D): this call holds the retention mutex AND
    /// the connection for the whole pass — phases 1 through 4 — and releases
    /// both only when it returns. Holding the connection is what makes the
    /// pass's observations sound:
    ///
    /// - R3-A: no write can land between the pinned-ceiling phase and the
    ///   global-budget phase, so a pinned scope cannot be pushed over its
    ///   ceiling after the check and have HEALTHY scopes evicted to pay for
    ///   the overshoot. The ceiling measured in phase 2 is the ceiling
    ///   enforced against phase 4's global eviction.
    /// - R3-B: no writer can add FTS segments mid-pass, so positive-rank
    ///   merge slices are the routine driver and the negative rank is only
    ///   ever issued as the second half of the settled certificate — the
    ///   positive-no-op-means-no-active-merge inference is gone.
    /// - R3-D: the live measure is taken with the connection held right
    ///   after the settled certificate, so it is final for the measured
    ///   state: no replaceable write can slide reclaimable postings under
    ///   the measure between certificate and eviction.
    ///
    /// The cost, stated honestly (C-1264-2): the writer and readers
    /// queue behind the pass's eviction work — which costs exactly what
    /// it costs on main — plus at most RETENTION_PASS_BUDGET of
    /// reclamation statements and the one reclamation statement in
    /// flight when that budget runs out (which a huge posting list can
    /// overrun). No other statement of the pass is deadline-gated.
    ///
    /// Cost: O(pinned scopes) inline values in the phase SQL — never
    /// O(rows × groups). With nothing pinned the predicate is empty and the
    /// original statements run unchanged.
    pub fn retain_with_pins(
        &self,
        policy: &RetentionPolicy,
        pinned: &PinnedScopes,
    ) -> HistoryResult<RetainOutcome> {
        let mut outcome = RetainOutcome {
            pinned_scopes: pinned.len() as u64,
            ..RetainOutcome::default()
        };
        // Whole passes serialize here (review round 2, R2-D): the reaper and
        // any embedder call on one shared `Arc<Store>` must not interleave
        // phases. The lock guards no SQL itself and is held for the entire
        // pass.
        let _retention = self
            .retention
            .lock()
            .map_err(|_| HistoryError::Database("retention mutex poisoned".into()))?;

        // This pass's pin exclusion, inlined into the SQL of every ordinary
        // phase below (R2-D: no connection-shared `TEMP` table another call
        // could clear — the pins travel with the call's own statements).
        // Empty when nothing is pinned, so the unquarantined node runs the
        // pre-ADR-0068 SQL verbatim.
        let exclude = pinned_exclusion_sql(pinned);

        // C-1264-1: the connection is held from here to the end of the pass.
        // Round-4 test hook: park the pass while it owns the connection (the
        // writer-blocked-during-a-pass fixture). Inert in production builds,
        // and paused time does not eat the budget computed after it.
        let guard = lock_conn(&self.conn)?;
        #[cfg(test)]
        while self.test_pause_pass.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Round-6 test hook (R4-A/R5-B fixtures): shrink the budget so a
        // fixture's SUM scan provably outlasts it. Inert in production
        // builds; 0 keeps the production budget.
        #[cfg(test)]
        let budget = {
            let ms = self.test_pass_budget_ms.load(Ordering::Relaxed);
            if ms == 0 {
                RETENTION_PASS_BUDGET
            } else {
                std::time::Duration::from_millis(ms)
            }
        };
        #[cfg(not(test))]
        let budget = RETENTION_PASS_BUDGET;
        let deadline = std::time::Instant::now() + budget;
        // 1. Age bound (C-1264-2: eviction is never deadline-gated —
        //    exactly the statement main runs, whenever age eviction is
        //    configured).
        if policy.max_age_days > 0 {
            let cutoff =
                now_ms().saturating_sub((policy.max_age_days as i64).saturating_mul(86_400_000));
            outcome.evicted += guard.execute(
                &format!(
                    "DELETE FROM history WHERE replace_key IS NULL \
                     AND seen_at_ms < ?1{exclude}"
                ),
                rusqlite::params![cutoff],
            )? as u64;
        }

        // 2. Pinned ceilings, per pinned scope, oldest-first WITHIN the
        //    scope.
        //
        //    BEFORE the budget phases, not after: a pinned scope's
        //    overshoot must be cut back before the whole-database budget
        //    is measured, or phase 4 — which cannot touch pinned rows —
        //    would evict HEALTHY scopes to pay for it. Getting this order
        //    wrong is exactly the "a flooder can burn only its own group's
        //    ceiling" promise inverted, and the flood fixture fails on it.
        //
        //    R3-A: because the connection is held through phases 2–4, no
        //    write can land between this ceiling check and the global
        //    eviction in phase 4 — the pinned scope cannot be pushed over
        //    its ceiling mid-pass, so ADR 0068's semantics hold for the
        //    whole pass, not for an instant.
        //
        //    C-1264-2: eviction phases are not deadline-gated; every
        //    pinned scope's ceiling is enforced in every pass, however
        //    much reclamation budget remains, at main's cost.
        for (kind, id) in &pinned.scopes {
            let scope = Scope::from_columns(*kind, id.clone())?;
            let ceiling = Self::pinned_ceiling(policy, &scope);
            let evicted = evict_pinned_scope_to_ceiling(&guard, &scope, ceiling)?;
            outcome.evicted += evicted;
            outcome.pinned_evicted += evicted;
        }

        // 3. Per-scope byte budgets. A pinned scope is governed by its
        //    ceiling in phase 2 instead, never by both. C-1264-2: not
        //    deadline-gated — every configured scope is served in every
        //    pass (main's loop order, main's cost), which is what removes
        //    the round-5/6 starvation class outright.
        //
        //    Issue #1286: an entry whose scope string does not parse is
        //    skipped, counted and logged once per store, and the pass goes
        //    on. A `?` here used to end the pass at the bad entry, so the
        //    limits after it, phase 4 and the cleanup never ran, and one
        //    typo in the config removed the whole-database cap. `open`
        //    still accepts such a config, as before.
        let mut skipped: Vec<&str> = Vec::new();
        for limit in &policy.scope_limits {
            let Ok(scope) = Scope::parse(&limit.scope) else {
                skipped.push(&limit.scope);
                continue;
            };
            if pinned.contains(&scope) {
                continue;
            }
            outcome.evicted += evict_scope_to_budget(&guard, &scope, limit.max_bytes)?;
        }
        self.note_skipped_scope_limits(&skipped);

        // 4. Whole-database byte budget (issue #1264 part 1).
        self.enforce_global_budget(&guard, policy, &exclude, deadline, &mut outcome)?;

        // Cleanup runs in every pass, exactly as on main: it is derived
        // state maintenance over rows the pass just deleted, not
        // reclamation, and leaving orphaned canonical-id rows behind on a
        // budget-out pass would only grow them.
        cleanup_canonical_ids(&guard)?;
        // The teardown checkpoint is reclamation (C-1264-2): like every
        // merge slice, vacuum step and cadence checkpoint, it does not
        // start once the budget is spent. A budget-out pass therefore
        // leaves the WAL holding whatever its last in-budget checkpoint
        // did not absorb plus the one in-flight statement — bounded the
        // same way as between statements — and the next writer or pass
        // folds it from there.
        if std::time::Instant::now() < deadline {
            Self::checkpoint_wal(&guard)?;
        }
        Ok(outcome)
    }

    /// Phase 4 of [`Store::retain_with_pins`]: the whole-database byte
    /// budget, executed entirely inside one held connection (C-1264-1).
    ///
    /// Measure LIVE bytes — (page_count − freelist_count) × page_size — not
    /// the file size: rows deleted by earlier phases leave pages on the
    /// freelist and FTS5 deletes append tombstone postings to the index
    /// shadow tables, so the file size barely moves while history is
    /// destroyed. Maintenance runs FIRST — tombstones from earlier passes
    /// can be most of the overshoot, and folding them may reach the cap
    /// with no deletion at all — and must produce the settled certificate
    /// (see [`Self::maintain_until_settled`]) before the live measure is
    /// trusted and any row is deleted (R2-C/R3-D: work performed is not
    /// work still pending, and only a settled index makes the measure
    /// final). While the certificate is outstanding the pass deletes
    /// nothing: deleting history that merging alone would have saved from
    /// the cap destroys rows the cap did not require.
    ///
    /// Eviction, once the index is settled: ONE bounded batch (at most
    /// [`RETAIN_EVICT_BATCH`] rows, selected by the running-estimate window
    /// that always includes the crossing row — see [`evict_oldest_batch`]),
    /// then merge/vacuum/checkpoint and a remeasure, all within the same
    /// pass and budget, repeating while the store is still over the cap.
    /// Because the connection is held, every remeasure is of a state only
    /// our own statements changed.
    ///
    /// Progress guarantee (R3-C): if the budget runs out before the index
    /// settles, the pass records one consecutive-unsettled count on the
    /// store (in memory) and deletes nothing. After
    /// [`UNSETTLED_PASSES_BEFORE_FORCED_EVICT`] such passes the next pass
    /// evicts anyway — [`Self::forced_evict_over_cap`] — so a store whose
    /// maintenance cannot keep up with ingestion still meets its cap, with
    /// bounded over-deletion instead of none.
    ///
    /// R4-B: the counter is written ONCE, from the pass's FINAL state —
    /// incremented only when the pass ends with the index unsettled while
    /// over the cap, reset only when it ends settled OR at/under the cap.
    /// An intermediate certificate (before or between eviction batches)
    /// never touches it: a pass can settle its backlog, delete a batch,
    /// then budget out folding that batch while still over the cap, and
    /// that pass must count as unsettled — resetting on the intermediate
    /// certificate would disable the escape hatch exactly when ingestion
    /// outpaces the ordinary batches.
    fn enforce_global_budget(
        &self,
        conn: &Connection,
        policy: &RetentionPolicy,
        exclude: &str,
        deadline: std::time::Instant,
        outcome: &mut RetainOutcome,
    ) -> HistoryResult<()> {
        // 4a. Escape hatch first (C-1264-1 §3): three consecutive passes
        // have already failed to settle this store while it sat over the
        // cap. C-1264-2: the forced path is global-cap EVICTION — its
        // leading measure and whole-table COUNT(*) are not reclamation
        // statements and are not deadline-gated; only the fold slices it
        // interleaves are, and they gate themselves.
        if self.unsettled_passes.load(Ordering::Relaxed) as usize
            >= UNSETTLED_PASSES_BEFORE_FORCED_EVICT
            && live_db_bytes(conn)?.max(0) as u64 > policy.max_bytes
        {
            self.forced_evict_over_cap(conn, policy, exclude, deadline, outcome)?;
        }

        // 4b. Maintenance until the settled certificate or the budget.
        // This certificate is INTERMEDIATE: it authorizes eviction below
        // but must not touch the counter (R4-B) — the pass's final state,
        // after its last statement, is what 4d accounts.
        let mut settled = self.maintain_until_settled(conn, deadline)?;

        // 4c. Settled eviction: measure, delete one bounded batch, fold its
        // tombstones, remeasure — all inside the held connection.
        // Adaptive batch sizing from the MEASURED marginal: the first
        // batch takes the estimate-window's pick (capped at
        // [`RETAIN_EVICT_BATCH`]); each completed batch then teaches the
        // loop the live bytes actually freed per deleted row — measured on
        // this held connection after the fold — and later batches are
        // sized to the remaining excess so the pass stops near the minimum
        // number of rows instead of a batch granularity past it. On rows
        // whose estimate is far below their real cost (short binary rows,
        // metadata-heavy signed rows) the estimate alone would overshoot
        // by whole extra batches (that was review round 2, finding 5).
        // C-1264-2: the batches and measures are eviction — never
        // deadline-gated; the loop's only gates are the settled
        // certificate (re-earned after every batch) and the cap itself.
        // A pass that budget-outs folding one batch therefore ends after
        // at most that one batch, unsettled, accounted by 4d below.
        let mut learned_marginal: Option<u64> = None;
        while settled {
            let live = live_db_bytes(conn)?.max(0) as u64;
            if live <= policy.max_bytes {
                break;
            }
            let excess = live - policy.max_bytes;
            let limit = match learned_marginal {
                None => RETAIN_EVICT_BATCH,
                // +1 row: the batch must always be able to include the
                // crossing row, and a learned marginal of 0 (a batch that
                // freed no whole page yet) must not stall the loop at
                // zero-row batches.
                Some(m) => ((excess / m.max(1)) as usize + 1).min(RETAIN_EVICT_BATCH),
            };
            let n = evict_oldest_batch(conn, excess, exclude, limit)?;
            if n == 0 {
                // No eligible durable row remains; the final-state
                // accounting below stays correct.
                break;
            }
            outcome.evicted += n;
            // The batch's deletes append FTS tombstones; fold them (and
            // vacuum, checkpoint) before the next measure, or the next
            // batch would be sized against bytes that are already
            // reclaimable (the R3-D discipline applied to our own writes).
            // Round-5 test hook (R4-B): stand in for "the deadline ran
            // out while folding this batch" — the same false
            // `maintain_until_settled` would return then, without timing
            // flakiness. Inert in production builds.
            #[cfg(test)]
            let fold_timed_out = self.test_timeout_fold.load(Ordering::Relaxed);
            #[cfg(not(test))]
            let fold_timed_out = false;
            settled = if fold_timed_out {
                false
            } else {
                self.maintain_until_settled(conn, deadline)?
            };
            if settled {
                let after = live_db_bytes(conn)?.max(0) as u64;
                learned_marginal = Some(live.saturating_sub(after) / n);
            }
        }

        // 4d. Account the pass ONCE, from its final state (R4-B): the only
        // writer of `unsettled_passes` in the pass. Budget-out with the
        // index still unsettled while over the cap increments; ending
        // settled, or at/under the cap, resets. The three-pragma live
        // measure is not a reclamation statement (C-1264-2) and is not
        // deadline-gated: the counter must read the pass's final state or
        // the R4-B accounting is wrong.
        if !settled && live_db_bytes(conn)?.max(0) as u64 > policy.max_bytes {
            self.unsettled_passes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.unsettled_passes.store(0, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Maintenance inside one held connection: fold FTS tombstones and
    /// return freelist pages to the OS until the index is SETTLED, the
    /// budget runs out, or — in test builds — the never-settles hook
    /// fires. Returns whether the certificate was obtained; `false` means
    /// only "not settled within this budget", never "nothing left", which
    /// is exactly the distinction R3-C required.
    ///
    /// Settled certificate (C-1264-1 §2): a POSITIVE-rank `'merge'` slice
    /// that does no work, followed — in the same held pass — by a
    /// NEGATIVE-rank slice that also does no work, plus an
    /// `incremental_vacuum` that returns no page. Because the connection
    /// is held, no writer can add segments between the probes, so the pair
    /// really does bound what the engine can still merge for this state:
    /// the positive rank covers automerge-shaped work (a level with
    /// enough segments, or an in-progress merge the engine's bottom-up
    /// selector will pick), and the negative rank — which re-flattens
    /// segments the positive selector stranded (R3-B: `fts5IndexMerge`
    /// only resumes a merge whose input count exceeds the segment count of
    /// every lower level, so a partial merge plus a few newer segments can
    /// make the positive rank a genuine no-op) — no-ops only when there is
    /// nothing left to flatten or rewrite. Work is detected by comparing
    /// the FTS structure record around each statement: the bundled engine
    /// rewrites that record if and only if the statement did work (WAL
    /// frame counts cannot be used: this store checkpoints TRUNCATE-style,
    /// and a TRUNCATE checkpoint reports its post-truncation frame count,
    /// always zero).
    ///
    /// R4-A: the certificate can only complete from statements that
    /// actually RAN. A vacuum that stopped because the deadline expired
    /// reports `skipped` and is not a no-op observation; a positive no-op
    /// followed by an expired budget does not run the negative probe and
    /// does not certify. No reclamation statement starts once the
    /// deadline has passed — one already in flight may overrun, by
    /// design. That rule is threaded BETWEEN the sub-calls, not just
    /// around them: the vacuum probe, its surrounding page-count reads,
    /// the cadence checkpoints and `merge_slice`'s trailing structure
    /// re-read never start behind an overlong merge or vacuum statement,
    /// so a cut-short slice can never be read as a no-op observation
    /// (every skipped slice reports "worked", conservatively).
    ///
    /// Every merge statement is followed by `wal_checkpoint(TRUNCATE)`, so
    /// the WAL between statements holds about one slice
    /// ([`FTS_MERGE_PAGES_PER_SLICE`] output pages) — the same honest
    /// exception as the latency bound applies inside a statement: one huge
    /// posting list can carry a single statement past its page budget, and
    /// the WAL grows with what that statement writes (R3-E).
    fn maintain_until_settled(
        &self,
        conn: &Connection,
        deadline: std::time::Instant,
    ) -> HistoryResult<bool> {
        loop {
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            // Round-4 test hook: stand in for "the budget ran out before
            // the index settled" without timing flakiness. Inert in
            // production builds.
            #[cfg(test)]
            if self.test_never_settles.load(Ordering::Relaxed) {
                return Ok(false);
            }
            // Merge slice: positive rank — resume an in-progress merge or
            // merge a level with enough segments.
            let worked = self.merge_slice(conn, FTS_MERGE_PAGES_PER_SLICE, deadline)?;
            // R4-A (round 6): the merge statement may have been the
            // in-flight overrun; the vacuum probe and the cadence
            // checkpoint are NEW statements and must not start behind
            // it. Reporting is moot — this return is "not settled".
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            let (vacuumed, vacuum_skipped) = self.vacuum_slice(conn, deadline)?;
            if vacuum_skipped || std::time::Instant::now() >= deadline {
                // The vacuum stopped on the deadline: its page count is
                // not the no-op the certificate needs (there may still be
                // freelist pages to return), and no further reclamation
                // statement may start (R4-A) — including the cadence
                // checkpoint below. What WAL the skipped cadence left is
                // bounded by the statements that did run and belongs to
                // the next statement in budget.
                return Ok(false);
            }
            Self::checkpoint_wal(conn)?;
            if worked || vacuumed > 0 {
                continue;
            }
            // The positive rank found nothing it will merge. Second half
            // of the certificate: the negative rank. It re-flattens
            // whatever optimize-shaped state the positive selector
            // stranded, so it no-ops only when the index truly has
            // nothing left to merge. A statement that does not run
            // cannot certify: if the budget expired with the positive
            // no-op, the negative probe belongs to the next pass (R4-A).
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            let flattened = self.merge_slice(conn, -FTS_MERGE_PAGES_PER_SLICE, deadline)?;
            // R4-A: same rule as the positive probe above — no vacuum
            // probe, no cadence checkpoint behind an overlong negative
            // merge.
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            let (vacuumed_after, vacuum_skipped_after) = self.vacuum_slice(conn, deadline)?;
            if vacuum_skipped_after || std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            Self::checkpoint_wal(conn)?;
            if flattened || vacuumed_after > 0 {
                continue;
            }
            // Settled: positive no-op, negative no-op, vacuum no-op —
            // inside one held connection. The live measure is final.
            return Ok(true);
        }
    }

    /// One bounded merge statement of the given rank plus its truncating
    /// checkpoint. Returns whether the statement did work (the FTS
    /// structure record changed around it).
    ///
    /// R4-A: every statement of the slice is deadline-checked
    /// individually — the leading structure read, the merge itself, the
    /// trailing checkpoint AND the trailing structure re-read (round 7:
    /// each may follow a statement that was the in-flight overrun).
    /// When any of them is skipped the slice reports `true` (worked):
    /// an unread structure cannot certify a no-op, and the caller's own
    /// post-slice deadline check ends the pass. An un-checkpointed merge
    /// tail is left for the next statement in budget — at worst the
    /// teardown checkpoint or the next pass's first checkpoint.
    ///
    /// Test builds also count the slice and observe the WAL size around
    /// the statement/checkpoint pair (R4-C): the deterministic in-pass
    /// peak record that replaced the round-4 external poller.
    fn merge_slice(
        &self,
        conn: &Connection,
        rank: i64,
        deadline: std::time::Instant,
    ) -> HistoryResult<bool> {
        if std::time::Instant::now() >= deadline {
            // Nothing ran: conservatively "worked", so no caller can
            // read this as a no-op observation (R4-A round 6).
            return Ok(true);
        }
        let structure_before = Self::fts_structure(conn)?;
        if std::time::Instant::now() >= deadline {
            return Ok(true);
        }
        conn.execute(
            "INSERT INTO history_fts(history_fts, rank) VALUES('merge', ?1)",
            rusqlite::params![rank],
        )?;
        #[cfg(test)]
        {
            self.test_merge_slices.fetch_add(1, Ordering::Relaxed);
            self.observe_wal_for_tests();
        }
        if std::time::Instant::now() >= deadline {
            // The merge statement above may have been the in-flight
            // overrun; its checkpoint and structure re-read are new
            // reclamation statements and must not start (R4-A).
            return Ok(true);
        }
        Self::checkpoint_wal(conn)?;
        #[cfg(test)]
        self.observe_wal_for_tests();
        // R4-A (round 7): the trailing structure re-read is the slice's
        // last statement; the checkpoint above may itself have been the
        // in-flight overrun, and no reclamation statement starts past the
        // deadline. An unread structure cannot certify a no-op, so report
        // "worked", conservatively.
        if std::time::Instant::now() >= deadline {
            return Ok(true);
        }
        Ok(Self::fts_structure(conn)? != structure_before)
    }

    /// One bounded vacuum slice: return freelist pages to the OS. The
    /// file's auto_vacuum mode is READ here, never set — changing it on an
    /// existing file rewrites the header, a file-format change this code
    /// must not make silently. `FULL` reclaims at commit (nothing
    /// incremental to do); `NONE` needs a whole-file VACUUM, which the
    /// reaper must not run on its own. In those modes this is a no-op and
    /// the merge slices and checkpoints still apply.
    ///
    /// Returns `(pages_returned, skipped)`. `skipped` is true ONLY when
    /// the slice stopped because the deadline expired (R4-A) — including
    /// the mode probe never running because the budget was already gone
    /// on entry (round 6): a deadline-skipped vacuum is not the same
    /// observation as a genuine no-op, and the settled certificate may
    /// complete only from statements that actually ran. Stopping because
    /// `page_count` stopped falling, or a non-incremental `auto_vacuum`
    /// mode, is a genuine no-op (`skipped = false`).
    ///
    /// One page moves per statement on the bundled SQLite whatever the
    /// argument says (measured; see [`VACUUM_PAGES_PER_SLICE`]), so the
    /// loop of statements is the real bound, stopping the moment the
    /// file stops shrinking. Every statement of the loop — the leading
    /// and trailing page-count reads and the cadence checkpoints — is
    /// individually deadline-checked (R4-A, round 7): a step that
    /// consumed the remaining budget is never followed by another.
    ///
    /// WAL bound (round 4, measured): one page move costs ~5 pages of WAL
    /// (the moved page plus pointer-map and freelist bookkeeping), so the
    /// loop checkpoints every [`VACUUM_CHECKPOINT_EVERY`] statements —
    /// without that, a 512-statement slice parks ~10 MiB in the WAL
    /// between the slice's checkpoints (R3-E). Test builds observe the WAL
    /// after every statement and every checkpoint (R4-C), so removing
    /// those checkpoints is observable as a peak overrun.
    fn vacuum_slice(
        &self,
        conn: &Connection,
        deadline: std::time::Instant,
    ) -> HistoryResult<(i64, bool)> {
        // R4-A (round 6): the mode probe is a statement too — an expired
        // budget means the slice did not run and must not be read as a
        // no-op.
        if std::time::Instant::now() >= deadline {
            return Ok((0, true));
        }
        let auto_vacuum: i64 = conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
        if auto_vacuum != 2 {
            return Ok((0, false));
        }
        let mut vacuumed = 0_i64;
        for i in 0..VACUUM_PAGES_PER_SLICE {
            if std::time::Instant::now() >= deadline {
                return Ok((vacuumed, true));
            }
            let before: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            // R4-A (round 7 review): the leading read may have used up the
            // budget; the vacuum step is a new reclamation write.
            if std::time::Instant::now() >= deadline {
                return Ok((vacuumed, true));
            }
            conn.execute_batch(&format!(
                "PRAGMA incremental_vacuum({VACUUM_PAGES_PER_SLICE});"
            ))?;
            #[cfg(test)]
            self.observe_wal_for_tests();
            // R4-A (round 7): the page-count read after a vacuum step and
            // the cadence checkpoint that may follow it are reclamation
            // statements too — if the step above consumed the remaining
            // budget they must not start, and the unobserved step reports
            // itself as skipped, never as a no-op toward the certificate.
            if std::time::Instant::now() >= deadline {
                return Ok((vacuumed, true));
            }
            let after: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            if after >= before {
                break;
            }
            vacuumed += before - after;
            if i % VACUUM_CHECKPOINT_EVERY == VACUUM_CHECKPOINT_EVERY - 1 {
                if std::time::Instant::now() >= deadline {
                    return Ok((vacuumed, true));
                }
                Self::checkpoint_wal(conn)?;
                #[cfg(test)]
                self.observe_wal_for_tests();
            }
        }
        Ok((vacuumed, false))
    }

    /// C-1264-1 §3, the escape hatch: evict by ESTIMATE after
    /// [`UNSETTLED_PASSES_BEFORE_FORCED_EVICT`] consecutive passes failed
    /// to settle the index while the store sat over its cap (R3-C:
    /// without this, a store whose maintenance cannot keep up with
    /// ingestion would defer global eviction forever while staying over
    /// the cap).
    ///
    /// The estimate: bytes per row = live bytes / history row count, both
    /// measured on the held connection; the pass deletes
    /// `ceil(excess / avg) + 1` oldest eligible rows — the `+1` is the
    /// crossing row, mirroring [`evict_oldest_batch`]'s window — in
    /// bounded batches of at most [`RETAIN_EVICT_BATCH`], each followed —
    /// while the pass budget lasts — by one bounded merge/vacuum slice and
    /// a truncating checkpoint, and it stops early the moment a remeasure
    /// fits the cap. C-1264-2: the deletes, the leading measure, the
    /// whole-table COUNT and the remeasures are eviction work and are not
    /// deadline-gated, so the escape hatch always runs to its bounded
    /// quota; only the interleaved fold slices and checkpoints are
    /// reclamation, and they stop starting once the budget is spent.
    ///
    /// OVER-DELETION IS BOUNDED BY THE ESTIMATE ERROR, no more: the
    /// average mixes cheap and expensive rows, and the tombstones this
    /// path's own deletes append are not yet folded into the measure, so
    /// it can delete rows the exact per-row costs would have spared (or
    /// leave the store over the cap for the next pass). Deleting data the
    /// cap did not strictly require is the accepted cost of eventually
    /// MEETING the cap; a later settled pass goes back to the exact
    /// window.
    fn forced_evict_over_cap(
        &self,
        conn: &Connection,
        policy: &RetentionPolicy,
        exclude: &str,
        deadline: std::time::Instant,
        outcome: &mut RetainOutcome,
    ) -> HistoryResult<()> {
        let live = live_db_bytes(conn)?.max(0) as u64;
        let rows: i64 = conn.query_row("SELECT COUNT(*) FROM history", [], |r| r.get(0))?;
        if rows <= 0 {
            return Ok(());
        }
        // Bytes per row across the whole measured store — the estimate an
        // unsettled index forces on us. The +1 keeps the crossing row in
        // the deleted set for any positive excess.
        let avg = (live / rows as u64).max(1);
        let excess = live.saturating_sub(policy.max_bytes);
        let mut remaining = excess / avg + 1;
        while remaining > 0 {
            let batch = remaining.min(RETAIN_EVICT_BATCH as u64) as usize;
            let n = evict_oldest_rows_by_count(conn, batch, exclude)?;
            if n == 0 {
                return Ok(());
            }
            outcome.evicted += n;
            remaining -= n;
            // Fold what the batch's tombstones allow and keep the WAL
            // bounded — the reclamation half of this path, deadline-gated
            // like every reclamation statement (the slice helpers check
            // before each of their own statements, so an exhausted budget
            // degrades only the folding, never the deletes above).
            let _ = self.merge_slice(conn, FTS_MERGE_PAGES_PER_SLICE, deadline)?;
            let (_vacuumed, _vacuum_skipped) = self.vacuum_slice(conn, deadline)?;
            if std::time::Instant::now() < deadline {
                Self::checkpoint_wal(conn)?;
            }
            // The remeasure is eviction work (C-1264-2), never gated:
            // deletes already moved freed pages to the freelist, so the
            // early stop stays meaningful even when the folds after the
            // budget's end have not run.
            if live_db_bytes(conn)?.max(0) as u64 <= policy.max_bytes {
                return Ok(());
            }
        }
        Ok(())
    }

    /// [`live_db_bytes`] under the store mutex — the live measure for
    /// diagnostics outside a pass (the pass itself measures on its own
    /// held connection).
    ///
    /// Read-only on purpose (review round 2, R2-F): the pager already
    /// takes the database size from the WAL (bundled sqlite3.c ~60381), so
    /// committed-but-uncheckpointed pages cannot hide from the cap and a
    /// measurement needs no checkpoint. Checkpointing is a deliberate
    /// maintenance cadence inside the pass, not part of measuring.
    #[cfg(test)]
    fn live_bytes(&self) -> HistoryResult<u64> {
        let guard = lock_conn(&self.conn)?;
        Ok(live_db_bytes(&guard)?.max(0) as u64)
    }

    /// Checkpoint the WAL, truncating it. Runs between the bounded
    /// maintenance statements so the WAL stays small between transactions
    /// (deliberate cadence, not part of measuring — R2-F).
    fn checkpoint_wal(conn: &Connection) -> HistoryResult<()> {
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| HistoryError::Database(format!("wal checkpoint failed: {e}")))
    }

    /// The FTS5 structure record — the bundled engine's persisted index
    /// layout (segments, in-progress merges), stored as the `history_fts`
    /// `%_data` row at the engine's fixed structure rowid (10). The engine
    /// rewrites this record if and only if a `'merge'` statement actually
    /// did work, which makes comparing it around a statement the exact
    /// "did this merge do anything" signal [`Store::merge_slice`] needs.
    fn fts_structure(conn: &Connection) -> HistoryResult<Vec<u8>> {
        conn.query_row(
            "SELECT block FROM history_fts_data WHERE id = 10",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| HistoryError::Database(format!("fts structure read failed: {e}")))
        .map(|row| row.unwrap_or_default())
    }

    /// Issue #1286: how many `scope_limits` entries the most recent
    /// retention pass skipped because their scope string does not parse
    /// (it must be `dm:<agent>`, `group:<id>` or `topic:<name>`). Zero means
    /// every configured limit was in force in that pass.
    #[must_use]
    pub fn skipped_scope_limits(&self) -> u64 {
        self.skipped_scope_limits.load(Ordering::Relaxed)
    }

    /// Record phase 3's skipped `scope_limits` entries: overwrite the gauge,
    /// and warn the first time any pass on this store skips one. The policy
    /// cannot change while the store is open, so one warning carries all
    /// the information; repeating it every pass would only add noise.
    fn note_skipped_scope_limits(&self, skipped: &[&str]) {
        self.skipped_scope_limits
            .store(skipped.len() as u64, Ordering::Relaxed);
        if skipped.is_empty()
            || self
                .skipped_scope_limits_logged
                .swap(true, Ordering::Relaxed)
        {
            return;
        }
        // Operator-supplied strings from the config file; show a bounded
        // number of them.
        let shown: Vec<&str> = skipped.iter().take(16).copied().collect();
        tracing::warn!(
            skipped = skipped.len(),
            scopes = ?shown,
            "[history] skipping [[history.scope_limits]] entries whose scope does not parse \
             (expected dm:<agent>, group:<id> or topic:<name>); the other limits and the \
             whole-database budget still apply (#1286). Logged once per store."
        );
    }

    /// ADR-0068 D1: the byte ceiling for one pinned scope.
    ///
    /// `min(MULTIPLIER * base, max_bytes / ABSOLUTE_DIVISOR)` where `base` is
    /// the operator's own [`ScopeLimit`] for the scope when they configured
    /// one, else `max_bytes / BASE_DIVISOR`. See the ADR for why these
    /// numbers: the multiplier is the ratified "4× the normal per-scope
    /// bound", the base divisor synthesises a per-scope bound for a scope
    /// that has none, and the absolute divisor caps a large explicit limit.
    #[must_use]
    pub fn pinned_ceiling(policy: &RetentionPolicy, scope: &Scope) -> u64 {
        let canonical = scope.canonical();
        let base = policy
            .scope_limits
            .iter()
            .find(|limit| limit.scope == canonical)
            .map_or_else(
                || policy.max_bytes / HISTORY_QUARANTINE_PIN_BASE_DIVISOR,
                |limit| limit.max_bytes,
            );
        base.saturating_mul(HISTORY_QUARANTINE_PIN_MULTIPLIER)
            .min(policy.max_bytes / HISTORY_QUARANTINE_PIN_ABSOLUTE_DIVISOR)
    }

    /// Delete every row in `scope`. Returns rows removed. Local-only.
    pub fn purge(&self, scope: &Scope) -> HistoryResult<u64> {
        let guard = lock_conn(&self.conn)?;
        let n = guard.execute(
            "DELETE FROM history WHERE scope_kind = ?1 AND scope_id = ?2",
            rusqlite::params![scope.kind(), scope.id()],
        )?;
        cleanup_canonical_ids(&guard)?;
        guard.execute_batch("PRAGMA incremental_vacuum;")?;
        Ok(n as u64)
    }

    /// Write a batch inside one transaction (writer thread path).
    /// Returns (inserted_or_replaced, duplicates).
    pub fn insert_batch(&self, records: &[HistoryRecord]) -> HistoryResult<(u64, u64)> {
        let mut written = 0u64;
        let mut dups = 0u64;
        for record in records {
            match self.insert(record)? {
                InsertOutcome::Inserted | InsertOutcome::Replaced => written += 1,
                InsertOutcome::Duplicate | InsertOutcome::StaleRejected => dups += 1,
            }
        }
        Ok((written, dups))
    }
}

/// Effective query limit: default 100, clamped to [`MAX_QUERY_LIMIT`].
fn effective_limit(requested: usize) -> usize {
    let l = if requested == 0 { 100 } else { requested };
    l.min(MAX_QUERY_LIMIT)
}

fn now_ms() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(_) => 0,
    }
}

/// Build the pin-exclusion SQL fragment for THIS retention call
/// (ADR-0068 D1; review round 2, R2-D): a row-value `NOT IN (VALUES …)`
/// list inlined into the age and global-budget statements. Deliberately
/// NOT a connection-local `TEMP` table: the pins would then live in
/// connection state another call could materialize into and clear — with
/// the list inlined, each call's pins travel with its own SQL while whole
/// passes serialize on [`Store::retention`]. Pin sets are small
/// (fork-quarantined scopes) and the values are literal-escaped, so the
/// fragment stays trivial.
fn pinned_exclusion_sql(pinned: &PinnedScopes) -> String {
    if pinned.scopes.is_empty() {
        return String::new();
    }
    let values = pinned
        .scopes
        .iter()
        .map(|(kind, id)| format!("({kind}, '{}')", id.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(", ");
    format!(" AND (history.scope_kind, history.scope_id) NOT IN (VALUES {values})")
}

/// Database size in bytes (page_count × page_size) as reported by
/// [`Store::stats`]: the size the main file occupies, including pages on
/// the freelist that retention has already emptied.
fn db_bytes(conn: &Connection) -> HistoryResult<i64> {
    let pages: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok(pages.saturating_mul(size))
}

/// Live bytes of the main database: pages in use (`page_count` minus the
/// freelist) × `page_size` (issue #1264 part 1). Freed pages sit on the
/// freelist until `incremental_vacuum` returns them and FTS5 delete
/// tombstones occupy live index pages until a `'merge'` folds them away, so
/// neither the file size nor `page_count` reflects what retention has
/// actually reclaimed — reaping against either over-deletes and never
/// converges.
fn live_db_bytes(conn: &Connection) -> HistoryResult<i64> {
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let freelist: i64 = conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok(page_count
        .saturating_sub(freelist)
        .saturating_mul(page_size))
}

/// Delete ONE bounded batch of the oldest durable rows whose estimated
/// footprint covers `excess` — INCLUDING the row that crosses the target
/// (issue #1264 part 1, review round 2). The window is
/// `running − own_estimate < excess` — every row whose predecessors' total
/// is below the excess — so the oldest eligible row is ALWAYS selected
/// while the store is over the cap (its predecessor total is zero, and the
/// caller only invokes this with `excess > 0`), and the batch never
/// overshoots the target by more than one row. A store whose oldest
/// eligible row estimates larger than the whole excess therefore still
/// loses that row: the alternative is stopping above the configured cap,
/// which the budget exists to prevent.
///
/// The per-row measure — payload + signed artifact + the FTS `payload_text`
/// projection — is a SELECTION ESTIMATE, not a footprint: it omits the
/// 32-byte `msg_id`, signature/public-key/author metadata, B-tree and index
/// overhead and the row's actual FTS postings, so short binary rows and
/// metadata-heavy signed rows both occupy more live bytes than the estimate
/// claims (review round 2). That is safe only because the caller never
/// trusts the estimate across batches: this helper returns after ONE
/// bounded transaction of at most `limit` rows (≤ [`RETAIN_EVICT_BATCH`]),
/// and the caller — inside one held pass — folds the batch's tombstones
/// and remeasures live pages before selecting the next batch.
/// Including `payload_text` keeps the estimate high enough that an
/// FTS-heavy text row is not under-counted several-fold within a single
/// batch. Same oldest-first ordering as [`evict_pinned_scope_to_ceiling`];
/// pinned scopes stay out of reach through the caller's `exclude`
/// predicate. Returns rows evicted (0 = no eligible durable row exists).
///
/// C-1264-2: like every eviction helper, this is not deadline-gated —
/// the batch always completes once selected; only the caller's fold
/// between batches is reclamation and carries the budget.
fn evict_oldest_batch(
    conn: &Connection,
    excess: u64,
    exclude: &str,
    limit: usize,
) -> HistoryResult<u64> {
    let tx = conn.unchecked_transaction()?;
    // `running` is the cumulative estimate in oldest-first order; admitting
    // rows while `running - len < excess` stops the window at — and includes
    // — the first row whose cumulative total reaches the excess.
    let ids: Vec<i64> = {
        let mut stmt = tx.prepare(&format!(
            "SELECT id FROM (SELECT id, len, \
               SUM(len) OVER (ORDER BY seen_at_ms ASC, id ASC) AS running \
             FROM (SELECT id, seen_at_ms, \
               LENGTH(payload) + LENGTH(COALESCE(signed_artifact, x'')) \
                 + LENGTH(COALESCE(payload_text, x'')) AS len \
             FROM history WHERE replace_key IS NULL{exclude})) \
             WHERE running - len < ?1 LIMIT ?2"
        ))?;
        let excess = excess.min(i64::MAX as u64) as i64;
        let rows = stmt.query_map(rusqlite::params![excess, limit as i64], |row| {
            row.get::<_, i64>(0)
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    if ids.is_empty() {
        tx.rollback()?;
        return Ok(0);
    }
    let values: Vec<rusqlite::types::Value> = ids
        .iter()
        .map(|id| rusqlite::types::Value::from(*id))
        .collect();
    let placeholders = (1..=values.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    tx.execute(
        &format!("DELETE FROM history WHERE id IN ({placeholders})"),
        rusqlite::params_from_iter(values),
    )?;
    tx.commit()?;
    Ok(ids.len() as u64)
}

/// Delete up to `count` of the OLDEST eligible durable rows in ONE bounded
/// statement — the count-driven counterpart of [`evict_oldest_batch`]'s
/// estimate-driven window, used only by the forced-eviction escape hatch
/// (C-1264-1 §3), where no settled measure exists to steer a window.
/// Pinned scopes stay out of reach through the caller's `exclude`
/// predicate. Returns rows evicted (0 = no eligible durable row exists).
fn evict_oldest_rows_by_count(
    conn: &Connection,
    count: usize,
    exclude: &str,
) -> HistoryResult<u64> {
    if count == 0 {
        return Ok(0);
    }
    let n = conn.execute(
        &format!(
            "DELETE FROM history WHERE id IN (\
               SELECT id FROM history WHERE replace_key IS NULL{exclude} \
               ORDER BY seen_at_ms ASC, id ASC LIMIT ?1)"
        ),
        rusqlite::params![count as i64],
    )?;
    Ok(n as u64)
}

/// ADR-0068 D1: bring ONE pinned scope back to its ceiling, oldest-first,
/// deleting no more than the overshoot requires. Returns rows evicted.
///
/// WHY this is not [`evict_scope_to_budget`]. That helper deletes a whole
/// `RETAIN_EVICT_BATCH` (256 rows) per step, so a scope one row over its budget
/// can lose 256 — acceptable for an ordinary budget, wrong for a *ceiling* on a
/// forensic record that ADR-0066 R3 and row 14 exist to keep. The running-total
/// window picks exactly the oldest rows whose bytes cover the excess, and the
/// batch cap still bounds one statement.
///
/// C-1264-2: this loop is eviction and is not deadline-gated — it runs
/// to completion in every pass, at main's cost, so a pinned scope's
/// ceiling is always enforced however little reclamation budget remains.
fn evict_pinned_scope_to_ceiling(
    conn: &Connection,
    scope: &Scope,
    ceiling: u64,
) -> HistoryResult<u64> {
    let mut evicted = 0u64;
    loop {
        let used: i64 = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(payload) + LENGTH(COALESCE(signed_artifact, x''))), 0) \
             FROM history WHERE scope_kind = ?1 AND scope_id = ?2",
            rusqlite::params![scope.kind(), scope.id()],
            |r| r.get(0),
        )?;
        let excess = (used as u64).saturating_sub(ceiling);
        if excess == 0 {
            return Ok(evicted);
        }
        let n = conn.execute(
            "DELETE FROM history WHERE id IN (\
               SELECT id FROM (\
                 SELECT id, SUM(LENGTH(payload) + LENGTH(COALESCE(signed_artifact, x''))) \
                   OVER (ORDER BY seen_at_ms ASC, id ASC) AS running \
                 FROM history \
                 WHERE scope_kind = ?1 AND scope_id = ?2 AND replace_key IS NULL) \
               WHERE running <= ?3 LIMIT ?4)",
            rusqlite::params![
                scope.kind(),
                scope.id(),
                excess as i64,
                RETAIN_EVICT_BATCH as i64
            ],
        )?;
        if n == 0 {
            // Either only replaceable rows remain, or the single oldest
            // durable row is itself larger than the excess — deleting it
            // would take the scope further below its ceiling than needed, so
            // leave it and accept the overshoot (bounded by one row).
            return Ok(evicted);
        }
        evicted += n as u64;
    }
}
/// Evict oldest-first inside ONE scope until its measured bytes fit
/// `max_bytes`. Returns rows evicted.
///
/// Shared by the per-scope budget phase and the ADR-0068 pinned-ceiling
/// phase so the two cannot drift in what they measure (payload +
/// `signed_artifact`) or in what they are willing to delete (durable rows
/// only — a replaceable row is current state and counts toward the measure
/// without being evictable).
///
/// C-1264-2: this loop is eviction and is not deadline-gated — every
/// configured scope is served to its limit in every pass, exactly as on
/// main, whatever the reclamation budget is doing.
fn evict_scope_to_budget(conn: &Connection, scope: &Scope, max_bytes: u64) -> HistoryResult<u64> {
    let mut evicted = 0u64;
    loop {
        let used: i64 = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(payload) + LENGTH(COALESCE(signed_artifact, x''))), 0) \
             FROM history WHERE scope_kind = ?1 AND scope_id = ?2",
            rusqlite::params![scope.kind(), scope.id()],
            |r| r.get(0),
        )?;
        if used as u64 <= max_bytes {
            return Ok(evicted);
        }
        let n = conn.execute(
            "DELETE FROM history WHERE id IN (\
               SELECT id FROM history \
               WHERE scope_kind = ?1 AND scope_id = ?2 AND replace_key IS NULL \
               ORDER BY seen_at_ms ASC LIMIT ?3)",
            rusqlite::params![scope.kind(), scope.id(), RETAIN_EVICT_BATCH as i64],
        )?;
        if n == 0 {
            // Only replaceable rows remain in this scope.
            return Ok(evicted);
        }
        evicted += n as u64;
    }
}

fn push_common_filters(
    q: &HistoryQuery,
    parts: &mut Vec<String>,
    params: &mut Vec<rusqlite::types::Value>,
) {
    if let Some(scope) = &q.scope {
        parts.push("scope_kind = ?".into());
        params.push(rusqlite::types::Value::from(scope.kind()));
        parts.push("scope_id = ?".into());
        params.push(rusqlite::types::Value::from(scope.id().to_string()));
    } else if let Some(kind) = q.scope_kind {
        parts.push("scope_kind = ?".into());
        params.push(rusqlite::types::Value::from(kind));
    }
    if let Some(since) = q.since_ms {
        parts.push("seen_at_ms >= ?".into());
        params.push(rusqlite::types::Value::from(since));
    }
    if let Some(until) = q.until_ms {
        parts.push("seen_at_ms <= ?".into());
        params.push(rusqlite::types::Value::from(until));
    }
    if let Some(before) = q.before_id {
        parts.push("id < ?".into());
        params.push(rusqlite::types::Value::from(before));
    }
}

fn collect_rows(
    conn: &Connection,
    sql: &str,
    params: Vec<rusqlite::types::Value>,
) -> HistoryResult<Vec<StoredRecord>> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| HistoryError::Database(format!("prepare failed: {e}")))?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), row_to_record)
        .map_err(|e| HistoryError::Database(format!("query failed: {e}")))?;
    let mut out = Vec::new();
    for row in rows {
        let (id, record) =
            row.map_err(|e| HistoryError::Database(format!("row read failed: {e}")))?;
        out.push(StoredRecord {
            id,
            record: record?,
        });
    }
    Ok(out)
}

type RowResult = std::result::Result<(i64, HistoryResult<HistoryRecord>), rusqlite::Error>;

#[allow(clippy::type_complexity)]
fn row_to_record(r: &rusqlite::Row<'_>) -> RowResult {
    let id: i64 = r.get(0)?;
    let msg_id_blob: Vec<u8> = r.get(1)?;
    let scope_kind: i64 = r.get(2)?;
    let scope_id: String = r.get(3)?;
    let author_agent: Option<String> = r.get(4)?;
    let author_machine: Option<String> = r.get(5)?;
    let author_pubkey: Option<Vec<u8>> = r.get(6)?;
    let sent_at_ms: i64 = r.get(7)?;
    let seen_at_ms: i64 = r.get(8)?;
    let direction: i64 = r.get(9)?;
    let content_type: String = r.get(10)?;
    let payload: Vec<u8> = r.get(11)?;
    let signed_artifact: Option<Vec<u8>> = r.get(12)?;
    let signature: Option<Vec<u8>> = r.get(13)?;
    let sig_context: Option<String> = r.get(14)?;
    let provenance: i64 = r.get(15)?;
    let replace_key: Option<String> = r.get(16)?;
    let thread_root: Option<String> = r.get(17)?;
    let thread_parent: Option<String> = r.get(18)?;
    let ingress_sender_agent: Option<String> = r.get(19)?;
    let logical_request_id_blob: Option<Vec<u8>> = r.get(20)?;

    let record = (|| -> HistoryResult<HistoryRecord> {
        let mut msg_id = [0u8; 32];
        if msg_id_blob.len() != 32 {
            return Err(HistoryError::InvalidRecord("msg_id not 32 bytes".into()));
        }
        msg_id.copy_from_slice(&msg_id_blob);
        let logical_request_id = logical_request_id_blob
            .map(|blob| {
                let mut request_id = [0_u8; 16];
                if blob.len() != request_id.len() {
                    return Err(HistoryError::InvalidRecord(
                        "logical_request_id not 16 bytes".into(),
                    ));
                }
                request_id.copy_from_slice(&blob);
                Ok(request_id)
            })
            .transpose()?;
        Ok(HistoryRecord {
            msg_id,
            scope: Scope::from_columns(scope_kind, scope_id)?,
            author_agent,
            author_machine,
            author_pubkey,
            sent_at_ms,
            seen_at_ms,
            direction: Direction::from_i64(direction)?,
            content_type,
            payload,
            signed_artifact,
            signature,
            sig_context,
            provenance: Provenance::from_i64(provenance)?,
            replace_key,
            thread_root,
            thread_parent,
            ingress_sender_agent,
            logical_request_id,
        })
    })();
    Ok((id, record))
}

fn insert_row(tx: &rusqlite::Transaction<'_>, record: &HistoryRecord) -> HistoryResult<()> {
    let payload_text = searchable_payload_text(&record.content_type, &record.payload);
    let msg_id: &[u8] = &record.msg_id;
    tx.execute(
        "INSERT INTO history (msg_id, scope_kind, scope_id, author_agent, author_machine, \
         author_pubkey, sent_at_ms, seen_at_ms, direction, content_type, payload, \
         payload_text, signed_artifact, signature, sig_context, provenance, replace_key, \
         thread_root, thread_parent, ingress_sender_agent, logical_request_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
         ?18, ?19, ?20, ?21)",
        rusqlite::params![
            msg_id,
            record.scope.kind(),
            record.scope.id(),
            record.author_agent,
            record.author_machine,
            record.author_pubkey,
            record.sent_at_ms,
            record.seen_at_ms,
            record.direction.as_i64(),
            record.content_type,
            record.payload,
            payload_text,
            record.signed_artifact,
            record.signature,
            record.sig_context,
            record.provenance.as_i64(),
            record.replace_key,
            record.thread_root,
            record.thread_parent,
            record.ingress_sender_agent,
            record.logical_request_id.as_ref().map(<[u8; 16]>::as_slice),
        ],
    )
    .map_err(|e| HistoryError::Database(format!("insert failed: {e}")))?;
    if let Some(canonical_msg_id) = canonical_group_msg_id(
        record.scope.kind(),
        record.scope.id(),
        record.signed_artifact.as_deref(),
        &record.payload,
    ) {
        tx.execute(
            "INSERT OR REPLACE INTO history_canonical_ids \
             (history_msg_id, canonical_msg_id, scope_kind, scope_id) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                record.msg_id.as_slice(),
                &canonical_msg_id[..],
                record.scope.kind(),
                record.scope.id(),
            ],
        )
        .map_err(|e| HistoryError::Database(format!("canonical index insert failed: {e}")))?;
    }
    Ok(())
}

/// Indexes and derived projections created idempotently at every open rather
/// than inside the versioned migration chain.
///
/// This is a deliberate departure from the migration convention, and the
/// reason is rollback safety. The auxiliary table contains only a rebuildable
/// projection; an older binary opening this database reads and writes the
/// unchanged v4 `history` table exactly as before. A new binary reconstructs
/// the projection on open, including rows written by that older binary.
/// Adding a column to `history` via a v4→v5 migration would instead bump
/// `SCHEMA_VERSION`, and `migrate` rejects any database newer than the running
/// binary. Schema changes that alter the existing data model still go through
/// the versioned chain.
///
/// `idx_logical_request` backs `find_by_logical_request`, the ADR 0030 §1
/// receiver durable-history lookup, which runs on every inbound v2 DM.
/// Partial (`WHERE logical_request_id IS NOT NULL`) because only rows written
/// by the receiver durable path populate the v4 columns — group rows and every
/// row predating schema v4 carry NULL, and indexing those wastes space for a
/// lookup that can never match them. Mirrors the existing `idx_replace`
/// partial-index precedent.
///
/// `history_backfill_progress` holds the canonical-backfill cursor (one row,
/// `scanned_to_id`). It follows the same rule as the projection table:
/// purely derived, rebuildable state created idempotently at open, never part
/// of the versioned migration chain, so `SCHEMA_VERSION` stays 4 and an older
/// binary opens this database unchanged (ADR 0085: an older build must still
/// open the DB; the marker is additive and ignorable, and deleting it just
/// costs one full rebuild pass on the next open).
///
/// `history.id` is `INTEGER PRIMARY KEY` without `AUTOINCREMENT`, so SQLite
/// REUSES rowids: purge the rows that held the highest ids and the next
/// insert lands at a reused id at or below the completed cursor, where the
/// backfill fast path (`scanned_to_id >= MAX(id)` scan from the cursor up)
/// would never look again. The `history_backfill_lower` trigger closes that
/// hole in the database file itself — triggers fire for every writer,
/// including older binaries that predate the cursor and maintain no
/// projections — by lowering the watermark to just below any inserted id at
/// or below it, so the next open rescans the reused range. An insert by this
/// binary normally takes `MAX(id)+1`, above the watermark, and never fires
/// the trigger; the one exception is the replace path (delete the current
/// max row, insert its successor), which re-lowers the watermark by one row
/// and costs a harmless idempotent rescan of a row `insert_row` already
/// projected.
fn ensure_indexes(conn: &Connection) -> HistoryResult<()> {
    let setup_err = |e: rusqlite::Error| HistoryError::Database(format!("index setup failed: {e}"));
    // One transaction: a projection recreated empty and the cursor reset it
    // needs commit together, so an interrupted open cannot keep the new
    // empty table with a stale completed cursor.
    let tx = conn.unchecked_transaction().map_err(setup_err)?;
    // A projection table created empty below (lost, dropped, or new) must be
    // rebuilt from the bottom, whatever a surviving cursor says.
    let projection_existed: bool = tx
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master \
             WHERE type = 'table' AND name = 'history_canonical_ids')",
            [],
            |row| row.get(0),
        )
        .map_err(setup_err)?;
    tx.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_logical_request \
         ON history(ingress_sender_agent, logical_request_id) \
         WHERE logical_request_id IS NOT NULL; \
         CREATE TABLE IF NOT EXISTS history_canonical_ids ( \
           history_msg_id BLOB NOT NULL PRIMARY KEY, \
           canonical_msg_id BLOB NOT NULL, \
           scope_kind INTEGER NOT NULL, \
           scope_id TEXT NOT NULL \
         ); \
         CREATE INDEX IF NOT EXISTS idx_history_canonical \
         ON history_canonical_ids(canonical_msg_id, scope_kind, scope_id); \
         CREATE TRIGGER IF NOT EXISTS history_canonical_ids_ad AFTER DELETE ON history BEGIN \
           DELETE FROM history_canonical_ids WHERE history_msg_id = old.msg_id; \
         END; \
         CREATE TABLE IF NOT EXISTS history_backfill_progress ( \
           singleton INTEGER PRIMARY KEY CHECK (singleton = 1), \
           scanned_to_id INTEGER NOT NULL \
         ); \
         INSERT OR IGNORE INTO history_backfill_progress (singleton, scanned_to_id) \
           VALUES (1, 0); \
         CREATE TRIGGER IF NOT EXISTS history_backfill_lower AFTER INSERT ON history \
         WHEN NEW.id <= (SELECT scanned_to_id FROM history_backfill_progress \
                         WHERE singleton = 1) \
         BEGIN \
           UPDATE history_backfill_progress SET scanned_to_id = NEW.id - 1 \
           WHERE singleton = 1; \
         END;",
    )
    .map_err(setup_err)?;
    if !projection_existed {
        tx.execute(
            "UPDATE history_backfill_progress SET scanned_to_id = 0 WHERE singleton = 1",
            [],
        )
        .map_err(setup_err)?;
    }
    tx.commit().map_err(setup_err)
}

/// Populate the rebuildable canonical projection for rows written by an older
/// binary or before this auxiliary table existed. Only a structurally valid
/// group artifact is indexed; the history row itself is never changed. The
/// existing unique history `msg_id` is the cache key so SQLite rowid reuse
/// cannot attach an old projection to a new row.
///
/// Progress persists in `history_backfill_progress`, so a full pass runs once
/// per database, not once per open (issue #1263 part 2). The cursor is the
/// highest history rowid examined; rows above it are new, or were written by
/// a binary that does not maintain projections at insert. Rows
/// `canonical_group_msg_id` rejects (e.g. MLS plaintext group rows with no
/// `signed_artifact`) are examined exactly once and then sit below the cursor
/// forever — never rescanned. A row inserted at a REUSED id at or below the
/// cursor (any writer, however old — see `history_backfill_lower` in
/// [`ensure_indexes`]) lowers the watermark inside the inserting
/// transaction, so the next open rescans it; `insert_row` has already
/// projected rows written by this binary, and re-projecting them is
/// idempotent (`INSERT OR REPLACE` keyed on the unique `msg_id`).
fn backfill_canonical_ids(conn: &Connection) -> HistoryResult<()> {
    // Fast path: two scalar reads, no scan. A pass is complete when the
    // cursor has reached the table maximum.
    let max_id: i64 =
        conn.query_row("SELECT COALESCE(MAX(id), 0) FROM history", [], |r| r.get(0))?;
    // A missing progress row (older tooling, manual repair) is not an error:
    // the projection is rebuildable, so restart from the bottom.
    let mut after_id: i64 = conn
        .query_row(
            "SELECT scanned_to_id FROM history_backfill_progress WHERE singleton = 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default();
    if after_id >= max_id {
        return Ok(());
    }
    loop {
        let tx = conn.unchecked_transaction()?;
        // `+h.scope_kind` makes the kind term un-indexable, so the planner
        // cannot pick `idx_scope_time` and sort a candidate set per batch
        // (issue #1263 part 2: O(n²/256) opens): the rowid range drives the
        // scan and `ORDER BY h.id` is the scan order itself. Keep each read
        // bounded so opening a large history cannot allocate all payloads at
        // once; invalid rows still advance the cursor and cannot stall this
        // loop.
        let candidates = {
            let mut stmt = tx.prepare(
                "SELECT h.id, h.msg_id, h.scope_id, h.payload, h.signed_artifact \
                 FROM history h \
                 WHERE h.id > ?1 AND +h.scope_kind = 1 \
                 ORDER BY h.id LIMIT 256",
            )?;
            let rows = stmt.query_map(rusqlite::params![after_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        #[cfg(test)]
        backfill_probe::add(candidates.len() as u64);
        let Some((last_id, ..)) = candidates.last() else {
            // No group rows remain above the cursor: the pass is complete.
            // Mark it at the table maximum (not the last group rowid) so a
            // table whose tail is non-group rows still takes the fast path.
            tx.execute(
                "UPDATE history_backfill_progress SET scanned_to_id = ?1 WHERE singleton = 1",
                rusqlite::params![max_id],
            )?;
            tx.commit()?;
            break;
        };
        let last_id = *last_id;
        for (_, history_msg_id, scope_id, payload, signed_artifact) in candidates {
            let Some(canonical_msg_id) =
                canonical_group_msg_id(1, &scope_id, signed_artifact.as_deref(), &payload)
            else {
                continue;
            };
            tx.execute(
                "INSERT OR REPLACE INTO history_canonical_ids \
                 (history_msg_id, canonical_msg_id, scope_kind, scope_id) \
                 VALUES (?1, ?2, 1, ?3)",
                rusqlite::params![history_msg_id, &canonical_msg_id[..], scope_id],
            )?;
        }
        // Commit each bounded batch independently (projection work AND the
        // cursor advance) so an interrupted open retains completed work and
        // resumes on the next open.
        tx.execute(
            "UPDATE history_backfill_progress SET scanned_to_id = ?1 WHERE singleton = 1",
            rusqlite::params![last_id],
        )?;
        tx.commit()?;
        after_id = last_id;
    }
    Ok(())
}

fn cleanup_canonical_ids(conn: &Connection) -> HistoryResult<()> {
    conn.execute(
        "DELETE FROM history_canonical_ids \
         WHERE history_msg_id NOT IN (SELECT msg_id FROM history)",
        [],
    )?;
    Ok(())
}

/// Derive the ADR-0029 identity without weakening the history record's
/// artifact/payload hash invariant. This deliberately mirrors the REST
/// projection's scope and body checks.
fn canonical_group_msg_id(
    scope_kind: i64,
    scope_id: &str,
    signed_artifact: Option<&[u8]>,
    payload: &[u8],
) -> Option<[u8; 32]> {
    if scope_kind != 1 {
        return None;
    }
    let message =
        serde_json::from_slice::<crate::groups::GroupPublicMessage>(signed_artifact?).ok()?;
    if message.group_id != scope_id || message.body.as_bytes() != payload {
        return None;
    }
    hex::decode(message.msg_id()).ok()?.try_into().ok()
}

/// Forward-only schema migration.
fn migrate(conn: &Connection) -> HistoryResult<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")?;
    let current: Option<i64> = conn
        .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    match current {
        // A fresh database is created at v1 and then walked through the same
        // migration steps an upgrading one takes. That costs a few no-op
        // statements at first open but guarantees the created schema and the
        // migrated schema cannot drift apart.
        None => {
            conn.execute_batch(SCHEMA_V1)?;
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                rusqlite::params![1_i64],
            )?;
            migrate_v1_to_v2(conn)?;
            migrate_v2_to_v3(conn)?;
            migrate_v3_to_v4(conn)
        }
        Some(v) if v == SCHEMA_VERSION => Ok(()),
        Some(1) => {
            migrate_v1_to_v2(conn)?;
            migrate_v2_to_v3(conn)?;
            migrate_v3_to_v4(conn)
        }
        Some(2) => {
            migrate_v2_to_v3(conn)?;
            migrate_v3_to_v4(conn)
        }
        Some(3) => migrate_v3_to_v4(conn),
        Some(v) if v < SCHEMA_VERSION => {
            // Future migrations chain here, bumping stored version each step.
            Err(HistoryError::Database(format!(
                "no migration path from schema v{v}"
            )))
        }
        Some(v) => Err(HistoryError::Database(format!(
            "history.db schema v{v} is newer than this binary (v{SCHEMA_VERSION})"
        ))),
    }
}

/// Schema v2 adds no columns: it backfills the existing FTS projection for
/// native channel-message JSON that schema v1 intentionally left empty. The
/// `history_fts_au` trigger refreshes each corresponding FTS row atomically.
fn migrate_v1_to_v2(conn: &Connection) -> HistoryResult<()> {
    let tx = conn.unchecked_transaction()?;
    let mut after_id = 0_i64;
    loop {
        let candidates = {
            let mut stmt = tx.prepare(
                "SELECT id, payload FROM history \
                 WHERE content_type = 'application/json' AND payload_text IS NULL AND id > ?1 \
                 ORDER BY id LIMIT 256",
            )?;
            let rows = stmt.query_map(rusqlite::params![after_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            let mut candidates = Vec::new();
            for row in rows {
                candidates.push(row?);
            }
            candidates
        };
        let Some((last_id, _)) = candidates.last() else {
            break;
        };
        after_id = *last_id;
        for (id, payload) in candidates {
            if let Some(text) = searchable_payload_text("application/json", &payload) {
                tx.execute(
                    "UPDATE history SET payload_text = ?1 WHERE id = ?2",
                    rusqlite::params![text, id],
                )?;
            }
        }
    }
    tx.execute(
        "UPDATE schema_version SET version = ?1",
        rusqlite::params![2_i64],
    )?;
    tx.commit()?;
    Ok(())
}

/// Schema v3 adds first-class nullable thread ancestry to every durable row.
/// Additive `ALTER`s only: existing rows keep their values and read back
/// `NULL` for the new columns.
fn migrate_v2_to_v3(conn: &Connection) -> HistoryResult<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "ALTER TABLE history ADD COLUMN thread_root TEXT; \
         ALTER TABLE history ADD COLUMN thread_parent TEXT;",
    )?;
    tx.execute(
        "UPDATE schema_version SET version = ?1",
        rusqlite::params![3_i64],
    )?;
    tx.commit()?;
    Ok(())
}

/// Schema v4 adds authenticated transport/logical-request binding for strict
/// durable typed ingress. Existing rows remain intentionally unbound.
fn migrate_v3_to_v4(conn: &Connection) -> HistoryResult<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "ALTER TABLE history ADD COLUMN ingress_sender_agent TEXT; \
         ALTER TABLE history ADD COLUMN logical_request_id BLOB;",
    )?;
    tx.execute(
        "UPDATE schema_version SET version = ?1",
        rusqlite::params![4_i64],
    )?;
    tx.commit()?;
    Ok(())
}

/// Derive the text stored in the external-content FTS table without changing
/// the original payload or its MIME type.
///
/// Besides ordinary `text/*`, recognize the native channel-message JSON used
/// by current clients. Requiring its correlation fields avoids indexing
/// unrelated JSON plumbing or metadata merely because it contains a `text`
/// property. Only the human-authored body is indexed; `clientId`, timestamps,
/// mentions, and any future metadata remain outside the search projection.
fn searchable_payload_text(content_type: &str, payload: &[u8]) -> Option<String> {
    if content_type.starts_with("text/") {
        return Some(String::from_utf8_lossy(payload).into_owned());
    }
    if content_type != "application/json" {
        return None;
    }

    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let object = value.as_object()?;
    let text = object.get("text")?.as_str()?;
    let client_id = object.get("clientId")?.as_str()?;
    object.get("createdAt")?.as_i64()?;
    if client_id.is_empty() {
        return None;
    }
    if let Some(mentions) = object.get("mentions") {
        let mentions = mentions.as_array()?;
        if !mentions.iter().all(serde_json::Value::is_string) {
            return None;
        }
    }
    Some(text.to_owned())
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS history (
  id            INTEGER PRIMARY KEY,
  msg_id        BLOB NOT NULL,
  scope_kind    INTEGER NOT NULL,
  scope_id      TEXT NOT NULL,
  author_agent  TEXT,
  author_machine TEXT,
  author_pubkey BLOB,
  sent_at_ms    INTEGER NOT NULL,
  seen_at_ms    INTEGER NOT NULL,
  direction     INTEGER NOT NULL,
  content_type  TEXT NOT NULL DEFAULT 'text/plain',
  payload       BLOB NOT NULL,
  payload_text  TEXT,
  signed_artifact BLOB,
  signature     BLOB,
  sig_context   TEXT,
  provenance    INTEGER NOT NULL,
  replace_key   TEXT,
  UNIQUE(msg_id)
);
CREATE INDEX IF NOT EXISTS idx_scope_time ON history(scope_kind, scope_id, seen_at_ms);
CREATE INDEX IF NOT EXISTS idx_author ON history(author_agent, seen_at_ms);
CREATE UNIQUE INDEX IF NOT EXISTS idx_replace ON history(replace_key) WHERE replace_key IS NOT NULL;

CREATE VIRTUAL TABLE IF NOT EXISTS history_fts USING fts5(
  payload_text,
  content='history',
  content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS history_fts_ai AFTER INSERT ON history BEGIN
  INSERT INTO history_fts(rowid, payload_text) VALUES (new.id, COALESCE(new.payload_text, ''));
END;
CREATE TRIGGER IF NOT EXISTS history_fts_ad AFTER DELETE ON history BEGIN
  INSERT INTO history_fts(history_fts, rowid, payload_text) VALUES('delete', old.id, COALESCE(old.payload_text, ''));
END;
CREATE TRIGGER IF NOT EXISTS history_fts_au AFTER UPDATE ON history BEGIN
  INSERT INTO history_fts(history_fts, rowid, payload_text) VALUES('delete', old.id, COALESCE(old.payload_text, ''));
  INSERT INTO history_fts(rowid, payload_text) VALUES (new.id, COALESCE(new.payload_text, ''));
END;
"#;

/// Quote each whitespace token so user input is treated as literal phrase
/// terms (AND of the terms), never as FTS5 operators. Donor semantics.
fn fts_match_expr(search: &str) -> String {
    search
        .split_whitespace()
        .map(|tok| {
            let escaped = tok.replace('"', "\"\"");
            format!("\"{escaped}\"")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::history::record::{Direction, Provenance};
    use ant_quic::crypto::raw_public_keys::pqc::{sign_with_ml_dsa, verify_with_ml_dsa};

    fn open() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("history.db")).unwrap();
        (store, dir)
    }

    /// Run retention passes with an unreachable cap until the live measure
    /// stops moving: the maintenance-only way to settle a fixture's FTS
    /// index (a pass under no pressure still maintains to the settled
    /// certificate — C-1264-1 §2). Bounded: 64 passes is far beyond what
    /// any fixture here needs, and stability — not activity counters — is
    /// the observable.
    fn settle(store: &Store) {
        let policy = RetentionPolicy {
            max_bytes: u64::MAX,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };
        let mut prev = store.live_bytes().unwrap();
        for _ in 0..64 {
            let _ = store.retain(&policy).unwrap();
            let now = store.live_bytes().unwrap();
            if now == prev {
                break;
            }
            prev = now;
        }
    }

    #[test]
    fn v1_migration_backfills_native_channel_message_search_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let payload = br#"{"text":"persisted-before-upgrade","createdAt":1786379111246,"clientId":"legacy-client-id"}"#;
        let scope = Scope::Dm("legacy-peer".into());
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL); \
                 INSERT INTO schema_version (version) VALUES (1);",
            )
            .unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            let msg_id = HistoryRecord::compute_msg_id(None, payload);
            conn.execute(
                "INSERT INTO history (msg_id, scope_kind, scope_id, sent_at_ms, seen_at_ms, \
                 direction, content_type, payload, payload_text, provenance) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9)",
                rusqlite::params![
                    &msg_id[..],
                    scope.kind(),
                    scope.id(),
                    1_i64,
                    1_i64,
                    Direction::Inbound.as_i64(),
                    "application/json",
                    payload,
                    Provenance::LocalAppDecrypt.as_i64(),
                ],
            )
            .unwrap();
        }

        let store = Store::open(&path).unwrap();
        let hits = store
            .search(
                "persisted-before-upgrade",
                &HistoryQuery {
                    scope: Some(scope),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(hits.len(), 1, "v1 JSON row must be searchable after open");
        let guard = lock_conn(&store.conn).unwrap();
        let version: i64 = guard
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    /// Column names currently present on the `history` table.
    fn history_columns(store: &Store) -> Vec<String> {
        let guard = lock_conn(&store.conn).unwrap();
        let mut stmt = guard.prepare("PRAGMA table_info(history)").unwrap();
        let names = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        names
    }

    fn stored_schema_version(store: &Store) -> i64 {
        let guard = lock_conn(&store.conn).unwrap();
        guard
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap()
    }

    /// The ADR 0030 §1 durable-history lookup runs on every inbound v2 DM, so
    /// it must not degrade into a table scan as history grows. Asserting on
    /// the query plan rather than on the index merely existing: an index that
    /// SQLite declines to use (wrong column order, predicate mismatch) is
    /// indistinguishable from no index at runtime, and that is the regression
    /// worth catching.
    #[test]
    fn find_by_logical_request_uses_its_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("history.db")).unwrap();
        let guard = lock_conn(&store.conn).unwrap();
        let plan: String = guard
            .query_row(
                "EXPLAIN QUERY PLAN SELECT id FROM history \
                 WHERE ingress_sender_agent = ?1 AND logical_request_id = ?2 \
                 ORDER BY id ASC",
                rusqlite::params!["aa", vec![0x11_u8; 16]],
                |row| row.get(3),
            )
            .unwrap();
        assert!(
            plan.contains("idx_logical_request"),
            "durable-history lookup must use idx_logical_request, got plan: {plan}"
        );
        assert!(
            !plan.contains("SCAN history"),
            "durable-history lookup must not table-scan, got plan: {plan}"
        );
    }

    /// The accelerator index is created outside the versioned migration chain,
    /// so it must reach databases that were already stamped v4 by an earlier
    /// release — those never re-run any migration step.
    #[test]
    fn existing_v4_database_gains_the_index_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(stored_schema_version(&store), 4);
        }
        // Drop the index to simulate a database migrated to v4 before this
        // release, then confirm reopening restores it without a version bump.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("DROP INDEX IF EXISTS idx_logical_request;")
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(
            stored_schema_version(&store),
            4,
            "adding an accelerator index must not bump the schema version, \
             which would make the db unopenable by the previous release"
        );
        let guard = lock_conn(&store.conn).unwrap();
        let count: i64 = guard
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_logical_request'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "reopening a v4 database must restore the index");
    }

    /// ADR 0030 schema continuity: v4 must land on top of a *released* v2
    /// store, not replace it. A v2 database carries real user history, so the
    /// upgrade has to be additive — every pre-existing row survives byte-for-
    /// byte and simply reads `NULL` for the columns it predates.
    #[test]
    fn v2_database_migrates_to_v4_preserving_existing_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let payload = b"written under schema v2";
        let scope = Scope::Dm("v2-peer".into());
        let msg_id = HistoryRecord::compute_msg_id(None, payload);
        {
            // v2 is v1's table shape with the FTS backfill already applied,
            // so the released v2 schema is SCHEMA_V1 stamped as version 2.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL); \
                 INSERT INTO schema_version (version) VALUES (2);",
            )
            .unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.execute(
                "INSERT INTO history (msg_id, scope_kind, scope_id, author_agent, sent_at_ms, \
                 seen_at_ms, direction, content_type, payload, payload_text, provenance) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    &msg_id[..],
                    scope.kind(),
                    scope.id(),
                    "v2-author",
                    7_000_i64,
                    7_001_i64,
                    Direction::Inbound.as_i64(),
                    "text/plain",
                    payload,
                    "written under schema v2",
                    Provenance::LocalAppDecrypt.as_i64(),
                ],
            )
            .unwrap();
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(stored_schema_version(&store), 4);
        let columns = history_columns(&store);
        for added in [
            "thread_root",
            "thread_parent",
            "ingress_sender_agent",
            "logical_request_id",
        ] {
            assert!(
                columns.iter().any(|c| c == added),
                "v4 must add column {added}; found {columns:?}"
            );
        }

        let rows = store
            .query(&HistoryQuery {
                scope: Some(scope),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rows.len(), 1, "the pre-existing v2 row must survive");
        let stored = &rows[0].record;
        assert_eq!(stored.msg_id, msg_id);
        assert_eq!(stored.payload, payload);
        assert_eq!(stored.author_agent.as_deref(), Some("v2-author"));
        assert_eq!(stored.sent_at_ms, 7_000);
        assert_eq!(stored.seen_at_ms, 7_001);
        // Rows that predate the columns are unbound, not defaulted.
        assert_eq!(stored.thread_root, None);
        assert_eq!(stored.thread_parent, None);
        assert_eq!(stored.ingress_sender_agent, None);
        assert_eq!(stored.logical_request_id, None);

        // The v2 FTS projection still resolves after the ALTERs.
        let hits = store.search("written", &HistoryQuery::default()).unwrap();
        assert_eq!(hits.len(), 1, "FTS must survive the v3/v4 ALTERs");
    }

    /// A database created fresh must be indistinguishable from one migrated
    /// up from v2 — same version, same columns. Divergence between the
    /// `CREATE TABLE` path and the `ALTER` path is the classic migration bug.
    #[test]
    fn fresh_database_opens_at_v4_matching_the_migrated_shape() {
        let (fresh, _fresh_dir) = open();
        assert_eq!(stored_schema_version(&fresh), SCHEMA_VERSION);
        assert_eq!(stored_schema_version(&fresh), 4);

        let migrated_dir = tempfile::tempdir().unwrap();
        let migrated_path = migrated_dir.path().join("history.db");
        {
            let conn = Connection::open(&migrated_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL); \
                 INSERT INTO schema_version (version) VALUES (2);",
            )
            .unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
        }
        let migrated = Store::open(&migrated_path).unwrap();
        assert_eq!(
            history_columns(&fresh),
            history_columns(&migrated),
            "fresh-create and v2->v4 migration must produce the same columns"
        );
    }

    /// Round-trip the v3/v4 columns through SQLite. They are dormant — no
    /// production writer sets them yet — so this is the only guard that the
    /// insert and select column lists stay aligned.
    #[test]
    fn thread_and_ingress_columns_round_trip() {
        let (store, _dir) = open();
        let mut r = rec(b"row with schema v4 columns", Scope::Dm("peer-v4".into()));
        r.thread_root = Some("aa".repeat(32));
        r.thread_parent = Some("bb".repeat(32));
        r.ingress_sender_agent = Some("cc".repeat(32));
        r.logical_request_id = Some([0x31; 16]);
        assert_eq!(store.insert(&r).unwrap(), InsertOutcome::Inserted);

        let stored = store.get_by_msg_id(r.msg_id).unwrap().unwrap().record;
        assert_eq!(stored.thread_root, r.thread_root);
        assert_eq!(stored.thread_parent, r.thread_parent);
        assert_eq!(stored.ingress_sender_agent, r.ingress_sender_agent);
        assert_eq!(stored.logical_request_id, Some([0x31; 16]));
    }

    fn group_record(group_id: &str, body: &str, timestamp: u64) -> (HistoryRecord, [u8; 32]) {
        group_record_with_provenance(group_id, body, timestamp, Provenance::VerifiedEnvelope)
    }

    fn group_record_with_provenance(
        group_id: &str,
        body: &str,
        timestamp: u64,
        provenance: Provenance,
    ) -> (HistoryRecord, [u8; 32]) {
        let message = crate::groups::GroupPublicMessage {
            group_id: group_id.to_string(),
            state_hash_at_send: "state-hash".to_string(),
            revision_at_send: timestamp,
            author_agent_id: "aa".repeat(32),
            author_public_key: "bb".repeat(64),
            author_user_id: None,
            kind: crate::groups::GroupPublicMessageKind::Chat,
            body: body.to_string(),
            timestamp,
            thread_root: None,
            thread_parent: None,
            mentions: Vec::new(),
            delegation_digest: None,
            rider_provenance: None,
            signature: "cc".repeat(64),
        };
        let artifact = serde_json::to_vec(&message).unwrap();
        let canonical = hex::decode(message.msg_id()).unwrap().try_into().unwrap();
        let payload = message.body.as_bytes().to_vec();
        let record = HistoryRecord {
            msg_id: HistoryRecord::compute_msg_id(Some(&artifact), &payload),
            scope: Scope::Group(group_id.to_string()),
            author_agent: Some(message.author_agent_id),
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: timestamp as i64,
            seen_at_ms: timestamp as i64,
            direction: Direction::Inbound,
            content_type: "text/plain".to_string(),
            payload,
            signed_artifact: Some(artifact),
            signature: Some(vec![1]),
            sig_context: Some("x0x.group.public-message.v1".to_string()),
            provenance,
            replace_key: None,
            thread_root: None,
            thread_parent: None,
            ingress_sender_agent: None,
            logical_request_id: None,
        };
        (record, canonical)
    }

    #[test]
    fn canonical_group_index_survives_reopen_and_old_writer_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let (target, canonical) = group_record("canonical-group", "canonical body", 1);
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.insert(&target).unwrap(), InsertOutcome::Inserted);
            let row = store
                .get_by_canonical_group_msg_id(canonical, "canonical-group")
                .unwrap()
                .unwrap();
            assert_eq!(row.record.msg_id, target.msg_id);
            assert_eq!(store.insert(&target).unwrap(), InsertOutcome::Duplicate);
            assert!(store
                .get_by_canonical_group_msg_id(canonical, "another-group")
                .unwrap()
                .is_none());
            let guard = lock_conn(&store.conn).unwrap();
            let count: i64 = guard
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='history_canonical_ids'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1);
            let plan: String = guard
                .query_row(
                    "EXPLAIN QUERY PLAN SELECT h.id FROM history h \
                     JOIN history_canonical_ids c ON c.history_msg_id = h.msg_id \
                     WHERE c.canonical_msg_id = ?1 AND c.scope_kind = 1 AND c.scope_id = ?2",
                    rusqlite::params![&canonical[..], "canonical-group"],
                    |row| row.get(3),
                )
                .unwrap();
            assert!(
                plan.contains("idx_history_canonical"),
                "canonical lookup must use its derived index, got plan: {plan}"
            );
        }

        // A v4 writer knows only the history table. Its insert and delete are
        // valid with the derived table present; reopening then backfills the
        // newly inserted signed group artifact.
        let (legacy, legacy_canonical) = group_record("legacy-group", "legacy group body", 2);
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO history (msg_id, scope_kind, scope_id, sent_at_ms, seen_at_ms, \
             author_agent, direction, content_type, payload, signed_artifact, signature, \
             sig_context, provenance) \
             VALUES (?1, 1, ?2, ?3, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, 0)",
            rusqlite::params![
                &legacy.msg_id[..],
                "legacy-group",
                legacy.sent_at_ms,
                legacy.author_agent,
                legacy.content_type,
                legacy.payload,
                legacy.signed_artifact,
                legacy.signature,
                legacy.sig_context,
            ],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM history WHERE msg_id = ?1",
            rusqlite::params![&target.msg_id[..]],
        )
        .unwrap();
        drop(conn);

        let store = Store::open(&path).unwrap();
        assert!(store
            .get_by_canonical_group_msg_id(canonical, "canonical-group")
            .unwrap()
            .is_none());
        let row = store
            .get_by_canonical_group_msg_id(legacy_canonical, "legacy-group")
            .unwrap()
            .unwrap();
        assert_eq!(row.record.msg_id, legacy.msg_id);
        assert!(store
            .get_by_canonical_group_msg_id([0x55; 32], "legacy-group")
            .unwrap()
            .is_none());
        assert_eq!(stored_schema_version(&store), 4);
    }

    #[test]
    fn canonical_backfill_is_batched_and_skips_invalid_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        // Create the v4 history shape and auxiliary projection first, then
        // write rows using only the v4 columns an older binary knows.
        let store = Store::open(&path).unwrap();
        drop(store);
        let conn = Connection::open(&path).unwrap();
        let mut canonical_ids = Vec::new();
        for n in 0..300_u64 {
            let (record, canonical) =
                group_record("batched-legacy-group", &format!("legacy body {n}"), n + 1);
            let payload = if n == 1 || n == 257 {
                b"payload does not match signed artifact".to_vec()
            } else {
                record.payload.clone()
            };
            conn.execute(
                "INSERT INTO history (msg_id, scope_kind, scope_id, sent_at_ms, seen_at_ms, \
                 author_agent, direction, content_type, payload, signed_artifact, signature, \
                 sig_context, provenance) \
                 VALUES (?1, 1, ?2, ?3, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, 0)",
                rusqlite::params![
                    &record.msg_id[..],
                    "batched-legacy-group",
                    record.sent_at_ms,
                    record.author_agent,
                    record.content_type,
                    payload,
                    record.signed_artifact,
                    record.signature,
                    record.sig_context,
                ],
            )
            .unwrap();
            canonical_ids.push((n, canonical));
        }
        drop(conn);

        let store = Store::open(&path).unwrap();
        // 300 candidates force at least two 256-row keyset batches. The
        // invalid rows must be skipped while their ids still advance the
        // cursor, otherwise startup would loop forever on the first bad row.
        for n in [0_usize, 2, 256, 299] {
            let (_, canonical) = canonical_ids[n];
            assert!(
                store
                    .get_by_canonical_group_msg_id(canonical, "batched-legacy-group")
                    .unwrap()
                    .is_some(),
                "valid row {n} must be backfilled"
            );
        }
        for n in [1_usize, 257] {
            let (_, canonical) = canonical_ids[n];
            assert!(
                store
                    .get_by_canonical_group_msg_id(canonical, "batched-legacy-group")
                    .unwrap()
                    .is_none(),
                "scope/body-mismatched row {n} must not be indexed"
            );
        }
        let guard = lock_conn(&store.conn).unwrap();
        let indexed: i64 = guard
            .query_row("SELECT count(*) FROM history_canonical_ids", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(indexed, 298);
    }

    #[test]
    fn canonical_backfill_resumes_after_second_batch_abort() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let store = Store::open(&path).unwrap();
        drop(store);

        let conn = Connection::open(&path).unwrap();
        let mut abort_msg_hex = None;
        for n in 0..600_u64 {
            let (record, _) =
                group_record("resume-legacy-group", &format!("resume body {n}"), n + 1);
            if n == 257 {
                // Row 258 is in the second 256-row candidate batch. The
                // trigger below must abort that batch after row 257 has been
                // attempted, proving the batch transaction rolls back as a
                // unit while batch one remains committed.
                abort_msg_hex = Some(hex::encode(record.msg_id));
            }
            conn.execute(
                "INSERT INTO history (msg_id, scope_kind, scope_id, sent_at_ms, seen_at_ms, \
                 author_agent, direction, content_type, payload, signed_artifact, signature, \
                 sig_context, provenance) \
                 VALUES (?1, 1, ?2, ?3, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, 0)",
                rusqlite::params![
                    &record.msg_id[..],
                    "resume-legacy-group",
                    record.sent_at_ms,
                    record.author_agent,
                    record.content_type,
                    record.payload,
                    record.signed_artifact,
                    record.signature,
                    record.sig_context,
                ],
            )
            .unwrap();
        }
        let abort_msg_hex = abort_msg_hex.unwrap();
        conn.execute_batch(&format!(
            "CREATE TRIGGER issue321_abort_second_batch BEFORE INSERT ON \
             history_canonical_ids WHEN NEW.history_msg_id = X'{abort_msg_hex}' BEGIN \
             SELECT RAISE(ABORT, 'issue321 injected second-batch failure'); END;"
        ))
        .unwrap();
        drop(conn);

        assert!(
            Store::open(&path).is_err(),
            "the injected second-batch failure must make this open fail"
        );

        let conn = Connection::open(&path).unwrap();
        let indexed: i64 = conn
            .query_row("SELECT count(*) FROM history_canonical_ids", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            indexed, 256,
            "the first committed batch must survive while the failed second batch rolls back"
        );
        let aborted_indexed: i64 = conn
            .query_row(
                "SELECT count(*) FROM history_canonical_ids WHERE history_msg_id = ?1",
                rusqlite::params![hex::decode(&abort_msg_hex).unwrap()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(aborted_indexed, 0);
        let history_rows: i64 = conn
            .query_row("SELECT count(*) FROM history", [], |row| row.get(0))
            .unwrap();
        assert_eq!(history_rows, 600, "backfill must never mutate history rows");
        conn.execute_batch("DROP TRIGGER issue321_abort_second_batch")
            .unwrap();
        drop(conn);

        let store = Store::open(&path).unwrap();
        let indexed: i64 = lock_conn(&store.conn)
            .unwrap()
            .query_row("SELECT count(*) FROM history_canonical_ids", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(indexed, 600, "a later open must resume all missing batches");
        assert_eq!(stored_schema_version(&store), 4);
    }

    /// Issue #1263 part 2: rows `canonical_group_msg_id` rejects (MLS
    /// plaintext group rows with no `signed_artifact`, the shape
    /// `record_mls_history` writes) must be examined exactly once, not
    /// rescanned on every open. The persisted cursor makes the steady-state
    /// open O(new rows).
    #[test]
    fn unprojectable_rows_are_not_rescanned_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        {
            let store = Store::open(&path).unwrap();
            drop(store);
        }
        // Rows written the way an embedding writes MLS history: scope_kind=1,
        // no signed_artifact — never projectable.
        let conn = Connection::open(&path).unwrap();
        for n in 0..600_u64 {
            let record = mls_rec("mls-group", n, format!("mls plaintext {n}").as_bytes());
            conn.execute(
                "INSERT INTO history (msg_id, scope_kind, scope_id, sent_at_ms, seen_at_ms, \
                 direction, content_type, payload, provenance) \
                 VALUES (?1, 1, 'mls-group', ?2, ?2, 0, 'text/plain', ?3, 1)",
                rusqlite::params![&record.msg_id[..], n as i64 + 1, &record.payload],
            )
            .unwrap();
        }
        drop(conn);

        backfill_probe::reset();
        let store = Store::open(&path).unwrap();
        assert_eq!(
            backfill_probe::read(),
            600,
            "the first open examines every row exactly once"
        );
        {
            let guard = lock_conn(&store.conn).unwrap();
            let indexed: i64 = guard
                .query_row("SELECT count(*) FROM history_canonical_ids", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(indexed, 0, "unprojectable rows never enter the projection");
            let scanned: i64 = guard
                .query_row(
                    "SELECT scanned_to_id FROM history_backfill_progress WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let max_id: i64 = guard
                .query_row("SELECT MAX(id) FROM history", [], |row| row.get(0))
                .unwrap();
            assert_eq!(scanned, max_id, "the cursor must complete the pass");
        }
        drop(store);

        // THE regression (#1263 part 2): reopening rescans nothing.
        backfill_probe::reset();
        let store = Store::open(&path).unwrap();
        assert_eq!(
            backfill_probe::read(),
            0,
            "a completed pass must make reopen O(1), not a full rescan"
        );
        drop(store);

        // Only rows above the cursor are examined on later opens.
        let conn = Connection::open(&path).unwrap();
        for n in 0..20_u64 {
            let record = mls_rec(
                "mls-group",
                1_000 + n,
                format!("later plaintext {n}").as_bytes(),
            );
            conn.execute(
                "INSERT INTO history (msg_id, scope_kind, scope_id, sent_at_ms, seen_at_ms, \
                 direction, content_type, payload, provenance) \
                 VALUES (?1, 1, 'mls-group', ?2, ?2, 0, 'text/plain', ?3, 1)",
                rusqlite::params![&record.msg_id[..], 2_000_i64 + n as i64, &record.payload],
            )
            .unwrap();
        }
        drop(conn);
        backfill_probe::reset();
        let _store = Store::open(&path).unwrap();
        assert_eq!(
            backfill_probe::read(),
            20,
            "reopen cost must be O(rows-new), not O(all rows)"
        );
    }

    /// Issue #1263 part 2: the backfill batch scan must run as a rowid range.
    /// Without the `+h.scope_kind` guard the planner picks `idx_scope_time`
    /// and builds a TEMP B-TREE for `ORDER BY h.id` on every 256-row batch —
    /// O(n²/256) on a database with no ANALYZE data.
    #[test]
    fn backfill_scan_is_a_rowid_range_not_a_sort() {
        let (store, _dir) = open();
        let guard = lock_conn(&store.conn).unwrap();
        let plan: String = guard
            .query_row(
                "EXPLAIN QUERY PLAN SELECT h.id FROM history h \
                 WHERE h.id > ?1 AND +h.scope_kind = 1 ORDER BY h.id LIMIT 256",
                rusqlite::params![0_i64],
                |row| row.get(3),
            )
            .unwrap();
        assert!(
            plan.contains("PRIMARY KEY"),
            "the batch scan must use the rowid range, got plan: {plan}"
        );
        assert!(
            !plan.to_uppercase().contains("TEMP B-TREE"),
            "ORDER BY h.id must not sort, got plan: {plan}"
        );
        assert!(
            !plan.contains("idx_scope_time"),
            "the kind filter must not drive the scan through idx_scope_time, got plan: {plan}"
        );
    }

    /// ADR 0085 posture for the persisted backfill cursor: the marker must
    /// not bump the schema version (an older binary keeps opening the
    /// database), rows written behind the cursor's back by a binary that
    /// does not maintain projections are picked up on the next open, and a
    /// missing progress row self-heals by rebuilding the projection.
    #[test]
    fn backfill_progress_is_downgrade_safe_and_rebuildable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let (target, target_canonical) = group_record("compat-group", "compat body", 1);
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.insert(&target).unwrap(), InsertOutcome::Inserted);
        }
        // Completing an open advances the cursor past the inserted row.
        backfill_probe::reset();
        {
            let _store = Store::open(&path).unwrap();
            assert_eq!(
                backfill_probe::read(),
                1,
                "the first completing open examines the row below the cursor"
            );
        }

        // An "older binary" (schema v4 only, no projection at insert, no
        // knowledge of the progress table) writes one more row.
        let (legacy, legacy_canonical) = group_record("compat-group", "legacy compat body", 2);
        {
            let conn = Connection::open(&path).unwrap();
            let version: i64 = conn
                .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                version, 4,
                "the progress marker must not bump the schema version"
            );
            conn.execute(
                "INSERT INTO history (msg_id, scope_kind, scope_id, sent_at_ms, seen_at_ms, \
                 author_agent, direction, content_type, payload, signed_artifact, signature, \
                 sig_context, provenance) \
                 VALUES (?1, 1, ?2, ?3, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, 0)",
                rusqlite::params![
                    &legacy.msg_id[..],
                    "compat-group",
                    legacy.sent_at_ms,
                    legacy.author_agent,
                    legacy.content_type,
                    legacy.payload,
                    legacy.signed_artifact,
                    legacy.signature,
                    legacy.sig_context,
                ],
            )
            .unwrap();
        }
        backfill_probe::reset();
        let store = Store::open(&path).unwrap();
        assert_eq!(
            backfill_probe::read(),
            1,
            "only the row above the cursor is examined"
        );
        assert!(store
            .get_by_canonical_group_msg_id(legacy_canonical, "compat-group")
            .unwrap()
            .is_some());
        assert_eq!(stored_schema_version(&store), 4);
        drop(store);

        // A dropped or corrupt progress table must not brick the store: the
        // next open restarts from the bottom and rebuilds the projection.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("DROP TABLE history_backfill_progress;")
                .unwrap();
        }
        backfill_probe::reset();
        let store = Store::open(&path).unwrap();
        assert_eq!(
            backfill_probe::read(),
            2,
            "a missing marker forces one full pass over the group rows"
        );
        assert!(store
            .get_by_canonical_group_msg_id(target_canonical, "compat-group")
            .unwrap()
            .is_some());
        assert!(store
            .get_by_canonical_group_msg_id(legacy_canonical, "compat-group")
            .unwrap()
            .is_some());
        assert_eq!(stored_schema_version(&store), 4);
    }

    /// Review round 3 (projection loss): a completed cursor must not survive
    /// the loss of the projection it describes. If `history_canonical_ids`
    /// is dropped while `history_backfill_progress` remains, the next open
    /// recreates the projection empty and must rebuild it from the bottom.
    #[test]
    fn lost_projection_table_is_rebuilt_despite_a_completed_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let (record, canonical) = group_record("lost-projection", "kept body", 1);
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.insert(&record).unwrap(), InsertOutcome::Inserted);
        }
        // Complete a pass so the cursor sits at the table maximum.
        drop(Store::open(&path).unwrap());
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("DROP TABLE history_canonical_ids;")
                .unwrap();
            let cursor: i64 = conn
                .query_row(
                    "SELECT scanned_to_id FROM history_backfill_progress WHERE singleton = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(cursor >= 1, "the cursor survives the projection loss");
        }
        backfill_probe::reset();
        let store = Store::open(&path).unwrap();
        assert_eq!(
            backfill_probe::read(),
            1,
            "the recreated projection is rebuilt from the bottom"
        );
        assert!(store
            .get_by_canonical_group_msg_id(canonical, "lost-projection")
            .unwrap()
            .is_some());
    }

    /// Review round 2 (cursor bypass): `history.id` is `INTEGER PRIMARY KEY`
    /// without `AUTOINCREMENT`, so an "older binary" that purges the rows
    /// holding the top ids and then inserts projectable group rows makes
    /// SQLite reuse ids AT OR BELOW the completed watermark — where the
    /// backfill fast path never looks. The `history_backfill_lower` trigger
    /// lives in the database file, so the old writer fires it without
    /// knowing it exists: the watermark drops inside the insert, and the
    /// next open rescans (and projects) the reused-id row.
    #[test]
    fn backfill_projects_rows_written_at_reused_ids_below_the_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        // Six projectable group rows (ids 1..=6).
        {
            let store = Store::open(&path).unwrap();
            for n in 0..6_u64 {
                let (record, _) = group_record("reuse-group", &format!("original {n}"), 100 + n);
                assert_eq!(store.insert(&record).unwrap(), InsertOutcome::Inserted);
            }
        }
        // Complete a pass so the watermark sits at the table maximum (6).
        backfill_probe::reset();
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(
                backfill_probe::read(),
                6,
                "the completing pass scans all rows"
            );
            let guard = lock_conn(&store.conn).unwrap();
            let watermark: i64 = guard
                .query_row(
                    "SELECT scanned_to_id FROM history_backfill_progress WHERE singleton = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(watermark, 6);
        }

        // The "old binary": a raw v4-only connection that knows nothing
        // about the cursor or the projection. It purges the newest rows —
        // dropping MAX(id) to 3 — and inserts one projectable group row,
        // which SQLite allocates at the REUSED id 4, below the watermark.
        let (legacy, legacy_canonical) = group_record("reuse-group", "reused-id body", 200);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("DELETE FROM history WHERE id >= 4", [])
                .unwrap();
            conn.execute(
                "INSERT INTO history (msg_id, scope_kind, scope_id, sent_at_ms, seen_at_ms, \
                 author_agent, direction, content_type, payload, signed_artifact, signature, \
                 sig_context, provenance) \
                 VALUES (?1, 1, ?2, ?3, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?9, 0)",
                rusqlite::params![
                    &legacy.msg_id[..],
                    "reuse-group",
                    legacy.sent_at_ms,
                    legacy.author_agent,
                    legacy.content_type,
                    legacy.payload,
                    legacy.signed_artifact,
                    legacy.signature,
                    legacy.sig_context,
                ],
            )
            .unwrap();
            let reused_id: i64 = conn
                .query_row(
                    "SELECT id FROM history WHERE msg_id = ?1",
                    rusqlite::params![&legacy.msg_id[..]],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(reused_id, 4, "the fixture must exercise rowid reuse");
            // The trigger fired inside the old binary's transaction.
            let watermark: i64 = conn
                .query_row(
                    "SELECT scanned_to_id FROM history_backfill_progress WHERE singleton = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(watermark, 3, "the trigger must lower the watermark");
        }

        // Re-upgrade: the next open rescans from the lowered watermark and
        // projects the reused-id row, so the canonical lookup finds it.
        backfill_probe::reset();
        let store = Store::open(&path).unwrap();
        assert_eq!(
            backfill_probe::read(),
            1,
            "only the reused-id row is above the lowered watermark"
        );
        assert!(
            store
                .get_by_canonical_group_msg_id(legacy_canonical, "reuse-group")
                .unwrap()
                .is_some(),
            "the reused-id row must be projected on the next open"
        );
    }

    #[test]
    fn canonical_index_preserves_local_and_verified_provenance() {
        let (store, _dir) = open();
        for (n, provenance) in [
            (1_u64, Provenance::LocalSend),
            (2_u64, Provenance::VerifiedEnvelope),
        ] {
            let (record, canonical) = group_record_with_provenance(
                "provenance-group",
                &format!("provenance body {n}"),
                n,
                provenance,
            );
            assert_eq!(store.insert(&record).unwrap(), InsertOutcome::Inserted);
            let stored = store
                .get_by_canonical_group_msg_id(canonical, "provenance-group")
                .unwrap()
                .unwrap();
            assert_eq!(stored.record.msg_id, record.msg_id);
            assert_eq!(stored.record.provenance, provenance);
        }
    }

    #[test]
    fn canonical_group_lookup_is_not_limited_by_history_scan_budget() {
        let (store, _dir) = open();
        let (target, canonical) = group_record("large-group", "old canonical body", 1);
        assert_eq!(store.insert(&target).unwrap(), InsertOutcome::Inserted);
        let newer: Vec<HistoryRecord> = (0..4_100)
            .map(|n| {
                rec(
                    format!("newer row {n}").as_bytes(),
                    Scope::Group("large-group".to_string()),
                )
            })
            .collect();
        assert_eq!(store.insert_batch(&newer).unwrap().0, newer.len() as u64);
        let row = store
            .get_by_canonical_group_msg_id(canonical, "large-group")
            .unwrap()
            .unwrap();
        assert_eq!(row.record.payload, target.payload);
    }

    #[test]
    fn invalid_group_artifact_is_not_added_to_canonical_index() {
        let (store, _dir) = open();
        let (mut record, canonical) = group_record("invalid-group", "signed body", 1);
        record.payload = b"different body".to_vec();
        assert_eq!(store.insert(&record).unwrap(), InsertOutcome::Inserted);
        assert!(store
            .get_by_canonical_group_msg_id(canonical, "invalid-group")
            .unwrap()
            .is_none());
    }

    fn rec(payload: &[u8], scope: Scope) -> HistoryRecord {
        let msg_id = HistoryRecord::compute_msg_id(None, payload);
        HistoryRecord {
            msg_id,
            scope,
            author_agent: Some("aa".into()),
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: 1_000,
            seen_at_ms: 1_000,
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
        }
    }

    fn mls_rec(stable_id: &str, epoch: u64, payload: &[u8]) -> HistoryRecord {
        HistoryRecord {
            msg_id: HistoryRecord::compute_epoch_msg_id(stable_id, epoch, payload),
            scope: Scope::Group(stable_id.into()),
            author_agent: None,
            author_machine: None,
            author_pubkey: None,
            sent_at_ms: 1_000,
            seen_at_ms: 1_000,
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
        }
    }

    /// #276: identical plaintext + coinciding MLS epochs in two groups
    /// must not collide on the global UNIQUE(msg_id).
    #[test]
    fn epoch_msg_id_two_groups_same_payload_and_epoch_both_insert() {
        let (store, _dir) = open();
        let a = mls_rec("group-a", 3, b"identical-plaintext");
        let b = mls_rec("group-b", 3, b"identical-plaintext");
        assert_ne!(
            a.msg_id, b.msg_id,
            "v2 helper must mix stable_id so two groups cannot share an id"
        );
        assert_eq!(store.insert(&a).unwrap(), InsertOutcome::Inserted);
        assert_eq!(store.insert(&b).unwrap(), InsertOutcome::Inserted);
        assert_eq!(store.query(&HistoryQuery::default()).unwrap().len(), 2);
    }

    /// Same group+epoch+payload is a replay and must keep UNIQUE(msg_id).
    #[test]
    fn epoch_msg_id_same_triple_is_duplicate() {
        let (store, _dir) = open();
        let first = mls_rec("group-a", 3, b"plaintext");
        let again = mls_rec("group-a", 3, b"plaintext");
        assert_eq!(first.msg_id, again.msg_id);
        assert_eq!(store.insert(&first).unwrap(), InsertOutcome::Inserted);
        assert_eq!(store.insert(&again).unwrap(), InsertOutcome::Duplicate);
        assert_eq!(store.query(&HistoryQuery::default()).unwrap().len(), 1);
    }

    /// I4: unsigned LocalAppDecrypt carries a v2 id that is not
    /// BLAKE3(payload) and cannot be recomputed (epoch is not stored).
    /// validate() must treat it as opaque, same as unsigned LocalSend.
    #[test]
    fn unsigned_local_app_decrypt_with_v2_id_validates_and_inserts() {
        let (store, _dir) = open();
        let r = mls_rec("group-a", 9, b"mls-plaintext");
        assert_ne!(
            r.msg_id,
            HistoryRecord::compute_msg_id(None, &r.payload),
            "v2 id must not collapse to BLAKE3(payload)"
        );
        r.validate()
            .expect("unsigned LocalAppDecrypt with v2 id must be opaque to validate");
        assert_eq!(store.insert(&r).unwrap(), InsertOutcome::Inserted);
    }

    /// A signed artifact whose msg_id does not match the artifact is still
    /// rejected — I4 only skips the check when there is no artifact.
    #[test]
    fn artifact_msg_id_mismatch_is_still_rejected() {
        let (store, _dir) = open();
        let mut r = rec(b"payload", Scope::Group("g".into()));
        r.signed_artifact = Some(b"signed-bytes".to_vec());
        r.provenance = Provenance::VerifiedEnvelope;
        r.msg_id = HistoryRecord::compute_epoch_msg_id("g", 1, b"payload");
        let err = r
            .validate()
            .expect_err("mismatched artifact id must fail validate");
        assert!(
            err.to_string().contains("msg_id does not match"),
            "validate must name the artifact mismatch; got: {err}"
        );
        let insert_err = store
            .insert(&r)
            .expect_err("insert must refuse artifact mismatch");
        assert!(
            insert_err.to_string().contains("msg_id does not match"),
            "insert must surface the same mismatch; got: {insert_err}"
        );
    }

    /// ADR-0023 §3: rows re-verify offline from signed_artifact +
    /// author_pubkey. Store a real ML-DSA-65-signed artifact, reload it
    /// from SQLite, and re-run verification over the stored bytes.
    #[test]
    fn offline_reverify_roundtrip_ml_dsa() {
        let (store, _dir) = open();
        let keypair = crate::identity::MachineKeypair::generate().unwrap();
        let artifact = b"signed wire bytes: envelope v1".to_vec();
        let sig = sign_with_ml_dsa(keypair.secret_key(), &artifact).unwrap();

        let mut r = rec(b"decrypted payload", Scope::Dm("peer1".into()));
        r.signed_artifact = Some(artifact.clone());
        r.signature = Some(sig.as_bytes().to_vec());
        r.author_pubkey = Some(keypair.public_key().as_bytes().to_vec());
        r.provenance = Provenance::VerifiedEnvelope;
        r.msg_id = HistoryRecord::compute_msg_id(Some(&artifact), &r.payload);
        assert_eq!(store.insert(&r).unwrap(), InsertOutcome::Inserted);

        let rows = store
            .query(&HistoryQuery {
                scope: Some(Scope::Dm("peer1".into())),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(rows.len(), 1);
        let stored = &rows[0].record;
        let pk = ant_quic::MlDsaPublicKey::from_bytes(stored.author_pubkey.as_ref().unwrap())
            .expect("stored pubkey parses");
        let sig = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
            stored.signature.as_ref().unwrap(),
        )
        .expect("stored signature parses");
        verify_with_ml_dsa(&pk, stored.signed_artifact.as_ref().unwrap(), &sig)
            .expect("stored artifact must re-verify offline");
    }

    /// Replaceable slots keep the latest sent_at_ms; equal timestamps keep
    /// the LOWEST msg_id (donor tie-break).
    #[test]
    fn replaceable_upsert_and_lowest_id_tiebreak() {
        let (store, _dir) = open();
        let mut a = rec(b"card v1", Scope::Topic("cards".into()));
        a.replace_key = Some("agent-card:x".into());
        assert_eq!(store.insert(&a).unwrap(), InsertOutcome::Inserted);

        // Newer wins.
        let mut b = rec(b"card v2", Scope::Topic("cards".into()));
        b.replace_key = Some("agent-card:x".into());
        b.sent_at_ms = 2_000;
        assert_eq!(store.insert(&b).unwrap(), InsertOutcome::Replaced);

        // Equal timestamp: winner is the lower msg_id.
        let mut c = rec(b"card v3", Scope::Topic("cards".into()));
        c.replace_key = Some("agent-card:x".into());
        c.sent_at_ms = 2_000;
        let expected = if c.msg_id < b.msg_id {
            InsertOutcome::Replaced
        } else {
            InsertOutcome::StaleRejected
        };
        assert_eq!(store.insert(&c).unwrap(), expected);

        let rows = store.query(&HistoryQuery::default()).unwrap();
        assert_eq!(rows.len(), 1, "one row per replaceable slot");
    }
    /// Item (b): a failed open must name the *resolved* db path (the path the
    /// daemon actually attempted), not just the raw io message. A db path whose
    /// parent is an existing file makes `create_dir_all` fail; the error must
    /// contain the resolved path so an operator with a derived `<data_dir>`
    /// sees which path was tried.
    #[test]
    fn open_error_names_the_resolved_db_path() {
        // `file` is a regular file; its path used as a parent dir is invalid,
        // so `create_dir_all` fails at open.
        let file = tempfile::NamedTempFile::new().unwrap();
        let bad_path = file.path().join("history.db");
        let err = Store::open(&bad_path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&bad_path.display().to_string()),
            "history init error must name the resolved db path; got: {msg}"
        );
    }

    /// Item (b) leftover (#281): pragma setup used to say only
    /// `pragma setup failed: …`, which sent operators down a lock-contention
    /// path when the real cause was the resolved db path. A non-SQLite file
    /// at that path fails at the first PRAGMA (SQLite opens lazily), so the
    /// error must name the path actually attempted — same wording style as
    /// `open history db {path}: …`.
    #[test]
    fn pragma_setup_error_names_the_resolved_db_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        std::fs::write(&path, b"not a sqlite database").unwrap();
        let err = Store::open(&path).unwrap_err();
        let msg = err.to_string();
        let resolved = path.display().to_string();
        assert!(
            msg.contains(&resolved),
            "pragma setup error must name the resolved db path; got: {msg}"
        );
        assert!(
            msg.contains("pragma setup"),
            "must be the pragma-setup path, not open/lock/create; got: {msg}"
        );
    }

    /// Issue #1264 part 1: the whole-database budget must converge on LIVE
    /// bytes (page_count − freelist) with FTS tombstones reclaimed, instead
    /// of over-deleting against a file size that deletes never shrink. The
    /// oldest rows deleted must cover the excess — and not much more — the
    /// file must physically shrink, and a converged store must stop losing
    /// rows on later passes.
    #[test]
    fn whole_db_budget_converges_without_over_deleting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let store = Store::open(&path).unwrap();

        // Durable text rows with many distinct words, so the FTS index (and
        // its tombstones) are a real share of the on-disk bytes.
        const ROWS: usize = 400;
        const WORDS: [&str; 16] = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
            "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
        ];
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(ROWS);
        for i in 0..ROWS {
            let mut body = String::new();
            while body.len() < 2048 {
                for word in WORDS {
                    body.push_str(word);
                    body.push(' ');
                }
                body.push_str(&format!("row{i:04} "));
            }
            payloads.push(body.into_bytes());
        }
        for (i, payload) in payloads.iter().enumerate() {
            let mut r = rec(payload, Scope::Group("reap".into()));
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            assert_eq!(store.insert(&r).unwrap(), InsertOutcome::Inserted);
        }

        let file_bytes = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let live = |store: &Store| -> u64 {
            let guard = lock_conn(&store.conn).unwrap();
            live_db_bytes(&guard).unwrap() as u64
        };
        {
            // Normalize the WAL before measuring the starting point.
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }
        let live_before = live(&store);
        let file_before = file_bytes(&path);
        // A cap the payloads can reach: the FTS postings of these wordy rows
        // are ~2.5× the payload bytes, so 3/4 of the live size leaves an
        // excess coverable by the oldest quarter of the rows (the earlier
        // half-of-live cap sat below the total payload bytes and could only
        // ever be met by deleting every durable row).
        let cap = live_before * 3 / 4;

        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };
        let evicted = store.retain(&policy).unwrap();
        assert!(evicted > 0, "cap is below the live size; rows must go");

        let live_after = live(&store);
        assert!(
            live_after <= cap,
            "one pass must reach the cap: live={live_after}, cap={cap}"
        );
        let file_after = file_bytes(&path);
        assert!(
            file_after < file_before,
            "the file must shrink after merge slices + incremental_vacuum + checkpoint: \
             before={file_before}, after={file_after}"
        );

        let rows_after: usize = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row("SELECT COUNT(*) FROM history", [], |r| r.get::<_, i64>(0))
                .unwrap() as usize
        };
        assert!(
            rows_after > 0,
            "the pass must not destroy everything (#1264 over-delete)"
        );
        // Deleted footprint stays close to the minimum: each row's window
        // measure is payload + FTS projection (~4 KiB for these 2 KiB text
        // rows), so the minimum is excess/4096 plus a little
        // page-granularity slack. The pre-fix behaviour deleted every
        // durable row and still missed the cap.
        let deleted_rows = ROWS - rows_after;
        let min_rows = ((live_before - cap) / 4096) as usize;
        assert!(
            deleted_rows <= min_rows + 2,
            "over-delete guard: deleted {deleted_rows} rows, minimum ~{min_rows} \
             (live_before={live_before}, cap={cap})"
        );
        // The oldest rows went first: every survivor is newer than the
        // deleted prefix.
        let remaining_seen: Vec<i64> = store
            .query(&HistoryQuery {
                limit: MAX_QUERY_LIMIT,
                ..HistoryQuery::default()
            })
            .unwrap()
            .iter()
            .map(|r| r.record.seen_at_ms)
            .collect();
        assert!(
            remaining_seen.iter().min().copied().unwrap_or(0) >= 1_000 + deleted_rows as i64 - 1,
            "eviction must be oldest-first"
        );
        // FTS survives the merges: a surviving row is still searchable.
        assert!(
            !store
                .search("alpha bravo", &HistoryQuery::default())
                .unwrap()
                .is_empty(),
            "search must still find surviving rows after the pass"
        );

        // A converged store must not keep shedding rows every pass — the
        // pre-fix loop never reached the cap and deleted on every pass.
        let evicted_again = store.retain(&policy).unwrap();
        assert_eq!(
            evicted_again, 0,
            "a second pass over a converged store must evict nothing"
        );
    }
    /// Review round 2, finding 4: a store barely over the cap whose OLDEST
    /// eligible row estimates larger than the whole excess must still lose
    /// that row — it is the row that crosses the target. The pre-fix window
    /// (`running <= excess`) selected nothing, the helper returned 0, and
    /// retention stopped ABOVE the cap with eligible rows remaining.
    #[test]
    fn whole_db_budget_takes_the_crossing_row_when_over_cap() {
        let (store, _dir) = open();
        // One big old text row (estimate ≫ one page), then small newer rows.
        let mut big = rec(&vec![b'x'; 64_000], Scope::Group("cross".into()));
        big.seen_at_ms = 1;
        big.sent_at_ms = 1;
        assert_eq!(store.insert(&big).unwrap(), InsertOutcome::Inserted);
        for i in 0..40_u64 {
            let mut r = rec(
                format!("small {i}").as_bytes(),
                Scope::Group("cross".into()),
            );
            r.seen_at_ms = 2_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        // Settle any insert-time FTS merge work so the fixture starts with
        // no pending reclamation (otherwise merging alone could reach the
        // cap and the delete path would never run). A pass with a cap it
        // already meets still maintains to the settled certificate; passes
        // repeat until the live measure stops moving.
        settle(&store);
        let live = store.live_bytes().unwrap();
        // One byte of excess: far below the big row's estimate, so only the
        // crossing-row rule can evict anything.
        let cap = live - 1;
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };
        let evicted = store.retain(&policy).unwrap();
        assert_eq!(
            evicted, 1,
            "the crossing row alone must bring the store under the cap"
        );
        assert!(
            store.live_bytes().unwrap() <= cap,
            "the pass must converge, not stop above the cap"
        );
        let rows: usize = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row("SELECT COUNT(*) FROM history", [], |r| r.get::<_, i64>(0))
                .unwrap() as usize
        };
        assert_eq!(rows, 40, "only the big row went; the newer rows remain");
        assert_eq!(
            store.retain(&policy).unwrap(),
            0,
            "converged: next pass idle"
        );
    }

    /// Review round 2, finding 5 (short binary rows): a row's live cost —
    /// row storage, the 32-byte `msg_id`, its FTS doc entry and B-tree
    /// overhead — is a large multiple of a short binary payload, so the
    /// per-row estimate under-counts badly. The pre-fix helper kept
    /// deleting against the original byte deficit until the estimates
    /// covered it — on such rows, until EVERY eligible row was gone. The
    /// reaper must delete one bounded batch, remeasure live pages, and stop
    /// as soon as the cap is met.
    #[test]
    fn whole_db_budget_converges_on_short_binary_rows_without_over_deleting() {
        let (store, _dir) = open();
        const ROWS: usize = 2000;
        let live_empty = store.live_bytes().unwrap();
        for i in 0..ROWS {
            let mut r = rec(format!("b{i:04}").as_bytes(), Scope::Group("tiny".into()));
            // NOT text/*: no payload_text, so the FTS projection holds an
            // empty doc while the row itself still costs real pages.
            r.content_type = "application/octet-stream".into();
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        let live_before = store.live_bytes().unwrap();
        // Average live cost of one short binary row, measured on this very
        // database — the yardstick for "close to the minimum". It is a
        // large multiple of the ~6-byte payload: row storage, the 32-byte
        // msg_id, index entries and the FTS doc entry.
        let per_row = (live_before - live_empty) / ROWS as u64;
        assert!(
            per_row > 64,
            "fixture must be metadata-dominated, got {per_row} B/row"
        );
        let cap = live_before * 3 / 4;
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };
        let evicted = store.retain(&policy).unwrap();
        assert!(evicted > 0, "the store starts above the cap");
        let live_after = store.live_bytes().unwrap();
        assert!(
            live_after <= cap,
            "must converge to the cap, not stop above it: live={live_after} cap={cap}"
        );
        // Near-minimum deletion in row counts: the loop remeasures after
        // every bounded batch, so the deleted set may exceed the true
        // minimum by at most one RETAIN_EVICT_BATCH plus page-granularity
        // slack. The pre-fix behaviour deleted EVERY eligible row (the
        // payload estimate could never cover the excess).
        let min_rows = (live_before - cap) / per_row;
        assert!(
            evicted <= min_rows + RETAIN_EVICT_BATCH as u64 + 8,
            "over-delete: {evicted} rows deleted, minimum ≈ {min_rows} \
             (per_row={per_row} B, excess {} B)",
            live_before - cap
        );
        let rows_after: usize = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row("SELECT COUNT(*) FROM history", [], |r| r.get::<_, i64>(0))
                .unwrap() as usize
        };
        assert_eq!(
            rows_after as u64,
            ROWS as u64 - evicted,
            "durable rows only"
        );
        assert!(rows_after > 0, "must not destroy everything");
        assert_eq!(
            store.retain(&policy).unwrap(),
            0,
            "converged: next pass idle"
        );
    }

    /// Review round 2, finding 5 (metadata-heavy signed rows): the estimate
    /// counts `signed_artifact` but not the signature, the public key or
    /// the author ids, so a signed row occupies ~3× its estimate. Same
    /// contract as the binary-row test: converge, delete near the minimum,
    /// stay converged.
    #[test]
    fn whole_db_budget_converges_on_metadata_heavy_rows_without_over_deleting() {
        let (store, _dir) = open();
        const ROWS: usize = 600;
        let live_empty = store.live_bytes().unwrap();
        for i in 0..ROWS {
            let payload = format!("meta {i:04}").into_bytes();
            let mut r = rec(&payload, Scope::Group("meta".into()));
            // Unique per row: msg_id is BLAKE3(artifact), so a shared
            // artifact would collapse the fixture to one row.
            let mut artifact = vec![7_u8; 2048];
            artifact[..8].copy_from_slice(&(i as u64).to_le_bytes());
            r.signed_artifact = Some(artifact);
            r.signature = Some(vec![8_u8; 3072]);
            r.author_pubkey = Some(vec![9_u8; 1536]);
            // validate() keys msg_id on the artifact once present.
            r.msg_id = HistoryRecord::compute_msg_id(r.signed_artifact.as_deref(), &payload);
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        let live_before = store.live_bytes().unwrap();
        let per_row = (live_before - live_empty) / ROWS as u64;
        // The estimate (payload + artifact + payload_text ≈ 2 KiB) must
        // under-count the real per-row cost for this fixture to bite.
        assert!(
            per_row > 3 * 2048,
            "fixture must be metadata-dominated, got {per_row} B/row"
        );
        let cap = live_before * 3 / 4;
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };
        let evicted = store.retain(&policy).unwrap();
        assert!(evicted > 0, "the store starts above the cap");
        let live_after = store.live_bytes().unwrap();
        assert!(
            live_after <= cap,
            "must converge to the cap: live={live_after} cap={cap}"
        );
        // Near-minimum in row counts (one remeasured batch of slack); the
        // pre-fix helper kept deleting until the ~2 KiB estimates covered
        // the excess — ~3× the necessary rows here.
        let min_rows = (live_before - cap) / per_row;
        assert!(
            evicted <= min_rows + RETAIN_EVICT_BATCH as u64 + 8,
            "over-delete: {evicted} rows deleted, minimum ≈ {min_rows} \
             (per_row={per_row} B, excess {} B)",
            live_before - cap
        );
        // Oldest-first: survivors are the newest rows.
        let oldest_survivor: i64 = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row("SELECT MIN(seen_at_ms) FROM history", [], |r| r.get(0))
                .unwrap()
        };
        assert!(
            oldest_survivor >= 1_000 + evicted as i64 - 1,
            "eviction must be oldest-first"
        );
        assert_eq!(
            store.retain(&policy).unwrap(),
            0,
            "converged: next pass idle"
        );
    }

    /// Review round 2 (R2-C): an overshoot held by FTS tombstones, not by
    /// live data, must be met by RECLAMATION alone — the reaper may not
    /// delete history while merging is still folding the tombstones, and a
    /// round that does not visibly move the live measure is NOT permission
    /// to delete. The cap here is reachable with zero deletion.
    #[test]
    fn whole_db_budget_meets_a_tombstone_overshoot_without_evicting() {
        let (store, _dir) = open();
        const ROWS: usize = 800;
        const WORDS: [&str; 16] = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
            "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
        ];
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(ROWS);
        for i in 0..ROWS {
            let mut body = String::new();
            while body.len() < 2048 {
                for word in WORDS {
                    body.push_str(word);
                    body.push(' ');
                }
                body.push_str(&format!("row{i:04} "));
            }
            payloads.push(body.into_bytes());
        }
        for (i, payload) in payloads.iter().enumerate() {
            let mut r = rec(payload, Scope::Group("tomb".into()));
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            assert_eq!(store.insert(&r).unwrap(), InsertOutcome::Inserted);
        }
        // Settle insert-time merge work, then delete half the rows RAW.
        // The deletes free their table pages, but the FTS index still
        // holds every deleted row's postings PLUS new tombstone postings —
        // index bytes only a merge can reclaim.
        settle(&store);
        {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .execute("DELETE FROM history WHERE id % 2 = 1", [])
                .unwrap();
        }
        // A cap between the post-delete live measure and the folded floor:
        // the deleted half's postings (plus the tombstones) are well over
        // a quarter of the index bytes, so folding alone reaches a cap set
        // one quarter of the index bytes below the post-delete measure.
        let live_after_deletes = store.live_bytes().unwrap();
        let fts_bytes: i64 = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row(
                    "SELECT COALESCE(SUM(LENGTH(block)), 0) FROM history_fts_data",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert!(fts_bytes > 0, "fixture must have a real FTS index");
        let cap = live_after_deletes - (fts_bytes as u64) / 4;
        assert!(
            store.live_bytes().unwrap() > cap,
            "the fixture must start over the cap with reclaimable index bytes"
        );
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };
        let evicted = store.retain(&policy).unwrap();
        assert_eq!(
            evicted, 0,
            "a tombstone overshoot must be met by reclamation, not deletion"
        );
        assert!(
            store.live_bytes().unwrap() <= cap,
            "folding the tombstones must reach the cap"
        );
    }

    /// Review rounds 2–4 (R2-B/R3-B): writer commits BETWEEN passes add
    /// new level-0 FTS segments, which an optimize-shaped (`-N`) merge
    /// start would re-flatten — restarting on the already-written lexical
    /// prefix and, under steady inserts, starving the tombstoned tail.
    /// Passes drive merging with positive-rank slices instead, and the
    /// negative rank runs only as the settle probe. At fixture scale the
    /// observable contract: interleaving writer commits with whole passes
    /// does not wedge the machinery — once the writer quiesces, the
    /// tombstones still fold and the index reaches the settled state.
    #[test]
    fn merges_keep_progressing_across_writer_commits() {
        let (store, _dir) = open();
        const ROWS: usize = 200;
        const WORDS: [&str; 8] = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
        ];
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(ROWS);
        for i in 0..ROWS {
            let mut body = String::new();
            while body.len() < 1024 {
                for word in WORDS {
                    body.push_str(word);
                    body.push(' ');
                }
                body.push_str(&format!("row{i:04} "));
            }
            payloads.push(body.into_bytes());
        }
        for (i, payload) in payloads.iter().enumerate() {
            let mut r = rec(payload, Scope::Group("il".into()));
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        // Tombstones: delete the oldest half raw.
        {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .execute(
                    "DELETE FROM history WHERE id IN \
                     (SELECT id FROM history ORDER BY seen_at_ms ASC LIMIT 100)",
                    [],
                )
                .unwrap();
        }
        let live_after_deletes = store.live_bytes().unwrap();

        // Several rounds of writer-commit-then-pass: each commit lands
        // between passes (a pass holds the connection for its whole
        // duration, so a writer can only ever land there) and adds an FTS
        // segment ahead of the next pass's maintenance.
        for round in 0..8_u64 {
            let mut r = rec(
                format!("interleave {round}").as_bytes(),
                Scope::Group("il".into()),
            );
            r.seen_at_ms = 100_000 + round as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
            settle(&store);
        }

        // Writer quiesced: the merge machinery must converge to the settled
        // state despite the interleaved commits (bounded: settle() caps at
        // 64 passes and stability — a wedged merger never stabilizes the
        // live measure — fails the guard below).
        settle(&store);
        assert!(
            store.live_bytes().unwrap() < live_after_deletes,
            "the tombstones must have been folded away after settling"
        );
    }

    /// C-1264-1 §1 (round 4): a pass whose work fits the wall-clock budget
    /// converges on its own — maintenance settles the index, the settled
    /// measure is final, and the eviction batches reach the cap — all
    /// inside the single held connection, with the consecutive-unsettled
    /// counter reset.
    #[test]
    fn pass_under_budget_converges_in_one_pass() {
        let (store, _dir) = open();
        const ROWS: usize = 300;
        const WORDS: [&str; 16] = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
            "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
        ];
        for i in 0..ROWS {
            let mut body = String::new();
            while body.len() < 1024 {
                for word in WORDS {
                    body.push_str(word);
                    body.push(' ');
                }
                body.push_str(&format!("row{i:04} "));
            }
            let mut r = rec(body.as_bytes(), Scope::Group("budget".into()));
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        let live_before = store.live_bytes().unwrap();
        let cap = live_before * 3 / 4;
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };
        let started = std::time::Instant::now();
        let evicted = store.retain(&policy).unwrap();
        let elapsed = started.elapsed();
        assert!(evicted > 0, "the store starts above the cap");
        assert!(
            store.live_bytes().unwrap() <= cap,
            "one in-budget pass must reach the cap: live={} cap={}",
            store.live_bytes().unwrap(),
            cap
        );
        assert!(
            elapsed < RETENTION_PASS_BUDGET,
            "the fixture must fit the pass budget (took {elapsed:?})"
        );
        assert_eq!(
            store.unsettled_passes_for_tests(),
            0,
            "a settled pass resets the consecutive-unsettled counter"
        );
        assert_eq!(
            store.retain(&policy).unwrap(),
            0,
            "converged: next pass idle"
        );
    }

    /// C-1264-1 §3 (R3-C): an over-cap store whose index never settles
    /// within one pass must still meet its cap. The first three passes
    /// record consecutive-unsettled counts and delete NOTHING (pending
    /// maintenance is not permission to destroy history); the fourth
    /// evicts by estimate; once maintenance can settle again the exact
    /// window finishes the job.
    ///
    /// Round 5 (R4-D): the over-deletion bound must be ABLE TO FAIL.
    /// The fixture mixes 1,600 evictable rows of two different binary
    /// sizes with 2,400 tiny REPLACEABLE rows (current state: no
    /// retention phase may delete them) that drag the live/rows average
    /// far below the real per-row cost of the rows the escape hatch
    /// deletes — the documented estimate error, made large on purpose.
    /// Binary payloads (no `payload_text`) keep FTS tombstone lag out of
    /// the convergence math, so the measured behavior is deterministic.
    #[test]
    fn over_cap_store_that_never_settles_evicts_after_three_passes() {
        let (store, _dir) = open();
        const REPLACEABLE: usize = 2400;
        const DURABLE: usize = 1600;
        for i in 0..REPLACEABLE {
            let mut r = rec(format!("s{i:05}").as_bytes(), Scope::Group("state".into()));
            r.content_type = "application/octet-stream".into();
            r.replace_key = Some(format!("slot-{i:05}"));
            r.seen_at_ms = 100 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        let live_replaceable = store.live_bytes().unwrap();
        for i in 0..DURABLE {
            // Mixed sizes: alternating ~0.5 KiB and ~4 KiB payloads,
            // unique via a little-endian counter prefix (msg_id is a
            // hash of the payload; a shared filler would collapse rows).
            let size = if i % 2 == 0 { 512 } else { 4096 };
            let mut payload = vec![0_u8; size];
            payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut r = rec(&payload, Scope::Group("history".into()));
            r.content_type = "application/octet-stream".into();
            r.seen_at_ms = 10_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        let live_before = store.live_bytes().unwrap();
        let rows_total: u64 = REPLACEABLE as u64 + DURABLE as u64;
        // The estimate basis the escape hatch itself uses, and the true
        // per-row cost of what it deletes — both measured on this
        // database.
        let avg_store = live_before / rows_total;
        let per_row_durable = (live_before - live_replaceable) / DURABLE as u64;
        assert!(
            per_row_durable > avg_store,
            "fixture must skew the average: durable {per_row_durable} B/row vs \
             store average {avg_store} B/row"
        );
        let cap = live_before * 3 / 4;
        let excess = live_before - cap;
        // The escape hatch's own quota: ceil(excess / avg) + 1 (the +1 is
        // the crossing row).
        let quota = excess / avg_store + 1;
        // VACUITY GUARD (R4-D): the tolerance must sit well below the
        // eligible row count, so deleting everything eligible (or an
        // estimate-ignoring whole extra batch past the quota) FAILS the
        // bound below instead of being accepted by it.
        assert!(
            quota + RETAIN_EVICT_BATCH as u64 + 16 < DURABLE as u64,
            "fixture must make the over-deletion bound able to fail \
             (quota {quota} + tolerance vs {DURABLE} eligible rows)"
        );
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };

        // Simulate "the budget ran out before the index settled" on every
        // pass: the hook makes maintenance report unsettled without
        // running, exactly what a store too fragmented to settle within
        // RETENTION_PASS_BUDGET looks like to phase 4.
        store.force_unsettled_passes_for_tests();
        for pass in 1..=3_u32 {
            assert_eq!(
                store.retain(&policy).unwrap(),
                0,
                "unsettled pass {pass} must not delete: pending maintenance is \
                 not permission to destroy history"
            );
            assert_eq!(
                store.unsettled_passes_for_tests(),
                pass,
                "each unsettled over-cap pass counts once"
            );
        }
        assert!(
            store.live_bytes().unwrap() > cap,
            "three unsettled passes left the store over the cap"
        );

        // Fourth pass: the escape hatch fires before maintenance, with the
        // pass's whole budget ahead of it.
        let forced = store.retain(&policy).unwrap();
        assert!(
            forced > 0,
            "after three consecutive unsettled passes the store must evict anyway"
        );

        // Maintenance can settle again: a settled pass returns to the exact
        // window and finishes precisely.
        store.allow_settling_for_tests();
        for _ in 0..3 {
            if store.live_bytes().unwrap() <= cap {
                break;
            }
            let _ = store.retain(&policy).unwrap();
        }
        assert!(
            store.live_bytes().unwrap() <= cap,
            "the store must reach the cap after the escape hatch plus settled passes"
        );
        assert_eq!(
            store.unsettled_passes_for_tests(),
            0,
            "a settled pass resets the counter"
        );

        // The non-evictable rows really were non-evictable: replaceable
        // current state survived the escape hatch intact.
        let (rows_after, replaceable_after): (u64, u64) = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row(
                    "SELECT COUNT(*), COUNT(*) FILTER (WHERE replace_key IS NOT NULL) \
                     FROM history",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        assert_eq!(
            replaceable_after, REPLACEABLE as u64,
            "the forced path must never take replaceable (current-state) rows"
        );
        let deleted = rows_total - rows_after;
        assert!(
            rows_after > 0,
            "must not destroy everything (deleted {deleted} of {rows_total})"
        );
        // Over-deletion within the STATED estimate error (R4-D): the
        // quota the average forced on this skewed store, plus one bounded
        // batch of slack for the early-exit remeasure's granularity.
        // Deleting everything eligible ({DURABLE} rows) fails this bound;
        // so does a batch past the quota.
        assert!(
            deleted <= quota + RETAIN_EVICT_BATCH as u64 + 16,
            "over-deletion bounded by the stated estimate error: deleted {deleted}, \
             quota {quota} (avg_store {avg_store} B, per_row_durable {per_row_durable} B, \
             excess {excess} B)"
        );
        // Oldest-first, as ever — among the durable rows (the
        // replaceable rows are older but untouchable).
        let oldest_survivor: i64 = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row(
                    "SELECT MIN(seen_at_ms) FROM history WHERE replace_key IS NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert!(
            oldest_survivor >= 10_000 + deleted as i64 - 1,
            "eviction must be oldest-first"
        );
    }

    /// Round 5 (R4-B): the consecutive-unsettled counter is set from the
    /// FINAL state of a pass, never from an intermediate certificate.
    /// The round-4 scenario, reproduced deterministically: every pass
    /// settles its backlog (an intermediate certificate), deletes one
    /// bounded batch, then "times out" while folding that batch and is
    /// still over the cap. The pre-fix code reset the counter at the
    /// intermediate certificate, so it stayed at 1 forever and the forced
    /// path never ran however long ingestion outpaced the batches. With
    /// final-state accounting the escape hatch fires on pass
    /// UNSETTLED_PASSES_BEFORE_FORCED_EVICT + 1, as promised.
    #[test]
    fn unsettled_counter_survives_intermediate_certificates_until_the_pass_ends() {
        let (store, _dir) = open();
        const ROWS: usize = 3000;
        let live_empty = store.live_bytes().unwrap();
        for i in 0..ROWS {
            let mut payload = vec![0_u8; 512];
            payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut r = rec(&payload, Scope::Group("fold".into()));
            r.content_type = "application/octet-stream".into();
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        let live_before = store.live_bytes().unwrap();
        let per_row = (live_before - live_empty) / ROWS as u64;
        assert!(per_row > 0, "fixture must have a measurable per-row cost");
        // Cap at half the store: one bounded batch frees far less than
        // the excess, so every hooked pass ends still over the cap — the
        // precondition for counting it as unsettled. Guard it so the
        // fixture cannot silently drift into three batches reaching the
        // cap.
        let cap = live_before / 2;
        assert!(
            3 * RETAIN_EVICT_BATCH as u64 * per_row < live_before - cap,
            "fixture: three single batches must not reach the cap"
        );
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };

        // The hook makes the fold AFTER the first settled eviction batch
        // report "budget ran out" — exactly what a pass that settles,
        // deletes a batch, then times out folding it looks like to the
        // counter.
        store.timeout_fold_after_first_batch_for_tests();
        for pass in 1..=UNSETTLED_PASSES_BEFORE_FORCED_EVICT as u32 {
            assert_eq!(
                store.retain(&policy).unwrap(),
                RETAIN_EVICT_BATCH as u64,
                "hooked pass {pass} deletes exactly one bounded batch, then \
                 budgets out folding it"
            );
            assert!(
                store.live_bytes().unwrap() > cap,
                "pass {pass} is still over the cap after its single batch"
            );
            assert_eq!(
                store.unsettled_passes_for_tests(),
                pass,
                "the intermediate settled certificate must NOT reset the \
                 counter (R4-B): a pass that ends unsettled and over the cap \
                 counts, whatever certificates it held midway"
            );
        }

        // The forced path runs within the promised number of passes — on
        // the very next one, while the folds are STILL timing out: the
        // round-4 defect was this path never firing at all.
        let forced = store.retain(&policy).unwrap();
        assert!(
            forced > 0,
            "after UNSETTLED_PASSES_BEFORE_FORCED_EVICT hooked passes the \
             escape hatch must evict despite every fold timing out"
        );

        // Folds recover: a settled pass finishes precisely and the streak
        // resets.
        store.clear_fold_timeout_for_tests();
        for _ in 0..3 {
            if store.live_bytes().unwrap() <= cap {
                break;
            }
            let _ = store.retain(&policy).unwrap();
        }
        assert!(
            store.live_bytes().unwrap() <= cap,
            "the store must reach the cap once folds settle again"
        );
        assert_eq!(
            store.unsettled_passes_for_tests(),
            0,
            "a pass that ends settled (or at/under the cap) resets the counter"
        );
    }

    /// C-1264-1 §4 (R3-A): the connection is held from the pinned-ceiling
    /// phase through global eviction, so no write can land between the
    /// ceiling check and the global phase. A pinned scope over its
    /// ceiling is cut back INSIDE the scope, and the healthy scope is
    /// never evicted to pay for the pinned overshoot. ADR 0068
    /// semantics, end to end, in one held pass.
    #[test]
    fn pinned_ceiling_cut_precedes_global_eviction_in_one_held_pass() {
        let (store, _dir) = open();
        // Pinned scope: rows worth well over the synthesized ceiling
        // (max_bytes/64 × 4, capped at max_bytes/16).
        const PINNED_ROWS: usize = 24;
        for i in 0..PINNED_ROWS {
            // Unique payload per row: msg_id is BLAKE3(payload), so a
            // shared filler would collapse the fixture to one row.
            let mut payload = vec![b'q'; 8_192];
            payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut r = rec(&payload, Scope::Group("quarantined".into()));
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        // Healthy scope: small rows, some of which global pressure may
        // legitimately take once the pinned overshoot is gone.
        for i in 0..40_u64 {
            let mut r = rec(
                format!("healthy {i}").as_bytes(),
                Scope::Group("healthy".into()),
            );
            r.seen_at_ms = 5_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        let max_bytes: u64 = 512 * 1024;
        let policy = RetentionPolicy {
            max_bytes,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };
        let pinned = PinnedScopes::from_canonical(["group:quarantined"]);
        let ceiling = Store::pinned_ceiling(&policy, &Scope::Group("quarantined".into()));

        let outcome = store.retain_with_pins(&policy, &pinned).unwrap();
        assert!(
            outcome.pinned_evicted > 0,
            "the pinned scope started well over its ceiling and must shed its own rows"
        );
        let pinned_bytes: i64 = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row(
                    "SELECT COALESCE(SUM(LENGTH(payload) \
                       + LENGTH(COALESCE(signed_artifact, x''))), 0) \
                     FROM history WHERE scope_kind = 1 AND scope_id = 'quarantined'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert!(
            pinned_bytes as u64 <= ceiling,
            "the pinned scope must be cut back to its ceiling, not further: \
             {pinned_bytes} > {ceiling}"
        );
        // The pinned scope keeps its forensic record (oldest rows went,
        // the recent span survives the incident window).
        let pinned_rows: i64 = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row(
                    "SELECT COUNT(*) FROM history \
                     WHERE scope_kind = 1 AND scope_id = 'quarantined'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert!(pinned_rows > 0, "the pinned scope survives its own cut");
        // And the healthy scope is still there: the global phase may trim
        // it for the GLOBAL excess only — never to pay the pinned
        // overshoot, which phase 2 already removed.
        let healthy_rows: i64 = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row(
                    "SELECT COUNT(*) FROM history \
                     WHERE scope_kind = 1 AND scope_id = 'healthy'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert!(healthy_rows > 0, "the healthy scope survives the pass");
    }

    /// Review round 2 (R2-F): measuring live bytes is read-only. It must
    /// not checkpoint-truncate the WAL — that synchronous I/O belongs to
    /// the maintenance cadence inside a pass, and the measure is correct
    /// without it (the pager reads the database size from the WAL).
    #[test]
    fn live_bytes_does_not_truncate_the_wal_but_a_pass_does() {
        let (store, _dir) = open();
        for i in 0..40_u64 {
            let mut r = rec(
                format!("wal probe {i}").as_bytes(),
                Scope::Group("wal".into()),
            );
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        let wal_frames = |store: &Store| -> i64 {
            let guard = lock_conn(&store.conn).unwrap();
            // PASSIVE reports the frame count without truncating.
            guard
                .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| r.get(1))
                .unwrap()
        };
        let before = wal_frames(&store);
        assert!(
            before > 0,
            "the fixture must leave committed frames in the WAL (got {before})"
        );
        let _measure = store.live_bytes().unwrap();
        assert_eq!(
            wal_frames(&store),
            before,
            "live_bytes must not checkpoint the WAL"
        );
        let _ = store
            .retain(&RetentionPolicy {
                max_bytes: u64::MAX,
                max_age_days: 0,
                scope_limits: Vec::new(),
            })
            .unwrap();
        assert_eq!(
            wal_frames(&store),
            0,
            "a pass must leave a truncated WAL between its statements and behind it"
        );
    }

    /// Review round 2 (R2-D): retention passes serialize on the store's
    /// retention lock, and each pass's pins are inlined into its own SQL
    /// (no connection-shared TEMP table another call could clear). While
    /// this test holds the lock, a concurrent `retain_with_pins` under
    /// global pressure with the store's only scope pinned must stay blocked
    /// — deterministically observable, it cannot finish — and once
    /// released it must complete without deleting the rows it pinned.
    #[test]
    fn retention_passes_serialize_and_pins_survive_their_own_pass() {
        let (store, _dir) = open();
        for i in 0..30_u64 {
            let mut r = rec(
                format!("pinned row {i}").as_bytes(),
                Scope::Group("pinned".into()),
            );
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        // Real global pressure: half the live size. Everything deletable is
        // pinned, so a corrupted pin set is the only way this pass could
        // delete rows.
        let cap = store.live_bytes().unwrap() / 2;
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };
        let pinned = PinnedScopes::from_canonical(["group:pinned"]);

        let hold = store.retention.lock().unwrap_or_else(|e| e.into_inner());
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            let spawned = s.spawn(|| {
                let _ = store.retain_with_pins(&policy, &pinned).unwrap();
                done.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(
                !done.load(std::sync::atomic::Ordering::SeqCst),
                "retain_with_pins must not run while another pass holds the retention lock"
            );
            drop(hold);
            spawned.join().unwrap();
        });
        assert!(
            done.load(std::sync::atomic::Ordering::SeqCst),
            "the serialized pass must complete once the lock is released"
        );
        let rows: i64 = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row(
                    "SELECT COUNT(*) FROM history WHERE scope_kind = 1 AND scope_id = 'pinned'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(rows, 30, "a fully pinned store keeps every row");
    }

    /// C-1264-1 §1 (round 4): a writer that arrives while a pass holds the
    /// connection waits — for at most the pass budget plus one statement —
    /// and completes once the pass returns. The pass is parked at the top
    /// of its held connection (test hook) so the blocked window is
    /// deterministic.
    #[test]
    fn writer_blocked_during_a_pass_completes_after_it() {
        let (store, _dir) = open();
        const ROWS: usize = 120;
        const WORDS: [&str; 8] = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
        ];
        for i in 0..ROWS {
            let mut body = String::new();
            while body.len() < 1024 {
                for word in WORDS {
                    body.push_str(word);
                    body.push(' ');
                }
                body.push_str(&format!("row{i:04} "));
            }
            let mut r = rec(body.as_bytes(), Scope::Group("blocked".into()));
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        let cap = store.live_bytes().unwrap() / 2;
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: Vec::new(),
        };

        store.pause_pass_for_tests();
        let written = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            let passer = s.spawn(|| {
                let _ = store.retain(&policy).unwrap();
            });
            // Let the pass take the connection and park on it.
            std::thread::sleep(std::time::Duration::from_millis(300));
            let writer = s.spawn(|| {
                let mut r = rec(
                    b"written while a pass held the connection",
                    Scope::Group("blocked".into()),
                );
                r.seen_at_ms = 500_000;
                r.sent_at_ms = 500_000;
                assert_eq!(store.insert(&r).unwrap(), InsertOutcome::Inserted);
                written.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(
                !written.load(std::sync::atomic::Ordering::SeqCst),
                "the writer must wait while the pass holds the connection"
            );
            store.unpause_pass_for_tests();
            passer.join().unwrap();
            writer.join().unwrap();
        });
        assert!(
            written.load(std::sync::atomic::Ordering::SeqCst),
            "the blocked writer must complete once the pass releases the connection"
        );
        // The pass converged before the writer's row landed; one more pass
        // absorbs it.
        let _ = store.retain(&policy).unwrap();
        assert!(
            store.live_bytes().unwrap() <= cap,
            "passes must converge around the unblocked writer"
        );
    }

    /// C-1264-1 §2 (R3-E): every merge slice inside a pass is followed by
    /// a truncating checkpoint and every vacuum slice checkpoints every
    /// [`VACUUM_CHECKPOINT_EVERY`] statements, so the WAL holds about one
    /// slice however many slices the pass runs, and a pass that ran many
    /// slices leaves a truncated WAL behind.
    ///
    /// Round 5 (R4-C): the peak is observed DETERMINISTICALLY. A cfg(test)
    /// recorder runs inside the pass — after every merge statement, every
    /// vacuum statement and every checkpoint — so no growth interval can
    /// be missed, a pass that ran zero slices cannot fake a bound, and
    /// metadata errors cannot pass silently. Removing the between-slice
    /// checkpoints FAILS this test: the WAL then accumulates each slice's
    /// output between truncations (~10 MB on this fixture against a 1 MB
    /// bound), and the recorder observes it exactly.
    #[test]
    fn wal_stays_bounded_across_many_maintenance_slices() {
        let (store, dir) = open();
        const ROWS: usize = 2000;
        const WORDS: [&str; 8] = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
        ];
        for i in 0..ROWS {
            let mut body = String::new();
            while body.len() < 4096 {
                for word in WORDS {
                    body.push_str(word);
                    body.push_str(&format!("row{i:04} "));
                }
            }
            let mut r = rec(body.as_bytes(), Scope::Group("walbound".into()));
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        // Tombstones: raw-delete the oldest half so the pass has real
        // folding and vacuuming to do across its many slices.
        {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .execute(
                    "DELETE FROM history WHERE id IN \
                     (SELECT id FROM history ORDER BY seen_at_ms ASC LIMIT 1000)",
                    [],
                )
                .unwrap();
        }
        // Start from a truncated WAL so the recorded peak measures only
        // what the pass itself writes, then arm the in-pass recorder.
        {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }
        let wal_path = dir.path().join("history.db-wal");
        let db_path = dir.path().join("history.db");
        let live_before = store.live_bytes().unwrap();
        store.record_wal_peak_for_tests(&wal_path);

        let _ = store
            .retain(&RetentionPolicy {
                max_bytes: u64::MAX,
                max_age_days: 0,
                scope_limits: Vec::new(),
            })
            .unwrap();

        // The pass really ran many merge slices — the bound is meaningless
        // on a pass that did nothing.
        let slices = store.merge_slices_for_tests();
        assert!(
            slices >= 8,
            "the pass must run several merge slices (ran {slices})"
        );
        // The recorder really observed the WAL inside the pass — not a
        // default zero (R4-C: absence of observation must not pass).
        let peak = store.wal_peak_for_tests();
        assert!(
            peak > 0,
            "the in-pass recorder must observe the WAL (peak stayed at 0)"
        );
        // One merge statement writes at most FTS_MERGE_PAGES_PER_SLICE
        // output pages (the honest exception — a single huge posting list —
        // does not occur in this uniform fixture) plus segment/structure
        // overhead; allow a generous multiple for the vacuum statements
        // between their periodic checkpoints.
        let bound = FTS_MERGE_PAGES_PER_SLICE as u64 * 4096 * 4;
        assert!(
            peak <= bound,
            "peak WAL across a many-slice pass: {peak} > {bound}"
        );
        let wal_after = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
        assert!(
            wal_after <= 64 * 1024,
            "the pass must leave a truncated WAL behind (got {wal_after} bytes)"
        );
        // The bounds are meaningful only if the pass really ran many slices
        // on a database far larger than the bound.
        assert!(
            store.live_bytes().unwrap() < live_before,
            "the pass did real merge/vacuum work across its slices"
        );
        let db_len = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
        assert!(
            db_len > 2 * bound,
            "fixture database must dwarf the WAL bound (db={db_len}, bound={bound})"
        );
    }

    /// Fixture helper: seed `rows` tiny durable rows into one scope with
    /// direct SQL (one transaction, one prepared statement), stamped
    /// `seen_base + i` so a fixture chooses whether the rows are old
    /// (age-evictable) or recent. The C-1264-2 fixtures need six-figure
    /// row counts so a full-scope SUM scan measurably outlasts a
    /// millisecond-scale pass budget — far past what the per-record
    /// insert path should absorb in a test. `tag` keeps `msg_id` unique
    /// across calls.
    fn seed_tiny_rows(
        store: &Store,
        scope: &Scope,
        rows: usize,
        payload_len: usize,
        tag: u64,
        seen_base: i64,
    ) {
        let mut guard = lock_conn(&store.conn).unwrap();
        let tx = guard.transaction().unwrap();
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO history (msg_id, scope_kind, scope_id, sent_at_ms, seen_at_ms, \
                     direction, content_type, payload, payload_text, provenance) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'application/octet-stream', ?7, NULL, ?8)",
                )
                .unwrap();
            for i in 0..rows as i64 {
                let mut msg_id = [0_u8; 32];
                msg_id[..8].copy_from_slice(&tag.to_le_bytes());
                msg_id[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                let mut payload = vec![b'f'; payload_len];
                payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
                stmt.execute(rusqlite::params![
                    &msg_id[..],
                    scope.kind(),
                    scope.id(),
                    seen_base + i,
                    seen_base + i,
                    Direction::Inbound.as_i64(),
                    &payload[..],
                    Provenance::LocalAppDecrypt.as_i64(),
                ])
                .unwrap();
            }
        }
        tx.commit().unwrap();
    }

    /// The exact SUM the per-scope helpers run, for fixture math and
    /// assertions.
    fn scope_payload_bytes(store: &Store, scope: &Scope) -> u64 {
        let guard = lock_conn(&store.conn).unwrap();
        let used: i64 = guard
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(payload) \
                   + LENGTH(COALESCE(signed_artifact, x''))), 0) \
                 FROM history WHERE scope_kind = ?1 AND scope_id = ?2",
                rusqlite::params![scope.kind(), scope.id()],
                |r| r.get(0),
            )
            .unwrap();
        used.max(0) as u64
    }

    fn scope_row_count(store: &Store, scope: &Scope) -> i64 {
        let guard = lock_conn(&store.conn).unwrap();
        guard
            .query_row(
                "SELECT COUNT(*) FROM history WHERE scope_kind = ?1 AND scope_id = ?2",
                rusqlite::params![scope.kind(), scope.id()],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// Time ONE warm full-scope SUM over `scope`, discarding the cold run
    /// so the calibration matches the in-pass scans that follow it (the
    /// fixture insert already touched every page; the discarded run
    /// settles any remaining cache difference).
    fn warm_scope_sum_ms(store: &Store, scope: &Scope) -> u64 {
        let run = || scope_payload_bytes(store, scope);
        let _cold = run();
        let t = std::time::Instant::now();
        let _warm = run();
        t.elapsed().as_millis() as u64
    }

    /// C-1264-2 test (a): every eviction phase runs in EVERY pass, even
    /// when the reclamation budget is spent before phase 4 — the age
    /// bound, pinned ceilings and per-scope limits are not deadline-gated
    /// and run to completion at main's cost, which is what removes the
    /// round-5/6 starvation class. The fixture gives each phase work in
    /// two consecutive passes with a 1 ms budget; the overdue scope's
    /// warm SUM (asserted >= 2 ms) plus the age bound's full-table scan
    /// provably spend it before maintenance, and the merge-slice counter
    /// proves no reclamation statement ever started.
    #[test]
    fn every_eviction_phase_runs_in_every_pass_with_the_reclamation_budget_spent() {
        const ROW_BYTES: u64 = 256;
        const OVERDUE_ROWS: usize = 120_000;
        const AGED_ROWS: usize = 400;
        const PINNED_ROWS: usize = 64;
        let (store, _dir) = open();
        let aged = Scope::Group("aged".into());
        let quarantined = Scope::Group("quarantined".into());
        let overdue = Scope::Group("overdue".into());
        let recent = now_ms();
        // max_bytes small enough that the synthesized pinned ceiling
        // (max_bytes/16) is real: 64 rows x 1 KiB dwarf the 32 KiB
        // ceiling, and the overdue scope dwarfs the global cap.
        let max_bytes: u64 = 512 * 1024;
        let policy = RetentionPolicy {
            max_bytes,
            max_age_days: 1,
            scope_limits: vec![ScopeLimit {
                scope: "group:overdue".into(),
                max_bytes: ROW_BYTES * (OVERDUE_ROWS as u64 - 300),
            }],
        };
        let pinned = PinnedScopes::from_canonical(["group:quarantined"]);
        let ceiling = Store::pinned_ceiling(&policy, &quarantined);
        let overdue_limit = policy.scope_limits[0].max_bytes;

        let seed = |tag: u64| {
            seed_tiny_rows(&store, &aged, AGED_ROWS, ROW_BYTES as usize, tag, 1_000);
            seed_tiny_rows(&store, &quarantined, PINNED_ROWS, 1_024, tag + 1, recent);
            seed_tiny_rows(
                &store,
                &overdue,
                if tag == 1 { OVERDUE_ROWS } else { 300 },
                ROW_BYTES as usize,
                tag + 2,
                recent,
            );
        };
        seed(1);
        let scan_ms = warm_scope_sum_ms(&store, &overdue);
        assert!(
            scan_ms >= 2,
            "fixture: the overdue scope's SUM must outlast the 1 ms budget \
             (took {scan_ms} ms)"
        );
        store.shrink_pass_budget_for_tests(std::time::Duration::from_millis(1));

        for pass in 1..=2_u32 {
            let outcome = store.retain_with_pins(&policy, &pinned).unwrap();
            // Phase 1 ran: the aged rows are gone in both passes.
            assert_eq!(
                scope_row_count(&store, &aged),
                0,
                "pass {pass}: the age bound must run with a spent budget"
            );
            // Phase 2 ran: the pinned scope was cut back to its ceiling.
            assert!(
                outcome.pinned_evicted > 0,
                "pass {pass}: the pinned ceiling must be enforced"
            );
            assert!(
                scope_payload_bytes(&store, &quarantined) <= ceiling,
                "pass {pass}: the pinned scope must fit its ceiling"
            );
            // Phase 3 ran: the over-limit scope was cut to its limit.
            assert!(
                scope_payload_bytes(&store, &overdue) <= overdue_limit,
                "pass {pass}: the per-scope budget must be enforced"
            );
            // Phase 4 correctly refuses to evict without a certificate:
            // the skipped maintenance counts as not settled while the
            // store sits over its cap.
            assert_eq!(
                store.unsettled_passes_for_tests(),
                pass,
                "pass {pass}: a spent reclamation budget must count as unsettled"
            );
            // And no reclamation statement ever started: 4b runs
            // unconditionally, so an unspent budget would have run at
            // least one merge slice by now.
            assert_eq!(
                store.merge_slices_for_tests(),
                0,
                "pass {pass}: no reclamation statement may start"
            );
            if pass == 1 {
                seed(4);
            }
        }
    }

    /// C-1264-2 test (b): once the budget is spent, no reclamation
    /// statement starts — not inside a merge slice, not inside a vacuum
    /// step, and not the pass's teardown checkpoint. The unit half hands
    /// an already-expired deadline to the slice helpers directly; the
    /// integration half runs a whole pass whose budget the per-scope
    /// phase provably spends, and observes that the pass's own deletes
    /// leave WAL frames behind precisely because the teardown checkpoint
    /// did not start past the deadline.
    #[test]
    fn no_reclamation_statement_starts_after_the_deadline() {
        const ROW_BYTES: u64 = 256;
        const OVERDUE_ROWS: usize = 120_000;
        let (store, _dir) = open();
        // Tombstones and freelist pages for the unit half.
        for i in 0..800_u64 {
            let mut payload = vec![b'd'; 512];
            payload[..8].copy_from_slice(&i.to_le_bytes());
            let mut r = rec(&payload, Scope::Group("deadline".into()));
            r.seen_at_ms = 1_000 + i as i64;
            r.sent_at_ms = r.seen_at_ms;
            store.insert(&r).unwrap();
        }
        {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .execute(
                    "DELETE FROM history WHERE id IN \
                     (SELECT id FROM history ORDER BY seen_at_ms ASC LIMIT 400)",
                    [],
                )
                .unwrap();
            guard
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }

        // Unit half: an expired deadline means the helpers run NOTHING.
        let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
        {
            let guard = lock_conn(&store.conn).unwrap();
            let structure_before = Store::fts_structure(&guard).unwrap();
            let freelist_before: i64 = guard
                .query_row("PRAGMA freelist_count", [], |r| r.get(0))
                .unwrap();
            assert!(
                freelist_before > 0,
                "fixture: the raw delete must leave freelist pages (got {freelist_before})"
            );
            let worked = store
                .merge_slice(&guard, FTS_MERGE_PAGES_PER_SLICE, past)
                .unwrap();
            assert!(
                worked,
                "an expired-deadline slice reports worked, never a no-op"
            );
            assert_eq!(
                store.merge_slices_for_tests(),
                0,
                "no merge statement may start past the deadline"
            );
            assert_eq!(
                Store::fts_structure(&guard).unwrap(),
                structure_before,
                "no statement of the slice may run past the deadline"
            );
            let (pages, skipped) = store.vacuum_slice(&guard, past).unwrap();
            assert_eq!(pages, 0, "no vacuum step may move a page past the deadline");
            assert!(skipped, "an expired-deadline vacuum reports skipped");
            let freelist: i64 = guard
                .query_row("PRAGMA freelist_count", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                freelist, freelist_before,
                "no vacuum statement may start past the deadline"
            );
        }

        // Integration half: a whole pass on a spent budget. The overdue
        // scope's SUM (asserted below, warm) spends the 1 ms budget
        // during phase 3, so phase 4's maintenance, its checkpoints and
        // the teardown checkpoint never start — while the per-scope
        // deletes themselves run to completion.
        let overdue = Scope::Group("waldeadline".into());
        seed_tiny_rows(
            &store,
            &overdue,
            OVERDUE_ROWS,
            ROW_BYTES as usize,
            7,
            now_ms(),
        );
        let limit = ROW_BYTES * (OVERDUE_ROWS as u64 - 300);
        assert!(
            scope_payload_bytes(&store, &overdue) > limit,
            "fixture: the overdue scope must start over its limit"
        );
        let scan_ms = warm_scope_sum_ms(&store, &overdue);
        assert!(
            scan_ms >= 2,
            "fixture: the overdue scope's SUM must outlast the 1 ms budget \
             (took {scan_ms} ms)"
        );
        store.shrink_pass_budget_for_tests(std::time::Duration::from_millis(1));
        let policy = RetentionPolicy {
            max_bytes: u64::MAX,
            max_age_days: 0,
            scope_limits: vec![ScopeLimit {
                scope: "group:waldeadline".into(),
                max_bytes: limit,
            }],
        };
        let wal_frames = |store: &Store| -> i64 {
            let guard = lock_conn(&store.conn).unwrap();
            // PASSIVE reports the frame count without truncating.
            guard
                .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| r.get(1))
                .unwrap()
        };
        let evicted = store.retain(&policy).unwrap();
        assert_eq!(
            evicted,
            2 * RETAIN_EVICT_BATCH as u64,
            "eviction runs to completion with a spent reclamation budget"
        );
        assert!(
            scope_payload_bytes(&store, &overdue) <= limit,
            "the over-limit scope is cut to its limit"
        );
        assert_eq!(
            store.merge_slices_for_tests(),
            0,
            "no reclamation statement started in the whole pass"
        );
        assert!(
            wal_frames(&store) > 0,
            "the pass's own deletes leave WAL frames behind: the teardown \
             checkpoint must not start past the deadline"
        );

        // Contrast: with the production budget restored, the next pass
        // runs its maintenance (folding the backlog) and leaves the
        // truncated WAL behind.
        store.shrink_pass_budget_for_tests(std::time::Duration::ZERO);
        let _ = store.retain(&policy).unwrap();
        assert!(
            store.merge_slices_for_tests() > 0,
            "an in-budget pass runs its maintenance"
        );
        assert_eq!(
            wal_frames(&store),
            0,
            "an in-budget pass still truncates the WAL"
        );
    }

    /// Issue #1286: one unparseable `scope_limits` entry must not stop the
    /// retention pass. On main `a36fc49`, phase 3 ran `Scope::parse(..)?`
    /// and returned `Err` at the bad entry, in every pass. The valid limit
    /// after it, the whole-database byte budget (phase 4) and the
    /// end-of-pass canonical-id cleanup therefore never ran, and
    /// `history.db` grew without bound.
    ///
    /// Fixture: an over-cap store. The bad entry is listed FIRST, so every
    /// later step sits behind it. The oldest rows are a filler scope, which
    /// only the global budget evicts. A newer limited scope sits over its
    /// own valid limit. An orphaned canonical-id row, planted after the
    /// fixture settles (the delete trigger never sees it), is removed only
    /// by the end-of-pass cleanup.
    #[test]
    fn unparseable_scope_limit_does_not_stop_the_retention_pass() {
        let (store, _dir) = open();
        let filler = Scope::Dm("cd".repeat(32));
        let limited = Scope::Dm("ab".repeat(32));
        seed_tiny_rows(&store, &filler, 3_000, 200, 0x1286_0001, 1_000);
        seed_tiny_rows(&store, &limited, 600, 64, 0x1286_0002, 100_000);
        settle(&store);
        {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .execute(
                    "INSERT INTO history_canonical_ids \
                     (history_msg_id, canonical_msg_id, scope_kind, scope_id) \
                     VALUES (?1, ?2, 1, 'orphan-1286')",
                    rusqlite::params![&[0x12_u8; 32][..], &[0x86_u8; 32][..]],
                )
                .unwrap();
        }

        let limit = 30_000_u64;
        assert!(
            scope_payload_bytes(&store, &limited) > limit,
            "precondition: the limited scope starts over its limit"
        );
        let filler_before = scope_row_count(&store, &filler);
        let live = store.live_bytes().unwrap();
        // A quarter of the live store must go: far more than the limited
        // scope can free, so only phase 4 can meet this cap.
        let cap = live - live / 4;
        let policy = RetentionPolicy {
            max_bytes: cap,
            max_age_days: 0,
            scope_limits: vec![
                ScopeLimit {
                    scope: "not-a-scope".into(),
                    max_bytes: 0,
                },
                ScopeLimit {
                    scope: limited.canonical(),
                    max_bytes: limit,
                },
            ],
        };

        let mut met = false;
        for pass in 0..16 {
            let result = store.retain(&policy);
            assert!(
                result.is_ok(),
                "pass {pass} failed on an unparseable scope_limits entry (#1286): {result:?}"
            );
            if store.live_bytes().unwrap() <= cap {
                met = true;
                break;
            }
        }
        assert!(
            met,
            "the whole-database budget behind the bad entry must be enforced"
        );
        assert!(
            scope_row_count(&store, &filler) < filler_before,
            "phase 4 evicted the oldest (filler) rows"
        );
        assert!(
            scope_payload_bytes(&store, &limited) <= limit,
            "the valid limit after the bad entry must apply"
        );
        assert!(
            scope_row_count(&store, &limited) > 0,
            "the limited scope is cut to its limit, not emptied"
        );
        let orphans: i64 = {
            let guard = lock_conn(&store.conn).unwrap();
            guard
                .query_row(
                    "SELECT COUNT(*) FROM history_canonical_ids WHERE scope_id = 'orphan-1286'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(orphans, 0, "the end-of-pass canonical-id cleanup must run");
        assert_eq!(store.skipped_scope_limits(), 1, "the bad entry is counted");
    }

    /// A `tracing` writer that keeps everything written to it, so a test can
    /// assert on warnings.
    #[derive(Clone, Default)]
    struct CapturedLog(std::sync::Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl CapturedLog {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    /// Issue #1286: every pass counts the skipped entries, and the store
    /// logs the skip once, not once per pass. A clean policy counts zero and
    /// logs nothing.
    #[test]
    fn unparseable_scope_limits_are_counted_each_pass_and_logged_once() {
        let log = CapturedLog::default();
        let writer = log.clone();
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .finish(),
        );
        let (store, _dir) = open();
        let scope = Scope::Dm("ef".repeat(32));
        seed_tiny_rows(&store, &scope, 10, 64, 0x1286_0003, 1_000);
        let valid = ScopeLimit {
            scope: scope.canonical(),
            max_bytes: u64::MAX,
        };
        let clean = RetentionPolicy {
            max_bytes: u64::MAX,
            max_age_days: 0,
            scope_limits: vec![valid.clone()],
        };
        store.retain(&clean).unwrap();
        assert_eq!(
            store.skipped_scope_limits(),
            0,
            "a clean policy skips nothing"
        );
        assert!(
            !log.text().contains("#1286"),
            "a clean policy logs nothing: {}",
            log.text()
        );

        let bad = RetentionPolicy {
            max_bytes: u64::MAX,
            max_age_days: 0,
            scope_limits: vec![
                ScopeLimit {
                    scope: "dm:".into(),
                    max_bytes: 0,
                },
                valid,
                ScopeLimit {
                    scope: "chan:x".into(),
                    max_bytes: 0,
                },
            ],
        };
        for pass in 0..3 {
            store.retain(&bad).unwrap();
            assert_eq!(
                store.skipped_scope_limits(),
                2,
                "pass {pass} counts both bad entries"
            );
        }
        assert_eq!(
            scope_row_count(&store, &scope),
            10,
            "a skipped entry's max_bytes = 0 applies to no scope"
        );
        let text = log.text();
        assert_eq!(
            text.matches("#1286").count(),
            1,
            "logged once per store, not once per pass: {text}"
        );
        assert!(
            text.contains("\"dm:\"") && text.contains("\"chan:x\""),
            "the warning names the bad entries: {text}"
        );

        store.retain(&clean).unwrap();
        assert_eq!(
            store.skipped_scope_limits(),
            0,
            "the gauge follows the latest pass"
        );
    }
}

// W3-H S3 (#1164), the restart drain: a harness must know when a store's
// connection has closed and released the database's EXCLUSIVE lock. The
// last `Arc<Store>` reaches a strong count of zero before the store's
// destructor runs (possibly on another thread, e.g. a reaper
// `spawn_blocking` task), so a count cannot tell. In test builds the two
// signal fields above report it; in other builds they are zero-sized types
// without a `Drop`, so production is unchanged. (Kept at the end of the
// file, after the tests: `scripts/check-panics.sh` treats every line after
// a file's first `#[cfg(test)]` as test code.)

/// Test builds: observe the end of a store's connection.
#[cfg(test)]
pub(crate) mod close_watch {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    /// Hook run on the dropping thread just before the connection closes.
    type Hook = Box<dyn FnOnce() + Send>;

    /// Shared between a store and its observers.
    #[derive(Default)]
    pub(crate) struct CloseWatch {
        closed: AtomicBool,
        before_close: Mutex<Option<Hook>>,
    }

    impl CloseWatch {
        /// Whether the store's connection has closed.
        pub(crate) fn closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }

        /// Run `hook` once, on the thread that drops the store, after its
        /// last reference is gone and before its connection closes (a test
        /// can hold the destruction in progress).
        pub(crate) fn before_close(&self, hook: impl FnOnce() + Send + 'static) {
            *self
                .before_close
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
        }
    }

    /// The store's first field: runs the before-close hook.
    pub(super) struct BeforeClose(Arc<CloseWatch>);

    impl Drop for BeforeClose {
        fn drop(&mut self) {
            let hook = self
                .0
                .before_close
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(hook) = hook {
                hook();
            }
        }
    }

    /// The store's last field: marks the connection closed.
    pub(super) struct AfterClose(pub(super) Arc<CloseWatch>);

    impl Drop for AfterClose {
        fn drop(&mut self) {
            self.0.closed.store(true, Ordering::SeqCst);
        }
    }

    /// The two signals of one new store.
    pub(super) fn signals() -> (BeforeClose, AfterClose) {
        let watch = Arc::new(CloseWatch::default());
        (BeforeClose(Arc::clone(&watch)), AfterClose(watch))
    }
}

#[cfg(test)]
impl Store {
    /// Test builds: the watch that reports when this store's connection
    /// has closed.
    pub(crate) fn close_watch(&self) -> std::sync::Arc<close_watch::CloseWatch> {
        std::sync::Arc::clone(&self._after_close.0)
    }

    /// Round-4 fixtures: every pass reports "budget ran out before the
    /// index settled" without running maintenance statements, making the
    /// forced-eviction path deterministically reachable.
    pub(crate) fn force_unsettled_passes_for_tests(&self) {
        self.test_never_settles.store(true, Ordering::Relaxed);
    }

    /// Round-4 fixtures: stop forcing unsettled passes.
    pub(crate) fn allow_settling_for_tests(&self) {
        self.test_never_settles.store(false, Ordering::Relaxed);
    }

    /// Round-4 fixtures: park the next (or in-flight) pass while it owns
    /// the connection, so a concurrent writer is observably blocked.
    pub(crate) fn pause_pass_for_tests(&self) {
        self.test_pause_pass.store(true, Ordering::Relaxed);
    }

    /// Round-4 fixtures: release a parked pass.
    pub(crate) fn unpause_pass_for_tests(&self) {
        self.test_pause_pass.store(false, Ordering::Relaxed);
    }

    /// Round-6 fixtures (R4-A/R5-B): shrink the pass budget so a scope's
    /// full-scope SUM scan provably outlasts it — a `Duration::ZERO`
    /// argument restores [`RETENTION_PASS_BUDGET`].
    pub(crate) fn shrink_pass_budget_for_tests(&self, budget: std::time::Duration) {
        self.test_pass_budget_ms.store(
            budget.as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    /// Round-5 fixtures (R4-B): every pass reports "budget ran out while
    /// folding the first settled eviction batch" — the round-4 scenario
    /// of a pass that settles, deletes a batch, then times out folding
    /// it while still over the cap.
    pub(crate) fn timeout_fold_after_first_batch_for_tests(&self) {
        self.test_timeout_fold.store(true, Ordering::Relaxed);
    }

    /// Round-5 fixtures: stop timing out the fold.
    pub(crate) fn clear_fold_timeout_for_tests(&self) {
        self.test_timeout_fold.store(false, Ordering::Relaxed);
    }

    /// Round-5 fixtures (R4-C): observe this store's WAL file INSIDE its
    /// retention passes — after every merge/vacuum statement and every
    /// checkpoint — turning the peak-WAL question into a deterministic
    /// in-pass record instead of a racy external poll.
    pub(crate) fn record_wal_peak_for_tests(&self, wal_path: impl Into<std::path::PathBuf>) {
        *self
            .test_wal_path
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(wal_path.into());
    }

    /// Round-5 fixtures (R4-C): fold the recorded WAL-size maximum into
    /// the running peak. No-op unless [`Self::record_wal_peak_for_tests`]
    /// armed the recorder; a missing file or a poisoned lock is skipped
    /// (absence is never evidence of a small WAL — the armed test's
    /// `peak > 0` assertion catches a recorder that observed nothing).
    fn observe_wal_for_tests(&self) {
        let Ok(path) = self.test_wal_path.lock() else {
            return;
        };
        let Some(path) = path.as_ref() else {
            return;
        };
        if let Ok(meta) = std::fs::metadata(path) {
            let len = meta.len();
            let prev = self.test_wal_peak.load(Ordering::Relaxed);
            if len > prev {
                self.test_wal_peak.store(len, Ordering::Relaxed);
            }
        }
    }

    /// Round-5 fixtures (R4-C): the recorded in-pass WAL peak.
    pub(crate) fn wal_peak_for_tests(&self) -> u64 {
        self.test_wal_peak.load(Ordering::Relaxed)
    }

    /// Round-5 fixtures (R4-C): merge statements run by this store's
    /// passes since open.
    pub(crate) fn merge_slices_for_tests(&self) -> u64 {
        self.test_merge_slices.load(Ordering::Relaxed)
    }

    /// The C-1264-1 §3 consecutive-unsettled counter, for assertions.
    pub(crate) fn unsettled_passes_for_tests(&self) -> u32 {
        self.unsettled_passes.load(Ordering::Relaxed)
    }
}

/// Other builds: the signals are zero-sized and do nothing.
#[cfg(not(test))]
mod close_watch {
    pub(super) struct BeforeClose;
    pub(super) struct AfterClose;

    pub(super) fn signals() -> (BeforeClose, AfterClose) {
        (BeforeClose, AfterClose)
    }
}

use close_watch::{AfterClose, BeforeClose};

/// Test builds: count the history rows the canonical backfill examined, so a
/// test can prove a reopen scanned nothing (issue #1263 part 2). Production
/// builds never reference it. Kept after the tests module for
/// `scripts/check-panics.sh` (same convention as `close_watch` above);
/// nextest runs each test in its own process, so the counter needs no
/// cross-test locking.
#[cfg(test)]
pub(crate) mod backfill_probe {
    use std::sync::atomic::{AtomicU64, Ordering};

    static ROWS_EXAMINED: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn reset() {
        ROWS_EXAMINED.store(0, Ordering::Relaxed);
    }

    pub(crate) fn add(rows: u64) {
        ROWS_EXAMINED.fetch_add(rows, Ordering::Relaxed);
    }

    pub(crate) fn read() -> u64 {
        ROWS_EXAMINED.load(Ordering::Relaxed)
    }
}
