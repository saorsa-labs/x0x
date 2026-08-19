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

/// Synchronous SQLite-backed history store.
pub struct Store {
    conn: Mutex<Connection>,
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
        Ok(Self {
            conn: Mutex::new(conn),
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
                Some((prev_id, _, _)) => {
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

    /// Enforce retention (ADR-0023 §6). Returns rows evicted.
    ///
    /// Replaceable rows are exempt from age eviction and from byte-pressure
    /// eviction (they are current state) but their size counts toward the
    /// byte measure.
    pub fn retain(&self, policy: &RetentionPolicy) -> HistoryResult<u64> {
        let mut evicted: u64 = 0;
        let guard = lock_conn(&self.conn)?;

        // 1. Age bound.
        if policy.max_age_days > 0 {
            let cutoff =
                now_ms().saturating_sub((policy.max_age_days as i64).saturating_mul(86_400_000));
            evicted += guard.execute(
                "DELETE FROM history WHERE replace_key IS NULL AND seen_at_ms < ?1",
                rusqlite::params![cutoff],
            )? as u64;
        }

        // 2. Per-scope byte budgets.
        for limit in &policy.scope_limits {
            let scope = Scope::parse(&limit.scope)?;
            loop {
                let used: i64 = guard.query_row(
                    "SELECT COALESCE(SUM(LENGTH(payload) + LENGTH(COALESCE(signed_artifact, x''))), 0) \
                     FROM history WHERE scope_kind = ?1 AND scope_id = ?2",
                    rusqlite::params![scope.kind(), scope.id()],
                    |r| r.get(0),
                )?;
                if used as u64 <= limit.max_bytes {
                    break;
                }
                let n = guard.execute(
                    "DELETE FROM history WHERE id IN (\
                       SELECT id FROM history \
                       WHERE scope_kind = ?1 AND scope_id = ?2 AND replace_key IS NULL \
                       ORDER BY seen_at_ms ASC LIMIT ?3)",
                    rusqlite::params![scope.kind(), scope.id(), RETAIN_EVICT_BATCH as i64],
                )?;
                if n == 0 {
                    break; // only replaceable rows remain in this scope
                }
                evicted += n as u64;
            }
        }

        // 3. Whole-database byte budget.
        loop {
            if db_bytes(&guard)? as u64 <= policy.max_bytes {
                break;
            }
            let n = guard.execute(
                "DELETE FROM history WHERE id IN (\
                   SELECT id FROM history WHERE replace_key IS NULL \
                   ORDER BY seen_at_ms ASC LIMIT ?1)",
                rusqlite::params![RETAIN_EVICT_BATCH as i64],
            )?;
            if n == 0 {
                break;
            }
            evicted += n as u64;
            guard.execute_batch("PRAGMA incremental_vacuum;")?;
        }
        if evicted > 0 {
            guard.execute_batch("PRAGMA incremental_vacuum;")?;
        }
        Ok(evicted)
    }

    /// Delete every row in `scope`. Returns rows removed. Local-only.
    pub fn purge(&self, scope: &Scope) -> HistoryResult<u64> {
        let guard = lock_conn(&self.conn)?;
        let n = guard.execute(
            "DELETE FROM history WHERE scope_kind = ?1 AND scope_id = ?2",
            rusqlite::params![scope.kind(), scope.id()],
        )?;
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

fn db_bytes(conn: &Connection) -> HistoryResult<i64> {
    let pages: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let size: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok(pages.saturating_mul(size))
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
    Ok(())
}

/// Indexes that are pure query accelerators, created idempotently at every
/// open rather than inside the versioned migration chain.
///
/// This is a deliberate departure from the migration convention, and the
/// reason is rollback safety. An index changes no column, no row meaning, and
/// no data: an older binary opening this database reads and writes it exactly
/// as before, and SQLite maintains the index for those writes transparently.
/// Adding one via a v4→v5 migration would instead bump `SCHEMA_VERSION`, and
/// `migrate` rejects any database newer than the running binary — so a
/// rollback from this release to v0.37.4 would leave every upgraded user with
/// a `history.db` that refuses to open. Paying that for a performance-only
/// change is the wrong trade. Schema changes that alter the data model still
/// go through the versioned chain.
///
/// `idx_logical_request` backs `find_by_logical_request`, the ADR 0030 §1
/// receiver durable-history lookup, which runs on every inbound v2 DM.
/// Partial (`WHERE logical_request_id IS NOT NULL`) because only rows written
/// by the receiver durable path populate the v4 columns — group rows and every
/// row predating schema v4 carry NULL, and indexing those wastes space for a
/// lookup that can never match them. Mirrors the existing `idx_replace`
/// partial-index precedent.
fn ensure_indexes(conn: &Connection) -> HistoryResult<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_logical_request \
         ON history(ingress_sender_agent, logical_request_id) \
         WHERE logical_request_id IS NOT NULL;",
    )
    .map_err(|e| HistoryError::Database(format!("index setup failed: {e}")))?;
    Ok(())
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
}
