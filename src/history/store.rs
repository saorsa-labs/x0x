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
const SCHEMA_VERSION: i64 = 1;

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
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(busy)?;
        // auto_vacuum must be decided before the first table exists; on an
        // already-populated db this pragma is a no-op (the setting is baked
        // into the file header).
        conn.execute_batch(
            "PRAGMA auto_vacuum = INCREMENTAL;\n             PRAGMA locking_mode = EXCLUSIVE;\n             PRAGMA journal_mode = WAL;\n             PRAGMA synchronous = NORMAL;",
        )
        .map_err(|e| HistoryError::Database(format!("pragma setup failed: {e}")))?;
        // Acquire the exclusive lock NOW so a second process fails at open,
        // not at first write.
        if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE; COMMIT;") {
            return Err(HistoryError::Locked(format!("{} ({e})", path.display())));
        }
        migrate(&conn)?;
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
             signed_artifact, signature, sig_context, provenance, replace_key \
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

    /// Full-text search over text payloads. Tokens are quoted so user input
    /// is literal terms, never FTS operators (donor `fts_match_expr`).
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
             h.provenance, h.replace_key FROM history h \
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

    let record = (|| -> HistoryResult<HistoryRecord> {
        let mut msg_id = [0u8; 32];
        if msg_id_blob.len() != 32 {
            return Err(HistoryError::InvalidRecord("msg_id not 32 bytes".into()));
        }
        msg_id.copy_from_slice(&msg_id_blob);
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
        })
    })();
    Ok((id, record))
}

fn insert_row(tx: &rusqlite::Transaction<'_>, record: &HistoryRecord) -> HistoryResult<()> {
    let payload_text: Option<String> = if record.is_text() {
        Some(String::from_utf8_lossy(&record.payload).into_owned())
    } else {
        None
    };
    let msg_id: &[u8] = &record.msg_id;
    tx.execute(
        "INSERT INTO history (msg_id, scope_kind, scope_id, author_agent, author_machine, \
         author_pubkey, sent_at_ms, seen_at_ms, direction, content_type, payload, \
         payload_text, signed_artifact, signature, sig_context, provenance, replace_key) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
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
        ],
    )
    .map_err(|e| HistoryError::Database(format!("insert failed: {e}")))?;
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
        None => {
            conn.execute_batch(SCHEMA_V1)?;
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                rusqlite::params![SCHEMA_VERSION],
            )?;
            Ok(())
        }
        Some(v) if v == SCHEMA_VERSION => Ok(()),
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
        }
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
}
