#![cfg(test)]
//! ADR 0116 Validation "Storage and downgrade" (slice F): a released
//! schema-4 `history.db`, written by the released v0.46.6 `x0xd` (see
//! `tests/fixtures/v0466_history_db/PROVENANCE.md`), opens under this
//! version, takes the ADR 0116 trim, and keeps schema 4 and consistent
//! derived indexes. A newer schema fails closed and leaves the file's bytes
//! unchanged in the database states the scoped contract on
//! [`Store::open_with_busy_timeout`] covers (`src/history/store.rs`): a
//! WAL-mode database, or a settled rollback-journal one. A hot rollback
//! journal is recovered first, as SQLite requires (controller decision
//! C-0116-F1).
//!
//! Inert: no network and no daemon. Every test works on a copy in a temp
//! dir; the committed fixture is never opened (opening a WAL database can
//! create `-wal`/`-shm` files beside it). The older-binary half of the row
//! (open the trimmed file with v0.46.6, then upgrade again) is the scripted
//! local proof `tests/fixtures/v0466_history_db/downgrade_proof.py`, which
//! runs [`verify_history_db_from_env`] after each step.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::*;

/// The fixture, relative to the crate root.
const FIXTURE: &str = "tests/fixtures/v0466_history_db/history.db";

/// The fixture's sha256, as recorded in its PROVENANCE.md.
const FIXTURE_SHA256: &str = "9fe7de6ea55496273df545cc1ea282107fa36a06ba701aaf6ce97dc744179baf";

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE)
}

fn sha256_file(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
}

/// Copy `source` to `<dir>/history.db`.
fn copy_db(source: &Path, dir: &Path) -> PathBuf {
    let path = dir.join("history.db");
    std::fs::copy(source, &path).unwrap();
    path
}

fn copy_fixture(dir: &Path) -> PathBuf {
    copy_db(&fixture_path(), dir)
}

/// What a schema-4 history database holds, read with plain SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DbFacts {
    schema_version: i64,
    /// `(type, name, sql)` of every table, index and trigger.
    master: Vec<(String, String, Option<String>)>,
    rows: i64,
    durable: i64,
    replaceable: i64,
    /// Rows per canonical scope string: `(durable, replaceable)`.
    by_scope: BTreeMap<String, (i64, i64)>,
    /// FTS documents (the index's own docsize table).
    fts_docs: i64,
    /// Canonical projection rows.
    canonical: i64,
    /// Canonical rows whose history row is gone, or whose scope differs.
    canonical_dangling: i64,
    /// Group rows carrying a signed artifact (each must be projected).
    group_artifact_rows: i64,
}

fn scope_string(kind: i64, id: &str) -> String {
    match kind {
        0 => format!("dm:{id}"),
        1 => format!("group:{id}"),
        2 => format!("topic:{id}"),
        other => format!("kind{other}:{id}"),
    }
}

fn read_facts(path: &Path) -> DbFacts {
    let conn = rusqlite::Connection::open(path).unwrap();
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    let mut master: Vec<(String, String, Option<String>)> = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master WHERE type IN ('table', 'index', 'trigger')",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    master.sort();
    let mut by_scope = BTreeMap::new();
    let scoped: Vec<(i64, String, i64)> = conn
        .prepare("SELECT scope_kind, scope_id, replace_key IS NOT NULL FROM history")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for (kind, id, replaceable) in scoped {
        let entry: &mut (i64, i64) = by_scope.entry(scope_string(kind, &id)).or_default();
        if replaceable != 0 {
            entry.1 += 1;
        } else {
            entry.0 += 1;
        }
    }
    DbFacts {
        schema_version: count("SELECT version FROM schema_version"),
        master,
        rows: count("SELECT COUNT(*) FROM history"),
        durable: count("SELECT COUNT(*) FROM history WHERE replace_key IS NULL"),
        replaceable: count("SELECT COUNT(*) FROM history WHERE replace_key IS NOT NULL"),
        by_scope,
        fts_docs: count("SELECT COUNT(*) FROM history_fts_docsize"),
        canonical: count("SELECT COUNT(*) FROM history_canonical_ids"),
        canonical_dangling: count(
            "SELECT COUNT(*) FROM history_canonical_ids c WHERE NOT EXISTS (\
               SELECT 1 FROM history h WHERE h.msg_id = c.history_msg_id \
               AND h.scope_kind = c.scope_kind AND h.scope_id = c.scope_id)",
        ),
        group_artifact_rows: count(
            "SELECT COUNT(*) FROM history WHERE scope_kind = 1 AND signed_artifact IS NOT NULL",
        ),
    }
}

/// FTS5's own check of the index against the external content table
/// (`rank = 1`: content checked too). Runs on a copy only.
fn fts_integrity(path: &Path) -> rusqlite::Result<()> {
    let conn = rusqlite::Connection::open(path)?;
    conn.execute(
        "INSERT INTO history_fts(history_fts, rank) VALUES('integrity-check', 1)",
        [],
    )?;
    Ok(())
}

/// The schema of the released fixture, read from a copy.
fn fixture_master() -> Vec<(String, String, Option<String>)> {
    let dir = tempfile::tempdir().unwrap();
    read_facts(&copy_fixture(dir.path())).master
}

/// Schema 4, the released schema object for object, and consistent derived
/// indexes: FTS checks clean and holds one document per row, every
/// canonical row points at a row of its scope, and every artifact-bearing
/// group row has its projection.
fn assert_consistent(path: &Path, what: &str) -> DbFacts {
    fts_integrity(path).unwrap_or_else(|e| panic!("{what}: FTS integrity-check failed: {e}"));
    let facts = read_facts(path);
    assert_eq!(facts.schema_version, 4, "{what}: schema version");
    assert_eq!(
        facts.master,
        fixture_master(),
        "{what}: schema objects changed"
    );
    assert_eq!(
        facts.fts_docs, facts.rows,
        "{what}: one FTS document per row"
    );
    assert_eq!(
        facts.canonical_dangling, 0,
        "{what}: dangling canonical rows"
    );
    assert_eq!(
        facts.canonical, facts.group_artifact_rows,
        "{what}: every group public message is projected"
    );
    facts
}

/// The fixture's rows, as the released binary wrote them (PROVENANCE.md).
fn assert_fixture_rows(facts: &DbFacts) {
    assert_eq!((facts.rows, facts.durable, facts.replaceable), (15, 13, 2));
    assert_eq!(facts.canonical, 3, "three group public messages");
    let shapes: Vec<(String, (i64, i64))> = facts
        .by_scope
        .iter()
        .map(|(scope, counts)| (scope.split(':').next().unwrap().to_string(), *counts))
        .collect();
    let mut shapes_sorted = shapes.clone();
    shapes_sorted.sort();
    assert_eq!(
        shapes_sorted,
        vec![
            ("dm".to_string(), (3, 1)),
            ("group".to_string(), (2, 0)),
            ("group".to_string(), (3, 1)),
            ("topic".to_string(), (2, 0)),
            ("topic".to_string(), (3, 0)),
        ],
        "{:?}",
        facts.by_scope
    );
    assert_eq!(facts.by_scope.get("topic:fixture.chat"), Some(&(3, 0)));
    assert_eq!(facts.by_scope.get("topic:fixture.notes"), Some(&(2, 0)));
}

/// The scope id of the fixture's public group (the one with artifacts).
fn public_group_id(path: &Path) -> String {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT scope_id FROM history WHERE scope_kind = 1 AND signed_artifact IS NOT NULL \
             LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// The committed file is the released binary's output, byte for byte.
#[test]
fn v0466_fixture_matches_its_provenance() {
    assert_eq!(sha256_file(&fixture_path()), FIXTURE_SHA256);
    let dir = tempfile::tempdir().unwrap();
    let copy = copy_fixture(dir.path());
    let facts = assert_consistent(&copy, "the released fixture");
    assert_fixture_rows(&facts);
}

/// Upgrade: this version opens the released file. Nothing in the schema
/// changes (no migration, no new object), every row is served, full-text
/// search and canonical lookups work, and the derived indexes stay
/// consistent.
#[test]
fn v0466_fixture_opens_with_current_code_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_fixture(dir.path());
    let canonical: Vec<(Vec<u8>, String)> = rusqlite::Connection::open(&path)
        .unwrap()
        .prepare("SELECT canonical_msg_id, scope_id FROM history_canonical_ids")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(canonical.len(), 3);
    {
        let store = Store::open(&path).unwrap();
        let stats = store.stats().unwrap();
        assert_eq!(
            (stats.rows, stats.durable_rows, stats.replaceable_rows),
            (15, 13, 2)
        );
        let found = store.search("fox", &HistoryQuery::default()).unwrap();
        assert_eq!(found.len(), 1, "FTS serves the released rows");
        assert_eq!(found[0].record.scope, Scope::Topic("fixture.chat".into()));
        assert_eq!(
            store
                .search("fixture", &HistoryQuery::default())
                .unwrap()
                .len(),
            store
                .search("fixture", &HistoryQuery::default())
                .unwrap()
                .iter()
                .filter(|row| row.record.payload.windows(7).any(|w| w == b"fixture"))
                .count(),
        );
        for (id, group) in &canonical {
            let id: [u8; 32] = id.as_slice().try_into().unwrap();
            let row = store.get_by_canonical_group_msg_id(id, group).unwrap();
            assert!(row.is_some(), "canonical lookup serves the released row");
        }
    }
    let facts = assert_consistent(&path, "after opening with this version");
    assert_fixture_rows(&facts);
}

struct FixturePins(Vec<String>);

impl QuarantinePins for FixturePins {
    fn pinned_scopes(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<String>> + Send + '_>> {
        let scopes = self.0.clone();
        Box::pin(async move { scopes })
    }
}

/// Upgrade, then trim under ADR 0116 rules: a Replaceable class budget of
/// one byte, a 31-byte budget on topic prefix `fixture.chat`, and the
/// public group pinned (fork quarantine, ADR 0068). The trim deletes
/// exactly the two oldest chat rows and the agent card. The pinned group
/// keeps all its rows, its group card included. The file stays schema 4
/// with the released schema objects and consistent derived indexes.
#[tokio::test]
async fn v0466_fixture_trims_under_the_new_policy_and_stays_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_fixture(dir.path());
    let group = public_group_id(&path);
    let config = HistoryConfig {
        enabled: true,
        db_path: Some(path.clone()),
        class_limits: vec![ClassLimit {
            class: RetainedClass::Replaceable,
            max_bytes: Some(1),
            max_age_days: None,
        }],
        topic_rules: vec![TopicRule {
            prefix: "fixture.chat".into(),
            recording: TopicRecording::Inherit,
            max_bytes: Some(31),
            max_age_days: None,
        }],
        ..HistoryConfig::default()
    };
    {
        let service = HistoryService::start(&config, dir.path()).unwrap();
        let handle = service.handle();
        assert!(
            handle.install_quarantine_pins(Arc::new(FixturePins(vec![format!("group:{group}")])))
        );
        let report = handle.retain(RetainOptions::default()).await.unwrap();
        assert_eq!(report.deleted, 3, "{report:?}");
        assert_eq!(report.deleted_by_phase.topic_budgets, 2, "{report:?}");
        assert_eq!(report.deleted_by_phase.class_budgets, 1, "{report:?}");
        assert_eq!(report.state, RetainState::Complete, "{report:?}");
        let store = Arc::clone(handle.store());
        let survivors = store.search("retained", &HistoryQuery::default()).unwrap();
        assert_eq!(
            survivors.len(),
            1,
            "the newest chat row survives its 31-byte budget"
        );
        assert!(store
            .search("fox", &HistoryQuery::default())
            .unwrap()
            .is_empty());
        drop(store);
        drop(handle);
        service.shutdown().await;
    }
    let facts = assert_consistent(&path, "after the trim");
    assert_eq!((facts.rows, facts.durable, facts.replaceable), (12, 11, 1));
    assert_eq!(
        facts.by_scope.get(&format!("group:{group}")),
        Some(&(3, 1)),
        "the pinned group keeps every row, its group card included"
    );
    assert_eq!(facts.by_scope.get("topic:fixture.chat"), Some(&(1, 0)));
    assert_eq!(facts.by_scope.get("topic:fixture.notes"), Some(&(2, 0)));
    assert_eq!(facts.canonical, 3);
}

/// Bump a copy's schema version to 5 (as a future binary would) and fold
/// the WAL into the main file, so the copy is a closed, settled database.
/// With `rollback_journal`, also take it out of WAL mode (a future binary
/// might use another journal mode).
fn as_schema_5(path: &Path, rollback_journal: bool) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute("UPDATE schema_version SET version = 5", [])
        .unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    if rollback_journal {
        let mode: String = conn
            .query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "delete");
    }
}

fn dir_listing(dir: &Path) -> Vec<(String, u64)> {
    let mut files: Vec<(String, u64)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let len = entry.metadata().unwrap().len();
            (entry.file_name().to_string_lossy().into_owned(), len)
        })
        .collect();
    files.sort();
    files
}

/// Unknown newer schemas fail closed: this version refuses a schema-5
/// database, through the store and through the service, and leaves the
/// file's bytes unchanged (no migration, no index, no backfill, no header
/// write, no journal-mode change, and no `-wal`/`-shm` left beside it).
#[test]
fn a_newer_wal_schema_fails_closed_and_leaves_the_file_unchanged() {
    assert_newer_schema_fails_closed(false);
}

/// The same for a newer database in rollback-journal mode: opening it must
/// not convert it to WAL before refusing it.
#[test]
fn a_newer_rollback_journal_schema_fails_closed_and_leaves_the_file_unchanged() {
    assert_newer_schema_fails_closed(true);
}

fn assert_newer_schema_fails_closed(rollback_journal: bool) {
    {
        let dir = tempfile::tempdir().unwrap();
        let path = copy_fixture(dir.path());
        as_schema_5(&path, rollback_journal);
        let before = sha256_file(&path);
        let listing = dir_listing(dir.path());
        assert_eq!(listing.len(), 1, "{listing:?}");

        let error = Store::open(&path)
            .expect_err("schema 5 must not open")
            .to_string();
        assert!(error.contains("newer than this binary"), "{error}");
        assert_eq!(
            sha256_file(&path),
            before,
            "the store left the bytes unchanged (rollback journal = {rollback_journal})"
        );
        assert_eq!(dir_listing(dir.path()), listing, "and no side file");

        let config = HistoryConfig {
            enabled: true,
            db_path: Some(path.clone()),
            ..HistoryConfig::default()
        };
        let error = match HistoryService::open(&config, dir.path()) {
            Ok(_) => panic!("the service must not open schema 5"),
            Err(e) => e.to_string(),
        };
        assert!(error.contains("newer than this binary"), "{error}");
        assert_eq!(
            sha256_file(&path),
            before,
            "the service left the bytes unchanged (rollback journal = {rollback_journal})"
        );
        assert_eq!(dir_listing(dir.path()), listing, "and no side file");
    }
}

/// The checks of this file, for any database: run by the scripted
/// downgrade proof (`downgrade_proof.py`) after each step, with
/// `X0X_F_VERIFY_DB=<path>`. It reads a copy and prints the facts as JSON.
#[test]
#[ignore = "run by tests/fixtures/v0466_history_db/downgrade_proof.py"]
fn verify_history_db_from_env() {
    let source = PathBuf::from(
        std::env::var("X0X_F_VERIFY_DB").expect("X0X_F_VERIFY_DB names the database"),
    );
    let dir = tempfile::tempdir().unwrap();
    let path = copy_db(&source, dir.path());
    let facts = assert_consistent(&path, &source.display().to_string());
    let summary = serde_json::json!({
        "db": source.display().to_string(),
        "sha256": sha256_file(&source),
        "schema_version": facts.schema_version,
        "schema_objects_match_v0466": true,
        "rows": facts.rows,
        "durable": facts.durable,
        "replaceable": facts.replaceable,
        "fts_docs": facts.fts_docs,
        "fts_integrity_check": "ok",
        "canonical": facts.canonical,
        "canonical_dangling": facts.canonical_dangling,
        "by_scope": facts
            .by_scope
            .iter()
            .map(|(scope, (d, r))| (scope.clone(), serde_json::json!({"durable": d, "replaceable": r})))
            .collect::<serde_json::Map<String, serde_json::Value>>(),
    });
    println!("X0X_F_VERIFY {summary}");
}

// ── Round 2 (Codex review of slice F) ───────────────────────────────────

/// Every file in `dir`: name, length and sha256. A refused open must leave
/// this exactly as it was: main file, `-wal`, `-shm` and `-journal` alike.
fn all_files(dir: &Path) -> Vec<(String, u64, String)> {
    let mut files: Vec<(String, u64, String)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = std::fs::read(entry.path()).unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                bytes.len() as u64,
                hex::encode(Sha256::digest(&bytes)),
            )
        })
        .collect();
    files.sort();
    files
}

/// A crash copy: a writer commits schema 5 to the WAL of a copy of the
/// fixture, and the database is copied with its live `-wal` and `-shm`
/// before that writer closes (so before any checkpoint). The copy's main
/// file still says schema 4; only its WAL says 5.
fn crash_copy_with_a_live_wal(dir: &Path) -> PathBuf {
    crash_copy_with_a_live_wal_after(dir, "UPDATE schema_version SET version = 5")
}

/// [`crash_copy_with_a_live_wal`], committing `statement` instead.
fn crash_copy_with_a_live_wal_after(dir: &Path, statement: &str) -> PathBuf {
    let work = tempfile::tempdir().unwrap();
    let live = copy_fixture(work.path());
    let writer = rusqlite::Connection::open(&live).unwrap();
    writer
        .execute_batch("PRAGMA wal_autocheckpoint = 0;")
        .unwrap();
    writer.execute(statement, []).unwrap();
    for name in ["history.db", "history.db-wal", "history.db-shm"] {
        let source = work.path().join(name);
        assert!(source.exists(), "the live writer has {name}");
        std::fs::copy(&source, dir.join(name)).unwrap();
    }
    drop(writer);
    let wal = std::fs::metadata(dir.join("history.db-wal")).unwrap().len();
    assert!(wal > 0, "the crash copy's WAL holds the schema-5 commit");
    dir.join("history.db")
}

/// Codex F r1 P2-1: a refused open must not checkpoint a WAL it did not
/// write. Before the fix the closing checkpoint folded the crash copy's
/// schema-5 frame into the main file and deleted the WAL.
#[test]
fn a_refused_newer_schema_leaves_a_crash_wal_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = crash_copy_with_a_live_wal(dir.path());
    let before = all_files(dir.path());
    assert_eq!(before.len(), 3, "{before:?}");

    let error = Store::open(&path)
        .expect_err("schema 5 must not open")
        .to_string();
    assert!(error.contains("newer than this binary"), "{error}");
    assert_eq!(
        all_files(dir.path()),
        before,
        "main, -wal and -shm untouched"
    );

    let config = HistoryConfig {
        enabled: true,
        db_path: Some(path.clone()),
        ..HistoryConfig::default()
    };
    let error = match HistoryService::open(&config, dir.path()) {
        Ok(_) => panic!("the service must not open schema 5"),
        Err(e) => e.to_string(),
    };
    assert!(error.contains("newer than this binary"), "{error}");
    assert_eq!(all_files(dir.path()), before, "and through the service too");
}

/// Codex F r1 P2-2: a version read that fails (here: busy) must stop the
/// open before setup can write. A schema-5 rollback-journal database is
/// locked by another connection, which releases it while the opener is
/// still in its busy wait. Before the fix the failed read counted as "no
/// schema", the next pragma got the freed lock and converted the file to
/// WAL (header bytes 18–19 from [1, 1] to [2, 2]), and only `migrate` then
/// refused it.
#[test]
fn a_busy_newer_schema_is_not_changed_while_the_lock_clears() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy_fixture(dir.path());
    as_schema_5(&path, true);
    let before = all_files(dir.path());
    let header = |path: &Path| std::fs::read(path).unwrap()[18..20].to_vec();
    assert_eq!(header(&path), vec![1, 1], "a rollback-journal file");

    let holder = rusqlite::Connection::open(&path).unwrap();
    holder.execute_batch("BEGIN EXCLUSIVE;").unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let opener = {
        let path = path.clone();
        std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let started = std::time::Instant::now();
            let result =
                Store::open_with_busy_timeout(&path, std::time::Duration::from_millis(100));
            (result.map(|_| ()), started.elapsed())
        })
    };
    started_rx.recv().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(150));
    holder.execute_batch("ROLLBACK;").unwrap();
    drop(holder);
    let (result, elapsed) = opener.join().unwrap();

    let error = result.expect_err("the open must not proceed").to_string();
    assert_eq!(
        header(&path),
        vec![1, 1],
        "not converted to WAL ({error}, {elapsed:?})"
    );
    assert_eq!(
        all_files(dir.path()),
        before,
        "untouched ({error}, {elapsed:?})"
    );
    assert!(error.contains(&path.display().to_string()), "{error}");
}

/// A crash copy with a HOT rollback journal. `prepare` makes the live
/// database (a rollback-journal file); a writer with a one-page cache then
/// runs `spill` in a transaction, so uncommitted pages reach the main file
/// after the journal is synced, and the main file and its `-journal` are
/// copied before that writer rolls back. A read/write open of the copy must
/// roll the journal back first: SQLite recovery.
fn crash_copy_with_a_hot_journal(
    dir: &Path,
    prepare: impl FnOnce(&Path) -> PathBuf,
    spill: &str,
) -> PathBuf {
    let work = tempfile::tempdir().unwrap();
    let live = prepare(work.path());
    let writer = rusqlite::Connection::open(&live).unwrap();
    writer
        .execute_batch("PRAGMA cache_size = 1; PRAGMA cache_spill = ON; BEGIN;")
        .unwrap();
    writer.execute_batch(spill).unwrap();
    for name in ["history.db", "history.db-journal"] {
        let source = work.path().join(name);
        assert!(source.exists(), "the live writer has {name}");
        std::fs::copy(&source, dir.join(name)).unwrap();
    }
    writer.execute_batch("ROLLBACK;").unwrap();
    drop(writer);
    let journal = std::fs::metadata(dir.join("history.db-journal"))
        .unwrap()
        .len();
    assert!(journal > 0, "the crash copy's journal is not empty");
    dir.join("history.db")
}

/// A copy of the fixture in rollback-journal mode, at `version`.
fn fixture_in_rollback_mode(dir: &Path, version: i64) -> PathBuf {
    let path = copy_fixture(dir);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("UPDATE schema_version SET version = ?1", [version])
        .unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode = DELETE", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    path
}

/// Uncommitted payload updates large enough to spill the one-page cache.
const SPILL_PAYLOADS: &str = "UPDATE history SET payload = randomblob(3000);";

/// Round 3, positive control 1 (controller decision C-0116-F1): an
/// interrupted first initialization recovers and opens. The snapshot is a
/// new database's first rollback transaction caught after its journal sync
/// with pages already in the main file, the state an interrupted pre-WAL
/// setup leaves. Store::open lets SQLite roll it back (to an empty file)
/// and then initializes a fresh schema-4 store.
#[test]
fn an_interrupted_first_initialization_recovers_and_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = crash_copy_with_a_hot_journal(
        dir.path(),
        |work| work.join("history.db"),
        "CREATE TABLE schema_version (version INTEGER NOT NULL); \
         INSERT INTO schema_version (version) VALUES (4); \
         CREATE TABLE filler (x BLOB); \
         INSERT INTO filler (x) WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL \
           SELECT i + 1 FROM c WHERE i < 40) SELECT randomblob(3000) FROM c;",
    );
    {
        let store = Store::open(&path).expect("an interrupted initialization recovers and opens");
        assert_eq!(store.stats().unwrap().rows, 0);
    }
    assert!(!dir.path().join("history.db-journal").exists(), "recovered");
    let facts = read_facts(&path);
    assert_eq!(facts.schema_version, 4);
    assert_eq!(facts.master, fixture_master(), "a fresh schema-4 store");
}

/// Round 3, positive control 2: a hot schema-4 database in rollback-journal
/// mode recovers, keeps all 15 released rows and passes SQLite's
/// integrity_check, then opens.
#[test]
fn a_hot_schema_4_rollback_journal_recovers_and_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = crash_copy_with_a_hot_journal(
        dir.path(),
        |work| fixture_in_rollback_mode(work, 4),
        SPILL_PAYLOADS,
    );
    {
        let store = Store::open(&path).expect("a hot schema-4 journal recovers and opens");
        let stats = store.stats().unwrap();
        assert_eq!(
            (stats.rows, stats.durable_rows, stats.replaceable_rows),
            (15, 13, 2)
        );
        let fox = store.search("fox", &HistoryQuery::default()).unwrap();
        assert_eq!(fox.len(), 1, "the original payloads are back");
    }
    assert!(!dir.path().join("history.db-journal").exists(), "recovered");
    let integrity: String = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let facts = assert_consistent(&path, "after recovering a hot schema-4 journal");
    assert_fixture_rows(&facts);
}

/// Round 3, the documented limit (C-0116-F1): a hot rollback journal is
/// recovered first, as SQLite requires, and only then is the schema read.
/// A newer schema behind a hot journal is therefore refused AFTER recovery:
/// the journal is rolled back and gone, and the main file is the settled
/// schema-5 database the crashed transaction started from. (x0x keeps
/// history in WAL mode from first initialization, so a newer history.db can
/// carry a hot journal only during its own pre-WAL initialization, before
/// any version is committed.)
#[test]
fn a_hot_journal_on_a_newer_schema_is_recovered_first_then_refused() {
    let pre_image = tempfile::tempdir().unwrap();
    let settled = fixture_in_rollback_mode(pre_image.path(), 5);
    let settled_sha = sha256_file(&settled);
    let dir = tempfile::tempdir().unwrap();
    let path = crash_copy_with_a_hot_journal(
        dir.path(),
        |work| fixture_in_rollback_mode(work, 5),
        SPILL_PAYLOADS,
    );
    assert_ne!(
        sha256_file(&path),
        settled_sha,
        "the crash copy holds spilled pages"
    );

    let error = Store::open(&path)
        .expect_err("schema 5 must not open")
        .to_string();
    assert!(error.contains("newer than this binary"), "{error}");
    assert!(
        !dir.path().join("history.db-journal").exists(),
        "recovered first"
    );
    let after = all_files(dir.path());
    assert_eq!(after.len(), 1, "{after:?}");
    let conn =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let version: i64 = conn
        .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
        .unwrap();
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM history", [], |r| r.get(0))
        .unwrap();
    assert_eq!((version, integrity.as_str(), rows), (5, "ok", 15));
    drop(conn);
    assert_eq!(
        sha256_file(&path),
        settled_sha,
        "recovery restored the settled schema-5 file exactly"
    );
}

/// Codex F r2 P2-2: a version that does not decode is refused through the
/// schema-read error arm, and that arm must not checkpoint a WAL this open
/// did not write either. The crash copy's WAL holds `version = 'next'`.
#[test]
fn an_undecodable_version_leaves_a_crash_wal_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path =
        crash_copy_with_a_live_wal_after(dir.path(), "UPDATE schema_version SET version = 'next'");
    let before = all_files(dir.path());
    assert_eq!(before.len(), 3, "{before:?}");
    let error = Store::open(&path)
        .expect_err("an unknown version must not open")
        .to_string();
    assert_eq!(
        all_files(dir.path()),
        before,
        "main, -wal and -shm untouched ({error})"
    );
    assert!(error.contains("schema check"), "{error}");
}
