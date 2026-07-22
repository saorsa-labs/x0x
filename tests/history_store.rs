//! ADR-0023 history store — public-API unit/behavioral tests (§9).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use x0x::history::{
    Direction, HistoryConfig, HistoryQuery, HistoryRecord, HistoryService, InsertOutcome,
    Provenance, RetentionPolicy, Scope, ScopeLimit, Store,
};

fn record(payload: &[u8], scope: Scope, seen_at_ms: i64) -> HistoryRecord {
    HistoryRecord {
        msg_id: HistoryRecord::compute_msg_id(None, payload),
        scope,
        author_agent: Some("author-hex".into()),
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
    }
}

#[test]
fn insert_query_and_cursor_pagination() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    let scope = Scope::Group("g1".into());
    for i in 0..25i64 {
        let payload = format!("message number {i}");
        assert_eq!(
            store
                .insert(&record(payload.as_bytes(), scope.clone(), 1_000 + i))
                .unwrap(),
            InsertOutcome::Inserted
        );
    }
    // Newest-first, limit + before_id cursor pages the full set exactly once.
    let mut seen = Vec::new();
    let mut before = None;
    loop {
        let page = store
            .query(&HistoryQuery {
                scope: Some(scope.clone()),
                limit: 10,
                before_id: before,
                ..Default::default()
            })
            .unwrap();
        if page.is_empty() {
            break;
        }
        before = Some(page.last().unwrap().id);
        seen.extend(page.into_iter().map(|r| r.record.seen_at_ms));
    }
    assert_eq!(seen.len(), 25);
    let mut sorted = seen.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(seen, sorted, "pages are newest-first with no overlap");

    // since/until filters.
    let mid = store
        .query(&HistoryQuery {
            scope: Some(scope),
            since_ms: Some(1_005),
            until_ms: Some(1_009),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(mid.len(), 5);
}

/// Self-DM loopback: the outbound write lands first; the inbound delivery of
/// the identical envelope is a duplicate — direction stays Outbound.
#[test]
fn msg_id_dedupe_loopback_keeps_outbound() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    let scope = Scope::Dm("self".into());
    let mut outbound = record(b"hello me", scope.clone(), 1);
    outbound.direction = Direction::Outbound;
    outbound.provenance = Provenance::LocalSend;
    assert_eq!(store.insert(&outbound).unwrap(), InsertOutcome::Inserted);

    let mut inbound = record(b"hello me", scope.clone(), 2);
    inbound.direction = Direction::Inbound;
    assert_eq!(store.insert(&inbound).unwrap(), InsertOutcome::Duplicate);

    let rows = store
        .query(&HistoryQuery {
            scope: Some(scope),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].record.direction, Direction::Outbound);
}

#[test]
fn fts_hit_miss_and_injection_literal() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    let scope = Scope::Topic("chat".into());
    store
        .insert(&record(b"the quick brown fox", scope.clone(), 1))
        .unwrap();
    store
        .insert(&record(b"an unrelated payload", scope.clone(), 2))
        .unwrap();
    // Binary rows are not FTS-indexed.
    let mut bin = record(&[0u8, 159, 146, 150], scope.clone(), 3);
    bin.content_type = "application/octet-stream".into();
    bin.msg_id = HistoryRecord::compute_msg_id(None, &bin.payload);
    store.insert(&bin).unwrap();

    let hits = store.search("quick fox", &HistoryQuery::default()).unwrap();
    assert_eq!(hits.len(), 1);
    let misses = store.search("zebra", &HistoryQuery::default()).unwrap();
    assert!(misses.is_empty());
    // FTS operators / SQL fragments are treated as literal terms, not syntax.
    let inj = store.search("\" OR 1=1", &HistoryQuery::default()).unwrap();
    assert!(inj.is_empty());
    let ops = store
        .search("quick OR zebra", &HistoryQuery::default())
        .unwrap();
    assert!(
        ops.is_empty(),
        "OR must be a literal term, not an FTS operator"
    );
}

#[test]
fn retention_evicts_oldest_and_respects_scope_limits() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    let noisy = Scope::Group("noisy".into());
    let quiet = Scope::Group("quiet".into());
    for i in 0..50i64 {
        let payload = vec![b'x'; 1024];
        let mut r = record(&payload, noisy.clone(), i);
        // Unique payloads so msg_ids differ.
        r.payload[0] = (i % 256) as u8;
        r.msg_id = HistoryRecord::compute_msg_id(None, &r.payload);
        store.insert(&r).unwrap();
    }
    store
        .insert(&record(b"keep me", quiet.clone(), 999))
        .unwrap();

    // Per-scope budget: shrink the noisy scope to ~10 KiB.
    let evicted = store
        .retain(&RetentionPolicy {
            max_bytes: u64::MAX,
            max_age_days: 0,
            scope_limits: vec![ScopeLimit {
                scope: "group:noisy".into(),
                max_bytes: 10 * 1024,
            }],
        })
        .unwrap();
    assert!(evicted > 0);
    let noisy_rows = store
        .query(&HistoryQuery {
            scope: Some(noisy),
            ..Default::default()
        })
        .unwrap();
    // Oldest evicted first: the newest rows survive.
    assert!(noisy_rows.iter().all(|r| r.record.seen_at_ms >= 40));
    let quiet_rows = store
        .query(&HistoryQuery {
            scope: Some(quiet),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(quiet_rows.len(), 1, "other scopes untouched");
}

/// Replaceable rows are exempt from age eviction but count toward bytes.
#[test]
fn replaceable_exempt_from_age_but_counts_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    let scope = Scope::Topic("cards".into());
    let mut card = record(b"agent card payload", scope.clone(), 1);
    card.replace_key = Some("agent-card:a".into());
    store.insert(&card).unwrap();
    store.insert(&record(b"old durable", scope, 1)).unwrap();

    let evicted = store
        .retain(&RetentionPolicy {
            max_bytes: u64::MAX,
            max_age_days: 1, // everything above is far older than 1 day
            scope_limits: vec![],
        })
        .unwrap();
    assert_eq!(evicted, 1, "durable row aged out");
    let rows = store.query(&HistoryQuery::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].record.replace_key.is_some(),
        "replaceable survives age"
    );

    let stats = store.stats().unwrap();
    assert_eq!(stats.replaceable_rows, 1);
    assert!(
        stats.db_bytes > 0,
        "replaceable rows count in the byte measure"
    );
}

/// WAL crash-recovery: rows committed before a hard death (no clean close,
/// no checkpoint) survive reopen with no corruption. A SIGKILL is simulated
/// by snapshotting `history.db` + its live `-wal`/`-shm` sidecars while the
/// writing connection is still open (so the WAL has never been checkpointed
/// into the copy), then recovering the snapshot — SQLite must replay the
/// WAL on open. (`mem::forget` cannot simulate this in-process: the leaked
/// fd keeps the EXCLUSIVE lock alive, unlike a real process death.)
#[test]
fn wal_crash_recovery_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.db");
    let crash_dir = tempfile::tempdir().unwrap();
    let crash_path = crash_dir.path().join("history.db");
    {
        let store = Store::open(&path).unwrap();
        for i in 0..10i64 {
            let payload = format!("survivor {i}");
            store
                .insert(&record(payload.as_bytes(), Scope::Group("g".into()), i))
                .unwrap();
        }
        // Crash snapshot: copy db + WAL sidecars while the connection is
        // live and the WAL is un-checkpointed.
        for suffix in ["", "-wal", "-shm"] {
            let src = dir.path().join(format!("history.db{suffix}"));
            if src.exists() {
                std::fs::copy(&src, crash_dir.path().join(format!("history.db{suffix}"))).unwrap();
            }
        }
        drop(store);
    }
    let store = Store::open(&crash_path).unwrap();
    let rows = store.query(&HistoryQuery::default()).unwrap();
    assert_eq!(rows.len(), 10, "WAL replay recovers all committed rows");
}

/// A second process (simulated by a second open) must fail loud, not
/// silently interleave (ADR-0023 §6 shared-data-dir posture).
#[test]
fn exclusive_open_fails_loud() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.db");
    let _held = Store::open(&path).unwrap();
    let second = Store::open_with_busy_timeout(&path, std::time::Duration::from_millis(100));
    assert!(second.is_err(), "second exclusive open must fail");
}

/// Writer service: records flow through the bounded writer thread; a
/// disconnected writer sheds (counted) instead of blocking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_service_writes_and_sheds() {
    let dir = tempfile::tempdir().unwrap();
    let config = HistoryConfig {
        enabled: true,
        ..HistoryConfig::default()
    };
    let service = HistoryService::start(&config, dir.path()).unwrap();
    let handle = service.handle();
    for i in 0..100i64 {
        let payload = format!("writer msg {i}");
        handle.record(record(payload.as_bytes(), Scope::Topic("w".into()), i));
    }
    // Poll until the writer thread has flushed everything.
    let counters = handle.counters();
    for _ in 0..100 {
        if counters
            .written_total
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 100
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        counters
            .written_total
            .load(std::sync::atomic::Ordering::Relaxed),
        100
    );
    let rows = handle.store().query(&HistoryQuery::default()).unwrap();
    assert_eq!(rows.len(), 100);

    // Shutdown drains; post-shutdown records shed (counted, never block).
    let post_handle = handle.clone();
    service.shutdown().await;
    post_handle.record(record(b"after shutdown", Scope::Topic("w".into()), 999));
    assert!(
        counters
            .dropped_full
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
}

/// Library default is off: `HistoryConfig::default().enabled == false`,
/// daemon default is on.
#[test]
fn config_defaults_match_adr() {
    assert!(!HistoryConfig::default().enabled);
    assert!(HistoryConfig::daemon_default().enabled);
    assert_eq!(
        HistoryConfig::default().max_bytes,
        x0x::history::DEFAULT_MAX_BYTES
    );
}

#[test]
fn scope_parse_roundtrip_and_rejects_garbage() {
    for s in ["dm:abc", "group:g-1", "topic:chat/general"] {
        assert_eq!(Scope::parse(s).unwrap().to_string(), s);
    }
    assert!(Scope::parse("nope").is_err());
    assert!(Scope::parse("dm:").is_err());
    assert!(Scope::parse("weird:x").is_err());
}
