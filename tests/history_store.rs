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
        thread_root: None,
        thread_parent: None,
        ingress_sender_agent: None,
        logical_request_id: None,
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
fn native_channel_message_json_searches_only_its_text_projection() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    let scope = Scope::Dm("peer-agent".into());
    let payload = br#"{"text":"e2e-ui-dm-search-marker","createdAt":1786379111246,"clientId":"metadata-must-not-be-indexed","mentions":["peer-agent"]}"#;
    let mut channel_message = record(payload, scope.clone(), 1);
    channel_message.content_type = "application/json".into();

    assert_eq!(
        store.insert(&channel_message).unwrap(),
        InsertOutcome::Inserted
    );

    let hits = store
        .search(
            "e2e-ui-dm-search-marker",
            &HistoryQuery {
                scope: Some(scope),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].record.content_type, "application/json");
    assert_eq!(hits[0].record.payload, payload);
    assert!(
        store
            .search("metadata-must-not-be-indexed", &HistoryQuery::default())
            .unwrap()
            .is_empty(),
        "FTS must index the human text field, not the full JSON envelope"
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

/// The schema v4 ingress columns are two halves of one authenticated fact:
/// which transport peer delivered the row, and which logical request bound
/// it. Recording a sender with no request id (or vice versa) would let a
/// future durable-ingress writer persist a binding nothing can be checked
/// against, so `validate` rejects the half-set pair at the store boundary.
#[test]
fn ingress_sender_and_logical_request_id_must_be_set_together() {
    let scope = Scope::Dm("peer".into());
    let base = record(b"typed ingress row", scope, 1_000);

    let mut sender_only = base.clone();
    sender_only.ingress_sender_agent = Some("aa".repeat(32));
    let err = sender_only.validate().unwrap_err().to_string();
    assert!(
        err.contains("must be set together"),
        "sender without logical request id must be rejected, got: {err}"
    );

    let mut request_only = base.clone();
    request_only.logical_request_id = Some([0x31; 16]);
    assert!(
        request_only.validate().is_err(),
        "logical request id without a sender must be rejected"
    );

    let mut both = base.clone();
    both.ingress_sender_agent = Some("aa".repeat(32));
    both.logical_request_id = Some([0x31; 16]);
    both.validate().expect("a fully bound pair is valid");

    // Neither set is the normal case for every row main writes today.
    base.validate().expect("an unbound record is valid");
}

/// The store applies the same rule, so a half-set pair cannot reach SQLite
/// even if a caller skips `validate` itself.
#[test]
fn insert_rejects_half_set_ingress_binding() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    let mut r = record(b"half bound row", Scope::Dm("peer".into()), 1_000);
    r.ingress_sender_agent = Some("aa".repeat(32));
    assert!(store.insert(&r).is_err());
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

// ─── Issue #275: cross-scope search + scope discovery ───────────────────

/// Seed three scopes that share the needle so a cross-scope search has
/// something to merge and a scoped search has something to exclude.
fn seed_cross_scope(store: &Store) {
    for (scope, seen) in [
        (Scope::Dm("peer-a".into()), 1_000),
        (Scope::Group("g-1".into()), 2_000),
        (Scope::Topic("chat".into()), 3_000),
    ] {
        let payload = format!("needle in {scope}");
        store
            .insert(&record(payload.as_bytes(), scope, seen))
            .unwrap();
    }
}

/// WHY (issue #275): the whole point of relaxing `scope` on
/// `/history/search` is that a caller who does not yet know a scope string
/// can still find their own rows. If a scope-less query silently kept a
/// filter, discovery would be impossible; if a scoped query stopped
/// filtering, the existing per-scope contract would leak rows.
#[test]
fn search_without_scope_spans_scopes_and_with_scope_stays_a_subset() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    seed_cross_scope(&store);

    let all = store.search("needle", &HistoryQuery::default()).unwrap();
    assert_eq!(all.len(), 3, "scope-less search must span every scope");
    let mut kinds: Vec<i64> = all.iter().map(|r| r.record.scope.kind()).collect();
    kinds.sort_unstable();
    assert_eq!(kinds, vec![0, 1, 2], "one hit per scope kind");
    assert!(
        all.windows(2).all(|w| w[0].id > w[1].id),
        "cross-scope results keep the newest-rowid-first order"
    );

    let scoped = store
        .search(
            "needle",
            &HistoryQuery {
                scope: Some(Scope::Group("g-1".into())),
                ..HistoryQuery::default()
            },
        )
        .unwrap();
    assert_eq!(scoped.len(), 1, "scoped search still filters");
    assert_eq!(scoped[0].record.scope, Scope::Group("g-1".into()));
}

/// WHY (issue #275): cross-scope search is only usable if it pages. The
/// rowid keyset must walk every matching row exactly once — a page boundary
/// that repeats or drops a row would make "search all my history" quietly
/// lossy, and rowids are globally unique so the cursor cannot depend on
/// which scope the previous page ended in.
#[test]
fn cross_scope_search_pages_by_rowid_without_gaps_or_repeats() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    // Interleave scopes so consecutive rowids cross scope boundaries.
    let scopes = [
        Scope::Dm("peer-a".into()),
        Scope::Group("g-1".into()),
        Scope::Topic("chat".into()),
    ];
    for n in 0..9_i64 {
        let payload = format!("needle row {n:02}");
        store
            .insert(&record(
                payload.as_bytes(),
                scopes[n as usize % scopes.len()].clone(),
                1_000 + n,
            ))
            .unwrap();
    }

    let mut seen_ids = Vec::new();
    let mut before_id = None;
    loop {
        let page = store
            .search(
                "needle",
                &HistoryQuery {
                    limit: 2,
                    before_id,
                    ..HistoryQuery::default()
                },
            )
            .unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 2, "limit is honored on the search path");
        before_id = page.last().map(|r| r.id);
        seen_ids.extend(page.into_iter().map(|r| r.id));
    }
    let mut deduped = seen_ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(seen_ids.len(), 9, "every matching row is visited");
    assert_eq!(deduped.len(), 9, "no row is served twice across pages");
    assert!(
        seen_ids.windows(2).all(|w| w[0] > w[1]),
        "paging stays strictly descending by rowid"
    );
}

/// WHY (issue #275): the enumeration cursor is `(scope_kind, scope_id)`.
/// Scope ids are only unique WITHIN a kind, so `dm:same` and `group:same`
/// are two distinct rows that must both appear — a cursor keyed on the id
/// alone would swallow one. Ordering must not depend on time either, so
/// identical `seen_at_ms` across scopes cannot perturb it.
#[test]
fn scopes_enumerate_equal_ids_across_kinds_and_ignore_equal_timestamps() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    for (scope, body) in [
        (Scope::Dm("same".into()), "dm body"),
        (Scope::Group("same".into()), "group body"),
        (Scope::Topic("same".into()), "topic body"),
    ] {
        // Identical seen_at_ms in all three scopes.
        store
            .insert(&record(body.as_bytes(), scope, 7_777))
            .unwrap();
    }

    let all = store.scopes(None, 0).unwrap();
    assert_eq!(
        all.iter().map(|s| s.scope.canonical()).collect::<Vec<_>>(),
        vec!["dm:same", "group:same", "topic:same"],
        "ordering is (scope_kind, scope_id) ascending, not time"
    );
    assert!(all
        .iter()
        .all(|s| s.rows == 1 && s.newest_seen_at_ms == 7_777));

    // Walk it one page at a time through the canonical cursor.
    let mut walked = Vec::new();
    let mut after = None;
    loop {
        let page = store.scopes(after.as_ref(), 1).unwrap();
        let Some(last) = page.last() else { break };
        after = Some(last.scope.clone());
        walked.extend(page.into_iter().map(|s| s.scope.canonical()));
    }
    assert_eq!(
        walked,
        vec!["dm:same", "group:same", "topic:same"],
        "keyset paging visits each (kind, id) exactly once"
    );
}

/// WHY (issue #275): the enumeration is aggregated from the CURRENT rows,
/// not from a scope registry. That is what makes it honest after deletion —
/// a purged scope must vanish rather than linger with a stale count, and a
/// retention eviction must lower the count it reports.
#[test]
fn scope_counts_track_purge_and_retention_of_retained_rows() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    for n in 0..3_i64 {
        store
            .insert(&record(
                format!("kept {n}").as_bytes(),
                Scope::Group("keep".into()),
                1_000 + n,
            ))
            .unwrap();
    }
    store
        .insert(&record(b"doomed", Scope::Dm("gone".into()), 5_000))
        .unwrap();

    let before: Vec<_> = store
        .scopes(None, 0)
        .unwrap()
        .into_iter()
        .map(|s| (s.scope.canonical(), s.rows))
        .collect();
    assert_eq!(
        before,
        vec![("dm:gone".to_string(), 1), ("group:keep".to_string(), 3)]
    );

    assert_eq!(store.purge(&Scope::Dm("gone".into())).unwrap(), 1);
    let after_purge: Vec<_> = store
        .scopes(None, 0)
        .unwrap()
        .into_iter()
        .map(|s| s.scope.canonical())
        .collect();
    assert_eq!(
        after_purge,
        vec!["group:keep".to_string()],
        "a scope with no retained rows leaves the enumeration entirely"
    );

    // Age retention: the three seeded rows are epoch-old, so a 1-day bound
    // evicts exactly them and leaves the two fresh ones behind.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    for n in 0..2_i64 {
        store
            .insert(&record(
                format!("fresh {n}").as_bytes(),
                Scope::Group("keep".into()),
                now_ms + n,
            ))
            .unwrap();
    }
    assert_eq!(
        store
            .retain(&RetentionPolicy {
                max_bytes: u64::MAX,
                max_age_days: 1,
                scope_limits: Vec::new(),
            })
            .unwrap(),
        3,
        "only the epoch-old rows age out"
    );
    let survivors = store.scopes(None, 0).unwrap();
    let kept = survivors
        .iter()
        .find(|s| s.scope == Scope::Group("keep".into()))
        .expect("scope still has rows");
    assert_eq!(kept.rows, 2, "the count reports retained rows only");
    assert_eq!(
        kept.newest_seen_at_ms,
        now_ms + 1,
        "the reported timestamp is the newest RETAINED row, not the evicted history"
    );
}

/// WHY (issue #275): the limit is caller-supplied and must be bounded by
/// the same convention the rest of the history read surface uses (0 ⇒ 100,
/// clamped to MAX_QUERY_LIMIT) — an unbounded page would let one request
/// materialize the entire scope space.
#[test]
fn scope_limit_defaults_to_100_and_clamps_to_max_query_limit() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    for n in 0..120_i64 {
        store
            .insert(&record(
                format!("row {n}").as_bytes(),
                Scope::Topic(format!("t-{n:04}")),
                1_000 + n,
            ))
            .unwrap();
    }
    assert_eq!(store.scopes(None, 0).unwrap().len(), 100, "0 ⇒ default 100");
    assert_eq!(store.scopes(None, 5).unwrap().len(), 5);
    assert_eq!(
        store.scopes(None, usize::MAX).unwrap().len(),
        120,
        "an absurd limit is clamped, never rejected or unbounded"
    );
}

/// WHY (issue #275): callers hit these two edges first — an install with no
/// history at all, and a cursor pointing past the last scope. Both must be
/// an empty page, not an error and not a wrap-around to the first scope.
#[test]
fn scopes_on_empty_store_and_past_the_end_cursor_are_empty_pages() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("history.db")).unwrap();
    assert!(store.scopes(None, 0).unwrap().is_empty());

    store
        .insert(&record(b"only row", Scope::Dm("solo".into()), 1_000))
        .unwrap();
    assert_eq!(store.scopes(None, 0).unwrap().len(), 1);
    assert!(
        store
            .scopes(Some(&Scope::Topic("zzzz".into())), 0)
            .unwrap()
            .is_empty(),
        "a cursor past the last (kind, id) yields nothing, not the first page"
    );
    assert!(
        store
            .scopes(Some(&Scope::Dm("solo".into())), 0)
            .unwrap()
            .is_empty(),
        "the cursor is exclusive — the scope it names is not repeated"
    );
}
