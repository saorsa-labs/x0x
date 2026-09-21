//! ADR-0068 D1 — the retention reaper pins fork-quarantined history scopes,
//! subject to a per-group ceiling.
//!
//! WHY this row exists at all, since ADR-0066 never enumerated it: R3 makes
//! history ingest tag-and-retain ("never refused") and slice 4 refuses the
//! explicit purge (row 14) because "a missed marker is not a degraded answer,
//! it is a deletion of the forensic record row 14 exists to protect". The
//! reaper was the same deletion through another door, and a *drivable* one — a
//! flooder raises byte pressure and the node does the deleting.
//!
//! What each test defends:
//!
//! - a quarantined scope survives a pass that evicts an **equally old** healthy
//!   scope, which is the only comparison that proves pinning rather than luck;
//! - the ceiling is enforced, and enforced INSIDE the pinned group only, with
//!   the eviction counted;
//! - a healthy group keeps its own bounds while a quarantined group floods, so
//!   the pin never redirects pressure onto a third party;
//! - an **alias-keyed** group (map key ≠ `stable_group_id()`, rows under the
//!   stable id) is pinned — the defect class review found three times in
//!   slices 3, 4 and 6 — with the pin source proven to list both spellings;
//! - after the marker clears, the next pass evicts normally, so the pin is a
//!   hold and not a leak;
//! - and the NEGATIVE CONTROL: the same fixture with nothing pinned destroys
//!   the same rows. Without it "the rows survived" could mean the pass never
//!   evicted anything.
//!
//! Deterministic: every row carries an explicit `seen_at_ms`, so age eviction
//! is decided by arithmetic, not by a sleep.

use super::*;

use x0x::history::{
    Direction, HistoryQuery, HistoryRecord, PinnedScopes, Provenance, RetentionPolicy, Scope,
    ScopeLimit, Store,
};

/// One durable inbound row of `bytes` bytes in `scope`, stamped `seen_at_ms`.
/// `nonce` keeps `msg_id` unique so inserts are not collapsed by dedupe.
fn row(scope: Scope, seen_at_ms: i64, bytes: usize, nonce: u64) -> HistoryRecord {
    let mut payload = vec![b'x'; bytes];
    let tag = nonce.to_be_bytes();
    payload[..tag.len().min(bytes)].copy_from_slice(&tag[..tag.len().min(bytes)]);
    HistoryRecord {
        msg_id: HistoryRecord::compute_msg_id(None, &payload),
        scope,
        author_agent: Some("adr0068-author".into()),
        author_machine: None,
        author_pubkey: None,
        sent_at_ms: seen_at_ms,
        seen_at_ms,
        direction: Direction::Inbound,
        content_type: "text/plain".into(),
        payload,
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

fn open_store(dir: &std::path::Path) -> Result<Store> {
    Ok(Store::open(&dir.join("history.db"))?)
}

fn rows_in(store: &Store, scope: &Scope) -> Result<usize> {
    Ok(store
        .query(&HistoryQuery {
            scope: Some(scope.clone()),
            ..Default::default()
        })?
        .len())
}

/// Age eviction with a 1-day bound: every row below is stamped at epoch, so it
/// is unambiguously older than the cutoff without any test sleeping.
fn age_policy() -> RetentionPolicy {
    RetentionPolicy {
        max_bytes: u64::MAX,
        max_age_days: 1,
        scope_limits: Vec::new(),
    }
}

/// The pinned scope survives an age pass that destroys an equally old healthy
/// scope — and the negative control (nothing pinned) destroys both, which is
/// what makes this test able to fail.
#[test]
fn adr0068_d1_pinned_scope_survives_an_age_pass_that_evicts_an_equally_old_healthy_scope(
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = open_store(dir.path())?;
    let quarantined = Scope::Group("contested".into());
    let healthy = Scope::Group("healthy".into());
    // Same timestamp for both: the ONLY difference between them is the pin.
    store.insert(&row(quarantined.clone(), 1, 64, 1))?;
    store.insert(&row(healthy.clone(), 1, 64, 2))?;

    let pinned = PinnedScopes::from_canonical([quarantined.canonical()]);
    let outcome = store.retain_with_pins(&age_policy(), &pinned)?;

    assert_eq!(outcome.evicted, 1, "exactly the healthy row aged out");
    assert_eq!(outcome.pinned_scopes, 1);
    assert_eq!(
        outcome.pinned_evicted, 0,
        "the pinned scope is far below its ceiling, so nothing was shed inside it"
    );
    assert_eq!(rows_in(&store, &quarantined)?, 1, "forensic record kept");
    assert_eq!(rows_in(&store, &healthy)?, 0, "healthy scope aged out");

    // NEGATIVE CONTROL: same store, same policy, nothing pinned. If this
    // passed, the assertions above would prove nothing about pinning.
    let control_dir = tempfile::tempdir()?;
    let control = open_store(control_dir.path())?;
    control.insert(&row(quarantined.clone(), 1, 64, 1))?;
    control.insert(&row(healthy.clone(), 1, 64, 2))?;
    let control_outcome = control.retain_with_pins(&age_policy(), &PinnedScopes::none())?;
    assert_eq!(control_outcome.evicted, 2, "control: BOTH rows age out");
    assert_eq!(
        rows_in(&control, &quarantined)?,
        0,
        "control: the same forensic row is destroyed when the scope is not pinned — \
         this is the gap ADR-0068 D1 closes"
    );
    Ok(())
}

/// The pinned ceiling is enforced, oldest-first, INSIDE the pinned group only,
/// and the eviction is counted separately from ordinary eviction.
#[test]
fn adr0068_d1_ceiling_is_enforced_within_the_pinned_group_and_counted() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = open_store(dir.path())?;
    let quarantined = Scope::Group("contested".into());
    let healthy = Scope::Group("healthy".into());

    // An explicit per-scope limit makes the ceiling exactly
    // 4 × 1 KiB = 4 KiB (the absolute cap is far above it here), so the
    // arithmetic in the assertions is the ADR's formula, not a guess.
    let policy = RetentionPolicy {
        max_bytes: u64::MAX,
        max_age_days: 0,
        scope_limits: vec![
            ScopeLimit {
                scope: quarantined.canonical(),
                max_bytes: 1024,
            },
            ScopeLimit {
                scope: healthy.canonical(),
                max_bytes: 1024,
            },
        ],
    };
    assert_eq!(
        Store::pinned_ceiling(&policy, &quarantined),
        4096,
        "4 × the configured per-scope bound"
    );

    // 10 KiB in each scope, in 1 KiB rows, ascending in age.
    for i in 0..10u64 {
        store.insert(&row(quarantined.clone(), 100 + i as i64, 1024, i))?;
        store.insert(&row(healthy.clone(), 100 + i as i64, 1024, 100 + i))?;
    }

    let pinned = PinnedScopes::from_canonical([quarantined.canonical()]);
    let outcome = store.retain_with_pins(&policy, &pinned)?;

    // The pinned scope is shrunk to its CEILING (4 KiB), the healthy one to
    // its ordinary bound (1 KiB): the pin raises the bound, it does not remove
    // it, and it does not touch the other scope's bound.
    let kept_quarantined = rows_in(&store, &quarantined)?;
    let kept_healthy = rows_in(&store, &healthy)?;
    assert!(
        (4..=5).contains(&kept_quarantined),
        "pinned scope held to ~4 KiB, kept {kept_quarantined} rows"
    );
    // The ordinary per-scope phase deletes a whole RETAIN_EVICT_BATCH (256
    // rows) per step, so a 10-row scope over its budget loses all ten. That
    // coarseness is pre-existing and deliberately left alone; the PINNED phase
    // is the one that must not overshoot, because it is bounding a forensic
    // record rather than a cache.
    assert_eq!(
        kept_healthy, 0,
        "pre-existing coarse per-scope eviction: the healthy scope's own bound \
         takes it to zero, and the pin is what stops that happening to the \
         quarantined scope"
    );
    assert_eq!(
        outcome.pinned_evicted,
        (10 - kept_quarantined) as u64,
        "every row shed inside the pinned scope is counted as a pinned eviction"
    );
    assert!(
        outcome.evicted > outcome.pinned_evicted,
        "the healthy scope's evictions are counted too, but not as pinned ones"
    );

    // Oldest-first, within the group: the newest rows are the survivors.
    let survivors = store.query(&HistoryQuery {
        scope: Some(quarantined),
        ..Default::default()
    })?;
    assert!(
        survivors.iter().all(|r| r.record.seen_at_ms >= 105),
        "oldest rows are the ones shed at the ceiling"
    );
    Ok(())
}

/// A quarantined group flooding its own scope does not touch a healthy scope:
/// the overshoot is charged to the flooder's own ceiling and to nobody else.
///
/// The control is the same policy with NO pin: the flooder's ordinary per-scope
/// bound then takes its whole record, which is both the gap D1 closes and the
/// proof that the surviving rows above are the ceiling's work.
#[test]
fn adr0068_d1_a_quarantined_flood_is_charged_to_its_own_ceiling_only() -> Result<()> {
    let quarantined = Scope::Group("flooder".into());
    let healthy = Scope::Group("bystander".into());
    // max_bytes is above the store's high-water mark (FTS roughly quadruples
    // the payload bytes on disk), so the whole-database phase never fires and
    // the only thing acting is the flooder's ceiling:
    // min(4 × 64 KiB, 64 MiB/16) = 256 KiB ⇒ 32 of its 8 KiB rows.
    let policy = RetentionPolicy {
        max_bytes: 64 * 1024 * 1024,
        max_age_days: 0,
        scope_limits: vec![ScopeLimit {
            scope: quarantined.canonical(),
            max_bytes: 64 * 1024,
        }],
    };
    assert_eq!(
        Store::pinned_ceiling(&policy, &quarantined),
        256 * 1024,
        "the ADR's formula: 4 × the configured per-scope bound, under the cap"
    );
    let seed = |store: &Store| -> Result<()> {
        store.insert(&row(healthy.clone(), 1, 512, 0))?;
        for i in 0..256u64 {
            store.insert(&row(quarantined.clone(), 10 + i as i64, 8192, i + 1))?;
        }
        Ok(())
    };

    let dir = tempfile::tempdir()?;
    let store = open_store(dir.path())?;
    seed(&store)?;
    let pinned = PinnedScopes::from_canonical([quarantined.canonical()]);
    let outcome = store.retain_with_pins(&policy, &pinned)?;

    assert_eq!(
        rows_in(&store, &healthy)?,
        1,
        "the bystander's row is NOT evicted to pay for the flooder's overshoot"
    );
    let flooder_rows = rows_in(&store, &quarantined)?;
    assert!(
        (32..=33).contains(&flooder_rows),
        "the flooder burned its OWN ceiling (256 KiB in 8 KiB rows): \
         {flooder_rows} rows left"
    );
    assert_eq!(
        outcome.pinned_evicted,
        (256 - flooder_rows) as u64,
        "every one of those evictions is booked to the pinned scope"
    );
    assert_eq!(
        outcome.evicted, outcome.pinned_evicted,
        "nothing outside the pinned scope was evicted at all"
    );

    // CONTROL: same policy, nothing pinned ⇒ the ordinary per-scope bound
    // applies and the forensic record is destroyed.
    let control_dir = tempfile::tempdir()?;
    let control = open_store(control_dir.path())?;
    seed(&control)?;
    let control_outcome = control.retain_with_pins(&policy, &PinnedScopes::none())?;
    assert_eq!(
        rows_in(&control, &quarantined)?,
        0,
        "control: unpinned, the quarantined scope keeps NOTHING — the pin is \
         what turns its bound into a 4× ceiling"
    );
    assert_eq!(control_outcome.pinned_evicted, 0);
    assert_eq!(
        rows_in(&control, &healthy)?,
        1,
        "the bystander is fine either way"
    );
    Ok(())
}

/// Under whole-database pressure the pinned rows survive and the UNPINNED rows
/// are evicted exactly as they were before ADR-0068.
///
/// This is the honest other half of the pin: it protects the quarantined scope,
/// it does not suspend the global budget for everyone else. The measurement the
/// global phase uses is the database's PAGE count, which SQLite does not return
/// promptly after a delete, so a store that has once exceeded its budget keeps
/// evicting whatever it is still allowed to reach — pre-existing behaviour,
/// unchanged here except that pinned rows are now out of reach.
#[test]
fn adr0068_d1_global_pressure_still_evicts_unpinned_rows_as_before() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = open_store(dir.path())?;
    let quarantined = Scope::Group("contested".into());
    let healthy = Scope::Group("ordinary".into());
    store.insert(&row(quarantined.clone(), 1, 4096, 1))?;
    store.insert(&row(healthy.clone(), 2, 4096, 2))?;
    // Far below the file's size, so the global phase evicts everything it can.
    let policy = RetentionPolicy {
        max_bytes: 1024,
        max_age_days: 0,
        scope_limits: Vec::new(),
    };

    let pinned = PinnedScopes::from_canonical([quarantined.canonical()]);
    let outcome = store.retain_with_pins(&policy, &pinned)?;

    assert_eq!(
        rows_in(&store, &quarantined)?,
        1,
        "the forensic record survives the global phase"
    );
    assert_eq!(
        rows_in(&store, &healthy)?,
        0,
        "the unpinned scope is evicted exactly as it was before ADR-0068"
    );
    assert!(outcome.evicted >= 1);

    // CONTROL: no pin ⇒ the forensic row goes too, which is the gap D1 closes.
    let control_dir = tempfile::tempdir()?;
    let control = open_store(control_dir.path())?;
    control.insert(&row(quarantined.clone(), 1, 4096, 1))?;
    control.insert(&row(healthy.clone(), 2, 4096, 2))?;
    let _ = control.retain_with_pins(&policy, &PinnedScopes::none())?;
    assert_eq!(
        rows_in(&control, &quarantined)?,
        0,
        "control: unpinned, the quarantined scope's rows are destroyed by byte pressure"
    );
    Ok(())
}

/// Clearing the marker returns the scope to normal retention on the next pass.
/// The pin is a hold, not a leak.
#[test]
fn adr0068_d1_after_clear_the_next_pass_evicts_normally() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = open_store(dir.path())?;
    let scope = Scope::Group("contested".into());
    store.insert(&row(scope.clone(), 1, 64, 1))?;

    let pinned = PinnedScopes::from_canonical([scope.canonical()]);
    assert_eq!(store.retain_with_pins(&age_policy(), &pinned)?.evicted, 0);
    assert_eq!(rows_in(&store, &scope)?, 1, "pinned across the first pass");

    // Marker cleared ⇒ the derived pin set is empty on the next pass.
    let outcome = store.retain_with_pins(&age_policy(), &PinnedScopes::none())?;
    assert_eq!(outcome.evicted, 1, "the aged row is evicted once unpinned");
    assert_eq!(outcome.pinned_scopes, 0);
    assert_eq!(rows_in(&store, &scope)?, 0);
    Ok(())
}

/// The ADR's ceiling formula, at the shipped defaults and at the cap.
#[test]
fn adr0068_d1_ceiling_formula_matches_the_adr() {
    let scope = Scope::Group("g".into());
    let default_policy = RetentionPolicy {
        max_bytes: x0x::history::DEFAULT_MAX_BYTES,
        max_age_days: 0,
        scope_limits: Vec::new(),
    };
    // Unconfigured scope at the 1 GiB default: base = 1 GiB/64 = 16 MiB,
    // ceiling = 4 × 16 MiB = 64 MiB = 1 GiB/16 — the two arms coincide, which
    // is the intended common case.
    assert_eq!(
        Store::pinned_ceiling(&default_policy, &scope),
        64 * 1024 * 1024
    );
    // A large explicit limit is capped rather than multiplied without bound.
    let generous = RetentionPolicy {
        scope_limits: vec![ScopeLimit {
            scope: scope.canonical(),
            max_bytes: 512 * 1024 * 1024,
        }],
        ..default_policy
    };
    assert_eq!(
        Store::pinned_ceiling(&generous, &scope),
        64 * 1024 * 1024,
        "the absolute cap (max_bytes/16) bites before 4 × a 512 MiB limit does"
    );
}

/// The alias-key regression, end to end: a group filed under a map key that is
/// NOT its stable id, with its rows under the stable id, is pinned — because
/// the pin source lists BOTH spellings.
///
/// This is the test that would have caught the slice 3/4/6 defect class in this
/// mechanism: a source that published only the map key would leave the rows
/// (which carry the stable id) completely unprotected.
#[tokio::test]
async fn adr0068_d1_alias_keyed_group_is_pinned_under_its_stable_id() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let stable = "adr0068-stable-id";
    let alias = "adr0068-alias-key";
    let mut info = x0x::groups::GroupInfo::new(
        "adr0068".to_string(),
        "D1 alias fixture".to_string(),
        state.agent.agent_id(),
        stable.to_string(),
    );
    let header = info.terminal_commit_header();
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: 7,
        state_hash: "cafe0007".to_string(),
        committed_by: "11".repeat(32),
        observed_at_ms: 1_700_000_000_000,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: header.clone(),
            conflicting_commit: header,
            classification: None,
        },
        no_anchor: true,
    });
    assert_ne!(
        info.stable_group_id(),
        alias,
        "the fixture is only meaningful if the map key differs from the stable id"
    );
    state
        .named_groups
        .write()
        .await
        .insert(alias.to_string(), info);

    // The pin source, exactly as the reaper consumes it.
    let scopes: Vec<String> = crate::server::routes::history::all_quarantine_markers(&state)
        .await
        .into_iter()
        .map(|(scope, _)| scope)
        .collect();
    assert!(
        scopes.contains(&format!("group:{stable}")),
        "the STABLE id — the spelling history rows carry — must be pinned: {scopes:?}"
    );
    assert!(
        scopes.contains(&format!("group:{alias}")),
        "the map key is pinned too, so a row written under the alias is covered: {scopes:?}"
    );

    // And the pin actually protects the rows, which live under the stable id.
    let dir = tempfile::tempdir()?;
    let store = open_store(dir.path())?;
    let stable_scope = Scope::Group(stable.to_string());
    store.insert(&row(stable_scope.clone(), 1, 64, 1))?;
    let pinned = PinnedScopes::from_canonical(scopes);
    assert_eq!(store.retain_with_pins(&age_policy(), &pinned)?.evicted, 0);
    assert_eq!(rows_in(&store, &stable_scope)?, 1);

    // NEGATIVE CONTROL: the single-spelling source the gate must not be — map
    // key only. The rows are under the stable id, so nothing is pinned.
    let alias_only = PinnedScopes::from_canonical([format!("group:{alias}")]);
    assert_eq!(
        store.retain_with_pins(&age_policy(), &alias_only)?.evicted,
        1,
        "control: a map-key-only pin source leaves the forensic rows exposed"
    );
    Ok(())
}
