//! #1239: the share-grant evaluation's candidates snapshot is a
//! ShareGrantStore std-RwLock read; it must run on a bounded blocking
//! worker, and contention past the read budget must fail closed with
//! `Err(())` while the store is still held (Greptile P2 on #1590). No
//! sockets or nodes: a real grant store, one owner-signed Dm grant, and a
//! direct evaluation.

use super::*;
use share_grant::EVIDENCE_READ_BUDGET;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

// Hold the grant store's state as a writer does, on an OS thread with a
// watchdog release, so the red baseline (an inline read) cannot wedge the
// current-thread runtime forever. Assert only after the intended result.
async fn hold_grant_store(
    store: Arc<share_grant::ShareGrantStore>,
    watchdog: Duration,
) -> (
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
    Arc<AtomicBool>,
) {
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&entered);
    let held_now = Arc::new(AtomicBool::new(false));
    let active = Arc::clone(&held_now);
    let (release, release_rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let held = store.hold_state_for_testing();
        active.store(true, Ordering::SeqCst);
        signal.notify_one();
        let _ = release_rx.recv_timeout(watchdog);
        active.store(false, Ordering::SeqCst);
        drop(held);
    });
    entered.notified().await;
    (release, writer, held_now)
}

/// A store holding one active owner-signed `Dm` grant for `requester`, and
/// an authenticated binding pairing `requester` with `machine`, so the
/// evaluation reaches its candidates read with no evidence runtime.
#[allow(clippy::type_complexity)]
async fn grant_fixture() -> (
    Arc<share_grant::ShareGrantStore>,
    dm_inbox::AuthenticatedMachineBindings,
    Arc<tokio::sync::RwLock<HashMap<identity::AgentId, DiscoveredAgent>>>,
    Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    identity::AgentId,
    identity::MachineId,
    u64,
) {
    let owner = identity::UserKeypair::generate().unwrap();
    let local = identity::AgentId([0x41; 32]);
    let requester = identity::AgentId([0x39; 32]);
    let machine = identity::MachineId([0x40; 32]);
    let now_unix = dm_capability::now_unix_ms() / 1000;
    let grants = Arc::new(share_grant::ShareGrantStore::in_memory(
        local,
        Some(owner.user_id()),
    ));
    let grant = share_grant::ShareGrant::sign(
        &owner,
        [9; 32],
        share_grant::Grantee::Agent(requester),
        vec![local],
        vec![share_grant::ShareCap::Dm],
        0,
        now_unix + 3600,
    )
    .unwrap();
    grants.accept(grant, now_unix).await.unwrap();
    let bindings: dm_inbox::AuthenticatedMachineBindings = Arc::new(tokio::sync::RwLock::new(
        dm_inbox::AuthenticatedMachineBindingCache::default(),
    ));
    dm_inbox::record_authenticated_machine_binding(&bindings, requester, machine, now_unix).await;
    (
        grants,
        bindings,
        Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        Arc::new(tokio::sync::RwLock::new(
            crate::revocation::RevocationSet::new(),
        )),
        requester,
        machine,
        now_unix,
    )
}

async fn evaluate(
    grants: &share_grant::ShareGrantStore,
    bindings: &dm_inbox::AuthenticatedMachineBindings,
    discovery: &tokio::sync::RwLock<HashMap<identity::AgentId, DiscoveredAgent>>,
    revocations: &tokio::sync::RwLock<crate::revocation::RevocationSet>,
    requester: &identity::AgentId,
    machine: &identity::MachineId,
    now_unix: u64,
) -> Result<share_grant::GrantAccessEval, ()> {
    share_grant::evaluate_grant_access_with_evidence(
        grants,
        bindings,
        discovery,
        revocations,
        requester,
        machine,
        now_unix,
        None,
        true,
    )
    .await
}

/// Whether every bounded reader permit is free again within `bound` — the
/// read that outlived its deadline must finish and return its permit once
/// the lock frees.
async fn drained(grants: &share_grant::ShareGrantStore, bound: Duration) -> bool {
    let deadline = std::time::Instant::now() + bound;
    loop {
        if grants.reads_idle_for_testing() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return grants.reads_idle_for_testing();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Greptile P2 on #1590: a store writer held past the read budget must fail
/// the evaluation closed (`Err(())`) BEFORE the writer releases, not block
/// the caller's Tokio worker. After release the workers drain and the next
/// evaluation retries and grants.
#[tokio::test(flavor = "current_thread")]
async fn held_grant_store_fails_closed_at_the_budget_and_recovers() {
    let (grants, bindings, discovery, revocations, requester, machine, now) = grant_fixture().await;
    let (release, writer, held_now) =
        hold_grant_store(Arc::clone(&grants), Duration::from_secs(15)).await;
    let started = std::time::Instant::now();
    let outcome = evaluate(
        &grants,
        &bindings,
        &discovery,
        &revocations,
        &requester,
        &machine,
        now,
    )
    .await;
    let elapsed = started.elapsed();
    let returned_while_held = held_now.load(Ordering::SeqCst);
    let _ = release.send(());
    writer.join().unwrap();

    assert!(
        matches!(outcome, Err(())),
        "contention past the budget must fail closed, not block: {outcome:?} after {elapsed:?}"
    );
    assert!(
        returned_while_held,
        "the evaluation must return before the writer releases the store"
    );
    assert!(
        elapsed >= EVIDENCE_READ_BUDGET,
        "the evaluation failed before waiting out its read budget: {elapsed:?}"
    );
    assert!(
        elapsed < EVIDENCE_READ_BUDGET + Duration::from_secs(2),
        "the evaluation outlived its read budget: {elapsed:?}"
    );
    assert!(
        drained(&grants, Duration::from_secs(2)).await,
        "the read that outlived its deadline never finished after release"
    );
    let retry = evaluate(
        &grants,
        &bindings,
        &discovery,
        &revocations,
        &requester,
        &machine,
        now,
    )
    .await
    .expect("the next evaluation must retry after release");
    assert!(
        retry.dm,
        "the retried evaluation must restore the Dm grant: {retry:?}"
    );
}

/// Control: a briefly held store (50 ms, well inside the budget) must keep
/// its grant — the bounded reader waits out short contention.
#[tokio::test(flavor = "current_thread")]
async fn briefly_held_grant_store_still_evaluates() {
    let (grants, bindings, discovery, revocations, requester, machine, now) = grant_fixture().await;
    let (release, writer, _) =
        hold_grant_store(Arc::clone(&grants), Duration::from_millis(50)).await;
    let started = std::time::Instant::now();
    let outcome = evaluate(
        &grants,
        &bindings,
        &discovery,
        &revocations,
        &requester,
        &machine,
        now,
    )
    .await;
    let elapsed = started.elapsed();
    let _ = release.send(());
    writer.join().unwrap();

    let access = outcome.expect("brief contention must not fail the evaluation");
    assert!(access.dm, "brief contention lost the grant: {access:?}");
    assert!(
        elapsed < EVIDENCE_READ_BUDGET,
        "brief contention outlived the read budget: {elapsed:?}"
    );
}

/// Review on #1598: admission is bounded too. A writer held past the
/// budget pins every reader permit (a running read keeps its permit until
/// the lock frees), so evaluations beyond the permit cap must still fail
/// closed at the budget while queued for admission — not wait unbounded.
#[tokio::test(flavor = "current_thread")]
async fn evaluations_past_the_reader_cap_still_fail_closed_at_the_budget() {
    let (grants, bindings, discovery, revocations, requester, machine, now) = grant_fixture().await;
    let (release, writer, held_now) =
        hold_grant_store(Arc::clone(&grants), Duration::from_secs(15)).await;

    let mut evaluations = tokio::task::JoinSet::new();
    for _ in 0..=share_grant::SHARE_GRANT_READ_PERMITS {
        let grants = Arc::clone(&grants);
        let bindings = Arc::clone(&bindings);
        let discovery = Arc::clone(&discovery);
        let revocations = Arc::clone(&revocations);
        evaluations.spawn(async move {
            let started = std::time::Instant::now();
            let outcome = evaluate(
                &grants,
                &bindings,
                &discovery,
                &revocations,
                &requester,
                &machine,
                now,
            )
            .await;
            (started.elapsed(), outcome)
        });
    }
    let mut results = Vec::new();
    while let Some(joined) = evaluations.join_next().await {
        results.push(joined.expect("evaluation task must not panic"));
    }
    let all_returned_while_held = held_now.load(Ordering::SeqCst);
    let _ = release.send(());
    writer.join().unwrap();

    assert_eq!(
        results.len(),
        share_grant::SHARE_GRANT_READ_PERMITS + 1,
        "every evaluation must return"
    );
    assert!(
        all_returned_while_held,
        "all evaluations must return before the writer releases the store"
    );
    for (index, (elapsed, outcome)) in results.into_iter().enumerate() {
        assert!(
            matches!(outcome, Err(())),
            "evaluation {index} past the reader cap must fail closed, not block: \
             {outcome:?} after {elapsed:?}"
        );
        assert!(
            elapsed < EVIDENCE_READ_BUDGET + Duration::from_secs(2),
            "evaluation {index} past the reader cap outlived the budget: {elapsed:?}"
        );
    }
    assert!(
        drained(&grants, Duration::from_secs(2)).await,
        "the pinned reads never finished after release"
    );
}
