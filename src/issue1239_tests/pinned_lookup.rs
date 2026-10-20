//! The last inline Lookup must obey the pinned resolver's existing deadline.
//! No sockets: empty-store Agents and the existing SimFabric evidence fixture.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// Release even on the broken baseline, where the synchronous read prevents
// the current-thread runtime from driving its own timeout. Assert only after
// releasing the writer and draining all evidence workers.
async fn hold_store(
    store: Arc<peer_evidence::PeerEvidenceStore>,
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

fn count_exchanges(agent: &Agent) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    assert!(agent
        .peer_evidence()
        .lookup_responder
        .set(Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }))
        .is_ok());
    calls
}

async fn held_lookup(caller_cancels: bool) {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = agent_in(dir.path()).await.unwrap();
    let (store, ready) = install_evidence(&mut agent, dir.path()).unwrap();
    ready.cancel();
    assert!(agent.network.is_none());
    let calls = count_exchanges(&agent);
    let recipient = identity::AgentId([0x39; 32]);
    let (release, writer, held) = hold_store(store, Duration::from_secs(2)).await;
    let budget = if caller_cancels {
        Duration::from_secs(30)
    } else {
        Duration::from_millis(100)
    };
    let resolve =
        agent.await_pinned_recipient_binding(&recipient, tokio::time::Instant::now() + budget);
    let refused = if caller_cancels {
        tokio::time::timeout(Duration::from_millis(100), resolve)
            .await
            .is_err()
    } else {
        matches!(resolve.await, Err(dm::DmError::RecipientUndiscovered(_)))
    };
    let ended_while_held = held.load(Ordering::SeqCst);
    let _ = release.send(());
    writer.join().unwrap();
    agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
    assert!(
        refused && ended_while_held,
        "caller_cancels={caller_cancels}: pinned Lookup blocked the resolver/caller timer; refused={refused}, held={ended_while_held}"
    );
    if !caller_cancels {
        assert_eq!(calls.load(Ordering::SeqCst), 0, "exchange after deadline");
    }
    assert_eq!(
        agent
            .direct_messaging
            .diagnostics_snapshot()
            .stats
            .outgoing_send_failed,
        0,
        "binding resolution must keep its existing pre-admission accounting"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn held_lookup_ends_at_pinned_resolution_deadline() {
    held_lookup(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn held_lookup_keeps_pinned_resolution_cancellable() {
    held_lookup(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn pinned_load_and_lookup_share_one_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = agent_in(dir.path()).await.unwrap();
    let (store, ready) = install_evidence(&mut agent, dir.path()).unwrap();
    assert!(agent.network.is_none());
    let calls = count_exchanges(&agent);
    let recipient = identity::AgentId([0x39; 32]);
    let (release, writer, held) = hold_store(store, Duration::from_secs(2)).await;
    tokio::time::pause();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut resolve = Box::pin(agent.await_pinned_recipient_binding(&recipient, deadline));
    assert!(futures::poll!(&mut resolve).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    ready.cancel();
    let after_load = futures::poll!(&mut resolve);
    let lookup_pending = after_load.is_pending();
    let result = if lookup_pending {
        tokio::time::advance(Duration::from_millis(2001)).await;
        futures::poll!(&mut resolve)
    } else {
        after_load
    };
    let ended_while_held = held.load(Ordering::SeqCst);
    drop(resolve);
    tokio::time::resume();
    let _ = release.send(());
    writer.join().unwrap();
    agent.try_shutdown().await.unwrap();
    assert!(
        lookup_pending && ended_while_held
            && matches!(result, Poll::Ready(Err(dm::DmError::RecipientUndiscovered(_)))),
        "load and Lookup must share the pinned deadline: {result:?}, pending={lookup_pending}, held={ended_while_held}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "late Lookup exchange");
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn brief_contention_preserves_pinned_evidence_binding() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, recipient, store, _inbox, _fabric) = gossip_fixture(dir.path()).await.unwrap();
    assert!(agent.network.is_none());
    let expected = agent
        .peer_evidence()
        .usable_agent(recipient, dm_capability::now_unix_ms())
        .unwrap()
        .announcement
        .machine_id;
    let calls = count_exchanges(&agent);
    let (release, writer, _) = hold_store(store, Duration::from_millis(50)).await;
    let result = agent
        .await_pinned_recipient_binding(
            &recipient,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;
    let _ = release.send(());
    writer.join().unwrap();
    agent.try_shutdown().await.unwrap();
    assert_eq!(result.unwrap().machine, expected);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "usable evidence needs no exchange"
    );
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn pinned_lookup_rereads_authority_after_async_response() {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = agent_in(dir.path()).await.unwrap();
    let (_store, ready) = install_evidence(&mut agent, dir.path()).unwrap();
    ready.cancel();
    assert!(agent.network.is_none());
    let recipient = identity::AgentId([0x39; 32]);
    let machine = identity::MachineId([0x40; 32]);
    let bindings = Arc::clone(&agent.authenticated_machine_bindings);
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    assert!(agent
        .peer_evidence()
        .lookup_responder
        .set(Arc::new(move |to| {
            assert_eq!(to, recipient);
            count.fetch_add(1, Ordering::SeqCst);
            let bindings = Arc::clone(&bindings);
            Box::pin(async move {
                // This timer must be driven by the awaiting current-thread runtime.
                tokio::time::sleep(Duration::from_millis(10)).await;
                dm_inbox::record_authenticated_machine_binding(
                    &bindings,
                    recipient,
                    machine,
                    dm_capability::now_unix_ms() / 1000,
                )
                .await;
            })
        }))
        .is_ok());
    let result = agent
        .await_pinned_recipient_binding(
            &recipient,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await;
    agent.try_shutdown().await.unwrap();
    assert_eq!(result.unwrap().machine, machine);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(agent.identity_discovery_cache.read().await.is_empty());
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
}
