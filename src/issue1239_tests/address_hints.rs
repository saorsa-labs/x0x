//! Address supplementation must not block the ordinary connector's executor.
//! The connector has no network; evidence fixtures use only SimFabric.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

fn discovered(recipient: identity::AgentId, machine: identity::MachineId) -> DiscoveredAgent {
    DiscoveredAgent {
        agent_id: recipient,
        machine_id: machine,
        user_id: None,
        addresses: Vec::new(),
        announced_at: 0,
        last_seen: 0,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        cert_digest: None,
        agent_public_key: Vec::new(),
        self_name: None,
    }
}

// The watchdog also cleans up current main, where the synchronous read
// prevents the sole Tokio thread from driving its own timeout.
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

#[tokio::test(flavor = "current_thread")]
async fn held_address_evidence_keeps_ordinary_connector_cancellable() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, recipient, store, _inbox, _fabric) = gossip_fixture(dir.path()).await.unwrap();
    assert!(agent.network.is_none());
    let view = agent
        .peer_evidence()
        .usable_agent(recipient, dm_capability::now_unix_ms())
        .unwrap();
    agent.identity_discovery_cache.write().await.insert(
        recipient,
        discovered(recipient, view.announcement.machine_id),
    );
    let (release, writer, held) = hold_store(store, Duration::from_secs(2)).await;
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        agent.connect_to_agent(&recipient),
    )
    .await;
    let ended_while_held = held.load(Ordering::SeqCst);
    let _ = release.send(());
    writer.join().unwrap();
    agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
    assert!(
        result.is_err() && ended_while_held,
        "address supplementation blocked the caller's timer: {result:?}, held={ended_while_held}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn address_load_expiry_keeps_ordinary_unreachable_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = agent_in(dir.path()).await.unwrap();
    let (_store, _ready) = install_evidence(&mut agent, dir.path()).unwrap();
    assert!(agent.network.is_none());
    let recipient = identity::AgentId([0x39; 32]);
    agent.identity_discovery_cache.write().await.insert(
        recipient,
        discovered(recipient, identity::MachineId([0x40; 32])),
    );
    tokio::time::pause();
    let mut connect = Box::pin(agent.connect_to_agent(&recipient));
    assert!(futures::poll!(&mut connect).is_pending());
    tokio::time::advance(dm::dm_attempt_timeout(None) + Duration::from_millis(1)).await;
    let result = futures::poll!(&mut connect);
    drop(connect);
    tokio::time::resume();
    agent.try_shutdown().await.unwrap();
    assert!(
        matches!(result, Poll::Ready(Ok(connectivity::ConnectOutcome::Unreachable))),
        "optional address load must end at the connector evidence budget with the existing fallback: {result:?}"
    );
    assert_eq!(
        agent
            .direct_messaging
            .diagnostics_snapshot()
            .stats
            .outgoing_send_failed,
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn address_load_and_read_share_one_budget() {
    let dir = tempfile::tempdir().unwrap();
    let (mut agent, recipient, store, _inbox, _fabric) = gossip_fixture(dir.path()).await.unwrap();
    assert!(agent.network.is_none());
    let machine = agent
        .peer_evidence()
        .usable_agent(recipient, dm_capability::now_unix_ms())
        .unwrap()
        .announcement
        .machine_id;
    agent
        .identity_discovery_cache
        .write()
        .await
        .insert(recipient, discovered(recipient, machine));
    let (runtime, ready) =
        peer_evidence::EvidenceRuntime::loading_store_for_test(Arc::clone(&store));
    let mut caps = dm_capability::CapabilityStore::new();
    caps.evidence = runtime;
    agent.capability_store = Arc::new(caps);
    let (release, writer, held) = hold_store(store, Duration::from_secs(2)).await;
    tokio::time::pause();
    let mut connect = Box::pin(agent.connect_to_agent(&recipient));
    assert!(futures::poll!(&mut connect).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    ready.cancel();
    let after_load = futures::poll!(&mut connect);
    let read_pending = after_load.is_pending();
    let result = if read_pending {
        tokio::time::advance(
            dm::dm_attempt_timeout(None) - Duration::from_secs(1) + Duration::from_millis(1),
        )
        .await;
        futures::poll!(&mut connect)
    } else {
        after_load
    };
    let ended_while_held = held.load(Ordering::SeqCst);
    drop(connect);
    tokio::time::resume();
    let _ = release.send(());
    writer.join().unwrap();
    agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
    assert!(
        read_pending && ended_while_held && matches!(result, Poll::Ready(Ok(connectivity::ConnectOutcome::Unreachable))),
        "address read must use the load's remaining budget and fallback while held: {result:?}, pending={read_pending}, held={ended_while_held}"
    );
    assert_eq!(
        agent
            .peer_evidence()
            .evidence_barrier_timeout
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        agent
            .direct_messaging
            .diagnostics_snapshot()
            .stats
            .outgoing_send_failed,
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn brief_address_contention_keeps_exact_machine_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, recipient, store, _inbox, _fabric) = gossip_fixture(dir.path()).await.unwrap();
    assert!(agent.network.is_none());
    let machine = agent
        .peer_evidence()
        .usable_agent(recipient, dm_capability::now_unix_ms())
        .unwrap()
        .announcement
        .machine_id;
    // A different machine's evidence must never supply this route's hints.
    for route in [identity::MachineId([0x41; 32]), machine] {
        agent
            .identity_discovery_cache
            .write()
            .await
            .insert(recipient, discovered(recipient, route));
        let before = store.counters().unwrap().evidence_usable_hits;
        let (release, writer, _) = hold_store(Arc::clone(&store), Duration::from_millis(50)).await;
        let result = agent.connect_to_agent(&recipient).await;
        let _ = release.send(());
        writer.join().unwrap();
        assert!(matches!(
            result,
            Ok(connectivity::ConnectOutcome::Unreachable)
        ));
        assert_eq!(
            store.counters().unwrap().evidence_usable_hits - before,
            u64::from(route == machine)
        );
        assert_eq!(
            agent.identity_discovery_cache.read().await[&recipient].machine_id,
            route
        );
    }
    agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn existing_addresses_skip_evidence_and_cold_contention_stays_nonblocking() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, recipient, store, _inbox, _fabric) = gossip_fixture(dir.path()).await.unwrap();
    assert!(agent.network.is_none());
    let machine = agent
        .peer_evidence()
        .usable_agent(recipient, dm_capability::now_unix_ms())
        .unwrap()
        .announcement
        .machine_id;
    for cold in [false, true] {
        let mut entry = discovered(recipient, machine);
        if !cold {
            entry.addresses.push("192.0.2.1:5483".parse().unwrap());
        }
        agent
            .identity_discovery_cache
            .write()
            .await
            .insert(recipient, entry);
        let (release, writer, held) = hold_store(Arc::clone(&store), Duration::from_secs(2)).await;
        let result = tokio::time::timeout(Duration::from_millis(100), async {
            if cold {
                agent
                    .connect_to_agent_with(
                        &recipient,
                        ColdResolution::starting_now(Some(ColdWait(Duration::from_secs(1)))),
                    )
                    .await
            } else {
                agent.connect_to_agent(&recipient).await
            }
        })
        .await;
        let ended_while_held = held.load(Ordering::SeqCst);
        let _ = release.send(());
        writer.join().unwrap();
        assert!(
            matches!(result, Ok(Ok(connectivity::ConnectOutcome::Unreachable))) && ended_while_held,
            "cold={cold}: existing hints or opt-in reads must not wait: {result:?}"
        );
    }
    agent.try_shutdown().await.unwrap();
}
