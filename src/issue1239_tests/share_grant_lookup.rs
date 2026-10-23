//! #1239: the share-grant evaluation must not run its borrowed EvidenceRuntime
//! Lookup or usable reads on the caller's Tokio worker. No sockets or nodes:
//! empty-store Agents, a real evidence store and one owner-signed Dm grant.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// Release even on the broken baseline, where the synchronous read prevents
// the current-thread runtime from driving its own timer. Assert only after
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

/// One active owner-signed `Dm` grant whose grantee is `requester`, installed
/// into the agent's owner trust so the grant store is the live relation source.
async fn install_dm_grant(agent: &Agent, requester: identity::AgentId) {
    let owner = identity::UserKeypair::generate().unwrap();
    let now_unix = dm_capability::now_unix_ms() / 1000;
    let grants = Arc::new(share_grant::ShareGrantStore::in_memory(
        agent.agent_id(),
        Some(owner.user_id()),
    ));
    let grant = share_grant::ShareGrant::sign(
        &owner,
        [9; 32],
        share_grant::Grantee::Agent(requester),
        vec![agent.agent_id()],
        vec![share_grant::ShareCap::Dm],
        0,
        now_unix + 3600,
    )
    .unwrap();
    grants.accept(grant, now_unix).await.unwrap();
    assert!(!grants.candidates_for_local_agent(now_unix).is_empty());
    agent.owner_trust.install_share_grant_store(grants);
}

/// The gate fixture with an EMPTY evidence store: the runtime is wired into
/// both the capability store and owner trust, and the grant's grantee is an
/// unbound requester, so the evaluation always enters its Lookup branch.
async fn gate_fixture(
    dir: &std::path::Path,
) -> (
    Agent,
    identity::AgentId,
    identity::MachineId,
    Arc<peer_evidence::PeerEvidenceStore>,
) {
    let mut agent = agent_in(dir).await.unwrap();
    let (store, ready) = install_evidence(&mut agent, dir).unwrap();
    ready.cancel();
    agent.owner_trust.install_evidence(agent.peer_evidence());
    let requester = identity::AgentId([0x39; 32]);
    install_dm_grant(&agent, requester).await;
    (agent, requester, identity::MachineId([0x40; 32]), store)
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

#[tokio::test(flavor = "current_thread")]
async fn share_grant_lookup_held_store_leaves_caller_running() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, requester, machine, store) = gate_fixture(dir.path()).await;
    assert!(agent.network.is_none());
    let agent = Arc::new(agent);
    let (release, writer, held_now) = hold_store(store, Duration::from_secs(2)).await;
    let gate = {
        let agent = Arc::clone(&agent);
        tokio::spawn(async move { agent.share_grant_access(&requester, &machine).await })
    };
    tokio::time::sleep(Duration::from_millis(25)).await;
    let timer_ran_while_held = held_now.load(Ordering::SeqCst);
    let _ = release.send(());
    writer.join().unwrap();
    let access = gate.await.unwrap();
    agent.try_shutdown().await.unwrap();
    assert!(
        timer_ran_while_held,
        "share-grant Lookup blocked the sole Tokio worker until the OS watchdog released it"
    );
    assert!(
        !access.dm,
        "an empty evidence store must keep the no-evidence deny outcome: {access:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn briefly_held_store_still_grants_dm() {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = agent_in(dir.path()).await.unwrap();
    let peer = identity::AgentKeypair::generate().unwrap();
    let machine_kp = identity::MachineKeypair::generate().unwrap();
    let requester = peer.agent_id();
    let machine = machine_kp.machine_id();
    install_dm_grant(&agent, requester).await;
    let now = dm_capability::now_unix_ms();
    let policy = Arc::new(peer_evidence::RuntimePolicy::new(
        agent.agent_id(),
        agent.owner_trust.clone(),
        Arc::clone(&agent.revocation_set),
    ));
    let store = Arc::new(
        peer_evidence::PeerEvidenceStore::open(dir.path(), Default::default(), policy, now)
            .unwrap(),
    );
    let kem = groups::kem_envelope::AgentKemKeypair::generate().unwrap();
    let v2 = IdentityAnnouncement {
        self_name: None,
        agent_id: requester,
        machine_id: machine,
        user_id: None,
        agent_certificate: None,
        machine_public_key: machine_kp.public_key().as_bytes().to_vec(),
        machine_signature: vec![],
        addresses: vec![],
        announced_at: now / 1000,
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: vec![],
        relay_candidates: vec![],
        agent_public_key: peer.public_key().as_bytes().to_vec(),
    };
    let mut ann =
        announce_v3::IdentityAnnouncementV3::build_from_v2(&v2, machine_kp.secret_key(), 0)
            .unwrap();
    ann.sign_v3_1(machine_kp.secret_key()).unwrap();
    let mut advert = dm_capability::CapabilityAdvert {
        protocol_version: dm_capability_service::ADVERT_PROTOCOL_VERSION,
        agent_id: requester.0,
        machine_id: machine.0,
        created_at_unix_ms: now,
        capabilities: dm::DmCapabilities {
            gossip_inbox: true,
            kem_public_key: kem.public_bytes,
            ..dm::DmCapabilities::pending()
        },
        signature: vec![],
    };
    advert.signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        peer.secret_key(),
        &advert.signed_bytes().unwrap(),
    )
    .unwrap()
    .as_bytes()
    .to_vec();
    store
        .ingest(
            peer_evidence::EvidenceRecordV1 {
                announcement: announce_v3::serialize_v3_1(&ann).unwrap(),
                advert: postcard::to_stdvec(&advert).unwrap(),
                certificate: None,
                relation: peer_evidence::GROUP,
                stored_at_ms: now,
            },
            peer_evidence::IngestSource::Gossip,
            now,
        )
        .unwrap();
    let (runtime, ready) =
        peer_evidence::EvidenceRuntime::loading_store_for_test(Arc::clone(&store));
    ready.cancel();
    let mut caps = dm_capability::CapabilityStore::new();
    caps.evidence = runtime;
    agent.capability_store = Arc::new(caps);
    agent.owner_trust.install_evidence(agent.peer_evidence());
    assert!(agent
        .peer_evidence()
        .usable_agent(requester, dm_capability::now_unix_ms())
        .is_some());
    let calls = count_exchanges(&agent);

    let (release, writer, _) = hold_store(store, Duration::from_millis(50)).await;
    let access = agent.share_grant_access(&requester, &machine).await;
    let _ = release.send(());
    writer.join().unwrap();
    agent.try_shutdown().await.unwrap();
    assert!(
        access.dm,
        "brief store contention lost the grant: {access:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "usable evidence needs no exchange"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn bound_requester_grants_while_store_held() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, requester, machine, store) = gate_fixture(dir.path()).await;
    dm_inbox::record_authenticated_machine_binding(
        &agent.authenticated_machine_bindings,
        requester,
        machine,
        dm_capability::now_unix_ms() / 1000,
    )
    .await;
    let (release, writer, held_now) = hold_store(store, Duration::from_secs(2)).await;
    let access = agent.share_grant_access(&requester, &machine).await;
    let ended_while_held = held_now.load(Ordering::SeqCst);
    let _ = release.send(());
    writer.join().unwrap();
    agent.try_shutdown().await.unwrap();
    assert!(
        access.dm && ended_while_held,
        "a bound requester must keep its grant without an evidence read: {access:?}"
    );
}
