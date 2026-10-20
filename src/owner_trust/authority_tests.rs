//! #1239: ordinary authority evidence must leave Tokio free to drive timers.
//! No network node or gossip runtime is constructed. Redial uses its scripted
//! transport; a real OS-thread writer holds the real evidence mutex.

use crate::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::Poll;
use std::time::Duration;

async fn agent_in(dir: &std::path::Path) -> error::Result<Agent> {
    Agent::builder()
        .with_machine_key(dir.join("machine.key"))
        .with_agent_key_path(dir.join("agent.key"))
        .with_agent_cert_path(dir.join("agent.cert"))
        .with_user_key_path(dir.join("user.key"))
        .with_identity_dir(dir)
        .with_contact_store_path(dir.join("contacts.json"))
        .with_peer_cache_disabled()
        .build()
        .await
}

struct Fixture {
    agent: Agent,
    recipient: identity::AgentId,
    machine: identity::MachineId,
    store: Arc<peer_evidence::PeerEvidenceStore>,
    eligible: Arc<AtomicBool>,
}

async fn fixture(dir: &std::path::Path) -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut agent = agent_in(dir).await?;
    let peer = identity::AgentKeypair::generate()?;
    let machine = identity::MachineKeypair::generate()?;
    let recipient = peer.agent_id();
    let kem = groups::kem_envelope::AgentKemKeypair::generate()?;
    let now = dm_capability::now_unix_ms();
    let policy = Arc::new(peer_evidence::RuntimePolicy::new(
        agent.agent_id(),
        agent.owner_trust.clone(),
        Arc::clone(&agent.revocation_set),
    ));
    let eligible = Arc::new(AtomicBool::new(true));
    let active = Arc::clone(&eligible);
    policy.set_groups(Arc::new(move |a| {
        Some(a == recipient && active.load(Ordering::SeqCst))
    }));
    let store = Arc::new(peer_evidence::PeerEvidenceStore::open(
        dir,
        Default::default(),
        policy,
        now,
    )?);
    let v2 = IdentityAnnouncement {
        self_name: None,
        agent_id: recipient,
        machine_id: machine.machine_id(),
        user_id: None,
        agent_certificate: None,
        machine_public_key: machine.public_key().as_bytes().to_vec(),
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
    let mut ann = announce_v3::IdentityAnnouncementV3::build_from_v2(&v2, machine.secret_key(), 0)?;
    ann.sign_v3_1(machine.secret_key())?;
    let mut advert = dm_capability::CapabilityAdvert {
        protocol_version: dm_capability_service::ADVERT_PROTOCOL_VERSION,
        agent_id: recipient.0,
        machine_id: machine.machine_id().0,
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
        &advert.signed_bytes()?,
    )?
    .as_bytes()
    .to_vec();
    store.ingest(
        peer_evidence::EvidenceRecordV1 {
            announcement: announce_v3::serialize_v3_1(&ann)?,
            advert: postcard::to_stdvec(&advert)?,
            certificate: None,
            relation: peer_evidence::GROUP,
            stored_at_ms: now,
        },
        peer_evidence::IngestSource::Gossip,
        now,
    )?;
    let (runtime, ready) =
        peer_evidence::EvidenceRuntime::loading_store_for_test(Arc::clone(&store));
    ready.cancel();
    let mut caps = dm_capability::CapabilityStore::new();
    caps.evidence = runtime;
    agent.capability_store = Arc::new(caps);
    assert!(agent.capability_store.lookup_binding(&recipient).is_none());
    assert!(agent.peer_evidence().usable_agent(recipient, now).is_some());

    agent.owner_trust.install_evidence(agent.peer_evidence());
    assert!(agent.network.is_none());
    Ok(Fixture {
        agent,
        recipient,
        machine: machine.machine_id(),
        store,
        eligible,
    })
}

// A watchdog releases the writer even on main, whose synchronous read stops
// the sole Tokio thread. Release and drain all workers before asserting.
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
    let held = Arc::new(AtomicBool::new(false));
    let active = Arc::clone(&held);
    let (release, released) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let guard = store.hold_state_for_testing();
        active.store(true, Ordering::SeqCst);
        signal.notify_one();
        let _ = released.recv_timeout(watchdog);
        active.store(false, Ordering::SeqCst);
        drop(guard);
    });
    entered.notified().await;
    (release, writer, held)
}

#[tokio::test(flavor = "current_thread")]
async fn held_authority_evidence_keeps_known_recipient_redial_cancellable() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    f.agent.identity_discovery_cache.write().await.insert(
        f.recipient,
        DiscoveredAgent {
            agent_id: f.recipient,
            machine_id: f.machine,
            user_id: None,
            addresses: vec![],
            announced_at: 0,
            last_seen: 0,
            machine_public_key: vec![],
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: vec![],
            relay_candidates: vec![],
            cert_not_after: None,
            agent_certificate: None,
            cert_digest: None,
            agent_public_key: vec![],
            self_name: None,
        },
    );
    let transport = RawQuicTransport::Scripted(Arc::new(PinnedTransportScript::default()));
    let (release, writer, held) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        f.agent
            .connected_direct_machine(&f.recipient, &transport, ColdResolution::Off),
    )
    .await;
    let ended_while_held = held.load(Ordering::SeqCst);
    let _ = release.send(());
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
    assert!(result.is_err() && ended_while_held,
        "authority read blocked the ordinary redial caller timer: {result:?}, held={ended_while_held}");
}

#[tokio::test(flavor = "current_thread")]
async fn authority_evidence_expires_within_its_budget() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let (release, writer, held) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    tokio::time::pause();
    let mut check = Box::pin(
        f.agent
            .owner_trust
            .authority_confirms(&f.recipient, &f.machine),
    );
    let first = futures::poll!(&mut check);
    let initially_pending = first.is_pending();
    let result = if initially_pending {
        tokio::time::advance(dm::dm_attempt_timeout(None) + Duration::from_millis(1)).await;
        futures::poll!(&mut check)
    } else {
        first
    };
    let ended_while_held = held.load(Ordering::SeqCst);
    drop(check);
    tokio::time::resume();
    let _ = release.send(());
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
    assert!(initially_pending && ended_while_held && matches!(result, Poll::Ready(false)),
        "authority evidence did not fail closed at its bound: {result:?}, pending={initially_pending}, held={ended_while_held}");
}

#[tokio::test(flavor = "current_thread")]
async fn brief_contention_preserves_exact_pairing_and_authority_counters() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let before = f.store.counters().unwrap().evidence_usable_hits;
    for machine in [
        identity::MachineId([0x39; 32]),
        identity::MachineId([0; 32]),
        f.machine,
    ] {
        let (release, writer, _) =
            hold_store(Arc::clone(&f.store), Duration::from_millis(50)).await;
        let confirmed = f
            .agent
            .owner_trust
            .authority_confirms(&f.recipient, &machine)
            .await;
        let _ = release.send(());
        writer.join().unwrap();
        assert_eq!(confirmed, machine == f.machine);
    }
    assert_eq!(f.store.counters().unwrap().evidence_usable_hits, before);
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn evidence_rechecks_relationship_after_waiting_for_store() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let (release, writer, held) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    let eligible = Arc::clone(&f.eligible);
    let revoke = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        eligible.store(false, Ordering::SeqCst);
        let was_held = held.load(Ordering::SeqCst);
        let _ = release.send(());
        was_held
    });
    let confirmed = f
        .agent
        .owner_trust
        .authority_confirms(&f.recipient, &f.machine)
        .await;
    let changed_while_held = revoke.await.unwrap();
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
    assert!(!confirmed && changed_while_held,
        "relationship change could not run before evidence read: confirmed={confirmed}, held={changed_while_held}");
}

#[tokio::test(flavor = "current_thread")]
async fn cold_checks_and_live_bindings_skip_held_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let (release, writer, held) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    let cold = f
        .agent
        .owner_trust
        .authority_confirms_nonblocking(&f.recipient, &f.machine)
        .await;
    dm_inbox::record_authenticated_machine_binding(
        &f.agent.authenticated_machine_bindings,
        f.recipient,
        f.machine,
        Agent::unix_timestamp_secs(),
    )
    .await;
    let warm = f
        .agent
        .owner_trust
        .authority_confirms(&f.recipient, &f.machine)
        .await;
    let skipped_held = held.load(Ordering::SeqCst);
    let _ = release.send(());
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
    // Held store → try_confirms_pairing None → Busy (not Done(false)).
    assert!(matches!(cold, crate::owner_trust::NonblockingEval::Busy) && warm && skipped_held);
}
