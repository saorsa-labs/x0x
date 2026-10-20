//! #1239: raw evidence selection and revalidation must not block Tokio.
//! Tests use signed evidence, a real store writer and the scripted transport.
//! No network node or gossip runtime is constructed.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

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
async fn redial_evidence_read_keeps_caller_timer_live() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
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
    assert!(
        result.is_err() && ended_while_held,
        "redial evidence blocked the caller timer: {result:?}, held={ended_while_held}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn raw_initial_evidence_read_keeps_caller_timer_live() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let transport = RawQuicTransport::Scripted(Arc::new(PinnedTransportScript::default()));
    let (release, writer, held) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        f.agent.resolve_raw_quic_target(
            &f.recipient,
            &transport,
            "test",
            1,
            std::time::Instant::now(),
            ColdResolution::Off,
        ),
    )
    .await;
    let ended_while_held = held.load(Ordering::SeqCst);
    let _ = release.send(());
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
    assert!(
        result.is_err() && ended_while_held,
        "initial raw evidence blocked the caller timer; held={ended_while_held}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn raw_final_evidence_read_keeps_caller_timer_live() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let gate = PinnedRepairGate::new();
    let transport = RawQuicTransport::Scripted(Arc::new(
        PinnedTransportScript::connected_only(&[], true).with_repair_gate(Arc::clone(&gate)),
    ));
    let mut resolve = Box::pin(f.agent.resolve_raw_quic_target(
        &f.recipient,
        &transport,
        "test",
        1,
        std::time::Instant::now(),
        ColdResolution::Off,
    ));
    tokio::select! {
        result = &mut resolve => panic!("resolution ended before repair: {}", result.is_ok()),
        permit = gate.reached.acquire() => permit.unwrap().forget(),
    }
    // The initial selection and connector checks have completed. Contend
    // only the final machine-pinned point-of-use read after repair.
    let (release, writer, held) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    gate.release();
    let result = tokio::time::timeout(Duration::from_millis(100), &mut resolve).await;
    let ended_while_held = held.load(Ordering::SeqCst);
    drop(resolve);
    let _ = release.send(());
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
    assert!(
        result.is_err() && ended_while_held,
        "final raw evidence blocked the caller timer; held={ended_while_held}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn redial_evidence_expires_while_store_remains_held() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let transport = RawQuicTransport::Scripted(Arc::new(PinnedTransportScript::default()));
    let (release, writer, held) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    tokio::time::pause();
    let mut resolve = Box::pin(f.agent.connected_direct_machine(
        &f.recipient,
        &transport,
        ColdResolution::Off,
    ));
    let first = futures::poll!(&mut resolve);
    let pending = first.is_pending();
    let result = if pending {
        tokio::time::advance(dm::dm_attempt_timeout(None) + Duration::from_millis(1)).await;
        futures::poll!(&mut resolve)
    } else {
        first
    };
    let ended_while_held = held.load(Ordering::SeqCst);
    drop(resolve);
    tokio::time::resume();
    let _ = release.send(());
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
    assert!(
        pending && matches!(result, Poll::Ready(None)) && ended_while_held,
        "redial must return no evidence at its read deadline: {result:?}, held={ended_while_held}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn raw_final_evidence_expiry_keeps_existing_retryable_error() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let gate = PinnedRepairGate::new();
    let transport = RawQuicTransport::Scripted(Arc::new(
        PinnedTransportScript::connected_only(&[], true).with_repair_gate(Arc::clone(&gate)),
    ));
    let mut resolve = Box::pin(f.agent.resolve_raw_quic_target(
        &f.recipient,
        &transport,
        "test",
        1,
        std::time::Instant::now(),
        ColdResolution::Off,
    ));
    tokio::select! {
        result = &mut resolve => panic!("resolution ended before repair: {}", result.is_ok()),
        permit = gate.reached.acquire() => permit.unwrap().forget(),
    }
    let (release, writer, held) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    gate.release();
    tokio::time::pause();
    let first = futures::poll!(&mut resolve);
    // The scripted repair has a zero-delay sleep after its gate. Drive that
    // timer before measuring the final evidence read's own deadline.
    let first = if first.is_pending() {
        tokio::time::advance(Duration::from_millis(2)).await;
        futures::poll!(&mut resolve)
    } else {
        first
    };
    let repaired = transport.is_connected(&ant_quic::PeerId(f.machine.0)).await;
    let pending = first.is_pending();
    let result = if pending {
        tokio::time::advance(dm::dm_attempt_timeout(None) + Duration::from_millis(1)).await;
        futures::poll!(&mut resolve)
    } else {
        first
    };
    let result = result.map(|result| result.map(|target| target.machine_id));
    let ended_while_held = held.load(Ordering::SeqCst);
    drop(resolve);
    tokio::time::resume();
    let _ = release.send(());
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
    assert!(
        repaired && pending && ended_while_held,
        "final raw evidence did not yield while held"
    );
    assert!(
        matches!(result, Poll::Ready(Err(error::NetworkError::AgentNotFound(id))) if id == f.recipient.0),
        "expired final evidence must keep the existing retryable AgentNotFound: {result:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn briefly_busy_evidence_recovers_exact_machine() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    // A different connected machine must not replace the signed machine.
    let other = identity::MachineId([0x70; 32]);
    let transport = RawQuicTransport::Scripted(Arc::new(PinnedTransportScript::connected_only(
        &[f.machine, other],
        false,
    )));
    let (release, writer, _) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    let (result, ()) = tokio::join!(
        f.agent
            .connected_direct_machine(&f.recipient, &transport, ColdResolution::Off),
        async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = release.send(());
        }
    );
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert_eq!(result, Some(f.machine));
    assert_eq!(Arc::strong_count(f.agent.peer_evidence()), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn raw_repair_rechecks_current_relationship() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let gate = PinnedRepairGate::new();
    let transport = RawQuicTransport::Scripted(Arc::new(
        PinnedTransportScript::connected_only(&[], true).with_repair_gate(Arc::clone(&gate)),
    ));
    let mut resolve = Box::pin(f.agent.resolve_raw_quic_target(
        &f.recipient,
        &transport,
        "test",
        1,
        std::time::Instant::now(),
        ColdResolution::Off,
    ));
    tokio::select! {
        result = &mut resolve => panic!("resolution ended before repair: {}", result.is_ok()),
        permit = gate.reached.acquire() => permit.unwrap().forget(),
    }
    f.eligible.store(false, Ordering::SeqCst);
    gate.release();
    let result = resolve.await;
    f.agent.try_shutdown().await.unwrap();
    assert!(matches!(result, Err(error::NetworkError::AgentNotFound(id)) if id == f.recipient.0));
}

#[tokio::test(flavor = "current_thread")]
async fn raw_evidence_and_cold_contention_preserve_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path()).await.unwrap();
    let transport = RawQuicTransport::Scripted(Arc::new(PinnedTransportScript::default()));
    let result = f
        .agent
        .resolve_raw_quic_target(
            &f.recipient,
            &transport,
            "test",
            1,
            std::time::Instant::now(),
            ColdResolution::Off,
        )
        .await
        .unwrap();
    assert_eq!(result.machine_id, f.machine);
    assert_eq!(result.resolution, "peer_evidence");
    let (release, writer, held) = hold_store(Arc::clone(&f.store), Duration::from_secs(2)).await;
    let mut check = Box::pin(f.agent.connected_direct_machine(
        &f.recipient,
        &transport,
        ColdResolution::Until(tokio::time::Instant::now() + Duration::from_secs(1)),
    ));
    let immediate = futures::poll!(&mut check);
    let ended_while_held = held.load(Ordering::SeqCst);
    drop(check);
    let _ = release.send(());
    writer.join().unwrap();
    f.agent.try_shutdown().await.unwrap();
    assert!(matches!(immediate, Poll::Ready(None)) && ended_while_held);
}
