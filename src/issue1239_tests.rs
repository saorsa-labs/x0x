#![cfg(test)]

//! Direct-send contention regressions. No sockets or external network.

use super::*;
use std::sync::Arc;
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

#[tokio::test]
async fn issue1239_discovery_lock_ends_ordinary_and_waiting_sends_at_the_bound(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let agent = agent_in(dir.path()).await?;
    assert!(agent.network.is_none());
    let recipient = identity::AgentId([0x39; 32]);
    let budget = Duration::from_secs(2);
    tokio::time::pause();

    for waiting in [false, true] {
        let held = agent.identity_discovery_cache.write().await;
        let config = dm::DmSendConfig {
            timeout_per_attempt: budget,
            ..Default::default()
        };
        let send = async {
            if waiting {
                agent
                    .send_direct_with_config_cold_wait(
                        &recipient,
                        vec![1],
                        config,
                        Duration::from_secs(30),
                    )
                    .await
            } else {
                agent
                    .send_direct_with_config(&recipient, vec![1], config)
                    .await
            }
        };
        tokio::pin!(send);
        assert!(futures::poll!(&mut send).is_pending());
        // Advance the clock without releasing the writer. One millisecond
        // accounts for Tokio's timer resolution; no wall-clock sleep is used.
        tokio::time::advance(budget + Duration::from_millis(1)).await;
        let result = futures::poll!(&mut send);
        assert!(
            matches!(result, Poll::Ready(Err(dm::DmError::RecipientUndiscovered(ref reason)))
                if reason == "the recipient's binding sources stayed locked past the resolution bound (discovery)"),
            "waiting={waiting}: a held discovery writer must return the retryable bound error: {result:?}"
        );
        let diagnostics = agent.direct_messaging.diagnostics_snapshot();
        assert_eq!(diagnostics.stats.outgoing_send_failed, 0);
        assert!(!diagnostics.per_peer.contains_key(&hex::encode(recipient.0)));
        drop(held);
    }
    agent.shutdown().await;
    Ok(())
}

fn install_evidence(
    agent: &mut Agent,
    dir: &std::path::Path,
) -> Result<
    (
        Arc<peer_evidence::PeerEvidenceStore>,
        tokio_util::sync::CancellationToken,
    ),
    Box<dyn std::error::Error>,
> {
    let policy = Arc::new(peer_evidence::RuntimePolicy::new(
        agent.agent_id(),
        agent.owner_trust.clone(),
        Arc::clone(&agent.revocation_set),
    ));
    let store = Arc::new(peer_evidence::PeerEvidenceStore::open(
        dir,
        Default::default(),
        policy,
        dm_capability::now_unix_ms(),
    )?);
    let (runtime, ready) =
        peer_evidence::EvidenceRuntime::loading_store_for_test(Arc::clone(&store));
    let mut caps = dm_capability::CapabilityStore::new();
    caps.evidence = runtime;
    agent.capability_store = Arc::new(caps);
    Ok((store, ready))
}

#[tokio::test]
async fn issue1239_evidence_load_shares_discovery_budget_and_counts_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut agent = agent_in(dir.path()).await?;
    let (_store, _ready) = install_evidence(&mut agent, dir.path())?;
    assert!(agent.network.is_none());
    let recipient = identity::AgentId([0x39; 32]);
    let budget = Duration::from_secs(2);
    tokio::time::pause();
    for waiting in [false, true] {
        let held = agent.identity_discovery_cache.write().await;
        let config = dm::DmSendConfig {
            timeout_per_attempt: budget,
            ..Default::default()
        };
        let send = async {
            if waiting {
                agent
                    .send_direct_with_config_cold_wait(
                        &recipient,
                        vec![1],
                        config,
                        Duration::from_secs(30),
                    )
                    .await
            } else {
                agent
                    .send_direct_with_config(&recipient, vec![1], config)
                    .await
            }
        };
        tokio::pin!(send);
        assert!(futures::poll!(&mut send).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        drop(held);
        assert!(futures::poll!(&mut send).is_pending());
        tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(1)).await;
        let result = futures::poll!(&mut send);
        assert!(
            matches!(
                result,
                Poll::Ready(Err(dm::DmError::NoConnectivity(ref reason))) if reason == "network not initialized"
            ),
            "waiting={waiting}: load must use the remaining send budget: {result:?}"
        );
        let diagnostics = agent.direct_messaging.diagnostics_snapshot();
        let failures = if waiting { 2 } else { 1 };
        assert_eq!(diagnostics.stats.outgoing_send_failed, failures);
        assert_eq!(
            diagnostics.per_peer[&hex::encode(recipient.0)].send_failed,
            failures
        );
    }
    agent.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue1239_held_evidence_store_ends_sends_and_counts_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut agent = agent_in(dir.path()).await?;
    let (store, ready) = install_evidence(&mut agent, dir.path())?;
    ready.cancel();
    assert!(agent.network.is_none());
    let agent = Arc::new(agent);
    let recipient = identity::AgentId([0x39; 32]);
    let budget = Duration::from_millis(200);
    for waiting in [false, true] {
        let held = store.hold_state_for_testing();
        let sender = Arc::clone(&agent);
        let mut send = tokio::spawn(async move {
            let config = dm::DmSendConfig {
                timeout_per_attempt: budget,
                ..Default::default()
            };
            let started = std::time::Instant::now();
            let result = if waiting {
                sender
                    .send_direct_with_config_cold_wait(
                        &recipient,
                        vec![1],
                        config,
                        Duration::from_secs(30),
                    )
                    .await
            } else {
                sender
                    .send_direct_with_config(&recipient, vec![1], config)
                    .await
            };
            (started.elapsed(), result)
        });
        // The observer runs separately from the sender. A synchronous store
        // wait on main cannot stop this watchdog or release its own lock.
        let observed = tokio::time::timeout(budget + Duration::from_millis(100), &mut send).await;
        let diagnostics = agent.direct_messaging.diagnostics_snapshot();
        drop(held);
        // Clean up the pre-fix blocked task before asserting the red result.
        if observed.is_err() {
            let _ = send.await;
        }
        assert!(
            observed.is_ok(),
            "waiting={waiting}: send outlived its deadline while the evidence store stayed locked"
        );
        let (elapsed, result) = observed??;
        assert!(
            matches!(result, Err(dm::DmError::NoConnectivity(ref reason)) if reason == "network not initialized"),
            "waiting={waiting}: {result:?}"
        );
        assert!(
            elapsed <= budget + Duration::from_millis(100),
            "waiting={waiting}: elapsed={elapsed:?}"
        );
        let failures = if waiting { 2 } else { 1 };
        assert_eq!(diagnostics.stats.outgoing_send_failed, failures);
        assert_eq!(
            diagnostics.per_peer[&hex::encode(recipient.0)].send_failed,
            failures
        );
    }
    agent.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn issue1239_discovery_lock_released_before_bound_preserves_loopback(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let agent = agent_in(dir.path()).await?;
    assert!(agent.network.is_none());
    let recipient = agent.agent_id();
    let held = agent.identity_discovery_cache.write().await;
    let config = dm::DmSendConfig {
        timeout_per_attempt: Duration::from_secs(2),
        ..Default::default()
    };
    let send = agent.send_direct_with_config(&recipient, vec![1], config);
    tokio::pin!(send);
    assert!(futures::poll!(&mut send).is_pending());
    drop(held);
    let receipt = send.await?;
    assert_eq!(receipt.path, dm::DmPath::Loopback);
    agent.shutdown().await;
    Ok(())
}

/// A real local PubSub publication, with no sockets or daemon/network join.
/// The runtime's transport is claimed by an in-memory fabric before construction;
/// Agent itself retains network=None. This proves send selection/publication,
/// not remote delivery or an application ACK.
async fn gossip_fixture(
    dir: &std::path::Path,
) -> Result<
    (
        Agent,
        identity::AgentId,
        Arc<peer_evidence::PeerEvidenceStore>,
        gossip::Subscription,
        Arc<network::sim::SimFabric>,
    ),
    Box<dyn std::error::Error>,
> {
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
    policy.set_groups(Arc::new(move |a| Some(a == recipient)));
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

    let plane = format!("issue1239-{}", hex::encode(&agent.agent_id().0[..8]));
    let fabric = network::sim::SimFabric::new(1239);
    network::sim::register(&plane, &fabric);
    let network = Arc::new(
        network::NetworkNode::new(
            network::NetworkConfig {
                bind_addr: Some("127.0.0.1:5483".parse()?),
                network_id: Some(plane),
                bootstrap_nodes: vec![],
                mdns_enabled: false,
                port_mapping_enabled: false,
                ..Default::default()
            },
            None,
            None,
        )
        .await?,
    );
    assert!(network.sim_link_for_test().is_some());
    let runtime = Arc::new(
        gossip::GossipRuntime::new(
            gossip::GossipConfig::default(),
            network,
            Arc::new(gossip::SigningContext::from_keypair(
                agent.identity.agent_keypair(),
            )),
        )
        .await?,
    );
    let inbox = runtime
        .pubsub()
        .subscribe_topic_id(
            dm_inbox::DmInboxService::inbox_topic_name(&recipient),
            dm::dm_inbox_topic(&recipient),
        )
        .await;
    agent.gossip_runtime = Some(runtime);
    assert!(agent.network.is_none());
    Ok((agent, recipient, store, inbox, fabric))
}

fn publish_config() -> dm::DmSendConfig {
    dm::DmSendConfig {
        timeout_per_attempt: Duration::from_millis(500),
        max_retries: 0,
        require_gossip: true,
        require_gossip_ack: false,
        ..Default::default()
    }
}

async fn assert_published(
    agent: &Agent,
    recipient: identity::AgentId,
    receipt: dm::DmReceipt,
    inbox: &mut gossip::Subscription,
) {
    assert_eq!(receipt.path, dm::DmPath::GossipInbox);
    let message = tokio::time::timeout(Duration::from_secs(1), inbox.recv())
        .await
        .unwrap()
        .unwrap();
    let envelope = dm::DmEnvelope::from_wire_bytes(&message.payload).unwrap();
    assert_eq!(envelope.request_id, receipt.request_id);
    assert_eq!(envelope.recipient_agent_id, recipient.0);
    assert_eq!(envelope.sender_agent_id, agent.agent_id().0);
    let diagnostics = agent.direct_messaging.diagnostics_snapshot();
    assert_eq!(diagnostics.stats.outgoing_send_failed, 0);
    assert_eq!(
        diagnostics.per_peer[&hex::encode(recipient.0)].send_failed,
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn issue1239_briefly_busy_store_preserves_gossip_send(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (agent, recipient, store, mut inbox, _fabric) = gossip_fixture(dir.path()).await?;
    // Occupy Lookup permits so the send reaches its own point-of-use read
    // while the store is held, rather than waiting inside Lookup first.
    let _lookups: Vec<_> = (0..16)
        .map(|_| {
            agent
                .peer_evidence()
                .wire_limits
                .try_lookup_permit()
                .unwrap()
        })
        .collect();
    let held = store.hold_state_for_testing();
    let send = agent.send_direct_with_config(&recipient, vec![0x39], publish_config());
    tokio::pin!(send);
    let first = futures::poll!(&mut send);
    drop(held);
    assert!(
        first.is_pending(),
        "a briefly busy store must wait, not fail: {first:?}"
    );
    let receipt = send.await?;
    assert_published(&agent, recipient, receipt, &mut inbox).await;
    agent.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn issue1239_slow_evidence_dial_preserves_gossip_fallback(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let (agent, recipient, _store, mut inbox, _fabric) = gossip_fixture(dir.path()).await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&entered);
    assert!(agent
        .peer_evidence()
        .evidence_dial
        .set(Arc::new(move |_| {
            let signal = Arc::clone(&signal);
            Box::pin(async move {
                signal.notify_one();
                std::future::pending::<()>().await;
            })
        }))
        .is_ok());
    tokio::time::pause();
    let send = agent.send_direct_with_config(&recipient, vec![0x39], publish_config());
    tokio::pin!(send);
    tokio::select! {
        _ = entered.notified() => {},
        result = &mut send => panic!("send ended before reaching the evidence dial: {result:?}"),
    }
    // Spend the existing 3 s dial cap, which is longer than the 500 ms
    // evidence budget. No wall-clock sleep, retry or larger timeout.
    tokio::time::advance(Duration::from_secs(3) + Duration::from_millis(1)).await;
    let receipt = send.await?;
    assert_published(&agent, recipient, receipt, &mut inbox).await;
    agent.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn issue1239_lookup_worker_awaits_current_thread_driver() {
    struct Finished(tokio::sync::mpsc::UnboundedSender<()>);
    impl Drop for Finished {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let runtime = Arc::new(peer_evidence::EvidenceRuntime::default());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (finished, mut completions) = tokio::sync::mpsc::unbounded_channel();
    let signal = Arc::clone(&entered);
    let wait = Arc::clone(&release);
    assert!(runtime
        .lookup_responder
        .set(Arc::new(move |_| {
            let signal = Arc::clone(&signal);
            let wait = Arc::clone(&wait);
            let finished = finished.clone();
            Box::pin(async move {
                let _finished = Finished(finished);
                signal.notify_one();
                wait.notified().await;
            })
        }))
        .is_ok());
    for phase in ["complete", "deadline", "cancel"] {
        let mut lookup = Box::pin(runtime.lookup_before(
            identity::AgentId([0x39; 32]),
            None,
            tokio::time::Instant::now() + Duration::from_secs(1),
        ));
        tokio::select! {
            _ = entered.notified() => {},
            result = &mut lookup => panic!("{phase}: Lookup must wait for the async responder: {result:?}"),
        }
        match phase {
            "complete" => {
                release.notify_one();
                assert_eq!(lookup.await, Ok(()));
            }
            "deadline" => {
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(1)).await;
                tokio::time::resume();
                assert_eq!(lookup.await, Err(()));
            }
            _ => drop(lookup),
        }
        // The worker must drop its pending async exchange after cancellation,
        // without waiting for its one-second deadline. Drain teardown before
        // this current-thread runtime stops driving timers.
        let finished = tokio::time::timeout(Duration::from_millis(100), completions.recv()).await;
        if finished.is_err() {
            // Clean up the old worker before reporting the red assertion.
            release.notify_one();
            assert_eq!(completions.recv().await, Some(()));
        }
        assert!(
            matches!(finished, Ok(Some(()))),
            "{phase}: async Lookup worker survived its caller"
        );
    }
}

mod address_hints;
mod connector;
mod fallback;
mod pinned_lookup;
mod share_grant_candidates;
mod share_grant_lookup;
mod shutdown;

mod raw_resolution;
