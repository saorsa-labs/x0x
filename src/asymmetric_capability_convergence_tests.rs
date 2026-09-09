#![cfg(test)]

//! Component acceptance, not public fallback-trigger or durable-ACK coverage.
//! Real Agent/socket test: never included in the locally admitted pure selectors.
mod custody;
use super::*;
use crate::dm::{DmBody, DmCapabilities, DmEnvelope, DmPath};
use crate::groups::kem_envelope::AgentKemKeypair;
use crate::peer_relay::{ConvergenceEvent, RelayDisposition, RelayRefusal};
use futures::FutureExt;
use serde_json::json;
use std::{panic::AssertUnwindSafe, sync::Arc, time::Duration};

/// Positive deadline for every "wait for real convergence" step below. It is
/// never a negative window — absence is asserted only over [`WINDOW`], which
/// this calibration does not touch.
///
/// Calibration basis (Coverage Gate barrier-timeout flake). These barriers
/// poll local state that changes when
/// a signed capability advert completes a real gossip round trip between
/// separate Agents on loopback, so their cost tracks gossip convergence
/// latency under whatever CPU pressure the host is under. Measured per-barrier
/// elapsed for this fixture, instrumented and run with the budget temporarily
/// lifted so every barrier could finish:
///
/// - isolated: 11 barrier executions, worst 253 ms;
/// - 2x CPU oversubscription: worst 477 ms and 578 ms over two runs;
/// - 5x CPU oversubscription: worst 1052 / 3568 / 4007 ms over three runs.
///
/// Every run completed every barrier, so contention makes convergence late
/// rather than absent. The former 3 s budget carried ~12x headroom isolated
/// but sat inside the 5x distribution, which is where the CI flake lives.
///
/// Note the slowest barrier is environment-dependent — locally it is "relay
/// observes sender extension", while the CI failure was "sender observes
/// released relay extension", which never exceeded 598 ms here. That is why
/// this stays a single shared budget: per-barrier budgets would over-fit to
/// whichever step happened to be slow on the measuring host. 15 s is ~3.7x the
/// slowest measured barrier and far inside nextest's 600 s terminate-after.
const PHASE: Duration = Duration::from_secs(15);
const WINDOW: Duration = Duration::from_millis(300);

async fn until(label: &'static str, mut ready: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(PHASE, async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    outcome.unwrap_or_else(|_| {
        panic!(
            "phase barrier ({PHASE:?}, waited {}ms): {label}",
            started.elapsed().as_millis()
        )
    });
}

async fn build(dir: &std::path::Path, name: &str, candidates: Vec<String>) -> Agent {
    Agent::builder()
        .with_machine_key(dir.join(format!("{name}-machine")))
        .with_agent_key_path(dir.join(format!("{name}-agent")))
        .with_contact_store_path(dir.join(format!("{name}-contacts.json")))
        .with_peer_cache_disabled()
        .with_network_config(network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
            bootstrap_nodes: vec![],
            port_mapping_enabled: false,
            mdns_enabled: false,
            peer_relay: network::PeerRelayConfig {
                enabled: true,
                candidates,
                require_contact_to_relay: true,
                ..Default::default()
            },
            ..Default::default()
        })
        .build()
        .await
        .expect("real Agent setup must succeed; no bind-denial skip")
}

async fn discover(owner: &Agent, peer: &Agent) {
    let addr = peer
        .network()
        .expect("network")
        .bound_addr()
        .await
        .expect("bound address");
    assert!(addr.ip().is_loopback());
    owner
        .insert_discovered_agent_for_testing(DiscoveredAgent {
            self_name: None,
            cert_digest: None,
            agent_id: peer.agent_id(),
            machine_id: peer.machine_id(),
            user_id: None,
            addresses: vec![addr],
            announced_at: dm::now_unix_ms() / 1000,
            last_seen: dm::now_unix_ms() / 1000,
            machine_public_key: vec![],
            nat_type: None,
            can_receive_direct: Some(true),
            is_relay: Some(true),
            is_coordinator: None,
            reachable_via: vec![],
            relay_candidates: vec![],
            cert_not_after: None,
            agent_certificate: None,
            agent_public_key: vec![],
        })
        .await;
    owner.set_contact_trusted_for_testing(peer.agent_id()).await;
}

fn events(agent: &Agent) -> Vec<ConvergenceEvent> {
    let snapshot = agent
        .peer_relay()
        .convergence_snapshot()
        .expect("installed healthy observer");
    assert!(
        !snapshot.overflow && !snapshot.decode_failed,
        "incomplete observer"
    );
    snapshot.events
}

fn baseline(agent: &Agent, sender: &Agent) -> bool {
    let snapshot = agent
        .peer_relay()
        .digest_diagnostic_snapshot(std::time::Instant::now(), Some(sender.agent_id().0));
    assert!(snapshot.totals.is_some(), "baseline snapshot unavailable");
    snapshot
        .rows
        .get(&sender.agent_id().0)
        .is_some_and(|r| r.state == "fresh")
}

async fn received_event(relay: &Agent, id: [u8; 16]) -> ConvergenceEvent {
    until("relay input classification recorded", || {
        events(relay).iter().any(|e| e.request_id == id)
    })
    .await;
    let matching: Vec<_> = events(relay)
        .into_iter()
        .filter(|e| e.request_id == id)
        .collect();
    assert_eq!(matching.len(), 1, "one observed relay input per request");
    matching[0].clone()
}

fn validate_delivery(
    msg: &direct::DirectMessage,
    sender: &Agent,
    relay: &Agent,
    destination: &Agent,
    kem: &AgentKemKeypair,
    id: [u8; 16],
    payload: &[u8],
) {
    assert_eq!(msg.sender, relay.agent_id());
    assert_eq!(msg.machine_id, relay.machine_id());
    assert!(msg.verified);
    let envelope = DmEnvelope::from_wire_bytes(&msg.payload).expect("real received envelope");
    assert_eq!(envelope.request_id, id);
    assert_eq!(envelope.sender_agent_id, sender.agent_id().0);
    assert_eq!(envelope.recipient_agent_id, destination.agent_id().0);
    let DmBody::Payload(body) = &envelope.body else {
        panic!("expected encrypted payload")
    };
    let plain =
        dm::decrypt_payload(kem, body, &envelope.aead_aad()).expect("decrypt actual delivery");
    assert_eq!(plain.request_id, id);
    assert_eq!(plain.payload, payload);
}

#[derive(Default)]
struct Counts {
    matching: u64,
    unrelated: u64,
}

async fn count_window(rx: &mut direct::DirectMessageReceiver, id: [u8; 16]) -> Counts {
    let deadline = tokio::time::Instant::now() + WINDOW;
    let mut counts = Counts::default();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Err(_) => break,
            Ok(None) => panic!("delivery channel closed"),
            Ok(Some(msg)) => {
                if DmEnvelope::from_wire_bytes(&msg.payload).is_ok_and(|e| e.request_id == id) {
                    counts.matching = counts.matching.checked_add(1).expect("bounded count");
                } else {
                    counts.unrelated = counts.unrelated.checked_add(1).expect("bounded count");
                }
            }
        }
    }
    counts
}

struct Evidence<'a> {
    sink: &'a mut Option<custody::Sink>,
    agents: &'a [Agent],
    service: &'a dm_capability_service::ConvergenceServiceObserver,
}

impl Evidence<'_> {
    fn save(&mut self, checkpoint: Option<&str>) {
        if let Some(sink) = self.sink {
            sink.capture(self.agents, Some(self.service));
            let previous = sink.value["checkpoint"]
                .as_str()
                .expect("closed checkpoint")
                .to_owned();
            sink.write("partial", checkpoint.unwrap_or(&previous))
                .expect("persist requested phase custody");
        }
    }
    fn enter(&mut self, phase: &str, id: [u8; 16], before: &peer_relay::RelayStatsSnapshot) {
        if let Some(sink) = self.sink {
            sink.value["phases"][phase] = json!({"request_id":hex::encode(id),"outcome":"entered",
                "delivery_count":null,"extra_count":null,"unrelated_count":null,"window_ms":null,
                "forwarded_before":before.relay_forwarded,"forwarded_after":null,
                "refused_before":before.relay_refused_missing_inner_digest,"refused_after":null,
                "extension_present":null,"baseline_present":null});
        }
        self.save(None);
    }
    fn counts(&mut self, phase: &str, delivered: u64, extra: u64, unrelated: u64) {
        let relay = &self.agents[0];
        let sender = &self.agents[2];
        let after = relay.peer_relay().stats().snapshot();
        if let Some(sink) = self.sink {
            let p = &mut sink.value["phases"][phase];
            p["delivery_count"] = json!(delivered);
            p["extra_count"] = json!(extra);
            p["unrelated_count"] = json!(unrelated);
            p["window_ms"] = json!(300);
            p["forwarded_after"] = json!(after.relay_forwarded);
            p["refused_after"] = json!(after.relay_refused_missing_inner_digest);
            p["extension_present"] = json!(sender
                .capability_store
                .lookup(&relay.agent_id())
                .is_some_and(|c| c.digest_support));
            p["baseline_present"] = json!(baseline(relay, sender));
        }
        self.save(None);
    }
    fn observed(&mut self, phase: &str) {
        if let Some(sink) = self.sink {
            sink.value["phases"][phase]["outcome"] = json!("observed");
        }
        self.save(Some(phase));
    }
}

async fn positive(
    evidence: &mut Evidence<'_>,
    kem: &AgentKemKeypair,
    rx: &mut direct::DirectMessageReceiver,
    payload: &[u8],
    bound: bool,
) -> [u8; 16] {
    let (relay, destination, sender) = (
        &evidence.agents[0],
        &evidence.agents[1],
        &evidence.agents[2],
    );
    let phase = if bound { "bound" } else { "legacy" };
    let before = relay.peer_relay().stats().snapshot();
    let receipt = tokio::time::timeout(
        PHASE,
        sender.try_relay_fallback(&destination.agent_id(), payload.to_vec(), &kem.public_bytes),
    )
    .await
    .expect("relay helper deadline")
    .expect("real relay send");
    evidence.enter(phase, receipt.request_id, &before);
    assert!(matches!(receipt.path, DmPath::Relayed { via } if via == relay.agent_id()));
    let sent: Vec<_> = events(sender)
        .into_iter()
        .filter(|e| e.request_id == receipt.request_id)
        .collect();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].hop, relay.agent_id().0);
    assert_eq!(sent[0].sender, sender.agent_id().0);
    assert_eq!(sent[0].destination, destination.agent_id().0);
    assert_eq!(sent[0].digest_present, bound);
    assert!(sent[0].sent_wire.is_some_and(|(len, _)| len > 0));
    let incoming = received_event(relay, receipt.request_id).await;
    assert_eq!(incoming.hop, sender.machine_id().0);
    assert_eq!(incoming.prefix, sender.agent_id().0);
    assert_eq!(incoming.sender, sender.agent_id().0);
    assert_eq!(incoming.destination, destination.agent_id().0);
    assert_eq!(incoming.digest_present, bound);
    // This is the pre-revocation classifier result, not terminal forwarding.
    // Production forward counters and actual D decryption prove the outcome.
    assert_eq!(
        incoming.disposition,
        Some(RelayDisposition::Forward {
            dst_agent_id: destination.agent_id().0
        })
    );
    let msg = tokio::time::timeout(PHASE, rx.recv())
        .await
        .expect("D delivery deadline")
        .expect("D receiver open");
    validate_delivery(
        &msg,
        sender,
        relay,
        destination,
        kem,
        receipt.request_id,
        payload,
    );
    let counts = count_window(rx, receipt.request_id).await;
    let total = counts
        .matching
        .checked_add(1)
        .expect("bounded delivery count");
    // Retain the measured receiver counts even if the subsequent commit
    // barrier fails; the second snapshot records the actual completed counter.
    evidence.counts(phase, total, counts.matching, counts.unrelated);
    let expected_forwarded = before
        .relay_forwarded
        .checked_add(1)
        .expect("bounded forward count");
    until("positive forward counter committed", || {
        relay.peer_relay().stats().snapshot().relay_forwarded >= expected_forwarded
    })
    .await;
    evidence.counts(phase, total, counts.matching, counts.unrelated);
    let after = relay.peer_relay().stats().snapshot();
    assert_eq!(
        after.relay_forwarded, expected_forwarded,
        "positive forward counter overshoot"
    );
    assert_eq!(total, 1, "bounded positive delivery count");
    assert_eq!(counts.unrelated, 0, "exclusive fixture unrelated count");
    assert_eq!(baseline(relay, sender), bound, "phase baseline");
    assert_eq!(
        after.relay_refused_missing_inner_digest,
        before.relay_refused_missing_inner_digest
    );
    evidence.observed(phase);
    receipt.request_id
}

#[tokio::test]
async fn asymmetric_signed_capability_convergence_over_relay() {
    let dir = tempfile::tempdir().expect("fixture directory");
    let mut sink = custody::Sink::activate(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
        .expect("requested custody must be valid before Agent setup");
    let mut agents = Vec::new();
    let mut installed_service_observer = None;
    // Retain every successfully built Agent for shutdown even if later setup,
    // phase assertions or cryptography panic. Never credit cleanup as custody.
    let outcome = AssertUnwindSafe(async {
        agents.push(build(dir.path(), "relay", vec![]).await);
        agents.push(build(dir.path(), "destination", vec![]).await);
        agents.push(build(dir.path(), "sender", vec![hex::encode(agents[0].agent_id().0)]).await);
        let (r, d, s) = (&agents[0], &agents[1], &agents[2]);
        let keys: Vec<_> = (0..3).map(|_| Arc::new(AgentKemKeypair::generate().expect("real KEM"))).collect();
        for (agent, key) in agents.iter().zip(&keys) {
            assert!(agent.capability_advert_service.lock().await.is_none());
            agent.start_dm_inbox(Arc::clone(key), dm_inbox::DmInboxConfig::default()).await.expect("real inbox");
            agent.peer_relay().enable_convergence_observer().expect("observer once before traffic");
        }
        let ready = r.current_dm_capabilities();
        assert!(ready.gossip_inbox && ready.digest_support && !ready.kem_public_key.is_empty());
        // This deliberately holds publication input pending while the actual
        // inbox remains live. No other lifecycle setter is used during hold.
        r.dm_capabilities_tx.send_replace(DmCapabilities::pending());
        let service_observer = Arc::new(dm_capability_service::ConvergenceServiceObserver::default());
        *r.capability_convergence_observer.lock().unwrap() = Some(Arc::clone(&service_observer));
        installed_service_observer = Some(Arc::clone(&service_observer));
        for agent in &agents {
            agent.join_network().await.expect("join actual runtime");
            assert!(agent.capability_advert_service.lock().await.is_some());
        }
        for owner in &agents { for peer in &agents { if owner.agent_id() != peer.agent_id() { discover(owner, peer).await; } } }
        for (from, to) in [(s, r), (r, d)] {
            let addr = to.network().unwrap().bound_addr().await.unwrap();
            let connected = tokio::time::timeout(PHASE, from.network().unwrap().connect_addr(addr)).await.expect("connect deadline").expect("real connect");
            assert_eq!(connected.0, to.machine_id().0);
        }
        for agent in &agents { agent.gossip_runtime.as_ref().unwrap().pubsub().refresh_topic_peers().await; }
        dm_capability_service::publish_targeted_capability_request(r.gossip_runtime.as_ref().unwrap().pubsub(), s.agent_id()).await.expect("request S capability through real PubSub");
        until("relay observes sender extension", || r.capability_store.lookup(&s.agent_id()).is_some_and(|c| c.digest_support)).await;
        assert!(!baseline(r, s));
        assert_eq!(r.capability_store.lookup_binding(&s.agent_id()).unwrap().machine_id, s.machine_id());
        if let Some(sink) = &mut sink {
            sink.value["topology"] = json!({"s":{"agent_id":hex::encode(s.agent_id().0),"machine_id":hex::encode(s.machine_id().0)},
                "r":{"agent_id":hex::encode(r.agent_id().0),"machine_id":hex::encode(r.machine_id().0)},
                "d":{"agent_id":hex::encode(d.agent_id().0),"machine_id":hex::encode(d.machine_id().0)}});
        }
        let mut evidence = Evidence { sink: &mut sink, agents: &agents, service: &service_observer };
        evidence.save(Some("setup"));
        let signing = gossip::SigningContext::from_keypair(r.identity.agent_keypair());
        let base = dm_capability_service::build_signed_advert(&signing, r.agent_id(), r.machine_id(), ready.clone()).expect("signed actual-ready base");
        r.publish(dm_capability::DM_CAPABILITY_TOPIC, base).await.expect("actual signed base publication");
        until("sender observes held relay base without extension", || s.capability_store.lookup(&r.agent_id()).is_some_and(|c| c.gossip_inbox && c.kem_public_key == ready.kem_public_key && !c.digest_support)).await;
        assert_eq!(s.capability_store.lookup_binding(&r.agent_id()).unwrap().machine_id, r.machine_id());
        use dm_capability_service::ServiceEvent;
        until("held service initially skips pending publication", || service_observer.snapshot().unwrap().contains(&ServiceEvent::PendingSkip)).await;
        assert!(service_observer.snapshot().unwrap().iter().all(|e| matches!(e, ServiceEvent::PendingSkip)));
        let cut = service_observer.snapshot().unwrap().len();
        // One signed Critical carrier only: the production request helper's
        // dual carriers intentionally coalesce and cannot identify consumption
        // per request. Do not pretend its unit queue carries request IDs.
        let request = dm_capability_service::convergence_request_bytes(r.agent_id());
        use sha2::{Digest, Sha256};
        let request_hash: [u8; 32] = Sha256::digest(&request).into();
        s.publish(dm_capability::DM_CAPABILITY_TARGETED_REQUEST_TOPIC, request).await.expect("signed actual held request");
        until("held request enqueued consumed and pending-skipped", || {
            let records = service_observer.snapshot().unwrap();
            let records = &records[cut..];
            records.iter().any(|e| matches!(e, ServiceEvent::Enqueue { accepted: true, .. }))
                && records.iter().position(|e| matches!(e, ServiceEvent::Consumed)).is_some_and(|i|
                    records[i+1..].contains(&ServiceEvent::PendingSkip))
        }).await;
        let verify_held_request = || {
            let records = service_observer.snapshot().unwrap();
            let enqueued: Vec<_> = records.iter().filter(|e| matches!(e, ServiceEvent::Enqueue { .. })).collect();
            assert_eq!(enqueued, vec![&ServiceEvent::Enqueue { requester: s.agent_id().0, carrier: "critical", payload_hash: request_hash, accepted: true }]);
            assert_eq!(records.iter().filter(|e| matches!(e, ServiceEvent::Consumed)).count(), 1);
            assert!(!r.current_dm_capabilities().gossip_inbox);
            assert!(!s.capability_store.lookup(&r.agent_id()).unwrap().digest_support);
        };
        verify_held_request();
        if let Some(sink) = &mut evidence.sink {
            sink.value["preconditions"] = json!({"relay_inbox_ready":ready.gossip_inbox,
                "relay_watch_held":!r.current_dm_capabilities().gossip_inbox,
                "sender_has_relay_base":s.capability_store.lookup(&r.agent_id()).is_some(),
                "sender_has_relay_extension":s.capability_store.lookup(&r.agent_id()).is_some_and(|c| c.digest_support),
                "relay_has_sender_extension":r.capability_store.lookup(&s.agent_id()).is_some_and(|c| c.digest_support),
                "relay_has_sender_v2_baseline":baseline(r,s)});
        }
        evidence.save(Some("held_request"));
        let mut rx = d.subscribe_direct();
        let first = positive(&mut evidence, &keys[1], &mut rx, b"asymmetric legacy payload", false).await;
        assert!(!baseline(r, s));
        verify_held_request();
        r.dm_capabilities_tx.send_replace(ready);
        until("sender observes released relay extension", || s.capability_store.lookup(&r.agent_id()).is_some_and(|c| c.digest_support)).await;
        let second = positive(&mut evidence, &keys[1], &mut rx, b"converged bound payload", true).await;
        assert_ne!(first, second);
        assert!(baseline(r, s));
        until("both positive forwards committed before downgrade", || r.peer_relay().stats().snapshot().relay_forwarded >= 2).await;
        let before = r.peer_relay().stats().snapshot();
        assert_eq!(before.relay_forwarded, 2, "forward counter before downgrade");
        // Deliberately crafted negative: this bypasses S's v2 frame choice,
        // but retains real signing, encryption, network and R enforcement.
        let id = dm_send::fresh_request_id();
        assert!(id != first && id != second);
        evidence.enter("downgrade", id, &before);
        let now = dm::now_unix_ms();
        let signing = gossip::SigningContext::from_keypair(s.identity.agent_keypair());
        let inner = dm::EnvelopeBuilder::build_payload_envelope(id, &s.agent_id(), &s.machine_id(),
            s.identity.machine_keypair(), &d.agent_id(), &keys[1].public_bytes,
            now, now + dm_send::DEFAULT_ENVELOPE_LIFETIME_MS, b"fresh downgrade payload".to_vec(),
            |bytes| signing.sign(bytes).map_err(|e| e.to_string())).expect("fresh actual sealed envelope");
        let frame = s.peer_relay().build_relayed_dm(&d.agent_id(), &s.agent_id(), signing.public_key_bytes.clone(), now, inner, false,
            |bytes| signing.sign(bytes).map_err(|e| e.to_string())).expect("fresh signed v1 negative");
        tokio::time::timeout(PHASE, s.network().unwrap().send_direct_typed(&ant_quic::PeerId(r.machine_id().0),
            s.agent_id().as_bytes(), network::RELAYED_DM_STREAM_TYPE, &frame.to_postcard().expect("v1 wire")))
            .await.expect("negative send deadline").expect("actual negative network send");
        let refusal = received_event(r, id).await;
        assert_eq!(refusal.hop, s.machine_id().0);
        assert_eq!(refusal.prefix, s.agent_id().0);
        assert_eq!(refusal.disposition, Some(RelayDisposition::Refuse(RelayRefusal::MissingInnerDigest)));
        let counts = count_window(&mut rx, id).await;
        evidence.counts("downgrade", counts.matching, counts.matching.saturating_sub(1), counts.unrelated);
        assert_eq!(counts.matching, 0, "no downgrade delivery through bounded post-barrier window");
        assert_eq!(counts.unrelated, 0, "exclusive negative window");
        let after = r.peer_relay().stats().snapshot();
        assert_eq!(after.relay_refused_missing_inner_digest, before.relay_refused_missing_inner_digest + 1);
        assert_eq!(after.relay_forwarded, before.relay_forwarded);
        assert_eq!(events(r).len(), 3);
        evidence.observed("downgrade");
        eprintln!("ISSUE442_PHASES legacy=1 bound=1 downgrade=0 positive_window_ms=300 negative_window_ms=300");
    }).catch_unwind().await;
    if outcome.is_err() {
        if let Some(sink) = &mut sink {
            sink.capture(&agents, installed_service_observer.as_deref());
            let checkpoint = sink.value["checkpoint"]
                .as_str()
                .expect("closed checkpoint")
                .to_owned();
            if sink.write("partial", &checkpoint).is_err() {
                eprintln!("ISSUE442_CUSTODY partial_write_failed");
            }
        }
    }
    for agent in &agents {
        agent.shutdown().await;
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    if let Some(sink) = sink {
        // Preserve the last asserted phase payload across shutdown. Completion
        // consumes the sink and cannot re-read any observer or Agent state.
        sink.complete_after_cleanup()
            .expect("persist completed requested custody after cleanup");
    }
}
