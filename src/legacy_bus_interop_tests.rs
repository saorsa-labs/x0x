#![cfg(test)]

//! Real separate-peer component controls for #501. These exercise the signed
//! gossip carriers, not Agent::send_direct route selection or durable v2 ACKs.
//! Controlled load reports send attempts only; no wire reduction, forwarding
//! attribution, public Leaf field acceptance or policy adoption is implied.

use crate::dm::{self, DmPath, DmSendConfig, DurableSendStages, EnvelopeBuilder, DM_PROTOCOL_V1};
use crate::dm_inbox::{DmInboxConfig, DmInboxService, DmTypedPayload, DM_BUS_TOPIC};
use crate::dm_send::{self, DmSendContext};
use crate::gossip::{PubSubManager, SigningContext};
use crate::groups::kem_envelope::AgentKemKeypair;
use crate::trust::TrustDecision;
use crate::{network, Agent};
use bytes::Bytes;
use futures::FutureExt;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

const PREFIX: &[u8] = b"x0x-501-interop\0";
const SETUP: Duration = Duration::from_secs(20);
const DELIVERY: Duration = Duration::from_secs(10);
const NEGATIVE_WINDOW: Duration = Duration::from_millis(300);

type Inbox = mpsc::Receiver<DmTypedPayload>;

fn pubsub(agent: &Agent) -> Arc<PubSubManager> {
    Arc::clone(
        agent
            .gossip_runtime
            .as_ref()
            .expect("real gossip runtime")
            .pubsub(),
    )
}

async fn bounded<T>(label: &'static str, budget: Duration, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(budget, future)
        .await
        .unwrap_or_else(|_| panic!("#501 labelled deadline: {label}"))
}

async fn build(dir: &Path, name: &str, skip: bool) -> Agent {
    let home = dir.join(name);
    assert!(!home.exists(), "each fixture identity starts absent");
    // Every identity/storage input is fixture-owned; no persisted peer cache,
    // mDNS, UPnP or embedded bootstrap destinations are used.
    let builder = Agent::builder()
        .with_identity_dir(&home)
        .with_machine_key(home.join("machine.key"))
        .with_agent_key_path(home.join("agent.key"))
        .with_user_key_path(home.join("user.key"))
        .with_agent_cert_path(home.join("agent.cert"))
        .with_contact_store_path(home.join("contacts.json"))
        .with_peer_cache_dir(home.join("peers"))
        .with_peer_cache_disabled()
        .with_network_config(network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback address")),
            bootstrap_nodes: vec![],
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..Default::default()
        });
    // The default arm really uses AgentBuilder's default; only O opts out.
    let builder = if skip {
        builder.with_skip_legacy_dm_bus(true)
    } else {
        builder
    };
    builder
        .build()
        .await
        .expect("real Agent construction; no setup-success skip")
}

async fn prepare(agents: &[Agent], keys: &[Arc<AgentKemKeypair>]) -> Vec<Inbox> {
    let mut receivers = Vec::new();
    for (agent, key) in agents.iter().zip(keys) {
        // Contacts and their machine records contain the peers' actual keys;
        // no synthetic delivered message or discovery record is injected.
        for peer in agents {
            if peer.agent_id() != agent.agent_id() {
                agent.set_contact_trusted_for_testing(peer.agent_id()).await;
                agent.contact_store().write().await.add_machine(
                    &peer.agent_id(),
                    crate::contacts::MachineRecord::new(peer.machine_id(), None),
                );
            }
        }
        let (tx, rx) = mpsc::channel(16);
        agent
            .start_dm_inbox(
                Arc::clone(key),
                DmInboxConfig::default().with_typed_payload_route(PREFIX, tx),
            )
            .await
            .expect("real typed inbox before publication");
        receivers.push(rx);
    }
    for agent in agents {
        agent.join_network().await.expect("join actual runtime");
    }
    // Dial each pair once. No retry-until-delivery or synthetic peer admission.
    for (i, from) in agents.iter().enumerate() {
        for to in &agents[i + 1..] {
            let address = to
                .network()
                .expect("network")
                .bound_addr()
                .await
                .expect("bound");
            assert!(address.ip().is_loopback());
            let peer = bounded(
                "pair connection",
                SETUP,
                from.network().expect("network").connect_addr(address),
            )
            .await
            .expect("actual QUIC connection");
            assert_eq!(peer.0, to.machine_id().0);
        }
    }
    bounded("all counterparts admitted to gossip plane", SETUP, async {
        loop {
            let mut ready = true;
            for agent in agents {
                // This is active setup readiness, not a passive measurement.
                let peers = agent.network().expect("network").gossip_plane_peers().await;
                ready &= agents
                    .iter()
                    .filter(|p| p.agent_id() != agent.agent_id())
                    .all(|p| peers.contains(&ant_quic::PeerId(p.machine_id().0)));
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    for agent in agents {
        pubsub(agent).refresh_topic_peers().await;
    }
    receivers
}

fn marked(label: &str) -> Vec<u8> {
    [PREFIX, label.as_bytes()].concat()
}

fn envelope(
    sender: &Agent,
    recipient: &Agent,
    key: &AgentKemKeypair,
    request_id: [u8; 16],
    payload: Vec<u8>,
) -> Vec<u8> {
    let signing = SigningContext::from_keypair(sender.identity.agent_keypair());
    let now = dm::now_unix_ms();
    let envelope = EnvelopeBuilder::build_payload_envelope_with_version(
        DM_PROTOCOL_V1,
        request_id,
        &sender.agent_id(),
        &sender.machine_id(),
        sender.identity.machine_keypair(),
        &recipient.agent_id(),
        &key.public_bytes,
        now,
        now + dm_send::DEFAULT_ENVELOPE_LIFETIME_MS,
        payload,
        |bytes| signing.sign(bytes).map_err(|e| e.to_string()),
    )
    .expect("real encrypted and machine-attested envelope");
    assert_eq!(envelope.protocol_version, DM_PROTOCOL_V1);
    assert_eq!(envelope.request_id, request_id);
    envelope
        .to_wire_bytes()
        .expect("serialize exact inner ciphertext")
}

async fn delivered(rx: &mut Inbox, sender: &Agent, id: [u8; 16], payload: &[u8]) {
    let actual = bounded("receiver typed decrypt delivery", DELIVERY, rx.recv())
        .await
        .expect("typed receiver must remain open");
    assert_eq!(actual.request_id, id, "exclusive request correlation");
    assert_eq!(actual.sender, sender.agent_id());
    assert_eq!(actual.machine_id, sender.machine_id());
    assert!(actual.verified);
    assert_eq!(actual.trust_decision, Some(TrustDecision::Accept));
    assert_eq!(actual.payload, payload);
    assert!(
        actual.completion.is_none(),
        "v1 makes no durable receipt promise"
    );
}

async fn absent(rx: &mut Inbox, id: [u8; 16]) {
    // Called immediately after the awaited bus publish returns; fanout and
    // the return do not establish remote delivery. Reject even unrelated
    // fixture traffic rather than quietly consume it in this exclusive cut.
    match tokio::time::timeout(NEGATIVE_WINDOW, rx.recv()).await {
        Err(_) => {}
        Ok(None) => panic!("negative invalid: receiver closed"),
        Ok(Some(actual)) => panic!(
            "negative invalid: received {:?}, expected no {:?}",
            actual.request_id, id
        ),
    }
}

#[derive(Default)]
struct TraceFields {
    stage: Option<String>,
    request_id: Option<String>,
}

impl Visit for TraceFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "stage" => self.stage = Some(value.to_owned()),
            "request_id" => self.request_id = Some(value.to_owned()),
            _ => {}
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "request_id" {
            self.request_id = Some(format!("{value:?}"));
        }
    }
}

#[derive(Clone)]
struct FallbackWitness {
    expected: String,
    // Fixed-size observation, no retained arbitrary fields, identities or logs.
    matches: Arc<Mutex<usize>>,
}

impl<S: tracing::Subscriber> Layer<S> for FallbackWitness {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "dm.trace" {
            return;
        }
        let mut fields = TraceFields::default();
        event.record(&mut fields);
        if fields.stage.as_deref() == Some("legacy_bus_fallback_publish")
            && fields.request_id.as_deref() == Some(self.expected.as_str())
        {
            let mut matches = self.matches.lock().expect("healthy witness");
            *matches = matches.saturating_add(1);
        }
    }
}

async fn gossip_send(
    sender: &Agent,
    recipient: &Agent,
    key: &AgentKemKeypair,
    id: [u8; 16],
    payload: Vec<u8>,
) -> usize {
    let witness = FallbackWitness {
        expected: hex::encode(id),
        matches: Arc::new(Mutex::new(0)),
    };
    let subscriber = tracing_subscriber::registry().with(witness.clone());
    let signing = SigningContext::from_keypair(sender.identity.agent_keypair());
    let mut stages = DurableSendStages::default();
    let config = DmSendConfig {
        max_retries: 0,
        require_gossip: true,
        require_gossip_ack: true,
        require_durable_app_ack: false,
        logical_request_id: Some(id),
        ..Default::default()
    };
    // send_via_gossip builds inner V1 when durable ACK is false. This calls the
    // production gossip helper directly, NOT Agent::send_direct route selection.
    assert!(!config.require_durable_app_ack);
    let receipt = bounded(
        "production gossip helper and v1 ACK",
        DELIVERY,
        dm_send::send_via_gossip(
            DmSendContext {
                pubsub: pubsub(sender),
                signing: &signing,
                self_agent_id: sender.agent_id(),
                self_machine_id: sender.machine_id(),
                machine_keypair: sender.identity.machine_keypair(),
                inflight: sender.dm_inflight_acks(),
                stages: &mut stages,
            },
            recipient.agent_id(),
            Some(recipient.machine_id()),
            &key.public_bytes,
            payload,
            &config,
            None,
        )
        .with_subscriber(subscriber),
    )
    .await
    .expect("real helper send and correlated ACK");
    assert_eq!(receipt.request_id, id);
    assert_eq!(receipt.path, DmPath::GossipInbox);
    assert_eq!(receipt.retries_used, 0);
    let count = *witness.matches.lock().expect("healthy witness");
    eprintln!(
        "ISSUE501 helper=gossip_only inner=v1 fallback_events={count} request={}",
        hex::encode(id)
    );
    count
}

#[derive(Clone, Copy)]
enum Case {
    BusPair,
    Fallback,
    Targeted,
    Subscription,
    Measurement,
}

async fn run(case: Case) {
    let dir = tempfile::tempdir().expect("fixture directory");
    let mut agents = Vec::new();
    let mut measurement = None;
    let outcome = AssertUnwindSafe(async {
        let roles: &[(&str, bool)] = match case {
            Case::BusPair => &[("L", false), ("D", false), ("O", true)],
            Case::Fallback => &[("O2", true), ("L2", false)],
            Case::Targeted => &[("S3", false), ("O3", true)],
            Case::Subscription => &[("D", false), ("O", true)],
            Case::Measurement => &[("G5", false), ("D5", false), ("O5", true), ("W5", false)],
        };
        for (name, skip) in roles {
            // Completed builds are owned before any later setup can panic.
            agents.push(build(dir.path(), name, *skip).await);
        }
        let keys: Vec<_> = agents.iter().map(|_| Arc::new(AgentKemKeypair::generate().expect("real KEM"))).collect();
        let mut receivers = bounded("fixture services and peer setup", Duration::from_secs(90), prepare(&agents, &keys)).await;
        for (agent, (_, skip)) in agents.iter().zip(roles) {
            assert_eq!(pubsub(agent).is_topic_subscribed(DM_BUS_TOPIC).await, !*skip);
            assert!(pubsub(agent).is_topic_subscribed(&DmInboxService::inbox_topic_name(&agent.agent_id())).await);
        }
        match case {
            Case::BusPair => {
                let (l, d, o) = (&agents[0], &agents[1], &agents[2]);
                let id_d = dm_send::fresh_request_id();
                let id_o = dm_send::fresh_request_id();
                assert_ne!(id_d, id_o);
                let payload_d = marked("default-positive");
                let payload_o = marked("optout-negative-and-exact-viability");
                let wire_d = envelope(l, d, &keys[1], id_d, payload_d.clone());
                let wire_o = envelope(l, o, &keys[2], id_o, payload_o.clone());
                let fanout_d = bounded("D-addressed bus publish", DELIVERY, l.publish_with_fanout(DM_BUS_TOPIC, wire_d)).await.expect("signed outer V2 bus publish");
                delivered(&mut receivers[1], l, id_d, &payload_d).await;
                eprintln!("ISSUE501 checkpoint=default_bus_positive result=observed fanout={fanout_d} request={}", hex::encode(id_d));
                let fanout_o = bounded("O-addressed bus publish", DELIVERY, l.publish_with_fanout(DM_BUS_TOPIC, wire_o.clone())).await.expect("signed outer V2 bus publish");
                absent(&mut receivers[2], id_o).await;
                assert!(!pubsub(o).is_topic_subscribed(DM_BUS_TOPIC).await);
                eprintln!("ISSUE501 checkpoint=optout_bus_negative result=bounded_nonobservation window_ms=300 fanout={fanout_o} request={}", hex::encode(id_o));
                // No rebuild/re-encryption: move precisely the same inner wire
                // to the domain-separated targeted ID, in a fresh signed V2 carrier.
                bounded("exact O ciphertext targeted publish", DELIVERY,
                    pubsub(l).publish_topic_id(DmInboxService::inbox_topic_name(&o.agent_id()), dm::dm_inbox_topic(&o.agent_id()), Bytes::from(wire_o)))
                    .await.expect("signed targeted publish");
                delivered(&mut receivers[2], l, id_o, &payload_o).await;
                assert!(!pubsub(o).is_topic_subscribed(DM_BUS_TOPIC).await);
                eprintln!("ISSUE501 checkpoint=exact_ciphertext_viability result=observed request={}", hex::encode(id_o));
            }
            Case::Fallback => {
                let (o, l) = (&agents[0], &agents[1]);
                let inbox = DmInboxService::inbox_topic_name(&l.agent_id());
                pubsub(l).unsubscribe(&inbox).await;
                assert!(!pubsub(l).is_topic_subscribed(&inbox).await);
                assert!(pubsub(l).is_topic_subscribed(DM_BUS_TOPIC).await);
                let id = dm_send::fresh_request_id();
                let payload = marked("real-helper-bus-fallback");
                assert!(!pubsub(l).is_topic_subscribed(&inbox).await, "pre-send bus-only receiver");
                let witnesses = gossip_send(o, l, &keys[1], id, payload.clone()).await;
                assert!(!pubsub(l).is_topic_subscribed(&inbox).await, "post-send targeted topic remains absent");
                assert_eq!(witnesses, 1, "exact request-correlated production bus fallback trace");
                delivered(&mut receivers[1], o, id, &payload).await;
                assert!(!pubsub(l).is_topic_subscribed(&inbox).await);
                eprintln!("ISSUE501 checkpoint=gossip_helper_fallback result=observed");
            }
            Case::Targeted => {
                let (s, o) = (&agents[0], &agents[1]);
                let id = dm_send::fresh_request_id();
                let payload = marked("modern-targeted-control");
                gossip_send(s, o, &keys[1], id, payload.clone()).await;
                delivered(&mut receivers[1], s, id, &payload).await;
                assert!(!pubsub(o).is_topic_subscribed(DM_BUS_TOPIC).await);
                eprintln!("ISSUE501 checkpoint=modern_targeted result=observed");
            }
            Case::Measurement => measurement = Some(measure(&agents).await),
            Case::Subscription => {
                assert!(pubsub(&agents[0]).is_topic_subscribed(DM_BUS_TOPIC).await);
                assert!(!pubsub(&agents[1]).is_topic_subscribed(DM_BUS_TOPIC).await);
                eprintln!("ISSUE501 checkpoint=post_join_subscription_guard result=observed");
            }
        }
    }).catch_unwind().await;
    // Explicit orderly teardown for success AND assertion/setup panic; no
    // spawned fixture tasks are detached. Launcher custody separately proves
    // process-tree reaping; this cleanup is not a replacement for that proof.
    for agent in &agents {
        agent.shutdown().await;
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    if let Some(mut raw) = measurement {
        raw["phase"] = serde_json::json!("complete");
        raw["outcome"] = serde_json::json!("PASS");
        emit_measurement(&raw);
    }
}

#[tokio::test]
async fn bus_only_interop_default_positive_and_optout_negative() {
    run(Case::BusPair).await;
}

#[tokio::test]
async fn optout_sender_bus_fallback_reaches_bus_only_receiver() {
    run(Case::Fallback).await;
}

#[tokio::test]
async fn optout_receiver_still_receives_modern_targeted_dm() {
    run(Case::Targeted).await;
}

#[tokio::test]
async fn default_keeps_bus_subscription_and_optout_does_not() {
    run(Case::Subscription).await;
}

#[tokio::test]
async fn paired_controlled_load_bus_eager_attempts_default_vs_optout() {
    run(Case::Measurement).await;
}

// Literal source-reviewed lifetime universe, not observed subscriptions. The
// full Agent fixture starts only identity/machine/user listeners, revocation,
// move listeners, capability services, blob service and the actual DM inboxes.
// It never starts group/discovery/rendezvous applications, transfers, user-key
// creation or application sends on measured D5/O5. Include every peer's shard
// and inbox even if an individual arm never inserts a row for it.
fn topic_universe(agents: &[Agent]) -> serde_json::Value {
    use saorsa_gossip_types::TopicId;
    let fixed = [
        crate::IDENTITY_ANNOUNCE_TOPIC,
        crate::MACHINE_ANNOUNCE_TOPIC,
        crate::USER_ANNOUNCE_TOPIC,
        crate::REVOCATION_TOPIC,
        crate::MACHINE_ANNOUNCE_V3_TOPIC,
        crate::REVOCATION_V2_TOPIC,
        crate::MOVE_ACTIVATION_TOPIC,
        crate::announce_blob::ANNOUNCE_BLOB_TOPIC,
        crate::dm_capability::DM_CAPABILITY_TOPIC,
        crate::dm_capability::DM_CAPABILITY_TARGETED_REQUEST_TOPIC,
        crate::dm_capability::DM_CAPABILITY_TARGETED_RESPONSE_TOPIC,
        crate::dm_capability::DM_CAPABILITY_DIGEST_TOPIC,
        DM_BUS_TOPIC,
    ];
    let mut universe = std::collections::BTreeMap::new();
    for name in fixed {
        let id = TopicId::from_entity(name.as_bytes());
        universe.insert(hex::encode(id.as_bytes()), name.to_owned());
    }
    for agent in agents {
        assert!(
            agent.user_id().is_none(),
            "fresh missing user key; universe premise"
        );
        for name in [
            crate::shard_topic_for_agent(&agent.agent_id()),
            crate::shard_topic_for_machine(&agent.machine_id()),
        ] {
            let id = TopicId::from_entity(name.as_bytes());
            universe.insert(hex::encode(id.as_bytes()), name);
        }
        let id = dm::dm_inbox_topic(&agent.agent_id());
        universe.insert(
            hex::encode(id.as_bytes()),
            DmInboxService::inbox_topic_name(&agent.agent_id()),
        );
    }
    serde_json::json!(universe
        .into_iter()
        .map(|(full, name)| {
            serde_json::json!({"name":name,"full_id_hex":full,"topic_id_hex8":&full[..16]})
        })
        .collect::<Vec<_>>())
}

// The graph and time contract are checker constants, never record-selected.
const DIAMOND_LABELS: [&str; 4] = ["G5", "D5", "O5", "W5"];
const DIAMOND_EDGES: [(usize, usize); 4] = [(0, 3), (3, 0), (1, 2), (2, 1)];
const DIAMOND_TTL_NS: u64 = 120_000_000_000;
const DIAMOND_MARGIN_NS: u64 = 5_000_000_000;

fn diamond_expected() -> serde_json::Value {
    serde_json::json!({"G5":["D5","O5"],"D5":["G5","W5"],"O5":["G5","W5"],"W5":["D5","O5"]})
}

fn diamond_offset(clock: std::time::Instant, at: std::time::Instant) -> Option<u64> {
    u64::try_from(at.checked_duration_since(clock)?.as_nanos()).ok()
}

fn diamond_now(clock: std::time::Instant) -> u64 {
    diamond_offset(clock, std::time::Instant::now())
        .expect("INCONCLUSIVE: same-process clock range")
}

async fn diamond_observations(agents: &[Agent], clock: std::time::Instant) -> serde_json::Value {
    let mut observations = serde_json::Map::new();
    for (label, agent) in DIAMOND_LABELS.iter().zip(agents) {
        let begin = diamond_now(clock);
        let peers = agent.network().expect("network").gossip_plane_peers().await;
        let end = diamond_now(clock);
        // Full, unfiltered returned IDs: an unknown peer is not silently lost.
        let admitted = peers.iter().map(|p| hex::encode(p.0)).collect::<Vec<_>>();
        observations.insert(
            (*label).into(),
            serde_json::json!({"admitted":admitted,"begin_ns":begin,"end_ns":end}),
        );
    }
    observations.into()
}

async fn diamond_suppression_check(
    agent: &Agent,
    peer: [u8; 32],
    clock: std::time::Instant,
) -> (serde_json::Value, Option<std::time::Instant>) {
    let begin = diamond_now(clock);
    let network = agent.network().expect("network");
    let set_at = network.reconnect_suppression_set_at(peer);
    let live = network.is_reconnect_suppressed(peer);
    let suppressed =
        network.peer_admission(&ant_quic::PeerId(peer)).await == network::PeerAdmission::Suppressed;
    let checked_at = std::time::Instant::now();
    let age = set_at
        .and_then(|at| checked_at.checked_duration_since(at))
        .and_then(|age| u64::try_from(age.as_nanos()).ok());
    let checked = diamond_offset(clock, checked_at);
    let end = diamond_now(clock);
    (
        serde_json::json!({"begin_ns":begin,"end_ns":end,"live":live,
        "verdict":if suppressed {"Suppressed"} else {"Other"},
        "set_at_ns":set_at.and_then(|at|diamond_offset(clock,at)),"check_ns":checked,"age_ns":age}),
        set_at,
    )
}

#[derive(Debug)]
struct RejectedReadiness {
    reason: String,
    last_observation: Option<serde_json::Value>,
    last_rejection_reason: Option<String>,
}

// One absolute deadline owns acquisition and polling. Only the full object
// validated here can become pre_cut; timed-out partial acquisitions are dropped.
async fn capture_ready_diamond<F, Fut>(
    topology: &serde_json::Value,
    deadline: tokio::time::Instant,
    mut observe: F,
) -> Result<serde_json::Value, RejectedReadiness>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    let mut rejected = RejectedReadiness {
        reason: "final diamond readiness deadline elapsed".into(),
        last_observation: None,
        last_rejection_reason: None,
    };
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(rejected);
        }
        let observed = match tokio::time::timeout_at(deadline, observe()).await {
            Ok(Ok(observed)) => observed,
            Ok(Err(reason)) => {
                rejected.reason = format!("final diamond observation failed: {reason}");
                return Err(rejected);
            }
            Err(_) => return Err(rejected),
        };
        match diamond_peer_sets(topology, &observed) {
            Ok(()) if tokio::time::Instant::now() < deadline => return Ok(observed),
            Ok(()) => return Err(rejected),
            Err(reason) => {
                rejected.last_observation = Some(observed);
                rejected.last_rejection_reason = Some(reason);
            }
        }
        if tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(10)))
            .await
            .is_err()
        {
            return Err(rejected);
        }
    }
}

fn retain_rejected_readiness(raw: &mut serde_json::Value, rejected: &RejectedReadiness) {
    raw["outcome"] = serde_json::json!("INCONCLUSIVE");
    raw["reason"] = serde_json::json!(rejected.reason);
    raw["rejected_readiness"] = serde_json::json!({
        "last_completed_rejected_observation": rejected.last_observation,
        "last_rejection_reason": rejected.last_rejection_reason,
        "completed_rejected_observation_available": rejected.last_observation.is_some(),
    });
}

async fn shape_diamond(
    agents: &[Agent],
    raw: &mut serde_json::Value,
    clock: std::time::Instant,
) -> Result<Vec<std::time::Instant>, RejectedReadiness> {
    let expected = diamond_expected();
    let peer_ids: serde_json::Map<String, serde_json::Value> = DIAMOND_LABELS
        .iter()
        .zip(agents)
        .map(|(label, a)| {
            (
                (*label).to_owned(),
                serde_json::json!(hex::encode(a.machine_id().0)),
            )
        })
        .collect();
    raw["topology"] = serde_json::json!({"expected_allowed":expected,
        "forbidden_pairs":[["G5","W5"],["D5","O5"]],"peer_ids":peer_ids,
        "operations":{},"observations":{},"suppression":{},"intervening_allowed_edge_state":"unknown",
        "configuration":"two reverse test Admin installations and two public forward disconnects; gossip admission only"});
    let mut originals = Vec::new();
    bounded("fifth-only administrative diamond shaping", SETUP, async {
        for (from, to) in [(0, 3), (1, 2)] {
            let forward = agents[from].network().expect("network");
            let reverse = agents[to].network().expect("network");
            let reverse_begin = diamond_now(clock);
            let installed = reverse.suppress_admin_reconnect_for_testing(agents[from].machine_id().0)
                .expect("INCONCLUSIVE: reverse Admin installation refused");
            let reverse_end = diamond_now(clock);
            let forward_begin = diamond_now(clock);
            forward.disconnect_with_reason(&ant_quic::PeerId(agents[to].machine_id().0), network::DisconnectReason::Admin)
                .await.expect("INCONCLUSIVE: actual forward administrative disconnect failed");
            let forward_at = forward.reconnect_suppression_set_at(agents[to].machine_id().0)
                .expect("INCONCLUSIVE: forward administrative tombstone unavailable");
            let reverse_at = reverse.reconnect_suppression_set_at(agents[from].machine_id().0)
                .expect("INCONCLUSIVE: reverse administrative tombstone unavailable");
            assert_eq!(reverse_at,installed,"INCONCLUSIVE: reverse installation timestamp changed");
            let forward_end = diamond_now(clock);
            let pair = format!("{}|{}",DIAMOND_LABELS[from],DIAMOND_LABELS[to]);
            raw["topology"]["operations"][&pair] = serde_json::json!({
                "reverse_install":{"owner":DIAMOND_LABELS[to],"peer":DIAMOND_LABELS[from],
                    "owner_peer_id":hex::encode(agents[to].machine_id().0),"peer_id":hex::encode(agents[from].machine_id().0),
                    "begin_ns":reverse_begin,"end_ns":reverse_end,"set_at_ns":diamond_offset(clock,installed),"result":"Installed"},
                "forward_disconnect":{"owner":DIAMOND_LABELS[from],"peer":DIAMOND_LABELS[to],
                    "owner_peer_id":hex::encode(agents[from].machine_id().0),"peer_id":hex::encode(agents[to].machine_id().0),
                    "begin_ns":forward_begin,"end_ns":forward_end,"set_at_ns":diamond_offset(clock,forward_at),"result":"Ok"}});
            originals.extend([forward_at,reverse_at]);
        }
    })
    .await;
    for agent in agents {
        pubsub(agent).refresh_topic_peers().await;
    }
    // Keep the existing settle outside the unchanged final 20-second budget.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let pre_cut = capture_ready_diamond(
        &raw["topology"],
        tokio::time::Instant::now() + SETUP,
        || async { Ok(diamond_observations(agents, clock).await) },
    )
    .await?;
    raw["topology"]["observations"]["pre_cut"] = pre_cut;
    for ((from, to), original) in DIAMOND_EDGES.into_iter().zip(&originals) {
        let (check, _) = bounded(
            "pre-cut directed suppression check",
            SETUP,
            diamond_suppression_check(&agents[from], agents[to].machine_id().0, clock),
        )
        .await;
        raw["topology"]["suppression"]
            [format!("{}|{}", DIAMOND_LABELS[from], DIAMOND_LABELS[to])] = serde_json::json!({
            "initial_set_at_ns":diamond_offset(clock,*original),"pre_check":check,
            "ttl_ns":DIAMOND_TTL_NS,"margin_ns":DIAMOND_MARGIN_NS});
    }
    Ok(originals)
}

fn diamond_keys(value: &serde_json::Value, expected: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("topology object missing")?;
    let actual = object
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected.iter().copied().collect() {
        return Err("topology keys mismatch".into());
    }
    Ok(())
}

fn diamond_peer_sets(
    topology: &serde_json::Value,
    observed: &serde_json::Value,
) -> Result<(), String> {
    diamond_keys(observed, &DIAMOND_LABELS)?;
    let expected = diamond_expected();
    for label in DIAMOND_LABELS {
        let actual = observed[label]["admitted"]
            .as_array()
            .ok_or("admitted peers missing")?;
        let ids = actual
            .iter()
            .map(|v| v.as_str().ok_or("admitted peer invalid"))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        let desired = expected[label]
            .as_array()
            .ok_or("literal graph")?
            .iter()
            .map(|v| {
                topology["peer_ids"][v.as_str().ok_or("literal label")?]
                    .as_str()
                    .ok_or("mapped peer missing")
            })
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        if ids.len() != actual.len() || ids != desired {
            return Err("admitted set differs from literal diamond".into());
        }
    }
    Ok(())
}

fn topology_u64(value: &serde_json::Value) -> Result<u64, String> {
    value.as_u64().ok_or("invalid topology/cut u64".into())
}

fn topology_interval(value: &serde_json::Value) -> Result<(u64, u64), String> {
    let begin = topology_u64(&value["begin_ns"])?;
    let end = topology_u64(&value["end_ns"])?;
    if begin > end {
        return Err("reversed topology interval".into());
    }
    Ok((begin, end))
}

fn validate_topology(raw: &serde_json::Value, final_required: bool) -> Result<(), String> {
    use serde_json::json;
    if raw["schema"].as_u64() != Some(2) {
        return Err("measurement schema2 required".into());
    }
    let t = &raw["topology"];
    diamond_keys(
        t,
        &[
            "expected_allowed",
            "forbidden_pairs",
            "peer_ids",
            "observations",
            "suppression",
            "intervening_allowed_edge_state",
            "configuration",
            "operations",
        ],
    )?;
    if t["expected_allowed"] != diamond_expected()
        || t["forbidden_pairs"] != json!([["G5", "W5"], ["D5", "O5"]])
        || t["intervening_allowed_edge_state"] != "unknown"
        || t["configuration"] != "two reverse test Admin installations and two public forward disconnects; gossip admission only"
    {
        return Err("literal topology contract changed".into());
    }
    diamond_keys(&t["peer_ids"], &DIAMOND_LABELS)?;
    let identities = raw["identities"]
        .as_array()
        .ok_or("identity array missing")?;
    if identities.len() != 4 {
        return Err("four identities required".into());
    }
    let mut distinct = std::collections::BTreeSet::new();
    for (i, label) in DIAMOND_LABELS.iter().enumerate() {
        let id = t["peer_ids"][label]
            .as_str()
            .ok_or("full machine ID missing")?;
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || identities[i]["machine"] != id
            || !distinct.insert(id)
        {
            return Err("full peer mapping invalid".into());
        }
    }
    let mut first_cut = u64::MAX;
    let mut last_cut = 0;
    for arm in ["D5", "O5"] {
        let (begin, end) = topology_interval(&raw["samples"][arm]["t0"])?;
        first_cut = first_cut.min(begin);
        if final_required {
            let (b, e) = topology_interval(&raw["samples"][arm]["t1"])?;
            if end >= b {
                return Err("nonmonotonic measurement cut".into());
            }
            last_cut = last_cut.max(e);
        }
    }
    diamond_keys(
        &t["observations"],
        if final_required {
            &["pre_cut", "t1"]
        } else {
            &["pre_cut"]
        },
    )?;
    for phase in if final_required {
        &["pre_cut", "t1"][..]
    } else {
        &["pre_cut"][..]
    } {
        diamond_peer_sets(t, &t["observations"][phase])?;
        for label in DIAMOND_LABELS {
            let observation = &t["observations"][phase][label];
            diamond_keys(observation, &["admitted", "begin_ns", "end_ns"])?;
            let (begin, end) = topology_interval(observation)?;
            if (*phase == "pre_cut" && end > first_cut) || (*phase == "t1" && begin < last_cut) {
                return Err("adjacency does not bracket both cuts".into());
            }
        }
    }
    diamond_keys(&t["suppression"], &["G5|W5", "W5|G5", "D5|O5", "O5|D5"])?;
    for edge in ["G5|W5", "W5|G5", "D5|O5", "O5|D5"] {
        let record = &t["suppression"][edge];
        diamond_keys(
            record,
            if final_required {
                &[
                    "initial_set_at_ns",
                    "pre_check",
                    "final_check",
                    "set_at_stable",
                    "ttl_ns",
                    "margin_ns",
                ]
            } else {
                &["initial_set_at_ns", "pre_check", "ttl_ns", "margin_ns"]
            },
        )?;
        let original = topology_u64(&record["initial_set_at_ns"])?;
        if topology_u64(&record["ttl_ns"])? != DIAMOND_TTL_NS
            || topology_u64(&record["margin_ns"])? != DIAMOND_MARGIN_NS
        {
            return Err("TTL/margin differs from Admin contract".into());
        }
        for phase in if final_required {
            &["pre_check", "final_check"][..]
        } else {
            &["pre_check"][..]
        } {
            let check = &record[phase];
            diamond_keys(
                check,
                &[
                    "begin_ns",
                    "end_ns",
                    "set_at_ns",
                    "check_ns",
                    "age_ns",
                    "live",
                    "verdict",
                ],
            )?;
            let (begin, end) = topology_interval(check)?;
            let at = topology_u64(&check["set_at_ns"])?;
            let now = topology_u64(&check["check_ns"])?;
            let age = topology_u64(&check["age_ns"])?;
            if check["live"] != true
                || check["verdict"] != "Suppressed"
                || at != original
                || at > begin
                || now < begin
                || now > end
                || now.checked_sub(at) != Some(age)
                || age
                    .checked_add(DIAMOND_MARGIN_NS)
                    .is_none_or(|n| n > DIAMOND_TTL_NS)
                || (*phase == "pre_check" && end > first_cut)
                || (*phase == "final_check" && begin < last_cut)
            {
                return Err("suppression chronology/liveness/age premise failed".into());
            }
        }
        if final_required && record["set_at_stable"] != true {
            return Err("actual same-process set_at changed".into());
        }
    }
    validate_shaping_operations(t)?;
    Ok(())
}

fn validate_shaping_operations(t: &serde_json::Value) -> Result<(), String> {
    diamond_keys(&t["operations"], &["G5|W5", "D5|O5"])?;
    for (from, to) in [("G5", "W5"), ("D5", "O5")] {
        let pair = format!("{from}|{to}");
        let reverse = format!("{to}|{from}");
        let ops = &t["operations"][&pair];
        diamond_keys(ops, &["reverse_install", "forward_disconnect"])?;
        let mut reverse_end = 0;
        for (kind, owner, peer, edge, result) in [
            ("reverse_install", to, from, reverse.as_str(), "Installed"),
            ("forward_disconnect", from, to, pair.as_str(), "Ok"),
        ] {
            let op = &ops[kind];
            diamond_keys(
                op,
                &[
                    "owner",
                    "peer",
                    "owner_peer_id",
                    "peer_id",
                    "begin_ns",
                    "end_ns",
                    "set_at_ns",
                    "result",
                ],
            )?;
            let (begin, end) = topology_interval(op)?;
            let at = topology_u64(&op["set_at_ns"])?;
            if op["owner"] != owner
                || op["peer"] != peer
                || op["owner_peer_id"] != t["peer_ids"][owner]
                || op["peer_id"] != t["peer_ids"][peer]
                || op["result"] != result
                || at < begin
                || at > end
                || at != topology_u64(&t["suppression"][edge]["initial_set_at_ns"])?
                || end > topology_u64(&t["suppression"][edge]["pre_check"]["begin_ns"])?
            {
                return Err("shaping operation binding/timestamp/result invalid".into());
            }
            if kind == "reverse_install" {
                reverse_end = end;
            } else if begin < reverse_end {
                return Err("forward close precedes reverse installation".into());
            }
        }
    }
    Ok(())
}

fn validate_topology_capture(
    pre: &serde_json::Value,
    later: &serde_json::Value,
) -> Result<(), String> {
    for field in [
        "expected_allowed",
        "forbidden_pairs",
        "peer_ids",
        "intervening_allowed_edge_state",
        "configuration",
        "operations",
    ] {
        if pre[field] != later[field] {
            return Err("topology identity replaced".into());
        }
    }
    if pre["observations"]["pre_cut"] != later["observations"]["pre_cut"] {
        return Err("pre-cut topology replaced".into());
    }
    for edge in ["G5|W5", "W5|G5", "D5|O5", "O5|D5"] {
        for field in ["initial_set_at_ns", "pre_check", "ttl_ns", "margin_ns"] {
            if pre["suppression"][edge][field] != later["suppression"][edge][field] {
                return Err("pre-cut suppression replaced".into());
            }
        }
    }
    Ok(())
}

fn raw_sample(agent: &Agent, clock: std::time::Instant) -> serde_json::Value {
    let begin = diamond_now(clock);
    let egress = agent
        .gossip_egress_diagnostics()
        .expect("actual egress getter");
    let participation = agent
        .gossip_participation()
        .expect("actual participation getter");
    let stages = pubsub(agent).stage_stats();
    serde_json::json!({"begin_ns":begin,"end_ns":diamond_now(clock),
        "egress":egress,"participation":participation,"stages":stages})
}

fn sample_rows(
    sample: &serde_json::Value,
) -> Result<std::collections::BTreeMap<String, serde_json::Value>, String> {
    let rows = sample["egress"]["outbound_by_topic_named"]
        .as_array()
        .ok_or("missing rows")?;
    let mut result = std::collections::BTreeMap::new();
    for row in rows {
        let id = row["topic_id_hex8"].as_str().ok_or("missing row ID")?;
        if result
            .insert(id.to_owned(), row["outbound"].clone())
            .is_some()
        {
            return Err("duplicate projected row".into());
        }
    }
    Ok(result)
}

fn validate_measurement(raw: &serde_json::Value) -> Result<(), String> {
    use std::collections::BTreeSet;
    validate_topology(raw, true)?;
    let u = raw["universe"].as_array().ok_or("unavailable universe")?;
    if u.is_empty() || u.len() > 64 {
        return Err("universe cardinality premise".into());
    }
    let mut projected = BTreeSet::new();
    for row in u {
        let full = row["full_id_hex"].as_str().ok_or("missing full ID")?;
        let short = row["topic_id_hex8"]
            .as_str()
            .ok_or("missing projected ID")?;
        if full.len() != 64
            || !full.bytes().all(|b| b.is_ascii_hexdigit())
            || short != &full[..16]
            || !projected.insert(short)
        {
            return Err("non-injective or invalid full-ID projection".into());
        }
    }
    let bus = saorsa_gossip_types::TopicId::from_entity(DM_BUS_TOPIC.as_bytes()).to_string();
    if !projected.contains(bus.as_str()) {
        return Err("bus missing from universe".into());
    }
    for arm in ["D5", "O5"] {
        let before = &raw["samples"][arm]["t0"];
        let after = &raw["samples"][arm]["t1"];
        let a = sample_rows(before)?;
        let b = sample_rows(after)?;
        if a.keys()
            .chain(b.keys())
            .any(|id| !projected.contains(id.as_str()))
        {
            return Err(format!("{arm}: observed topic outside admitted universe"));
        }
        if before["egress"]["subscribed_topics"] != after["egress"]["subscribed_topics"] {
            return Err(format!("{arm}: local subscribed-topic state changed"));
        }
        for sample in [before, after] {
            if sample["participation"]["mode"] != "leaf"
                || sample["egress"]["egress_budget"]["byte_policy"] != "observe_only"
            {
                return Err(format!("{arm}: fixture policy premise"));
            }
            if sample["egress"]["egress_budget"]["repair"]["tracking_overflow"].as_u64() != Some(0)
            {
                return Err(format!("{arm}: repair tracking overflow"));
            }
        }
        if before["participation"]["relay_bytes"].as_u64().is_none()
            || before["participation"]["relay_bytes"] != after["participation"]["relay_bytes"]
        {
            return Err(format!("FAIL: {arm}: relay counter changed or unavailable"));
        }
        for (id, old) in &a {
            let new = b.get(id).ok_or("counter row disappeared")?;
            for kind in ["eager", "ihave", "iwant", "anti_entropy"] {
                for field in ["msgs", "bytes"] {
                    let x = old[kind][field].as_u64().ok_or("invalid old counter")?;
                    let y = new[kind][field].as_u64().ok_or("invalid new counter")?;
                    if y < x {
                        return Err("counter decrease".into());
                    }
                }
            }
        }
        let eager =
            |rows: &std::collections::BTreeMap<String, serde_json::Value>| -> Result<u64, String> {
                match rows.get(&bus) {
                    None => Ok(0), // Only after the source-universe and continuity premises.
                    Some(row) => row["eager"]["bytes"]
                        .as_u64()
                        .ok_or("invalid bus eager bytes".into()),
                }
            };
        let delta = eager(&b)?
            .checked_sub(eager(&a)?)
            .ok_or("bus counter decreased")?;
        if arm == "D5" {
            if !b.contains_key(&bus) {
                return Err("D5 positive bus row/attempt not observed".into());
            }
            // Cached endpoint peer_scores are diagnostic only.
            if delta == 0 {
                return Err("FAIL: D5 recorded no bus eager attempts".into());
            }
        } else if delta != 0 {
            return Err("FAIL: O5 recorded bus eager attempts".into());
        }
    }
    Ok(())
}

fn emit_measurement(raw: &serde_json::Value) {
    // Raw per-test output stays private. The separately run derivation tool
    // emits hashes and numerical summaries; do not upload this identity data.
    eprintln!(
        "ISSUE501_MEASUREMENT {}",
        serde_json::to_string(raw).expect("raw evidence serialization")
    );
}

async fn measure(agents: &[Agent]) -> serde_json::Value {
    use serde_json::json;
    use sha2::{Digest, Sha256};
    let clock = std::time::Instant::now();
    let binary = std::env::current_exe().expect("executing test binary");
    let mut reader = std::fs::File::open(binary).expect("read executing binary");
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = std::io::Read::read(&mut reader, &mut buffer).expect("hash executing binary");
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    let binary_hash = hex::encode(hash.finalize());
    let mut raw = json!({"schema":2,"selector":"legacy_bus_interop_tests::paired_controlled_load_bus_eager_attempts_default_vs_optout",
        "phase":"setup","outcome":"UNRUN","pid":std::process::id(),
        "claim":"controlled bus eager send attempts; not forwarding, wire occupancy or field reduction",
        "universe":topic_universe(agents),"samples":{},"load":{},
        "identities":agents.iter().map(|a|json!({"agent":hex::encode(a.agent_id().0),"machine":hex::encode(a.machine_id().0)})).collect::<Vec<_>>(),
        "generator_peer_hex8":saorsa_gossip_types::PeerId::new(agents[0].machine_id().0).to_string(),
        "binary_sha256":binary_hash,
        "build_lock_sha256":hex::encode(Sha256::digest(include_bytes!("../Cargo.lock")))});
    let lock: toml::Value =
        toml::from_str(include_str!("../Cargo.lock")).expect("actual build lock");
    let pinned = lock["package"]
        .as_array()
        .expect("lock packages")
        .iter()
        .filter(|p| p["name"].as_str() == Some("saorsa-gossip-pubsub"))
        .collect::<Vec<_>>();
    if pinned.len() != 1
        || pinned[0]["version"].as_str() != Some("0.5.76")
        || pinned[0]["checksum"].as_str()
            != Some("f75f756d26e5011e17d15aa5cfaad17b5d56b8be37ab1003f9fd2592181ee09d")
    {
        raw["outcome"] = json!("INCONCLUSIVE");
        raw["reason"] = json!("published meter producer pin unavailable");
        emit_measurement(&raw);
        panic!("INCONCLUSIVE: lock producer premise");
    }
    // W5 already has a real bus inbox; retain an additional raw subscription
    // to count observed generator messages without attributing their path.
    let mut witness = pubsub(&agents[3]).subscribe(DM_BUS_TOPIC.to_owned()).await;
    // Front-load binary hashing, lock/universe/identity work and witness setup.
    // Only this fifth case now shapes the already prepared full mesh.
    let originals = match shape_diamond(agents, &mut raw, clock).await {
        Ok(originals) => originals,
        Err(rejected) => {
            retain_rejected_readiness(&mut raw, &rejected);
            emit_measurement(&raw);
            panic!("INCONCLUSIVE: {}", rejected.reason);
        }
    };
    let captured_pre = raw["topology"].clone();
    emit_measurement(&raw);
    raw["samples"] =
        json!({"D5":{"t0":raw_sample(&agents[1],clock)},"O5":{"t0":raw_sample(&agents[2],clock)}});
    raw["phase"] = json!("t0");
    if let Err(reason) = validate_topology(&raw, false) {
        raw["outcome"] = json!("INCONCLUSIVE");
        raw["reason"] = json!(reason);
        emit_measurement(&raw);
        panic!("INCONCLUSIVE: {reason}");
    }
    emit_measurement(&raw);
    let started = tokio::time::Instant::now();
    let mut timer = tokio::time::interval_at(started, Duration::from_millis(50));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sent = 0u64;
    let mut observed = std::collections::BTreeSet::new();
    let mut fanouts = Vec::new();
    bounded("fixed 200-publication controlled load", Duration::from_secs(30), async {
        while sent < 200 {
            tokio::select! {
                _ = timer.tick() => {
                    let mut payload = vec![0x50;4096];
                    payload[..8].copy_from_slice(&sent.to_be_bytes());
                    let fanout=agents[0].publish_with_fanout(DM_BUS_TOPIC,payload).await.expect("generator publish");
                    fanouts.push(fanout);sent+=1;
                }
                message=witness.recv() => {
                    let message=message.expect("W5 raw receiver open");
                    if message.sender==Some(agents[0].agent_id()) && message.verified && message.payload.len()==4096 && message.payload[8..].iter().all(|&b|b==0x50) {
                        let seq=u64::from_be_bytes(message.payload[..8].try_into().expect("eight bytes"));
                        if seq<200 { observed.insert(seq); }
                    }
                }
            }
        }
    }).await;
    raw["samples"]["D5"]["t1"] = raw_sample(&agents[1], clock);
    raw["samples"]["O5"]["t1"] = raw_sample(&agents[2], clock);
    raw["load"] = json!({"sent":sent,"payload_bytes":4096,"period_ms":50,"elapsed_ns":started.elapsed().as_nanos() as u64,"fanouts":fanouts,"witness_observed_during_load":observed.len(),"witness_attribution":"none"});
    raw["topology"]["observations"]["t1"] = bounded(
        "final diamond observation",
        SETUP,
        diamond_observations(agents, clock),
    )
    .await;
    for ((from, to), original) in DIAMOND_EDGES.into_iter().zip(&originals) {
        let (check, returned) = bounded(
            "final directed suppression check",
            SETUP,
            diamond_suppression_check(&agents[from], agents[to].machine_id().0, clock),
        )
        .await;
        let edge = format!("{}|{}", DIAMOND_LABELS[from], DIAMOND_LABELS[to]);
        raw["topology"]["suppression"][&edge]["set_at_stable"] = json!(returned == Some(*original));
        raw["topology"]["suppression"][&edge]["final_check"] = check;
    }
    raw["phase"] = json!("t1");
    emit_measurement(&raw);
    match validate_topology_capture(&captured_pre, &raw["topology"])
        .and_then(|()| validate_measurement(&raw))
    {
        Ok(()) => {
            raw["outcome"] = json!("OBSERVED");
            raw["phase"] = json!("validated");
            emit_measurement(&raw);
        }
        Err(reason) => {
            let outcome = if reason.starts_with("FAIL:") {
                "FAIL"
            } else {
                "INCONCLUSIVE"
            };
            raw["outcome"] = json!(outcome);
            raw["reason"] = json!(reason);
            emit_measurement(&raw);
            panic!("{outcome}: measurement premises/oracle not established: {reason}");
        }
    }
    raw
}

// JSON-only controls: no Agent, socket, runtime or transport construction.
fn synthetic_diamond_evidence() -> serde_json::Value {
    use serde_json::json;
    let mut raw = json!({"schema":2,"identities":[],"samples":{},"topology":{
        "expected_allowed":diamond_expected(),"forbidden_pairs":[["G5","W5"],["D5","O5"]],
        "peer_ids":{},"observations":{"pre_cut":{},"t1":{}},"suppression":{},
        "intervening_allowed_edge_state":"unknown",
        "configuration":"two reverse test Admin installations and two public forward disconnects; gossip admission only"}});
    for (i, label) in DIAMOND_LABELS.into_iter().enumerate() {
        let id = format!("{:064x}", i + 1);
        raw["identities"]
            .as_array_mut()
            .expect("array")
            .push(json!({"machine":id}));
        raw["topology"]["peer_ids"][label] = json!(id);
    }
    for label in DIAMOND_LABELS {
        let peers = diamond_expected()[label]
            .as_array()
            .expect("literal")
            .iter()
            .map(|v| raw["topology"]["peer_ids"][v.as_str().expect("label")].clone())
            .collect::<Vec<_>>();
        for (phase, at) in [("pre_cut", 1_000_000_000u64), ("t1", 13_000_000_000)] {
            raw["topology"]["observations"][phase][label] =
                json!({"begin_ns":at,"end_ns":at+1,"admitted":peers});
        }
    }
    for arm in ["D5", "O5"] {
        raw["samples"][arm] = json!({"t0":{"begin_ns":2_000_000_000u64,"end_ns":2_000_000_001u64},
            "t1":{"begin_ns":12_000_000_000u64,"end_ns":12_000_000_001u64}});
    }
    for edge in ["G5|W5", "W5|G5", "D5|O5", "O5|D5"] {
        let mut row = json!({"initial_set_at_ns":100,"ttl_ns":DIAMOND_TTL_NS,"margin_ns":DIAMOND_MARGIN_NS,"set_at_stable":true});
        for (phase, at) in [
            ("pre_check", 1_000_000_000u64),
            ("final_check", 13_000_000_000),
        ] {
            row[phase] = json!({"begin_ns":at,"end_ns":at+2,"set_at_ns":100,"check_ns":at+1,
                "age_ns":at+1-100,"live":true,"verdict":"Suppressed"});
        }
        raw["topology"]["suppression"][edge] = row;
    }
    for (from, to) in [("G5", "W5"), ("D5", "O5")] {
        let pair = format!("{from}|{to}");
        for (kind, owner, peer, begin, end, result) in [
            ("reverse_install", to, from, 99, 100, "Installed"),
            ("forward_disconnect", from, to, 100, 101, "Ok"),
        ] {
            raw["topology"]["operations"][&pair][kind] = json!({"owner":owner,"peer":peer,
                "owner_peer_id":raw["topology"]["peer_ids"][owner],"peer_id":raw["topology"]["peer_ids"][peer],
                "begin_ns":begin,"end_ns":end,"set_at_ns":100,"result":result});
        }
    }
    raw
}

#[test]
fn diamond_validator_literal_graph_and_full_peer_sets() {
    use serde_json::json;
    let good = synthetic_diamond_evidence();
    assert_eq!(validate_topology(&good, true), Ok(()));
    for mutation in 0..7 {
        let mut raw = good.clone();
        let t = &mut raw["topology"];
        match mutation {
            0 => t["expected_allowed"]["G5"] = json!(["W5"]),
            1 => {
                t["suppression"]
                    .as_object_mut()
                    .expect("object")
                    .remove("W5|G5");
            }
            2 => t["peer_ids"]["G5"] = json!("ff".repeat(32)),
            3 => t["observations"]["pre_cut"]["G5"]["admitted"]
                .as_array_mut()
                .expect("array")
                .push(json!("ff".repeat(32))),
            4 => {
                let duplicate = t["observations"]["t1"]["D5"]["admitted"][0].clone();
                t["observations"]["t1"]["D5"]["admitted"]
                    .as_array_mut()
                    .expect("array")
                    .push(duplicate);
            }
            5 => t["peer_ids"]["W5"] = json!("00".repeat(8)),
            _ => t["suppression"]["G5|D5"] = json!({}),
        }
        assert!(
            validate_topology(&raw, true).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn diamond_validator_suppression_chronology_and_union_brackets() {
    use serde_json::json;
    for mutation in 0..13 {
        let mut raw = synthetic_diamond_evidence();
        let row = &mut raw["topology"]["suppression"]["O5|D5"];
        match mutation {
            0 => row["final_check"]["set_at_ns"] = json!(101),
            1 => row["set_at_stable"] = json!(false),
            2 => row["final_check"]["age_ns"] = json!(0),
            3 => row["ttl_ns"] = json!(DIAMOND_TTL_NS + 1),
            4 => row["margin_ns"] = json!(0),
            5 => row["final_check"]["age_ns"] = json!(u64::MAX),
            6 => row["pre_check"]["begin_ns"] = json!(true),
            7 => row["final_check"]["live"] = json!(false),
            8 => row["final_check"]["begin_ns"] = json!(0),
            9 => raw["samples"]["D5"]["t1"]["end_ns"] = json!(14_000_000_000u64),
            10 => raw["samples"]["O5"]["t0"]["begin_ns"] = json!(0),
            11 => {
                raw["topology"]["observations"]["pre_cut"]["G5"]["end_ns"] = json!(3_000_000_000u64)
            }
            _ => raw["samples"]["O5"]["t0"]["end_ns"] = json!(0),
        }
        assert!(
            validate_topology(&raw, true).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn diamond_validator_preserves_captured_pre_facts() {
    let raw = synthetic_diamond_evidence();
    let pre = &raw["topology"];
    assert_eq!(validate_topology_capture(pre, pre), Ok(()));
    let mut changed = pre.clone();
    changed["suppression"]["D5|O5"]["pre_check"]["age_ns"] = serde_json::json!(0);
    assert!(validate_topology_capture(pre, &changed).is_err());
    let mut changed = pre.clone();
    changed["observations"]["pre_cut"]["D5"]["begin_ns"] = serde_json::json!(0);
    assert!(validate_topology_capture(pre, &changed).is_err());
}

#[test]
fn diamond_validator_closed_shaping_operations() {
    use serde_json::json;
    for mutation in 0..7 {
        let mut raw = synthetic_diamond_evidence();
        let ops = &mut raw["topology"]["operations"];
        match mutation {
            0 => {
                ops.as_object_mut().expect("object").remove("D5|O5");
            }
            1 => ops["W5|G5"] = json!({}),
            2 => ops["G5|W5"]["forward_disconnect"]["result"] = json!("Err"),
            3 => ops["G5|W5"]["reverse_install"]["set_at_ns"] = json!(99),
            4 => ops["D5|O5"]["reverse_install"]["peer_id"] = json!("ff".repeat(32)),
            5 => ops["D5|O5"]["forward_disconnect"]["begin_ns"] = json!(99),
            _ => ops["G5|W5"]["reverse_disconnect"] = json!({}),
        }
        assert!(
            validate_topology(&raw, true).is_err(),
            "operation mutation {mutation}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn diamond_readiness_returns_exact_validated_post_refresh_observation() {
    let raw = synthetic_diamond_evidence();
    let topology = &raw["topology"];
    let before_refresh = topology["observations"]["pre_cut"].clone();
    let mut missing = before_refresh.clone();
    missing["W5"]["admitted"] = serde_json::json!([]);
    // Old validation/discard/recapture could select the invalid second object.
    assert!(diamond_peer_sets(topology, &before_refresh).is_ok());
    assert!(diamond_peer_sets(topology, &missing).is_err());
    let mut valid = before_refresh.clone();
    valid["W5"]["begin_ns"] = serde_json::json!(12345);
    valid["W5"]["end_ns"] = serde_json::json!(12346);
    let mut observations = std::collections::VecDeque::from([missing, valid.clone()]);
    let observed = capture_ready_diamond(
        topology,
        tokio::time::Instant::now() + Duration::from_secs(1),
        || std::future::ready(Ok(observations.pop_front().expect("two acquisitions"))),
    )
    .await
    .expect("second full observation is exact");
    assert_eq!(
        observed, valid,
        "retain every field and interval of the admitted object"
    );
    assert!(observations.is_empty());
}

#[tokio::test(start_paused = true)]
async fn diamond_readiness_retains_rejection_on_absolute_deadline() {
    for mutation in 0..3 {
        let mut raw = synthetic_diamond_evidence();
        let mut invalid = raw["topology"]["observations"]["pre_cut"].clone();
        match mutation {
            0 => invalid["W5"]["admitted"] = serde_json::json!([]),
            1 => invalid["W5"]["admitted"][0] = serde_json::json!("ff".repeat(32)),
            _ => {
                let duplicate = invalid["W5"]["admitted"][0].clone();
                invalid["W5"]["admitted"]
                    .as_array_mut()
                    .expect("array")
                    .push(duplicate);
            }
        }
        let mut acquisitions = 0;
        let mut reached_t0_or_load = false;
        let result = capture_ready_diamond(
            &raw["topology"],
            tokio::time::Instant::now() + Duration::from_millis(30),
            || {
                acquisitions += 1;
                if acquisitions == 1 {
                    std::future::ready(Ok(invalid.clone())).boxed_local()
                } else {
                    std::future::pending::<Result<serde_json::Value, String>>().boxed_local()
                }
            },
        )
        .await;
        match result {
            Ok(_) => reached_t0_or_load = true,
            Err(rejected) => {
                assert_eq!(rejected.last_observation.as_ref(), Some(&invalid));
                assert_eq!(
                    rejected.last_rejection_reason.as_deref(),
                    Some("admitted set differs from literal diamond")
                );
                assert_eq!(rejected.reason, "final diamond readiness deadline elapsed");
                let original_topology = raw["topology"].clone();
                retain_rejected_readiness(&mut raw, &rejected);
                assert_eq!(
                    raw["topology"], original_topology,
                    "no tombstone reinstall or closed-schema mutation"
                );
                assert_eq!(raw["outcome"], "INCONCLUSIVE");
                assert_eq!(
                    raw["rejected_readiness"]["last_completed_rejected_observation"],
                    invalid
                );
            }
        }
        assert!(!reached_t0_or_load);
    }
}

#[tokio::test(start_paused = true)]
async fn diamond_readiness_reports_no_completed_observation() {
    let raw = synthetic_diamond_evidence();
    let rejected = capture_ready_diamond(
        &raw["topology"],
        tokio::time::Instant::now() + Duration::from_millis(10),
        std::future::pending::<Result<serde_json::Value, String>>,
    )
    .await
    .expect_err("a partial acquisition never becomes successful");
    assert!(rejected.last_observation.is_none());
    assert!(rejected.last_rejection_reason.is_none());
    let mut retained = raw;
    retain_rejected_readiness(&mut retained, &rejected);
    assert_eq!(
        retained["rejected_readiness"]["completed_rejected_observation_available"],
        false
    );
    assert!(retained["rejected_readiness"]["last_completed_rejected_observation"].is_null());
}

#[tokio::test(start_paused = true)]
async fn diamond_readiness_retains_last_rejection_on_acquisition_error() {
    let raw = synthetic_diamond_evidence();
    let mut invalid = raw["topology"]["observations"]["pre_cut"].clone();
    invalid["W5"]["admitted"] = serde_json::json!([]);
    let mut observations = std::collections::VecDeque::from([
        Ok(invalid.clone()),
        Err("inert acquisition failure".to_owned()),
    ]);
    let rejected = capture_ready_diamond(
        &raw["topology"],
        tokio::time::Instant::now() + Duration::from_secs(1),
        || std::future::ready(observations.pop_front().expect("two acquisitions")),
    )
    .await
    .expect_err("acquisition error remains nonpass");
    assert_eq!(rejected.last_observation, Some(invalid));
    assert_eq!(
        rejected.reason,
        "final diamond observation failed: inert acquisition failure"
    );
}
