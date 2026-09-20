#![cfg(test)]

//! Real separate-peer component controls for #501. These exercise the signed
//! gossip carriers, not Agent::send_direct route selection or durable v2 ACKs.
//! Controlled load reports send attempts only; no wire reduction, forwarding
//! attribution, public Leaf field acceptance or policy adoption is implied.

use crate::dm::{self, DmPath, DmSendConfig, DurableSendStages, EnvelopeBuilder, DM_PROTOCOL_V1};
use crate::dm_inbox::{DmInboxConfig, DmInboxService, DmTypedPayload, DM_BUS_TOPIC};
use crate::dm_send::{self, DmSendContext};
use crate::gossip::{PubSubManager, SigningContext, Subscription};
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
// #607 contention recalibration. SETUP wraps real network convergence steps
// (QUIC pair dials, gossip-plane admission) that degrade ~16x under CI CPU
// oversubscription (measured 253 ms isolated -> 4007 ms at 5x; worst local
// 5x completing dial 5.9 s, leaving only 3.4x headroom at the old 20 s).
// 60 s keeps >= 10x headroom over the measured worst case. POSITIVE deadline.
//
// DELIVERY stays at 10 s deliberately: this cycle's CI (PR #619 Coverage,
// 2026-09-10) PROVED the one DELIVERY site that fires under CI — "receiver
// typed decrypt delivery" after the targeted exact-ciphertext publish — is
// non-arrival, not slowness: it still failed with a 60 s budget (62.78 s
// test) while the first bus delivery in the same run completed
// (default_bus_positive observed). The other DELIVERY sites' measured 5x
// worst is 4.5 s, inside 10 s with >= 2.2x headroom. The non-arrival defect
// is tracked in #613 and must NOT be papered over with a bigger budget.
const SETUP: Duration = Duration::from_secs(60);
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

async fn prepare(
    agents: &[Agent],
    keys: &[Arc<AgentKemKeypair>],
    observe_inbox: Option<usize>,
) -> (Vec<Inbox>, Option<Subscription>) {
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
    // Install the diagnostic observer before peers connect. Its second local
    // subscription therefore cannot repair or reshape the live target mesh;
    // the ordinary join/readiness/refresh sequence below remains authoritative.
    let outer_observer = if let Some(index) = observe_inbox {
        let agent = &agents[index];
        let topic = DmInboxService::inbox_topic_name(&agent.agent_id());
        Some(
            pubsub(agent)
                .subscribe_topic_id(topic, dm::dm_inbox_topic(&agent.agent_id()))
                .await,
        )
    } else {
        None
    };
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
    (receivers, outer_observer)
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
    let mut config = DmSendConfig {
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
    // #607: the default per-attempt budget (RTT fallback 250 ms x 16 = 4 s,
    // dm.rs dm_attempt_timeout) fires under CI CPU contention before the
    // outer DELIVERY bound (observed 1/10 failures at local 5x with
    // `Timeout { retries: 0, elapsed: 4.31 s }`). This is a POSITIVE
    // deadline: it awaits the v1 gossip ACK. Raise the fixture's own
    // per-attempt budget to the dm.rs ceiling for the same recalibration
    // reason as SETUP/DELIVERY; retries stay 0 and the fallback witness
    // count assertion is unchanged.
    config.timeout_per_attempt = Duration::from_secs(30);
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
        let measurement_preparation = matches!(case, Case::Measurement).then(prepare_measurement);
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
        let observe_inbox = matches!(case, Case::BusPair).then_some(2);
        let (mut receivers, mut outer_observer) = bounded(
            "fixture services and peer setup",
            Duration::from_secs(90),
            prepare(&agents, &keys, observe_inbox),
        )
        .await;
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
                let target_name = DmInboxService::inbox_topic_name(&o.agent_id());
                let target_id = dm::dm_inbox_topic(&o.agent_id());
                let outer_observer = outer_observer
                    .as_mut()
                    .expect("bus-pair targeted outer observer");

                // A fresh, valid envelope on a different, consistently named
                // transport topic must not credit the targeted observation.
                let wrong_id = dm_send::fresh_request_id();
                let wrong_payload = marked("wrong-topic-negative");
                let wrong_wire = envelope(l, o, &keys[2], wrong_id, wrong_payload);
                let wrong_topic = format!("x0x/dm/v1/diagnostic-wrong/{}", hex::encode(wrong_id));
                let wrong_topic_id = saorsa_gossip_types::TopicId::from_entity(wrong_topic.as_bytes());
                let wrong_fanout = bounded(
                    "wrong-topic diagnostic publish",
                    DELIVERY,
                    pubsub(l).publish_topic_id_with_fanout_for_test(
                        wrong_topic,
                        wrong_topic_id,
                        Bytes::from(wrong_wire),
                    ),
                )
                .await
                .expect("signed wrong-topic diagnostic publish");
                eprintln!(
                    "ISSUE501 checkpoint=wrong_topic_publish result=accepted fanout={wrong_fanout} request={}",
                    hex::encode(wrong_id)
                );
                assert!(
                    wrong_fanout > 0,
                    "wrong-topic negative requires a real sender fan-out attempt"
                );
                let (outer_negative, typed_negative) = tokio::join!(
                    tokio::time::timeout(NEGATIVE_WINDOW, outer_observer.recv()),
                    tokio::time::timeout(NEGATIVE_WINDOW, receivers[2].recv()),
                );
                match outer_negative {
                    Err(_) => {}
                    Ok(None) => panic!("targeted outer observer closed"),
                    Ok(Some(message)) => panic!(
                        "wrong topic reached targeted outer observer: {:?}",
                        message.topic
                    ),
                }
                match typed_negative {
                    Err(_) => {}
                    Ok(None) => panic!("typed receiver closed"),
                    Ok(Some(actual)) => panic!(
                        "wrong topic reached typed receiver: {:?}, expected no {:?}",
                        actual.request_id, wrong_id
                    ),
                }
                eprintln!(
                    "ISSUE501 checkpoint=wrong_topic_negative result=bounded_nonobservation outer=false typed=false fanout={wrong_fanout} request={}",
                    hex::encode(wrong_id)
                );

                // No rebuild/re-encryption: move precisely the same inner wire
                // to the domain-separated targeted ID, in a fresh signed V2 carrier.
                let targeted_fanout = bounded(
                    "exact O ciphertext targeted publish",
                    DELIVERY,
                    pubsub(l).publish_topic_id_with_fanout_for_test(
                        target_name.clone(),
                        target_id,
                        Bytes::from(wire_o.clone()),
                    ),
                )
                .await
                .expect("signed targeted publish");
                eprintln!(
                    "ISSUE501 checkpoint=targeted_publish result=accepted fanout={targeted_fanout} request={}",
                    hex::encode(id_o)
                );
                assert!(
                    targeted_fanout > 0,
                    "targeted sender recorded no fan-out attempt"
                );
                bounded("targeted outer and typed observations", DELIVERY, async {
                    tokio::join!(
                        async {
                            let outer = outer_observer
                                .recv()
                                .await
                                .expect("targeted outer observer must remain open");
                            assert_eq!(outer.topic, target_name);
                            assert_eq!(outer.payload, Bytes::from(wire_o));
                            eprintln!(
                                "ISSUE501 checkpoint=targeted_outer result=observed request={}",
                                hex::encode(id_o)
                            );
                        },
                        async {
                            delivered(&mut receivers[2], l, id_o, &payload_o).await;
                            eprintln!(
                                "ISSUE501 checkpoint=targeted_typed result=observed request={}",
                                hex::encode(id_o)
                            );
                        },
                    );
                })
                .await;
                assert!(!pubsub(o).is_topic_subscribed(DM_BUS_TOPIC).await);
                eprintln!(
                    "ISSUE501 checkpoint=exact_ciphertext_viability result=observed outer=true typed=true fanout={targeted_fanout} request={}",
                    hex::encode(id_o)
                );
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
            Case::Measurement => measurement = Some(measure(&agents, measurement_preparation.expect("measurement preparation")).await),
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
    diamond_observations_with_recorder(agents, clock, None).await
}

async fn diamond_observations_with_recorder(
    agents: &[Agent],
    clock: std::time::Instant,
    attempt: Option<&ReadinessAttempt>,
) -> serde_json::Value {
    let mut observations = serde_json::Map::new();
    for (i, (label, agent)) in DIAMOND_LABELS.iter().zip(agents).enumerate() {
        let begin = diamond_now(clock);
        let network = agent.network().expect("network");
        let peers = match attempt {
            Some(attempt) => {
                network
                    .gossip_plane_peers_recorded(&attempt.owners[i])
                    .await
            }
            None => network.gossip_plane_peers().await,
        };
        let end = diamond_now(clock);
        // Full, unfiltered returned IDs: an unknown peer is not silently lost.
        let admitted = peers.iter().map(|p| hex::encode(p.0)).collect::<Vec<_>>();
        // Embed peer_scores_by_topic so capture_ready_diamond can run the
        // #611 eager-role oracle beside diamond_peer_sets in the same retry loop.
        // Null when the gossip runtime has not yet started; the eager check
        // skips gracefully on null (scores lag plane admission by at most one
        // iteration during the initial bring-up).
        let peer_scores_by_topic = agent
            .gossip_pubsub_stage_stats()
            .and_then(|s| serde_json::to_value(&s.peer_scores_by_topic).ok())
            .unwrap_or(serde_json::Value::Null);
        observations.insert(
            (*label).into(),
            serde_json::json!({
                "admitted": admitted,
                "begin_ns": begin,
                "end_ns": end,
                "peer_scores_by_topic": peer_scores_by_topic,
            }),
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

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq, Eq)]
enum ReadinessTerminal {
    BeforeAcquireDeadline,
    AcquireTimedOut,
    AcquireError,
    ValidatedAfterDeadline,
    RetrySleepTimedOut,
}

#[derive(Debug, Default, serde::Serialize)]
struct ReadinessCounts {
    attempts_started: u64,
    acquisitions_completed: u64,
    acquisition_errors: u64,
    validations_rejected: u64,
    validations_accepted: u64,
    counter_overflow: bool,
}

fn readiness_increment(value: &mut u64, overflow: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *overflow = true,
    }
}

fn readiness_offset(start: tokio::time::Instant, at: tokio::time::Instant) -> Option<u64> {
    at.checked_duration_since(start)
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
}

fn readiness_identities(topology: &serde_json::Value) -> Option<[[u8; 32]; 4]> {
    let object = topology["peer_ids"].as_object()?;
    if object.len() != DIAMOND_LABELS.len() {
        return None;
    }
    let mut ids = [[0; 32]; 4];
    for (i, label) in DIAMOND_LABELS.iter().enumerate() {
        let full = object.get(*label)?.as_str()?;
        if full.len() != 64 {
            return None;
        }
        hex::decode_to_slice(full, &mut ids[i]).ok()?;
        if ids[..i].contains(&ids[i]) {
            return None;
        }
    }
    Some(ids)
}

#[derive(Debug, Clone)]
struct ReadinessAttempt {
    number: u64,
    begin_ns: Option<u64>,
    end_ns: Option<u64>,
    validation_end_ns: Option<u64>,
    acquisition_completed: bool,
    identities: Option<[[u8; 32]; 4]>,
    owners: [network::gossip_selection_diagnostics::Recorder; 4],
}

impl ReadinessAttempt {
    fn new(number: u64, start: tokio::time::Instant, identities: Option<[[u8; 32]; 4]>) -> Self {
        Self {
            number,
            begin_ns: readiness_offset(start, tokio::time::Instant::now()),
            end_ns: None,
            validation_end_ns: None,
            acquisition_completed: false,
            identities,
            owners: std::array::from_fn(|_| {
                network::gossip_selection_diagnostics::Recorder::new(start, identities)
            }),
        }
    }

    fn freeze(&self) -> serde_json::Value {
        let mut owners = serde_json::Map::new();
        for (i, (label, recorder)) in DIAMOND_LABELS.iter().zip(&self.owners).enumerate() {
            let snapshot = recorder.snapshot();
            // The literal four expected directed neighbor pairs, not a record-selected graph.
            let expected = [[1, 2], [0, 3], [0, 3], [1, 2]][i];
            let edges = expected
                .into_iter()
                .map(|other| {
                    let decision = self
                        .identities
                        .map(|ids| snapshot.edge(ids[other]))
                        .unwrap_or("Unknown");
                    (DIAMOND_LABELS[other], decision)
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            owners.insert((*label).into(), serde_json::json!({
                "diagnostic_complete":snapshot.complete(), "selection":snapshot,"expected_edges":edges,
            }));
        }
        serde_json::json!({"attempt":self.number,"begin_ns":self.begin_ns,"end_ns":self.end_ns,
            "validation_end_ns":self.validation_end_ns,"acquisition_completed":self.acquisition_completed,
            "owners":owners})
    }
}

#[derive(Debug, serde::Serialize)]
struct ReadinessDiagnostics {
    schema: u8,
    clock_domain: &'static str,
    graph_clock_domain: &'static str,
    candidate_omission_cause: &'static str,
    late_valid_raw_observation_retained: bool,
    terminal_stage: Option<ReadinessTerminal>,
    start_ns: u64,
    deadline_ns: Option<u64>,
    terminal_ns: Option<u64>,
    clock_incomplete: bool,
    output_overflow: bool,
    counts: ReadinessCounts,
    last_completed_rejected_attempt: Option<serde_json::Value>,
    terminal_attempt: Option<serde_json::Value>,
}

impl ReadinessDiagnostics {
    fn new(start: tokio::time::Instant, deadline: tokio::time::Instant) -> Self {
        let deadline_ns = readiness_offset(start, deadline);
        Self {
            schema: 1,
            clock_domain: "tokio_since_final_readiness_start",
            graph_clock_domain: "std_since_fixture_start",
            candidate_omission_cause: "Unknown",
            late_valid_raw_observation_retained: false,
            terminal_stage: None,
            start_ns: 0,
            deadline_ns,
            terminal_ns: None,
            clock_incomplete: deadline_ns.is_none(),
            output_overflow: false,
            counts: ReadinessCounts::default(),
            last_completed_rejected_attempt: None,
            terminal_attempt: None,
        }
    }

    fn finish(
        &mut self,
        stage: ReadinessTerminal,
        start: tokio::time::Instant,
        attempt: Option<&ReadinessAttempt>,
    ) {
        self.terminal_stage = Some(stage);
        self.terminal_ns = readiness_offset(start, tokio::time::Instant::now());
        self.clock_incomplete |= self.terminal_ns.is_none();
        self.terminal_attempt = attempt.map(ReadinessAttempt::freeze);
    }

    fn bounded_value(&self) -> serde_json::Value {
        const MAX_DIAGNOSTIC_BYTES: usize = 64 * 1024;
        if let Ok(encoded) = serde_json::to_vec(self) {
            if encoded.len() <= MAX_DIAGNOSTIC_BYTES {
                if let Ok(value) = serde_json::from_slice(&encoded) {
                    return value;
                }
            }
        }
        // Fixed scalar fallback: never truncate JSON, replace the old graph, or change an oracle.
        serde_json::json!({"schema":1,"clock_domain":self.clock_domain,
            "graph_clock_domain":self.graph_clock_domain,"candidate_omission_cause":"Unknown",
            "late_valid_raw_observation_retained":false,"terminal_stage":self.terminal_stage,
            "start_ns":self.start_ns,"deadline_ns":self.deadline_ns,"terminal_ns":self.terminal_ns,
            "clock_incomplete":self.clock_incomplete,"output_overflow":true,"counts":self.counts,
            "last_completed_rejected_attempt":null,"terminal_attempt":null})
    }
}

#[derive(Debug)]
struct RejectedReadiness {
    reason: String,
    last_observation: Option<serde_json::Value>,
    last_rejection_reason: Option<String>,
    // #604: boxed so `Result<_, RejectedReadiness>` stays under the
    // `result_large_err` threshold (288 bytes unboxed). Field access and
    // `&self` borrows are unchanged via `Box`'s `Deref`.
    diagnostics: Box<ReadinessDiagnostics>,
}

/// Run [`check_eager_mesh_recovered`] for every node in the diamond topology,
/// using the `peer_scores_by_topic` embedded in `observed` by
/// [`diamond_observations_with_recorder`].
///
/// Chained with [`diamond_peer_sets`] inside [`capture_ready_diamond`]'s
/// bounded retry loop so that the eager-role check retries under the SETUP
/// deadline alongside plane-admission validation.  This means a transient
/// PlumTree set still at 1 (the #611 collapse shape) causes the loop to keep
/// polling — no extra sleep or outer retry is needed.
///
/// Returns `Ok(())` when all four nodes have their two expected neighbors
/// as eager peers.  Returns `Err(String)` naming the first failing node.
///
/// Skips gracefully when:
/// - `identities` is `None` (peer IDs not yet resolved), or
/// - a node's `peer_scores_by_topic` is `null` (gossip runtime not yet started;
///   scores lag plane admission by at most one iteration during bring-up).
///
/// The subscription decision is **configuration-driven** via
/// `non_subscriber_indices` (DIAMOND_LABELS indices of nodes built with
/// `with_skip_legacy_dm_bus(true)` or otherwise not subscribed to DM bus):
///
/// - **Declared non-subscriber**: the DM bus topic MUST be absent from its
///   `peer_scores_by_topic`.  If it is present, the function returns `Err` —
///   the opt-out flag had no effect, a configuration invariant violation.
/// - **Subscriber** (all other nodes): a missing topic entry is a **retryable
///   failure** — the retry loop revisits in 10 ms.  This prevents the oracle
///   from passing vacuously when a subscriber's topic entry is transiently
///   absent from the snapshot.
///
/// `non_subscriber_indices` is passed directly to `capture_ready_diamond` by
/// `shape_diamond` (not embedded in the topology JSON, which must carry exactly
/// the 8 canonical keys checked by `validate_topology` → `diamond_keys`).
///
/// # Degree note
/// Harness agents are built with `Agent::builder()` which produces Leaf
/// nodes; the default `leaf_max_eager_degree = 2` is the right ceiling here.
/// Full or relay nodes would need `FULL_EAGER_DEGREE_CEILING = 6`.
fn check_eager_mesh_for_diamond(
    observed: &serde_json::Value,
    identities: Option<[[u8; 32]; 4]>,
    non_subscriber_indices: &[usize],
) -> Result<(), String> {
    let Some(ids) = identities else {
        return Ok(());
    };
    let bus_topic = saorsa_gossip_types::TopicId::from_entity(DM_BUS_TOPIC.as_bytes()).to_string();
    // Expected neighbor indices per DIAMOND_LABELS order:
    //   G5→{D5,O5}, D5→{G5,W5}, O5→{G5,W5}, W5→{D5,O5}
    const NEIGHBOR_INDICES: [[usize; 2]; 4] = [[1, 2], [0, 3], [0, 3], [1, 2]];
    for (i, label) in DIAMOND_LABELS.iter().enumerate() {
        let scores = &observed[*label]["peer_scores_by_topic"];
        if scores.is_null() {
            // Gossip runtime not yet started; skip, the retry loop will revisit.
            continue;
        }
        let topic_present = scores
            .get(&bus_topic)
            .map(|v| !v.is_null())
            .unwrap_or(false);
        if non_subscriber_indices.contains(&i) {
            // Declared non-subscriber: assert the DM bus topic is absent.
            // Topic present means the opt-out flag had no effect — config error.
            if topic_present {
                return Err(format!(
                    "node {label}: declared non-subscriber has DM bus topic {bus_topic:?} \
                     in peer_scores_by_topic — with_skip_legacy_dm_bus flag had no effect"
                ));
            }
            continue; // Correctly absent; nothing to check.
        }
        // Subscriber: topic absent is retryable (scores not yet populated),
        // not a silent pass.  The retry loop revisits in 10 ms.
        if !topic_present {
            return Err(format!(
                "node {label}: subscribes to DM bus but topic {bus_topic:?} absent from \
                 peer_scores_by_topic — scores not yet populated (retryable)"
            ));
        }
        let neighbor_hex8: Vec<String> = NEIGHBOR_INDICES[i]
            .iter()
            .map(|&j| hex::encode(ids[j])[..16].to_string())
            .collect();
        let neighbor_refs: Vec<&str> = neighbor_hex8.iter().map(String::as_str).collect();
        check_eager_mesh_recovered(scores, &bus_topic, &neighbor_refs, 2)
            .map_err(|e| format!("node {label}: {e}"))?;
    }
    Ok(())
}

// One absolute deadline owns acquisition and polling. Only the full object
// validated here can become pre_cut; timed-out partial acquisitions are dropped.
async fn capture_ready_diamond<F, Fut>(
    topology: &serde_json::Value,
    non_subscriber_indices: &[usize],
    start: tokio::time::Instant,
    deadline: tokio::time::Instant,
    mut observe: F,
) -> Result<serde_json::Value, RejectedReadiness>
where
    F: FnMut(ReadinessAttempt) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    let mut rejected = RejectedReadiness {
        reason: "final diamond readiness deadline elapsed".into(),
        last_observation: None,
        last_rejection_reason: None,
        diagnostics: Box::new(ReadinessDiagnostics::new(start, deadline)),
    };
    let identities = readiness_identities(topology);
    loop {
        if tokio::time::Instant::now() >= deadline {
            rejected
                .diagnostics
                .finish(ReadinessTerminal::BeforeAcquireDeadline, start, None);
            return Err(rejected);
        }
        let counts = &mut rejected.diagnostics.counts;
        readiness_increment(&mut counts.attempts_started, &mut counts.counter_overflow);
        let mut attempt = ReadinessAttempt::new(counts.attempts_started, start, identities);
        rejected.diagnostics.clock_incomplete |= attempt.begin_ns.is_none();
        let acquired = tokio::time::timeout_at(deadline, observe(attempt.clone())).await;
        let observed = match acquired {
            Ok(Ok(observed)) => {
                readiness_increment(
                    &mut counts.acquisitions_completed,
                    &mut counts.counter_overflow,
                );
                attempt.acquisition_completed = true;
                attempt.end_ns = readiness_offset(start, tokio::time::Instant::now());
                rejected.diagnostics.clock_incomplete |= attempt.end_ns.is_none();
                observed
            }
            Ok(Err(reason)) => {
                readiness_increment(
                    &mut counts.acquisitions_completed,
                    &mut counts.counter_overflow,
                );
                readiness_increment(&mut counts.acquisition_errors, &mut counts.counter_overflow);
                attempt.acquisition_completed = true;
                attempt.end_ns = readiness_offset(start, tokio::time::Instant::now());
                rejected.diagnostics.clock_incomplete |= attempt.end_ns.is_none();
                rejected.reason = format!("final diamond observation failed: {reason}");
                rejected
                    .diagnostics
                    .finish(ReadinessTerminal::AcquireError, start, Some(&attempt));
                return Err(rejected);
            }
            Err(_) => {
                rejected.diagnostics.finish(
                    ReadinessTerminal::AcquireTimedOut,
                    start,
                    Some(&attempt),
                );
                return Err(rejected);
            }
        };
        let validation = diamond_peer_sets(topology, &observed).and_then(|()| {
            check_eager_mesh_for_diamond(&observed, identities, non_subscriber_indices)
        });
        attempt.validation_end_ns = readiness_offset(start, tokio::time::Instant::now());
        rejected.diagnostics.clock_incomplete |= attempt.validation_end_ns.is_none();
        match validation {
            Ok(()) => {
                readiness_increment(
                    &mut counts.validations_accepted,
                    &mut counts.counter_overflow,
                );
                if tokio::time::Instant::now() < deadline {
                    return Ok(observed);
                }
                rejected.diagnostics.finish(
                    ReadinessTerminal::ValidatedAfterDeadline,
                    start,
                    Some(&attempt),
                );
                return Err(rejected);
            }
            Err(reason) => {
                readiness_increment(
                    &mut counts.validations_rejected,
                    &mut counts.counter_overflow,
                );
                rejected.last_observation = Some(observed);
                rejected.last_rejection_reason = Some(reason);
                rejected.diagnostics.last_completed_rejected_attempt = None;
                rejected.diagnostics.last_completed_rejected_attempt = Some(attempt.freeze());
            }
        }
        if tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(10)))
            .await
            .is_err()
        {
            rejected.diagnostics.finish(
                ReadinessTerminal::RetrySleepTimedOut,
                start,
                Some(&attempt),
            );
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
    raw["readiness_diagnostics"] = rejected.diagnostics.bounded_value();
}

async fn shape_diamond(
    agents: &[Agent],
    raw: &mut serde_json::Value,
    clock: std::time::Instant,
    dm_bus_non_subscriber_label_indices: &[usize],
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
    let start = tokio::time::Instant::now();
    let pre_cut = capture_ready_diamond(
        &raw["topology"],
        dm_bus_non_subscriber_label_indices,
        start,
        start + SETUP,
        |attempt| async move {
            Ok(diamond_observations_with_recorder(agents, clock, Some(&attempt)).await)
        },
    )
    .await?;
    raw["topology"]["observations"]["pre_cut"] = strip_peer_scores(pre_cut);
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

/// Remove the `peer_scores_by_topic` field that `diamond_observations_with_recorder`
/// embeds in every per-label observation for oracle use.  The topology-contract
/// checker (`validate_topology` → `diamond_keys`) expects exactly
/// {"admitted", "begin_ns", "end_ns"} per observation; strip before storing.
fn strip_peer_scores(mut observations: serde_json::Value) -> serde_json::Value {
    if let Some(map) = observations.as_object_mut() {
        for obs in map.values_mut() {
            if let Some(obj) = obs.as_object_mut() {
                obj.remove("peer_scores_by_topic");
            }
        }
    }
    observations
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

// These cuts include background/local/relayed activity. Only load_returns
// attributes counts to controlled calls. publish_total deltas do not validate
// vector length or controlled origin; no cut is an acceptance predicate.
fn generator_topic_projection(
    rows: &std::collections::BTreeMap<String, saorsa_gossip_pubsub::OutboundTopicMeterSnapshot>,
    zero_fanout: &std::collections::BTreeMap<String, u64>,
    bus: saorsa_gossip_types::TopicId,
) -> serde_json::Value {
    use serde_json::json;
    let key = bus.to_string(); // Same pinned TopicId projection as the existing meter.
    let row = rows.get(&key).map(|row| {
        let kind = |v: &saorsa_gossip_pubsub::OutboundKindMeterSnapshot| {
            json!({"msgs":v.msgs,"bytes":v.bytes})
        };
        json!({"eager":kind(&row.eager),"ihave":kind(&row.ihave),
            "iwant":kind(&row.iwant),"anti_entropy":kind(&row.anti_entropy)})
    });
    json!({"tracked_rows":rows.len(),"bus_row_present":row.is_some(),
        "bus_outbound":row,"bus_zero_fanout":zero_fanout.get(&key)})
}

fn generator_cut(agent: &Agent, clock: std::time::Instant) -> serde_json::Value {
    use serde_json::json;
    let begin = diamond_now(clock);
    let publish = agent
        .gossip_stats()
        .map(|s| json!({"publish_total":s.publish_total,"publish_failed":s.publish_failed}));
    let stages = agent.gossip_pubsub_stage_stats().map(|s| {
        let a = s.admission;
        let origin = s.outbound_publish_origin;
        json!({"topics":generator_topic_projection(&s.outbound_by_topic,
                &s.zero_fanout_publishes_by_topic,
                saorsa_gossip_types::TopicId::from_entity(DM_BUS_TOPIC.as_bytes())),
            "origin":{"local_msgs":origin.local_msgs,"local_bytes":origin.local_bytes,
                "relay_msgs":origin.relay_msgs,"relay_bytes":origin.relay_bytes},
            "zero_fanout_publishes":s.zero_fanout_publishes,
            "zero_succeeded_publishes":s.zero_succeeded_publishes,
            "republish_per_peer_timeout":s.republish_per_peer_timeout,
            "peers_evicted_not_connected":s.peers_evicted_not_connected,
            "outbound_budget_exhausted":s.outbound_budget_exhausted,
            "admission":{"admitted_critical":a.admitted_critical,"admitted_normal":a.admitted_normal,
                "admitted_bulk":a.admitted_bulk,"dropped_bulk_peer_dead":a.dropped_bulk_peer_dead,
                "dropped_bulk_peer_suspect":a.dropped_bulk_peer_suspect,
                "dropped_bulk_peer_cooled":a.dropped_bulk_peer_cooled,
                "dropped_bulk_backpressure":a.dropped_bulk_backpressure,
                "dropped_normal_peer_dead":a.dropped_normal_peer_dead,
                "dropped_normal_peer_suspect":a.dropped_normal_peer_suspect,
                "dropped_critical_hard_error":a.dropped_critical_hard_error,
                "dropped_critical_cooling":a.dropped_critical_cooling,
                "dropped_critical_no_target":a.dropped_critical_no_target}})
    });
    generator_cut_projection(begin, diamond_now(clock), publish, stages)
}

fn generator_cut_projection(
    begin: u64,
    end: u64,
    publish: Option<serde_json::Value>,
    stages: Option<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({"begin_ns":begin,"end_ns":end,"publish":publish,"stages":stages})
}

fn generator_load_returns(
    calls: &[(u32, Option<saorsa_gossip_pubsub::FanoutCounts>)],
) -> serde_json::Value {
    // Never silently truncate or turn missing counts into zero. Real caller is
    // the unchanged fixed 200 loop; an oversized diagnostic is unavailable.
    if calls.len() > 200 {
        return serde_json::Value::Null;
    }
    serde_json::Value::Array(
        calls
            .iter()
            .enumerate()
            .map(|(ordinal, (reported, counts))| {
                serde_json::json!({"ordinal":ordinal,"reported_fanout":reported,
            "attempted":counts.map(|c|c.attempted),"succeeded":counts.map(|c|c.succeeded)})
            })
            .collect(),
    )
}

fn interpret_generator_load(rows: &serde_json::Value) -> Option<serde_json::Value> {
    let rows = rows.as_array()?;
    if rows.len() != 200 {
        return None;
    }
    let (mut attempted, mut succeeded, mut zero_attempt_calls, mut no_success_calls) =
        (0u64, 0u64, 0u64, 0u64);
    for (ordinal, row) in rows.iter().enumerate() {
        diamond_keys(
            row,
            &["ordinal", "reported_fanout", "attempted", "succeeded"],
        )
        .ok()?;
        if row["ordinal"].as_u64()? != ordinal as u64
            || row["reported_fanout"].as_u64()? > u64::from(u32::MAX)
        {
            return None;
        }
        let a = row["attempted"].as_u64()?;
        let s = row["succeeded"].as_u64()?;
        if s > a {
            return None;
        }
        attempted = attempted.checked_add(a)?;
        succeeded = succeeded.checked_add(s)?;
        zero_attempt_calls += u64::from(a == 0);
        no_success_calls += u64::from(a > 0 && s == 0);
    }
    // Send-stage Ok only: not remote receipt, decode, forwarding or durable ACK.
    // No soft/hard error taxonomy is available in FanoutCounts.
    Some(
        serde_json::json!({"attempted":attempted,"send_stage_succeeded":succeeded,
        "zero_attempt_calls":zero_attempt_calls,"attempted_without_send_stage_success_calls":no_success_calls}),
    )
}

fn attach_generator_load(
    raw: &mut serde_json::Value,
    calls: &[(u32, Option<saorsa_gossip_pubsub::FanoutCounts>)],
) {
    let rows = generator_load_returns(calls);
    raw["generator_diagnostics"]["load_interpretation"] =
        serde_json::json!(interpret_generator_load(&rows));
    raw["generator_diagnostics"]["load_returns"] = rows;
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
    // #613: the ingress side of this arm. `stages` starts at sg's decode, so
    // a frame x0x's own receive pump discarded (bounded forward channel full,
    // or ADR 0013 near-overload shed) is invisible to every counter this
    // record previously carried — leaving "arrived and was dropped here" and
    // "never arrived" indistinguishable. `recv_pump.pubsub.produced_total`
    // counts frames read off the wire BEFORE that queue, so the pair
    // (produced, dropped_full + shed_priority) separates them.
    let recv_pump = agent
        .recv_pump_diagnostics()
        .expect("actual recv pump getter");
    serde_json::json!({"begin_ns":begin,"end_ns":diamond_now(clock),
        "egress":egress,"participation":participation,"stages":stages,
        "recv_pump":recv_pump})
}

/// The bus wire kinds each arm's oracle judges on. Shared by
/// `validate_measurement` and by the drain barrier so the barrier's reset
/// condition covers **exactly** the verdict it protects — no more and no
/// less — by construction rather than by two lists agreeing. A barrier
/// watching a narrower quantity than the oracle judges on is what produced
/// the 189-vs-200 gap; these consts are what stop that recurring if either
/// oracle's kinds change.
///
/// D5 is judged on active dissemination (#674: eager re-publish, or the
/// IHAVE announce a `LazyForward` verdict withholds it for). O5 is judged on
/// the strictly stronger claim of no bus egress of ANY kind.
const D5_BUS_ORACLE_KINDS: [&str; 2] = ["eager", "ihave"];
const O5_BUS_ORACLE_KINDS: [&str; 4] = ["eager", "ihave", "iwant", "anti_entropy"];

/// #613: the cumulative quantities the t1 cut depends on. The bus-egress
/// terms are load-bearing and were missing from the first version of this
/// barrier: the oracle reads **bus egress** (`sample_rows` over
/// `egress.outbound_by_topic_named`), and that lags ingress. In the drain
/// probe that motivated the barrier, D5 had already produced and decoded 201
/// at the old cut instant — ingress essentially complete — while its bus
/// eager egress read 189. Stabilising on ingress alone would therefore
/// report quiescent while the measured quantity was still draining.
///
/// `kinds` is that arm's entry from the consts above, read from the same
/// `stage_stats().outbound_by_topic` row under the same topic key the oracle
/// projects, so there is no parallel counter that could drift. Including
/// egress cannot mask anything on the O5 arm: the value that arm's oracle
/// requires is 0, stable on the first poll, so the terms tighten it.
fn drain_counts(agent: &Agent, bus: &str, kinds: &[&str]) -> (u64, u64, u64, Vec<u64>) {
    let pump = agent
        .recv_pump_diagnostics()
        .expect("actual recv pump getter");
    let stages = pubsub(agent).stage_stats();
    let bus_row = stages.outbound_by_topic.get(bus);
    let bus_msgs = kinds
        .iter()
        .map(|kind| {
            bus_row.map_or(0, |row| match *kind {
                "eager" => row.eager.msgs,
                "ihave" => row.ihave.msgs,
                "iwant" => row.iwant.msgs,
                "anti_entropy" => row.anti_entropy.msgs,
                // Fail loud: silently reading 0 for a mistyped kind would
                // leave the barrier blind to exactly what it must watch.
                other => panic!("unknown bus wire kind {other}"),
            })
        })
        .collect();
    (
        pump.pubsub.produced_total,
        pump.pubsub.dequeued_total,
        stages.message_kinds.eager,
        bus_msgs,
    )
}

/// #613 premise repair: the oracle compares a generator count accumulated
/// across the whole load against the measured arms' counters read at one
/// instant. That comparison is only valid once the pipeline the generator
/// filled has drained: the publish returns when the SEND succeeded, not when
/// the receiver has processed the frame, so a cut taken at the last publish
/// measures "how much had the arm processed by the time I looked". Measured
/// on this fixture (2026-09-14, quiet 18-core host, load 20.4 s): D5's bus
/// eager egress was 189 at the old cut instant and 200 three seconds later —
/// 5.5% of the load was still in flight. Under runner starvation that
/// fraction has no bound, and "delta == 0" is its limit.
///
/// So wait for BOTH measured arms to stop moving — ingress AND the bus
/// egress the oracle actually reads — before cutting. This is a quiescence
/// barrier, not a tolerance: it does not weaken what the oracle requires, it
/// makes the instant the oracle reads a valid one. A bounded barrier cannot
/// manufacture counts: frames that were genuinely dropped, refused or never
/// forwarded produce nothing extra no matter how long it waits, so a real
/// forwarding failure still fails — now with attribution. It is bounded, it
/// stops early in the normal case, and whether it actually reached
/// quiescence is recorded in the evidence rather than assumed.
async fn await_drain_quiescence(d5: &Agent, o5: &Agent) -> serde_json::Value {
    const POLL: Duration = Duration::from_millis(250);
    const BUDGET: Duration = Duration::from_secs(20);
    // Four consecutive unchanged observations (1 s of stillness). Two was
    // 500 ms, which is thin on exactly the starved runners this targets: one
    // scheduling gap of that length would read as a drained pipeline.
    // Measured cost at 4 is ~2 s against a 20 s cap.
    const STABLE_POLLS: u32 = 4;
    let bus = saorsa_gossip_types::TopicId::from_entity(DM_BUS_TOPIC.as_bytes()).to_string();
    let sample = || {
        (
            drain_counts(d5, &bus, &D5_BUS_ORACLE_KINDS),
            drain_counts(o5, &bus, &O5_BUS_ORACLE_KINDS),
        )
    };
    let started = tokio::time::Instant::now();
    let mut previous = sample();
    let mut stable = 0u32;
    let mut polls = 0u64;
    while stable < STABLE_POLLS && started.elapsed() < BUDGET {
        tokio::time::sleep(POLL).await;
        polls += 1;
        let current = sample();
        stable = if current == previous { stable + 1 } else { 0 };
        previous = current;
    }
    serde_json::json!({
        "quiescent": stable >= STABLE_POLLS,
        "waited_ms": started.elapsed().as_millis() as u64,
        "polls": polls,
        "poll_ms": POLL.as_millis() as u64,
        "budget_ms": BUDGET.as_millis() as u64,
        "stable_polls_required": STABLE_POLLS,
        "counts": "per measured arm: (recv_pump.pubsub.produced_total, recv_pump.pubsub.dequeued_total, stages.message_kinds.eager, bus outbound msgs for that arm's oracle kinds)",
        "bus_kinds_watched": {"D5": D5_BUS_ORACLE_KINDS, "O5": O5_BUS_ORACLE_KINDS},
        "timeout_behaviour": "records quiescent=false and cuts as before; never retries, fails or widens the oracle",
    })
}

/// #613: what the record can say about one arm's ingress, for a failure
/// reason. `stages` begins at saorsa-gossip's decode, so a frame x0x's own
/// receive pump discarded was invisible to every counter this record
/// previously carried, leaving "arrived and was dropped here" and "never
/// arrived" indistinguishable. These are the fields that separate them.
fn ingress_facts(sample: &serde_json::Value, generator_machine_hex: &str) -> String {
    let pump = &sample["recv_pump"]["pubsub"];
    let field = |value: &serde_json::Value, key: &str| -> String {
        value[key]
            .as_u64()
            .map_or_else(|| "?".to_owned(), |v| v.to_string())
    };
    format!(
        "ingress[produced={} enqueued={} dequeued={} dropped_full={} shed_priority={} \
         depth={}/{} max_depth={} from_generator={} dropped_from_generator={} \
         decoded_eager={} refused_unsubscribed={}]",
        field(pump, "produced_total"),
        field(pump, "enqueued_total"),
        field(pump, "dequeued_total"),
        field(pump, "dropped_full"),
        field(pump, "shed_priority"),
        field(pump, "latest_depth"),
        field(pump, "capacity"),
        field(pump, "max_depth"),
        field(
            &sample["recv_pump"]["per_peer"][generator_machine_hex],
            "pubsub_produced"
        ),
        field(
            &sample["recv_pump"]["per_peer"][generator_machine_hex],
            "pubsub_dropped_full"
        ),
        field(&sample["stages"]["message_kinds"], "eager"),
        field(&sample["participation"], "unsubscribed_refused_frames"),
    )
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
    // #613: the generator's machine ID keys the per-peer receive-pump rows.
    let generator_machine_hex = raw["identities"][0]["machine"]
        .as_str()
        .ok_or("missing generator machine identity")?;
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
        // #674 C2/C3 oracle: eager re-publish is no longer the only bus
        // forwarding mechanism — a relay whose verdict went lazy withholds
        // the eager send and announces via IHAVE instead (peers pull by
        // IWANT; those serve bytes land in `eager` too, so a pull-heavy
        // run adds to the eager side). Measure ACTIVE DISSEMINATION
        // (eager + ihave), not the wire kind:
        //   D5 (bus inbox, forwarding expected) must move bus egress —
        //       eager re-publish pre-budget-exhaustion, IHAVE announce
        //       under a #674 lazy verdict, or both. Zero of both is a
        //       real forwarding regression (broken fan-out, refused
        //       admission, or a dropped subscription) and still fails.
        //   O5 (optout) must contribute NO bus egress of ANY kind — a
        //       strictly stronger claim than the previous eager-only
        //       check: no eager, no IHAVE announce, no IWANT, no
        //       anti-entropy on a topic this arm opted out of.
        let bus_bytes = |rows: &std::collections::BTreeMap<String, serde_json::Value>,
                         kinds: &[&str]|
         -> Result<u64, String> {
            match rows.get(&bus) {
                None => Ok(0), // Only after the source-universe and continuity premises.
                Some(row) => {
                    let mut total = 0u64;
                    for kind in kinds {
                        total = total
                            .checked_add(row[*kind]["bytes"].as_u64().ok_or("invalid bus counter")?)
                            .ok_or("bus counter overflow")?;
                    }
                    Ok(total)
                }
            }
        };
        let delta = |a: &std::collections::BTreeMap<String, serde_json::Value>,
                     b: &std::collections::BTreeMap<String, serde_json::Value>,
                     kinds: &[&str]|
         -> Result<u64, String> {
            bus_bytes(b, kinds)?
                .checked_sub(bus_bytes(a, kinds)?)
                .ok_or("bus counter decreased".into())
        };
        // #613: neither verdict on this arm is self-explaining. A D5 zero is
        // identical for "never received the load", "x0x's own receive pump
        // discarded it" and "received it and refused to forward"; and an O5
        // result — including a PASS — is only trustworthy if the barrier
        // actually settled, since nothing having drained also produces zero
        // bus egress. Carry the facts that separate those, so an occurrence
        // is triaged from the failure line rather than by hand.
        let facts = || {
            format!(
                " [{} quiescence={}]",
                ingress_facts(after, generator_machine_hex),
                raw["load"]["quiescence"]["quiescent"]
            )
        };
        if arm == "D5" {
            if !b.contains_key(&bus) {
                return Err(format!(
                    "D5 positive bus row/attempt not observed{}",
                    facts()
                ));
            }
            // Cached endpoint peer_scores are diagnostic only.
            if delta(&a, &b, &D5_BUS_ORACLE_KINDS)? == 0 {
                return Err(format!(
                    "FAIL: D5 recorded no bus dissemination (eager or IHAVE){}",
                    facts()
                ));
            }
        } else if delta(&a, &b, &O5_BUS_ORACLE_KINDS)? != 0 {
            return Err(format!(
                "FAIL: O5 recorded bus egress of any kind{}",
                facts()
            ));
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
struct MeasurementPreparation {
    binary_sha256: String,
    build_lock_sha256: String,
    build_lock: Result<toml::Value, toml::de::Error>,
}

fn prepare_measurement() -> MeasurementPreparation {
    use sha2::{Digest, Sha256};
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
    MeasurementPreparation {
        binary_sha256: binary_hash,
        build_lock_sha256: hex::encode(Sha256::digest(include_bytes!("../Cargo.lock"))),
        build_lock: toml::from_str(include_str!("../Cargo.lock")),
    }
}

async fn measure(agents: &[Agent], preparation: MeasurementPreparation) -> serde_json::Value {
    use serde_json::json;
    let clock = std::time::Instant::now();
    let mut raw = json!({"schema":2,"selector":"legacy_bus_interop_tests::paired_controlled_load_bus_eager_attempts_default_vs_optout",
        "phase":"setup","outcome":"UNRUN","pid":std::process::id(),
        "claim":"controlled bus dissemination (eager re-publish or #674 lazy IHAVE announce); optout contributes no bus egress of any kind; not wire occupancy or field reduction",
        "universe":topic_universe(agents),"samples":{},"load":{},
        "generator_diagnostics":{"schema":1,"role":"G5","cuts":{},"load_returns":[],"load_interpretation":null},
        "identities":agents.iter().map(|a|json!({"agent":hex::encode(a.agent_id().0),"machine":hex::encode(a.machine_id().0)})).collect::<Vec<_>>(),
        "generator_peer_hex8":saorsa_gossip_types::PeerId::new(agents[0].machine_id().0).to_string(),
        "binary_sha256":preparation.binary_sha256,
        "build_lock_sha256":preparation.build_lock_sha256});
    let lock = preparation.build_lock.expect("actual build lock");
    let pinned = lock["package"]
        .as_array()
        .expect("lock packages")
        .iter()
        .filter(|p| p["name"].as_str() == Some("saorsa-gossip-pubsub"))
        .collect::<Vec<_>>();
    if pinned.len() != 1
        || pinned[0]["version"].as_str() != Some("0.5.82")
        || pinned[0]["checksum"].as_str()
            != Some("5c53f3c2cf8f671b405ccf5810c0fff1cc19fe852f8853fd3f56d1eb731a276a")
    {
        raw["outcome"] = json!("INCONCLUSIVE");
        raw["reason"] = json!("published meter producer pin unavailable");
        emit_measurement(&raw);
        panic!("INCONCLUSIVE: lock producer premise");
    }
    // W5 already has a real bus inbox; retain an additional raw subscription
    // to count observed generator messages without attributing their path.
    let mut witness = pubsub(&agents[3]).subscribe(DM_BUS_TOPIC.to_owned()).await;
    // Provenance preparation ran before Agent construction; agent-dependent
    // universe/identity work and witness setup remain before shaping.
    // Only this fifth case now shapes the already prepared full mesh.
    // O5 = DIAMOND_LABELS index 2, built with with_skip_legacy_dm_bus(true).
    let originals = match shape_diamond(agents, &mut raw, clock, &[2]).await {
        Ok(originals) => originals,
        Err(rejected) => {
            retain_rejected_readiness(&mut raw, &rejected);
            emit_measurement(&raw);
            panic!("INCONCLUSIVE: {}", rejected.reason);
        }
    };
    let captured_pre = raw["topology"].clone();
    emit_measurement(&raw);
    raw["generator_diagnostics"]["cuts"]["t0"] = generator_cut(&agents[0], clock);
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
    let mut load_returns = Vec::with_capacity(200);
    // Calibration basis (#501 Coverage-Gate flake). This phase is rate-limited,
    // not latency-limited: 200 ticks at 50 ms is a 10 s floor, but
    // MissedTickBehavior::Skip rounds every publication up to the next 50 ms
    // boundary, so the phase costs 200 * 50 ms * ceil(publish / 50 ms).
    // Measured load-phase elapsed for this fixture: 10.5-10.9 s unloaded
    // (53 ms mean period), 18.8 s at 2x CPU oversubscription (94 ms), and
    // 41.4 / 42.4 / 45.4 / 50.1 / 61.9 / 78.5 s at 5x (207-393 ms). Every one
    // of those runs still sent all 200 publications with publish_failed 0 and
    // a non-zero fanout, so contention costs this phase time, not its
    // observation. The former 30 s budget was derived from the 10 s nominal
    // schedule and sat inside that measured range, so it aborted the load
    // phase on loaded CI runners before the required observation could
    // complete (ADR 0025, decision 3). 180 s is ~2.3x the slowest measured
    // phase and still far inside nextest's 600 s terminate-after, so a genuine
    // hang is still caught and still attributed to this label.
    bounded("fixed 200-publication controlled load", Duration::from_secs(180), async {
        while sent < 200 {
            tokio::select! {
                _ = timer.tick() => {
                    let mut payload = vec![0x50;4096];
                    payload[..8].copy_from_slice(&sent.to_be_bytes());
                    let returned=agents[0].publish_with_observed_fanout(DM_BUS_TOPIC,payload).await.expect("generator publish");
                    let fanout=returned.0;
                    load_returns.push(returned);
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
    // The generator's own phase ends HERE. `elapsed_ns` is the measured load
    // phase and feeds `load_achieved_per_second` in the CI derivation, so the
    // drain barrier below must not be billed to it — that would understate the
    // achieved rate and report a load the fixture did sustain as one it did
    // not. The barrier's own cost is recorded inside `load.quiescence`.
    let load_elapsed = started.elapsed();
    // #613: cut only once the quantity the oracle reads has stopped moving on
    // both measured arms; see `await_drain_quiescence`.
    let quiescence = bounded(
        "post-load drain quiescence",
        Duration::from_secs(30),
        await_drain_quiescence(&agents[1], &agents[2]),
    )
    .await;
    raw["samples"]["D5"]["t1"] = raw_sample(&agents[1], clock);
    raw["samples"]["O5"]["t1"] = raw_sample(&agents[2], clock);
    // #613: retain the ingress attribution for BOTH arms whatever the verdict.
    // The O5 arm passes by observing zero bus egress, and "nothing drained"
    // produces that too — so an O5 PASS is exactly the result whose
    // trustworthiness rests on the barrier having settled, and it never
    // reaches a failure reason where the facts could otherwise be attached.
    let generator_machine_hex = hex::encode(agents[0].machine_id().0);
    raw["ingress_attribution"] = json!({
        "D5": ingress_facts(&raw["samples"]["D5"]["t1"], &generator_machine_hex),
        "O5": ingress_facts(&raw["samples"]["O5"]["t1"], &generator_machine_hex),
        "quiescent": quiescence["quiescent"].clone(),
    });
    raw["load"] = json!({"quiescence":quiescence,"sent":sent,"payload_bytes":4096,"period_ms":50,"elapsed_ns":load_elapsed.as_nanos() as u64,"elapsed_excludes":"post-load drain barrier (see load.quiescence.waited_ms)","fanouts":fanouts,"witness_observed_during_load":observed.len(),"witness_attribution":"none"});
    raw["generator_diagnostics"]["cuts"]["t1"] = generator_cut(&agents[0], clock);
    attach_generator_load(&mut raw, &load_returns);
    raw["topology"]["observations"]["t1"] = strip_peer_scores(
        bounded(
            "final diamond observation",
            SETUP,
            diamond_observations(agents, clock),
        )
        .await,
    );
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
    let start = tokio::time::Instant::now();
    let observed =
        capture_ready_diamond(topology, &[], start, start + Duration::from_secs(1), |_| {
            std::future::ready(Ok(observations.pop_front().expect("two acquisitions")))
        })
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
        let start = tokio::time::Instant::now();
        let result = capture_ready_diamond(
            &raw["topology"],
            &[],
            start,
            start + Duration::from_millis(30),
            |_| {
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
    let start = tokio::time::Instant::now();
    let rejected = capture_ready_diamond(
        &raw["topology"],
        &[],
        start,
        start + Duration::from_millis(10),
        |_| std::future::pending::<Result<serde_json::Value, String>>(),
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
    let start = tokio::time::Instant::now();
    let rejected = capture_ready_diamond(
        &raw["topology"],
        &[],
        start,
        start + Duration::from_secs(1),
        |_| std::future::ready(observations.pop_front().expect("two acquisitions")),
    )
    .await
    .expect_err("acquisition error remains nonpass");
    assert_eq!(rejected.last_observation, Some(invalid));
    assert_eq!(
        rejected.reason,
        "final diamond observation failed: inert acquisition failure"
    );
}

#[tokio::test(start_paused = true)]
async fn readiness_diagnostic_distinguishes_terminal_branches_and_counts() {
    let raw = synthetic_diamond_evidence();
    for stage in [
        ReadinessTerminal::BeforeAcquireDeadline,
        ReadinessTerminal::AcquireTimedOut,
        ReadinessTerminal::AcquireError,
        ReadinessTerminal::RetrySleepTimedOut,
    ] {
        let start = tokio::time::Instant::now();
        let deadline = start
            + if stage == ReadinessTerminal::BeforeAcquireDeadline {
                Duration::ZERO
            } else {
                Duration::from_millis(5)
            };
        let result =
            capture_ready_diamond(&raw["topology"], &[], start, deadline, |_| async move {
                match stage {
                    ReadinessTerminal::BeforeAcquireDeadline => {
                        panic!("must not acquire after deadline")
                    }
                    ReadinessTerminal::AcquireTimedOut => std::future::pending().await,
                    ReadinessTerminal::AcquireError => Err("inert acquisition".to_owned()),
                    _ => Ok(serde_json::json!({})),
                }
            })
            .await
            .expect_err("every terminal branch remains nonpass");
        let diag = result.diagnostics;
        assert_eq!(diag.terminal_stage, Some(stage));
        assert_eq!(diag.start_ns, 0);
        assert_eq!(
            diag.deadline_ns,
            Some(if stage == ReadinessTerminal::BeforeAcquireDeadline {
                0
            } else {
                5_000_000
            })
        );
        assert!(!diag.clock_incomplete);
        let counts = diag.counts;
        let expected = match stage {
            ReadinessTerminal::BeforeAcquireDeadline => (0, 0, 0, 0),
            ReadinessTerminal::AcquireTimedOut => (1, 0, 0, 0),
            ReadinessTerminal::AcquireError => (1, 1, 1, 0),
            _ => (1, 1, 0, 1),
        };
        assert_eq!(
            (
                counts.attempts_started,
                counts.acquisitions_completed,
                counts.acquisition_errors,
                counts.validations_rejected
            ),
            expected
        );
        assert_eq!(counts.validations_accepted, 0);
        assert!(!counts.counter_overflow);
    }
}

#[tokio::test(start_paused = true)]
async fn readiness_diagnostic_labels_late_valid_without_retaining_graph() {
    let raw = synthetic_diamond_evidence();
    let valid = raw["topology"]["observations"]["pre_cut"].clone();
    let start = tokio::time::Instant::now();
    // Timeout polls the inner future before its timer; a ready full result can
    // arrive at the deadline and must still fail the separate validation-time check.
    let rejected = capture_ready_diamond(
        &raw["topology"],
        &[],
        start,
        start + Duration::from_millis(1),
        |_| {
            let valid = valid.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(1)).await;
                Ok(valid)
            }
        },
    )
    .await
    .expect_err("late full graph does not extend readiness");
    assert_eq!(
        rejected.diagnostics.terminal_stage,
        Some(ReadinessTerminal::ValidatedAfterDeadline)
    );
    assert_eq!(rejected.diagnostics.counts.validations_accepted, 1);
    assert_eq!(rejected.diagnostics.counts.validations_rejected, 0);
    assert!(rejected.last_observation.is_none());
    assert!(!rejected.diagnostics.late_valid_raw_observation_retained);
}

#[tokio::test(start_paused = true)]
async fn readiness_diagnostic_keeps_distinct_rejected_and_partial_actual_core_attempts() {
    let raw = synthetic_diamond_evidence();
    let ids = readiness_identities(&raw["topology"]).expect("four full inert IDs");
    let mut invalid = raw["topology"]["observations"]["pre_cut"].clone();
    invalid["W5"]["admitted"] = serde_json::json!([]);
    let mut calls = 0;
    let start = tokio::time::Instant::now();
    let rejected = capture_ready_diamond(
        &raw["topology"],
        &[],
        start,
        start + Duration::from_millis(30),
        |attempt| {
            calls += 1;
            let invalid = invalid.clone();
            async move {
                if attempt.number == 1 {
                    return Ok(invalid);
                }
                let peers = vec![ant_quic::PeerId(ids[1]), ant_quic::PeerId(ids[2])];
                network::select_gossip_peers(
                    std::future::ready(peers),
                    |_| std::future::ready(network::PeerAdmission::Admitted),
                    Some(&attempt.owners[0]),
                )
                .await;
                network::select_gossip_peers(
                    std::future::pending(),
                    |_| std::future::ready(network::PeerAdmission::Admitted),
                    Some(&attempt.owners[1]),
                )
                .await;
                panic!("pending acquisition cannot reach a later owner")
            }
        },
    )
    .await
    .expect_err("partial second attempt remains nonpass");
    assert_eq!(calls, 2);
    assert_eq!(rejected.last_observation.as_ref(), Some(&invalid));
    let diag = rejected.diagnostics.bounded_value();
    assert_eq!(diag["terminal_stage"], "AcquireTimedOut");
    assert_eq!(diag["last_completed_rejected_attempt"]["attempt"], 1);
    assert_eq!(diag["terminal_attempt"]["attempt"], 2);
    assert_eq!(diag["terminal_attempt"]["acquisition_completed"], false);
    let owners = &diag["terminal_attempt"]["owners"];
    assert_eq!(owners["G5"]["selection"]["stage"], "Complete");
    assert_eq!(
        owners["G5"]["expected_edges"]["D5"],
        "CandidateAdmissionAdmitted"
    );
    assert_eq!(owners["D5"]["selection"]["stage"], "CandidateQueryInFlight");
    assert!(owners["D5"]["selection"]["total_candidates"].is_null());
    assert_eq!(owners["D5"]["expected_edges"]["W5"], "Unknown");
    assert_eq!(owners["O5"]["selection"]["stage"], "NotStarted");
    assert_eq!(diag["counts"]["attempts_started"], 2);
    assert_eq!(diag["counts"]["acquisitions_completed"], 1);
    assert_eq!(diag["counts"]["validations_rejected"], 1);
}

#[test]
fn readiness_diagnostic_checks_identity_clock_overflow_and_closed_fallback() {
    let raw = synthetic_diamond_evidence();
    assert!(readiness_identities(&raw["topology"]).is_some());
    for mutation in 0..4 {
        let mut topology = raw["topology"].clone();
        match mutation {
            0 => topology["peer_ids"]["G5"] = topology["peer_ids"]["D5"].clone(),
            1 => topology["peer_ids"]["G5"] = serde_json::json!("01".repeat(8)),
            2 => topology["peer_ids"]["G5"] = serde_json::json!("gg".repeat(32)),
            _ => topology["peer_ids"]["extra"] = serde_json::json!("01".repeat(32)),
        }
        assert!(readiness_identities(&topology).is_none());
    }
    let start = tokio::time::Instant::now();
    assert_eq!(
        readiness_offset(start + Duration::from_nanos(1), start),
        None
    );
    let mut diag = ReadinessDiagnostics::new(start, start + SETUP);
    diag.counts.attempts_started = u64::MAX;
    readiness_increment(
        &mut diag.counts.attempts_started,
        &mut diag.counts.counter_overflow,
    );
    assert_eq!(diag.counts.attempts_started, u64::MAX);
    assert!(diag.counts.counter_overflow);
    diag.finish(ReadinessTerminal::AcquireTimedOut, start, None);
    diag.terminal_attempt = Some(serde_json::json!("x".repeat(64 * 1024)));
    let value = diag.bounded_value();
    assert!(serde_json::to_vec(&value).unwrap().len() <= 64 * 1024);
    assert_eq!(value["output_overflow"], true);
    assert_eq!(value["terminal_stage"], "AcquireTimedOut");
    assert_eq!(value["counts"]["attempts_started"], u64::MAX);
    assert!(value["terminal_attempt"].is_null());
    let rejected = RejectedReadiness {
        reason: "inert rejection".into(),
        last_observation: None,
        last_rejection_reason: None,
        diagnostics: Box::new(diag),
    };
    let mut retained = raw.clone();
    retained["phase"] = serde_json::json!("setup");
    let topology = retained["topology"].clone();
    let samples = retained["samples"].clone();
    let load = retained["load"].clone();
    retain_rejected_readiness(&mut retained, &rejected);
    assert_eq!(retained["phase"], "setup");
    assert_eq!(retained["outcome"], "INCONCLUSIVE");
    assert_eq!(retained["topology"], topology);
    assert_eq!(retained["samples"], samples);
    assert_eq!(retained["load"], load);
    assert_eq!(retained["readiness_diagnostics"], value);
}

// Constructor-free ancillary diagnostics controls; no call into generator_cut.
#[test]
fn generator_returns_preserve_order_override_and_unavailable() {
    use saorsa_gossip_pubsub::FanoutCounts;
    let rows = generator_load_returns(&[
        (
            9,
            Some(FanoutCounts {
                attempted: 2,
                succeeded: 1,
            }),
        ),
        (0, None),
        (0, Some(FanoutCounts::default())),
    ]);
    assert_eq!(
        rows[0],
        serde_json::json!({"ordinal":0,"reported_fanout":9,"attempted":2,"succeeded":1})
    );
    assert_eq!(rows[1]["ordinal"], 1);
    assert!(rows[1]["attempted"].is_null() && rows[1]["succeeded"].is_null());
    assert_eq!(rows[2]["attempted"], 0);
    assert_eq!(rows[2]["succeeded"], 0);
    assert!(interpret_generator_load(&rows).is_none());
    assert!(generator_load_returns(&vec![(0, None); 201]).is_null());
}

#[test]
fn generator_load_interpretation_rejects_incoherent_or_partial_records() {
    use saorsa_gossip_pubsub::FanoutCounts;
    use serde_json::json;
    let good = generator_load_returns(&vec![
        (
            7,
            Some(FanoutCounts {
                attempted: 2,
                succeeded: 1
            })
        );
        200
    ]);
    assert_eq!(
        interpret_generator_load(&good),
        Some(json!({"attempted":400,"send_stage_succeeded":200,
        "zero_attempt_calls":0,"attempted_without_send_stage_success_calls":0}))
    );
    for (key, value) in [
        ("succeeded", json!(3)),
        ("attempted", json!(true)),
        ("attempted", json!(-1)),
        ("succeeded", json!(null)),
        ("ordinal", json!(0)),
        ("reported_fanout", json!(u64::MAX)),
    ] {
        let mut bad = good.clone();
        bad[1][key] = value;
        assert!(interpret_generator_load(&bad).is_none(), "{key}");
    }
    let mut missing = good.clone();
    missing.as_array_mut().unwrap().pop();
    assert!(interpret_generator_load(&missing).is_none());
    let mut overflow = good.clone();
    for row in overflow.as_array_mut().unwrap() {
        row["attempted"] = json!(u64::MAX);
    }
    assert!(interpret_generator_load(&overflow).is_none());
    let mut extra = good;
    extra[0]["unexpected"] = json!(1);
    assert!(interpret_generator_load(&extra).is_none());
}

#[test]
fn generator_topic_projection_preserves_absence_and_exact_bus_selection() {
    use saorsa_gossip_pubsub::{OutboundKindMeterSnapshot, OutboundTopicMeterSnapshot};
    use saorsa_gossip_types::TopicId;
    use std::collections::BTreeMap;
    let bus = TopicId::from_entity(DM_BUS_TOPIC.as_bytes());
    let other = TopicId::from_entity(b"different-topic");
    let zero = || OutboundKindMeterSnapshot {
        label: "not-retained",
        msgs: 0,
        bytes: 0,
    };
    let row = || OutboundTopicMeterSnapshot {
        eager: zero(),
        ihave: zero(),
        iwant: zero(),
        anti_entropy: zero(),
    };
    let mut rows = BTreeMap::new();
    rows.insert(other.to_string(), row());
    let mut zeros = BTreeMap::new();
    zeros.insert(other.to_string(), 17);
    let absent = generator_topic_projection(&rows, &zeros, bus);
    assert_eq!(absent["bus_row_present"], false);
    assert!(absent["bus_outbound"].is_null() && absent["bus_zero_fanout"].is_null());
    rows.insert(bus.to_string(), row());
    zeros.insert(bus.to_string(), 0);
    let present = generator_topic_projection(&rows, &zeros, bus);
    assert_eq!(present["bus_row_present"], true);
    assert_eq!(present["tracked_rows"], 2);
    assert_eq!(present["bus_outbound"]["eager"]["bytes"], 0);
    assert_eq!(present["bus_zero_fanout"], 0);
    diamond_keys(
        &present,
        &[
            "tracked_rows",
            "bus_row_present",
            "bus_outbound",
            "bus_zero_fanout",
        ],
    )
    .unwrap();
    for kind in ["eager", "ihave", "iwant", "anti_entropy"] {
        diamond_keys(&present["bus_outbound"][kind], &["msgs", "bytes"]).unwrap();
    }
    let text = present.to_string();
    assert!(
        !text.contains(&bus.to_string())
            && !text.contains(&other.to_string())
            && !text.contains("not-retained")
    );
    let unavailable = generator_cut_projection(1, 2, None, None);
    assert!(unavailable["publish"].is_null() && unavailable["stages"].is_null());
}

#[test]
fn generator_ancillary_attachment_is_bounded_and_ignores_cut_totals() {
    use saorsa_gossip_pubsub::FanoutCounts;
    use serde_json::json;
    let calls = vec![
        (
            u32::MAX,
            Some(FanoutCounts {
                attempted: usize::MAX,
                succeeded: usize::MAX
            })
        );
        200
    ];
    let mut raw = json!({"phase":"t1","outcome":"INCONCLUSIVE","reason":"existing oracle",
        "generator_diagnostics":{"schema":1,"role":"G5","cuts":{"t0":{"publish":{"publish_total":0}},
        "t1":{"publish":{"publish_total":u64::MAX}}}}});
    attach_generator_load(&mut raw, &calls);
    assert!(
        serde_json::to_vec(&raw["generator_diagnostics"])
            .unwrap()
            .len()
            < 65536
    );
    let calls = vec![
        (
            2,
            Some(FanoutCounts {
                attempted: 2,
                succeeded: 0
            })
        );
        200
    ];
    attach_generator_load(&mut raw, &calls);
    assert_eq!(
        raw["generator_diagnostics"]["load_interpretation"]
            ["attempted_without_send_stage_success_calls"],
        200
    );
    assert_eq!(raw["phase"], "t1");
    assert_eq!(raw["outcome"], "INCONCLUSIVE");
    assert_eq!(raw["reason"], "existing oracle");
    raw["generator_diagnostics"]["cuts"] = json!(null);
    let prior = raw["generator_diagnostics"]["load_interpretation"].clone();
    attach_generator_load(&mut raw, &calls);
    assert_eq!(raw["generator_diagnostics"]["load_interpretation"], prior);
}

/// #613: a zero-dissemination failure must name WHERE the load stopped.
/// Three physically different situations produce the identical oracle
/// verdict — the generator's frames never reached this host, they reached
/// it and x0x's own bounded receive queue discarded them, or they were
/// decoded and simply not forwarded. Before this record carried the
/// receive pump, every occurrence had to be hand-classified. The facts
/// line must therefore distinguish those three, which means it must read
/// the pump (not only `stages`, which starts at saorsa-gossip's decode).
#[test]
fn ingress_facts_separate_non_arrival_from_local_shedding() {
    let sample = |produced: u64, from_generator: u64, dropped: u64, decoded: u64| {
        serde_json::json!({
            "recv_pump": {
                "pubsub": {"produced_total": produced, "enqueued_total": produced - dropped,
                    "dequeued_total": produced - dropped, "dropped_full": dropped,
                    "shed_priority": 0, "latest_depth": 0, "capacity": 10_000, "max_depth": 4},
                "per_peer": {"aa": {"pubsub_produced": from_generator, "pubsub_dropped_full": dropped}},
            },
            "stages": {"message_kinds": {"eager": decoded}},
            "participation": {"unsubscribed_refused_frames": 0},
        })
    };
    let never_arrived = ingress_facts(&sample(4, 0, 0, 4), "aa");
    let shed_locally = ingress_facts(&sample(204, 200, 196, 8), "aa");
    let arrived_not_forwarded = ingress_facts(&sample(204, 200, 0, 204), "aa");
    assert!(
        never_arrived.contains("from_generator=0"),
        "{never_arrived}"
    );
    assert!(
        shed_locally.contains("from_generator=200") && shed_locally.contains("dropped_full=196"),
        "{shed_locally}"
    );
    assert!(
        arrived_not_forwarded.contains("from_generator=200")
            && arrived_not_forwarded.contains("dropped_full=0")
            && arrived_not_forwarded.contains("decoded_eager=204"),
        "{arrived_not_forwarded}"
    );
    // All three are distinct lines: a triager reading only the panic message
    // can tell them apart without opening the raw record.
    assert_ne!(never_arrived, shed_locally);
    assert_ne!(shed_locally, arrived_not_forwarded);
    // An absent per-peer row must degrade to "?" rather than reading as zero
    // frames from the generator, which would invert the conclusion.
    assert!(ingress_facts(&sample(4, 0, 0, 4), "bb").contains("from_generator=?"));
}

// ── #611 eager-mesh oracle ────────────────────────────────────────────────────

/// Check that every named peer on `topic` holds `role:"eager"` in a
/// `peer_scores_by_topic` snapshot and that no peer carries an active cooldown.
///
/// # Why this matters (#611)
///
/// The existing oracle in this file observes **plane admission** only
/// (`shape_diamond`): it checks that peers are connected and admitted to the
/// gossip plane.  A mesh can look "admitted" while the PlumTree eager set has
/// permanently collapsed to 1.  The failure mode is:
///
/// 1. Under sustained load a local CPU stall blows the per-peer 2500 ms send
///    budget; five timeouts in 30 s book the peer as slow and apply a ≥120 s
///    cooldown (`PEER_SUPPRESSION_COOLDOWN`, saorsa-gossip-pubsub).
/// 2. The 1 Hz `refresh_topic_peers` re-adds the returning peer as **lazy**
///    (by design, to avoid overriding a demotion) then runs `maintain_degree_at`,
///    whose candidate filter (`can_graft_peer_at`) drops any cooled peer.
/// 3. The issue-#32 cooling floor forbids suppressing the **last** eligible eager
///    peer, so with `leaf_max_eager_degree = 2` the set pins at exactly 1 — never
///    0, never back to 2 — for the remainder of the cooldown window (≥120 s).
/// 4. Delivery continues via the pull path (IHAVE/IWANT) so the plane looks
///    healthy, but every publication now incurs pull-path latency instead of
///    eager push, silently degrading throughput without tripping the plane
///    admission gate.
///
/// This predicate closes that gap.  It fails when any named peer is lazy,
/// missing, or has a non-zero `cooldown_ms` — the exact signal that cooling is
/// blocking re-promotion.
///
/// # Arguments
///
/// * `peer_scores_by_topic` — the value at key `"peer_scores_by_topic"` from
///   `GET /diagnostics/gossip` (or an equivalent in-process snapshot).
///   Shape: `{ "<topic>": { "<peer_id>": { "role": "eager"|"lazy",
///   "cooling_events": u64, "cooldown_ms": u64|null, ... } } }`.
/// * `topic` — the topic key as it appears in the map (named or hex8).
/// * `peer_ids` — peer IDs expected to be present and eager on this topic.
/// * `expected_degree` — `leaf_max_eager_degree` configured for this node
///   (default **2** on a Leaf; confirmed in `src/gossip/config.rs`).
///
/// # Returns
///
/// `Ok(())` when all invariants hold.  `Err(String)` with a diagnostic message
/// suitable for `assert!(…, "{}", err)` when any peer is lazy, absent, or
/// has `cooldown_ms > 0`.
///
/// # Integration note
///
/// To assert recovery rather than just a snapshot, call this function on two
/// consecutive observations taken after the load window and compare
/// `last_cool_at_unix_ms` between them.  Use [`check_eager_mesh_stable`] for that
/// two-snapshot form.  Never use a fixed sleep between observations: poll up to
/// a bounded iteration count so optimised builds cannot beat the wait
/// (repo lesson from the race-test evidence trap).
fn check_eager_mesh_recovered(
    peer_scores_by_topic: &serde_json::Value,
    topic: &str,
    peer_ids: &[&str],
    expected_degree: usize,
) -> Result<(), String> {
    let topic_map = match peer_scores_by_topic.get(topic) {
        Some(serde_json::Value::Object(m)) => m,
        Some(other) => {
            return Err(format!(
                "#611 eager-mesh oracle: topic {topic:?} is not an object in \
                 peer_scores_by_topic: {other}"
            ))
        }
        None => {
            return Err(format!(
                "#611 eager-mesh oracle: topic {topic:?} absent from peer_scores_by_topic \
                 (present topics: {:?})",
                peer_scores_by_topic
                    .as_object()
                    .map(|m| m.keys().collect::<Vec<_>>())
                    .unwrap_or_default()
            ))
        }
    };

    let mut eager_count = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for &peer_id in peer_ids {
        let peer = match topic_map.get(peer_id) {
            Some(v) => v,
            None => {
                errors.push(format!(
                    "  peer {peer_id}: absent from topic {topic:?} \
                     (present peers: {:?})",
                    topic_map.keys().collect::<Vec<_>>()
                ));
                continue;
            }
        };

        let role = peer
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("(missing)");
        let cooldown_ms = peer.get("cooldown_ms").and_then(|v| v.as_u64());
        let suppression_state = peer
            .get("suppression_state")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        // cooling_events is f64 in PeerScoreBreakdownSnapshot; use as_f64() not as_u64().
        let cooling_events = peer.get("cooling_events").and_then(|v| v.as_f64());

        if role == "eager" {
            eager_count += 1;
        } else {
            errors.push(format!(
                "  peer {peer_id}: role={role:?} want \"eager\" \
                 [cooldown_ms={cooldown_ms:?} suppression_state={suppression_state:?} \
                 cooling_events={cooling_events:?}] — peer is demoted, #611 collapse active"
            ));
        }

        // An eager peer that still carries an active cooldown is in a recovery-probe
        // state and can re-enter suppression under renewed load.  Flag it regardless
        // of role so callers can assert full stability, not just momentary promotion.
        if cooldown_ms.map(|ms| ms > 0).unwrap_or(false) {
            errors.push(format!(
                "  peer {peer_id}: cooldown_ms={cooldown_ms:?} > 0 \
                 (suppression_state={suppression_state:?}) — recovery not complete"
            ));
        }
    }

    // Degree check: the count of eager peers must equal the configured ceiling.
    // A count below expected_degree means the cool floor has pinned the set at a
    // degraded value without the peer-level errors above catching it (e.g. a peer
    // that was pruned entirely from the map and is therefore absent).
    if eager_count != expected_degree {
        // Prepend so the degree mismatch is the first line of the error.
        errors.insert(
            0,
            format!(
                "#611 eager-mesh oracle: eager_count={eager_count} want {expected_degree} \
                 on topic {topic:?} — the cooling floor has degraded the eager set"
            ),
        );
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Two-snapshot stability check: verify that the eager mesh is not only
/// recovered (`snapshot_after` passes [`check_eager_mesh_recovered`]) but also
/// **stable** — the peer was not re-cooled between the two observations.
///
/// Uses `last_cool_at_unix_ms` (monotonic `Option<u64>`) rather than
/// `cooling_events` to detect re-cooling.  `cooling_events` is an **f64
/// decayed counter** in `PeerScoreBreakdownSnapshot`; `serde_json`'s
/// `Value::as_u64()` returns `None` for float JSON values, so a comparison
/// on `cooling_events` can **never fire** on real saorsa-gossip-pubsub
/// snapshots.  `last_cool_at_unix_ms` is `Option<u64>` and monotonically
/// increases whenever the peer is cooled: if `after > before` the peer was
/// re-cooled between observations.
///
/// A re-cooled peer will produce another 2→1 collapse under the next load
/// spike even though the single-snapshot check passed.
///
/// Call this after a bounded polling loop, never after a fixed sleep:
/// `snapshot_before` is taken immediately after load completes;
/// `snapshot_after` is taken after the same number of iterations that
/// `check_eager_mesh_recovered` used to observe a passing state.
fn check_eager_mesh_stable(
    peer_scores_by_topic_before: &serde_json::Value,
    peer_scores_by_topic_after: &serde_json::Value,
    topic: &str,
    peer_ids: &[&str],
    expected_degree: usize,
) -> Result<(), String> {
    // The after snapshot must pass the single-snapshot check first.
    check_eager_mesh_recovered(peer_scores_by_topic_after, topic, peer_ids, expected_degree)?;

    // Verify last_cool_at_unix_ms did not advance between snapshots.
    // cooling_events is an f64 decayed counter; as_u64() is always None for
    // float JSON values, making any cooling_events comparison silently vacuous.
    // last_cool_at_unix_ms is monotonic Option<u64> and is safe to compare.
    let before_map = peer_scores_by_topic_before.get(topic);
    let after_map = peer_scores_by_topic_after
        .get(topic)
        .and_then(|v| v.as_object());

    let Some(after_map) = after_map else {
        return Err(format!(
            "#611 stability oracle: topic {topic:?} absent from after-snapshot"
        ));
    };

    let mut errors: Vec<String> = Vec::new();
    for &peer_id in peer_ids {
        let before_ts = before_map
            .and_then(|m| m.get(peer_id))
            .and_then(|p| p.get("last_cool_at_unix_ms"))
            .and_then(|v| v.as_u64());
        let after_ts = after_map
            .get(peer_id)
            .and_then(|p| p.get("last_cool_at_unix_ms"))
            .and_then(|v| v.as_u64());

        // (before=None, after=Some) = first cooling appeared during window.
        // (Some(b), Some(a)) with a > b = timestamp advanced = re-cooled.
        // (_, None) = no cooling recorded at all = stable.
        let recooled = match (before_ts, after_ts) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(b), Some(a)) => a > b,
        };
        if recooled {
            errors.push(format!(
                "  peer {peer_id}: last_cool_at_unix_ms advanced {before_ts:?}→{after_ts:?} \
                 — peer was re-cooled after eager promotion, unstable recovery (#611)"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "#611 stability oracle: re-cooling detected on topic {topic:?}:\n{}",
            errors.join("\n")
        ))
    }
}

// ── Unit tests for the #611 oracle predicates ─────────────────────────────────
//
// These tests operate against **synthetic** peer_scores_by_topic JSON.
// No daemon is spawned; no network I/O occurs.
//
// Induction of cooling deterministically end-to-end belongs in
// saorsa-gossip's paused-clock test
// `cooling_does_not_demote_when_no_graft_eligible_replacement_exists`
// (sg#62/#65 PR #67).  The x0x layer only supplies the degree ceiling and the
// diagnostic surface; the predicate logic below is what x0x owns.

/// Happy path: both peers eager, no cooldown, degree == 2.
/// This is the shape the diamond topology requires after load.
///
/// Fixtures use **float** `cooling_events` (e.g. `2.0`) to match the real
/// `PeerScoreBreakdownSnapshot` shape from saorsa-gossip-pubsub 0.5.82.
/// `cooling_events` is an f64 decayed counter; integer JSON literals like `2`
/// would silently pass `as_u64()` in the old code but float values never do.
#[test]
fn eager_mesh_oracle_passes_on_fully_recovered_shape() {
    let snapshot = serde_json::json!({
        "dm_bus": {
            "peer_aaaa": {
                "role": "eager",
                "score": 1.0,
                "cooling_events": 2.0,
                "last_cool_at_unix_ms": null,
                "eager_eligible": true,
                "suppression_state": null,
                "cooldown_ms": null
            },
            "peer_bbbb": {
                "role": "eager",
                "score": 0.9,
                "cooling_events": 1.0,
                "last_cool_at_unix_ms": null,
                "eager_eligible": true,
                "suppression_state": null,
                "cooldown_ms": null
            }
        }
    });
    check_eager_mesh_recovered(&snapshot, "dm_bus", &["peer_aaaa", "peer_bbbb"], 2)
        .expect("fully-recovered shape must pass the #611 oracle");
}

/// **Negative control** — the oracle MUST fail on the exact #611 collapse shape:
/// peer_bbbb demoted to lazy, cooldown_ms=120000, eager_count=1 while
/// expected_degree=2.  Without this the oracle cannot be claimed "able to fail".
///
/// This is the synthetic version of what a degraded run's `peer_scores_by_topic`
/// snapshot would show: peer was suppressed for 120 s and pinned the mesh at 1.
#[test]
fn eager_mesh_oracle_fails_on_611_collapse_shape() {
    let snapshot = serde_json::json!({
        "dm_bus": {
            "peer_aaaa": {
                "role": "eager",
                "score": 1.0,
                "cooling_events": 5.0,
                "last_cool_at_unix_ms": 1_700_000_000_000u64,
                "eager_eligible": true,
                "suppression_state": null,
                "cooldown_ms": null
            },
            "peer_bbbb": {
                "role": "lazy",
                "score": 0.1,
                "cooling_events": 5.0,
                "last_cool_at_unix_ms": 1_700_000_120_000u64,
                "eager_eligible": false,
                "suppression_state": "cooled",
                "cooldown_ms": 120000
            }
        }
    });
    let result = check_eager_mesh_recovered(&snapshot, "dm_bus", &["peer_aaaa", "peer_bbbb"], 2);
    assert!(
        result.is_err(),
        "degraded shape (eager_count=1, peer_bbbb role=lazy cooldown=120s) must fail the \
         #611 oracle; got Ok — the predicate is blind to the collapse"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("peer_bbbb"),
        "#611 oracle error must name the demoted peer; got: {msg}"
    );
    assert!(
        msg.contains("lazy") || msg.contains("eager_count"),
        "#611 oracle error must explain the demotion; got: {msg}"
    );
}

/// **Negative control** — a peer eager but carrying `cooldown_ms > 0` is in a
/// recovery-probe window and can re-enter suppression under the next load spike.
/// The oracle must flag this even though `role == "eager"`.
#[test]
fn eager_mesh_oracle_fails_on_eager_peer_with_active_cooldown() {
    let snapshot = serde_json::json!({
        "dm_bus": {
            "peer_aaaa": {
                "role": "eager",
                "score": 1.0,
                "cooling_events": 0.0,
                "last_cool_at_unix_ms": null,
                "eager_eligible": true,
                "suppression_state": null,
                "cooldown_ms": null
            },
            "peer_bbbb": {
                "role": "eager",
                "score": 0.6,
                "cooling_events": 3.0,
                "last_cool_at_unix_ms": 1_700_000_045_000u64,
                "eager_eligible": true,
                "suppression_state": "recovery_probe",
                "cooldown_ms": 45000
            }
        }
    });
    let result = check_eager_mesh_recovered(&snapshot, "dm_bus", &["peer_aaaa", "peer_bbbb"], 2);
    assert!(
        result.is_err(),
        "eager peer with cooldown_ms=45000 (recovery_probe) must fail the #611 oracle; \
         a recovery-probe peer can re-enter suppression under renewed load"
    );
}

/// **Negative control** — illustrates the gate/measure mismatch the old oracle
/// suffered: asserting degree=1 would let a 2→1 collapse pass silently.
/// The same snapshot must FAIL once we correctly assert degree=2.
#[test]
fn eager_mesh_oracle_degree_mismatch_is_detectable() {
    // Only one peer is present and eager — the collapsed-mesh shape.
    let snapshot = serde_json::json!({
        "dm_bus": {
            "peer_aaaa": {
                "role": "eager",
                "score": 1.0,
                "cooling_events": 0.0,
                "last_cool_at_unix_ms": null,
                "eager_eligible": true,
                "suppression_state": null,
                "cooldown_ms": null
            }
        }
    });
    // Wrong assertion (degree=1): silently passes — this is what the old
    // oracle effectively did by not checking the eager set at all.
    assert!(
        check_eager_mesh_recovered(&snapshot, "dm_bus", &["peer_aaaa"], 1).is_ok(),
        "degree=1 assertion passes on a single eager peer (illustrating old oracle blindness)"
    );
    // Correct assertion (degree=2): fails because peer_bbbb is absent.
    // The degree check + absent-peer error together surface the collapse.
    let result = check_eager_mesh_recovered(&snapshot, "dm_bus", &["peer_aaaa", "peer_bbbb"], 2);
    assert!(
        result.is_err(),
        "degree=2 assertion must fail when peer_bbbb is absent — \
         the #611 collapse is now visible"
    );
}

/// Stability oracle: `last_cool_at_unix_ms` must not advance between two
/// observations.  If it does, the peer was re-cooled after promotion — a
/// transient recovery.
///
/// Fixtures use float `cooling_events` (the real shape from saorsa-gossip-pubsub)
/// to guard against any regression that re-introduces `cooling_events.as_u64()`.
#[test]
fn eager_mesh_stability_oracle_passes_when_ts_stable() {
    let make_snap = |ts_a: Option<u64>, ts_b: Option<u64>| {
        serde_json::json!({
            "dm_bus": {
                "peer_aaaa": { "role": "eager", "cooling_events": 3.0,
                               "last_cool_at_unix_ms": ts_a,
                               "eager_eligible": true, "suppression_state": null, "cooldown_ms": null },
                "peer_bbbb": { "role": "eager", "cooling_events": 2.0,
                               "last_cool_at_unix_ms": ts_b,
                               "eager_eligible": true, "suppression_state": null, "cooldown_ms": null }
            }
        })
    };
    // Same last_cool_at_unix_ms before and after — stable recovery.
    let before = make_snap(Some(1_700_000_000_000), Some(1_700_000_010_000));
    let after = make_snap(Some(1_700_000_000_000), Some(1_700_000_010_000));
    check_eager_mesh_stable(&before, &after, "dm_bus", &["peer_aaaa", "peer_bbbb"], 2)
        .expect("stable last_cool_at_unix_ms must pass the stability oracle");
}

/// **Negative control** — stability oracle must fail when `last_cool_at_unix_ms`
/// advanced (peer was re-cooled after eager promotion).
///
/// Uses float `cooling_events` so that any attempt to re-introduce
/// `cooling_events.as_u64()` would silently fail to detect re-cooling — this
/// test would then incorrectly pass, making the regression visible.
#[test]
fn eager_mesh_stability_oracle_fails_when_ts_advances() {
    let before = serde_json::json!({
        "dm_bus": {
            "peer_aaaa": { "role": "eager", "cooling_events": 3.0,
                           "last_cool_at_unix_ms": 1_700_000_000_000u64,
                           "eager_eligible": true, "suppression_state": null, "cooldown_ms": null },
            "peer_bbbb": { "role": "eager", "cooling_events": 2.0,
                           "last_cool_at_unix_ms": 1_700_000_010_000u64,
                           "eager_eligible": true, "suppression_state": null, "cooldown_ms": null }
        }
    });
    // peer_bbbb was re-cooled: last_cool_at_unix_ms advanced.
    let after = serde_json::json!({
        "dm_bus": {
            "peer_aaaa": { "role": "eager", "cooling_events": 3.0,
                           "last_cool_at_unix_ms": 1_700_000_000_000u64,
                           "eager_eligible": true, "suppression_state": null, "cooldown_ms": null },
            "peer_bbbb": { "role": "eager", "cooling_events": 2.4,
                           "last_cool_at_unix_ms": 1_700_000_130_000u64,
                           "eager_eligible": true, "suppression_state": null, "cooldown_ms": null }
        }
    });
    let result = check_eager_mesh_stable(&before, &after, "dm_bus", &["peer_aaaa", "peer_bbbb"], 2);
    assert!(
        result.is_err(),
        "advancing last_cool_at_unix_ms must fail the stability oracle"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("peer_bbbb"),
        "stability error must name the re-cooled peer; got: {msg}"
    );
}

/// **Negative control** for the `cooling_events` f64 / `as_u64()` trap.
///
/// `PeerScoreBreakdownSnapshot.cooling_events` is an **f64 decayed counter**;
/// `serde_json::Value::as_u64()` always returns `None` for float JSON values.
/// Any stability oracle that compares `cooling_events` via `as_u64()` would
/// silently pass even when `cooling_events` advanced — invisible re-cooling.
///
/// This test uses float `cooling_events` (the real snapshot shape) and verifies
/// that the oracle correctly detects re-cooling through `last_cool_at_unix_ms`
/// even though `cooling_events.as_u64()` would return `None` for both values.
#[test]
fn eager_mesh_stability_oracle_not_fooled_by_float_cooling_events() {
    // cooling_events is f64: as_u64() is always None, so the old oracle
    // could never fire on this shape, even when cooling_events clearly advanced.
    let before = serde_json::json!({
        "dm_bus": {
            "peer_aaaa": { "role": "eager", "cooling_events": 2.0,
                           "last_cool_at_unix_ms": 1_000_000u64,
                           "eager_eligible": true, "suppression_state": null, "cooldown_ms": null },
            "peer_bbbb": { "role": "eager", "cooling_events": 1.5,
                           "last_cool_at_unix_ms": 2_000_000u64,
                           "eager_eligible": true, "suppression_state": null, "cooldown_ms": null }
        }
    });
    // peer_bbbb was re-cooled: cooling_events advanced (f64, as_u64=None) AND
    // last_cool_at_unix_ms advanced (u64, reliably detectable).
    let after = serde_json::json!({
        "dm_bus": {
            "peer_aaaa": { "role": "eager", "cooling_events": 2.0,
                           "last_cool_at_unix_ms": 1_000_000u64,
                           "eager_eligible": true, "suppression_state": null, "cooldown_ms": null },
            "peer_bbbb": { "role": "eager", "cooling_events": 2.4,
                           "last_cool_at_unix_ms": 3_000_000u64,
                           "eager_eligible": true, "suppression_state": null, "cooldown_ms": null }
        }
    });
    let result = check_eager_mesh_stable(&before, &after, "dm_bus", &["peer_aaaa", "peer_bbbb"], 2);
    assert!(
        result.is_err(),
        "re-cooling must be detected via last_cool_at_unix_ms even when cooling_events is f64; \
         if this passes, the oracle is silently blind to re-cooling on real snapshots (#611)"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("peer_bbbb"),
        "stability error must name the re-cooled peer; got: {msg}"
    );
}

// ── Unit tests for check_eager_mesh_for_diamond subscription semantics ────────
//
// These tests validate the configuration-driven subscriber/non-subscriber
// distinction.  The subscription decision is driven by `non_subscriber_indices`
// (passed directly to `capture_ready_diamond` by shape_diamond, NOT embedded
// in topology JSON), NOT by observing whether the topic is absent in the snapshot.
//
// All tests use synthetic observations; no daemon or network I/O is needed.

/// **Negative control** — subscriber with topic absent: oracle must return Err
/// (retryable), NOT silently pass.  Guards against the vacuous-pass scenario
/// where a subscriber's scores haven't populated yet and the oracle passes.
#[test]
fn eager_mesh_for_diamond_subscriber_absent_topic_is_retryable_err() {
    // G5 (index 0) has peer_scores_by_topic populated with another topic but
    // NOT the DM bus topic — scores present but not yet populated for DM bus.
    let other_topic = "cafebabe12345678";
    let observed = serde_json::json!({
        "G5": {
            "admitted": [],
            "peer_scores_by_topic": { other_topic: {} }
        },
        "D5": { "admitted": [], "peer_scores_by_topic": null },
        "O5": { "admitted": [], "peer_scores_by_topic": null },
        "W5": { "admitted": [], "peer_scores_by_topic": null },
    });
    // Non-zero fake identities so neighbor_hex8 is computable if the check
    // ever reaches the peer lookup (it should not — topic check fires first).
    let fake_ids = Some([[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);
    let result = check_eager_mesh_for_diamond(&observed, fake_ids, &[]);
    assert!(
        result.is_err(),
        "subscriber (G5) with DM bus topic absent must return Err (retryable); \
         a silent Ok would let the oracle pass vacuously before scores populate"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("G5"),
        "retryable error must name the failing node; got: {msg}"
    );
    assert!(
        msg.contains("retryable") || msg.contains("absent"),
        "error must describe the retryable condition; got: {msg}"
    );
}

/// Declared non-subscriber with topic absent: oracle must return Ok.
/// This is the opt-out arm: O5 (index 2) is declared as non-subscriber and
/// its `peer_scores_by_topic` correctly lacks the DM bus topic.
#[test]
fn eager_mesh_for_diamond_declared_non_subscriber_absent_topic_is_ok() {
    let other_topic = "cafebabe12345678";
    let observed = serde_json::json!({
        "G5": { "admitted": [], "peer_scores_by_topic": null },
        "D5": { "admitted": [], "peer_scores_by_topic": null },
        // O5 has scores for other topics but not DM bus — correct opt-out shape.
        "O5": {
            "admitted": [],
            "peer_scores_by_topic": { other_topic: {} }
        },
        "W5": { "admitted": [], "peer_scores_by_topic": null },
    });
    let fake_ids = Some([[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);
    // O5 = index 2 in DIAMOND_LABELS order.
    check_eager_mesh_for_diamond(&observed, fake_ids, &[2])
        .expect("declared non-subscriber (O5) with topic correctly absent must pass");
}

/// **Negative control** — declared non-subscriber WITH the DM bus topic present:
/// oracle must return Err (opt-out flag had no effect — configuration violation).
#[test]
fn eager_mesh_for_diamond_declared_non_subscriber_with_topic_is_err() {
    let dm_topic = saorsa_gossip_types::TopicId::from_entity(DM_BUS_TOPIC.as_bytes()).to_string();
    // O5 declared non-subscriber but has the DM bus topic in its scores.
    let mut o5_scores = serde_json::json!({});
    o5_scores[&dm_topic] = serde_json::json!({
        "peer_aaaa": {
            "role": "eager", "cooling_events": 0.0,
            "last_cool_at_unix_ms": null,
            "eager_eligible": true, "suppression_state": null, "cooldown_ms": null
        }
    });
    let observed = serde_json::json!({
        "G5": { "admitted": [], "peer_scores_by_topic": null },
        "D5": { "admitted": [], "peer_scores_by_topic": null },
        "O5": { "admitted": [], "peer_scores_by_topic": o5_scores },
        "W5": { "admitted": [], "peer_scores_by_topic": null },
    });
    let fake_ids = Some([[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);
    let result = check_eager_mesh_for_diamond(&observed, fake_ids, &[2]);
    assert!(
        result.is_err(),
        "declared non-subscriber (O5) WITH the DM bus topic must return Err \
         — the opt-out flag had no effect, a configuration invariant violation"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("O5"),
        "error must name the violating node; got: {msg}"
    );
}

// validate_topology rejects observations that still carry peer_scores_by_topic
// (the field added by diamond_observations_with_recorder for oracle use), and
// accepts observations where strip_peer_scores has removed it.  This pins the
// topology-contract invariant so a regression surfaces inertly in CI rather
// than through a live integration test panic.
#[test]
fn validate_topology_rejects_observation_with_extra_key() {
    let mut evidence = synthetic_diamond_evidence();
    // Inject the oracle field into one pre_cut observation, simulating the
    // storage bug that existed before strip_peer_scores was applied.
    evidence["topology"]["observations"]["pre_cut"]["G5"]["peer_scores_by_topic"] =
        serde_json::Value::Null;
    let result = validate_measurement(&evidence);
    assert!(
        result.is_err(),
        "validate_topology must reject an observation carrying peer_scores_by_topic"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("topology keys mismatch"),
        "expected 'topology keys mismatch'; got: {msg}"
    );
}

#[test]
fn validate_topology_accepts_stripped_observations() {
    // synthetic_diamond_evidence already produces clean observations
    // ({"admitted","begin_ns","end_ns"} only), so validate_measurement must pass
    // the topology-contract portion of its checks.
    let evidence = synthetic_diamond_evidence();
    // validate_measurement may fail for reasons beyond topology keys (e.g. load
    // counters not present in synthetic data), but the topology-key check must
    // NOT be among them.
    match validate_measurement(&evidence) {
        Ok(()) => {} // clean pass — fine
        Err(e) => {
            assert!(
                !e.contains("topology keys mismatch"),
                "stripped observations must not trigger topology-key check; got: {e}"
            );
        }
    }
}
