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

fn raw_sample(agent: &Agent, clock: std::time::Instant) -> serde_json::Value {
    let begin = clock.elapsed().as_nanos() as u64;
    let egress = agent
        .gossip_egress_diagnostics()
        .expect("actual egress getter");
    let participation = agent
        .gossip_participation()
        .expect("actual participation getter");
    let stages = pubsub(agent).stage_stats();
    serde_json::json!({"begin_ns":begin,"end_ns":clock.elapsed().as_nanos() as u64,
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
            return Err(format!("{arm}: membership changed"));
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
            let origin = raw["generator_peer_hex8"]
                .as_str()
                .ok_or("generator identity missing")?;
            for sample in [before, after] {
                let peers = sample["stages"]["peer_scores"]
                    .as_array()
                    .ok_or("peer scores absent")?;
                if !peers.iter().any(|p| {
                    p["topic"] == bus
                        && p["role"] == "eager"
                        && p["eager_eligible"] == true
                        && p["peer_id"].as_str().is_some_and(|id| id != origin)
                }) {
                    return Err("D5 lacks recorded non-origin eager opportunity".into());
                }
            }
            if delta == 0 {
                return Err(
                    "FAIL: D5 recorded no bus eager attempts despite endpoint opportunity".into(),
                );
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
    let mut raw = json!({"schema":1,"selector":"legacy_bus_interop_tests::paired_controlled_load_bus_eager_attempts_default_vs_optout",
        "phase":"setup","outcome":"UNRUN","pid":std::process::id(),
        "claim":"controlled bus eager send attempts; not forwarding, wire occupancy or field reduction",
        "universe":topic_universe(agents),"samples":{},"load":{},
        "identities":agents.iter().map(|a|json!({"agent":hex::encode(a.agent_id().0),"machine":hex::encode(a.machine_id().0)})).collect::<Vec<_>>(),
        "generator_peer_hex8":saorsa_gossip_types::PeerId::new(agents[0].machine_id().0).to_string(),
        "binary_sha256":binary_hash,
        "build_lock_sha256":hex::encode(Sha256::digest(include_bytes!("../Cargo.lock")))});
    emit_measurement(&raw);
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
    // The design's declared settle follows the labelled plane-readiness barrier.
    tokio::time::sleep(Duration::from_secs(2)).await;
    raw["samples"] =
        json!({"D5":{"t0":raw_sample(&agents[1],clock)},"O5":{"t0":raw_sample(&agents[2],clock)}});
    raw["phase"] = json!("t0");
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
    raw["phase"] = json!("t1");
    emit_measurement(&raw);
    match validate_measurement(&raw) {
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
