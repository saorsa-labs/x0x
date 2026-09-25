//! Live x0x PubSub transport witness for negotiated outer signer-key references.
//!
//! Runs only in the isolated Linux integration lane: this starts two real
//! x0xd processes and sends public application messages over QUIC.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

#[path = "harness/src/cluster.rs"]
mod cluster;
use cluster::{join_peer, solo, AgentInstance};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(20);
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_MESSAGES_PER_PHASE: usize = 12;

const COUNTERS: [&str; 22] = [
    "full_out_frames",
    "full_out_bytes",
    "ref_out_frames",
    "ref_out_bytes",
    "full_in_frames",
    "full_in_bytes",
    "ref_in_frames",
    "ref_in_bytes",
    "cache_hits",
    "cache_misses",
    "cache_evictions",
    "requests",
    "responses",
    "pending_frames_high_water",
    "pending_bytes_high_water",
    "pending_timeouts",
    "pending_peer_limit_drops",
    "pending_global_limit_drops",
    "malformed_controls",
    "hash_mismatches",
    "replay_success",
    "replay_failure",
];

#[derive(Debug, Clone)]
struct Snapshot {
    uptime_secs: u64,
    key_cache: Value,
}

struct PhaseBaseline {
    alice_before: Snapshot,
    bob_before: Snapshot,
    alice_before_peer_start: Snapshot,
}

#[derive(Default)]
struct FullPhaseWitness {
    outbound_seen: bool,
    inbound_seen: bool,
}

impl FullPhaseWitness {
    fn observe(&mut self, alice_start: &Snapshot, alice_now: &Snapshot, bob_now: &Snapshot) {
        self.outbound_seen |= alice_now.increase(alice_start, "full_out_frames");
        // Bob is a fresh process in both phases, so its counter began at zero.
        self.inbound_seen |= bob_now.count("full_in_frames") > 0;
    }

    fn complete(&self) -> bool {
        self.outbound_seen && self.inbound_seen
    }
}

impl Snapshot {
    fn count(&self, field: &str) -> u64 {
        self.key_cache[field]
            .as_u64()
            .unwrap_or_else(|| panic!("key_cache.{field} missing or nonnumeric: {self:?}"))
    }

    fn increase(&self, previous: &Self, field: &str) -> bool {
        let before = previous.count(field);
        let after = self.count(field);
        assert!(
            after >= before,
            "key_cache.{field} regressed: {previous:?} -> {self:?}"
        );
        after > before
    }
}

async fn diagnostics(node: &AgentInstance) -> Snapshot {
    let response = tokio::time::timeout(DELIVERY_TIMEOUT, node.get("/diagnostics/gossip"))
        .await
        .expect("gossip diagnostics deadline");
    assert!(
        response.status().is_success(),
        "gossip diagnostics unavailable"
    );
    let body: Value = response.json().await.expect("gossip diagnostics JSON");
    assert_eq!(body["ok"], true);
    let uptime_secs = body["uptime_secs"].as_u64().expect("daemon uptime");
    let key_cache = body["key_cache"].clone();
    assert!(key_cache.is_object(), "missing key-cache producer snapshot");
    let snapshot = Snapshot {
        uptime_secs,
        key_cache,
    };
    for field in COUNTERS {
        snapshot.count(field);
    }
    snapshot
}

async fn subscribe(node: &AgentInstance, topic: &str) -> Ws {
    let (mut ws, _) = tokio::time::timeout(DELIVERY_TIMEOUT, async {
        tokio_tungstenite::connect_async(node.ws_url("/ws").await).await
    })
    .await
    .expect("WebSocket connect deadline")
    .expect("authenticated WebSocket connection");
    ws.send(Message::Text(
        json!({"type": "subscribe", "topics": [topic]}).to_string(),
    ))
    .await
    .expect("send WebSocket subscription");
    let confirmation = tokio::time::timeout(DELIVERY_TIMEOUT, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    let frame: Value = serde_json::from_str(&text).expect("WebSocket JSON");
                    if frame["type"] == "subscribed" {
                        return frame;
                    }
                }
                other => panic!("WebSocket closed before subscription: {other:?}"),
            }
        }
    })
    .await
    .expect("subscription confirmation deadline");
    assert_eq!(confirmation["type"], "subscribed");
    ws
}

async fn publish_and_receive(
    publisher: &AgentInstance,
    receiver: &mut Ws,
    topic: &str,
    sender: &str,
    label: &str,
    sequence: usize,
) {
    let payload = BASE64.encode(format!(
        "key-cache-{label}-{sequence}-{}",
        rand::random::<u64>()
    ));
    let response = tokio::time::timeout(
        DELIVERY_TIMEOUT,
        publisher.post("/publish", json!({"topic": topic, "payload": payload})),
    )
    .await
    .expect("application publish deadline");
    assert!(response.status().is_success(), "application publish failed");
    let frame = tokio::time::timeout(DELIVERY_TIMEOUT, async {
        loop {
            match receiver.next().await {
                Some(Ok(Message::Text(text))) => {
                    let value: Value = serde_json::from_str(&text).expect("WebSocket JSON");
                    if value["type"] == "message" && value["topic"] == topic {
                        // Anti-entropy legitimately re-serves earlier-phase
                        // payloads (Alice's 60 s message cache) to a restarted
                        // Bob whose dedupe state is gone; wait for this one.
                        if value["payload"] != payload {
                            eprintln!(
                                "{label}/{sequence}: skipping earlier payload {}",
                                value["payload"]
                            );
                            continue;
                        }
                        return value;
                    }
                }
                other => panic!("WebSocket closed before application delivery: {other:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no application delivery for {label}/{sequence}"));
    assert_eq!(frame["payload"], payload, "application payload mismatch");
    assert_eq!(frame["origin"], sender, "verified origin mismatch");
}

async fn wait_for_reconnect(node: &AgentInstance) {
    tokio::time::timeout(RECONNECT_TIMEOUT, async {
        loop {
            let response = node.get("/peers").await;
            assert!(response.status().is_success(), "peer list unavailable");
            let body: Value = response.json().await.expect("peer list JSON");
            if body
                .as_array()
                .or_else(|| body["peers"].as_array())
                .is_some_and(|peers| !peers.is_empty())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("reconnect deadline");
}

async fn prove_full_then_ref(
    alice: &AgentInstance,
    bob: &AgentInstance,
    receiver: &mut Ws,
    topic: &str,
    sender: &str,
    label: &str,
    baseline: PhaseBaseline,
) {
    let PhaseBaseline {
        alice_before,
        bob_before,
        alice_before_peer_start,
    } = baseline;
    let mut full = FullPhaseWitness::default();
    full.observe(&alice_before_peer_start, &alice_before, &bob_before);
    let mut saw_full = full.complete();
    let mut saw_ref_after_full = false;
    let mut alice_previous = alice_before.clone();
    let mut bob_previous = bob_before.clone();
    for sequence in 0..MAX_MESSAGES_PER_PHASE {
        publish_and_receive(alice, receiver, topic, sender, label, sequence).await;
        let alice_after = diagnostics(alice).await;
        let bob_after = diagnostics(bob).await;
        // Full may straddle the pre-application snapshot or two later polls.
        // Ref still has to appear after a prior complete Full sample.
        let reference = alice_after.increase(&alice_previous, "ref_out_frames")
            && bob_after.increase(&bob_previous, "ref_in_frames")
            && bob_after.increase(&bob_previous, "cache_hits");
        let ref_after_full = saw_full && reference;
        full.observe(&alice_before_peer_start, &alice_after, &bob_after);
        saw_full = full.complete();
        if ref_after_full {
            saw_ref_after_full = true;
            eprintln!(
                "{label}: exact deliveries={} alice_before={alice_before:?} bob_before={bob_before:?} alice_after={alice_after:?} bob_after={bob_after:?}",
                sequence + 1
            );
            break;
        }
        alice_previous = alice_after;
        bob_previous = bob_after;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        saw_full,
        "{label}: missing phase-wide Full counter evidence (out_seen={} in_seen={}) after {MAX_MESSAGES_PER_PHASE} exact deliveries; alice_start={alice_before_peer_start:?} alice_before={alice_before:?} bob_before={bob_before:?} alice_last={alice_previous:?} bob_last={bob_previous:?}",
        full.outbound_seen,
        full.inbound_seen,
    );
    assert!(
        saw_ref_after_full,
        "{label}: no later Ref out/in and cache-hit delta after {MAX_MESSAGES_PER_PHASE} exact deliveries; alice_before={alice_before:?} bob_before={bob_before:?} alice_last={alice_previous:?} bob_last={bob_previous:?}"
    );
}

#[test]
fn full_phase_witness_survives_pre_application_and_split_poll_boundaries() {
    let baseline = Snapshot {
        uptime_secs: 1,
        key_cache: json!({"full_out_frames": 0, "full_in_frames": 0}),
    };
    let alice_sent = Snapshot {
        uptime_secs: 1,
        key_cache: json!({"full_out_frames": 1}),
    };
    let bob_before_receive = Snapshot {
        uptime_secs: 1,
        key_cache: json!({"full_in_frames": 0}),
    };
    let alice_unchanged = alice_sent.clone();
    let bob_received = Snapshot {
        uptime_secs: 1,
        key_cache: json!({"full_in_frames": 1}),
    };

    // Alice sends before the application baseline; Bob receives afterward.
    let mut witness = FullPhaseWitness::default();
    witness.observe(&baseline, &alice_sent, &bob_before_receive);
    assert!(witness.outbound_seen);
    assert!(!witness.inbound_seen);
    assert!(!witness.complete());
    witness.observe(&baseline, &alice_unchanged, &bob_received);
    assert!(witness.complete());

    // The same split can occur entirely within the application phase.
    let mut within_phase = FullPhaseWitness::default();
    within_phase.observe(&baseline, &baseline, &bob_before_receive);
    assert!(!within_phase.complete());
    within_phase.observe(&baseline, &alice_sent, &bob_before_receive);
    assert!(!within_phase.complete());
    within_phase.observe(&baseline, &alice_unchanged, &bob_received);
    assert!(within_phase.complete());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "starts real x0xd/QUIC; Linux isolated runtime only"]
async fn public_pubsub_key_cache_full_ref_restart_recovery() {
    if !cfg!(target_os = "linux") {
        panic!("run only in isolated Linux lane");
    }
    let (alice, alice_bind) = solo().await;
    // This snapshot precedes Bob's process, authenticated session, and all
    // Alice -> Bob key-cache traffic. No startup/mesh-settle frames can hide
    // the first Full in an already-warm baseline.
    let alice_pre_connect = diagnostics(&alice).await;
    let mut bob = join_peer(&alice, alice_bind).await;
    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let topic = format!("key-cache-transport-{}", rand::random::<u64>());

    let alice_before = diagnostics(&alice).await;
    let bob_before = diagnostics(&bob).await;
    // Full counters are process-wide. A fresh Bob inbound count and Alice's
    // post-connection outbound delta show phase traffic, not frame identity.
    // Full may be startup traffic; app delivery and later Ref are separate.
    let _alice_subscription = subscribe(&alice, &topic).await;
    let mut bob_subscription = subscribe(&bob, &topic).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    prove_full_then_ref(
        &alice,
        &bob,
        &mut bob_subscription,
        &topic,
        &alice_id,
        "initial",
        PhaseBaseline {
            alice_before,
            bob_before,
            alice_before_peer_start: alice_pre_connect,
        },
    )
    .await;

    let alice_before_restart = diagnostics(&alice).await;
    let bob_before_restart = diagnostics(&bob).await;
    let old_pid = bob.pid();
    drop(bob_subscription);
    bob.restart().await;
    assert_ne!(bob.pid(), old_pid, "restart reused daemon PID");
    assert_eq!(bob.agent_id().await, bob_id, "restart changed identity");
    let bob_after_restart = diagnostics(&bob).await;
    assert!(
        bob_after_restart.uptime_secs < bob_before_restart.uptime_secs,
        "daemon uptime did not reset: {bob_before_restart:?} -> {bob_after_restart:?}"
    );
    wait_for_reconnect(&alice).await;
    wait_for_reconnect(&bob).await;
    let alice_before_recovery = diagnostics(&alice).await;
    let bob_before_recovery = diagnostics(&bob).await;
    let mut bob_subscription = subscribe(&bob, &topic).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    prove_full_then_ref(
        &alice,
        &bob,
        &mut bob_subscription,
        &topic,
        &alice_id,
        "after-restart",
        PhaseBaseline {
            alice_before: alice_before_recovery,
            bob_before: bob_before_recovery,
            alice_before_peer_start: alice_before_restart,
        },
    )
    .await;
}
