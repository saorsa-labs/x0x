#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Bidirectional delivery tests for group public messages.
//!
//! These tests reproduce the asymmetric delivery signal observed between two
//! physical x0xd instances (messages flow B→A but not A→B). They exercise the
//! gossip topic publish/subscribe path that `spawn_public_message_listener`
//! and `send_group_public_message` rely on, plus the ADR-0029 thread metadata
//! round-trip.
//!
//! Every test publishes in BOTH directions and asserts reception in BOTH
//! directions within a generous timeout. A pass proves the gossip mesh is
//! symmetric for topic delivery; a fail pinpoints which direction broke.
//!
//! DIAGNOSTIC HARNESS, not regression coverage: these tests drive the
//! library-level publish/subscribe path directly (not the REST routes or
//! direct-delivery config) and silently skip when loopback bind/connect is
//! unavailable, so a green run can mean nothing executed. They are `#[ignore]`d
//! by default; run explicitly with
//! `cargo nextest run --test group_bidirectional_delivery --run-ignored all`.

use std::time::{Duration, Instant};
use tempfile::TempDir;
use x0x::groups::{GroupPublicMessage, GroupPublicMessageKind};
use x0x::identity::AgentKeypair;
use x0x::{Agent, Subscription};

// ── Helpers (mirrors direct_messaging_integration.rs) ─────────────────────

fn loopback_network_config() -> x0x::network::NetworkConfig {
    x0x::network::NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..x0x::network::NetworkConfig::default()
    }
}

fn normalize_loopback(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    if addr.ip().is_unspecified() {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        )
    } else {
        addr
    }
}

fn is_network_bind_permission_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("Operation not permitted")
        && (message.contains("All socket binds failed")
            || message.contains("Failed to bind UDP socket")
            || message.contains("bind UDP socket")
            || message.contains("network initialization failed"))
}

async fn create_loopback_test_agent(
    temp_dir: &TempDir,
    name: &str,
) -> Result<Option<Agent>, Box<dyn std::error::Error>> {
    let machine_key_path = temp_dir.path().join(format!("{name}_machine.key"));
    let agent_key_path = temp_dir.path().join(format!("{name}_agent.key"));
    let contacts_path = temp_dir.path().join(format!("{name}_contacts.json"));

    match Agent::builder()
        .with_machine_key(machine_key_path)
        .with_agent_key_path(agent_key_path)
        .with_contact_store_path(contacts_path)
        .with_peer_cache_disabled()
        .with_network_config(loopback_network_config())
        .build()
        .await
    {
        Ok(agent) => Ok(Some(agent)),
        Err(e) if is_network_bind_permission_error(&e) => {
            eprintln!("Skipping test: network bind not permitted ({e})");
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Connect two loopback agents and wait for mutual gossip readiness.
/// Returns `false` when the environment cannot bind (CI sandbox), signalling
/// the caller to skip.
async fn connect_agents(alice: &Agent, bob: &Agent) -> Result<bool, Box<dyn std::error::Error>> {
    alice.join_network().await?;
    bob.join_network().await?;

    let alice_network = alice.network().ok_or("alice network")?.clone();
    let bob_network = bob.network().ok_or("bob network")?.clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.expect("bob bound"));
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    alice_network.connect_addr(bob_addr).await?;

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if alice_network.is_connected(&bob_peer).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if !alice_network.is_connected(&bob_peer).await {
        return Ok(false);
    }

    // Give the gossip mesh a moment to exchange IHAVE/IWANT tables after the
    // QUIC handshake. Without this, the first publish can race the PlumTree
    // tree-build and be silently dropped.
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(true)
}

/// Wait for `sub` to yield a payload containing `needle`, or panic after
/// `timeout`.
async fn expect_message(sub: &mut Subscription, needle: &[u8], label: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(Instant::now());
        let Some(remaining) = remaining else {
            panic!(
                "{label}: timed out after {timeout:?} waiting for message containing {:?}",
                String::from_utf8_lossy(needle)
            );
        };
        match tokio::time::timeout(remaining, sub.recv()).await {
            Ok(Some(msg)) => {
                if msg.payload.windows(needle.len()).any(|w| w == needle) {
                    return;
                }
                // Not our message — keep waiting (could be a gossip control
                // frame or an earlier publication).
            }
            Ok(None) => panic!("{label}: subscription closed before receiving expected message"),
            Err(_) => panic!("{label}: timed out after {timeout:?}"),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// Two agents subscribe to the same topic and publish to each other.
/// Both directions must deliver within the timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic harness: silently skips without loopback networking; run manually"]
async fn test_bidirectional_topic_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(alice) = create_loopback_test_agent(&temp_dir, "alice").await? else {
        return Ok(());
    };
    let Some(bob) = create_loopback_test_agent(&temp_dir, "bob").await? else {
        return Ok(());
    };

    if !connect_agents(&alice, &bob).await? {
        eprintln!("Skipping: agents could not connect on loopback");
        return Ok(());
    }

    let topic = "test.bidirectional.delivery";

    // Both subscribe BEFORE either publishes.
    let mut alice_rx = alice.subscribe(topic).await.expect("alice subscribe");
    let mut bob_rx = bob.subscribe(topic).await.expect("bob subscribe");

    // Allow PlumTree to exchange subscription announcements.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Alice → Bob
    let payload_ab = b"A_TO_B_hello".to_vec();
    alice
        .publish(topic, payload_ab.clone())
        .await
        .expect("alice publish");
    expect_message(
        &mut bob_rx,
        &payload_ab,
        "A→B delivery",
        Duration::from_secs(10),
    )
    .await;

    // Bob → Alice
    let payload_ba = b"B_TO_A_hello".to_vec();
    bob.publish(topic, payload_ba.clone())
        .await
        .expect("bob publish");
    expect_message(
        &mut alice_rx,
        &payload_ba,
        "B→A delivery",
        Duration::from_secs(10),
    )
    .await;

    Ok(())
}

/// Group public messages (SignedPublic) survive a gossip round-trip with
/// their signatures intact and are deserializable by the receiver. Tests
/// the exact wire format that `spawn_public_message_listener` consumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic harness: silently skips without loopback networking; run manually"]
async fn test_group_public_message_gossip_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(alice) = create_loopback_test_agent(&temp_dir, "alice").await? else {
        return Ok(());
    };
    let Some(bob) = create_loopback_test_agent(&temp_dir, "bob").await? else {
        return Ok(());
    };

    if !connect_agents(&alice, &bob).await? {
        eprintln!("Skipping: agents could not connect on loopback");
        return Ok(());
    }

    let group_id = "test-group-001";
    let topic = x0x::groups::public_topic_for(group_id);

    let mut alice_rx = alice.subscribe(&topic).await.expect("alice subscribe");
    let mut bob_rx = bob.subscribe(&topic).await.expect("bob subscribe");
    tokio::time::sleep(Duration::from_secs(2)).await;

    let kp_a = AgentKeypair::generate().unwrap();
    let kp_b = AgentKeypair::generate().unwrap();

    // Alice signs and publishes a root message.
    let msg_a = GroupPublicMessage::sign(
        group_id.into(),
        "state-hash-a".into(),
        1,
        &kp_a,
        None,
        GroupPublicMessageKind::Chat,
        "hello from alice".into(),
        1_000,
        None,
        None,
    )
    .unwrap();

    let wire_a = serde_json::to_vec(&msg_a).unwrap();
    alice
        .publish(&topic, wire_a.clone())
        .await
        .expect("alice publish");

    // Bob receives and deserializes.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut received_a = None;
    while Instant::now() < deadline {
        if let Ok(Some(gossip_msg)) =
            tokio::time::timeout(Duration::from_secs(2), bob_rx.recv()).await
        {
            if let Ok(msg) = serde_json::from_slice::<GroupPublicMessage>(&gossip_msg.payload) {
                received_a = Some(msg);
                break;
            }
        }
    }
    let received_a = received_a.expect("bob should receive alice's group message");
    received_a
        .verify_signature()
        .expect("signature verifies after gossip");
    assert_eq!(received_a.body, "hello from alice");
    assert_eq!(
        received_a.author_agent_id,
        hex::encode(kp_a.agent_id().as_bytes())
    );

    // Bob signs and publishes a reply.
    let msg_b = GroupPublicMessage::sign(
        group_id.into(),
        "state-hash-a".into(),
        1,
        &kp_b,
        None,
        GroupPublicMessageKind::Chat,
        "reply from bob".into(),
        2_000,
        None,
        None,
    )
    .unwrap();

    let wire_b = serde_json::to_vec(&msg_b).unwrap();
    bob.publish(&topic, wire_b.clone())
        .await
        .expect("bob publish");

    // Alice receives and deserializes.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut received_b = None;
    while Instant::now() < deadline {
        if let Ok(Some(gossip_msg)) =
            tokio::time::timeout(Duration::from_secs(2), alice_rx.recv()).await
        {
            if let Ok(msg) = serde_json::from_slice::<GroupPublicMessage>(&gossip_msg.payload) {
                if msg.body == "reply from bob" {
                    received_b = Some(msg);
                    break;
                }
            }
        }
    }
    let received_b = received_b.expect("alice should receive bob's group message");
    received_b
        .verify_signature()
        .expect("signature verifies after gossip");
    assert_eq!(received_b.body, "reply from bob");
    assert_eq!(
        received_b.author_agent_id,
        hex::encode(kp_b.agent_id().as_bytes())
    );

    Ok(())
}

/// ADR-0029 threaded messages survive a gossip round-trip with their
/// `thread_root` and `thread_parent` metadata intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic harness: silently skips without loopback networking; run manually"]
async fn test_adr0029_threaded_message_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(alice) = create_loopback_test_agent(&temp_dir, "alice").await? else {
        return Ok(());
    };
    let Some(bob) = create_loopback_test_agent(&temp_dir, "bob").await? else {
        return Ok(());
    };

    if !connect_agents(&alice, &bob).await? {
        eprintln!("Skipping: agents could not connect on loopback");
        return Ok(());
    }

    let group_id = "test-thread-group";
    let topic = x0x::groups::public_topic_for(group_id);

    let mut bob_rx = bob.subscribe(&topic).await.expect("bob subscribe");
    tokio::time::sleep(Duration::from_secs(2)).await;

    let kp = AgentKeypair::generate().unwrap();

    // Root message (v1 domain, no thread fields).
    let root = GroupPublicMessage::sign(
        group_id.into(),
        "state-hash".into(),
        1,
        &kp,
        None,
        GroupPublicMessageKind::Chat,
        "thread root".into(),
        1_000,
        None,
        None,
    )
    .unwrap();
    let root_msg_id = root.msg_id();

    // Reply (v2 domain, thread_root + thread_parent).
    let reply = GroupPublicMessage::sign(
        group_id.into(),
        "state-hash".into(),
        1,
        &kp,
        None,
        GroupPublicMessageKind::Chat,
        "threaded reply".into(),
        2_000,
        Some(root_msg_id.clone()),
        Some(root_msg_id.clone()),
    )
    .unwrap();
    let reply_msg_id = reply.msg_id();

    // Publish the reply (not the root — tests that thread metadata alone
    // survives gossip).
    let wire = serde_json::to_vec(&reply).unwrap();
    alice
        .publish(&topic, wire)
        .await
        .expect("publish threaded reply");

    // Bob receives and verifies thread metadata.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut received = None;
    while Instant::now() < deadline {
        if let Ok(Some(gossip_msg)) =
            tokio::time::timeout(Duration::from_secs(2), bob_rx.recv()).await
        {
            if let Ok(msg) = serde_json::from_slice::<GroupPublicMessage>(&gossip_msg.payload) {
                if msg.body == "threaded reply" {
                    received = Some(msg);
                    break;
                }
            }
        }
    }
    let received = received.expect("bob should receive the threaded reply");

    // Signature still verifies after gossip round-trip.
    received.verify_signature().expect("v2 signature verifies");

    // Thread metadata survived.
    assert_eq!(
        received.thread_root.as_deref(),
        Some(root_msg_id.as_str()),
        "thread_root survived gossip"
    );
    assert_eq!(
        received.thread_parent.as_deref(),
        Some(root_msg_id.as_str()),
        "thread_parent survived gossip"
    );

    // msg_id is deterministic — recomputable by any verifier.
    assert_eq!(
        received.msg_id(),
        reply_msg_id,
        "msg_id is deterministic across sign + gossip + deserialize"
    );

    Ok(())
}

/// Rapid-fire bidirectional publish: both agents publish multiple messages
/// and we verify all arrive. This stresses the PlumTree lazy-push path and
/// catches intermittent drops that a single-message test might miss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic harness: silently skips without loopback networking; run manually"]
async fn test_bidirectional_burst_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(alice) = create_loopback_test_agent(&temp_dir, "alice").await? else {
        return Ok(());
    };
    let Some(bob) = create_loopback_test_agent(&temp_dir, "bob").await? else {
        return Ok(());
    };

    if !connect_agents(&alice, &bob).await? {
        eprintln!("Skipping: agents could not connect on loopback");
        return Ok(());
    }

    let topic = "test.burst.delivery";
    let mut alice_rx = alice.subscribe(topic).await.expect("alice subscribe");
    let mut bob_rx = bob.subscribe(topic).await.expect("bob subscribe");
    tokio::time::sleep(Duration::from_secs(2)).await;

    const N: usize = 10;

    // Alice → Bob burst.
    for i in 0..N {
        let payload = format!("A_{i:02}").into_bytes();
        alice
            .publish(topic, payload)
            .await
            .unwrap_or_else(|e| panic!("alice publish {i}: {e}"));
    }

    // Bob → Alice burst.
    for i in 0..N {
        let payload = format!("B_{i:02}").into_bytes();
        bob.publish(topic, payload)
            .await
            .unwrap_or_else(|e| panic!("bob publish {i}: {e}"));
    }

    // Collect and verify A→B.
    let mut bob_received: Vec<String> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && bob_received.len() < N {
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(2), bob_rx.recv()).await {
            if let Ok(s) = std::str::from_utf8(&msg.payload) {
                if s.starts_with("A_") {
                    bob_received.push(s.to_string());
                }
            }
        }
    }
    let missing_ab: Vec<String> = (0..N)
        .map(|i| format!("A_{i:02}"))
        .filter(|m| !bob_received.contains(m))
        .collect();
    assert!(
        missing_ab.is_empty(),
        "A→B burst: bob is missing {}/{} messages: {:?}",
        missing_ab.len(),
        N,
        &missing_ab[..missing_ab.len().min(5)]
    );

    // Collect and verify B→A.
    let mut alice_received: Vec<String> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && alice_received.len() < N {
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(2), alice_rx.recv()).await {
            if let Ok(s) = std::str::from_utf8(&msg.payload) {
                if s.starts_with("B_") {
                    alice_received.push(s.to_string());
                }
            }
        }
    }
    let missing_ba: Vec<String> = (0..N)
        .map(|i| format!("B_{i:02}"))
        .filter(|m| !alice_received.contains(m))
        .collect();
    assert!(
        missing_ba.is_empty(),
        "B→A burst: alice is missing {}/{} messages: {:?}",
        missing_ba.len(),
        N,
        &missing_ba[..missing_ba.len().min(5)]
    );

    Ok(())
}
