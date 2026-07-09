//! Integration tests for direct agent-to-agent messaging.
//!
//! Tests the full send_direct/recv_direct flow between agents.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::{Duration, Instant};
use tempfile::TempDir;
use x0x::identity::{AgentId, MachineId};
use x0x::network::NetworkConfig;
use x0x::{Agent, DirectMessage, DiscoveredAgent};

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..NetworkConfig::default()
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

fn discovered_agent(agent: &Agent, addr: std::net::SocketAddr, now_secs: u64) -> DiscoveredAgent {
    DiscoveredAgent {
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: None,
        addresses: vec![addr],
        announced_at: now_secs,
        last_seen: now_secs,
        machine_public_key: vec![],
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    }
}

/// Helper to create a test agent with isolated storage.
async fn create_test_agent(temp_dir: &TempDir, name: &str) -> Agent {
    let machine_key_path = temp_dir.path().join(format!("{name}_machine.key"));
    let agent_key_path = temp_dir.path().join(format!("{name}_agent.key"));
    let contacts_path = temp_dir.path().join(format!("{name}_contacts.json"));
    let cache_dir = temp_dir.path().join(format!("{name}_cache"));

    Agent::builder()
        .with_machine_key(machine_key_path)
        .with_agent_key_path(agent_key_path)
        .with_contact_store_path(contacts_path)
        .with_peer_cache_dir(cache_dir)
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .expect("Failed to create test agent")
}

/// Helper to create a loopback-only test agent with isolated storage.
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
        Err(error) if is_network_bind_permission_error(&error) => Ok(None),
        Err(error) => Err(Box::new(error)),
    }
}

/// Test basic DirectMessage creation and field access.
#[test]
fn test_direct_message_construction() {
    let sender = AgentId([1u8; 32]);
    let machine_id = MachineId([2u8; 32]);
    let payload = b"test payload".to_vec();

    let msg = DirectMessage::new(sender, machine_id, payload.clone());

    assert_eq!(msg.sender, sender);
    assert_eq!(msg.machine_id, machine_id);
    assert_eq!(msg.payload, payload);
    assert_eq!(msg.payload_str(), Some("test payload"));
    assert!(msg.received_at > 0);
}

/// Test that payload_str returns None for binary data.
#[test]
fn test_direct_message_binary_payload() {
    let sender = AgentId([1u8; 32]);
    let machine_id = MachineId([2u8; 32]);
    let payload = vec![0xff, 0xfe, 0x00]; // Invalid UTF-8

    let msg = DirectMessage::new(sender, machine_id, payload);

    assert!(msg.payload_str().is_none());
}

/// Test that the Agent provides direct messaging infrastructure.
#[tokio::test]
async fn test_agent_has_direct_messaging() {
    let temp_dir = TempDir::new().unwrap();
    let agent = create_test_agent(&temp_dir, "agent").await;

    // The agent should have direct messaging infrastructure
    let dm = agent.direct_messaging();

    // Initially no agents are connected
    let connected = dm.connected_agents().await;
    assert!(connected.is_empty());
}

/// Test connected_agents returns empty when no connections.
#[tokio::test]
async fn test_connected_agents_empty() {
    let temp_dir = TempDir::new().unwrap();
    let agent = create_test_agent(&temp_dir, "agent").await;

    let connected = agent.connected_agents().await;
    assert!(connected.is_empty());
}

/// Test is_agent_connected returns false for unknown agent.
#[tokio::test]
async fn test_is_agent_connected_unknown() {
    let temp_dir = TempDir::new().unwrap();
    let agent = create_test_agent(&temp_dir, "agent").await;

    let unknown_agent = AgentId([99u8; 32]);
    let connected = agent.is_agent_connected(&unknown_agent).await;
    assert!(!connected);
}

/// Test send_direct fails when agent not in discovery cache.
#[tokio::test]
async fn test_send_direct_agent_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let agent = create_test_agent(&temp_dir, "agent").await;

    let unknown_agent = AgentId([99u8; 32]);
    let result = agent.send_direct(&unknown_agent, b"hello".to_vec()).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, x0x::dm::DmError::RecipientKeyUnavailable(_)),
        "Expected DmError::RecipientKeyUnavailable, got: {:?}",
        err
    );
}

/// Test a successful public send_direct/subscribe_direct flow over loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_send_direct_loopback_delivery_between_agents(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().unwrap();
    let Some(alice) = create_loopback_test_agent(&temp_dir, "alice").await? else {
        return Ok(());
    };
    let Some(bob) = create_loopback_test_agent(&temp_dir, "bob").await? else {
        return Ok(());
    };

    alice.join_network().await?;
    bob.join_network().await?;

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let alice_addr = normalize_loopback(alice_network.bound_addr().await.expect("alice bound"));
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.expect("bob bound"));
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    let connected = alice_network.connect_addr(bob_addr).await?;
    assert_eq!(connected.0, bob.machine_id().0);

    let connected_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < connected_deadline {
        if alice_network.is_connected(&bob_peer).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(alice_network.is_connected(&bob_peer).await);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr, now_secs))
        .await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr, now_secs))
        .await;
    alice
        .direct_messaging()
        .mark_connected(bob.agent_id(), bob.machine_id())
        .await;

    let payload = b"direct-message-success-path".to_vec();
    let mut bob_rx = bob.subscribe_direct();

    let receipt = alice.send_direct(&bob.agent_id(), payload.clone()).await?;
    assert_eq!(receipt.path, x0x::dm::DmPath::RawQuic);

    let received = tokio::time::timeout(Duration::from_secs(2), bob_rx.recv())
        .await
        .expect("bob should receive direct message")
        .expect("bob direct subscription remains open");
    assert_eq!(received.sender, alice.agent_id());
    assert_eq!(received.machine_id, alice.machine_id());
    assert_eq!(received.payload, payload);
    assert_eq!(received.payload_str(), Some("direct-message-success-path"));
    assert!(received.verified);

    Ok(())
}

/// Test the DirectMessageReceiver subscription mechanism.
#[tokio::test]
async fn test_subscribe_direct() {
    let temp_dir = TempDir::new().unwrap();
    let agent = create_test_agent(&temp_dir, "agent").await;

    // Can create multiple subscriptions
    let _rx1 = agent.subscribe_direct();
    let _rx2 = agent.subscribe_direct();

    // Both are valid receivers (cloneable via resubscribe)
}

/// Test DirectMessaging registration and lookup.
#[tokio::test]
async fn test_direct_messaging_registration() {
    let dm = x0x::DirectMessaging::new();

    let agent_id = AgentId([1u8; 32]);
    let machine_id = MachineId([2u8; 32]);

    // Initially not registered
    assert!(dm.lookup_agent(&machine_id).await.is_none());

    // Register
    dm.register_agent(agent_id, machine_id).await;

    // Now can look up
    assert_eq!(dm.lookup_agent(&machine_id).await, Some(agent_id));
}

/// Test DirectMessaging connection state tracking.
#[tokio::test]
async fn test_direct_messaging_connection_state() {
    let dm = x0x::DirectMessaging::new();

    let agent_id = AgentId([1u8; 32]);
    let machine_id = MachineId([2u8; 32]);

    // Not connected initially
    assert!(!dm.is_connected(&agent_id).await);
    assert!(dm.connected_agents().await.is_empty());

    // Mark connected
    dm.mark_connected(agent_id, machine_id).await;

    // Now connected
    assert!(dm.is_connected(&agent_id).await);
    assert_eq!(dm.connected_agents().await, vec![agent_id]);
    assert_eq!(dm.get_machine_id(&agent_id).await, Some(machine_id));

    // Disconnect
    dm.mark_disconnected(&agent_id).await;

    // No longer connected
    assert!(!dm.is_connected(&agent_id).await);
    assert!(dm.connected_agents().await.is_empty());
}

/// Test message encoding/decoding via DirectMessaging.
#[test]
fn test_direct_messaging_encoding() {
    let agent_id = AgentId([42u8; 32]);
    let payload = b"hello world".to_vec();

    // Encode
    let encoded = x0x::DirectMessaging::encode_message(&agent_id, &payload).unwrap();

    // Verify format: [0x10][agent_id: 32][payload]
    assert_eq!(encoded[0], 0x10);
    assert_eq!(encoded.len(), 1 + 32 + payload.len());

    // Decode
    let (decoded_agent, decoded_payload) = x0x::DirectMessaging::decode_message(&encoded).unwrap();

    assert_eq!(decoded_agent, agent_id);
    assert_eq!(decoded_payload, payload);
}

/// Test that encoding fails for payloads exceeding max size.
#[test]
fn test_direct_messaging_max_payload_size() {
    let agent_id = AgentId([1u8; 32]);
    let max_size = x0x::direct::MAX_DIRECT_PAYLOAD_SIZE;

    // Exactly at max should work
    let at_max = vec![0u8; max_size];
    assert!(x0x::DirectMessaging::encode_message(&agent_id, &at_max).is_ok());

    // Over max should fail
    let over_max = vec![0u8; max_size + 1];
    assert!(x0x::DirectMessaging::encode_message(&agent_id, &over_max).is_err());
}

/// Test decoding rejects messages with wrong stream type.
#[test]
fn test_direct_messaging_decode_wrong_type() {
    // Message with gossip stream type (0x00) instead of direct (0x10)
    let mut data = vec![0x00; 50];
    data[0] = 0x00;

    let result = x0x::DirectMessaging::decode_message(&data);
    assert!(result.is_err());
}

/// Test decoding rejects messages that are too short.
#[test]
fn test_direct_messaging_decode_too_short() {
    // Less than 33 bytes (1 type + 32 agent_id)
    let short = vec![0x10; 20];

    let result = x0x::DirectMessaging::decode_message(&short);
    assert!(result.is_err());
}

// Additional behaviors covered by code but not easily unit-testable:
// - recv_direct_annotated() returns all messages with trust annotations
// - Network layer drops oversized direct messages (>16MB + 32 bytes)
// - Sender AgentId is self-asserted (security documentation)
