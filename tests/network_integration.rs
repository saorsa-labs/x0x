//! Integration tests for x0x agent network lifecycle.
//!
//! These tests verify the complete workflow of creating agents,
//! configuring network settings, and participating in the gossip network.

use tempfile::TempDir;
use x0x::{network, Agent};

/// Test agent creation with default network configuration.
#[tokio::test]
async fn test_agent_creation() {
    let agent = Agent::new().await;
    assert!(agent.is_ok());
    
    let agent = agent.unwrap();
    assert!(agent.identity().machine_id().as_bytes() != &[0u8; 32]);
    assert!(agent.identity().agent_id().as_bytes() != &[0u8; 32]);
}

/// Test agent creation with custom network configuration.
#[tokio::test]
async fn test_agent_with_network_config() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    let builder = Agent::builder();
    let builder = builder.with_machine_key(temp_dir.path().join("machine.key"));
    let builder = builder.with_network_config(network::NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: vec!["127.0.0.1:12000".parse().unwrap()],
        ..Default::default()
    });
    
    let agent = builder.build().await.expect("Failed to build agent");
    assert!(agent.network().is_some());
}

/// Test agent joining network with configuration.
#[tokio::test]
async fn test_agent_join_network() {
    let agent = Agent::new().await.expect("Failed to create agent");
    
    let result = agent.join_network().await;
    assert!(result.is_ok());
}

/// Test agent subscribe functionality.
#[tokio::test]
async fn test_agent_subscribe() {
    let agent = Agent::new().await.expect("Failed to create agent");
    
    let result = agent.subscribe("test-topic").await;
    assert!(result.is_ok());
    
    let mut subscription = result.unwrap();
    // No messages yet, so recv should return None
    assert!(subscription.recv().await.is_none());
}

/// Test agent publish functionality.
#[tokio::test]
async fn test_agent_publish() {
    let agent = Agent::new().await.expect("Failed to create agent");
    
    let result = agent.publish("test-topic", b"hello world".to_vec()).await;
    assert!(result.is_ok());
}

/// Test agent identity stability across operations.
#[tokio::test]
async fn test_identity_stability() {
    let agent = Agent::new().await.expect("Failed to create agent");
    
    let machine_id = agent.machine_id();
    let agent_id = agent.agent_id();
    
    // Perform network operations
    let _ = agent.join_network().await;
    let _ = agent.subscribe("test-topic").await;
    let _ = agent.publish("test-topic", vec![]).await;
    
    // Verify IDs are stable
    assert_eq!(agent.machine_id(), machine_id);
    assert_eq!(agent.agent_id(), agent_id);
}

/// Test agent builder with custom machine key path.
#[tokio::test]
async fn test_builder_custom_machine_key() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_path = temp_dir.path().join("custom_machine.key");
    
    // Create first agent with custom key
    let agent1 = Agent::builder()
        .with_machine_key(&key_path)
        .build()
        .await
        .expect("Failed to create agent1");
    
    let machine_id1 = agent1.machine_id();
    
    // Create second agent with same key - should reuse
    let agent2 = Agent::builder()
        .with_machine_key(&key_path)
        .build()
        .await
        .expect("Failed to create agent2");
    
    let machine_id2 = agent2.machine_id();
    
    // Machine IDs should be the same (same machine key)
    assert_eq!(machine_id1, machine_id2);
    
    // Agent IDs should be different (different agent keys)
    assert_ne!(agent1.agent_id(), agent2.agent_id());
}

/// Test message format and structure.
#[tokio::test]
async fn test_message_format() {
    use x0x::Message;
    
    let msg = Message {
        origin: "test-agent".to_string(),
        payload: b"test payload".to_vec(),
        topic: "test-topic".to_string(),
    };
    
    assert_eq!(msg.origin, "test-agent");
    assert_eq!(msg.payload, b"test payload");
    assert_eq!(msg.topic, "test-topic");
}
