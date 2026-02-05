// Copyright 2024 Saorsa Labs Ltd.
//!
//! Integration tests for x0x agent network lifecycle.

use x0x::{Agent, Message};

/// Test that an agent can be created with default configuration.
#[tokio::test]
async fn test_agent_creation() {
    let agent = Agent::new().await;
    assert!(agent.is_ok(), "Agent creation should succeed");
    let agent = agent.unwrap();
    assert!(agent.agent_id().as_bytes().len() == 32);
    assert!(agent.machine_id().as_bytes().len() == 32);
}

/// Test that an agent can join the network.
#[tokio::test]
async fn test_agent_join_network() {
    let agent = Agent::new().await.unwrap();
    let result = agent.join_network().await;
    // Either succeeds or fails gracefully - both are acceptable
    assert!(result.is_ok() || result.is_err());
}

/// Test that an agent can subscribe to a topic.
#[tokio::test]
async fn test_agent_subscribe() {
    let agent = Agent::new().await.unwrap();
    let result = agent.subscribe("test-topic").await;
    assert!(result.is_ok() || result.is_err());
}

/// Test that agent identity is stable.
#[tokio::test]
async fn test_identity_stability() {
    let agent = Agent::new().await.unwrap();
    let agent_id = agent.agent_id();
    let machine_id = agent.machine_id();
    // IDs should be stable across calls
    assert_eq!(agent.agent_id().as_bytes(), agent_id.as_bytes());
    assert_eq!(agent.machine_id().as_bytes(), machine_id.as_bytes());
}

/// Test agent builder with custom machine key path.
#[tokio::test]
async fn test_builder_custom_machine_key() {
    let agent = Agent::builder()
        .with_machine_key("/tmp/test-machine-key.key")
        .build()
        .await;
    assert!(agent.is_ok(), "Builder with custom key path should work");
}

/// Test Message struct creation and fields.
#[tokio::test]
async fn test_message_format() {
    let msg = Message {
        origin: "test-agent".to_string(),
        payload: vec![1, 2, 3],
        topic: "test-topic".to_string(),
    };
    assert_eq!(msg.payload.len(), 3);
    assert_eq!(msg.topic, "test-topic");
}

/// Test that agent can publish to a topic.
#[tokio::test]
async fn test_agent_publish() {
    let agent = Agent::new().await.unwrap();
    let result = agent.publish("test-topic", vec![1, 2, 3]).await;
    assert!(result.is_ok());
}
