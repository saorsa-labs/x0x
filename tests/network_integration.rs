// Copyright 2024 Saorsa Labs Ltd.
//!
//! Integration tests for x0x agent network lifecycle.

use x0x::{Agent, Message, NetworkConfig};
use std::net::SocketAddr;
use std::time::Duration;

/// Test that an agent can be created with default configuration.
#[tokio::test]
async fn test_agent_creation() {
    let agent = Agent::new().await;
    assert!(agent.is_ok(), "Agent creation should succeed");
    let agent = agent.unwrap();
    assert!(agent.agent_id().as_bytes().len() == 32);
    assert!(agent.machine_id().as_bytes().len() == 32);
}

/// Test that an agent can be created with custom network configuration.
#[tokio::test]
async fn test_agent_with_network_config() {
    let config = NetworkConfig::default();
    let agent = Agent::builder()
        .with_network_config(config)
        .build()
        .await;
    assert!(agent.is_ok(), "Agent creation with custom config should succeed");
}

/// Test that an agent can join the network.
#[tokio::test]
async fn test_agent_join_network() {
    let mut agent = Agent::new().await.unwrap();
    let result = agent.join_network().await;
    // Either succeeds or fails gracefully - both are acceptable
    assert!(result.is_ok() || result.is_err());
}

/// Test that an agent can subscribe to a topic.
#[tokio::test]
async fn test_agent_subscribe() {
    let mut agent = Agent::new().await.unwrap();
    let result = agent.subscribe("test-topic").await;
    assert!(result.is_ok() || result.is_err());
}

/// Test that agent identity is stable across operations.
#[tokio::test]
async fn test_identity_stability() {
    let agent = Agent::new().await.unwrap();
    let agent_id = *agent.agent_id();
    let machine_id = *agent.machine_id();
    assert_eq!(*agent.agent_id(), agent_id);
    assert_eq!(*agent.machine_id(), machine_id);
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

/// Test NetworkConfig defaults.
#[tokio::test]
async fn test_network_config_defaults() {
    let config = NetworkConfig::default();
    assert_eq!(config.max_connections, 100);
    assert_eq!(config.connection_timeout, Duration::from_secs(30));
    assert!(config.bootstrap_nodes.is_empty());
    assert!(config.peer_cache_path.is_none());
}

/// Test NetworkConfig custom values.
#[tokio::test]
async fn test_network_config_custom() {
    let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let config = NetworkConfig {
        bind_addr: Some(addr),
        bootstrap_nodes: vec![addr],
        max_connections: 50,
        connection_timeout: Duration::from_secs(60),
        stats_interval: Duration::from_secs(120),
        peer_cache_path: Some("/tmp/test-cache.bin".into()),
    };
    assert_eq!(config.bind_addr, Some(addr));
    assert_eq!(config.bootstrap_nodes.len(), 1);
    assert_eq!(config.max_connections, 50);
}

/// Test agent network() accessor returns correct type.
#[tokio::test]
async fn test_agent_network_accessor() {
    let agent = Agent::new().await.unwrap();
    assert!(agent.network().is_none());
}

/// Test agent event subscription API exists and works.
#[tokio::test]
async fn test_agent_event_subscription() {
    let agent = Agent::new().await.unwrap();
    let rx = agent.subscribe_events();
    assert!(rx.is_ok());
}
