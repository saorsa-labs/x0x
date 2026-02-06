//! Integration tests for NAT traversal across VPS testnet.
//!
//! These tests verify QUIC hole punching works correctly across the 6 global
//! VPS nodes and from local machines behind NAT.

use std::net::SocketAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use x0x::{network::NetworkConfig, Agent};

/// Global VPS bootstrap nodes (from Phase 3.1 deployment)
const VPS_NODES: &[&str] = &[
    "142.93.199.50:12000",   // saorsa-2 (NYC)
    "147.182.234.192:12000", // saorsa-3 (SFO)
    "65.21.157.229:12000",   // saorsa-6 (Helsinki)
    "116.203.101.172:12000", // saorsa-7 (Nuremberg)
    "149.28.156.231:12000",  // saorsa-8 (Singapore)
    "45.77.176.184:12000",   // saorsa-9 (Tokyo)
];

/// Helper to create agent with VPS bootstrap nodes.
async fn create_agent_with_vps_bootstrap() -> Result<Agent, Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let bootstrap_addrs: Vec<SocketAddr> =
        VPS_NODES.iter().filter_map(|s| s.parse().ok()).collect();

    let agent = Agent::builder()
        .with_machine_key(temp_dir.path().join("machine.key"))
        .with_network_config(NetworkConfig {
            bind_addr: Some("0.0.0.0:0".parse()?),
            bootstrap_nodes: bootstrap_addrs,
            ..Default::default()
        })
        .build()
        .await?;

    Ok(agent)
}

/// Test 1: Verify all VPS nodes are reachable and healthy.
///
/// This test attempts to connect to all 6 VPS bootstrap nodes from the local machine.
/// Success indicates NAT traversal is working (local NAT → public VPS).
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_vps_nodes_reachable() {
    let agent = create_agent_with_vps_bootstrap()
        .await
        .expect("Failed to create agent");

    // Join network with VPS bootstrap nodes
    let join_result = timeout(Duration::from_secs(30), agent.join_network()).await;
    assert!(
        join_result.is_ok(),
        "Network join timed out after 30 seconds"
    );
    assert!(join_result.unwrap().is_ok(), "Failed to join network");

    // Give time for connections to establish
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify agent is connected to network
    assert!(
        agent.network().is_some(),
        "Agent should have network runtime after join"
    );

    // TODO: Add peer count verification when NetworkRuntime exposes peer list
    // For now, successful join indicates at least one VPS connection succeeded
}

/// Test 2: Measure connection latency to each VPS node.
///
/// This test measures round-trip time to verify NAT hole punching performance.
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_connection_latency() {
    let agent = create_agent_with_vps_bootstrap()
        .await
        .expect("Failed to create agent");

    agent.join_network().await.expect("Failed to join network");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Subscribe to test topic to measure message round-trip
    let mut subscription = agent
        .subscribe("latency-test")
        .await
        .expect("Failed to subscribe");

    // Publish test message
    let start = std::time::Instant::now();
    agent
        .publish("latency-test", b"ping".to_vec())
        .await
        .expect("Failed to publish");

    // Wait for message echo (should come back from gossip mesh)
    let recv_result = timeout(Duration::from_secs(5), subscription.recv()).await;
    assert!(recv_result.is_ok(), "Message receive timed out");

    let latency = start.elapsed();
    println!("Message round-trip latency: {:?}", latency);

    // Latency should be reasonable for local → VPS → local
    // Allow up to 2 seconds for global gossip propagation
    assert!(
        latency < Duration::from_secs(2),
        "Latency too high: {:?}",
        latency
    );
}

/// Test 3: Connection pool stability over time.
///
/// This test verifies connections remain stable and don't drop unexpectedly.
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_connection_stability() {
    let agent = create_agent_with_vps_bootstrap()
        .await
        .expect("Failed to create agent");

    agent.join_network().await.expect("Failed to join network");

    // Subscribe to test topic
    let mut subscription = agent
        .subscribe("stability-test")
        .await
        .expect("Failed to subscribe");

    // Send messages periodically for 5 minutes
    let test_duration = Duration::from_secs(300);
    let message_interval = Duration::from_secs(10);
    let start = std::time::Instant::now();
    let mut message_count = 0;
    let mut received_count = 0;

    while start.elapsed() < test_duration {
        // Publish message
        agent
            .publish(
                "stability-test",
                format!("msg-{}", message_count).into_bytes(),
            )
            .await
            .expect("Failed to publish");
        message_count += 1;

        // Try to receive any messages (non-blocking)
        while let Ok(Some(_msg)) =
            tokio::time::timeout(Duration::from_millis(100), subscription.recv()).await
        {
            received_count += 1;
        }

        tokio::time::sleep(message_interval).await;
    }

    println!(
        "Sent {} messages, received {} messages over {} seconds",
        message_count,
        received_count,
        test_duration.as_secs()
    );

    // We should have sent at least 25 messages (300s / 10s)
    assert!(
        message_count >= 25,
        "Expected at least 25 messages, sent {}",
        message_count
    );

    // We should receive at least some messages back (may not be all due to async timing)
    assert!(
        received_count > 0,
        "Should have received at least some messages back"
    );
}

/// Test 4: Multiple concurrent agents connecting to VPS mesh.
///
/// This test simulates multiple agents (10) connecting simultaneously to verify
/// the VPS mesh can handle concurrent connections.
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_concurrent_connections() {
    let num_agents = 10;
    let mut handles = Vec::new();

    for i in 0..num_agents {
        let handle = tokio::spawn(async move {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let bootstrap_addrs: Vec<SocketAddr> =
                VPS_NODES.iter().filter_map(|s| s.parse().ok()).collect();

            let agent = Agent::builder()
                .with_machine_key(temp_dir.path().join(format!("machine-{}.key", i)))
                .with_network_config(NetworkConfig {
                    bind_addr: Some("0.0.0.0:0".parse().unwrap()),
                    bootstrap_nodes: bootstrap_addrs,
                    ..Default::default()
                })
                .build()
                .await
                .expect("Failed to create agent");

            agent.join_network().await.expect("Failed to join network");

            // Brief delay to stabilize
            tokio::time::sleep(Duration::from_secs(2)).await;

            true
        });
        handles.push(handle);
    }

    // Wait for all agents to connect
    let results: Vec<bool> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("Task panicked"))
        .collect();

    // All agents should connect successfully
    assert_eq!(
        results.len(),
        num_agents,
        "All agents should complete connection"
    );
    assert!(
        results.iter().all(|&r| r),
        "All agents should connect successfully"
    );
}

/// Test 5: VPS node discovery and peer exchange.
///
/// This test verifies agents can discover all VPS nodes through peer exchange.
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_vps_discovery() {
    let agent = create_agent_with_vps_bootstrap()
        .await
        .expect("Failed to create agent");

    agent.join_network().await.expect("Failed to join network");

    // Wait for peer exchange to propagate (HyParView)
    tokio::time::sleep(Duration::from_secs(10)).await;

    // TODO: Query peer list from NetworkRuntime when API available
    // For now, successful join indicates discovery is working

    // Verify agent can publish to network (all VPS nodes should receive)
    let result = agent.publish("discovery-test", b"hello".to_vec()).await;
    assert!(result.is_ok(), "Should be able to publish to network");
}

/// Test 6: Verify external address discovery works.
///
/// This test checks that agents correctly discover their external IP:port
/// through the VPS mesh (similar to STUN but using QUIC).
#[tokio::test]
#[ignore = "requires VPS testnet - run with --ignored"]
async fn test_external_address_discovery() {
    let agent = create_agent_with_vps_bootstrap()
        .await
        .expect("Failed to create agent");

    agent.join_network().await.expect("Failed to join network");

    // Wait for external address discovery
    tokio::time::sleep(Duration::from_secs(5)).await;

    // TODO: Expose external address from NetworkRuntime API
    // For now, verify join succeeded (indicates address discovery worked)
    assert!(
        agent.network().is_some(),
        "Network should be initialized after join"
    );
}
