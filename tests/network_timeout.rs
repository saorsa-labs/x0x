#![allow(clippy::expect_used)]

//! Network timeout behavior tests

use saorsa_gossip_transport::GossipTransport;
use std::time::Duration;
use x0x::network::{NetworkConfig, NetworkNode};

/// Hermetic node config: loopback bind, no bootstrap peers. "No messages
/// arrive" is then load- AND environment-independent — `NetworkConfig::
/// default()` lists the real WAN bootstrap seeds, so a gossip message
/// landing inside the short timeout window completes `receive_message()`
/// and races the timeout assertion (issue #241).
fn isolated_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr")),
        bootstrap_nodes: Vec::new(),
        ..NetworkConfig::default()
    }
}

#[tokio::test]
async fn test_receive_message_blocks_until_message() {
    // Create a network node
    let network = NetworkNode::new(isolated_config(), None, None)
        .await
        .expect("Failed to create network node");

    // Verify receive_message() correctly blocks when no messages available
    let result = tokio::time::timeout(Duration::from_millis(100), network.receive_message()).await;

    // The timeout ERROR CONTEXT is the assertion, not the wall-clock bound:
    // on an isolated node the receive can only end via the caller's
    // deadline (Elapsed) — never via an arriving message or a closed
    // channel — however long a loaded runtime takes to fire the timer.
    let Err(_elapsed) = result else {
        panic!("receive_message() completed on an isolated node; expected Elapsed");
    };
}

#[tokio::test]
async fn test_receive_message_with_timeout_context() {
    // This test verifies that receive_message() doesn't panic or leak resources
    // when timing out
    let network = NetworkNode::new(isolated_config(), None, None)
        .await
        .expect("Failed to create network node");

    // Multiple timeout attempts should be safe. Each must end in the
    // caller's timeout context (Elapsed): on an isolated node no message
    // can arrive, so the outcome no longer depends on when a loaded
    // runtime fires the timer (issue #241).
    for _ in 0..3 {
        let result: Result<_, tokio::time::error::Elapsed> =
            tokio::time::timeout(Duration::from_millis(50), network.receive_message()).await;
        let Err(_elapsed) = result else {
            panic!("receive_message() completed on an isolated node; expected Elapsed");
        };
    }

    // Network should still be functional
    assert!(network.peer_id().0.len() == 32);
}
