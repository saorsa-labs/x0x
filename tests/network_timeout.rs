//! Network timeout behavior tests

use saorsa_gossip_transport::GossipTransport;
use std::time::Duration;
use x0x::network::{NetworkConfig, NetworkNode};

#[tokio::test]
async fn test_receive_message_blocks_until_message() {
    // Create a network node
    let network = NetworkNode::new(NetworkConfig::default())
        .await
        .expect("Failed to create network node");

    // Verify receive_message() correctly blocks when no messages available
    let result = tokio::time::timeout(Duration::from_millis(100), network.receive_message()).await;

    // Should timeout since no peers are connected and no messages sent
    assert!(
        result.is_err(),
        "receive_message() should timeout when no messages available"
    );
}

#[tokio::test]
async fn test_receive_message_with_timeout_context() {
    // This test verifies that receive_message() doesn't panic or leak resources
    // when timing out
    let network = NetworkNode::new(NetworkConfig::default())
        .await
        .expect("Failed to create network node");

    // Multiple timeout attempts should be safe
    for _ in 0..3 {
        let result: Result<_, tokio::time::error::Elapsed> =
            tokio::time::timeout(Duration::from_millis(50), network.receive_message()).await;
        assert!(result.is_err());
    }

    // Network should still be functional
    assert!(network.peer_id().0.len() == 32);
}
