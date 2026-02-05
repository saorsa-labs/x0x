//! Transport adapter for saorsa-gossip using ant-quic.

use crate::error::{NetworkError, NetworkResult};
use crate::network::NetworkNode;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Transport adapter that wraps ant-quic NetworkNode for saorsa-gossip.
///
/// This adapter implements the saorsa-gossip Transport trait, allowing
/// the gossip overlay to use ant-quic as its underlying transport layer.
#[derive(Debug, Clone)]
pub struct QuicTransportAdapter {
    /// The underlying ant-quic network node.
    network: Arc<NetworkNode>,
    /// Event channel for transport events.
    event_tx: broadcast::Sender<TransportEvent>,
}

/// Events from the transport layer.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A peer has connected.
    PeerConnected(SocketAddr),
    /// A peer has disconnected.
    PeerDisconnected(SocketAddr),
    /// Message received from a peer.
    MessageReceived { from: SocketAddr, payload: Bytes },
}

impl QuicTransportAdapter {
    /// Create a new transport adapter wrapping the given network node.
    ///
    /// # Arguments
    ///
    /// * `network` - The ant-quic NetworkNode to wrap
    ///
    /// # Returns
    ///
    /// A new `QuicTransportAdapter` instance
    pub fn new(network: Arc<NetworkNode>) -> Self {
        let (event_tx, _event_rx) = broadcast::channel(1024);
        Self { network, event_tx }
    }

    /// Send a message to a specific peer.
    ///
    /// # Arguments
    ///
    /// * `peer` - The peer's socket address
    /// * `message` - The message bytes to send
    ///
    /// # Errors
    ///
    /// Returns an error if the send fails.
    pub async fn send(&self, peer: SocketAddr, message: Bytes) -> NetworkResult<()> {
        // Placeholder - will integrate with ant-quic Node::send_to
        let _ = (peer, message);
        Ok(())
    }

    /// Broadcast a message to multiple peers.
    ///
    /// # Arguments
    ///
    /// * `peers` - List of peer socket addresses
    /// * `message` - The message bytes to broadcast
    ///
    /// # Errors
    ///
    /// Returns an error if the broadcast fails.
    pub async fn broadcast(&self, peers: Vec<SocketAddr>, message: Bytes) -> NetworkResult<()> {
        // Send to all peers in parallel
        let mut tasks = Vec::new();
        for peer in peers {
            let msg = message.clone();
            let adapter = self.clone();
            tasks.push(tokio::spawn(async move { adapter.send(peer, msg).await }));
        }

        // Wait for all sends to complete
        for task in tasks {
            task.await
                .map_err(|e| NetworkError::ConnectionFailed(format!("broadcast task failed: {}", e)))??;
        }

        Ok(())
    }

    /// Get the local peer address.
    ///
    /// # Returns
    ///
    /// The local socket address this node is bound to.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        // Placeholder - will get from ant-quic Node
        None
    }

    /// Subscribe to transport events.
    ///
    /// # Returns
    ///
    /// A broadcast receiver for transport events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<TransportEvent> {
        self.event_tx.subscribe()
    }

    /// Get a reference to the underlying network node.
    #[must_use]
    pub fn network(&self) -> &Arc<NetworkNode> {
        &self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkConfig;

    #[tokio::test]
    async fn test_transport_adapter_creation() {
        let config = NetworkConfig::default();
        let network = NetworkNode::new(config).await.expect("Failed to create network");
        let adapter = QuicTransportAdapter::new(Arc::new(network));

        // Verify adapter was created
        assert!(adapter.network().config().bind_addr.is_none());
    }

    #[tokio::test]
    async fn test_event_subscription() {
        let config = NetworkConfig::default();
        let network = NetworkNode::new(config).await.expect("Failed to create network");
        let adapter = QuicTransportAdapter::new(Arc::new(network));

        // Subscribe to events
        let mut rx = adapter.subscribe_events();

        // Should not block (no events yet)
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_send_placeholder() {
        let config = NetworkConfig::default();
        let network = NetworkNode::new(config).await.expect("Failed to create network");
        let adapter = QuicTransportAdapter::new(Arc::new(network));

        let peer: SocketAddr = "127.0.0.1:12000".parse().unwrap();
        let message = Bytes::from("test message");

        // Placeholder implementation should succeed
        let result = adapter.send(peer, message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_broadcast_placeholder() {
        let config = NetworkConfig::default();
        let network = NetworkNode::new(config).await.expect("Failed to create network");
        let adapter = QuicTransportAdapter::new(Arc::new(network));

        let peers: Vec<SocketAddr> = vec![
            "127.0.0.1:12000".parse().unwrap(),
            "127.0.0.1:12001".parse().unwrap(),
            "127.0.0.1:12002".parse().unwrap(),
        ];
        let message = Bytes::from("broadcast message");

        // Placeholder implementation should succeed
        let result = adapter.broadcast(peers, message).await;
        assert!(result.is_ok());
    }
}
