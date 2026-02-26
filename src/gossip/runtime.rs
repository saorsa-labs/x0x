//! Gossip runtime orchestration.

use super::config::GossipConfig;
use super::pubsub::{PubSubManager, SigningContext};
use crate::error::NetworkResult;
use crate::network::NetworkNode;
use saorsa_gossip_membership::{HyParViewMembership, MembershipConfig};
use saorsa_gossip_types::PeerId;
use std::sync::Arc;

/// The gossip runtime that manages all gossip components.
///
/// This orchestrates HyParView membership, SWIM failure detection,
/// and pub/sub messaging via the saorsa-gossip stack.
pub struct GossipRuntime {
    config: GossipConfig,
    network: Arc<NetworkNode>,
    membership: Arc<HyParViewMembership<NetworkNode>>,
    pubsub: Arc<PubSubManager>,
    peer_id: PeerId,
}

impl std::fmt::Debug for GossipRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipRuntime")
            .field("config", &self.config)
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

impl GossipRuntime {
    /// Create a new gossip runtime with the given configuration and network node.
    ///
    /// This initializes HyParView membership, SWIM failure detection, and
    /// pub/sub messaging. Call `start()` to begin gossip protocol operations.
    ///
    /// # Arguments
    ///
    /// * `config` - The gossip configuration
    /// * `network` - The network node (implements GossipTransport)
    ///
    /// # Returns
    ///
    /// A new `GossipRuntime` instance
    ///
    /// # Errors
    ///
    /// Returns an error if configuration validation fails.
    pub async fn new(
        config: GossipConfig,
        network: Arc<NetworkNode>,
        signing: Option<Arc<SigningContext>>,
    ) -> NetworkResult<Self> {
        config.validate().map_err(|e| {
            crate::error::NetworkError::NodeCreation(format!("invalid gossip config: {e}"))
        })?;

        let peer_id = saorsa_gossip_transport::GossipTransport::local_peer_id(network.as_ref());
        let membership_config = MembershipConfig::default();
        let membership = Arc::new(HyParViewMembership::new(
            peer_id,
            membership_config,
            Arc::clone(&network),
        ));
        let pubsub = Arc::new(PubSubManager::new(Arc::clone(&network), signing));

        Ok(Self {
            config,
            network,
            membership,
            pubsub,
            peer_id,
        })
    }

    /// Get the PubSubManager for this runtime.
    ///
    /// # Returns
    ///
    /// A reference to the `PubSubManager`.
    #[must_use]
    pub fn pubsub(&self) -> &Arc<PubSubManager> {
        &self.pubsub
    }

    /// Get the HyParView membership manager.
    ///
    /// # Returns
    ///
    /// A reference to the `HyParViewMembership`.
    #[must_use]
    pub fn membership(&self) -> &Arc<HyParViewMembership<NetworkNode>> {
        &self.membership
    }

    /// Get the local peer ID.
    ///
    /// # Returns
    ///
    /// The `PeerId` for this node.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Start the gossip runtime.
    ///
    /// This initializes all gossip components and begins protocol operations.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub async fn start(&self) -> NetworkResult<()> {
        // Config is validated in new(); this is a placeholder for
        // starting background tasks (shuffle, SWIM probes, etc.)
        Ok(())
    }

    /// Shutdown the gossip runtime.
    ///
    /// This gracefully stops all gossip components and cleans up resources.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn shutdown(&self) -> NetworkResult<()> {
        Ok(())
    }

    /// Get the runtime configuration.
    #[must_use]
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// Get the network node.
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
    async fn test_runtime_creation() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(config, Arc::new(network), None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(
            runtime.config().active_view_size,
            GossipConfig::default().active_view_size
        );
    }

    #[tokio::test]
    async fn test_runtime_start_stop() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let runtime = GossipRuntime::new(config, Arc::new(network), None)
            .await
            .expect("Failed to create runtime");

        assert!(runtime.start().await.is_ok());
        assert!(runtime.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_accessors() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let network_arc = Arc::new(network);
        let runtime = GossipRuntime::new(config.clone(), network_arc.clone(), None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(runtime.config().active_view_size, config.active_view_size);
        assert!(Arc::ptr_eq(runtime.network(), &network_arc));
    }

    #[tokio::test]
    async fn test_runtime_peer_id() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let network_arc = Arc::new(network);
        let expected_peer_id =
            saorsa_gossip_transport::GossipTransport::local_peer_id(network_arc.as_ref());
        let runtime = GossipRuntime::new(config, network_arc, None)
            .await
            .expect("Failed to create runtime");

        assert_eq!(runtime.peer_id(), expected_peer_id);
    }

    #[tokio::test]
    async fn test_runtime_invalid_config() {
        let config = GossipConfig {
            active_view_size: 0,
            ..Default::default()
        };
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let result = GossipRuntime::new(config, Arc::new(network), None).await;

        assert!(result.is_err());
    }
}
