//! Gossip runtime orchestration.

use super::config::GossipConfig;
use super::pubsub::PubSubManager;
use crate::error::NetworkResult;
use crate::network::NetworkNode;
use std::sync::Arc;

/// The gossip runtime that manages all gossip components.
///
/// This orchestrates pub/sub messaging, and will eventually include
/// HyParView membership, Plumtree pub/sub, presence beacons,
/// FOAF discovery, rendezvous sharding, coordinator advertisements, and
/// anti-entropy reconciliation.
#[derive(Debug)]
pub struct GossipRuntime {
    config: GossipConfig,
    network: Arc<NetworkNode>,
    pubsub: Arc<PubSubManager>,
}

impl GossipRuntime {
    /// Create a new gossip runtime with the given configuration and network node.
    ///
    /// This initializes the runtime but does not start it. Call `start()`
    /// to begin gossip protocol operations.
    ///
    /// # Arguments
    ///
    /// * `config` - The gossip configuration
    /// * `network` - The network node (implements GossipTransport)
    ///
    /// # Returns
    ///
    /// A new `GossipRuntime` instance
    pub fn new(config: GossipConfig, network: Arc<NetworkNode>) -> Self {
        let pubsub = Arc::new(PubSubManager::new(network.clone()));
        Self {
            config,
            network,
            pubsub,
        }
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

    /// Start the gossip runtime.
    ///
    /// This initializes all gossip components and begins protocol operations.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub async fn start(&self) -> NetworkResult<()> {
        // TODO: Phase 1.6 Task 4 will start background message handler
        // For now, this is a placeholder that validates config
        self.config.validate().map_err(|e| {
            crate::error::NetworkError::NodeCreation(format!("invalid gossip config: {}", e))
        })?;

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
        // TODO: Phase 1.6 Tasks 2-12 will implement actual shutdown logic
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
        let runtime = GossipRuntime::new(config, Arc::new(network));

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
        let runtime = GossipRuntime::new(config, Arc::new(network));

        // Start runtime (placeholder - just validates config)
        assert!(runtime.start().await.is_ok());

        // Shutdown runtime (placeholder - no-op)
        assert!(runtime.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_accessors() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let network_arc = Arc::new(network);
        let runtime = GossipRuntime::new(config.clone(), network_arc.clone());

        assert_eq!(runtime.config().active_view_size, config.active_view_size);
        assert!(Arc::ptr_eq(runtime.network(), &network_arc));
    }
}
