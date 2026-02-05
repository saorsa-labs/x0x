//! Gossip runtime orchestration.

use super::config::GossipConfig;
use super::transport::QuicTransportAdapter;
use crate::error::NetworkResult;
use std::sync::Arc;

/// The gossip runtime that manages all gossip components.
///
/// This orchestrates HyParView membership, Plumtree pub/sub, presence beacons,
/// FOAF discovery, rendezvous sharding, coordinator advertisements, and
/// anti-entropy reconciliation.
#[derive(Debug)]
pub struct GossipRuntime {
    config: GossipConfig,
    transport: Arc<QuicTransportAdapter>,
    running: Arc<tokio::sync::RwLock<bool>>,
}

impl GossipRuntime {
    /// Create a new gossip runtime with the given configuration and transport.
    ///
    /// This initializes the runtime but does not start it. Call `start()`
    /// to begin gossip protocol operations.
    ///
    /// # Arguments
    ///
    /// * `config` - The gossip configuration
    /// * `transport` - The QUIC transport adapter
    ///
    /// # Returns
    ///
    /// A new `GossipRuntime` instance
    pub fn new(config: GossipConfig, transport: Arc<QuicTransportAdapter>) -> Self {
        Self {
            config,
            transport,
            running: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }

    /// Start the gossip runtime.
    ///
    /// This initializes all gossip components and begins protocol operations:
    /// - HyParView membership management
    /// - SWIM failure detection
    /// - Plumtree pub/sub
    /// - Presence beacons
    /// - Anti-entropy reconciliation
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime is already running or if initialization fails.
    pub async fn start(&self) -> NetworkResult<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(crate::error::NetworkError::NodeCreation(
                "gossip runtime already running".to_string(),
            ));
        }

        // Mark as running
        *running = true;

        // TODO: Initialize gossip components in subsequent tasks:
        // - Task 6: HyParView membership
        // - Task 7: Plumtree pub/sub
        // - Task 8: Presence beacons
        // - Task 9: FOAF discovery
        // - Task 10: Rendezvous shards
        // - Task 11: Coordinator adverts
        // - Task 12: Anti-entropy

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
        let mut running = self.running.write().await;
        if !*running {
            return Ok(()); // Already stopped, no-op
        }

        // TODO: Shutdown gossip components in reverse order

        // Mark as stopped
        *running = false;

        Ok(())
    }

    /// Check if the runtime is currently running.
    ///
    /// # Returns
    ///
    /// `true` if the runtime is running, `false` otherwise.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get the runtime configuration.
    #[must_use]
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// Get the transport adapter.
    #[must_use]
    pub fn transport(&self) -> &Arc<QuicTransportAdapter> {
        &self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{NetworkConfig, NetworkNode};

    #[tokio::test]
    async fn test_runtime_creation() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let transport = Arc::new(QuicTransportAdapter::new(Arc::new(network)));
        let runtime = GossipRuntime::new(config, transport);

        assert!(!runtime.is_running().await);
    }

    #[tokio::test]
    async fn test_runtime_start_stop() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let transport = Arc::new(QuicTransportAdapter::new(Arc::new(network)));
        let runtime = GossipRuntime::new(config, transport);

        // Start runtime
        assert!(runtime.start().await.is_ok());
        assert!(runtime.is_running().await);

        // Shutdown runtime
        assert!(runtime.shutdown().await.is_ok());
        assert!(!runtime.is_running().await);
    }

    #[tokio::test]
    async fn test_runtime_double_start() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let transport = Arc::new(QuicTransportAdapter::new(Arc::new(network)));
        let runtime = GossipRuntime::new(config, transport);

        // First start should succeed
        assert!(runtime.start().await.is_ok());

        // Second start should fail
        assert!(runtime.start().await.is_err());

        // Cleanup
        runtime.shutdown().await.ok();
    }

    #[tokio::test]
    async fn test_runtime_double_shutdown() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let transport = Arc::new(QuicTransportAdapter::new(Arc::new(network)));
        let runtime = GossipRuntime::new(config, transport);

        runtime.start().await.ok();

        // First shutdown should succeed
        assert!(runtime.shutdown().await.is_ok());

        // Second shutdown should also succeed (idempotent)
        assert!(runtime.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_runtime_accessors() {
        let config = GossipConfig::default();
        let network = NetworkNode::new(NetworkConfig::default())
            .await
            .expect("Failed to create network");
        let transport = Arc::new(QuicTransportAdapter::new(Arc::new(network)));
        let runtime = GossipRuntime::new(config.clone(), transport.clone());

        assert_eq!(runtime.config().active_view_size, config.active_view_size);
        assert!(Arc::ptr_eq(runtime.transport(), &transport));
    }
}

