//! Gossip runtime orchestration.

use super::config::GossipConfig;
use super::pubsub::{PubSubManager, SigningContext};
use crate::error::NetworkResult;
use crate::network::NetworkNode;
use crate::presence::PresenceWrapper;
use saorsa_gossip_membership::{HyParViewMembership, MembershipConfig};
use saorsa_gossip_transport::GossipStreamType;
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
    presence: std::sync::Mutex<Option<Arc<PresenceWrapper>>>,
    dispatcher_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    peer_sync_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    keepalive_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
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
        let pubsub = Arc::new(PubSubManager::new(Arc::clone(&network), signing)?);

        Ok(Self {
            config,
            network,
            membership,
            pubsub,
            peer_id,
            presence: std::sync::Mutex::new(None),
            dispatcher_handle: std::sync::Mutex::new(None),
            peer_sync_handle: std::sync::Mutex::new(None),
            keepalive_handle: std::sync::Mutex::new(None),
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

    /// Set the presence wrapper for Bulk stream dispatch.
    ///
    /// Must be called before `start()` so that the dispatcher loop can
    /// route `GossipStreamType::Bulk` messages to the presence manager.
    pub fn set_presence(&self, presence: Arc<PresenceWrapper>) {
        if let Ok(mut guard) = self.presence.lock() {
            *guard = Some(presence);
        }
    }

    /// Get the presence wrapper, if configured.
    #[must_use]
    pub fn presence(&self) -> Option<Arc<PresenceWrapper>> {
        self.presence.lock().ok().and_then(|guard| guard.clone())
    }

    /// Start the gossip runtime.
    ///
    /// This initializes all gossip components and begins protocol operations.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub async fn start(&self) -> NetworkResult<()> {
        let network = Arc::clone(&self.network);
        let membership = Arc::clone(&self.membership);
        let pubsub = Arc::clone(&self.pubsub);
        let presence = self.presence();

        let handle = tokio::spawn(async move {
            loop {
                match saorsa_gossip_transport::GossipTransport::receive_message(network.as_ref())
                    .await
                {
                    Ok((peer, stream_type, data)) => match stream_type {
                        GossipStreamType::PubSub => {
                            tracing::info!(
                                from = %peer,
                                bytes = data.len(),
                                "[2/6 runtime] dispatching PubSub message to handle_incoming"
                            );
                            pubsub.handle_incoming(peer, data).await;
                        }
                        GossipStreamType::Membership => {
                            if let Err(e) = membership.dispatch_message(peer, &data).await {
                                tracing::debug!(
                                    "Failed to handle membership message from {peer}: {e}"
                                );
                            }
                        }
                        GossipStreamType::Bulk => {
                            if let Some(ref pm) = presence {
                                match pm.manager().handle_presence_message(&data).await {
                                    Ok(Some(source)) => {
                                        tracing::debug!(
                                            from = %source,
                                            bytes = data.len(),
                                            "Handled presence beacon"
                                        );
                                    }
                                    Ok(None) => {
                                        tracing::trace!(
                                            bytes = data.len(),
                                            "Presence message processed (no source)"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            from = %peer,
                                            "Failed to handle presence message: {e}"
                                        );
                                    }
                                }
                            } else {
                                tracing::trace!("Ignoring Bulk stream (presence not configured)");
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!("Message receive failed: {}", e);
                        break;
                    }
                }
            }
            tracing::info!("Gossip message dispatcher shut down");
        });

        // Periodically refresh PlumTree topic peers with current connections.
        // This ensures newly connected peers (discovered via HyParView or
        // direct connection) are added to the eager set for existing topics.
        // Using 1-second interval to minimize the window where a newly-connected
        // peer could miss a published message (e.g. release manifest broadcast).
        let pubsub_refresh = Arc::clone(&self.pubsub);
        let peer_sync_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                pubsub_refresh.refresh_topic_peers().await;
            }
        });

        if let Ok(mut guard) = self.peer_sync_handle.lock() {
            *guard = Some(peer_sync_handle);
        }

        // Keepalive: send a SWIM Ping to every connected peer every 15 seconds.
        // This prevents QUIC idle timeout (30s) from dropping direct connections
        // that were established via auto-connect. Without this, connections with
        // no application traffic are closed by QUIC after 30s of inactivity.
        // See ADR-0002 for rationale.
        let keepalive_membership = Arc::clone(&self.membership);
        let keepalive_network = Arc::clone(&self.network);
        let keepalive_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;

                let peers = keepalive_network.connected_peers().await;
                for peer in peers {
                    let gossip_peer = PeerId::new(peer.0);
                    if let Err(e) = keepalive_membership.send_ping(gossip_peer).await {
                        tracing::debug!(
                            peer = %gossip_peer,
                            "Keepalive ping failed: {e}"
                        );
                    }
                }
            }
        });

        if let Ok(mut guard) = self.keepalive_handle.lock() {
            *guard = Some(keepalive_handle);
        }

        match self.dispatcher_handle.lock() {
            Ok(mut guard) => *guard = Some(handle),
            Err(_) => {
                return Err(crate::error::NetworkError::NodeCreation(
                    "dispatcher handle lock poisoned".into(),
                ));
            }
        }
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
        if let Ok(mut guard) = self.keepalive_handle.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.peer_sync_handle.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.dispatcher_handle.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
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
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
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
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
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
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
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
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
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
        let network = NetworkNode::new(NetworkConfig::default(), None, None)
            .await
            .expect("Failed to create network");
        let result = GossipRuntime::new(config, Arc::new(network), None).await;

        assert!(result.is_err());
    }
}
