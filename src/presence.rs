//! Presence system integration for x0x.
//!
//! Wraps [`saorsa_gossip_presence::PresenceManager`] to provide presence
//! beacons, FOAF discovery, and online/offline events for the agent network.
//!
//! This module provides:
//! - [`PresenceConfig`](crate::presence::PresenceConfig) — tunable parameters for beacon interval, FOAF TTL, etc.
//! - [`PresenceEvent`](crate::presence::PresenceEvent) — online/offline notifications for discovered agents.
//! - [`PresenceWrapper`](crate::presence::PresenceWrapper) — lifecycle wrapper around the underlying `PresenceManager`.

use std::collections::HashMap;
use std::sync::Arc;

use saorsa_gossip_groups::GroupContext;
use saorsa_gossip_presence::PresenceManager;
use saorsa_gossip_types::{PeerId, TopicId};
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;

use crate::error::NetworkError;
use crate::identity::AgentId;
use crate::network::NetworkNode;

/// Configuration for the presence system.
#[derive(Debug, Clone)]
pub struct PresenceConfig {
    /// Interval in seconds between beacon broadcasts.
    pub beacon_interval_secs: u64,
    /// Default TTL for FOAF discovery queries.
    pub foaf_default_ttl: u8,
    /// Timeout in milliseconds for FOAF queries.
    pub foaf_timeout_ms: u64,
    /// Whether to enable periodic beacon broadcasting.
    pub enable_beacons: bool,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            beacon_interval_secs: 30,
            foaf_default_ttl: 2,
            foaf_timeout_ms: 5000,
            enable_beacons: true,
        }
    }
}

/// Events emitted by the presence system.
#[derive(Debug, Clone)]
pub enum PresenceEvent {
    /// An agent has come online or refreshed its beacon.
    AgentOnline {
        /// The agent that came online.
        agent_id: AgentId,
        /// Network addresses advertised by the agent.
        addresses: Vec<String>,
    },
    /// An agent has gone offline (beacon expired).
    AgentOffline {
        /// The agent that went offline.
        agent_id: AgentId,
    },
}

/// Wrapper around [`PresenceManager`] that manages lifecycle, configuration,
/// and event broadcasting for the x0x agent.
pub struct PresenceWrapper {
    /// The underlying gossip presence manager.
    manager: Arc<PresenceManager>,
    /// Configuration for this presence instance.
    config: PresenceConfig,
    /// Handle to the beacon broadcast task, if running.
    beacon_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    /// Sender for presence events (online/offline notifications).
    event_tx: broadcast::Sender<PresenceEvent>,
}

impl PresenceWrapper {
    /// Create a new presence wrapper.
    ///
    /// Generates a fresh ML-DSA-65 signing keypair for beacon authentication,
    /// creates an empty group context map, and initializes the underlying
    /// `PresenceManager`.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError`] if keypair generation fails.
    pub fn new(
        peer_id: PeerId,
        network: Arc<NetworkNode>,
        config: PresenceConfig,
    ) -> Result<Self, NetworkError> {
        let signing_key = saorsa_gossip_identity::MlDsaKeyPair::generate().map_err(|e| {
            NetworkError::NodeCreation(format!("failed to create presence signing key: {e}"))
        })?;

        let groups: Arc<RwLock<HashMap<TopicId, GroupContext>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let manager = PresenceManager::new_with_identity(
            peer_id,
            network,
            groups,
            None, // four_words populated later from network status
            signing_key,
        );

        let (event_tx, _) = broadcast::channel(256);

        Ok(Self {
            manager: Arc::new(manager),
            config,
            beacon_handle: tokio::sync::Mutex::new(None),
            event_tx,
        })
    }

    /// Returns a reference to the underlying [`PresenceManager`].
    pub fn manager(&self) -> &Arc<PresenceManager> {
        &self.manager
    }

    /// Returns the current presence configuration.
    pub fn config(&self) -> &PresenceConfig {
        &self.config
    }

    /// Subscribe to presence events (agent online/offline).
    ///
    /// Returns a broadcast receiver that yields [`PresenceEvent`] values.
    /// Multiple subscribers can exist simultaneously.
    pub fn subscribe_events(&self) -> broadcast::Receiver<PresenceEvent> {
        self.event_tx.subscribe()
    }

    /// Shut down the presence system.
    ///
    /// Aborts the beacon broadcast task if running. Safe to call multiple times.
    pub async fn shutdown(&self) {
        let mut handle = self.beacon_handle.lock().await;
        if let Some(h) = handle.take() {
            h.abort();
        }
    }
}
