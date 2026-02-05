//! Presence beacons for agent online/offline status.

use super::config::GossipConfig;
use crate::error::NetworkResult;
use crate::identity::AgentId;
use tokio::sync::broadcast;

/// Presence event indicating agent status changes.
#[derive(Debug, Clone)]
pub enum PresenceEvent {
    /// An agent came online.
    AgentOnline(AgentId),
    /// An agent went offline.
    AgentOffline(AgentId),
}

/// Presence manager for broadcasting agent status.
///
/// Agents broadcast encrypted presence beacons at beacon_ttl/2 interval.
/// Beacons expire after beacon_ttl if not refreshed.
#[derive(Debug)]
pub struct PresenceManager {
    #[allow(dead_code)]
    config: GossipConfig,
}

impl PresenceManager {
    /// Create a new presence manager.
    pub fn new(config: GossipConfig) -> Self {
        Self { config }
    }

    /// Broadcast a presence beacon.
    pub async fn broadcast_presence(&self) -> NetworkResult<()> {
        // TODO: Integrate saorsa-gossip-presence
        Ok(())
    }

    /// Get list of online agents.
    pub async fn get_online_agents(&self) -> NetworkResult<Vec<AgentId>> {
        // TODO: Return agents with valid beacons
        Ok(Vec::new())
    }

    /// Subscribe to presence events.
    pub fn subscribe_presence(&self) -> broadcast::Receiver<PresenceEvent> {
        let (tx, rx) = broadcast::channel(256);
        drop(tx);
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_broadcast_presence() {
        let manager = PresenceManager::new(GossipConfig::default());
        assert!(manager.broadcast_presence().await.is_ok());
    }

    #[tokio::test]
    async fn test_get_online_agents() {
        let manager = PresenceManager::new(GossipConfig::default());
        let agents = manager.get_online_agents().await.unwrap();
        assert_eq!(agents.len(), 0);
    }
}
