//! Rendezvous sharding for global agent findability.

use crate::error::NetworkResult;
use crate::identity::AgentId;
use std::net::SocketAddr;

/// Rendezvous manager with content-addressed sharding.
///
/// 65,536 shards provide global agent lookup. Shard ID is computed as:
/// BLAKE3("saorsa-rendezvous" || agent_id) & 0xFFFF
#[derive(Debug)]
pub struct RendezvousManager;

impl RendezvousManager {
    /// Create a new rendezvous manager.
    pub fn new() -> Self {
        Self
    }

    /// Compute shard ID for an agent.
    pub fn shard_id(agent_id: &AgentId) -> u16 {
        let mut data = Vec::new();
        data.extend_from_slice(b"saorsa-rendezvous");
        data.extend_from_slice(agent_id.as_bytes());
        let hash = blake3::hash(&data);
        u16::from_le_bytes([hash.as_bytes()[0], hash.as_bytes()[1]])
    }

    /// Register agent addresses in rendezvous.
    pub async fn register(&self, _agent_id: AgentId, _addrs: Vec<SocketAddr>) -> NetworkResult<()> {
        // TODO: Integrate saorsa-gossip-rendezvous
        Ok(())
    }

    /// Lookup agent addresses.
    pub async fn lookup(&self, _agent_id: AgentId) -> NetworkResult<Option<Vec<SocketAddr>>> {
        // TODO: Query rendezvous shard
        Ok(None)
    }

    /// Unregister agent.
    pub async fn unregister(&self, _agent_id: AgentId) -> NetworkResult<()> {
        // TODO: Remove from rendezvous
        Ok(())
    }
}

impl Default for RendezvousManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_id_consistency() {
        let agent_id = AgentId([42u8; 32]);
        let shard1 = RendezvousManager::shard_id(&agent_id);
        let shard2 = RendezvousManager::shard_id(&agent_id);
        assert_eq!(shard1, shard2);
    }

    #[test]
    fn test_shard_id_distribution() {
        let mut shards = std::collections::HashSet::new();
        for i in 0..100 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            let agent_id = AgentId(bytes);
            shards.insert(RendezvousManager::shard_id(&agent_id));
        }
        assert!(shards.len() > 50, "Shards should be well-distributed");
    }
}
