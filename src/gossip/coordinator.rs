//! Coordinator advertisements for public bootstrap nodes.

use crate::error::NetworkResult;
use std::net::SocketAddr;

/// Coordinator advertisement.
#[derive(Debug, Clone)]
pub struct CoordinatorAdvert {
    /// Peer addresses.
    pub addrs: Vec<SocketAddr>,
    /// Advertisement timestamp.
    pub timestamp: u64,
}

/// Coordinator manager for public node advertisements.
///
/// Public nodes advertise on "x0x.coordinators" topic with ML-DSA signatures.
/// Advertisements have 24h TTL.
#[derive(Debug)]
pub struct CoordinatorManager;

impl CoordinatorManager {
    /// Create a new coordinator manager.
    pub fn new() -> Self {
        Self
    }

    /// Advertise as a coordinator.
    pub async fn advertise_as_coordinator(&self) -> NetworkResult<()> {
        // TODO: Integrate saorsa-gossip-coordinator
        Ok(())
    }

    /// Get list of active coordinators.
    pub async fn get_coordinators(&self) -> NetworkResult<Vec<CoordinatorAdvert>> {
        // TODO: Return coordinators with valid signatures and TTL
        Ok(Vec::new())
    }
}

impl Default for CoordinatorManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_advertise_as_coordinator() {
        let manager = CoordinatorManager::new();
        assert!(manager.advertise_as_coordinator().await.is_ok());
    }

    #[tokio::test]
    async fn test_get_coordinators() {
        let manager = CoordinatorManager::new();
        let coordinators = manager.get_coordinators().await.unwrap();
        assert_eq!(coordinators.len(), 0);
    }
}
