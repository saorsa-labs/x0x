//! Gossip runtime orchestration.

use super::config::GossipConfig;

/// The gossip runtime that manages all gossip components.
///
/// This orchestrates HyParView membership, Plumtree pub/sub, presence beacons,
/// FOAF discovery, rendezvous sharding, coordinator advertisements, and
/// anti-entropy reconciliation.
#[derive(Debug)]
pub struct GossipRuntime {
    #[allow(dead_code)]
    config: GossipConfig,
}

impl GossipRuntime {
    /// Create a new gossip runtime with the given configuration.
    ///
    /// This initializes the runtime but does not start it. Call `start()`
    /// to begin gossip protocol operations.
    ///
    /// # Arguments
    ///
    /// * `config` - The gossip configuration
    ///
    /// # Returns
    ///
    /// A new `GossipRuntime` instance
    #[must_use]
    pub fn new(config: GossipConfig) -> Self {
        Self { config }
    }
}
