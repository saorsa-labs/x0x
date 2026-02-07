//! Configuration for the gossip overlay network.

use serde::{Deserialize, Serialize};

/// Configuration for the gossip overlay network.
///
/// These parameters control the HyParView membership protocol behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Size of active view (peers we actively gossip with).
    /// Default: 6
    pub active_view_size: usize,

    /// Size of passive view (backup peers for failure recovery).
    /// Default: 30
    pub passive_view_size: usize,

    /// Active Random Walk Length - hops for FORWARD_JOIN in active view.
    /// Default: 6
    pub arwl: usize,

    /// Passive Random Walk Length - hops for FORWARD_JOIN in passive view.
    /// Default: 3
    pub prwl: usize,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            active_view_size: 6,
            passive_view_size: 30,
            arwl: 6,
            prwl: 3,
        }
    }
}

impl GossipConfig {
    /// Validate configuration parameters.
    pub fn validate(&self) -> Result<(), String> {
        if self.active_view_size == 0 {
            return Err("active_view_size must be > 0".to_string());
        }
        if self.passive_view_size == 0 {
            return Err("passive_view_size must be > 0".to_string());
        }
        if self.arwl == 0 {
            return Err("arwl must be > 0".to_string());
        }
        if self.prwl == 0 {
            return Err("prwl must be > 0".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GossipConfig::default();
        assert_eq!(config.active_view_size, 6);
        assert_eq!(config.passive_view_size, 30);
        assert_eq!(config.arwl, 6);
        assert_eq!(config.prwl, 3);
    }

    #[test]
    fn test_config_validation() {
        let valid = GossipConfig::default();
        assert!(valid.validate().is_ok());

        let invalid = GossipConfig {
            active_view_size: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }
}
