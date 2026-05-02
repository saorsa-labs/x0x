//! Configuration for the gossip overlay network.

use serde::{Deserialize, Serialize};

/// Configuration for the gossip overlay network.
///
/// These parameters control the HyParView membership protocol behavior and
/// x0x's receive-side dispatch pipeline.
///
/// All fields are individually `#[serde(default)]` so an operator can write a
/// partial `[gossip]` section in TOML (for example only `dispatch_workers = 4`)
/// without having to repeat every other tunable. Any unspecified field falls
/// back to the value from `GossipConfig::default()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Size of active view (peers we actively gossip with).
    /// Default: 6
    #[serde(default = "default_active_view_size")]
    pub active_view_size: usize,

    /// Size of passive view (backup peers for failure recovery).
    /// Default: 30
    #[serde(default = "default_passive_view_size")]
    pub passive_view_size: usize,

    /// Active Random Walk Length - hops for FORWARD_JOIN in active view.
    /// Default: 6
    #[serde(default = "default_arwl")]
    pub arwl: usize,

    /// Passive Random Walk Length - hops for FORWARD_JOIN in passive view.
    /// Default: 3
    #[serde(default = "default_prwl")]
    pub prwl: usize,

    /// Number of concurrent PubSub decode/verify/fanout workers draining the
    /// inbound PubSub queue. Default stays 1 for one release cycle so rollback
    /// is a config-only change; operators can raise it to 2–8 for X0X-0005
    /// soak validation.
    #[serde(default = "default_dispatch_workers")]
    pub dispatch_workers: usize,
}

const MAX_DISPATCH_WORKERS: usize = 8;

const fn default_active_view_size() -> usize {
    6
}

const fn default_passive_view_size() -> usize {
    30
}

const fn default_arwl() -> usize {
    6
}

const fn default_prwl() -> usize {
    3
}

const fn default_dispatch_workers() -> usize {
    1
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            active_view_size: 6,
            passive_view_size: 30,
            arwl: 6,
            prwl: 3,
            dispatch_workers: default_dispatch_workers(),
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
        if self.dispatch_workers == 0 {
            return Err("dispatch_workers must be > 0".to_string());
        }
        if self.dispatch_workers > MAX_DISPATCH_WORKERS {
            return Err(format!(
                "dispatch_workers must be <= {MAX_DISPATCH_WORKERS}"
            ));
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
        assert_eq!(config.dispatch_workers, 1);
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

        let invalid = GossipConfig {
            dispatch_workers: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = GossipConfig {
            dispatch_workers: MAX_DISPATCH_WORKERS + 1,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn partial_toml_section_falls_back_to_defaults() {
        // Operators must be able to override a single field without repeating
        // the rest of the struct. This guards against the regression that
        // shipped briefly during the X0X-0005 soak rollout where missing
        // `active_view_size` in a partial `[gossip]` section caused x0xd to
        // restart-loop on every node.
        let cfg: GossipConfig = toml::from_str("dispatch_workers = 4").expect("partial TOML");
        let defaults = GossipConfig::default();
        assert_eq!(cfg.dispatch_workers, 4);
        assert_eq!(cfg.active_view_size, defaults.active_view_size);
        assert_eq!(cfg.passive_view_size, defaults.passive_view_size);
        assert_eq!(cfg.arwl, defaults.arwl);
        assert_eq!(cfg.prwl, defaults.prwl);
    }

    #[test]
    fn empty_toml_section_yields_full_defaults() {
        let cfg: GossipConfig = toml::from_str("").expect("empty TOML");
        let defaults = GossipConfig::default();
        assert_eq!(cfg.active_view_size, defaults.active_view_size);
        assert_eq!(cfg.passive_view_size, defaults.passive_view_size);
        assert_eq!(cfg.arwl, defaults.arwl);
        assert_eq!(cfg.prwl, defaults.prwl);
        assert_eq!(cfg.dispatch_workers, defaults.dispatch_workers);
    }
}
