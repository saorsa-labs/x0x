//! Configuration for the gossip overlay network.

use super::participation::ParticipationMode;
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
    /// is a config-only change; the adaptive supervisor may temporarily raise
    /// the active worker target up to 32 during overload or restart bursts.
    #[serde(default = "default_dispatch_workers")]
    pub dispatch_workers: usize,

    /// Operator opt-in to Full (pass-through relay) participation.
    ///
    /// TOML: `gossip.relay = true`. The `--relay` CLI flag sets the same
    /// intent. Seed / dual-listen / managed-binary detection still
    /// fail-closes to Full when this is false (issue #380).
    #[serde(default)]
    pub relay: bool,

    /// Process-resolved participation mode. Not a TOML key — the daemon
    /// writes this after [`super::resolve_participation`].
    #[serde(skip)]
    pub participation: ParticipationMode,

    /// Why [`Self::participation`] was selected (`dual_listen`, `seed_addr`,
    /// `managed_binary`, `operator_relay`, `default_leaf`).
    #[serde(skip)]
    pub participation_reason: String,
}

const MAX_DISPATCH_WORKERS: usize = 32;

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
            relay: false,
            participation: ParticipationMode::Leaf,
            participation_reason: String::new(),
        }
    }
}

impl GossipConfig {
    /// Effective mode: operator `relay` or a resolved Full both select Full.
    #[must_use]
    pub fn resolved_participation(&self) -> ParticipationMode {
        if self.relay || self.participation.forwards_passthrough() {
            ParticipationMode::Full
        } else {
            ParticipationMode::Leaf
        }
    }

    /// Reason string for diagnostics; defaults when the daemon has not
    /// filled [`Self::participation_reason`].
    #[must_use]
    pub fn resolved_participation_reason(&self) -> &str {
        if !self.participation_reason.is_empty() {
            return self.participation_reason.as_str();
        }
        if self.relay {
            "operator_relay"
        } else if self.participation.forwards_passthrough() {
            "full"
        } else {
            "default_leaf"
        }
    }

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
        assert!(!cfg.relay);
        assert_eq!(cfg.resolved_participation(), ParticipationMode::Leaf);
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
        assert!(!cfg.relay);
        assert_eq!(cfg.resolved_participation(), ParticipationMode::Leaf);
    }

    #[test]
    fn relay_toml_opts_in_to_full() {
        let cfg: GossipConfig = toml::from_str("relay = true").expect("relay TOML");
        assert!(cfg.relay);
        assert_eq!(cfg.resolved_participation(), ParticipationMode::Full);
        assert_eq!(cfg.resolved_participation_reason(), "operator_relay");
    }
    /// ADR-0034: `gossip.relay = true` (TOML) must resolve Full — one operator
    /// concept across CLI/env/TOML; the server startup normalises the env var
    /// so the announcement side (#406) observes the same opt-in.
    #[test]
    fn toml_relay_resolves_full_participation() {
        let mut c = GossipConfig::default();
        assert_eq!(
            c.resolved_participation(),
            super::super::ParticipationMode::Leaf
        );
        c.relay = true;
        assert_eq!(
            c.resolved_participation(),
            super::super::ParticipationMode::Full
        );
        assert_eq!(c.resolved_participation_reason(), "operator_relay");
    }
}
