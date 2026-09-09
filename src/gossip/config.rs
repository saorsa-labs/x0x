//! Configuration for the gossip overlay network.

use super::participation::ParticipationMode;
use serde::{Deserialize, Serialize};

/// Configuration for the gossip overlay network.
///
/// These parameters control x0x's Leaf egress budget, participation mode and
/// receive-side dispatch pipeline.
///
/// The former HyParView view-size knobs (`active_view_size`,
/// `passive_view_size`, `arwl`, `prwl`) are **deprecated and ignored**: they
/// were validated but never reached
/// `saorsa_gossip_membership::MembershipConfig`, so setting them changed
/// nothing. See `docs/design/504-leaf-egress-budget.md` §2. To bound Leaf
/// gossip egress use [`Self::leaf_max_eager_degree`] instead.
///
/// All fields are individually `#[serde(default)]` so an operator can write a
/// partial `[gossip]` section in TOML (for example only `dispatch_workers = 4`)
/// without having to repeat every other tunable. Any unspecified field falls
/// back to the value from `GossipConfig::default()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Deprecated: `[gossip] active_view_size`. Parsed only so existing
    /// operator TOML keeps loading; the value is ignored.
    #[serde(default, skip_serializing, rename = "active_view_size")]
    pub deprecated_active_view_size: Option<usize>,

    /// Deprecated: `[gossip] passive_view_size`. Ignored, see above.
    #[serde(default, skip_serializing, rename = "passive_view_size")]
    pub deprecated_passive_view_size: Option<usize>,

    /// Deprecated: `[gossip] arwl`. Ignored, see above.
    #[serde(default, skip_serializing, rename = "arwl")]
    pub deprecated_arwl: Option<usize>,

    /// Deprecated: `[gossip] prwl`. Ignored, see above.
    #[serde(default, skip_serializing, rename = "prwl")]
    pub deprecated_prwl: Option<usize>,

    /// Number of concurrent PubSub decode/verify/fanout workers draining the
    /// inbound PubSub queue. Default stays 1 for one release cycle so rollback
    /// is a config-only change; the adaptive supervisor may temporarily raise
    /// the active worker target up to 32 during overload or restart bursts.
    #[serde(default = "default_dispatch_workers")]
    pub dispatch_workers: usize,

    /// Experimental x0x Leaf peer selection limit; 0 retains stock sg policy.
    #[serde(
        default = "default_leaf_max_eager_degree",
        deserialize_with = "deserialize_leaf_degree"
    )]
    pub leaf_max_eager_degree: usize,

    /// Observe-only subscribed-topic outbound threshold. 0 disables it.
    #[serde(default = "default_leaf_egress_soft")]
    pub leaf_egress_soft_bytes_per_sec: u64,

    /// Observe-only hard threshold; slice 1 never sheds bytes.
    #[serde(default = "default_leaf_egress_hard")]
    pub leaf_egress_hard_bytes_per_sec: u64,

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

const fn default_dispatch_workers() -> usize {
    1
}

fn deserialize_leaf_degree<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<usize, D::Error> {
    let value = i64::deserialize(deserializer)?;
    // Preserve out-of-range status until normalization can emit a warning.
    Ok(usize::try_from(value).unwrap_or(13))
}

const fn default_leaf_max_eager_degree() -> usize {
    2
}
const fn default_leaf_egress_soft() -> u64 {
    65_536
}
const fn default_leaf_egress_hard() -> u64 {
    131_072
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            deprecated_active_view_size: None,
            deprecated_passive_view_size: None,
            deprecated_arwl: None,
            deprecated_prwl: None,
            dispatch_workers: default_dispatch_workers(),
            leaf_max_eager_degree: default_leaf_max_eager_degree(),
            leaf_egress_soft_bytes_per_sec: default_leaf_egress_soft(),
            leaf_egress_hard_bytes_per_sec: default_leaf_egress_hard(),
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

    /// Validate the budget separately so budget typos can fall back without
    /// turning an otherwise valid daemon config into a restart loop.
    pub fn validate_egress_budget(&self) -> Result<(), String> {
        if self.leaf_max_eager_degree > 12 {
            return Err("leaf_max_eager_degree must be 0 or 1..=12".into());
        }
        if self.leaf_egress_hard_bytes_per_sec != 0
            && self.leaf_egress_soft_bytes_per_sec > self.leaf_egress_hard_bytes_per_sec
        {
            return Err("leaf egress hard threshold must be >= soft (or 0 to disable)".into());
        }
        Ok(())
    }

    /// Restore only invalid budget settings to defaults; return an operator warning.
    pub fn normalize_egress_budget(&mut self) -> Option<String> {
        let error = self.validate_egress_budget().err()?;
        self.leaf_max_eager_degree = default_leaf_max_eager_degree();
        self.leaf_egress_soft_bytes_per_sec = default_leaf_egress_soft();
        self.leaf_egress_hard_bytes_per_sec = default_leaf_egress_hard();
        Some(format!("{error}; using default Leaf egress budget"))
    }

    /// Operator warnings for deprecated `[gossip]` keys that are still set.
    ///
    /// Why this warns instead of failing: live nodes already carry these keys
    /// in their TOML and must keep starting. They were previously `> 0`
    /// validated, so a stale `active_view_size = 0` could restart-loop a
    /// daemon over a knob that had no effect at all.
    #[must_use]
    pub fn deprecation_warnings(&self) -> Vec<String> {
        [
            ("active_view_size", self.deprecated_active_view_size),
            ("passive_view_size", self.deprecated_passive_view_size),
            ("arwl", self.deprecated_arwl),
            ("prwl", self.deprecated_prwl),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|_| key))
        .map(|key| {
            format!(
                "[gossip] {key} is deprecated and ignored - it never reached HyParView \
                 membership, so it has never changed overlay behaviour. Remove it from your \
                 config. To bound Leaf gossip egress use leaf_max_eager_degree."
            )
        })
        .collect()
    }

    /// Validate configuration parameters.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_egress_budget()?;
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
    fn slice1_budget_defaults_escape_and_invalid_fallback() {
        for degree in [0, 1, 2, 12] {
            let mut config: GossipConfig =
                toml::from_str(&format!("leaf_max_eager_degree = {degree}")).unwrap();
            assert!(config.validate_egress_budget().is_ok());
            assert!(config.normalize_egress_budget().is_none());
            assert_eq!(config.leaf_max_eager_degree, degree);
            assert_eq!(config.leaf_egress_soft_bytes_per_sec, 65536);
        }
        for text in [
            "leaf_max_eager_degree = -1",
            "leaf_max_eager_degree = 13",
            "leaf_egress_soft_bytes_per_sec = 200000",
        ] {
            let mut config: GossipConfig = toml::from_str(text).unwrap();
            config.dispatch_workers = 4;
            assert!(config.validate_egress_budget().is_err());
            assert!(config.normalize_egress_budget().is_some());
            assert!(config.validate().is_ok());
            assert_eq!(config.leaf_max_eager_degree, 2);
            assert_eq!(config.leaf_egress_hard_bytes_per_sec, 131072);
            assert_eq!(config.dispatch_workers, 4);
        }
        let config: GossipConfig = toml::from_str("").unwrap();
        assert_eq!(config.leaf_max_eager_degree, 2);
    }

    #[test]
    fn test_default_config() {
        let config = GossipConfig::default();
        assert_eq!(config.dispatch_workers, 1);
        assert_eq!(config.leaf_max_eager_degree, 2);
    }

    #[test]
    fn test_config_validation() {
        let valid = GossipConfig::default();
        assert!(valid.validate().is_ok());

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
        // shipped briefly during the X0X-0005 soak rollout where a missing
        // field in a partial `[gossip]` section caused x0xd to restart-loop on
        // every node.
        let cfg: GossipConfig = toml::from_str("dispatch_workers = 4").expect("partial TOML");
        let defaults = GossipConfig::default();
        assert_eq!(cfg.dispatch_workers, 4);
        assert_eq!(cfg.leaf_max_eager_degree, defaults.leaf_max_eager_degree);
        assert!(cfg.deprecation_warnings().is_empty());
        assert!(!cfg.relay);
        assert_eq!(cfg.resolved_participation(), ParticipationMode::Leaf);
    }

    #[test]
    fn deprecated_view_knobs_still_parse_and_warn_instead_of_failing() {
        // Why this matters: live nodes have `active_view_size` etc. in their
        // deployed TOML. Removing the knobs must not stop a single daemon from
        // starting, but an operator who believes they are tuning fan-out has
        // to be told the key does nothing (docs/design/504-leaf-egress-budget.md
        // section 2 — the values never reached HyParView membership).
        let cfg: GossipConfig =
            toml::from_str("active_view_size = 4\npassive_view_size = 12\narwl = 2\nprwl = 1\n")
                .expect("deprecated keys must keep parsing");

        assert!(
            cfg.validate().is_ok(),
            "deprecated keys must never fail validation"
        );

        let warnings = cfg.deprecation_warnings();
        assert_eq!(warnings.len(), 4, "every set deprecated key must warn");
        for key in ["active_view_size", "passive_view_size", "arwl", "prwl"] {
            assert!(
                warnings.iter().any(|w| w.contains(key)),
                "missing deprecation warning for {key}"
            );
        }
        assert!(
            warnings.iter().all(|w| w.contains("leaf_max_eager_degree")),
            "warning must point operators at the knob that does bound egress"
        );
    }

    #[test]
    fn deprecated_zero_view_size_no_longer_restart_loops_the_daemon() {
        // Regression guard: `active_view_size = 0` used to fail validate() and
        // therefore crash-loop x0xd, for a knob with zero runtime effect.
        let cfg: GossipConfig =
            toml::from_str("active_view_size = 0").expect("zero must still parse");
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.deprecation_warnings().len(), 1);
    }

    #[test]
    fn deprecated_keys_are_not_written_back_on_serialize() {
        // They are ignored, so echoing them into a rendered config would keep
        // telling operators the knob exists.
        let cfg: GossipConfig = toml::from_str("active_view_size = 4").expect("parses");
        let rendered = toml::to_string(&cfg).expect("serializes");
        assert!(!rendered.contains("active_view_size"));
    }

    #[test]
    fn empty_toml_section_yields_full_defaults() {
        let cfg: GossipConfig = toml::from_str("").expect("empty TOML");
        let defaults = GossipConfig::default();
        assert_eq!(cfg.dispatch_workers, defaults.dispatch_workers);
        assert_eq!(cfg.leaf_max_eager_degree, defaults.leaf_max_eager_degree);
        assert!(cfg.deprecation_warnings().is_empty());
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
