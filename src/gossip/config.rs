//! Configuration for the gossip overlay network.

use super::participation::ParticipationMode;
use serde::{Deserialize, Serialize};

/// What an exhausted Leaf egress budget is allowed to *do*.
///
/// TOML: `[gossip] byte_policy`. Shedding is opt-in because dropping gossip
/// is a behaviour change that must be attributable to a deliberate operator
/// decision, never to the side effect of setting a non-zero byte rate
/// (#504 slice 2). A non-zero `leaf_egress_hard_bytes_per_sec` is a meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeafBytePolicy {
    /// Account and meter every send, but deny none. The default.
    #[default]
    ObserveOnly,
    /// Shed *forwarded* Normal/Bulk traffic once a Leaf budget is exhausted.
    ///
    /// saorsa-gossip never sheds Critical-class topics (DM inbox, control
    /// plane), locally originated publishes, own-inbox delivery or targeted
    /// sends, whatever this is set to.
    ShedNormal,
}

impl LeafBytePolicy {
    /// The TOML / diagnostics spelling of this policy.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::ShedNormal => "shed_normal",
        }
    }
}

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

    /// Sustained hard threshold. A non-zero value turns the budget on as a
    /// **meter**; it never by itself sheds bytes. See [`Self::byte_policy`].
    #[serde(default = "default_leaf_egress_hard")]
    pub leaf_egress_hard_bytes_per_sec: u64,

    /// Leaf serialized-byte bucket capacity. Must hold one maximum frame,
    /// otherwise saorsa-gossip refuses the budget outright.
    #[serde(default = "default_leaf_egress_burst")]
    pub leaf_egress_burst_bytes: u64,

    /// #504 slice 2: what an exhausted budget is allowed to *do*.
    ///
    /// Opt-in, and only on a Leaf — see [`LeafBytePolicy`].
    #[serde(default)]
    pub byte_policy: LeafBytePolicy,

    /// #674 C3: per-topic budget for *eager* re-forwarding of relayed
    /// messages on topics this node subscribes to. Within budget, verdicts
    /// stay `ForwardAndDeliver` (today's behaviour); beyond it the topic
    /// degrades to `LazyForward` — eager re-publish withheld, msg-ids
    /// announced via IHAVE, peers pull by IWANT — and recovers as the
    /// bucket refills. Topics with **zero local subscribers** are always
    /// `LazyForward` (#674 C2) regardless of this budget. 0 disables the
    /// C3 gate (consumed topics never go lazy); it does not disable C2.
    #[serde(default = "default_relay_fanout_budget_msgs_per_sec")]
    pub relay_fanout_budget_msgs_per_sec: u64,

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
const fn default_leaf_egress_burst() -> u64 {
    4 * 1024 * 1024
}
pub(crate) const fn default_relay_fanout_budget() -> u64 {
    default_relay_fanout_budget_msgs_per_sec()
}
const fn default_relay_fanout_budget_msgs_per_sec() -> u64 {
    50
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
            leaf_egress_burst_bytes: default_leaf_egress_burst(),
            byte_policy: LeafBytePolicy::ObserveOnly,
            relay_fanout_budget_msgs_per_sec: default_relay_fanout_budget_msgs_per_sec(),
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
        // #504 slice 2: saorsa-gossip refuses a budget whose burst cannot hold
        // one maximum frame, and a refused budget means *no* accounting at
        // all. Normalizing here (rather than failing startup) keeps the same
        // promise the other budget typos make: a bad byte knob must never
        // restart-loop a live daemon.
        if self.leaf_egress_hard_bytes_per_sec != 0
            && self.leaf_egress_burst_bytes < super::pubsub::MAX_LEAF_GOSSIP_FRAME_BYTES as u64
        {
            return Err(format!(
                "leaf_egress_burst_bytes must be at least {} bytes (one maximum frame)",
                super::pubsub::MAX_LEAF_GOSSIP_FRAME_BYTES
            ));
        }
        Ok(())
    }

    /// Restore only invalid budget settings to defaults; return an operator warning.
    pub fn normalize_egress_budget(&mut self) -> Option<String> {
        let error = self.validate_egress_budget().err()?;
        self.leaf_max_eager_degree = default_leaf_max_eager_degree();
        self.leaf_egress_soft_bytes_per_sec = default_leaf_egress_soft();
        self.leaf_egress_hard_bytes_per_sec = default_leaf_egress_hard();
        self.leaf_egress_burst_bytes = default_leaf_egress_burst();
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

    /// WHY: #504 slice 2 must not change what an existing operator's TOML
    /// does. Every deployed `[gossip]` section predates `byte_policy`, so
    /// omitting it has to mean "observe only" — if this ever defaulted to
    /// `shed_normal`, every node in the fleet would start dropping forwarded
    /// gossip on an upgrade nobody opted into.
    #[test]
    fn omitted_byte_policy_means_observe_only() {
        let parsed: GossipConfig = toml::from_str("leaf_max_eager_degree = 2").unwrap();
        assert_eq!(parsed.byte_policy, LeafBytePolicy::ObserveOnly);
        assert_eq!(GossipConfig::default().byte_policy, parsed.byte_policy);
        assert_eq!(parsed.byte_policy.as_str(), "observe_only");

        let opted_in: GossipConfig = toml::from_str("byte_policy = \"shed_normal\"").unwrap();
        assert_eq!(opted_in.byte_policy, LeafBytePolicy::ShedNormal);
        assert_eq!(opted_in.byte_policy.as_str(), "shed_normal");
        // Opting into shedding must not disturb the metered thresholds.
        assert_eq!(
            opted_in.leaf_egress_hard_bytes_per_sec,
            default_leaf_egress_hard()
        );
    }

    /// WHY: saorsa-gossip refuses a budget whose burst cannot hold one
    /// maximum frame, and a refused budget means *no* accounting at all. An
    /// operator who mistypes the burst must get metering back with a warning,
    /// not a daemon that silently stopped measuring — and not a restart loop,
    /// which is the trap the deprecated view-size keys already sprang once.
    #[test]
    fn undersized_burst_normalizes_rather_than_disabling_accounting() {
        let mut config = GossipConfig {
            leaf_egress_burst_bytes: 1_024,
            ..Default::default()
        };
        assert!(config.validate_egress_budget().is_err());
        assert!(config.normalize_egress_budget().is_some());
        assert_eq!(config.leaf_egress_burst_bytes, default_leaf_egress_burst());
        assert!(config.validate().is_ok());

        // A disabled budget has no frame to size a burst against.
        let disabled = GossipConfig {
            leaf_egress_hard_bytes_per_sec: 0,
            leaf_egress_burst_bytes: 1,
            ..Default::default()
        };
        assert!(disabled.validate_egress_budget().is_ok());
    }

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
    fn relay_fanout_budget_parses_partial_toml_and_defaults_to_50() {
        // Why (#674 C3): the budget is the operator's only lever on eager
        // re-forwarding of consumed topics; a partial TOML section must
        // keep the 50 msg/s default (above the busiest measured fleet
        // topic, ~19/s) and 0 must round-trip as "gate disabled" — not be
        // silently normalized away.
        let cfg: GossipConfig = toml::from_str("dispatch_workers = 2").expect("partial TOML");
        assert_eq!(cfg.relay_fanout_budget_msgs_per_sec, 50);
        let cfg: GossipConfig =
            toml::from_str("relay_fanout_budget_msgs_per_sec = 0").expect("explicit zero");
        assert_eq!(cfg.relay_fanout_budget_msgs_per_sec, 0);
        let cfg: GossipConfig =
            toml::from_str("relay_fanout_budget_msgs_per_sec = 7").expect("explicit value");
        assert_eq!(cfg.relay_fanout_budget_msgs_per_sec, 7);
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
