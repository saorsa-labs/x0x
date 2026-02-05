//! Configuration for the gossip overlay network.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for the gossip overlay network.
///
/// This struct defines parameters for HyParView membership, SWIM failure
/// detection, presence beacons, anti-entropy reconciliation, and FOAF discovery.
///
/// Default values are optimized for typical x0x deployments based on ROADMAP
/// recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipConfig {
    /// Number of active peers in HyParView (default: 10, range: 8-12)
    ///
    /// Active peers receive all messages and participate in eager push gossip.
    pub active_view_size: usize,

    /// Number of passive peers in HyParView (default: 96, range: 64-128)
    ///
    /// Passive peers are backup connections used for failure recovery.
    pub passive_view_size: usize,

    /// Interval for SWIM failure detection probes (default: 1 second)
    ///
    /// How often to probe peers to detect failures.
    #[serde(with = "duration_serde")]
    pub probe_interval: Duration,

    /// Timeout before marking peer as suspected in SWIM (default: 3 seconds)
    ///
    /// If a peer doesn't respond to probes within this time, it's marked as suspect.
    #[serde(with = "duration_serde")]
    pub suspect_timeout: Duration,

    /// TTL for presence beacons (default: 15 minutes)
    ///
    /// Agents broadcast presence beacons at TTL/2 interval to indicate they're online.
    #[serde(with = "duration_serde")]
    pub presence_beacon_ttl: Duration,

    /// Interval for anti-entropy reconciliation (default: 30 seconds)
    ///
    /// How often to run IBLT reconciliation to repair missed messages.
    #[serde(with = "duration_serde")]
    pub anti_entropy_interval: Duration,

    /// Maximum hops for FOAF discovery queries (default: 3)
    ///
    /// Limits how far discovery queries propagate to preserve privacy.
    pub foaf_ttl: u8,

    /// Fanout for FOAF discovery (default: 3)
    ///
    /// Number of peers to forward discovery queries to at each hop.
    pub foaf_fanout: u8,

    /// Size of message deduplication cache (default: 10,000 messages)
    ///
    /// LRU cache for detecting duplicate messages by BLAKE3 ID.
    pub message_cache_size: usize,

    /// TTL for cached messages in deduplication cache (default: 5 minutes)
    ///
    /// Messages older than this are evicted from the dedup cache.
    #[serde(with = "duration_serde")]
    pub message_cache_ttl: Duration,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            active_view_size: 10,
            passive_view_size: 96,
            probe_interval: Duration::from_secs(1),
            suspect_timeout: Duration::from_secs(3),
            presence_beacon_ttl: Duration::from_secs(15 * 60), // 15 minutes
            anti_entropy_interval: Duration::from_secs(30),
            foaf_ttl: 3,
            foaf_fanout: 3,
            message_cache_size: 10_000,
            message_cache_ttl: Duration::from_secs(5 * 60), // 5 minutes
        }
    }
}

/// Helper module for serde Duration serialization.
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GossipConfig::default();

        // Verify HyParView parameters
        assert_eq!(config.active_view_size, 10);
        assert!(
            (8..=12).contains(&config.active_view_size),
            "active_view_size should be in range 8-12"
        );
        assert_eq!(config.passive_view_size, 96);
        assert!(
            (64..=128).contains(&config.passive_view_size),
            "passive_view_size should be in range 64-128"
        );

        // Verify SWIM parameters
        assert_eq!(config.probe_interval, Duration::from_secs(1));
        assert_eq!(config.suspect_timeout, Duration::from_secs(3));

        // Verify presence parameters
        assert_eq!(config.presence_beacon_ttl, Duration::from_secs(15 * 60));

        // Verify anti-entropy parameters
        assert_eq!(config.anti_entropy_interval, Duration::from_secs(30));

        // Verify FOAF parameters
        assert_eq!(config.foaf_ttl, 3);
        assert_eq!(config.foaf_fanout, 3);

        // Verify message cache parameters
        assert_eq!(config.message_cache_size, 10_000);
        assert_eq!(config.message_cache_ttl, Duration::from_secs(5 * 60));
    }

    #[test]
    fn test_config_serialization() {
        let config = GossipConfig::default();

        // Serialize to JSON
        let json = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(!json.is_empty());

        // Deserialize back
        let deserialized: GossipConfig =
            serde_json::from_str(&json).expect("Failed to deserialize");

        // Verify round-trip
        assert_eq!(config.active_view_size, deserialized.active_view_size);
        assert_eq!(config.passive_view_size, deserialized.passive_view_size);
        assert_eq!(config.probe_interval, deserialized.probe_interval);
        assert_eq!(config.suspect_timeout, deserialized.suspect_timeout);
        assert_eq!(config.presence_beacon_ttl, deserialized.presence_beacon_ttl);
        assert_eq!(
            config.anti_entropy_interval,
            deserialized.anti_entropy_interval
        );
        assert_eq!(config.foaf_ttl, deserialized.foaf_ttl);
        assert_eq!(config.foaf_fanout, deserialized.foaf_fanout);
        assert_eq!(config.message_cache_size, deserialized.message_cache_size);
        assert_eq!(config.message_cache_ttl, deserialized.message_cache_ttl);
    }
}
