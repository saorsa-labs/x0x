use std::time::Duration;

use sha2::{Digest, Sha256};
use tracing::debug;

/// Staged rollout delay calculator.
///
/// Uses a deterministic hash of the node ID to spread upgrades across a time
/// window, preventing all nodes from upgrading simultaneously.
pub struct StagedRollout {
    /// The node's unique identifier (typically MachineId, 32 bytes).
    node_id: Vec<u8>,
    /// Maximum delay in minutes.
    max_delay_minutes: u64,
}

impl StagedRollout {
    /// Create a new staged rollout calculator.
    ///
    /// # Arguments
    /// * `node_id` - Unique node identifier (MachineId bytes)
    /// * `max_delay_minutes` - Maximum rollout window in minutes (0 = no delay)
    pub fn new(node_id: &[u8], max_delay_minutes: u64) -> Self {
        Self {
            node_id: node_id.to_vec(),
            max_delay_minutes,
        }
    }

    /// Calculate the rollout delay for this node.
    ///
    /// Returns Duration::ZERO if max_delay_minutes is 0.
    pub fn calculate_delay(&self) -> Duration {
        if self.max_delay_minutes == 0 {
            return Duration::ZERO;
        }

        let hash = Sha256::digest(&self.node_id);
        let fraction = self.hash_to_fraction(&hash);
        let delay_secs = (fraction * (self.max_delay_minutes as f64) * 60.0) as u64;
        let delay = Duration::from_secs(delay_secs);

        let hours = delay_secs / 3600;
        let minutes = (delay_secs % 3600) / 60;
        let seconds = delay_secs % 60;
        debug!(
            delay_hours = hours,
            delay_minutes = minutes,
            delay_seconds = seconds,
            "Calculated staged rollout delay: {}h {}m {}s",
            hours,
            minutes,
            seconds
        );

        delay
    }

    /// Calculate a version-specific delay.
    ///
    /// Includes the version string in the hash so that different releases
    /// produce different delay orderings across the fleet.
    pub fn calculate_delay_for_version(&self, version: &str) -> Duration {
        if self.max_delay_minutes == 0 {
            return Duration::ZERO;
        }

        let mut hasher = Sha256::new();
        hasher.update(&self.node_id);
        hasher.update(version.as_bytes());
        let hash = hasher.finalize();

        let fraction = self.hash_to_fraction(&hash);
        let delay_secs = (fraction * (self.max_delay_minutes as f64) * 60.0) as u64;
        let delay = Duration::from_secs(delay_secs);

        let hours = delay_secs / 3600;
        let minutes = (delay_secs % 3600) / 60;
        let seconds = delay_secs % 60;
        debug!(
            delay_hours = hours,
            delay_minutes = minutes,
            delay_seconds = seconds,
            "Calculated staged rollout delay: {}h {}m {}s",
            hours,
            minutes,
            seconds
        );

        delay
    }

    /// Convert a SHA-256 hash to a fraction in [0.0, 1.0).
    fn hash_to_fraction(&self, hash: &[u8]) -> f64 {
        let value = u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);
        value as f64 / u64::MAX as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_delay_when_disabled() {
        let rollout = StagedRollout::new(b"test-node", 0);
        assert_eq!(rollout.calculate_delay(), Duration::ZERO);
    }

    #[test]
    fn test_zero_delay_for_version_when_disabled() {
        let rollout = StagedRollout::new(b"test-node", 0);
        assert_eq!(rollout.calculate_delay_for_version("1.0.0"), Duration::ZERO);
    }

    #[test]
    fn test_delay_within_expected_range() {
        let rollout = StagedRollout::new(b"test-node-1", 1440);
        let delay = rollout.calculate_delay();
        assert!(delay <= Duration::from_secs(1440 * 60));
    }

    #[test]
    fn test_deterministic_delays() {
        let rollout1 = StagedRollout::new(b"same-node", 1440);
        let rollout2 = StagedRollout::new(b"same-node", 1440);
        assert_eq!(rollout1.calculate_delay(), rollout2.calculate_delay());
    }

    #[test]
    fn test_different_nodes_get_different_delays() {
        let rollout1 = StagedRollout::new(b"node-alpha", 1440);
        let rollout2 = StagedRollout::new(b"node-beta", 1440);
        // Extremely unlikely (but theoretically possible) to be equal
        assert_ne!(rollout1.calculate_delay(), rollout2.calculate_delay());
    }

    #[test]
    fn test_delay_scales_with_max_hours() {
        let rollout_short = StagedRollout::new(b"node-x", 120);
        let rollout_long = StagedRollout::new(b"node-x", 1440);

        let short_delay = rollout_short.calculate_delay();
        let long_delay = rollout_long.calculate_delay();

        assert!(short_delay <= Duration::from_secs(120 * 60));
        assert!(long_delay <= Duration::from_secs(1440 * 60));
        // The ratio should be approximately 120:1440 = 1:12
        // Allow some tolerance due to the hash distribution
        assert!(long_delay > short_delay);
    }

    #[test]
    fn test_version_specific_delays_differ() {
        let rollout = StagedRollout::new(b"same-node", 1440);
        let delay_v1 = rollout.calculate_delay_for_version("1.0.0");
        let delay_v2 = rollout.calculate_delay_for_version("2.0.0");
        // Different versions should produce different delays for the same node
        assert_ne!(delay_v1, delay_v2);
    }

    #[test]
    fn test_empty_node_id() {
        let rollout = StagedRollout::new(b"", 1440);
        let delay = rollout.calculate_delay();
        assert!(delay <= Duration::from_secs(1440 * 60));
    }

    #[test]
    fn test_large_node_id() {
        let large_id = vec![0xABu8; 1024];
        let rollout = StagedRollout::new(&large_id, 1440);
        let delay = rollout.calculate_delay();
        assert!(delay <= Duration::from_secs(1440 * 60));
    }

    #[test]
    fn test_distribution_across_100_nodes() {
        let max_minutes = 1440u64;
        let max_secs = max_minutes * 60;
        let mut delays: Vec<u64> = Vec::new();

        for i in 0..100u32 {
            let node_id = i.to_be_bytes();
            let rollout = StagedRollout::new(&node_id, max_minutes);
            let delay = rollout.calculate_delay();
            delays.push(delay.as_secs());
        }

        // All delays should be within range
        assert!(delays.iter().all(|&d| d <= max_secs));

        // Check reasonable spread: delays should span at least 50% of the window
        let min_delay = *delays.iter().min().unwrap();
        let max_delay = *delays.iter().max().unwrap();
        let spread = max_delay - min_delay;
        assert!(
            spread > max_secs / 2,
            "Distribution too narrow: spread={spread}s out of {max_secs}s window"
        );
    }
}
