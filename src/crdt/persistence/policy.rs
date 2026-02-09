//! Persistence policy defaults and validation.

use std::str::FromStr;
use std::time::Duration;

const DEFAULT_MUTATION_THRESHOLD: u32 = 32;
const DEFAULT_DIRTY_TIME_FLOOR_SECS: u64 = 5 * 60;
const DEFAULT_DEBOUNCE_FLOOR_SECS: u64 = 2;
const DEFAULT_RETENTION_COUNT: u8 = 3;
const DEFAULT_STORAGE_BUDGET_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_WARN_THRESHOLD_PERCENT: u8 = 80;
const DEFAULT_CRITICAL_THRESHOLD_PERCENT: u8 = 90;

/// Persistence failure mode policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PersistenceMode {
    #[default]
    Degraded,
    Strict,
}

impl FromStr for PersistenceMode {
    type Err = PersistencePolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "degraded" => Ok(Self::Degraded),
            "strict" => Ok(Self::Strict),
            _ => Err(PersistencePolicyError::InvalidMode(s.to_string())),
        }
    }
}

/// Strict-mode startup behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StrictInitializationPolicy {
    pub initialize_if_missing: bool,
}

/// Checkpoint trigger defaults from ADR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPolicy {
    pub mutation_threshold: u32,
    pub dirty_time_floor: Duration,
    pub debounce_floor: Duration,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            mutation_threshold: DEFAULT_MUTATION_THRESHOLD,
            dirty_time_floor: Duration::from_secs(DEFAULT_DIRTY_TIME_FLOOR_SECS),
            debounce_floor: Duration::from_secs(DEFAULT_DEBOUNCE_FLOOR_SECS),
        }
    }
}

/// Retention and budget defaults from ADR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub checkpoints_to_keep: u8,
    pub storage_budget_bytes: u64,
    pub warning_threshold_percent: u8,
    pub critical_threshold_percent: u8,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            checkpoints_to_keep: DEFAULT_RETENTION_COUNT,
            storage_budget_bytes: DEFAULT_STORAGE_BUDGET_BYTES,
            warning_threshold_percent: DEFAULT_WARN_THRESHOLD_PERCENT,
            critical_threshold_percent: DEFAULT_CRITICAL_THRESHOLD_PERCENT,
        }
    }
}

/// Runtime persistence policy resolved at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistencePolicy {
    pub enabled: bool,
    pub mode: PersistenceMode,
    pub checkpoint: CheckpointPolicy,
    pub retention: RetentionPolicy,
    pub strict_initialization: StrictInitializationPolicy,
}

impl Default for PersistencePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: PersistenceMode::Degraded,
            checkpoint: CheckpointPolicy::default(),
            retention: RetentionPolicy::default(),
            strict_initialization: StrictInitializationPolicy::default(),
        }
    }
}

impl PersistencePolicy {
    pub fn validate(&self) -> Result<(), PersistencePolicyError> {
        if self.checkpoint.mutation_threshold == 0 {
            return Err(PersistencePolicyError::InvalidMutationThreshold(
                self.checkpoint.mutation_threshold,
            ));
        }

        if self.checkpoint.debounce_floor.as_secs() == 0 {
            return Err(PersistencePolicyError::InvalidDebounceFloor);
        }

        if self.retention.warning_threshold_percent >= self.retention.critical_threshold_percent {
            return Err(PersistencePolicyError::InvalidRetentionThresholds {
                warning: self.retention.warning_threshold_percent,
                critical: self.retention.critical_threshold_percent,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PersistencePolicyError {
    #[error("invalid persistence mode: {0}")]
    InvalidMode(String),
    #[error("mutation threshold must be at least 1, got {0}")]
    InvalidMutationThreshold(u32),
    #[error("debounce floor must be at least 1 second")]
    InvalidDebounceFloor,
    #[error("invalid retention thresholds: warning={warning}, critical={critical}")]
    InvalidRetentionThresholds { warning: u8, critical: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_adr_values() {
        let policy = PersistencePolicy::default();
        assert!(!policy.enabled);
        assert_eq!(policy.mode, PersistenceMode::Degraded);
        assert_eq!(policy.checkpoint.mutation_threshold, 32);
        assert_eq!(policy.checkpoint.dirty_time_floor, Duration::from_secs(300));
        assert_eq!(policy.checkpoint.debounce_floor, Duration::from_secs(2));
        assert_eq!(policy.retention.checkpoints_to_keep, 3);
        assert_eq!(policy.retention.storage_budget_bytes, 256 * 1024 * 1024);
        assert_eq!(policy.retention.warning_threshold_percent, 80);
        assert_eq!(policy.retention.critical_threshold_percent, 90);
        assert!(!policy.strict_initialization.initialize_if_missing);
    }

    #[test]
    fn mode_parsing_is_case_insensitive() {
        assert_eq!(
            PersistenceMode::from_str("degraded").unwrap(),
            PersistenceMode::Degraded
        );
        assert_eq!(
            PersistenceMode::from_str("STRICT").unwrap(),
            PersistenceMode::Strict
        );
    }

    #[test]
    fn invalid_mode_is_rejected() {
        assert_eq!(
            PersistenceMode::from_str("best_effort").unwrap_err(),
            PersistencePolicyError::InvalidMode("best_effort".to_string())
        );
    }

    #[test]
    fn invalid_mutation_threshold_is_rejected() {
        let mut policy = PersistencePolicy::default();
        policy.checkpoint.mutation_threshold = 0;

        assert_eq!(
            policy.validate().unwrap_err(),
            PersistencePolicyError::InvalidMutationThreshold(0)
        );
    }

    #[test]
    fn strict_mode_allows_resolution_without_initialize_intent() {
        let mut policy = PersistencePolicy {
            enabled: true,
            mode: PersistenceMode::Strict,
            ..PersistencePolicy::default()
        };

        assert!(policy.validate().is_ok());

        policy.strict_initialization.initialize_if_missing = true;
        assert!(policy.validate().is_ok());
    }
}
