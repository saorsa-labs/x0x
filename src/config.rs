//! Startup configuration and persistence policy resolution.

use crate::crdt::persistence::{
    CheckpointPolicy, PersistenceMode, PersistencePolicy, PersistencePolicyError, RetentionPolicy,
    StrictInitializationPolicy,
};
use crate::runtime::policy_bounds::{
    ensure_policy_within_envelope, validate_host_envelope, PolicyBoundsError,
};
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid persistence mode: {0}")]
    InvalidPersistenceMode(String),
    #[error("invalid persistence policy: {0}")]
    InvalidPersistencePolicy(#[from] PersistencePolicyError),
    #[error("invalid host policy envelope: {0}")]
    InvalidHostPolicyEnvelope(#[from] PolicyBoundsError),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StartupConfig {
    pub persistence: PersistenceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PersistenceConfig {
    pub enabled: bool,
    pub mode: Option<String>,
    pub checkpoint_mutation_threshold: Option<u32>,
    pub checkpoint_dirty_time_floor_secs: Option<u64>,
    pub checkpoint_debounce_floor_secs: Option<u64>,
    pub retention_checkpoints_to_keep: Option<u8>,
    pub retention_storage_budget_bytes: Option<u64>,
    pub retention_warning_threshold_percent: Option<u8>,
    pub retention_critical_threshold_percent: Option<u8>,
    pub strict_initialize_if_missing: Option<bool>,
    pub host_policy: HostPolicyEnvelopeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPolicyEnvelopeConfig {
    pub allow_runtime_checkpoint_frequency_adjustment: bool,
    pub min_mutation_threshold: u32,
    pub max_mutation_threshold: u32,
    pub min_dirty_time_floor_secs: u64,
    pub max_dirty_time_floor_secs: u64,
    pub min_debounce_floor_secs: u64,
    pub max_debounce_floor_secs: u64,
}

impl Default for HostPolicyEnvelopeConfig {
    fn default() -> Self {
        let policy = PersistencePolicy::default();
        Self {
            allow_runtime_checkpoint_frequency_adjustment: false,
            min_mutation_threshold: policy.checkpoint.mutation_threshold,
            max_mutation_threshold: policy.checkpoint.mutation_threshold,
            min_dirty_time_floor_secs: policy.checkpoint.dirty_time_floor.as_secs(),
            max_dirty_time_floor_secs: policy.checkpoint.dirty_time_floor.as_secs(),
            min_debounce_floor_secs: policy.checkpoint.debounce_floor.as_secs(),
            max_debounce_floor_secs: policy.checkpoint.debounce_floor.as_secs(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPersistenceConfig {
    pub policy: PersistencePolicy,
    pub host_policy: HostPolicyEnvelopeConfig,
}

impl StartupConfig {
    pub fn resolve_persistence(&self) -> Result<ResolvedPersistenceConfig, ConfigError> {
        let mode = self
            .persistence
            .mode
            .as_deref()
            .map(PersistenceMode::from_str)
            .transpose()
            .map_err(|_| {
                ConfigError::InvalidPersistenceMode(
                    self.persistence.mode.clone().unwrap_or_default(),
                )
            })?
            .unwrap_or(PersistenceMode::Degraded);

        let defaults = PersistencePolicy::default();
        let checkpoint = CheckpointPolicy {
            mutation_threshold: self
                .persistence
                .checkpoint_mutation_threshold
                .unwrap_or(defaults.checkpoint.mutation_threshold),
            dirty_time_floor: Duration::from_secs(
                self.persistence
                    .checkpoint_dirty_time_floor_secs
                    .unwrap_or(defaults.checkpoint.dirty_time_floor.as_secs()),
            ),
            debounce_floor: Duration::from_secs(
                self.persistence
                    .checkpoint_debounce_floor_secs
                    .unwrap_or(defaults.checkpoint.debounce_floor.as_secs()),
            ),
        };

        let retention = RetentionPolicy {
            checkpoints_to_keep: self
                .persistence
                .retention_checkpoints_to_keep
                .unwrap_or(defaults.retention.checkpoints_to_keep),
            storage_budget_bytes: self
                .persistence
                .retention_storage_budget_bytes
                .unwrap_or(defaults.retention.storage_budget_bytes),
            warning_threshold_percent: self
                .persistence
                .retention_warning_threshold_percent
                .unwrap_or(defaults.retention.warning_threshold_percent),
            critical_threshold_percent: self
                .persistence
                .retention_critical_threshold_percent
                .unwrap_or(defaults.retention.critical_threshold_percent),
        };

        let strict_initialization = StrictInitializationPolicy {
            initialize_if_missing: self
                .persistence
                .strict_initialize_if_missing
                .unwrap_or(false),
        };

        let policy = PersistencePolicy {
            enabled: self.persistence.enabled,
            mode,
            checkpoint,
            retention,
            strict_initialization,
        };

        policy.validate()?;

        validate_host_envelope(&self.persistence.host_policy)?;
        ensure_policy_within_envelope(&policy, &self.persistence.host_policy)?;

        Ok(ResolvedPersistenceConfig {
            policy,
            host_policy: self.persistence.host_policy.clone(),
        })
    }
}
