use std::str::FromStr;

use x0x::config::{ConfigError, HostPolicyEnvelopeConfig, PersistenceConfig, StartupConfig};
use x0x::crdt::persistence::PersistenceMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingPersistenceConfigInput {
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
    pub host_policy: BindingHostPolicyEnvelope,
}

impl Default for BindingPersistenceConfigInput {
    fn default() -> Self {
        let defaults = PersistenceConfig::default();
        Self {
            enabled: defaults.enabled,
            mode: defaults.mode,
            checkpoint_mutation_threshold: defaults.checkpoint_mutation_threshold,
            checkpoint_dirty_time_floor_secs: defaults.checkpoint_dirty_time_floor_secs,
            checkpoint_debounce_floor_secs: defaults.checkpoint_debounce_floor_secs,
            retention_checkpoints_to_keep: defaults.retention_checkpoints_to_keep,
            retention_storage_budget_bytes: defaults.retention_storage_budget_bytes,
            retention_warning_threshold_percent: defaults.retention_warning_threshold_percent,
            retention_critical_threshold_percent: defaults.retention_critical_threshold_percent,
            strict_initialize_if_missing: defaults.strict_initialize_if_missing,
            host_policy: defaults.host_policy.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingHostPolicyEnvelope {
    pub allow_runtime_checkpoint_frequency_adjustment: bool,
    pub min_mutation_threshold: u32,
    pub max_mutation_threshold: u32,
    pub min_dirty_time_floor_secs: u64,
    pub max_dirty_time_floor_secs: u64,
    pub min_debounce_floor_secs: u64,
    pub max_debounce_floor_secs: u64,
}

impl From<HostPolicyEnvelopeConfig> for BindingHostPolicyEnvelope {
    fn from(value: HostPolicyEnvelopeConfig) -> Self {
        Self {
            allow_runtime_checkpoint_frequency_adjustment: value
                .allow_runtime_checkpoint_frequency_adjustment,
            min_mutation_threshold: value.min_mutation_threshold,
            max_mutation_threshold: value.max_mutation_threshold,
            min_dirty_time_floor_secs: value.min_dirty_time_floor_secs,
            max_dirty_time_floor_secs: value.max_dirty_time_floor_secs,
            min_debounce_floor_secs: value.min_debounce_floor_secs,
            max_debounce_floor_secs: value.max_debounce_floor_secs,
        }
    }
}

impl From<BindingHostPolicyEnvelope> for HostPolicyEnvelopeConfig {
    fn from(value: BindingHostPolicyEnvelope) -> Self {
        Self {
            allow_runtime_checkpoint_frequency_adjustment: value
                .allow_runtime_checkpoint_frequency_adjustment,
            min_mutation_threshold: value.min_mutation_threshold,
            max_mutation_threshold: value.max_mutation_threshold,
            min_dirty_time_floor_secs: value.min_dirty_time_floor_secs,
            max_dirty_time_floor_secs: value.max_dirty_time_floor_secs,
            min_debounce_floor_secs: value.min_debounce_floor_secs,
            max_debounce_floor_secs: value.max_debounce_floor_secs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingResolvedPersistenceConfig {
    pub enabled: bool,
    pub mode: String,
    pub checkpoint_mutation_threshold: u32,
    pub checkpoint_dirty_time_floor_secs: u64,
    pub checkpoint_debounce_floor_secs: u64,
    pub retention_checkpoints_to_keep: u8,
    pub retention_storage_budget_bytes: u64,
    pub retention_warning_threshold_percent: u8,
    pub retention_critical_threshold_percent: u8,
    pub strict_initialize_if_missing: bool,
    pub host_policy: BindingHostPolicyEnvelope,
}

pub fn resolve_persistence_config(
    input: BindingPersistenceConfigInput,
) -> Result<BindingResolvedPersistenceConfig, ConfigError> {
    let startup = StartupConfig {
        persistence: PersistenceConfig {
            enabled: input.enabled,
            mode: input.mode,
            checkpoint_mutation_threshold: input.checkpoint_mutation_threshold,
            checkpoint_dirty_time_floor_secs: input.checkpoint_dirty_time_floor_secs,
            checkpoint_debounce_floor_secs: input.checkpoint_debounce_floor_secs,
            retention_checkpoints_to_keep: input.retention_checkpoints_to_keep,
            retention_storage_budget_bytes: input.retention_storage_budget_bytes,
            retention_warning_threshold_percent: input.retention_warning_threshold_percent,
            retention_critical_threshold_percent: input.retention_critical_threshold_percent,
            strict_initialize_if_missing: input.strict_initialize_if_missing,
            host_policy: input.host_policy.into(),
        },
    };

    let resolved = startup.resolve_persistence()?;
    Ok(BindingResolvedPersistenceConfig {
        enabled: resolved.policy.enabled,
        mode: resolved.policy.mode.as_str().to_string(),
        checkpoint_mutation_threshold: resolved.policy.checkpoint.mutation_threshold,
        checkpoint_dirty_time_floor_secs: resolved.policy.checkpoint.dirty_time_floor.as_secs(),
        checkpoint_debounce_floor_secs: resolved.policy.checkpoint.debounce_floor.as_secs(),
        retention_checkpoints_to_keep: resolved.policy.retention.checkpoints_to_keep,
        retention_storage_budget_bytes: resolved.policy.retention.storage_budget_bytes,
        retention_warning_threshold_percent: resolved.policy.retention.warning_threshold_percent,
        retention_critical_threshold_percent: resolved.policy.retention.critical_threshold_percent,
        strict_initialize_if_missing: resolved.policy.strict_initialization.initialize_if_missing,
        host_policy: resolved.host_policy.into(),
    })
}

pub fn parse_persistence_mode(mode: &str) -> Result<String, ConfigError> {
    PersistenceMode::from_str(mode)
        .map(|parsed| parsed.as_str().to_string())
        .map_err(|_| ConfigError::InvalidPersistenceMode(mode.to_string()))
}
