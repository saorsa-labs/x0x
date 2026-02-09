use x0x::crdt::persistence::{
    BudgetPressure, PersistenceErrorInfo, PersistenceHealth, PersistenceObservabilityContract,
    RecoveryHealthOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingPersistenceErrorInfo {
    pub code: String,
    pub message: String,
    pub remediation: String,
}

impl From<PersistenceErrorInfo> for BindingPersistenceErrorInfo {
    fn from(value: PersistenceErrorInfo) -> Self {
        Self {
            code: value.code.as_str().to_string(),
            message: value.message,
            remediation: value.remediation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingPersistenceHealth {
    pub mode: String,
    pub state: String,
    pub degraded: bool,
    pub last_recovery_outcome: Option<String>,
    pub last_error: Option<BindingPersistenceErrorInfo>,
    pub budget_pressure: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingPersistenceObservability {
    pub health: BindingPersistenceHealth,
    pub checkpoint_frequency: BindingCheckpointFrequency,
    pub checkpoint_frequency_bounds: BindingCheckpointFrequencyBounds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingCheckpointFrequency {
    pub mutation_threshold: u32,
    pub dirty_time_floor_secs: u64,
    pub debounce_floor_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingCheckpointFrequencyBounds {
    pub allow_runtime_checkpoint_frequency_adjustment: bool,
    pub min_mutation_threshold: u32,
    pub max_mutation_threshold: u32,
    pub min_dirty_time_floor_secs: u64,
    pub max_dirty_time_floor_secs: u64,
    pub min_debounce_floor_secs: u64,
    pub max_debounce_floor_secs: u64,
}

pub fn map_persistence_health(health: &PersistenceHealth) -> BindingPersistenceHealth {
    BindingPersistenceHealth {
        mode: health.mode.as_str().to_string(),
        state: health.state.as_str().to_string(),
        degraded: health.degraded,
        last_recovery_outcome: health.last_recovery_outcome.map(recovery_outcome_as_str),
        last_error: health.last_error.clone().map(Into::into),
        budget_pressure: budget_pressure_as_str(health.budget_pressure).to_string(),
    }
}

pub fn map_persistence_observability(
    contract: &PersistenceObservabilityContract,
) -> BindingPersistenceObservability {
    BindingPersistenceObservability {
        health: map_persistence_health(&contract.health),
        checkpoint_frequency: BindingCheckpointFrequency {
            mutation_threshold: contract.checkpoint_frequency.mutation_threshold,
            dirty_time_floor_secs: contract.checkpoint_frequency.dirty_time_floor_secs,
            debounce_floor_secs: contract.checkpoint_frequency.debounce_floor_secs,
        },
        checkpoint_frequency_bounds: BindingCheckpointFrequencyBounds {
            allow_runtime_checkpoint_frequency_adjustment: contract
                .checkpoint_frequency_bounds
                .allow_runtime_checkpoint_frequency_adjustment,
            min_mutation_threshold: contract.checkpoint_frequency_bounds.min_mutation_threshold,
            max_mutation_threshold: contract.checkpoint_frequency_bounds.max_mutation_threshold,
            min_dirty_time_floor_secs: contract
                .checkpoint_frequency_bounds
                .min_dirty_time_floor_secs,
            max_dirty_time_floor_secs: contract
                .checkpoint_frequency_bounds
                .max_dirty_time_floor_secs,
            min_debounce_floor_secs: contract.checkpoint_frequency_bounds.min_debounce_floor_secs,
            max_debounce_floor_secs: contract.checkpoint_frequency_bounds.max_debounce_floor_secs,
        },
    }
}

fn recovery_outcome_as_str(outcome: RecoveryHealthOutcome) -> String {
    match outcome {
        RecoveryHealthOutcome::LoadedSnapshot => "loaded_snapshot",
        RecoveryHealthOutcome::EmptyStore => "empty_store",
        RecoveryHealthOutcome::DegradedFallback => "degraded_fallback",
        RecoveryHealthOutcome::StrictInitFailure => "strict_init_failure",
        RecoveryHealthOutcome::UnsupportedLegacyEncryptedArtifact => {
            "unsupported_legacy_encrypted_artifact"
        }
    }
    .to_string()
}

fn budget_pressure_as_str(value: BudgetPressure) -> &'static str {
    value.as_str()
}
