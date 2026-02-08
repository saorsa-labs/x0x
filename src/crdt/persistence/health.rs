use crate::crdt::persistence::{BudgetDecision, PersistenceBackendError, PersistenceMode};

pub const EVENT_INIT_STARTED: &str = "persistence.init.started";
pub const EVENT_INIT_LOADED: &str = "persistence.init.loaded";
pub const EVENT_INIT_EMPTY: &str = "persistence.init.empty_store";
pub const EVENT_INIT_FAILURE: &str = "persistence.init.failure";
pub const EVENT_CHECKPOINT_ATTEMPT: &str = "persistence.checkpoint.attempt";
pub const EVENT_CHECKPOINT_SUCCESS: &str = "persistence.checkpoint.success";
pub const EVENT_CHECKPOINT_FAILURE: &str = "persistence.checkpoint.failure";
pub const EVENT_BUDGET_THRESHOLD: &str = "persistence.budget.threshold";
pub const EVENT_LEGACY_ARTIFACT_DETECTED: &str = "persistence.legacy_artifact.detected";
pub const EVENT_DEGRADED_TRANSITION: &str = "persistence.health.degraded_transition";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceState {
    StartingUp,
    Ready,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryHealthOutcome {
    LoadedSnapshot,
    EmptyStore,
    DegradedFallback,
    StrictInitFailure,
    UnsupportedLegacyEncryptedArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetPressure {
    Normal,
    Warning,
    Critical,
    AtCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceErrorCode {
    StartupLoadFailure,
    StrictInitializationFailure,
    CheckpointFailure,
    UnsupportedLegacyEncryptedArtifact,
    BudgetWarning,
    BudgetCritical,
    BudgetAtCapacity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceErrorInfo {
    pub code: PersistenceErrorCode,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceHealth {
    pub mode: PersistenceMode,
    pub state: PersistenceState,
    pub degraded: bool,
    pub last_recovery_outcome: Option<RecoveryHealthOutcome>,
    pub last_error: Option<PersistenceErrorInfo>,
    pub budget_pressure: BudgetPressure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointFrequencyContract {
    pub mutation_threshold: u32,
    pub dirty_time_floor_secs: u64,
    pub debounce_floor_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointFrequencyUpdateRequest {
    pub mutation_threshold: Option<u32>,
    pub dirty_time_floor_secs: Option<u64>,
    pub debounce_floor_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointFrequencyBounds {
    pub allow_runtime_checkpoint_frequency_adjustment: bool,
    pub min_mutation_threshold: u32,
    pub max_mutation_threshold: u32,
    pub min_dirty_time_floor_secs: u64,
    pub max_dirty_time_floor_secs: u64,
    pub min_debounce_floor_secs: u64,
    pub max_debounce_floor_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceObservabilityContract {
    pub health: PersistenceHealth,
    pub checkpoint_frequency: CheckpointFrequencyContract,
    pub checkpoint_frequency_bounds: CheckpointFrequencyBounds,
}

impl PersistenceHealth {
    #[must_use]
    pub fn new(mode: PersistenceMode) -> Self {
        Self {
            mode,
            state: PersistenceState::StartingUp,
            degraded: false,
            last_recovery_outcome: None,
            last_error: None,
            budget_pressure: BudgetPressure::Normal,
        }
    }

    pub fn startup_loaded_snapshot(&mut self) {
        self.state = PersistenceState::Ready;
        self.degraded = false;
        self.last_recovery_outcome = Some(RecoveryHealthOutcome::LoadedSnapshot);
        self.last_error = None;
        tracing::info!(
            event = EVENT_INIT_LOADED,
            mode = self.mode.as_str(),
            state = self.state.as_str(),
            degraded = self.degraded
        );
    }

    pub fn startup_empty_store(&mut self) {
        self.state = PersistenceState::Ready;
        self.degraded = false;
        self.last_recovery_outcome = Some(RecoveryHealthOutcome::EmptyStore);
        self.last_error = None;
        tracing::info!(
            event = EVENT_INIT_EMPTY,
            mode = self.mode.as_str(),
            state = self.state.as_str(),
            degraded = self.degraded
        );
    }

    pub fn startup_fallback(&mut self, err: &PersistenceBackendError) {
        let legacy = is_legacy_artifact_error(err);
        self.state = PersistenceState::Degraded;
        self.degraded = true;
        self.last_recovery_outcome = Some(if legacy {
            RecoveryHealthOutcome::UnsupportedLegacyEncryptedArtifact
        } else {
            RecoveryHealthOutcome::DegradedFallback
        });
        self.last_error = Some(PersistenceErrorInfo {
            code: if legacy {
                PersistenceErrorCode::UnsupportedLegacyEncryptedArtifact
            } else {
                PersistenceErrorCode::StartupLoadFailure
            },
            message: err.to_string(),
            remediation: if legacy {
                "Remove legacy encrypted snapshots or migrate to plaintext snapshot format."
                    .to_string()
            } else {
                "Inspect persistence backend/storage path and recover from latest valid snapshot."
                    .to_string()
            },
        });
        tracing::warn!(
            event = EVENT_DEGRADED_TRANSITION,
            mode = self.mode.as_str(),
            state = self.state.as_str(),
            degraded = self.degraded,
            error_code = self
                .last_error
                .as_ref()
                .map_or("unknown", |error| error.code.as_str()),
            error = self
                .last_error
                .as_ref()
                .map_or("unknown", |error| error.message.as_str())
        );
    }

    pub fn strict_init_failure(&mut self, err: impl Into<String>) {
        self.state = PersistenceState::Failed;
        self.degraded = true;
        self.last_recovery_outcome = Some(RecoveryHealthOutcome::StrictInitFailure);
        self.last_error = Some(PersistenceErrorInfo {
            code: PersistenceErrorCode::StrictInitializationFailure,
            message: err.into(),
            remediation: "Fix strict initialization prerequisites (manifest/store) and restart."
                .to_string(),
        });
        tracing::error!(
            event = EVENT_INIT_FAILURE,
            mode = self.mode.as_str(),
            state = self.state.as_str(),
            degraded = self.degraded,
            error_code = PersistenceErrorCode::StrictInitializationFailure.as_str(),
            error = self
                .last_error
                .as_ref()
                .map_or("unknown", |error| error.message.as_str())
        );
    }

    pub fn checkpoint_succeeded(&mut self) {
        if matches!(self.state, PersistenceState::Degraded) && self.degraded {
            tracing::info!(
                event = EVENT_DEGRADED_TRANSITION,
                mode = self.mode.as_str(),
                reason = "checkpoint_self_healed",
                from = "degraded",
                to = "ready"
            );
            self.state = PersistenceState::Ready;
            self.degraded = false;
            self.last_error = None;
        } else if !self.degraded {
            self.state = PersistenceState::Ready;
            self.last_error = None;
        }
        tracing::info!(
            event = EVENT_CHECKPOINT_SUCCESS,
            mode = self.mode.as_str(),
            state = self.state.as_str(),
            degraded = self.degraded
        );
    }

    pub fn checkpoint_failed(&mut self, err: &PersistenceBackendError, strict_mode: bool) {
        self.last_error = Some(PersistenceErrorInfo {
            code: PersistenceErrorCode::CheckpointFailure,
            message: err.to_string(),
            remediation: "Retry checkpoint and inspect backend I/O/log output for root cause."
                .to_string(),
        });

        if strict_mode {
            self.state = PersistenceState::Failed;
            self.degraded = true;
            tracing::error!(
                event = EVENT_CHECKPOINT_FAILURE,
                mode = self.mode.as_str(),
                state = self.state.as_str(),
                degraded = self.degraded,
                error_code = PersistenceErrorCode::CheckpointFailure.as_str(),
                error = self
                    .last_error
                    .as_ref()
                    .map_or("unknown", |error| error.message.as_str())
            );
        } else {
            self.state = PersistenceState::Degraded;
            self.degraded = true;
            tracing::warn!(
                event = EVENT_CHECKPOINT_FAILURE,
                mode = self.mode.as_str(),
                state = self.state.as_str(),
                degraded = self.degraded,
                error_code = PersistenceErrorCode::CheckpointFailure.as_str(),
                error = self
                    .last_error
                    .as_ref()
                    .map_or("unknown", |error| error.message.as_str())
            );
        }
    }

    pub fn apply_budget_decision(&mut self, decision: BudgetDecision) {
        let previous = self.budget_pressure;
        match decision {
            BudgetDecision::BelowWarning => {
                self.budget_pressure = BudgetPressure::Normal;
            }
            BudgetDecision::Warning80 => {
                self.budget_pressure = BudgetPressure::Warning;
                self.last_error = Some(PersistenceErrorInfo {
                    code: PersistenceErrorCode::BudgetWarning,
                    message: "persistence storage crossed warning threshold".to_string(),
                    remediation: "Review retention/checkpoint policy to reduce snapshot churn."
                        .to_string(),
                });
            }
            BudgetDecision::Warning90 => {
                self.budget_pressure = BudgetPressure::Critical;
                self.last_error = Some(PersistenceErrorInfo {
                    code: PersistenceErrorCode::BudgetCritical,
                    message: "persistence storage crossed critical threshold".to_string(),
                    remediation:
                        "Delete stale snapshots or increase storage budget before capacity is hit."
                            .to_string(),
                });
            }
            BudgetDecision::StrictFailAtCapacity | BudgetDecision::DegradedSkipAtCapacity => {
                self.budget_pressure = BudgetPressure::AtCapacity;
                self.last_error = Some(PersistenceErrorInfo {
                    code: PersistenceErrorCode::BudgetAtCapacity,
                    message: "persistence storage budget exhausted".to_string(),
                    remediation:
                        "Free storage or adjust retention budget/checkpoint frequency immediately."
                            .to_string(),
                });
            }
        }

        if previous != self.budget_pressure {
            tracing::warn!(
                event = EVENT_BUDGET_THRESHOLD,
                mode = self.mode.as_str(),
                state = self.state.as_str(),
                degraded = self.degraded,
                budget_pressure = self.budget_pressure.as_str()
            );
        }
    }
}

impl PersistenceMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PersistenceMode::Strict => "strict",
            PersistenceMode::Degraded => "degraded",
        }
    }
}

impl PersistenceState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PersistenceState::StartingUp => "starting_up",
            PersistenceState::Ready => "ready",
            PersistenceState::Degraded => "degraded",
            PersistenceState::Failed => "failed",
        }
    }
}

impl BudgetPressure {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetPressure::Normal => "normal",
            BudgetPressure::Warning => "warning",
            BudgetPressure::Critical => "critical",
            BudgetPressure::AtCapacity => "at_capacity",
        }
    }
}

impl PersistenceErrorCode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PersistenceErrorCode::StartupLoadFailure => "startup_load_failure",
            PersistenceErrorCode::StrictInitializationFailure => "strict_initialization_failure",
            PersistenceErrorCode::CheckpointFailure => "checkpoint_failure",
            PersistenceErrorCode::UnsupportedLegacyEncryptedArtifact => {
                "unsupported_legacy_encrypted_artifact"
            }
            PersistenceErrorCode::BudgetWarning => "budget_warning",
            PersistenceErrorCode::BudgetCritical => "budget_critical",
            PersistenceErrorCode::BudgetAtCapacity => "budget_at_capacity",
        }
    }
}

#[must_use]
pub fn is_legacy_artifact_error(err: &PersistenceBackendError) -> bool {
    matches!(
        err,
        PersistenceBackendError::UnsupportedLegacyEncryptedArtifact { .. }
            | PersistenceBackendError::DegradedSkippedLegacyArtifact { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_health_startup_transitions_cover_loaded_and_empty() {
        let mut health = PersistenceHealth::new(PersistenceMode::Degraded);
        health.startup_loaded_snapshot();
        assert_eq!(health.state, PersistenceState::Ready);
        assert_eq!(
            health.last_recovery_outcome,
            Some(RecoveryHealthOutcome::LoadedSnapshot)
        );

        health.startup_empty_store();
        assert_eq!(health.state, PersistenceState::Ready);
        assert_eq!(
            health.last_recovery_outcome,
            Some(RecoveryHealthOutcome::EmptyStore)
        );
    }

    #[test]
    fn persistence_health_checkpoint_failure_marks_degraded_or_failed() {
        let mut health = PersistenceHealth::new(PersistenceMode::Degraded);
        let error = PersistenceBackendError::Operation("checkpoint failed".to_string());
        health.checkpoint_failed(&error, false);
        assert_eq!(health.state, PersistenceState::Degraded);
        assert!(health.degraded);
        assert_eq!(
            health.last_error.as_ref().map(|err| err.code),
            Some(PersistenceErrorCode::CheckpointFailure)
        );
        health.checkpoint_succeeded();
        assert_eq!(health.state, PersistenceState::Ready);
        assert!(!health.degraded);
        assert!(health.last_error.is_none());

        let mut strict_health = PersistenceHealth::new(PersistenceMode::Strict);
        let strict_error = PersistenceBackendError::Operation("checkpoint failed".to_string());
        strict_health.checkpoint_failed(&strict_error, true);
        assert_eq!(strict_health.state, PersistenceState::Failed);
        assert!(strict_health.degraded);
        assert!(strict_health.last_error.is_some());
        strict_health.checkpoint_succeeded();
        assert_eq!(strict_health.state, PersistenceState::Failed);
        assert!(strict_health.degraded);
        assert!(strict_health.last_error.is_some());

        let mut healthy = PersistenceHealth::new(PersistenceMode::Degraded);
        healthy.startup_loaded_snapshot();
        healthy.checkpoint_succeeded();
        assert_eq!(healthy.state, PersistenceState::Ready);
        assert!(healthy.last_error.is_none());
    }

    #[test]
    fn persistence_health_unsupported_legacy_artifact_sets_actionable_error() {
        let mut health = PersistenceHealth::new(PersistenceMode::Degraded);
        let legacy_error = PersistenceBackendError::DegradedSkippedLegacyArtifact {
            path: "store/legacy.snapshot".to_string(),
        };
        health.startup_fallback(&legacy_error);

        assert_eq!(health.state, PersistenceState::Degraded);
        assert_eq!(
            health.last_recovery_outcome,
            Some(RecoveryHealthOutcome::UnsupportedLegacyEncryptedArtifact)
        );
        let error = health.last_error.expect("legacy error recorded");
        assert_eq!(
            error.code,
            PersistenceErrorCode::UnsupportedLegacyEncryptedArtifact
        );
        assert!(error.remediation.contains("plaintext snapshot format"));
    }
}
