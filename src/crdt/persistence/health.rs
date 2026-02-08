use crate::crdt::persistence::{BudgetDecision, PersistenceBackendError, PersistenceMode};

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
    }

    pub fn startup_empty_store(&mut self) {
        self.state = PersistenceState::Ready;
        self.degraded = false;
        self.last_recovery_outcome = Some(RecoveryHealthOutcome::EmptyStore);
        self.last_error = None;
    }

    pub fn startup_fallback(&mut self, err: &PersistenceBackendError) {
        let legacy = is_legacy_artifact_error(&err);
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
    }

    pub fn checkpoint_succeeded(&mut self) {
        if !self.degraded {
            self.state = PersistenceState::Ready;
            self.last_error = None;
        }
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
        } else {
            self.state = PersistenceState::Degraded;
            self.degraded = true;
        }
    }

    pub fn apply_budget_decision(&mut self, decision: BudgetDecision) {
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
        assert_eq!(health.state, PersistenceState::Degraded);

        let mut strict_health = PersistenceHealth::new(PersistenceMode::Strict);
        let strict_error = PersistenceBackendError::Operation("checkpoint failed".to_string());
        strict_health.checkpoint_failed(&strict_error, true);
        assert_eq!(strict_health.state, PersistenceState::Failed);
        assert!(strict_health.degraded);

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
