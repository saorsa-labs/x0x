use crate::config::HostPolicyEnvelopeConfig;
use crate::crdt::persistence::checkpoint::{run_checkpoint, CheckpointAction, CheckpointScheduler};
use crate::crdt::persistence::{
    CheckpointFrequencyBounds, CheckpointFrequencyContract, CheckpointFrequencyUpdateRequest,
    CheckpointPolicy, PersistenceBackend, PersistenceBackendError, PersistenceHealth,
    PersistenceMode, PersistenceObservabilityContract, PersistencePolicy, PersistenceSnapshot,
    RetentionPolicy, StrictInitializationPolicy,
};
use crate::runtime::policy_bounds::{
    apply_checkpoint_frequency_update, PolicyBoundsError, RuntimeCheckpointPolicyUpdate,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplicitCheckpointOutcome {
    Persisted,
    NoopClean,
    Debounced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomaticCheckpointOutcome {
    Persisted,
    NotDue,
    Debounced,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentApiError {
    #[error("checkpoint backend error: {0}")]
    Backend(#[from] PersistenceBackendError),
    #[error("invalid runtime checkpoint controls request: {0}")]
    PolicyBounds(#[from] PolicyBoundsError),
}

pub struct AgentCheckpointApi<B: PersistenceBackend> {
    backend: B,
    entity_id: String,
    schema_version: u32,
    scheduler: CheckpointScheduler,
    started_at: Instant,
    health: PersistenceHealth,
    host_policy: HostPolicyEnvelopeConfig,
}

impl<B: PersistenceBackend> AgentCheckpointApi<B> {
    #[must_use]
    pub fn new(
        backend: B,
        entity_id: impl Into<String>,
        schema_version: u32,
        policy: CheckpointPolicy,
    ) -> Self {
        Self::new_with_mode(
            backend,
            entity_id,
            schema_version,
            PersistenceMode::Degraded,
            policy,
        )
    }

    #[must_use]
    pub fn new_with_mode(
        backend: B,
        entity_id: impl Into<String>,
        schema_version: u32,
        mode: PersistenceMode,
        policy: CheckpointPolicy,
    ) -> Self {
        let host_policy = fixed_host_policy_from_checkpoint_policy(&policy);
        Self::new_with_runtime_controls(
            backend,
            entity_id,
            schema_version,
            mode,
            policy,
            host_policy,
        )
    }

    #[must_use]
    pub fn new_with_runtime_controls(
        backend: B,
        entity_id: impl Into<String>,
        schema_version: u32,
        mode: PersistenceMode,
        policy: CheckpointPolicy,
        host_policy: HostPolicyEnvelopeConfig,
    ) -> Self {
        Self {
            backend,
            entity_id: entity_id.into(),
            schema_version,
            scheduler: CheckpointScheduler::new(policy),
            started_at: Instant::now(),
            health: PersistenceHealth::new(mode),
            host_policy,
        }
    }

    #[must_use]
    pub fn checkpoint_policy(&self) -> &CheckpointPolicy {
        self.scheduler.policy()
    }

    #[must_use]
    pub fn persistence_health(&self) -> PersistenceHealth {
        self.health.clone()
    }

    #[must_use]
    pub fn checkpoint_frequency_contract(&self) -> CheckpointFrequencyContract {
        let policy = self.scheduler.policy();
        CheckpointFrequencyContract {
            mutation_threshold: policy.mutation_threshold,
            dirty_time_floor_secs: policy.dirty_time_floor.as_secs(),
            debounce_floor_secs: policy.debounce_floor.as_secs(),
        }
    }

    #[must_use]
    pub fn checkpoint_frequency_bounds(&self) -> CheckpointFrequencyBounds {
        CheckpointFrequencyBounds {
            allow_runtime_checkpoint_frequency_adjustment: self
                .host_policy
                .allow_runtime_checkpoint_frequency_adjustment,
            min_mutation_threshold: self.host_policy.min_mutation_threshold,
            max_mutation_threshold: self.host_policy.max_mutation_threshold,
            min_dirty_time_floor_secs: self.host_policy.min_dirty_time_floor_secs,
            max_dirty_time_floor_secs: self.host_policy.max_dirty_time_floor_secs,
            min_debounce_floor_secs: self.host_policy.min_debounce_floor_secs,
            max_debounce_floor_secs: self.host_policy.max_debounce_floor_secs,
        }
    }

    #[must_use]
    pub fn observability_contract(&self) -> PersistenceObservabilityContract {
        PersistenceObservabilityContract {
            health: self.persistence_health(),
            checkpoint_frequency: self.checkpoint_frequency_contract(),
            checkpoint_frequency_bounds: self.checkpoint_frequency_bounds(),
        }
    }

    pub fn request_checkpoint_frequency_update(
        &mut self,
        update: CheckpointFrequencyUpdateRequest,
    ) -> Result<CheckpointFrequencyContract, AgentApiError> {
        let current_policy = PersistencePolicy {
            enabled: true,
            mode: self.health.mode,
            checkpoint: self.scheduler.policy().clone(),
            retention: RetentionPolicy::default(),
            strict_initialization: StrictInitializationPolicy {
                initialize_if_missing: false,
            },
        };

        let resolved = apply_checkpoint_frequency_update(
            &current_policy,
            &self.host_policy,
            &RuntimeCheckpointPolicyUpdate {
                mutation_threshold: update.mutation_threshold,
                dirty_time_floor: update.dirty_time_floor_secs.map(Duration::from_secs),
                debounce_floor: update.debounce_floor_secs.map(Duration::from_secs),
            },
        )?;

        self.scheduler.set_policy(resolved.checkpoint);
        Ok(self.checkpoint_frequency_contract())
    }

    pub async fn record_mutation_and_maybe_checkpoint(
        &mut self,
        payload: Vec<u8>,
    ) -> Result<AutomaticCheckpointOutcome, AgentApiError> {
        let now = self.now();
        self.scheduler.record_mutation(now);
        let action = self.scheduler.action_after_mutation(now);
        self.execute_automatic_action(action, payload, now).await
    }

    pub async fn maybe_checkpoint_from_timer(
        &mut self,
        payload: Vec<u8>,
    ) -> Result<AutomaticCheckpointOutcome, AgentApiError> {
        let now = self.now();
        let action = self.scheduler.action_on_timer(now);
        self.execute_automatic_action(action, payload, now).await
    }

    pub async fn request_explicit_checkpoint(
        &mut self,
        payload: Vec<u8>,
    ) -> Result<ExplicitCheckpointOutcome, AgentApiError> {
        let now = self.now();
        match self.scheduler.action_on_explicit_request(now) {
            CheckpointAction::Persist { reason } => {
                let persisted = run_checkpoint(
                    &self.backend,
                    &self.entity_id,
                    self.schema_version,
                    self.scheduler.mutation_count(),
                    reason,
                    payload,
                )
                .await;

                match persisted {
                    Ok(()) => {
                        self.scheduler.mark_checkpoint(now);
                        self.health.checkpoint_succeeded();
                        Ok(ExplicitCheckpointOutcome::Persisted)
                    }
                    Err(err) => {
                        self.health
                            .checkpoint_failed(&err, matches!(self.health.mode, PersistenceMode::Strict));
                        Err(AgentApiError::Backend(err))
                    }
                }
            }
            CheckpointAction::SkipClean => Ok(ExplicitCheckpointOutcome::NoopClean),
            CheckpointAction::SkipDebounced => Ok(ExplicitCheckpointOutcome::Debounced),
            CheckpointAction::SkipPolicy => Ok(ExplicitCheckpointOutcome::NoopClean),
        }
    }

    pub async fn load_latest(&mut self) -> Result<PersistenceSnapshot, AgentApiError> {
        let loaded = self.backend.load_latest(&self.entity_id).await;
        match loaded {
            Ok(snapshot) => {
                self.health.startup_loaded_snapshot();
                Ok(snapshot)
            }
            Err(PersistenceBackendError::SnapshotNotFound(_))
            | Err(PersistenceBackendError::NoLoadableSnapshot(_)) => {
                self.health.startup_empty_store();
                Err(AgentApiError::Backend(PersistenceBackendError::SnapshotNotFound(
                    self.entity_id.clone(),
                )))
            }
            Err(err) => {
                self.health.startup_fallback(&err);
                Err(AgentApiError::Backend(err))
            }
        }
    }

    fn now(&self) -> Duration {
        self.started_at.elapsed()
    }

    async fn execute_automatic_action(
        &mut self,
        action: CheckpointAction,
        payload: Vec<u8>,
        now: Duration,
    ) -> Result<AutomaticCheckpointOutcome, AgentApiError> {
        match action {
            CheckpointAction::Persist { reason } => {
                let persisted = run_checkpoint(
                    &self.backend,
                    &self.entity_id,
                    self.schema_version,
                    self.scheduler.mutation_count(),
                    reason,
                    payload,
                )
                .await;

                match persisted {
                    Ok(()) => {
                        self.scheduler.mark_checkpoint(now);
                        self.health.checkpoint_succeeded();
                        Ok(AutomaticCheckpointOutcome::Persisted)
                    }
                    Err(err) => {
                        self.health
                            .checkpoint_failed(&err, matches!(self.health.mode, PersistenceMode::Strict));
                        Err(AgentApiError::Backend(err))
                    }
                }
            }
            CheckpointAction::SkipDebounced => Ok(AutomaticCheckpointOutcome::Debounced),
            CheckpointAction::SkipClean | CheckpointAction::SkipPolicy => {
                Ok(AutomaticCheckpointOutcome::NotDue)
            }
        }
    }
}

fn fixed_host_policy_from_checkpoint_policy(policy: &CheckpointPolicy) -> HostPolicyEnvelopeConfig {
    HostPolicyEnvelopeConfig {
        allow_runtime_checkpoint_frequency_adjustment: false,
        min_mutation_threshold: policy.mutation_threshold,
        max_mutation_threshold: policy.mutation_threshold,
        min_dirty_time_floor_secs: policy.dirty_time_floor.as_secs(),
        max_dirty_time_floor_secs: policy.dirty_time_floor.as_secs(),
        min_debounce_floor_secs: policy.debounce_floor.as_secs(),
        max_debounce_floor_secs: policy.debounce_floor.as_secs(),
    }
}
