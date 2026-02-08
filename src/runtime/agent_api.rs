use crate::crdt::persistence::checkpoint::{run_checkpoint, CheckpointAction, CheckpointScheduler};
use crate::crdt::persistence::{
    CheckpointPolicy, PersistenceBackend, PersistenceBackendError, PersistenceHealth,
    PersistenceMode, PersistenceSnapshot,
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
}

pub struct AgentCheckpointApi<B: PersistenceBackend> {
    backend: B,
    entity_id: String,
    schema_version: u32,
    scheduler: CheckpointScheduler,
    started_at: Instant,
    health: PersistenceHealth,
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
        Self {
            backend,
            entity_id: entity_id.into(),
            schema_version,
            scheduler: CheckpointScheduler::new(policy),
            started_at: Instant::now(),
            health: PersistenceHealth::new(mode),
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
