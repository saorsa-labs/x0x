use crate::crdt::persistence::checkpoint::{run_checkpoint, CheckpointAction, CheckpointScheduler};
use crate::crdt::persistence::{
    CheckpointPolicy, PersistenceBackend, PersistenceBackendError, PersistenceSnapshot,
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
}

impl<B: PersistenceBackend> AgentCheckpointApi<B> {
    #[must_use]
    pub fn new(
        backend: B,
        entity_id: impl Into<String>,
        schema_version: u32,
        policy: CheckpointPolicy,
    ) -> Self {
        Self {
            backend,
            entity_id: entity_id.into(),
            schema_version,
            scheduler: CheckpointScheduler::new(policy),
            started_at: Instant::now(),
        }
    }

    #[must_use]
    pub fn checkpoint_policy(&self) -> &CheckpointPolicy {
        self.scheduler.policy()
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
                run_checkpoint(
                    &self.backend,
                    &self.entity_id,
                    self.schema_version,
                    self.scheduler.mutation_count(),
                    reason,
                    payload,
                )
                .await?;
                self.scheduler.mark_checkpoint(now);
                Ok(ExplicitCheckpointOutcome::Persisted)
            }
            CheckpointAction::SkipClean => Ok(ExplicitCheckpointOutcome::NoopClean),
            CheckpointAction::SkipDebounced => Ok(ExplicitCheckpointOutcome::Debounced),
            CheckpointAction::SkipPolicy => Ok(ExplicitCheckpointOutcome::NoopClean),
        }
    }

    pub async fn load_latest(&self) -> Result<PersistenceSnapshot, AgentApiError> {
        self.backend
            .load_latest(&self.entity_id)
            .await
            .map_err(AgentApiError::Backend)
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
                run_checkpoint(
                    &self.backend,
                    &self.entity_id,
                    self.schema_version,
                    self.scheduler.mutation_count(),
                    reason,
                    payload,
                )
                .await?;
                self.scheduler.mark_checkpoint(now);
                Ok(AutomaticCheckpointOutcome::Persisted)
            }
            CheckpointAction::SkipDebounced => Ok(AutomaticCheckpointOutcome::Debounced),
            CheckpointAction::SkipClean | CheckpointAction::SkipPolicy => {
                Ok(AutomaticCheckpointOutcome::NotDue)
            }
        }
    }
}
