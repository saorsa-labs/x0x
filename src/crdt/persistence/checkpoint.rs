use crate::crdt::persistence::{
    CheckpointPolicy, CheckpointReason, CheckpointRequest, PersistenceBackend,
    PersistenceBackendError, PersistenceSnapshot,
};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointAction {
    Persist { reason: CheckpointReason },
    SkipClean,
    SkipDebounced,
    SkipPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointScheduler {
    policy: CheckpointPolicy,
    dirty_since: Option<Duration>,
    last_checkpoint_at: Option<Duration>,
    mutation_count: u64,
}

impl CheckpointScheduler {
    #[must_use]
    pub fn new(policy: CheckpointPolicy) -> Self {
        Self {
            policy,
            dirty_since: None,
            last_checkpoint_at: None,
            mutation_count: 0,
        }
    }

    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty_since.is_some()
    }

    #[must_use]
    pub fn mutation_count(&self) -> u64 {
        self.mutation_count
    }

    #[must_use]
    pub fn policy(&self) -> &CheckpointPolicy {
        &self.policy
    }

    pub fn set_policy(&mut self, policy: CheckpointPolicy) {
        self.policy = policy;
    }

    pub fn record_mutation(&mut self, now: Duration) {
        if self.dirty_since.is_none() {
            self.dirty_since = Some(now);
        }
        self.mutation_count = self.mutation_count.saturating_add(1);
    }

    #[must_use]
    pub fn action_after_mutation(&self, now: Duration) -> CheckpointAction {
        if !self.is_dirty() {
            return CheckpointAction::SkipClean;
        }

        if self.mutation_count < u64::from(self.policy.mutation_threshold) {
            return CheckpointAction::SkipPolicy;
        }

        if !self.debounce_satisfied(now) {
            return CheckpointAction::SkipDebounced;
        }

        CheckpointAction::Persist {
            reason: CheckpointReason::MutationThreshold,
        }
    }

    #[must_use]
    pub fn action_on_timer(&self, now: Duration) -> CheckpointAction {
        let Some(dirty_since) = self.dirty_since else {
            return CheckpointAction::SkipClean;
        };

        if now < dirty_since + self.policy.dirty_time_floor {
            return CheckpointAction::SkipPolicy;
        }

        if !self.debounce_satisfied(now) {
            return CheckpointAction::SkipDebounced;
        }

        CheckpointAction::Persist {
            reason: CheckpointReason::DirtyTimeFloor,
        }
    }

    #[must_use]
    pub fn action_on_explicit_request(&self, now: Duration) -> CheckpointAction {
        if !self.is_dirty() {
            return CheckpointAction::SkipClean;
        }

        if !self.debounce_satisfied(now) {
            return CheckpointAction::SkipDebounced;
        }

        CheckpointAction::Persist {
            reason: CheckpointReason::ExplicitRequest,
        }
    }

    pub fn mark_checkpoint(&mut self, now: Duration) {
        self.last_checkpoint_at = Some(now);
        self.dirty_since = None;
        self.mutation_count = 0;
    }

    fn debounce_satisfied(&self, now: Duration) -> bool {
        let Some(last) = self.last_checkpoint_at else {
            return true;
        };
        now >= last + self.policy.debounce_floor
    }
}

pub async fn run_checkpoint<B: PersistenceBackend>(
    backend: &B,
    entity_id: &str,
    schema_version: u32,
    mutation_count: u64,
    reason: CheckpointReason,
    payload: Vec<u8>,
) -> Result<(), PersistenceBackendError> {
    backend
        .checkpoint(
            &CheckpointRequest {
                entity_id: entity_id.to_string(),
                mutation_count,
                reason,
            },
            &PersistenceSnapshot {
                entity_id: entity_id.to_string(),
                schema_version,
                payload,
            },
        )
        .await
}
