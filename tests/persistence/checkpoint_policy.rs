use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use x0x::crdt::persistence::{
    CheckpointAction, CheckpointPolicy, CheckpointReason, CheckpointRequest, CheckpointScheduler,
    PersistenceBackend, PersistenceBackendError, PersistenceSnapshot,
};
use x0x::runtime::{AgentCheckpointApi, ExplicitCheckpointOutcome};

#[derive(Clone, Default)]
struct CountingBackend {
    writes: Arc<Mutex<Vec<CheckpointReason>>>,
}

impl CountingBackend {
    fn write_count(&self) -> usize {
        self.writes
            .lock()
            .expect("counting backend lock")
            .len()
    }

    fn reasons(&self) -> Vec<CheckpointReason> {
        self.writes
            .lock()
            .expect("counting backend lock")
            .clone()
    }
}

#[async_trait]
impl PersistenceBackend for CountingBackend {
    async fn checkpoint(
        &self,
        request: &CheckpointRequest,
        _snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError> {
        self.writes
            .lock()
            .map_err(|_| PersistenceBackendError::Operation("lock poisoned".to_string()))?
            .push(request.reason.clone());
        Ok(())
    }

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError> {
        Err(PersistenceBackendError::SnapshotNotFound(
            entity_id.to_string(),
        ))
    }

    async fn delete_entity(&self, _entity_id: &str) -> Result<(), PersistenceBackendError> {
        Ok(())
    }
}

#[test]
fn checkpoint_policy_operation_threshold_triggers_at_32_mutations() {
    let mut scheduler = CheckpointScheduler::new(CheckpointPolicy::default());
    let start = Duration::from_secs(0);

    for i in 0..31 {
        scheduler.record_mutation(start + Duration::from_secs(i));
        assert_eq!(
            scheduler.action_after_mutation(start + Duration::from_secs(i)),
            CheckpointAction::SkipPolicy
        );
    }

    scheduler.record_mutation(start + Duration::from_secs(31));
    assert_eq!(
        scheduler.action_after_mutation(start + Duration::from_secs(31)),
        CheckpointAction::Persist {
            reason: CheckpointReason::MutationThreshold
        }
    );
}

#[test]
fn checkpoint_policy_dirty_time_floor_triggers_after_five_minutes_when_dirty() {
    let mut scheduler = CheckpointScheduler::new(CheckpointPolicy::default());
    scheduler.record_mutation(Duration::from_secs(0));

    assert_eq!(
        scheduler.action_on_timer(Duration::from_secs(299)),
        CheckpointAction::SkipPolicy
    );

    assert_eq!(
        scheduler.action_on_timer(Duration::from_secs(300)),
        CheckpointAction::Persist {
            reason: CheckpointReason::DirtyTimeFloor
        }
    );
}

#[test]
fn checkpoint_policy_debounce_floor_blocks_repeated_checkpoints_for_two_seconds() {
    let mut scheduler = CheckpointScheduler::new(CheckpointPolicy::default());
    scheduler.record_mutation(Duration::from_secs(0));
    for i in 0..31 {
        scheduler.record_mutation(Duration::from_millis(10 * i));
    }
    assert_eq!(
        scheduler.action_after_mutation(Duration::from_secs(1)),
        CheckpointAction::Persist {
            reason: CheckpointReason::MutationThreshold
        }
    );
    scheduler.mark_checkpoint(Duration::from_secs(1));

    scheduler.record_mutation(Duration::from_secs(1));
    for i in 0..31 {
        scheduler.record_mutation(Duration::from_millis(1000 + (10 * i)));
    }

    assert_eq!(
        scheduler.action_after_mutation(Duration::from_secs(2)),
        CheckpointAction::SkipDebounced
    );
    assert_eq!(
        scheduler.action_after_mutation(Duration::from_secs(3)),
        CheckpointAction::Persist {
            reason: CheckpointReason::MutationThreshold
        }
    );
}

#[tokio::test]
async fn checkpoint_policy_explicit_request_api_honors_dirty_state_and_debounce() {
    let backend = CountingBackend::default();
    let backend_probe = backend.clone();
    let mut api = AgentCheckpointApi::new(
        backend,
        "entity-explicit",
        2,
        CheckpointPolicy {
            mutation_threshold: 1,
            dirty_time_floor: Duration::from_secs(300),
            debounce_floor: Duration::from_secs(60),
        },
    );

    let explicit_clean = api
        .request_explicit_checkpoint(vec![1, 2, 3])
        .await
        .expect("explicit on clean list");
    assert_eq!(explicit_clean, ExplicitCheckpointOutcome::NoopClean);

    api.record_mutation_and_maybe_checkpoint(vec![4, 5, 6])
        .await
        .expect("threshold checkpoint");

    let debounced = api
        .record_mutation_and_maybe_checkpoint(vec![7, 8, 9])
        .await
        .expect("debounced threshold attempt");
    assert_eq!(
        debounced,
        x0x::runtime::AutomaticCheckpointOutcome::Debounced
    );

    let explicit = api
        .request_explicit_checkpoint(vec![10, 11, 12])
        .await
        .expect("explicit while debounced");
    assert_eq!(explicit, ExplicitCheckpointOutcome::Debounced);
    assert_eq!(backend_probe.write_count(), 1);
    assert_eq!(
        backend_probe.reasons(),
        vec![CheckpointReason::MutationThreshold]
    );
}
