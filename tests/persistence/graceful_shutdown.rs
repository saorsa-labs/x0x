use async_trait::async_trait;
use saorsa_gossip_types::PeerId;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use x0x::crdt::persistence::{
    recover_task_list_startup, CheckpointPolicy, CheckpointRequest, CheckpointScheduler,
    OrchestratorError, PersistenceBackend, PersistenceBackendError, PersistenceMode,
    PersistencePolicy, PersistenceSnapshot, RecoveryState,
};
use x0x::crdt::{TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;
use x0x::runtime::{graceful_shutdown, GracefulShutdownResult};

#[derive(Clone)]
struct ToggleBackend {
    fail_checkpoints: bool,
    snapshot: Arc<Mutex<Option<PersistenceSnapshot>>>,
}

impl ToggleBackend {
    fn failing() -> Self {
        Self {
            fail_checkpoints: true,
            snapshot: Arc::new(Mutex::new(None)),
        }
    }

    fn healthy() -> Self {
        Self {
            fail_checkpoints: false,
            snapshot: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl PersistenceBackend for ToggleBackend {
    async fn checkpoint(
        &self,
        _request: &CheckpointRequest,
        snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError> {
        if self.fail_checkpoints {
            return Err(PersistenceBackendError::Operation(
                "simulated checkpoint failure".to_string(),
            ));
        }

        self.snapshot
            .lock()
            .map_err(|_| PersistenceBackendError::Operation("lock poisoned".to_string()))?
            .replace(snapshot.clone());
        Ok(())
    }

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError> {
        self.snapshot
            .lock()
            .map_err(|_| PersistenceBackendError::Operation("lock poisoned".to_string()))?
            .clone()
            .ok_or_else(|| PersistenceBackendError::SnapshotNotFound(entity_id.to_string()))
    }

    async fn delete_entity(&self, _entity_id: &str) -> Result<(), PersistenceBackendError> {
        Ok(())
    }
}

fn list_id(n: u8) -> TaskListId {
    TaskListId::new([n; 32])
}

fn peer(n: u8) -> PeerId {
    PeerId::new([n; 32])
}

fn task(id_byte: u8, peer_id: PeerId) -> TaskItem {
    let metadata = TaskMetadata::new(
        format!("Task {id_byte}"),
        format!("Description {id_byte}"),
        80,
        AgentId([id_byte; 32]),
        1200,
    );
    TaskItem::new(TaskId::from_bytes([id_byte; 32]), metadata, peer_id)
}

#[tokio::test]
async fn graceful_shutdown_strict_mode_returns_error_on_checkpoint_failure() {
    let backend = ToggleBackend::failing();
    let mut scheduler = CheckpointScheduler::new(CheckpointPolicy::default());
    scheduler.record_mutation(Duration::from_secs(1));
    let mut recovery = RecoveryState::loaded();

    let err = graceful_shutdown(
        &backend,
        &PersistencePolicy {
            enabled: true,
            mode: PersistenceMode::Strict,
            strict_initialization: x0x::crdt::persistence::StrictInitializationPolicy {
                initialize_if_missing: true,
            },
            ..PersistencePolicy::default()
        },
        &mut scheduler,
        &mut recovery,
        "shutdown-strict",
        2,
        vec![1, 2, 3],
        Duration::from_secs(5),
    )
    .await
    .expect_err("strict mode must fail");

    assert!(matches!(err, OrchestratorError::Checkpoint(_)));
}

#[tokio::test]
async fn graceful_shutdown_degraded_mode_continues_and_marks_health_degraded() {
    let backend = ToggleBackend::failing();
    let mut scheduler = CheckpointScheduler::new(CheckpointPolicy::default());
    scheduler.record_mutation(Duration::from_secs(1));
    let mut recovery = RecoveryState::loaded();

    let result = graceful_shutdown(
        &backend,
        &PersistencePolicy {
            enabled: true,
            mode: PersistenceMode::Degraded,
            ..PersistencePolicy::default()
        },
        &mut scheduler,
        &mut recovery,
        "shutdown-degraded",
        2,
        vec![1, 2, 3],
        Duration::from_secs(5),
    )
    .await
    .expect("degraded mode continues");

    assert_eq!(result, GracefulShutdownResult::ContinuedInDegradedMode);
    assert!(recovery.degraded);
    assert!(recovery.last_error.is_some());
}

#[tokio::test]
async fn graceful_shutdown_success_persists_state_for_restart_recovery() {
    let backend = ToggleBackend::healthy();
    let peer_id = peer(9);
    let mut list = TaskList::new(list_id(9), "restartable".to_string(), peer_id);
    list.add_task(task(1, peer_id), peer_id, 1)
        .expect("add task before shutdown");

    let mut scheduler = CheckpointScheduler::new(CheckpointPolicy::default());
    scheduler.record_mutation(Duration::from_secs(2));
    let mut recovery = RecoveryState::loaded();

    let shutdown = graceful_shutdown(
        &backend,
        &PersistencePolicy {
            enabled: true,
            ..PersistencePolicy::default()
        },
        &mut scheduler,
        &mut recovery,
        "shutdown-restart",
        2,
        list.to_persistence_payload().expect("serialize list"),
        Duration::from_secs(10),
    )
    .await
    .expect("graceful shutdown checkpoint");
    assert_eq!(shutdown, GracefulShutdownResult::CheckpointPersisted);

    let recovered = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            ..PersistencePolicy::default()
        },
        tempfile::tempdir().expect("temp dir").path(),
        "shutdown-restart",
        TaskList::new(list_id(9), "restartable".to_string(), peer_id),
    )
    .await
    .expect("restart recovery");
    assert_eq!(recovered.task_list.task_count(), 1);
    assert_eq!(
        recovered.recovery.outcome,
        x0x::crdt::persistence::RecoveryOutcome::LoadedSnapshot
    );
}
