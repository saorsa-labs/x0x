use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use x0x::crdt::persistence::{
    recover_task_list_startup, CheckpointReason, CheckpointRequest, PersistenceBackend,
    PersistenceBackendError, PersistencePolicy, PersistenceSnapshot, RecoveryOutcome,
};
use x0x::crdt::{TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;
use saorsa_gossip_types::PeerId;

#[derive(Clone, Default)]
struct InMemoryBackend {
    snapshots: Arc<Mutex<HashMap<String, PersistenceSnapshot>>>,
}

impl InMemoryBackend {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PersistenceBackend for InMemoryBackend {
    async fn checkpoint(
        &self,
        request: &CheckpointRequest,
        snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError> {
        let mut guard = self
            .snapshots
            .lock()
            .map_err(|_| PersistenceBackendError::Operation("lock poisoned".to_string()))?;
        guard.insert(request.entity_id.clone(), snapshot.clone());
        Ok(())
    }

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError> {
        let guard = self
            .snapshots
            .lock()
            .map_err(|_| PersistenceBackendError::Operation("lock poisoned".to_string()))?;
        guard
            .get(entity_id)
            .cloned()
            .ok_or_else(|| PersistenceBackendError::SnapshotNotFound(entity_id.to_string()))
    }

    async fn delete_entity(&self, entity_id: &str) -> Result<(), PersistenceBackendError> {
        let mut guard = self
            .snapshots
            .lock()
            .map_err(|_| PersistenceBackendError::Operation("lock poisoned".to_string()))?;
        guard.remove(entity_id);
        Ok(())
    }
}

fn peer(n: u8) -> PeerId {
    PeerId::new([n; 32])
}

fn list_id(n: u8) -> TaskListId {
    TaskListId::new([n; 32])
}

fn make_task(id_byte: u8, peer_id: PeerId) -> TaskItem {
    let metadata = TaskMetadata::new(
        format!("Task {id_byte}"),
        format!("Description {id_byte}"),
        100,
        AgentId([7; 32]),
        1000,
    );
    TaskItem::new(TaskId::from_bytes([id_byte; 32]), metadata, peer_id)
}

#[tokio::test]
async fn startup_recovery_loads_latest_snapshot_when_present() {
    let backend = InMemoryBackend::new();
    let entity_id = "project-alpha";
    let peer_id = peer(1);
    let mut task_list = TaskList::new(list_id(1), "alpha".to_string(), peer_id);
    task_list
        .add_task(make_task(1, peer_id), peer_id, 1)
        .expect("add task");

    backend
        .checkpoint(
            &CheckpointRequest {
                entity_id: entity_id.to_string(),
                mutation_count: 1,
                reason: CheckpointReason::ExplicitRequest,
            },
            &PersistenceSnapshot {
                entity_id: entity_id.to_string(),
                schema_version: 2,
                payload: task_list.to_persistence_payload().expect("serialize list"),
            },
        )
        .await
        .expect("checkpoint");

    let recovered = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            ..PersistencePolicy::default()
        },
        tempfile::tempdir().expect("temp dir").path(),
        entity_id,
        TaskList::new(list_id(9), "empty".to_string(), peer(9)),
    )
    .await
    .expect("recover task list");

    assert_eq!(recovered.recovery.outcome, RecoveryOutcome::LoadedSnapshot);
    assert_eq!(recovered.task_list.task_count(), 1);
}

#[tokio::test]
async fn startup_recovery_stale_snapshot_rejoins_and_converges_via_merge_path() {
    let backend = InMemoryBackend::new();
    let entity_id = "project-beta";
    let peer_id = peer(2);

    let mut stale = TaskList::new(list_id(2), "beta".to_string(), peer_id);
    stale
        .add_task(make_task(1, peer_id), peer_id, 1)
        .expect("seed stale snapshot");

    backend
        .checkpoint(
            &CheckpointRequest {
                entity_id: entity_id.to_string(),
                mutation_count: 1,
                reason: CheckpointReason::ExplicitRequest,
            },
            &PersistenceSnapshot {
                entity_id: entity_id.to_string(),
                schema_version: 2,
                payload: stale.to_persistence_payload().expect("serialize stale"),
            },
        )
        .await
        .expect("checkpoint stale snapshot");

    let mut live_peer = stale.clone();
    live_peer
        .add_task(make_task(2, peer_id), peer_id, 2)
        .expect("append live task");

    let mut recovered = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            ..PersistencePolicy::default()
        },
        tempfile::tempdir().expect("temp dir").path(),
        entity_id,
        TaskList::new(list_id(2), "beta".to_string(), peer_id),
    )
    .await
    .expect("recover stale snapshot")
    .task_list;

    recovered.merge(&live_peer).expect("merge anti-entropy payload");
    assert_eq!(recovered.task_count(), live_peer.task_count());
}

#[tokio::test]
async fn startup_recovery_empty_store_is_degraded_mode_safe() {
    let backend = InMemoryBackend::new();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let recovered = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            ..PersistencePolicy::default()
        },
        temp_dir.path(),
        "project-empty",
        TaskList::new(list_id(3), "new".to_string(), peer(3)),
    )
    .await
    .expect("degraded mode startup should proceed");

    assert_eq!(recovered.recovery.outcome, RecoveryOutcome::EmptyStore);
    assert_eq!(recovered.task_list.task_count(), 0);
}
