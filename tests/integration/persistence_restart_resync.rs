use saorsa_gossip_types::PeerId;
use tokio::time::{sleep, Duration};
use x0x::crdt::persistence::{
    backends::file_backend::FileSnapshotBackend, recover_task_list_startup, CheckpointReason,
    CheckpointRequest, PersistenceBackend, PersistenceMode, PersistencePolicy, RecoveryOutcome,
};
use x0x::crdt::{TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;

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
        10,
        AgentId([7; 32]),
        1000 + u64::from(id_byte),
    );
    TaskItem::new(TaskId::from_bytes([id_byte; 32]), metadata, peer_id)
}

#[tokio::test]
async fn restart_resync_recovers_snapshot_and_converges_after_merge() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Strict);
    let entity_id = "project-restart-resync";
    let peer_id = peer(1);
    let list_id = list_id(1);

    let mut baseline = TaskList::new(list_id, "restart".to_string(), peer_id);
    baseline
        .add_task(make_task(1, peer_id), peer_id, 1)
        .expect("seed baseline task");

    backend
        .checkpoint(
            &CheckpointRequest {
                entity_id: entity_id.to_string(),
                mutation_count: 1,
                reason: CheckpointReason::ExplicitRequest,
            },
            &x0x::crdt::persistence::PersistenceSnapshot {
                entity_id: entity_id.to_string(),
                schema_version: 2,
                payload: baseline
                    .to_persistence_payload()
                    .expect("serialize baseline"),
            },
        )
        .await
        .expect("write baseline checkpoint");

    let mut live_peer = baseline.clone();
    live_peer
        .add_task(make_task(2, peer_id), peer_id, 2)
        .expect("add update while peer was offline");

    let recovered = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            mode: PersistenceMode::Strict,
            strict_initialization: x0x::crdt::persistence::StrictInitializationPolicy {
                initialize_if_missing: true,
            },
            ..PersistencePolicy::default()
        },
        temp.path(),
        entity_id,
        TaskList::new(list_id, "restart".to_string(), peer_id),
    )
    .await
    .expect("recover checkpoint");

    assert_eq!(recovered.recovery.outcome, RecoveryOutcome::LoadedSnapshot);

    let mut converged = recovered.task_list;
    converged.merge(&live_peer).expect("merge live updates");
    assert_eq!(converged.task_count(), 2);
}

#[tokio::test]
async fn restart_resync_converges_with_delayed_out_of_order_state_delivery() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Degraded);
    let entity_id = "project-out-of-order";
    let peer_id = peer(2);
    let list_id = list_id(2);

    let mut persisted = TaskList::new(list_id, "ordering".to_string(), peer_id);
    persisted
        .add_task(make_task(1, peer_id), peer_id, 1)
        .expect("seed persisted task");

    backend
        .checkpoint(
            &CheckpointRequest {
                entity_id: entity_id.to_string(),
                mutation_count: 1,
                reason: CheckpointReason::ExplicitRequest,
            },
            &x0x::crdt::persistence::PersistenceSnapshot {
                entity_id: entity_id.to_string(),
                schema_version: 2,
                payload: persisted
                    .to_persistence_payload()
                    .expect("serialize persisted"),
            },
        )
        .await
        .expect("write persisted checkpoint");

    let mut delayed = persisted.clone();
    delayed
        .add_task(make_task(2, peer_id), peer_id, 2)
        .expect("add delayed update");

    let mut newest = delayed.clone();
    newest
        .add_task(make_task(3, peer_id), peer_id, 3)
        .expect("add newest update");

    sleep(Duration::from_millis(2)).await;

    let recovered = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            ..PersistencePolicy::default()
        },
        temp.path(),
        entity_id,
        TaskList::new(list_id, "ordering".to_string(), peer_id),
    )
    .await
    .expect("recover persisted state");

    let mut converged = recovered.task_list;
    converged
        .merge(&newest)
        .expect("apply newest delivery first");
    converged
        .merge(&delayed)
        .expect("apply delayed delivery second");

    assert_eq!(converged.task_count(), newest.task_count());
    assert_eq!(converged.task_count(), 3);
}
