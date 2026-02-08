use async_trait::async_trait;
use std::io;
use x0x::crdt::persistence::{
    recover_task_list_startup, CheckpointRequest, PersistenceBackend, PersistenceBackendError,
    PersistenceMode, PersistencePolicy, PersistenceSnapshot, RecoveryOutcome,
};
use x0x::crdt::{TaskId, TaskItem, TaskList, TaskListId, TaskMetadata};
use x0x::identity::AgentId;
use saorsa_gossip_types::PeerId;

struct FailingLoadBackend {
    error: PersistenceBackendError,
}

#[async_trait]
impl PersistenceBackend for FailingLoadBackend {
    async fn checkpoint(
        &self,
        _request: &CheckpointRequest,
        _snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError> {
        Ok(())
    }

    async fn load_latest(
        &self,
        _entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError> {
        Err(match &self.error {
            PersistenceBackendError::Io(_) => {
                PersistenceBackendError::Io(io::Error::other("simulated io outage"))
            }
            PersistenceBackendError::Operation(msg) => PersistenceBackendError::Operation(msg.clone()),
            other => PersistenceBackendError::Operation(other.to_string()),
        })
    }

    async fn delete_entity(&self, _entity_id: &str) -> Result<(), PersistenceBackendError> {
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
        10,
        AgentId([9; 32]),
        2000 + u64::from(id_byte),
    );
    TaskItem::new(TaskId::from_bytes([id_byte; 32]), metadata, peer_id)
}

#[tokio::test]
async fn mixed_mode_recovery_degraded_fallback_still_allows_peer_merge() {
    let backend = FailingLoadBackend {
        error: PersistenceBackendError::Io(io::Error::other("simulated io failure")),
    };
    let peer_id = peer(4);
    let id = list_id(4);

    let mut non_persistent_peer = TaskList::new(id, "shared".to_string(), peer_id);
    non_persistent_peer
        .add_task(make_task(1, peer_id), peer_id, 1)
        .expect("add remote task one");
    non_persistent_peer
        .add_task(make_task(2, peer_id), peer_id, 2)
        .expect("add remote task two");

    let recovered = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            mode: PersistenceMode::Degraded,
            ..PersistencePolicy::default()
        },
        tempfile::tempdir().expect("temp dir").path(),
        "mixed-mode-list",
        TaskList::new(id, "shared".to_string(), peer_id),
    )
    .await
    .expect("degraded mode should continue with fallback");

    assert_eq!(recovered.recovery.outcome, RecoveryOutcome::DegradedFallback);

    let mut converged = recovered.task_list;
    converged
        .merge(&non_persistent_peer)
        .expect("merge from non-persistent peer");
    assert_eq!(converged.task_count(), non_persistent_peer.task_count());
}

#[tokio::test]
async fn mixed_mode_recovery_strict_mode_blocks_on_io_failure() {
    let backend = FailingLoadBackend {
        error: PersistenceBackendError::Operation("No space left on device".to_string()),
    };
    let peer_id = peer(5);
    let id = list_id(5);

    let err = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            mode: PersistenceMode::Strict,
            strict_initialization: x0x::crdt::persistence::StrictInitializationPolicy {
                initialize_if_missing: true,
            },
            ..PersistencePolicy::default()
        },
        tempfile::tempdir().expect("temp dir").path(),
        "strict-mixed-mode-list",
        TaskList::new(id, "strict".to_string(), peer_id),
    )
    .await
    .expect_err("strict mode must fail closed when backend load fails");

    assert!(matches!(
        err,
        x0x::crdt::persistence::OrchestratorError::StartupLoad(
            PersistenceBackendError::Operation(_)
        )
    ));
}
