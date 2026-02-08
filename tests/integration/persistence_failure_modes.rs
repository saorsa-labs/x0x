use async_trait::async_trait;
use std::io;
use std::time::Duration;
use tokio::fs;
use x0x::crdt::persistence::{
    backends::file_backend::FileSnapshotBackend, recover_task_list_startup,
    run_graceful_shutdown_checkpoint, CheckpointPolicy, CheckpointScheduler, PersistenceBackend,
    PersistenceBackendError, PersistenceMode, PersistencePolicy, PersistenceSnapshot,
    RecoveryOutcome, RecoveryState, ShutdownCheckpointOutcome,
};
use x0x::crdt::{TaskList, TaskListId};
use saorsa_gossip_types::PeerId;

struct FailingCheckpointBackend {
    error: PersistenceBackendError,
}

#[async_trait]
impl PersistenceBackend for FailingCheckpointBackend {
    async fn checkpoint(
        &self,
        _request: &x0x::crdt::persistence::CheckpointRequest,
        _snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError> {
        Err(match &self.error {
            PersistenceBackendError::Io(_) => {
                PersistenceBackendError::Io(io::Error::other("simulated io error"))
            }
            PersistenceBackendError::Operation(msg) => PersistenceBackendError::Operation(msg.clone()),
            other => PersistenceBackendError::Operation(other.to_string()),
        })
    }

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError> {
        Err(PersistenceBackendError::SnapshotNotFound(entity_id.to_string()))
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

#[tokio::test]
async fn failure_mode_strict_init_requires_manifest_when_uninitialized() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Strict);
    let err = recover_task_list_startup(
        &backend,
        &PersistencePolicy {
            enabled: true,
            mode: PersistenceMode::Strict,
            strict_initialization: x0x::crdt::persistence::StrictInitializationPolicy {
                initialize_if_missing: false,
            },
            ..PersistencePolicy::default()
        },
        temp.path(),
        "manifest-required",
        TaskList::new(list_id(10), "manifest".to_string(), peer(10)),
    )
    .await
    .expect_err("strict startup should fail without init sentinel intent");

    assert!(matches!(
        err,
        x0x::crdt::persistence::OrchestratorError::Manifest(
            x0x::crdt::persistence::ManifestError::PersistenceNotInitialized(_)
        )
    ));
}

#[tokio::test]
async fn failure_mode_corrupt_snapshot_is_quarantined_and_reported() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Strict);
    let entity = "corrupt-entity";
    let entity_dir = temp.path().join(entity);
    fs::create_dir_all(&entity_dir)
        .await
        .expect("create entity directory");
    fs::write(entity_dir.join("99999999999999999999.snapshot"), b"not-json")
        .await
        .expect("write corrupt snapshot");

    let err = backend
        .load_latest(entity)
        .await
        .expect_err("corrupt snapshot should fail");

    assert!(matches!(err, PersistenceBackendError::SnapshotCorrupt { .. }));
    assert!(
        fs::try_exists(entity_dir.join("quarantine"))
            .await
            .expect("quarantine check")
    );
}

#[tokio::test]
async fn failure_mode_legacy_encrypted_artifact_is_mode_deterministic() {
    let strict_temp = tempfile::tempdir().expect("strict temp");
    let strict_backend =
        FileSnapshotBackend::new(strict_temp.path().to_path_buf(), PersistenceMode::Strict);
    let entity = "legacy-artifact";
    let strict_path = strict_temp
        .path()
        .join(entity)
        .join("00000000000000000001.snapshot");
    fs::create_dir_all(strict_path.parent().expect("strict parent"))
        .await
        .expect("create strict path");
    fs::write(
        &strict_path,
        br#"{"ciphertext":"abc","nonce":"123","key_id":"legacy"}"#,
    )
    .await
    .expect("write strict legacy artifact");

    let strict_err = strict_backend
        .load_latest(entity)
        .await
        .expect_err("strict mode should fail");
    assert!(matches!(
        strict_err,
        PersistenceBackendError::UnsupportedLegacyEncryptedArtifact { .. }
    ));

    let degraded_temp = tempfile::tempdir().expect("degraded temp");
    let degraded_backend =
        FileSnapshotBackend::new(degraded_temp.path().to_path_buf(), PersistenceMode::Degraded);
    let degraded_path = degraded_temp
        .path()
        .join(entity)
        .join("00000000000000000001.snapshot");
    fs::create_dir_all(degraded_path.parent().expect("degraded parent"))
        .await
        .expect("create degraded path");
    fs::write(
        &degraded_path,
        br#"{"ciphertext":"abc","nonce":"123","key_id":"legacy"}"#,
    )
    .await
    .expect("write degraded legacy artifact");

    let degraded_err = degraded_backend
        .load_latest(entity)
        .await
        .expect_err("degraded mode should skip artifact");
    assert!(matches!(
        degraded_err,
        PersistenceBackendError::DegradedSkippedLegacyArtifact { .. }
    ));
}

#[tokio::test]
async fn failure_mode_shutdown_checkpoint_handles_disk_full_and_io_errors() {
    let mut scheduler = CheckpointScheduler::new(CheckpointPolicy::default());
    scheduler.record_mutation(Duration::from_secs(0));

    let strict_backend = FailingCheckpointBackend {
        error: PersistenceBackendError::Operation("No space left on device".to_string()),
    };
    let mut strict_recovery = RecoveryState::loaded();
    let strict_err = run_graceful_shutdown_checkpoint(
        &strict_backend,
        &PersistencePolicy {
            enabled: true,
            mode: PersistenceMode::Strict,
            ..PersistencePolicy::default()
        },
        &mut scheduler,
        &mut strict_recovery,
        "disk-full-entity",
        2,
        vec![1, 2, 3],
        Duration::from_secs(301),
    )
    .await
    .expect_err("strict mode must fail on disk full");

    assert!(matches!(
        strict_err,
        x0x::crdt::persistence::OrchestratorError::Checkpoint(
            PersistenceBackendError::Operation(_)
        )
    ));

    let mut degraded_scheduler = CheckpointScheduler::new(CheckpointPolicy::default());
    degraded_scheduler.record_mutation(Duration::from_secs(0));
    let io_backend = FailingCheckpointBackend {
        error: PersistenceBackendError::Io(io::Error::other("simulated io write failure")),
    };
    let mut degraded_recovery = RecoveryState::empty_store();
    let outcome = run_graceful_shutdown_checkpoint(
        &io_backend,
        &PersistencePolicy {
            enabled: true,
            mode: PersistenceMode::Degraded,
            ..PersistencePolicy::default()
        },
        &mut degraded_scheduler,
        &mut degraded_recovery,
        "io-error-entity",
        2,
        vec![4, 5, 6],
        Duration::from_secs(301),
    )
    .await
    .expect("degraded mode should continue after io error");

    assert_eq!(outcome, ShutdownCheckpointOutcome::DegradedContinued);
    assert_eq!(degraded_recovery.outcome, RecoveryOutcome::EmptyStore);
    assert!(degraded_recovery.degraded);
    assert!(degraded_recovery.last_error.is_some());
}
