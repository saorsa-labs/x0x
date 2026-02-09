use tokio::fs;
use x0x::crdt::persistence::{
    backends::file_backend::FileSnapshotBackend, CheckpointReason, CheckpointRequest,
    PersistenceBackend, PersistenceBackendError, PersistenceMode, PersistenceSnapshot,
};

const INVALID_ENTITY_IDS: [&str; 6] = [
    "../escape",
    "..\\escape",
    "/tmp/escape",
    "nested/path",
    "nested\\path",
    "%2e%2e%2fescape",
];

fn checkpoint_request(entity_id: &str) -> CheckpointRequest {
    CheckpointRequest {
        entity_id: entity_id.to_string(),
        mutation_count: 1,
        reason: CheckpointReason::ExplicitRequest,
    }
}

fn snapshot(entity_id: &str) -> PersistenceSnapshot {
    PersistenceSnapshot {
        entity_id: entity_id.to_string(),
        schema_version: 2,
        payload: vec![1, 2, 3],
    }
}

#[tokio::test]
async fn path_safety_rejects_invalid_entity_ids_for_checkpoint_and_load() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Degraded);

    for invalid in INVALID_ENTITY_IDS {
        let checkpoint_err = backend
            .checkpoint(&checkpoint_request(invalid), &snapshot(invalid))
            .await
            .expect_err("invalid entity id must be rejected by checkpoint");
        assert!(matches!(
            checkpoint_err,
            PersistenceBackendError::InvalidEntityId { .. }
        ));

        let load_err = backend
            .load_latest(invalid)
            .await
            .expect_err("invalid entity id must be rejected by load_latest");
        assert!(matches!(
            load_err,
            PersistenceBackendError::InvalidEntityId { .. }
        ));
    }
}

#[tokio::test]
async fn path_safety_prevents_delete_side_effects_outside_store_root() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().join("store"), PersistenceMode::Strict);

    let outside = temp.path().join("outside-target");
    fs::create_dir_all(&outside)
        .await
        .expect("create outside target");
    fs::write(outside.join("sentinel.txt"), b"keep")
        .await
        .expect("write sentinel file");

    let err = backend
        .delete_entity("../outside-target")
        .await
        .expect_err("delete_entity traversal attempt must be rejected");
    assert!(matches!(
        err,
        PersistenceBackendError::InvalidEntityId { .. }
    ));

    assert!(fs::try_exists(outside.join("sentinel.txt"))
        .await
        .expect("sentinel exists check"));
}
