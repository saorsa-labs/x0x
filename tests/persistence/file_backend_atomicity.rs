use std::path::PathBuf;

use tokio::fs;
use x0x::crdt::persistence::{
    backends::file_backend::FileSnapshotBackend, CheckpointReason, CheckpointRequest,
    PersistenceBackend, PersistenceBackendError, PersistenceMode, PersistenceSnapshot,
};

fn checkpoint_request(entity_id: &str) -> CheckpointRequest {
    CheckpointRequest {
        entity_id: entity_id.to_string(),
        mutation_count: 1,
        reason: CheckpointReason::ExplicitRequest,
    }
}

fn snapshot(entity_id: &str, payload: &[u8]) -> PersistenceSnapshot {
    PersistenceSnapshot {
        entity_id: entity_id.to_string(),
        schema_version: 2,
        payload: payload.to_vec(),
    }
}

#[tokio::test]
async fn file_backend_atomicity_ignores_torn_temp_files() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Strict);
    let entity = "entity-a";

    let entity_dir = temp.path().join(entity);
    fs::create_dir_all(&entity_dir).await.expect("create entity dir");
    let torn_temp = entity_dir.join("00000000000000000001.tmp");
    fs::write(&torn_temp, b"partial").await.expect("write torn temp");

    backend
        .checkpoint(&checkpoint_request(entity), &snapshot(entity, b"good"))
        .await
        .expect("write valid snapshot");

    let loaded = backend.load_latest(entity).await.expect("load latest");
    assert_eq!(loaded.payload, b"good");
}

#[tokio::test]
async fn file_backend_atomicity_quarantines_corrupt_snapshot() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Strict);
    let entity = "entity-b";

    backend
        .checkpoint(&checkpoint_request(entity), &snapshot(entity, b"baseline"))
        .await
        .expect("write baseline snapshot");

    let entity_dir = PathBuf::from(temp.path()).join(entity);
    let corrupt_latest = entity_dir.join("99999999999999999999.snapshot");
    fs::write(&corrupt_latest, b"not-json").await.expect("write corrupt snapshot");

    let err = backend
        .load_latest(entity)
        .await
        .expect_err("corrupt latest should not be accepted");
    assert!(matches!(err, PersistenceBackendError::SnapshotCorrupt { .. }));

    let quarantine_dir = entity_dir.join("quarantine");
    assert!(fs::try_exists(&quarantine_dir).await.expect("quarantine dir check"));
}

#[tokio::test]
async fn file_backend_atomicity_legacy_artifacts_are_mode_deterministic() {
    let strict_temp = tempfile::tempdir().expect("strict temp dir");
    let strict_backend =
        FileSnapshotBackend::new(strict_temp.path().to_path_buf(), PersistenceMode::Strict);
    let entity = "entity-c";
    let strict_path = strict_temp
        .path()
        .join(entity)
        .join("00000000000000000042.snapshot");
    fs::create_dir_all(strict_path.parent().expect("parent"))
        .await
        .expect("create strict entity dir");
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

    let degraded_temp = tempfile::tempdir().expect("degraded temp dir");
    let degraded_backend =
        FileSnapshotBackend::new(degraded_temp.path().to_path_buf(), PersistenceMode::Degraded);
    let degraded_path = degraded_temp
        .path()
        .join(entity)
        .join("00000000000000000042.snapshot");
    fs::create_dir_all(degraded_path.parent().expect("parent"))
        .await
        .expect("create degraded entity dir");
    fs::write(
        &degraded_path,
        br#"{"ciphertext":"abc","nonce":"123","key_id":"legacy"}"#,
    )
    .await
    .expect("write degraded legacy artifact");

    let degraded_err = degraded_backend
        .load_latest(entity)
        .await
        .expect_err("degraded mode should skip with typed error");
    assert!(matches!(
        degraded_err,
        PersistenceBackendError::DegradedSkippedLegacyArtifact { .. }
    ));
}

#[tokio::test]
async fn file_backend_atomicity_ignores_malformed_snapshot_names_on_load_latest() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Strict);
    let entity = "entity-malformed";
    let entity_dir = temp.path().join(entity);
    fs::create_dir_all(&entity_dir)
        .await
        .expect("create entity directory");

    fs::write(entity_dir.join("not-a-timestamp.snapshot"), b"junk")
        .await
        .expect("write malformed name");
    fs::write(entity_dir.join("123.snapshot"), b"junk")
        .await
        .expect("write short malformed name");

    backend
        .checkpoint(&checkpoint_request(entity), &snapshot(entity, b"older"))
        .await
        .expect("write first valid snapshot");
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    backend
        .checkpoint(&checkpoint_request(entity), &snapshot(entity, b"newest"))
        .await
        .expect("write second valid snapshot");

    let loaded = backend
        .load_latest(entity)
        .await
        .expect("load latest valid snapshot");
    assert_eq!(loaded.payload, b"newest");
}
