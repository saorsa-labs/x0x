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
        .expect("older valid snapshot should load after corrupt latest is quarantined");
    assert_eq!(err.payload, b"baseline");

    let quarantine_dir = entity_dir.join("quarantine");
    assert!(fs::try_exists(&quarantine_dir).await.expect("quarantine dir check"));
}

#[tokio::test]
async fn file_backend_atomicity_skips_unreadable_newest_snapshot_and_loads_older_valid_snapshot() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Strict);
    let entity = "entity-unreadable";

    backend
        .checkpoint(&checkpoint_request(entity), &snapshot(entity, b"baseline"))
        .await
        .expect("write baseline snapshot");

    let entity_dir = temp.path().join(entity);
    let unreadable_newest = entity_dir.join("99999999999999999999.snapshot");
    fs::create_dir_all(&unreadable_newest)
        .await
        .expect("create unreadable newest snapshot directory");

    let loaded = backend
        .load_latest(entity)
        .await
        .expect("older valid snapshot should load when newest candidate is unreadable");
    assert_eq!(loaded.payload, b"baseline");
}

#[tokio::test]
async fn file_backend_atomicity_unreadable_candidates_without_valid_snapshot_return_no_loadable() {
    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Strict);
    let entity = "entity-only-unreadable";

    let entity_dir = temp.path().join(entity);
    fs::create_dir_all(entity_dir.join("99999999999999999999.snapshot"))
        .await
        .expect("create unreadable candidate directory");

    let err = backend
        .load_latest(entity)
        .await
        .expect_err("unreadable-only candidates should not fail with an I/O short-circuit");
    assert!(matches!(err, PersistenceBackendError::NoLoadableSnapshot(_)));
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

    strict_backend
        .checkpoint(&checkpoint_request(entity), &snapshot(entity, b"strict-valid"))
        .await
        .expect("write strict valid snapshot");

    let strict_loaded = strict_backend
        .load_latest(entity)
        .await
        .expect("strict mode should skip legacy and load valid snapshot");
    assert_eq!(strict_loaded.payload, b"strict-valid");

    let strict_legacy_only_entity = "entity-c-strict-legacy-only";
    let strict_legacy_only_path = strict_temp
        .path()
        .join(strict_legacy_only_entity)
        .join("00000000000000000001.snapshot");
    fs::create_dir_all(strict_legacy_only_path.parent().expect("parent"))
        .await
        .expect("create strict legacy-only entity dir");
    fs::write(
        &strict_legacy_only_path,
        br#"{"ciphertext":"abc","nonce":"123","key_id":"legacy"}"#,
    )
    .await
    .expect("write strict legacy-only artifact");

    let strict_legacy_only_err = strict_backend
        .load_latest(strict_legacy_only_entity)
        .await
        .expect_err("strict mode with only legacy artifacts should report no loadable snapshot");
    assert!(matches!(
        strict_legacy_only_err,
        PersistenceBackendError::NoLoadableSnapshot(_) 
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

    degraded_backend
        .checkpoint(&checkpoint_request(entity), &snapshot(entity, b"degraded-valid"))
        .await
        .expect("write degraded valid snapshot");

    let degraded_loaded = degraded_backend
        .load_latest(entity)
        .await
        .expect("degraded mode should skip legacy and load valid snapshot");
    assert_eq!(degraded_loaded.payload, b"degraded-valid");

    let degraded_legacy_only_entity = "entity-c-degraded-legacy-only";
    let degraded_legacy_only_path = degraded_temp
        .path()
        .join(degraded_legacy_only_entity)
        .join("00000000000000000001.snapshot");
    fs::create_dir_all(degraded_legacy_only_path.parent().expect("parent"))
        .await
        .expect("create degraded legacy-only entity dir");
    fs::write(
        &degraded_legacy_only_path,
        br#"{"ciphertext":"abc","nonce":"123","key_id":"legacy"}"#,
    )
    .await
    .expect("write degraded legacy-only artifact");

    let degraded_legacy_only_err = degraded_backend
        .load_latest(degraded_legacy_only_entity)
        .await
        .expect_err("degraded mode with only legacy artifacts should report no loadable snapshot");
    assert!(matches!(
        degraded_legacy_only_err,
        PersistenceBackendError::NoLoadableSnapshot(_)
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
