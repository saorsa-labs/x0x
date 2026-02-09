use x0x::crdt::persistence::{
    CheckpointReason, FileSnapshotBackend, PersistenceBackendError, PersistenceMode,
};

#[test]
fn persistence_surface_exports_file_backend_contract() {
    let backend = FileSnapshotBackend::new(
        std::path::PathBuf::from("/tmp/x0x"),
        PersistenceMode::Strict,
    );
    let err = PersistenceBackendError::SnapshotNotFound("entity".to_string());
    assert!(matches!(err, PersistenceBackendError::SnapshotNotFound(_)));
    assert!(matches!(
        CheckpointReason::ExplicitRequest,
        CheckpointReason::ExplicitRequest
    ));
    std::mem::drop(backend);
}

#[test]
fn legacy_task_list_storage_bypass_is_not_reexported() {
    let persistence_mod = include_str!("../../src/crdt/persistence/mod.rs");
    let crdt_mod = include_str!("../../src/crdt/mod.rs");

    assert!(!persistence_mod.contains("pub struct TaskListStorage"));
    assert!(!crdt_mod.contains("pub use persistence::TaskListStorage"));
}
