//! Persistent storage contracts and implementations for CRDT task lists.

pub mod backend;
pub mod backends;
pub mod budget;
pub mod checkpoint;
pub mod manifest;
pub mod migration;
pub mod orchestrator;
pub mod policy;
pub mod retention;
pub mod snapshot;

use crate::crdt::{TaskList, TaskListId};
use std::path::PathBuf;
use tokio::fs;

pub use backend::{
    CheckpointReason, CheckpointRequest, PersistenceBackend, PersistenceBackendError,
    PersistenceSnapshot,
};
pub use backends::FileSnapshotBackend;
pub use budget::{evaluate_budget, BudgetDecision};
pub use checkpoint::{run_checkpoint, CheckpointAction, CheckpointScheduler};
pub use manifest::{
    resolve_strict_startup_manifest, ManifestError, StoreManifest, MANIFEST_FILE_NAME,
};
pub use migration::{
    resolve_legacy_artifact_outcome, ArtifactLoadOutcome, MigrationError, MigrationResult,
    CURRENT_SNAPSHOT_SCHEMA_VERSION,
};
pub use orchestrator::{
    checkpoint_policy_defaults, recover_task_list_startup, OrchestratorError, RecoveredTaskList,
    RecoveryOutcome, RecoveryState,
};
pub use policy::{
    CheckpointPolicy, PersistenceMode, PersistencePolicy, PersistencePolicyError,
    RetentionPolicy, StrictInitializationPolicy,
};
pub use snapshot::{
    IntegrityMetadata, SnapshotDecodeError, SnapshotEnvelope, CODEC_MARKER_BINC, CODEC_VERSION_V1,
};
pub use retention::{enforce_retention_cycle, storage_usage_bytes, RetentionOutcome};

/// Storage backend for task lists with atomic writes and error recovery.
#[derive(Debug, Clone)]
pub struct TaskListStorage {
    storage_path: PathBuf,
}

impl TaskListStorage {
    /// Create a new storage instance with the given path.
    #[must_use]
    pub fn new(storage_path: PathBuf) -> Self {
        Self { storage_path }
    }

    /// Save a task list to persistent storage with atomic writes.
    pub async fn save_task_list(
        &self,
        list_id: &TaskListId,
        task_list: &TaskList,
    ) -> crate::crdt::error::Result<()> {
        fs::create_dir_all(&self.storage_path).await?;
        let serialized =
            bincode::serialize(task_list).map_err(crate::crdt::error::CrdtError::Serialization)?;

        let file_path = self.list_file_path(list_id);
        let temp_path = file_path.with_extension("tmp");
        fs::write(&temp_path, &serialized).await?;
        fs::rename(&temp_path, &file_path).await?;
        Ok(())
    }

    /// Load a task list from persistent storage.
    pub async fn load_task_list(
        &self,
        list_id: &TaskListId,
    ) -> crate::crdt::error::Result<TaskList> {
        let file_path = self.list_file_path(list_id);
        let serialized = fs::read(&file_path).await?;
        bincode::deserialize(&serialized).map_err(crate::crdt::error::CrdtError::Serialization)
    }

    /// List all stored task lists.
    pub async fn list_task_lists(&self) -> crate::crdt::error::Result<Vec<String>> {
        if !self.storage_path.exists() {
            return Ok(Vec::new());
        }

        let mut dir_entries = fs::read_dir(&self.storage_path).await?;
        let mut list_ids = Vec::new();

        while let Some(entry) = dir_entries.next_entry().await? {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "tmp") {
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "bin") {
                if let Some(file_name) = path.file_stem() {
                    if let Some(id_str) = file_name.to_str() {
                        list_ids.push(id_str.to_string());
                    }
                }
            }
        }

        Ok(list_ids)
    }

    /// Delete a task list from persistent storage.
    pub async fn delete_task_list(&self, list_id: &TaskListId) -> crate::crdt::error::Result<()> {
        let file_path = self.list_file_path(list_id);
        fs::remove_file(file_path).await?;
        Ok(())
    }

    fn list_file_path(&self, list_id: &TaskListId) -> PathBuf {
        self.storage_path.join(format!("{}.bin", list_id))
    }
}
