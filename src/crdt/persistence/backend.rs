//! Persistence backend contracts used by runtime orchestration.

use async_trait::async_trait;

/// Reason why a checkpoint request was issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointReason {
    MutationThreshold,
    DirtyTimeFloor,
    ExplicitRequest,
    GracefulShutdown,
}

/// Runtime request for persisting a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRequest {
    pub entity_id: String,
    pub mutation_count: u64,
    pub reason: CheckpointReason,
}

/// Persisted snapshot payload for backend implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceSnapshot {
    pub entity_id: String,
    pub schema_version: u32,
    pub payload: Vec<u8>,
}

/// Persistence backend errors.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceBackendError {
    #[error("snapshot not found for entity: {0}")]
    SnapshotNotFound(String),
    #[error("backend I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("backend operation failed: {0}")]
    Operation(String),
}

/// Trait boundary for persistence backend implementations.
#[async_trait]
pub trait PersistenceBackend: Send + Sync {
    async fn checkpoint(
        &self,
        request: &CheckpointRequest,
        snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError>;

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError>;

    async fn delete_entity(&self, entity_id: &str) -> Result<(), PersistenceBackendError>;
}
