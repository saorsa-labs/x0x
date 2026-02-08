//! Persistent storage contracts and implementations for CRDT task lists.

pub mod backend;
pub mod backends;
pub mod budget;
pub mod checkpoint;
pub mod health;
pub mod manifest;
pub mod migration;
pub mod orchestrator;
pub mod policy;
pub mod retention;
pub mod snapshot;
pub(crate) mod snapshot_filename;

pub use backend::{
    CheckpointReason, CheckpointRequest, PersistenceBackend, PersistenceBackendError,
    PersistenceSnapshot,
};
pub use backends::FileSnapshotBackend;
pub use budget::{evaluate_budget, BudgetDecision};
pub use checkpoint::{run_checkpoint, CheckpointAction, CheckpointScheduler};
pub use health::{
    is_legacy_artifact_error, BudgetPressure, CheckpointFrequencyBounds,
    CheckpointFrequencyContract, CheckpointFrequencyUpdateRequest, PersistenceErrorCode,
    PersistenceErrorInfo, PersistenceHealth, PersistenceObservabilityContract, PersistenceState,
    RecoveryHealthOutcome, EVENT_BUDGET_THRESHOLD, EVENT_CHECKPOINT_ATTEMPT,
    EVENT_CHECKPOINT_FAILURE, EVENT_CHECKPOINT_SUCCESS, EVENT_DEGRADED_TRANSITION,
    EVENT_INIT_EMPTY, EVENT_INIT_FAILURE, EVENT_INIT_LOADED, EVENT_INIT_STARTED,
    EVENT_LEGACY_ARTIFACT_DETECTED,
};
pub use manifest::{
    resolve_strict_startup_manifest, ManifestError, StoreManifest, MANIFEST_FILE_NAME,
};
pub use migration::{
    resolve_legacy_artifact_outcome, ArtifactLoadOutcome, MigrationError, MigrationResult,
    CURRENT_SNAPSHOT_SCHEMA_VERSION,
};
pub use orchestrator::{
    checkpoint_policy_defaults, recover_task_list_startup, OrchestratorError, RecoveredTaskList,
    RecoveryOutcome, RecoveryState, ShutdownCheckpointOutcome, run_graceful_shutdown_checkpoint,
};
pub use policy::{
    CheckpointPolicy, PersistenceMode, PersistencePolicy, PersistencePolicyError,
    RetentionPolicy, StrictInitializationPolicy,
};
pub use snapshot::{
    IntegrityMetadata, SnapshotDecodeError, SnapshotEnvelope, CODEC_MARKER_BINC, CODEC_VERSION_V1,
};
pub use retention::{enforce_retention_cycle, storage_usage_bytes, RetentionOutcome};
