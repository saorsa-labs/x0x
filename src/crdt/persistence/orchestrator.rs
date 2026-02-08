use crate::crdt::persistence::{
    resolve_strict_startup_manifest, run_checkpoint, CheckpointPolicy, CheckpointReason,
    CheckpointScheduler, ManifestError, PersistenceBackend, PersistenceBackendError,
    PersistenceMode, PersistencePolicy, StoreManifest, EVENT_CHECKPOINT_ATTEMPT,
    EVENT_CHECKPOINT_FAILURE, EVENT_CHECKPOINT_SUCCESS, EVENT_DEGRADED_TRANSITION,
    EVENT_INIT_EMPTY, EVENT_INIT_FAILURE, EVENT_INIT_LOADED, EVENT_INIT_STARTED,
};
use crate::crdt::TaskList;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    LoadedSnapshot,
    EmptyStore,
    DegradedFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryState {
    pub outcome: RecoveryOutcome,
    pub degraded: bool,
    pub last_error: Option<String>,
}

impl RecoveryState {
    #[must_use]
    pub fn loaded() -> Self {
        Self {
            outcome: RecoveryOutcome::LoadedSnapshot,
            degraded: false,
            last_error: None,
        }
    }

    #[must_use]
    pub fn empty_store() -> Self {
        Self {
            outcome: RecoveryOutcome::EmptyStore,
            degraded: false,
            last_error: None,
        }
    }

    #[must_use]
    pub fn degraded_fallback(err: impl Into<String>) -> Self {
        Self {
            outcome: RecoveryOutcome::DegradedFallback,
            degraded: true,
            last_error: Some(err.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveredTaskList {
    pub task_list: TaskList,
    pub recovery: RecoveryState,
}

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("manifest resolution failed: {0}")]
    Manifest(#[from] ManifestError),
    #[error("startup load failed in strict mode: {0}")]
    StartupLoad(#[from] PersistenceBackendError),
    #[error("snapshot decode failed: {0}")]
    SnapshotDecode(String),
    #[error("network rejoin failed: {0}")]
    Rejoin(String),
    #[error("checkpoint failed in strict mode: {0}")]
    Checkpoint(PersistenceBackendError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownCheckpointOutcome {
    Persisted,
    SkippedClean,
    DegradedContinued,
}

pub async fn recover_task_list_startup<B: PersistenceBackend>(
    backend: &B,
    policy: &PersistencePolicy,
    store_root: &Path,
    entity_id: &str,
    empty_task_list: TaskList,
) -> Result<RecoveredTaskList, OrchestratorError> {
    tracing::info!(
        event = EVENT_INIT_STARTED,
        entity_id,
        mode = policy.mode.as_str()
    );

    ensure_manifest_for_mode(policy, store_root, entity_id)?;

    match backend.load_latest(entity_id).await {
        Ok(snapshot) => {
            let decoded = TaskList::from_persistence_payload(&snapshot.payload)
                .map_err(|err| OrchestratorError::SnapshotDecode(err.to_string()))?;
            tracing::info!(
                event = EVENT_INIT_LOADED,
                entity_id,
                mode = policy.mode.as_str(),
                schema_version = snapshot.schema_version
            );
            Ok(RecoveredTaskList {
                task_list: decoded,
                recovery: RecoveryState::loaded(),
            })
        }
        Err(PersistenceBackendError::SnapshotNotFound(_))
        | Err(PersistenceBackendError::NoLoadableSnapshot(_)) => {
            tracing::info!(
                event = EVENT_INIT_EMPTY,
                entity_id,
                mode = policy.mode.as_str()
            );
            Ok(RecoveredTaskList {
                task_list: empty_task_list,
                recovery: RecoveryState::empty_store(),
            })
        }
        Err(err) if matches!(policy.mode, PersistenceMode::Strict) => {
            tracing::error!(
                event = EVENT_INIT_FAILURE,
                entity_id,
                mode = policy.mode.as_str(),
                error = err.to_string()
            );
            Err(OrchestratorError::StartupLoad(err))
        }
        Err(err) => {
            tracing::warn!(
                event = EVENT_DEGRADED_TRANSITION,
                entity_id,
                mode = policy.mode.as_str(),
                reason = "startup_fallback",
                error = err.to_string()
            );
            Ok(RecoveredTaskList {
                task_list: empty_task_list,
                recovery: RecoveryState::degraded_fallback(err.to_string()),
            })
        }
    }
}

pub fn checkpoint_policy_defaults(policy: &PersistencePolicy) -> CheckpointPolicy {
    policy.checkpoint.clone()
}

#[allow(clippy::too_many_arguments)]
pub async fn run_graceful_shutdown_checkpoint<B: PersistenceBackend>(
    backend: &B,
    policy: &PersistencePolicy,
    scheduler: &mut CheckpointScheduler,
    recovery_state: &mut RecoveryState,
    entity_id: &str,
    schema_version: u32,
    payload: Vec<u8>,
    now: Duration,
) -> Result<ShutdownCheckpointOutcome, OrchestratorError> {
    if !scheduler.is_dirty() {
        return Ok(ShutdownCheckpointOutcome::SkippedClean);
    }

    let mutation_count = scheduler.mutation_count();
    tracing::info!(
        event = EVENT_CHECKPOINT_ATTEMPT,
        entity_id,
        mode = policy.mode.as_str(),
        reason = "graceful_shutdown",
        mutation_count
    );
    match run_checkpoint(
        backend,
        entity_id,
        schema_version,
        mutation_count,
        CheckpointReason::GracefulShutdown,
        payload,
    )
    .await
    {
        Ok(()) => {
            scheduler.mark_checkpoint(now);
            tracing::info!(
                event = EVENT_CHECKPOINT_SUCCESS,
                entity_id,
                mode = policy.mode.as_str(),
                reason = "graceful_shutdown"
            );
            Ok(ShutdownCheckpointOutcome::Persisted)
        }
        Err(err) if matches!(policy.mode, PersistenceMode::Strict) => {
            tracing::error!(
                event = EVENT_CHECKPOINT_FAILURE,
                entity_id,
                mode = policy.mode.as_str(),
                reason = "graceful_shutdown",
                error = err.to_string()
            );
            Err(OrchestratorError::Checkpoint(err))
        }
        Err(err) => {
            recovery_state.degraded = true;
            recovery_state.last_error = Some(err.to_string());
            tracing::warn!(
                event = EVENT_DEGRADED_TRANSITION,
                entity_id,
                mode = policy.mode.as_str(),
                reason = "graceful_shutdown",
                error = recovery_state.last_error.as_deref().unwrap_or("unknown")
            );
            Ok(ShutdownCheckpointOutcome::DegradedContinued)
        }
    }
}

fn ensure_manifest_for_mode(
    policy: &PersistencePolicy,
    store_root: &Path,
    entity_id: &str,
) -> Result<(), ManifestError> {
    if !matches!(policy.mode, PersistenceMode::Strict) {
        return Ok(());
    }

    let resolved = resolve_strict_startup_manifest(
        store_root,
        policy.strict_initialization.initialize_if_missing,
        &StoreManifest::v1(entity_id),
    );
    if let Err(err) = resolved {
        tracing::error!(
            event = EVENT_INIT_FAILURE,
            entity_id,
            mode = policy.mode.as_str(),
            error = err.to_string()
        );
        return Err(err);
    }

    Ok(())
}
