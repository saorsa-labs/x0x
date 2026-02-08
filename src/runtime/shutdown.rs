use crate::crdt::persistence::{
    run_graceful_shutdown_checkpoint, CheckpointScheduler, OrchestratorError, PersistenceBackend,
    PersistencePolicy, RecoveryState, ShutdownCheckpointOutcome,
};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GracefulShutdownResult {
    CheckpointPersisted,
    NoCheckpointNeeded,
    ContinuedInDegradedMode,
}

pub async fn graceful_shutdown<B: PersistenceBackend>(
    backend: &B,
    policy: &PersistencePolicy,
    scheduler: &mut CheckpointScheduler,
    recovery_state: &mut RecoveryState,
    entity_id: &str,
    schema_version: u32,
    payload: Vec<u8>,
    now: Duration,
) -> Result<GracefulShutdownResult, OrchestratorError> {
    let outcome = run_graceful_shutdown_checkpoint(
        backend,
        policy,
        scheduler,
        recovery_state,
        entity_id,
        schema_version,
        payload,
        now,
    )
    .await?;

    Ok(match outcome {
        ShutdownCheckpointOutcome::Persisted => GracefulShutdownResult::CheckpointPersisted,
        ShutdownCheckpointOutcome::SkippedClean => GracefulShutdownResult::NoCheckpointNeeded,
        ShutdownCheckpointOutcome::DegradedContinued => {
            GracefulShutdownResult::ContinuedInDegradedMode
        }
    })
}
