#[path = "../../bindings/nodejs/src/health.rs"]
mod node_health;
#[path = "../../bindings/python/src/health.rs"]
mod python_health;

use x0x::crdt::persistence::{PersistenceBackendError, PersistenceHealth, PersistenceMode};
use x0x::runtime::AgentCheckpointApi;

#[derive(Clone, Default)]
struct NoopBackend;

#[derive(Clone)]
struct FixedLoadBackend {
    response: FixedLoadResponse,
}

#[derive(Clone)]
enum FixedLoadResponse {
    NoLoadable,
    OperationFailure,
}

#[async_trait::async_trait]
impl x0x::crdt::persistence::PersistenceBackend for NoopBackend {
    async fn checkpoint(
        &self,
        _request: &x0x::crdt::persistence::CheckpointRequest,
        _snapshot: &x0x::crdt::persistence::PersistenceSnapshot,
    ) -> Result<(), x0x::crdt::persistence::PersistenceBackendError> {
        Ok(())
    }

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<
        x0x::crdt::persistence::PersistenceSnapshot,
        x0x::crdt::persistence::PersistenceBackendError,
    > {
        Err(
            x0x::crdt::persistence::PersistenceBackendError::SnapshotNotFound(
                entity_id.to_string(),
            ),
        )
    }

    async fn delete_entity(
        &self,
        _entity_id: &str,
    ) -> Result<(), x0x::crdt::persistence::PersistenceBackendError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl x0x::crdt::persistence::PersistenceBackend for FixedLoadBackend {
    async fn checkpoint(
        &self,
        _request: &x0x::crdt::persistence::CheckpointRequest,
        _snapshot: &x0x::crdt::persistence::PersistenceSnapshot,
    ) -> Result<(), x0x::crdt::persistence::PersistenceBackendError> {
        Ok(())
    }

    async fn load_latest(
        &self,
        _entity_id: &str,
    ) -> Result<
        x0x::crdt::persistence::PersistenceSnapshot,
        x0x::crdt::persistence::PersistenceBackendError,
    > {
        match &self.response {
            FixedLoadResponse::NoLoadable => Err(PersistenceBackendError::NoLoadableSnapshot(
                "entity-no-valid".to_string(),
            )),
            FixedLoadResponse::OperationFailure => Err(PersistenceBackendError::Operation(
                "simulated io failure".to_string(),
            )),
        }
    }

    async fn delete_entity(
        &self,
        _entity_id: &str,
    ) -> Result<(), x0x::crdt::persistence::PersistenceBackendError> {
        Ok(())
    }
}

#[test]
fn persistence_health_surface_includes_required_fields_with_stable_names() {
    let mut health = PersistenceHealth::new(PersistenceMode::Degraded);
    health.startup_loaded_snapshot();

    let node = node_health::map_persistence_health(&health);
    let python = python_health::map_persistence_health(&health);

    assert_eq!(node.mode, "degraded");
    assert_eq!(node.state, "ready");
    assert!(!node.degraded);
    assert_eq!(
        node.last_recovery_outcome.as_deref(),
        Some("loaded_snapshot")
    );
    assert!(node.last_error.is_none());
    assert_eq!(node.budget_pressure, "normal");

    assert_eq!(node.mode, python.mode);
    assert_eq!(node.state, python.state);
    assert_eq!(node.degraded, python.degraded);
    assert_eq!(node.last_recovery_outcome, python.last_recovery_outcome);
    assert_eq!(node.last_error.is_some(), python.last_error.is_some());
    assert_eq!(node.budget_pressure, python.budget_pressure);
}

#[test]
fn persistence_health_surface_maps_error_and_recovery_outcome_parity() {
    let mut health = PersistenceHealth::new(PersistenceMode::Strict);
    let backend_error = PersistenceBackendError::Operation("checkpoint write failed".to_string());
    health.startup_fallback(&backend_error);

    let node = node_health::map_persistence_health(&health);
    let python = python_health::map_persistence_health(&health);

    assert_eq!(node.mode, "strict");
    assert_eq!(node.state, "degraded");
    assert!(node.degraded);
    assert_eq!(
        node.last_recovery_outcome.as_deref(),
        Some("degraded_fallback")
    );

    let node_error = node.last_error.expect("node error payload present");
    let python_error = python.last_error.expect("python error payload present");

    assert_eq!(node_error.code, "startup_load_failure");
    assert!(node_error.message.contains("checkpoint write failed"));
    assert!(node_error
        .remediation
        .contains("Inspect persistence backend"));

    assert_eq!(node_error.code, python_error.code);
    assert_eq!(node_error.message, python_error.message);
    assert_eq!(node_error.remediation, python_error.remediation);
}

#[test]
fn persistence_health_surface_observability_includes_frequency_and_bounds() {
    let api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "entity-observability",
        2,
        PersistenceMode::Degraded,
        x0x::crdt::persistence::CheckpointPolicy::default(),
        x0x::config::HostPolicyEnvelopeConfig {
            allow_runtime_checkpoint_frequency_adjustment: true,
            min_mutation_threshold: 16,
            max_mutation_threshold: 96,
            min_dirty_time_floor_secs: 120,
            max_dirty_time_floor_secs: 900,
            min_debounce_floor_secs: 1,
            max_debounce_floor_secs: 10,
        },
    );

    let contract = api.observability_contract();
    let node = node_health::map_persistence_observability(&contract);
    let python = python_health::map_persistence_observability(&contract);

    assert_eq!(
        node.checkpoint_frequency.mutation_threshold,
        contract.checkpoint_frequency.mutation_threshold
    );
    assert_eq!(
        node.checkpoint_frequency.dirty_time_floor_secs,
        contract.checkpoint_frequency.dirty_time_floor_secs
    );
    assert_eq!(
        node.checkpoint_frequency.debounce_floor_secs,
        contract.checkpoint_frequency.debounce_floor_secs
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.min_mutation_threshold,
        contract.checkpoint_frequency_bounds.min_mutation_threshold
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.max_mutation_threshold,
        contract.checkpoint_frequency_bounds.max_mutation_threshold
    );
    assert_eq!(
        node.checkpoint_frequency_bounds
            .allow_runtime_checkpoint_frequency_adjustment,
        contract
            .checkpoint_frequency_bounds
            .allow_runtime_checkpoint_frequency_adjustment
    );

    assert_eq!(
        node.checkpoint_frequency.mutation_threshold,
        python.checkpoint_frequency.mutation_threshold
    );
    assert_eq!(
        node.checkpoint_frequency.dirty_time_floor_secs,
        python.checkpoint_frequency.dirty_time_floor_secs
    );
    assert_eq!(
        node.checkpoint_frequency.debounce_floor_secs,
        python.checkpoint_frequency.debounce_floor_secs
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.max_dirty_time_floor_secs,
        python.checkpoint_frequency_bounds.max_dirty_time_floor_secs
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.max_debounce_floor_secs,
        python.checkpoint_frequency_bounds.max_debounce_floor_secs
    );
}

#[tokio::test]
async fn persistence_health_surface_load_latest_no_valid_snapshot_maps_to_empty_store_contract() {
    let mut api = AgentCheckpointApi::new_with_mode(
        FixedLoadBackend {
            response: FixedLoadResponse::NoLoadable,
        },
        "entity-no-valid",
        2,
        PersistenceMode::Degraded,
        x0x::crdt::persistence::CheckpointPolicy::default(),
    );

    let err = api
        .load_latest()
        .await
        .expect_err("no loadable snapshots should report not found contract");
    assert!(matches!(
        err,
        x0x::runtime::AgentApiError::Backend(PersistenceBackendError::SnapshotNotFound(_))
    ));

    let health = api.persistence_health();
    assert_eq!(
        health.state,
        x0x::crdt::persistence::PersistenceState::Ready
    );
    assert!(!health.degraded);
    assert_eq!(
        health.last_recovery_outcome,
        Some(x0x::crdt::persistence::RecoveryHealthOutcome::EmptyStore)
    );

    let node = node_health::map_persistence_health(&health);
    let python = python_health::map_persistence_health(&health);
    assert_eq!(node.last_recovery_outcome.as_deref(), Some("empty_store"));
    assert_eq!(python.last_recovery_outcome, node.last_recovery_outcome);
}

#[tokio::test]
async fn persistence_health_surface_load_latest_hard_failure_maps_to_degraded_contract() {
    let mut api = AgentCheckpointApi::new_with_mode(
        FixedLoadBackend {
            response: FixedLoadResponse::OperationFailure,
        },
        "entity-hard-failure",
        2,
        PersistenceMode::Degraded,
        x0x::crdt::persistence::CheckpointPolicy::default(),
    );

    let err = api
        .load_latest()
        .await
        .expect_err("hard load failure should surface backend error");
    assert!(matches!(
        err,
        x0x::runtime::AgentApiError::Backend(PersistenceBackendError::Operation(_))
    ));

    let health = api.persistence_health();
    assert_eq!(
        health.state,
        x0x::crdt::persistence::PersistenceState::Degraded
    );
    assert!(health.degraded);
    assert_eq!(
        health.last_recovery_outcome,
        Some(x0x::crdt::persistence::RecoveryHealthOutcome::DegradedFallback)
    );
    let node = node_health::map_persistence_health(&health);
    let python = python_health::map_persistence_health(&health);
    assert_eq!(
        node.last_recovery_outcome.as_deref(),
        Some("degraded_fallback")
    );
    assert_eq!(python.last_recovery_outcome, node.last_recovery_outcome);
}

#[tokio::test]
async fn persistence_health_surface_load_latest_recoverable_invalid_latest_stays_loaded() {
    use tokio::fs;
    use x0x::crdt::persistence::{backends::file_backend::FileSnapshotBackend, PersistenceBackend};

    let temp = tempfile::tempdir().expect("temp dir");
    let backend = FileSnapshotBackend::new(temp.path().to_path_buf(), PersistenceMode::Degraded);
    let entity_id = "entity-recoverable-invalid-latest";
    let request = x0x::crdt::persistence::CheckpointRequest {
        entity_id: entity_id.to_string(),
        mutation_count: 1,
        reason: x0x::crdt::persistence::CheckpointReason::ExplicitRequest,
    };
    let snapshot = x0x::crdt::persistence::PersistenceSnapshot {
        entity_id: entity_id.to_string(),
        schema_version: 2,
        payload: vec![9, 8, 7],
    };
    backend
        .checkpoint(&request, &snapshot)
        .await
        .expect("write valid snapshot");

    fs::write(
        temp.path()
            .join(entity_id)
            .join("99999999999999999999.snapshot"),
        b"not-json",
    )
    .await
    .expect("write corrupt latest snapshot");

    let mut api = AgentCheckpointApi::new_with_mode(
        backend,
        entity_id,
        2,
        PersistenceMode::Degraded,
        x0x::crdt::persistence::CheckpointPolicy::default(),
    );
    let loaded = api
        .load_latest()
        .await
        .expect("corrupt latest should be skipped when older valid snapshot exists");
    assert_eq!(loaded.payload, vec![9, 8, 7]);

    let health = api.persistence_health();
    assert_eq!(
        health.state,
        x0x::crdt::persistence::PersistenceState::Ready
    );
    assert!(!health.degraded);
    assert_eq!(
        health.last_recovery_outcome,
        Some(x0x::crdt::persistence::RecoveryHealthOutcome::LoadedSnapshot)
    );
}
