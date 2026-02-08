#[path = "../../bindings/nodejs/src/health.rs"]
mod node_health;
#[path = "../../bindings/python/src/health.rs"]
mod python_health;

use x0x::crdt::persistence::{PersistenceBackendError, PersistenceHealth, PersistenceMode};
use x0x::runtime::AgentCheckpointApi;

#[derive(Clone, Default)]
struct NoopBackend;

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
    ) -> Result<x0x::crdt::persistence::PersistenceSnapshot, x0x::crdt::persistence::PersistenceBackendError>
    {
        Err(x0x::crdt::persistence::PersistenceBackendError::SnapshotNotFound(
            entity_id.to_string(),
        ))
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
        node.checkpoint_frequency_bounds.allow_runtime_checkpoint_frequency_adjustment,
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
