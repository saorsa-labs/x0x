#[path = "../../bindings/nodejs/src/health.rs"]
mod node_health;
#[path = "../../bindings/python/src/health.rs"]
mod python_health;

use async_trait::async_trait;
use x0x::config::HostPolicyEnvelopeConfig;
use x0x::crdt::persistence::{
    CheckpointFrequencyUpdateRequest, CheckpointPolicy, PersistenceBackend,
    PersistenceBackendError, PersistenceMode, PersistenceSnapshot,
};
use x0x::runtime::{AgentApiError, AgentCheckpointApi, PolicyBoundsError};

#[derive(Clone, Default)]
struct NoopBackend;

#[async_trait]
impl PersistenceBackend for NoopBackend {
    async fn checkpoint(
        &self,
        _request: &x0x::crdt::persistence::CheckpointRequest,
        _snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError> {
        Ok(())
    }

    async fn load_latest(
        &self,
        entity_id: &str,
    ) -> Result<PersistenceSnapshot, PersistenceBackendError> {
        Err(PersistenceBackendError::SnapshotNotFound(
            entity_id.to_string(),
        ))
    }

    async fn delete_entity(&self, _entity_id: &str) -> Result<(), PersistenceBackendError> {
        Ok(())
    }
}

#[test]
fn persistence_control_bounds_reject_disallowed_runtime_adjustments() {
    let mut api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "entity-disallow",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy::default(),
        HostPolicyEnvelopeConfig::default(),
    );

    let result = api.request_checkpoint_frequency_update(CheckpointFrequencyUpdateRequest {
        mutation_threshold: Some(64),
        dirty_time_floor_secs: None,
        debounce_floor_secs: None,
    });

    assert!(matches!(
        result.expect_err("request should be rejected"),
        AgentApiError::PolicyBounds(PolicyBoundsError::RuntimeCheckpointAdjustmentNotAllowed)
    ));
}

#[test]
fn persistence_control_bounds_reject_out_of_range_requests() {
    let mut api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "entity-out-of-range",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy::default(),
        HostPolicyEnvelopeConfig {
            allow_runtime_checkpoint_frequency_adjustment: true,
            min_mutation_threshold: 16,
            max_mutation_threshold: 64,
            min_dirty_time_floor_secs: 120,
            max_dirty_time_floor_secs: 900,
            min_debounce_floor_secs: 1,
            max_debounce_floor_secs: 10,
        },
    );

    let result = api.request_checkpoint_frequency_update(CheckpointFrequencyUpdateRequest {
        mutation_threshold: Some(80),
        dirty_time_floor_secs: Some(300),
        debounce_floor_secs: Some(3),
    });

    assert!(matches!(
        result.expect_err("mutation threshold should be bounded"),
        AgentApiError::PolicyBounds(PolicyBoundsError::MutationThresholdOutOfBounds { .. })
    ));
}

#[test]
fn persistence_control_bounds_observability_parity_includes_bounds_contract() {
    let api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "entity-observability-bounds",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy::default(),
        HostPolicyEnvelopeConfig {
            allow_runtime_checkpoint_frequency_adjustment: true,
            min_mutation_threshold: 16,
            max_mutation_threshold: 96,
            min_dirty_time_floor_secs: 120,
            max_dirty_time_floor_secs: 900,
            min_debounce_floor_secs: 1,
            max_debounce_floor_secs: 10,
        },
    );

    let observability = api.observability_contract();
    let node = node_health::map_persistence_observability(&observability);
    let python = python_health::map_persistence_observability(&observability);

    assert_eq!(
        node.checkpoint_frequency_bounds.min_mutation_threshold,
        observability.checkpoint_frequency_bounds.min_mutation_threshold
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.max_mutation_threshold,
        observability.checkpoint_frequency_bounds.max_mutation_threshold
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.min_dirty_time_floor_secs,
        observability.checkpoint_frequency_bounds.min_dirty_time_floor_secs
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.max_dirty_time_floor_secs,
        observability.checkpoint_frequency_bounds.max_dirty_time_floor_secs
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.min_debounce_floor_secs,
        observability.checkpoint_frequency_bounds.min_debounce_floor_secs
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.max_debounce_floor_secs,
        observability.checkpoint_frequency_bounds.max_debounce_floor_secs
    );

    assert_eq!(
        node.checkpoint_frequency_bounds.allow_runtime_checkpoint_frequency_adjustment,
        python
            .checkpoint_frequency_bounds
            .allow_runtime_checkpoint_frequency_adjustment
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.min_mutation_threshold,
        python.checkpoint_frequency_bounds.min_mutation_threshold
    );
    assert_eq!(
        node.checkpoint_frequency_bounds.max_mutation_threshold,
        python.checkpoint_frequency_bounds.max_mutation_threshold
    );
}
