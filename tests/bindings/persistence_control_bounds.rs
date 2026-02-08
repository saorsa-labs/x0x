mod node_binding {
    pub mod health {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings/nodejs/src/health.rs"));
    }
    pub mod runtime_controls {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/bindings/nodejs/src/runtime_controls.rs"
        ));
    }
}

mod python_binding {
    pub mod health {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings/python/src/health.rs"));
    }
    pub mod runtime_controls {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/bindings/python/src/runtime_controls.rs"
        ));
    }
}

use async_trait::async_trait;
use x0x::config::HostPolicyEnvelopeConfig;
use x0x::crdt::persistence::{
    CheckpointPolicy, PersistenceBackend, PersistenceBackendError, PersistenceMode,
    PersistenceSnapshot,
};
use x0x::runtime::AgentCheckpointApi;

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
    let mut node_api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "node-entity-disallow",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy::default(),
        HostPolicyEnvelopeConfig::default(),
    );
    let mut python_api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "python-entity-disallow",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy::default(),
        HostPolicyEnvelopeConfig::default(),
    );

    let request = node_binding::runtime_controls::BindingCheckpointFrequencyUpdateRequest {
        mutation_threshold: Some(64),
        dirty_time_floor_secs: None,
        debounce_floor_secs: None,
    };

    let node_err = node_binding::runtime_controls::request_checkpoint_frequency_adjustment(
        &mut node_api,
        request.clone(),
    )
    .expect_err("node request should be rejected");
    let python_err = python_binding::runtime_controls::request_checkpoint_frequency_adjustment(
        &mut python_api,
        python_binding::runtime_controls::BindingCheckpointFrequencyUpdateRequest {
            mutation_threshold: request.mutation_threshold,
            dirty_time_floor_secs: request.dirty_time_floor_secs,
            debounce_floor_secs: request.debounce_floor_secs,
        },
    )
    .expect_err("python request should be rejected");

    assert_eq!(
        node_err.code,
        "runtime_checkpoint_adjustment_not_allowed"
    );
    assert_eq!(python_err.code, node_err.code);
    assert_eq!(python_err.message, node_err.message);
}

#[test]
fn persistence_control_bounds_reject_out_of_range_requests() {
    let host_policy = HostPolicyEnvelopeConfig {
        allow_runtime_checkpoint_frequency_adjustment: true,
        min_mutation_threshold: 16,
        max_mutation_threshold: 64,
        min_dirty_time_floor_secs: 120,
        max_dirty_time_floor_secs: 900,
        min_debounce_floor_secs: 1,
        max_debounce_floor_secs: 10,
    };
    let mut node_api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "node-entity-out-of-range",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy::default(),
        host_policy.clone(),
    );
    let mut python_api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "python-entity-out-of-range",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy::default(),
        host_policy,
    );

    let request = node_binding::runtime_controls::BindingCheckpointFrequencyUpdateRequest {
        mutation_threshold: Some(80),
        dirty_time_floor_secs: Some(300),
        debounce_floor_secs: Some(3),
    };

    let node_err = node_binding::runtime_controls::request_checkpoint_frequency_adjustment(
        &mut node_api,
        request.clone(),
    )
    .expect_err("node mutation threshold should be bounded");
    let python_err = python_binding::runtime_controls::request_checkpoint_frequency_adjustment(
        &mut python_api,
        python_binding::runtime_controls::BindingCheckpointFrequencyUpdateRequest {
            mutation_threshold: request.mutation_threshold,
            dirty_time_floor_secs: request.dirty_time_floor_secs,
            debounce_floor_secs: request.debounce_floor_secs,
        },
    )
    .expect_err("python mutation threshold should be bounded");

    assert_eq!(node_err.code, "mutation_threshold_out_of_bounds");
    assert_eq!(python_err.code, node_err.code);
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
    let node = node_binding::runtime_controls::query_persistence_observability(&api);
    let python = python_binding::runtime_controls::query_persistence_observability(&api);

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

#[test]
fn persistence_control_bounds_applies_in_bounds_updates_with_parity() {
    let host_policy = HostPolicyEnvelopeConfig {
        allow_runtime_checkpoint_frequency_adjustment: true,
        min_mutation_threshold: 16,
        max_mutation_threshold: 128,
        min_dirty_time_floor_secs: 120,
        max_dirty_time_floor_secs: 900,
        min_debounce_floor_secs: 1,
        max_debounce_floor_secs: 10,
    };

    let mut node_api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "node-entity-allow",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy::default(),
        host_policy.clone(),
    );
    let mut python_api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "python-entity-allow",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy::default(),
        host_policy,
    );

    let request = node_binding::runtime_controls::BindingCheckpointFrequencyUpdateRequest {
        mutation_threshold: Some(48),
        dirty_time_floor_secs: Some(600),
        debounce_floor_secs: Some(3),
    };

    let node = node_binding::runtime_controls::request_checkpoint_frequency_adjustment(
        &mut node_api,
        request.clone(),
    )
    .expect("node update should apply");
    let python = python_binding::runtime_controls::request_checkpoint_frequency_adjustment(
        &mut python_api,
        python_binding::runtime_controls::BindingCheckpointFrequencyUpdateRequest {
            mutation_threshold: request.mutation_threshold,
            dirty_time_floor_secs: request.dirty_time_floor_secs,
            debounce_floor_secs: request.debounce_floor_secs,
        },
    )
    .expect("python update should apply");

    assert_eq!(node.mutation_threshold, 48);
    assert_eq!(node.dirty_time_floor_secs, 600);
    assert_eq!(node.debounce_floor_secs, 3);
    assert_eq!(python.mutation_threshold, node.mutation_threshold);
    assert_eq!(python.dirty_time_floor_secs, node.dirty_time_floor_secs);
    assert_eq!(python.debounce_floor_secs, node.debounce_floor_secs);
}
