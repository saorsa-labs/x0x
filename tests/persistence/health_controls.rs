use async_trait::async_trait;
use std::time::Duration;
use x0x::config::HostPolicyEnvelopeConfig;
use x0x::crdt::persistence::{
    CheckpointFrequencyUpdateRequest, CheckpointPolicy, PersistenceBackend,
    PersistenceBackendError, PersistenceMode, PersistenceSnapshot,
};
use x0x::runtime::{AgentApiError, AgentCheckpointApi};

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
fn health_controls_reject_runtime_updates_when_host_disallows_adjustment() {
    let mut api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "entity-host-disallow",
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
        result.expect_err("host disallow must reject update"),
        AgentApiError::PolicyBounds(
            x0x::runtime::PolicyBoundsError::RuntimeCheckpointAdjustmentNotAllowed
        )
    ));
}

#[test]
fn health_controls_reject_out_of_bounds_runtime_updates() {
    let mut api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "entity-oob",
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
        mutation_threshold: Some(100),
        dirty_time_floor_secs: Some(300),
        debounce_floor_secs: Some(3),
    });

    assert!(matches!(
        result.expect_err("out-of-bounds mutation threshold must fail"),
        AgentApiError::PolicyBounds(x0x::runtime::PolicyBoundsError::MutationThresholdOutOfBounds {
            ..
        })
    ));
}

#[test]
fn health_controls_apply_in_bounds_runtime_updates_and_freeze_contract_shape() {
    let mut api = AgentCheckpointApi::new_with_runtime_controls(
        NoopBackend,
        "entity-valid",
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

    let updated = api
        .request_checkpoint_frequency_update(CheckpointFrequencyUpdateRequest {
            mutation_threshold: Some(48),
            dirty_time_floor_secs: Some(600),
            debounce_floor_secs: Some(3),
        })
        .expect("in-bounds update should apply");

    assert_eq!(updated.mutation_threshold, 48);
    assert_eq!(updated.dirty_time_floor_secs, 600);
    assert_eq!(updated.debounce_floor_secs, 3);

    let policy = api.checkpoint_policy();
    assert_eq!(policy.mutation_threshold, 48);
    assert_eq!(policy.dirty_time_floor, Duration::from_secs(600));
    assert_eq!(policy.debounce_floor, Duration::from_secs(3));

    let contract = api.observability_contract();
    assert_eq!(contract.health.mode, PersistenceMode::Degraded);
    assert_eq!(
        contract
            .checkpoint_frequency_bounds
            .allow_runtime_checkpoint_frequency_adjustment,
        true
    );
    assert_eq!(contract.checkpoint_frequency.mutation_threshold, 48);
}
