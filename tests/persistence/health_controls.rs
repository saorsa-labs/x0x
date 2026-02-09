use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use x0x::config::HostPolicyEnvelopeConfig;
use x0x::crdt::persistence::{
    CheckpointFrequencyUpdateRequest, CheckpointPolicy, PersistenceBackend,
    PersistenceBackendError, PersistenceMode, PersistenceSnapshot,
};
use x0x::runtime::{AgentApiError, AgentCheckpointApi};

#[derive(Clone, Default)]
struct NoopBackend;

#[derive(Clone)]
struct FlakyBackend {
    fail_next_checkpoint: Arc<AtomicBool>,
}

impl FlakyBackend {
    fn fail_once_then_succeed() -> Self {
        Self {
            fail_next_checkpoint: Arc::new(AtomicBool::new(true)),
        }
    }
}

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

#[async_trait]
impl PersistenceBackend for FlakyBackend {
    async fn checkpoint(
        &self,
        _request: &x0x::crdt::persistence::CheckpointRequest,
        _snapshot: &PersistenceSnapshot,
    ) -> Result<(), PersistenceBackendError> {
        if self.fail_next_checkpoint.swap(false, Ordering::SeqCst) {
            return Err(PersistenceBackendError::Operation(
                "simulated checkpoint failure".to_string(),
            ));
        }

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
        AgentApiError::PolicyBounds(
            x0x::runtime::PolicyBoundsError::MutationThresholdOutOfBounds { .. }
        )
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
    assert!(
        contract
            .checkpoint_frequency_bounds
            .allow_runtime_checkpoint_frequency_adjustment
    );
    assert_eq!(contract.checkpoint_frequency.mutation_threshold, 48);
}

#[tokio::test]
async fn health_controls_checkpoint_success_self_heals_degraded_state() {
    let mut api = AgentCheckpointApi::new_with_mode(
        FlakyBackend::fail_once_then_succeed(),
        "entity-self-heal",
        2,
        PersistenceMode::Degraded,
        CheckpointPolicy {
            mutation_threshold: 1,
            dirty_time_floor: Duration::from_secs(300),
            debounce_floor: Duration::from_secs(0),
        },
    );

    let first = api
        .record_mutation_and_maybe_checkpoint(vec![1, 2, 3])
        .await;
    assert!(matches!(first, Err(AgentApiError::Backend(_))));

    let degraded = api.persistence_health();
    assert_eq!(
        degraded.state,
        x0x::crdt::persistence::PersistenceState::Degraded
    );
    assert!(degraded.degraded);
    assert!(degraded.last_error.is_some());

    let second = api.request_explicit_checkpoint(vec![1, 2, 3]).await;
    assert_eq!(
        second.expect("second checkpoint should succeed"),
        x0x::runtime::ExplicitCheckpointOutcome::Persisted
    );

    let healed = api.persistence_health();
    assert_eq!(
        healed.state,
        x0x::crdt::persistence::PersistenceState::Ready
    );
    assert!(!healed.degraded);
    assert!(healed.last_error.is_none());
}

#[tokio::test]
async fn health_controls_checkpoint_success_does_not_auto_clear_failed_strict_state() {
    let mut api = AgentCheckpointApi::new_with_mode(
        FlakyBackend::fail_once_then_succeed(),
        "entity-strict-failed",
        2,
        PersistenceMode::Strict,
        CheckpointPolicy {
            mutation_threshold: 1,
            dirty_time_floor: Duration::from_secs(300),
            debounce_floor: Duration::from_secs(0),
        },
    );

    let first = api
        .record_mutation_and_maybe_checkpoint(vec![1, 2, 3])
        .await;
    assert!(matches!(first, Err(AgentApiError::Backend(_))));

    let failed = api.persistence_health();
    assert_eq!(
        failed.state,
        x0x::crdt::persistence::PersistenceState::Failed
    );
    assert!(failed.degraded);
    assert!(failed.last_error.is_some());

    let second = api.request_explicit_checkpoint(vec![1, 2, 3]).await;
    assert_eq!(
        second.expect("second checkpoint should succeed"),
        x0x::runtime::ExplicitCheckpointOutcome::Persisted
    );

    let still_failed = api.persistence_health();
    assert_eq!(
        still_failed.state,
        x0x::crdt::persistence::PersistenceState::Failed
    );
    assert!(still_failed.degraded);
    assert!(still_failed.last_error.is_some());
}
