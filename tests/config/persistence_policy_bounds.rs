use std::time::Duration;

use x0x::config::{HostPolicyEnvelopeConfig, PersistenceConfig, StartupConfig};
use x0x::crdt::persistence::PersistencePolicy;
use x0x::runtime::{
    apply_checkpoint_frequency_update, PolicyBoundsError, RuntimeCheckpointPolicyUpdate,
};

#[test]
fn persistence_policy_bounds_invalid_host_envelope_is_rejected() {
    let config = StartupConfig {
        persistence: PersistenceConfig {
            enabled: true,
            host_policy: HostPolicyEnvelopeConfig {
                min_mutation_threshold: 64,
                max_mutation_threshold: 32,
                ..HostPolicyEnvelopeConfig::default()
            },
            ..PersistenceConfig::default()
        },
    };

    let result = config.resolve_persistence();
    assert!(matches!(
        result.unwrap_err(),
        x0x::config::ConfigError::InvalidHostPolicyEnvelope(
            PolicyBoundsError::InvalidMutationThresholdBounds { .. }
        )
    ));
}

#[test]
fn persistence_policy_bounds_runtime_updates_rejected_without_host_allowance() {
    let policy = PersistencePolicy {
        enabled: true,
        ..PersistencePolicy::default()
    };
    let envelope = HostPolicyEnvelopeConfig::default();

    let result = apply_checkpoint_frequency_update(
        &policy,
        &envelope,
        &RuntimeCheckpointPolicyUpdate {
            mutation_threshold: Some(48),
            dirty_time_floor: None,
            debounce_floor: None,
        },
    );

    assert_eq!(
        result.unwrap_err(),
        PolicyBoundsError::RuntimeCheckpointAdjustmentNotAllowed
    );
}

#[test]
fn persistence_policy_bounds_out_of_range_runtime_updates_are_rejected() {
    let policy = PersistencePolicy {
        enabled: true,
        ..PersistencePolicy::default()
    };
    let envelope = HostPolicyEnvelopeConfig {
        allow_runtime_checkpoint_frequency_adjustment: true,
        min_mutation_threshold: 16,
        max_mutation_threshold: 64,
        min_dirty_time_floor_secs: 120,
        max_dirty_time_floor_secs: 900,
        min_debounce_floor_secs: 1,
        max_debounce_floor_secs: 10,
    };

    let result = apply_checkpoint_frequency_update(
        &policy,
        &envelope,
        &RuntimeCheckpointPolicyUpdate {
            mutation_threshold: Some(80),
            dirty_time_floor: Some(Duration::from_secs(300)),
            debounce_floor: Some(Duration::from_secs(3)),
        },
    );

    assert!(matches!(
        result.unwrap_err(),
        PolicyBoundsError::MutationThresholdOutOfBounds { .. }
    ));
}
