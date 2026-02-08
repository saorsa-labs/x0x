#[path = "../../bindings/nodejs/src/config.rs"]
mod node_config;
#[path = "../../bindings/python/src/config.rs"]
mod python_config;

use x0x::config::{ConfigError, StartupConfig};

#[test]
fn persistence_config_parity_defaults_match_core_resolution() {
    let core = StartupConfig::default()
        .resolve_persistence()
        .expect("core defaults resolve");

    let node = node_config::resolve_persistence_config(
        node_config::BindingPersistenceConfigInput::default(),
    )
    .expect("node defaults resolve");
    let python = python_config::resolve_persistence_config(
        python_config::BindingPersistenceConfigInput::default(),
    )
    .expect("python defaults resolve");

    assert_eq!(node.enabled, python.enabled);
    assert_eq!(node.mode, python.mode);
    assert_eq!(
        node.checkpoint_mutation_threshold,
        python.checkpoint_mutation_threshold
    );
    assert_eq!(
        node.checkpoint_dirty_time_floor_secs,
        python.checkpoint_dirty_time_floor_secs
    );
    assert_eq!(
        node.checkpoint_debounce_floor_secs,
        python.checkpoint_debounce_floor_secs
    );
    assert_eq!(
        node.retention_checkpoints_to_keep,
        python.retention_checkpoints_to_keep
    );
    assert_eq!(
        node.retention_storage_budget_bytes,
        python.retention_storage_budget_bytes
    );
    assert_eq!(
        node.retention_warning_threshold_percent,
        python.retention_warning_threshold_percent
    );
    assert_eq!(
        node.retention_critical_threshold_percent,
        python.retention_critical_threshold_percent
    );
    assert_eq!(
        node.strict_initialize_if_missing,
        python.strict_initialize_if_missing
    );
    assert_eq!(
        node.host_policy
            .allow_runtime_checkpoint_frequency_adjustment,
        python
            .host_policy
            .allow_runtime_checkpoint_frequency_adjustment
    );
    assert_eq!(node.enabled, core.policy.enabled);
    assert_eq!(node.mode, core.policy.mode.as_str());
    assert_eq!(
        node.checkpoint_mutation_threshold,
        core.policy.checkpoint.mutation_threshold
    );
    assert_eq!(
        node.checkpoint_dirty_time_floor_secs,
        core.policy.checkpoint.dirty_time_floor.as_secs()
    );
    assert_eq!(
        node.checkpoint_debounce_floor_secs,
        core.policy.checkpoint.debounce_floor.as_secs()
    );
    assert_eq!(
        node.strict_initialize_if_missing,
        core.policy.strict_initialization.initialize_if_missing
    );
    assert_eq!(
        node.host_policy
            .allow_runtime_checkpoint_frequency_adjustment,
        core.host_policy
            .allow_runtime_checkpoint_frequency_adjustment
    );
}

#[test]
fn persistence_config_parity_mode_parsing_matches_core_contract() {
    assert_eq!(
        node_config::parse_persistence_mode("STRICT").expect("node strict parse"),
        "strict"
    );
    assert_eq!(
        python_config::parse_persistence_mode("degraded").expect("python degraded parse"),
        "degraded"
    );

    assert!(matches!(
        node_config::parse_persistence_mode("best_effort"),
        Err(ConfigError::InvalidPersistenceMode(mode)) if mode == "best_effort"
    ));
    assert!(matches!(
        python_config::parse_persistence_mode("best_effort"),
        Err(ConfigError::InvalidPersistenceMode(mode)) if mode == "best_effort"
    ));
}

#[test]
fn persistence_config_parity_allows_strict_without_init_intent_at_resolution_boundary() {
    let node_result =
        node_config::resolve_persistence_config(node_config::BindingPersistenceConfigInput {
            enabled: true,
            mode: Some("strict".to_string()),
            ..node_config::BindingPersistenceConfigInput::default()
        });

    let python_result =
        python_config::resolve_persistence_config(python_config::BindingPersistenceConfigInput {
            enabled: true,
            mode: Some("strict".to_string()),
            ..python_config::BindingPersistenceConfigInput::default()
        });

    let node = node_result.expect("node strict config should resolve");
    let python = python_result.expect("python strict config should resolve");

    assert_eq!(node.mode, "strict");
    assert!(!node.strict_initialize_if_missing);
    assert_eq!(python.mode, "strict");
    assert!(!python.strict_initialize_if_missing);
}
