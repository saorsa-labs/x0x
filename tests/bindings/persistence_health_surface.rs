#[path = "../../bindings/nodejs/src/health.rs"]
mod node_health;
#[path = "../../bindings/python/src/health.rs"]
mod python_health;

use x0x::crdt::persistence::{PersistenceBackendError, PersistenceHealth, PersistenceMode};

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
