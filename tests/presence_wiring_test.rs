//! Smoke tests for presence system wiring.
//!
//! Verifies that the `PresenceWrapper` is correctly initialized
//! when an Agent is built, and that basic accessors work.

#![allow(clippy::unwrap_used)]

use tempfile::TempDir;

/// Agent built without network config should have no presence.
#[tokio::test]
async fn test_presence_none_without_network() {
    let tmp = TempDir::new().unwrap();
    let machine_key = tmp.path().join("machine.key");

    let agent = x0x::Agent::builder()
        .with_machine_key(machine_key.to_str().unwrap())
        .build()
        .await
        .unwrap();

    assert!(
        agent.presence_system().is_none(),
        "Agent without network should not have presence"
    );
}

/// Agent built with network config should have presence.
#[tokio::test]
async fn test_presence_some_with_network() {
    let tmp = TempDir::new().unwrap();
    let machine_key = tmp.path().join("machine.key");

    let agent = x0x::Agent::builder()
        .with_machine_key(machine_key.to_str().unwrap())
        .with_network_config(x0x::network::NetworkConfig::default())
        .build()
        .await
        .unwrap();

    assert!(
        agent.presence_system().is_some(),
        "Agent with network should have presence"
    );
}

/// Presence wrapper exposes a working event subscriber.
#[tokio::test]
async fn test_presence_subscribe_events() {
    let tmp = TempDir::new().unwrap();
    let machine_key = tmp.path().join("machine.key");

    let agent = x0x::Agent::builder()
        .with_machine_key(machine_key.to_str().unwrap())
        .with_network_config(x0x::network::NetworkConfig::default())
        .build()
        .await
        .unwrap();

    let pw = agent.presence_system().unwrap();
    let _rx = pw.subscribe_events();
    // Just verifying the channel was created — no events expected yet.
}

/// Presence config has sane defaults.
#[tokio::test]
async fn test_presence_config_defaults() {
    let tmp = TempDir::new().unwrap();
    let machine_key = tmp.path().join("machine.key");

    let agent = x0x::Agent::builder()
        .with_machine_key(machine_key.to_str().unwrap())
        .with_network_config(x0x::network::NetworkConfig::default())
        .build()
        .await
        .unwrap();

    let pw = agent.presence_system().unwrap();
    let config = pw.config();
    assert_eq!(config.beacon_interval_secs, 30);
    assert_eq!(config.foaf_default_ttl, 2);
    assert_eq!(config.foaf_timeout_ms, 5000);
    assert!(config.enable_beacons);
}

/// Shutdown is idempotent and safe to call multiple times.
#[tokio::test]
async fn test_presence_shutdown_idempotent() {
    let tmp = TempDir::new().unwrap();
    let machine_key = tmp.path().join("machine.key");

    let agent = x0x::Agent::builder()
        .with_machine_key(machine_key.to_str().unwrap())
        .with_network_config(x0x::network::NetworkConfig::default())
        .build()
        .await
        .unwrap();

    let pw = agent.presence_system().unwrap();
    pw.shutdown().await;
    pw.shutdown().await; // Second call should be safe.
}
