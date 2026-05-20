#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

//! Integration tests for the bootstrap cache (ant_quic::BootstrapCache) integration.

use std::{ffi::OsString, path::Path};
use tempfile::TempDir;
use tokio::sync::Mutex;
use x0x::Agent;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

struct EnvVarOverride {
    key: &'static str,
    original: Option<OsString>,
}

impl EnvVarOverride {
    fn set(key: &'static str, value: &Path) -> Self {
        let original = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, original }
    }
}

impl Drop for EnvVarOverride {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

fn is_network_bind_permission_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("All socket binds failed") && message.contains("Operation not permitted")
}

/// Helper: build an agent with a temp peer cache directory.
async fn agent_with_cache(temp_dir: &TempDir) -> Agent {
    Agent::builder()
        .with_machine_key(temp_dir.path().join("machine.key"))
        .with_agent_key_path(temp_dir.path().join("agent.key"))
        .with_peer_cache_dir(temp_dir.path().join("peers"))
        .build()
        .await
        .expect("failed to build agent")
}

#[tokio::test]
async fn test_agent_builds_with_peer_cache_dir() {
    let temp = TempDir::new().unwrap();
    let agent = agent_with_cache(&temp).await;
    // Agent should have built successfully with cache dir configured.
    // No network config means no bootstrap cache is created (cache is only
    // created when network_config is set).
    assert!(agent.network().is_none());
}

#[tokio::test]
async fn test_agent_with_network_creates_cache_dir() {
    let temp = TempDir::new().unwrap();
    let cache_dir = temp.path().join("peers");

    let _agent = Agent::builder()
        .with_machine_key(temp.path().join("machine.key"))
        .with_agent_key_path(temp.path().join("agent.key"))
        .with_peer_cache_dir(&cache_dir)
        .with_network_config(x0x::network::NetworkConfig::default())
        .build()
        .await
        .expect("failed to build agent");

    // The cache directory should have been created by BootstrapCache::open().
    assert!(cache_dir.exists(), "Cache directory should be created");
}

#[tokio::test]
async fn test_shutdown_saves_cache() {
    let temp = TempDir::new().unwrap();
    let cache_dir = temp.path().join("peers");

    let agent = Agent::builder()
        .with_machine_key(temp.path().join("machine.key"))
        .with_agent_key_path(temp.path().join("agent.key"))
        .with_peer_cache_dir(&cache_dir)
        .with_network_config(x0x::network::NetworkConfig::default())
        .build()
        .await
        .expect("failed to build agent");

    // Shutdown should save without error (even with no peers to save).
    agent.shutdown().await;
}

#[tokio::test]
async fn test_cache_persists_across_restarts() {
    let temp = TempDir::new().unwrap();
    let cache_dir = temp.path().join("peers");

    // First agent: create cache and connect to build entries.
    {
        let agent = Agent::builder()
            .with_machine_key(temp.path().join("machine.key"))
            .with_agent_key_path(temp.path().join("agent.key"))
            .with_peer_cache_dir(&cache_dir)
            .with_network_config(x0x::network::NetworkConfig::default())
            .build()
            .await
            .expect("failed to build first agent");

        agent.shutdown().await;
    }

    // Second agent: should load from same cache dir without error.
    {
        let agent = Agent::builder()
            .with_machine_key(temp.path().join("machine.key"))
            .with_agent_key_path(temp.path().join("agent.key"))
            .with_peer_cache_dir(&cache_dir)
            .with_network_config(x0x::network::NetworkConfig::default())
            .build()
            .await
            .expect("failed to build second agent");

        agent.shutdown().await;
    }
}

#[tokio::test]
async fn test_default_cache_dir_when_not_specified() {
    let _env_lock = ENV_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let home_dir = temp.path().join("home");
    let xdg_cache_dir = temp.path().join("xdg-cache");
    let xdg_config_dir = temp.path().join("xdg-config");
    let xdg_data_dir = temp.path().join("xdg-data");
    std::fs::create_dir_all(&home_dir).expect("create isolated home");
    let _home = EnvVarOverride::set("HOME", &home_dir);
    let _xdg_cache = EnvVarOverride::set("XDG_CACHE_HOME", &xdg_cache_dir);
    let _xdg_config = EnvVarOverride::set("XDG_CONFIG_HOME", &xdg_config_dir);
    let _xdg_data = EnvVarOverride::set("XDG_DATA_HOME", &xdg_data_dir);

    // Build with network config but without explicit cache dir.
    // Should use default (~/.x0x/peers/) inside the isolated HOME.
    let build_result = Agent::builder()
        .with_machine_key(temp.path().join("machine.key"))
        .with_agent_key_path(temp.path().join("agent.key"))
        .with_network_config(x0x::network::NetworkConfig::default())
        .build()
        .await;

    match build_result {
        Ok(agent) => agent.shutdown().await,
        Err(err) => assert!(
            is_network_bind_permission_error(&err),
            "failed to build agent with default cache dir: {err}"
        ),
    }

    assert!(
        home_dir.join(".x0x").join("peers").exists(),
        "default cache directory should be created under isolated HOME"
    );
}
