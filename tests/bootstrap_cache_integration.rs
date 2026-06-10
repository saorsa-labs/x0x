#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

//! Integration tests for the bootstrap cache (ant_quic::BootstrapCache) integration.

use saorsa_gossip_coordinator::{AddrHint, CoordinatorAdvert, CoordinatorRoles, NatClass};
use saorsa_gossip_types::PeerId;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    time::SystemTime,
};
use tempfile::TempDir;
use tokio::sync::Mutex;
use x0x::{network::NetworkConfig, Agent};

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
    message.contains("Operation not permitted")
        && (message.contains("All socket binds failed")
            || message.contains("Failed to bind UDP socket"))
}

fn path_snapshot(path: &Path) -> Option<(bool, u64, Option<SystemTime>)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.is_dir(), metadata.len(), metadata.modified().ok()))
}

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
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

async fn agent_with_network_cache(
    temp_dir: &TempDir,
    cache_dir: &Path,
) -> x0x::error::Result<Option<Agent>> {
    match Agent::builder()
        .with_machine_key(temp_dir.path().join("machine.key"))
        .with_agent_key_path(temp_dir.path().join("agent.key"))
        .with_peer_cache_dir(cache_dir)
        .with_network_config(loopback_network_config())
        .build()
        .await
    {
        Ok(agent) => Ok(Some(agent)),
        Err(err) if is_network_bind_permission_error(&err) => Ok(None),
        Err(err) => Err(err),
    }
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
    let peer_id = PeerId::new([17u8; 32]);
    let addr = "127.0.0.1:5483".parse().unwrap();
    let advert = CoordinatorAdvert::new(
        peer_id,
        CoordinatorRoles::default(),
        vec![AddrHint::new(addr)],
        NatClass::Unknown,
        60_000,
    );

    // First agent: seed a real cache entry and save it on shutdown.
    {
        let Some(agent) = agent_with_network_cache(&temp, &cache_dir)
            .await
            .expect("failed to build first agent")
        else {
            return;
        };
        let adapter = agent
            .gossip_cache_adapter()
            .expect("network agent should expose cache adapter");

        assert!(adapter.insert_advert(advert).await);
        assert_eq!(adapter.peer_count().await, 1);

        agent.shutdown().await;
    }

    // Second agent: load from the same cache dir and observe the saved peer.
    {
        let agent = agent_with_network_cache(&temp, &cache_dir)
            .await
            .expect("failed to build second agent")
            .expect("network should still be available for second agent");
        let adapter = agent
            .gossip_cache_adapter()
            .expect("network agent should expose cache adapter");
        let cached_peer = adapter
            .get_peer(&peer_id)
            .await
            .expect("seeded peer should persist across restart");

        assert_eq!(cached_peer.peer_id, ant_quic::PeerId(*peer_id.as_bytes()));
        assert!(
            cached_peer.addresses.contains(&addr),
            "persisted peer should retain seeded address"
        );

        agent.shutdown().await;
    }
}

#[tokio::test]
async fn test_default_cache_dir_when_not_specified() {
    let _env_lock = ENV_LOCK.lock().await;
    let temp = TempDir::new().unwrap();
    let real_cache_paths = std::env::var_os("HOME").map(|home| {
        let dir = PathBuf::from(home).join(".x0x").join("peers");
        let cache_file = dir.join("bootstrap_cache.json");
        let lock_file = dir.join("bootstrap_cache.json.lock");
        (
            dir.clone(),
            path_snapshot(&dir),
            cache_file.clone(),
            path_snapshot(&cache_file),
            lock_file.clone(),
            path_snapshot(&lock_file),
        )
    });
    let home_dir = temp.path().join("home");
    let xdg_cache_dir = temp.path().join("xdg-cache");
    let xdg_config_dir = temp.path().join("xdg-config");
    let xdg_data_dir = temp.path().join("xdg-data");
    let default_cache_dir = home_dir.join(".x0x").join("peers");
    std::fs::create_dir_all(&home_dir).expect("create isolated home");
    let _home = EnvVarOverride::set("HOME", &home_dir);
    let _user_profile = EnvVarOverride::set("USERPROFILE", &home_dir);
    let _xdg_cache = EnvVarOverride::set("XDG_CACHE_HOME", &xdg_cache_dir);
    let _xdg_config = EnvVarOverride::set("XDG_CONFIG_HOME", &xdg_config_dir);
    let _xdg_data = EnvVarOverride::set("XDG_DATA_HOME", &xdg_data_dir);
    assert!(
        !default_cache_dir.exists(),
        "isolated default cache directory should start absent"
    );

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
        default_cache_dir.exists(),
        "default cache directory should be created under isolated HOME"
    );

    if let Some((
        real_cache_dir,
        real_cache_dir_before,
        real_cache_file,
        real_cache_file_before,
        real_cache_lock_file,
        real_cache_lock_file_before,
    )) = real_cache_paths
    {
        assert_eq!(
            path_snapshot(&real_cache_dir),
            real_cache_dir_before,
            "real HOME cache directory should not be created or modified"
        );
        assert_eq!(
            path_snapshot(&real_cache_file),
            real_cache_file_before,
            "real HOME cache file should not be created or modified"
        );
        assert_eq!(
            path_snapshot(&real_cache_lock_file),
            real_cache_lock_file_before,
            "real HOME cache lock file should not be created or modified"
        );
    }
}
