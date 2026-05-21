//! Smoke tests for presence system wiring.
//!
//! Verifies that the `PresenceWrapper` is correctly initialized
//! when an Agent is built, and that basic accessors work.

#![allow(clippy::unwrap_used)]

use saorsa_gossip_types::{PeerId, PresenceRecord};
use tempfile::TempDir;
use x0x::identity::{AgentId, MachineId};
use x0x::DiscoveredAgent;

fn isolated_builder(tmp: &TempDir) -> x0x::AgentBuilder {
    x0x::Agent::builder()
        .with_machine_key(tmp.path().join("machine.key"))
        .with_agent_key_path(tmp.path().join("agent.key"))
        .with_peer_cache_disabled()
}

fn loopback_network_config() -> x0x::network::NetworkConfig {
    x0x::network::NetworkConfig {
        bind_addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..Default::default()
    }
}

async fn build_or_skip_network_bind_error(
    builder: x0x::AgentBuilder,
) -> Result<Option<x0x::Agent>, Box<dyn std::error::Error>> {
    match builder.build().await {
        Ok(agent) => Ok(Some(agent)),
        Err(error) if is_network_bind_permission_error(&error) => Ok(None),
        Err(error) => Err(Box::new(error)),
    }
}

fn is_network_bind_permission_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("Operation not permitted")
        && (message.contains("bind UDP socket")
            || message.contains("network initialization failed"))
}

/// Agent built without network config should have no presence.
#[tokio::test]
async fn test_presence_none_without_network() {
    let tmp = TempDir::new().unwrap();

    let agent = isolated_builder(&tmp).build().await.unwrap();

    assert!(
        agent.presence_system().is_none(),
        "Agent without network should not have presence"
    );
}

/// Agent built with network config should have presence.
#[tokio::test]
async fn test_presence_some_with_network() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new().unwrap();

    let Some(agent) = build_or_skip_network_bind_error(
        isolated_builder(&tmp).with_network_config(loopback_network_config()),
    )
    .await?
    else {
        return Ok(());
    };

    assert!(
        agent.presence_system().is_some(),
        "Agent with network should have presence"
    );
    Ok(())
}

/// Presence wrapper exposes a working event subscriber.
#[tokio::test]
async fn test_presence_subscribe_events() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new().unwrap();

    let Some(agent) = build_or_skip_network_bind_error(
        isolated_builder(&tmp).with_network_config(loopback_network_config()),
    )
    .await?
    else {
        return Ok(());
    };

    let pw = agent.presence_system().unwrap();
    let _rx = pw.subscribe_events();
    // Just verifying the channel was created — no events expected yet.
    Ok(())
}

/// Presence config has sane defaults.
#[tokio::test]
async fn test_presence_config_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new().unwrap();

    let Some(agent) = build_or_skip_network_bind_error(
        isolated_builder(&tmp).with_network_config(loopback_network_config()),
    )
    .await?
    else {
        return Ok(());
    };

    let pw = agent.presence_system().unwrap();
    let config = pw.config();
    assert_eq!(config.beacon_interval_secs, 30);
    assert_eq!(config.foaf_default_ttl, 2);
    assert_eq!(config.foaf_timeout_ms, 5000);
    assert!(config.enable_beacons);
    Ok(())
}

/// `/presence/online` backing data comes from presence beacons, not only
/// identity announcement freshness.
#[tokio::test]
async fn test_online_agents_uses_presence_beacon_liveness() -> Result<(), Box<dyn std::error::Error>>
{
    let tmp = TempDir::new().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let peer_bytes = [42u8; 32];
    let agent_id = AgentId([7u8; 32]);
    let stale = now.saturating_sub(3_600);

    let Some(agent) = build_or_skip_network_bind_error(
        isolated_builder(&tmp)
            .with_identity_ttl(2)
            .with_network_config(loopback_network_config()),
    )
    .await?
    else {
        return Ok(());
    };

    agent
        .insert_discovered_agent_for_testing(DiscoveredAgent {
            agent_id,
            machine_id: MachineId(peer_bytes),
            user_id: None,
            addresses: Vec::new(),
            announced_at: stale,
            last_seen: stale,
            machine_public_key: vec![1u8; 32],
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
        })
        .await;

    agent
        .presence_system()
        .unwrap()
        .manager()
        .handle_beacon(
            x0x::presence::global_presence_topic(),
            PeerId::new(peer_bytes),
            PresenceRecord::new([3u8; 32], Vec::new(), 300),
        )
        .await
        .unwrap();

    let online = agent.online_agents().await.unwrap();
    let refreshed = online
        .iter()
        .find(|entry| entry.agent_id == agent_id)
        .unwrap();
    assert!(refreshed.last_seen > stale);
    Ok(())
}

/// Shutdown is idempotent and safe to call multiple times.
#[tokio::test]
async fn test_presence_shutdown_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new().unwrap();

    let Some(agent) = build_or_skip_network_bind_error(
        isolated_builder(&tmp).with_network_config(loopback_network_config()),
    )
    .await?
    else {
        return Ok(());
    };

    let pw = agent.presence_system().unwrap();
    pw.shutdown().await;
    pw.shutdown().await; // Second call should be safe.
    Ok(())
}
