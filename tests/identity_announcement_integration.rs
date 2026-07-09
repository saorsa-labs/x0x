//! Integration tests for identity announcement, discovery, heartbeat, and TTL expiry.
//!
//! Tests 1–5 and 8–9 are offline tests that do not require a live network.
//! Tests 6+ that need the gossip overlay to propagate announcements are `#[ignore]`.

use tempfile::TempDir;
use x0x::{network::NetworkConfig, Agent, DiscoveredAgent};

// ---------------------------------------------------------------------------
// Test 1: Signature verification (offline)
// ---------------------------------------------------------------------------

/// A signed announcement from a newly built agent should verify successfully.
#[tokio::test]
async fn test_identity_announcement_signature_verified() {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .build()
        .await
        .unwrap();

    let ann = agent.build_announcement(false, false).unwrap();
    ann.verify().unwrap();
    assert_eq!(ann.agent_id, agent.agent_id());
    assert_eq!(ann.machine_id, agent.machine_id());
    assert!(ann.user_id.is_none());
    assert!(ann.announced_at > 0);
}

// ---------------------------------------------------------------------------
// Test 2: Tampered signature rejected (offline)
// ---------------------------------------------------------------------------

/// Flipping a byte in the machine_signature should cause verify() to fail.
#[tokio::test]
async fn test_tampered_signature_rejected() {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .build()
        .await
        .unwrap();

    let mut ann = agent.build_announcement(false, false).unwrap();
    // Flip the first byte of the signature
    if let Some(b) = ann.machine_signature.first_mut() {
        *b ^= 0xFF;
    }
    assert!(
        ann.verify().is_err(),
        "tampered signature should fail verification"
    );
}

// ---------------------------------------------------------------------------
// Test 3: User identity in announcement (offline)
// ---------------------------------------------------------------------------

/// An announcement with user identity included should have user_id set and
/// should still verify correctly.
#[tokio::test]
async fn test_user_identity_in_announcement() {
    let dir = TempDir::new().unwrap();
    let user_kp = x0x::identity::UserKeypair::generate().unwrap();
    let expected_user_id = user_kp.user_id();

    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_agent_cert_path(dir.path().join("agent.cert"))
        .with_user_key(user_kp)
        .build()
        .await
        .unwrap();

    let ann = agent.build_announcement(true, true).unwrap();
    assert_eq!(ann.user_id, Some(expected_user_id));
    ann.verify().unwrap();
}

// ---------------------------------------------------------------------------
// Test 4: TTL expiry removes from presence (offline)
// ---------------------------------------------------------------------------

/// Cache entries with last_seen older than identity_ttl_secs should be
/// filtered from presence() and discovered_agents(), but still visible
/// via discovered_agents_unfiltered().
#[tokio::test]
async fn test_ttl_expiry_removes_from_presence() -> Result<(), Box<dyn std::error::Error>> {
    const IDENTITY_TTL_SECS: u64 = 2;

    let dir = TempDir::new()?;
    let Some(agent) = build_or_skip_network_bind_error(
        Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_identity_ttl(IDENTITY_TTL_SECS)
            .with_network_config(hermetic_network_config())
            .with_peer_cache_disabled(),
    )
    .await?
    else {
        return Ok(());
    };

    // Insert a fresh entry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    agent
        .insert_discovered_agent_for_testing(fake_agent(now))
        .await;

    let presence = agent.presence().await?;
    assert!(!presence.is_empty(), "entry should be visible immediately");

    let stale_last_seen = now.saturating_sub(IDENTITY_TTL_SECS + 1);
    agent
        .insert_discovered_agent_for_testing(fake_agent_with_timestamps(now, stale_last_seen))
        .await;

    let presence_after = agent.presence().await?;
    assert!(
        presence_after.is_empty(),
        "entry should be filtered after TTL expires"
    );
    let discovered_after = agent.discovered_agents().await?;
    assert!(
        discovered_after.is_empty(),
        "discovered_agents should also be empty"
    );
    let unfiltered = agent.discovered_agents_unfiltered().await?;
    assert!(
        !unfiltered.is_empty(),
        "unfiltered cache should still hold the stale entry"
    );

    Ok(())
}

async fn build_or_skip_network_bind_error(
    builder: x0x::AgentBuilder,
) -> Result<Option<Agent>, Box<dyn std::error::Error>> {
    match builder.build().await {
        Ok(agent) => Ok(Some(agent)),
        Err(err) if is_network_bind_permission_error(&err) => Ok(None),
        Err(err) => Err(Box::new(err)),
    }
}

fn is_network_bind_permission_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("Operation not permitted")
        && (message.contains("bind UDP socket")
            || message.contains("network initialization failed"))
}

// ---------------------------------------------------------------------------
// Test 5: Default heartbeat and TTL constants
// ---------------------------------------------------------------------------

#[test]
fn test_default_heartbeat_and_ttl_constants() {
    // Heartbeats are anti-entropy and remain well inside the 900 s TTL, while
    // avoiding sustained PubSub pressure from repeated signed announcements.
    assert_eq!(x0x::IDENTITY_HEARTBEAT_INTERVAL_SECS, 300);
    assert_eq!(x0x::IDENTITY_TTL_SECS, 900);
}

#[test]
fn test_hermetic_network_config_has_no_bootstrap_nodes() {
    assert!(
        hermetic_network_config().bootstrap_nodes.is_empty(),
        "offline identity tests must not inherit live bootstrap nodes"
    );
}

// ---------------------------------------------------------------------------
// Test 6: find_agents_by_user returns agents linked to a user identity
// ---------------------------------------------------------------------------

/// announce_identity populates the agent's own cache (self-discovery).
/// After announcing with include_user=true, find_agents_by_user should
/// return this agent.
#[tokio::test]
async fn test_find_agents_by_user_linked() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let user_kp = x0x::identity::UserKeypair::generate()?;
    let expected_user_id = user_kp.user_id();

    let Some(agent) = build_or_skip_network_bind_error(
        Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_agent_cert_path(dir.path().join("agent.cert"))
            .with_user_key(user_kp)
            .with_network_config(hermetic_network_config())
            .with_peer_cache_disabled(),
    )
    .await?
    else {
        return Ok(());
    };

    // announce_identity populates own cache
    agent.announce_identity(true, true).await?;

    let found = agent.find_agents_by_user(expected_user_id).await?;
    assert_eq!(
        found.len(),
        1,
        "should find exactly one agent for this user"
    );
    assert_eq!(found[0].agent_id, agent.agent_id());
    assert_eq!(found[0].user_id, Some(expected_user_id));
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 7: find_agents_by_user returns empty without user declaration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_find_agents_by_user_without_declaration_returns_empty(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let user_kp = x0x::identity::UserKeypair::generate()?;
    let user_id = user_kp.user_id();

    let Some(agent) = build_or_skip_network_bind_error(
        Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_agent_cert_path(dir.path().join("agent.cert"))
            .with_user_key(user_kp)
            .with_network_config(hermetic_network_config())
            .with_peer_cache_disabled(),
    )
    .await?
    else {
        return Ok(());
    };

    // Announce WITHOUT user identity
    agent.announce_identity(false, false).await?;

    let found = agent.find_agents_by_user(user_id).await?;
    assert!(
        found.is_empty(),
        "should return empty when user_id not included in announcement"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 8: shard topic is deterministic
// ---------------------------------------------------------------------------

#[test]
fn test_shard_topic_deterministic() {
    let agent_id = x0x::identity::AgentId([42u8; 32]);
    let topic_a = x0x::shard_topic_for_agent(&agent_id);
    let topic_b = x0x::shard_topic_for_agent(&agent_id);
    assert_eq!(
        topic_a, topic_b,
        "same AgentId must always yield the same topic"
    );
    assert!(
        topic_a.starts_with("x0x.identity.shard.v2."),
        "topic must use expected prefix"
    );
}

// ---------------------------------------------------------------------------
// Test 9: shard distribution is roughly uniform
// ---------------------------------------------------------------------------

#[test]
fn test_shard_distribution_uniform() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;
    let n = 10_000u32;
    let mut counts: HashMap<u16, u32> = HashMap::new();
    for i in 0..n {
        let mut id_bytes = [0u8; 32];
        id_bytes[..4].copy_from_slice(&i.to_le_bytes());
        let agent_id = x0x::identity::AgentId(id_bytes);
        let topic = x0x::shard_topic_for_agent(&agent_id);
        let shard: u16 = topic.trim_start_matches("x0x.identity.shard.v2.").parse()?;
        *counts.entry(shard).or_insert(0) += 1;
    }
    // Expected occupancy for 10000 samples over 65536 shards is ~9274 distinct shards.
    let distinct_shards = counts.len();
    assert!(
        distinct_shards > 9_000,
        "shard distribution covered too few shards: {distinct_shards} distinct shards"
    );
    // Keep a conservative per-shard collision ceiling as a backstop.
    let max_count = counts.values().copied().max().unwrap_or(0);
    assert!(
        max_count <= 10,
        "shard distribution too skewed: max count per shard = {max_count}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 10: rendezvous shard topic is deterministic
// ---------------------------------------------------------------------------

#[test]
fn test_rendezvous_shard_topic_deterministic() {
    let agent_id = x0x::identity::AgentId([99u8; 32]);
    let topic_a = x0x::rendezvous_shard_topic_for_agent(&agent_id);
    let topic_b = x0x::rendezvous_shard_topic_for_agent(&agent_id);
    assert_eq!(
        topic_a, topic_b,
        "same AgentId must always yield the same rendezvous topic"
    );
    assert!(
        topic_a.starts_with("x0x.rendezvous.shard."),
        "rendezvous topic must use expected prefix"
    );
}

// ---------------------------------------------------------------------------
// Test 11: rendezvous and identity shards use the same shard number
//          (same AgentId → same shard, different prefix)
// ---------------------------------------------------------------------------

#[test]
fn test_rendezvous_and_identity_shard_numbers_match() {
    let agent_id = x0x::identity::AgentId([77u8; 32]);
    let id_topic = x0x::shard_topic_for_agent(&agent_id);
    let rdv_topic = x0x::rendezvous_shard_topic_for_agent(&agent_id);
    // Both should end in the same shard number
    let id_num = id_topic.trim_start_matches("x0x.identity.shard.v2.");
    let rdv_num = rdv_topic.trim_start_matches("x0x.rendezvous.shard.");
    assert_eq!(id_num, rdv_num, "shard numbers must be identical");
}

// ---------------------------------------------------------------------------
// Test 12: round-trip via live gossip overlay (requires network)
// ---------------------------------------------------------------------------

#[ignore = "requires gossip overlay propagation between two agents"]
#[tokio::test]
async fn test_identity_announcement_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let (agent_a, agent_b, _dir_a, _dir_b) = two_local_agents().await?;
    agent_a.announce_identity(false, false).await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let discovered = agent_b.discovered_agents().await?;
    assert!(
        discovered.iter().any(|a| a.agent_id == agent_a.agent_id()),
        "agent B should discover agent A after announcement"
    );
    Ok(())
}

#[ignore = "requires live VPS bootstrap nodes"]
#[tokio::test]
async fn test_vps_round_trip() {
    // Use default network config with real bootstrap nodes
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();

    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    let discovered = agent_b.discovered_agents().await.unwrap();
    assert!(
        discovered.iter().any(|a| a.agent_id == agent_a.agent_id()),
        "agent B should discover agent A within 15s via VPS bootstrap"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fake_agent(last_seen: u64) -> DiscoveredAgent {
    fake_agent_with_timestamps(last_seen, last_seen)
}

fn fake_agent_with_timestamps(announced_at: u64, last_seen: u64) -> DiscoveredAgent {
    DiscoveredAgent {
        agent_id: x0x::identity::AgentId([1u8; 32]),
        machine_id: x0x::identity::MachineId([2u8; 32]),
        user_id: None,
        addresses: Vec::new(),
        announced_at,
        last_seen,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    }
}

fn hermetic_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..Default::default()
    }
}

#[allow(dead_code)]
async fn two_local_agents() -> Result<(Agent, Agent, TempDir, TempDir), Box<dyn std::error::Error>>
{
    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;
    let cfg_a = hermetic_network_config();
    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a)
        .with_peer_cache_disabled()
        .build()
        .await?;
    agent_a.join_network().await?;

    let a_addr = agent_a
        .bound_addr()
        .await
        .ok_or_else(|| std::io::Error::other("agent A did not report a bound address"))?;
    if a_addr.port() == 0 {
        return Err(std::io::Error::other("agent A reported port 0 as its bound address").into());
    }
    let cfg_b = NetworkConfig {
        bind_addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
        bootstrap_nodes: vec![a_addr],
        port_mapping_enabled: false,
        ..Default::default()
    };
    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b)
        .with_peer_cache_disabled()
        .build()
        .await?;
    agent_b.join_network().await?;

    Ok((agent_a, agent_b, dir_a, dir_b))
}
