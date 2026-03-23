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
        .with_network_config(NetworkConfig::default())
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
        .with_network_config(NetworkConfig::default())
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
        .with_user_key(user_kp)
        .with_network_config(NetworkConfig::default())
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
async fn test_ttl_expiry_removes_from_presence() {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_identity_ttl(2)
        .with_network_config(NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            bootstrap_nodes: vec![],
            ..Default::default()
        })
        .build()
        .await
        .unwrap();

    // Insert a fresh entry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    agent
        .insert_discovered_agent_for_testing(fake_agent(now))
        .await;

    let presence = agent.presence().await.unwrap();
    assert!(!presence.is_empty(), "entry should be visible immediately");

    // Wait for TTL to expire (TTL = 2s, sleep 3s)
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let presence_after = agent.presence().await.unwrap();
    assert!(
        presence_after.is_empty(),
        "entry should be filtered after TTL expires"
    );
    let discovered_after = agent.discovered_agents().await.unwrap();
    assert!(
        discovered_after.is_empty(),
        "discovered_agents should also be empty"
    );
    let unfiltered = agent.discovered_agents_unfiltered().await.unwrap();
    assert!(
        !unfiltered.is_empty(),
        "unfiltered cache should still hold the stale entry"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Default heartbeat and TTL constants
// ---------------------------------------------------------------------------

#[test]
fn test_default_heartbeat_and_ttl_constants() {
    assert_eq!(x0x::IDENTITY_HEARTBEAT_INTERVAL_SECS, 300);
    assert_eq!(x0x::IDENTITY_TTL_SECS, 900);
}

// ---------------------------------------------------------------------------
// Test 6: find_agents_by_user returns agents linked to a user identity
// ---------------------------------------------------------------------------

/// announce_identity populates the agent's own cache (self-discovery).
/// After announcing with include_user=true, find_agents_by_user should
/// return this agent.
#[tokio::test]
async fn test_find_agents_by_user_linked() {
    let dir = TempDir::new().unwrap();
    let user_kp = x0x::identity::UserKeypair::generate().unwrap();
    let expected_user_id = user_kp.user_id();

    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_user_key(user_kp)
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    // announce_identity populates own cache
    agent.announce_identity(true, true).await.unwrap();

    let found = agent.find_agents_by_user(expected_user_id).await.unwrap();
    assert_eq!(
        found.len(),
        1,
        "should find exactly one agent for this user"
    );
    assert_eq!(found[0].agent_id, agent.agent_id());
    assert_eq!(found[0].user_id, Some(expected_user_id));
}

// ---------------------------------------------------------------------------
// Test 7: find_agents_by_user returns empty without user declaration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_find_agents_by_user_without_declaration_returns_empty() {
    let dir = TempDir::new().unwrap();
    let user_kp = x0x::identity::UserKeypair::generate().unwrap();
    let user_id = user_kp.user_id();

    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_user_key(user_kp)
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    // Announce WITHOUT user identity
    agent.announce_identity(false, false).await.unwrap();

    let found = agent.find_agents_by_user(user_id).await.unwrap();
    assert!(
        found.is_empty(),
        "should return empty when user_id not included in announcement"
    );
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
        topic_a.starts_with("x0x.identity.shard."),
        "topic must use expected prefix"
    );
}

// ---------------------------------------------------------------------------
// Test 9: shard distribution is roughly uniform
// ---------------------------------------------------------------------------

#[test]
fn test_shard_distribution_uniform() {
    use std::collections::HashMap;
    let n = 10_000u32;
    let mut counts: HashMap<u16, u32> = HashMap::new();
    for i in 0..n {
        let mut id_bytes = [0u8; 32];
        id_bytes[..4].copy_from_slice(&i.to_le_bytes());
        let agent_id = x0x::identity::AgentId(id_bytes);
        let topic = x0x::shard_topic_for_agent(&agent_id);
        let shard: u16 = topic
            .trim_start_matches("x0x.identity.shard.")
            .parse()
            .unwrap();
        *counts.entry(shard).or_insert(0) += 1;
    }
    // With 65536 shards and 10000 samples, the expected count per shard is ~0.15.
    // No single shard should account for more than 0.5% (50 out of 10000).
    let max_count = counts.values().copied().max().unwrap_or(0);
    assert!(
        max_count <= 50,
        "shard distribution too skewed: max count per shard = {max_count}"
    );
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
    let id_num = id_topic.trim_start_matches("x0x.identity.shard.");
    let rdv_num = rdv_topic.trim_start_matches("x0x.rendezvous.shard.");
    assert_eq!(id_num, rdv_num, "shard numbers must be identical");
}

// ---------------------------------------------------------------------------
// Test 12: round-trip via live gossip overlay (requires network)
// ---------------------------------------------------------------------------

#[ignore = "requires gossip overlay propagation between two agents"]
#[tokio::test]
async fn test_identity_announcement_round_trip() {
    let (agent_a, agent_b, _dir_a, _dir_b) = two_local_agents().await;
    agent_a.announce_identity(false, false).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let discovered = agent_b.discovered_agents().await.unwrap();
    assert!(
        discovered.iter().any(|a| a.agent_id == agent_a.agent_id()),
        "agent B should discover agent A after announcement"
    );
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
    DiscoveredAgent {
        agent_id: x0x::identity::AgentId([1u8; 32]),
        machine_id: x0x::identity::MachineId([2u8; 32]),
        user_id: None,
        addresses: Vec::new(),
        announced_at: last_seen,
        last_seen,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: None,
        is_relay: None,
        is_coordinator: None,
    }
}

#[allow(dead_code)]
async fn two_local_agents() -> (Agent, Agent, TempDir, TempDir) {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let cfg_a = NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: vec![],
        ..Default::default()
    };
    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a)
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();

    let a_addr = agent_a
        .local_addr()
        .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
    let cfg_b = NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: vec![a_addr],
        ..Default::default()
    };
    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b)
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    (agent_a, agent_b, dir_a, dir_b)
}
