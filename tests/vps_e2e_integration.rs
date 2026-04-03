//! End-to-end integration tests for x0x v0.3.0 feature coverage.
//!
//! ## Test categories
//!
//! - **Local e2e** (no `#[ignore]`): Two agents on loopback, directly
//!   connected via explicit bootstrap address. Tests the full library stack
//!   without network access. Suitable for CI.
//!
//! - **VPS e2e** (`#[ignore = "requires live VPS bootstrap nodes"]`):
//!   Same tests but with VPS bootstrap nodes added. Must be run from a
//!   machine with UDP access to port 5483 on the VPS nodes (not behind
//!   restrictive NAT). Run from a VPS or with UDP 5483 open.
//!
//! Run local tests:
//! ```bash
//! cargo nextest run --test vps_e2e_integration
//! ```
//!
//! Run VPS tests (from a machine with QUIC/UDP access):
//! ```bash
//! cargo nextest run --test vps_e2e_integration --run-ignored only
//! ```
//!
//! ## Coverage
//!
//! 1. Identity announcement → discovery via gossip overlay
//! 2. Heartbeat-driven late-join discovery
//! 3. Three-stage `find_agent()`: cache → shard → rendezvous
//! 4. User identity (`find_agents_by_user`)
//!
//! ## PlumTree routing note
//!
//! PlumTree dissemination is fire-and-forget: a subscriber only receives
//! messages published after it subscribes. More importantly, messages only
//! route to nodes that are in the sender's PlumTree for that topic, which
//! is initialised from `connected_peers()` at subscribe/publish time.
//!
//! For two agents A and B to exchange pub/sub messages they must be
//! **directly connected** (or connected via a node that has both in its
//! topic tree). Tests achieve this by passing A's local address to B as an
//! explicit bootstrap peer.

use tempfile::TempDir;
use x0x::{network::NetworkConfig, Agent};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a NetworkConfig for Agent A: bind to loopback with ephemeral port.
/// No VPS bootstrap nodes — local-only.
fn cfg_a_local(_port_offset: u16) -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: vec![],
        ..Default::default()
    }
}

/// Build a NetworkConfig for Agent A: bind to loopback + connect to live VPS.
fn cfg_a_vps(_port_offset: u16) -> NetworkConfig {
    use x0x::network::DEFAULT_BOOTSTRAP_PEERS;
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: DEFAULT_BOOTSTRAP_PEERS
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect(),
        ..Default::default()
    }
}

/// Build a NetworkConfig for Agent B, adding Agent A's local address as an
/// explicit bootstrap peer so PlumTree routing is immediate.
fn cfg_b(a_addr: std::net::SocketAddr, vps: bool) -> NetworkConfig {
    let mut nodes: Vec<std::net::SocketAddr> = if vps {
        use x0x::network::DEFAULT_BOOTSTRAP_PEERS;
        DEFAULT_BOOTSTRAP_PEERS
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    } else {
        vec![]
    };
    nodes.push(a_addr);
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: nodes,
        ..Default::default()
    }
}

/// Rendezvous advertisement validity used in VPS tests: 1 hour in milliseconds.
const RENDEZVOUS_VALIDITY_MS: u64 = 3_600_000;

/// Poll `discovered_agents()` until `target_id` appears or the timeout elapses.
async fn wait_for_discovery(
    observer: &Agent,
    target_id: x0x::identity::AgentId,
    timeout: std::time::Duration,
) -> bool {
    let start = tokio::time::Instant::now();
    loop {
        let agents = observer.discovered_agents().await.unwrap_or_default();
        if agents.iter().any(|a| a.agent_id == target_id) {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

// ---------------------------------------------------------------------------
// Test 1 (local): Identity announcement + discovery
// ---------------------------------------------------------------------------

/// A joins and auto-announces. B has a direct link to A (via bootstrap addr).
/// B should discover A within 10s via the gossip overlay.
#[ignore = "requires real QUIC loopback connections — timing-sensitive on macOS dual-stack"]
#[tokio::test(flavor = "multi_thread")]
async fn test_local_identity_announcement_and_discovery() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a_local(0))
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();

    let a_addr = agent_a
        .bound_addr()
        .await
        .expect("agent A must have a bound address");

    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b(a_addr, false))
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    // B is now directly connected to A; re-announce so the announcement
    // is delivered while B's PlumTree peer set includes A.
    agent_a.announce_identity(false, false).await.unwrap();

    let found = wait_for_discovery(
        &agent_b,
        agent_a.agent_id(),
        std::time::Duration::from_secs(10),
    )
    .await;

    assert!(found, "Agent B should discover Agent A within 10s");

    let discovered = agent_b.discovered_agents().await.unwrap();
    let entry = discovered
        .iter()
        .find(|a| a.agent_id == agent_a.agent_id())
        .expect("entry must be present");

    assert_eq!(entry.machine_id, agent_a.machine_id());
    assert!(entry.user_id.is_none());
    assert!(entry.announced_at > 0);
    assert!(
        !entry.machine_public_key.is_empty(),
        "machine public key must be populated"
    );
}

// ---------------------------------------------------------------------------
// Test 2 (local): Heartbeat-driven late-join discovery
// ---------------------------------------------------------------------------

/// A joins with a 5s heartbeat. B joins 8s later — missing A's initial
/// announcement — then catches A's next heartbeat within 8s.
#[ignore = "requires real QUIC loopback connections — timing-sensitive on macOS dual-stack"]
#[tokio::test(flavor = "multi_thread")]
async fn test_local_late_join_heartbeat_discovery() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a_local(1))
        .with_heartbeat_interval(5)
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();

    let a_addr = agent_a
        .bound_addr()
        .await
        .expect("agent A must have a bound address");

    // B joins 8s after A — after the initial announcement but before the
    // second heartbeat (fires at t ≈ 10s).
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;

    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b(a_addr, false))
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    // Heartbeat fires within ~5s; give 10s total.
    let found = wait_for_discovery(
        &agent_b,
        agent_a.agent_id(),
        std::time::Duration::from_secs(10),
    )
    .await;

    assert!(
        found,
        "Late-joining Agent B should discover Agent A within 10s via heartbeat"
    );
}

// ---------------------------------------------------------------------------
// Test 3 (local): Three-stage find_agent()
// ---------------------------------------------------------------------------

/// A and B connect (B bootstraps via A). After both are online, A re-announces
/// so B's identity listener (running on the legacy topic) populates B's cache.
/// `find_agent()` is then called from B — it must return via the cache-hit
/// path (stage 1) immediately.
///
/// This exercises the real QUIC → PlumTree → cache → find_agent pipeline end
/// to end on the local network stack.
#[ignore = "requires real QUIC loopback connections — timing-sensitive on macOS dual-stack"]
#[tokio::test(flavor = "multi_thread")]
async fn test_local_find_agent_returns_cached_result() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a_local(2))
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();

    let a_addr = agent_a
        .bound_addr()
        .await
        .expect("agent A must have a bound address");

    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b(a_addr, false))
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    // Both agents are now directly connected. Re-announce so B's identity
    // listener receives the legacy-topic broadcast and populates its cache.
    agent_a.announce_identity(false, false).await.unwrap();

    // Wait until B discovers A, confirming the full gossip delivery path works.
    let discovered = wait_for_discovery(
        &agent_b,
        agent_a.agent_id(),
        std::time::Duration::from_secs(10),
    )
    .await;
    assert!(
        discovered,
        "identity listener must populate B's cache from A's announcement"
    );

    // Now find_agent() must return immediately via stage-1 cache hit.
    let result = agent_b
        .find_agent(agent_a.agent_id())
        .await
        .expect("find_agent must not error");

    assert!(
        result.is_some(),
        "find_agent must return Some when target is already in cache"
    );

    let addrs = result.unwrap();
    assert!(
        !addrs.is_empty(),
        "cached entry must include at least one address"
    );
}

// ---------------------------------------------------------------------------
// Test 4 (local): User identity — find_agents_by_user
// ---------------------------------------------------------------------------

/// A joins with a UserKeypair, announces with `include_user = true`.
/// B should be able to look up A by UserId.
#[ignore = "requires real QUIC loopback connections — timing-sensitive on macOS dual-stack"]
#[tokio::test(flavor = "multi_thread")]
async fn test_local_user_identity_discovery() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let user_kp = x0x::identity::UserKeypair::generate().unwrap();
    let user_id = user_kp.user_id();

    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a_local(3))
        .with_user_key(user_kp)
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();
    agent_a.announce_identity(true, true).await.unwrap();

    let a_addr = agent_a
        .bound_addr()
        .await
        .expect("agent A must have a bound address");

    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b(a_addr, false))
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    // Both A and B are now connected. Re-announce with user identity so
    // B's PlumTree receives the user-bearing announcement.
    agent_a.announce_identity(true, true).await.unwrap();

    let found = wait_for_discovery(
        &agent_b,
        agent_a.agent_id(),
        std::time::Duration::from_secs(10),
    )
    .await;
    assert!(found, "Agent B should discover Agent A within 10s");

    let by_user = agent_b
        .find_agents_by_user(user_id)
        .await
        .expect("find_agents_by_user must not error");

    assert!(
        !by_user.is_empty(),
        "find_agents_by_user should return Agent A"
    );
    assert_eq!(by_user[0].agent_id, agent_a.agent_id());
    assert_eq!(by_user[0].user_id, Some(user_id));
}

// ---------------------------------------------------------------------------
// VPS variants (same tests but with live bootstrap nodes)
// Must be run from a machine with UDP access to port 5483.
// ---------------------------------------------------------------------------

#[ignore = "requires live VPS bootstrap nodes (UDP port 5483 must be accessible)"]
#[tokio::test(flavor = "multi_thread")]
async fn test_vps_identity_announcement_and_discovery() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a_vps(10))
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();

    let a_addr = agent_a
        .bound_addr()
        .await
        .expect("agent A must have a bound address");

    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b(a_addr, true))
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    let found = wait_for_discovery(
        &agent_b,
        agent_a.agent_id(),
        std::time::Duration::from_secs(20),
    )
    .await;
    assert!(
        found,
        "Agent B should discover Agent A within 20s via VPS gossip"
    );

    let discovered = agent_b.discovered_agents().await.unwrap();
    let entry = discovered
        .iter()
        .find(|a| a.agent_id == agent_a.agent_id())
        .expect("entry must be present");
    assert_eq!(entry.machine_id, agent_a.machine_id());
    assert!(!entry.machine_public_key.is_empty());
}

#[ignore = "requires live VPS bootstrap nodes (UDP port 5483 must be accessible)"]
#[tokio::test(flavor = "multi_thread")]
async fn test_vps_late_join_heartbeat_discovery() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a_vps(11))
        .with_heartbeat_interval(10)
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();
    let a_addr = agent_a
        .bound_addr()
        .await
        .expect("agent A must have a bound address");

    tokio::time::sleep(std::time::Duration::from_secs(15)).await;

    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b(a_addr, true))
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    let found = wait_for_discovery(
        &agent_b,
        agent_a.agent_id(),
        std::time::Duration::from_secs(15),
    )
    .await;
    assert!(
        found,
        "Late-joining Agent B should discover Agent A via heartbeat"
    );
}

#[ignore = "requires live VPS bootstrap nodes (UDP port 5483 must be accessible)"]
#[tokio::test(flavor = "multi_thread")]
async fn test_vps_rendezvous_find_agent() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a_vps(12))
        .with_heartbeat_interval(4)
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();
    agent_a
        .advertise_identity(RENDEZVOUS_VALIDITY_MS)
        .await
        .unwrap();

    let a_addr = agent_a
        .bound_addr()
        .await
        .expect("agent A must have a bound address");

    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b(a_addr, true))
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    let result = agent_b
        .find_agent(agent_a.agent_id())
        .await
        .expect("find_agent must not error");

    assert!(
        result.is_some(),
        "find_agent should locate Agent A within 10s"
    );
}

#[ignore = "requires live VPS bootstrap nodes (UDP port 5483 must be accessible)"]
#[tokio::test(flavor = "multi_thread")]
async fn test_vps_user_identity_discovery() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let user_kp = x0x::identity::UserKeypair::generate().unwrap();
    let user_id = user_kp.user_id();

    let agent_a = Agent::builder()
        .with_machine_key(dir_a.path().join("machine.key"))
        .with_agent_key_path(dir_a.path().join("agent.key"))
        .with_network_config(cfg_a_vps(13))
        .with_user_key(user_kp)
        .build()
        .await
        .unwrap();
    agent_a.join_network().await.unwrap();
    agent_a.announce_identity(true, true).await.unwrap();

    let a_addr = agent_a
        .bound_addr()
        .await
        .expect("agent A must have a bound address");

    let agent_b = Agent::builder()
        .with_machine_key(dir_b.path().join("machine.key"))
        .with_agent_key_path(dir_b.path().join("agent.key"))
        .with_network_config(cfg_b(a_addr, true))
        .build()
        .await
        .unwrap();
    agent_b.join_network().await.unwrap();

    let found = wait_for_discovery(
        &agent_b,
        agent_a.agent_id(),
        std::time::Duration::from_secs(20),
    )
    .await;
    assert!(found, "Agent B should discover Agent A within 20s");

    let by_user = agent_b
        .find_agents_by_user(user_id)
        .await
        .expect("find_agents_by_user must not error");

    assert!(
        !by_user.is_empty(),
        "find_agents_by_user must return Agent A"
    );
    assert_eq!(by_user[0].agent_id, agent_a.agent_id());
    assert_eq!(by_user[0].user_id, Some(user_id));
}
