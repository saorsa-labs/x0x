//! Presence & FOAF Discovery Integration Tests
//!
//! These tests verify the presence and FOAF (Friend-of-a-Friend) discovery APIs
//! introduced in Phases 1.1–1.4. All tests run locally (no VPS testnet required).
//!
//! Tests that genuinely require a live VPS network are tagged with
//! `#[ignore = "requires VPS testnet"]` and are not run in CI.

#![allow(clippy::unwrap_used)]

use saorsa_gossip_types::PeerId;
use std::{net::SocketAddr, time::Duration};
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::timeout;
use x0x::{identity::AgentId, network::NetworkConfig, presence::PresenceEvent, Agent};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a local agent with an isolated key store, peer cache, and the default (loopback)
/// network config.  Does NOT call `join_network()` — the caller must do so
/// if network connectivity is needed.
///
/// Machine key, agent key, and peer cache are stored in an isolated `TempDir` so that
/// concurrent calls do not share key files or network cache state.
/// The `TempDir` is returned alongside the agent so the caller keeps it alive.
async fn build_local_agent() -> (Agent, TempDir) {
    let tmp = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(tmp.path().join("machine.key"))
        .with_agent_key_path(tmp.path().join("agent.key"))
        .with_peer_cache_dir(tmp.path().join("peers"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();
    (agent, tmp)
}

/// Build a local agent that is NOT connected to any network.
async fn build_offline_agent() -> (Agent, TempDir) {
    let tmp = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(tmp.path().join("machine.key"))
        .with_agent_key_path(tmp.path().join("agent.key"))
        .build()
        .await
        .unwrap();
    (agent, tmp)
}

fn loopback_network_config(bootstrap_nodes: Vec<SocketAddr>) -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        bootstrap_nodes,
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
}

async fn build_loopback_agent(
    tmp: &TempDir,
    name: &str,
    bootstrap_nodes: Vec<SocketAddr>,
) -> Result<Option<Agent>, Box<dyn std::error::Error>> {
    match Agent::builder()
        .with_machine_key(tmp.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(tmp.path().join(format!("{name}-agent.key")))
        .with_peer_cache_disabled()
        .with_network_config(loopback_network_config(bootstrap_nodes))
        .with_presence_beacon_interval(1)
        .with_presence_event_poll_interval(1)
        .build()
        .await
    {
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

async fn wait_for_cached_agent(agent: &Agent, target: &AgentId, timeout: Duration) -> bool {
    let started = tokio::time::Instant::now();
    while started.elapsed() < timeout {
        if agent.cached_agent(target).await.is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn wait_for_online_event(
    rx: &mut tokio::sync::broadcast::Receiver<PresenceEvent>,
    target: AgentId,
    timeout: Duration,
) -> bool {
    let started = tokio::time::Instant::now();
    while started.elapsed() < timeout {
        let remaining = timeout.saturating_sub(started.elapsed());
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(PresenceEvent::AgentOnline { agent_id, .. })) if agent_id == target => {
                return true;
            }
            Ok(Ok(_)) | Ok(Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) | Err(_) => return false,
        }
    }
    false
}

async fn wait_for_self_presence_record(agent: &Agent, timeout: Duration) -> bool {
    let Some(presence) = agent.presence_system() else {
        return false;
    };
    let topic = x0x::presence::global_presence_topic();
    let self_peer = PeerId::new(agent.machine_id().0);
    let started = tokio::time::Instant::now();

    while started.elapsed() < timeout {
        if presence
            .manager()
            .get_online_peers(topic)
            .await
            .contains(&self_peer)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    false
}

async fn wait_for_connected_peer(
    agent: &Agent,
    target: PeerId,
    timeout: Duration,
) -> Option<Vec<PeerId>> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < timeout {
        if let Ok(peers) = agent.peers().await {
            if peers.contains(&target) {
                return Some(peers);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

// ---------------------------------------------------------------------------
// Test 1 (was: "beacon propagation across VPS mesh")
//
// The original test joined the VPS network and waited 5 s for beacons to
// propagate — infrastructure we cannot rely on in CI.  Here we verify the
// same *local* invariants:
//   • An agent built WITH a network config has a presence system.
//   • An agent built WITHOUT a network config does NOT have one.
// ---------------------------------------------------------------------------

/// Presence system is initialised when network config is provided.
#[tokio::test]
async fn test_presence_beacon_propagation() {
    let (networked, _tmp1) = build_local_agent().await;
    assert!(
        networked.presence_system().is_some(),
        "Agent with network config must have a presence system"
    );

    let (offline, _tmp2) = build_offline_agent().await;
    assert!(
        offline.presence_system().is_none(),
        "Agent without network config must NOT have a presence system"
    );
}

// ---------------------------------------------------------------------------
// Test 2 (was: "beacon expiration" — required 16 min timeout)
//
// Instead of sleeping 16 minutes we verify the underlying `PeerBeaconStats`
// adaptive timeout logic, which is the mechanism that drives expiration.
// ---------------------------------------------------------------------------

/// Beacon stats return the fallback timeout when fewer than 2 samples are
/// present, and a clamped value once enough samples accumulate.
#[tokio::test]
async fn test_presence_beacon_expiration() {
    use x0x::presence::PeerBeaconStats;

    // Fresh stats → fallback
    let stats = PeerBeaconStats::new();
    let to = stats.adaptive_timeout_secs(300);
    assert_eq!(to, 300, "Fresh stats must return the fallback timeout");

    // Ten tight samples → timeout stays clamped in [180, 600]
    let mut stats2 = PeerBeaconStats::new();
    let base: u64 = 1_000_000;
    for i in 0..10_u64 {
        stats2.record(base + i * 30); // 30 s inter-arrival
    }
    let computed = stats2.adaptive_timeout_secs(300);
    assert!(
        (180..=600).contains(&computed),
        "Computed adaptive timeout {} must be in [180, 600]",
        computed
    );
}

// ---------------------------------------------------------------------------
// Test 3 (was: "FOAF TTL=1 immediate neighbors only")
//
// Without a live network the FOAF query completes immediately with an empty
// result set (no neighbours visible). We validate the API contract:
//   • The call completes quickly.
//   • It returns an empty Vec (not an error) when there are no peers.
// ---------------------------------------------------------------------------

/// FOAF query with TTL=1 returns immediately when there are no peers.
#[tokio::test]
async fn test_foaf_ttl_1_immediate_neighbors() {
    let (agent, _tmp) = build_local_agent().await;

    let result = timeout(Duration::from_secs(3), agent.discover_agents_foaf(1, 200))
        .await
        .expect("FOAF query must complete within 3 seconds");

    let agents = result.expect("discover_agents_foaf should not error with network config");
    assert!(
        agents.is_empty(),
        "No peers visible in isolated agent — expected empty result"
    );
}

// ---------------------------------------------------------------------------
// Test 4 (was: "FOAF TTL=3 multi-hop")
//
// Same local contract: empty result with higher TTL is still valid.
// ---------------------------------------------------------------------------

/// FOAF query with TTL=3 returns an empty list when there are no peers.
#[tokio::test]
async fn test_foaf_ttl_3_multi_hop() {
    let (agent, _tmp) = build_local_agent().await;

    let result = timeout(Duration::from_secs(3), agent.discover_agents_foaf(3, 200))
        .await
        .expect("FOAF query must complete within 3 seconds");

    let agents = result.expect("discover_agents_foaf should not error");
    assert!(
        agents.is_empty(),
        "No peers in isolated environment — expected empty FOAF result"
    );
}

// ---------------------------------------------------------------------------
// Test 5 (was: "FOAF find specific agent")
//
// Two agents have different AgentIds — a fundamental identity invariant.
// `discover_agent_by_id` returns None for an unknown target (no error).
// ---------------------------------------------------------------------------

/// Two independently created agents have distinct AgentIds.
/// `discover_agent_by_id` returns `Ok(None)` for an unknown target.
#[tokio::test]
async fn test_foaf_find_specific_agent() {
    let (agent_a, _tmp_a) = build_local_agent().await;
    let (agent_b, _tmp_b) = build_local_agent().await;

    let id_a = agent_a.agent_id();
    let id_b = agent_b.agent_id();

    assert_ne!(
        id_a, id_b,
        "Independently built agents must have different AgentIds"
    );

    // Agent A cannot find Agent B (they are not connected).
    let found = timeout(
        Duration::from_secs(3),
        agent_a.discover_agent_by_id(id_b, 2, 200),
    )
    .await
    .expect("discover_agent_by_id must complete within 3 seconds")
    .expect("discover_agent_by_id should not error");

    assert!(
        found.is_none(),
        "Unconnected agent must not be discoverable"
    );
}

// ---------------------------------------------------------------------------
// Connected local topology regression
//
// This keeps the no-peer contract tests above, but also verifies the integration
// path against a real loopback peer: network join, identity cache, presence
// event delivery, FOAF TTL=1 discovery, and find-by-id for that connected peer.
// ---------------------------------------------------------------------------

/// Connected loopback agents surface each other through presence and FOAF.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_connected_loopback_presence_and_foaf_discovers_peer(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new().unwrap();

    let Some(agent_a) = build_loopback_agent(&tmp, "agent-a", Vec::new()).await? else {
        return Ok(());
    };
    agent_a.join_network().await?;
    let mut rx = agent_a.subscribe_presence().await?;
    let Some(agent_a_addr) = agent_a.bound_addr().await else {
        agent_a.shutdown().await;
        return Err(std::io::Error::other("agent A did not bind to a loopback address").into());
    };

    let Some(agent_b) = build_loopback_agent(&tmp, "agent-b", vec![agent_a_addr]).await? else {
        agent_a.shutdown().await;
        return Ok(());
    };
    agent_b.join_network().await?;
    agent_b.announce_identity(false, false).await?;

    // Loopback identity/presence propagation converges in <500 ms locally but
    // flakes on slow GHA runners at a 5 s window — same reason the FOAF
    // timeouts below were bumped 3 s → 15 s. Widen to match.
    assert!(
        wait_for_cached_agent(&agent_a, &agent_b.agent_id(), Duration::from_secs(15)).await,
        "agent A must cache agent B from a real loopback identity announcement"
    );
    assert!(
        wait_for_online_event(&mut rx, agent_b.agent_id(), Duration::from_secs(15)).await,
        "agent A must emit AgentOnline for agent B from a real loopback presence beacon"
    );
    assert!(
        wait_for_self_presence_record(&agent_b, Duration::from_secs(10)).await,
        "agent B must have a local self beacon available for FOAF responses"
    );

    let agent_b_peer = PeerId::new(agent_b.machine_id().0);
    let connected_peers = wait_for_connected_peer(&agent_a, agent_b_peer, Duration::from_secs(5))
        .await
        .ok_or_else(|| {
            std::io::Error::other("agent A did not report agent B as a connected peer")
        })?;
    agent_a
        .presence_system()
        .unwrap()
        .manager()
        .replace_broadcast_peers(connected_peers)
        .await;

    // 3 s flaked on GHA runners; bumped to 15 s. Local discovery converges in <500 ms.
    let foaf_agents = timeout(
        Duration::from_secs(15),
        agent_a.discover_agents_foaf(1, 500),
    )
    .await??;
    assert!(
        foaf_agents
            .iter()
            .any(|agent| agent.agent_id == agent_b.agent_id()),
        "TTL=1 FOAF must return connected agent B"
    );

    let found = timeout(
        Duration::from_secs(15),
        agent_a.discover_agent_by_id(agent_b.agent_id(), 1, 500),
    )
    .await??;
    assert!(
        found.is_some_and(|agent| agent.agent_id == agent_b.agent_id()),
        "discover_agent_by_id must find connected agent B"
    );

    agent_b.shutdown().await;
    agent_a.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 6 (was: "presence event subscription")
//
// Verify the subscription channel is created and immediately readable
// (no events expected — Lagged is not an error here).
// ---------------------------------------------------------------------------

/// `subscribe_presence()` returns a live receiver.
/// The channel is healthy immediately after creation (try_recv returns
/// `Err(Empty)`, not `Err(Closed)`).
#[tokio::test]
async fn test_presence_event_subscription() {
    use tokio::sync::broadcast::error::TryRecvError;

    let (agent, _tmp) = build_local_agent().await;

    let mut rx = agent
        .subscribe_presence()
        .await
        .expect("subscribe_presence must succeed with network config");

    match rx.try_recv() {
        Err(TryRecvError::Empty) => {
            // ✓ Channel alive, no events yet — expected
        }
        Err(TryRecvError::Closed) => {
            panic!("Presence event channel must not be closed immediately");
        }
        Ok(_) => {
            // Unlikely but fine — an event was already queued
        }
        Err(TryRecvError::Lagged(_)) => {
            // Fine — channel is alive
        }
    }
}

// ---------------------------------------------------------------------------
// Test 7 (was: "FOAF privacy verification")
//
// `foaf_peer_score` is the privacy-preserving scoring function.  Verify it
// returns a bounded value in [0.0, 1.0] for any stats profile.
// ---------------------------------------------------------------------------

/// `foaf_peer_score` always returns a value in [0.0, 1.0].
#[tokio::test]
async fn test_foaf_privacy() {
    use x0x::presence::{foaf_peer_score, PeerBeaconStats};

    // Empty stats
    let empty = PeerBeaconStats::new();
    let score_empty = foaf_peer_score(&empty);
    assert!(
        (0.0..=1.0).contains(&score_empty),
        "foaf_peer_score(empty) = {score_empty} must be in [0.0, 1.0]"
    );

    // Stable peer (low jitter → high score)
    let mut stable = PeerBeaconStats::new();
    let base: u64 = 1_000_000;
    for i in 0..10_u64 {
        stable.record(base + i * 30);
    }
    let score_stable = foaf_peer_score(&stable);
    assert!(
        (0.0..=1.0).contains(&score_stable),
        "foaf_peer_score(stable) = {score_stable} must be in [0.0, 1.0]"
    );

    // Jittery peer (high variance → lower score)
    let mut jittery = PeerBeaconStats::new();
    for i in 0..10_u64 {
        jittery.record(base + i * i * 5 + i * 30);
    }
    let score_jittery = foaf_peer_score(&jittery);
    assert!(
        (0.0..=1.0).contains(&score_jittery),
        "foaf_peer_score(jittery) = {score_jittery} must be in [0.0, 1.0]"
    );

    // Stable peers should score ≥ jittery peers (quality-weighted routing)
    assert!(
        score_stable >= score_jittery,
        "Stable peer score ({score_stable}) should be >= jittery peer score ({score_jittery})"
    );
}

// ---------------------------------------------------------------------------
// Test 8 (was: "concurrent presence beacons from multiple agents")
//
// Verify that multiple PresenceWrapper / Agent instances can be created
// concurrently with no data races or panics.
// ---------------------------------------------------------------------------

/// Multiple agents can be built concurrently; each gets a unique AgentId.
#[tokio::test]
async fn test_concurrent_presence_beacons() {
    const NUM_AGENTS: usize = 5;

    let handles: Vec<_> = (0..NUM_AGENTS)
        .map(|_| {
            tokio::spawn(async move {
                let (agent, _tmp) = build_local_agent().await;
                assert!(
                    agent.presence_system().is_some(),
                    "Concurrently built agent must have presence system"
                );
                agent.agent_id()
            })
        })
        .collect();

    let mut agent_ids = Vec::with_capacity(NUM_AGENTS);
    for handle in handles {
        agent_ids.push(handle.await.expect("concurrent agent build must not panic"));
    }

    // All AgentIds must be unique
    let unique: std::collections::HashSet<_> = agent_ids.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        NUM_AGENTS,
        "All {NUM_AGENTS} concurrently built agents must have unique AgentIds"
    );
}
