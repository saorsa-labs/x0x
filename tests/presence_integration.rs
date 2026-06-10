//! Local integration tests for the SOTA Presence System.
//!
//! All tests in this file run without a live VPS network. They exercise the
//! full `Agent` lifecycle (builder → build → APIs) using loopback or no
//! network, validating the presence stack from the public crate API.

#![allow(clippy::unwrap_used)]

use std::{net::SocketAddr, time::Duration};

use saorsa_gossip_types::PeerId;
use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;
use x0x::{identity::AgentId, network::NetworkConfig, presence::PresenceEvent, Agent};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an agent with network config and isolated key storage.
/// Returns `(Agent, TempDir)` — the `TempDir` must stay alive for the test.
async fn build_networked() -> (Agent, TempDir) {
    let tmp = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(tmp.path().join("machine.key"))
        .with_agent_key_path(tmp.path().join("agent.key"))
        .with_peer_cache_disabled()
        .with_network_config(loopback_network_config(Vec::new()))
        .build()
        .await
        .unwrap();
    (agent, tmp)
}

/// Build an agent WITHOUT network config (offline agent).
async fn build_offline() -> (Agent, TempDir) {
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
        .with_contact_store_path(tmp.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_disabled()
        .with_network_config(loopback_network_config(bootstrap_nodes))
        .with_presence_beacon_interval(1)
        // Poll faster than the beacon TTL. The beacon TTL is
        // beacon_interval * 3 = 3 s; an event-poll interval of 10 s would
        // almost always land between live beacons (TTL < poll), so a peer
        // would never be observed online within the test window. Production
        // keeps the invariant the other way (beacon_interval 30 s → TTL 90 s
        // ≫ 10 s poll); this fast-beacon test must mirror that ordering.
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

#[test]
fn test_loopback_network_config_is_hermetic() {
    let config = loopback_network_config(Vec::new());
    assert_eq!(
        config.bind_addr,
        Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        "networked presence tests must bind loopback only"
    );
    assert!(
        config.bootstrap_nodes.is_empty(),
        "networked presence tests must not inherit default bootstrap peers"
    );
    assert!(
        !config.port_mapping_enabled,
        "networked presence tests must not enable port mapping"
    );
}

// ---------------------------------------------------------------------------
// Test 1: Presence system initialized with network config
// ---------------------------------------------------------------------------

/// `Agent::presence_system()` returns `Some` when a `NetworkConfig` is supplied.
#[tokio::test]
async fn test_presence_system_initialized_with_network() {
    let (agent, _tmp) = build_networked().await;
    assert!(
        agent.presence_system().is_some(),
        "Presence system must be Some when network config is provided"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Presence system absent without network config
// ---------------------------------------------------------------------------

/// `Agent::presence_system()` returns `None` when no `NetworkConfig` is supplied.
#[tokio::test]
async fn test_presence_system_none_without_network() {
    let (agent, _tmp) = build_offline().await;
    assert!(
        agent.presence_system().is_none(),
        "Presence system must be None when no network config is provided"
    );
}

// ---------------------------------------------------------------------------
// Test 3: subscribe_presence returns Ok
// ---------------------------------------------------------------------------

/// `subscribe_presence()` succeeds and returns a valid receiver.
#[tokio::test]
async fn test_subscribe_presence_returns_receiver() {
    let (agent, _tmp) = build_networked().await;
    let result = agent.subscribe_presence().await;
    assert!(
        result.is_ok(),
        "subscribe_presence must return Ok with network config, got: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// Test 4: Presence event channel is alive after subscribe
// ---------------------------------------------------------------------------

/// After `subscribe_presence()`, `try_recv()` must return `Err(Empty)` (not
/// `Err(Closed)`), proving the channel is open and healthy.
#[tokio::test]
async fn test_presence_event_channel_alive() {
    use tokio::sync::broadcast::error::TryRecvError;

    let (agent, _tmp) = build_networked().await;
    let mut rx = agent.subscribe_presence().await.unwrap();

    assert!(
        !matches!(rx.try_recv(), Err(TryRecvError::Closed)),
        "Presence broadcast channel must not be closed immediately"
    );
}

// ---------------------------------------------------------------------------
// Test 5: cached_agent returns None for unknown ID
// ---------------------------------------------------------------------------

/// `Agent::cached_agent(&unknown_id)` returns `None` without a prior
/// `join_network()` call or presence beacon from the target agent.
#[tokio::test]
async fn test_cached_agent_returns_none_for_unknown() {
    use x0x::identity::AgentId;

    let (agent, _tmp) = build_networked().await;
    let unknown_id = AgentId([0xAB_u8; 32]);

    let result = agent.cached_agent(&unknown_id).await;
    assert!(
        result.is_none(),
        "cached_agent must return None for an unknown AgentId"
    );
}

// ---------------------------------------------------------------------------
// Test 6: foaf_peer_candidates returns empty without network activity
// ---------------------------------------------------------------------------

/// Before any presence beacons are received, `foaf_peer_candidates()` returns
/// an empty list.
#[tokio::test]
async fn test_foaf_candidates_empty_without_peers() {
    let (agent, _tmp) = build_networked().await;
    let pw = agent.presence_system().unwrap();
    let candidates = pw.foaf_peer_candidates().await;
    assert!(
        candidates.is_empty(),
        "No peers visible yet — FOAF candidates must be empty"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Two independently built agents have unique AgentIds
// ---------------------------------------------------------------------------

/// The `AgentBuilder` generates a fresh ML-DSA-65 keypair for each new agent
/// (when using isolated key paths). Unique keypairs → unique AgentIds.
#[tokio::test]
async fn test_two_agents_have_different_ids() {
    let (agent_a, _tmp_a) = build_networked().await;
    let (agent_b, _tmp_b) = build_networked().await;

    assert_ne!(
        agent_a.agent_id(),
        agent_b.agent_id(),
        "Two independently built agents must have different AgentIds"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Loopback peer presence emits online event and populates peer state
// ---------------------------------------------------------------------------

/// Two loopback agents connected through the normal network path must deliver
/// a live presence beacon to the subscriber, map it to the peer `AgentId`, and
/// update the FOAF candidate set from that real beacon.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_loopback_presence_emits_peer_online_event() -> Result<(), Box<dyn std::error::Error>>
{
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
    assert!(
        wait_for_cached_agent(&agent_a, &agent_b.agent_id(), Duration::from_secs(5)).await,
        "agent A must cache agent B from a real loopback identity announcement"
    );

    assert!(
        wait_for_online_event(&mut rx, agent_b.agent_id(), Duration::from_secs(15)).await,
        "agent A must emit AgentOnline for agent B from a real loopback presence beacon"
    );

    let foaf_candidates = agent_a
        .presence_system()
        .unwrap()
        .foaf_peer_candidates()
        .await;
    assert!(
        foaf_candidates
            .iter()
            .any(|(peer, _)| *peer == PeerId::new(agent_b.machine_id().0)),
        "agent A must record agent B as a FOAF candidate after receiving its beacon"
    );

    agent_b.shutdown().await;
    agent_a.shutdown().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 9: subscribe_presence errors for offline agent
// ---------------------------------------------------------------------------

/// `subscribe_presence()` returns an error when no network config was supplied.
#[tokio::test]
async fn test_subscribe_presence_errors_without_network() {
    let (agent, _tmp) = build_offline().await;
    let result = agent.subscribe_presence().await;
    assert!(
        result.is_err(),
        "subscribe_presence must fail when no network config is provided"
    );
}
