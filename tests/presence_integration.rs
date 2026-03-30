//! Local integration tests for the SOTA Presence System.
//!
//! All tests in this file run without a live VPS network. They exercise the
//! full `Agent` lifecycle (builder → build → APIs) using loopback or no
//! network, validating the presence stack from the public crate API.

#![allow(clippy::unwrap_used)]

use tempfile::TempDir;
use x0x::{network::NetworkConfig, Agent};

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
        .with_network_config(NetworkConfig::default())
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

    match rx.try_recv() {
        Err(TryRecvError::Empty) | Err(TryRecvError::Lagged(_)) | Ok(_) => {
            // Channel is alive — all these outcomes are valid.
        }
        Err(TryRecvError::Closed) => {
            panic!("Presence broadcast channel must not be closed immediately");
        }
    }
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
// Test 8: subscribe_presence errors for offline agent
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
