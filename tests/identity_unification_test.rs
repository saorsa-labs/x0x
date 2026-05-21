#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for identity unification: machine_id == ant-quic PeerId.
//!
//! Verifies that the machine ML-DSA-65 keypair is correctly threaded through to
//! the QUIC transport layer so that `machine_id` and the QUIC `PeerId` are
//! derived from the same key.

use tempfile::TempDir;
use x0x::{network::NetworkConfig, Agent};

fn isolated_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback bind address")),
        bootstrap_nodes: Vec::new(),
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
}

fn socket_bind_blocked(err: &impl std::fmt::Display) -> bool {
    let message = err.to_string();
    message.contains("Failed to bind UDP socket")
        && (message.contains("Operation not permitted")
            || message.contains("Permission denied")
            || message.contains("os error 1"))
}

// ---------------------------------------------------------------------------
// Test 1: Machine ID is non-zero on build
// ---------------------------------------------------------------------------

/// A freshly built agent must have a non-zero machine_id.
#[tokio::test]
async fn test_machine_id_non_zero() {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    assert_ne!(
        agent.machine_id().as_bytes(),
        &[0u8; 32],
        "machine_id must be non-zero"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Machine ID is stable across restarts
// ---------------------------------------------------------------------------

/// Loading the same machine key file must yield the same machine_id.
#[tokio::test]
async fn test_machine_id_stable_across_restarts() {
    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("machine.key");

    let agent1 = Agent::builder()
        .with_machine_key(key_path.clone())
        .with_agent_key_path(dir.path().join("agent1.key"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();
    let machine_id1 = agent1.machine_id();

    let agent2 = Agent::builder()
        .with_machine_key(key_path.clone())
        .with_agent_key_path(dir.path().join("agent2.key"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();
    let machine_id2 = agent2.machine_id();

    assert_eq!(
        machine_id1, machine_id2,
        "same key file must produce the same machine_id"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Different key files yield different machine IDs
// ---------------------------------------------------------------------------

/// Two agents with separate machine key files must have distinct machine IDs.
#[tokio::test]
async fn test_different_key_files_different_machine_ids() {
    let dir = TempDir::new().unwrap();

    let agent1 = Agent::builder()
        .with_machine_key(dir.path().join("machine1.key"))
        .with_agent_key_path(dir.path().join("agent1.key"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    let agent2 = Agent::builder()
        .with_machine_key(dir.path().join("machine2.key"))
        .with_agent_key_path(dir.path().join("agent2.key"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    assert_ne!(
        agent1.machine_id(),
        agent2.machine_id(),
        "different key files must yield different machine IDs"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Agent ID is portable (different machines, same agent key)
// ---------------------------------------------------------------------------

/// The same agent key file loaded on two different "machines" (different
/// machine key files) yields the same agent_id but different machine_ids.
#[tokio::test]
async fn test_agent_id_portable_across_machines() {
    let dir = TempDir::new().unwrap();
    let agent_key = dir.path().join("portable_agent.key");

    // First "machine"
    let agent1 = Agent::builder()
        .with_machine_key(dir.path().join("machineA.key"))
        .with_agent_key_path(agent_key.clone())
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    // Second "machine" — same agent key, different machine key
    let agent2 = Agent::builder()
        .with_machine_key(dir.path().join("machineB.key"))
        .with_agent_key_path(agent_key.clone())
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    assert_eq!(
        agent1.agent_id(),
        agent2.agent_id(),
        "same agent key must produce the same agent_id regardless of machine"
    );
    assert_ne!(
        agent1.machine_id(),
        agent2.machine_id(),
        "different machine keys must produce different machine_ids"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Announcement machine_id matches agent machine_id
// ---------------------------------------------------------------------------

/// An identity announcement must carry the same machine_id as the agent.
#[tokio::test]
async fn test_announcement_machine_id_matches_agent() {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    let ann = agent.build_announcement(false, false).unwrap();
    assert_eq!(
        ann.machine_id,
        agent.machine_id(),
        "announcement machine_id must match agent.machine_id()"
    );
    assert_eq!(
        ann.agent_id,
        agent.agent_id(),
        "announcement agent_id must match agent.agent_id()"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Announcement verifies cleanly
// ---------------------------------------------------------------------------

/// A freshly built announcement must pass signature verification.
#[tokio::test]
async fn test_announcement_verifies() {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    let ann = agent.build_announcement(false, false).unwrap();
    ann.verify()
        .expect("freshly built announcement should verify");
}

// ---------------------------------------------------------------------------
// Test 7: machine_public_key in announcement matches machine_id derivation
// ---------------------------------------------------------------------------

/// The `machine_public_key` bytes carried in an announcement must hash to
/// the same `machine_id` that the agent reports.
#[tokio::test]
async fn test_machine_public_key_derives_machine_id() {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    let ann = agent.build_announcement(false, false).unwrap();
    let machine_pub = ant_quic::MlDsaPublicKey::from_bytes(&ann.machine_public_key)
        .expect("machine_public_key bytes should be a valid ML-DSA-65 public key");

    let derived = x0x::identity::MachineId::from_public_key(&machine_pub);
    assert_eq!(
        derived,
        agent.machine_id(),
        "SHA-256(machine_public_key) must equal agent.machine_id()"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Transport PeerId matches machine_id
// ---------------------------------------------------------------------------

/// A network-backed agent must expose the same ant-quic `PeerId` bytes as
/// its x0x `machine_id`, proving the QUIC transport uses the machine key.
#[tokio::test]
async fn test_transport_peer_id_matches_machine_id() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new().unwrap();
    let agent = match Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_peer_cache_disabled()
        .with_network_config(isolated_network_config())
        .build()
        .await
    {
        Ok(agent) => agent,
        Err(err) if socket_bind_blocked(&err) => {
            eprintln!("skipping transport PeerId assertion: UDP bind is not permitted");
            return Ok(());
        }
        Err(err) => return Err(Box::new(err) as Box<dyn std::error::Error>),
    };

    let transport_peer_id = agent
        .network()
        .expect("network-backed agent should expose NetworkNode")
        .peer_id();

    assert_eq!(
        transport_peer_id.0,
        agent.machine_id().0,
        "ant-quic transport PeerId must be derived from the same machine key as MachineId"
    );

    Ok(())
}
