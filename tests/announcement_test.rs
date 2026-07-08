#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for identity announcement round-trips.
//!
//! Verifies that announcements are correctly built, signed, serialised,
//! deserialised, and verified — including the NAT fields added in Phase 1.3.

use tempfile::TempDir;
use x0x::{
    network::NetworkConfig, Agent, DiscoveredAgent, IdentityAnnouncement, MachineAnnouncement,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_peer_cache_dir(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("peers")
}

async fn build_agent(dir: &TempDir) -> Agent {
    let peer_cache_dir = test_peer_cache_dir(dir);
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_peer_cache_dir(&peer_cache_dir)
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    assert!(
        peer_cache_dir.exists(),
        "networked tests must use the TempDir peer cache"
    );
    agent
}

#[derive(serde::Serialize)]
struct IdentityAnnouncementUnsignedForTest {
    agent_id: x0x::identity::AgentId,
    machine_id: x0x::identity::MachineId,
    user_id: Option<x0x::identity::UserId>,
    agent_certificate: Option<x0x::identity::AgentCertificate>,
    machine_public_key: Vec<u8>,
    addresses: Vec<std::net::SocketAddr>,
    announced_at: u64,
    nat_type: Option<String>,
    can_receive_direct: Option<bool>,
    is_relay: Option<bool>,
    is_coordinator: Option<bool>,
    reachable_via: Vec<x0x::identity::MachineId>,
    relay_candidates: Vec<x0x::identity::MachineId>,
}

#[derive(serde::Serialize)]
struct MachineAnnouncementUnsignedForTest {
    machine_id: x0x::identity::MachineId,
    machine_public_key: Vec<u8>,
    addresses: Vec<std::net::SocketAddr>,
    announced_at: u64,
    nat_type: Option<String>,
    can_receive_direct: Option<bool>,
    is_relay: Option<bool>,
    is_coordinator: Option<bool>,
    reachable_via: Vec<x0x::identity::MachineId>,
    relay_candidates: Vec<x0x::identity::MachineId>,
}

fn machine_signature_for_test(
    machine_keypair: &x0x::identity::MachineKeypair,
    unsigned_bytes: &[u8],
) -> Vec<u8> {
    ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        machine_keypair.secret_key(),
        unsigned_bytes,
    )
    .unwrap()
    .as_bytes()
    .to_vec()
}

fn signed_identity_announcement_with_nat_fields() -> IdentityAnnouncement {
    let machine_keypair = x0x::identity::MachineKeypair::generate().unwrap();
    let agent_keypair = x0x::identity::AgentKeypair::generate().unwrap();
    let unsigned = IdentityAnnouncementUnsignedForTest {
        agent_id: agent_keypair.agent_id(),
        machine_id: machine_keypair.machine_id(),
        user_id: None,
        agent_certificate: None,
        machine_public_key: machine_keypair.public_key().as_bytes().to_vec(),
        addresses: Vec::new(),
        announced_at: 1_000,
        nat_type: Some(String::from("Symmetric")),
        can_receive_direct: Some(false),
        is_relay: Some(false),
        is_coordinator: Some(true),
        reachable_via: vec![x0x::identity::MachineId([0xAA; 32])],
        relay_candidates: vec![x0x::identity::MachineId([0xBB; 32])],
    };
    let unsigned_bytes = bincode::serialize(&unsigned).unwrap();
    let machine_signature = machine_signature_for_test(&machine_keypair, &unsigned_bytes);

    IdentityAnnouncement {
        agent_id: unsigned.agent_id,
        machine_id: unsigned.machine_id,
        user_id: unsigned.user_id,
        agent_certificate: unsigned.agent_certificate,
        machine_public_key: unsigned.machine_public_key,
        machine_signature,
        addresses: unsigned.addresses,
        announced_at: unsigned.announced_at,
        nat_type: unsigned.nat_type,
        can_receive_direct: unsigned.can_receive_direct,
        is_relay: unsigned.is_relay,
        is_coordinator: unsigned.is_coordinator,
        reachable_via: unsigned.reachable_via,
        relay_candidates: unsigned.relay_candidates,
    }
}

fn signed_machine_announcement_with_nat_fields() -> MachineAnnouncement {
    let machine_keypair = x0x::identity::MachineKeypair::generate().unwrap();
    let unsigned = MachineAnnouncementUnsignedForTest {
        machine_id: machine_keypair.machine_id(),
        machine_public_key: machine_keypair.public_key().as_bytes().to_vec(),
        addresses: Vec::new(),
        announced_at: 1_000,
        nat_type: Some(String::from("Symmetric")),
        can_receive_direct: Some(false),
        is_relay: Some(false),
        is_coordinator: Some(true),
        reachable_via: vec![x0x::identity::MachineId([0xAA; 32])],
        relay_candidates: vec![x0x::identity::MachineId([0xBB; 32])],
    };
    let unsigned_bytes = bincode::serialize(&unsigned).unwrap();
    let machine_signature = machine_signature_for_test(&machine_keypair, &unsigned_bytes);

    MachineAnnouncement {
        machine_id: unsigned.machine_id,
        machine_public_key: unsigned.machine_public_key,
        machine_signature,
        addresses: unsigned.addresses,
        announced_at: unsigned.announced_at,
        nat_type: unsigned.nat_type,
        can_receive_direct: unsigned.can_receive_direct,
        is_relay: unsigned.is_relay,
        is_coordinator: unsigned.is_coordinator,
        reachable_via: unsigned.reachable_via,
        relay_candidates: unsigned.relay_candidates,
    }
}

fn assert_identity_announcement_rejects_tamper<F>(base: &IdentityAnnouncement, mutate: F)
where
    F: FnOnce(&mut IdentityAnnouncement),
{
    let mut tampered = base.clone();
    mutate(&mut tampered);
    assert!(
        tampered.verify().is_err(),
        "tampered identity announcement must fail verification"
    );
}

fn assert_machine_announcement_rejects_tamper<F>(base: &MachineAnnouncement, mutate: F)
where
    F: FnOnce(&mut MachineAnnouncement),
{
    let mut tampered = base.clone();
    mutate(&mut tampered);
    assert!(
        tampered.verify().is_err(),
        "tampered machine announcement must fail verification"
    );
}

// ---------------------------------------------------------------------------
// Test 1: Basic announcement round-trip (no user, no NAT)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn announcement_basic_round_trip() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let ann = agent.build_announcement(false, false).unwrap();
    // Serialise → deserialise
    let bytes = bincode::serialize(&ann).unwrap();
    let decoded: IdentityAnnouncement = bincode::deserialize(&bytes).unwrap();

    assert_eq!(decoded.agent_id, agent.agent_id());
    assert_eq!(decoded.machine_id, agent.machine_id());
    assert!(decoded.user_id.is_none());
    assert!(decoded.nat_type.is_none());
    assert!(decoded.can_receive_direct.is_none());
    assert!(decoded.is_relay.is_none());
    assert!(decoded.is_coordinator.is_none());
    decoded
        .verify()
        .expect("decoded announcement should verify");
}

// ---------------------------------------------------------------------------
// Test 2: Announcement with user identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn announcement_with_user_identity_round_trip() {
    let dir = TempDir::new().unwrap();
    let user_kp = x0x::identity::UserKeypair::generate().unwrap();
    let expected_user_id = user_kp.user_id();

    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_user_key(user_kp)
        .with_peer_cache_dir(test_peer_cache_dir(&dir))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap();

    let ann = agent.build_announcement(true, true).unwrap();
    let bytes = bincode::serialize(&ann).unwrap();
    let decoded: IdentityAnnouncement = bincode::deserialize(&bytes).unwrap();

    assert_eq!(decoded.user_id, Some(expected_user_id));
    assert!(decoded.agent_certificate.is_some());
    decoded
        .verify()
        .expect("announcement with user should verify");
}

// ---------------------------------------------------------------------------
// Test 3: Tampered announcement fails verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_announcement_fails_verification() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let mut ann = agent.build_announcement(false, false).unwrap();
    // Flip a byte in the signature
    if let Some(b) = ann.machine_signature.first_mut() {
        *b ^= 0xFF;
    }
    assert!(
        ann.verify().is_err(),
        "tampered signature must fail verification"
    );
}

// ---------------------------------------------------------------------------
// Test 4: announced_at is populated
// ---------------------------------------------------------------------------

#[tokio::test]
async fn announcement_timestamp_non_zero() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let ann = agent.build_announcement(false, false).unwrap();
    assert!(
        ann.announced_at > 0,
        "announced_at must be a non-zero unix timestamp"
    );
}

// ---------------------------------------------------------------------------
// Test 5: NAT fields present when set explicitly
// ---------------------------------------------------------------------------

/// An announcement built with explicit NAT fields carries them correctly.
///
/// Note: the standard `build_announcement()` leaves NAT fields as None because
/// it is sync and has no access to async network state. The heartbeat path
/// populates them when the network layer is running.
/// Here we verify the struct accepts and round-trips NAT fields correctly.
#[test]
fn announcement_nat_fields_round_trip() {
    let coord = x0x::identity::MachineId([9u8; 32]);
    let ann = IdentityAnnouncement {
        agent_id: x0x::identity::AgentId([1u8; 32]),
        machine_id: x0x::identity::MachineId([2u8; 32]),
        user_id: None,
        agent_certificate: None,
        machine_public_key: vec![],
        machine_signature: vec![],
        addresses: vec![],
        announced_at: 1_000,
        nat_type: Some("FullCone".to_string()),
        can_receive_direct: Some(true),
        is_relay: Some(false),
        is_coordinator: Some(true),
        reachable_via: vec![coord],
        relay_candidates: vec![coord],
    };

    let bytes = bincode::serialize(&ann).unwrap();
    let decoded: IdentityAnnouncement = bincode::deserialize(&bytes).unwrap();

    assert_eq!(decoded.nat_type.as_deref(), Some("FullCone"));
    assert_eq!(decoded.can_receive_direct, Some(true));
    assert_eq!(decoded.is_relay, Some(false));
    assert_eq!(decoded.is_coordinator, Some(true));
    assert_eq!(decoded.reachable_via, vec![coord]);
    assert_eq!(decoded.relay_candidates, vec![coord]);
}

#[test]
fn signed_announcement_nat_fields_round_trip_and_reject_tampering() {
    let ann = signed_identity_announcement_with_nat_fields();
    let bytes = bincode::serialize(&ann).unwrap();
    let decoded: IdentityAnnouncement = bincode::deserialize(&bytes).unwrap();

    assert_eq!(decoded.nat_type.as_deref(), Some("Symmetric"));
    assert_eq!(decoded.can_receive_direct, Some(false));
    assert_eq!(decoded.is_relay, Some(false));
    assert_eq!(decoded.is_coordinator, Some(true));
    assert_eq!(
        decoded.reachable_via,
        vec![x0x::identity::MachineId([0xAA; 32])]
    );
    assert_eq!(
        decoded.relay_candidates,
        vec![x0x::identity::MachineId([0xBB; 32])]
    );
    decoded
        .verify()
        .expect("signed announcement with NAT fields should verify");

    assert_identity_announcement_rejects_tamper(&decoded, |ann| {
        ann.nat_type = Some(String::from("FullCone"));
    });
    assert_identity_announcement_rejects_tamper(&decoded, |ann| {
        ann.can_receive_direct = Some(true);
    });
    assert_identity_announcement_rejects_tamper(&decoded, |ann| {
        ann.is_relay = Some(true);
    });
    assert_identity_announcement_rejects_tamper(&decoded, |ann| {
        ann.is_coordinator = Some(false);
    });
    assert_identity_announcement_rejects_tamper(&decoded, |ann| {
        ann.reachable_via[0] = x0x::identity::MachineId([0xCC; 32]);
    });
    assert_identity_announcement_rejects_tamper(&decoded, |ann| {
        ann.relay_candidates[0] = x0x::identity::MachineId([0xDD; 32]);
    });
}

// ---------------------------------------------------------------------------
// Test 6: NAT fields default to None when absent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn announcement_nat_fields_default_to_none() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let ann = agent.build_announcement(false, false).unwrap();
    assert!(
        ann.nat_type.is_none(),
        "NAT type should be None when network not started"
    );
    assert!(
        ann.can_receive_direct.is_none(),
        "can_receive_direct should be None when network not started"
    );
    assert!(
        ann.is_relay.is_none(),
        "is_relay should be None when network not started"
    );
    assert!(
        ann.is_coordinator.is_none(),
        "is_coordinator should be None when network not started"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Discovery cache insert and retrieval
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_cache_insert_and_retrieve() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let fake_id = x0x::identity::AgentId([42u8; 32]);
    let fake = DiscoveredAgent {
        agent_id: fake_id,
        machine_id: x0x::identity::MachineId([7u8; 32]),
        user_id: None,
        addresses: vec!["127.0.0.1:8000".parse().unwrap()],
        announced_at: now,
        last_seen: now,
        machine_public_key: vec![],
        nat_type: Some("FullCone".to_string()),
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
    };

    agent
        .insert_discovered_agent_for_testing(fake.clone())
        .await;

    let discovered = agent.discovered_agents().await.unwrap();
    let found = discovered.iter().find(|a| a.agent_id == fake_id);
    assert!(
        found.is_some(),
        "inserted agent should appear in discovered list"
    );
    let found = found.unwrap();
    assert_eq!(found.nat_type.as_deref(), Some("FullCone"));
    assert_eq!(found.can_receive_direct, Some(true));
    assert!(found.is_relay.is_none());
}

// ---------------------------------------------------------------------------
// Test 8: ReachabilityInfo built from DiscoveredAgent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reachability_info_from_discovery_cache() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let fake_id = x0x::identity::AgentId([55u8; 32]);
    let fake = DiscoveredAgent {
        agent_id: fake_id,
        machine_id: x0x::identity::MachineId([6u8; 32]),
        user_id: None,
        addresses: vec!["10.0.0.1:9000".parse().unwrap()],
        announced_at: now,
        last_seen: now,
        machine_public_key: vec![],
        nat_type: Some("Symmetric".to_string()),
        can_receive_direct: Some(false),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
    };

    agent.insert_discovered_agent_for_testing(fake).await;

    let info = agent.reachability(&fake_id).await;
    assert!(
        info.is_some(),
        "reachability should be available after insertion"
    );
    let info = info.unwrap();
    assert!(
        !info.likely_direct(),
        "Symmetric NAT should not be likely_direct"
    );
    assert!(
        info.needs_coordination(),
        "Symmetric NAT should need coordination"
    );
    assert!(!info.is_relay(), "is_relay should be false when None");
    assert!(
        !info.is_coordinator(),
        "is_coordinator should be false when None"
    );
}

// ---------------------------------------------------------------------------
// Test 9: ReachabilityInfo returns None for unknown agent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reachability_none_for_unknown_agent() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let unknown_id = x0x::identity::AgentId([99u8; 32]);
    let info = agent.reachability(&unknown_id).await;
    assert!(
        info.is_none(),
        "reachability should be None for agent not in cache"
    );
}

// ---------------------------------------------------------------------------
// Test 10: Self-announcement populates discovery cache
// ---------------------------------------------------------------------------

#[tokio::test]
async fn self_announcement_populates_discovery_cache() {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_peer_cache_dir(test_peer_cache_dir(&dir))
        .with_network_config(NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            bootstrap_nodes: vec![],
            ..Default::default()
        })
        .build()
        .await
        .unwrap();

    // announce_identity with no real gossip overlay still populates own cache
    agent.announce_identity(false, false).await.unwrap();

    let discovered = agent.discovered_agents().await.unwrap();
    assert!(
        discovered.iter().any(|a| a.agent_id == agent.agent_id()),
        "own agent should appear in discovery cache after announcing"
    );
}

#[tokio::test]
async fn machine_announcement_round_trip() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let ann = agent.build_machine_announcement().unwrap();
    let bytes = bincode::serialize(&ann).unwrap();
    let decoded: MachineAnnouncement = bincode::deserialize(&bytes).unwrap();

    assert_eq!(decoded.machine_id, agent.machine_id());
    assert!(decoded.nat_type.is_none());
    assert!(decoded.can_receive_direct.is_none());
    assert!(decoded.is_relay.is_none());
    assert!(decoded.is_coordinator.is_none());
    decoded
        .verify()
        .expect("decoded machine announcement should verify");
}

#[test]
fn signed_machine_announcement_nat_fields_round_trip_and_reject_tampering() {
    let ann = signed_machine_announcement_with_nat_fields();
    let bytes = bincode::serialize(&ann).unwrap();
    let decoded: MachineAnnouncement = bincode::deserialize(&bytes).unwrap();

    assert_eq!(decoded.nat_type.as_deref(), Some("Symmetric"));
    assert_eq!(decoded.can_receive_direct, Some(false));
    assert_eq!(decoded.is_relay, Some(false));
    assert_eq!(decoded.is_coordinator, Some(true));
    assert_eq!(
        decoded.reachable_via,
        vec![x0x::identity::MachineId([0xAA; 32])]
    );
    assert_eq!(
        decoded.relay_candidates,
        vec![x0x::identity::MachineId([0xBB; 32])]
    );
    decoded
        .verify()
        .expect("signed machine announcement with NAT fields should verify");

    assert_machine_announcement_rejects_tamper(&decoded, |ann| {
        ann.nat_type = Some(String::from("FullCone"));
    });
    assert_machine_announcement_rejects_tamper(&decoded, |ann| {
        ann.can_receive_direct = Some(true);
    });
    assert_machine_announcement_rejects_tamper(&decoded, |ann| {
        ann.is_relay = Some(true);
    });
    assert_machine_announcement_rejects_tamper(&decoded, |ann| {
        ann.is_coordinator = Some(false);
    });
    assert_machine_announcement_rejects_tamper(&decoded, |ann| {
        ann.reachable_via[0] = x0x::identity::MachineId([0xCC; 32]);
    });
    assert_machine_announcement_rejects_tamper(&decoded, |ann| {
        ann.relay_candidates[0] = x0x::identity::MachineId([0xDD; 32]);
    });
}

#[tokio::test]
async fn machine_announcement_decode_rejects_trailing_bytes() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let ann = agent.build_machine_announcement().unwrap();
    let mut bytes = bincode::serialize(&ann).unwrap();
    bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    let decoded = {
        use bincode::Options;
        bincode::DefaultOptions::new()
            .with_limit(64 * 1024)
            .reject_trailing_bytes()
            .deserialize::<MachineAnnouncement>(&bytes)
    };

    assert!(decoded.is_err(), "trailing bytes must be rejected");
}

#[tokio::test]
async fn self_announcement_populates_machine_cache() {
    let dir = TempDir::new().unwrap();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_peer_cache_dir(test_peer_cache_dir(&dir))
        .with_network_config(NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            bootstrap_nodes: vec![],
            ..Default::default()
        })
        .build()
        .await
        .unwrap();

    agent.announce_identity(false, false).await.unwrap();

    let machines = agent.discovered_machines().await.unwrap();
    let found = machines
        .iter()
        .find(|machine| machine.machine_id == agent.machine_id())
        .expect("own machine should appear in machine cache");
    assert!(found.agent_ids.contains(&agent.agent_id()));
}

#[tokio::test]
async fn user_and_agent_link_to_discovered_machine() {
    let dir = TempDir::new().unwrap();
    let user_kp = x0x::identity::UserKeypair::generate().unwrap();
    let user_id = user_kp.user_id();
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_user_key(user_kp)
        .with_peer_cache_dir(test_peer_cache_dir(&dir))
        .with_network_config(NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            bootstrap_nodes: vec![],
            ..Default::default()
        })
        .build()
        .await
        .unwrap();

    agent.announce_identity(true, true).await.unwrap();

    let machine = agent
        .discovered_machine(agent.machine_id())
        .await
        .unwrap()
        .expect("own machine should be discoverable");
    assert!(machine.agent_ids.contains(&agent.agent_id()));
    assert!(machine.user_ids.contains(&user_id));

    let by_user = agent.find_machines_by_user(user_id).await.unwrap();
    assert!(by_user.iter().any(|m| m.machine_id == agent.machine_id()));
}
