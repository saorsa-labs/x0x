#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for the connectivity module.
//!
//! Tests ReachabilityInfo heuristics, ConnectOutcome behaviour, and the
//! `connect_to_agent()` / `reachability()` methods on `Agent`.

use tempfile::TempDir;
use x0x::connectivity::{ConnectOutcome, ReachabilityInfo};
use x0x::{network::NetworkConfig, Agent, DiscoveredAgent};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn build_agent(dir: &TempDir) -> Agent {
    Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_network_config(NetworkConfig::default())
        .build()
        .await
        .unwrap()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fake_discovered(
    id_byte: u8,
    addresses: Vec<std::net::SocketAddr>,
    nat_type: Option<&str>,
    can_receive_direct: Option<bool>,
    is_relay: Option<bool>,
    is_coordinator: Option<bool>,
) -> DiscoveredAgent {
    let now = now_secs();
    DiscoveredAgent {
        agent_id: x0x::identity::AgentId([id_byte; 32]),
        machine_id: x0x::identity::MachineId([id_byte + 100; 32]),
        user_id: None,
        addresses,
        announced_at: now,
        last_seen: now,
        machine_public_key: vec![],
        nat_type: nat_type.map(str::to_string),
        can_receive_direct,
        is_relay,
        is_coordinator,
    }
}

// ---------------------------------------------------------------------------
// ReachabilityInfo unit tests
// ---------------------------------------------------------------------------

#[test]
fn likely_direct_with_can_receive_direct_true() {
    let da = fake_discovered(
        1,
        vec!["127.0.0.1:9000".parse().unwrap()],
        None,
        Some(true),
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(info.likely_direct());
    assert!(!info.needs_coordination());
}

#[test]
fn not_likely_direct_with_can_receive_direct_false() {
    let da = fake_discovered(
        2,
        vec!["127.0.0.1:9000".parse().unwrap()],
        None,
        Some(false),
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.needs_coordination());
}

#[test]
fn likely_direct_for_full_cone_nat_is_false_without_peer_verification() {
    let da = fake_discovered(
        3,
        vec!["127.0.0.1:9000".parse().unwrap()],
        Some("FullCone"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.should_attempt_direct());
    assert!(info.needs_coordination());
}

#[test]
fn not_likely_direct_for_symmetric_nat() {
    let da = fake_discovered(
        4,
        vec!["127.0.0.1:9000".parse().unwrap()],
        Some("Symmetric"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.needs_coordination());
}

#[test]
fn not_likely_direct_without_addresses() {
    let da = fake_discovered(5, vec![], None, Some(true), None, None);
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct(), "no addresses means no direct path");
}

#[test]
fn unknown_reachability_still_attempts_direct() {
    let da = fake_discovered(
        6,
        vec!["192.168.1.1:9000".parse().unwrap()],
        None,
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(
        info.should_attempt_direct(),
        "unknown peers still get a direct probe"
    );
    assert!(info.needs_coordination());
}

#[test]
fn is_relay_returns_false_when_none() {
    let da = fake_discovered(7, vec![], None, None, None, None);
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.is_relay());
}

#[test]
fn is_relay_returns_true_when_some_true() {
    let da = fake_discovered(8, vec![], None, None, Some(true), None);
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(info.is_relay());
}

#[test]
fn is_coordinator_returns_false_when_none() {
    let da = fake_discovered(9, vec![], None, None, None, None);
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.is_coordinator());
}

#[test]
fn is_coordinator_returns_true_when_some_true() {
    let da = fake_discovered(10, vec![], None, None, None, Some(true));
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(info.is_coordinator());
}

// ---------------------------------------------------------------------------
// ConnectOutcome unit tests
// ---------------------------------------------------------------------------

#[test]
fn connect_outcome_display() {
    let addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
    assert_eq!(
        ConnectOutcome::Direct(addr).to_string(),
        format!("direct({addr})")
    );
    assert_eq!(
        ConnectOutcome::Coordinated(addr).to_string(),
        format!("coordinated({addr})")
    );
    assert_eq!(ConnectOutcome::Unreachable.to_string(), "unreachable");
    assert_eq!(ConnectOutcome::NotFound.to_string(), "not_found");
}

#[test]
fn connect_outcome_equality() {
    let addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
    assert_eq!(ConnectOutcome::Direct(addr), ConnectOutcome::Direct(addr));
    assert_eq!(ConnectOutcome::Unreachable, ConnectOutcome::Unreachable);
    assert_ne!(ConnectOutcome::Direct(addr), ConnectOutcome::Unreachable);
    assert_ne!(
        ConnectOutcome::Direct(addr),
        ConnectOutcome::Coordinated(addr)
    );
    assert_ne!(ConnectOutcome::NotFound, ConnectOutcome::Unreachable);
}

// ---------------------------------------------------------------------------
// Agent::connect_to_agent() integration tests
// ---------------------------------------------------------------------------

/// Connecting to a non-existent agent returns NotFound.
#[tokio::test]
async fn connect_to_unknown_agent_returns_not_found() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let unknown_id = x0x::identity::AgentId([200u8; 32]);
    let outcome = agent.connect_to_agent(&unknown_id).await.unwrap();
    assert_eq!(outcome, ConnectOutcome::NotFound);
}

/// Connecting to a non-existent machine returns NotFound.
#[tokio::test]
async fn connect_to_unknown_machine_returns_not_found() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let unknown_id = x0x::identity::MachineId([201u8; 32]);
    let outcome = agent.connect_to_machine(&unknown_id).await.unwrap();
    assert_eq!(outcome, ConnectOutcome::NotFound);
}

/// An agent with no addresses returns Unreachable.
#[tokio::test]
async fn connect_to_agent_with_no_addresses_returns_unreachable() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let da = fake_discovered(100, vec![], None, Some(true), None, None);
    let target_id = da.agent_id;
    agent.insert_discovered_agent_for_testing(da).await;

    let outcome = agent.connect_to_agent(&target_id).await.unwrap();
    assert_eq!(
        outcome,
        ConnectOutcome::Unreachable,
        "no addresses means unreachable"
    );
}

/// Without a network started, connecting returns Unreachable (not an error).
#[tokio::test]
async fn connect_without_network_returns_unreachable() {
    let dir = TempDir::new().unwrap();
    // Build agent WITHOUT a bind address (no network)
    let agent = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        // No network config = no network started
        .build()
        .await
        .unwrap();

    let da = fake_discovered(
        101,
        vec!["127.0.0.1:9999".parse().unwrap()],
        None,
        Some(true),
        None,
        None,
    );
    let target_id = da.agent_id;
    agent.insert_discovered_agent_for_testing(da).await;

    let outcome = agent.connect_to_agent(&target_id).await.unwrap();
    assert_eq!(
        outcome,
        ConnectOutcome::Unreachable,
        "no network started → Unreachable, not an error"
    );
}

// ---------------------------------------------------------------------------
// Agent::reachability() integration tests
// ---------------------------------------------------------------------------

/// reachability() returns None for an agent not in the cache.
#[tokio::test]
async fn reachability_none_for_unknown_agent() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let unknown_id = x0x::identity::AgentId([201u8; 32]);
    assert!(agent.reachability(&unknown_id).await.is_none());
}

/// reachability() returns correct info for an agent in the cache.
#[tokio::test]
async fn reachability_returns_correct_info_from_cache() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let da = fake_discovered(
        102,
        vec!["10.0.0.2:8080".parse().unwrap()],
        Some("FullCone"),
        Some(true),
        Some(false),
        Some(true),
    );
    let target_id = da.agent_id;
    agent.insert_discovered_agent_for_testing(da).await;

    let info = agent.reachability(&target_id).await;
    assert!(info.is_some());
    let info = info.unwrap();

    assert!(info.likely_direct());
    assert!(info.should_attempt_direct());
    assert!(!info.needs_coordination());
    assert!(!info.is_relay());
    assert!(info.is_coordinator());
    assert_eq!(info.addresses.len(), 1);
}

/// Inserting an agent discovery record also creates the machine endpoint link.
#[tokio::test]
async fn machine_for_agent_returns_linked_endpoint() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(&dir).await;

    let da = fake_discovered(
        103,
        vec!["10.0.0.3:8080".parse().unwrap()],
        Some("FullCone"),
        Some(true),
        Some(false),
        Some(true),
    );
    let target_id = da.agent_id;
    let target_machine = da.machine_id;
    agent.insert_discovered_agent_for_testing(da).await;

    let machine = agent
        .machine_for_agent(target_id)
        .await
        .unwrap()
        .expect("agent should resolve to a machine");
    assert_eq!(machine.machine_id, target_machine);
    assert!(machine.agent_ids.contains(&target_id));
    assert_eq!(machine.addresses.len(), 1);
}

// ---------------------------------------------------------------------------
// ReachabilityInfo: all NAT type heuristics
// ---------------------------------------------------------------------------

#[test]
fn nat_type_none_string_is_not_enough_without_peer_verification() {
    let da = fake_discovered(
        20,
        vec!["1.2.3.4:9000".parse().unwrap()],
        Some("None"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.should_attempt_direct());
}

#[test]
fn nat_type_address_restricted_still_attempts_direct_but_is_not_verified() {
    let da = fake_discovered(
        21,
        vec!["1.2.3.4:9000".parse().unwrap()],
        Some("AddressRestricted"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.should_attempt_direct());
    assert!(info.needs_coordination());
}

#[test]
fn nat_type_port_restricted_still_attempts_direct_but_is_not_verified() {
    let da = fake_discovered(
        22,
        vec!["1.2.3.4:9000".parse().unwrap()],
        Some("PortRestricted"),
        None,
        None,
        None,
    );
    let info = ReachabilityInfo::from_discovered(&da);
    assert!(!info.likely_direct());
    assert!(info.should_attempt_direct());
    assert!(info.needs_coordination());
}
