#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for the connectivity module.
//!
//! Tests ReachabilityInfo heuristics, ConnectOutcome behaviour, and the
//! `connect_to_agent()` / `reachability()` methods on `Agent`.

use tempfile::TempDir;
use x0x::connectivity::{ConnectOutcome, ReachabilityInfo};
use x0x::{network::NetworkConfig, Agent, DiscoveredAgent};

/// Explicit test-only network config (#417/#337): loopback bind, no
/// seeds, discovery/port-mapping off. Still a real socket constructor.
fn test_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn build_agent(dir: &TempDir) -> Agent {
    Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key_path(dir.path().join("agent.key"))
        .with_network_config(test_network_config())
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
        self_name: None,
        cert_digest: None,
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
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
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
// #927/#898: unverified claims must not reach the discovery cache via
// connect_to_agent's DirectMessaging promotion
// ---------------------------------------------------------------------------

/// #898 (promotion arm): a raw Direct payload from a LIVE machine M2 that
/// claims agent A (verified binding on M1) must not rebind A — and crucially
/// must not be PROMOTED: `connect_to_agent` rewrites A's discovery-cache
/// machine whenever `DirectMessaging` maps A to a transport-connected
/// machine, so the gate has to hold at the routing write, not just the
/// listener.
///
/// This test builds the live connection for real (so `is_connected(M2)` is
/// genuinely true and the promotion branch is reachable), makes the exact
/// listener call for a spoof (`mark_raw_direct_sender_connected(A, M2,
/// verified=false)`), and then runs `connect_to_agent(A)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unverified_raw_claim_cannot_promote_into_discovery_cache() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;

    // A real, live connection to M2 so the promotion branch's
    // `is_connected(M2)` is true — otherwise this test would prove nothing
    // (without a live M2 the promotion cannot fire even if the gate is
    // reverted).
    let m2_addr = m2.bound_addr().await.expect("m2 bound addr");
    let m2_machine = m2.machine_id();
    local
        .network()
        .expect("local network")
        .connect_addr(m2_addr)
        .await
        .expect("dial m2");
    let m2_peer = ant_quic::PeerId(m2_machine.0);
    let local_network = local.network().expect("local network");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !local_network.is_connected(&m2_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "m2 never became transport-connected"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Agent A: verified binding on M1 (fake, offline), cached in discovery.
    let da = fake_discovered(0x21, vec![], None, Some(true), None, None);
    let a_id = da.agent_id;
    let m1 = da.machine_id;
    let _ = m2_machine; // used implicitly via m2_peer above
    local.insert_discovered_agent_for_testing(da).await;
    local
        .direct_messaging()
        .mark_raw_direct_sender_connected(a_id, m1, true)
        .await;
    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        Some(m1),
        "precondition: A's verified binding is M1"
    );

    // The spoof: M2 prefixes A's id; the listener computed verified=false
    // and made exactly this call.
    assert!(
        !local
            .direct_messaging()
            .mark_raw_direct_sender_connected(a_id, m2.machine_id(), false)
            .await,
        "the unverified claim must be refused"
    );
    // The promotion: connect_to_agent reads DirectMessaging and rewrites
    // the discovery cache when the mapped machine is live. With the gate
    // held, A stays on M1 in BOTH structures.
    let _outcome = local.connect_to_agent(&a_id).await.unwrap();
    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        Some(m1),
        "connect_to_agent must not promote the refused claim (#898)"
    );
    // `machine_for_agent` resolves from the discovery cache, so this pins
    // the promotion target too.
    let resolved = local
        .machine_for_agent(a_id)
        .await
        .unwrap()
        .expect("A stays in the discovery cache");
    assert_eq!(
        resolved.machine_id, m1,
        "the discovery cache must still route A to M1"
    );

    local.shutdown().await;
    m2.shutdown().await;
}

/// S1 (#898 review): step 4 (`direct_per_addr`) must not rebind an agent
/// whose machine is KNOWN to whichever machine answers a stale address.
/// M2 (real daemon) answers at the address the cache holds for A@M1; the
/// dial succeeds, the answered machine is NOT M1, and both the discovery
/// cache and DirectMessaging must stay on M1. Without the mismatch check
/// this test fails: A rebinds to M2, and M2's later raw claims for A
/// would compute verified=true.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_address_answered_by_a_different_machine_never_rebinds() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;

    // M2 is LIVE at X; the cache says A@M1 lives at X too.
    let x = m2.bound_addr().await.expect("m2 bound");
    let da = fake_discovered(0x31, vec![x], None, Some(true), None, None);
    let a_id = da.agent_id;
    let m1 = da.machine_id;
    assert_ne!(
        m1,
        m2.machine_id(),
        "the attacker must differ from the binding"
    );
    local.insert_discovered_agent_for_testing(da).await;
    local
        .direct_messaging()
        .mark_raw_direct_sender_connected(a_id, m1, true)
        .await;

    // Hinted dial to M1 (step 3) fails: M2 answers X but is not M1's
    // PeerId; step 4 then dials X with NO peer expectation — M2 answers.
    let _outcome = local.connect_to_agent(&a_id).await.unwrap();

    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        Some(m1),
        "step 4 must not hand A to the machine that merely answered the address (#898 S1)"
    );
    let resolved = local
        .machine_for_agent(a_id)
        .await
        .unwrap()
        .expect("A stays in the discovery cache");
    assert_eq!(
        resolved.machine_id, m1,
        "the discovery cache must still route A to M1"
    );

    local.shutdown().await;
    m2.shutdown().await;
}

/// T1 (#898 review, Rule 9): drive REAL raw Direct bytes through the
/// production listener. M2 (a live daemon) sends a Direct payload whose
/// 32-byte prefix claims A; A is cached on M1, so the listener computes
/// verified=false. The message must still be DELIVERED (annotated
/// unverified) and A must never be marked connected to M2. Reverting the
/// listener's call site to a plain `mark_connected` (the mutant that
/// survived the r1 review) makes this test FAIL at the routing assert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_direct_listener_refuses_an_unverified_claim_end_to_end() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;
    // join_network starts the REAL direct listener (and the identity /
    // network-event loops) on the loopback plane.
    local.join_network().await.expect("local join network");

    let da = fake_discovered(0x41, vec![], None, Some(true), None, None);
    let a_id = da.agent_id;
    let m1 = da.machine_id;
    local.insert_discovered_agent_for_testing(da).await;

    // Connect M2 → local, then spoof: M2 sends a raw Direct frame whose
    // sender prefix claims A.
    let local_addr = local.bound_addr().await.expect("local bound");
    let m2_network = m2.network().expect("m2 network");
    m2_network
        .connect_addr(local_addr)
        .await
        .expect("dial local");
    let local_peer = ant_quic::PeerId(local.machine_id().0);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !m2_network.is_connected(&local_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "local never became transport-connected to m2"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut claimed_sender = [0u8; 32];
    claimed_sender.copy_from_slice(a_id.as_bytes());
    m2_network
        .send_direct(&local_peer, &claimed_sender, b"898 spoof")
        .await
        .expect("spoofed raw direct send");

    // Delivery is unchanged: the message arrives, annotated UNVERIFIED.
    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(msg) = local.recv_direct_annotated().await {
                return msg;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the spoofed DM must still be delivered");
    assert_eq!(delivered.sender, a_id);
    assert!(
        !delivered.verified,
        "an unverified claim is delivered annotated unverified"
    );
    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        None,
        "the listener must never mark A onto the claiming machine (#898)"
    );
    let _ = m1; // binding machine; A was never marked to it either

    local.shutdown().await;
    m2.shutdown().await;
}

/// C1 (#898 review): evidence is `verified` OR an authenticated binding
/// naming THIS machine. A moved agent whose announcement updated
/// AuthenticatedMachineBindings but is too stale for the discovery cache
/// (raw `verified` stays false) must still have its routing updated by
/// the listener. Drives the same real listener path as T1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_binding_names_the_machine_and_routing_follows() {
    let local_dir = TempDir::new().unwrap();
    let m2_dir = TempDir::new().unwrap();
    let local = build_agent(&local_dir).await;
    let m2 = build_agent(&m2_dir).await;
    local.join_network().await.expect("local join network");

    // The cache still says A@M1 (stale); the AUTHENTICATED binding says
    // A moved to M2 (announcement landed, cache insert did not).
    let da = fake_discovered(0x51, vec![], None, Some(true), None, None);
    let a_id = da.agent_id;
    let _m1 = da.machine_id;
    local.insert_discovered_agent_for_testing(da).await;
    local
        .record_authenticated_machine_binding_for_testing(a_id, m2.machine_id())
        .await;

    let local_addr = local.bound_addr().await.expect("local bound");
    let m2_network = m2.network().expect("m2 network");
    m2_network
        .connect_addr(local_addr)
        .await
        .expect("dial local");
    let local_peer = ant_quic::PeerId(local.machine_id().0);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    while !m2_network.is_connected(&local_peer).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "local never became transport-connected to m2"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut sender_bytes = [0u8; 32];
    sender_bytes.copy_from_slice(a_id.as_bytes());
    m2_network
        .send_direct(&local_peer, &sender_bytes, b"898 c1 move")
        .await
        .expect("raw direct send");

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if local
                .direct_messaging()
                .get_machine_id(&a_id)
                .await
                .is_some()
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the authenticated binding must let the routing write through");
    assert_eq!(
        local.direct_messaging().get_machine_id(&a_id).await,
        Some(m2.machine_id()),
        "C1: a binding naming THIS machine is evidence enough to update routing"
    );

    local.shutdown().await;
    m2.shutdown().await;
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
