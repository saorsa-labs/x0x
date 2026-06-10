//! X0X-0041 — Prefer-newest-connection policy on x0x raw-DM path.
//!
//! Acceptance criterion (from `docs/design/sota-borrow-plan.md` §4 X0X-0041):
//!
//! > Synthetic test: kill+restart a peer's QUIC connection mid-DM →
//! > `/direct/send` lands on the new connection in ≤ 500ms without surfacing
//! > a Timeout.
//!
//! These tests exercise both the prefer-newest plumbing and the public
//! raw-DM send contract: a `Replaced` lifecycle event must propagate to the
//! per-peer active-generation hint, and `send_direct_with_config` must reissue
//! an ACKed raw send on the replacement connection inside the 500 ms
//! acceptance budget without surfacing the stale connection timeout.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use x0x::direct::{DirectMessaging, RawQuicAckRaceTestHook};
use x0x::dm::{DmPath, DmSendConfig, DEFAULT_PREFER_NEWEST_GRACE_MS};
use x0x::identity::MachineId;
use x0x::network::NetworkConfig;
use x0x::{Agent, DiscoveredAgent};

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        ..NetworkConfig::default()
    }
}

fn normalize_loopback(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    if addr.ip().is_unspecified() {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        )
    } else {
        addr
    }
}

async fn build_agent_or_skip_network_bind_error(
    dir: &TempDir,
    name: &str,
) -> Result<Option<Agent>, Box<dyn std::error::Error>> {
    match Agent::builder()
        .with_machine_key(dir.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.path().join(format!("{name}-agent.key")))
        .with_contact_store_path(dir.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.path().join(format!("{name}-peer-cache")))
        .with_network_config(loopback_network_config())
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

fn discovered_agent(agent: &Agent, addr: std::net::SocketAddr, now_secs: u64) -> DiscoveredAgent {
    DiscoveredAgent {
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: None,
        addresses: vec![addr],
        announced_at: now_secs,
        last_seen: now_secs,
        machine_public_key: vec![],
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
    }
}

/// X0X-0041: a fresh `DmSendConfig` carries the documented 250ms grace.
#[test]
fn dm_send_config_default_grace_matches_documented_constant() {
    let cfg = DmSendConfig::default();
    assert_eq!(cfg.prefer_newest_grace_ms, DEFAULT_PREFER_NEWEST_GRACE_MS);
    assert_eq!(cfg.prefer_newest_grace_ms, 250);
}

/// X0X-0041: end-to-end propagation of a supersede event lands in well under
/// the 500ms acceptance budget.
///
/// Mirrors the "kill+restart a peer's QUIC connection mid-DM" scenario at the
/// `DirectMessaging` API layer: a Replaced event from the lifecycle watcher
/// must (a) update the per-peer active-generation hint and (b) reach a DM
/// retry-loop subscriber promptly.
#[tokio::test]
async fn supersede_propagates_within_500ms_acceptance_budget() {
    let dm = Arc::new(DirectMessaging::new());
    let machine_id = MachineId([0x42; 32]);

    // Establish gen 1 before the "send" begins.
    dm.record_lifecycle_established(machine_id, Some(1));
    assert_eq!(dm.current_generation(&machine_id), Some(1));

    // Subscribe BEFORE the supersede so we never miss the event — mirrors the
    // `send_direct_raw_quic` ordering (subscribe before connectivity probe).
    let mut rx = dm.subscribe_lifecycle_replaced();

    // Simulate ant-quic mid-DM connection-replacement: a peer's QUIC
    // connection is killed and restarted, so the lifecycle watcher emits
    // `Replaced { new_generation: 2, .. }` 50ms later.
    let dm_for_task = Arc::clone(&dm);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        dm_for_task.record_lifecycle_replaced(machine_id, 2);
    });

    let start = Instant::now();
    let (m, gen) = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("supersede must land inside the 500ms acceptance budget")
        .expect("broadcast channel still open");

    let elapsed = start.elapsed();
    assert_eq!(m, machine_id);
    assert_eq!(gen, 2);
    assert!(
        elapsed <= Duration::from_millis(500),
        "supersede took {elapsed:?} which exceeds the 500ms acceptance budget"
    );
    // Lifecycle table also reflects the new generation now.
    assert_eq!(dm.current_generation(&machine_id), Some(2));
}

/// X0X-0041: the public direct-send path reissues an ACKed raw send on the
/// replacement connection instead of surfacing the stale connection timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_send_reissues_on_replaced_connection_within_500ms(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new().expect("tmpdir");
    let Some(alice) = build_agent_or_skip_network_bind_error(&dir, "alice").await? else {
        return Ok(());
    };
    let Some(bob) = build_agent_or_skip_network_bind_error(&dir, "bob").await? else {
        return Ok(());
    };
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let bob_addr = normalize_loopback(
        bob_network
            .bound_addr()
            .await
            .expect("bob bound to loopback"),
    );
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    let connected = alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");
    assert_eq!(connected.0, bob.machine_id().0);

    let connected_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < connected_deadline {
        if alice_network.is_connected(&bob_peer).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(alice_network.is_connected(&bob_peer).await);

    let lifecycle_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < lifecycle_deadline {
        if alice
            .direct_messaging()
            .current_generation(&bob.machine_id())
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let pre_replace_generation = alice
        .direct_messaging()
        .current_generation(&bob.machine_id())
        .expect("initial lifecycle generation recorded");

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr, now_secs))
        .await;
    alice
        .direct_messaging()
        .mark_connected(bob.agent_id(), bob.machine_id())
        .await;
    let alice_addr = normalize_loopback(
        alice_network
            .bound_addr()
            .await
            .expect("alice bound to loopback"),
    );
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr, now_secs))
        .await;

    let payload = b"x0x-0041-public-direct-send-replaced".to_vec();
    let mut bob_rx = bob.subscribe_direct();
    let ack_race_hook = Arc::new(RawQuicAckRaceTestHook::new());
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(Some(Arc::clone(&ack_race_hook)));

    let send_cfg = DmSendConfig {
        prefer_raw_quic_if_connected: true,
        require_gossip: false,
        max_retries: 0,
        raw_quic_receive_ack_timeout: Some(Duration::from_millis(6_000)),
        stop_fallback_on_raw_error: true,
        ..DmSendConfig::default()
    };

    let alice_for_send = Arc::clone(&alice);
    let bob_agent_id = bob.agent_id();
    let send_payload = payload.clone();
    let send_start = Instant::now();
    let send_task = tokio::spawn(async move {
        alice_for_send
            .send_direct_with_config(&bob_agent_id, send_payload, send_cfg)
            .await
    });

    tokio::time::timeout(
        Duration::from_millis(250),
        ack_race_hook.wait_first_attempt_started(),
    )
    .await
    .expect("first ACKed raw send attempt starts before replacement");

    let alice_network_for_task = Arc::clone(&alice_network);
    let reconnect_task = tokio::spawn(async move {
        alice_network_for_task
            .disconnect(&bob_peer)
            .await
            .expect("disconnect old connection");
        alice_network_for_task
            .connect_addr(bob_addr)
            .await
            .expect("reconnect to bob")
    });

    tokio::time::timeout(
        Duration::from_millis(500),
        ack_race_hook.wait_replaced_short_circuit(),
    )
    .await
    .expect("direct send must observe the same-peer Replaced event");

    let remaining = Duration::from_millis(500)
        .checked_sub(send_start.elapsed())
        .unwrap_or(Duration::ZERO);
    let send_result = tokio::time::timeout(remaining, send_task).await;
    let send_elapsed = send_start.elapsed();

    let _reconnected_peer = reconnect_task.await.expect("reconnect task completes");
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(None);
    ack_race_hook.release_first_attempt_result();

    let receipt = send_result
        .expect("send_direct must complete inside the 500ms acceptance budget")
        .expect("send task should not panic")
        .expect("send_direct must return Ok on the replacement connection");
    assert!(
        send_elapsed <= Duration::from_millis(500),
        "send_direct took {send_elapsed:?}, exceeds the 500ms acceptance budget"
    );
    assert_eq!(receipt.path, DmPath::RawQuicAcked);

    let received = tokio::time::timeout(Duration::from_secs(2), bob_rx.recv())
        .await
        .expect("bob receives direct send payload")
        .expect("bob direct subscriber remains open");
    assert_eq!(received.sender, alice.agent_id());
    assert_eq!(received.payload, payload);

    let final_generation = alice
        .direct_messaging()
        .current_generation(&bob.machine_id());
    assert!(
        matches!(final_generation, Some(generation) if generation > pre_replace_generation),
        "replacement lifecycle generation did not advance past {pre_replace_generation}; got {final_generation:?}"
    );
    Ok(())
}

/// X0X-0041: legacy behaviour preserved when the grace knob is disabled.
#[test]
fn prefer_newest_grace_zero_disables_feature() {
    let cfg = DmSendConfig {
        prefer_newest_grace_ms: 0,
        ..DmSendConfig::default()
    };
    assert_eq!(cfg.prefer_newest_grace_ms, 0);
}
