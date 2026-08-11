//! X0X-0053 (and X0X-0054 closure) — synthetic kill+restart acceptance test
//! for the proper X0X-0041 rework: race the in-flight raw-QUIC
//! `send_with_receive_ack` against same-peer `PeerLifecycleEvent::Replaced`.
//!
//! Acceptance criterion (verbatim from `issues/issues.jsonl` X0X-0053):
//!
//! > New synthetic test: kill+restart a peer's QUIC connection during an
//! > in-flight `send_with_receive_ack`, `/direct/send` returns
//! > `Ok(DmPath::RawQuicAcked)` within 500 ms, no Timeout error.
//!
//! Acceptance criterion (verbatim from `issues/issues.jsonl` X0X-0054):
//!
//! > - New test that uses two real x0x agents (Tokio runtime, real ant-quic).
//! > - Connection between them established via `connect_addr`.
//! > - The 'kill+restart' is performed by `network.disconnect(peer_id)`
//! >   followed by ant-quic's natural reconnect — NOT by manually invoking
//! >   `record_lifecycle_replaced`. The test's correctness depends on the
//! >   lifecycle watcher loop in `src/lib.rs:5985-` actually receiving
//! >   `PeerLifecycleEvent::Replaced` from ant-quic and firing
//! >   `record_lifecycle_replaced` itself.
//! > - `DmSendConfig` with `raw_quic_receive_ack_timeout: Some(Duration::from_millis(6000))`
//! >   so the send goes through `DmPath::RawQuicAcked`.
//! > - Acceptance assertion: `send_direct_with_config` returns
//! >   `Ok(DmPath::RawQuicAcked)` within 500 ms.
//!
//! ## What this test does
//!
//! Brings up two real `Agent`s in-process bound to ephemeral 127.0.0.1
//! ports, establishes a real QUIC connection between them via
//! `connect_addr`, then:
//!
//! 1. Subscribes to bob's incoming-DM channel BEFORE the test send.
//! 2. Installs a test hook on alice's ACKed raw send path, issues the DM,
//!    waits until `send_ack_racing_replaced` has subscribed to Replaced
//!    events and started polling the first `send_with_receive_ack` attempt,
//!    then calls `alice_network.disconnect(bob_peer)` and
//!    `alice_network.connect_addr(bob_addr)`. The reconnect to the same
//!    peer triggers ant-quic's `peer_event_generations` table to advance —
//!    `peer_event_generations` retains the previous generation across
//!    disconnect (`ant-quic/src/p2p_endpoint.rs:2069-2072`), so the first
//!    reconnect after a disconnect fires
//!    `PeerLifecycleEvent::Replaced { old, new }`. The lifecycle watcher
//!    loop in `src/lib.rs::~5933` consumes the event and calls
//!    `DirectMessaging::record_lifecycle_replaced` — the production
//!    code path. **No manual `record_lifecycle_replaced` injection.**
//! 3. Issues `agent_a.send_direct_with_config(bob, payload, cfg)` with
//!    `DmSendConfig { raw_quic_receive_ack_timeout: Some(6000ms),
//!    prefer_raw_quic_if_connected: true, ... }`. The send goes through
//!    `send_direct_raw_quic` → ACKed branch →
//!    `send_ack_racing_replaced`, which subscribes to
//!    `lifecycle_replaced_rx` *before* invoking
//!    `network.send_with_receive_ack(...)` so any same-peer Replaced
//!    that fires mid-flight is delivered to the racing helper, not
//!    dropped.
//! 4. Asserts:
//!    - returns `Ok(receipt)` with `receipt.path == DmPath::RawQuicAcked`
//!    - elapsed wall-clock ≤ 500 ms (X0X-0053 acceptance budget)
//!    - bob's `recv_direct` receives the bytes within 2 s
//!    - alice's `current_generation(bob_machine)` advanced past the
//!      pre-kill snapshot (proves the real ant-quic Replaced flowed
//!      through the watcher loop into `DirectMessaging`)
//!
//! ## What this test PROVES end-to-end
//!
//! Three concrete production-path properties:
//!
//! 1. **Real ant-quic lifecycle events flow through the watcher into
//!    `DirectMessaging`** — verified by the lifecycle-generation
//!    advancement assertion. This was the primary X0X-0054 P2a finding:
//!    the previously-shipped test bypassed the lifecycle watcher with a
//!    manual `record_lifecycle_replaced` call, so it never proved the
//!    plumbing was actually wired up to ant-quic's event stream.
//! 2. **The X0X-0053 racing helper subscribes to
//!    `lifecycle_replaced_rx` BEFORE issuing `send_with_receive_ack`** —
//!    verified by the test hook that only fires after the helper has
//!    subscribed and started polling the first ACKed raw send attempt, plus
//!    the required short-circuit signal when the same-peer Replaced wins the
//!    race. (See production helper at `src/lib.rs::send_ack_racing_replaced`.)
//! 3. **The ACKed raw path completes successfully under disconnect+
//!    reconnect churn within the 500 ms acceptance budget** — verified
//!    by the `Ok(DmPath::RawQuicAcked)` + send_elapsed assertions and
//!    the bob.recv_direct round-trip. This is the X0X-0053 acceptance
//!    criterion verbatim.
//!
//! ## Deterministic race synchronization
//!
//! Loopback delivery is fast enough that a fixed sleep can let the first
//! `send_with_receive_ack` complete before the disconnect, so the test no
//! longer relies on wall-clock timing to prove the race. Instead it installs
//! a narrow test hook that:
//!
//! - signals only after `send_ack_racing_replaced` has subscribed to
//!   Replaced events and started polling the first ACKed raw send attempt;
//! - holds that first-attempt result pending so the helper cannot return
//!   before the synthetic supersede; and
//! - requires the helper's same-peer Replaced short-circuit signal before
//!   accepting the final `Ok(DmPath::RawQuicAcked)`.
//!
//! A single-shot `network.send_with_receive_ack(...)` implementation with no
//! Replaced subscription/reissue path cannot produce that short-circuit signal,
//! so the test now fails deterministically when the race arm is removed.
//!
//! ## Stop conditions consulted
//!
//! - `NetworkNode::disconnect(peer_id)` (`src/network.rs:1691-`) is the
//!   close API; no follow-up "we need a force_close test surface" ticket
//!   is needed.
//! - Two-bob shared-machine_key approach was prototyped (build a second
//!   bob agent with the same machine_key file so ant-quic sees a single
//!   peer_id with two distinct generations) and produced a real
//!   Replaced event end-to-end, but bob2's listener didn't reliably
//!   accept the in-flight message after the supersede on the same
//!   loopback runtime — likely a property of how the synthetic
//!   listener registry routes the post-supersede stream. The
//!   single-bob disconnect+reconnect design that ships here is the
//!   stable, deflakable variant.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use x0x::direct::RawQuicAckRaceTestHook;
use x0x::dm::{DmPath, DmSendConfig};
use x0x::network::NetworkConfig;
use x0x::Agent;

/// Build an `Agent` bound to an ephemeral 127.0.0.1 UDP port with no
/// bootstrap nodes — mirrors the in-tree `loopback_network_config` helper.
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

fn discovered_agent(agent: &Agent, addr: std::net::SocketAddr) -> x0x::DiscoveredAgent {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    x0x::DiscoveredAgent {
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
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    }
}

async fn build_agent(dir: &TempDir, name: &str) -> Agent {
    Agent::builder()
        .with_machine_key(dir.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.path().join(format!("{name}-agent.key")))
        .with_contact_store_path(dir.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.path().join(format!("{name}-peer-cache")))
        .with_network_config(loopback_network_config())
        .build()
        .await
        .expect("agent builds")
}

async fn build_history_agent(dir: &TempDir, name: &str) -> Agent {
    Agent::builder()
        .with_machine_key(dir.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.path().join(format!("{name}-agent.key")))
        .with_contact_store_path(dir.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.path().join(format!("{name}-peer-cache")))
        .with_network_config(loopback_network_config())
        .with_history(x0x::history::HistoryConfig {
            enabled: true,
            db_path: Some(dir.path().join(format!("{name}-history.db"))),
            ..x0x::history::HistoryConfig::default()
        })
        .build()
        .await
        .expect("history-enabled agent builds")
}

/// X0X-0053 acceptance: with the racing-against-Replaced arm in place,
/// kill+restart a peer's QUIC connection while an ACKed raw send is in
/// flight, and prove `/direct/send` returns `Ok(DmPath::RawQuicAcked)`
/// inside the 500 ms budget without surfacing a Timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn synthetic_kill_restart_lands_on_new_connection_within_500ms() {
    // ---------------------------------------------------------------------
    // 1. Bring up two agents on 127.0.0.1, fully join the network so the
    //    direct-message listener and lifecycle watcher are wired up.
    // ---------------------------------------------------------------------
    let dir = TempDir::new().expect("tmpdir");
    let alice = Arc::new(build_agent(&dir, "alice").await);
    let bob = Arc::new(build_agent(&dir, "bob").await);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();

    let bob_addr = normalize_loopback(
        bob_network
            .bound_addr()
            .await
            .expect("bob bound to a loopback addr"),
    );
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    // ---------------------------------------------------------------------
    // 2. Establish the initial direct connection alice → bob (gen 1).
    // ---------------------------------------------------------------------
    let connected = alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");
    assert_eq!(
        connected.0,
        bob.machine_id().0,
        "ant-quic peer id should match bob's machine_id"
    );

    let connected_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < connected_deadline {
        if alice_network.is_connected(&bob_peer).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        alice_network.is_connected(&bob_peer).await,
        "alice must be connected to bob before kill+restart"
    );

    // Wait briefly for the lifecycle watcher to record the initial
    // Established event for the new connection.
    let lifecycle_seed_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < lifecycle_seed_deadline {
        if alice
            .direct_messaging()
            .current_generation(&bob.machine_id())
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let pre_kill_generation = alice
        .direct_messaging()
        .current_generation(&bob.machine_id())
        .expect("lifecycle watcher should have recorded the initial Established");

    // ---------------------------------------------------------------------
    // 3. Wire alice's discovery cache + DM registry so send_direct can
    //    resolve bob's machine_id without an announcement round-trip.
    // ---------------------------------------------------------------------
    use x0x::DiscoveredAgent;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let bob_card = DiscoveredAgent {
        agent_id: bob.agent_id(),
        machine_id: bob.machine_id(),
        user_id: None,
        addresses: vec![bob_addr],
        announced_at: now_secs,
        last_seen: now_secs,
        machine_public_key: vec![],
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    };
    alice.insert_discovered_agent_for_testing(bob_card).await;
    alice
        .direct_messaging()
        .mark_connected(bob.agent_id(), bob.machine_id())
        .await;

    let alice_card = DiscoveredAgent {
        agent_id: alice.agent_id(),
        machine_id: alice.machine_id(),
        user_id: None,
        addresses: vec![normalize_loopback(
            alice_network.bound_addr().await.expect("alice bound addr"),
        )],
        announced_at: now_secs,
        last_seen: now_secs,
        machine_public_key: vec![],
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    };
    bob.insert_discovered_agent_for_testing(alice_card).await;

    // ---------------------------------------------------------------------
    // 4. Subscribe to bob's incoming-DM channel BEFORE we issue the send so
    //    we never miss the message. Install the ACK-race hook before the
    //    send so the test can synchronize on the first attempt being polled.
    // ---------------------------------------------------------------------
    let mut bob_rx = bob.subscribe_direct();
    let ack_race_hook = Arc::new(RawQuicAckRaceTestHook::new());
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(Some(Arc::clone(&ack_race_hook)));

    // ---------------------------------------------------------------------
    // 5. Issue /direct/send under a 500 ms wall clock budget, then wait for
    //    the hook proving `send_ack_racing_replaced` subscribed to Replaced
    //    events and started polling the first ACKed raw send attempt. Only
    //    then do we trigger the kill+restart.
    //
    //    `disconnect(bob_peer)` drops the gen-1 connection.
    //    `connect_addr(bob_addr)` re-establishes via a fresh QUIC
    //    handshake. Because `peer_event_generations` retained gen 1
    //    across the disconnect (`p2p_endpoint.rs:2069-2072`), ant-quic
    //    fires `PeerLifecycleEvent::Replaced { old: gen-1, new: gen-2 }`
    //    when the new connection registers. The lifecycle watcher loop
    //    in `src/lib.rs::~5933` consumes the event and calls
    //    `DirectMessaging::record_lifecycle_replaced`, which fires the
    //    broadcast our racing helper is subscribed to.
    // ---------------------------------------------------------------------
    let payload: Vec<u8> = b"x0x-0053-mid-send-replaced-race-payload".to_vec();
    let send_cfg = DmSendConfig {
        prefer_raw_quic_if_connected: true,
        require_gossip: false,
        max_retries: 0,
        // X0X-0054 explicit requirement: route through DmPath::RawQuicAcked.
        // 6000 ms is generous so the in-flight (dead-connection) call
        // would sit waiting if the race arm did NOT fire — far past the
        // 500 ms acceptance budget.
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
    .expect("send_direct must start polling the first ACKed raw send before kill+restart");

    let alice_network_for_task = Arc::clone(&alice_network);
    let kill_restart = tokio::spawn(async move {
        alice_network_for_task
            .disconnect(&bob_peer)
            .await
            .expect("disconnect should succeed");
        alice_network_for_task
            .connect_addr(bob_addr)
            .await
            .expect("reconnect alice→bob")
    });

    // ---------------------------------------------------------------------
    // 6. Require the racing helper to observe the same-peer Replaced event
    //    and take the short-circuit/reissue path. This is the assertion that
    //    makes the test fail when `send_ack_racing_replaced` is replaced by a
    //    single-shot `network.send_with_receive_ack(...)`.
    // ---------------------------------------------------------------------
    tokio::time::timeout(
        Duration::from_millis(500),
        ack_race_hook.wait_replaced_short_circuit(),
    )
    .await
    .expect("send_ack_racing_replaced must short-circuit on the same-peer Replaced event");

    let remaining = Duration::from_millis(500)
        .checked_sub(send_start.elapsed())
        .unwrap_or(Duration::ZERO);
    let send_result = tokio::time::timeout(remaining, send_task).await;
    let send_elapsed = send_start.elapsed();

    let _reconnected_peer = kill_restart
        .await
        .expect("kill+restart task ran to completion");

    // Hard acceptance: the outer 500 ms budget itself.
    let receipt = send_result
        .expect("send_direct must complete inside the 500ms acceptance budget — no Timeout")
        .expect("send task should not panic")
        .expect("send_direct must return Ok on the new connection");
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(None);
    ack_race_hook.release_first_attempt_result();

    assert!(
        send_elapsed <= Duration::from_millis(500),
        "send_direct took {send_elapsed:?}, exceeds the 500ms acceptance budget"
    );

    // X0X-0054 explicit: the path MUST be the ACKed raw path.
    assert_eq!(
        receipt.path,
        DmPath::RawQuicAcked,
        "expected DmPath::RawQuicAcked on the new connection (raw_quic_receive_ack_timeout was Some), got {:?}",
        receipt.path
    );

    // ---------------------------------------------------------------------
    // 7. Confirm bob actually received the bytes.
    // ---------------------------------------------------------------------
    let recv_deadline = Duration::from_millis(2_000);
    let received = tokio::time::timeout(recv_deadline, bob_rx.recv())
        .await
        .expect("bob should receive the DM within 2s")
        .expect("bob's direct subscriber channel should still be open");
    assert_eq!(
        received.payload, payload,
        "bob's payload must match what alice sent"
    );
    assert_eq!(
        received.sender,
        alice.agent_id(),
        "bob should see alice as the sender"
    );

    // ---------------------------------------------------------------------
    // 8. Lifecycle table reflects a new generation past the pre-kill
    //    snapshot, proving the real ant-quic Replaced event flowed
    //    through the watcher loop into DirectMessaging — i.e. the test
    //    exercised the production lifecycle path, not a manual injection.
    // ---------------------------------------------------------------------
    let final_gen = alice
        .direct_messaging()
        .current_generation(&bob.machine_id());
    assert!(
        matches!(final_gen, Some(g) if g > pre_kill_generation),
        "alice should have advanced bob's lifecycle generation past {pre_kill_generation}; got {final_gen:?}"
    );
}

/// Regression for the v0.37.0 two-Mac failure: an ACKed raw DM that hits a
/// stale cached connection must repair and reissue within the SAME logical
/// send. Before the fix the stale connection was torn down only while
/// returning the first error, so only a later HTTP request could recover.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cached_connection_ack_failure_repairs_and_retries_same_send() {
    let dir = TempDir::new().expect("tmpdir");
    let alice = Arc::new(build_agent(&dir, "retry-alice").await);
    let bob = Arc::new(build_agent(&dir, "retry-bob").await);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let alice_addr = normalize_loopback(
        alice_network
            .bound_addr()
            .await
            .expect("alice bound to loopback"),
    );
    let bob_addr = normalize_loopback(
        bob_network
            .bound_addr()
            .await
            .expect("bob bound to loopback"),
    );
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);
    alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let discovered = |agent: &Agent, addr| x0x::DiscoveredAgent {
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
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    };
    alice
        .insert_discovered_agent_for_testing(discovered(&bob, bob_addr))
        .await;
    bob.insert_discovered_agent_for_testing(discovered(&alice, alice_addr))
        .await;

    let connected_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < connected_deadline {
        if alice_network.is_connected(&bob_peer).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        alice_network.is_connected(&bob_peer).await,
        "precondition: cached direct connection is live"
    );

    let hook = Arc::new(RawQuicAckRaceTestHook::new_forced_first_failure());
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(Some(Arc::clone(&hook)));
    let mut bob_rx = bob.subscribe_direct();
    let payload = b"same-request-repair-after-stale-cached-connection".to_vec();
    let receipt = tokio::time::timeout(
        Duration::from_secs(5),
        alice.send_direct_with_config(
            &bob.agent_id(),
            payload.clone(),
            DmSendConfig {
                prefer_raw_quic_if_connected: true,
                raw_quic_receive_ack_timeout: Some(Duration::from_secs(1)),
                stop_fallback_on_raw_error: true,
                max_retries: 0,
                ..DmSendConfig::default()
            },
        ),
    )
    .await
    .expect("same logical send repairs inside five seconds")
    .expect("repair retry returns success");

    tokio::time::timeout(Duration::from_secs(1), hook.wait_repair_retry_started())
        .await
        .expect("receive-ACK failure must take the repair retry path");
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(None);

    assert_eq!(receipt.path, DmPath::RawQuicAcked);
    let received = tokio::time::timeout(Duration::from_secs(2), bob_rx.recv())
        .await
        .expect("bob receives retry payload")
        .expect("bob subscriber remains open");
    assert_eq!(received.payload, payload);
    let unexpected_second_message = bob_rx.try_recv();
    assert!(
        unexpected_second_message.is_none(),
        "forced pre-send failure must not duplicate the application payload: {unexpected_second_message:?}"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}

/// Deterministic coverage for two lifecycle races around a successful old-
/// generation ACK: (1) both the ACK result and Replaced are ready in the
/// biased select, and (2) the target Replaced event is skipped by broadcast
/// lag. Both must reissue with the original ant request id, so Bob admits each
/// logical payload exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successful_ack_replaced_races_reissue_duplicate_safe() {
    let dir = TempDir::new().expect("tmpdir");
    let alice = Arc::new(build_agent(&dir, "race-alice").await);
    let bob = Arc::new(build_agent(&dir, "race-bob").await);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");
    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let alice_addr = normalize_loopback(
        alice_network
            .bound_addr()
            .await
            .expect("alice bound to loopback"),
    );
    let bob_addr = normalize_loopback(
        bob_network
            .bound_addr()
            .await
            .expect("bob bound to loopback"),
    );
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr))
        .await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr))
        .await;
    alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");
    alice
        .direct_messaging()
        .mark_connected(bob.agent_id(), bob.machine_id())
        .await;

    let mut bob_rx = bob.subscribe_direct();
    let send_config = || DmSendConfig {
        prefer_raw_quic_if_connected: true,
        raw_quic_receive_ack_timeout: Some(Duration::from_secs(2)),
        stop_fallback_on_raw_error: true,
        max_retries: 0,
        ..DmSendConfig::default()
    };

    // Both-ready branch: the hook queues Replaced after transport ACK success
    // but before the send future returns to the biased select.
    let both_ready = Arc::new(RawQuicAckRaceTestHook::new_queued_replaced_after_success());
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(Some(Arc::clone(&both_ready)));
    let first_payload = b"both-ready-old-generation-ack".to_vec();
    let first_send = {
        let alice = Arc::clone(&alice);
        let bob_agent_id = bob.agent_id();
        let payload = first_payload.clone();
        tokio::spawn(async move {
            alice
                .send_direct_with_config(&bob_agent_id, payload, send_config())
                .await
        })
    };
    tokio::time::timeout(
        Duration::from_secs(1),
        both_ready.wait_replaced_short_circuit(),
    )
    .await
    .expect("queued Replaced must beat the simultaneously ready old ACK");
    let first_receipt = first_send
        .await
        .expect("first send task completes")
        .expect("both-ready reissue succeeds");
    assert_eq!(first_receipt.path, DmPath::RawQuicAcked);
    let first_received = tokio::time::timeout(Duration::from_secs(1), bob_rx.recv())
        .await
        .expect("bob receives both-ready payload")
        .expect("bob subscriber remains open");
    assert_eq!(first_received.payload, first_payload);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), bob_rx.recv())
            .await
            .is_err(),
        "same request id must dedupe the both-ready reissue"
    );

    // Lag branch: hold a successful result, advance the target generation,
    // then overflow the receiver with unrelated lifecycle events so the
    // target event itself is skipped. The lifecycle table must recover it.
    let lagged = Arc::new(RawQuicAckRaceTestHook::new());
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(Some(Arc::clone(&lagged)));
    let second_payload = b"lagged-replaced-old-generation-ack".to_vec();
    let second_send = {
        let alice = Arc::clone(&alice);
        let bob_agent_id = bob.agent_id();
        let payload = second_payload.clone();
        tokio::spawn(async move {
            alice
                .send_direct_with_config(&bob_agent_id, payload, send_config())
                .await
        })
    };
    tokio::time::timeout(
        Duration::from_secs(1),
        lagged.wait_first_attempt_result_ready(),
    )
    .await
    .expect("old-generation ACK result is ready before lifecycle flood");
    let previous = alice
        .direct_messaging()
        .current_generation(&bob.machine_id())
        .unwrap_or(0);
    alice
        .direct_messaging()
        .record_lifecycle_replaced(bob.machine_id(), previous.saturating_add(1));
    for marker in 0_u16..300 {
        let mut bytes = [0_u8; 32];
        bytes[..2].copy_from_slice(&marker.to_be_bytes());
        alice
            .direct_messaging()
            .record_lifecycle_replaced(x0x::identity::MachineId(bytes), u64::from(marker));
    }
    lagged.release_first_attempt_result();
    tokio::time::timeout(Duration::from_secs(1), lagged.wait_replaced_short_circuit())
        .await
        .expect("lag reconciliation must recover the skipped target generation");
    let second_receipt = second_send
        .await
        .expect("second send task completes")
        .expect("lag-reconciled reissue succeeds");
    assert_eq!(second_receipt.path, DmPath::RawQuicAcked);
    let second_received = tokio::time::timeout(Duration::from_secs(1), bob_rx.recv())
        .await
        .expect("bob receives lag-race payload")
        .expect("bob subscriber remains open");
    assert_eq!(second_received.payload, second_payload);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), bob_rx.recv())
            .await
            .is_err(),
        "same request id must dedupe the lag-reconciled reissue"
    );

    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(None);
    alice.shutdown().await;
    bob.shutdown().await;
}

/// `raw_quic_receive_ack_timeout` is the deadline for the complete logical
/// raw send, not one ant-quic ACK exchange. If the receiver admits the bytes
/// but the ACK result remains stuck, the sender returns a typed timeout once,
/// records no outbound LocalSend row, and does not re-admit the payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_ack_result_obeys_total_deadline_without_duplicate_admission() {
    let dir = TempDir::new().expect("tmpdir");
    let alice = Arc::new(build_history_agent(&dir, "deadline-alice").await);
    let bob = Arc::new(build_agent(&dir, "deadline-bob").await);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let alice_addr = normalize_loopback(
        alice_network
            .bound_addr()
            .await
            .expect("alice bound to loopback"),
    );
    let bob_addr = normalize_loopback(
        bob_network
            .bound_addr()
            .await
            .expect("bob bound to loopback"),
    );
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr))
        .await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr))
        .await;
    alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");

    let hook = Arc::new(RawQuicAckRaceTestHook::new());
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(Some(Arc::clone(&hook)));
    let mut bob_rx = bob.subscribe_direct();
    let payload = b"stalled-ack-result-total-deadline".to_vec();
    let budget = Duration::from_millis(300);
    let started = Instant::now();
    let error = alice
        .send_direct_with_config(
            &bob.agent_id(),
            payload.clone(),
            DmSendConfig {
                prefer_raw_quic_if_connected: true,
                raw_quic_receive_ack_timeout: Some(budget),
                stop_fallback_on_raw_error: true,
                max_retries: 0,
                ..DmSendConfig::default()
            },
        )
        .await
        .expect_err("held ACK result must hit the total raw deadline");
    let elapsed = started.elapsed();
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(None);

    assert!(
        matches!(
            error,
            x0x::dm::DmError::Timeout {
                retries: 0,
                elapsed: reported,
            } if reported == budget
        ),
        "deadline must surface as typed timeout: {error:?}"
    );
    assert!(
        elapsed >= budget && elapsed <= budget + Duration::from_millis(500),
        "logical raw send must finish by budget + scheduler epsilon: {elapsed:?}"
    );

    let received = tokio::time::timeout(Duration::from_secs(1), bob_rx.recv())
        .await
        .expect("bob admitted the payload before its ACK result was held")
        .expect("bob subscriber remains open");
    assert_eq!(received.payload, payload);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), bob_rx.recv())
            .await
            .is_err(),
        "deadline cancellation must not cause duplicate receiver admission"
    );

    let diagnostics = alice.direct_messaging().diagnostics_snapshot();
    assert_eq!(diagnostics.stats.outgoing_send_total, 1);
    assert_eq!(diagnostics.stats.outgoing_send_succeeded, 0);
    assert_eq!(diagnostics.stats.outgoing_send_failed, 1);
    let history_rows = alice
        .history()
        .expect("alice history enabled")
        .store()
        .query(&x0x::history::HistoryQuery {
            scope: Some(x0x::history::Scope::Dm(hex::encode(
                bob.agent_id().as_bytes(),
            ))),
            ..x0x::history::HistoryQuery::default()
        })
        .expect("query alice history");
    assert!(
        history_rows.is_empty(),
        "a timed-out raw send must not create a LocalSend history row: {history_rows:?}"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}

/// A half-dead connected generation can fail the first ACK exchange, repair,
/// and then wedge before the repaired transport write. The same raw deadline
/// must cancel that whole sequence; a repair must not start a fresh budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_dead_generation_repair_reissue_stays_inside_total_deadline() {
    let dir = TempDir::new().expect("tmpdir");
    let alice = Arc::new(build_history_agent(&dir, "half-dead-alice").await);
    let bob = Arc::new(build_agent(&dir, "half-dead-bob").await);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let alice_addr = normalize_loopback(
        alice_network
            .bound_addr()
            .await
            .expect("alice bound to loopback"),
    );
    let bob_addr = normalize_loopback(
        bob_network
            .bound_addr()
            .await
            .expect("bob bound to loopback"),
    );
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr))
        .await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr))
        .await;
    alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");

    let hook = Arc::new(RawQuicAckRaceTestHook::new_stalled_repair_retry());
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(Some(Arc::clone(&hook)));
    let mut bob_rx = bob.subscribe_direct();
    let payload = b"half-dead-generation-total-deadline".to_vec();
    let budget = Duration::from_secs(1);
    let started = Instant::now();
    let error = alice
        .send_direct_with_config(
            &bob.agent_id(),
            payload,
            DmSendConfig {
                prefer_raw_quic_if_connected: true,
                raw_quic_receive_ack_timeout: Some(budget),
                stop_fallback_on_raw_error: true,
                max_retries: 0,
                ..DmSendConfig::default()
            },
        )
        .await
        .expect_err("stalled repair reissue must hit the total raw deadline");
    let elapsed = started.elapsed();

    tokio::time::timeout(Duration::from_millis(100), hook.wait_repair_retry_started())
        .await
        .expect("the half-dead first generation must enter same-send repair");
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(None);

    assert!(
        matches!(
            error,
            x0x::dm::DmError::Timeout {
                retries: 0,
                elapsed: reported,
            } if reported == budget
        ),
        "repair deadline must surface as typed timeout: {error:?}"
    );
    assert!(
        elapsed >= budget && elapsed <= budget + Duration::from_millis(500),
        "repair and reissue must not receive fresh timeout budgets: {elapsed:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), bob_rx.recv())
            .await
            .is_err(),
        "stalled pre-write repair must not admit a receiver payload"
    );

    let diagnostics = alice.direct_messaging().diagnostics_snapshot();
    assert_eq!(diagnostics.stats.outgoing_send_total, 1);
    assert_eq!(diagnostics.stats.outgoing_send_succeeded, 0);
    assert_eq!(diagnostics.stats.outgoing_send_failed, 1);
    let history_rows = alice
        .history()
        .expect("alice history enabled")
        .store()
        .query(&x0x::history::HistoryQuery {
            scope: Some(x0x::history::Scope::Dm(hex::encode(
                bob.agent_id().as_bytes(),
            ))),
            ..x0x::history::HistoryQuery::default()
        })
        .expect("query alice history");
    assert!(
        history_rows.is_empty(),
        "a timed-out repair must not create a LocalSend history row: {history_rows:?}"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}

/// The daemon/default policy permits gossip fallback. Its raw ACK timeout is
/// nevertheless the total logical-send budget: a fast terminal raw failure
/// followed by a gossip attempt with no application ACK must return one typed
/// timeout, rather than starting a fresh gossip retry budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_fallback_policy_stays_inside_total_send_deadline() {
    let dir = TempDir::new().expect("tmpdir");
    let alice = Arc::new(build_history_agent(&dir, "fallback-alice").await);
    let bob = Arc::new(build_agent(&dir, "fallback-bob").await);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let alice_addr = normalize_loopback(
        alice_network
            .bound_addr()
            .await
            .expect("alice bound to loopback"),
    );
    let bob_addr = normalize_loopback(
        bob_network
            .bound_addr()
            .await
            .expect("bob bound to loopback"),
    );
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr))
        .await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr))
        .await;
    alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");

    // Advertise a structurally valid but deliberately unrelated KEM key for
    // Bob. The raw hook fails before transport I/O, then gossip publishes a
    // valid envelope that Bob cannot decrypt and therefore never ACKs.
    let unrelated_kem =
        x0x::groups::kem_envelope::AgentKemKeypair::generate().expect("generate unrelated KEM key");
    alice.insert_capability_for_testing(
        bob.agent_id(),
        bob.machine_id(),
        x0x::dm::DmCapabilities::v1_gossip_ready(unrelated_kem.public_bytes),
    );
    let hook = Arc::new(RawQuicAckRaceTestHook::new_forced_backpressure());
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(Some(Arc::clone(&hook)));
    let mut bob_rx = bob.subscribe_direct();
    let budget = Duration::from_millis(400);
    let started = Instant::now();
    let error = alice
        .send_direct_with_config(
            &bob.agent_id(),
            b"raw-then-stalled-gossip-total-deadline".to_vec(),
            DmSendConfig {
                prefer_raw_quic_if_connected: true,
                raw_quic_receive_ack_timeout: Some(budget),
                // Match the daemon/default policy: fallback remains enabled.
                stop_fallback_on_raw_error: false,
                ..DmSendConfig::default()
            },
        )
        .await
        .expect_err("stalled gossip fallback must share the total send deadline");
    let elapsed = started.elapsed();
    tokio::time::timeout(
        Duration::from_millis(100),
        hook.wait_first_attempt_started(),
    )
    .await
    .expect("preferred raw path must be attempted before gossip fallback");
    alice
        .direct_messaging()
        .set_raw_quic_ack_race_test_hook_for_testing(None);

    assert!(
        matches!(
            error,
            x0x::dm::DmError::Timeout {
                retries: 0,
                elapsed: reported,
            } if reported == budget
        ),
        "total fallback deadline must surface as typed timeout: {error:?}"
    );
    assert!(
        elapsed >= budget && elapsed <= budget + Duration::from_millis(500),
        "raw plus gossip fallback must finish by one budget + epsilon: {elapsed:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), bob_rx.recv())
            .await
            .is_err(),
        "forced pre-I/O raw failure and undecryptable gossip must not admit a DM"
    );

    let diagnostics = alice.direct_messaging().diagnostics_snapshot();
    assert_eq!(diagnostics.stats.outgoing_send_total, 1);
    assert_eq!(diagnostics.stats.outgoing_send_succeeded, 0);
    assert_eq!(diagnostics.stats.outgoing_send_failed, 1);
    let history_rows = alice
        .history()
        .expect("alice history enabled")
        .store()
        .query(&x0x::history::HistoryQuery {
            scope: Some(x0x::history::Scope::Dm(hex::encode(
                bob.agent_id().as_bytes(),
            ))),
            ..x0x::history::HistoryQuery::default()
        })
        .expect("query alice history");
    assert!(
        history_rows.is_empty(),
        "timed-out fallback must not create a LocalSend row: {history_rows:?}"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}

/// Regression for the second v0.37.0 two-Mac failure shape: presence and
/// identity discovery can be fresh while no transport connection currently
/// exists. A raw send must use the discovered addresses to establish that
/// connection instead of limiting repair to a bootstrap-cache lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn discovered_but_disconnected_peer_is_dialed_by_same_send() {
    let dir = TempDir::new().expect("tmpdir");
    let alice = Arc::new(build_agent(&dir, "discovery-alice").await);
    let bob = Arc::new(build_agent(&dir, "discovery-bob").await);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let alice_addr = normalize_loopback(
        alice_network
            .bound_addr()
            .await
            .expect("alice bound to loopback"),
    );
    let bob_addr = normalize_loopback(
        bob_network
            .bound_addr()
            .await
            .expect("bob bound to loopback"),
    );
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let discovered = |agent: &Agent, addr| x0x::DiscoveredAgent {
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
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    };
    alice
        .insert_discovered_agent_for_testing(discovered(&bob, bob_addr))
        .await;
    bob.insert_discovered_agent_for_testing(discovered(&alice, alice_addr))
        .await;

    assert!(
        !alice_network.is_connected(&bob_peer).await,
        "precondition: discovery is fresh but no direct transport exists"
    );

    let mut bob_rx = bob.subscribe_direct();
    let payload = b"same-request-connect-from-fresh-discovery".to_vec();
    let receipt = tokio::time::timeout(
        Duration::from_secs(8),
        alice.send_direct_with_config(
            &bob.agent_id(),
            payload.clone(),
            DmSendConfig {
                prefer_raw_quic_if_connected: true,
                raw_quic_receive_ack_timeout: Some(Duration::from_secs(1)),
                stop_fallback_on_raw_error: true,
                max_retries: 0,
                ..DmSendConfig::default()
            },
        ),
    )
    .await
    .expect("same logical send should dial from discovery inside eight seconds")
    .expect("discovery redial should make the raw send succeed");

    assert_eq!(receipt.path, DmPath::RawQuicAcked);
    assert!(
        alice_network.is_connected(&bob_peer).await,
        "send should establish the discovered peer connection"
    );
    let received = tokio::time::timeout(Duration::from_secs(2), bob_rx.recv())
        .await
        .expect("bob receives payload")
        .expect("bob subscriber remains open");
    assert_eq!(received.payload, payload);
    assert_eq!(received.sender, alice.agent_id());

    alice.shutdown().await;
    bob.shutdown().await;
}
