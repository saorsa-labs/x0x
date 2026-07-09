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
