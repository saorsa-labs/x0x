//! X0X-0066 — request-hedging wiring acceptance.
//!
//! ## What this test proves
//!
//! 1. `Agent::hedge_rtt_tracker()` is a real accessor wired into the
//!    Agent — not a free-floating module.
//! 2. A normal ACKed raw-QUIC send on loopback **does not** trigger
//!    the hedge (loopback completes in ~ms, well under the 250 ms
//!    `HEDGE_MIN_TRIGGER` floor — so on healthy intra-host paths the
//!    duplicate-send overhead is zero).
//! 3. After the send completes, the hedge tracker has recorded an
//!    observed RTT sample for the destination peer — so the EWMA
//!    will adapt to the path the first time hedge-eligible RTTs are
//!    observed.
//! 4. `/diagnostics/dm` (via `direct_messaging().diagnostics_snapshot()`)
//!    surfaces `hedge_fired_total` / `hedge_won_total` /
//!    `hedge_lost_total` counters — proving the wire-up to the
//!    diagnostics API is in place.
//!
//! ## What this test does NOT prove (deliberate)
//!
//! Loopback cannot reproduce cross-region tail latency. To force the
//! hedge to actually fire and win on a real network, the SOAK on the
//! 6-node VPS bootstrap mesh (helsinki ↔ singapore/sydney path family)
//! is the authoritative evidence — see X0X-0066 acceptance criteria.
//! The hedge selection logic itself is covered by 9 unit tests in
//! `src/hedge.rs::tests`. The select! loop is exercised end-to-end by
//! `tests/x0x_0041_synthetic_kill_restart.rs` (still passes after the
//! hedge branch was added).

use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::time::Instant;

use x0x::dm::{DmPath, DmSendConfig};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_send_does_not_fire_hedge_and_records_rtt_sample() {
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

    let returned_peer = alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");
    assert_eq!(returned_peer.0, bob.machine_id().0);

    let connected_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < connected_deadline {
        if alice_network.is_connected(&bob_peer).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        alice_network.is_connected(&bob_peer).await,
        "alice must be connected to bob before the test send"
    );

    // Wait for the lifecycle watcher to record bob's first generation
    // so the X0X-0053 path is fully wired.
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

    // Seed alice's discovery cache + DM registry so send_direct can
    // resolve bob without an announcement round-trip. Mirrors the
    // X0X-0053 synthetic test (tests/x0x_0041_synthetic_kill_restart.rs).
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
    };
    bob.insert_discovered_agent_for_testing(alice_card).await;

    let pre = alice.direct_messaging().diagnostics_snapshot();
    assert_eq!(pre.stats.hedge_fired_total, 0);
    assert_eq!(pre.stats.hedge_won_total, 0);
    assert_eq!(pre.stats.hedge_lost_total, 0);
    assert_eq!(
        alice.hedge_rtt_tracker().samples(&bob_peer),
        0,
        "no observed samples before the first send"
    );

    let cfg = DmSendConfig {
        prefer_raw_quic_if_connected: true,
        raw_quic_receive_ack_timeout: Some(Duration::from_secs(6)),
        ..DmSendConfig::default()
    };
    let receipt = alice
        .send_direct_with_config(&bob.agent_id(), b"hedge-wiring-test".to_vec(), cfg)
        .await
        .expect("send_direct_with_config returns Ok on loopback");
    assert_eq!(
        receipt.path,
        DmPath::RawQuicAcked,
        "loopback send should take the ACKed raw-QUIC path"
    );

    let post = alice.direct_messaging().diagnostics_snapshot();
    assert_eq!(
        post.stats.hedge_fired_total, 0,
        "loopback completes well under the 250 ms hedge floor; hedge must not fire"
    );
    assert_eq!(
        post.stats.hedge_won_total, 0,
        "no hedge fired ⇒ no hedge won"
    );
    assert_eq!(
        post.stats.hedge_lost_total, 0,
        "no hedge fired ⇒ no hedge lost"
    );
    assert_eq!(
        alice.hedge_rtt_tracker().samples(&bob_peer),
        1,
        "the successful send must register one observed RTT sample"
    );
    let ewma = alice
        .hedge_rtt_tracker()
        .ewma_ms(&bob_peer)
        .expect("ewma populated after first sample");
    assert!(
        (0.0..5_000.0).contains(&ewma),
        "observed loopback RTT should be a small positive ms value, got {ewma}"
    );
}
