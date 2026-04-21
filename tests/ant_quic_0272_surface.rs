//! Consumer-side smoke test for the ant-quic 0.27.1/0.27.2 surface that x0x
//! depends on. Proves that x0x links against and can drive:
//!
//! - `P2pEndpoint::probe_peer` (0.27.2 #173) — active liveness + RTT
//! - `P2pEndpoint::connection_health` (0.27.1 #170) — per-peer health
//! - `P2pEndpoint::send_with_receive_ack` (0.27.1 #172) — delivery-confirmed
//! - `P2pEndpoint::subscribe_all_peer_events` (0.27.1 #171) — lifecycle bus
//!
//! Uses `P2pEndpoint` + `P2pConfig` so the localhost NAT/relay plumbing is
//! configured identically to ant-quic's own `b_probe_peer.rs` /
//! `b_health_snapshot.rs` / `b_send_with_receive_ack.rs` suites. If upstream
//! ever changes the semantics of any of these primitives the x0x release
//! must not ship.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PeerLifecycleEvent, PqcConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

fn normalize(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

fn localhost_config(known_peers: Vec<SocketAddr>) -> P2pConfig {
    P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .known_peers(known_peers)
        .nat(NatConfig {
            enable_relay_fallback: false,
            ..Default::default()
        })
        .pqc(PqcConfig::default())
        .build()
        .expect("P2pConfig::build")
}

async fn make_endpoint(known_peers: Vec<SocketAddr>) -> Arc<P2pEndpoint> {
    Arc::new(
        P2pEndpoint::new(localhost_config(known_peers))
            .await
            .expect("P2pEndpoint::new"),
    )
}

fn spawn_accept_loop(ep: Arc<P2pEndpoint>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { while ep.accept().await.is_some() {} })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_peer_returns_finite_rtt_on_localhost_connection() {
    let receiver = make_endpoint(vec![]).await;
    let receiver_addr = normalize(receiver.local_addr().expect("receiver bound"));
    let receiver_id = receiver.peer_id();
    let r_accept = spawn_accept_loop(Arc::clone(&receiver));

    let sender = make_endpoint(vec![receiver_addr]).await;
    let s_accept = spawn_accept_loop(Arc::clone(&sender));

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("connect_addr");
    sleep(Duration::from_millis(150)).await;

    let rtt = sender
        .probe_peer(&receiver_id, Duration::from_secs(10))
        .await
        .expect("probe_peer on live connection");

    // Generous bound so nextest parallel-load scheduling jitter doesn't
    // flake the test — the point is to prove probe_peer returns a finite
    // RTT, not to measure raw localhost latency.
    assert!(
        rtt < Duration::from_secs(5),
        "probe RTT on localhost {rtt:?} should be well under 5s even under load"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    r_accept.abort();
    s_accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_health_after_connect_is_observable() {
    let receiver = make_endpoint(vec![]).await;
    let receiver_addr = normalize(receiver.local_addr().expect("receiver bound"));
    let receiver_id = receiver.peer_id();
    let r_accept = spawn_accept_loop(Arc::clone(&receiver));

    let sender = make_endpoint(vec![receiver_addr]).await;
    let s_accept = spawn_accept_loop(Arc::clone(&sender));

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("connect_addr");
    sleep(Duration::from_millis(200)).await;

    // `ConnectionHealth` is opaque but `Debug` renders the lifecycle state +
    // timestamps. A probe after inspecting health proves the call doesn't
    // invalidate the connection.
    let health = sender.connection_health(&receiver_id).await;
    let _ = format!("{health:?}");
    sender
        .probe_peer(&receiver_id, Duration::from_secs(10))
        .await
        .expect("probe after health-check");

    sender.shutdown().await;
    receiver.shutdown().await;
    r_accept.abort();
    s_accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_with_receive_ack_round_trips_on_localhost() {
    let receiver = make_endpoint(vec![]).await;
    let receiver_addr = normalize(receiver.local_addr().expect("receiver bound"));
    let receiver_id = receiver.peer_id();
    let r_accept = spawn_accept_loop(Arc::clone(&receiver));

    let sender = make_endpoint(vec![receiver_addr]).await;
    let s_accept = spawn_accept_loop(Arc::clone(&sender));

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("connect_addr");
    sleep(Duration::from_millis(150)).await;

    // Drain receiver recv() so the ACK isn't starved.
    let recv_task = {
        let r = Arc::clone(&receiver);
        tokio::spawn(async move { while r.recv().await.is_ok() {} })
    };

    sender
        .send_with_receive_ack(&receiver_id, b"x0x-ack-roundtrip", Duration::from_secs(10))
        .await
        .expect("send_with_receive_ack on healthy link");

    recv_task.abort();
    sender.shutdown().await;
    receiver.shutdown().await;
    r_accept.abort();
    s_accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribe_all_peer_events_fires_established_on_connect() {
    let receiver = make_endpoint(vec![]).await;
    let receiver_addr = normalize(receiver.local_addr().expect("receiver bound"));
    let r_accept = spawn_accept_loop(Arc::clone(&receiver));

    let sender = make_endpoint(vec![receiver_addr]).await;
    let s_accept = spawn_accept_loop(Arc::clone(&sender));

    let mut events = sender.subscribe_all_peer_events();

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("connect_addr");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_established = false;
    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(250), events.recv()).await {
            Ok(Ok((_peer, ev))) => {
                if matches!(ev, PeerLifecycleEvent::Established { .. }) {
                    saw_established = true;
                    break;
                }
            }
            _ => continue,
        }
    }
    assert!(
        saw_established,
        "subscribe_all_peer_events should deliver an Established transition within 2s"
    );

    sender.shutdown().await;
    receiver.shutdown().await;
    r_accept.abort();
    s_accept.abort();
}
