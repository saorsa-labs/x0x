//! #1419 real-ant-quic loopback receipt.
//!
//! The 31 Oct 20:20 GMT Engineer ruling asked for a loopback test on real
//! ant-quic that tries to reproduce the one-sided relay-supersede case
//! (ant-quic#332). The supersede decision itself lives inside ant-quic, so
//! this suite drives the closest x0x-visible analogue on a real loopback
//! QUIC link: one end disconnects while the other keeps its connection,
//! and both ends' `probe_peer` outcomes are recorded. Together with the
//! quiet-link probe it receipts, on real ant-quic:
//!
//! - a healthy quiet link answers the probe, so the both-directions-stale
//!   rule cannot false-degrade it;
//! - what a one-sided torn link's probe returns on each end, which is the
//!   evidence for whether x0x can see the fault without ant-quic#332.
//!
//! Uses `P2pEndpoint` + `P2pConfig` the same way
//! `tests/ant_quic_0272_surface.rs` does, so the localhost NAT/relay
//! plumbing matches ant-quic's own suites.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ant_quic::{NatConfig, P2pConfig, P2pEndpoint, PqcConfig};
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
        .mdns_enabled(false)
        .port_mapping_enabled(false)
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

/// A real quiet loopback link answers the probe. This is the quiet-peer
/// half of the #1419 both-directions-stale rule on real ant-quic: a
/// healthy idle link is never degraded by the probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quiet_healthy_loopback_link_answers_the_probe() {
    let receiver = make_endpoint(vec![]).await;
    let receiver_addr = normalize(receiver.local_addr().expect("receiver bound"));
    let receiver_id = receiver.peer_id();
    let _r_accept = spawn_accept_loop(Arc::clone(&receiver));

    let sender = make_endpoint(vec![]).await;
    let _s_accept = spawn_accept_loop(Arc::clone(&sender));

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("connect_addr");
    sleep(Duration::from_millis(150)).await;

    // No application data is exchanged: the link is quiet on both
    // directions, exactly the shape the both-directions-stale rule sees.
    let probe = timeout(
        Duration::from_secs(8),
        sender.probe_peer(&receiver_id, Duration::from_secs(3)),
    )
    .await
    .expect("probe bounded");
    let rtt = probe.expect("a healthy quiet loopback link answers the probe");
    assert!(
        rtt < Duration::from_secs(3),
        "RTT inside the bound: {rtt:?}"
    );
}

/// One end disconnects while the other keeps its connection: the
/// x0x-visible analogue of a one-sided winner move on real ant-quic. The
/// receipt records what each end's probe returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_sided_torn_loopback_link_probe_receipt() {
    let receiver = make_endpoint(vec![]).await;
    let receiver_addr = normalize(receiver.local_addr().expect("receiver bound"));
    let receiver_id = receiver.peer_id();
    let _r_accept = spawn_accept_loop(Arc::clone(&receiver));

    let sender = make_endpoint(vec![]).await;
    let sender_id = sender.peer_id();
    let _s_accept = spawn_accept_loop(Arc::clone(&sender));

    sender
        .connect_addr(receiver_addr)
        .await
        .expect("connect_addr");
    sleep(Duration::from_millis(150)).await;

    // The moved end tears its connection down; the other end keeps its
    // half. ant-quic owns the winner, so this is as close to a one-sided
    // supersede as x0x can drive on a real link.
    sender.disconnect(&receiver_id).await.expect("disconnect");

    let sender_probe = timeout(
        Duration::from_secs(8),
        sender.probe_peer(&receiver_id, Duration::from_secs(3)),
    )
    .await
    .expect("probe bounded");
    // The end that moved cannot probe its old peer: whatever the exact
    // class, it is not a success.
    assert!(
        sender_probe.is_err(),
        "the disconnected end's probe fails on real ant-quic: {sender_probe:?}"
    );

    // The end that still holds the connection probes across the torn
    // link. The recorded outcome is the receipt for whether x0x can see
    // the fault without ant-quic#332: a timeout or a closed connection
    // confirms it; a success means the probe cannot see it.
    let receiver_probe = timeout(
        Duration::from_secs(8),
        receiver.probe_peer(&sender_id, Duration::from_secs(3)),
    )
    .await
    .expect("probe bounded");
    match receiver_probe {
        Ok(rtt) => panic!(
            "receipt: the holding end's probe still succeeds on a torn real \
             link (rtt {rtt:?}); the both-stale probe cannot see this fault \
             without ant-quic#332"
        ),
        Err(error) => {
            // The receipt the PR body cites: the holding end sees an
            // error naming the link. A propagated close can also drop the
            // peer from the table, which is PeerNotFound.
            let names_link = matches!(
                error,
                ant_quic::EndpointError::ProbeTimeout
                    | ant_quic::EndpointError::ConnectionClosed { .. }
                    | ant_quic::EndpointError::PeerNotFound(_)
            );
            assert!(
                names_link,
                "receipt: unexpected probe error class on a torn real link: {error:?}"
            );
        }
    }
}
