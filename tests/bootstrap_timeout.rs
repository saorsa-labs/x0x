#![allow(clippy::expect_used)]

//! Bootstrap dial timeout — issue #123 / WS1.2.
//!
//! Proves `BootstrapConnector::connect_with_retry` bounds each dial with
//! `dial_timeout` and advances through the capped backoff/retry loop instead
//! of stalling on a black-holed address.
//!
//! The blackhole is a UDP socket bound on loopback: it absorbs the QUIC
//! Initial packets the dial sends (so the kernel never returns ICMP
//! port-unreachable) but never produces a QUIC handshake response, so the
//! underlying `connect_addr` hangs until our timeout cuts it. Without the
//! timeout wrapper added in #123, this test would hang for QUIC's far longer
//! internal PTO and blow the wall-clock bound below.

use std::net::UdpSocket;
use std::time::{Duration, Instant};
use x0x::bootstrap::{BootstrapConfig, BootstrapConnector};
use x0x::network::{NetworkConfig, NetworkNode};

#[tokio::test]
async fn bootstrap_dial_timeout_is_bounded_and_advances() {
    // Loopback blackhole: a socket that swallows QUIC Initials but never
    // answers the handshake.
    let blackhole = UdpSocket::bind("127.0.0.1:0").expect("bind blackhole socket");
    let addr = blackhole.local_addr().expect("read blackhole local addr");

    let network = NetworkNode::new(NetworkConfig::default(), None, None)
        .await
        .expect("create network node");

    // Short dial timeout + a few retries with tiny backoff so the whole loop
    // completes well under the bound even though each dial would otherwise hang.
    let config = BootstrapConfig {
        max_retries: 3,
        backoff_multiplier: 1.0,
        initial_backoff: Duration::from_millis(5),
        max_backoff: Duration::from_millis(5),
        dial_timeout: Duration::from_millis(150),
    };

    let start = Instant::now();
    let result = BootstrapConnector::with_config(config)
        .connect_with_retry(&network, addr)
        .await;
    let elapsed = start.elapsed();

    // A black-holed dial must fail, never succeed.
    assert!(result.is_err(), "black-holed bootstrap dial must fail");

    // 3 attempts × 150 ms timeout + tiny backoff must stay well under this
    // bound. If the per-attempt timeout wrapper were absent, a single hung
    // attempt would stall the loop for QUIC's internal PTO (seconds) and this
    // bound would be blown — which is exactly the regression #123 prevents.
    assert!(
        elapsed < Duration::from_secs(3),
        "bootstrap retry loop took {elapsed:?}; the dial timeout did not bound the attempts"
    );
}
