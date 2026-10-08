//! Real-socket regressions. Run only inside the approved loopback sandbox.

#![cfg(test)]

use super::{serve_with_options, DaemonConfig, ServeOptions};
use std::net::{TcpListener, UdpSocket};
use std::time::Duration;

async fn concurrent_shutdown_and_relaunch(peered: bool) {
    let root = tempfile::tempdir().expect("isolated daemon directories");
    let plane = format!("x0x.test.shutdown.{}", std::process::id());
    let configs: Vec<DaemonConfig> = (0..3)
        .map(|index| {
            serde_json::from_value(serde_json::json!({
                "bind_address": "127.0.0.1:0",
                "api_address": "127.0.0.1:0",
                "data_dir": root.path().join(format!("daemon-{index}")),
                "identity_dir": root.path().join(format!("identity-{index}")),
                "bootstrap_peers": [],
                "mdns_enabled": false,
                "port_mapping_enabled": false,
                "network_id": plane
            }))
            .expect("loopback-only daemon configuration")
        })
        .collect();

    // The second cycle uses the SAME directories and identities. The old
    // handles must have released their instance locks as well as sockets.
    for cycle in 0..2 {
        let starts = configs.iter().cloned().map(|config| async move {
            serve_with_options(
                config,
                ServeOptions {
                    skip_update_check: true,
                    cli_no_port_mapping: true,
                    cli_disable_peer_cache: true,
                    self_update_enabled: false,
                    ..ServeOptions::default()
                },
            )
            .await
            .expect("serve on fresh or released directories")
        });
        let handles = futures::future::join_all(starts).await;
        let mut addresses = Vec::new();
        let mut networks = Vec::new();
        for handle in &handles {
            let state = handle.test_state.upgrade().expect("live daemon state");
            let network = state.agent.network().expect("real QUIC network").clone();
            let udp = network.bound_addr().await.expect("bound UDP address");
            assert!(udp.ip().is_loopback());
            assert_ne!(udp.port(), 0);
            addresses.push((udp, handle.local_addr()));
            networks.push(network);
        }
        if peered {
            for index in 0..networks.len() {
                networks[index]
                    .connect_addr(addresses[(index + 1) % networks.len()].0)
                    .await
                    .expect("connect loopback daemons");
            }
        }
        // Keep NetworkNode handles alive deliberately: typed shutdown must
        // release the bound socket even when an embedder retains a handle.
        let results = tokio::time::timeout(
            Duration::from_secs(30),
            futures::future::join_all(handles.into_iter().map(|h| h.shutdown_and_wait())),
        )
        .await
        .expect("all concurrent shutdowns complete within 30 seconds");
        for (index, result) in results.into_iter().enumerate() {
            assert!(result.is_ok(), "cycle {cycle}, daemon {index}: {result:?}");
        }
        // Keep all rebound sockets open together: every original address
        // must be free, not merely a single reused ephemeral port.
        let probes: Vec<_> = addresses
            .iter()
            .map(|(udp, tcp)| {
                (
                    UdpSocket::bind(udp).expect("original UDP socket released"),
                    TcpListener::bind(tcp).expect("original API listener released"),
                )
            })
            .collect();
        drop(probes);
        drop(networks);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real sockets: requires the approved loopback-only sandbox"]
async fn issue1262_concurrent_embedded_shutdown_idle() {
    concurrent_shutdown_and_relaunch(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real sockets: requires the approved loopback-only sandbox"]
async fn issue1262_concurrent_embedded_shutdown_peered() {
    concurrent_shutdown_and_relaunch(true).await;
}
