//! Real ForwardV2 peer-gate denial in front of SOCKS.
//!
//! Bob allows Alice only `127.0.0.1:1`. A SOCKS CONNECT to Bob at a different
//! loopback port must answer SOCKS `0x02` and must not accept or read on that
//! target. The path is `handle_tcp_client` → `ForwardSocksConnector` →
//! `ForwardService::prepare_socks_tunnel`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/network_gate.rs"]
mod network_gate;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use x0x::connect::{ConnectAcl, ConnectAllowEntry, ConnectDiagnostics, ConnectPolicy};
use x0x::forward::ForwardService;
use x0x::network::NetworkConfig;
use x0x::socks::{handle_tcp_client, ForwardSocksConnector, SocksConnectError, SocksConnector};
use x0x::DiscoveredAgent;

const TOKEN: &str = "socks-peer-gate-token";

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        // Loopback only: no UPnP IGD discovery on the runner's LAN.
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
}

async fn build_agent(dir: &TempDir, name: &str) -> Option<x0x::Agent> {
    network_gate::init_stream_tracing();
    match x0x::Agent::builder()
        .with_machine_key(dir.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.path().join(format!("{name}-agent.key")))
        .with_contact_store_path(dir.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.path().join(format!("{name}-peer-cache")))
        .with_network_config(loopback_network_config())
        .build()
        .await
    {
        Ok(agent) => Some(agent),
        Err(e) if network_gate::skip_on_refused_network(&e) => None,
        Err(e) => panic!("agent build failed: {e}"),
    }
}

fn normalize_loopback(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
        )
    } else {
        addr
    }
}

fn beacon_discovered_agent(agent: &x0x::Agent, addr: SocketAddr, now_secs: u64) -> DiscoveredAgent {
    DiscoveredAgent {
        self_name: None,
        cert_digest: None,
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: None,
        addresses: vec![addr],
        announced_at: now_secs,
        last_seen: now_secs,
        machine_public_key: Vec::new(),
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

/// Join both agents, connect them over loopback, and fixture both directions
/// of the identity gate (discovery-cache binding + `Trusted` contact).
async fn link_pair(alice: &x0x::Agent, bob: &x0x::Agent) {
    alice.join_network().await.unwrap();
    bob.join_network().await.unwrap();
    let alice_network = alice.network().unwrap().clone();
    let bob_network = bob.network().unwrap().clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.unwrap());
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    alice_network.connect_addr(bob_addr).await.unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if alice_network.is_connected(&bob_peer).await
            && bob_network
                .is_connected(&ant_quic::PeerId(alice.machine_id().0))
                .await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        alice_network.is_connected(&bob_peer).await,
        "alice->bob connected"
    );

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let alice_addr = normalize_loopback(alice_network.bound_addr().await.unwrap());

    alice
        .insert_discovered_agent_for_testing(beacon_discovered_agent(bob, bob_addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(beacon_discovered_agent(alice, alice_addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;
}

/// Exact pair entry. Pair `targets` are `Vec<SocketAddr>`, not owner ranges.
fn allow_exact(opener: &x0x::Agent, target: SocketAddr) -> Arc<ConnectPolicy> {
    Arc::new(ConnectPolicy::Enabled(ConnectAcl {
        loaded_from: "test".into(),
        loaded_at_unix_ms: 0,
        allow: vec![ConnectAllowEntry {
            description: None,
            agent_id: opener.agent_id(),
            machine_id: opener.machine_id(),
            targets: vec![target],
        }],
        owner_allow: Vec::new(),
        grant_allow: Vec::new(),
    }))
}

fn forwarder(agent: &Arc<x0x::Agent>, policy: Arc<ConnectPolicy>) -> Arc<ForwardService> {
    let diag = Arc::new(ConnectDiagnostics::new(policy.summary()));
    let service = Arc::new(
        ForwardService::new(Arc::clone(agent), policy, diag, true).expect("ForwardService::new"),
    );
    service.spawn_inbound();
    service
}

struct TargetProbe {
    accepts: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    port: u16,
    cancel: CancellationToken,
}

async fn spawn_target() -> TargetProbe {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let accepts_task = Arc::clone(&accepts);
    let bytes_task = Arc::clone(&bytes);
    let cancel_task = cancel.clone();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = cancel_task.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((mut sock, _)) = accepted else {
                break;
            };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let bytes_task = Arc::clone(&bytes_task);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            bytes_task.fetch_add(n as u64, Ordering::SeqCst);
                        }
                    }
                }
            });
        }
    });
    TargetProbe {
        accepts,
        bytes,
        port,
        cancel,
    }
}

async fn client_roundtrip(client: &mut TcpStream, host: &str, port: u16) -> u8 {
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02]);

    let user = b"x0x";
    let pass = TOKEN.as_bytes();
    let mut auth = vec![0x01, user.len() as u8];
    auth.extend_from_slice(user);
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass);
    client.write_all(&auth).await.unwrap();
    let mut status = [0u8; 2];
    client.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [0x01, 0x00]);

    let host_b = host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_b.len() as u8];
    req.extend_from_slice(host_b);
    req.extend_from_slice(&port.to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05);
    resp[1]
}

async fn socks_session(connector: &ForwardSocksConnector, host: &str, port: u16) -> u8 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client_res, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let mut client = client_res.unwrap();
    let (server, _) = accepted.unwrap();
    let cancel = CancellationToken::new();
    let denied = AtomicU64::new(0);
    let (handler, rep) = tokio::join!(
        handle_tcp_client(server, TOKEN, connector, &denied, None, &cancel),
        client_roundtrip(&mut client, host, port),
    );
    handler.expect("socks session");
    assert_eq!(denied.load(Ordering::SeqCst), 1);
    rep
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_forward_v2_peer_gate_denial_sends_zero_target_bytes() {
    let dir = TempDir::new().unwrap();
    let Some(alice) = build_agent(&dir, "alice").await else {
        return;
    };
    let Some(bob) = build_agent(&dir, "bob").await else {
        alice.shutdown().await;
        return;
    };
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);
    link_pair(&alice, &bob).await;

    let target = spawn_target().await;
    let allowed_other: SocketAddr = "127.0.0.1:1".parse().unwrap();
    assert_ne!(target.port, allowed_other.port());

    let bob_fwd = forwarder(&bob, allow_exact(&alice, allowed_other));
    let alice_fwd = forwarder(&alice, allow_exact(&bob, "127.0.0.1:9".parse().unwrap()));
    let connector = ForwardSocksConnector::new(Arc::clone(&alice_fwd));
    let host = format!("{}.x0x", hex::encode(bob.agent_id().as_bytes()));

    let prep = tokio::time::timeout(
        Duration::from_secs(15),
        SocksConnector::prepare(&connector, bob.agent_id(), target.port),
    )
    .await;
    let rep = tokio::time::timeout(
        Duration::from_secs(15),
        socks_session(&connector, &host, target.port),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let accepts = target.accepts.load(Ordering::SeqCst);
    let nbytes = target.bytes.load(Ordering::SeqCst);
    target.cancel.cancel();
    bob_fwd.shutdown();
    alice_fwd.shutdown();
    alice.shutdown().await;
    bob.shutdown().await;

    let prep = prep.expect("ForwardSocksConnector::prepare finished");
    assert!(
        matches!(prep, Err(SocksConnectError::NotAllowed)),
        "peer gate denial must be NotAllowed"
    );
    assert_eq!(
        rep.expect("socks session finished"),
        0x02,
        "SOCKS reply must be REP_NOT_ALLOWED"
    );
    assert_eq!(accepts, 0, "denied target accepted a connection");
    assert_eq!(nbytes, 0, "denied target received bytes");
}
