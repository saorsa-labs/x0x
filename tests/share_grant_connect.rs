//! ADR-0074 §5 / #1390: `Connect { ports }` admits one listener through a
//! forward and through SOCKS, denies the other listener listed on the same
//! `principal = "grant"` entry, and after `revoke_share_grant` tears both
//! live tunnels down. The peer gate is `authorize_attested_opener`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

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
use x0x::connect::{ConnectAcl, ConnectDiagnostics, ConnectOwnerEntry, ConnectPolicy, OwnerTarget};
use x0x::forward::ForwardService;
use x0x::identity::UserKeypair;
use x0x::network::NetworkConfig;
use x0x::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
use x0x::socks::{handle_tcp_client, ForwardSocksConnector};
use x0x::DiscoveredAgent;

const TOKEN: &str = "share-grant-connect-token";

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        port_mapping_enabled: false,
        ..NetworkConfig::default()
    }
}

async fn build_agent(dir: &TempDir, name: &str, user: Option<UserKeypair>) -> Option<x0x::Agent> {
    network_gate::init_stream_tracing();
    let mut builder = x0x::Agent::builder()
        .with_machine_key(dir.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.path().join(format!("{name}-agent.key")))
        .with_contact_store_path(dir.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.path().join(format!("{name}-peer-cache")))
        .with_network_config(loopback_network_config());
    if let Some(user) = user {
        builder = builder.with_user_key(user);
    }
    match builder.build().await {
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

fn beacon(agent: &x0x::Agent, addr: SocketAddr, now_secs: u64) -> DiscoveredAgent {
    DiscoveredAgent {
        self_name: None,
        cert_digest: None,
        agent_id: agent.agent_id(),
        machine_id: agent.machine_id(),
        user_id: agent.user_id(),
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

async fn link_pair(alice: &x0x::Agent, bob: &x0x::Agent) {
    alice.join_network().await.unwrap();
    bob.join_network().await.unwrap();
    let alice_network = alice.network().unwrap().clone();
    let bob_network = bob.network().unwrap().clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.unwrap());
    alice_network.connect_addr(bob_addr).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);
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
    assert!(alice_network.is_connected(&bob_peer).await, "alice->bob");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let alice_addr = normalize_loopback(alice_network.bound_addr().await.unwrap());
    alice
        .insert_discovered_agent_for_testing(beacon(bob, bob_addr, now))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(beacon(alice, alice_addr, now))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;
    bob.record_authenticated_machine_binding_for_testing(alice.agent_id(), alice.machine_id())
        .await;
}

fn grant_policy(allowed: SocketAddr, denied: SocketAddr) -> Arc<ConnectPolicy> {
    Arc::new(ConnectPolicy::Enabled(ConnectAcl {
        loaded_from: "test".into(),
        loaded_at_unix_ms: 0,
        allow: Vec::new(),
        owner_allow: Vec::new(),
        grant_allow: vec![ConnectOwnerEntry {
            description: None,
            targets: vec![OwnerTarget::Exact(allowed), OwnerTarget::Exact(denied)],
        }],
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

struct Probe {
    port: u16,
    accepts: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    cancel: CancellationToken,
}

async fn spawn_probe() -> Probe {
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
            let Ok((mut sock, _)) = accepted else { break };
            accepts_task.fetch_add(1, Ordering::SeqCst);
            let bytes_task = Arc::clone(&bytes_task);
            tokio::spawn(async move {
                let mut buf = [0u8; 1];
                if sock.read_exact(&mut buf).await.is_ok() {
                    bytes_task.fetch_add(1, Ordering::SeqCst);
                    let _ = sock.write_all(&buf).await;
                }
                // Hold the socket so a live forward stays open until revoke.
                let mut sink = [0u8; 8];
                let _ = sock.read(&mut sink).await;
            });
        }
    });
    Probe {
        port,
        accepts,
        bytes,
        cancel,
    }
}

async fn forward_exchange(local: SocketAddr) -> Result<u8, String> {
    let mut client = TcpStream::connect(local)
        .await
        .map_err(|e| format!("connect {local}: {e}"))?;
    client
        .write_all(&[0x42])
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut got = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(15), client.read_exact(&mut got)).await {
        Ok(Ok(_)) => Ok(got[0]),
        Ok(Err(e)) => Err(format!("read: {e}")),
        Err(_) => Err("forward exchange timed out".into()),
    }
}

async fn socks_reply(
    connector: &dyn x0x::socks::SocksConnector,
    host: &str,
    port: u16,
    exchange: bool,
) -> u8 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client_res, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let mut client = client_res.unwrap();
    let (server, _) = accepted.unwrap();
    let cancel = CancellationToken::new();
    let denied = AtomicU64::new(0);
    let host = host.to_string();
    // Drop the client before the handler future ends. `bridge` returns only
    // on client EOF, so joining while `client` is still held deadlocks.
    let (handler, rep) = tokio::join!(
        handle_tcp_client(server, TOKEN, connector, &denied, None, &cancel),
        async move {
            let rep = socks_roundtrip(&mut client, &host, port, exchange).await;
            drop(client);
            rep
        },
    );
    handler.expect("socks session");
    rep
}

async fn socks_roundtrip(client: &mut TcpStream, host: &str, port: u16, exchange: bool) -> u8 {
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
    if exchange && resp[1] == 0x00 {
        client.write_all(&[0x42]).await.unwrap();
        let mut got = [0u8; 1];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got[0], 0x42, "SOCKS tunnel must echo the granted port");
    }
    resp[1]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn share_grant_connect_reaches_forward_and_socks() {
    let dir = TempDir::new().unwrap();
    let Some(alice) = build_agent(&dir, "alice", None).await else {
        return;
    };
    let Some(bob) = build_agent(&dir, "bob", Some(UserKeypair::generate().unwrap())).await else {
        alice.shutdown().await;
        return;
    };
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);
    link_pair(&alice, &bob).await;

    let allowed = spawn_probe().await;
    let denied = spawn_probe().await;
    assert_ne!(allowed.port, denied.port);
    // The grant lists only the allowed listener. Both ports are on the
    // grant ACL entry, so the other port is refused by the grant. These
    // ports stand in for :22 and :80; the test cannot bind privileged ports.
    let allowed_addr: SocketAddr = format!("127.0.0.1:{}", allowed.port).parse().unwrap();
    let denied_addr: SocketAddr = format!("127.0.0.1:{}", denied.port).parse().unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let owner = bob.identity().user_keypair().expect("bob owner key");
    let grant = ShareGrant::sign(
        owner,
        [0x52; 32],
        Grantee::Agent(alice.agent_id()),
        vec![bob.agent_id()],
        vec![ShareCap::Connect {
            ports: vec![allowed.port],
        }],
        now.saturating_sub(60),
        now + 3_600,
    )
    .expect("sign grant");
    let store = Arc::new(ShareGrantStore::in_memory(bob.agent_id(), bob.user_id()));
    store.accept(grant.clone(), now).await.expect("store grant");
    bob.install_share_grant_store(store);
    let access = bob
        .share_grant_access(&alice.agent_id(), &alice.machine_id())
        .await;
    assert!(
        access.allows_connect_port(allowed.port),
        "issued grant must cover the allowed port: {access:?}"
    );
    assert!(
        !access.allows_connect_port(denied.port),
        "issued grant must not cover the other port: {access:?}"
    );

    let bob_fwd = forwarder(&bob, grant_policy(allowed_addr, denied_addr));
    let alice_fwd = forwarder(
        &alice,
        Arc::new(ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: "test".into(),
            loaded_at_unix_ms: 0,
            allow: Vec::new(),
            owner_allow: Vec::new(),
            grant_allow: Vec::new(),
        })),
    );
    let local_ok = alice_fwd
        .add_forward(x0x::forward::ForwardSpec {
            local_addr: "127.0.0.1:0".parse().unwrap(),
            peer_agent: bob.agent_id(),
            target_host: "127.0.0.1".into(),
            target_port: allowed.port,
        })
        .await
        .expect("forward to granted port");
    let echoed = forward_exchange(local_ok).await;
    let local_no = alice_fwd
        .add_forward(x0x::forward::ForwardSpec {
            local_addr: "127.0.0.1:0".parse().unwrap(),
            peer_agent: bob.agent_id(),
            target_host: "127.0.0.1".into(),
            target_port: denied.port,
        })
        .await
        .expect("forward to unganted port");
    let denied_forward = forward_exchange(local_no).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let connector = Arc::new(ForwardSocksConnector::new(Arc::clone(&alice_fwd)));
    let host = format!("{}.x0x", hex::encode(bob.agent_id().as_bytes()));
    let socks_no = tokio::time::timeout(
        Duration::from_secs(15),
        socks_reply(connector.as_ref(), &host, denied.port, false),
    )
    .await;
    let socks_ok = tokio::time::timeout(
        Duration::from_secs(15),
        socks_reply(connector.as_ref(), &host, allowed.port, true),
    )
    .await;

    // Live forward + SOCKS, then revoke. Slice 3 tears the open streams down.
    let mut held_forward = TcpStream::connect(local_ok).await.unwrap();
    held_forward.write_all(&[0x11]).await.unwrap();
    let mut fwd_ack = [0u8; 1];
    tokio::time::timeout(
        Duration::from_secs(15),
        held_forward.read_exact(&mut fwd_ack),
    )
    .await
    .expect("held forward echo")
    .unwrap();
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let (socks_client_res, socks_accepted) =
        tokio::join!(TcpStream::connect(socks_addr), socks_listener.accept());
    let mut held_socks = socks_client_res.unwrap();
    let (socks_server, _) = socks_accepted.unwrap();
    let socks_cancel = CancellationToken::new();
    let socks_denied = AtomicU64::new(0);
    let socks_handler = tokio::spawn({
        let connector = Arc::clone(&connector);
        async move {
            handle_tcp_client(
                socks_server,
                TOKEN,
                connector.as_ref(),
                &socks_denied,
                None,
                &socks_cancel,
            )
            .await
        }
    });
    let held_rep = socks_roundtrip(&mut held_socks, &host, allowed.port, true).await;
    bob.revoke_share_grant(grant.grant_id, None)
        .await
        .expect("revoke grant");
    let teardown = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 1];
        let _ = held_forward.read(&mut buf).await;
        let _ = held_socks.read(&mut buf).await;
    })
    .await;
    let after_forward = forward_exchange(local_ok).await;
    let after_socks = tokio::time::timeout(
        Duration::from_secs(15),
        socks_reply(connector.as_ref(), &host, allowed.port, false),
    )
    .await;
    drop(held_forward);
    drop(held_socks);
    let _ = socks_handler.await;

    let sink_accepts = denied.accepts.load(Ordering::SeqCst);
    let sink_bytes = denied.bytes.load(Ordering::SeqCst);
    let echo_bytes = allowed.bytes.load(Ordering::SeqCst);

    allowed.cancel.cancel();
    denied.cancel.cancel();
    bob_fwd.shutdown();
    alice_fwd.shutdown();
    alice.shutdown().await;
    bob.shutdown().await;

    assert_eq!(
        echoed.expect("granted forward must echo"),
        0x42,
        "forward to the granted port must carry a byte"
    );
    assert!(
        denied_forward.is_err(),
        "forward to the unganted port must not echo: {denied_forward:?}"
    );
    assert_eq!(
        socks_no.expect("socks deny finished"),
        0x02,
        "SOCKS to the unganted port must be REP_NOT_ALLOWED"
    );
    assert_eq!(
        socks_ok.expect("socks allow finished"),
        0x00,
        "SOCKS to the granted port must succeed"
    );
    assert_eq!(sink_accepts, 0, "unganted target accepted a connection");
    assert_eq!(sink_bytes, 0, "unganted target received bytes");
    assert!(
        echo_bytes >= 2,
        "forward and SOCKS must both have delivered a byte, got {echo_bytes}"
    );
    assert_eq!(held_rep, 0x00, "held SOCKS tunnel must be up before revoke");
    assert!(
        teardown.is_ok(),
        "open forward and SOCKS must unblock within 5s of revoke"
    );
    assert!(
        after_forward.is_err(),
        "forward after revoke must be denied: {after_forward:?}"
    );
    // Revoke empties `connect_ports`, so the stream gate drops the grantee
    // before the forwarder can write a connect-denied byte. SOCKS maps that
    // failed open to `0x04`. A forwarder denial while the grant is live is
    // `0x02`. Either reply is a denial; success is not.
    let after_rep = after_socks.expect("socks after revoke finished");
    assert!(
        after_rep == 0x02 || after_rep == 0x04,
        "SOCKS after revoke must be denied, got {after_rep:#x}"
    );
}
