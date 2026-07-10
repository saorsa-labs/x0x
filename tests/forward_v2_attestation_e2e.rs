//! End-to-end ForwardV2 attestation proof (#204 soak fix).
//!
//! Two in-process agents connect over loopback. Alice opens a ForwardV2
//! stream to Bob, signs a V2 header (carrying her public key), and sends it.
//! Bob reads the header and verifies the attestation — which SUCCEEDS
//! despite Bob's discovery cache having an EMPTY `agent_public_key` for Alice
//! (the presence-beacon case that blocked the soak). Bob sends "connected"
//! and data round-trips in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use x0x::forward::{ForwardV2Header, MAX_HEADER_V2_BYTES};
use x0x::network::NetworkConfig;
use x0x::streams::StreamProtocol;
use x0x::DiscoveredAgent;

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: Vec::new(),
        ..NetworkConfig::default()
    }
}

fn is_network_bind_permission_error(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    message.contains("Operation not permitted")
        && (message.contains("bind UDP socket")
            || message.contains("network initialization failed"))
}

async fn build_agent(dir: &TempDir, name: &str) -> Option<x0x::Agent> {
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
        Err(e) if is_network_bind_permission_error(&e) => None,
        Err(e) => panic!("agent build failed: {e}"),
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

fn beacon_discovered_agent(
    agent: &x0x::Agent,
    addr: std::net::SocketAddr,
    now_secs: u64,
) -> DiscoveredAgent {
    DiscoveredAgent {
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

async fn take_incoming(agent: &x0x::Agent, timeout: Duration) -> Option<x0x::streams::PeerStream> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, agent.next_incoming_stream()).await {
            Ok(Some(stream)) => return Some(stream),
            Ok(None) => return None,
            Err(_) => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback V2 attestation proof; binds UDP. Integration tier."]
async fn forward_v2_attestation_succeeds_on_loopback() {
    let dir = TempDir::new().unwrap();
    let Some(alice) = build_agent(&dir, "alice").await else {
        return;
    };
    let Some(bob) = build_agent(&dir, "bob").await else {
        return;
    };
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);

    alice.join_network().await.unwrap();
    bob.join_network().await.unwrap();
    let alice_network = alice.network().unwrap().clone();
    let bob_network = bob.network().unwrap().clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.unwrap());
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    alice_network.connect_addr(bob_addr).await.unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
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
        .insert_discovered_agent_for_testing(beacon_discovered_agent(&bob, bob_addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(beacon_discovered_agent(&alice, alice_addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;

    let alice_machine = alice.machine_id();
    let alice_id = alice.agent_id();
    let bob_agent_id = bob.agent_id();

    // Run opener (alice) and acceptor (bob) concurrently via join.
    let alice_ref = Arc::clone(&alice);
    let bob_ref = Arc::clone(&bob);

    let _ = tokio::join!(
        // ── Alice: open V2 stream, sign+send header, read response, ping/pong ──
        async {
            let mut stream = alice_ref
                .open_peer_stream(&bob_agent_id, StreamProtocol::ForwardV2)
                .await
                .unwrap();

            let mut header = ForwardV2Header::new(
                "127.0.0.1".to_string(),
                18080,
                alice_ref.agent_id(),
                alice_ref
                    .identity()
                    .agent_keypair()
                    .public_key()
                    .as_bytes()
                    .to_vec(),
                stream.peer(),
            );
            header.sign(alice_ref.identity().agent_keypair()).unwrap();

            let frame = header.encode();
            stream.send_mut().write_all(&frame).await.unwrap();

            let mut resp = [0u8; 1];
            stream.recv_mut().read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x01], "bob accepted");

            stream.send_mut().write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            stream.recv_mut().read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
        },
        // ── Bob: accept stream, read+verify header, send connected, echo ──
        async {
            let mut bob_stream = take_incoming(&bob_ref, Duration::from_secs(15))
                .await
                .unwrap();
            assert_eq!(bob_stream.protocol(), StreamProtocol::ForwardV2);
            assert_eq!(bob_stream.peer(), alice_machine);

            let mut len_buf = [0u8; 4];
            bob_stream
                .recv_mut()
                .read_exact(&mut len_buf)
                .await
                .unwrap();
            let len = u32::from_be_bytes(len_buf);
            assert!(len <= MAX_HEADER_V2_BYTES);
            let mut body = vec![0u8; len as usize];
            bob_stream.recv_mut().read_exact(&mut body).await.unwrap();
            let header: ForwardV2Header = bincode::deserialize(&body).unwrap();

            // ── KEY ASSERTION: attestation verifies despite empty cached pubkey ──
            header
                .verify_attestation(&header.opener_agent_public_key)
                .unwrap();
            assert_eq!(header.opener_agent_id, alice_id);

            bob_stream.send_mut().write_all(&[0x01]).await.unwrap();
            let mut ping = [0u8; 4];
            bob_stream.recv_mut().read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            bob_stream.send_mut().write_all(b"pong").await.unwrap();
        }
    );
}
