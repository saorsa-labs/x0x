//! Tailnet Phase 1 byte-stream integration proof (#132 T1).
//!
//! Two in-process agents connect over loopback, clear the identity gate
//! (verified discovery-cache binding + `Trusted` contact), and exchange a
//! 1 MiB payload in both directions over a [`x0x::streams::StreamProtocol`]
//! stream. Proves the end-to-end wiring — `Agent::open_peer_stream` →
//! ant-quic `open_bi` → protocol prefix → inbound accept loop → identity
//! gate → `Agent::next_incoming_stream` — that the deterministic unit tests
//! in `src/streams.rs` (gate matrix + protocol framing) cannot reach.
//!
//! All tests here are `#[ignore]`: they bind real UDP sockets and wait on
//! loopback connection convergence, so they run in the integration tier
//! (`--run-ignored ignored-only`) rather than the always-on Test Suite.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use x0x::network::NetworkConfig;
use x0x::streams::StreamProtocol;
use x0x::DiscoveredAgent;

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
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

fn discovered_agent(
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
    }
}

/// Wait for the agent's accept loop to surface a stream, bounded by `timeout`.
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
#[ignore = "two-agent loopback byte-stream proof; binds UDP + waits on convergence. Integration tier."]
async fn peer_stream_echoes_1mib_both_directions() {
    let dir = TempDir::new().expect("tmpdir");
    let Some(alice) = build_agent(&dir, "alice").await else {
        return;
    };
    let Some(bob) = build_agent(&dir, "bob").await else {
        return;
    };
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.expect("bob bound"));
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    let connected = alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");
    assert_eq!(connected.0, bob.machine_id().0);

    // Wait until ant-quic reports the connection established on both sides.
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
        "alice→bob connected"
    );
    assert!(
        bob_network
            .is_connected(&ant_quic::PeerId(alice.machine_id().0))
            .await,
        "bob→alice connected"
    );

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let alice_addr = normalize_loopback(alice_network.bound_addr().await.expect("alice bound"));

    // Outbound gate (alice): verified binding + Trusted contact for bob.
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    // Inbound gate (bob): verified binding + Trusted contact for alice, so the
    // accept loop resolves alice's agent and the trust check returns Accept.
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;

    // Open + accept concurrently: open_peer_stream writes the prefix and the
    // stream halves; bob's accept loop reads the prefix after the gate.
    let bob_agent_id = bob.agent_id();
    let alice_for_open = Arc::clone(&alice);
    let open_task = tokio::spawn(async move {
        alice_for_open
            .open_peer_stream(&bob_agent_id, StreamProtocol::ForwardV1)
            .await
            .expect("open stream")
    });
    let mut bob_stream = take_incoming(&bob, Duration::from_secs(15))
        .await
        .expect("bob accepted the inbound stream");
    let mut alice_stream = open_task.await.expect("open task");

    assert_eq!(alice_stream.peer(), bob.machine_id());
    assert_eq!(alice_stream.protocol(), StreamProtocol::ForwardV1);
    assert_eq!(bob_stream.peer(), alice.machine_id());
    assert_eq!(bob_stream.protocol(), StreamProtocol::ForwardV1);

    // 1 MiB each direction. QUIC flow control means the writer blocks until the
    // reader drains, so each direction is a concurrent (write || read) pair.
    let payload_a = vec![0xA5u8; 1024 * 1024];
    let payload_b = vec![0x3Cu8; 1024 * 1024];
    let mut buf_a = vec![0u8; payload_a.len()];
    let mut buf_b = vec![0u8; payload_b.len()];

    let payload_a_ref = &payload_a;
    let buf_a_ref = &mut buf_a;
    let (_, r_a) = tokio::join!(
        async { alice_stream.send_mut().write_all(payload_a_ref).await },
        async { bob_stream.recv_mut().read_exact(buf_a_ref).await },
    );
    r_a.expect("bob read 1MiB from alice");
    assert_eq!(buf_a, payload_a, "alice→bob integrity");

    let payload_b_ref = &payload_b;
    let buf_b_ref = &mut buf_b;
    let (_, r_b) = tokio::join!(
        async { bob_stream.send_mut().write_all(payload_b_ref).await },
        async { alice_stream.recv_mut().read_exact(buf_b_ref).await },
    );
    r_b.expect("alice read 1MiB from bob");
    assert_eq!(buf_b, payload_b, "bob→alice integrity");
}

/// FIX 1 regression (#132): a peer that opens a QUIC stream and never sends
/// the protocol-prefix byte must NOT stall the accept loop — another stream
/// (with its prefix) is still accepted. Before FIX 1 the prefix read was
/// awaited inline in the loop, so the silent stream blocked every other
/// peer's inbound service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback; binds UDP. Integration tier. Proves FIX 1 (accept-loop no-stall)."]
async fn accept_loop_not_stalled_by_missing_prefix() {
    let dir = TempDir::new().expect("tmpdir");
    let Some(alice) = build_agent(&dir, "alice").await else {
        return;
    };
    let Some(bob) = build_agent(&dir, "bob").await else {
        return;
    };
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.expect("bob bound"));
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);

    let connected = alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");
    assert_eq!(connected.0, bob.machine_id().0);

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
        bob_network
            .is_connected(&ant_quic::PeerId(alice.machine_id().0))
            .await
    );

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let alice_addr = normalize_loopback(alice_network.bound_addr().await.expect("alice bound"));
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;

    // (1) alice opens a RAW stream and NEVER sends the prefix — the stall
    //     vector. The halves are deliberately held (not dropped) so the
    //     stream stays open and silent.
    let _silent = alice_network
        .open_bi_raw_for_testing(&bob_peer)
        .await
        .expect("open raw stream");

    // (2) alice then opens a normal ForwardV1 stream (writes its prefix).
    let bob_agent_id = bob.agent_id();
    let alice_for_open = Arc::clone(&alice);
    let normal = tokio::spawn(async move {
        alice_for_open
            .open_peer_stream(&bob_agent_id, StreamProtocol::ForwardV1)
            .await
            .expect("open normal stream")
    });

    // (3) bob must surface the NORMAL stream promptly despite the silent one.
    //     Before FIX 1 the accept loop would be blocked on the silent prefix
    //     read and this would time out.
    let surfaced = take_incoming(&bob, Duration::from_secs(8))
        .await
        .expect("accept loop was stalled by the missing-prefix stream");
    let _ = normal.await;
    assert_eq!(surfaced.protocol(), StreamProtocol::ForwardV1);
}
