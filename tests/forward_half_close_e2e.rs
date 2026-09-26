//! Forwarder FIN propagation + clean denial replies (#961).
//!
//! Two in-process agents connect over loopback, each running a real
//! `ForwardService`. These tests go through `bridge()` / the denial path in
//! `src/forward.rs`, not a hand-rolled stream, so they observe what the
//! forwarder actually puts on the wire.
//!
//! - `half_close_propagates_and_response_tail_arrives`: the common
//!   request/response pattern (client writes, `shutdown(Write)`, reads to
//!   EOF). Without FIN propagation the server never sees EOF and the client
//!   hangs; without a clean finish the response tail is lost to a reset.
//! - `denied_forward_reply_is_frame_then_eof`: a refused forward must deliver
//!   exactly the denial frame followed by a clean EOF — not a reset, and never
//!   any byte from (or connection to) the refused loopback target.
//!
//! Both are `#[ignore]`: they bind UDP and wait on convergence (integration
//! tier, `--run-ignored ignored-only`). The CI `tailnet` job runs them with
//! `X0X_REQUIRE_NETWORK_TESTS=1`, where a refused bind fails instead of
//! skipping.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x0x::connect::{ConnectAcl, ConnectAllowEntry, ConnectDiagnostics, ConnectPolicy};
use x0x::forward::{ForwardService, ForwardSpec, ForwardV2Header};
use x0x::network::NetworkConfig;
use x0x::streams::StreamProtocol;
use x0x::DiscoveredAgent;

#[path = "common/network_gate.rs"]
mod network_gate;

const RESPONSE_LEN: usize = 1024 * 1024;

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        ..NetworkConfig::default()
    }
}

/// Skips on a refused UDP bind, but FAILS when `X0X_REQUIRE_NETWORK_TESTS=1`
/// (the CI tailnet job), so a sandboxed run can never report a silent pass.
async fn build_agent(dir: &TempDir, name: &str) -> Option<Arc<x0x::Agent>> {
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
        Ok(agent) => Some(Arc::new(agent)),
        Err(e) if network_gate::skip_on_refused_network(&e) => None,
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

/// Join both agents, connect them over loopback and fixture both directions
/// of the identity gate (discovery-cache binding + `Trusted` contact).
async fn link_pair(a: &Arc<x0x::Agent>, b: &Arc<x0x::Agent>) {
    a.join_network().await.expect("a joins");
    b.join_network().await.expect("b joins");
    let a_network = a.network().expect("a network").clone();
    let b_network = b.network().expect("b network").clone();
    let b_addr = normalize_loopback(b_network.bound_addr().await.expect("b bound"));
    a_network
        .connect_addr(b_addr)
        .await
        .expect("a connects to b");

    let a_peer = ant_quic::PeerId(a.machine_id().0);
    let b_peer = ant_quic::PeerId(b.machine_id().0);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if a_network.is_connected(&b_peer).await && b_network.is_connected(&a_peer).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(a_network.is_connected(&b_peer).await, "a→b connected");
    assert!(b_network.is_connected(&a_peer).await, "b→a connected");

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let a_addr = normalize_loopback(a_network.bound_addr().await.expect("a bound"));
    a.insert_discovered_agent_for_testing(discovered_agent(b, b_addr, now_secs))
        .await;
    a.set_contact_trusted_for_testing(b.agent_id()).await;
    b.insert_discovered_agent_for_testing(discovered_agent(a, a_addr, now_secs))
        .await;
    b.set_contact_trusted_for_testing(a.agent_id()).await;
}

/// Connect policy on `acceptor` allowing exactly `opener` → `target`.
fn allow_only(opener: &x0x::Agent, target: std::net::SocketAddr) -> Arc<ConnectPolicy> {
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
    }))
}

/// Start `acceptor`'s inbound forwarder under `policy`.
fn start_inbound_forwarder(
    acceptor: &Arc<x0x::Agent>,
    policy: Arc<ConnectPolicy>,
) -> Arc<ForwardService> {
    acceptor.set_connect_policy(Arc::clone(&policy));
    let diag = Arc::new(ConnectDiagnostics::new(policy.summary()));
    let service = Arc::new(
        ForwardService::new(Arc::clone(acceptor), policy, diag, true)
            .expect("register forward acceptors"),
    );
    service.spawn_inbound();
    service
}

/// Deterministic position-dependent pattern (xorshift64): any dropped,
/// duplicated or reordered byte breaks equality.
fn xorshift_pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// #961 (a): TCP half-close must become a QUIC FIN, and the peer's response
/// tail must arrive intact after it finishes.
///
/// Why it matters: request/response clients (HTTP/1.0, `nc -N`, RPC over
/// stdin) signal "request done" with `shutdown(Write)` and then read to EOF.
/// Pre-fix, `bridge()` used bare `tokio::io::copy`, which never shuts the
/// destination down, so the server below never saw EOF, never replied, and
/// the client's `read_to_end` timed out (the `expect("…within timeout")`
/// fails). Even when data does flow, dropping the unfinished send stream
/// resets it (ant-quic 0xA17C0244) and discards the unread tail — the
/// byte-for-byte equality catches that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback forward; binds UDP + TCP. Integration tier."]
async fn half_close_propagates_and_response_tail_arrives() {
    let dir = TempDir::new().unwrap();
    let Some(alice) = build_agent(&dir, "alice").await else {
        return;
    };
    let Some(bob) = build_agent(&dir, "bob").await else {
        return;
    };
    link_pair(&alice, &bob).await;

    // Bob's loopback service: read the request to EOF, then reply 1 MiB and
    // close. It can only reply once the client's half-close reaches it.
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let response = xorshift_pattern(RESPONSE_LEN, 0x961);
    let server_response = response.clone();
    let server_task = tokio::spawn(async move {
        let (mut sock, _) = server.accept().await.unwrap();
        let mut request = Vec::new();
        sock.read_to_end(&mut request).await.unwrap();
        sock.write_all(&server_response).await.unwrap();
        sock.shutdown().await.unwrap();
        request
    });

    let _bob_fwd = start_inbound_forwarder(&bob, allow_only(&alice, server_addr));
    let alice_diag = Arc::new(ConnectDiagnostics::new(ConnectPolicy::default().summary()));
    let alice_fwd = ForwardService::new(
        Arc::clone(&alice),
        Arc::new(ConnectPolicy::default()),
        alice_diag,
        true,
    )
    .expect("alice forwarder");
    let local = alice_fwd
        .add_forward(ForwardSpec {
            local_addr: "127.0.0.1:0".parse().unwrap(),
            peer_agent: bob.agent_id(),
            target_host: "127.0.0.1".to_string(),
            target_port: server_addr.port(),
        })
        .await
        .expect("add forward");

    let mut client = TcpStream::connect(local).await.unwrap();
    client.write_all(b"request-961").await.unwrap();
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), client.read_to_end(&mut got))
        .await
        .expect("client half-close must propagate and the response complete within timeout")
        .expect("response must end in a clean EOF, not a reset");

    assert_eq!(got.len(), RESPONSE_LEN, "exactly 1 MiB must arrive");
    assert!(got == response, "response must be byte-identical");
    let request = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server finished")
        .expect("server task");
    assert_eq!(
        request, b"request-961",
        "server saw the full request then EOF"
    );
}

/// #961 (b): a denied forward must reply with exactly the denial frame and
/// then a clean EOF — and the refused target must never be touched.
///
/// Why it matters: the opener's only diagnostic for a refusal is that frame.
/// Pre-fix, the acceptor returned right after `write_all`, dropping the
/// unfinished send stream, so ant-quic reset it; no FIN is ever sent, so
/// `read_to_end` below returns `Err(Reset)` and the `expect("…clean EOF…")`
/// fails. Security half: `finish()` must not open a path to the target, so the
/// test also asserts the listener at the refused target is never connected
/// and the reply carries zero application bytes beyond the frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback forward; binds UDP + TCP. Integration tier."]
async fn denied_forward_reply_is_frame_then_eof() {
    let dir = TempDir::new().unwrap();
    let Some(alice) = build_agent(&dir, "alice").await else {
        return;
    };
    let Some(bob) = build_agent(&dir, "bob").await else {
        return;
    };
    link_pair(&alice, &bob).await;

    // A live loopback service that alice is NOT allowed to reach: the ACL
    // lists a different port. If the forwarder ever connected, the accept
    // below would fire and any bytes would show up in the reply.
    let refused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let refused_addr = refused.local_addr().unwrap();
    let allowed_other: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let _bob_fwd = start_inbound_forwarder(&bob, allow_only(&alice, allowed_other));

    let mut stream = alice
        .open_peer_stream(&bob.agent_id(), StreamProtocol::ForwardV2)
        .await
        .expect("open forward v2 stream");
    let mut header = ForwardV2Header::new(
        "127.0.0.1".to_string(),
        refused_addr.port(),
        alice.agent_id(),
        alice
            .identity()
            .agent_keypair()
            .public_key()
            .as_bytes()
            .to_vec(),
        stream.peer(),
    );
    header.sign(alice.identity().agent_keypair()).unwrap();
    stream.send_mut().write_all(&header.encode()).await.unwrap();

    let reply = tokio::time::timeout(Duration::from_secs(15), stream.recv_mut().read_to_end(4096))
        .await
        .expect("denial reply within timeout")
        .expect("denial must end in a clean EOF, not a reset");

    // Frame: 0x00 || u32 BE len || JSON reason — and nothing after it.
    assert!(reply.len() >= 5, "denial frame header present: {reply:?}");
    assert_eq!(reply[0], 0x00, "first byte is RESP_DENIED");
    let len = u32::from_be_bytes([reply[1], reply[2], reply[3], reply[4]]) as usize;
    assert_eq!(
        reply.len(),
        5 + len,
        "exactly the denial frame, then EOF — zero application bytes"
    );
    let reason: serde_json::Value = serde_json::from_slice(&reply[5..]).expect("reason JSON");
    assert!(!reason.is_null(), "denial carries a reason");

    assert!(
        tokio::time::timeout(Duration::from_millis(500), refused.accept())
            .await
            .is_err(),
        "a denied forward must never connect to the refused target"
    );
}
