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
        agent_public_key: Vec::new(),
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
    //     Paced behind the raw open: ant-quic's connection driver can
    //     permanently strand the first frames of burst-opened streams on an
    //     otherwise-idle connection (see `acceptor_channel_is_bounded`), and
    //     the normal stream carries no post-prefix bytes here that would
    //     re-trigger the driver — an unpaced open can strand its prefix frame
    //     and wedge this proof. A timed-out open is therefore replaced by a
    //     fresh one (the connection stays healthy for new streams), exactly
    //     as in the boundedness test.
    tokio::time::sleep(Duration::from_millis(250)).await;
    let bob_agent_id = bob.agent_id();
    let mut surfaced = None;
    for _attempt in 0..4 {
        let alice_for_open = Arc::clone(&alice);
        let normal = tokio::spawn(async move {
            alice_for_open
                .open_peer_stream(&bob_agent_id, StreamProtocol::ForwardV1)
                .await
                .expect("open normal stream")
        });
        // (3) bob must surface the NORMAL stream promptly despite the silent
        //     one. Before FIX 1 the accept loop would be blocked on the
        //     silent prefix read and no attempt would ever surface.
        match take_incoming(&bob, Duration::from_secs(5)).await {
            Some(stream) => {
                surfaced = Some(stream);
                break;
            }
            None => normal.abort(), // stranded open; replace it
        }
    }
    let surfaced = surfaced.expect("accept loop was stalled by the missing-prefix stream");
    assert_eq!(surfaced.protocol(), StreamProtocol::ForwardV1);
}

// ---------------------------------------------------------------------------
// Shared harness for the deliverable-1 tests below (acceptor routing, ACL
// gate, backpressure, large-transfer integrity).
// ---------------------------------------------------------------------------

/// Connect two joined agents over loopback and fixture both directions of the
/// identity gate (discovery-cache binding + `Trusted` contact). Returns once
/// ant-quic reports the connection established on BOTH sides.
async fn link_pair(a: &Arc<x0x::Agent>, b: &Arc<x0x::Agent>) {
    let a_network = a.network().expect("a network").clone();
    let b_network = b.network().expect("b network").clone();
    let b_addr = normalize_loopback(b_network.bound_addr().await.expect("b bound"));

    let connected = a_network
        .connect_addr(b_addr)
        .await
        .expect("a connects to b");
    assert_eq!(connected.0, b.machine_id().0);

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if a_network
            .is_connected(&ant_quic::PeerId(b.machine_id().0))
            .await
            && b_network
                .is_connected(&ant_quic::PeerId(a.machine_id().0))
                .await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        a_network
            .is_connected(&ant_quic::PeerId(b.machine_id().0))
            .await,
        "a→b connected"
    );
    assert!(
        b_network
            .is_connected(&ant_quic::PeerId(a.machine_id().0))
            .await,
        "b→a connected"
    );

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

/// Deterministic position-dependent pattern (xorshift64) — any dropped,
/// duplicated, reordered, or cross-contaminated byte breaks the checksum.
fn xorshift_pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1; // xorshift degenerates at 0
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

/// Two protocol ids multiplexed over ONE connection must not interleave:
/// each registered acceptor surfaces exactly its own protocol's stream, the
/// default sink stays empty, and per-stream byte streams arrive intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback; binds UDP. Integration tier. Proves per-protocol acceptor demux."]
async fn multiplexed_protocols_do_not_interleave() {
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
    link_pair(&alice, &bob).await;

    // bob owns both protocols via registered acceptors.
    let mut socks_acceptor = bob
        .register_stream_acceptor(StreamProtocol::SocksV1)
        .expect("register socks");
    let mut fwd_acceptor = bob
        .register_stream_acceptor(StreamProtocol::ForwardV2)
        .expect("register fwd");
    // Single-owner invariant: a duplicate registration is a typed conflict.
    assert!(matches!(
        bob.register_stream_acceptor(StreamProtocol::SocksV1),
        Err(x0x::error::NetworkError::StreamAcceptorConflict {
            protocol_byte: 0x02
        })
    ));

    // alice opens one stream of each protocol over the same connection.
    // Serially, confirming each surfacing before the next open: burst-opened
    // streams can strand in ant-quic's connection driver under load (see
    // `acceptor_channel_is_bounded`), while single opens on a calm connection
    // deliver reliably. The PROOF — concurrent 1 MiB transfers over the two
    // protocols — is unaffected by how the streams were opened.
    let bob_agent = bob.agent_id();
    let mut s_socks = alice
        .open_peer_stream(&bob_agent, StreamProtocol::SocksV1)
        .await
        .expect("open socks stream");
    let mut b_socks = tokio::time::timeout(Duration::from_secs(30), socks_acceptor.next())
        .await
        .expect("socks acceptor timed out")
        .expect("socks stream");
    let mut s_fwd = alice
        .open_peer_stream(&bob_agent, StreamProtocol::ForwardV2)
        .await
        .expect("open fwd stream");
    let mut b_fwd = tokio::time::timeout(Duration::from_secs(30), fwd_acceptor.next())
        .await
        .expect("fwd acceptor timed out")
        .expect("fwd stream");
    assert_eq!(b_socks.protocol(), StreamProtocol::SocksV1);
    assert_eq!(b_fwd.protocol(), StreamProtocol::ForwardV2);

    // The default sink sees nothing: both protocols have registered owners.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), bob.next_incoming_stream())
            .await
            .is_err(),
        "registered protocols must not leak into the default sink"
    );

    // 1 MiB of distinct position-dependent patterns per stream, written
    // concurrently over the shared connection. Any cross-talk between the two
    // streams corrupts a pattern and fails the equality check.
    let p_socks = xorshift_pattern(1024 * 1024, 0x50C5);
    let p_fwd = xorshift_pattern(1024 * 1024, 0xF02D);
    assert_ne!(p_socks, p_fwd, "patterns must be distinct");

    let (w_socks, w_fwd, r_socks, r_fwd) = tokio::join!(
        async { s_socks.send_mut().write_all(&p_socks).await },
        async { s_fwd.send_mut().write_all(&p_fwd).await },
        async {
            let mut buf = vec![0u8; p_socks.len()];
            b_socks.recv_mut().read_exact(&mut buf).await.map(|_| buf)
        },
        async {
            let mut buf = vec![0u8; p_fwd.len()];
            b_fwd.recv_mut().read_exact(&mut buf).await.map(|_| buf)
        },
    );
    w_socks.expect("socks write");
    w_fwd.expect("fwd write");
    assert_eq!(
        r_socks.expect("socks read"),
        p_socks,
        "socks stream integrity"
    );
    assert_eq!(r_fwd.expect("fwd read"), p_fwd, "fwd stream integrity");
}

/// ACL-refused peer cannot open: with an `Enabled` connect ACL that lists
/// only alice, carol (verified + trusted but unlisted) gets her stream reset
/// by bob's accept loop — never surfaced, writes fail, reads hit EOF — while
/// the listed alice still streams fine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "three-agent loopback; binds UDP. Integration tier. Proves the #131 stream ACL gate."]
async fn connect_acl_refuses_unlisted_peer_stream() {
    let dir = TempDir::new().expect("tmpdir");
    let Some(alice) = build_agent(&dir, "alice").await else {
        return;
    };
    let Some(bob) = build_agent(&dir, "bob").await else {
        return;
    };
    let Some(carol) = build_agent(&dir, "carol").await else {
        return;
    };
    let alice = Arc::new(alice);
    let bob = Arc::new(bob);
    let carol = Arc::new(carol);

    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");
    carol.join_network().await.expect("carol joins");

    // Carol clears bob's identity gate (verified + trusted) — the ACL must be
    // the layer that refuses her, not trust.
    link_pair(&alice, &bob).await;
    link_pair(&carol, &bob).await;

    // bob: Enabled connect ACL listing ONLY (alice.agent, alice.machine).
    let policy = x0x::connect::ConnectPolicy::Enabled(x0x::connect::ConnectAcl {
        loaded_from: "test".into(),
        loaded_at_unix_ms: 0,
        allow: vec![x0x::connect::ConnectAllowEntry {
            description: None,
            agent_id: alice.agent_id(),
            machine_id: alice.machine_id(),
            targets: vec!["127.0.0.1:22".parse().expect("loopback literal")],
        }],
    });
    bob.set_connect_policy(Arc::new(policy));
    let mut acceptor = bob
        .register_stream_acceptor(StreamProtocol::SocksV1)
        .expect("register socks");

    // ── Unlisted carol: open is refused ──────────────────────────────────
    // The QUIC-level open succeeds; bob's accept loop clears her through the
    // identity gate and then resets the stream at the ACL gate.
    let mut carol_stream = carol
        .open_peer_stream(&bob.agent_id(), StreamProtocol::SocksV1)
        .await
        .expect("carol QUIC-level open");

    // bob must never surface her stream.
    assert!(
        tokio::time::timeout(Duration::from_secs(3), acceptor.next())
            .await
            .is_err(),
        "unlisted peer's stream must not be surfaced"
    );

    // Carol observes the refusal: bob dropped the stream halves, so her read
    // hits EOF (FIN from the dropped send half)…
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(
        Duration::from_secs(10),
        carol_stream.recv_mut().read(&mut buf),
    )
    .await
    .expect("refused stream read must settle")
    .expect("refused stream read must not error (FIN, not reset)");
    assert!(read.is_none(), "refused stream reads EOF, got {read:?}");

    // …and her writes fail (STOP_SENDING from the dropped recv half). Retry
    // a few times: the STOP_SENDING frame may lag the FIN by a packet.
    let mut write_error = None;
    for _ in 0..50 {
        match carol_stream
            .send_mut()
            .write_all(&[0xABu8; 64 * 1024])
            .await
        {
            Ok(()) => tokio::time::sleep(Duration::from_millis(20)).await,
            Err(e) => {
                write_error = Some(e);
                break;
            }
        }
    }
    assert!(
        write_error.is_some(),
        "refused stream writes must fail (STOP_SENDING)"
    );

    // ── Listed alice: still opens and echoes ─────────────────────────────
    let mut alice_stream = alice
        .open_peer_stream(&bob.agent_id(), StreamProtocol::SocksV1)
        .await
        .expect("alice open");
    let mut b_stream = tokio::time::timeout(Duration::from_secs(15), acceptor.next())
        .await
        .expect("listed peer must be surfaced")
        .expect("alice stream");
    assert_eq!(b_stream.protocol(), StreamProtocol::SocksV1);

    let payload = xorshift_pattern(64 * 1024, 0xA11CE);
    let (w, r) = tokio::join!(
        async { alice_stream.send_mut().write_all(&payload).await },
        async {
            let mut buf = vec![0u8; payload.len()];
            b_stream.recv_mut().read_exact(&mut buf).await.map(|_| buf)
        },
    );
    w.expect("alice write");
    assert_eq!(r.expect("bob read"), payload, "listed peer integrity");
}

/// The acceptor channel is provably bounded: its depth never exceeds
/// `STREAM_ACCEPTOR_CAPACITY`, and while it is pinned full every surplus
/// stream is dropped (reset) at `try_send` — never buffered.
///
/// Opens are PACED (~100 ms apart): ant-quic's connection driver can strand
/// the first frames of burst-opened streams for tens of seconds on an
/// otherwise-idle connection (a wake landing mid-cycle is lost once the
/// driver slot is empty; isolated in a two-`NetworkNode` repro where 8
/// back-to-back `open_bi` calls deliver only ~3-7 streams within 45 s, while
/// 100 ms-paced opens all deliver within microseconds). Pacing is a
/// test-harness technique so the boundedness assertions exercise delivery,
/// not the upstream driver race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback; binds UDP. Integration tier. Proves bounded acceptor depth."]
async fn acceptor_channel_is_bounded() {
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
    link_pair(&alice, &bob).await;

    let mut acceptor = bob
        .register_stream_acceptor(StreamProtocol::SocksV1)
        .expect("register socks");

    const CAP: usize = x0x::streams::STREAM_ACCEPTOR_CAPACITY;
    const SURPLUS: usize = 8;
    /// Per-open landing deadline. Serial opens on a calm connection land in
    /// milliseconds; the deadline only fires for streams stranded by the
    /// ant-quic burst-open frame-stranding race (isolated in a two-
    /// `NetworkNode` repro: a burst of 8 `open_bi` calls permanently strands
    /// ~1-5 streams' first frames on an idle connection, while fresh streams
    /// opened afterwards deliver normally — so a timed-out open is simply
    /// replaced by another open below).
    const LAND_DEADLINE: Duration = Duration::from_secs(10);

    let bob_agent = bob.agent_id();
    let mut held: Vec<x0x::streams::PeerStream> = Vec::new();

    // Serial fill to exactly capacity: open one, wait for it to land, repeat.
    // A stranded open (rare) is replaced by a fresh one — the connection
    // stays healthy for new streams even when an earlier burst frames never
    // transmit.
    while acceptor.queued() < CAP {
        let before = acceptor.queued();
        held.push(
            alice
                .open_peer_stream(&bob_agent, StreamProtocol::SocksV1)
                .await
                .expect("open stream"),
        );
        let deadline = Instant::now() + LAND_DEADLINE;
        while acceptor.queued() == before && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    assert_eq!(acceptor.queued(), CAP, "channel filled to exactly capacity");

    // Surplus: 8 more streams. While the channel stays pinned full, every
    // surplus dispatch hits `try_send` on a full channel and is dropped.
    // The observation window asserts the invariant continuously: depth NEVER
    // exceeds CAP.
    for _ in 0..SURPLUS {
        held.push(
            alice
                .open_peer_stream(&bob_agent, StreamProtocol::SocksV1)
                .await
                .expect("open surplus stream"),
        );
        // Give each surplus stream time to deliver + dispatch before the next.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            acceptor.queued(),
            CAP,
            "boundedness violated mid-surplus: depth exceeded capacity"
        );
    }
    let window = Instant::now() + Duration::from_secs(10);
    while Instant::now() < window {
        assert_eq!(
            acceptor.queued(),
            CAP,
            "boundedness violated: depth exceeded capacity (surplus was buffered)"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Draining yields exactly the capacity.
    let mut drained = 0usize;
    while acceptor.try_next().is_some() {
        drained += 1;
    }
    assert_eq!(drained, CAP, "channel held exactly its capacity");
    drop(held);
}

/// Backpressure is real and bounded: with a stalled reader the writer
/// throttles at the QUIC flow-control window (~1.25 MiB stream credit) — it
/// neither completes nor buffers unboundedly — then finishes with full
/// integrity once the reader drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback; binds UDP. Integration tier. Proves bounded backpressure."]
async fn backpressure_throttles_writer_with_bounded_buffering() {
    use sha2::Digest;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TOTAL: usize = 32 * 1024 * 1024;
    const WCHUNK: usize = 64 * 1024;
    const RCHUNK: usize = 256 * 1024;
    /// ant-quic's per-stream initial flow-control credit is 1_250_000 bytes
    /// (STREAM_RWND); allow generous in-flight slack but far below TOTAL.
    const STALL_BOUND: usize = 8 * 1024 * 1024;

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
    link_pair(&alice, &bob).await;

    let mut alice_stream = alice
        .open_peer_stream(&bob.agent_id(), StreamProtocol::SocksV1)
        .await
        .expect("open stream");
    let mut bob_stream = take_incoming(&bob, Duration::from_secs(15))
        .await
        .expect("bob accepted");

    let pattern = xorshift_pattern(TOTAL, 0xBAACC4ED);
    let expected_hash = sha2::Sha256::digest(&pattern);

    // Writer task: push the whole pattern, publishing progress.
    let written = Arc::new(AtomicUsize::new(0));
    let written_in_task = Arc::clone(&written);
    let writer = tokio::spawn(async move {
        let mut offset = 0usize;
        while offset < TOTAL {
            let end = (offset + WCHUNK).min(TOTAL);
            alice_stream
                .send_mut()
                .write_all(&pattern[offset..end])
                .await
                .expect("write chunk");
            offset = end;
            written_in_task.store(offset, Ordering::Release);
        }
        offset
    });

    // Stall the reader: the writer must throttle at the flow-control window.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let stalled = written.load(Ordering::Acquire);
    assert!(
        !writer.is_finished(),
        "writer completed with a stalled reader — backpressure is broken"
    );
    assert!(stalled > 0, "writer should have made initial progress");
    assert!(
        stalled <= STALL_BOUND,
        "stalled writer accepted {stalled} bytes — exceeds the flow-control bound \
         (stream window + slack), i.e. unbounded buffering"
    );

    // Drain: the writer unblocks and every byte arrives intact.
    let mut hasher = sha2::Sha256::new();
    let mut rbuf = vec![0u8; RCHUNK];
    for _ in 0..(TOTAL / RCHUNK) {
        bob_stream
            .recv_mut()
            .read_exact(&mut rbuf)
            .await
            .expect("read chunk");
        hasher.update(&rbuf);
    }
    let completed = writer.await.expect("writer join");
    assert_eq!(completed, TOTAL);
    assert_eq!(
        hasher.finalize(),
        expected_hash,
        "32 MiB transfer integrity after backpressure"
    );
}

/// Large-transfer integrity: 8 MiB deterministic pattern each direction over
/// one stream, SHA-256 verified.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback; binds UDP. Integration tier. Proves 8 MiB transfer integrity."]
async fn large_transfer_integrity_8mib() {
    use sha2::Digest;

    const LEN: usize = 8 * 1024 * 1024;
    const CHUNK: usize = 256 * 1024;

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
    link_pair(&alice, &bob).await;

    let mut alice_stream = alice
        .open_peer_stream(&bob.agent_id(), StreamProtocol::ForwardV2)
        .await
        .expect("open stream");
    let mut bob_stream = take_incoming(&bob, Duration::from_secs(15))
        .await
        .expect("bob accepted");

    let p_ab = xorshift_pattern(LEN, 0xA2B);
    let p_ba = xorshift_pattern(LEN, 0xB2A);

    // alice → bob
    let p_ab_ref = &p_ab;
    let (w, r) = tokio::join!(
        async { alice_stream.send_mut().write_all(p_ab_ref).await },
        async {
            let mut buf = vec![0u8; LEN];
            let mut got = 0usize;
            while got < LEN {
                let end = (got + CHUNK).min(LEN);
                bob_stream
                    .recv_mut()
                    .read_exact(&mut buf[got..end])
                    .await
                    .expect("read a→b");
                got = end;
            }
            buf
        },
    );
    w.expect("write a→b");
    assert_eq!(
        sha2::Sha256::digest(&r),
        sha2::Sha256::digest(&p_ab),
        "alice→bob 8 MiB checksum"
    );

    // bob → alice
    let p_ba_ref = &p_ba;
    let (w, r) = tokio::join!(
        async { bob_stream.send_mut().write_all(p_ba_ref).await },
        async {
            let mut buf = vec![0u8; LEN];
            let mut got = 0usize;
            while got < LEN {
                let end = (got + CHUNK).min(LEN);
                alice_stream
                    .recv_mut()
                    .read_exact(&mut buf[got..end])
                    .await
                    .expect("read b→a");
                got = end;
            }
            buf
        },
    );
    w.expect("write b→a");
    assert_eq!(
        sha2::Sha256::digest(&r),
        sha2::Sha256::digest(&p_ba),
        "bob→alice 8 MiB checksum"
    );
}
