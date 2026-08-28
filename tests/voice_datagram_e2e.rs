//! Datagram audio lane e2e (ADR-0042 decision (c), feature `voice`).
//!
//! Mirrors `voice_e2e.rs` with BOTH transports pinned
//! [`AudioLaneMode::Datagram`]: the same real Opus pipeline (encode →
//! `AudioDatagram` wire framing → lane → jitter buffer → decode), but
//! audio rides **unreliable QUIC datagrams** on the peer connection
//! instead of the ordered `WebRtcV1` stream.
//!
//! Why a separate file (not a mode flag inside `voice_e2e`): the two
//! files pin different contracts. `voice_e2e` guards the reliable lane's
//! ≥99 %/SNR/latency posture; this file guards the datagram lane's
//! ≥96 % post-jitter gate (the saorsa-webrtc `e2e_datagram_lane.rs`
//! standard) under both clean loopback and injected loss/reorder, plus
//! the lane-routing proof — the frame counters must show audio actually
//! left as datagrams, so a silent reliable-fallback bug cannot pass as
//! green.
//!
//! `#[ignore]`: binds real UDP sockets and waits on loopback convergence
//! (integration tier, like `voice_e2e.rs`).

#![cfg(feature = "voice")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::f64::consts::TAU;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use saorsa_webrtc_core::link_transport::{LinkTransport, StreamType};
use saorsa_webrtc_core::{AudioDatagram, JitterBuffer, JitterConfig, JitterEvent};
use tempfile::TempDir;
use x0x::network::NetworkConfig;
use x0x::voice::codecs::opus::{
    samples_per_20ms, AudioFrame, Channels, OpusDecoder, OpusEncoder, OpusEncoderConfig, SampleRate,
};
use x0x::voice::{AudioLaneMode, X0xLinkTransport};
use x0x::DiscoveredAgent;

const FRAMES: usize = 250;
const TONE_A_HZ: f64 = 440.0;
const TONE_B_HZ: f64 = 1200.0;

/// Post-jitter delivery gate on the datagram lane (the saorsa-webrtc
/// `e2e_datagram_lane.rs` standard — looser than the reliable lane's
/// ≥99 % because datagrams may legitimately be lost).
const MIN_DELIVERED_PERCENT: usize = 96;

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
        // Never a silent pass on environment failure (Codex r2 finding
        // 4): without real UDP sockets this e2e proves nothing, so fail
        // loudly rather than returning Ok from a body that ran nothing.
        Err(e) if is_network_bind_permission_error(&e) => panic!(
            "environment forbids UDP binds — this datagram e2e cannot run and must not pass: {e}"
        ),
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
        self_name: None,
        cert_digest: None,
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

async fn trusted_pair(dir: &TempDir) -> Option<(Arc<x0x::Agent>, Arc<x0x::Agent>)> {
    let alice = Arc::new(build_agent(dir, "alice").await?);
    let bob = Arc::new(build_agent(dir, "bob").await?);
    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");
    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.expect("bob bound"));
    let alice_addr = normalize_loopback(alice_network.bound_addr().await.expect("alice bound"));
    alice_network
        .connect_addr(bob_addr)
        .await
        .expect("alice connects to bob");
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);
    let alice_peer = ant_quic::PeerId(alice.machine_id().0);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if alice_network.is_connected(&bob_peer).await
            && bob_network.is_connected(&alice_peer).await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;
    Some((alice, bob))
}

fn tone_frame(frame_idx: usize, samples: usize) -> Vec<i16> {
    let sr = f64::from(SampleRate::Hz48000.as_hz());
    (0..samples)
        .map(|i| {
            let t = (frame_idx * samples + i) as f64 / sr;
            let v = 0.4 * (TAU * TONE_A_HZ * t).sin() + 0.3 * (TAU * TONE_B_HZ * t).sin();
            (v * f64::from(i16::MAX) * 0.5) as i16
        })
        .collect()
}

fn goertzel(pcm: &[i16], freq: f64) -> f64 {
    let sr = f64::from(SampleRate::Hz48000.as_hz());
    let w = TAU * freq / sr;
    let coeff = 2.0 * w.cos();
    let (mut s1, mut s2) = (0.0f64, 0.0f64);
    for &x in pcm {
        let s0 = f64::from(x) + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    (s1 * s1 + s2 * s2 - coeff * s1 * s2) / pcm.len() as f64
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_millis() as u64
}

/// Both sides must see the peer's advert before media flows — the switch
/// to datagrams is gated on it, so waiting here makes the frame-counter
/// assertions below exact (`sent == FRAMES`), not racy.
async fn await_mutual_capability(alice: &X0xLinkTransport, bob: &X0xLinkTransport) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if alice.peer_datagram_capable() && bob.peer_datagram_capable() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Outcome of one datagram-lane call: receiver stats plus both sides'
/// lane counters (the links are consumed by the call, so the counters
/// ride out as values).
struct CallOutcome {
    pcm: Vec<i16>,
    latencies_ms: Vec<u64>,
    delivered: usize,
    gaps: usize,
    /// Datagrams sent by the caller (routing proof: must equal FRAMES).
    datagrams_sent: u64,
    /// Datagrams decoded + queued by the callee.
    datagrams_received: u64,
}

/// Drive the full pipeline over the datagram lane.
async fn run_call(mut bob_link: X0xLinkTransport, mut alice_link: X0xLinkTransport) -> CallOutcome {
    bob_link.start().await.expect("bob link");
    alice_link.start().await.expect("alice link");
    assert!(
        await_mutual_capability(&alice_link, &bob_link).await,
        "mutual datagram capability advert did not land — DM path broken?"
    );

    let receiver = tokio::spawn(async move {
        let mut jitter = JitterBuffer::new(JitterConfig::default());
        let mut decoder = OpusDecoder::new(SampleRate::Hz48000, Channels::Mono).expect("decoder");
        let mut pcm: Vec<i16> = Vec::new();
        let mut latencies_ms: Vec<u64> = Vec::new();
        let mut delivered = 0usize;
        let mut gaps = 0usize;
        let deadline = Instant::now() + Duration::from_secs(60);
        while delivered + gaps < FRAMES && Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok(Ok((_, ty, data))) = tokio::time::timeout(remaining, bob_link.receive()).await
            else {
                break;
            };
            if ty != StreamType::Audio {
                continue;
            }
            let dg = AudioDatagram::decode(data.into()).expect("wire decode");
            latencies_ms.push(now_ms().saturating_sub(dg.timestamp_ms));
            jitter.push(dg);
            for ev in jitter.poll_ready() {
                match ev {
                    JitterEvent::Frame(f) => {
                        pcm.extend_from_slice(
                            &decoder.decode(&f.payload).expect("opus decode").data,
                        );
                        delivered += 1;
                    }
                    JitterEvent::Gap { .. } => gaps += 1,
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
        for ev in jitter.poll_ready() {
            match ev {
                JitterEvent::Frame(f) => {
                    pcm.extend_from_slice(&decoder.decode(&f.payload).expect("opus decode").data);
                    delivered += 1;
                }
                JitterEvent::Gap { .. } => gaps += 1,
            }
        }
        // Capture the receive-side lane counter before stop() drops it.
        let datagrams_received = bob_link.datagram_frames_received();
        let _ = bob_link.stop().await;
        (pcm, latencies_ms, delivered, gaps, datagrams_received)
    });

    let samples = samples_per_20ms(SampleRate::Hz48000);
    let mut encoder = OpusEncoder::new(OpusEncoderConfig::default()).expect("encoder");
    for seq in 0..FRAMES {
        let frame = AudioFrame {
            data: tone_frame(seq, samples),
            sample_rate: SampleRate::Hz48000,
            channels: Channels::Mono,
            timestamp: (seq * 20) as u64,
        };
        let payload = encoder.encode(&frame).expect("opus encode");
        let dg = AudioDatagram {
            seq: seq as u32,
            timestamp_ms: now_ms(),
            flags: 0,
            payload,
        };
        let wire = dg.encode().expect("wire encode");
        let peer = alice_link.default_peer().expect("default peer");
        alice_link
            .send(&peer, StreamType::Audio, &wire)
            .await
            .expect("send frame");
        // Real-audio pacing (one 20 ms frame per tick): the jitter
        // buffer's reorder window is 3 frames/60 ms, so a tight burst
        // would exceed it BY CONSTRUCTION (dozens in flight, independent
        // per-packet delays) and emit false gaps — that would test the
        // proxy, not the lane. Real capture is paced; loss, not burst
        // reorder, is the condition under test.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let (pcm, latencies_ms, delivered, gaps, datagrams_received) =
        receiver.await.expect("receiver task");
    let datagrams_sent = alice_link.datagram_frames_sent();
    let _ = alice_link.stop().await;
    CallOutcome {
        pcm,
        latencies_ms,
        delivered,
        gaps,
        datagrams_sent,
        datagrams_received,
    }
}

/// Lossy, reordering UDP proxy: two-party (1:1 call scope) — side B is
/// pinned to `bob_addr` at construction (bob otherwise never sends to
/// the proxy, so it could never be learned from traffic); the first
/// OTHER source address to send becomes side A. Every packet between
/// the sides is forwarded with `drop_pct` % loss and 0–7 ms of
/// per-packet jitter. Jittered per-packet delays are what create
/// reordering (a fixed delay would preserve order). QUIC's own loss
/// recovery retransmits the reliable traffic (handshake, signaling DMs,
/// stream lanes); the datagram lane must eat the loss with the jitter
/// buffer — exactly the condition ADR-0042 (c) exists for.
struct LossyUdpProxy {
    addr: std::net::SocketAddr,
}

/// Tiny LCG — deterministic, no rand dependency.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 16
    }
}

async fn spawn_lossy_udp_proxy(drop_pct: u64, bob_addr: std::net::SocketAddr) -> LossyUdpProxy {
    let sock = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("proxy bind"),
    );
    let addr = sock.local_addr().expect("proxy addr");
    let recv = Arc::clone(&sock);
    tokio::spawn(async move {
        // PQC handshakes can carry multi-kilobyte datagrams; size the
        // buffer for the UDP maximum so nothing is truncated silently.
        let mut buf = vec![0u8; 65_507];
        // Side B is pinned (bob's real socket); the first other source
        // address to send becomes side A (alice's QUIC socket).
        let mut sides: [Option<std::net::SocketAddr>; 2] = [None, Some(bob_addr)];
        let mut rng = Lcg(0x5EED_1234_ABCD_0001);
        loop {
            let (n, from) = match recv.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => break,
            };
            if sides.contains(&Some(from)) {
                // known side
            } else if from == bob_addr || sides[0].is_some() {
                continue; // third party — two-party proxy by contract
            } else {
                sides[0] = Some(from);
            }
            let (Some(a), Some(b)) = (sides[0], sides[1]) else {
                continue; // only one side seen yet
            };
            let to = if from == a { b } else { a };
            if rng.next() % 100 < drop_pct {
                continue; // injected loss
            }
            let delay_ms = rng.next() % 8; // 0–7 ms → reordering
            let data = buf[..n].to_vec();
            let fwd = Arc::clone(&recv);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let _ = fwd.send_to(&data, to).await;
            });
        }
    });
    LossyUdpProxy { addr }
}

/// Clean-loopback datagram parity with the reliable path: the full Opus
/// pipeline over QUIC datagrams — ≥96 % post-jitter (saorsa
/// `e2e_datagram_lane` gate), tone SNR sanity, p95 < 100 ms — and the
/// routing proof: every audio frame left as a datagram (a silent
/// reliable-fallback bug cannot pass this).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback datagram voice pipeline; binds UDP + waits on convergence. Integration tier."]
async fn datagram_lane_delivers_decodable_audio_on_loopback() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };

    let alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    let bob_link = X0xLinkTransport::new(Arc::clone(&bob), alice.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);

    let out = run_call(bob_link, alice_link).await;

    // Routing proof: all audio took the datagram lane, both directions
    // of the contract (sent as datagrams, consumed as datagrams).
    assert_eq!(
        out.datagrams_sent, FRAMES as u64,
        "every audio frame must leave as a datagram"
    );
    assert!(
        out.datagrams_received >= out.delivered as u64,
        "datagrams received ({}) must cover post-jitter delivery ({})",
        out.datagrams_received,
        out.delivered
    );

    assert!(
        out.delivered * 100 >= FRAMES * MIN_DELIVERED_PERCENT,
        "delivered {}/{} (gaps {}) — below {MIN_DELIVERED_PERCENT}%",
        out.delivered,
        FRAMES,
        out.gaps
    );

    let p_a = goertzel(&out.pcm, TONE_A_HZ);
    let p_b = goertzel(&out.pcm, TONE_B_HZ);
    let p_off = goertzel(&out.pcm, 700.0).max(1e-9);
    assert!(
        p_a / p_off > 100.0 && p_b / p_off > 100.0,
        "decoded tone SNR too low: 440Hz ratio {:.1}, 1200Hz ratio {:.1}",
        p_a / p_off,
        p_b / p_off
    );

    let mut sorted = out.latencies_ms;
    sorted.sort_unstable();
    if !sorted.is_empty() {
        let p95 = sorted[((sorted.len() as f64 - 1.0) * 0.95) as usize];
        assert!(p95 < 100, "p95 one-way frame latency {p95} ms ≥ 100 ms");
    }

    alice.shutdown().await;
    bob.shutdown().await;
}

/// The ADR-0042 (c) condition itself: 2 % injected loss + 0–7 ms
/// reordering through a UDP proxy between the two agents. The datagram
/// lane must still deliver ≥96 % of frames post-jitter — loss costs
/// single frames, never head-of-line blocking.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "lossy-proxy datagram voice pipeline; binds UDP + injects loss/reorder. Integration tier."]
async fn datagram_lane_survives_injected_loss_and_reorder() {
    let dir = TempDir::new().expect("tmpdir");
    let alice = Arc::new(build_agent(&dir, "alice").await.expect("agent"));
    let bob = Arc::new(build_agent(&dir, "bob").await.expect("agent"));
    alice.join_network().await.expect("alice joins");
    bob.join_network().await.expect("bob joins");

    let alice_network = alice.network().expect("alice network").clone();
    let bob_network = bob.network().expect("bob network").clone();
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.expect("bob bound"));
    let proxy = spawn_lossy_udp_proxy(2, bob_addr).await;
    alice_network
        .connect_addr(proxy.addr)
        .await
        .expect("alice connects through the lossy proxy");
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);
    let alice_peer = ant_quic::PeerId(alice.machine_id().0);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if alice_network.is_connected(&bob_peer).await
            && bob_network.is_connected(&alice_peer).await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        alice_network.is_connected(&bob_peer).await,
        "connection through the lossy proxy must converge (QUIC loss recovery)"
    );

    let alice_addr = normalize_loopback(alice_network.bound_addr().await.expect("alice bound"));
    let bob_addr = normalize_loopback(bob_network.bound_addr().await.expect("bob bound"));
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;

    let alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    let bob_link = X0xLinkTransport::new(Arc::clone(&bob), alice.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);

    let out = run_call(bob_link, alice_link).await;

    // 2 % injected loss must not cost more than the datagram gate allows:
    // ≥96 % of frames still delivered post-jitter. (The jitter buffer's
    // reorder window covers the 0–7 ms reorder; anything beyond surfaces
    // as a bounded Gap, exactly like real-network jitter.)
    assert!(
        out.delivered * 100 >= FRAMES * MIN_DELIVERED_PERCENT,
        "delivered {}/{} (gaps {}) under 2% loss + reorder — below {MIN_DELIVERED_PERCENT}%",
        out.delivered,
        FRAMES,
        out.gaps
    );
    // And the lane must have carried the audio as datagrams throughout.
    assert_eq!(
        out.datagrams_sent, FRAMES as u64,
        "every audio frame must leave as a datagram"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}

/// Flood defense (ADR-0042 addendum): the per-connection inbound byte
/// ceiling must make a datagram flood cost the SENDER, not the lane —
/// excess is dropped and counted, and the limiter must recover (bucket
/// refills) so legitimate post-flood audio still flows. 300 × ~1 KB
/// valid frames in a tight loop ≈ 300 KB against a 50 KB burst +
/// 100 KB/s ceiling ⇒ a large fraction must drop on any fast machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback datagram flood; binds UDP. Integration tier."]
async fn datagram_flood_rate_limited_and_lane_recovers() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };

    let mut alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    let mut bob_link = X0xLinkTransport::new(Arc::clone(&bob), alice.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    bob_link.start().await.expect("bob link");
    alice_link.start().await.expect("alice link");
    assert!(
        await_mutual_capability(&alice_link, &bob_link).await,
        "mutual datagram capability advert did not land"
    );

    const FLOOD: u32 = 300;
    let peer = alice_link.default_peer().expect("default peer");
    for seq in 0..FLOOD {
        let dg = AudioDatagram {
            seq,
            timestamp_ms: now_ms(),
            flags: 0,
            payload: bytes::Bytes::from(vec![0u8; 1000]), // ~1 KB wire frame
        };
        let wire = dg.encode().expect("wire encode");
        alice_link
            .send(&peer, StreamType::Audio, &wire)
            .await
            .expect("send flood frame");
    }

    // Let the reader drain and the counters settle.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let dropped = bob_link.datagram_rate_limited_dropped();
    let received = bob_link.datagram_frames_received();
    assert!(
        dropped > 0,
        "a {FLOOD}-frame ~1 KB tight-loop flood (~{} KB) must exceed the 50 KB burst + 100 KB/s ceiling",
        FLOOD
    );
    assert!(
        received < u64::from(FLOOD),
        "not all flood frames may be accepted (received {received}, dropped {dropped})"
    );

    // Recovery: after the bucket refills, paced real-rate audio still
    // flows (the limiter is a token bucket, not a circuit breaker).
    tokio::time::sleep(Duration::from_millis(600)).await;
    for seq in FLOOD..FLOOD + 10 {
        let dg = AudioDatagram {
            seq,
            timestamp_ms: now_ms(),
            flags: 0,
            payload: bytes::Bytes::from(vec![0u8; 200]),
        };
        let wire = dg.encode().expect("wire encode");
        alice_link
            .send(&peer, StreamType::Audio, &wire)
            .await
            .expect("send post-flood frame");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Drain: flood leftovers first, then the paced tail. Recovery is
    // proven by any post-flood seq (≥ FLOOD) surfacing.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut max_seq = None;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, bob_link.receive()).await {
            Ok(Ok((_, ty, data))) => {
                assert_eq!(ty, StreamType::Audio);
                if let Ok(dg) = AudioDatagram::decode(data.into()) {
                    max_seq = Some(max_seq.map_or(dg.seq, |m: u32| m.max(dg.seq)));
                    if dg.seq >= FLOOD {
                        break; // post-flood frame surfaced — lane recovered
                    }
                }
            }
            Ok(Err(e)) => panic!("bob receive failed: {e}"),
            Err(_) => break,
        }
    }
    assert!(
        max_seq.is_some_and(|s| s >= FLOOD),
        "post-flood paced audio must still flow after the byte ceiling refills (max seq {max_seq:?})"
    );

    let _ = alice_link.stop().await;
    let _ = bob_link.stop().await;
    alice.shutdown().await;
    bob.shutdown().await;
}

/// Advert authentication + session binding (Codex review P1-1): a
/// connected, authenticated peer that is NOT running a datagram-capable
/// transport must not be able to flip our lane by sending crafted
/// advert frames — right sender id, right (authenticated) machine, but
/// no valid echo of OUR per-start nonce. Every variant (old v1 shape,
/// bogus response, bare challenge) must leave the lane un-flipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback advert-auth proof; binds UDP. Integration tier."]
async fn spoofed_or_replayed_advert_cannot_flip_lane() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };

    // Alice pins Datagram; bob runs NO transport at all (old-peer
    // stand-in — nothing of his will ever legitimately respond).
    let mut alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    alice_link.start().await.expect("alice link");

    // Crafted advert frames from the REAL bob (his DMs carry the right
    // authenticated machine + verified + trust) — the auth layer alone
    // would pass all of these; only the nonce binding must stop them.
    let crafted = [
        // v1 shape (no challenge/response) — a replay of an old build.
        r#"{"type":"x0x_datagram_cap","datagram":true}"#,
        // Bogus response echo.
        r#"{"type":"x0x_datagram_cap","datagram":true,"response":"0000000000000000"}"#,
        // A bare challenge (peer initial) — must never flip OUR lane.
        r#"{"type":"x0x_datagram_cap","datagram":true,"challenge":"deadbeef"}"#,
    ];
    for body in crafted {
        let mut payload = x0x::voice::VOICE_SIGNALING_DM_PREFIX.to_vec();
        payload.extend_from_slice(body.as_bytes());
        bob.send_direct(&alice.agent_id(), payload)
            .await
            .expect("crafted advert DM delivered");
    }
    // Give the listener ample time to (wrongly) process them.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        !alice_link.peer_datagram_capable(),
        "crafted/replayed adverts without our nonce echo must never flip the lane"
    );
    assert_eq!(
        alice_link.datagram_frames_sent(),
        0,
        "lane never flipped, so no audio left as datagrams"
    );

    let _ = alice_link.stop().await;
    alice.shutdown().await;
    bob.shutdown().await;
}

/// Connection churn must degrade the lane, never kill the call (Codex
/// review P1-3): after the negotiated connection closes, the reader
/// exits and clears capability, and subsequent audio flows over the
/// reliable stream (re-opened through the redial machinery) instead of
/// wedging on the dead datagram connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback churn-fallback proof; binds UDP. Integration tier."]
async fn connection_churn_falls_back_to_reliable() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };

    let mut alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    let mut bob_link = X0xLinkTransport::new(Arc::clone(&bob), alice.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    bob_link.start().await.expect("bob link");
    alice_link.start().await.expect("alice link");
    assert!(
        await_mutual_capability(&alice_link, &bob_link).await,
        "mutual capability must land before the churn"
    );

    // PRIME a reliable lane before the churn (Codex r2 finding 2): the
    // Data lane always rides the reliable stream (only Audio is
    // routable to datagrams), so this populates the cached-stream map
    // the eviction logic must recover from.
    let peer = alice_link.default_peer().expect("default peer");
    alice_link
        .send(&peer, StreamType::Data, &[0xA5; 64])
        .await
        .expect("prime reliable Data lane");

    // Kill the connection alice's datagram lane negotiated on, then
    // bring up its REPLACEMENT (realistic churn: the old connection is
    // gone, a new one takes over — `disconnect` removes the peer, so the
    // reliable path needs the replacement before open_bi can succeed).
    let bob_peer = ant_quic::PeerId(bob.machine_id().0);
    let alice_network = alice.network().expect("alice network").clone();
    let bob_addr = normalize_loopback(
        bob.network()
            .expect("bob network")
            .bound_addr()
            .await
            .expect("bob bound"),
    );
    alice_network
        .disconnect(&bob_peer)
        .await
        .expect("disconnect");
    alice_network
        .connect_addr(bob_addr)
        .await
        .expect("replacement connection");
    // Let the replacement converge on BOTH sides (same discipline as
    // `trusted_pair`): a stream opened into a half-torn-down connection
    // gets reset by the teardown, not by the peer's accept loop.
    let alice_peer = ant_quic::PeerId(alice.machine_id().0);
    let bob_network = bob.network().expect("bob network").clone();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if alice_network.is_connected(&bob_peer).await
            && bob_network.is_connected(&alice_peer).await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The reader must exit and clear capability (this is the regression:
    // a stale capable flag would wedge every send on the dead lane).
    let deadline = Instant::now() + Duration::from_secs(10);
    while alice_link.peer_datagram_capable() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !alice_link.peer_datagram_capable(),
        "reader exit on connection close must clear the capability flag"
    );
    let sent_at_churn = alice_link.datagram_frames_sent();

    // Post-churn audio: reliable lane, still delivered — the primed
    // cached stream from the dead connection must be evicted and
    // reopened (audio lane was never cached, so also exercise the Data
    // lane again: eviction covers every cached lane type).
    alice_link
        .send(&peer, StreamType::Data, &[0x5A; 64])
        .await
        .expect("post-churn Data send must evict the dead cached lane and reopen");
    const POST: usize = 25;
    for seq in 0..POST {
        let dg = AudioDatagram {
            seq: seq as u32,
            timestamp_ms: now_ms(),
            flags: 0,
            payload: bytes::Bytes::from(vec![0u8; 200]),
        };
        let wire = dg.encode().expect("wire encode");
        alice_link
            .send(&peer, StreamType::Audio, &wire)
            .await
            .expect("post-churn send must fall back to the reliable lane");
    }

    // Count AUDIO frames only: the primed + evicted Data-lane frames
    // also surface here (same inbound queue) and prove their own
    // delivery by arriving at all.
    let mut received = 0usize;
    let deadline = Instant::now() + Duration::from_secs(30);
    while received < POST && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, bob_link.receive()).await {
            Ok(Ok((_, ty, _))) => {
                if ty == StreamType::Audio {
                    received += 1;
                }
            }
            Ok(Err(e)) => panic!("bob receive failed: {e}"),
            Err(_) => break,
        }
    }
    assert_eq!(
        received, POST,
        "post-churn audio frames must arrive via the reliable lane"
    );
    assert_eq!(
        alice_link.datagram_frames_sent(),
        sent_at_churn,
        "no post-churn frame may leave as a datagram"
    );

    let _ = alice_link.stop().await;
    let _ = bob_link.stop().await;
    alice.shutdown().await;
    bob.shutdown().await;
}

/// Sequential startup regression (Codex r2 finding 1): DM subscribers
/// only receive FUTURE messages, so a peer that starts AFTER our first
/// challenge never sees it. The periodic advert retry (2 s cadence,
/// 20 s budget) must recover mutual capability even when one side is
/// already running for seconds before the other starts — the one-shot
/// implementation silently timed out here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback sequential-startup negotiation; binds UDP. Integration tier."]
async fn sequential_startup_still_negotiates_datagram_lane() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };

    // Alice fully starts FIRST — her initial challenge is fanned out
    // long before bob's listener exists (well past the DM window).
    let mut alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    alice_link.start().await.expect("alice link starts alone");
    assert!(
        !alice_link.peer_datagram_capable(),
        "no peer yet — lane must not be capable"
    );
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Bob starts NOW; alice's retry cadence must deliver a fresh
    // challenge his subscriber can see, and his ack must flip her lane.
    let mut bob_link = X0xLinkTransport::new(Arc::clone(&bob), alice.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    bob_link.start().await.expect("bob link starts late");

    assert!(
        await_mutual_capability(&alice_link, &bob_link).await,
        "periodic advert retry must recover negotiation across sequential startup"
    );

    let _ = alice_link.stop().await;
    let _ = bob_link.stop().await;
    alice.shutdown().await;
    bob.shutdown().await;
}
