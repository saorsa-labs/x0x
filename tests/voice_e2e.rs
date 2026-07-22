//! Voice pipeline e2e (feature `voice`, integration tier).
//!
//! Asserts the full 1:1 pipeline the `voice_call` example demonstrates:
//! real Opus encode → `AudioDatagram` wire framing → `X0xLinkTransport`
//! Audio lane → jitter buffer → Opus decode, between two in-process
//! agents on loopback. 250 frames (5 s): ≥99 % delivered post-jitter,
//! decoded tone dominates an off-band frequency (SNR sanity vs the
//! synthesized source), p95 one-way frame latency < 100 ms.
//!
//! `#[ignore]`: binds real UDP sockets and waits on loopback convergence
//! (integration tier, like `voice_adapters.rs`).

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
use x0x::voice::X0xLinkTransport;
use x0x::DiscoveredAgent;

const FRAMES: usize = 250;
const TONE_A_HZ: f64 = 440.0;
const TONE_B_HZ: f64 = 1200.0;

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

/// Full pipeline: 250 Opus frames through wire framing, the Audio lane,
/// and the jitter buffer — asserting delivery, audio fidelity, latency.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback voice pipeline; binds UDP + waits on convergence. Integration tier."]
async fn voice_pipeline_delivers_decodable_audio() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };

    let mut alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id());
    let mut bob_link = X0xLinkTransport::new(Arc::clone(&bob), alice.agent_id());
    bob_link.start().await.expect("bob link");
    alice_link.start().await.expect("alice link");
    let peer = alice_link.default_peer().expect("default peer");

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
        let _ = bob_link.stop().await;
        (pcm, latencies_ms, delivered, gaps)
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
        alice_link
            .send(&peer, StreamType::Audio, &wire)
            .await
            .expect("send frame");
    }

    let (pcm, latencies_ms, delivered, gaps) = receiver.await.expect("receiver task");
    let _ = alice_link.stop().await;

    // ≥99% delivered post-jitter.
    assert!(
        delivered * 100 >= FRAMES * 99,
        "delivered {delivered}/{FRAMES} (gaps {gaps}) — below 99%"
    );

    // Decoded audio is the tone, not noise: both targets ≥ 20 dB over off-band.
    let p_a = goertzel(&pcm, TONE_A_HZ);
    let p_b = goertzel(&pcm, TONE_B_HZ);
    let p_off = goertzel(&pcm, 700.0).max(1e-9);
    assert!(
        p_a / p_off > 100.0 && p_b / p_off > 100.0,
        "decoded tone SNR too low: 440Hz ratio {:.1}, 1200Hz ratio {:.1}",
        p_a / p_off,
        p_b / p_off
    );

    // p95 one-way < 100 ms on loopback.
    let mut sorted = latencies_ms;
    sorted.sort_unstable();
    let p95 = sorted[((sorted.len() as f64 - 1.0) * 0.95) as usize];
    assert!(p95 < 100, "p95 one-way frame latency {p95} ms ≥ 100 ms");

    alice.shutdown().await;
    bob.shutdown().await;
}
