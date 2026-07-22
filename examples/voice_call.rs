//! 1:1 voice call demo — the full pipeline over the x0x mesh.
//!
//! Two in-process agents on loopback: QUIC-native signaling over real DMs
//! (`CapabilityExchange → ConnectionConfirm → ConnectionReady`), then five
//! seconds of a synthesized speech-band tone (440 Hz + 1200 Hz) as 20 ms
//! frames — **real Opus** encode → `AudioDatagram` wire framing →
//! `X0xLinkTransport` Audio lane (ADR-0022 `StreamProtocol::WebRtcV1`) →
//! **jitter buffer** → Opus decode — with per-frame one-way latency stats
//! and jitter counters printed at the end.
//!
//! Lane mode: **Reliable** (a single ordered ADR-0022 byte stream per
//! lane). The saorsa-webrtc `AudioLaneMode::Datagram` path exists in
//! `saorsa-webrtc-core 0.5.0` over raw ant-quic connections, but the x0x
//! adapter seam (`X0xLinkTransport` over `PeerStream`) does not expose an
//! unreliable lane yet — that is V1.2/V1.3 follow-up work, noted in
//! `docs/design/` upstream. The datagram *wire format* and the jitter
//! buffer run end-to-end here regardless, so the playout path is the real
//! one.
//!
//! Run:
//! ```text
//! cargo run --features voice --example voice_call
//! ```
//!
//! Real microphone → speaker on two machines (manual Studio run): pair
//! this demo's transport with the `saorsa-webrtc-audio` crate's capture /
//! playout (`cargo run -p saorsa-webrtc-audio --example loopback 10` in
//! the saorsa-webrtc repo proves the device path; wiring mic → this
//! sender loop is the tic-tac-toe M-voice milestone, kept out of x0x so
//! the daemon crate carries no cpal/device dependency).

use std::f64::consts::TAU;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use saorsa_webrtc_core::link_transport::{LinkTransport, StreamType};
use saorsa_webrtc_core::signaling::{SignalingMessage, SignalingTransport};
use saorsa_webrtc_core::{AudioDatagram, JitterBuffer, JitterConfig, JitterEvent};
use x0x::network::NetworkConfig;
use x0x::voice::codecs::opus::{
    samples_per_20ms, AudioFrame, Channels, OpusDecoder, OpusEncoder, OpusEncoderConfig, SampleRate,
};
use x0x::voice::{VoicePeerId, X0xLinkTransport, X0xSignaling};
use x0x::DiscoveredAgent;

const CALL_SECS: usize = 5;
const FRAMES: usize = CALL_SECS * 50; // 20 ms frames
const TONE_A_HZ: f64 = 440.0;
const TONE_B_HZ: f64 = 1200.0;

fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        ..NetworkConfig::default()
    }
}

async fn build_agent(dir: &tempfile::TempDir, name: &str) -> x0x::Agent {
    x0x::Agent::builder()
        .with_machine_key(dir.path().join(format!("{name}-machine.key")))
        .with_agent_key_path(dir.path().join(format!("{name}-agent.key")))
        .with_contact_store_path(dir.path().join(format!("{name}-contacts.json")))
        .with_peer_cache_dir(dir.path().join(format!("{name}-peer-cache")))
        .with_network_config(loopback_network_config())
        .build()
        .await
        .expect("agent build")
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

/// 20 ms of the speech-band test tone at 48 kHz mono.
fn tone_frame(frame_idx: usize, samples: usize) -> Vec<i16> {
    let sr = SampleRate::Hz48000.as_hz() as f64;
    (0..samples)
        .map(|i| {
            let t = (frame_idx * samples + i) as f64 / sr;
            let v = 0.4 * (TAU * TONE_A_HZ * t).sin() + 0.3 * (TAU * TONE_B_HZ * t).sin();
            (v * i16::MAX as f64 * 0.5) as i16
        })
        .collect()
}

/// Goertzel power of `freq` in `pcm` (48 kHz).
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

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let dir = tempfile::TempDir::new().expect("tmpdir");
    println!("── x0x voice call demo: {CALL_SECS}s, {FRAMES} × 20ms frames, real Opus ──");

    // Two agents, mutual trust, loopback (mirrors the tailnet harness).
    let alice = Arc::new(build_agent(&dir, "alice").await);
    let bob = Arc::new(build_agent(&dir, "bob").await);
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
    let now_secs = now_ms() / 1000;
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, bob_addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, alice_addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;

    // Signaling: CapabilityExchange → ConnectionConfirm → ConnectionReady.
    let alice_sig = X0xSignaling::new(Arc::clone(&alice));
    let bob_sig = X0xSignaling::new(Arc::clone(&bob));
    alice_sig
        .send_message(
            &VoicePeerId(bob.agent_id()),
            SignalingMessage::CapabilityExchange {
                session_id: "demo-call".into(),
                audio: true,
                video: false,
                data_channel: false,
                max_bandwidth_kbps: 64,
                quic_endpoint: None,
            },
        )
        .await
        .expect("capability exchange");
    let (from, _) = bob_sig.receive_message().await.expect("bob rx capex");
    bob_sig
        .send_message(
            &from,
            SignalingMessage::ConnectionConfirm {
                session_id: "demo-call".into(),
                audio: true,
                video: false,
                data_channel: false,
                max_bandwidth_kbps: 64,
                quic_endpoint: None,
            },
        )
        .await
        .expect("connection confirm");
    let _ = alice_sig.receive_message().await.expect("alice rx confirm");
    alice_sig
        .send_message(
            &VoicePeerId(bob.agent_id()),
            SignalingMessage::ConnectionReady {
                session_id: "demo-call".into(),
            },
        )
        .await
        .expect("connection ready");
    let _ = bob_sig.receive_message().await.expect("bob rx ready");
    println!("signaling complete (CapabilityExchange → ConnectionConfirm → ConnectionReady)");

    // Media lanes.
    let mut alice_link = X0xLinkTransport::new(Arc::clone(&alice), bob.agent_id());
    let mut bob_link = X0xLinkTransport::new(Arc::clone(&bob), alice.agent_id());
    bob_link.start().await.expect("bob link");
    alice_link.start().await.expect("alice link");
    let peer = alice_link.default_peer().expect("default peer");

    // Receiver task: lane → AudioDatagram::decode → jitter → Opus decode.
    let receiver = tokio::spawn(async move {
        let mut jitter = JitterBuffer::new(JitterConfig::default());
        let mut decoder = OpusDecoder::new(SampleRate::Hz48000, Channels::Mono).expect("decoder");
        let mut pcm: Vec<i16> = Vec::with_capacity(FRAMES * 960);
        let mut latencies_ms: Vec<u64> = Vec::with_capacity(FRAMES);
        let mut delivered = 0usize;
        let mut gaps = 0usize;
        let deadline = Instant::now() + Duration::from_secs(30);
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
                        let frame = decoder.decode(&f.payload).expect("opus decode");
                        pcm.extend_from_slice(&frame.data);
                        delivered += 1;
                    }
                    JitterEvent::Gap { .. } => gaps += 1,
                }
            }
        }
        // Drain anything the reorder window still holds.
        tokio::time::sleep(Duration::from_millis(80)).await;
        for ev in jitter.poll_ready() {
            match ev {
                JitterEvent::Frame(f) => {
                    let frame = decoder.decode(&f.payload).expect("opus decode");
                    pcm.extend_from_slice(&frame.data);
                    delivered += 1;
                }
                JitterEvent::Gap { .. } => gaps += 1,
            }
        }
        let _ = bob_link.stop().await;
        (pcm, latencies_ms, delivered, gaps, jitter.counters())
    });

    // Sender: tone → Opus → AudioDatagram wire bytes → Audio lane, paced.
    let samples = samples_per_20ms(SampleRate::Hz48000);
    let mut encoder = OpusEncoder::new(OpusEncoderConfig::default()).expect("encoder");
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    for seq in 0..FRAMES {
        interval.tick().await;
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
    println!("sender done: {FRAMES} frames encoded + sent");

    let (pcm, latencies_ms, delivered, gaps, counters) = receiver.await.expect("receiver task");
    let _ = alice_link.stop().await;

    // Tone verification: target frequencies must dominate an off-frequency.
    let p_a = goertzel(&pcm, TONE_A_HZ);
    let p_b = goertzel(&pcm, TONE_B_HZ);
    let p_off = goertzel(&pcm, 700.0).max(1e-9);
    let mut sorted = latencies_ms.clone();
    sorted.sort_unstable();
    let pct = |p: f64| -> u64 {
        if sorted.is_empty() {
            0
        } else {
            sorted[((sorted.len() as f64 - 1.0) * p) as usize]
        }
    };

    println!("── results ──");
    println!(
        "frames: sent={FRAMES} delivered={delivered} gaps={gaps} ({:.1}% delivered post-jitter)",
        100.0 * delivered as f64 / FRAMES as f64
    );
    println!(
        "one-way frame latency ms: p50={} p95={} max={}",
        pct(0.50),
        pct(0.95),
        sorted.last().copied().unwrap_or(0)
    );
    println!(
        "jitter counters: delivered={} reordered={} late_dropped={} duplicates={} gaps_emitted={}",
        counters.delivered,
        counters.reordered,
        counters.late_dropped,
        counters.duplicates_dropped,
        counters.gaps_emitted
    );
    println!(
        "tone check (Goertzel power): 440Hz={:.1}dB over off-band, 1200Hz={:.1}dB over off-band",
        10.0 * (p_a / p_off).log10(),
        10.0 * (p_b / p_off).log10()
    );
    println!(
        "lane mode: Reliable (ordered ADR-0022 stream; datagram lane = V1.2/V1.3 seam follow-up)"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}
