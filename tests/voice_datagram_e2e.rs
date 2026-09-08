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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use saorsa_webrtc_core::link_transport::{LinkTransport, StreamType};
use saorsa_webrtc_core::{AudioDatagram, JitterBuffer, JitterConfig, JitterCounters, JitterEvent};
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

/// Loopback-only fixture posture. Every agent in this suite binds
/// `127.0.0.1:0` and reaches its peer only over `lo`:
///
/// * `bootstrap_nodes: []` — no public bootstrap peer is ever dialled;
/// * `mdns_enabled: false` — no multicast LAN discovery, so a co-located
///   node (a developer's own daemon, another CI job on the same host)
///   can never be discovered and joined mid-test;
/// * `port_mapping_enabled: false` — no UPnP discovery task, so nothing
///   asks a gateway to map a port outward.
///
/// The CI wrapper (`scripts/ci/isolated-runtime.py`, issue #417) already
/// runs this suite in a fresh network namespace whose only interface is
/// `lo`, so these are belt-and-braces there — but they are what makes
/// the fixture hermetic when it is run outside that namespace, and they
/// remove three sources of nondeterministic background work from the
/// phase oracles, which assert exact jitter-counter deltas.
fn loopback_network_config() -> NetworkConfig {
    NetworkConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("loopback addr literal")),
        bootstrap_nodes: Vec::new(),
        mdns_enabled: false,
        port_mapping_enabled: false,
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

// ---------------------------------------------------------------------
// Deterministic jitter-counter phase oracles (#277)
//
// ADR-0042 (c) requires the datagram lane to absorb reorder, duplicate
// and late arrivals; issue #277 requires that the `reordered` /
// `late_dropped` / `duplicates_dropped` counters actually prove it.
// Those three cannot be proven by a random-loss/random-delay network:
//
//   * a <=7 ms perturbation at a 20 ms send cadence may legitimately
//     leave order fully intact, so `reordered > 0` under random jitter
//     is a coin flip, not an oracle; and
//   * upstream increments `duplicates_dropped` ONLY while the identical
//     extended sequence is still in `buffered`
//     (`JitterBuffer::push`, saorsa-webrtc-core 0.5.0 `src/jitter.rs`).
//     Once `poll_ready` has drained that sequence the cursor has moved
//     past it and the same bytes arriving again land in the `ext < next`
//     arm, counting as `late_dropped`. A generic "re-emit a frame"
//     schedule therefore cannot assert duplicates at all — which of the
//     two counters moves depends entirely on whether the receiver
//     happened to poll in between.
//
// So the receiver runs an EXPLICIT PHASE SCRIPT with control acks: the
// sender does not emit the next datagram until the receiver confirms
// the previous one was pushed, and the receiver polls only where the
// script says to. That makes "duplicate arrives while still buffered"
// and "late arrives after a gap and playout" reachable by construction
// instead of by luck, and makes the counter deltas exact.
//
// The control plane is in-process channels; the DATA PLANE is not
// simulated. Every frame is a real Opus payload in a real
// `AudioDatagram`, sent with `X0xLinkTransport::send(StreamType::Audio)`
// over the real QUIC datagram lane and pulled back out with
// `X0xLinkTransport::receive()`. The jitter buffer is the real upstream
// one and its real `counters()` are asserted. Nothing is mocked.
// ---------------------------------------------------------------------

/// One step of a phase script.
#[derive(Clone, Copy, Debug)]
enum PhaseStep {
    /// Encode a real Opus frame, wrap it as this lane sequence, send it
    /// over the datagram lane, and block until the receiver confirms it
    /// was pushed into the jitter buffer. Deliberately does NOT poll:
    /// the frame stays *buffered*, the only state in which upstream
    /// counts a duplicate.
    Send(u32),
    /// Drain the receiver's playout and block until it finishes. This
    /// advances the playout cursor past everything buffered, which is
    /// what turns a later re-emit of a drained sequence into
    /// `late_dropped` rather than `duplicates_dropped`.
    Poll,
}

/// Warm-up prefix shared by every phase script.
///
/// Upstream treats the buffer as warming up until the first frame or
/// gap has played out (`delivered == 0 && gaps_emitted == 0`), and
/// while warming up an early sequence *re-anchors* the cursor and
/// counts as `reordered` instead of being dropped as late. Every oracle
/// below asserts post-warm-up semantics, so all of them start here:
/// sequences 0,1,2 in order then one poll, which retires the warm-up
/// and leaves the cursor at 3 with an empty buffer and an all-zero
/// counter set apart from `delivered == 3`.
const WARMUP: [PhaseStep; 4] = [
    PhaseStep::Send(0),
    PhaseStep::Send(1),
    PhaseStep::Send(2),
    PhaseStep::Poll,
];

/// Commands the driver issues to the phase receiver.
enum RxCmd {
    /// Await exactly this lane sequence off the datagram lane and push
    /// it. No poll.
    RecvPush(u32),
    /// Drain playout.
    Poll,
    /// Stop and report.
    Finish,
}

/// Result of a phase script.
struct PhaseOutcome {
    /// The real upstream jitter counters at end of script.
    counters: JitterCounters,
    /// `JitterEvent::Frame` events drained.
    delivered_events: usize,
    /// `JitterEvent::Gap` events drained.
    gap_events: usize,
    /// Lane routing proof: datagrams the sender actually emitted.
    datagrams_sent: u64,
    /// Lane routing proof: datagrams the receiver actually consumed.
    datagrams_received: u64,
    /// Decoded PCM length — proves the frames were real Opus, not stubs.
    decoded_samples: usize,
}

/// Run a deterministic phase script over the real datagram lane.
///
/// `WARMUP` is prepended automatically. Panics loudly (rather than
/// asserting a wrong number) if the lane loses or reorders a frame: the
/// oracles below require a lossless clean loopback lane, and a loss
/// there is a real lane defect, not a tolerated condition.
async fn run_phase_script(
    mut bob_link: X0xLinkTransport,
    mut alice_link: X0xLinkTransport,
    tail: &[PhaseStep],
) -> PhaseOutcome {
    bob_link.start().await.expect("bob link");
    alice_link.start().await.expect("alice link");
    assert!(
        await_mutual_capability(&alice_link, &bob_link).await,
        "mutual datagram capability advert did not land — DM path broken?"
    );

    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<RxCmd>(1);
    let (ack_tx, mut ack_rx) = tokio::sync::mpsc::channel::<()>(1);

    let mut receiver = tokio::spawn(async move {
        let mut jitter = JitterBuffer::new(JitterConfig::default());
        let mut decoder = OpusDecoder::new(SampleRate::Hz48000, Channels::Mono).expect("decoder");
        let mut decoded_samples = 0usize;
        let mut delivered_events = 0usize;
        let mut gap_events = 0usize;
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                RxCmd::RecvPush(want) => {
                    let deadline = Instant::now() + Duration::from_secs(20);
                    loop {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        let Ok(Ok((_, ty, data))) =
                            tokio::time::timeout(remaining, bob_link.receive()).await
                        else {
                            panic!(
                                "datagram lane did not deliver lane seq {want} within 20 s — \
                                 the phase oracle requires a lossless clean loopback lane"
                            );
                        };
                        if ty != StreamType::Audio {
                            continue;
                        }
                        let dg = AudioDatagram::decode(data.into()).expect("wire decode");
                        assert_eq!(
                            dg.seq, want,
                            "phase script expected lane seq {want}, lane delivered {} — \
                             the clean lane must not reorder; the schedule owns ordering",
                            dg.seq
                        );
                        jitter.push(dg);
                        break;
                    }
                }
                RxCmd::Poll => {
                    for ev in jitter.poll_ready() {
                        match ev {
                            JitterEvent::Frame(f) => {
                                decoded_samples +=
                                    decoder.decode(&f.payload).expect("opus decode").data.len();
                                delivered_events += 1;
                            }
                            JitterEvent::Gap { .. } => gap_events += 1,
                        }
                    }
                }
                RxCmd::Finish => break,
            }
            if ack_tx.send(()).await.is_err() {
                break;
            }
        }
        let counters = jitter.counters();
        let datagrams_received = bob_link.datagram_frames_received();
        let _ = bob_link.stop().await;
        (
            counters,
            delivered_events,
            gap_events,
            datagrams_received,
            decoded_samples,
        )
    });

    let samples = samples_per_20ms(SampleRate::Hz48000);
    let mut encoder = OpusEncoder::new(OpusEncoderConfig::default()).expect("encoder");
    let script: Vec<PhaseStep> = WARMUP.iter().copied().chain(tail.iter().copied()).collect();

    for step in script {
        match step {
            PhaseStep::Send(seq) => {
                let frame = AudioFrame {
                    data: tone_frame(seq as usize, samples),
                    sample_rate: SampleRate::Hz48000,
                    channels: Channels::Mono,
                    timestamp: u64::from(seq) * 20,
                };
                let payload = encoder.encode(&frame).expect("opus encode");
                let dg = AudioDatagram {
                    seq,
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
                send_cmd(&cmd_tx, RxCmd::RecvPush(seq), &mut receiver).await;
            }
            PhaseStep::Poll => send_cmd(&cmd_tx, RxCmd::Poll, &mut receiver).await,
        }
        await_ack(&mut ack_rx, &mut receiver).await;
    }

    let datagrams_sent = alice_link.datagram_frames_sent();
    let _ = cmd_tx.send(RxCmd::Finish).await;
    let _ = alice_link.stop().await;
    let (counters, delivered_events, gap_events, datagrams_received, decoded_samples) =
        match receiver.await {
            Ok(v) => v,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => panic!("phase receiver task failed: {e}"),
        };
    PhaseOutcome {
        counters,
        delivered_events,
        gap_events,
        datagrams_sent,
        datagrams_received,
        decoded_samples,
    }
}

/// Type of the phase receiver's join handle.
type PhaseRx = tokio::task::JoinHandle<(JitterCounters, usize, usize, u64, usize)>;

/// Issue a command, surfacing a receiver panic instead of deadlocking
/// on a channel whose consumer has already died.
async fn send_cmd(tx: &tokio::sync::mpsc::Sender<RxCmd>, cmd: RxCmd, rx_task: &mut PhaseRx) {
    if tx.send(cmd).await.is_err() {
        surface_receiver_failure(rx_task).await;
    }
}

/// Wait for the receiver's control ack. On timeout the receiver has
/// either panicked or wedged; either way the test must fail loudly with
/// the receiver's own message rather than hang to the harness timeout.
async fn await_ack(ack_rx: &mut tokio::sync::mpsc::Receiver<()>, rx_task: &mut PhaseRx) {
    match tokio::time::timeout(Duration::from_secs(30), ack_rx.recv()).await {
        Ok(Some(())) => {}
        _ => surface_receiver_failure(rx_task).await,
    }
}

/// Re-raise the receiver task's panic on the test thread.
async fn surface_receiver_failure(rx_task: &mut PhaseRx) -> ! {
    match rx_task.await {
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => panic!("phase receiver task failed: {e}"),
        Ok(_) => panic!("phase receiver ended before the script finished"),
    }
}

/// Assert the full counter tuple. Every phase oracle states all five
/// values, so the counters that must NOT move are asserted to be zero
/// in the same breath as the one that must — a counter wired to a
/// constant, or incremented on the wrong arm, fails here.
#[track_caller]
fn assert_counters(
    got: JitterCounters,
    delivered: u64,
    reordered: u64,
    late_dropped: u64,
    duplicates_dropped: u64,
    gaps_emitted: u64,
) {
    let want = JitterCounters {
        delivered,
        reordered,
        late_dropped,
        duplicates_dropped,
        gaps_emitted,
    };
    assert_eq!(got, want, "jitter counters for this phase schedule");
}

/// Shared setup: a trusted pair on the clean loopback lane with both
/// transports pinned to the datagram lane.
async fn phase_links(
    alice: &Arc<x0x::Agent>,
    bob: &Arc<x0x::Agent>,
) -> (X0xLinkTransport, X0xLinkTransport) {
    let alice_link = X0xLinkTransport::new(Arc::clone(alice), bob.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    let bob_link = X0xLinkTransport::new(Arc::clone(bob), alice.agent_id())
        .with_audio_lane_mode(AudioLaneMode::Datagram);
    (bob_link, alice_link)
}

/// Negative control for all three #277 counters: a strictly in-order
/// schedule with no perturbation must leave `reordered`,
/// `late_dropped`, `duplicates_dropped` AND `gaps_emitted` at exactly
/// zero. This is what makes the three positive oracles below
/// discriminating — a counter stuck non-zero, or incremented on every
/// push, fails here and only here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback datagram phase oracle; binds UDP. Integration tier."]
async fn jitter_counters_stay_zero_on_in_order_datagram_schedule() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };
    let (bob_link, alice_link) = phase_links(&alice, &bob).await;

    // Warm-up (0,1,2 + poll) then 3,4,5 in order and one poll.
    let out = run_phase_script(
        bob_link,
        alice_link,
        &[
            PhaseStep::Send(3),
            PhaseStep::Send(4),
            PhaseStep::Send(5),
            PhaseStep::Poll,
        ],
    )
    .await;

    assert_counters(out.counters, 6, 0, 0, 0, 0);
    assert_eq!(out.delivered_events, 6, "all six frames must play out");
    assert_eq!(out.gap_events, 0, "an in-order schedule declares no gaps");
    assert_eq!(
        out.datagrams_sent, 6,
        "every scheduled frame must leave as a datagram"
    );
    // `>=` not `==`: the receive-side lane counter is owned by
    // `link_transport.rs`, and the claim under test is the routing one —
    // every scheduled frame was consumed as a datagram, not over a
    // silent reliable fallback. Exactness on the counters this fixture
    // does own is asserted above via `assert_counters`.
    assert!(
        out.datagrams_received >= 6,
        "every scheduled frame must be consumed as a datagram (got {})",
        out.datagrams_received
    );
    assert!(
        out.decoded_samples > 0,
        "frames must be real Opus, decodable end to end"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}

/// `reordered` oracle: after warm-up the cursor sits at 3. Sending 4
/// first and 3 second means 3 arrives with `ext >= next` but below the
/// highest sequence seen, which is upstream's reorder arm — it is
/// recovered, not dropped, so both frames still play out. Exactly one
/// reorder is scheduled, so exactly one must be counted, and the other
/// three counters must not move.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback datagram phase oracle; binds UDP. Integration tier."]
async fn scheduled_reorder_counts_exactly_one_reordered_frame() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };
    let (bob_link, alice_link) = phase_links(&alice, &bob).await;

    let out = run_phase_script(
        bob_link,
        alice_link,
        &[PhaseStep::Send(4), PhaseStep::Send(3), PhaseStep::Poll],
    )
    .await;

    assert_counters(out.counters, 5, 1, 0, 0, 0);
    assert_eq!(
        out.delivered_events, 5,
        "a recovered reorder loses no audio — both 3 and 4 must play out"
    );
    assert_eq!(
        out.gap_events, 0,
        "reorder inside the window must not be surfaced as loss"
    );
    assert_eq!(out.datagrams_sent, 5, "lane routing proof");

    alice.shutdown().await;
    bob.shutdown().await;
}

/// `duplicates_dropped` oracle. Upstream counts a duplicate only while
/// the identical sequence is STILL BUFFERED, so the script sends 3,
/// waits for the receiver's ack that it was pushed, and sends 3 again
/// with no intervening poll. The second copy therefore meets the first
/// in the buffer and is dropped as a duplicate — and, critically, the
/// audio is not double-played: `delivered` is 4, not 5.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback datagram phase oracle; binds UDP. Integration tier."]
async fn duplicate_arriving_while_buffered_counts_as_duplicate_not_late() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };
    let (bob_link, alice_link) = phase_links(&alice, &bob).await;

    let out = run_phase_script(
        bob_link,
        alice_link,
        &[PhaseStep::Send(3), PhaseStep::Send(3), PhaseStep::Poll],
    )
    .await;

    // delivered=4, reordered=0, late_dropped=0, duplicates_dropped=1,
    // gaps_emitted=0. The zero on `late_dropped` is the discriminating
    // half of this oracle: it is the counter the same re-emit would move
    // if the receiver had polled in between.
    assert_counters(out.counters, 4, 0, 0, 1, 0);
    assert_eq!(
        out.delivered_events, 4,
        "the duplicate must be dropped, not played out twice"
    );
    assert_eq!(out.gap_events, 0, "a duplicate is not a loss");
    assert_eq!(
        out.datagrams_sent, 5,
        "both copies must actually leave over the datagram lane"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}

/// `late_dropped` oracle: a re-emit AFTER a gap and playout.
///
/// The script sends 4,5,6 with 3 missing; three newer frames exceed the
/// reorder window, so 3 is declared a gap and 4,5,6 play out, leaving
/// the cursor at 7. Sequence 3 then arrives behind the cursor and is
/// dropped as late — the same bytes that count as a *duplicate* in the
/// test above count as *late* here purely because playout intervened,
/// which is exactly why the receiver phases have to be explicit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two-agent loopback datagram phase oracle; binds UDP. Integration tier."]
async fn frame_arriving_after_gap_and_playout_counts_as_late() {
    let dir = TempDir::new().expect("tmpdir");
    let Some((alice, bob)) = trusted_pair(&dir).await else {
        return;
    };
    let (bob_link, alice_link) = phase_links(&alice, &bob).await;

    let out = run_phase_script(
        bob_link,
        alice_link,
        &[
            PhaseStep::Send(4),
            PhaseStep::Send(5),
            PhaseStep::Send(6),
            PhaseStep::Poll,
            PhaseStep::Send(3),
            PhaseStep::Poll,
        ],
    )
    .await;

    assert_counters(out.counters, 6, 0, 1, 0, 1);
    assert_eq!(
        out.gap_events, 1,
        "the missing sequence must reach playout-loss concealment as one gap"
    );
    assert_eq!(
        out.delivered_events, 6,
        "the late frame must not be played out behind the cursor"
    );
    assert_eq!(out.datagrams_sent, 7, "lane routing proof");

    alice.shutdown().await;
    bob.shutdown().await;
}

/// Lossy, reordering UDP proxy: two-party (1:1 call scope) — side B is
/// pinned to `bob_addr` at construction (bob otherwise never sends to
/// the proxy, so it could never be learned from traffic); the first
/// OTHER source address to send becomes side A. Every packet between
/// the sides is forwarded with `drop_pct` % loss and 0–7 ms of
/// per-packet jitter. QUIC's own loss recovery retransmits the reliable
/// traffic (handshake, signaling DMs, stream lanes); the datagram lane
/// must eat the loss with the jitter buffer — exactly the condition
/// ADR-0042 (c) exists for.
///
/// The counters here are **diagnostics only, never a pass condition**.
/// A dropped UDP packet may be a handshake, an ACK, a signalling DM or
/// a stream frame, and QUIC may discard a duplicated packet before
/// anything reaches the jitter buffer, so proxy packet counts cannot be
/// reconciled against `AudioDatagram` counts. Likewise a ≤7 ms
/// perturbation at a 20 ms send cadence may legitimately leave order
/// fully intact, so no reordering is asserted here. The deterministic
/// counter oracles live in the phase tests on the clean lane; this test
/// owns network realism (loss, resilience, SNR, latency) only.
struct LossyUdpProxy {
    addr: std::net::SocketAddr,
    stats: Arc<ProxyStats>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

/// Proxy packet diagnostics. Reported on failure to aid triage; never
/// asserted on (see [`LossyUdpProxy`]).
#[derive(Default)]
struct ProxyStats {
    forwarded: AtomicU64,
    dropped: AtomicU64,
    delayed: AtomicU64,
}

impl LossyUdpProxy {
    /// `(forwarded, dropped, delayed)` — diagnostics only.
    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.stats.forwarded.load(Ordering::Relaxed),
            self.stats.dropped.load(Ordering::Relaxed),
            self.stats.delayed.load(Ordering::Relaxed),
        )
    }

    /// Graceful stop: signal the loop, then join it, so the socket and
    /// every still-pending forward in the in-loop delay queue are
    /// reclaimed before the test returns.
    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

/// Abort-on-unwind backstop: an assertion failure between `spawn` and
/// `shutdown` must not leave the recv loop, its socket, or the pending
/// forward queue running for the rest of the process.
impl Drop for LossyUdpProxy {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
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
    let stats = Arc::new(ProxyStats::default());
    let task_stats = Arc::clone(&stats);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        // PQC handshakes can carry multi-kilobyte datagrams; size the
        // buffer for the UDP maximum so nothing is truncated silently.
        let mut buf = vec![0u8; 65_507];
        // Side B is pinned (bob's real socket); the first other source
        // address to send becomes side A (alice's QUIC socket).
        let mut sides: [Option<std::net::SocketAddr>; 2] = [None, Some(bob_addr)];
        let mut rng = Lcg(0x5EED_1234_ABCD_0001);
        // The delay queue lives *inside* the proxy task. A detached
        // `tokio::spawn` per packet would outlive the proxy and keep
        // forwarding after shutdown; owning it here means one abort or
        // one graceful stop reclaims the socket and every pending
        // forward together.
        let mut pending: Vec<(tokio::time::Instant, Vec<u8>, std::net::SocketAddr)> = Vec::new();
        loop {
            let next_due = pending.iter().map(|(due, _, _)| *due).min();
            let mut due_now: Vec<(Vec<u8>, std::net::SocketAddr)> = Vec::new();
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => break,
                () = async {
                    match next_due {
                        Some(due) => tokio::time::sleep_until(due).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let now = tokio::time::Instant::now();
                    pending.retain(|(due, data, to)| {
                        if *due <= now {
                            due_now.push((data.clone(), *to));
                            false
                        } else {
                            true
                        }
                    });
                }
                res = sock.recv_from(&mut buf) => {
                    let Ok((n, from)) = res else { break };
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
                        task_stats.dropped.fetch_add(1, Ordering::Relaxed);
                        continue; // injected loss
                    }
                    let delay_ms = rng.next() % 8; // 0–7 ms
                    if delay_ms > 0 {
                        task_stats.delayed.fetch_add(1, Ordering::Relaxed);
                    }
                    pending.push((
                        tokio::time::Instant::now() + Duration::from_millis(delay_ms),
                        buf[..n].to_vec(),
                        to,
                    ));
                }
            }
            for (data, to) in due_now {
                let _ = sock.send_to(&data, to).await;
                task_stats.forwarded.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    LossyUdpProxy {
        addr,
        stats,
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
    }
}

/// Render a 32-byte id the way `TransportPeerEntry::peer_id` does,
/// without pulling a hex dependency into the test.
fn peer_id_hex(id: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in id {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Assert that the live connection `network` holds to `peer` really
/// terminates on `expected`.
///
/// Uses `NetworkNode::transport_diagnostics()`, whose `peer_entries`
/// carry the x0x-visible remote transport address rendered as
/// `udp://<ip>:<port>`. `observed_peer_origin` is deliberately NOT used
/// here: it is documented to return `None` when the observed IP carries
/// no origin information (loopback / unspecified), so on this fixture it
/// could never tell a proxied path from a direct one and would pass
/// vacuously.
///
/// Unknown must not pass. If there is no entry for the peer, or the
/// entry's address is not in the form this assertion knows how to read,
/// this panics with the raw value instead of skipping the check.
async fn assert_path_custody(
    network: &Arc<x0x::network::NetworkNode>,
    peer: &[u8; 32],
    expected: std::net::SocketAddr,
    label: &str,
) {
    let want = peer_id_hex(peer);
    let snapshot = network.transport_diagnostics().await;
    let entry = snapshot
        .peer_entries
        .iter()
        .find(|e| e.peer_id == want)
        .unwrap_or_else(|| {
            panic!(
                "{label}: no x0x-visible connection to peer {want}; path custody unproven — \
                 entries: {:?}",
                snapshot.peer_entries
            )
        });
    let raw = entry.remote_addr.as_str();
    let stripped = raw.strip_prefix("udp://").unwrap_or_else(|| {
        panic!(
            "{label}: remote address {raw:?} is not a UDP transport address; \
             path custody cannot be established from it"
        )
    });
    let got: std::net::SocketAddr = stripped.parse().unwrap_or_else(|e| {
        panic!("{label}: remote address {raw:?} did not parse as a socket address: {e}")
    });
    assert_eq!(
        normalize_loopback(got),
        normalize_loopback(expected),
        "{label}: connection must terminate on the lossy proxy, not on a direct path"
    );
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

    // Path custody, by construction: BOTH discovery hints point at the
    // proxy, never at a real bound address. Seeding the peers' real
    // addresses here would advertise a clean, loss-free path alongside
    // the lossy one, and the lane could then carry the audio over it
    // while this test still asserted a loss-resilience posture it never
    // exercised.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    alice
        .insert_discovered_agent_for_testing(discovered_agent(&bob, proxy.addr, now_secs))
        .await;
    alice.set_contact_trusted_for_testing(bob.agent_id()).await;
    bob.insert_discovered_agent_for_testing(discovered_agent(&alice, proxy.addr, now_secs))
        .await;
    bob.set_contact_trusted_for_testing(alice.agent_id()).await;

    // ...and by observation: the live connection alice holds to bob must
    // really terminate on the proxy.
    assert_path_custody(
        &alice_network,
        &bob.machine_id().0,
        proxy.addr,
        "alice -> bob",
    )
    .await;

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
    let (forwarded, dropped, delayed) = proxy.snapshot();
    eprintln!(
        "lossy proxy diagnostics (not a pass condition): \
         forwarded={forwarded} dropped={dropped} delayed={delayed}"
    );
    proxy.shutdown().await;
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
    // Declare after the transports so unwind freezes before their Drop hooks.
    use x0x::voice::observation::{FailureCapture, Phase};
    let mut capture = FailureCapture::new(bob.machine_id().0, alice.machine_id().0);
    let alice_observation = capture.alice();
    let bob_observation = capture.bob();
    alice_link = alice_link.with_observation(alice_observation.clone());
    bob_link = bob_link.with_observation(bob_observation.clone());
    let alice_events = match alice.network() {
        Some(network) => network.subscribe_all_peer_events().await,
        None => None,
    };
    capture.subscribe(alice_observation, alice_events);
    let bob_events = match bob.network() {
        Some(network) => network.subscribe_all_peer_events().await,
        None => None,
    };
    capture.subscribe(bob_observation.clone(), bob_events);
    capture.phase(Phase::PreChurn);
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
    capture.phase(Phase::Disconnect);
    alice_network
        .disconnect(&bob_peer)
        .await
        .expect("disconnect");
    alice_network
        .connect_addr(bob_addr)
        .await
        .expect("replacement connection");
    capture.phase(Phase::Reconnected);
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
    capture.phase(Phase::PostSendStart);

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

    capture.phase(Phase::PostSendEnd);

    // Count AUDIO frames only: the primed + evicted Data-lane frames
    // also surface here (same inbound queue) and prove their own
    // delivery by arriving at all.
    let mut received = 0usize;
    capture.phase(Phase::ReceiveStart);
    let deadline = Instant::now() + Duration::from_secs(30);
    while received < POST && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, bob_link.receive()).await {
            Ok(Ok((_, ty, _))) => {
                bob_observation.consumed(ty.as_u8());
                if ty == StreamType::Audio {
                    received += 1;
                }
            }
            Ok(Err(e)) => panic!("bob receive failed: {e}"),
            Err(_) => break,
        }
    }
    capture.phase(Phase::ReceiveEnd);
    assert_eq!(
        received, POST,
        "post-churn audio frames must arrive via the reliable lane"
    );
    assert_eq!(
        alice_link.datagram_frames_sent(),
        sent_at_churn,
        "no post-churn frame may leave as a datagram"
    );

    capture.passed();
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
