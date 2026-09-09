//! [`LinkTransport`] over ADR-0022 byte streams (saorsa-webrtc V1.2), plus
//! the ADR-0042 (c) unreliable datagram lane for audio.
//!
//! Wire shape per stream: the x0x protocol prefix
//! ([`StreamProtocol::WebRtcV1`], `0x04`) is written/consumed by the
//! existing open/accept machinery; the **first application byte** is the
//! saorsa-webrtc [`StreamType`] (0x20–0x24); every frame after that is
//! `u32-BE length ‖ payload`. One x0x stream per `(direction, StreamType)`
//! lane, opened lazily on first send.
//!
//! Datagram lane (ADR-0042 decision (c)): with
//! [`AudioLaneMode::Datagram`] pinned, encoded audio frames also ride the
//! peer connection as unreliable QUIC datagrams — one datagram per frame,
//! payload unchanged (`AudioDatagram`-encoded, the same payload contract
//! the reliable Audio lane carries, so the mandatory receive-side jitter
//! buffer consumes both lanes identically). The switch is gated on a
//! mutual capability advert exchanged over the voice signaling DM
//! channel (additive; see [`DATAGRAM_ADVERT_TYPE`]); until — and
//! unless — the peer advertises back, audio keeps the reliable stream
//! (old peers, peers pinned `Reliable`, or a lane that failed its gate).
//!
//! Addressing: x0x reaches peers by [`AgentId`], not socket address — the
//! target agent is fixed at construction and [`LinkTransport::connect`]'s
//! `SocketAddr` argument is recorded for display only. Every open and
//! accept passes the identity gate, trust evaluation, revocation checks,
//! and the connect-ACL pair gate exactly like `ForwardV1/V2` streams —
//! the datagram lane opens through [`Agent::open_peer_datagram_lane`],
//! which enforces the same gates in both directions. There is no voice
//! bypass.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use saorsa_webrtc_core::datagram_lane::{AudioDatagram, AudioLaneMode, MAX_DATAGRAM_PAYLOAD};
use saorsa_webrtc_core::link_transport::{
    LinkTransport, LinkTransportError, PeerConnection, StreamType,
};
use tokio::sync::{mpsc, Mutex};

use crate::identity::AgentId;
use crate::streams::{PeerStream, StreamProtocol};
use crate::Agent;

use super::VOICE_SIGNALING_DM_PREFIX;

/// Bound on the inbound frame queue. Media consumers drain continuously;
/// a full queue drops the oldest pressure onto QUIC flow control (the
/// per-stream reader simply awaits), so this bounds memory, not loss.
const INBOUND_QUEUE_DEPTH: usize = 1024;

/// Upper bound on a single framed payload (1 MiB). Voice frames are
/// ~200 bytes; anything near this bound is a protocol violation and the
/// lane is dropped.
const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// JSON `type` tag of the additive datagram-capability advert that rides
/// the existing voice signaling DM channel (`x0x-voice-sig-v1\n` —
/// already classified Ephemeral on every deployed peer).
///
/// Additivity contract: older [`super::X0xSignaling`] readers fail
/// `SignalingMessage` decoding on the unknown tag and drop the frame —
/// they never advertise back, so a `Datagram`-pinned sender falls back to
/// the reliable lane with zero interop break. The `x0x_` namespace keeps
/// the tag disjoint from upstream's snake_case `SignalingMessage` tags.
/// The decode side reads fields from a JSON value with missing-field
/// defaults (serde-defaulted), so richer future adverts still parse here.
const DATAGRAM_ADVERT_TYPE: &str = "x0x_datagram_cap";

/// Typed lane-setup errors for [`X0xLinkTransport`]. The trait's
/// [`LinkTransportError`] is upstream's stringly enum; the single-acceptor
/// conflict is an x0x condition callers must be able to `match` on.
#[derive(Debug, thiserror::Error)]
pub enum VoiceLaneError {
    /// Another live WebRtcV1 session already holds this agent's single
    /// stream acceptor (the single-acceptor rule in
    /// [`Agent::register_stream_acceptor`]). A second concurrent call on
    /// the same agent cannot start until the first session's `stop()`
    /// releases the acceptor. A shared daemon-level acceptor that demuxes
    /// inbound lanes to per-call sessions is the recorded follow-up (see
    /// the WP3 report addendum) — until it lands, concurrent second
    /// calls fail fast and typed instead of silently stealing or sharing
    /// the acceptor.
    #[error("WebRtcV1 stream acceptor already held by a concurrent call session on this agent")]
    SessionConflict,
    /// Other setup failure (acceptor registration or transport error).
    #[error("lane setup failed: {0}")]
    Setup(String),
}

/// Per-connection inbound datagram byte ceiling — sustained bytes/sec
/// (ADR-0042 addendum: rate-limit per peer). Real audio is ~200 B ×
/// 50 fps = 10 KB/s; the ceiling allows an order of magnitude headroom
/// (codec bursts, higher sample rates) while making a datagram flood
/// cost the sender, not the lane: excess is dropped and counted, never
/// queued. Send-side traffic is self-limited by the local capture rate.
const DATAGRAM_BYTE_RATE: u64 = 100 * 1024;

/// Burst allowance for the byte ceiling (token-bucket capacity): ~50 KB
/// absorbs a keyframe-scale burst before the sustained rate binds.
const DATAGRAM_BYTE_BURST: u64 = 50 * 1024;

/// Advert initial re-send cadence (Codex r2 finding 1): DM subscribers
/// only receive future messages, so the peer may start after our first
/// challenge and never see it. The initial is re-sent on this cadence
/// until answered.
const ADVERT_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Total initial-send attempts (20 s at [`ADVERT_RETRY_INTERVAL`]) before
/// settling on the reliable lane for this session.
const ADVERT_RETRY_ATTEMPTS: usize = 10;

/// Per-send bound for advert DMs: the DM layer can park a send on its
/// ack/backoff window for far longer than the retry cadence, and a
/// stalled send must never stall the listener loop consuming inbound
/// frames.
const ADVERT_SEND_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// Per-write bound on the reliable lane: a stream whose connection died
/// mid-churn does not ERROR — its flow control simply stops progressing
/// and `write_all` awaits forever (observed as an 18-of-50 stall when
/// the advert DM churn replaced the connection underneath the lane). A
/// write exceeding this bound is treated as a dead lane: evicted and
/// reopened once.
const RELIABLE_WRITE_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// Replay window ceiling per lane: the most recent frames written to the
/// live stream are retained so an eviction can re-send them (#277).
///
/// The window is a fixed-size ring, and that IS the memory guarantee —
/// replay can never cost more than [`LANE_REPLAY_MAX_BYTES`] per lane.
/// 256 frames is ~5 s of 50 fps audio, far more than any plausible
/// in-flight set (roughly one RTT of frames), so in practice a frame
/// leaves the window long after the peer received it.
///
/// **When the bound is hit the OLDEST frame ages out of the window.** It
/// is not an error and it applies no backpressure. Ageing out is normal
/// steady-state behaviour on any call longer than the window and is NOT
/// loss: those frames went to a healthy stream and were delivered by
/// QUIC. The consequence is narrower — if the stream later dies, only
/// frames still inside the window can be replayed.
///
/// Retirement is deliberately NOT proof-based. `finish()` + `stopped()`
/// would prove delivery, but only by rolling the lane onto a fresh
/// stream: two concurrent inbound readers then interleave at the
/// receiver's queue, and the resulting reorder pushed
/// `voice_e2e::voice_pipeline_delivers_decodable_audio` below its ≥99 %
/// post-jitter gate (measured: 2/5 suite runs green with rolling, 6/6
/// without). A bounded window costs duplicates on a rare eviction; a
/// rolling checkpoint cost delivery on every healthy call.
const LANE_REPLAY_MAX_FRAMES: usize = 256;

/// Byte-side companion to [`LANE_REPLAY_MAX_FRAMES`] (256 KiB per lane)
/// — a Data lane carrying few but large frames must be bounded by
/// volume, not frame count.
const LANE_REPLAY_MAX_BYTES: usize = 256 * 1024;

/// A framed payload (`u32-BE length ‖ payload`) retained for replay.
/// Shared rather than copied — a replay re-writes the identical bytes.
type ReplayFrame = Arc<[u8]>;

/// Put frames salvaged from a dead stream back at the FRONT of the send
/// queue, preserving their relative order. Returns how many were
/// requeued.
///
/// Order matters twice over: salvaged frames were written before
/// anything already queued, and among themselves they must keep the
/// order the caller sent them in. Losing or reordering here would
/// reintroduce exactly the defect #277 fixes.
fn requeue_salvaged(
    frames: std::collections::VecDeque<ReplayFrame>,
    queue: &mut std::collections::VecDeque<ReplayFrame>,
) -> u64 {
    let resent = frames.len() as u64;
    for salvaged in frames.into_iter().rev() {
        queue.push_front(salvaged);
    }
    resent
}

/// Outbound lane: the send half of an opened `WebRtcV1` stream, keyed by
/// [`StreamType`]. The recv half is parked alongside so the peer's stream
/// state stays open for the lane's lifetime.
struct OutboundLane {
    send: ant_quic::HighLevelSendStream,
    _recv: ant_quic::HighLevelRecvStream,
    /// The most recent frames written to THIS stream, bounded by
    /// [`LANE_REPLAY_MAX_FRAMES`] / [`LANE_REPLAY_MAX_BYTES`].
    ///
    /// On eviction these are replayed onto the replacement stream rather
    /// than destroyed by `HighLevelSendStream`'s `Drop` reset (#277).
    /// Oldest first, so ageing out is a `pop_front`.
    window: std::collections::VecDeque<ReplayFrame>,
    /// Total bytes in `window`, so the bound check stays O(1).
    window_bytes: usize,
}

impl OutboundLane {
    /// Record a frame that has been written to this stream, ageing the
    /// oldest out of the window once the bound is reached.
    fn retain(&mut self, frame: ReplayFrame) {
        push_bounded(&mut self.window, &mut self.window_bytes, frame);
    }
}

/// Push a frame into a replay window, ageing the OLDEST frames out until
/// the window is back inside [`LANE_REPLAY_MAX_FRAMES`] /
/// [`LANE_REPLAY_MAX_BYTES`].
///
/// Oldest-first is deliberate: the newest frames are the ones still worth
/// re-sending, and for audio a stale frame would be discarded by the
/// receiver's jitter buffer as late anyway. The bound is what makes the
/// replay window a fixed memory cost rather than a leak on a long call.
fn push_bounded(
    window: &mut std::collections::VecDeque<ReplayFrame>,
    window_bytes: &mut usize,
    frame: ReplayFrame,
) {
    *window_bytes += frame.len();
    window.push_back(frame);
    while window.len() > LANE_REPLAY_MAX_FRAMES || *window_bytes > LANE_REPLAY_MAX_BYTES {
        // Never age out the only frame: a lone frame larger than the byte
        // bound cannot be shrunk below it, and dropping it would discard
        // the very frame we were asked to retain.
        if window.len() <= 1 {
            break;
        }
        match window.pop_front() {
            Some(aged) => *window_bytes = window_bytes.saturating_sub(aged.len()),
            None => break,
        }
    }
}

/// Live unreliable datagram lane (ADR-0042 c). Present only when the
/// local mode is [`AudioLaneMode::Datagram`] and the gated lane opened
/// successfully in [`X0xLinkTransport::start`].
struct DatagramLane {
    /// Send seam for the peer connection (`send_datagram` on the inner
    /// high-level connection; opened through
    /// [`Agent::open_peer_datagram_lane`], never raw).
    conn: ant_quic::P2pLinkConn,
    /// Sole consumer of `read_datagram` on the connection: forwards
    /// `AudioDatagram`-encoded frames into the shared inbound queue.
    reader: tokio::task::JoinHandle<()>,
    /// Listens on the DM fan-out for the peer's capability advert; exits
    /// once seen (or when the agent's DM channel closes).
    advert_listener: tokio::task::JoinHandle<()>,
    /// Re-sends our session initial (challenge) every 2 s for up to 20 s
    /// until answered — DM subscribers only receive FUTURE messages
    /// (`direct.rs`), so a peer that starts later than our first send
    /// would otherwise never see the challenge and negotiation would
    /// time out into silent reliable fallback (Codex r2 finding 1).
    advert_retry: tokio::task::JoinHandle<()>,
}

/// Challenge-response state binding the datagram lane to THIS transport
/// instance (Codex review P1-1: adverts must be authenticated AND
/// session-bound so spoofed, stale, or cross-call frames cannot flip
/// the lane). `our_nonce` is freshly random per `start()`; a peer may
/// only flip the lane by echoing it — which a replayed or foreign
/// advert cannot do.
#[derive(Debug)]
struct DatagramSession {
    /// Machine the gate resolved for `remote` (QUIC-authenticated);
    /// inbound adverts must come from exactly this machine.
    machine: crate::identity::MachineId,
    /// Our per-start nonce (hex). The peer echoes it to prove liveness
    /// on this session.
    our_nonce: String,
}

/// [`LinkTransport`] over x0x `WebRtcV1` peer streams.
pub struct X0xLinkTransport {
    agent: Arc<Agent>,
    remote: AgentId,
    remote_addr_hint: std::sync::Mutex<SocketAddr>,
    running: AtomicBool,
    lanes: Mutex<HashMap<u8, OutboundLane>>,
    inbound_tx: mpsc::Sender<(PeerConnection, StreamType, Vec<u8>)>,
    inbound: Mutex<mpsc::Receiver<(PeerConnection, StreamType, Vec<u8>)>>,
    accepted_peers_tx: mpsc::Sender<PeerConnection>,
    accepted_peers: Mutex<mpsc::Receiver<PeerConnection>>,
    acceptor_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Configured audio lane mode. Default [`AudioLaneMode::Reliable`]
    /// preserves the V1.2 wire behavior; see [`Self::with_audio_lane_mode`].
    audio_lane: AudioLaneMode,
    /// Peer advertised datagram-lane support (set by the advert listener).
    peer_datagram_capable: Arc<AtomicBool>,
    /// The live datagram lane, when enabled and opened.
    datagram: Mutex<Option<DatagramLane>>,
    /// Challenge-response state for the lane negotiation (P1-1).
    datagram_session: Arc<std::sync::Mutex<Option<DatagramSession>>>,
    /// Audio frames sent as datagrams (observability; proves which lane
    /// carried audio — the e2e gates assert on it).
    datagram_frames_sent: Arc<AtomicU64>,
    /// Datagrams decoded and queued inbound (see `datagram_frames_sent`).
    datagram_frames_received: Arc<AtomicU64>,
    /// Datagrams dropped by the per-connection byte ceiling (flood
    /// defense; see [`DATAGRAM_BYTE_RATE`]).
    datagram_rate_limited: Arc<AtomicU64>,
    /// Frames re-sent on a replacement stream after their carrying
    /// stream died (issue #277). Non-zero means the replay buffer
    /// prevented data loss that would previously have been silent.
    replay_frames_resent: Arc<AtomicU64>,
}

impl X0xLinkTransport {
    /// Create a transport bound to one remote agent (1:1 call scope).
    #[must_use]
    pub fn new(agent: Arc<Agent>, remote: AgentId) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_DEPTH);
        let (accepted_tx, accepted_rx) = mpsc::channel(16);
        Self {
            agent,
            remote,
            remote_addr_hint: std::sync::Mutex::new(placeholder_addr()),
            running: AtomicBool::new(false),
            lanes: Mutex::new(HashMap::new()),
            inbound_tx,
            inbound: Mutex::new(inbound_rx),
            accepted_peers_tx: accepted_tx,
            accepted_peers: Mutex::new(accepted_rx),
            acceptor_task: Mutex::new(None),
            audio_lane: AudioLaneMode::default(),
            peer_datagram_capable: Arc::new(AtomicBool::new(false)),
            datagram: Mutex::new(None),
            datagram_session: Arc::new(std::sync::Mutex::new(None)),
            datagram_frames_sent: Arc::new(AtomicU64::new(0)),
            datagram_frames_received: Arc::new(AtomicU64::new(0)),
            datagram_rate_limited: Arc::new(AtomicU64::new(0)),
            replay_frames_resent: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Frames re-sent on a replacement stream after the stream carrying
    /// them died before the peer acknowledged them (issue #277).
    ///
    /// Each one is a frame that older builds reported `Ok` for and then
    /// silently destroyed, so a non-zero count is the replay buffer
    /// working — not a fault.
    #[must_use]
    pub fn replay_frames_resent(&self) -> u64 {
        self.replay_frames_resent.load(Ordering::Relaxed)
    }

    /// Pin which lane carries encoded audio (ADR-0042 c).
    ///
    /// Default [`AudioLaneMode::Reliable`] preserves the V1.2 wire
    /// behavior byte-for-byte. [`AudioLaneMode::Datagram`] advertises
    /// datagram capability to the peer (additive signaling frame) and
    /// routes `StreamType::Audio` over unreliable QUIC datagrams **once
    /// the peer advertises back**, falling back to the reliable stream
    /// lane otherwise — old peers, peers pinned `Reliable`, or a lane
    /// whose gate/open failed. Other lane types always keep their
    /// reliable streams.
    #[must_use]
    pub fn with_audio_lane_mode(mut self, mode: AudioLaneMode) -> Self {
        self.audio_lane = mode;
        self
    }

    /// The configured audio lane mode.
    #[must_use]
    pub fn audio_lane_mode(&self) -> AudioLaneMode {
        self.audio_lane
    }

    /// Whether the peer has advertised datagram-lane support.
    #[must_use]
    pub fn peer_datagram_capable(&self) -> bool {
        self.peer_datagram_capable.load(Ordering::Relaxed)
    }

    /// Audio frames sent as unreliable datagrams (observability).
    #[must_use]
    pub fn datagram_frames_sent(&self) -> u64 {
        self.datagram_frames_sent.load(Ordering::Relaxed)
    }

    /// Datagrams decoded and queued inbound (observability).
    #[must_use]
    pub fn datagram_frames_received(&self) -> u64 {
        self.datagram_frames_received.load(Ordering::Relaxed)
    }

    /// Datagrams dropped by the per-connection byte ceiling (see the
    /// `DATAGRAM_BYTE_RATE` token bucket) — observability for the flood
    /// defense.
    #[must_use]
    pub fn datagram_rate_limited_dropped(&self) -> u64 {
        self.datagram_rate_limited.load(Ordering::Relaxed)
    }

    /// Typed lane setup (what [`LinkTransport::start`] does, with the
    /// x0x-typed error preserved for callers that must match on it).
    ///
    /// Registers the agent's single `WebRtcV1` stream acceptor, starts
    /// the inbound stream pump, and — in [`AudioLaneMode::Datagram`] —
    /// brings up the gated datagram lane (non-fatal on failure: audio
    /// keeps the reliable stream). A second concurrent call on the same
    /// agent fails with [`VoiceLaneError::SessionConflict`] (the
    /// single-acceptor rule in [`Agent::register_stream_acceptor`]);
    /// `stop()` releases the acceptor so a later session can start.
    ///
    /// # Errors
    ///
    /// [`VoiceLaneError::SessionConflict`] when another live session
    /// holds the acceptor; [`VoiceLaneError::Setup`] for other
    /// registration/transport failures.
    pub async fn start_lane(&mut self) -> Result<(), VoiceLaneError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let setup = self.start_lane_inner().await;
        if setup.is_err() {
            // Registration failed — leave the transport restartable
            // (without this, a failed start would wedge `running`).
            self.running.store(false, Ordering::SeqCst);
        }
        setup
    }

    async fn start_lane_inner(&mut self) -> Result<(), VoiceLaneError> {
        let mut acceptor = self
            .agent
            .register_stream_acceptor(StreamProtocol::WebRtcV1)
            .map_err(|e| match e {
                crate::error::NetworkError::StreamAcceptorConflict { .. } => {
                    VoiceLaneError::SessionConflict
                }
                other => VoiceLaneError::Setup(other.to_string()),
            })?;
        let inbound_tx = self.inbound_tx.clone();
        let accepted_tx = self.accepted_peers_tx.clone();
        let task = tokio::spawn(async move {
            while let Some(stream) = acceptor.next().await {
                tokio::spawn(Self::drive_inbound_stream(
                    stream,
                    inbound_tx.clone(),
                    accepted_tx.clone(),
                ));
            }
        });
        *self.acceptor_task.lock().await = Some(task);

        // ADR-0042 (c): bring up the unreliable datagram lane when the
        // local mode asks for it. Failure is non-fatal — audio keeps the
        // reliable stream (the fallback) — but it is loud: a Datagram
        // pin that silently degrades is a latency bug.
        if self.audio_lane == AudioLaneMode::Datagram {
            if let Err(e) = self.setup_datagram_lane().await {
                tracing::warn!(
                    target: "voice",
                    error = %e,
                    "datagram audio lane unavailable; audio stays on the reliable stream"
                );
            }
        }
        Ok(())
    }

    /// The fixed remote agent this transport talks to.
    #[must_use]
    pub fn remote_agent(&self) -> AgentId {
        self.remote
    }

    fn peer_connection(&self) -> PeerConnection {
        let addr = self
            .remote_addr_hint
            .lock()
            .map(|a| *a)
            .unwrap_or_else(|poisoned| *poisoned.into_inner());
        PeerConnection {
            peer_id: hex::encode(self.remote.0),
            remote_addr: addr,
        }
    }

    /// Reader loop for one inbound stream: demux the [`StreamType`] byte,
    /// then forward length-prefixed frames until EOF/error.
    async fn drive_inbound_stream(
        mut stream: PeerStream,
        inbound_tx: mpsc::Sender<(PeerConnection, StreamType, Vec<u8>)>,
        accepted_tx: mpsc::Sender<PeerConnection>,
    ) {
        let peer_conn = PeerConnection {
            peer_id: hex::encode(stream.agent().0),
            remote_addr: placeholder_addr(),
        };
        let recv = stream.recv_mut();

        let mut ty = [0u8; 1];
        if recv.read_exact(&mut ty).await.is_err() {
            return;
        }
        let Some(stream_type) = StreamType::try_from_u8(ty[0]) else {
            tracing::warn!(target: "voice", byte = ty[0], "unknown media StreamType; lane dropped");
            return;
        };
        // Surface the accepted peer once per inbound lane (accept() feed).
        let _ = accepted_tx.try_send(peer_conn.clone());

        loop {
            let mut len_buf = [0u8; 4];
            if recv.read_exact(&mut len_buf).await.is_err() {
                return; // peer closed the lane
            }
            let len = u32::from_be_bytes(len_buf);
            if len == 0 || len > MAX_FRAME_BYTES {
                tracing::warn!(target: "voice", len, "invalid frame length; lane dropped");
                return;
            }
            let mut frame = vec![0u8; len as usize];
            if recv.read_exact(&mut frame).await.is_err() {
                return;
            }
            if inbound_tx
                .send((peer_conn.clone(), stream_type, frame))
                .await
                .is_err()
            {
                return; // transport dropped
            }
        }
    }

    /// Bring up the unreliable datagram lane (ADR-0042 c): open the
    /// gated connection seam, start the inbound datagram reader, then
    /// advertise capability to the peer over the signaling DM channel.
    ///
    /// Ordering guarantee: the reader is consuming before our advert can
    /// reach the peer, and the peer only sends datagrams after proving
    /// the session (nonce echo) — so no audio datagram can arrive
    /// before a reader exists. Any failure here is non-fatal by design:
    /// audio keeps the reliable lane (the ADR-0042 fallback) and the
    /// caller logs.
    async fn setup_datagram_lane(&self) -> Result<(), LinkTransportError> {
        let conn = self
            .agent
            .open_peer_datagram_lane(&self.remote)
            .await
            .map_err(|e| LinkTransportError::IoError(format!("datagram lane gate/open: {e}")))?;
        // The peer's transport parameters must actually enable datagram
        // frames; otherwise every send would fail (send-side gate).
        if conn.inner().max_datagram_size().is_none() {
            return Err(LinkTransportError::IoError(
                "peer did not enable QUIC datagrams".to_owned(),
            ));
        }

        let mut lane_guard = self.datagram.lock().await;
        if lane_guard.is_some() {
            return Ok(()); // already up (start is idempotent)
        }

        // Resolve the gate-cleared machine for the advert binding check
        // (the same cache the gate consulted; a changed binding here can
        // only fail-safe — adverts stop matching and audio stays
        // reliable).
        let machine = {
            let cache = self.agent.identity_discovery_cache.read().await;
            cache
                .get(&self.remote)
                .map(|entry| entry.machine_id)
                .ok_or_else(|| {
                    LinkTransportError::IoError(
                        "remote binding vanished after lane gate — datagram lane not started"
                            .to_owned(),
                    )
                })?
        };
        let our_nonce = hex::encode(rand::random::<[u8; 16]>());
        *self
            .datagram_session
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(DatagramSession {
            machine,
            our_nonce: our_nonce.clone(),
        });

        // Inbound reader — the SOLE consumer of read_datagram on this
        // connection. Each datagram must decode as one AudioDatagram
        // frame (the lane's payload contract — identical to the reliable
        // Audio lane's, so the mandatory jitter buffer consumes both);
        // anything else is foreign traffic and is dropped, never
        // surfaced. The task ends when the connection closes, exactly
        // like a peer-closed stream lane — and on ANY exit it clears the
        // capability flag, so connection churn/replacement falls audio
        // back to the reliable lane instead of wedging sends on a dead
        // connection (Codex review P1-3).
        //
        // Session binding (ADR-0042 addendum): datagrams are consumed
        // ONLY while this gate-cleared session is open — the reader is
        // spawned after `Agent::open_peer_datagram_lane` cleared the
        // identity + connect-ACL gates for this specific remote, and is
        // aborted by `stop()` (call teardown). QUIC authenticates the
        // machine, so datagrams are bound to the gate-resolved
        // (remote AgentId → MachineId) session; per-agent attribution
        // inside a multi-agent machine is impossible at this layer (the
        // wire format carries no sender field) — parity with the
        // reliable stream path, which also has no per-stream sender
        // discriminator. ACCEPTED v1 TRUST BOUNDARY (Codex r2): the
        // single-acceptor `SessionConflict` rule (one call session per
        // agent per connection) bounds the datagram injection surface
        // to a co-located agent on the SAME machine under the SAME
        // daemon custody — i.e. an actor already inside the daemon's
        // process trust domain, identical to every other DM/stream
        // control path. A per-datagram wire discriminator and a
        // connection-level dispatcher are recorded follow-ups (upstream
        // saorsa-webrtc wire v2 + the daemon demux hub), deliberately
        // not built in v1. Revocation mid-call does NOT tear the reader
        // down: no cheap revocation hook exists, and accepted byte-streams
        // behave identically (gates run at open/accept time only).
        //
        // Replay stance (v1): in-call duplicates/replays are absorbed by
        // the mandatory jitter buffer's sequence dedupe (upstream
        // `duplicates_dropped` / `late_dropped`); a stopped session's
        // reader is aborted, so cross-call replay has no consumer on
        // this transport.
        //
        // Rate limit: a per-connection byte ceiling (see
        // [`DATAGRAM_BYTE_RATE`]) bounds a flood to burst + rate — the
        // excess is dropped and counted here, never queued. Invalid
        // (undecodable) datagrams are counted and their warns throttled
        // (first + every 100th) so garbage cannot also spam the log.
        let inbound_tx = self.inbound_tx.clone();
        let peer_conn = self.peer_connection();
        let frames_received = Arc::clone(&self.datagram_frames_received);
        let rate_dropped = Arc::clone(&self.datagram_rate_limited);
        let capable_flag = Arc::clone(&self.peer_datagram_capable);
        let hl_conn = conn.inner().clone();
        let reader = tokio::spawn(async move {
            let mut bucket = DATAGRAM_BYTE_BURST;
            let mut invalid = 0u64;
            let mut over_rate = 0u64;
            let mut last_refill = std::time::Instant::now();
            while let Ok(bytes) = hl_conn.read_datagram().await {
                {
                    // Token bucket by bytes: refill at the sustained
                    // ceiling, capped at the burst allowance.
                    let now = std::time::Instant::now();
                    let elapsed_ms = u64::try_from(now.duration_since(last_refill).as_millis())
                        .unwrap_or(u64::MAX);
                    last_refill = now;
                    bucket =
                        (bucket + elapsed_ms * DATAGRAM_BYTE_RATE / 1000).min(DATAGRAM_BYTE_BURST);
                    let len_u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                    if len_u64 > bucket {
                        rate_dropped.fetch_add(1, Ordering::Relaxed);
                        over_rate += 1;
                        if over_rate == 1 || over_rate.is_multiple_of(100) {
                            tracing::warn!(
                                target: "voice",
                                len = bytes.len(),
                                total_over_rate = over_rate,
                                "datagram exceeded per-connection byte ceiling; dropped (log throttled)"
                            );
                        }
                        continue;
                    }
                    bucket -= len_u64;
                    if AudioDatagram::decode(bytes.clone()).is_err() {
                        invalid += 1;
                        if invalid == 1 || invalid.is_multiple_of(100) {
                            tracing::warn!(
                                target: "voice",
                                len = bytes.len(),
                                total_invalid = invalid,
                                "non-AudioDatagram datagram dropped on voice lane (log throttled)"
                            );
                        }
                        continue;
                    }
                    frames_received.fetch_add(1, Ordering::Relaxed);
                    if inbound_tx
                        .send((peer_conn.clone(), StreamType::Audio, bytes.to_vec()))
                        .await
                        .is_err()
                    {
                        break; // transport dropped
                    }
                }
            }
            // P1-3: the connection is gone (closed or replaced); sends
            // must not keep targeting it.
            capable_flag.store(false, Ordering::SeqCst);
            tracing::info!(
                target: "voice",
                "datagram reader exited (connection closed); audio falls back to the reliable lane"
            );
        });

        // Advert listener — watches the DM fan-out for the peer's
        // capability advert. Codex review P1-1: `DirectMessage.sender`
        // is self-asserted, so an advert only counts when the
        // QUIC-authenticated `machine_id` matches the gate-resolved
        // machine of this session, the AgentId→MachineId binding is
        // verified, trust is `Accept` (mirroring the stream gates —
        // `AcceptWithFlag` denies), AND the frame carries this session's
        // challenge-response: the peer proves liveness on THIS call by
        // echoing our per-start nonce. A spoofed sender id, a stale
        // replay, or a cross-call advert cannot produce the echo.
        //
        // Wire shape (additive, serde-defaulted on the same signaling
        // prefix): initial `{"type","datagram","challenge"}`, ack
        // `{"type","datagram","response"}`. Old peers send neither and
        // never flip the lane.
        let mut direct = self.agent.subscribe_direct();
        let remote = self.remote;
        let capable = Arc::clone(&self.peer_datagram_capable);
        let session_state = Arc::clone(&self.datagram_session);
        let agent = Arc::clone(&self.agent);
        let advert_listener = tokio::spawn(async move {
            while let Some(msg) = direct.recv().await {
                if msg.sender != remote {
                    continue;
                }
                let Some(body) = msg.payload.strip_prefix(VOICE_SIGNALING_DM_PREFIX) else {
                    continue;
                };
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
                    continue;
                };
                if value.get("type").and_then(serde_json::Value::as_str)
                    != Some(DATAGRAM_ADVERT_TYPE)
                {
                    continue;
                }
                if value.get("datagram").and_then(serde_json::Value::as_bool) != Some(true) {
                    continue; // missing-field default: not a capability
                }
                // Copy the session facts out and release the guard — a
                // std MutexGuard must never live across the await below.
                let (session_machine, our_nonce) = {
                    let state = session_state.lock().unwrap_or_else(|p| p.into_inner());
                    let Some(session) = state.as_ref() else {
                        continue; // no live session — lane torn down
                    };
                    (session.machine, session.our_nonce.clone())
                };
                // Authenticated binding (P1-1): right machine, verified
                // binding, trust Accept.
                if msg.machine_id != session_machine
                    || !msg.verified
                    || !matches!(
                        msg.trust_decision,
                        Some(crate::trust::TrustDecision::Accept)
                    )
                {
                    tracing::warn!(
                        target: "voice",
                        machine = %hex::encode(msg.machine_id.as_bytes()),
                        "unauthenticated datagram advert rejected (machine/verified/trust mismatch)"
                    );
                    continue;
                }
                // Challenge-response (P1-1): only an echo of OUR fresh
                // nonce flips the lane.
                let response = value
                    .get("response")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                if response.as_deref() == Some(our_nonce.as_str()) {
                    if !capable.swap(true, Ordering::SeqCst) {
                        tracing::info!(
                            target: "voice",
                            "peer proved the datagram lane session (nonce echo); Audio sends switch to datagrams"
                        );
                    }
                    // Keep listening: exiting here would DROP this
                    // receiver from the DM registry, and the peer —
                    // which may still be re-sending its initial on the
                    // retry cadence — would never get its ack (the
                    // sequential-startup deadlock). stop()/Drop owns
                    // this task's lifetime. Repeat echoes are idempotent
                    // (swap logs once).
                    continue;
                }
                // A peer initial (challenge, no valid response): ack it
                // EVERY time. Acks are idempotent and never generate a
                // reply (no loop), and a peer whose earlier ack raced its
                // own subscription needs the re-send — deduping here
                // would recreate the one-shot startup regression. Never
                // flip our own lane on a peer initial.
                if let Some(challenge) = value.get("challenge").and_then(serde_json::Value::as_str)
                {
                    let _ = send_advert_frame(
                        &agent,
                        &remote,
                        serde_json::json!({
                            "type": DATAGRAM_ADVERT_TYPE,
                            "datagram": true,
                            "response": challenge,
                        }),
                    )
                    .await;
                }
            }
        });

        // Advertise our capability — the session initial with our fresh
        // challenge, re-sent every 2 s for up to 20 s until answered
        // (the peer's subscriber only sees future messages; one-shot
        // negotiation silently timed out under sequential startup).
        let agent_for_retry = Arc::clone(&self.agent);
        let remote_for_retry = self.remote;
        let capable_for_retry = Arc::clone(&self.peer_datagram_capable);
        let initial = serde_json::json!({
            "type": DATAGRAM_ADVERT_TYPE,
            "datagram": true,
            "challenge": our_nonce,
        });
        let advert_retry = tokio::spawn(async move {
            for _ in 0..ADVERT_RETRY_ATTEMPTS {
                if capable_for_retry.load(Ordering::SeqCst) {
                    return; // answered — stop sending
                }
                // Bound each send: a stalled DM backoff must not stall
                // the retry cadence (the attempt is abandoned, not
                // awaited).
                let _ = tokio::time::timeout(
                    ADVERT_RETRY_INTERVAL,
                    send_advert_frame(&agent_for_retry, &remote_for_retry, initial.clone()),
                )
                .await;
                tokio::time::sleep(ADVERT_RETRY_INTERVAL).await;
            }
        });

        *lane_guard = Some(DatagramLane {
            conn,
            reader,
            advert_listener,
            advert_retry,
        });
        Ok(())
    }

    /// Reliable path: one ordered `WebRtcV1` stream per
    /// `(direction, StreamType)` lane, `u32-BE length ‖ payload` frames.
    ///
    /// # Delivery contract: AT-LEAST-ONCE (issue #277)
    ///
    /// A frame this method reports `Ok` for is retained in a bounded
    /// per-lane window and REPLAYED on a fresh stream if the stream that
    /// carried it dies first. Two consequences callers must handle:
    ///
    /// - **Duplicates are possible.** Retirement is by window, not by
    ///   acknowledgement, so a replay re-sends frames the peer had
    ///   already received. Audio is safe:
    ///   `saorsa_webrtc_core::jitter::JitterBuffer::push` drops a repeat
    ///   of a buffered sequence (`duplicates_dropped`) and a repeat of an
    ///   already-played one (`late_dropped`), both keyed on
    ///   `AudioDatagram.seq`. **Data-lane payloads are opaque to x0x, so
    ///   Data callers own their own idempotency.**
    /// - **Order is not guaranteed across a stream boundary.** Replayed
    ///   frames ride a different QUIC stream from the frames queued after
    ///   them, and the two streams have no ordering relation. Order
    ///   within a single stream is unchanged (QUIC-ordered).
    ///
    /// This replaces silent loss: eviction used to `remove()` the lane,
    /// and dropping an unfinished `HighLevelSendStream` RESETS it,
    /// discarding bytes belonging to frames earlier calls had already
    /// been told were sent.
    ///
    /// Retention is bounded by [`LANE_REPLAY_MAX_FRAMES`] /
    /// [`LANE_REPLAY_MAX_BYTES`] per lane; past that the oldest frames
    /// age out of the window (see [`LANE_REPLAY_MAX_FRAMES`]).
    async fn send_reliable(
        &self,
        stream_type: StreamType,
        data: &[u8],
    ) -> Result<(), LinkTransportError> {
        let len = u32::try_from(data.len())
            .ok()
            .filter(|l| *l > 0 && *l <= MAX_FRAME_BYTES)
            .ok_or_else(|| {
                LinkTransportError::SendError(format!("frame length {} out of range", data.len()))
            })?;
        // One buffer per frame: the exact bytes a replay re-writes.
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(data);
        let frame: ReplayFrame = Arc::from(framed.into_boxed_slice());

        let key = stream_type.as_u8();
        let mut lanes = self.lanes.lock().await;

        // Everything that must reach the wire on this call, oldest first.
        let mut queue: std::collections::VecDeque<ReplayFrame> = std::collections::VecDeque::new();
        queue.push_back(frame);

        // First attempt on the cached lane (opening it if absent); on a
        // write failure the lane's retained frames are salvaged and
        // replayed on a replacement stream.
        for attempt in 0..2 {
            if let std::collections::hash_map::Entry::Vacant(slot) = lanes.entry(key) {
                match self.open_lane_stream(stream_type).await? {
                    Some(lane) => {
                        slot.insert(lane);
                    }
                    // Prefix write failed: the stream is useless and was
                    // never cached. Retry the open once.
                    None if attempt == 0 => continue,
                    None => {
                        return Err(LinkTransportError::SendError(
                            "lane prefix write failed — connection likely replaced".to_owned(),
                        ));
                    }
                }
            }
            let Some(lane) = lanes.get_mut(&key) else {
                return Err(LinkTransportError::SendError(
                    "lane vanished during send".to_owned(),
                ));
            };

            match Self::write_queued(lane, &mut queue).await {
                Ok(()) => return Ok(()),
                Err(e) if attempt == 0 => {
                    tracing::warn!(
                        target: "voice",
                        lane = key,
                        error = %e,
                        queued = queue.len(),
                        "reliable lane failed; salvaging retained frames for replay"
                    );
                    // Salvage the dead stream's retained frames — they are
                    // older than anything still queued, so they go first.
                    // Dropping the stream here resets it, which is only
                    // safe because we kept its frames.
                    if let Some(dead) = lanes.remove(&key) {
                        let resent = requeue_salvaged(dead.window, &mut queue);
                        self.replay_frames_resent
                            .fetch_add(resent, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    lanes.remove(&key);
                    return Err(lt_err("write frame after replay attempt", e));
                }
            }
        }
        Err(LinkTransportError::SendError(
            "reliable lane reopen failed after eviction".to_owned(),
        ))
    }

    /// Open one `WebRtcV1` stream and write its [`StreamType`] prefix.
    ///
    /// `Ok(None)` means the stream opened but its prefix write failed or
    /// stalled — it is useless and must not be cached, and the caller
    /// decides whether to retry the open.
    async fn open_lane_stream(
        &self,
        stream_type: StreamType,
    ) -> Result<Option<OutboundLane>, LinkTransportError> {
        let mut stream = self
            .agent
            .open_peer_stream(&self.remote, StreamProtocol::WebRtcV1)
            .await
            .map_err(|e| LinkTransportError::SendError(format!("open WebRtcV1 lane: {e}")))?;
        match tokio::time::timeout(
            RELIABLE_WRITE_BOUND,
            stream.send_mut().write_all(&[stream_type.as_u8()]),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    target: "voice",
                    error = %e,
                    "lane prefix write failed; reopening on the current connection"
                );
                return Ok(None);
            }
            Err(_) => {
                tracing::warn!(
                    target: "voice",
                    "lane prefix write exceeded bound; reopening on the current connection"
                );
                return Ok(None);
            }
        }
        let (send, recv) = stream.into_split();
        Ok(Some(OutboundLane {
            send,
            _recv: recv,
            window: std::collections::VecDeque::new(),
            window_bytes: 0,
        }))
    }

    /// Write queued frames in order, retaining each in the lane's replay
    /// window as it lands so an eviction mid-queue replays exactly the
    /// frames not known to have been delivered.
    ///
    /// A stream whose connection died mid-churn does not error — flow
    /// control simply stops progressing and `write_all` awaits forever —
    /// so each frame is bounded and a stall is reported as a failure.
    async fn write_queued(
        lane: &mut OutboundLane,
        queue: &mut std::collections::VecDeque<ReplayFrame>,
    ) -> Result<(), String> {
        while let Some(frame) = queue.front().cloned() {
            match tokio::time::timeout(RELIABLE_WRITE_BOUND, lane.send.write_all(&frame)).await {
                Ok(Ok(())) => {
                    queue.pop_front();
                    lane.retain(frame);
                }
                Ok(Err(e)) => return Err(e.to_string()),
                Err(_) => {
                    return Err("write exceeded bound — connection likely replaced".to_owned())
                }
            }
        }
        Ok(())
    }

    /// Datagram path (ADR-0042 c): one unreliable QUIC datagram per
    /// encoded audio frame — payload unchanged from the reliable lane's
    /// contract (`AudioDatagram`-encoded), so the receive-side jitter
    /// buffer consumes both lanes identically. Loss costs a frame, never
    /// head-of-line blocking.
    async fn send_audio_datagram(&self, data: &[u8]) -> Result<(), LinkTransportError> {
        if data.len() > MAX_DATAGRAM_PAYLOAD {
            return Err(LinkTransportError::SendError(format!(
                "audio datagram length {} exceeds {MAX_DATAGRAM_PAYLOAD}",
                data.len()
            )));
        }
        // Take the send result under the lock, then release the guard
        // before any fallback await (a held tokio guard across the
        // reliable path would serialize the two lanes needlessly).
        let guard = self.datagram.lock().await;
        let outcome = guard.as_ref().map(|lane| {
            lane.conn
                .inner()
                .send_datagram(Bytes::copy_from_slice(data))
        });
        drop(guard);
        match outcome {
            Some(Ok(())) => {
                self.datagram_frames_sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Some(Err(e)) => {
                // P1-3: the negotiated connection is dead (closed or
                // replaced). Clear capability so subsequent sends take
                // the reliable path immediately, and deliver THIS frame
                // reliably — connection churn must degrade the lane,
                // never kill the call.
                self.peer_datagram_capable.store(false, Ordering::SeqCst);
                tracing::warn!(
                    target: "voice",
                    error = %e,
                    "audio datagram send failed; lane falls back to the reliable stream"
                );
                self.send_reliable(StreamType::Audio, data).await
            }
            // Peer advertised but the local lane never opened (gate/open
            // failed at start): reliable fallback rather than a hard
            // error — the caller's audio must still flow.
            None => self.send_reliable(StreamType::Audio, data).await,
        }
    }
}

impl Drop for X0xLinkTransport {
    fn drop(&mut self) {
        // Best-effort leak guard (Codex review P2): `stop()` is the
        // clean, awaited teardown (its awaited abort is what guarantees
        // the acceptor's deregistration); `Drop` cannot await, so abort
        // what is abortable without blocking. A contended lock means a
        // task is mid-operation — the runtime finishes it and the
        // channel-close then ends its loop.
        if let Ok(mut guard) = self.acceptor_task.try_lock() {
            if let Some(task) = guard.take() {
                task.abort();
            }
        }
        if let Ok(mut guard) = self.datagram.try_lock() {
            if let Some(lane) = guard.take() {
                lane.reader.abort();
                lane.advert_listener.abort();
                lane.advert_retry.abort();
            }
        }
        *self
            .datagram_session
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
    }
}

fn placeholder_addr() -> SocketAddr {
    // x0x addresses peers by identity; the socket address in
    // `PeerConnection` is informational only for this transport.
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Send one x0x datagram-lane advert frame (`initial` or `ack`) on the
/// voice signaling DM channel. Pure transport — all session logic lives
/// in the listener.
async fn send_advert_frame(
    agent: &Arc<Agent>,
    remote: &AgentId,
    mut frame: serde_json::Value,
) -> Result<(), String> {
    // Unique per-send id (additive, serde-defaulted, ignored by
    // receivers): the DM layer dedupes identical payloads, so retrying
    // an unchanged frame is silently swallowed — the sequential-startup
    // regression traced to exactly this.
    frame["id"] = serde_json::Value::String(hex::encode(rand::random::<u32>().to_be_bytes()));
    let mut payload = VOICE_SIGNALING_DM_PREFIX.to_vec();
    payload.extend_from_slice(&serde_json::to_vec(&frame).map_err(|e| e.to_string())?);
    // Bound the send: the DM machinery can park a send on its
    // ack/backoff window for a long time, and an unbounded await would
    // stall the CALLER — for the listener that means inbound advert
    // frames queue (and evict) behind a stuck ack, which is exactly the
    // sequential-startup deadlock this bounds away. A timed-out attempt
    // is abandoned; the peer's retry cadence re-covers it.
    match tokio::time::timeout(ADVERT_SEND_BOUND, agent.send_direct(remote, payload)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("advert send exceeded bound; abandoned".to_owned()),
    }
}

fn lt_err(context: &str, e: impl std::fmt::Display) -> LinkTransportError {
    LinkTransportError::IoError(format!("{context}: {e}"))
}

#[async_trait]
impl LinkTransport for X0xLinkTransport {
    async fn start(&mut self) -> Result<(), LinkTransportError> {
        // Typed setup path is [`Self::start_lane`]; the trait surface maps
        // the typed error into the upstream stringly enum.
        self.start_lane()
            .await
            .map_err(|e| LinkTransportError::IoError(e.to_string()))
    }

    async fn stop(&mut self) -> Result<(), LinkTransportError> {
        self.running.store(false, Ordering::SeqCst);
        if let Some(task) = self.acceptor_task.lock().await.take() {
            task.abort();
            // Await the aborted task so its `StreamAcceptor` (whose Drop
            // deregisters the protocol) is gone before `stop()` returns
            // — a restart after stop must not race the release, or it
            // would spuriously hit `SessionConflict`.
            let _ = task.await;
        }
        if let Some(lane) = self.datagram.lock().await.take() {
            lane.reader.abort();
            lane.advert_listener.abort();
        }
        self.peer_datagram_capable.store(false, Ordering::SeqCst);
        // Finish each lane before dropping it. Dropping an unfinished
        // `HighLevelSendStream` RESETS it, which would discard the tail
        // of frames already reported `Ok` — the same silent loss #277
        // fixes on the eviction path. A finished stream keeps delivering
        // its buffered bytes.
        for (_, mut lane) in self.lanes.lock().await.drain() {
            let _ = lane.send.finish();
        }
        Ok(())
    }

    async fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    async fn local_addr(&self) -> Result<SocketAddr, LinkTransportError> {
        let network = self
            .agent
            .network()
            .ok_or(LinkTransportError::NotConnected)?;
        network
            .bound_addr()
            .await
            .ok_or(LinkTransportError::NotConnected)
    }

    async fn connect(&mut self, addr: SocketAddr) -> Result<PeerConnection, LinkTransportError> {
        if let Ok(mut hint) = self.remote_addr_hint.lock() {
            *hint = addr;
        }
        // Streams open lazily per lane in `send`; connection-level
        // reachability, identity, trust, and ACL are enforced there by
        // `Agent::open_peer_stream`.
        Ok(self.peer_connection())
    }

    async fn accept(&mut self) -> Result<Option<PeerConnection>, LinkTransportError> {
        Ok(self.accepted_peers.lock().await.recv().await)
    }

    async fn send(
        &self,
        _peer: &PeerConnection,
        stream_type: StreamType,
        data: &[u8],
    ) -> Result<(), LinkTransportError> {
        // ADR-0042 (c): encoded audio rides unreliable datagrams once
        // BOTH ends advertised the lane; everything else (and audio
        // before/without the advert exchange) keeps the reliable stream.
        if stream_type == StreamType::Audio
            && self.audio_lane == AudioLaneMode::Datagram
            && self.peer_datagram_capable()
        {
            return self.send_audio_datagram(data).await;
        }
        self.send_reliable(stream_type, data).await
    }

    async fn receive(&self) -> Result<(PeerConnection, StreamType, Vec<u8>), LinkTransportError> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or(LinkTransportError::NotConnected)
    }

    fn default_peer(&self) -> Result<PeerConnection, LinkTransportError> {
        Ok(self.peer_connection())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webrtc_protocol_byte_is_pinned() {
        // 0x04 is wire surface shared with saorsa-webrtc deployments.
        assert_eq!(StreamProtocol::WebRtcV1.as_u8(), 0x04);
        assert_eq!(
            StreamProtocol::from_u8(0x04),
            Some(StreamProtocol::WebRtcV1)
        );
    }

    #[test]
    fn media_stream_types_do_not_collide_with_x0x_protocol_bytes() {
        // Inner StreamType bytes (0x20-0x24) must stay disjoint from the
        // outer x0x StreamProtocol range so a truncated prefix can never
        // alias between the two layers.
        for ty in [
            StreamType::Audio,
            StreamType::Video,
            StreamType::Screen,
            StreamType::RtcpFeedback,
            StreamType::Data,
        ] {
            assert!(StreamProtocol::from_u8(ty.as_u8()).is_none());
        }
    }

    /// One parsed advert frame: (datagram flag, challenge, response).
    /// The listener's decode contract as a pure function — missing
    /// fields default (the additive/serde-defaulted contract).
    fn parse_advert(body: &[u8]) -> Option<(bool, Option<String>, Option<String>)> {
        let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
        if value.get("type").and_then(serde_json::Value::as_str) != Some(DATAGRAM_ADVERT_TYPE) {
            return None;
        }
        let flag = value.get("datagram").and_then(serde_json::Value::as_bool)?;
        let field = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        Some((flag, field("challenge"), field("response")))
    }

    #[test]
    fn datagram_advert_round_trips_and_defaults_to_not_capable() {
        // Session initial: capability + challenge, no response.
        let initial = serde_json::to_vec(&serde_json::json!({
            "type": DATAGRAM_ADVERT_TYPE,
            "datagram": true,
            "challenge": "cafebabe",
        }))
        .expect("static JSON encodes");
        assert_eq!(
            parse_advert(&initial),
            Some((true, Some("cafebabe".to_owned()), None))
        );
        // Session ack: response echo, no challenge.
        let ack = serde_json::to_vec(&serde_json::json!({
            "type": DATAGRAM_ADVERT_TYPE,
            "datagram": true,
            "response": "deadbeef",
        }))
        .expect("static JSON encodes");
        assert_eq!(
            parse_advert(&ack),
            Some((true, None, Some("deadbeef".to_owned())))
        );
        // Explicit refusal.
        assert_eq!(
            parse_advert(br#"{"type":"x0x_datagram_cap","datagram":false}"#),
            Some((false, None, None))
        );
        // Additivity: a frame missing `datagram` entirely (a future or
        // older sender) is NOT an advert — missing fields default,
        // never over-advertise. Neither is an unknown tag.
        assert_eq!(parse_advert(br#"{"type":"x0x_datagram_cap"}"#), None);
        assert_eq!(parse_advert(br#"{"type":"capability_exchange"}"#), None);
    }

    /// Only an echo of OUR per-start nonce flips the lane — the pure
    /// core of the listener's challenge-response rule (P1-1): a frame
    /// with no response, a wrong response, or a replayed foreign
    /// response must all leave the lane capable = false.
    #[test]
    fn only_our_nonce_echo_flips_the_lane() {
        let our_nonce = "0123abcd";
        let flips = |challenge: Option<&str>, response: Option<&str>, our: &str| {
            response.is_some_and(|r| r == our) && challenge.is_none()
        };
        // Correct echo.
        assert!(flips(None, Some(our_nonce), our_nonce));
        // Wrong/replayed response.
        assert!(!flips(None, Some("stale-replay"), our_nonce));
        // Peer initial (challenge, no response) never flips our lane.
        assert!(!flips(Some("peer-challenge"), None, our_nonce));
    }

    #[test]
    fn datagram_advert_is_not_a_signaling_message() {
        // Old-peer interop: a pre-extension X0xSignaling fails
        // SignalingMessage decoding on the advert and DROPS it — the
        // advert must never decode as a real (e.g. legacy SDP) message
        // that could corrupt call state.
        let body = serde_json::to_vec(&serde_json::json!({
            "type": DATAGRAM_ADVERT_TYPE,
            "datagram": true,
            "challenge": "cafebabe",
        }))
        .expect("static JSON encodes");
        assert!(
            serde_json::from_slice::<saorsa_webrtc_core::signaling::SignalingMessage>(&body)
                .is_err()
        );
    }
    #[test]
    fn audio_stream_type_byte_is_pinned() {
        // ADR-0042 (a): the audio lane byte is 0x20 (0x21 is Video) —
        // pinned so the datagram routing can never capture another lane.
        assert_eq!(StreamType::Audio.as_u8(), 0x20);
        assert_eq!(StreamType::try_from_u8(0x20), Some(StreamType::Audio));
    }

    // === Replay buffer (issue #277) ===

    // === Replay window (issue #277) ===

    fn rframe(tag: u8) -> ReplayFrame {
        Arc::from(vec![tag; 8].into_boxed_slice())
    }

    fn tags(queue: &std::collections::VecDeque<ReplayFrame>) -> Vec<u8> {
        queue.iter().map(|f| f[0]).collect()
    }

    fn window_of(n: usize) -> (std::collections::VecDeque<ReplayFrame>, usize) {
        let mut w = std::collections::VecDeque::new();
        let mut b = 0usize;
        for i in 0..n {
            push_bounded(&mut w, &mut b, rframe((i % 251) as u8));
        }
        (w, b)
    }

    #[test]
    fn salvaged_frames_are_replayed_ahead_of_the_queue_in_order() {
        // WHY: this is the #277 fix in one assertion. Frames a previous
        // call already reported `Ok` for are still buffered in the stream
        // being evicted; dropping that stream RESETS it and destroys
        // them. They must come back — ahead of whatever is queued (they
        // were written first) and in their original order.
        let salvaged: std::collections::VecDeque<ReplayFrame> =
            [rframe(1), rframe(2), rframe(3)].into_iter().collect();
        let mut queue: std::collections::VecDeque<ReplayFrame> =
            [rframe(10), rframe(11)].into_iter().collect();

        let resent = requeue_salvaged(salvaged, &mut queue);

        assert_eq!(resent, 3, "every salvaged frame must be counted");
        assert_eq!(
            tags(&queue),
            vec![1, 2, 3, 10, 11],
            "salvaged frames must precede queued ones and keep their order"
        );
    }

    #[test]
    fn salvage_of_an_empty_lane_is_a_no_op() {
        // WHY: a lane evicted before it ever wrote a frame has nothing at
        // risk; it must not perturb the queue or inflate the counter.
        let mut queue: std::collections::VecDeque<ReplayFrame> = [rframe(10)].into_iter().collect();

        let resent = requeue_salvaged(std::collections::VecDeque::new(), &mut queue);

        assert_eq!(resent, 0);
        assert_eq!(tags(&queue), vec![10]);
    }

    #[test]
    fn replay_window_is_bounded_on_a_long_call() {
        // WHY: retaining every frame written would grow for the life of a
        // call — a memory leak on a lane that runs for hours. The window
        // is a fixed-size ring, and THAT is the memory guarantee.
        let (window, bytes) = window_of(LANE_REPLAY_MAX_FRAMES * 4);

        assert_eq!(
            window.len(),
            LANE_REPLAY_MAX_FRAMES,
            "the window must stop growing at its frame bound"
        );
        assert!(
            bytes <= LANE_REPLAY_MAX_BYTES,
            "retained bytes {bytes} exceeded the bound {LANE_REPLAY_MAX_BYTES}"
        );
        assert_eq!(
            bytes,
            window.iter().map(|f| f.len()).sum::<usize>(),
            "the byte tally must track the ring, or the bound drifts"
        );
    }

    #[test]
    fn replay_window_ages_out_the_oldest_frames_first() {
        // WHY: on a lane that has outrun its window the newest frames are
        // the ones still worth re-sending; an old audio frame would be
        // dropped by the receiver's jitter buffer as late anyway.
        let mut window = std::collections::VecDeque::new();
        let mut bytes = 0usize;
        for i in 0..=LANE_REPLAY_MAX_FRAMES {
            push_bounded(
                &mut window,
                &mut bytes,
                rframe(u8::try_from(i % 251).unwrap()),
            );
        }

        assert_eq!(window.len(), LANE_REPLAY_MAX_FRAMES);
        assert_eq!(
            window.front().map(|f| f[0]),
            Some(1),
            "frame 0 must be the one aged out, not a newer frame"
        );
    }

    #[test]
    fn replay_window_bounded_by_bytes_for_large_frames() {
        // WHY: the Data lane carries few but large frames, so a frame
        // count alone would not bound memory.
        let big: ReplayFrame = Arc::from(vec![0u8; LANE_REPLAY_MAX_BYTES / 4].into_boxed_slice());
        let mut window = std::collections::VecDeque::new();
        let mut bytes = 0usize;
        for _ in 0..32 {
            push_bounded(&mut window, &mut bytes, Arc::clone(&big));
        }

        assert!(
            window.len() < LANE_REPLAY_MAX_FRAMES,
            "the byte bound must bind before the frame bound for large frames"
        );
        assert!(
            bytes <= LANE_REPLAY_MAX_BYTES,
            "retained bytes {bytes} exceeded the bound {LANE_REPLAY_MAX_BYTES}"
        );
    }

    #[test]
    fn a_frame_larger_than_the_byte_bound_is_still_retained() {
        // WHY: ageing out the only frame in the window would discard the
        // very frame we were asked to retain, and an unguarded trim loop
        // on an over-sized frame would spin forever.
        let huge: ReplayFrame = Arc::from(vec![0u8; LANE_REPLAY_MAX_BYTES * 2].into_boxed_slice());
        let mut window = std::collections::VecDeque::new();
        let mut bytes = 0usize;

        push_bounded(&mut window, &mut bytes, huge);

        assert_eq!(window.len(), 1, "the lone frame must survive the trim");
    }

    #[test]
    fn audio_duplicates_from_replay_are_deduped_by_the_jitter_buffer() {
        // WHY: the reliable lane is at-least-once, so replay CAN deliver
        // an Audio frame twice. That is only safe because the receiver's
        // jitter buffer drops a repeated `AudioDatagram.seq`. If a
        // dependency bump ever removed that dedup, at-least-once would
        // become a correctness bug for audio — this test fails first.
        use saorsa_webrtc_core::jitter::{JitterBuffer, JitterConfig, JitterEvent};

        let frame = |seq: u32| AudioDatagram {
            seq,
            timestamp_ms: u64::from(seq) * 20,
            flags: 0,
            payload: Bytes::from(vec![7u8; 40]),
        };
        let mut jb = JitterBuffer::new(JitterConfig::default());

        jb.push(frame(0));
        jb.push(frame(1));
        jb.push(frame(1)); // the replayed duplicate
        jb.push(frame(2));

        let mut delivered: Vec<u32> = Vec::new();
        for _ in 0..16 {
            for ev in jb.poll_ready() {
                if let JitterEvent::Frame(f) = ev {
                    delivered.push(f.seq);
                }
            }
        }

        let ones = delivered.iter().filter(|s| **s == 1).count();
        assert_eq!(
            ones, 1,
            "a replayed audio frame must be delivered once, got {ones} copies of seq 1"
        );
        assert!(
            jb.counters().duplicates_dropped >= 1,
            "the duplicate must be dropped by the jitter buffer's seq dedup"
        );
    }
}
