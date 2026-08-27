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

/// Outbound lane: the send half of an opened `WebRtcV1` stream, keyed by
/// [`StreamType`]. The recv half is parked alongside so the peer's stream
/// state stays open for the lane's lifetime.
struct OutboundLane {
    send: ant_quic::HighLevelSendStream,
    _recv: ant_quic::HighLevelRecvStream,
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
    /// Audio frames sent as datagrams (observability; proves which lane
    /// carried audio — the e2e gates assert on it).
    datagram_frames_sent: Arc<AtomicU64>,
    /// Datagrams decoded and queued inbound (see `datagram_frames_sent`).
    datagram_frames_received: Arc<AtomicU64>,
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
            datagram_frames_sent: Arc::new(AtomicU64::new(0)),
            datagram_frames_received: Arc::new(AtomicU64::new(0)),
        }
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
    /// reach the peer, and the peer only sends datagrams after seeing our
    /// advert — so no audio datagram can arrive before a reader exists.
    /// Any failure here is non-fatal by design: audio keeps the reliable
    /// lane (the ADR-0042 fallback) and the caller logs.
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

        // Inbound reader — the SOLE consumer of read_datagram on this
        // connection. Each datagram must decode as one AudioDatagram
        // frame (the lane's payload contract — identical to the reliable
        // Audio lane's, so the mandatory jitter buffer consumes both);
        // anything else is foreign traffic and is dropped, never
        // surfaced. The task ends when the connection closes, exactly
        // like a peer-closed stream lane.
        let inbound_tx = self.inbound_tx.clone();
        let peer_conn = self.peer_connection();
        let frames_received = Arc::clone(&self.datagram_frames_received);
        let hl_conn = conn.inner().clone();
        let reader = tokio::spawn(async move {
            loop {
                match hl_conn.read_datagram().await {
                    Ok(bytes) => {
                        if AudioDatagram::decode(bytes.clone()).is_err() {
                            tracing::warn!(
                                target: "voice",
                                len = bytes.len(),
                                "non-AudioDatagram datagram dropped on voice lane"
                            );
                            continue;
                        }
                        frames_received.fetch_add(1, Ordering::Relaxed);
                        if inbound_tx
                            .send((peer_conn.clone(), StreamType::Audio, bytes.to_vec()))
                            .await
                            .is_err()
                        {
                            return; // transport dropped
                        }
                    }
                    Err(_) => return, // connection closed — lane ends
                }
            }
        });

        // Advert listener — watches the DM fan-out for the peer's
        // capability advert. Only the fixed remote's frames count.
        let mut direct = self.agent.subscribe_direct();
        let remote = self.remote;
        let capable = Arc::clone(&self.peer_datagram_capable);
        let advert_listener = tokio::spawn(async move {
            while let Some(msg) = direct.recv().await {
                if msg.sender != remote {
                    continue;
                }
                let Some(body) = msg.payload.strip_prefix(VOICE_SIGNALING_DM_PREFIX) else {
                    continue;
                };
                // Missing-field defaults: an advert without `"datagram":
                // true` (or without the field at all) is not a capability.
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                    if value.get("type").and_then(serde_json::Value::as_str)
                        == Some(DATAGRAM_ADVERT_TYPE)
                        && value.get("datagram").and_then(serde_json::Value::as_bool) == Some(true)
                    {
                        capable.store(true, Ordering::Relaxed);
                        tracing::info!(
                            target: "voice",
                            "peer advertised the datagram audio lane; Audio sends switch to datagrams"
                        );
                        return;
                    }
                }
            }
        });

        // Advertise our capability — additive frame on the signaling
        // channel. A failed DM send leaves the lane up (the reader still
        // drains) but the peer will never switch to datagrams toward us;
        // audio stays reliable in that direction until the next start.
        let mut payload = VOICE_SIGNALING_DM_PREFIX.to_vec();
        payload.extend_from_slice(
            &serde_json::to_vec(&serde_json::json!({
                "type": DATAGRAM_ADVERT_TYPE,
                "datagram": true,
            }))
            .map_err(|e| LinkTransportError::IoError(format!("encode advert: {e}")))?,
        );
        if let Err(e) = self.agent.send_direct(&self.remote, payload).await {
            tracing::warn!(
                target: "voice",
                error = %e,
                "datagram capability advert not delivered; audio stays reliable"
            );
        }

        *lane_guard = Some(DatagramLane {
            conn,
            reader,
            advert_listener,
        });
        Ok(())
    }
    /// Reliable path: one ordered `WebRtcV1` stream per
    /// `(direction, StreamType)` lane, `u32-BE length ‖ payload` frames.
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

        let mut lanes = self.lanes.lock().await;
        if let std::collections::hash_map::Entry::Vacant(slot) = lanes.entry(stream_type.as_u8()) {
            let mut stream = self
                .agent
                .open_peer_stream(&self.remote, StreamProtocol::WebRtcV1)
                .await
                .map_err(|e| LinkTransportError::SendError(format!("open WebRtcV1 lane: {e}")))?;
            stream
                .send_mut()
                .write_all(&[stream_type.as_u8()])
                .await
                .map_err(|e| lt_err("write StreamType byte", e))?;
            let (send, recv) = stream.into_split();
            slot.insert(OutboundLane { send, _recv: recv });
        }
        // Entry guaranteed by the insert above; avoid unwrap per house rules.
        let Some(lane) = lanes.get_mut(&stream_type.as_u8()) else {
            return Err(LinkTransportError::SendError(
                "lane vanished during send".to_owned(),
            ));
        };
        lane.send
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| lt_err("write frame length", e))?;
        lane.send
            .write_all(data)
            .await
            .map_err(|e| lt_err("write frame body", e))?;
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
        let lane = self.datagram.lock().await;
        let Some(lane) = lane.as_ref() else {
            // Peer advertised but the local lane never opened (gate/open
            // failed at start): reliable fallback rather than a hard
            // error — the caller's audio must still flow.
            drop(lane);
            return self.send_reliable(StreamType::Audio, data).await;
        };
        lane.conn
            .inner()
            .send_datagram(Bytes::copy_from_slice(data))
            .map_err(|e| LinkTransportError::SendError(format!("audio datagram: {e}")))?;
        self.datagram_frames_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn placeholder_addr() -> SocketAddr {
    // x0x addresses peers by identity; the socket address in
    // `PeerConnection` is informational only for this transport.
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn lt_err(context: &str, e: impl std::fmt::Display) -> LinkTransportError {
    LinkTransportError::IoError(format!("{context}: {e}"))
}

#[async_trait]
impl LinkTransport for X0xLinkTransport {
    async fn start(&mut self) -> Result<(), LinkTransportError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut acceptor = self
            .agent
            .register_stream_acceptor(StreamProtocol::WebRtcV1)
            .map_err(|e| lt_err("register WebRtcV1 acceptor", e))?;
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

    async fn stop(&mut self) -> Result<(), LinkTransportError> {
        self.running.store(false, Ordering::SeqCst);
        if let Some(task) = self.acceptor_task.lock().await.take() {
            task.abort();
        }
        if let Some(lane) = self.datagram.lock().await.take() {
            lane.reader.abort();
            lane.advert_listener.abort();
        }
        self.peer_datagram_capable.store(false, Ordering::SeqCst);
        self.lanes.lock().await.clear();
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

    /// The advert body as `X0xLinkTransport` writes it on the wire.
    fn advert_body(datagram: bool) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": DATAGRAM_ADVERT_TYPE,
            "datagram": datagram,
        }))
        .expect("advert JSON is static and always encodes")
    }

    /// The advert-decode predicate from `setup_datagram_lane`'s listener,
    /// as a pure function over a DM body (missing fields default — the
    /// additive/serde-defaulted contract).
    fn advertises_datagram(body: &[u8]) -> bool {
        serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|value| {
            value.get("type").and_then(serde_json::Value::as_str) == Some(DATAGRAM_ADVERT_TYPE)
                && value.get("datagram").and_then(serde_json::Value::as_bool) == Some(true)
        })
    }

    #[test]
    fn datagram_advert_round_trips_and_defaults_to_not_capable() {
        // Full advert: capable.
        assert!(advertises_datagram(&advert_body(true)));
        // Explicit refusal.
        assert!(!advertises_datagram(&advert_body(false)));
        // Additivity: an advert missing the `datagram` field entirely (a
        // future/older sender) must decode as NOT capable — missing
        // fields default, never panic, never over-advertise.
        assert!(!advertises_datagram(br#"{"type":"x0x_datagram_cap"}"#));
        // Unknown tags are not adverts.
        assert!(!advertises_datagram(br#"{"type":"capability_exchange"}"#));
    }

    #[test]
    fn datagram_advert_is_not_a_signaling_message() {
        // Old-peer interop: a pre-extension X0xSignaling fails
        // SignalingMessage decoding on the advert and DROPS it — the
        // advert must never decode as a real (e.g. legacy SDP) message
        // that could corrupt call state.
        let body = advert_body(true);
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
}
