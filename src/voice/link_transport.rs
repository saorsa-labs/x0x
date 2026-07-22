//! [`LinkTransport`] over ADR-0022 byte streams (saorsa-webrtc V1.2).
//!
//! Wire shape per stream: the x0x protocol prefix
//! ([`StreamProtocol::WebRtcV1`], `0x04`) is written/consumed by the
//! existing open/accept machinery; the **first application byte** is the
//! saorsa-webrtc [`StreamType`] (0x20–0x24); every frame after that is
//! `u32-BE length ‖ payload`. One x0x stream per `(direction, StreamType)`
//! lane, opened lazily on first send.
//!
//! Addressing: x0x reaches peers by [`AgentId`], not socket address — the
//! target agent is fixed at construction and [`LinkTransport::connect`]'s
//! `SocketAddr` argument is recorded for display only. Every open and
//! accept passes the identity gate, trust evaluation, revocation checks,
//! and the connect-ACL pair gate exactly like `ForwardV1/V2` streams.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use saorsa_webrtc_core::link_transport::{
    LinkTransport, LinkTransportError, PeerConnection, StreamType,
};
use tokio::sync::{mpsc, Mutex};

use crate::identity::AgentId;
use crate::streams::{PeerStream, StreamProtocol};
use crate::Agent;

/// Bound on the inbound frame queue. Media consumers drain continuously;
/// a full queue drops the oldest pressure onto QUIC flow control (the
/// per-stream reader simply awaits), so this bounds memory, not loss.
const INBOUND_QUEUE_DEPTH: usize = 1024;

/// Upper bound on a single framed payload (1 MiB). Voice frames are
/// ~200 bytes; anything near this bound is a protocol violation and the
/// lane is dropped.
const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Outbound lane: the send half of an opened `WebRtcV1` stream, keyed by
/// [`StreamType`]. The recv half is parked alongside so the peer's stream
/// state stays open for the lane's lifetime.
struct OutboundLane {
    send: ant_quic::HighLevelSendStream,
    _recv: ant_quic::HighLevelRecvStream,
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
        }
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
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), LinkTransportError> {
        self.running.store(false, Ordering::SeqCst);
        if let Some(task) = self.acceptor_task.lock().await.take() {
            task.abort();
        }
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
}
