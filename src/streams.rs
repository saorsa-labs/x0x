//! Per-peer bidirectional byte-streams over ant-quic (tailnet Phase 1, #132 T1).
//!
//! Builds on [`ant_quic::Node::open_bi`] / [`ant_quic::Node::accept_bi`] to
//! expose reliable, backpressure-correct byte-streams between two x0x peers.
//! These are the substrate for the local port-forwarder (T4, `src/forward/`)
//! and the SOCKS5 listener (T5). The underlying transport is end-to-end
//! post-quantum (ML-KEM-768 / ML-DSA-65); ant-quic relays forward ciphertext
//! only, so streams work identically over direct and relayed connections.
//!
//! ## Wire framing
//!
//! Each application stream carries a single protocol-prefix byte as its first
//! payload byte, demultiplexing stream types on top of ant-quic's own
//! app-vs-internal demux (which already keeps `accept_bi` from surfacing
//! ACK-v2 / MASQUE-relay / message-transport streams):
//!
//! ```text
//! [protocol: u8][protocol-specific bytes...]
//! ```
//!
//! `0x00` is reserved (treated as unknown → reset). See `StreamProtocol`.
//!
//! ## Identity gate — fail closed, in fixed order
//!
//! Both the outbound open ([`crate::Agent::open_peer_stream`]) and the inbound
//! accept loop enforce the same gate, in this order, before any application
//! byte is sent or read:
//!
//! 1. **transport-verified** — ant-quic authenticates the peer's `MachineId`
//!    at the QUIC/TLS layer; an unauthenticated connection can never yield a
//!    stream. Outbound additionally requires the `AgentId → MachineId` binding
//!    to be present in the identity discovery cache (the same `verified`
//!    annotation the direct-DM path uses). On the inbound path the accept
//!    loop resolves **all** agents whose `MachineId` matches the transport-
//!    authenticated peer — the specific opener cannot be distinguished at
//!    this layer (the QUIC session proves the machine, not the agent), so
//!    every resolved agent must clear the remaining gate checks (#192).
//! 2. **trust-accepted** — the local [`TrustDecision`](crate::trust::TrustDecision)
//!    for every `(AgentId, MachineId)` pair on the peer machine must be
//!    `Accept` (`AcceptWithFlag` is rejected, mirroring exec + the connect
//!    gate). Fail-closed for multi-agent machines: a single non-Accept agent
//!    denies the stream.
//! 3. **not revoked** — neither any agent on the machine nor the machine
//!    itself may be in the local revocation set (positive knowledge of
//!    compromise fails closed, mirroring EP3 / EP4 / the relay and direct-DM
//!    gates).
//!
//! Any failure produces a typed `NetworkError` (`PeerNotVerified` /
//! `PeerTrustRejected` / `PeerRevoked`) and the stream is refused or reset
//! with zero application bytes exchanged. This chokepoint is what makes the
//! T4 inbound forwarder safe by construction: it receives only streams that
//! have already cleared the identity gate.

use crate::error::{NetworkError, NetworkResult};
use crate::identity::MachineId;

/// Shared state for the inbound byte-stream accept loop.
///
/// Owns the bounded channel that surfaces identity-gated [`PeerStream`]s to
/// the consumer (the T4 forwarder / a test), plus an idempotent started-flag
/// so [`crate::Agent`] starts exactly one accept loop even if
/// `join_network` races.
pub(crate) struct StreamAccept {
    tx: tokio::sync::mpsc::Sender<PeerStream>,
    rx: std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<PeerStream>>>,
    started: std::sync::atomic::AtomicBool,
}

impl StreamAccept {
    /// New accept state with a bounded surfacing channel.
    pub(crate) fn new(capacity: usize) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        Self {
            tx,
            rx: std::sync::Arc::new(tokio::sync::Mutex::new(rx)),
            started: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Sender half for the accept loop to push gated streams onto.
    pub(crate) fn sender(&self) -> &tokio::sync::mpsc::Sender<PeerStream> {
        &self.tx
    }

    /// Receiver half for the consumer to drain accepted streams.
    pub(crate) fn receiver(
        &self,
    ) -> &std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<PeerStream>>> {
        &self.rx
    }

    /// Try to mark the accept loop as started. Returns `true` if this call is
    /// the winner (the loop should start); `false` if a loop is already running.
    pub(crate) fn start_once(&self) -> bool {
        !self.started.swap(true, std::sync::atomic::Ordering::AcqRel)
    }
}

/// Identity gate decision shared by the outbound open and inbound accept
/// paths (issue #132 T1). Pure function of the resolved inputs so the whole
/// verified/trust/revoked/expired matrix is fast unit-testable without a
/// network.
///
/// Callers resolve `(trust_decision, revoked_agent, revoked_machine, expired)`
/// from the discovery cache / contact store / revocation set first; a missing
/// identity (unknown agent or machine) is surfaced as [`NetworkError::PeerNotVerified`]
/// by the caller before reaching this helper.
///
/// # Gate order (do not reorder — security property)
/// 1. revoked (agent OR machine) ⇒ [`NetworkError::PeerRevoked`]. Revocation
///    is positive knowledge of compromise and supersedes trust; checking it
///    first also avoids revealing trust state to a revoked peer.
/// 2. `expired` (cached `cert_not_after` past expiry + skew) ⇒
///    [`NetworkError::PeerNotVerified`]. EP1 drops expired announcements at
///    ingest, but a previously-cached entry is never re-checked on the live
///    path; without this an expired peer stays trusted until TTL eviction
///    (issue #191). Absent expiry (`cert_not_after == None`, pre-#130 peers)
///    is fail-open — callers pass `expired == false`.
/// 3. `trust_decision != Some(Accept)` ⇒ [`NetworkError::PeerTrustRejected`].
///    Mirrors exec + the connect gate: `AcceptWithFlag` and `None` both deny.
pub(crate) fn stream_gate(
    agent_id: &crate::identity::AgentId,
    trust_decision: Option<crate::trust::TrustDecision>,
    revoked_agent: bool,
    revoked_machine: bool,
    expired: bool,
) -> NetworkResult<()> {
    use crate::trust::TrustDecision;
    if revoked_agent || revoked_machine {
        return Err(NetworkError::PeerRevoked {
            agent_id: agent_id.0,
        });
    }
    if expired {
        return Err(NetworkError::PeerNotVerified {
            agent_id: agent_id.0,
        });
    }
    if trust_decision != Some(TrustDecision::Accept) {
        return Err(NetworkError::PeerTrustRejected {
            agent_id: agent_id.0,
        });
    }
    Ok(())
}

/// Maximum time to wait for a stream's protocol-prefix byte before resetting
/// it. Belt-and-braces behind the per-stream spawn: a peer that opens a QUIC
/// stream and never sends the prefix cannot hold an accept-loop slot — the
/// read runs in the per-stream task and times out here, resetting the stream.
pub const PREFIX_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Protocol-prefix byte carried as the first byte of an application stream.
///
/// `0x00` is deliberately reserved and rejected as unknown so a zeroed/truncated
/// prefix cannot be mistaken for a valid protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamProtocol {
    /// Local port-forwarding (`src/forward/`). Header is a length-prefixed
    /// bincode `{target_host, target_port}`, gated by the connect ACL at the
    /// inbound accept seam.
    ForwardV1 = 0x01,
    /// SOCKS5 dynamic listener (`src/socks/`, T5). Carries the CONNECT target.
    SocksV1 = 0x02,
}

impl StreamProtocol {
    /// Parse a protocol-prefix byte. Returns `None` for `0x00` (reserved) and
    /// any other unassigned byte.
    #[must_use]
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::ForwardV1),
            0x02 => Some(Self::SocksV1),
            _ => None,
        }
    }

    /// The on-wire prefix byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A bidirectional byte-stream to a verified, trusted peer.
///
/// Wraps ant-quic's send/recv halves. The send half implements
/// [`tokio::io::AsyncWrite`] and the recv half implements
/// [`tokio::io::AsyncRead`], so a forwarder bridges a local `TcpStream` to a
/// `PeerStream` with two `tokio::io::copy` tasks (one per direction). QUIC
/// provides native flow-control / backpressure — no intermediate unbounded
/// buffers are introduced.
///
/// The `agents`, `peer`, and `protocol` fields are fixed at open/accept time
/// after the identity gate has cleared; consumers can rely on them without
/// re-checking.
pub struct PeerStream {
    /// All agent identities known (announced) to run on the peer machine
    /// (≥1). On the inbound path these are resolved from the transport-
    /// authenticated `MachineId` via the identity discovery cache; on the
    /// outbound path this is the single target agent the opener selected.
    ///
    /// When the list holds more than one agent the QUIC transport cannot
    /// prove which one opened the stream — only the machine is
    /// authenticated. Downstream authorization (the connect ACL) must
    /// therefore check **every** agent and fail-closed if any is
    /// unauthorized (issue #192). The list reflects announced agents only;
    /// see `docs/connect-acl.md` "Limitations: announced agents only".
    agents: Vec<crate::identity::AgentId>,
    peer: MachineId,
    protocol: StreamProtocol,
    send: ant_quic::HighLevelSendStream,
    recv: ant_quic::HighLevelRecvStream,
}

impl PeerStream {
    /// Construct a stream handle from already-gated halves plus the negotiated
    /// protocol. Called by the Agent open/accept paths after the identity gate
    /// and protocol handshake have succeeded.
    pub(crate) fn new(
        agents: Vec<crate::identity::AgentId>,
        peer: MachineId,
        protocol: StreamProtocol,
        send: ant_quic::HighLevelSendStream,
        recv: ant_quic::HighLevelRecvStream,
    ) -> Self {
        Self {
            agents,
            peer,
            protocol,
            send,
            recv,
        }
    }

    /// The first agent identity on the peer machine. For the common
    /// single-agent-per-machine case this is that agent. When multiple
    /// agents share the peer machine the specific opener cannot be
    /// determined — use [`PeerStream::peer_agents`] for authorization
    /// decisions so the connect ACL checks every agent.
    #[must_use]
    pub fn agent(&self) -> crate::identity::AgentId {
        self.agents[0]
    }

    /// All agent identities known to run on the peer machine. The connect
    /// ACL (`evaluate_connect_gate`) must pass for **every** agent in this
    /// list — fail-closed for multi-agent machines where the transport
    /// authenticates only the machine, not the individual agent (#192).
    #[must_use]
    pub fn peer_agents(&self) -> &[crate::identity::AgentId] {
        &self.agents
    }

    /// The peer's transport-authenticated machine identity.
    #[must_use]
    pub fn peer(&self) -> MachineId {
        self.peer
    }

    /// The negotiated application protocol.
    #[must_use]
    pub fn protocol(&self) -> StreamProtocol {
        self.protocol
    }

    /// Borrow the send (write) half.
    pub fn send_mut(&mut self) -> &mut ant_quic::HighLevelSendStream {
        &mut self.send
    }

    /// Borrow the recv (read) half.
    pub fn recv_mut(&mut self) -> &mut ant_quic::HighLevelRecvStream {
        &mut self.recv
    }

    /// Deconstruct into the owned send/recv halves (e.g. for two-task copy
    /// loops in the forwarder).
    pub fn into_split(self) -> (ant_quic::HighLevelSendStream, ant_quic::HighLevelRecvStream) {
        (self.send, self.recv)
    }
}

/// Write the protocol-prefix byte on a freshly-opened outbound stream.
///
/// Called by the opener immediately after [`ant_quic::Node::open_bi`] so the
/// accept side can demux the stream type.
pub(crate) async fn write_protocol_prefix(
    send: &mut ant_quic::HighLevelSendStream,
    protocol: StreamProtocol,
) -> NetworkResult<()> {
    send.write_all(&[protocol.as_u8()])
        .await
        .map_err(|e| NetworkError::StreamError(format!("write protocol prefix: {e}")))
}

/// Read and validate the protocol-prefix byte on an accepted stream.
///
/// Returns the negotiated protocol, or [`NetworkError::StreamProtocolUnknown`]
/// for a reserved/unassigned byte (the caller resets the stream).
pub(crate) async fn read_protocol_prefix(
    recv: &mut ant_quic::HighLevelRecvStream,
) -> NetworkResult<StreamProtocol> {
    let mut buf = [0u8; 1];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| NetworkError::StreamError(format!("read protocol prefix: {e}")))?;
    StreamProtocol::from_u8(buf[0]).ok_or(NetworkError::StreamProtocolUnknown {
        protocol_byte: buf[0],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_prefix_round_trips() {
        for p in [StreamProtocol::ForwardV1, StreamProtocol::SocksV1] {
            assert_eq!(StreamProtocol::from_u8(p.as_u8()), Some(p));
        }
    }

    #[test]
    fn reserved_and_unassigned_bytes_are_unknown() {
        // 0x00 reserved by design; anything outside the assigned set is unknown.
        for byte in 0x00u8..=0xFF {
            let parsed = StreamProtocol::from_u8(byte);
            match byte {
                0x01 | 0x02 => assert!(parsed.is_some(), "byte {byte:#x} should parse"),
                _ => assert_eq!(parsed, None, "byte {byte:#x} must be unknown"),
            }
        }
    }

    #[test]
    fn stream_gate_matrix() {
        // Issue #132 T1: the identity-gate decision must fail closed in the
        // documented order — revoked supersedes trust (a revoked-but-still-
        // trusted peer is refused, and never learns its trust state); only
        // (not-revoked AND trust==Accept) passes. AcceptWithFlag/None deny.
        use crate::error::NetworkError;
        use crate::identity::AgentId;
        use crate::trust::TrustDecision;

        let agent = AgentId([9u8; 32]);
        let accept = Some(TrustDecision::Accept);
        let accept_with_flag = Some(TrustDecision::AcceptWithFlag);
        let reject = Some(TrustDecision::RejectBlocked);

        // Happy path: trusted + clean.
        assert!(stream_gate(&agent, accept, false, false, false).is_ok());

        // Revocation supersedes trust — even an Accept+trusted peer is refused,
        // and the error is PeerRevoked regardless of trust.
        assert!(matches!(
            stream_gate(&agent, accept, true, false, false),
            Err(NetworkError::PeerRevoked { agent_id }) if agent_id == agent.0
        ));
        assert!(matches!(
            stream_gate(&agent, accept, false, true, false),
            Err(NetworkError::PeerRevoked { .. })
        ));
        // A revoked + untrusted peer surfaces PeerRevoked, NOT the trust
        // reason (no trust-state leak to a compromised key).
        assert!(matches!(
            stream_gate(&agent, reject, true, false, false),
            Err(NetworkError::PeerRevoked { .. })
        ));

        // Trust variants that are NOT plain Accept all deny when not revoked.
        for decision in [accept_with_flag, reject, None] {
            assert!(
                matches!(
                    stream_gate(&agent, decision, false, false, false),
                    Err(NetworkError::PeerTrustRejected { agent_id }) if agent_id == agent.0
                ),
                "decision {decision:?} must deny (only plain Accept passes)"
            );
        }
    }
    // Issue #191 gap 1: a cached peer whose agent certificate has expired
    // past `not_after` MUST be refused at the runtime stream gate, even when
    // it is trusted (Accept) and not revoked. Pre-fix `stream_gate` took no
    // expiry input and returned `Ok` for this case — an expired peer stayed
    // trusted until TTL eviction. Absent expiry (None → caller passes
    // `expired == false`) stays fail-open for pre-#130 peers.
    #[test]
    fn stream_gate_rejects_expired_cert() {
        use crate::error::NetworkError;
        use crate::identity::AgentId;
        use crate::trust::TrustDecision;

        let agent = AgentId([9u8; 32]);
        let accept = Some(TrustDecision::Accept);

        // Expired + trusted + clean ⇒ denied as PeerNotVerified (the binding
        // is no longer trustworthy once its cert has expired).
        assert!(matches!(
            stream_gate(&agent, accept, false, false, true),
            Err(NetworkError::PeerNotVerified { agent_id }) if agent_id == agent.0
        ));

        // Not expired (present-and-valid, or absent) ⇒ the gate passes for a
        // trusted, clean peer — fail-open on absent expiry is preserved.
        assert!(stream_gate(&agent, accept, false, false, false).is_ok());

        // Revocation still supersedes expiry: a revoked-and-expired peer is
        // reported as PeerRevoked (no trust-state leak, consistent order).
        assert!(matches!(
            stream_gate(&agent, accept, true, false, true),
            Err(NetworkError::PeerRevoked { agent_id }) if agent_id == agent.0
        ));
    }
}
