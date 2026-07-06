//! Local port-forwarder over tailnet byte-streams (#132 T4).
//!
//! `forward add --local 127.0.0.1:PORT --peer <agent> --target 127.0.0.1:PORT`
//! behaves like `ssh -L`: a local TCP listener on machine A tunnels to a
//! loopback service on machine B over a [`crate::streams::PeerStream`].
//!
//! ## Two halves, one gate
//!
//! - **Outbound (the local listener side):** each accepted local TCP
//!   connection opens a `ForwardV1` stream to the peer
//!   ([`crate::Agent::open_peer_stream`], which already enforces the
//!   identity gate), writes the `ForwardHeader`, waits for the peer's
//!   response, and on `connected` bridges the two with `tokio::io::copy`.
//! - **Inbound (the peer's accept side — security-critical):** consumes
//!   `ForwardV1` streams from [`crate::Agent::next_incoming_stream`], reads
//!   the header, and calls [`crate::connect::evaluate_connect_gate`] BEFORE
//!   any `TcpStream::connect`. The stream already cleared the T1 identity
//!   gate (verified + trust `Accept` + not revoked), so the connect gate is
//!   passed `verified=true, trust=Some(Accept)`; its job is the ACL
//!   target-match + loopback re-check. A denial produces a typed
//!   [`crate::connect::ConnectDenialReason`] frame back to the opener and a
//!   `record_denied` counter; zero bytes reach the target.
//!
//! ## Loopback-only (Phase 1)
//!
//! Targets are numeric loopback IPs only (`127.0.0.0/8`, `::1`). A hostname
//! or non-loopback IP in a header is refused before the gate (defense in
//! depth — the ACL loader already rejects non-loopback at load time, and the
//! gate re-checks `is_loopback`).
//!
//! The header codec and the inbound gate decision are pure functions of
//! bytes / resolved inputs so the whole deny/allow matrix is fast unit-
//! testable without a live QUIC pair (the real stream wiring is proven by
//! `tests/tailnet_streams_integration.rs` + T7).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::connect::gate::ConnectDenialReason;
use crate::connect::{evaluate_connect_gate, ConnectDiagnostics, ConnectPolicy};
use crate::error::{NetworkError, NetworkResult};
use crate::identity::{AgentId, MachineId};
use crate::streams::PeerStream;
use crate::trust::TrustDecision;

// Import the ant-quic stream halves under stable names for the bridge helper.
use ant_quic::{HighLevelRecvStream, HighLevelSendStream};

/// Response byte: the inbound side accepted the target and connected.
const RESP_CONNECTED: u8 = 0x01;
/// Response byte: the inbound side denied the target (ACL / loopback / etc.).
const RESP_DENIED: u8 = 0x00;

/// Hard cap on the encoded header size. A loopback `host:port` is tiny; a
/// larger frame is either malformed or an attack — reject rather than read.
const MAX_HEADER_BYTES: u32 = 256;

/// Local connect timeout for the inbound side's `TcpStream::connect`.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Maximum time to read the full forward header (length prefix + body) from a
/// peer before resetting the stream (DoS bound — FIX 2).
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Global cap on concurrently-active INBOUND forward streams (FIX 3). A peer
/// cannot exhaust task/memory beyond this; the (N+1)th is reset + counted.
const MAX_INBOUND_STREAMS: usize = 256;
/// Global cap on concurrently-active OUTBOUND driven connections (FIX 3).
const MAX_OUTBOUND_STREAMS: usize = 256;
/// Per-peer cap on concurrently-active forward streams, inbound + outbound
/// combined (FIX 3). Matches the issue #132 plan's "32 streams/peer" default.
const MAX_STREAMS_PER_PEER: u32 = 32;

/// Forward header — the first framed message on a `ForwardV1` stream.
///
/// `target_host` is a numeric IP only (no DNS); the inbound side refuses
/// anything else before consulting the ACL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardHeader {
    /// Numeric loopback IP the peer wants to reach (e.g. `127.0.0.1`, `::1`).
    pub target_host: String,
    /// TCP port on the loopback target.
    pub target_port: u16,
}

impl ForwardHeader {
    /// Encode as a length-prefixed bincode frame: `u32 BE len || bincode`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body = bincode::serialize(self).unwrap_or_default();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode a length-prefixed frame from a complete buffer. Returns the
    /// consumed byte count alongside the header on success.
    ///
    /// # Errors
    /// - [`ForwardError::Truncated`] — not enough bytes for the length prefix
    ///   or the announced body.
    /// - [`ForwardError::Oversize`] — announced length exceeds
    ///   `MAX_HEADER_BYTES`.
    /// - [`ForwardError::Decode`] — bincode deserialization failed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ForwardError> {
        if buf.len() < 4 {
            return Err(ForwardError::Truncated);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if len > MAX_HEADER_BYTES {
            return Err(ForwardError::Oversize(len));
        }
        let end = 4 + len as usize;
        if buf.len() < end {
            return Err(ForwardError::Truncated);
        }
        let header: Self =
            bincode::deserialize(&buf[4..end]).map_err(|e| ForwardError::Decode(e.to_string()))?;
        Ok((header, end))
    }
}

/// Encode the inbound side's `connected` response (1 byte — copy begins).
#[must_use]
fn encode_response_connected() -> [u8; 1] {
    [RESP_CONNECTED]
}

/// Encode the inbound side's `denied` response: `0x00 || u32 BE len || reason`.
#[must_use]
fn encode_response_denied(reason: ConnectDenialReason) -> Vec<u8> {
    let reason_bytes = serde_json::to_vec(&reason).unwrap_or_default();
    let mut out = Vec::with_capacity(1 + 4 + reason_bytes.len());
    out.push(RESP_DENIED);
    out.extend_from_slice(&(reason_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&reason_bytes);
    out
}

/// Parse the leading response byte: `true` = connected (copy follows),
/// `false` = denied (a framed reason follows).
#[must_use]
fn response_connected(byte: u8) -> Option<bool> {
    match byte {
        RESP_CONNECTED => Some(true),
        RESP_DENIED => Some(false),
        _ => None,
    }
}

/// Errors raised by the forward header codec.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ForwardError {
    /// Not enough bytes to decode a complete frame.
    #[error("truncated forward frame")]
    Truncated,
    /// Announced frame length exceeds the cap.
    #[error("oversize forward frame: {0} bytes")]
    Oversize(u32),
    /// bincode deserialization failed.
    #[error("forward frame decode failed: {0}")]
    Decode(String),
    /// `target_host` is not a numeric loopback IP.
    #[error("target host is not a numeric loopback IP: {0}")]
    NotLoopbackTarget(String),
}

/// Resolve a `(host, port)` to a loopback `SocketAddr`. Numeric IP only — a
/// hostname (including `localhost`) is refused so the ACL can never be
/// bypassed via resolution. This mirrors the ACL loader's loopback/numeric
/// invariant at the runtime accept seam (defense in depth).
fn resolve_loopback_target(
    target_host: &str,
    target_port: u16,
) -> Result<SocketAddr, ForwardError> {
    let ip: IpAddr = target_host
        .parse()
        .map_err(|_| ForwardError::NotLoopbackTarget(target_host.to_string()))?;
    if !crate::connect::is_loopback(ip) {
        return Err(ForwardError::NotLoopbackTarget(target_host.to_string()));
    }
    Ok(SocketAddr::new(ip, target_port))
}

/// Pure inbound gate decision: resolve + ACL-check the requested target.
///
/// The stream has already cleared the T1 identity gate (verified + trust
/// `Accept` + not revoked), so this is the connect-ACL layer: it returns the
/// resolved loopback `SocketAddr` on allow, or the typed denial reason on
/// deny. The caller writes the denial frame + records the counter and must
/// NOT call `TcpStream::connect` on `Err`.
///
/// Extracted pure so the full deny/allow matrix is unit-testable without a
/// live QUIC pair.
fn decide_inbound(
    header: &ForwardHeader,
    policy: &ConnectPolicy,
    agent_id: &AgentId,
    machine_id: &MachineId,
) -> Result<SocketAddr, ConnectDenialReason> {
    // Resolve first: a non-loopback/hostname target is refused before the
    // gate (the gate would also reject it, but resolving gives a precise
    // reason and avoids handing an attacker-resolved address to the ACL).
    let target = resolve_loopback_target(&header.target_host, header.target_port)
        .map_err(|_| ConnectDenialReason::TargetNotLoopback)?;
    evaluate_connect_gate(
        /* verified */ true,
        Some(TrustDecision::Accept),
        policy,
        agent_id,
        machine_id,
        &target,
    )?;
    Ok(target)
}

/// Forwarder-owned diagnostics beyond the connect ACL's allow/deny counters
/// (which live in [`ConnectDiagnostics`]). Tracks local-connect failures and
/// active stream count for observability + limits.
#[derive(Debug, Default)]
pub struct ForwardDiagnostics {
    /// Inbound streams that passed the gate but whose local
    /// `TcpStream::connect` failed (target service down / refused).
    connect_failed: AtomicU64,
    /// Currently active forward streams (inbound + outbound).
    active_streams: AtomicU64,
    /// Streams refused because the global or per-peer concurrency cap was hit
    /// (FIX 3, DoS bound).
    streams_over_cap: AtomicU64,
    /// Streams dropped because the peer was revoked between the T1 accept gate
    /// and the forwarder's header read (FIX 4, stale-authorization window).
    revoked_mid_flight: AtomicU64,
    /// Streams reset because the forward header did not arrive within
    /// `HEADER_READ_TIMEOUT` (FIX 2).
    header_timeout: AtomicU64,
}

impl ForwardDiagnostics {
    /// Record a local-connect failure.
    pub fn record_connect_failed(&self) {
        self.connect_failed.fetch_add(1, Ordering::Relaxed);
    }
    /// Increment active streams; returns the new count.
    pub fn enter_stream(&self) -> u64 {
        self.active_streams.fetch_add(1, Ordering::Relaxed) + 1
    }
    /// Decrement active streams when a stream ends.
    pub fn leave_stream(&self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
    /// Record a stream refused at the concurrency cap (FIX 3).
    pub fn record_over_cap(&self) {
        self.streams_over_cap.fetch_add(1, Ordering::Relaxed);
    }
    /// Record a stream dropped for mid-flight revocation (FIX 4).
    pub fn record_revoked_mid_flight(&self) {
        self.revoked_mid_flight.fetch_add(1, Ordering::Relaxed);
    }
    /// Record a header-read timeout (FIX 2).
    pub fn record_header_timeout(&self) {
        self.header_timeout.fetch_add(1, Ordering::Relaxed);
    }
    /// Current connect-failure count.
    #[must_use]
    pub fn connect_failed(&self) -> u64 {
        self.connect_failed.load(Ordering::Relaxed)
    }
    /// Current active-stream count.
    #[must_use]
    pub fn active_streams(&self) -> u64 {
        self.active_streams.load(Ordering::Relaxed)
    }
    /// Streams refused at the concurrency cap.
    #[must_use]
    pub fn streams_over_cap(&self) -> u64 {
        self.streams_over_cap.load(Ordering::Relaxed)
    }
    /// Streams dropped for mid-flight revocation.
    #[must_use]
    pub fn revoked_mid_flight(&self) -> u64 {
        self.revoked_mid_flight.load(Ordering::Relaxed)
    }
    /// Streams reset for a header-read timeout.
    #[must_use]
    pub fn header_timeout(&self) -> u64 {
        self.header_timeout.load(Ordering::Relaxed)
    }
}

/// Drive the inbound half of a forward: read the header, run the connect
/// gate, connect the local loopback target, and bridge the stream to it.
///
/// The peer identity comes from the [`PeerStream`] (already cleared the T1
/// identity gate). Records allow/deny into `connect_diag` and connect
/// failures into `fwd_diag`. On any failure the stream is closed (the halves
/// are dropped) — zero bytes reach the target on a denial.
pub(crate) async fn handle_inbound(
    mut stream: PeerStream,
    policy: Arc<ConnectPolicy>,
    connect_diag: Arc<ConnectDiagnostics>,
    fwd_diag: Arc<ForwardDiagnostics>,
    revocation_set: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
) {
    let agent_id = stream.agent();
    let machine_id = stream.peer();
    let peer = machine_id;

    // FIX 4 (stale-authorization window): the T1 accept-loop identity gate
    // cleared before this stream was surfaced. A peer revoked in that window
    // must not consume a header read or reach the connect gate. Re-check the
    // shared revocation set BEFORE reading any peer bytes; drop on
    // revocation. (The connect gate would still deny by policy, so this is
    // not a bypass — it closes the per-flow stale-authz window. Full
    // mid-stream teardown is a documented Phase-2 item.)
    {
        let revoked = revocation_set.read().await;
        if revoked.is_agent_revoked(&agent_id) || revoked.is_machine_revoked(&machine_id) {
            fwd_diag.record_revoked_mid_flight();
            tracing::info!(
                target: "x0x::forward",
                agent = %hex::encode(agent_id.as_bytes()),
                machine = %hex::encode(peer.as_bytes()),
                outcome = "drop_revoked_mid_flight",
                "inbound forward: peer revoked after accept — dropping before header read"
            );
            return;
        }
    }

    // FIX 2: bound the header read so a peer that opens a forward stream and
    // then stalls cannot hold a forwarder task (and its concurrency permit).
    // Reset + count on timeout. The declared length prefix is already capped
    // at MAX_HEADER_BYTES inside read_header, so no huge pre-allocation.
    let header =
        match tokio::time::timeout(HEADER_READ_TIMEOUT, read_header(stream.recv_mut())).await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                tracing::info!(
                    target: "x0x::forward",
                    peer = %hex::encode(peer.as_bytes()),
                    error = %e,
                    "inbound forward: header read failed — closing stream"
                );
                return;
            }
            Err(_) => {
                fwd_diag.record_header_timeout();
                tracing::info!(
                    target: "x0x::forward",
                    peer = %hex::encode(peer.as_bytes()),
                    "inbound forward: header read timed out — resetting stream"
                );
                return;
            }
        };

    // Gate: resolve + ACL. On deny, write a typed frame + record, then close.
    let target = match decide_inbound(&header, &policy, &agent_id, &machine_id) {
        Ok(addr) => addr,
        Err(reason) => {
            connect_diag.record_denied(reason);
            let _ = stream
                .send_mut()
                .write_all(&encode_response_denied(reason))
                .await;
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer.as_bytes()),
                ?reason,
                target = %header.target_host,
                port = header.target_port,
                "inbound forward denied at connect gate"
            );
            return;
        }
    };

    // Defense in depth: re-check the resolved target is loopback before
    // connecting (the gate already enforces it; this keeps the invariant
    // local to the connect call site).
    if !target.ip().is_loopback() {
        connect_diag.record_denied(ConnectDenialReason::TargetNotLoopback);
        let _ = stream
            .send_mut()
            .write_all(&encode_response_denied(
                ConnectDenialReason::TargetNotLoopback,
            ))
            .await;
        return;
    }

    // Connect the local loopback target with a bounded timeout.
    let local = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            fwd_diag.record_connect_failed();
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer.as_bytes()),
                target = %target,
                error = %e,
                "inbound forward: local connect failed"
            );
            return;
        }
        Err(_) => {
            fwd_diag.record_connect_failed();
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer.as_bytes()),
                target = %target,
                "inbound forward: local connect timed out"
            );
            return;
        }
    };

    // Signal connected, then bridge. The connect-allow counter records that
    // the gate admitted this flow.
    connect_diag.record_allowed();
    if stream
        .send_mut()
        .write_all(&encode_response_connected())
        .await
        .is_err()
    {
        return;
    }
    let (send, recv) = stream.into_split();
    fwd_diag.enter_stream();
    let _guard = StreamLeaveGuard(Arc::clone(&fwd_diag));
    bridge(local, send, recv).await;
}

/// RAII guard that decrements the active-stream counter when a forward task ends.
struct StreamLeaveGuard(Arc<ForwardDiagnostics>);
impl Drop for StreamLeaveGuard {
    fn drop(&mut self) {
        self.0.leave_stream();
    }
}

/// Bridge a local TCP connection and the peer stream's two halves until one
/// side closes. QUIC provides native flow control; `copy` is bounded by QUIC
/// backpressure so no unbounded buffer is introduced.
async fn bridge(tcp: TcpStream, mut send: HighLevelSendStream, mut recv: HighLevelRecvStream) {
    // Split the TCP socket into owned read/write halves so the two copy tasks
    // can run concurrently without overlapping mutable borrows.
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let to_stream = tokio::io::copy(&mut tcp_read, &mut send);
    let from_stream = tokio::io::copy(&mut recv, &mut tcp_write);
    let _ = tokio::join!(to_stream, from_stream);
}

/// Read a length-prefixed `ForwardHeader` from an async reader.
async fn read_header<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> Result<ForwardHeader, ForwardError> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|_| ForwardError::Truncated)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_HEADER_BYTES {
        return Err(ForwardError::Oversize(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)
        .await
        .map_err(|_| ForwardError::Truncated)?;
    bincode::deserialize(&body).map_err(|e| ForwardError::Decode(e.to_string()))
}

/// Write a length-prefixed `ForwardHeader` to an async writer.
async fn write_header<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    header: &ForwardHeader,
) -> Result<(), NetworkError> {
    use tokio::io::AsyncWriteExt;
    let frame = header.encode();
    w.write_all(&frame)
        .await
        .map_err(|e| NetworkError::StreamError(format!("write forward header: {e}")))
}

// ===========================================================================
// ForwardService — owns the inbound consumer + outbound local listeners.
// ===========================================================================

/// A registered local forward (`forward add`).
#[derive(Debug, Clone, Serialize)]
pub struct ForwardSpec {
    /// Local loopback address the daemon binds (`127.0.0.1:PORT`).
    pub local_addr: SocketAddr,
    /// Peer agent to tunnel to (hex).
    pub peer_agent: AgentId,
    /// Loopback target host on the peer's machine (numeric IP).
    pub target_host: String,
    /// Loopback target port.
    pub target_port: u16,
}

impl ForwardSpec {
    /// The peer agent id as a hex string (for REST/CLI display).
    #[must_use]
    pub fn peer_agent_hex(&self) -> String {
        hex::encode(self.peer_agent.as_bytes())
    }
}

/// A registered forward + its cancellation token (internal).
struct ForwardEntry {
    spec: ForwardSpec,
    cancel: CancellationToken,
}

/// Owns the inbound forward consumer + the outbound local listeners.
///
/// The inbound loop is the sole consumer of `ForwardV1` streams surfaced by
/// [`crate::Agent::next_incoming_stream`]; each is gated by `handle_inbound`
/// (resolve → `evaluate_connect_gate` → connect loopback → bridge). Outbound
/// listeners (`add_forward`) accept local TCP, open a peer stream, write the
/// `ForwardHeader`, and bridge on `connected`.
pub struct ForwardService {
    agent: Arc<crate::Agent>,
    policy: Arc<ConnectPolicy>,
    connect_diag: Arc<ConnectDiagnostics>,
    fwd_diag: Arc<ForwardDiagnostics>,
    /// Registered forwards (spec + cancellation) so `shutdown` / `remove` can
    /// tear down individual listeners and `list` can return them.
    forwards: std::sync::Mutex<Vec<ForwardEntry>>,
    inbound_token: CancellationToken,
    /// FIX 3: global + per-peer concurrency caps. Admission requires a global
    /// permit (held for the stream's lifetime) AND a per-peer slot; a stream
    /// beyond either cap is reset + counted rather than spawned unbounded.
    inbound_permits: Arc<tokio::sync::Semaphore>,
    outbound_permits: Arc<tokio::sync::Semaphore>,
    per_peer: Arc<std::sync::Mutex<HashMap<AgentId, u32>>>,
    /// Shared revocation set for the FIX 4 pre-header re-check.
    revocation_set: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
}

/// RAII per-peer slot: decrements the per-peer counter (and prunes the entry
/// at zero) when dropped, so a forwarder task ending releases the slot.
struct PeerSlot {
    peer: AgentId,
    map: Arc<std::sync::Mutex<HashMap<AgentId, u32>>>,
}
impl Drop for PeerSlot {
    fn drop(&mut self) {
        if let Ok(mut m) = self.map.lock() {
            if let Some(count) = m.get_mut(&self.peer) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    m.remove(&self.peer);
                }
            }
        }
    }
}

/// Holds the global semaphore permit + per-peer slot for the lifetime of one
/// forward stream task. Dropping it (when the task ends) releases both, so the
/// concurrency caps stay accurate even on error/panic paths.
struct Admission {
    _permit: tokio::sync::OwnedSemaphorePermit,
    _slot: PeerSlot,
}

/// FIX 3: try to admit a forward stream against a global permit pool + the
/// shared per-peer map. Free function so both the inbound consumer and the
/// outbound listener (which owns cloned caps) share one admission path.
/// Global cap first (leaves per-peer untouched on failure), then per-peer.
fn admit_to(
    permits: &Arc<tokio::sync::Semaphore>,
    per_peer: &Arc<std::sync::Mutex<HashMap<AgentId, u32>>>,
    peer: AgentId,
) -> Option<Admission> {
    let permit = permits.clone().try_acquire_owned().ok()?;
    let slot = try_peer_slot(per_peer, peer)?;
    Some(Admission {
        _permit: permit,
        _slot: slot,
    })
}

/// Increment the per-peer counter if under [`MAX_STREAMS_PER_PEER`]; returns a
/// [`PeerSlot`] whose Drop decrements it. Fails closed on poison.
fn try_peer_slot(
    map: &Arc<std::sync::Mutex<HashMap<AgentId, u32>>>,
    peer: AgentId,
) -> Option<PeerSlot> {
    let Ok(mut m) = map.lock() else {
        return None;
    };
    let count = m.entry(peer).or_insert(0);
    if *count >= MAX_STREAMS_PER_PEER {
        return None;
    }
    *count += 1;
    Some(PeerSlot {
        peer,
        map: Arc::clone(map),
    })
}

impl ForwardService {
    /// Construct a forwarder over a loaded connect policy + its diagnostics.
    #[must_use]
    pub fn new(
        agent: Arc<crate::Agent>,
        policy: Arc<ConnectPolicy>,
        connect_diag: Arc<ConnectDiagnostics>,
    ) -> Self {
        let revocation_set = agent.revocation_set();
        Self {
            agent,
            policy,
            connect_diag,
            fwd_diag: Arc::new(ForwardDiagnostics::default()),
            forwards: std::sync::Mutex::new(Vec::new()),
            inbound_token: CancellationToken::new(),
            inbound_permits: Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND_STREAMS)),
            outbound_permits: Arc::new(tokio::sync::Semaphore::new(MAX_OUTBOUND_STREAMS)),
            per_peer: Arc::new(std::sync::Mutex::new(HashMap::new())),
            revocation_set,
        }
    }

    /// Forwarder-owned diagnostics (connect-failed + active-stream counters).
    #[must_use]
    pub fn diagnostics(&self) -> &ForwardDiagnostics {
        &self.fwd_diag
    }

    /// FIX 3: try to admit a forward stream against the global + per-peer
    /// concurrency caps. On success returns an [`Admission`] whose lifetime
    /// bounds the stream's task (it releases both slots on drop). On a cap
    /// hit returns `None` — the caller resets the stream + counts it. `inbound`
    /// selects the global permit pool (separate inbound/outbound caps).
    fn admit(&self, peer: AgentId, inbound: bool) -> Option<Admission> {
        let permits = if inbound {
            &self.inbound_permits
        } else {
            &self.outbound_permits
        };
        admit_to(permits, &self.per_peer, peer)
    }

    /// Start the inbound consumer loop. Spawns a task that surfaces
    /// `ForwardV1` streams to `handle_inbound`. Returns immediately.
    pub fn spawn_inbound(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let token = self.inbound_token.clone();
        tokio::spawn(async move {
            tracing::info!(target: "x0x::forward", "inbound forward consumer started");
            loop {
                let stream = tokio::select! {
                    _ = token.cancelled() => break,
                    s = this.agent.next_incoming_stream() => match s {
                        Some(s) => s,
                        None => break,
                    },
                };
                if stream.protocol() != crate::streams::StreamProtocol::ForwardV1 {
                    // T5 (SOCKS5) owns 0x02; until then drop non-forward streams.
                    tracing::debug!(
                        target: "x0x::forward",
                        protocol = ?stream.protocol(),
                        "non-forward inbound stream — not handled by the forwarder"
                    );
                    continue;
                }
                // FIX 3: cap admission before spawning. Over-cap streams are
                // reset (dropped) + counted rather than spawning unbounded.
                let peer_agent = stream.agent();
                let admission = match this.admit(peer_agent, true) {
                    Some(a) => a,
                    None => {
                        this.fwd_diag.record_over_cap();
                        tracing::info!(
                            target: "x0x::forward",
                            agent = %hex::encode(peer_agent.as_bytes()),
                            "inbound forward refused: concurrency cap reached — resetting"
                        );
                        continue;
                    }
                };
                let this = Arc::clone(&this);
                tokio::spawn(async move {
                    let _admission = admission;
                    this.fwd_diag.enter_stream();
                    let _leave = StreamLeaveGuard(Arc::clone(&this.fwd_diag));
                    handle_inbound(
                        stream,
                        Arc::clone(&this.policy),
                        Arc::clone(&this.connect_diag),
                        Arc::clone(&this.fwd_diag),
                        Arc::clone(&this.revocation_set),
                    )
                    .await;
                });
            }
        });
    }
    /// Register a local forward: bind `local_addr`, and for each accepted TCP
    /// connection open a peer stream, write the header, and bridge on
    /// `connected`. Returns the bound local address (useful when port = 0).
    ///
    /// # Errors
    /// `NetworkError` if the local listener cannot be bound.
    pub async fn add_forward(&self, spec: ForwardSpec) -> NetworkResult<SocketAddr> {
        let listener = TcpListener::bind(spec.local_addr).await.map_err(|e| {
            NetworkError::ConnectionFailed(format!("bind {}: {e}", spec.local_addr))
        })?;
        let bound = listener
            .local_addr()
            .map_err(|e| NetworkError::ConnectionFailed(format!("local_addr: {e}")))?;
        let cancel = CancellationToken::new();
        if let Ok(mut forwards) = self.forwards.lock() {
            forwards.push(ForwardEntry {
                spec: spec.clone(),
                cancel: cancel.clone(),
            });
        }

        let agent = Arc::clone(&self.agent);
        let fwd_diag = Arc::clone(&self.fwd_diag);
        let outbound_permits = Arc::clone(&self.outbound_permits);
        let per_peer = Arc::clone(&self.per_peer);
        let peer_agent = spec.peer_agent;
        let header = ForwardHeader {
            target_host: spec.target_host,
            target_port: spec.target_port,
        };
        tokio::spawn(async move {
            tracing::info!(
                target: "x0x::forward",
                local = %bound,
                peer = %hex::encode(peer_agent.as_bytes()),
                "outbound forward listener started"
            );
            loop {
                let (tcp, _) = tokio::select! {
                    _ = cancel.cancelled() => break,
                    a = listener.accept() => match a {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!(
                                target: "x0x::forward",
                                local = %bound,
                                error = %e,
                                "accept failed; listener stopping"
                            );
                            break;
                        }
                    },
                };
                // FIX 3: cap outbound driven connections. Over-cap TCP
                // accepts are dropped (the client sees a refused connection)
                // + counted rather than spawning unbounded.
                let admission = match admit_to(&outbound_permits, &per_peer, peer_agent) {
                    Some(a) => a,
                    None => {
                        fwd_diag.record_over_cap();
                        tracing::info!(
                            target: "x0x::forward",
                            local = %bound,
                            "outbound forward refused: concurrency cap reached — closing local TCP"
                        );
                        continue;
                    }
                };
                let agent = Arc::clone(&agent);
                let fwd_diag = Arc::clone(&fwd_diag);
                let header = header.clone();
                tokio::spawn(async move {
                    let _admission = admission;
                    fwd_diag.enter_stream();
                    let _guard = StreamLeaveGuard(Arc::clone(&fwd_diag));
                    drive_outbound(agent, peer_agent, header, tcp).await;
                });
            }
        });
        Ok(bound)
    }

    /// Snapshot of registered forwards (for `GET /forwards` / `x0x forward list`).
    #[must_use]
    pub fn list_forwards(&self) -> Vec<ForwardSpec> {
        self.forwards
            .lock()
            .map(|f| f.iter().map(|e| e.spec.clone()).collect())
            .unwrap_or_default()
    }

    /// Remove a forward by its bound local address. Cancels the listener.
    /// Returns `true` if a forward was removed.
    pub fn remove_forward(&self, local_addr: SocketAddr) -> bool {
        let mut removed = false;
        if let Ok(mut forwards) = self.forwards.lock() {
            if let Some(pos) = forwards
                .iter()
                .position(|e| e.spec.local_addr == local_addr)
            {
                forwards[pos].cancel.cancel();
                forwards.remove(pos);
                removed = true;
            }
        }
        removed
    }

    /// Tear down every listener + the inbound consumer.
    pub fn shutdown(&self) {
        self.inbound_token.cancel();
        if let Ok(forwards) = self.forwards.lock() {
            for entry in forwards.iter() {
                entry.cancel.cancel();
            }
        }
    }
}

/// Outbound driver: open the peer stream, write the header, read the peer's
/// connect response, and bridge on `connected`. On any failure the local TCP
/// connection is simply closed (the client sees a reset/refused).
async fn drive_outbound(
    agent: Arc<crate::Agent>,
    peer_agent: AgentId,
    header: ForwardHeader,
    tcp: TcpStream,
) {
    let mut stream = match agent
        .open_peer_stream(&peer_agent, crate::streams::StreamProtocol::ForwardV1)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer_agent.as_bytes()),
                error = %e,
                "outbound forward: could not open peer stream"
            );
            return;
        }
    };
    if write_header(stream.send_mut(), &header).await.is_err() {
        return;
    }
    // Read the peer's connect-response byte.
    let mut resp = [0u8; 1];
    if stream.recv_mut().read_exact(&mut resp).await.is_err() {
        return;
    }
    match response_connected(resp[0]) {
        Some(true) => {
            let (send, recv) = stream.into_split();
            bridge(tcp, send, recv).await;
        }
        Some(false) => {
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer_agent.as_bytes()),
                "outbound forward: peer denied at connect gate — closing local TCP"
            );
        }
        None => {
            tracing::info!(
                target: "x0x::forward",
                "outbound forward: malformed connect response — closing local TCP"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::acl::{ConnectAcl, ConnectAllowEntry};

    fn header(host: &str, port: u16) -> ForwardHeader {
        ForwardHeader {
            target_host: host.to_string(),
            target_port: port,
        }
    }

    #[test]
    fn header_frame_round_trips() {
        let h = header("127.0.0.1", 22);
        let bytes = h.encode();
        let (decoded, n) = ForwardHeader::decode(&bytes).expect("decode");
        assert_eq!(decoded, h);
        assert_eq!(n, bytes.len());
    }

    /// Build `len || body` manually for negative cases.
    fn h_frame_with_len(len: u32, body: &[u8]) -> Vec<u8> {
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn header_decode_rejects_truncated_and_oversize() {
        // Too short for the length prefix.
        assert_eq!(
            ForwardHeader::decode(&[0u8, 0]).unwrap_err(),
            ForwardError::Truncated
        );
        // Announces more than available.
        let bytes = h_frame_with_len(10, &[]);
        assert_eq!(
            ForwardHeader::decode(&bytes).unwrap_err(),
            ForwardError::Truncated
        );
        // Oversize announcement.
        let bytes = h_frame_with_len(MAX_HEADER_BYTES + 1, &[]);
        assert_eq!(
            ForwardHeader::decode(&bytes).unwrap_err(),
            ForwardError::Oversize(MAX_HEADER_BYTES + 1)
        );
    }

    #[test]
    fn resolve_rejects_hostnames_and_non_loopback() {
        // Numeric loopback IPs resolve.
        assert!(resolve_loopback_target("127.0.0.1", 22).is_ok());
        assert!(resolve_loopback_target("::1", 22).is_ok());
        // Hostnames (including localhost) are refused — no DNS in the TCB.
        assert_eq!(
            resolve_loopback_target("localhost", 22).unwrap_err(),
            ForwardError::NotLoopbackTarget("localhost".to_string())
        );
        // Non-loopback numeric IPs are refused.
        assert_eq!(
            resolve_loopback_target("10.0.0.1", 22).unwrap_err(),
            ForwardError::NotLoopbackTarget("10.0.0.1".to_string())
        );
    }

    fn policy_with_allow(agent: AgentId, machine: MachineId, target: SocketAddr) -> ConnectPolicy {
        ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: "test".into(),
            loaded_at_unix_ms: 0,
            allow: vec![ConnectAllowEntry {
                description: None,
                agent_id: agent,
                machine_id: machine,
                targets: vec![target],
            }],
        })
    }

    #[test]
    fn decide_inbound_matrix() {
        let agent = AgentId([1u8; 32]);
        let machine = MachineId([2u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();

        // Disabled policy ⇒ ConnectDisabled (default-deny).
        let disabled = ConnectPolicy::default();
        assert_eq!(
            decide_inbound(&header("127.0.0.1", 22), &disabled, &agent, &machine).unwrap_err(),
            ConnectDenialReason::ConnectDisabled
        );

        // Enabled but pair not in ACL ⇒ AgentMachineNotInAcl.
        let other_agent = AgentId([9u8; 32]);
        let policy = policy_with_allow(other_agent, machine, target);
        assert_eq!(
            decide_inbound(&header("127.0.0.1", 22), &policy, &agent, &machine).unwrap_err(),
            ConnectDenialReason::AgentMachineNotInAcl
        );

        // Pair in ACL but target not in its entry ⇒ TargetNotAllowed.
        let policy = policy_with_allow(agent, machine, "127.0.0.1:2222".parse().unwrap());
        assert_eq!(
            decide_inbound(&header("127.0.0.1", 22), &policy, &agent, &machine).unwrap_err(),
            ConnectDenialReason::TargetNotAllowed
        );

        // Happy path: exact (agent, machine, target) ⇒ allow.
        let policy = policy_with_allow(agent, machine, target);
        assert_eq!(
            decide_inbound(&header("127.0.0.1", 22), &policy, &agent, &machine).unwrap(),
            target
        );

        // Non-loopback target ⇒ TargetNotLoopback (refused before the ACL).
        let policy = policy_with_allow(agent, machine, target);
        assert_eq!(
            decide_inbound(&header("10.0.0.1", 22), &policy, &agent, &machine).unwrap_err(),
            ConnectDenialReason::TargetNotLoopback
        );
    }

    #[test]
    fn response_frames_are_well_formed() {
        let connected = encode_response_connected();
        assert_eq!(response_connected(connected[0]), Some(true));
        let denied = encode_response_denied(ConnectDenialReason::ConnectDisabled);
        assert_eq!(denied[0], RESP_DENIED);
        // Reason is a length-prefixed JSON enum value (write-side only — the
        // opener reads the byte + length; ConnectDenialReason is Serialize
        // only, so verify the frame shape rather than round-tripping).
        let len = u32::from_be_bytes([denied[1], denied[2], denied[3], denied[4]]) as usize;
        assert_eq!(
            denied.len(),
            5 + len,
            "denied frame length must match the prefix"
        );
        assert!(len > 0, "a serialized ConnectDenialReason is non-empty");
        assert_eq!(response_connected(RESP_DENIED), Some(false));
        assert_eq!(response_connected(0xFF), None);
    }

    #[test]
    fn admit_enforces_global_and_per_peer_caps() {
        // FIX 3: admission must bound both global concurrency and per-peer
        // concurrency, releasing the global permit when the per-peer check
        // fails so the global pool is not leaked.
        let global = Arc::new(tokio::sync::Semaphore::new(2));
        let per_peer: Arc<std::sync::Mutex<HashMap<AgentId, u32>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let peer_a = AgentId([1u8; 32]);
        let peer_b = AgentId([2u8; 32]);

        // Global cap of 2: two admits across any peers succeed.
        let a1 = admit_to(&global, &per_peer, peer_a).expect("first admit");
        let a2 = admit_to(&global, &per_peer, peer_b).expect("second admit");
        // Third admit fails on the global cap; per_peer must be unchanged for
        // the not-yet-admitted peer (no leak of a partial admission).
        assert!(
            admit_to(&global, &per_peer, peer_a).is_none(),
            "global cap must refuse the third admit"
        );
        // Releasing one global permit re-admits admission.
        drop(a2);
        let a3 = admit_to(&global, &per_peer, peer_b).expect("readmit after release");
        drop(a1);
        drop(a3);

        // Per-peer cap: a fresh large global pool so only the per-peer limit
        // binds. Admit MAX_STREAMS_PER_PEER for one peer, then the next fails.
        let big = Arc::new(tokio::sync::Semaphore::new(1024));
        let pp: Arc<std::sync::Mutex<HashMap<AgentId, u32>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut held = Vec::new();
        for _ in 0..MAX_STREAMS_PER_PEER {
            held.push(admit_to(&big, &pp, peer_a).expect("under per-peer cap"));
        }
        assert!(
            admit_to(&big, &pp, peer_a).is_none(),
            "per-peer cap must refuse the (N+1)th admit for the same peer"
        );
        // A different peer is unaffected (per-peer, not global, is the limit).
        assert!(
            admit_to(&big, &pp, peer_b).is_some(),
            "a second peer must still be admitted under its own per-peer cap"
        );
        // Releasing one slot for peer_a re-opens its cap.
        held.pop();
        assert!(
            admit_to(&big, &pp, peer_a).is_some(),
            "per-peer cap must re-admit after a slot is released"
        );
    }
}
