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
//!   target-match + loopback re-check. The gate checks **every** agent on
//!   the peer machine (the QUIC transport authenticates the machine, not
//!   the specific opener) and fails-closed if any is unauthorized (#192).
//!   A denial produces a typed [`crate::connect::ConnectDenialReason`] frame
//!   back to the opener and a `record_denied` counter; zero bytes reach the
//!   target.
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
use crate::identity::{AgentId, AgentKeypair, MachineId};
use crate::streams::{PeerStream, StreamProtocol};
use crate::trust::TrustDecision;

// Import the ant-quic stream halves under stable names for the bridge helper,
// plus the ML-DSA-65 sign/verify primitives for ForwardV2 attestation.
use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::{HighLevelRecvStream, HighLevelSendStream, MlDsaPublicKey};

/// Response byte: the inbound side accepted the target and connected.
const RESP_CONNECTED: u8 = 0x01;
/// Response byte: the inbound side denied the target (ACL / loopback / etc.).
const RESP_DENIED: u8 = 0x00;

/// Hard cap on the encoded header size. A loopback `host:port` is tiny; a
/// larger frame is either malformed or an attack — reject rather than read.
const MAX_HEADER_BYTES: u32 = 256;

/// Hard cap on the encoded V2 header size. The ML-DSA-65 signature is ~3.3 KB;
/// a V2 frame larger than this is malformed or an attack.
const MAX_HEADER_V2_BYTES: u32 = 4096;

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

/// Domain separator for ForwardV2 attestation signatures (#204).
///
/// Prevents a signature from being replayed across protocol contexts — the
/// signed bytes always begin with this prefix so a signature over a forward
/// header can never be confused with (or substituted for) an agent-card or
/// certificate signature.
const FORWARD_V2_ATTESTATION_DOMAIN: &[u8] = b"x0x-forward-v2-attestation";

/// Forward header with agent attestation (`ForwardV2`, #204).
///
/// Carries the opener's `agent_id` plus an ML-DSA-65 signature over the
/// header's signable bytes. The inbound side verifies the signature against
/// the **cached** agent public key (from the discovery cache), confirms the
/// agent is on the transport-authenticated machine, then ACL-checks that
/// specific agent. This closes the unannounced-agent window: the opener
/// proves its identity cryptographically, independent of whether its
/// announcement has propagated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardV2Header {
    /// Numeric loopback IP the peer wants to reach (e.g. `127.0.0.1`, `::1`).
    pub target_host: String,
    /// TCP port on the loopback target.
    pub target_port: u16,
    /// The opener's agent identity (proves which agent opened the stream).
    pub opener_agent_id: AgentId,
    /// ML-DSA-65 signature over [`ForwardV2Header::signable_bytes`].
    pub signature: Vec<u8>,
}

impl ForwardV2Header {
    /// Build an unsigned V2 header (signature empty — call `sign` to attest).
    #[must_use]
    pub fn new(target_host: String, target_port: u16, opener_agent_id: AgentId) -> Self {
        Self {
            target_host,
            target_port,
            opener_agent_id,
            signature: Vec::new(),
        }
    }

    /// Canonical bytes signed by the opener to produce `signature`.
    ///
    /// Deterministic, domain-prefixed, length-prefixed encoding of every
    /// semantic field. Excludes `signature` itself. Mirrors the `AgentCard`
    /// signing scheme (`src/groups/card.rs`) for consistency.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(FORWARD_V2_ATTESTATION_DOMAIN);
        // length-prefixed target_host
        buf.extend_from_slice(&(self.target_host.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.target_host.as_bytes());
        // target_port
        buf.extend_from_slice(&self.target_port.to_le_bytes());
        // opener_agent_id (fixed 32 bytes)
        buf.extend_from_slice(&self.opener_agent_id.0);
        buf
    }

    /// Sign this header with the opener's agent keypair.
    ///
    /// Populates `signature`. The signed bytes commit to the opener's
    /// `agent_id` (which is `SHA-256` of the signing key) so the recipient
    /// can verify the binding.
    ///
    /// # Errors
    /// Returns `ForwardError::AttestationSign` if ML-DSA-65 signing fails.
    pub fn sign(&mut self, keypair: &AgentKeypair) -> Result<(), ForwardError> {
        let sig = sign_with_ml_dsa(keypair.secret_key(), &self.signable_bytes())
            .map_err(|e| ForwardError::AttestationSign(format!("{e:?}")))?;
        self.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Verify the attestation signature against a cached agent public key.
    ///
    /// Checks that the provided `agent_public_key` hashes to the header's
    /// `opener_agent_id` (binding — a recipient cannot be fooled by a swapped
    /// key), then verifies the ML-DSA-65 signature over `signable_bytes`.
    ///
    /// # Errors
    /// - [`ForwardError::AttestationMissing`] — `signature` is empty.
    /// - [`ForwardError::AttestationKeyMismatch`] — the key does not hash to
    ///   `opener_agent_id`.
    /// - [`ForwardError::AttestationInvalid`] — signature verification failed.
    pub fn verify_attestation(&self, agent_public_key: &[u8]) -> Result<(), ForwardError> {
        if self.signature.is_empty() {
            return Err(ForwardError::AttestationMissing);
        }
        let pubkey = MlDsaPublicKey::from_bytes(agent_public_key)
            .map_err(|e| ForwardError::AttestationKeyMismatch(format!("bad pubkey: {e:?}")))?;
        // Binding: the key must hash to the claimed agent_id.
        let derived = AgentId::from_public_key(&pubkey);
        if derived != self.opener_agent_id {
            return Err(ForwardError::AttestationKeyMismatch(format!(
                "agent_id {} does not match key-derived id {}",
                hex::encode(self.opener_agent_id.as_bytes()),
                hex::encode(derived.as_bytes()),
            )));
        }
        let sig = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|e| ForwardError::AttestationInvalid(format!("bad sig: {e:?}")))?;
        verify_with_ml_dsa(&pubkey, &self.signable_bytes(), &sig)
            .map_err(|e| ForwardError::AttestationInvalid(format!("verify: {e:?}")))?;
        Ok(())
    }

    /// Encode as a length-prefixed bincode frame: `u32 BE len || bincode`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body = bincode::serialize(self).unwrap_or_default();
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode a length-prefixed V2 frame from a complete buffer. Returns the
    /// consumed byte count alongside the header on success.
    ///
    /// # Errors
    /// - [`ForwardError::Truncated`] — not enough bytes for the length prefix
    ///   or the announced body.
    /// - [`ForwardError::Oversize`] — announced length exceeds
    ///   `MAX_HEADER_V2_BYTES`.
    /// - [`ForwardError::Decode`] — bincode deserialization failed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ForwardError> {
        if buf.len() < 4 {
            return Err(ForwardError::Truncated);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if len > MAX_HEADER_V2_BYTES {
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
    /// ForwardV2 attestation: the header carries no signature.
    #[error("forward v2 attestation missing")]
    AttestationMissing,
    /// ForwardV2 attestation: the agent public key does not hash to the
    /// claimed `opener_agent_id` (binding failure), or the key bytes are
    /// unparseable.
    #[error("forward v2 attestation key mismatch: {0}")]
    AttestationKeyMismatch(String),
    /// ForwardV2 attestation: the ML-DSA-65 signature is invalid or
    /// unparseable.
    #[error("forward v2 attestation invalid: {0}")]
    AttestationInvalid(String),
    /// ForwardV2 attestation: signing failed (internal crypto error).
    #[error("forward v2 attestation sign failed: {0}")]
    AttestationSign(String),
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
/// **Multi-agent fail-closed (#192):** `agents` holds every agent known to
/// run on the transport-authenticated peer machine (from the discovery
/// cache — see docs/connect-acl.md "Limitations: announced agents only"
/// for the residual unannounced-agent window). The gate must pass for
/// **every** agent — if any is unauthorized the forward is denied. When
/// the machine hosts a single agent (the common case) this reduces to the
/// existing exact-pair check. When it hosts multiple the QUIC transport
/// cannot prove which agent opened the stream, so every announced agent
/// must be authorized.
///
/// Extracted pure so the full deny/allow matrix is unit-testable without a
/// live QUIC pair.
fn decide_inbound(
    header: &ForwardHeader,
    policy: &ConnectPolicy,
    agents: &[AgentId],
    machine_id: &MachineId,
) -> Result<SocketAddr, ConnectDenialReason> {
    // Resolve first: a non-loopback/hostname target is refused before the
    // gate (the gate would also reject it, but resolving gives a precise
    // reason and avoids handing an attacker-resolved address to the ACL).
    let target = resolve_loopback_target(&header.target_host, header.target_port)
        .map_err(|_| ConnectDenialReason::TargetNotLoopback)?;
    // Fail-closed: every agent on the peer machine must be authorized.
    for agent_id in agents {
        evaluate_connect_gate(
            /* verified */ true,
            Some(TrustDecision::Accept),
            policy,
            agent_id,
            machine_id,
            &target,
        )?;
    }
    Ok(target)
}

/// Inbound gate decision for a `ForwardV2` attested stream (#204).
///
/// The opener has cryptographically proven its identity (the ML-DSA-65
/// signature verifies against the cached agent public key), so — unlike the
/// [`decide_inbound`] multi-agent path — the ACL is checked for the **single
/// attested agent**, not every agent on the machine. This closes the
/// unannounced-agent window: even if a hostile agent has not yet propagated
/// its announcement, its key is absent from the cache and the attestation
/// fails-closed.
///
/// Fail-closed on: agent not in the discovery cache, no cached public key,
/// agent's cached machine ≠ transport peer, signature/key binding failure,
/// signature verification failure, or ACL denial.
async fn decide_inbound_attested(
    header: &ForwardV2Header,
    policy: &ConnectPolicy,
    peer_machine: &MachineId,
    discovery_cache: &std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<AgentId, crate::DiscoveredAgent>>,
    >,
) -> Result<SocketAddr, ConnectDenialReason> {
    // Resolve the target first (same as V1 — a non-loopback target is
    // refused before the attestation check, so an unverified peer learns
    // nothing about which agents exist).
    let target = resolve_loopback_target(&header.target_host, header.target_port)
        .map_err(|_| ConnectDenialReason::TargetNotLoopback)?;

    // Look up the opener in the discovery cache. An agent absent from the
    // cache (unannounced or revoked-and-evicted) cannot be attested.
    let cached = {
        let cache = discovery_cache.read().await;
        cache.get(&header.opener_agent_id).cloned()
    };
    let agent = cached.ok_or(ConnectDenialReason::AttestationFailed)?;

    // Confirm the agent is on the transport-authenticated machine. A valid
    // signature from an agent on a *different* machine is still a
    // cross-machine impersonation attempt.
    if agent.machine_id != *peer_machine {
        return Err(ConnectDenialReason::AgentNotOnMachine);
    }

    // Verify the attestation against the cached key. An empty key (pre-v2
    // announcement without a cert) means the agent cannot be attested.
    if agent.agent_public_key.is_empty() {
        return Err(ConnectDenialReason::AttestationFailed);
    }
    header
        .verify_attestation(&agent.agent_public_key)
        .map_err(|_| ConnectDenialReason::AttestationFailed)?;

    // The opener is now cryptographically authenticated: ACL-check that
    // specific agent (not every agent on the machine).
    evaluate_connect_gate(
        /* verified */ true,
        Some(TrustDecision::Accept),
        policy,
        &header.opener_agent_id,
        peer_machine,
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
    discovery_cache: Arc<
        tokio::sync::RwLock<std::collections::HashMap<AgentId, crate::DiscoveredAgent>>,
    >,
) {
    let agents: Vec<AgentId> = stream.peer_agents().to_vec();
    let machine_id = stream.peer();
    let peer = machine_id;

    // FIX 4 (stale-authorization window): the T1 accept-loop identity gate
    // cleared before this stream was surfaced. A peer revoked in that window
    // must not consume a header read or reach the connect gate. Re-check the
    // shared revocation set BEFORE reading any peer bytes; drop on
    // revocation of ANY agent on the peer machine (#192 multi-agent
    // fail-closed). (The connect gate would still deny by policy, so this is
    // not a bypass — it closes the per-flow stale-authz window. Full
    // mid-stream teardown is a documented Phase-2 item.)
    {
        let revoked = revocation_set.read().await;
        let any_agent_revoked = agents.iter().any(|a| revoked.is_agent_revoked(a));
        if any_agent_revoked || revoked.is_machine_revoked(&machine_id) {
            fwd_diag.record_revoked_mid_flight();
            tracing::info!(
                target: "x0x::forward",
                agent = %hex::encode(agents[0].as_bytes()),
                agent_count = agents.len(),
                machine = %hex::encode(peer.as_bytes()),
                outcome = "drop_revoked_mid_flight",
                "inbound forward: peer revoked after accept — dropping before header read"
            );
            return;
        }
    }

    // Read header + run the connect gate, branching on the stream protocol.
    // ForwardV2: attestation path — verify the opener's signature against the
    // cached agent key, confirm machine binding, ACL-check the single
    // authenticated agent (#204). ForwardV1: legacy multi-agent fail-closed
    // (#192), kept for backward compatibility with pre-#204 peers.
    let target = match stream.protocol() {
        StreamProtocol::ForwardV2 => {
            // FIX 2: bound the header read (larger budget for the ~3.3 KB
            // ML-DSA-65 signature). Reset + count on timeout.
            let header =
                match tokio::time::timeout(HEADER_READ_TIMEOUT, read_header_v2(stream.recv_mut()))
                    .await
                {
                    Ok(Ok(h)) => h,
                    Ok(Err(e)) => {
                        tracing::info!(
                            target: "x0x::forward",
                            peer = %hex::encode(peer.as_bytes()),
                            error = %e,
                            "inbound forward v2: header read failed — closing stream"
                        );
                        return;
                    }
                    Err(_) => {
                        fwd_diag.record_header_timeout();
                        tracing::info!(
                            target: "x0x::forward",
                            peer = %hex::encode(peer.as_bytes()),
                            "inbound forward v2: header read timed out — resetting stream"
                        );
                        return;
                    }
                };
            match decide_inbound_attested(&header, &policy, &machine_id, &discovery_cache).await {
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
                        "inbound forward v2 denied at attestation/connect gate"
                    );
                    return;
                }
            }
        }
        _ => {
            // ForwardV1: legacy path (#192 multi-agent fail-closed).
            let header =
                match tokio::time::timeout(HEADER_READ_TIMEOUT, read_header(stream.recv_mut()))
                    .await
                {
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
            match decide_inbound(&header, &policy, &agents, &machine_id) {
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
            }
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

/// Read a length-prefixed `ForwardV2Header` from an async reader.
async fn read_header_v2<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> Result<ForwardV2Header, ForwardError> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|_| ForwardError::Truncated)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_HEADER_V2_BYTES {
        return Err(ForwardError::Oversize(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)
        .await
        .map_err(|_| ForwardError::Truncated)?;
    bincode::deserialize(&body).map_err(|e| ForwardError::Decode(e.to_string()))
}

/// Write a length-prefixed `ForwardV2Header` to an async writer.
async fn write_header_v2<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    header: &ForwardV2Header,
) -> Result<(), NetworkError> {
    use tokio::io::AsyncWriteExt;
    let frame = header.encode();
    w.write_all(&frame)
        .await
        .map_err(|e| NetworkError::StreamError(format!("write forward v2 header: {e}")))
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
    /// Shared identity discovery cache — for ForwardV2 attestation key
    /// lookups (#204).
    discovery_cache:
        Arc<tokio::sync::RwLock<std::collections::HashMap<AgentId, crate::DiscoveredAgent>>>,
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
        let discovery_cache = agent.identity_discovery_cache();
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
            discovery_cache,
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
                if !matches!(
                    stream.protocol(),
                    crate::streams::StreamProtocol::ForwardV1
                        | crate::streams::StreamProtocol::ForwardV2
                ) {
                    // T5 (SOCKS5) owns 0x02; drop non-forward streams.
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
                        Arc::clone(&this.discovery_cache),
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
        let target_host = spec.target_host;
        let target_port = spec.target_port;
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
                let target_host = target_host.clone();
                tokio::spawn(async move {
                    let _admission = admission;
                    fwd_diag.enter_stream();
                    let _guard = StreamLeaveGuard(Arc::clone(&fwd_diag));
                    drive_outbound(agent, peer_agent, target_host, target_port, tcp).await;
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
/// connect response, and bridge on `connected'. On any failure the local TCP
/// connection is simply closed (the client sees a reset/refused).
///
/// Tries `ForwardV2` (agent attestation, #204) first. If the peer rejects V2
/// (pre-#204 software — the stream is reset after the unknown protocol byte),
/// falls back to `ForwardV1` so mixed-fleet upgrades degrade gracefully.
async fn drive_outbound(
    agent: Arc<crate::Agent>,
    peer_agent: AgentId,
    target_host: String,
    target_port: u16,
    tcp: TcpStream,
) {
    // Try ForwardV2 (attestation). On peer rejection (old software), fall
    // back to ForwardV1 with the same TCP connection.
    match try_outbound_v2(&agent, &peer_agent, &target_host, target_port, tcp).await {
        OutboundOutcome::Done => (),
        OutboundOutcome::PeerRejectedV2(tcp) => {
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer_agent.as_bytes()),
                "outbound forward: peer does not support ForwardV2 — falling back to V1"
            );
            drive_outbound_v1(&agent, &peer_agent, &target_host, target_port, tcp).await;
        }
    }
}

/// Outcome of a V2 outbound attempt.
enum OutboundOutcome {
    /// The V2 forward completed (connected, denied, or failed permanently).
    Done,
    /// The peer rejected ForwardV2 (old software); the TCP is returned so the
    /// caller can retry with V1.
    PeerRejectedV2(TcpStream),
}

/// Attempt a `ForwardV2` outbound forward. Returns `PeerRejectedV2` only when
/// the failure is specifically the peer not understanding the V2 protocol
/// byte (the write to the opened stream fails immediately).
async fn try_outbound_v2(
    agent: &Arc<crate::Agent>,
    peer_agent: &AgentId,
    target_host: &str,
    target_port: u16,
    tcp: TcpStream,
) -> OutboundOutcome {
    let mut stream = match agent
        .open_peer_stream(peer_agent, StreamProtocol::ForwardV2)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer_agent.as_bytes()),
                error = %e,
                "outbound forward v2: could not open peer stream"
            );
            return OutboundOutcome::PeerRejectedV2(tcp);
        }
    };
    // Build + sign the V2 header with the local agent keypair.
    let mut header = ForwardV2Header::new(target_host.to_string(), target_port, agent.agent_id());
    if let Err(e) = header.sign(agent.identity().agent_keypair()) {
        tracing::warn!(
            target: "x0x::forward",
            error = %e,
            "outbound forward v2: failed to sign attestation — falling back to V1"
        );
        return OutboundOutcome::PeerRejectedV2(tcp);
    }
    // Write the V2 header. If this fails the peer likely reset the stream
    // after reading the unknown V2 protocol byte (old software) — fall back.
    if write_header_v2(stream.send_mut(), &header).await.is_err() {
        return OutboundOutcome::PeerRejectedV2(tcp);
    }
    // Read the peer's connect-response byte.
    let mut resp = [0u8; 1];
    if stream.recv_mut().read_exact(&mut resp).await.is_err() {
        return OutboundOutcome::Done;
    }
    finish_outbound(stream, resp, peer_agent, tcp).await;
    OutboundOutcome::Done
}

/// Legacy `ForwardV1` outbound forward (no attestation). Used for pre-#204
/// peers and as a last-resort fallback.
async fn drive_outbound_v1(
    agent: &Arc<crate::Agent>,
    peer_agent: &AgentId,
    target_host: &str,
    target_port: u16,
    tcp: TcpStream,
) {
    let mut stream = match agent
        .open_peer_stream(peer_agent, StreamProtocol::ForwardV1)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer_agent.as_bytes()),
                error = %e,
                "outbound forward v1: could not open peer stream"
            );
            return;
        }
    };
    let header = ForwardHeader {
        target_host: target_host.to_string(),
        target_port,
    };
    if write_header(stream.send_mut(), &header).await.is_err() {
        return;
    }
    let mut resp = [0u8; 1];
    if stream.recv_mut().read_exact(&mut resp).await.is_err() {
        return;
    }
    finish_outbound(stream, resp, peer_agent, tcp).await;
}

/// Shared tail: interpret the connect-response byte and bridge on `connected`.
async fn finish_outbound(stream: PeerStream, resp: [u8; 1], peer_agent: &AgentId, tcp: TcpStream) {
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
            decide_inbound(&header("127.0.0.1", 22), &disabled, &[agent], &machine).unwrap_err(),
            ConnectDenialReason::ConnectDisabled
        );

        // Enabled but pair not in ACL ⇒ AgentMachineNotInAcl.
        let other_agent = AgentId([9u8; 32]);
        let policy = policy_with_allow(other_agent, machine, target);
        assert_eq!(
            decide_inbound(&header("127.0.0.1", 22), &policy, &[agent], &machine).unwrap_err(),
            ConnectDenialReason::AgentMachineNotInAcl
        );

        // Pair in ACL but target not in its entry ⇒ TargetNotAllowed.
        let policy = policy_with_allow(agent, machine, "127.0.0.1:2222".parse().unwrap());
        assert_eq!(
            decide_inbound(&header("127.0.0.1", 22), &policy, &[agent], &machine).unwrap_err(),
            ConnectDenialReason::TargetNotAllowed
        );

        // Happy path: exact (agent, machine, target) ⇒ allow.
        let policy = policy_with_allow(agent, machine, target);
        assert_eq!(
            decide_inbound(&header("127.0.0.1", 22), &policy, &[agent], &machine).unwrap(),
            target
        );

        // Non-loopback target ⇒ TargetNotLoopback (refused before the ACL).
        let policy = policy_with_allow(agent, machine, target);
        assert_eq!(
            decide_inbound(&header("10.0.0.1", 22), &policy, &[agent], &machine).unwrap_err(),
            ConnectDenialReason::TargetNotLoopback
        );
    }

    /// Build a policy from explicit allow entries (multi-agent scenarios).
    fn policy_multi(entries: Vec<ConnectAllowEntry>) -> ConnectPolicy {
        ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: "test".into(),
            loaded_at_unix_ms: 0,
            allow: entries,
        })
    }

    fn allow_entry(
        agent: AgentId,
        machine: MachineId,
        targets: &[SocketAddr],
    ) -> ConnectAllowEntry {
        ConnectAllowEntry {
            description: None,
            agent_id: agent,
            machine_id: machine,
            targets: targets.to_vec(),
        }
    }

    #[test]
    fn decide_inbound_multi_agent_fail_closed() {
        // Issue #192: when a machine hosts multiple agents the QUIC transport
        // authenticates only the machine — not which agent opened the stream.
        // The ACL must check EVERY agent and fail-closed if any is
        // unauthorized, so one agent cannot piggyback on another's entry.
        let machine = MachineId([2u8; 32]);
        let agent_a = AgentId([1u8; 32]);
        let agent_b = AgentId([3u8; 32]);
        let ssh: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let vnc: SocketAddr = "127.0.0.1:5900".parse().unwrap();

        // Both agents authorized for the same target ⇒ allow.
        let policy = policy_multi(vec![
            allow_entry(agent_a, machine, &[ssh]),
            allow_entry(agent_b, machine, &[ssh]),
        ]);
        assert_eq!(
            decide_inbound(
                &header("127.0.0.1", 22),
                &policy,
                &[agent_a, agent_b],
                &machine
            )
            .unwrap(),
            ssh,
        );

        // Agent A authorized for :22 but agent B is not in the ACL at all ⇒
        // DENIED — B cannot piggyback on A's entry.
        let policy = policy_multi(vec![allow_entry(agent_a, machine, &[ssh])]);
        assert_eq!(
            decide_inbound(
                &header("127.0.0.1", 22),
                &policy,
                &[agent_a, agent_b],
                &machine
            )
            .unwrap_err(),
            ConnectDenialReason::AgentMachineNotInAcl,
        );

        // Both agents in the ACL but for different targets ⇒ DENIED for a
        // target only one of them has.
        let policy = policy_multi(vec![
            allow_entry(agent_a, machine, &[ssh]),
            allow_entry(agent_b, machine, &[vnc]),
        ]);
        assert_eq!(
            decide_inbound(
                &header("127.0.0.1", 22),
                &policy,
                &[agent_a, agent_b],
                &machine
            )
            .unwrap_err(),
            ConnectDenialReason::TargetNotAllowed,
        );

        // Agent order in the slice is irrelevant: [B, A] ≡ [A, B].
        let policy = policy_multi(vec![
            allow_entry(agent_a, machine, &[ssh]),
            allow_entry(agent_b, machine, &[ssh]),
        ]);
        assert_eq!(
            decide_inbound(
                &header("127.0.0.1", 22),
                &policy,
                &[agent_b, agent_a],
                &machine
            )
            .unwrap(),
            ssh,
        );

        // Single-agent list (the common case) behaves like the legacy check.
        let policy = policy_multi(vec![allow_entry(agent_a, machine, &[ssh])]);
        assert_eq!(
            decide_inbound(&header("127.0.0.1", 22), &policy, &[agent_a], &machine).unwrap(),
            ssh,
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

    // ── ForwardV2 attestation tests (#204) ─────────────────────────────────

    use crate::identity::AgentKeypair;
    use std::collections::HashMap;

    /// Build a discovery cache with one agent entry (key + machine binding).
    fn cache_with_agent(
        keypair: &AgentKeypair,
        machine: MachineId,
    ) -> Arc<tokio::sync::RwLock<HashMap<AgentId, crate::DiscoveredAgent>>> {
        let agent_id = keypair.agent_id();
        let mut cache = HashMap::new();
        cache.insert(
            agent_id,
            crate::DiscoveredAgent {
                agent_id,
                machine_id: machine,
                user_id: None,
                addresses: Vec::new(),
                announced_at: 0,
                last_seen: 0,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                cert_not_after: None,
                agent_certificate: None,
                agent_public_key: keypair.public_key().as_bytes().to_vec(),
            },
        );
        Arc::new(tokio::sync::RwLock::new(cache))
    }

    /// Build a signed V2 header for `(target, port)` from the given keypair.
    fn signed_v2_header(target: &str, port: u16, keypair: &AgentKeypair) -> ForwardV2Header {
        let mut h = ForwardV2Header::new(target.to_string(), port, keypair.agent_id());
        h.sign(keypair).expect("sign");
        h
    }

    #[test]
    fn v2_header_frame_round_trips() {
        let kp = AgentKeypair::generate().unwrap();
        let h = signed_v2_header("127.0.0.1", 22, &kp);
        let bytes = h.encode();
        let (decoded, n) = ForwardV2Header::decode(&bytes).expect("decode");
        assert_eq!(decoded, h);
        assert_eq!(n, bytes.len());
    }

    #[test]
    fn v2_header_decode_rejects_oversize() {
        let kp = AgentKeypair::generate().unwrap();
        let h = signed_v2_header("127.0.0.1", 22, &kp);
        let bytes = h.encode();
        // Tamper the length prefix to exceed the cap.
        let mut bad = bytes.clone();
        let len = (MAX_HEADER_V2_BYTES + 1).to_be_bytes();
        bad[..4].copy_from_slice(&len);
        assert_eq!(
            ForwardV2Header::decode(&bad).unwrap_err(),
            ForwardError::Oversize(MAX_HEADER_V2_BYTES + 1)
        );
    }

    #[test]
    fn v2_attestation_sign_and_verify() {
        let kp = AgentKeypair::generate().unwrap();
        let h = signed_v2_header("127.0.0.1", 22, &kp);
        // Valid attestation: the key hashes to the agent_id and the sig verifies.
        h.verify_attestation(kp.public_key().as_bytes())
            .expect("valid attestation must verify");
    }

    #[test]
    fn v2_attestation_rejects_missing_signature() {
        let kp = AgentKeypair::generate().unwrap();
        let h = ForwardV2Header::new("127.0.0.1".to_string(), 22, kp.agent_id());
        // Empty signature → AttestationMissing.
        assert_eq!(
            h.verify_attestation(kp.public_key().as_bytes())
                .unwrap_err(),
            ForwardError::AttestationMissing
        );
    }

    #[test]
    fn v2_attestation_rejects_forged_signature() {
        let kp = AgentKeypair::generate().unwrap();
        let mut h = signed_v2_header("127.0.0.1", 22, &kp);
        // Flip a byte in the signature → verification must fail.
        let sig_len = h.signature.len();
        h.signature[sig_len / 2] ^= 0xFF;
        assert!(matches!(
            h.verify_attestation(kp.public_key().as_bytes())
                .unwrap_err(),
            ForwardError::AttestationInvalid(_)
        ));
    }

    #[test]
    fn v2_attestation_rejects_wrong_key() {
        let kp = AgentKeypair::generate().unwrap();
        let h = signed_v2_header("127.0.0.1", 22, &kp);
        // A different agent's key does not hash to the same agent_id.
        let other = AgentKeypair::generate().unwrap();
        assert!(matches!(
            h.verify_attestation(other.public_key().as_bytes())
                .unwrap_err(),
            ForwardError::AttestationKeyMismatch(_)
        ));
    }

    #[test]
    fn v2_signable_bytes_are_deterministic_and_domain_separated() {
        let kp = AgentKeypair::generate().unwrap();
        let h1 = ForwardV2Header::new("127.0.0.1".to_string(), 22, kp.agent_id());
        let h2 = ForwardV2Header::new("127.0.0.1".to_string(), 22, kp.agent_id());
        assert_eq!(h1.signable_bytes(), h2.signable_bytes());
        // A different target changes the bytes.
        let h3 = ForwardV2Header::new("::1".to_string(), 22, kp.agent_id());
        assert_ne!(h1.signable_bytes(), h3.signable_bytes());
        // Domain prefix is present.
        assert!(h1
            .signable_bytes()
            .starts_with(FORWARD_V2_ATTESTATION_DOMAIN));
    }

    #[tokio::test]
    async fn decide_inbound_attested_matrix() {
        // #204: the attested gate verifies the opener's signature against the
        // cached agent key, confirms machine binding, then ACL-checks that
        // single agent.
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let machine = MachineId([2u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let cache = cache_with_agent(&kp, machine);

        // Happy path: valid attestation + agent in ACL + correct machine.
        let policy = policy_with_allow(agent, machine, target);
        let header = signed_v2_header("127.0.0.1", 22, &kp);
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &cache)
                .await
                .unwrap(),
            target,
        );

        // Missing attestation (empty sig) → AttestationFailed.
        let header = ForwardV2Header::new("127.0.0.1".to_string(), 22, agent);
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &cache)
                .await
                .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );

        // Forged signature → AttestationFailed.
        let mut header = signed_v2_header("127.0.0.1", 22, &kp);
        let mid = header.signature.len() / 2;
        header.signature[mid] ^= 0xFF;
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &cache)
                .await
                .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );

        // Agent unknown to cache → AttestationFailed.
        let stranger = AgentKeypair::generate().unwrap();
        let header = signed_v2_header("127.0.0.1", 22, &stranger);
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &cache)
                .await
                .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );

        // ACL denial (target not in entry) → TargetNotAllowed.
        let policy = policy_with_allow(agent, machine, "127.0.0.1:9999".parse().unwrap());
        let header = signed_v2_header("127.0.0.1", 22, &kp);
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &cache)
                .await
                .unwrap_err(),
            ConnectDenialReason::TargetNotAllowed,
        );

        // Non-loopback target → TargetNotLoopback.
        let policy = policy_with_allow(agent, machine, target);
        let header = signed_v2_header("10.0.0.1", 22, &kp);
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &cache)
                .await
                .unwrap_err(),
            ConnectDenialReason::TargetNotLoopback,
        );
    }

    #[tokio::test]
    async fn decide_inbound_attested_wrong_machine_denied() {
        // Signature is valid and the agent is in the cache, but the cached
        // machine_id ≠ transport peer machine. This is a cross-machine
        // impersonation attempt — must be denied.
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let real_machine = MachineId([2u8; 32]);
        let other_machine = MachineId([9u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let cache = cache_with_agent(&kp, real_machine);
        let policy = policy_with_allow(agent, real_machine, target);

        let header = signed_v2_header("127.0.0.1", 22, &kp);
        // Transport peer is `other_machine` but the agent is cached on
        // `real_machine` → AgentNotOnMachine.
        assert_eq!(
            decide_inbound_attested(&header, &policy, &other_machine, &cache)
                .await
                .unwrap_err(),
            ConnectDenialReason::AgentNotOnMachine,
        );
    }

    #[tokio::test]
    async fn decide_inbound_attested_multi_agent_checks_only_attested() {
        // #204: on a multi-agent machine the attested gate checks ONLY the
        // authenticated opener — not every agent on the machine. A second
        // agent that is NOT in the ACL (and would cause a V1 multi-agent
        // fail-closed) does not affect the V2 path.
        let machine = MachineId([2u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();

        // Agent A (the opener) — authorized.
        let kp_a = AgentKeypair::generate().unwrap();
        let agent_a = kp_a.agent_id();

        // Agent B (also on the machine, NOT authorized for the target).
        let kp_b = AgentKeypair::generate().unwrap();
        let agent_b = kp_b.agent_id();

        // Cache holds both agents on the same machine.
        let mut cache_map = HashMap::new();
        for kp in [&kp_a, &kp_b] {
            let id = kp.agent_id();
            cache_map.insert(
                id,
                crate::DiscoveredAgent {
                    agent_id: id,
                    machine_id: machine,
                    user_id: None,
                    addresses: Vec::new(),
                    announced_at: 0,
                    last_seen: 0,
                    machine_public_key: Vec::new(),
                    nat_type: None,
                    can_receive_direct: None,
                    is_relay: None,
                    is_coordinator: None,
                    reachable_via: Vec::new(),
                    relay_candidates: Vec::new(),
                    cert_not_after: None,
                    agent_certificate: None,
                    agent_public_key: kp.public_key().as_bytes().to_vec(),
                },
            );
        }
        let cache = Arc::new(tokio::sync::RwLock::new(cache_map));

        // Policy: only agent_a is authorized. Agent B is absent from the ACL.
        let policy = policy_multi(vec![allow_entry(agent_a, machine, &[target])]);

        // V2 attestation from agent_a succeeds even though agent_b is
        // unauthorized — the gate checks ONLY the authenticated opener.
        let header_a = signed_v2_header("127.0.0.1", 22, &kp_a);
        assert_eq!(
            decide_inbound_attested(&header_a, &policy, &machine, &cache)
                .await
                .unwrap(),
            target,
        );

        // V2 attestation from agent_b is denied (not in ACL).
        let header_b = signed_v2_header("127.0.0.1", 22, &kp_b);
        assert_eq!(
            decide_inbound_attested(&header_b, &policy, &machine, &cache)
                .await
                .unwrap_err(),
            ConnectDenialReason::AgentMachineNotInAcl,
        );

        // Sanity: the V1 multi-agent path WOULD fail-closed here (both
        // agents checked, B is unauthorized). This confirms V2 lifts the
        // restriction for the authenticated opener.
        assert_eq!(
            decide_inbound(
                &header("127.0.0.1", 22),
                &policy,
                &[agent_a, agent_b],
                &machine
            )
            .unwrap_err(),
            ConnectDenialReason::AgentMachineNotInAcl,
        );
    }

    #[tokio::test]
    async fn decide_inbound_attested_no_cached_key_denied() {
        // Agent is in the cache but has no public key (pre-v2 announcement
        // without a cert) → cannot be attested → fail-closed.
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let machine = MachineId([2u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();

        let mut cache_map = HashMap::new();
        cache_map.insert(
            agent,
            crate::DiscoveredAgent {
                agent_id: agent,
                machine_id: machine,
                user_id: None,
                addresses: Vec::new(),
                announced_at: 0,
                last_seen: 0,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                cert_not_after: None,
                agent_certificate: None,
                agent_public_key: Vec::new(), // no key!
            },
        );
        let cache = Arc::new(tokio::sync::RwLock::new(cache_map));
        let policy = policy_with_allow(agent, machine, target);

        let header = signed_v2_header("127.0.0.1", 22, &kp);
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &cache)
                .await
                .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );
    }
}
