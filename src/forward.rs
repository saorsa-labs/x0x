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
/// Hard cap on the encoded V2 header size. The ML-DSA-65 signature (~3.3 KB)
/// + the agent public key (~2 KB) + overhead; 8 KB gives headroom.
pub const MAX_HEADER_V2_BYTES: u32 = 8192;

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
/// Version `.v2` binds `recipient_machine_id` and `issued_at_ms` into the
/// signed bytes so a captured header cannot be replayed to a different
/// recipient or after the TTL window. The version suffix ensures old `.v1`
/// signatures (domain-only, no recipient/timestamp) cannot validate against
/// the new scope.
const FORWARD_V2_ATTESTATION_DOMAIN: &[u8] = b"x0x-forward-v2-attestation.v2";

/// Maximum age (milliseconds) of a ForwardV2 attestation before it is
/// rejected as stale. Bounds the replay window to the same recipient +
/// target pair within this interval.
const FORWARD_V2_ATTESTATION_TTL_MS: u64 = 60_000;
/// Clock-skew allowance (milliseconds): an attestation dated slightly in
/// the future is accepted to absorb NTP drift between peers.
const FORWARD_V2_ATTESTATION_FUTURE_SKEW_MS: u64 = 5_000;

/// Forward header with agent attestation (`ForwardV2`, #204).
///
/// Carries the opener's `agent_id` + **public key** plus an ML-DSA-65
/// signature over the header's signable bytes. The inbound side verifies
/// the signature against the **header's** key (after checking the binding
/// `SHA-256(key) == agent_id`), confirms the agent is on the transport-
/// authenticated machine via the discovery cache, then ACL-checks that
/// specific agent. The key travels in the header (not just the cache) so
/// the verifier never depends on announce-propagation timing — the soak
/// NO-GO root cause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardV2Header {
    /// Numeric loopback IP the peer wants to reach (e.g. `127.0.0.1`, `::1`).
    pub target_host: String,
    /// TCP port on the loopback target.
    pub target_port: u16,
    /// The opener's agent identity (proves which agent opened the stream).
    pub opener_agent_id: AgentId,
    /// The opener's raw ML-DSA-65 public key bytes. Bound to
    /// `opener_agent_id` via `SHA-256(key) == agent_id`; the verifier checks
    /// this binding before trusting the key. Carrying the key in the header
    /// (rather than relying on the discovery cache) eliminates the announce-
    /// propagation gap that blocked the V2 happy path in the soak (#204).
    pub opener_agent_public_key: Vec<u8>,
    /// The recipient's machine identity — binds the attestation to the
    /// specific peer the opener dialled so a captured header cannot be
    /// replayed to a different machine.
    pub recipient_machine_id: MachineId,
    /// Unix-millisecond timestamp at which the opener created the header.
    /// The inbound side rejects headers older than `FORWARD_V2_ATTESTATION_TTL_MS`
    /// or more than `FORWARD_V2_ATTESTATION_FUTURE_SKEW_MS` in the future.
    pub issued_at_ms: u64,
    /// ML-DSA-65 signature over [`ForwardV2Header::signable_bytes`].
    pub signature: Vec<u8>,
}

impl ForwardV2Header {
    /// Build an unsigned V2 header (signature empty — call `sign` to attest).
    #[must_use]
    pub fn new(
        target_host: String,
        target_port: u16,
        opener_agent_id: AgentId,
        opener_agent_public_key: Vec<u8>,
        recipient_machine_id: MachineId,
    ) -> Self {
        Self {
            target_host,
            target_port,
            opener_agent_id,
            opener_agent_public_key,
            recipient_machine_id,
            issued_at_ms: 0,
            signature: Vec::new(),
        }
    }
    /// Canonical bytes signed by the opener to produce `signature`.
    ///
    /// Deterministic, domain-prefixed, length-prefixed encoding of every
    /// semantic field **except `signature` itself**. Binds the recipient
    /// machine and a freshness timestamp so a captured header cannot be
    /// replayed to a different peer or after the TTL window. Mirrors the
    /// `AgentCard` signing scheme (`src/groups/card.rs`).
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(FORWARD_V2_ATTESTATION_DOMAIN);
        // length-prefixed target_host
        buf.extend_from_slice(&(self.target_host.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.target_host.as_bytes());
        // target_port
        buf.extend_from_slice(&self.target_port.to_le_bytes());
        // opener_agent_id (fixed 32 bytes)
        buf.extend_from_slice(&self.opener_agent_id.0);
        // opener_agent_public_key (length-prefixed) — bound to agent_id via
        // hash; committed to the signature so it cannot be swapped (#204).
        buf.extend_from_slice(&(self.opener_agent_public_key.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.opener_agent_public_key);
        // recipient_machine_id (fixed 32 bytes) — scope binding (#204 replay)
        buf.extend_from_slice(&self.recipient_machine_id.0);
        // issued_at_ms (u64 LE) — freshness binding (#204 replay)
        buf.extend_from_slice(&self.issued_at_ms.to_le_bytes());
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
        // Stamp the freshness timestamp just before signing so it is covered
        // by the signature.
        self.issued_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
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

/// Verification context bundled to keep `decide_inbound_attested` arg-count
/// under the clippy threshold (#204).
struct AttestationVerifyCtx {
    discovery_cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<AgentId, crate::DiscoveredAgent>>,
    >,
    contact_store: std::sync::Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
    own_machine_id: MachineId,
    now_ms: u64,
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
/// **Replay protection (#204 must-fix 2):** the signature binds
/// `recipient_machine_id` and `issued_at_ms`. The verifier checks:
/// - recipient matches the local (transport-authenticated) machine;
/// - `issued_at_ms` is within `[now − TTL, now + future-skew]`.
///
/// **Trust evaluation (#204 must-fix 3):** the attested agent's real trust
/// decision is evaluated via `TrustEvaluator` against the contact
/// store (same pattern as the stream gate). A Blocked-but-announced agent is
/// denied here.
///
/// Fail-closed on: agent not in cache, no cached key, wrong machine,
/// recipient mismatch, stale/future timestamp, signature failure, trust
/// rejection, or ACL denial.
async fn decide_inbound_attested(
    header: &ForwardV2Header,
    policy: &ConnectPolicy,
    peer_machine: &MachineId,
    ctx: &AttestationVerifyCtx,
) -> Result<SocketAddr, ConnectDenialReason> {
    // Resolve the target first (same as V1 — a non-loopback target is
    // refused before the attestation check, so an unverified peer learns
    // nothing about which agents exist).
    let target = resolve_loopback_target(&header.target_host, header.target_port)
        .map_err(|_| ConnectDenialReason::TargetNotLoopback)?;

    // ── Replay: recipient scope binding ──────────────────────────────
    // The header must name THIS machine as the recipient — a header captured
    // on machine A cannot be replayed to machine B.
    if header.recipient_machine_id != ctx.own_machine_id {
        return Err(ConnectDenialReason::AttestationFailed);
    }

    // ── Replay: freshness / TTL ──────────────────────────────────────
    if header.issued_at_ms == 0 {
        return Err(ConnectDenialReason::AttestationFailed);
    }
    // Stale: older than the TTL window.
    if ctx.now_ms
        > header
            .issued_at_ms
            .saturating_add(FORWARD_V2_ATTESTATION_TTL_MS)
    {
        return Err(ConnectDenialReason::AttestationFailed);
    }
    // Future: more than the skew allowance ahead of our clock.
    if header.issued_at_ms
        > ctx
            .now_ms
            .saturating_add(FORWARD_V2_ATTESTATION_FUTURE_SKEW_MS)
    {
        return Err(ConnectDenialReason::AttestationFailed);
    }

    // Look up the opener in the discovery cache. An agent absent from the
    // cache (unannounced or revoked-and-evicted) cannot be attested. The cache
    // is used for EXISTENCE + machine binding only — the public key travels
    // in the header (bound via hash → agent_id), so the verifier never depends
    // on announce-propagation timing (#204 soak NO-GO fix).
    let cached = {
        let cache = ctx.discovery_cache.read().await;
        cache.get(&header.opener_agent_id).cloned()
    };
    let agent = cached.ok_or(ConnectDenialReason::AttestationFailed)?;

    // Confirm the agent is on the transport-authenticated machine.
    if agent.machine_id != *peer_machine {
        return Err(ConnectDenialReason::AgentNotOnMachine);
    }

    // Verify the attestation against the HEADER's public key. The
    // `verify_attestation` method checks `SHA-256(key) == opener_agent_id`
    // (binding) and the ML-DSA-65 signature. This eliminates the dependency
    // on the discovery cache having a non-empty `agent_public_key` — the soak
    // NO-GO root cause.
    header
        .verify_attestation(&header.opener_agent_public_key)
        .map_err(|_| ConnectDenialReason::AttestationFailed)?;

    // Opportunistically upgrade the cache entry with the header's key so
    // subsequent forwards (and other subsystems) benefit.
    if agent.agent_public_key.is_empty() && !header.opener_agent_public_key.is_empty() {
        let mut cache = ctx.discovery_cache.write().await;
        if let Some(entry) = cache.get_mut(&header.opener_agent_id) {
            entry.agent_public_key = header.opener_agent_public_key.clone();
        }
    }

    // ── Trust evaluation (#204 must-fix 3): evaluate the attested agent's
    // real trust — NOT a hard-coded Accept. A Blocked-but-announced agent
    // must be denied here (same pattern as the stream gate).
    let trust_decision = {
        let contacts = ctx.contact_store.read().await;
        let evaluator = crate::trust::TrustEvaluator::new(&contacts);
        evaluator.evaluate(&crate::trust::TrustContext {
            agent_id: &header.opener_agent_id,
            machine_id: peer_machine,
        })
    };

    // The opener is now cryptographically authenticated: ACL-check that
    // specific agent with its REAL trust decision.
    evaluate_connect_gate(
        /* verified */ true,
        Some(trust_decision),
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

/// Shared context for the inbound forward handler (#204 must-fix 1: bundles
/// the service-level Arcs so `handle_inbound` stays under clippy's arg limit).
pub(crate) struct InboundCtx {
    pub policy: Arc<ConnectPolicy>,
    pub connect_diag: Arc<ConnectDiagnostics>,
    pub fwd_diag: Arc<ForwardDiagnostics>,
    pub revocation_set: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    pub discovery_cache:
        Arc<tokio::sync::RwLock<std::collections::HashMap<AgentId, crate::DiscoveredAgent>>>,
    pub contact_store: Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
    pub own_machine_id: MachineId,
    pub require_attestation: bool,
}

/// Drive the inbound half of a forward: read the header, run the connect
/// gate, connect the local loopback target, and bridge the stream to it.
///
/// The peer identity comes from the [`PeerStream`] (already cleared the T1
/// identity gate). Records allow/deny into `connect_diag` and connect
/// failures into `fwd_diag`. On any failure the stream is closed (the halves
/// are dropped) — zero bytes reach the target on a denial.
pub(crate) async fn handle_inbound(mut stream: PeerStream, ctx: &InboundCtx) {
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
        let revoked = ctx.revocation_set.read().await;
        let any_agent_revoked = agents.iter().any(|a| revoked.is_agent_revoked(a));
        if any_agent_revoked || revoked.is_machine_revoked(&machine_id) {
            ctx.fwd_diag.record_revoked_mid_flight();
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
                        ctx.fwd_diag.record_header_timeout();
                        tracing::info!(
                            target: "x0x::forward",
                            peer = %hex::encode(peer.as_bytes()),
                            "inbound forward v2: header read timed out — resetting stream"
                        );
                        return;
                    }
                };
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let verify_ctx = AttestationVerifyCtx {
                discovery_cache: Arc::clone(&ctx.discovery_cache),
                contact_store: Arc::clone(&ctx.contact_store),
                own_machine_id: ctx.own_machine_id,
                now_ms,
            };
            match decide_inbound_attested(&header, &ctx.policy, &machine_id, &verify_ctx).await {
                Ok(addr) => addr,
                Err(reason) => {
                    ctx.connect_diag.record_denied(reason);
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
            // ForwardV1: legacy path. When `ctx.require_attestation` is true
            // (the default), V1 streams are DENIED — the unannounced-agent
            // window (#204) stays closed. Set `[forward]
            // ctx.require_attestation = false` to allow V1 for mixed-version
            // deployments.
            if ctx.require_attestation {
                ctx.connect_diag
                    .record_denied(ConnectDenialReason::AttestationFailed);
                tracing::info!(
                    target: "x0x::forward",
                    peer = %hex::encode(peer.as_bytes()),
                    "inbound forward v1 denied: attestation required (ctx.require_attestation=true)"
                );
                return;
            }
            // ctx.require_attestation=false: legacy multi-agent fail-closed (#192).
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
                        ctx.fwd_diag.record_header_timeout();
                        tracing::info!(
                            target: "x0x::forward",
                            peer = %hex::encode(peer.as_bytes()),
                            "inbound forward: header read timed out — resetting stream"
                        );
                        return;
                    }
                };
            match decide_inbound(&header, &ctx.policy, &agents, &machine_id) {
                Ok(addr) => addr,
                Err(reason) => {
                    ctx.connect_diag.record_denied(reason);
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
        ctx.connect_diag
            .record_denied(ConnectDenialReason::TargetNotLoopback);
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
            ctx.fwd_diag.record_connect_failed();
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
            ctx.fwd_diag.record_connect_failed();
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
    ctx.connect_diag.record_allowed();
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

/// Forward (tailnet) configuration, loaded from `[forward]` in the daemon TOML.
///
/// `require_attestation` defaults to `true` — inbound ForwardV1 streams are
/// denied (closes the V1 downgrade path, #204 must-fix 1). Set to `false`
/// for mixed-version deployments where pre-v0.30 peers must open inbound
/// forwards.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForwardConfig {
    /// When `true` (the default), inbound ForwardV1 streams are denied and
    /// the outbound path does not fall back to V1. Set `false` to allow V1.
    #[serde(default = "default_require_attestation")]
    pub require_attestation: bool,
}

fn default_require_attestation() -> bool {
    true
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            require_attestation: true,
        }
    }
}

impl ForwardConfig {
    /// Shorthand for the default-secure config (attestation required).
    #[must_use]
    pub fn secure() -> Self {
        Self::default()
    }
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
    /// Shared contact store — for trust evaluation of attested agents
    /// (#204 must-fix 3).
    contact_store: Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
    /// When true (the default) inbound ForwardV1 streams are denied and the
    /// outbound path does not fall back to V1 — closes the V1 downgrade path
    /// (#204 must-fix 1). Set `[forward] require_attestation = false` in the
    /// daemon TOML to allow V1 for mixed-version deployments.
    require_attestation: bool,
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
    ///
    /// `require_attestation` (default `true`) denies inbound ForwardV1 streams
    /// and gates the outbound V1 fallback — set `false` for mixed-version
    /// deployments (#204 must-fix 1).
    #[must_use]
    pub fn new(
        agent: Arc<crate::Agent>,
        policy: Arc<ConnectPolicy>,
        connect_diag: Arc<ConnectDiagnostics>,
        require_attestation: bool,
    ) -> Self {
        let revocation_set = agent.revocation_set();
        let discovery_cache = agent.identity_discovery_cache();
        let contact_store = agent.contact_store();
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
            contact_store,
            require_attestation,
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
                    let inbound_ctx = InboundCtx {
                        policy: Arc::clone(&this.policy),
                        connect_diag: Arc::clone(&this.connect_diag),
                        fwd_diag: Arc::clone(&this.fwd_diag),
                        revocation_set: Arc::clone(&this.revocation_set),
                        discovery_cache: Arc::clone(&this.discovery_cache),
                        contact_store: Arc::clone(&this.contact_store),
                        own_machine_id: this.agent.machine_id(),
                        require_attestation: this.require_attestation,
                    };
                    handle_inbound(stream, &inbound_ctx).await;
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
        let require_attestation = self.require_attestation;
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
                    drive_outbound(
                        agent,
                        peer_agent,
                        target_host,
                        target_port,
                        tcp,
                        require_attestation,
                    )
                    .await;
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
    require_attestation: bool,
) {
    // Try ForwardV2 (attestation). On peer rejection (old software), fall
    // back to ForwardV1 — but ONLY when require_attestation is false. When
    // true (the default) there is no fallback: a peer that cannot handle V2
    // simply cannot forward (#204 must-fix 1).
    match try_outbound_v2(&agent, &peer_agent, &target_host, target_port, tcp).await {
        OutboundOutcome::Done => (),
        OutboundOutcome::PeerRejectedV2(tcp) => {
            if require_attestation {
                tracing::info!(
                    target: "x0x::forward",
                    peer = %hex::encode(peer_agent.as_bytes()),
                    "outbound forward: peer rejected V2 and require_attestation=true — closing local TCP"
                );
            } else {
                tracing::info!(
                    target: "x0x::forward",
                    peer = %hex::encode(peer_agent.as_bytes()),
                    "outbound forward: peer does not support ForwardV2 — falling back to V1"
                );
                drive_outbound_v1(&agent, &peer_agent, &target_host, target_port, tcp).await;
            }
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
    // Build + sign the V2 header with the local agent keypair. The header
    // carries the opener's public key so the verifier doesn't depend on
    // announce propagation (#204 soak fix).
    let mut header = ForwardV2Header::new(
        target_host.to_string(),
        target_port,
        agent.agent_id(),
        agent
            .identity()
            .agent_keypair()
            .public_key()
            .as_bytes()
            .to_vec(),
        stream.peer(),
    );
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

    use crate::contacts::{ContactStore, IdentityType, TrustLevel};
    use crate::identity::AgentKeypair;
    use std::collections::HashMap;

    /// Current Unix-millisecond timestamp (for TTL tests).
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

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

    /// Build a contact store with the agent at Trusted (Accept).
    fn trusted_store(agent: AgentId) -> Arc<tokio::sync::RwLock<ContactStore>> {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ContactStore::new(dir.path().join("contacts.json"));
        store.set_identity_type(&agent, IdentityType::Anonymous);
        store.set_trust(&agent, TrustLevel::Trusted);
        std::mem::forget(dir);
        Arc::new(tokio::sync::RwLock::new(store))
    }

    /// Build a contact store with the agent Blocked.
    fn blocked_store(agent: AgentId) -> Arc<tokio::sync::RwLock<ContactStore>> {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ContactStore::new(dir.path().join("contacts.json"));
        store.set_trust(&agent, TrustLevel::Blocked);
        std::mem::forget(dir);
        Arc::new(tokio::sync::RwLock::new(store))
    }

    fn signed_v2_header(
        target: &str,
        port: u16,
        keypair: &AgentKeypair,
        recipient: MachineId,
    ) -> ForwardV2Header {
        let mut h = ForwardV2Header::new(
            target.to_string(),
            port,
            keypair.agent_id(),
            keypair.public_key().as_bytes().to_vec(),
            recipient,
        );
        h.sign(keypair).expect("sign");
        h
    }

    #[test]
    fn v2_header_frame_round_trips() {
        let kp = AgentKeypair::generate().unwrap();
        let machine = MachineId([2u8; 32]);
        let h = signed_v2_header("127.0.0.1", 22, &kp, machine);
        let bytes = h.encode();
        let (decoded, n) = ForwardV2Header::decode(&bytes).expect("decode");
        assert_eq!(decoded, h);
        assert_eq!(n, bytes.len());
    }

    #[test]
    fn v2_header_decode_rejects_oversize() {
        let kp = AgentKeypair::generate().unwrap();
        let machine = MachineId([2u8; 32]);
        let h = signed_v2_header("127.0.0.1", 22, &kp, machine);
        let bytes = h.encode();
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
        let machine = MachineId([2u8; 32]);
        let h = signed_v2_header("127.0.0.1", 22, &kp, machine);
        h.verify_attestation(kp.public_key().as_bytes())
            .expect("valid attestation must verify");
    }

    #[test]
    fn v2_attestation_sign_encode_decode_and_verify() {
        let kp = AgentKeypair::generate().unwrap();
        let machine = MachineId([2u8; 32]);
        let h = signed_v2_header("127.0.0.1", 22, &kp, machine);
        let bytes = h.encode();
        let (decoded, _) = ForwardV2Header::decode(&bytes).expect("decode");

        let verification = decoded.verify_attestation(&decoded.opener_agent_public_key);
        eprintln!("wire-round-trip verify_attestation result: {verification:?}");
        assert_eq!(verification, Ok(()));
    }

    #[test]
    fn v2_attestation_rejects_missing_signature() {
        let kp = AgentKeypair::generate().unwrap();
        let machine = MachineId([2u8; 32]);
        let h = ForwardV2Header::new(
            "127.0.0.1".to_string(),
            22,
            kp.agent_id(),
            kp.public_key().as_bytes().to_vec(),
            machine,
        );
        assert_eq!(
            h.verify_attestation(kp.public_key().as_bytes())
                .unwrap_err(),
            ForwardError::AttestationMissing
        );
    }

    #[test]
    fn v2_attestation_rejects_forged_signature() {
        let kp = AgentKeypair::generate().unwrap();
        let machine = MachineId([2u8; 32]);
        let mut h = signed_v2_header("127.0.0.1", 22, &kp, machine);
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
        let machine = MachineId([2u8; 32]);
        let h = signed_v2_header("127.0.0.1", 22, &kp, machine);
        let other = AgentKeypair::generate().unwrap();
        assert!(matches!(
            h.verify_attestation(other.public_key().as_bytes())
                .unwrap_err(),
            ForwardError::AttestationKeyMismatch(_)
        ));
    }

    #[test]
    fn v2_signable_bytes_bind_target_port_and_recipient() {
        // Must-fix 2: port/host/recipient mutation invalidates the signature.
        let kp = AgentKeypair::generate().unwrap();
        let machine = MachineId([2u8; 32]);
        let mut h = signed_v2_header("127.0.0.1", 22, &kp, machine);
        let pubkey = kp.public_key().as_bytes().to_vec();
        assert!(h.verify_attestation(&pubkey).is_ok());
        h.target_port = 2222;
        assert!(h.verify_attestation(&pubkey).is_err());
        h.target_port = 22;
        h.target_host = "::1".to_string();
        assert!(h.verify_attestation(&pubkey).is_err());
        h.target_host = "127.0.0.1".to_string();
        h.recipient_machine_id = MachineId([9u8; 32]);
        assert!(h.verify_attestation(&pubkey).is_err());
    }

    #[test]
    fn v2_signable_bytes_are_deterministic_and_domain_separated() {
        let kp = AgentKeypair::generate().unwrap();
        let machine = MachineId([2u8; 32]);
        let h1 = ForwardV2Header::new(
            "127.0.0.1".to_string(),
            22,
            kp.agent_id(),
            kp.public_key().as_bytes().to_vec(),
            machine,
        );
        let h2 = ForwardV2Header::new(
            "127.0.0.1".to_string(),
            22,
            kp.agent_id(),
            kp.public_key().as_bytes().to_vec(),
            machine,
        );
        assert_eq!(h1.signable_bytes(), h2.signable_bytes());
        let h3 = ForwardV2Header::new(
            "::1".to_string(),
            22,
            kp.agent_id(),
            kp.public_key().as_bytes().to_vec(),
            machine,
        );
        assert_ne!(h1.signable_bytes(), h3.signable_bytes());
        assert!(h1
            .signable_bytes()
            .starts_with(FORWARD_V2_ATTESTATION_DOMAIN));
    }

    #[test]
    fn forward_config_defaults_to_require_attestation() {
        // Must-fix 1: default config must deny V1.
        assert!(ForwardConfig::default().require_attestation);
        assert!(ForwardConfig::secure().require_attestation);
    }

    #[tokio::test]
    async fn decide_inbound_attested_matrix() {
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let machine = MachineId([2u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let cache = cache_with_agent(&kp, machine);
        let contacts = trusted_store(agent);
        let ts = now_ms();
        let policy = policy_with_allow(agent, machine, target);

        // Happy path.
        let hdr = signed_v2_header("127.0.0.1", 22, &kp, machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: ts
                }
            )
            .await
            .unwrap(),
            target,
        );
        // Missing attestation.
        let hdr = ForwardV2Header::new("127.0.0.1".to_string(), 22, agent, Vec::new(), machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: ts
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );
        // Forged signature.
        let mut hdr = signed_v2_header("127.0.0.1", 22, &kp, machine);
        let _mid = hdr.signature.len() / 2;
        hdr.signature[_mid] ^= 0xFF;
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: ts
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );
        // Unknown agent.
        let stranger = AgentKeypair::generate().unwrap();
        let hdr = signed_v2_header("127.0.0.1", 22, &stranger, machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: ts
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );
        // ACL: target not in entry.
        let policy = policy_with_allow(agent, machine, "127.0.0.1:9999".parse().unwrap());
        let hdr = signed_v2_header("127.0.0.1", 22, &kp, machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: ts
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::TargetNotAllowed,
        );
        // Non-loopback.
        let policy = policy_with_allow(agent, machine, target);
        let hdr = signed_v2_header("10.0.0.1", 22, &kp, machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: ts
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::TargetNotLoopback,
        );
    }

    #[tokio::test]
    async fn v2_cross_node_wire_header_verifies_then_distinct_machine_allows() {
        // Distinct-machine happy path. The opener lives on `opener_machine`
        // (transport-authenticated as `peer_machine`) and signs the header for
        // the local recipient `own_machine`. The cache + ACL bind the opener
        // agent to `opener_machine`; the recipient scope binding accepts
        // because the header names `own_machine` as recipient. Under the OLD
        // comparison the header's recipient was checked against `peer_machine`
        // (`opener_machine`) and wrongly denied — the fix checks it against
        // `own_machine_id`, so the legitimate cross-node forward succeeds.
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let opener_machine = MachineId([2u8; 32]);
        let own_machine = MachineId([3u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let cache = cache_with_agent(&kp, opener_machine);
        let contacts = trusted_store(agent);
        let policy = policy_with_allow(agent, opener_machine, target);

        // Explicit wire encode/decode round trip + signature verification.
        let header = signed_v2_header("127.0.0.1", 22, &kp, own_machine);
        let bytes = header.encode();
        let (decoded, _) = ForwardV2Header::decode(&bytes).expect("decode");
        decoded
            .verify_attestation(&decoded.opener_agent_public_key)
            .expect("wire-round-trip attestation must verify");

        // Distinct-machine gate decision: opener on `opener_machine`, local
        // recipient is `own_machine` — gate returns the resolved target.
        assert_eq!(
            decide_inbound_attested(
                &decoded,
                &policy,
                &opener_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache,
                    contact_store: contacts,
                    own_machine_id: own_machine,
                    now_ms: now_ms(),
                },
            )
            .await
            .unwrap(),
            target,
        );
    }

    #[tokio::test]
    async fn decide_inbound_attested_wrong_recipient_denied() {
        // Replay / misdelivery: the opener (on `opener_machine`) signed a
        // header addressed to `other_recipient`, but THIS machine is
        // `own_machine`. The cache binding, signature, trust, and ACL are
        // all set up to ALLOW a legitimate forward — the ONLY reason this
        // denies is that the signed recipient differs from `own_machine_id`.
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let opener_machine = MachineId([2u8; 32]);
        let own_machine = MachineId([3u8; 32]);
        let other_recipient = MachineId([9u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let cache = cache_with_agent(&kp, opener_machine);
        let contacts = trusted_store(agent);
        let policy = policy_with_allow(agent, opener_machine, target);
        let hdr = signed_v2_header("127.0.0.1", 22, &kp, other_recipient);
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &opener_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: own_machine,
                    now_ms: now_ms()
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );
    }

    #[tokio::test]
    async fn decide_inbound_attested_wrong_cached_machine_denied() {
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let real_machine = MachineId([2u8; 32]);
        let other_machine = MachineId([9u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let cache = cache_with_agent(&kp, real_machine);
        let contacts = trusted_store(agent);
        let policy = policy_with_allow(agent, real_machine, target);
        let hdr = signed_v2_header("127.0.0.1", 22, &kp, other_machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &other_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: other_machine,
                    now_ms: now_ms()
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::AgentNotOnMachine,
        );
    }

    #[tokio::test]
    async fn decide_inbound_attested_replay_expired() {
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let machine = MachineId([2u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let cache = cache_with_agent(&kp, machine);
        let contacts = trusted_store(agent);
        let policy = policy_with_allow(agent, machine, target);
        let ts = now_ms();
        let mut hdr = ForwardV2Header::new("127.0.0.1".to_string(), 22, agent, Vec::new(), machine);
        hdr.issued_at_ms = ts.saturating_sub(FORWARD_V2_ATTESTATION_TTL_MS + 1000);
        let _sig = sign_with_ml_dsa(kp.secret_key(), &hdr.signable_bytes()).unwrap();
        hdr.signature = _sig.as_bytes().to_vec();
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: ts
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );
    }

    #[tokio::test]
    async fn decide_inbound_attested_replay_future() {
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let machine = MachineId([2u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let cache = cache_with_agent(&kp, machine);
        let contacts = trusted_store(agent);
        let policy = policy_with_allow(agent, machine, target);
        let ts = now_ms();
        let mut hdr = ForwardV2Header::new("127.0.0.1".to_string(), 22, agent, Vec::new(), machine);
        hdr.issued_at_ms = ts + FORWARD_V2_ATTESTATION_FUTURE_SKEW_MS + 1000;
        let _sig = sign_with_ml_dsa(kp.secret_key(), &hdr.signable_bytes()).unwrap();
        hdr.signature = _sig.as_bytes().to_vec();
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: ts
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::AttestationFailed,
        );
    }

    #[tokio::test]
    async fn decide_inbound_attested_blocked_agent_denied() {
        // Must-fix 3: Blocked-but-announced agent denied.
        let kp = AgentKeypair::generate().unwrap();
        let agent = kp.agent_id();
        let machine = MachineId([2u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let cache = cache_with_agent(&kp, machine);
        let contacts = blocked_store(agent);
        let policy = policy_with_allow(agent, machine, target);
        let hdr = signed_v2_header("127.0.0.1", 22, &kp, machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: now_ms()
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::TrustRejected,
        );
    }

    #[tokio::test]
    async fn decide_inbound_attested_multi_agent_checks_only_attested() {
        let machine = MachineId([2u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let kp_a = AgentKeypair::generate().unwrap();
        let agent_a = kp_a.agent_id();
        let kp_b = AgentKeypair::generate().unwrap();
        let agent_b = kp_b.agent_id();
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
        let contacts = trusted_store(agent_a);
        // Also trust agent_b so the trust check passes and we isolate the
        // ACL denial (agent_b is in the cache + trusted but NOT in the ACL).
        {
            let mut cs = contacts.write().await;
            cs.set_identity_type(&agent_b, IdentityType::Anonymous);
            cs.set_trust(&agent_b, TrustLevel::Trusted);
        }
        let policy = policy_multi(vec![allow_entry(agent_a, machine, &[target])]);
        let hdr_a = signed_v2_header("127.0.0.1", 22, &kp_a, machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr_a,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: now_ms()
                }
            )
            .await
            .unwrap(),
            target,
        );
        let hdr_b = signed_v2_header("127.0.0.1", 22, &kp_b, machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr_b,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: now_ms()
                }
            )
            .await
            .unwrap_err(),
            ConnectDenialReason::AgentMachineNotInAcl,
        );
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
    async fn decide_inbound_attested_empty_cache_key_allowed_via_header() {
        // Soak NO-GO fix: even when the discovery cache has an EMPTY
        // agent_public_key (the presence-beacon case), the V2 forward
        // succeeds because the public key travels in the header itself.
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
                agent_public_key: Vec::new(), // empty — beacon case
            },
        );
        let cache = Arc::new(tokio::sync::RwLock::new(cache_map));
        let contacts = trusted_store(agent);
        let policy = policy_with_allow(agent, machine, target);
        let hdr = signed_v2_header("127.0.0.1", 22, &kp, machine);
        assert_eq!(
            decide_inbound_attested(
                &hdr,
                &policy,
                &machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache.clone(),
                    contact_store: contacts.clone(),
                    own_machine_id: machine,
                    now_ms: now_ms(),
                }
            )
            .await
            .unwrap(),
            target,
        );
    }
}
