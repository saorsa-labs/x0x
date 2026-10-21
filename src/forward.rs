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
//!   `ForwardV1`/`ForwardV2` streams from its registered protocol acceptors
//!   ([`crate::Agent::register_stream_acceptor`]), reads
//!   the header, and calls [`crate::connect::evaluate_connect_gate`] BEFORE
//!   any `TcpStream::connect`. The stream already cleared the T1 identity
//!   gate (verified + trust `Accept` + not revoked) and the stream-layer
//!   connect-ACL pair gate, so the connect gate is
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
//! ## Persistence and machine binding (ADR-0074 §2 / §1)
//!
//! Forwards persist by default in [`crate::forward::store`]; `--ephemeral`
//! opts out. A forward with a pinned [`crate::identity::MachineId`] checks
//! `PeerStream::peer()` before any forward-header byte; a mismatch resets
//! the stream and counts `machine_mismatch`, and never falls back to V1.
//!
//! The header codec and the inbound gate decision are pure functions of
//! bytes / resolved inputs so the whole deny/allow matrix is fast unit-
//! testable without a live QUIC pair (the real stream wiring is proven by
//! `tests/tailnet_streams_integration.rs` + T7).

pub mod store;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::connect::gate::ConnectDenialReason;
use crate::connect::{
    evaluate_connect_gate, evaluate_connect_gate_for_principals, ConnectDiagnostics, ConnectPolicy,
};
use crate::error::{NetworkError, NetworkResult};
use crate::identity::{AgentId, AgentKeypair, MachineId};
use crate::streams::{PeerStream, StreamProtocol};
use crate::trust::TrustDecision;

pub(crate) mod teardown;

// Import the ant-quic stream halves under stable names for the bridge helper,
// plus the ML-DSA-65 sign/verify primitives for ForwardV2 attestation.
use crate::network::{StreamRecv as HighLevelRecvStream, StreamSend as HighLevelSendStream};
use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;

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
pub(crate) struct AttestationVerifyCtx {
    discovery_cache: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<AgentId, crate::DiscoveredAgent>>,
    >,
    contact_store: std::sync::Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
    own_machine_id: MachineId,
    /// Unix-ms clock set at construction (system / ReauthCtx). Freshness and
    /// post-await cert expiry read `(clock)()`; callers cannot stamp `now`.
    clock: teardown::Clock,
    revocation_set: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    move_state: Arc<tokio::sync::RwLock<crate::key_move::MoveState>>,
    /// ADR-0070 §1 owner trust: feeds the trust decision and the
    /// `principal = "owner"` connect-ACL selector.
    owner_trust: crate::owner_trust::OwnerTrust,
    /// When true (ADR-0074 §4 re-check), grant evaluation uses only local
    /// authority stores — no EvidenceV1 wait/lookup.
    local_authority_only: bool,
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
/// Also returns the authority the stream is admitted under (ADR-0074 §4).
async fn decide_inbound_attested_with_authority(
    header: &ForwardV2Header,
    policy: &ConnectPolicy,
    peer_machine: &MachineId,
    ctx: &AttestationVerifyCtx,
) -> Result<(SocketAddr, teardown::StreamAuthority), ConnectDenialReason> {
    // Resolve the target first (same as V1 — a non-loopback target is
    // refused before the attestation check, so an unverified peer learns
    // nothing about which agents exist).
    let target = resolve_loopback_target(&header.target_host, header.target_port)
        .map_err(|_| ConnectDenialReason::TargetNotLoopback)?;

    // ── Replay: recipient scope binding ──────────────────────────────
    // The header must name THIS machine as the recipient — a header captured
    // on machine A cannot be replayed to machine B. NOTE: the comparison is
    // against the LOCAL machine id, never `peer_machine` — comparing against
    // the opener's machine denied every cross-node forward (#216).
    if header.recipient_machine_id != ctx.own_machine_id {
        tracing::warn!(
            target: "x0x::forward",
            reason = "recipient_mismatch",
            stamped_recipient = %hex::encode(header.recipient_machine_id.as_bytes()),
            own_machine = %hex::encode(ctx.own_machine_id.as_bytes()),
            "forward v2 attestation denied: recipient binding is not this machine"
        );
        return Err(ConnectDenialReason::AttestationFailed);
    }

    // ── Replay: freshness / TTL ──────────────────────────────────────
    if header.issued_at_ms == 0 {
        tracing::warn!(
            target: "x0x::forward",
            reason = "missing_issued_at",
            "forward v2 attestation denied: header carries no issue timestamp"
        );
        return Err(ConnectDenialReason::AttestationFailed);
    }
    let now_ms = (ctx.clock)();
    // Stale: older than the TTL window.
    if now_ms
        > header
            .issued_at_ms
            .saturating_add(FORWARD_V2_ATTESTATION_TTL_MS)
    {
        tracing::warn!(
            target: "x0x::forward",
            reason = "stale_attestation",
            issued_at_ms = header.issued_at_ms,
            now_ms,
            ttl_ms = FORWARD_V2_ATTESTATION_TTL_MS,
            "forward v2 attestation denied: attestation older than TTL"
        );
        return Err(ConnectDenialReason::AttestationFailed);
    }
    // Future: more than the skew allowance ahead of our clock.
    if header.issued_at_ms > now_ms.saturating_add(FORWARD_V2_ATTESTATION_FUTURE_SKEW_MS) {
        tracing::warn!(
            target: "x0x::forward",
            reason = "future_attestation",
            issued_at_ms = header.issued_at_ms,
            now_ms,
            skew_ms = FORWARD_V2_ATTESTATION_FUTURE_SKEW_MS,
            "forward v2 attestation denied: attestation dated beyond clock-skew allowance"
        );
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
    let agent = cached.ok_or_else(|| {
        tracing::warn!(
            target: "x0x::forward",
            reason = "agent_not_in_discovery_cache",
            agent = %hex::encode(header.opener_agent_id.as_bytes()),
            "forward v2 attestation denied: opener absent from discovery cache"
        );
        ConnectDenialReason::AttestationFailed
    })?;

    // Confirm the agent is on the transport-authenticated machine.
    if agent.machine_id != *peer_machine {
        tracing::warn!(
            target: "x0x::forward",
            reason = "agent_not_on_machine",
            agent = %hex::encode(header.opener_agent_id.as_bytes()),
            cached_machine = %hex::encode(agent.machine_id.as_bytes()),
            peer_machine = %hex::encode(peer_machine.as_bytes()),
            "forward v2 attestation denied: cached machine differs from transport peer"
        );
        return Err(ConnectDenialReason::AgentNotOnMachine);
    }

    // Verify the attestation against the HEADER's public key. The
    // `verify_attestation` method checks `SHA-256(key) == opener_agent_id`
    // (binding) and the ML-DSA-65 signature. This eliminates the dependency
    // on the discovery cache having a non-empty `agent_public_key` — the soak
    // NO-GO root cause.
    // #216: log the inner ForwardError (missing / key-binding / signature)
    // BEFORE collapsing to `AttestationFailed` — the silent collapse made the
    // cross-node happy-path failure undiagnosable at the default WARN level.
    header
        .verify_attestation(&header.opener_agent_public_key)
        .map_err(|e| {
            tracing::warn!(
                target: "x0x::forward",
                reason = "attestation_verify_failed",
                error = %e,
                agent = %hex::encode(header.opener_agent_id.as_bytes()),
                "forward v2 attestation denied: cryptographic verification failed"
            );
            ConnectDenialReason::AttestationFailed
        })?;

    // Opportunistically upgrade the cache entry with the header's key so
    // subsequent forwards (and other subsystems) benefit.
    if agent.agent_public_key.is_empty() && !header.opener_agent_public_key.is_empty() {
        let mut cache = ctx.discovery_cache.write().await;
        if let Some(entry) = cache.get_mut(&header.opener_agent_id) {
            entry.agent_public_key = header.opener_agent_public_key.clone();
        }
    }

    // The opener is now cryptographically authenticated: authorize that
    // specific agent against current authority. The same check re-runs on
    // every live stream (ADR-0074 §4, `teardown`).
    let authority = match authorize_attested_opener(
        &header.opener_agent_id,
        peer_machine,
        &target,
        policy,
        ctx,
    )
    .await
    {
        LocalAuthorityOutcome::Allow(a) => a,
        LocalAuthorityOutcome::Deny(d) => return Err(d.connect_reason()),
        // Admission uses blocking evidence reads; Busy is reauth-only.
        LocalAuthorityOutcome::Busy => return Err(ConnectDenialReason::AttestationFailed),
    };
    Ok((target, authority))
}

/// [`decide_inbound_attested_with_authority`] without the authority (the
/// gate-matrix tests compare the admitted target only).
#[cfg(test)]
async fn decide_inbound_attested(
    header: &ForwardV2Header,
    policy: &ConnectPolicy,
    peer_machine: &MachineId,
    ctx: &AttestationVerifyCtx,
) -> Result<SocketAddr, ConnectDenialReason> {
    decide_inbound_attested_with_authority(header, policy, peer_machine, ctx)
        .await
        .map(|(target, _)| target)
}

/// Outcome of a local-authority gate or authorize evaluation (crate-private).
///
/// `Busy` means any nonblocking authority read performed during this
/// evaluation was contended (`try_usable` → `Err`). Teardown retries on Busy
/// and treats Deny as a fresh authority verdict — it must not probe agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalAuthorityOutcome<T, E> {
    Allow(T),
    Deny(E),
    Busy,
}

/// Gate error for local-authority (`local_authority_only`) peer gates.
///
/// `Busy` when any resident's nonblocking authority read during that eval
/// was contended (`try_usable` → `Err`, or `try_confirms_pairing` → `None`).
#[derive(Debug)]
pub(crate) enum PeerGateError {
    Busy,
    Network(NetworkError),
}

impl From<NetworkError> for PeerGateError {
    fn from(e: NetworkError) -> Self {
        Self::Network(e)
    }
}

impl PeerGateError {
    pub(crate) fn into_outcome<T>(self) -> LocalAuthorityOutcome<T, NetworkError> {
        match self {
            Self::Busy => LocalAuthorityOutcome::Busy,
            Self::Network(e) => LocalAuthorityOutcome::Deny(e),
        }
    }

    /// Admission / new-stream fail-closed mapping (Busy is not a public error).
    pub(crate) fn fail_closed_admission(self, agent_id: [u8; 32]) -> NetworkError {
        match self {
            Self::Busy => NetworkError::PeerNotVerified { agent_id },
            Self::Network(e) => e,
        }
    }
}

/// Reauth wrapper for [`crate::Agent::gate_peer_outbound_at`].
///
/// Busy comes from the gate itself when the peer agent's nonblocking
/// authority read was contended.
pub(crate) async fn gate_peer_outbound_outcome(
    ctx: &teardown::ReauthCtx,
    peer_agent: &AgentId,
) -> LocalAuthorityOutcome<MachineId, NetworkError> {
    match crate::Agent::gate_peer_outbound_at(
        &ctx.discovery_cache,
        &ctx.contact_store,
        &ctx.revocation_set,
        &ctx.move_state,
        &ctx.owner_trust,
        &ctx.announced_bindings,
        &ctx.authenticated_bindings,
        peer_agent,
        true,
    )
    .await
    {
        Ok(machine) => LocalAuthorityOutcome::Allow(machine),
        Err(e) => e.into_outcome(),
    }
}

/// Reauth wrapper for [`crate::Agent::gate_peer_machine_inbound_at`].
///
/// Busy when **any** resident agent's nonblocking authority read was
/// contended (not only the attested opener).
pub(crate) async fn gate_peer_machine_inbound_outcome(
    ctx: &teardown::ReauthCtx,
    machine: &MachineId,
) -> LocalAuthorityOutcome<Vec<AgentId>, NetworkError> {
    match crate::Agent::gate_peer_machine_inbound_at(
        &ctx.discovery_cache,
        &ctx.contact_store,
        &ctx.revocation_set,
        &ctx.move_state,
        &ctx.connect_policy,
        &ctx.owner_trust,
        machine,
        true,
    )
    .await
    {
        Ok(agents) => LocalAuthorityOutcome::Allow(agents),
        Err(e) => e.into_outcome(),
    }
}

/// Why [`authorize_attested_opener`] refused (internal). Maps onto the wire
/// [`ConnectDenialReason`] exactly as the pre-split gate did, and onto a
/// finer teardown reason for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthzDenial {
    /// The connect gate refused.
    Gate(ConnectDenialReason),
    /// The opener is absent from the discovery cache.
    AgentUnknown,
    /// The opener's cached machine is not the transport peer.
    AgentNotOnMachine,
    /// The opener or its machine is revoked.
    Revoked,
    /// The opener's certificate has expired.
    CertExpired,
    /// The opener's trust decision is not `Accept`.
    TrustRejected,
    /// ADR-0043: the (agent, machine) pairing is retired.
    PairingRetired,
}

impl AuthzDenial {
    /// The typed denial frame the opener sees at admission.
    fn connect_reason(self) -> ConnectDenialReason {
        match self {
            Self::Gate(reason) => reason,
            Self::AgentNotOnMachine => ConnectDenialReason::AgentNotOnMachine,
            Self::AgentUnknown
            | Self::Revoked
            | Self::CertExpired
            | Self::TrustRejected
            | Self::PairingRetired => ConnectDenialReason::AttestationFailed,
        }
    }
}

/// Authorization half of the attested (`ForwardV2`) inbound gate: every
/// check that depends on current authority rather than on the header bytes.
/// Admission runs it after the attestation checks; the ADR-0074 §4 re-check
/// runs it again on every live stream, so a stream is kept exactly while a
/// fresh admission would still pass.
///
/// Returns the authority the stream holds: the ACL entry kind that matched
/// and, for a grant, the Connect grants covering the target port.
///
/// When a nonblocking authority read inside this path is contended,
/// returns [`LocalAuthorityOutcome::Busy`].
pub(crate) async fn authorize_attested_opener(
    opener: &AgentId,
    peer_machine: &MachineId,
    target: &SocketAddr,
    policy: &ConnectPolicy,
    ctx: &AttestationVerifyCtx,
) -> LocalAuthorityOutcome<teardown::StreamAuthority, AuthzDenial> {
    use crate::owner_trust::NonblockingEval;

    let agent = {
        let cache = ctx.discovery_cache.read().await;
        cache.get(opener).cloned()
    };
    let Some(agent) = agent else {
        return LocalAuthorityOutcome::Deny(AuthzDenial::AgentUnknown);
    };
    if agent.machine_id != *peer_machine {
        return LocalAuthorityOutcome::Deny(AuthzDenial::AgentNotOnMachine);
    }

    // ── Trust evaluation (#204 must-fix 3): evaluate the attested agent's
    // real trust — NOT a hard-coded Accept. A Blocked-but-announced agent
    // must be denied here (same pattern as the stream gate).
    // ADR-0070 §1: owner trust is an input to that decision, and the only
    // way a `principal = "owner"` ACL entry can match.
    // ADR-0074 §4: reauth (`local_authority_only`) surfaces Busy on a
    // contended evidence store inside owner-trust / grant eval.
    let pair = if ctx.local_authority_only {
        match ctx
            .owner_trust
            .evaluate_pair_nonblocking(
                &ctx.contact_store,
                &ctx.discovery_cache,
                &ctx.revocation_set,
                opener,
                peer_machine,
            )
            .await
        {
            NonblockingEval::Busy => return LocalAuthorityOutcome::Busy,
            NonblockingEval::Done(pair) => pair,
        }
    } else {
        ctx.owner_trust
            .evaluate_pair_with(
                &ctx.contact_store,
                &ctx.discovery_cache,
                &ctx.revocation_set,
                opener,
                peer_machine,
                false,
            )
            .await
    };

    // ADR-0070 §2: a current ShareGrant whose Connect ports cover THIS
    // target lets a `principal = "grant"` entry match, and raises the trust
    // decision for this target only. Blocked/pin mismatch get no grant.
    // Grant expiry uses OwnerTrust's construction-injected clock (no now arg).
    let access = if ctx.local_authority_only {
        match ctx
            .owner_trust
            .grant_access_nonblocking(
                &ctx.contact_store,
                &ctx.discovery_cache,
                &ctx.revocation_set,
                opener,
                peer_machine,
            )
            .await
        {
            NonblockingEval::Busy => return LocalAuthorityOutcome::Busy,
            NonblockingEval::Done(access) => access,
        }
    } else {
        ctx.owner_trust
            .grant_access_at(
                &ctx.contact_store,
                &ctx.discovery_cache,
                &ctx.revocation_set,
                opener,
                peer_machine,
                true,
            )
            .await
    };
    let grant_port_allowed = access.allows_connect_port(target.port());
    let decision = pair.decision.with_owner_trust(grant_port_allowed);

    // ACL-check that specific agent with its REAL trust decision.
    if let Err(reason) = evaluate_connect_gate_for_principals(
        /* verified */ true,
        Some(decision),
        policy,
        opener,
        peer_machine,
        pair.owner_trusted,
        grant_port_allowed,
        target,
    ) {
        return LocalAuthorityOutcome::Deny(AuthzDenial::Gate(reason));
    }

    // The machine-level gate may have excluded a moved-away co-resident
    // while accepting a live agent on the same machine. Authenticate the
    // header's exact opener against CURRENT authority too: a valid signature
    // and a stale discovery binding must not resurrect that dead pairing.
    // Snapshot only this placement, then release its lock before reading
    // revocation state; no shared locks are held across another lock await.
    let placement = ctx.move_state.read().await.placement(opener).cloned();
    let placements = placement
        .map(|record| std::collections::HashMap::from([(*opener, record)]))
        .unwrap_or_default();
    let revoked = ctx.revocation_set.read().await;
    // Read clock immediately before expiry — not a stamp captured pre-await.
    let now_secs = (ctx.clock)() / 1000;
    if let Err(e) = crate::streams::stream_gate(
        opener,
        Some(decision),
        revoked.is_agent_revoked(opener),
        revoked.is_machine_revoked(peer_machine),
        crate::identity::is_expired(agent.cert_not_after, now_secs),
    ) {
        let denial = match e {
            NetworkError::PeerRevoked { .. } => AuthzDenial::Revoked,
            NetworkError::PeerNotVerified { .. } => AuthzDenial::CertExpired,
            _ => AuthzDenial::TrustRejected,
        };
        return LocalAuthorityOutcome::Deny(denial);
    }
    if crate::key_move::enforce_pairing(&revoked, &placements, opener, peer_machine).is_some() {
        return LocalAuthorityOutcome::Deny(AuthzDenial::PairingRetired);
    }

    LocalAuthorityOutcome::Allow(teardown::StreamAuthority::classify(
        policy,
        opener,
        peer_machine,
        pair.owner_trusted,
        target,
        &access.connect_grant_ids,
    ))
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
    /// Live streams torn down because their authority is gone (ADR-0074 §4).
    torn_down_reauth: AtomicU64,
    /// Live streams torn down by process/service shutdown (not trust-loss).
    torn_down_shutdown: AtomicU64,
    /// Teardown reasons for debug (`revoked`, `trust_rejected`, `shutdown`, …).
    /// Shutdown increments [`Self::torn_down_shutdown`], not
    /// [`Self::torn_down_reauth`].
    torn_down_reasons: std::sync::Mutex<std::collections::BTreeMap<&'static str, u64>>,
    /// Outbound streams reset before any header byte because they reached a
    /// different machine than the forward's pinned `MachineId` (ADR-0074 §1).
    machine_mismatch: AtomicU64,
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
    /// Record a live stream torn down for `reason` (ADR-0074 §4).
    pub(crate) fn record_torn_down(&self, reason: &'static str) {
        self.torn_down_reauth.fetch_add(1, Ordering::Relaxed);
        let mut reasons = self
            .torn_down_reasons
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *reasons.entry(reason).or_insert(0) += 1;
    }
    /// Record a live stream torn down by shutdown (not trust-loss).
    pub(crate) fn record_torn_down_shutdown(&self) {
        self.torn_down_shutdown.fetch_add(1, Ordering::Relaxed);
        let mut reasons = self
            .torn_down_reasons
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *reasons.entry("shutdown").or_insert(0) += 1;
    }
    /// Live streams torn down because their authority is gone (ADR-0074 §4).
    /// Logged as `torn_down_total` on each teardown.
    #[must_use]
    pub(crate) fn torn_down_reauth(&self) -> u64 {
        self.torn_down_reauth.load(Ordering::Relaxed)
    }
    /// Live streams torn down by shutdown (not trust-loss).
    #[must_use]
    pub(crate) fn torn_down_shutdown(&self) -> u64 {
        self.torn_down_shutdown.load(Ordering::Relaxed)
    }
    /// Teardown reasons for debug (`revoked`, `trust_rejected`,
    /// `target_not_allowed`, `shutdown`, ...).
    #[must_use]
    pub(crate) fn torn_down_reasons(&self) -> std::collections::BTreeMap<String, u64> {
        self.torn_down_reasons
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(k, count)| ((*k).to_string(), *count))
            .collect()
    }
    /// Record an outbound stream refused at the machine-binding check
    /// (ADR-0074 §1).
    pub fn record_machine_mismatch(&self) {
        self.machine_mismatch.fetch_add(1, Ordering::Relaxed);
    }
    /// Outbound streams refused because they reached an unpinned machine.
    #[must_use]
    pub fn machine_mismatch(&self) -> u64 {
        self.machine_mismatch.load(Ordering::Relaxed)
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
    /// ADR-0043 derived move state — the mid-flight re-check evaluates
    /// B/P for EVERY (agent, machine) pairing the lane resolves (both
    /// machines during the transition window), never per agent.
    pub move_state: Arc<tokio::sync::RwLock<crate::key_move::MoveState>>,
    pub discovery_cache:
        Arc<tokio::sync::RwLock<std::collections::HashMap<AgentId, crate::DiscoveredAgent>>>,
    pub contact_store: Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
    pub own_machine_id: MachineId,
    pub require_attestation: bool,
    /// ADR-0070 §1 owner trust for the attested (`ForwardV2`) gate.
    pub owner_trust: crate::owner_trust::OwnerTrust,
    /// ADR-0074 §4 registry of live forward streams (re-checked on every
    /// authority change; see [`teardown`]).
    pub live: Arc<teardown::LiveStreams>,
    /// Wake the open-stream reauth loop after early registration so a
    /// revocation that landed in the admit→register gap is applied promptly.
    pub reauth: Arc<tokio::sync::Notify>,
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

    // ADR-0043 §9: B/P for every (agent, machine) pairing the lane
    // resolves — per pairing, never per agent, so the transition window
    // (agent discoverable on both machines) resolves correctly: the
    // source pairing dies, the target passes.
    {
        let placements = ctx.move_state.read().await;
        let revoked = ctx.revocation_set.read().await;
        for agent in &agents {
            if crate::key_move::enforce_pairing(
                &revoked,
                placements.placement_view(),
                agent,
                &machine_id,
            )
            .is_some()
            {
                ctx.fwd_diag.record_revoked_mid_flight();
                tracing::info!(
                    target: "x0x::forward",
                    agent = %hex::encode(agent.as_bytes()),
                    machine = %hex::encode(peer.as_bytes()),
                    outcome = "drop_pairing_mid_flight",
                    "inbound forward: ADR-0043 B/P pairing gate — dropping before header read"
                );
                return;
            }
        }
    }

    // Read header + run the connect gate, branching on the stream protocol.
    // ForwardV2: attestation path — verify the opener's signature against the
    // cached agent key, confirm machine binding, ACL-check the single
    // authenticated agent (#204). ForwardV1: legacy multi-agent fail-closed
    // (#192), kept for backward compatibility with pre-#204 peers.
    let (target, gate, authority) = match stream.protocol() {
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
            let verify_ctx = AttestationVerifyCtx {
                discovery_cache: Arc::clone(&ctx.discovery_cache),
                contact_store: Arc::clone(&ctx.contact_store),
                own_machine_id: ctx.own_machine_id,
                clock: teardown::system_clock(),
                revocation_set: Arc::clone(&ctx.revocation_set),
                move_state: Arc::clone(&ctx.move_state),
                owner_trust: ctx.owner_trust.clone(),
                local_authority_only: false,
            };
            match decide_inbound_attested_with_authority(
                &header,
                &ctx.policy,
                &machine_id,
                &verify_ctx,
            )
            .await
            {
                Ok((addr, authority)) => (
                    addr,
                    teardown::StreamGate::InboundAttested {
                        opener: header.opener_agent_id,
                        machine: machine_id,
                        target: addr,
                    },
                    authority,
                ),
                Err(reason) => {
                    ctx.connect_diag.record_denied(reason);
                    send_denial(&mut stream, reason).await;
                    tracing::warn!(
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
                tracing::warn!(
                    target: "x0x::forward",
                    peer = %hex::encode(peer.as_bytes()),
                    reason = "attestation_required",
                    "inbound forward v1 denied: attestation required (require_attestation=true)"
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
                Ok(addr) => (
                    addr,
                    teardown::StreamGate::InboundLegacy {
                        machine: machine_id,
                        target: addr,
                    },
                    teardown::StreamAuthority::AclEntry,
                ),
                Err(reason) => {
                    ctx.connect_diag.record_denied(reason);
                    send_denial(&mut stream, reason).await;
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
        send_denial(&mut stream, ConnectDenialReason::TargetNotLoopback).await;
        return;
    }

    // ADR-0074 §4: register before the connect/response window so a
    // revocation in that gap is visible to the reauth loop (≤5 s), not only
    // after the 30 s sweep. Kick a pass now; abort if already cancelled.
    let live = ctx.live.register(gate, authority);
    ctx.reauth.notify_one();
    if live.token().is_cancelled() {
        teardown::deny_pre_bridge(&mut stream, None);
        return;
    }

    // Connect the local loopback target with a bounded timeout; abort early
    // if reauth tears the registration down while we wait.
    let local = match teardown::wait_cancellable(
        live.token(),
        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target)),
    )
    .await
    {
        Err(teardown::Cancelled) => {
            teardown::deny_pre_bridge(&mut stream, None);
            return;
        }
        Ok(Ok(Ok(tcp))) => tcp,
        Ok(Ok(Err(e))) => {
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
        Ok(Err(_)) => {
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
    if live.token().is_cancelled() {
        teardown::deny_pre_bridge(&mut stream, Some(&local));
        return;
    }

    // Signal connected, then bridge. The connect-allow counter records that
    // the gate admitted this flow.
    ctx.connect_diag.record_allowed();
    match teardown::wait_cancellable(
        live.token(),
        stream.send_mut().write_all(&encode_response_connected()),
    )
    .await
    {
        Err(teardown::Cancelled) => {
            teardown::deny_pre_bridge(&mut stream, Some(&local));
            return;
        }
        Ok(Err(_)) => return,
        Ok(Ok(())) => {}
    }
    if live.token().is_cancelled() {
        teardown::deny_pre_bridge(&mut stream, Some(&local));
        return;
    }
    let (send, recv) = stream.into_split();
    bridge(local, send, recv, live.token()).await;
}

/// RAII guard that decrements the active-stream counter when a forward task ends.
struct StreamLeaveGuard(Arc<ForwardDiagnostics>);
impl Drop for StreamLeaveGuard {
    fn drop(&mut self) {
        self.0.leave_stream();
    }
}

/// Write the connect-denied response byte and `finish()` the send stream so
/// the opener reads the denial byte followed by a clean FIN (#961). Without
/// the finish, dropping the stream resets it and the reset can overtake the
/// byte. Nothing else is ever written: the opener sees exactly one byte, then
/// EOF. A finished-then-dropped ant-quic stream keeps retransmitting its
/// buffered data, so returning right after is safe.
async fn send_denial(stream: &mut PeerStream, reason: ConnectDenialReason) {
    let send = stream.send_mut();
    if send
        .write_all(&encode_response_denied(reason))
        .await
        .is_ok()
    {
        let _ = send.finish();
    }
}

/// Bridge a local TCP connection and the peer stream's two halves until both
/// directions close. QUIC provides native flow control; `copy` is bounded by
/// QUIC backpressure so no unbounded buffer is introduced.
///
/// Half-close propagates per direction (#961): when a source reaches a clean
/// EOF the destination writer is shut down — a QUIC FIN for the send stream,
/// a TCP `shutdown(Write)` for the socket — while the other direction keeps
/// flowing. On a copy error the writer is left unfinished, so dropping the
/// QUIC send stream resets it and the truncation surfaces as an error rather
/// than a well-formed but short stream.
async fn bridge(
    tcp: TcpStream,
    mut send: HighLevelSendStream,
    mut recv: HighLevelRecvStream,
    cancel: &CancellationToken,
) {
    // #961: split the TCP so each direction can half-close independently.
    // When the local client is done writing, we finish the QUIC send half
    // (FIN) without resetting the stream — the peer can still drain its
    // response. A full reset only happens on error or reauth teardown.
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    // ADR-0074 §4: `cancel` fires when the stream's authority is gone. Both
    // halves reset with DROPPED_UNFINISHED_ERROR_CODE (same as main's deny
    // drop path) and TCP linger 0 / RST so neither end keeps a half-open
    // zombie. Reauth teardowns are counted in `torn_down_reauth`.
    let torn_down =
        teardown::bridge_io(&mut tcp_read, &mut tcp_write, &mut recv, &mut send, cancel).await;
    if torn_down {
        teardown::reset_quic(&mut send, &mut recv);
        // Linger 0 + forget the write half so drop does not send FIN first
        // (OwnedWriteHalf::drop calls shutdown(Write) unless forgotten). The
        // read-half drop then closes the socket with RST (ADR-0074 §4).
        teardown::reset_tcp(&tcp_write);
        tcp_write.forget();
    }
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
///
/// TCP forwards write through [`send_header_to_pinned`] so a machine-pin
/// mismatch sends zero header bytes. SOCKS prepare has no pin and writes here.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForwardSpec {
    /// Local loopback address the daemon binds (`127.0.0.1:PORT`).
    pub local_addr: SocketAddr,
    /// Peer agent to tunnel to (hex).
    pub peer_agent: AgentId,
    /// Loopback target host on the peer's machine (numeric IP).
    pub target_host: String,
    /// Loopback target port.
    pub target_port: u16,
    /// Canonical kind-prefixed name, or `None` for a hex peer.
    pub name: Option<String>,
    /// Agent or machine target (meaningful with `name`).
    pub kind: crate::names::NameKind,
    /// ADR-0074 §1 machine binding: when set, every stream this forward
    /// opens must reach this `MachineId` (`PeerStream::peer()`), checked
    /// before any forward-header byte is sent; a mismatch resets the
    /// stream and counts `machine_mismatch`.
    pub pinned_machine: Option<MachineId>,
    /// Persisted in `forwards.json` (ADR-0074 §2); `false` for
    /// `--ephemeral` forwards.
    pub persistent: bool,
}

impl ForwardSpec {
    /// The peer agent id as a hex string (for REST/CLI display).
    #[must_use]
    pub fn peer_agent_hex(&self) -> String {
        hex::encode(self.peer_agent.as_bytes())
    }
}

/// One registered forward as `GET /forwards` reports it: its spec, and the
/// reason it is down when it is not listening (a restored forward whose
/// name no longer resolves to its pinned ids, or whose port is busy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardStatus {
    /// The forward.
    pub spec: ForwardSpec,
    /// `None` while listening; otherwise why the forward is down.
    pub error: Option<String>,
}

/// Whether a registered forward is listening (internal).
enum EntryState {
    /// Listening; cancelling the token stops the listener.
    Active(CancellationToken),
    /// Registered but down, with the reason (ADR-0074 §2: a restored
    /// forward that could not be re-resolved or re-bound).
    Disabled(String),
}

/// A registered forward + its state (internal).
struct ForwardEntry {
    spec: ForwardSpec,
    state: EntryState,
}

/// `add_forward` returns this when a `:0` bind lands on a forward that
/// already owns the address. The caller retries. The colliding listener
/// stays open until [`ForwardService::release_allocation_holds`].
const PORT_ALLOCATION_COLLISION: &str = "allocated port belongs to another forward";

pub(crate) fn is_port_allocation_collision(err: &NetworkError) -> bool {
    matches!(
        err,
        NetworkError::ConnectionFailed(message) if message == PORT_ALLOCATION_COLLISION
    )
}

/// How [`ForwardService::shutdown_and_release`] finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForwardShutdownReport {
    /// Transactions still running when the 2s drain ended. They were aborted.
    pub abandoned_transactions: usize,
}

/// Owns the inbound forward consumers + the outbound local listeners.
///
/// The forwarder is the registered acceptor for the `ForwardV1` and
/// `ForwardV2` stream protocols
/// ([`crate::Agent::register_stream_acceptor`]): the accept loop routes
/// identity-gated, ACL-gated forward streams straight to this service's
/// bounded acceptor channels, and each is gated again by `handle_inbound`
/// (resolve → `evaluate_connect_gate` → connect loopback → bridge). Outbound
/// listeners (`add_forward`) accept local TCP, open a peer stream, write the
/// `ForwardHeader`, and bridge on `connected`.
pub struct ForwardService {
    agent: Arc<crate::Agent>,
    connect_diag: Arc<ConnectDiagnostics>,
    fwd_diag: Arc<ForwardDiagnostics>,
    /// Registered forwards (spec + cancellation) so `shutdown` / `remove` can
    /// tear down individual listeners and `list` can return them.
    ///
    /// Also the gate for [`Self::listeners_closed`]: `add_forward` checks that
    /// flag and publishes its accept-loop [`JoinHandle`](tokio::task::JoinHandle)
    /// while it holds this lock, and shutdown takes those handles under the
    /// same lock. A bind that resumes after shutdown cannot publish a listener
    /// the drain will miss.
    forwards: std::sync::Mutex<Vec<ForwardEntry>>,
    /// Accept loops for [`Self::add_forward`]. Shutdown awaits these after it
    /// cancels them, so the bound port is free when shutdown returns.
    listener_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Ports from a `:0` allocation that matched a saved forward.
    /// Held so the next allocation cannot take the same port, then released
    /// when the add finishes or the forwarder shuts down.
    allocation_holds: std::sync::Mutex<Vec<tokio::net::TcpListener>>,
    /// Set under [`Self::forwards`] before listener tokens are cancelled.
    listeners_closed: std::sync::atomic::AtomicBool,
    /// Test-only bind addresses, consumed from the front.
    #[cfg(test)]
    bind_script: std::sync::Mutex<Vec<SocketAddr>>,
    /// Add, remove, and restore transactions. `None` refuses new ones.
    /// Shutdown drains the admitted tasks before it cancels listeners, so a
    /// transaction cannot bind after shutdown has returned.
    transactions: std::sync::Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>,
    inbound_token: CancellationToken,
    /// The forwarder-owned protocol acceptors (`ForwardV1`, `ForwardV2`),
    /// moved into their consumer loops by `spawn_inbound`. `None` once the
    /// consumers are running (or after shutdown, when dropping the loops'
    /// acceptor handles deregisters them).
    inbound_acceptors: std::sync::Mutex<
        Option<(
            crate::streams::StreamAcceptor,
            crate::streams::StreamAcceptor,
        )>,
    >,
    /// FIX 3: global + per-peer concurrency caps. Admission requires a global
    /// permit (held for the stream's lifetime) AND a per-peer slot; a stream
    /// beyond either cap is reset + counted rather than spawned unbounded.
    inbound_permits: Arc<tokio::sync::Semaphore>,
    outbound_permits: Arc<tokio::sync::Semaphore>,
    per_peer: Arc<std::sync::Mutex<HashMap<AgentId, u32>>>,
    /// Shared revocation set for the FIX 4 pre-header re-check.
    revocation_set: Arc<tokio::sync::RwLock<crate::revocation::RevocationSet>>,
    /// ADR-0043 derived move state — the mid-flight B/P pairing re-check.
    move_state: Arc<tokio::sync::RwLock<crate::key_move::MoveState>>,
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
    /// ADR-0074 §4: live bridged streams, re-checked when authority changes.
    live: Arc<teardown::LiveStreams>,
    /// Ensures the reauth loop is spawned once.
    reauth_started: std::sync::atomic::AtomicBool,
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
    /// `policy` is installed on the agent ([`crate::Agent::set_connect_policy`]),
    /// which is the single hot-swappable holder (ADR-0070 §3): inbound
    /// streams are gated against the agent's policy current at accept.
    ///
    /// Registers the forwarder as the single acceptor for the `ForwardV1` and
    /// `ForwardV2` stream protocols ([`crate::Agent::register_stream_acceptor`])
    /// — inbound forward streams are routed to this service by the accept
    /// loop, never through a shared demux.
    ///
    /// `require_attestation` (default `true`) denies inbound ForwardV1 streams
    /// and gates the outbound V1 fallback — set `false` for mixed-version
    /// deployments (#204 must-fix 1).
    ///
    /// # Errors
    /// [`NetworkError::StreamAcceptorConflict`] if another consumer already
    /// owns one of the forward protocols on this agent (a second
    /// `ForwardService` on the same agent is refused).
    pub fn new(
        agent: Arc<crate::Agent>,
        policy: Arc<ConnectPolicy>,
        connect_diag: Arc<ConnectDiagnostics>,
        require_attestation: bool,
    ) -> NetworkResult<Self> {
        let acceptor_v1 =
            agent.register_stream_acceptor(crate::streams::StreamProtocol::ForwardV1)?;
        let acceptor_v2 =
            agent.register_stream_acceptor(crate::streams::StreamProtocol::ForwardV2)?;
        let revocation_set = agent.revocation_set();
        let discovery_cache = agent.identity_discovery_cache();
        let contact_store = agent.contact_store();
        let move_state = agent.move_state();
        // The agent owns the effective (hot-swappable) connect policy; the
        // forwarder reads it per stream rather than pinning a copy.
        agent.set_connect_policy(policy);
        let fwd_diag = Arc::new(ForwardDiagnostics::default());
        Ok(Self {
            agent,
            connect_diag,
            live: Arc::new(teardown::LiveStreams::new(Arc::clone(&fwd_diag))),
            fwd_diag,
            forwards: std::sync::Mutex::new(Vec::new()),
            listener_tasks: std::sync::Mutex::new(Vec::new()),
            allocation_holds: std::sync::Mutex::new(Vec::new()),
            listeners_closed: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            bind_script: std::sync::Mutex::new(Vec::new()),
            transactions: std::sync::Mutex::new(Some(Vec::new())),
            inbound_token: CancellationToken::new(),
            inbound_acceptors: std::sync::Mutex::new(Some((acceptor_v1, acceptor_v2))),
            inbound_permits: Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND_STREAMS)),
            outbound_permits: Arc::new(tokio::sync::Semaphore::new(MAX_OUTBOUND_STREAMS)),
            per_peer: Arc::new(std::sync::Mutex::new(HashMap::new())),
            revocation_set,
            move_state,
            discovery_cache,
            contact_store,
            require_attestation,
            reauth_started: std::sync::atomic::AtomicBool::new(false),
        })
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

    /// Start the inbound consumer loops — one per registered forward-protocol
    /// acceptor (`ForwardV1`, `ForwardV2`). Idempotent: a second call finds
    /// the acceptors already moved into their loops and returns without
    /// spawning duplicates. Returns immediately.
    pub fn spawn_inbound(self: &Arc<Self>) {
        self.ensure_reauth_loop();
        let acceptors = self
            .inbound_acceptors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some((acceptor_v1, acceptor_v2)) = acceptors else {
            tracing::debug!(
                target: "x0x::forward",
                "inbound forward consumers already started — ignoring duplicate spawn"
            );
            return;
        };
        self.spawn_acceptor_loop(acceptor_v1);
        self.spawn_acceptor_loop(acceptor_v2);
    }

    fn ensure_reauth_loop(&self) {
        if self.reauth_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let ctx = teardown::ReauthCtx {
            discovery_cache: Arc::clone(&self.discovery_cache),
            contact_store: Arc::clone(&self.contact_store),
            revocation_set: Arc::clone(&self.revocation_set),
            move_state: Arc::clone(&self.move_state),
            connect_policy: self.agent.connect_policy_holder(),
            owner_trust: self.agent.owner_trust().clone(),
            announced_bindings: self.agent.announced_machine_bindings(),
            authenticated_bindings: self.agent.authenticated_machine_bindings(),
            own_machine_id: self.agent.machine_id(),
            clock: teardown::system_clock(),
        };
        teardown::spawn_reauth_loop(
            Arc::clone(&self.live),
            ctx,
            self.agent.stream_reauth_signal(),
            self.inbound_token.clone(),
            Some(teardown::REAUTH_SWEEP_INTERVAL),
        );
    }

    /// Drain one protocol acceptor until shutdown or accept-loop stop,
    /// handing each surfaced stream to [`Self::spawn_stream_handler`].
    fn spawn_acceptor_loop(self: &Arc<Self>, mut acceptor: crate::streams::StreamAcceptor) {
        let this = Arc::clone(self);
        let token = self.inbound_token.clone();
        tokio::spawn(async move {
            tracing::info!(
                target: "x0x::forward",
                protocol = ?acceptor.protocol(),
                "inbound forward consumer started"
            );
            loop {
                let stream = tokio::select! {
                    _ = token.cancelled() => break,
                    s = acceptor.next() => match s {
                        Some(s) => s,
                        None => break,
                    },
                };
                this.spawn_stream_handler(stream);
            }
        });
    }

    /// Admit one inbound forward stream (FIX 3 concurrency caps) and spawn
    /// its `handle_inbound` task. Over-cap streams are reset (dropped) +
    /// counted rather than spawning unbounded.
    fn spawn_stream_handler(self: &Arc<Self>, stream: PeerStream) {
        // Forward streams reach this acceptor only after the agent identity
        // gate, so they always carry an agent. An agentless stream (only the
        // #1040 enrollment-only SyncV1 path creates one) fails closed: it is
        // dropped, which resets it, before admission or any handler runs.
        let Some(peer_agent) = stream.agent() else {
            tracing::warn!(
                target: "x0x::forward",
                peer = %hex::encode(stream.peer().0),
                "inbound forward refused: stream carries no agent identity — resetting"
            );
            return;
        };
        let admission = match self.admit(peer_agent, true) {
            Some(a) => a,
            None => {
                self.fwd_diag.record_over_cap();
                tracing::info!(
                    target: "x0x::forward",
                    agent = %hex::encode(peer_agent.as_bytes()),
                    "inbound forward refused: concurrency cap reached — resetting"
                );
                return;
            }
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let _admission = admission;
            this.fwd_diag.enter_stream();
            let _leave = StreamLeaveGuard(Arc::clone(&this.fwd_diag));
            let inbound_ctx = InboundCtx {
                // ADR-0070 §3: the agent holds the one hot-swappable connect
                // policy; each stream is gated against the snapshot current at
                // accept, so a reload never alters an in-flight stream.
                policy: this.agent.connect_policy(),
                connect_diag: Arc::clone(&this.connect_diag),
                revocation_set: Arc::clone(&this.revocation_set),
                move_state: Arc::clone(&this.move_state),
                fwd_diag: Arc::clone(&this.fwd_diag),
                discovery_cache: Arc::clone(&this.discovery_cache),
                contact_store: Arc::clone(&this.contact_store),
                own_machine_id: this.agent.machine_id(),
                require_attestation: this.require_attestation,
                owner_trust: this.agent.owner_trust().clone(),
                live: Arc::clone(&this.live),
                reauth: this.agent.stream_reauth_signal(),
            };
            handle_inbound(stream, &inbound_ctx).await;
        });
    }

    fn next_bind_addr(&self, requested: SocketAddr) -> SocketAddr {
        #[cfg(test)]
        {
            if let Some(addr) = self
                .bind_script
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop()
            {
                return addr;
            }
        }
        #[cfg(not(test))]
        {
            let _ = self;
        }
        requested
    }

    /// Keep `listener` open so a `:0` retry cannot bind this port again.
    pub(crate) fn hold_allocation(&self, listener: tokio::net::TcpListener) {
        self.allocation_holds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(listener);
    }

    /// Close ports held back from a `:0` allocation.
    pub(crate) fn release_allocation_holds(&self) {
        self.allocation_holds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Next `add_forward` calls bind these addresses, in order, instead of
    /// the spec address. Used to force a collision with a saved forward.
    #[cfg(test)]
    pub(crate) fn script_binds_for_test(&self, addrs: Vec<SocketAddr>) {
        let mut addrs = addrs;
        addrs.reverse();
        *self
            .bind_script
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = addrs;
    }

    /// Register a local forward: bind `local_addr`, and for each accepted TCP
    /// connection open a peer stream, write the header, and bridge on
    /// `connected`. Returns the bound local address (useful when port = 0).
    ///
    /// # Errors
    /// `NetworkError` if the local listener cannot be bound, or if the
    /// forwarder has shut down. A shutdown that wins the race drops the
    /// socket before this returns; it does not publish a listener.
    pub async fn add_forward(&self, spec: ForwardSpec) -> NetworkResult<SocketAddr> {
        if self.listeners_closed.load(Ordering::Acquire) {
            return Err(NetworkError::ConnectionFailed(
                "forwarder is shut down".to_string(),
            ));
        }
        self.ensure_reauth_loop();
        let bind_addr = self.next_bind_addr(spec.local_addr);
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("bind {bind_addr}: {e}")))?;
        let bound = listener
            .local_addr()
            .map_err(|e| NetworkError::ConnectionFailed(format!("local_addr: {e}")))?;
        // A kernel-assigned port must not replace a forward that already
        // owns that address. The listener is held so the retry cannot bind
        // it again. An explicit address still replaces that entry.
        if spec.local_addr.port() == 0 {
            let occupied = {
                let forwards = self
                    .forwards
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                forwards.iter().any(|entry| entry.spec.local_addr == bound)
            };
            if occupied {
                self.hold_allocation(listener);
                return Err(NetworkError::ConnectionFailed(
                    PORT_ALLOCATION_COLLISION.to_string(),
                ));
            }
        }
        let cancel = CancellationToken::new();
        // Register the kernel-assigned address.  Keeping the requested
        // `:0` here makes list/remove unable to identify the listener that
        // was actually opened (and makes two ephemeral forwards collide).
        let mut registered_spec = spec.clone();
        registered_spec.local_addr = bound;
        let accept = {
            let mut forwards = self
                .forwards
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Shutdown sets `listeners_closed` under this same lock and then
            // takes `listener_tasks`. Checking here, and publishing the
            // accept loop before the lock is released, means a bind that
            // resumes after shutdown cannot keep the port.
            if self.listeners_closed.load(Ordering::Acquire) {
                drop(listener);
                return Err(NetworkError::ConnectionFailed(
                    "forwarder is shut down".to_string(),
                ));
            }
            // A prior disabled entry for this address (restore that failed,
            // then a successful re-add) is replaced.
            forwards.retain(|e| e.spec.local_addr != bound);
            forwards.push(ForwardEntry {
                spec: registered_spec,
                state: EntryState::Active(cancel.clone()),
            });
            let agent = Arc::clone(&self.agent);
            let fwd_diag = Arc::clone(&self.fwd_diag);
            let outbound_permits = Arc::clone(&self.outbound_permits);
            let per_peer = Arc::clone(&self.per_peer);
            let target = OutboundTarget {
                peer_agent: spec.peer_agent,
                pinned_machine: spec.pinned_machine,
                target_host: spec.target_host.clone(),
                target_port: spec.target_port,
            };
            let require_attestation = self.require_attestation;
            let live = Arc::clone(&self.live);
            let handle = tokio::spawn(async move {
                tracing::info!(
                    target: "x0x::forward",
                    local = %bound,
                    peer = %hex::encode(target.peer_agent.as_bytes()),
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
                    let admission = match admit_to(&outbound_permits, &per_peer, target.peer_agent)
                    {
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
                    let live = Arc::clone(&live);
                    let target = target.clone();
                    tokio::spawn(async move {
                        let _admission = admission;
                        fwd_diag.enter_stream();
                        let _guard = StreamLeaveGuard(Arc::clone(&fwd_diag));
                        drive_outbound(agent, &target, tcp, require_attestation, &live, &fwd_diag)
                            .await;
                    });
                }
            });
            self.reap_finished_listener_tasks();
            self.listener_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(handle);
            bound
        };
        Ok(accept)
    }

    /// Register `spec` as a forward that is down for `reason` (ADR-0074 §2:
    /// a restored forward whose name did not re-resolve to its pinned ids,
    /// or whose port could not be bound). It is listed with its reason and
    /// never listens; a later successful [`Self::add_forward`] for the same
    /// address replaces it. An active forward on that address is left alone.
    pub fn add_disabled(&self, spec: ForwardSpec, reason: String) {
        if let Ok(mut forwards) = self.forwards.lock() {
            if forwards.iter().any(|e| {
                e.spec.local_addr == spec.local_addr && matches!(e.state, EntryState::Active(_))
            }) {
                return;
            }
            forwards.retain(|e| e.spec.local_addr != spec.local_addr);
            forwards.push(ForwardEntry {
                spec,
                state: EntryState::Disabled(reason),
            });
        }
    }

    /// Snapshot of registered forwards (for `GET /forwards` / `x0x forward list`).
    #[must_use]
    pub fn list_forwards(&self) -> Vec<ForwardStatus> {
        self.forwards
            .lock()
            .map(|f| {
                f.iter()
                    .map(|e| ForwardStatus {
                        spec: e.spec.clone(),
                        error: match &e.state {
                            EntryState::Active(_) => None,
                            EntryState::Disabled(reason) => Some(reason.clone()),
                        },
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The registered forward bound to `local_addr`, if any.
    #[must_use]
    pub fn forward_at(&self, local_addr: SocketAddr) -> Option<ForwardSpec> {
        self.forwards.lock().ok().and_then(|f| {
            f.iter()
                .find(|e| e.spec.local_addr == local_addr)
                .map(|e| e.spec.clone())
        })
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
                if let EntryState::Active(cancel) = &forwards[pos].state {
                    cancel.cancel();
                }
                forwards.remove(pos);
                removed = true;
            }
        }
        self.reap_finished_listener_tasks();
        removed
    }

    /// Drop accept-loop handles that have already exited.
    ///
    /// [`Self::remove_forward`] cancels the listener and returns before that
    /// task finishes. The next add or remove drops the finished handle, so
    /// completed listeners do not stay in memory until shutdown.
    fn reap_finished_listener_tasks(&self) {
        self.listener_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|task| !task.is_finished());
    }

    /// Tear down every listener + the inbound consumer.
    ///
    /// This cancels listeners and refuses later binds. It does not wait for
    /// accept loops to drop their sockets, and it does not drain in-flight
    /// add, remove, or restore transactions. `shutdown_and_release` does both,
    /// and the daemon shutdown path uses that.
    pub fn shutdown(&self) {
        // Cancel live bridges before stopping reauth (`inbound_token`).
        // Otherwise shutdown leaves registrations that reauth no longer
        // guards while the Agent may still be alive (Codex P2 / #1388).
        self.live.cancel_all("shutdown");
        self.inbound_token.cancel();
        self.cancel_listener_tokens();
    }

    /// Close admission, drain in-flight add/remove/restore transactions,
    /// cancel every listener, and wait until those accept loops drop their
    /// sockets.
    ///
    /// A transaction still inside `add_forward` when this starts is allowed
    /// to finish. Its listener is in [`Self::listener_tasks`] before the
    /// transaction returns, and the cancel below observes it. A bind that
    /// starts after the cancel finds [`Self::listeners_closed`] and drops
    /// the socket before publishing a listener.
    pub(crate) async fn shutdown_and_release(&self) -> ForwardShutdownReport {
        let abandoned_transactions = self.close_and_drain_transactions().await;
        self.release_allocation_holds();
        self.shutdown();
        self.await_listener_tasks().await;
        if abandoned_transactions > 0 {
            tracing::warn!(
                target: "x0x::forward",
                abandoned_transactions,
                "forward shutdown abandoned in-flight transactions after 2s"
            );
        }
        ForwardShutdownReport {
            abandoned_transactions,
        }
    }

    /// Run `work` as one forward transaction. The task stays in
    /// [`Self::transactions`] until it finishes, including when the caller
    /// is dropped. [`Self::shutdown_and_release`] awaits it before
    /// cancelling listeners.
    ///
    /// # Errors
    /// [`ForwardTransactionError::Closed`] when shutdown has already closed
    /// admission (`work` is not started). [`ForwardTransactionError::Failed`]
    /// when the task panics.
    pub(crate) async fn run_transaction<T, F>(&self, work: F) -> Result<T, ForwardTransactionError>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        {
            let mut guard = self
                .transactions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(tasks) = guard.as_mut() else {
                return Err(ForwardTransactionError::Closed);
            };
            tasks.retain(|task| !task.is_finished());
            tasks.push(tokio::spawn(async move {
                let _ = done_tx.send(work.await);
            }));
        }
        match done_rx.await {
            Ok(value) => Ok(value),
            Err(_) => Err(ForwardTransactionError::Failed(
                "forward transaction ended before it returned".to_string(),
            )),
        }
    }

    /// `true` once [`Self::shutdown_and_release`] has closed transaction
    /// admission and is waiting for the admitted tasks (or has finished).
    #[cfg(test)]
    pub(crate) fn transactions_closed(&self) -> bool {
        self.transactions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
    }

    async fn close_and_drain_transactions(&self) -> usize {
        let tasks = self
            .transactions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .unwrap_or_default();
        let abort_handles: Vec<_> = tasks
            .iter()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect();
        let pending = futures::future::join_all(tasks);
        tokio::pin!(pending);
        if tokio::time::timeout(std::time::Duration::from_secs(2), pending.as_mut())
            .await
            .is_err()
        {
            let abandoned = abort_handles
                .iter()
                .filter(|handle| !handle.is_finished())
                .count();
            for handle in &abort_handles {
                handle.abort();
            }
            let _ = pending.await;
            abandoned
        } else {
            0
        }
    }

    /// Set the closed flag and cancel active listeners under `forwards`.
    /// Does not take the accept-loop tasks: [`Self::shutdown`] is
    /// synchronous and must not detach them. [`Self::await_listener_tasks`]
    /// takes them under the same lock after this returns.
    fn cancel_listener_tokens(&self) {
        let forwards = self
            .forwards
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.listeners_closed.store(true, Ordering::Release);
        for entry in forwards.iter() {
            if let EntryState::Active(cancel) = &entry.state {
                cancel.cancel();
            }
        }
    }

    async fn await_listener_tasks(&self) {
        // `add_forward` publishes its accept loop while it holds `forwards`,
        // and only after it has observed `listeners_closed == false`. Taking
        // the handles under that lock, after shutdown stored `true` under
        // it, collects every loop that was published and refuses any later
        // one.
        let handles = {
            let _forwards = self
                .forwards
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(
                &mut *self
                    .listener_tasks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
        };
        if handles.is_empty() {
            return;
        }
        let aborts: Vec<_> = handles
            .iter()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect();
        let pending = futures::future::join_all(handles);
        tokio::pin!(pending);
        if tokio::time::timeout(std::time::Duration::from_secs(2), pending.as_mut())
            .await
            .is_err()
        {
            for abort in &aborts {
                abort.abort();
            }
            let _ = pending.await;
        }
    }

    /// ADR-0074 §3: open a ForwardV2 tunnel for SOCKS without bridging yet.
    ///
    /// On [`Ok`], the peer's connect gate allowed `127.0.0.1:port` and the
    /// caller should send the SOCKS success reply then [`PreparedSocksTunnel::bridge`].
    /// [`PrepareSocksError::Denied`] means the peer refused and zero bytes
    /// reached the target.
    pub async fn prepare_socks_tunnel(
        &self,
        peer: &AgentId,
        target_port: u16,
    ) -> Result<PreparedSocksTunnel, PrepareSocksError> {
        // ADR-0074 §4: a SOCKS-only embedder (`ForwardService::new` +
        // `ForwardSocksConnector`) never calls `spawn_inbound` or
        // `add_forward`. Start the same monitor so a local trust downgrade
        // still tears the tunnel down.
        self.ensure_reauth_loop();
        // Same global outbound / per-peer caps as `add_forward`. The permit
        // stays inside the returned tunnel until `bridge` finishes.
        let Some(admission) = self.admit(*peer, false) else {
            self.fwd_diag.record_over_cap();
            return Err(PrepareSocksError::Failed);
        };
        prepare_outbound_v2_for_socks(
            &self.agent,
            peer,
            "127.0.0.1",
            target_port,
            &self.live,
            admission,
            &self.fwd_diag,
        )
        .await
    }
}

/// Why [`ForwardService::run_transaction`] did not return the task's value.
#[derive(Debug)]
pub(crate) enum ForwardTransactionError {
    /// Shutdown has closed admission. The task was not started.
    Closed,
    /// The transaction task panicked or was aborted.
    Failed(String),
}

impl std::fmt::Display for ForwardTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("forward admission is closed"),
            Self::Failed(error) => write!(f, "forward transaction failed: {error}"),
        }
    }
}

/// Outcome of [`ForwardService::prepare_socks_tunnel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrepareSocksError {
    /// Peer connect gate denied the target (SOCKS `0x02`).
    Denied,
    /// Stream open / attestation / transport failure (SOCKS `0x04`).
    Failed,
}

/// A peer stream that has cleared the remote connect gate and is ready to bridge.
pub struct PreparedSocksTunnel {
    /// `None` after [`Self::bridge`] takes the stream, or when Drop resets it.
    stream: Option<PeerStream>,
    guard: teardown::LiveStreamGuard,
    /// Outbound admission. Held until [`Self::bridge`] returns.
    admission: Admission,
    /// Active-stream count for `/streams`. Held for the tunnel lifetime,
    /// including [`Self::bridge`], and released on drop.
    active: StreamLeaveGuard,
}

impl PreparedSocksTunnel {
    /// Bridge `client` to the prepared peer stream until either side closes.
    pub async fn bridge(mut self, tcp: TcpStream) {
        let Some(mut stream) = self.stream.take() else {
            return;
        };
        if self.guard.token().is_cancelled() {
            teardown::deny_pre_bridge(&mut stream, Some(&tcp));
            return;
        }
        let (send, recv) = stream.into_split();
        bridge(tcp, send, recv, self.guard.token()).await;
        // Admission and the active-stream guard drop with `self`.
        let _caps = (&self.admission, &self.active);
    }
}

impl Drop for PreparedSocksTunnel {
    fn drop(&mut self) {
        // A session that won the race after prepare, then lost cancel or the
        // client, must not leave the admitted QUIC stream open.
        if let Some(stream) = self.stream.as_mut() {
            teardown::deny_pre_bridge(stream, None::<&TcpStream>);
        }
    }
}

/// Open ForwardV2, write the attested header, read the peer response.
/// Does not take a local TCP — the SOCKS layer writes its reply first.
async fn prepare_outbound_v2_for_socks(
    agent: &Arc<crate::Agent>,
    peer_agent: &AgentId,
    target_host: &str,
    target_port: u16,
    live: &Arc<teardown::LiveStreams>,
    admission: Admission,
    fwd_diag: &Arc<ForwardDiagnostics>,
) -> Result<PreparedSocksTunnel, PrepareSocksError> {
    let ready =
        match open_signed_forward_v2(agent, peer_agent, target_host, target_port, live).await {
            Ok(ready) => ready,
            Err(fail) => return Err(map_socks_v2_fail(fail, peer_agent)),
        };
    match response_connected(ready.response) {
        Some(true) => {
            fwd_diag.enter_stream();
            Ok(PreparedSocksTunnel {
                stream: Some(ready.stream),
                guard: ready.guard,
                admission,
                active: StreamLeaveGuard(Arc::clone(fwd_diag)),
            })
        }
        Some(false) => {
            // Peer denied — reset the QUIC halves; target got zero bytes.
            let mut stream = ready.stream;
            teardown::deny_pre_bridge(&mut stream, None);
            drop(ready.guard);
            Err(PrepareSocksError::Denied)
        }
        None => {
            let mut stream = ready.stream;
            teardown::deny_pre_bridge(&mut stream, None::<&TcpStream>);
            Err(PrepareSocksError::Failed)
        }
    }
}

/// ForwardV2 stream that has a connect-response byte and is not yet bridged.
struct V2Handshake {
    stream: PeerStream,
    guard: teardown::LiveStreamGuard,
    response: u8,
}

/// Why [`open_signed_forward_v2`] stopped before a response byte.
enum V2DriveFail {
    /// `open_peer_stream` failed. No stream was opened.
    Open(Box<NetworkError>),
    /// A stream was opened. The caller resets or drops it.
    AfterOpen(Box<V2AfterOpen>),
    /// [`PreBridgeReset`] already reset the stream. Nothing remains to close.
    AlreadyReset,
}

/// Resets a ForwardV2 stream when preparation is dropped before the caller
/// takes the stream. A peer that keeps QUIC up and withholds the response
/// byte must not leave the stream or its admission behind.
struct PreBridgeReset {
    stream: Option<PeerStream>,
}

impl PreBridgeReset {
    fn arm(stream: PeerStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    fn stream_mut(&mut self) -> Option<&mut PeerStream> {
        self.stream.as_mut()
    }

    fn disarm(&mut self) -> Option<PeerStream> {
        self.stream.take()
    }
}

impl Drop for PreBridgeReset {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            teardown::deny_pre_bridge(stream, None::<&TcpStream>);
        }
    }
}

struct V2AfterOpen {
    kind: V2AfterOpenKind,
    stream: PeerStream,
    guard: teardown::LiveStreamGuard,
}

enum V2AfterOpenKind {
    Cancelled,
    SigningGateRefused,
    SignFailed(ForwardError),
    WriteFailed,
    ReadFailed(std::io::Error),
}

fn v2_after_open(
    kind: V2AfterOpenKind,
    stream: PeerStream,
    guard: teardown::LiveStreamGuard,
) -> V2DriveFail {
    V2DriveFail::AfterOpen(Box::new(V2AfterOpen {
        kind,
        stream,
        guard,
    }))
}

/// Hand `held` to the caller, or report that Drop already reset it.
fn fail_held(
    held: &mut PreBridgeReset,
    kind: V2AfterOpenKind,
    guard: teardown::LiveStreamGuard,
) -> V2DriveFail {
    match held.disarm() {
        Some(stream) => v2_after_open(kind, stream, guard),
        None => {
            drop(guard);
            V2DriveFail::AlreadyReset
        }
    }
}

/// Shared ForwardV2 open, sign, header write, and response read.
///
/// Does not bridge and does not reset the stream. [`prepare_outbound_v2_for_socks`]
/// maps [`V2DriveFail`] on its own. TCP forwards keep the pinned-machine check
/// in [`try_outbound_v2`] and do not use this path.
async fn open_signed_forward_v2(
    agent: &Arc<crate::Agent>,
    peer_agent: &AgentId,
    target_host: &str,
    target_port: u16,
    live: &Arc<teardown::LiveStreams>,
) -> Result<V2Handshake, V2DriveFail> {
    let mut held = match agent
        .open_peer_stream(peer_agent, StreamProtocol::ForwardV2)
        .await
    {
        Ok(stream) => PreBridgeReset::arm(stream),
        Err(error) => return Err(V2DriveFail::Open(Box::new(error))),
    };
    // ADR-0074 §4: register before the header/response window so a trust
    // loss while waiting still hits the ≤5 s bound. `held` resets the stream
    // if this future is dropped while the peer withholds the response byte.
    let Some(machine) = held.stream_mut().map(|stream| stream.peer()) else {
        return Err(V2DriveFail::AlreadyReset);
    };
    let guard = live.register(
        teardown::StreamGate::Outbound {
            peer_agent: *peer_agent,
            machine,
        },
        teardown::StreamAuthority::PeerTrust,
    );
    agent.stream_reauth_signal().notify_one();
    if guard.token().is_cancelled() {
        return Err(fail_held(&mut held, V2AfterOpenKind::Cancelled, guard));
    }

    match wait_signing_gate_or_cancel(guard.token(), agent.signing_gate_allows(&agent.agent_id()))
        .await
    {
        Err(teardown::Cancelled) => {
            return Err(fail_held(&mut held, V2AfterOpenKind::Cancelled, guard));
        }
        Ok(false) => {
            return Err(fail_held(
                &mut held,
                V2AfterOpenKind::SigningGateRefused,
                guard,
            ));
        }
        Ok(true) => {}
    }
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
        machine,
    );
    if let Err(error) = header.sign(agent.identity().agent_keypair()) {
        return Err(fail_held(
            &mut held,
            V2AfterOpenKind::SignFailed(error),
            guard,
        ));
    }
    let written = {
        let Some(stream) = held.stream_mut() else {
            return Err(fail_held(&mut held, V2AfterOpenKind::WriteFailed, guard));
        };
        teardown::wait_cancellable(guard.token(), write_header_v2(stream.send_mut(), &header)).await
    };
    match written {
        Err(teardown::Cancelled) => {
            return Err(fail_held(&mut held, V2AfterOpenKind::Cancelled, guard));
        }
        Ok(Err(_)) => return Err(fail_held(&mut held, V2AfterOpenKind::WriteFailed, guard)),
        Ok(Ok(())) => {}
    }
    let mut resp = [0u8; 1];
    let read = {
        let Some(stream) = held.stream_mut() else {
            return Err(fail_held(
                &mut held,
                V2AfterOpenKind::ReadFailed(std::io::Error::other(
                    "forward v2 stream already reset",
                )),
                guard,
            ));
        };
        teardown::wait_cancellable(guard.token(), stream.recv_mut().read_exact(&mut resp)).await
    };
    match read {
        Err(teardown::Cancelled) => {
            return Err(fail_held(&mut held, V2AfterOpenKind::Cancelled, guard));
        }
        Ok(Err(error)) => {
            return Err(fail_held(
                &mut held,
                V2AfterOpenKind::ReadFailed(std::io::Error::other(error)),
                guard,
            ));
        }
        Ok(Ok(())) => {}
    }
    if guard.token().is_cancelled() {
        return Err(fail_held(&mut held, V2AfterOpenKind::Cancelled, guard));
    }
    let Some(stream) = held.disarm() else {
        drop(guard);
        return Err(V2DriveFail::AlreadyReset);
    };
    Ok(V2Handshake {
        stream,
        guard,
        response: resp[0],
    })
}

/// SOCKS maps every open/sign/write/read/cancel failure to `Failed`.
/// A `connected == false` byte is handled by the caller as `Denied`.
fn map_socks_v2_fail(fail: V2DriveFail, peer_agent: &AgentId) -> PrepareSocksError {
    match fail {
        V2DriveFail::Open(error) => {
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer_agent.as_bytes()),
                error = %error,
                "socks prepare: could not open ForwardV2"
            );
            PrepareSocksError::Failed
        }
        V2DriveFail::AfterOpen(opened) => {
            let V2AfterOpen {
                kind,
                mut stream,
                guard,
            } = *opened;
            match &kind {
                V2AfterOpenKind::SignFailed(error) => {
                    tracing::info!(
                        target: "x0x::forward",
                        peer = %hex::encode(peer_agent.as_bytes()),
                        error = %error,
                        "socks prepare: sign failed"
                    );
                }
                V2AfterOpenKind::ReadFailed(error) => {
                    tracing::info!(
                        target: "x0x::forward",
                        peer = %hex::encode(peer_agent.as_bytes()),
                        error = %error,
                        "socks prepare: response read failed"
                    );
                }
                V2AfterOpenKind::Cancelled
                | V2AfterOpenKind::SigningGateRefused
                | V2AfterOpenKind::WriteFailed => {
                    tracing::info!(
                        target: "x0x::forward",
                        peer = %hex::encode(peer_agent.as_bytes()),
                        "socks prepare: forward v2 did not complete"
                    );
                }
            }
            teardown::deny_pre_bridge(&mut stream, None::<&TcpStream>);
            drop(guard);
            PrepareSocksError::Failed
        }
        V2DriveFail::AlreadyReset => PrepareSocksError::Failed,
    }
}

/// Where an outbound forward opens and what it must reach.
#[derive(Debug, Clone)]
struct OutboundTarget {
    peer_agent: AgentId,
    /// ADR-0074 §1: the machine every stream must reach, if pinned.
    pinned_machine: Option<MachineId>,
    target_host: String,
    target_port: u16,
}

/// Result of [`send_header_to_pinned`].
#[derive(Debug)]
enum HeaderSend {
    /// The stream reaches the pinned machine (or nothing is pinned) and the
    /// whole header frame was written.
    Sent,
    /// The stream reaches a different machine than the pinned one. Nothing
    /// was written.
    MachineMismatch {
        pinned: MachineId,
        actual: MachineId,
    },
    /// The write itself failed.
    Failed,
}

/// ADR-0074 §1 machine binding: write the forward-header `frame` only when
/// the stream's transport-authenticated peer (`PeerStream::peer()`) is the
/// pinned machine. On a mismatch not one byte of the header is written, so
/// the peer never learns the target.
async fn send_header_to_pinned<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    peer: MachineId,
    pinned: Option<MachineId>,
    frame: &[u8],
) -> HeaderSend {
    use tokio::io::AsyncWriteExt;
    if let Some(pinned) = pinned {
        if pinned != peer {
            return HeaderSend::MachineMismatch {
                pinned,
                actual: peer,
            };
        }
    }
    match w.write_all(frame).await {
        Ok(()) => HeaderSend::Sent,
        Err(e) => {
            tracing::debug!(target: "x0x::forward", error = %e, "write forward header failed");
            HeaderSend::Failed
        }
    }
}

/// Reset a stream refused at the machine-binding check and count it.
fn refuse_machine_mismatch(
    stream: &mut PeerStream,
    pinned: MachineId,
    actual: MachineId,
    fwd_diag: &ForwardDiagnostics,
) {
    fwd_diag.record_machine_mismatch();
    // Reset (not finish): the peer sees an aborted stream with zero header
    // bytes. A reset on an already-closed stream is harmless.
    let _ = stream.send_mut().reset(ant_quic::VarInt::from_u32(0));
    tracing::warn!(
        target: "x0x::forward",
        pinned = %hex::encode(pinned.as_bytes()),
        actual = %hex::encode(actual.as_bytes()),
        "outbound forward refused: stream reached a different machine than pinned (machine_mismatch)"
    );
}

/// What [`write_pinned_header`] did with the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinnedHeader {
    /// `PeerStream::peer()` is the pinned machine (or nothing is pinned)
    /// and the header frame was written.
    Sent,
    /// The stream reaches a different machine. It has been reset, and no
    /// header version may be tried on it.
    Refused,
    /// The write failed. A V2 attempt may fall back to V1.
    Failed,
}

/// How a V2 outbound attempt continues after [`PinnedHeader`].
///
/// `Stop` is the machine-binding refusal: the attempt is finished, and
/// [`drive_outbound`] must not open a V1 stream. `Fallback` is only a
/// failed write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterPin {
    Continue,
    Stop,
    Fallback,
}

fn after_pin(header: PinnedHeader) -> AfterPin {
    match header {
        PinnedHeader::Sent => AfterPin::Continue,
        PinnedHeader::Refused => AfterPin::Stop,
        PinnedHeader::Failed => AfterPin::Fallback,
    }
}

/// ADR-0074 §1: read [`PeerStream::peer`] and write `frame` only when that
/// machine is the pin. A mismatch resets the stream and counts
/// `machine_mismatch`. Callers turn [`PinnedHeader::Refused`] into a
/// finished attempt ([`AfterPin::Stop`]), never a V1 retry.
async fn write_pinned_header(
    stream: &mut PeerStream,
    pinned: Option<MachineId>,
    frame: &[u8],
    fwd_diag: &ForwardDiagnostics,
) -> PinnedHeader {
    let actual = stream.peer();
    match send_header_to_pinned(stream.send_mut(), actual, pinned, frame).await {
        HeaderSend::Sent => PinnedHeader::Sent,
        HeaderSend::MachineMismatch { pinned, actual } => {
            refuse_machine_mismatch(stream, pinned, actual, fwd_diag);
            PinnedHeader::Refused
        }
        HeaderSend::Failed => PinnedHeader::Failed,
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
    target: &OutboundTarget,
    tcp: TcpStream,
    require_attestation: bool,
    live: &Arc<teardown::LiveStreams>,
    fwd_diag: &ForwardDiagnostics,
) {
    let peer_agent = target.peer_agent;
    // Try ForwardV2 (attestation). On peer rejection (old software), fall
    // back to ForwardV1 — but ONLY when require_attestation is false. When
    // true (the default) there is no fallback: a peer that cannot handle V2
    // simply cannot forward (#204 must-fix 1). A machine-binding refusal is
    // `Done`, never a fallback.
    match try_outbound_v2(&agent, target, tcp, live, fwd_diag).await {
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
                drive_outbound_v1(&agent, target, tcp, live, fwd_diag).await;
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

/// ADR-0074: race the signing-gate await against live-stream cancel.
///
/// A stalled move-state lock must not keep the registered stream (and its
/// TCP/permit) alive past reauth cancel — same pattern as the header write
/// and response read that follow in [`try_outbound_v2`].
pub(crate) async fn wait_signing_gate_or_cancel(
    cancel: &CancellationToken,
    gate: impl std::future::Future<Output = bool>,
) -> Result<bool, teardown::Cancelled> {
    teardown::wait_cancellable(cancel, gate).await
}

/// Attempt a `ForwardV2` outbound forward. Returns `PeerRejectedV2` only when
/// the failure is specifically the peer not understanding the V2 protocol
/// byte (the write to the opened stream fails immediately).
async fn try_outbound_v2(
    agent: &Arc<crate::Agent>,
    target: &OutboundTarget,
    tcp: TcpStream,
    live: &Arc<teardown::LiveStreams>,
    fwd_diag: &ForwardDiagnostics,
) -> OutboundOutcome {
    let peer_agent = &target.peer_agent;
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
    // ADR-0074 §4: register before the header/response window so a trust
    // loss while waiting still hits the ≤5 s bound.
    let guard = live.register(
        teardown::StreamGate::Outbound {
            peer_agent: *peer_agent,
            machine: stream.peer(),
        },
        teardown::StreamAuthority::PeerTrust,
    );
    agent.stream_reauth_signal().notify_one();
    if guard.token().is_cancelled() {
        teardown::deny_pre_bridge(&mut stream, Some(&tcp));
        return OutboundOutcome::Done;
    }

    // ADR-0043 AgentSigningGate (review r2 C2): the V2 attestation is an
    // agent-key signature — a quiesced/quarantined machine produces none.
    // Fail toward the V1 fallback exactly like a signing error would; the
    // V1 path carries no agent signature (transport-machine context only,
    // filtered receiver-side by B/P).
    // ADR-0074 §4: race the gate against reauth cancel so a stalled
    // move-state lock cannot hold sockets/permits past the 5 s bound.
    match wait_signing_gate_or_cancel(guard.token(), agent.signing_gate_allows(&agent.agent_id()))
        .await
    {
        Err(teardown::Cancelled) => {
            teardown::deny_pre_bridge(&mut stream, Some(&tcp));
            return OutboundOutcome::Done;
        }
        Ok(false) => {
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer_agent.as_bytes()),
                "outbound forward v2: signing gate refused (ADR-0043 custodian) — falling back to V1"
            );
            return OutboundOutcome::PeerRejectedV2(tcp);
        }
        Ok(true) => {}
    }
    // Build + sign the V2 header with the local agent keypair. The header
    // carries the opener's public key so the verifier doesn't depend on
    // announce propagation (#204 soak fix).
    let mut header = ForwardV2Header::new(
        target.target_host.clone(),
        target.target_port,
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
    // ADR-0074 §1: check PeerStream::peer() before any header byte.
    // ADR-0074 §4: cancel during the write resets both halves.
    // A mismatch is `AfterPin::Stop`: this attempt is finished, and the
    // caller must not fall back to V1.
    let frame = header.encode();
    let header = match teardown::wait_cancellable(
        guard.token(),
        write_pinned_header(&mut stream, target.pinned_machine, &frame, fwd_diag),
    )
    .await
    {
        Err(teardown::Cancelled) => {
            teardown::deny_pre_bridge(&mut stream, Some(&tcp));
            return OutboundOutcome::Done;
        }
        Ok(header) => header,
    };
    match after_pin(header) {
        AfterPin::Continue => {}
        AfterPin::Stop => return OutboundOutcome::Done,
        AfterPin::Fallback => {
            // Peer likely reset after unknown V2 protocol byte — fall back.
            return OutboundOutcome::PeerRejectedV2(tcp);
        }
    }
    // Read the peer's connect-response byte.
    let mut resp = [0u8; 1];
    match teardown::wait_cancellable(guard.token(), stream.recv_mut().read_exact(&mut resp)).await {
        Err(teardown::Cancelled) => {
            teardown::deny_pre_bridge(&mut stream, Some(&tcp));
            return OutboundOutcome::Done;
        }
        Ok(Err(error)) => {
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer_agent.as_bytes()),
                %error,
                "outbound forward v2: peer closed/reset before connect response — closing local TCP"
            );
            return OutboundOutcome::Done;
        }
        Ok(Ok(())) => {}
    }
    finish_outbound(stream, resp, peer_agent, tcp, guard).await;
    OutboundOutcome::Done
}

/// Legacy `ForwardV1` outbound forward (no attestation). Used for pre-#204
/// peers and as a last-resort fallback.
async fn drive_outbound_v1(
    agent: &Arc<crate::Agent>,
    target: &OutboundTarget,
    tcp: TcpStream,
    live: &Arc<teardown::LiveStreams>,
    fwd_diag: &ForwardDiagnostics,
) {
    let peer_agent = &target.peer_agent;
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
    let guard = live.register(
        teardown::StreamGate::Outbound {
            peer_agent: *peer_agent,
            machine: stream.peer(),
        },
        teardown::StreamAuthority::PeerTrust,
    );
    agent.stream_reauth_signal().notify_one();
    if guard.token().is_cancelled() {
        teardown::deny_pre_bridge(&mut stream, Some(&tcp));
        return;
    }
    let header = ForwardHeader {
        target_host: target.target_host.clone(),
        target_port: target.target_port,
    };
    let frame = header.encode();
    let header = match teardown::wait_cancellable(
        guard.token(),
        write_pinned_header(&mut stream, target.pinned_machine, &frame, fwd_diag),
    )
    .await
    {
        Err(teardown::Cancelled) => {
            teardown::deny_pre_bridge(&mut stream, Some(&tcp));
            return;
        }
        Ok(header) => header,
    };
    match after_pin(header) {
        AfterPin::Continue => {}
        AfterPin::Stop | AfterPin::Fallback => return,
    }
    let mut resp = [0u8; 1];
    match teardown::wait_cancellable(guard.token(), stream.recv_mut().read_exact(&mut resp)).await {
        Err(teardown::Cancelled) => {
            teardown::deny_pre_bridge(&mut stream, Some(&tcp));
            return;
        }
        Ok(Err(error)) => {
            tracing::info!(
                target: "x0x::forward",
                peer = %hex::encode(peer_agent.as_bytes()),
                %error,
                "outbound forward v1: peer closed/reset before connect response — closing local TCP"
            );
            return;
        }
        Ok(Ok(())) => {}
    }
    finish_outbound(stream, resp, peer_agent, tcp, guard).await;
}

/// Shared tail: interpret the connect-response byte and bridge on `connected`.
///
/// ADR-0074 §4 ("both ends enforce"): the stream was registered as soon as
/// the peer stream opened (before the header/response window), so a trust
/// loss during that window still tears it down within the 5 s bound.
async fn finish_outbound(
    mut stream: PeerStream,
    resp: [u8; 1],
    peer_agent: &AgentId,
    tcp: TcpStream,
    guard: teardown::LiveStreamGuard,
) {
    if guard.token().is_cancelled() {
        teardown::deny_pre_bridge(&mut stream, Some(&tcp));
        return;
    }
    match response_connected(resp[0]) {
        Some(true) => {
            let (send, recv) = stream.into_split();
            bridge(tcp, send, recv, guard.token()).await;
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
            owner_allow: Vec::new(),
            grant_allow: Vec::new(),
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
            owner_allow: Vec::new(),
            grant_allow: Vec::new(),
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
                self_name: None,
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
                cert_digest: None,
            },
        );
        Arc::new(tokio::sync::RwLock::new(cache))
    }

    /// Owner-trust source whose authenticated bindings record each
    /// (agent, machine) pair, as an accepted class A announcement would
    /// (ADR 0115 §2: the shared inbound gate admits only confirmed agents).
    async fn bound_owner_trust(pairs: &[(AgentId, MachineId)]) -> crate::owner_trust::OwnerTrust {
        let bindings = crate::dm_inbox::AuthenticatedMachineBindings::default();
        for (agent, machine) in pairs {
            crate::dm_inbox::record_authenticated_machine_binding(&bindings, *agent, *machine, 1)
                .await;
        }
        crate::owner_trust::OwnerTrust::new(None, bindings)
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

    /// Shared sink that captures fmt-layer tracing output so tests can assert
    /// the distinct `reason` identity emitted with each attestation denial
    /// (#216). Cloneable; the fmt layer writes through the shared buffer.
    #[derive(Clone, Default)]
    struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut v) = self.0.lock() {
                v.extend_from_slice(buf);
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl LogCapture {
        /// Captured output as text (lossy).
        fn text(&self) -> String {
            self.0
                .lock()
                .map(|v| String::from_utf8_lossy(&v).into_owned())
                .unwrap_or_default()
        }
        /// Reset the buffer between tamper cases.
        fn clear(&self) {
            if let Ok(mut v) = self.0.lock() {
                v.clear();
            }
        }
    }

    /// Install a thread-local WARN-level fmt subscriber writing into a
    /// [`LogCapture`]. The guard is thread-scoped and `#[tokio::test]` runs
    /// the body on the current-thread runtime, so every event the gate emits
    /// lands in the buffer without cross-test interference.
    fn capture_warn_logs() -> (LogCapture, tracing::subscriber::DefaultGuard) {
        let capture = LogCapture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }

    /// Frame a header through the real async codec pair the QUIC stream uses
    /// (`write_header_v2` → `read_header_v2`).
    async fn v2_wire_round_trip(header: &ForwardV2Header) -> ForwardV2Header {
        let mut wire = Vec::new();
        write_header_v2(&mut wire, header)
            .await
            .expect("write v2 header");
        let mut cursor: &[u8] = &wire;
        read_header_v2(&mut cursor).await.expect("read v2 header")
    }

    #[tokio::test]
    async fn v2_two_agent_cross_node_attestation_verifies_end_to_end() {
        // #216: the exact cross-node path the live testnet exercised —
        // construct as the opener does, sign, frame through the REAL async
        // stream codec (write_header_v2 → read_header_v2), then verify as
        // the recipient does. Two agents on two distinct machines; asserts
        // the happy path SUCCEEDS and pins key-binding vs signature vs
        // recipient-machine if any inner check fails (the inner ForwardError
        // is inspected here, before any map_err collapse).
        let opener_kp = AgentKeypair::generate().unwrap();
        let opener_machine = MachineId([2u8; 32]);
        let recipient_machine = MachineId([3u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();

        // ── Opener: construct exactly as try_outbound_v2 does — the header
        // names the RECIPIENT machine (stream.peer() on the dial side).
        let mut header = ForwardV2Header::new(
            "127.0.0.1".to_string(),
            22,
            opener_kp.agent_id(),
            opener_kp.public_key().as_bytes().to_vec(),
            recipient_machine,
        );
        header.sign(&opener_kp).expect("sign");

        // ── Wire: the real async codec pair used on the QUIC stream (the
        // encode/decode-only tests never exercised these).
        let decoded = v2_wire_round_trip(&header).await;
        assert_eq!(decoded, header);

        // ── Recipient: pin the key↔id binding check separately from the
        // ML-DSA signature check, then run the full attestation verify.
        let pubkey =
            MlDsaPublicKey::from_bytes(&decoded.opener_agent_public_key).expect("pubkey parses");
        assert_eq!(
            AgentId::from_public_key(&pubkey),
            decoded.opener_agent_id,
            "key↔id binding: header key must derive the claimed agent id"
        );
        let verification = decoded.verify_attestation(&decoded.opener_agent_public_key);
        assert_eq!(
            verification,
            Ok(()),
            "cross-node wire-round-trip attestation must verify"
        );

        // ── Full recipient gate: opener announced on `opener_machine`, the
        // local machine is `recipient_machine`, ACL permits the pair.
        let cache = cache_with_agent(&opener_kp, opener_machine);
        let contacts = trusted_store(opener_kp.agent_id());
        let policy = policy_with_allow(opener_kp.agent_id(), opener_machine, target);
        assert_eq!(
            decide_inbound_attested(
                &decoded,
                &policy,
                &opener_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache,
                    contact_store: contacts,
                    own_machine_id: recipient_machine,
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
                },
            )
            .await,
            Ok(target),
            "cross-node attested gate must allow the verified opener"
        );
    }

    #[tokio::test]
    async fn v2_wire_codec_tamper_suite_denies_with_distinct_reasons() {
        // #216: codec/round-trip tamper suite. Each case frames the header
        // through the real async codec, tampers exactly one input, and asserts
        // (a) the gate denies with the expected ConnectDenialReason AND
        // (b) the denial carries its DISTINCT structured `reason` at warn! —
        // the identity previously collapsed silently into `attestation_failed`.
        let (logs, _guard) = capture_warn_logs();
        let opener_kp = AgentKeypair::generate().unwrap();
        let opener = opener_kp.agent_id();
        let opener_machine = MachineId([2u8; 32]);
        let recipient_machine = MachineId([3u8; 32]);
        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();

        // ── Control: the untampered wire header is allowed and logs no
        // denial reason.
        let header = signed_v2_header("127.0.0.1", 22, &opener_kp, recipient_machine);
        let decoded = v2_wire_round_trip(&header).await;
        assert_eq!(
            decide_inbound_attested(
                &decoded,
                &policy_with_allow(opener, opener_machine, target),
                &opener_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache_with_agent(&opener_kp, opener_machine),
                    contact_store: trusted_store(opener),
                    own_machine_id: recipient_machine,
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
                },
            )
            .await,
            Ok(target),
            "control: untampered wire header must be allowed"
        );
        assert!(
            !logs.text().contains("attestation denied"),
            "control: no denial reason may be logged for the happy path"
        );
        logs.clear();

        // ── Tamper: header signed for a DIFFERENT recipient machine. The
        // recipient scope-binding check fires before any crypto verify.
        let other_recipient = MachineId([9u8; 32]);
        let header = signed_v2_header("127.0.0.1", 22, &opener_kp, other_recipient);
        let decoded = v2_wire_round_trip(&header).await;
        assert_eq!(
            decide_inbound_attested(
                &decoded,
                &policy_with_allow(opener, opener_machine, target),
                &opener_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache_with_agent(&opener_kp, opener_machine),
                    contact_store: trusted_store(opener),
                    own_machine_id: recipient_machine,
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
                },
            )
            .await,
            Err(ConnectDenialReason::AttestationFailed),
            "wrong recipient must deny"
        );
        assert!(
            logs.text().contains("recipient_mismatch"),
            "wrong recipient must log its distinct reason"
        );
        logs.clear();

        // ── Tamper: stale timestamp (post-codec). The freshness check fires
        // BEFORE signature verification, so the logged reason must be the
        // timestamp — not the (also-invalidated) signature.
        let header = signed_v2_header("127.0.0.1", 22, &opener_kp, recipient_machine);
        let mut decoded = v2_wire_round_trip(&header).await;
        decoded.issued_at_ms = now_ms().saturating_sub(FORWARD_V2_ATTESTATION_TTL_MS + 1000);
        assert_eq!(
            decide_inbound_attested(
                &decoded,
                &policy_with_allow(opener, opener_machine, target),
                &opener_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache_with_agent(&opener_kp, opener_machine),
                    contact_store: trusted_store(opener),
                    own_machine_id: recipient_machine,
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
                },
            )
            .await,
            Err(ConnectDenialReason::AttestationFailed),
            "stale timestamp must deny"
        );
        assert!(
            logs.text().contains("stale_attestation"),
            "stale timestamp must log its distinct reason"
        );
        logs.clear();

        // ── Tamper: timestamp beyond the future-skew allowance (post-codec).
        let header = signed_v2_header("127.0.0.1", 22, &opener_kp, recipient_machine);
        let mut decoded = v2_wire_round_trip(&header).await;
        decoded.issued_at_ms = now_ms() + FORWARD_V2_ATTESTATION_FUTURE_SKEW_MS + 1000;
        assert_eq!(
            decide_inbound_attested(
                &decoded,
                &policy_with_allow(opener, opener_machine, target),
                &opener_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache_with_agent(&opener_kp, opener_machine),
                    contact_store: trusted_store(opener),
                    own_machine_id: recipient_machine,
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
                },
            )
            .await,
            Err(ConnectDenialReason::AttestationFailed),
            "future timestamp must deny"
        );
        assert!(
            logs.text().contains("future_attestation"),
            "future timestamp must log its distinct reason"
        );
        logs.clear();

        // ── Tamper: discovery cache binds the opener to a DIFFERENT machine
        // than the transport-authenticated peer. The signature, recipient,
        // and timestamps are all valid — only the machine binding fails.
        let stranger_machine = MachineId([7u8; 32]);
        let header = signed_v2_header("127.0.0.1", 22, &opener_kp, recipient_machine);
        let decoded = v2_wire_round_trip(&header).await;
        assert_eq!(
            decide_inbound_attested(
                &decoded,
                &policy_with_allow(opener, opener_machine, target),
                &opener_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache_with_agent(&opener_kp, stranger_machine),
                    contact_store: trusted_store(opener),
                    own_machine_id: recipient_machine,
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
                },
            )
            .await,
            Err(ConnectDenialReason::AgentNotOnMachine),
            "wrong cached machine must deny"
        );
        assert!(
            logs.text().contains("agent_not_on_machine"),
            "wrong cached machine must log its distinct reason"
        );
        logs.clear();

        // ── Tamper: signature byte flipped post-codec. Every check before
        // the cryptographic verify passes, so the logged reason must be the
        // verify failure with the inner AttestationInvalid Display.
        let header = signed_v2_header("127.0.0.1", 22, &opener_kp, recipient_machine);
        let mut decoded = v2_wire_round_trip(&header).await;
        let mid = decoded.signature.len() / 2;
        decoded.signature[mid] ^= 0xFF;
        assert_eq!(
            decide_inbound_attested(
                &decoded,
                &policy_with_allow(opener, opener_machine, target),
                &opener_machine,
                &AttestationVerifyCtx {
                    discovery_cache: cache_with_agent(&opener_kp, opener_machine),
                    contact_store: trusted_store(opener),
                    own_machine_id: recipient_machine,
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
                },
            )
            .await,
            Err(ConnectDenialReason::AttestationFailed),
            "bad signature must deny"
        );
        let text = logs.text();
        assert!(
            text.contains("attestation_verify_failed"),
            "bad signature must log its distinct reason"
        );
        assert!(
            text.contains("attestation invalid"),
            "bad signature must surface the inner ForwardError"
        );
    }

    /// No Agent/Node construction: real identity primitives, shared inbound
    /// gate and wire header codec, entirely in memory.
    #[tokio::test]
    async fn r132_attested_opener_obeys_current_pairing_after_shared_gate() {
        use crate::key_move::{MoveState, Placement, PlacementAuthority, PlacementRecord};
        let a = AgentKeypair::generate().unwrap();
        let b = AgentKeypair::generate().unwrap();
        let owner = crate::identity::UserKeypair::generate().unwrap();
        let machine = MachineId([21; 32]);
        let recipient = MachineId([22; 32]);
        let cache = cache_with_agent(&a, machine);
        cache
            .write()
            .await
            .extend(cache_with_agent(&b, machine).read().await.clone());
        let contacts = trusted_store(a.agent_id());
        contacts
            .write()
            .await
            .set_identity_type(&b.agent_id(), IdentityType::Anonymous);
        contacts
            .write()
            .await
            .set_trust(&b.agent_id(), TrustLevel::Trusted);
        let revoked = Arc::new(tokio::sync::RwLock::new(
            crate::revocation::RevocationSet::new(),
        ));
        let moves = Arc::new(tokio::sync::RwLock::new(MoveState::new()));
        let target = "127.0.0.1:22".parse().unwrap();
        let policy = policy_multi(vec![
            allow_entry(a.agent_id(), machine, &[target]),
            allow_entry(b.agent_id(), machine, &[target]),
        ]);
        let shared_policy = Arc::new(std::sync::RwLock::new(Arc::new(policy.clone())));
        let record = PlacementRecord::sign(
            a.agent_id(),
            owner.public_key().as_bytes(),
            Placement::Pinned(MachineId([23; 32])),
            1,
            1,
            owner.secret_key(),
        )
        .unwrap();
        moves
            .write()
            .await
            .cache_placement(record, PlacementAuthority::local_owner(&owner))
            .unwrap();
        let surviving = crate::Agent::gate_peer_machine_inbound(
            &cache,
            &contacts,
            &revoked,
            &moves,
            &shared_policy,
            &bound_owner_trust(&[(a.agent_id(), machine), (b.agent_id(), machine)]).await,
            &machine,
        )
        .await
        .unwrap();
        assert_eq!(surviving, vec![b.agent_id()]);
        let ctx = AttestationVerifyCtx {
            discovery_cache: cache,
            contact_store: contacts,
            own_machine_id: recipient,
            clock: Arc::new(now_ms),
            revocation_set: revoked,
            move_state: moves,
            owner_trust: crate::owner_trust::OwnerTrust::default(),
            local_authority_only: false,
        };
        let good = v2_wire_round_trip(&signed_v2_header("127.0.0.1", 22, &b, recipient)).await;
        assert_eq!(
            decide_inbound_attested(&good, &policy, &machine, &ctx).await,
            Ok(target)
        );
        let excluded = v2_wire_round_trip(&signed_v2_header("127.0.0.1", 22, &a, recipient)).await;
        assert_eq!(
            decide_inbound_attested(&excluded, &policy, &machine, &ctx).await,
            Err(ConnectDenialReason::AttestationFailed),
            "a valid old opener signature cannot restore a dead placement"
        );
    }

    #[tokio::test]
    async fn r132_attested_opener_rechecks_expiry_and_revocation() {
        let kp = AgentKeypair::generate().unwrap();
        let machine = MachineId([24; 32]);
        let recipient = MachineId([25; 32]);
        let cache = cache_with_agent(&kp, machine);
        let ctx = AttestationVerifyCtx {
            discovery_cache: cache.clone(),
            contact_store: trusted_store(kp.agent_id()),
            own_machine_id: recipient,
            clock: Arc::new(now_ms),
            revocation_set: Arc::new(tokio::sync::RwLock::new(
                crate::revocation::RevocationSet::new(),
            )),
            move_state: Arc::new(tokio::sync::RwLock::new(crate::key_move::MoveState::new())),
            owner_trust: crate::owner_trust::OwnerTrust::default(),
            local_authority_only: false,
        };
        let target = "127.0.0.1:22".parse().unwrap();
        let policy = policy_with_allow(kp.agent_id(), machine, target);
        let shared_policy = Arc::new(std::sync::RwLock::new(Arc::new(policy.clone())));
        assert_eq!(
            crate::Agent::gate_peer_machine_inbound(
                &ctx.discovery_cache,
                &ctx.contact_store,
                &ctx.revocation_set,
                &ctx.move_state,
                &shared_policy,
                &bound_owner_trust(&[(kp.agent_id(), machine)]).await,
                &machine
            )
            .await
            .unwrap(),
            vec![kp.agent_id()]
        );
        let header = v2_wire_round_trip(&signed_v2_header("127.0.0.1", 22, &kp, recipient)).await;
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &ctx).await,
            Ok(target)
        );
        cache
            .write()
            .await
            .get_mut(&kp.agent_id())
            .unwrap()
            .cert_not_after = Some(1);
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &ctx).await,
            Err(ConnectDenialReason::AttestationFailed)
        );
        cache
            .write()
            .await
            .get_mut(&kp.agent_id())
            .unwrap()
            .cert_not_after = None;
        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(kp.agent_id()),
            kp.public_key(),
            kp.secret_key(),
            1,
            None,
        )
        .unwrap();
        ctx.revocation_set
            .write()
            .await
            .verify_and_insert(record, None)
            .unwrap();
        assert_eq!(
            decide_inbound_attested(&header, &policy, &machine, &ctx).await,
            Err(ConnectDenialReason::AttestationFailed)
        );
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

    /// RC12 / Codex P2 (#1388): `ForwardService::shutdown` cancels every live
    /// registration before the inbound/reauth token, so a bridge closes
    /// immediately while the Agent stays alive.
    #[tokio::test]
    async fn shutdown_cancels_live_streams_while_agent_alive() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        // Explicit paths (incl. absent user.key) so unit runs without
        // nextest's X0X_HOME — avoids #456 real-home panic in Agent::build.
        let agent = Arc::new(
            crate::Agent::builder()
                .with_identity_dir(dir.path())
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key_path(dir.path().join("agent.key"))
                .with_user_key_path(dir.path().join("user.key"))
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .build()
                .await
                .expect("offline agent build"),
        );
        let policy = Arc::new(ConnectPolicy::default());
        let diagnostics = Arc::new(ConnectDiagnostics::new(policy.summary()));
        let service = ForwardService::new(agent.clone(), policy, diagnostics, true)
            .expect("forward acceptor registration");

        let guard = service.live.register(
            teardown::StreamGate::Outbound {
                peer_agent: AgentId([0x51; 32]),
                machine: MachineId([0xB0; 32]),
            },
            teardown::StreamAuthority::PeerTrust,
        );
        assert_eq!(service.live.len(), 1);
        assert!(!guard.token().is_cancelled());

        service.shutdown();

        assert!(
            guard.token().is_cancelled(),
            "shutdown must cancel live bridge tokens immediately"
        );
        assert_eq!(service.live.len(), 0, "shutdown must drain live registry");
        assert_eq!(service.diagnostics().torn_down_reauth(), 0);
        assert_eq!(service.diagnostics().torn_down_shutdown(), 1);
        assert_eq!(
            service.diagnostics().torn_down_reasons().get("shutdown"),
            Some(&1)
        );
        // Agent stays alive: do not call agent.shutdown(); Arc still usable.
        assert!(!agent.shutdown_token().is_cancelled());
        assert!(!agent.agent_id().as_bytes().is_empty());
    }

    /// RC13 / #1488: `ForwardService::shutdown` closes the live registry so a
    /// register that lands afterward cannot obtain an uncancelled bridge token,
    /// while the Agent stays alive (#456 explicit identity paths).
    #[tokio::test]
    async fn shutdown_late_register_cancelled_while_agent_alive() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        // Explicit paths (incl. absent user.key) so unit runs without
        // nextest's X0X_HOME — avoids #456 real-home panic in Agent::build.
        let agent = Arc::new(
            crate::Agent::builder()
                .with_identity_dir(dir.path())
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key_path(dir.path().join("agent.key"))
                .with_user_key_path(dir.path().join("user.key"))
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .build()
                .await
                .expect("offline agent build"),
        );
        let policy = Arc::new(ConnectPolicy::default());
        let diagnostics = Arc::new(ConnectDiagnostics::new(policy.summary()));
        let service = ForwardService::new(agent.clone(), policy, diagnostics, true)
            .expect("forward acceptor registration");

        // Shutdown first; Agent stays alive — do not call agent.shutdown().
        service.shutdown();
        assert!(!agent.shutdown_token().is_cancelled());

        let late = service.live.register(
            teardown::StreamGate::Outbound {
                peer_agent: AgentId([0x51; 32]),
                machine: MachineId([0xB0; 32]),
            },
            teardown::StreamAuthority::PeerTrust,
        );
        assert!(
            late.token().is_cancelled(),
            "register after ForwardService::shutdown must yield a cancelled token"
        );
        assert!(!agent.shutdown_token().is_cancelled());
        assert_eq!(
            service.diagnostics().torn_down_reauth(),
            0,
            "empty/late shutdown path must not count as trust-loss"
        );
    }

    /// RC13 / #1488: a handler that stalls before `live.register`, then resumes
    /// after `ForwardService::shutdown` while the Agent is still alive, must
    /// see a cancelled registration and must not start bridging.
    ///
    /// Unit-style oneshot barrier; no real QUIC.
    #[tokio::test]
    async fn shutdown_cancels_registration_resumed_after_pending_handler() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let agent = Arc::new(
            crate::Agent::builder()
                .with_identity_dir(dir.path())
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key_path(dir.path().join("agent.key"))
                .with_user_key_path(dir.path().join("user.key"))
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .build()
                .await
                .expect("offline agent build"),
        );
        let policy = Arc::new(ConnectPolicy::default());
        let diagnostics = Arc::new(ConnectDiagnostics::new(policy.summary()));
        let service = ForwardService::new(agent.clone(), policy, diagnostics, true)
            .expect("forward acceptor registration");

        let (pending_tx, pending_rx) = tokio::sync::oneshot::channel::<()>();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel::<()>();
        let live = Arc::clone(&service.live);
        let join = tokio::spawn(async move {
            let _ = pending_tx.send(());
            let _ = resume_rx.await;
            let guard = live.register(
                teardown::StreamGate::Outbound {
                    peer_agent: AgentId([0x51; 32]),
                    machine: MachineId([0xB0; 32]),
                },
                teardown::StreamAuthority::PeerTrust,
            );
            let token = guard.token().clone();
            let mut bridge_started = false;
            tokio::select! {
                biased;
                _ = token.cancelled() => {}
                _ = async {
                    bridge_started = true;
                    std::future::pending::<()>().await
                } => {}
            }
            (token.is_cancelled(), bridge_started)
        });

        pending_rx.await.expect("handler reached pending point");
        service.shutdown();
        assert!(
            !agent.shutdown_token().is_cancelled(),
            "Agent must stay alive across ForwardService::shutdown"
        );
        resume_tx.send(()).expect("resume pending handler");
        let (cancelled, bridge_started) = join.await.expect("handler join");
        assert!(
            cancelled,
            "registration resumed after shutdown must be cancelled"
        );
        assert!(
            !bridge_started,
            "cancelled registration must not start bridging"
        );
        assert_eq!(
            service.diagnostics().torn_down_reauth(),
            0,
            "pending-handler race must not count as trust-loss"
        );
    }

    #[tokio::test]
    #[ignore = "binds loopback TCP listeners; run only in the isolated integration tier"]
    async fn port_zero_forwards_are_listed_and_removed_by_bound_address() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key_path(dir.path().join("agent.key"))
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .build()
                .await
                .expect("offline agent build"),
        );
        let policy = Arc::new(ConnectPolicy::default());
        let diagnostics = Arc::new(ConnectDiagnostics::new(policy.summary()));
        let service = ForwardService::new(agent.clone(), policy, diagnostics, true)
            .expect("forward acceptor registration");
        let peer = AgentId([7; 32]);
        let spec = |peer_agent| ForwardSpec {
            local_addr: "127.0.0.1:0".parse().expect("loopback address"),
            peer_agent,
            target_host: "127.0.0.1".to_string(),
            target_port: 9,
            name: None,
            kind: crate::names::NameKind::Agent,
            pinned_machine: None,
            persistent: false,
        };

        let first = service.add_forward(spec(peer)).await.expect("first bind");
        let second = service.add_forward(spec(peer)).await.expect("second bind");
        assert_ne!(first, second);
        assert!(first.port() != 0 && second.port() != 0);
        let listed = service.list_forwards();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|entry| entry.spec.local_addr == first));
        assert!(listed.iter().any(|entry| entry.spec.local_addr == second));

        assert!(service.remove_forward(first));
        assert!(!service.remove_forward(first));
        wait_until_bindable(first).await;
        assert_eq!(service.list_forwards().len(), 1);
        assert!(service.remove_forward(second));
        wait_until_bindable(second).await;
        assert!(service.list_forwards().is_empty());
        service.shutdown();
        agent.shutdown().await;
    }

    async fn wait_until_bindable(addr: SocketAddr) {
        for _ in 0..100 {
            if TcpListener::bind(addr).await.is_ok() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("listener {addr} did not close within bounded wait");
    }

    /// WHY: each add publishes an accept-loop handle, and remove only
    /// cancels it. Without a reap, finished handles stay until shutdown
    /// and grow with every add/remove cycle.
    #[tokio::test]
    async fn removed_listener_handles_do_not_accumulate() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key_path(dir.path().join("agent.key"))
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .build()
                .await
                .expect("offline agent build"),
        );
        let policy = Arc::new(ConnectPolicy::default());
        let diagnostics = Arc::new(ConnectDiagnostics::new(policy.summary()));
        let service = ForwardService::new(Arc::clone(&agent), policy, diagnostics, true)
            .expect("forward acceptor registration");
        let spec = ForwardSpec {
            local_addr: "127.0.0.1:0".parse().expect("loopback address"),
            peer_agent: AgentId([7; 32]),
            target_host: "127.0.0.1".to_string(),
            target_port: 9,
            name: None,
            kind: crate::names::NameKind::Agent,
            pinned_machine: None,
            persistent: false,
        };

        for _ in 0..24 {
            let bound = service.add_forward(spec.clone()).await.expect("bind");
            assert!(service.remove_forward(bound));
            wait_until_bindable(bound).await;
        }
        let mut left = usize::MAX;
        for _ in 0..100 {
            service.reap_finished_listener_tasks();
            left = service
                .listener_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len();
            if left == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(left, 0, "finished accept-loop handles must be dropped");
        service.shutdown();
        agent.shutdown().await;
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
                    clock: Arc::new(move || ts),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(move || ts),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(move || ts),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(move || ts),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(move || ts),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(move || ts),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(move || ts),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(move || ts),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    self_name: None,
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
                    cert_digest: None,
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
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
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
                self_name: None,
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
                cert_digest: None,
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
                    clock: Arc::new(now_ms),
                    revocation_set: Arc::new(tokio::sync::RwLock::new(
                        crate::revocation::RevocationSet::new()
                    )),
                    move_state: Arc::new(tokio::sync::RwLock::new(
                        crate::key_move::MoveState::new()
                    )),
                    owner_trust: crate::owner_trust::OwnerTrust::default(),
                    local_authority_only: false,
                }
            )
            .await
            .unwrap(),
            target,
        );
    }

    /// ADR-0074 §4 bound after an applied reauth event (same as teardown tests).
    const EVENT_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

    /// WHY (Codex P2 / RC6): `try_outbound_v2` races the signing-gate await
    /// against the live-stream cancel token. A forever-pending gate (stalled
    /// move-state lock) must return [`teardown::Cancelled`] within the 5 s
    /// bound so the handler can [`teardown::deny_pre_bridge`] / RST TCP and
    /// drop the registry entry (permit release via guard drop).
    #[tokio::test]
    async fn signing_gate_wait_cancel_closes_tcp_and_clears_registry_within_5s() {
        use std::io::ErrorKind;
        use tokio::io::AsyncReadExt;
        use tokio::net::{TcpListener, TcpStream};
        use tokio::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let server = listener.accept().await.unwrap().0;

        let diag = Arc::new(ForwardDiagnostics::default());
        let live = Arc::new(teardown::LiveStreams::new(Arc::clone(&diag)));
        let guard = live.register(
            teardown::StreamGate::Outbound {
                peer_agent: AgentId([0x51; 32]),
                machine: MachineId([0xB0; 32]),
            },
            teardown::StreamAuthority::PeerTrust,
        );
        assert_eq!(live.len(), 1);

        let token = guard.token().clone();
        let started = Instant::now();
        let stalled = tokio::spawn(async move {
            wait_signing_gate_or_cancel(&token, std::future::pending::<bool>()).await
        });
        tokio::task::yield_now().await;
        guard.token().cancel();

        let result = tokio::time::timeout(EVENT_BOUND, stalled)
            .await
            .expect("signing-gate wait must resolve within ADR-0074 5s bound")
            .expect("join");
        assert!(
            matches!(result, Err(teardown::Cancelled)),
            "stalled signing-gate wait must return Cancelled on live-stream cancel"
        );
        assert!(
            started.elapsed() <= EVENT_BOUND,
            "cancel must interrupt within {EVENT_BOUND:?}, took {:?}",
            started.elapsed()
        );

        // Handler path after Cancelled: deny_pre_bridge RSTs TCP (QUIC half
        // needs real PeerStream halves — covered elsewhere).
        teardown::reset_tcp(&server);
        drop(server);

        let mut buf = [0u8; 8];
        match client.read(&mut buf).await {
            Ok(0) => panic!("got clean EOF (FIN); expected ConnectionReset from linger-0 close"),
            Ok(n) => panic!("unexpected {n} bytes from reset peer"),
            Err(err) => assert_eq!(
                err.kind(),
                ErrorKind::ConnectionReset,
                "expected ConnectionReset, got {err:?}"
            ),
        }

        drop(guard);
        assert_eq!(
            live.len(),
            0,
            "LiveStreamGuard drop must remove the stream from the registry"
        );
    }

    /// WHY (Codex P2 / RC6): cancel during the signing-gate wait maps to
    /// [`OutboundOutcome::Done`] (after deny_pre_bridge), never
    /// [`OutboundOutcome::PeerRejectedV2`]. Refuse (`Ok(false)`) alone falls
    /// back to V1.
    #[tokio::test]
    async fn signing_gate_cancel_is_done_not_peer_rejected_v2() {
        let cancel = CancellationToken::new();
        let wait = tokio::spawn({
            let cancel = cancel.clone();
            async move { wait_signing_gate_or_cancel(&cancel, std::future::pending::<bool>()).await }
        });
        tokio::task::yield_now().await;
        cancel.cancel();

        let result = tokio::time::timeout(EVENT_BOUND, wait)
            .await
            .expect("cancel must resolve within ADR-0074 5s bound")
            .expect("join");

        // Same branch table as try_outbound_v2's signing-gate match.
        let outcome = match result {
            Err(teardown::Cancelled) => "Done",
            Ok(false) => "PeerRejectedV2",
            Ok(true) => "Continue",
        };
        assert_eq!(
            outcome, "Done",
            "cancel during signing-gate wait must be Done, not PeerRejectedV2"
        );

        // Refuse stays on the V1-fallback path (still distinct from cancel).
        let refuse = wait_signing_gate_or_cancel(&CancellationToken::new(), async { false }).await;
        assert!(matches!(refuse, Ok(false)));
        let refuse_outcome = match refuse {
            Err(teardown::Cancelled) => "Done",
            Ok(false) => "PeerRejectedV2",
            Ok(true) => "Continue",
        };
        assert_eq!(refuse_outcome, "PeerRejectedV2");
    }

    /// WHY (Codex P2 on #1488 RC10): forward admission uses construction-injected
    /// clocks. `authorize_attested_opener` awaits `evaluate_pair_with` then
    /// `grant_access_at` (OwnerTrust clock, no caller now). A grant that expires
    /// during the contact-store wait must be denied.
    #[tokio::test]
    async fn authorize_attested_opener_denies_grant_expired_during_contact_lock_wait() {
        use crate::connect::acl::ConnectOwnerEntry;
        use crate::identity::{MachineKeypair, UserKeypair};
        use crate::share_grant::{Grantee, ShareCap, ShareGrant, ShareGrantStore};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::Duration;

        let owner = UserKeypair::generate().expect("owner keygen");
        let local_agent = AgentKeypair::generate().expect("local agent").agent_id();
        let remote_kp = AgentKeypair::generate().expect("remote agent");
        let remote_agent = remote_kp.agent_id();
        let remote_machine = MachineKeypair::generate()
            .expect("remote machine")
            .machine_id();

        let t0 = 1_700_000_000u64;
        let bindings = crate::dm_inbox::AuthenticatedMachineBindings::default();
        crate::dm_inbox::record_authenticated_machine_binding(
            &bindings,
            remote_agent,
            remote_machine,
            t0,
        )
        .await;
        let clock_secs = Arc::new(AtomicU64::new(t0));
        let clock_for_trust = Arc::clone(&clock_secs);
        let trust = crate::owner_trust::OwnerTrust::new(Some(owner.user_id()), bindings)
            .with_clock(Arc::new(move || clock_for_trust.load(Ordering::SeqCst)));

        let grants = Arc::new(ShareGrantStore::in_memory(
            local_agent,
            Some(owner.user_id()),
        ));
        let expiry = t0 + 2;
        let grant = ShareGrant::sign(
            &owner,
            [0xA2; 32],
            Grantee::Agent(remote_agent),
            vec![local_agent],
            vec![ShareCap::Connect { ports: vec![22] }],
            t0.saturating_sub(60),
            expiry,
        )
        .expect("sign short-lived grant");
        grants.accept(grant, t0).await.expect("accept grant");
        trust.install_share_grant_store(grants);

        let target: SocketAddr = "127.0.0.1:22".parse().unwrap();
        let policy = ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: "test".into(),
            loaded_at_unix_ms: 0,
            allow: Vec::new(),
            owner_allow: Vec::new(),
            grant_allow: vec![ConnectOwnerEntry {
                description: None,
                targets: vec![crate::connect::acl::OwnerTarget::Exact(target)],
            }],
        });

        let dir = tempfile::tempdir().expect("tmpdir");
        let contacts = Arc::new(tokio::sync::RwLock::new(ContactStore::new(
            dir.path().join("contacts.json"),
        )));
        let cache = cache_with_agent(&remote_kp, remote_machine);
        let revocations = Arc::new(tokio::sync::RwLock::new(
            crate::revocation::RevocationSet::new(),
        ));
        let move_state = Arc::new(tokio::sync::RwLock::new(crate::key_move::MoveState::new()));

        let clock_for_ctx = Arc::clone(&clock_secs);
        let ctx = AttestationVerifyCtx {
            discovery_cache: Arc::clone(&cache),
            contact_store: Arc::clone(&contacts),
            own_machine_id: MachineId([0x0A; 32]),
            clock: Arc::new(move || clock_for_ctx.load(Ordering::SeqCst).saturating_mul(1000)),
            revocation_set: Arc::clone(&revocations),
            move_state: Arc::clone(&move_state),
            owner_trust: trust.clone(),
            local_authority_only: false,
        };

        let live =
            authorize_attested_opener(&remote_agent, &remote_machine, &target, &policy, &ctx).await;
        assert!(
            matches!(live, LocalAuthorityOutcome::Allow(_)),
            "control: grant must admit Connect at T0: {live:?}"
        );

        let held = contacts.write().await;
        let pending = tokio::spawn({
            let cache = Arc::clone(&cache);
            let contacts = Arc::clone(&contacts);
            let revocations = Arc::clone(&revocations);
            let move_state = Arc::clone(&move_state);
            let trust = trust.clone();
            let policy = policy.clone();
            let clock_for_ctx = Arc::clone(&clock_secs);
            async move {
                let ctx = AttestationVerifyCtx {
                    discovery_cache: cache,
                    contact_store: contacts,
                    own_machine_id: MachineId([0x0A; 32]),
                    clock: Arc::new(move || {
                        clock_for_ctx.load(Ordering::SeqCst).saturating_mul(1000)
                    }),
                    revocation_set: revocations,
                    move_state,
                    owner_trust: trust,
                    local_authority_only: false,
                };
                authorize_attested_opener(&remote_agent, &remote_machine, &target, &policy, &ctx)
                    .await
            }
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        clock_secs.store(expiry + 1, Ordering::SeqCst);
        drop(held);

        let denied = pending.await.expect("authorize task");
        assert!(
            matches!(denied, LocalAuthorityOutcome::Deny(_)),
            "grant that expired during contact-lock wait must not admit: {denied:?}"
        );
    }

    /// WHY (RC10): gate expiry must read OwnerTrust's clock after the
    /// discovery-cache await, not a caller stamp taken before it. Holding the
    /// discovery write lock parks the gate's cache read; advancing the clock
    /// past `cert_not_after` before release must Deny the new lane.
    #[tokio::test]
    async fn gate_peer_denies_cert_expired_during_discovery_lock_wait() {
        use crate::identity::MachineKeypair;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::Duration;

        let remote_kp = AgentKeypair::generate().expect("remote agent");
        let remote_agent = remote_kp.agent_id();
        let remote_machine = MachineKeypair::generate()
            .expect("remote machine")
            .machine_id();

        let t0 = 1_700_000_000u64;
        let cert_not_after = t0 + 10;
        let cache = cache_with_agent(&remote_kp, remote_machine);
        {
            let mut guard = cache.write().await;
            let entry = guard.get_mut(&remote_agent).expect("cached");
            entry.cert_not_after = Some(cert_not_after);
        }

        let clock = Arc::new(AtomicU64::new(t0));
        let clock_task = Arc::clone(&clock);
        let bindings = crate::dm_inbox::AuthenticatedMachineBindings::default();
        crate::dm_inbox::record_authenticated_machine_binding(
            &bindings,
            remote_agent,
            remote_machine,
            t0,
        )
        .await;
        let announced = crate::dm_inbox::AuthenticatedMachineBindings::default();
        crate::dm_inbox::record_authenticated_machine_binding(
            &announced,
            remote_agent,
            remote_machine,
            t0,
        )
        .await;
        let trust = crate::owner_trust::OwnerTrust::new(None, Arc::clone(&bindings))
            .with_clock(Arc::new(move || clock_task.load(Ordering::SeqCst)));
        trust.install_announced_bindings(Arc::clone(&announced));

        let contacts = trusted_store(remote_agent);
        let revocations = Arc::new(tokio::sync::RwLock::new(
            crate::revocation::RevocationSet::new(),
        ));
        let move_state = Arc::new(tokio::sync::RwLock::new(crate::key_move::MoveState::new()));
        let connect_policy = Arc::new(std::sync::RwLock::new(Arc::new(ConnectPolicy::default())));

        let live = crate::Agent::gate_peer_outbound_at(
            &cache,
            &contacts,
            &revocations,
            &move_state,
            &trust,
            &announced,
            &bindings,
            &remote_agent,
            false,
        )
        .await;
        assert!(
            matches!(live, Ok(m) if m == remote_machine),
            "control: unexpired cert must admit outbound: {live:?}"
        );
        let live_in = crate::Agent::gate_peer_machine_inbound_at(
            &cache,
            &contacts,
            &revocations,
            &move_state,
            &connect_policy,
            &trust,
            &remote_machine,
            false,
        )
        .await;
        assert!(
            matches!(live_in, Ok(ref agents) if agents == &[remote_agent]),
            "control: unexpired cert must admit inbound: {live_in:?}"
        );

        let held = cache.write().await;
        let pending_out = tokio::spawn({
            let cache = Arc::clone(&cache);
            let contacts = Arc::clone(&contacts);
            let revocations = Arc::clone(&revocations);
            let move_state = Arc::clone(&move_state);
            let trust = trust.clone();
            let announced = Arc::clone(&announced);
            let bindings = Arc::clone(&bindings);
            async move {
                crate::Agent::gate_peer_outbound_at(
                    &cache,
                    &contacts,
                    &revocations,
                    &move_state,
                    &trust,
                    &announced,
                    &bindings,
                    &remote_agent,
                    false,
                )
                .await
            }
        });
        let pending_in = tokio::spawn({
            let cache = Arc::clone(&cache);
            let contacts = Arc::clone(&contacts);
            let revocations = Arc::clone(&revocations);
            let move_state = Arc::clone(&move_state);
            let connect_policy = Arc::clone(&connect_policy);
            let trust = trust.clone();
            async move {
                crate::Agent::gate_peer_machine_inbound_at(
                    &cache,
                    &contacts,
                    &revocations,
                    &move_state,
                    &connect_policy,
                    &trust,
                    &remote_machine,
                    false,
                )
                .await
            }
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Past not_after and the identity skew window so is_expired is true.
        clock.store(
            cert_not_after
                .saturating_add(crate::identity::EXPIRY_CLOCK_SKEW_SECS)
                .saturating_add(1),
            Ordering::SeqCst,
        );
        drop(held);

        let denied_out = pending_out.await.expect("outbound gate task");
        assert!(
            matches!(denied_out, Err(PeerGateError::Network(_))),
            "cert expired during discovery-lock wait must deny outbound: {denied_out:?}"
        );
        let denied_in = pending_in.await.expect("inbound gate task");
        assert!(
            matches!(denied_in, Err(PeerGateError::Network(_))),
            "cert expired during discovery-lock wait must deny inbound: {denied_in:?}"
        );
    }

    // ── ADR-0074 §1 machine binding (slice 2) ─────────────────────────────

    /// Everything the peer side of `w` received once the writer is gone.
    async fn received(mut peer_side: tokio::io::DuplexStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;
        let mut got = Vec::new();
        peer_side
            .read_to_end(&mut got)
            .await
            .expect("read peer side");
        got
    }

    fn signed_frame() -> Vec<u8> {
        let opener = AgentKeypair::generate().expect("keypair");
        let mut header = ForwardV2Header::new(
            "::1".to_string(),
            22,
            opener.agent_id(),
            opener.public_key().as_bytes().to_vec(),
            MachineId([0x11; 32]),
        );
        header.sign(&opener).expect("sign");
        header.encode()
    }

    /// WHY (ADR-0074 §1): a pinned forward whose stream reaches another
    /// machine must be refused BEFORE the forward header goes out — the
    /// header names the target service and carries the opener's signed
    /// attestation, so a wrong machine must learn neither. Zero bytes on
    /// the stream, for both header versions.
    #[tokio::test]
    async fn peer_mismatch_sends_no_header_bytes() {
        let pinned = MachineId([0x11; 32]);
        let actual = MachineId([0x22; 32]);
        let v1 = ForwardHeader {
            target_host: "127.0.0.1".to_string(),
            target_port: 22,
        }
        .encode();
        for frame in [signed_frame(), v1] {
            let (mut opener_side, peer_side) = tokio::io::duplex(64 * 1024);
            let outcome =
                send_header_to_pinned(&mut opener_side, actual, Some(pinned), &frame).await;
            assert!(
                matches!(
                    outcome,
                    HeaderSend::MachineMismatch { pinned: p, actual: a } if p == pinned && a == actual
                ),
                "mismatch must be refused, got {outcome:?}"
            );
            drop(opener_side);
            assert!(
                received(peer_side).await.is_empty(),
                "no header byte may reach an unpinned machine"
            );
        }
    }

    /// WHY: the check must not break the forwards it protects — the right
    /// machine, or an unpinned (ephemeral agent) forward, gets the exact
    /// header frame.
    #[tokio::test]
    async fn pinned_or_unpinned_peer_receives_the_exact_header() {
        let pinned = MachineId([0x11; 32]);
        let frame = signed_frame();
        for pin in [Some(pinned), None] {
            let (mut opener_side, peer_side) = tokio::io::duplex(64 * 1024);
            let outcome = send_header_to_pinned(&mut opener_side, pinned, pin, &frame).await;
            assert!(matches!(outcome, HeaderSend::Sent), "{outcome:?}");
            drop(opener_side);
            assert_eq!(received(peer_side).await, frame);
        }
    }

    /// WHY: the pin has to travel with the listener the daemon restores,
    /// not only with the header helper. A local client on the restored
    /// port must be refused before any header byte, and must not fall
    /// back to V1, when the stream's machine is not the pin.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn listener_refuses_a_wrong_machine_before_any_header_byte() {
        use tokio::io::AsyncWriteExt;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let Some(alice) = build_loopback_agent(dir.path(), "alice").await else {
            return;
        };
        let Some(bob) = build_loopback_agent(dir.path(), "bob").await else {
            alice.shutdown().await;
            return;
        };
        let alice = Arc::new(alice);
        let bob = Arc::new(bob);
        link_loopback_pair(&alice, &bob).await;

        let (target_port, target_bytes, target_cancel) = spawn_counting_target().await;
        let target = SocketAddr::from(([127, 0, 0, 1], target_port));
        let bob_policy = allow_exact(&alice, target);
        let bob_diag = Arc::new(ConnectDiagnostics::new(bob_policy.summary()));
        let bob_fwd = Arc::new(
            ForwardService::new(Arc::clone(&bob), bob_policy, bob_diag, true)
                .expect("bob forwarder"),
        );
        bob_fwd.spawn_inbound();

        let alice_policy = Arc::new(ConnectPolicy::default());
        let alice_diag = Arc::new(ConnectDiagnostics::new(alice_policy.summary()));
        let alice_fwd = Arc::new(
            ForwardService::new(Arc::clone(&alice), alice_policy, alice_diag, true)
                .expect("alice forwarder"),
        );
        let wrong = MachineId([0xEE; 32]);
        assert_ne!(wrong, bob.machine_id());
        let bound = alice_fwd
            .add_forward(ForwardSpec {
                local_addr: "127.0.0.1:0".parse().expect("loopback"),
                peer_agent: bob.agent_id(),
                target_host: "127.0.0.1".to_string(),
                target_port,
                name: Some("machine:box.me".to_string()),
                kind: crate::names::NameKind::Machine,
                pinned_machine: Some(wrong),
                persistent: true,
            })
            .await
            .expect("listener");
        let mut client = TcpStream::connect(bound).await.expect("local client");
        client
            .write_all(b"secret-target")
            .await
            .expect("local write");

        let counted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if alice_fwd.diagnostics().machine_mismatch() >= 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        target_cancel.cancel();
        alice_fwd.shutdown();
        bob_fwd.shutdown();
        alice.shutdown().await;
        bob.shutdown().await;

        assert!(
            counted.is_ok(),
            "the listener must count a pin mismatch from the outbound driver"
        );
        assert_eq!(
            target_bytes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a wrong machine must receive no header and no V1 fallback"
        );
    }

    fn resolved_machine(agent: AgentId, machine: MachineId) -> crate::names::Resolved {
        crate::names::Resolved {
            name: "machine:box.me".to_string(),
            kind: crate::names::NameKind::Machine,
            owner: crate::identity::UserId([0x33; 32]),
            agent_id: Some(agent),
            machine_id: Some(machine),
            newly_pinned: false,
        }
    }

    fn peer_stream(
        machine: MachineId,
        send: crate::network::StreamSend,
        recv: crate::network::StreamRecv,
    ) -> PeerStream {
        PeerStream::new(
            vec![AgentId([0x44; 32])],
            machine,
            StreamProtocol::ForwardV2,
            send,
            recv,
        )
    }

    /// WHY (replaces slice 1's interim refusal of `machine:` forwards):
    /// machine names are allowed only because the peer check exists. The
    /// check is `PeerStream::peer()`, the same read `try_outbound_v2` and
    /// `drive_outbound_v1` use. A mismatch resets the stream (the peer sees
    /// connection reset, not a finished header) and [`after_pin`] says
    /// stop, so V2 does not fall back to V1. The matching machine is the
    /// positive control: the same path writes the exact frame and continues.
    #[tokio::test]
    async fn machine_pin_uses_peer_stream_and_does_not_fall_back() {
        let box_machine = MachineId([0x11; 32]);
        let elsewhere = MachineId([0x22; 32]);
        let resolved = resolved_machine(AgentId([0x44; 32]), box_machine);
        let name = crate::names::NameRef::parse("machine:box.me").expect("name");
        let (agent, pinned) = crate::names::forward_target(&resolved, &name).expect("target");
        assert_eq!(agent, AgentId([0x44; 32]));
        assert_eq!(pinned, Some(box_machine), "a machine name must pin");
        assert_eq!(after_pin(PinnedHeader::Refused), AfterPin::Stop);
        assert_eq!(after_pin(PinnedHeader::Failed), AfterPin::Fallback);
        assert_eq!(after_pin(PinnedHeader::Sent), AfterPin::Continue);

        let v1 = ForwardHeader {
            target_host: "127.0.0.1".to_string(),
            target_port: 22,
        }
        .encode();
        let diag = ForwardDiagnostics::default();
        for frame in [signed_frame(), v1] {
            let ((send, recv), (_peer_send, mut peer_recv)) =
                crate::network::sim::connected_bi_halves().await;
            let mut stream = peer_stream(elsewhere, send, recv);
            assert_eq!(stream.peer(), elsewhere);
            let outcome = write_pinned_header(&mut stream, pinned, &frame, &diag).await;
            assert_eq!(outcome, PinnedHeader::Refused, "{outcome:?}");
            assert_eq!(after_pin(outcome), AfterPin::Stop);
            let err = peer_recv
                .read_exact(&mut [0u8; 1])
                .await
                .expect_err("a reset stream has no header byte");
            assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
            drop(stream);

            let ((send, recv), (_peer_send, mut peer_recv)) =
                crate::network::sim::connected_bi_halves().await;
            let mut stream = peer_stream(box_machine, send, recv);
            assert_eq!(stream.peer(), box_machine);
            let before = diag.machine_mismatch();
            let outcome = write_pinned_header(&mut stream, pinned, &frame, &diag).await;
            assert_eq!(outcome, PinnedHeader::Sent, "{outcome:?}");
            assert_eq!(after_pin(outcome), AfterPin::Continue);
            assert_eq!(diag.machine_mismatch(), before);
            let mut got = vec![0u8; frame.len()];
            peer_recv
                .read_exact(&mut got)
                .await
                .expect("the pinned machine receives the header");
            assert_eq!(got, frame);
            drop(stream);
        }
        assert_eq!(diag.machine_mismatch(), 2);
    }

    fn offline_agent_paths(dir: &std::path::Path) -> crate::AgentBuilder {
        crate::Agent::builder()
            .with_identity_dir(dir)
            .with_machine_key(dir.join("machine.key"))
            .with_agent_key_path(dir.join("agent.key"))
            .with_user_key_path(dir.join("user.key"))
            .with_agent_cert_path(dir.join("agent.cert"))
            .with_contact_store_path(dir.join("contacts.json"))
            .with_peer_cache_disabled()
    }

    async fn offline_forward_service() -> (tempfile::TempDir, Arc<crate::Agent>, Arc<ForwardService>)
    {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let agent = Arc::new(
            offline_agent_paths(dir.path())
                .build()
                .await
                .expect("offline agent build"),
        );
        let policy = Arc::new(ConnectPolicy::default());
        let diagnostics = Arc::new(ConnectDiagnostics::new(policy.summary()));
        let service = Arc::new(
            ForwardService::new(Arc::clone(&agent), policy, diagnostics, true)
                .expect("forward acceptor registration"),
        );
        (dir, agent, service)
    }

    fn peer_card(
        agent_id: AgentId,
        machine_id: MachineId,
        now_secs: u64,
    ) -> crate::DiscoveredAgent {
        crate::DiscoveredAgent {
            self_name: None,
            cert_digest: None,
            agent_id,
            machine_id,
            user_id: None,
            addresses: Vec::new(),
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

    /// WHY (Codex P1 / #1505): `prepare_socks_tunnel` is the only entry a
    /// SOCKS embedder calls. It must start ADR-0074 reauth, so blocking the
    /// peer closes a live outbound tunnel without `spawn_inbound` or
    /// `add_forward`.
    #[tokio::test]
    async fn socks_prepare_trust_downgrade_closes_live_tunnel() {
        let (_dir, agent, service) = offline_forward_service().await;
        let peer = AgentId([0x51; 32]);
        let machine = MachineId([0xB0; 32]);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        agent
            .record_authenticated_machine_binding_for_testing(peer, machine)
            .await;
        agent
            .insert_discovered_agent_for_testing(peer_card(peer, machine, now_secs))
            .await;
        agent.set_contact_trusted_for_testing(peer).await;

        let prepared = service.prepare_socks_tunnel(&peer, 9).await;
        match prepared {
            Err(PrepareSocksError::Failed) => {}
            Err(other) => panic!("offline SOCKS prepare must fail closed, got {other:?}"),
            Ok(_) => panic!("offline agent has no QUIC peer; prepare must not succeed"),
        }
        assert!(
            service
                .inbound_acceptors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some(),
            "SOCKS-only embedder must not consume inbound acceptors"
        );
        assert!(service.list_forwards().is_empty());

        // Let the monitor consume the trust-add kick before the stream exists.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let guard = service.live.register(
            teardown::StreamGate::Outbound {
                peer_agent: peer,
                machine,
            },
            teardown::StreamAuthority::PeerTrust,
        );
        assert!(
            !guard.token().is_cancelled(),
            "trusted peer must not be torn down at registration"
        );

        agent
            .contacts()
            .write()
            .await
            .set_trust(&peer, crate::contacts::TrustLevel::Blocked);
        tokio::time::timeout(std::time::Duration::from_secs(5), guard.token().cancelled())
            .await
            .expect("local trust downgrade must close the SOCKS-path tunnel within 5s");
        assert_eq!(service.diagnostics().torn_down_reauth(), 1);
        assert_eq!(
            service
                .diagnostics()
                .torn_down_reasons()
                .get("trust_rejected"),
            Some(&1)
        );
        service.shutdown();
        agent.shutdown().await;
    }

    fn loopback_network_config() -> crate::network::NetworkConfig {
        crate::network::NetworkConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..crate::network::NetworkConfig::default()
        }
    }

    fn refused_udp(err: &impl std::fmt::Display) -> bool {
        let message = err.to_string();
        let refused = message.contains("Operation not permitted")
            && (message.contains("bind UDP socket")
                || message.contains("network initialization failed"));
        if refused && std::env::var("X0X_REQUIRE_NETWORK_TESTS").as_deref() == Ok("1") {
            panic!(
                "network setup refused but X0X_REQUIRE_NETWORK_TESTS=1 requires this test: {message}"
            );
        }
        refused
    }

    async fn build_loopback_agent(dir: &std::path::Path, name: &str) -> Option<crate::Agent> {
        let home = dir.join(name);
        std::fs::create_dir_all(&home).expect("agent home");
        match crate::Agent::builder()
            .with_identity_dir(&home)
            .with_machine_key(home.join("machine.key"))
            .with_agent_key_path(home.join("agent.key"))
            .with_user_key_path(home.join("user.key"))
            .with_agent_cert_path(home.join("agent.cert"))
            .with_contact_store_path(home.join("contacts.json"))
            .with_peer_cache_dir(home.join("peer-cache"))
            .with_network_config(loopback_network_config())
            .build()
            .await
        {
            Ok(agent) => Some(agent),
            Err(err) if refused_udp(&err) => None,
            Err(err) => panic!("agent build failed: {err}"),
        }
    }

    fn normalize_loopback(addr: SocketAddr) -> SocketAddr {
        if addr.ip().is_unspecified() {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), addr.port())
        } else {
            addr
        }
    }

    fn allow_exact(opener: &crate::Agent, target: SocketAddr) -> Arc<ConnectPolicy> {
        Arc::new(ConnectPolicy::Enabled(ConnectAcl {
            loaded_from: "test".into(),
            loaded_at_unix_ms: 0,
            allow: vec![ConnectAllowEntry {
                description: None,
                agent_id: opener.agent_id(),
                machine_id: opener.machine_id(),
                targets: vec![target],
            }],
            owner_allow: Vec::new(),
            grant_allow: Vec::new(),
        }))
    }

    async fn link_loopback_pair(alice: &Arc<crate::Agent>, bob: &Arc<crate::Agent>) {
        alice.join_network().await.expect("alice join");
        bob.join_network().await.expect("bob join");
        let alice_net = alice.network().expect("alice network").clone();
        let bob_net = bob.network().expect("bob network").clone();
        let bob_addr = normalize_loopback(bob_net.bound_addr().await.expect("bob addr"));
        alice_net
            .connect_addr(bob_addr)
            .await
            .expect("alice dials bob");
        let bob_peer = ant_quic::PeerId(bob.machine_id().0);
        let linked = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if alice_net.is_connected(&bob_peer).await
                    && bob_net
                        .is_connected(&ant_quic::PeerId(alice.machine_id().0))
                        .await
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(linked.is_ok(), "loopback pair did not connect");

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let alice_addr = normalize_loopback(alice_net.bound_addr().await.expect("alice addr"));
        alice
            .insert_discovered_agent_for_testing({
                let mut card = peer_card(bob.agent_id(), bob.machine_id(), now_secs);
                card.addresses = vec![bob_addr];
                card
            })
            .await;
        alice.set_contact_trusted_for_testing(bob.agent_id()).await;
        bob.insert_discovered_agent_for_testing({
            let mut card = peer_card(alice.agent_id(), alice.machine_id(), now_secs);
            card.addresses = vec![alice_addr];
            card
        })
        .await;
        bob.set_contact_trusted_for_testing(alice.agent_id()).await;
        alice
            .record_authenticated_machine_binding_for_testing(bob.agent_id(), bob.machine_id())
            .await;
        bob.record_authenticated_machine_binding_for_testing(alice.agent_id(), alice.machine_id())
            .await;
    }

    async fn spawn_counting_target() -> (u16, Arc<std::sync::atomic::AtomicU64>, CancellationToken)
    {
        use tokio::io::AsyncReadExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("target");
        let port = listener.local_addr().expect("target addr").port();
        let bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let bytes_task = Arc::clone(&bytes);
        let cancel_task = cancel.clone();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = cancel_task.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((mut sock, _)) = accepted else { break };
                let bytes_task = Arc::clone(&bytes_task);
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                bytes_task.fetch_add(n as u64, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    }
                });
            }
        });
        (port, bytes, cancel)
    }

    /// SOCKS CONNECT, one payload, then block the peer. Returns the opener's
    /// active-stream count while the payload was in flight, and whether the
    /// tunnel closed within 5 s of the downgrade.
    async fn drive_socks_then_block(
        alice: &Arc<crate::Agent>,
        alice_fwd: &Arc<ForwardService>,
        bob_id: AgentId,
        target_port: u16,
        target_bytes: &Arc<std::sync::atomic::AtomicU64>,
    ) -> (u64, bool) {
        use std::sync::atomic::AtomicU64;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const TOKEN: &str = "socks-rc2-token";
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("socks");
        let addr = listener.local_addr().expect("socks addr");
        let (client_res, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let mut client = client_res.expect("socks client");
        let (server, _) = accepted.expect("socks accept");
        let host = format!("{}.x0x", hex::encode(bob_id.as_bytes()));
        let connector = crate::socks::ForwardSocksConnector::new(Arc::clone(alice_fwd));
        let denied = AtomicU64::new(0);
        let cancel = CancellationToken::new();
        let contacts = alice.contacts().clone();
        let fwd = Arc::clone(alice_fwd);
        let bytes = Arc::clone(target_bytes);

        let handler =
            crate::socks::handle_tcp_client(server, TOKEN, &connector, &denied, None, &cancel);
        let client_side = async move {
            client.write_all(&[0x05, 0x01, 0x02]).await.expect("greet");
            let mut method = [0u8; 2];
            client.read_exact(&mut method).await.expect("method");
            assert_eq!(method, [0x05, 0x02]);
            let user = b"x0x";
            let pass = TOKEN.as_bytes();
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user);
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass);
            client.write_all(&auth).await.expect("auth");
            let mut status = [0u8; 2];
            client.read_exact(&mut status).await.expect("auth status");
            assert_eq!(status, [0x01, 0x00]);
            let host_b = host.as_bytes();
            let mut req = vec![0x05, 0x01, 0x00, 0x03, host_b.len() as u8];
            req.extend_from_slice(host_b);
            req.extend_from_slice(&target_port.to_be_bytes());
            client.write_all(&req).await.expect("connect");
            let mut resp = [0u8; 10];
            client.read_exact(&mut resp).await.expect("connect reply");
            assert_eq!(resp[1], 0x00, "SOCKS CONNECT must succeed");
            client.write_all(b"ping").await.expect("payload");
            let saw_bytes = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while bytes.load(std::sync::atomic::Ordering::SeqCst) < 4 {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await;
            assert!(
                saw_bytes.is_ok(),
                "proxied payload did not reach the target"
            );
            let active = fwd.diagnostics().active_streams();
            contacts
                .write()
                .await
                .set_trust(&bob_id, crate::contacts::TrustLevel::Blocked);
            let torn = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut buf = [0u8; 8];
                let _ = client.read(&mut buf).await;
                while fwd.diagnostics().torn_down_reauth() < 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await;
            (active, torn.is_ok())
        };
        let (handler, counted) = tokio::join!(handler, client_side);
        handler.expect("socks session");
        counted
    }

    /// WHY (Codex P2 / #1505): a successful SOCKS proxy must show up in the
    /// opener's active-stream count (`GET /streams`) while bytes flow, and a
    /// local trust downgrade must close that tunnel. Alice never calls
    /// `spawn_inbound` or `add_forward`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn socks_proxy_counts_active_stream_until_trust_downgrade() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let Some(alice) = build_loopback_agent(dir.path(), "alice").await else {
            return;
        };
        let Some(bob) = build_loopback_agent(dir.path(), "bob").await else {
            alice.shutdown().await;
            return;
        };
        let alice = Arc::new(alice);
        let bob = Arc::new(bob);
        link_loopback_pair(&alice, &bob).await;

        let (target_port, target_bytes, target_cancel) = spawn_counting_target().await;
        let bob_policy = allow_exact(&alice, SocketAddr::from(([127, 0, 0, 1], target_port)));
        let bob_diag = Arc::new(ConnectDiagnostics::new(bob_policy.summary()));
        let bob_fwd = Arc::new(
            ForwardService::new(Arc::clone(&bob), bob_policy, bob_diag, true)
                .expect("bob forwarder"),
        );
        bob_fwd.spawn_inbound();

        let alice_policy = Arc::new(ConnectPolicy::default());
        let alice_diag = Arc::new(ConnectDiagnostics::new(alice_policy.summary()));
        let alice_fwd = Arc::new(
            ForwardService::new(Arc::clone(&alice), alice_policy, alice_diag, true)
                .expect("alice forwarder"),
        );
        assert!(
            alice_fwd
                .inbound_acceptors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some(),
            "opener must stay SOCKS-only: no spawn_inbound"
        );
        assert_eq!(alice_fwd.diagnostics().active_streams(), 0);

        let counted = tokio::time::timeout(
            std::time::Duration::from_secs(25),
            drive_socks_then_block(
                &alice,
                &alice_fwd,
                bob.agent_id(),
                target_port,
                &target_bytes,
            ),
        )
        .await;

        target_cancel.cancel();
        bob_fwd.shutdown();
        alice_fwd.shutdown();
        alice.shutdown().await;
        bob.shutdown().await;

        let (active_during, closed) = counted.expect("proxy session finished");
        assert_eq!(
            active_during, 1,
            "GET /streams reads this counter and must be non-zero while SOCKS traffic flows"
        );
        assert!(
            closed,
            "local trust downgrade must close the live SOCKS tunnel within 5s"
        );
        assert_eq!(alice_fwd.diagnostics().active_streams(), 0);
        assert_eq!(alice_fwd.diagnostics().torn_down_reauth(), 1);
        assert_eq!(
            alice_fwd
                .diagnostics()
                .torn_down_reasons()
                .get("trust_rejected"),
            Some(&1)
        );
    }

    /// WHY (Codex P2 / #1505): a trusted peer that accepts ForwardV2 and
    /// withholds the response byte must not keep the QUIC stream after the
    /// SOCKS client disconnects. Cleanup has to beat the 10 second deadline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn socks_stalled_peer_resets_stream_on_client_disconnect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::TempDir::new().expect("tempdir");
        let Some(alice) = build_loopback_agent(dir.path(), "alice").await else {
            return;
        };
        let Some(bob) = build_loopback_agent(dir.path(), "bob").await else {
            return;
        };
        let alice = Arc::new(alice);
        let bob = Arc::new(bob);
        link_loopback_pair(&alice, &bob).await;

        let bob_policy = Arc::new(ConnectPolicy::default());
        let bob_diag = Arc::new(ConnectDiagnostics::new(bob_policy.summary()));
        let bob_fwd = Arc::new(
            ForwardService::new(Arc::clone(&bob), bob_policy, bob_diag, true)
                .expect("bob forwarder"),
        );
        let mut bob_v2 = bob_fwd
            .inbound_acceptors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("bob acceptors")
            .1;

        let alice_policy = Arc::new(ConnectPolicy::default());
        let alice_diag = Arc::new(ConnectDiagnostics::new(alice_policy.summary()));
        let alice_fwd = Arc::new(
            ForwardService::new(Arc::clone(&alice), alice_policy, alice_diag, true)
                .expect("alice forwarder"),
        );
        assert_eq!(alice_fwd.diagnostics().active_streams(), 0);

        let (saw_header_tx, saw_header_rx) = tokio::sync::oneshot::channel();
        let bob_hold = tokio::spawn(async move {
            let Some(mut stream) = bob_v2.next().await else {
                return false;
            };
            let header = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                read_header_v2(stream.recv_mut()),
            )
            .await;
            let Ok(Ok(_)) = header else {
                return false;
            };
            let _ = saw_header_tx.send(());
            let mut buf = [0u8; 1];
            // Timeout is failure: the opener must reset, not leave us blocked.
            matches!(
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    stream.recv_mut().read(&mut buf),
                )
                .await,
                Ok(Ok(0)) | Ok(Err(_))
            )
        });

        let probe = TcpListener::bind("127.0.0.1:0").await.expect("socks probe");
        let port = probe.local_addr().expect("socks addr").port();
        drop(probe);
        let listen: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("loopback socks listen");
        let service = crate::socks::SocksService::spawn(
            &crate::socks::SocksConfig {
                listen: Some(listen),
            },
            Arc::new("socks-rc3-token".to_string()),
            Arc::new(crate::socks::ForwardSocksConnector::new(Arc::clone(
                &alice_fwd,
            ))),
            CancellationToken::new(),
        )
        .await
        .expect("socks spawn");

        let mut client = TcpStream::connect(listen).await.expect("socks client");
        client.write_all(&[0x05, 0x01, 0x02]).await.expect("greet");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.expect("method");
        assert_eq!(method, [0x05, 0x02]);
        let pass = b"socks-rc3-token";
        let mut auth = vec![0x01, 3];
        auth.extend_from_slice(b"x0x");
        auth.push(u8::try_from(pass.len()).expect("token fits a u8"));
        auth.extend_from_slice(pass);
        client.write_all(&auth).await.expect("auth");
        let mut auth_rep = [0u8; 2];
        client.read_exact(&mut auth_rep).await.expect("auth reply");
        assert_eq!(auth_rep, [0x01, 0x00]);
        let host = format!("{}.x0x", hex::encode(bob.agent_id().as_bytes()));
        let host_b = host.as_bytes();
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host_b.len() as u8];
        req.extend_from_slice(host_b);
        req.extend_from_slice(&9u16.to_be_bytes());
        client.write_all(&req).await.expect("connect");

        tokio::time::timeout(std::time::Duration::from_secs(8), saw_header_rx)
            .await
            .expect("stalled peer must accept the ForwardV2 header")
            .expect("header signal");
        assert_eq!(
            alice_fwd.live.len(),
            1,
            "prepare must register the live stream while the reply is withheld"
        );
        assert_eq!(alice_fwd.diagnostics().active_streams(), 0);

        drop(client);
        let reset = tokio::time::timeout(std::time::Duration::from_secs(2), bob_hold)
            .await
            .expect("peer must observe the reset within 2s of client disconnect")
            .expect("bob task");
        assert!(reset, "withheld ForwardV2 reply must end in a stream reset");
        assert_eq!(
            alice_fwd.live.len(),
            0,
            "dropped prepare must unregister the stream"
        );
        assert_eq!(alice_fwd.diagnostics().active_streams(), 0);
        assert_eq!(alice_fwd.diagnostics().streams_over_cap(), 0);

        let mut again = TcpStream::connect(listen).await.expect("second client");
        again
            .write_all(&[0x05, 0x01, 0x02])
            .await
            .expect("second greet");
        let greeted = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            again.read_exact(&mut method),
        )
        .await;
        assert!(
            matches!(greeted, Ok(Ok(_))),
            "listener must still admit a session after the stalled client left: {greeted:?}"
        );

        service.shutdown_and_wait().await;
        bob_fwd.shutdown();
        alice_fwd.shutdown();
        alice.shutdown().await;
        bob.shutdown().await;
    }
}
