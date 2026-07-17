//! Direct messaging over gossip — envelope types, crypto, dedupe, and ACK
//! protocol. Implements the C design at `docs/design/dm-over-gossip.md`.
//!
//! Raw-QUIC direct-message path (in `src/direct.rs` + `src/network.rs`) is
//! preserved unchanged as the legacy/fallback path during the 0.18 overlap
//! release. This module adds the gossip-based path on top.

use crate::error::{IdentityError, Result};
use crate::groups::kem_envelope::{AgentKemKeypair, KEM_VARIANT};
use crate::identity::{AgentId, MachineId};
use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use saorsa_gossip_types::TopicId;
use saorsa_pqc::api::kem::{MlKem, MlKemPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

/// DM protocol version. Bumped on any backward-incompatible wire change.
pub const DM_PROTOCOL_VERSION: u16 = 1;

/// Maximum envelope bytes (postcard-serialised). Soft cap: receivers drop
/// envelopes over this size without processing or ACKing.
pub const MAX_ENVELOPE_BYTES: usize = 65_536;

/// Maximum user-supplied payload bytes inside a DM.
pub const MAX_PAYLOAD_BYTES: usize = 49_152;

/// Hard cap on an envelope's lifetime. Senders set
/// `expires_at_unix_ms <= created_at_unix_ms + MAX_ENVELOPE_LIFETIME_MS`;
/// receivers enforce the same.
pub const MAX_ENVELOPE_LIFETIME_MS: u64 = 600_000;

/// Tolerance for sender-local clock being ahead of receiver-local clock.
pub const CLOCK_SKEW_TOLERANCE_MS: u64 = 30_000;

/// Domain-separation prefix for the signed envelope bytes.
const DM_SIGN_DOMAIN: &[u8] = b"x0x-dm-v1";

/// Domain-separation prefix for AEAD AD on `DmPayload`.
const DM_AEAD_DOMAIN: &[u8] = b"x0x-dm-payload-v1";

/// Topic-derivation prefix for per-agent inbox.
const DM_INBOX_TOPIC_PREFIX: &[u8] = b"x0x/dm/v1/inbox/";

// ─── Wire format types ─────────────────────────────────────────────────────

/// Advertisement of the DM transport capabilities this agent supports.
///
/// Carried on `AgentCard.dm_capabilities` (additive, optional field — cards
/// predating 0.18 have `None` which senders interpret as "legacy-only").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmCapabilities {
    /// Highest DM protocol version this agent understands on the receive
    /// path. Senders addressing this agent MUST NOT use versions above this.
    pub max_protocol_version: u16,

    /// True if this agent is subscribed to its gossip DM inbox topic AND
    /// has published a KEM public key. False means pre-0.18 / legacy-only
    /// or a daemon that has not yet wired its KEM keypair — sender should
    /// fall back to the raw-QUIC path.
    pub gossip_inbox: bool,

    /// KEM algorithm identifier for payload encryption. For v1 always
    /// `"ML-KEM-768"`.
    pub kem_algorithm: String,

    /// Maximum envelope size (in bytes) this agent will accept.
    pub max_envelope_bytes: usize,

    /// ML-KEM-768 public key bytes. Senders encapsulate the per-message
    /// content key to this key. Empty means "not yet available" — senders
    /// MUST fall back to the raw-QUIC path (or return
    /// `DmError::RecipientKeyUnavailable` when `require_gossip` is set).
    #[serde(default)]
    pub kem_public_key: Vec<u8>,
}

impl DmCapabilities {
    /// Placeholder capability advert for agents that have not yet wired
    /// their KEM keypair. `gossip_inbox` is `false` and `kem_public_key`
    /// is empty — senders will fall back to the raw-QUIC path.
    #[must_use]
    pub fn pending() -> Self {
        Self {
            max_protocol_version: DM_PROTOCOL_VERSION,
            gossip_inbox: false,
            kem_algorithm: "ML-KEM-768".to_string(),
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
            kem_public_key: Vec::new(),
        }
    }

    /// Fully-wired capability advert for a v1 / 0.18+ gossip-DM-capable
    /// agent. `kem_public_key` is the agent's ML-KEM-768 public key bytes.
    #[must_use]
    pub fn v1_gossip_ready(kem_public_key: Vec<u8>) -> Self {
        Self {
            max_protocol_version: DM_PROTOCOL_VERSION,
            gossip_inbox: true,
            kem_algorithm: "ML-KEM-768".to_string(),
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
            kem_public_key,
        }
    }

    /// Return a clone with the given KEM public key and `gossip_inbox=true`.
    #[must_use]
    pub fn with_kem_public_key(mut self, kem_public_key: Vec<u8>) -> Self {
        self.kem_public_key = kem_public_key;
        self.gossip_inbox = true;
        self
    }
}

/// A direct-message envelope, signed by the sender's ML-DSA-65 agent key
/// and (for `Payload` variants) encrypted to the recipient's ML-KEM-768
/// public key.
///
/// See `docs/design/dm-over-gossip.md` for the full spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmEnvelope {
    /// Wire-format protocol version. Receivers reject envelopes whose
    /// `protocol_version > self.max_protocol_version`.
    pub protocol_version: u16,

    /// 128-bit per-message id. Random on first send; **reused on retries
    /// of the same logical message** to enable recipient dedupe.
    pub request_id: [u8; 16],

    /// Sender's AgentId (32 bytes, SHA-256 of ML-DSA-65 pubkey).
    pub sender_agent_id: [u8; 32],

    /// Sender's MachineId. Populates trust-policy evaluation.
    pub sender_machine_id: [u8; 32],

    /// Recipient's AgentId. Receivers drop envelopes addressed to a
    /// different agent_id (defence-in-depth; topic filtering normally
    /// prevents this).
    pub recipient_agent_id: [u8; 32],

    /// Sender-local unix-ms timestamp at envelope creation.
    pub created_at_unix_ms: u64,

    /// Envelope expiry. Receivers drop envelopes past this time.
    pub expires_at_unix_ms: u64,

    /// Kind — Payload or Ack.
    pub body: DmBody,

    /// ML-DSA-65 signature over the domain-separated envelope bytes
    /// computed via `build_signed_bytes()`.
    pub signature: Vec<u8>,

    /// Fresh origin-machine attestation (issue #213). Signed by the
    /// sender's **machine** ML-DSA-65 key; proves the claimed
    /// `sender_machine_id` authorized THIS DM. Additive trailing field:
    /// old receivers skip it (postcard ignores trailing bytes), new
    /// receivers decode `None` for pre-#213 peers and fall back to the
    /// retained-binding check. See `docs/adr/0021-dm-origin-machine-attestation.md`.
    ///
    /// Deliberately OUTSIDE the agent signature scope (`signed_bytes` is
    /// unchanged) so mixed-version interop keeps verifying both ways.
    #[serde(default, deserialize_with = "deserialize_origin_attestation")]
    pub origin_attestation: Option<DmOriginAttestation>,
}

/// Envelope body — either a payload DM or an acknowledgement of a prior one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DmBody {
    /// Encrypted user payload.
    Payload(DmPayload),
    /// Recipient-side acknowledgement of a prior `Payload`.
    Ack(DmAckBody),
}

/// Ciphertext portion of a DM payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmPayload {
    /// ML-KEM-768 encapsulation of the content key. Opaque to observers
    /// without the recipient's ML-KEM secret key.
    pub kem_ciphertext: Vec<u8>,

    /// Per-message content-cipher nonce.
    pub body_nonce: [u8; 12],

    /// ChaCha20-Poly1305 AEAD of the inner `DmPlaintext`. AAD is the
    /// domain-separated envelope-metadata hash; see `build_aead_aad`.
    pub body_ciphertext: Vec<u8>,
}

/// Plaintext inside `DmPayload::body_ciphertext`. Binds the envelope
/// metadata (request_id) so the AEAD cannot be replayed with swapped
/// metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmPlaintext {
    /// Repeated here (also in envelope) to bind inner payload to outer
    /// metadata.
    pub request_id: [u8; 16],

    /// The user's payload bytes.
    pub payload: Vec<u8>,

    /// Optional content-type hint. Free-form, e.g. `"application/json"`.
    pub content_type: Option<String>,
}

/// Body of an Ack envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmAckBody {
    /// `request_id` of the `DmPayload` envelope being ACKed.
    pub acks_request_id: [u8; 16],

    /// Outcome as observed by the recipient's DM pipeline.
    pub outcome: DmAckOutcome,
}

/// Per-design-doc ACK semantics — "recipient agent accepted" or policy
/// rejection. Never implies durable storage or user read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmAckOutcome {
    /// Envelope decrypted, signature verified, trust-policy passed, and
    /// enqueued to the recipient's DM handler / inbox.
    Accepted,
    /// Envelope was valid but the recipient's trust policy rejected it.
    /// The sender learns *why* they were rejected via `reason`. Deployments
    /// that prefer silent rejection can set `trust.silent_reject = true`
    /// and skip emitting this ACK entirely.
    RejectedByPolicy { reason: String },
}

// ─── Origin-machine attestation (issue #213) ──────────────────────────────

/// Domain separator for DM origin-machine attestation signatures.
///
/// Mirrors `FORWARD_V2_ATTESTATION_DOMAIN` (#204): a distinct, versioned
/// prefix so an attestation can never be reinterpreted as any other signed
/// object in the crate, and a future layout change bumps the suffix so old
/// attestations fail verification rather than silently re-binding.
const DM_ORIGIN_ATTESTATION_DOMAIN: &[u8] = b"x0x-dm-origin-attestation.v1";

/// Current [`DmOriginAttestation`] format version.
pub const DM_ORIGIN_ATTESTATION_VERSION: u16 = 1;

/// Fresh, per-DM proof that the claimed origin machine authorized this
/// envelope (issue #213).
///
/// The sender's **machine** ML-DSA-65 key signs a struct mirroring the
/// envelope's security-relevant fields. The machine public key travels
/// with the attestation and is self-certifying —
/// `MachineId::from_public_key(key)` MUST equal `sender_machine_id` — so
/// verification needs ZERO prior discovery-cache state: no retained
/// binding, no announcement, no reachability data.
///
/// See `docs/adr/0021-dm-origin-machine-attestation.md` for the full
/// design, including the portable-move, replay, and downgrade policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmOriginAttestation {
    /// Attestation format version. Receivers fail closed on unknown
    /// versions (a present-but-unverifiable attestation is never skipped).
    pub attestation_version: u16,
    /// DM protocol version this attestation was minted for — mirrors the
    /// envelope field and binds the attestation to the protocol generation.
    pub protocol_version: u16,
    /// Sender's AgentId — MUST equal the envelope's.
    pub sender_agent_id: [u8; 32],
    /// Claimed origin machine — MUST equal the envelope's
    /// `sender_machine_id` AND `MachineId::from_public_key(machine_public_key)`.
    pub sender_machine_id: [u8; 32],
    /// Sender machine's ML-DSA-65 public key. Self-certifying via the hash
    /// binding to `sender_machine_id`; carried so verification is
    /// cache-independent (offline / cold-restart receivers).
    pub machine_public_key: Vec<u8>,
    /// Recipient's AgentId — replay scope: an attestation captured from a
    /// DM to Alice cannot be retargeted to Bob.
    pub recipient_agent_id: [u8; 32],
    /// The DM's request id — binds the attestation to exactly one logical
    /// DM (retries of the same DM reuse `request_id`, so one attestation
    /// covers all retry attempts).
    pub request_id: [u8; 16],
    /// Freshness window start — mirrors `DmEnvelope::created_at_unix_ms`.
    pub created_at_unix_ms: u64,
    /// Freshness window end — mirrors `DmEnvelope::expires_at_unix_ms`.
    /// The receiver's timestamp-window check on the envelope covers this
    /// attestation because the fields MUST match exactly.
    pub expires_at_unix_ms: u64,
    /// ML-DSA-65 signature over [`DmOriginAttestation::signed_bytes`],
    /// produced by the machine secret key.
    pub signature: Vec<u8>,
}

/// Why an origin-machine attestation failed verification.
///
/// Every variant is a **hard drop** at the receiver (no fallback to the
/// claimed machine or the retained binding): a present-but-invalid
/// attestation is an attack or corruption signal, never a legacy peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OriginAttestationError {
    /// `attestation_version` is not one this build understands.
    #[error("unsupported attestation version {0}")]
    UnsupportedVersion(u16),
    /// A mirrored field differs from the envelope (agent, machine,
    /// recipient, request id, timestamps, or protocol version).
    #[error("attestation fields do not match the envelope")]
    EnvelopeMismatch,
    /// `machine_public_key` does not parse as ML-DSA-65.
    #[error("malformed machine public key")]
    MalformedPublicKey,
    /// `machine_public_key` does not hash to `sender_machine_id`.
    #[error("machine public key does not hash to sender_machine_id")]
    KeyBindingMismatch,
    /// The signature is empty or fails ML-DSA-65 verification.
    #[error("machine attestation signature invalid")]
    SignatureInvalid,
}

impl DmOriginAttestation {
    /// Build an unsigned attestation mirroring `envelope`'s fields, with
    /// the given machine public key. Call [`Self::sign`] next.
    #[must_use]
    pub fn for_envelope(envelope: &DmEnvelope, machine_public_key: Vec<u8>) -> Self {
        Self {
            attestation_version: DM_ORIGIN_ATTESTATION_VERSION,
            protocol_version: envelope.protocol_version,
            sender_agent_id: envelope.sender_agent_id,
            sender_machine_id: envelope.sender_machine_id,
            machine_public_key,
            recipient_agent_id: envelope.recipient_agent_id,
            request_id: envelope.request_id,
            created_at_unix_ms: envelope.created_at_unix_ms,
            expires_at_unix_ms: envelope.expires_at_unix_ms,
            signature: Vec::new(),
        }
    }

    /// Canonical signed bytes: domain-separated, fixed-layout encoding of
    /// every field except `signature`. Both ends MUST agree byte-for-byte.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            DM_ORIGIN_ATTESTATION_DOMAIN.len() + 2 + 2 + 16 + 32 * 3 + 4
                + self.machine_public_key.len() + 8 * 2,
        );
        out.extend_from_slice(DM_ORIGIN_ATTESTATION_DOMAIN);
        out.extend_from_slice(&self.attestation_version.to_be_bytes());
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.sender_agent_id);
        out.extend_from_slice(&self.sender_machine_id);
        out.extend_from_slice(&(self.machine_public_key.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.machine_public_key);
        out.extend_from_slice(&self.recipient_agent_id);
        out.extend_from_slice(&self.created_at_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        out
    }

    /// Sign with the sender's machine keypair. The keypair MUST own
    /// `sender_machine_id`; a mismatch produces an attestation receivers
    /// reject with [`OriginAttestationError::KeyBindingMismatch`].
    ///
    /// # Errors
    /// Returns [`DmError::EnvelopeConstruction`] if ML-DSA-65 signing fails.
    pub fn sign(&mut self, machine_keypair: &crate::identity::MachineKeypair) -> std::result::Result<(), DmError> {
        let sig = sign_with_ml_dsa(machine_keypair.secret_key(), &self.signed_bytes())
            .map_err(|e| DmError::EnvelopeConstruction(format!("origin attestation sign: {e:?}")))?;
        self.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Verify the attestation against the envelope it rides in.
    ///
    /// Self-contained: parses the carried machine key, checks the hash
    /// binding to `sender_machine_id`, checks every mirrored field against
    /// `envelope`, then verifies the ML-DSA-65 signature. Returns the
    /// attested [`MachineId`] on success.
    ///
    /// # Errors
    /// One of [`OriginAttestationError`]; every failure is a hard drop at
    /// the receiver.
    pub fn verify(&self, envelope: &DmEnvelope) -> std::result::Result<MachineId, OriginAttestationError> {
        if self.attestation_version != DM_ORIGIN_ATTESTATION_VERSION {
            return Err(OriginAttestationError::UnsupportedVersion(
                self.attestation_version,
            ));
        }
        if !self.matches_envelope(envelope) {
            return Err(OriginAttestationError::EnvelopeMismatch);
        }
        let pubkey = MlDsaPublicKey::from_bytes(&self.machine_public_key)
            .map_err(|_| OriginAttestationError::MalformedPublicKey)?;
        // Hash binding: the carried key MUST own the claimed machine id —
        // the same `from_public_key == claimed` binding used by ForwardV2
        // (#204) and CRDT provenance.
        let derived = MachineId::from_public_key(&pubkey);
        if derived.as_bytes() != &self.sender_machine_id {
            return Err(OriginAttestationError::KeyBindingMismatch);
        }
        if self.signature.is_empty() {
            return Err(OriginAttestationError::SignatureInvalid);
        }
        let sig = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|_| OriginAttestationError::SignatureInvalid)?;
        verify_with_ml_dsa(&pubkey, &self.signed_bytes(), &sig)
            .map_err(|_| OriginAttestationError::SignatureInvalid)?;
        Ok(derived)
    }

    /// True when every mirrored field equals the envelope's.
    #[must_use]
    pub fn matches_envelope(&self, envelope: &DmEnvelope) -> bool {
        self.protocol_version == envelope.protocol_version
            && self.sender_agent_id == envelope.sender_agent_id
            && self.sender_machine_id == envelope.sender_machine_id
            && self.recipient_agent_id == envelope.recipient_agent_id
            && self.request_id == envelope.request_id
            && self.created_at_unix_ms == envelope.created_at_unix_ms
            && self.expires_at_unix_ms == envelope.expires_at_unix_ms
    }
}

/// Tolerant deserializer for the trailing attestation field. Old envelopes
/// end after `signature`; postcard then hits EOF reading the option tag,
/// which we recover as `None` (legacy peer → retained-binding fallback).
/// Mirrors the `deserialize_attestations` pattern in `crdt/task_item.rs`.
fn deserialize_origin_attestation<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<DmOriginAttestation>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<DmOriginAttestation>::deserialize(deserializer).unwrap_or(None))
}

// ─── Error model ───────────────────────────────────────────────────────────

/// Errors surfaced by the gossip DM path. See design doc §"Error model".
#[derive(Debug, thiserror::Error)]
pub enum DmError {
    /// Recipient's AgentCard / capability advert is not known locally, or
    /// their KEM public key is missing. Caller should retry after a
    /// capability-cache refresh.
    #[error("recipient key material unavailable: {0}")]
    RecipientKeyUnavailable(String),

    /// No application-layer ACK received within the retry budget. The DM
    /// MAY or may not have been delivered; the sender cannot distinguish.
    /// Safe to retry (recipient dedupes on `request_id`).
    #[error("timed out after {retries} retries over {elapsed:?}")]
    Timeout { retries: u8, elapsed: Duration },

    /// Presence/identity data says the peer is probably offline before we
    /// start a transport attempt.
    #[error("peer likely offline: phi={phi}, last_seen_ms_ago={last_seen_ms_ago:?}")]
    PeerLikelyOffline {
        /// Phi-accrual suspicion score.
        phi: f64,
        /// Time since the last positive signal, when known.
        last_seen_ms_ago: Option<u64>,
    },

    /// The transport lifecycle bus says the peer's active connection is
    /// closing/closed/superseded, so waiting for the full timeout would be a
    /// false hang.
    #[error("peer disconnected: {reason}")]
    PeerDisconnected {
        /// Lifecycle or health reason.
        reason: String,
    },

    /// The recipient's receive pipeline is live but congested. Safe to retry
    /// with backoff or use a store-and-forward fallback; do not reconnect.
    #[error("receiver backpressured: {reason}")]
    ReceiverBackpressured {
        /// Transport-provided backpressure detail.
        reason: String,
    },

    /// Recipient's agent accepted the envelope but their trust policy
    /// rejected the sender.
    #[error("recipient rejected: {reason}")]
    RecipientRejected { reason: String },

    /// Local gossip publish failed — typically because the mesh is not
    /// joined yet or the inbox topic has no active peers. Distinct from
    /// `Timeout`, which is "remote didn't respond".
    #[error("local gossip publish failed: {0}")]
    LocalGossipUnavailable(String),

    /// Sender-side failure constructing the envelope (signing, KEM
    /// encapsulation, or AEAD encryption).
    #[error("envelope construction failed: {0}")]
    EnvelopeConstruction(String),

    /// User payload exceeds the direct-message transport's limit.
    #[error("payload too large: {len} bytes exceeds max {max}")]
    PayloadTooLarge {
        /// Actual supplied payload length.
        len: usize,
        /// Maximum supported payload length.
        max: usize,
    },

    /// The local network stack is not running or has no usable connectivity.
    #[error("no usable connectivity: {0}")]
    NoConnectivity(String),

    /// Catch-all for gossip transport errors not classified above.
    #[error("gossip transport error: {0}")]
    PublishFailed(String),

    /// X0X-0070b: the direct path failed and `PeerRelay::needs_relay`
    /// returned true, but `PeerRelay::select_relay` had no candidate
    /// to pick (empty or only self / dst). The caller surfaces the
    /// original direct error; this variant is for internal
    /// `try_relay_fallback` bookkeeping.
    #[error("no relay candidate available")]
    NoRelayCandidate,

    /// X0X-0070b: `PeerRelay::build_relayed_dm` failed, typically a
    /// signing or domain-separated serialization error. The caller
    /// surfaces the original direct error; this variant is for
    /// internal `try_relay_fallback` bookkeeping.
    #[error("relay envelope build failed: {0}")]
    RelayBuildFailed(String),
}

impl From<IdentityError> for DmError {
    fn from(value: IdentityError) -> Self {
        Self::EnvelopeConstruction(value.to_string())
    }
}

// ─── Receipt and caller-configurable send behaviour ────────────────────────

/// Result of a successful `send_direct`. `path` lets callers observe which
/// transport actually delivered.
#[derive(Debug, Clone)]
pub struct DmReceipt {
    pub request_id: [u8; 16],
    pub accepted_at: Instant,
    pub retries_used: u8,
    pub path: DmPath,
}

/// Which transport delivered the DM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmPath {
    /// Local loopback path for messages addressed to this same agent.
    Loopback,
    /// New gossip-inbox path (C).
    GossipInbox,
    /// Legacy raw-QUIC direct-stream path. Still functional during the
    /// 0.18 overlap release.
    RawQuic,
    /// Raw-QUIC path with ant-quic receive-pipeline ACK confirmation.
    RawQuicAcked,
    /// X0X-0070b: delivered via the application-level peer relay
    /// (`PeerRelay`) after the direct paths failed `fail_threshold`
    /// times within `fail_window`. `via` is the relay candidate that
    /// forwarded the inner `DmEnvelope`.
    Relayed {
        /// The relay candidate that forwarded the inner envelope.
        via: AgentId,
    },
}

/// Fallback RTT used when no per-peer RTT sample has reached the local cache.
pub const DM_TIMEOUT_FALLBACK_RTT_MS: u32 = 250;

/// Minimum per-attempt DM timeout.
pub const DM_TIMEOUT_MIN_MS: u64 = 500;

/// Maximum per-attempt DM timeout.
pub const DM_TIMEOUT_MAX_MS: u64 = 30_000;

/// RTT multiplier used for adaptive per-attempt DM timeouts.
pub const DM_TIMEOUT_RTT_MULTIPLIER: u64 = 16;

/// Compute an adaptive per-attempt DM timeout from a smoothed peer RTT.
///
/// Unknown or zero RTT falls back to a conservative network-wide P95 estimate.
/// The result is clamped so fast peers fail quickly while slow or unhealthy
/// peers cannot pin an API request forever.
#[must_use]
pub fn dm_attempt_timeout(peer_rtt_ms: Option<u32>) -> Duration {
    let base_ms = peer_rtt_ms
        .filter(|rtt| *rtt > 0)
        .unwrap_or(DM_TIMEOUT_FALLBACK_RTT_MS) as u64;
    let timeout_ms = base_ms
        .saturating_mul(DM_TIMEOUT_RTT_MULTIPLIER)
        .clamp(DM_TIMEOUT_MIN_MS, DM_TIMEOUT_MAX_MS);
    Duration::from_millis(timeout_ms)
}

/// Per-call configuration for `send_direct_with_config`.
#[derive(Debug, Clone)]
pub struct DmSendConfig {
    /// Timeout for each individual attempt.
    pub timeout_per_attempt: Duration,
    /// Retries after the first attempt. Total attempts = 1 + max_retries.
    pub max_retries: u8,
    /// Backoff schedule between attempts.
    pub backoff: BackoffPolicy,
    /// If true, never fall back to the raw-QUIC path even when the
    /// recipient's capability advert is missing. Used to enforce the
    /// gossip path in test harnesses.
    pub require_gossip: bool,
    /// If true and `require_gossip` is false, first try the legacy/raw
    /// QUIC direct-stream path when a live direct connection already exists.
    /// If that fast path is unavailable, fall back to the normal
    /// capability-aware send logic.
    pub prefer_raw_quic_if_connected: bool,
    /// When set, raw-QUIC sends use ant-quic's receive-pipeline ACK surface
    /// and only return success after the remote reader task has drained the
    /// bytes. `None` keeps the old fire-and-forget raw path.
    pub raw_quic_receive_ack_timeout: Option<Duration>,
    /// If true, a preferred raw-QUIC failure is terminal and the sender will
    /// not silently fall back to gossip-inbox even when a capability advert is
    /// present. Use this for higher-volume protocols (for example file
    /// transfer) whose own back-pressure/ACK logic is tuned for raw QUIC.
    pub stop_fallback_on_raw_error: bool,
    /// If true, gossip-inbox sends wait for the recipient's application-layer
    /// ACK before returning success. If false, a successful gossip publish is
    /// reported as accepted-for-delivery and any later ACK is ignored.
    pub require_gossip_ack: bool,
    /// X0X-0041: bounded grace window (ms) the DM path holds when ant-quic has
    /// just observed a `Replaced` event but the new `Established` has not yet
    /// fired. Mirrors iroh-gossip #43 "always prefer newest connection" — when
    /// a supersede is in flight we wait briefly for the new generation rather
    /// than declaring the peer disconnected. Default 250ms. Setting to 0
    /// disables the grace and reverts to legacy behaviour.
    pub prefer_newest_grace_ms: u64,
}

impl Default for DmSendConfig {
    fn default() -> Self {
        // Adaptive default: unknown peers fall back to 250 ms × 16 = 4 s.
        // `Agent::send_direct_with_config` replaces this fallback with the
        // peer-specific bootstrap-cache EWMA RTT when available. The raw-QUIC
        // receive-pipeline ACK is opt-in: leaving it disabled preserves the
        // legacy fire-and-forget raw fallback and lets capability-aware sends
        // prefer the gossip-inbox path's application-level ACK.
        Self {
            timeout_per_attempt: dm_attempt_timeout(None),
            max_retries: 1,
            backoff: BackoffPolicy::ExponentialFromTimeout { factor: 2 },
            require_gossip: false,
            prefer_raw_quic_if_connected: false,
            raw_quic_receive_ack_timeout: None,
            stop_fallback_on_raw_error: false,
            require_gossip_ack: true,
            // X0X-0041: 250ms is the soak-tested grace from iroh-gossip #43.
            prefer_newest_grace_ms: DEFAULT_PREFER_NEWEST_GRACE_MS,
        }
    }
}

/// X0X-0041: default prefer-newest-connection grace window.
pub const DEFAULT_PREFER_NEWEST_GRACE_MS: u64 = 250;

/// Backoff schedule between send attempts.
#[derive(Debug, Clone, Copy)]
pub enum BackoffPolicy {
    /// Constant delay between retries (diagnostic use).
    Fixed(Duration),
    /// Double the per-attempt timeout each retry: 10 s, 20 s, 40 s, ...
    /// `factor` controls the multiplier.
    ExponentialFromTimeout { factor: u32 },
}

impl BackoffPolicy {
    /// Compute the delay before the `attempt_idx`-th retry (0-indexed —
    /// attempt_idx=0 is the first retry, attempt_idx=1 is the second).
    #[must_use]
    pub fn delay(&self, base_timeout: Duration, attempt_idx: u8) -> Duration {
        match self {
            Self::Fixed(d) => *d,
            Self::ExponentialFromTimeout { factor } => {
                let mut delay = base_timeout;
                for _ in 0..attempt_idx {
                    delay = delay.saturating_mul(*factor);
                }
                delay
            }
        }
    }
}

// ─── Topic derivation ─────────────────────────────────────────────────────

/// The gossip topic on which `agent_id` receives DM envelopes + ACKs.
///
/// Derivation is a domain-separated BLAKE3 hash of the agent id:
/// `blake3(b"x0x/dm/v1/inbox/" || agent_id.as_bytes())`.
#[must_use]
pub fn dm_inbox_topic(agent_id: &AgentId) -> TopicId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DM_INBOX_TOPIC_PREFIX);
    hasher.update(agent_id.as_bytes());
    TopicId::new(hasher.finalize().into())
}

// ─── Dedupe key and recent-delivery cache ──────────────────────────────────

/// Dedupe key: uniquely identifies a logical DM across retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DedupeKey {
    pub sender_agent_id: [u8; 32],
    pub request_id: [u8; 16],
}

impl DedupeKey {
    #[must_use]
    pub fn new(sender_agent_id: [u8; 32], request_id: [u8; 16]) -> Self {
        Self {
            sender_agent_id,
            request_id,
        }
    }
}

/// Bounded, TTL-aware dedupe cache.
///
/// Receivers consult this on every inbound envelope. A cache hit short-
/// circuits all expensive work (signature, decrypt, policy, handler);
/// the sender is re-ACKed with the cached outcome so retries terminate.
pub struct RecentDeliveryCache {
    inner: Mutex<RecentDeliveryCacheInner>,
}

struct RecentDeliveryCacheInner {
    /// Insertion-ordered LRU (VecDeque + HashMap combo — good enough at
    /// this size; no external crate needed).
    order: VecDeque<DedupeKey>,
    entries: HashMap<DedupeKey, CachedOutcome>,
    ttl: Duration,
    max_size: usize,
}

/// A cached per-DM outcome.
#[derive(Debug, Clone)]
pub struct CachedOutcome {
    pub outcome: DmAckOutcome,
    pub first_seen: Instant,
}

impl RecentDeliveryCache {
    /// Construct with the recommended defaults (630 s TTL, 10 000 entries).
    ///
    /// The TTL MUST cover the full exact-replay window: an envelope stays
    /// valid for `MAX_ENVELOPE_LIFETIME_MS` (600 s) plus up to
    /// `CLOCK_SKEW_TOLERANCE_MS` (30 s) of accepted sender-ahead skew, and
    /// the dedupe entry is the ONLY thing absorbing an identical
    /// re-delivery while the timestamp window still passes (a shorter TTL
    /// re-opens a replay hole in the 300–600 s band, issue #213 review F1).
    ///
    /// Capacity implication: entries now live ~2.1× longer, so the 10 000-
    /// entry cap holds proportionally more live traffic — bounded at roughly
    /// a few MiB even with worst-case `RejectedByPolicy` reason strings,
    /// which is acceptable for the replay-safety invariant.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(
            Duration::from_millis(MAX_ENVELOPE_LIFETIME_MS + CLOCK_SKEW_TOLERANCE_MS),
            10_000,
        )
    }

    /// Custom cache bounds.
    #[must_use]
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            inner: Mutex::new(RecentDeliveryCacheInner {
                order: VecDeque::new(),
                entries: HashMap::new(),
                ttl,
                max_size,
            }),
        }
    }

    /// Look up a key. Returns `Some(CachedOutcome)` on a non-expired hit,
    /// `None` on miss or expired entry.
    pub fn lookup(&self, key: &DedupeKey) -> Option<CachedOutcome> {
        let Ok(mut inner) = self.inner.lock() else {
            return None;
        };
        let now = Instant::now();
        let entry = inner.entries.get(key)?.clone();
        if now.duration_since(entry.first_seen) > inner.ttl {
            // Expired — evict.
            inner.entries.remove(key);
            if let Some(pos) = inner.order.iter().position(|k| k == key) {
                inner.order.remove(pos);
            }
            return None;
        }
        Some(entry)
    }

    /// Insert an outcome, returning `true` iff this call was the one that
    /// inserted the key (i.e. it *claimed* the dedupe slot). If the key is
    /// already present, the existing `first_seen` is preserved (so TTL doesn't
    /// restart on re-delivery) and `false` is returned.
    ///
    /// The boolean makes this usable as an atomic claim: a caller can insert a
    /// placeholder outcome and only proceed with delivery when it observes the
    /// `true` return, so two tasks racing the same envelope (e.g. the primary
    /// per-recipient inbox and the legacy bus delivering the same DM) cannot
    /// both deliver it to the application. On lock poisoning we return `true`
    /// (proceed) so a poisoned cache degrades to possible double-delivery
    /// rather than silent message loss.
    pub fn insert(&self, key: DedupeKey, outcome: DmAckOutcome) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return true;
        };
        if inner.entries.contains_key(&key) {
            return false;
        }
        inner.entries.insert(
            key,
            CachedOutcome {
                outcome,
                first_seen: Instant::now(),
            },
        );
        inner.order.push_back(key);

        // LRU trim.
        while inner.entries.len() > inner.max_size {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.entries.remove(&oldest);
        }
        true
    }

    /// Current cache size (diagnostic).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|g| g.entries.len())
            .unwrap_or_default()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── Timestamp window validation ───────────────────────────────────────────

/// Validate an envelope's timestamp fields against `now_unix_ms`.
///
/// Per design doc:
/// 1. `created_at_unix_ms <= now + CLOCK_SKEW_TOLERANCE_MS` (reject
///    far-future envelopes beyond 30s skew)
/// 2. `now < expires_at_unix_ms`
/// 3. `expires_at_unix_ms <= created_at_unix_ms + MAX_ENVELOPE_LIFETIME_MS`
pub fn validate_timestamp_window(
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    now_unix_ms: u64,
) -> std::result::Result<(), TimestampValidationError> {
    if created_at_unix_ms > now_unix_ms.saturating_add(CLOCK_SKEW_TOLERANCE_MS) {
        return Err(TimestampValidationError::FromFuture);
    }
    if now_unix_ms >= expires_at_unix_ms {
        return Err(TimestampValidationError::Expired);
    }
    if expires_at_unix_ms > created_at_unix_ms.saturating_add(MAX_ENVELOPE_LIFETIME_MS) {
        return Err(TimestampValidationError::LifetimeExceedsMax);
    }
    Ok(())
}

/// Non-panicking variants of timestamp-window failures (for logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampValidationError {
    /// `created_at` is beyond the allowed skew tolerance ahead of now.
    FromFuture,
    /// `now >= expires_at`.
    Expired,
    /// `expires_at - created_at` exceeds the protocol cap.
    LifetimeExceedsMax,
}

impl std::fmt::Display for TimestampValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FromFuture => write!(f, "envelope created_at is too far in the future"),
            Self::Expired => write!(f, "envelope has expired"),
            Self::LifetimeExceedsMax => write!(
                f,
                "envelope lifetime exceeds protocol max ({} ms)",
                MAX_ENVELOPE_LIFETIME_MS
            ),
        }
    }
}

// ─── Crypto helpers ────────────────────────────────────────────────────────

/// Build the domain-separated bytes that the sender signs.
///
/// Format: `DM_SIGN_DOMAIN || protocol_version.to_be_bytes() || request_id
/// || sender_agent_id || sender_machine_id || recipient_agent_id
/// || created_at_unix_ms.to_be_bytes() || expires_at_unix_ms.to_be_bytes()
/// || postcard(body)`.
#[allow(clippy::too_many_arguments)]
fn build_signed_bytes(
    protocol_version: u16,
    request_id: &[u8; 16],
    sender_agent_id: &[u8; 32],
    sender_machine_id: &[u8; 32],
    recipient_agent_id: &[u8; 32],
    created_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    body: &DmBody,
) -> Result<Vec<u8>> {
    let body_bytes = postcard::to_stdvec(body)
        .map_err(|e| IdentityError::Serialization(format!("DM body postcard: {e}")))?;
    let mut out =
        Vec::with_capacity(DM_SIGN_DOMAIN.len() + 2 + 16 + 32 * 3 + 8 * 2 + body_bytes.len());
    out.extend_from_slice(DM_SIGN_DOMAIN);
    out.extend_from_slice(&protocol_version.to_be_bytes());
    out.extend_from_slice(request_id);
    out.extend_from_slice(sender_agent_id);
    out.extend_from_slice(sender_machine_id);
    out.extend_from_slice(recipient_agent_id);
    out.extend_from_slice(&created_at_unix_ms.to_be_bytes());
    out.extend_from_slice(&expires_at_unix_ms.to_be_bytes());
    out.extend_from_slice(&body_bytes);
    Ok(out)
}

/// Build the AEAD associated-data for a `DmPayload`. Binds ciphertext to
/// envelope metadata.
fn build_aead_aad(
    request_id: &[u8; 16],
    sender_agent_id: &[u8; 32],
    recipient_agent_id: &[u8; 32],
    created_at_unix_ms: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DM_AEAD_DOMAIN.len() + 16 + 32 * 2 + 8);
    aad.extend_from_slice(DM_AEAD_DOMAIN);
    aad.extend_from_slice(request_id);
    aad.extend_from_slice(sender_agent_id);
    aad.extend_from_slice(recipient_agent_id);
    aad.extend_from_slice(&created_at_unix_ms.to_be_bytes());
    aad
}

/// Encrypt an inner `DmPlaintext` into a `DmPayload` using the recipient's
/// ML-KEM-768 public key.
pub fn encrypt_payload(
    recipient_kem_pubkey_bytes: &[u8],
    plaintext: &DmPlaintext,
    aad: &[u8],
) -> Result<DmPayload> {
    let plaintext_bytes = postcard::to_stdvec(plaintext)
        .map_err(|e| IdentityError::Serialization(format!("DM plaintext postcard: {e}")))?;

    let pk = MlKemPublicKey::from_bytes(KEM_VARIANT, recipient_kem_pubkey_bytes)
        .map_err(|e| IdentityError::Serialization(format!("recipient KEM pubkey decode: {e}")))?;
    let kem = MlKem::new(KEM_VARIANT);
    let (shared, kem_ct) = kem
        .encapsulate(&pk)
        .map_err(|e| IdentityError::Serialization(format!("KEM encap: {e}")))?;

    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(shared.as_bytes())
        .map_err(|e| IdentityError::Serialization(format!("AEAD init (encrypt): {e}")))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext_bytes,
                aad,
            },
        )
        .map_err(|e| IdentityError::Serialization(format!("AEAD encrypt: {e}")))?;

    Ok(DmPayload {
        kem_ciphertext: kem_ct.to_bytes(),
        body_nonce: nonce,
        body_ciphertext: ct,
    })
}

/// Decrypt a `DmPayload` using the receiver's ML-KEM-768 secret key.
pub fn decrypt_payload(
    receiver_kem_keypair: &AgentKemKeypair,
    payload: &DmPayload,
    aad: &[u8],
) -> Result<DmPlaintext> {
    let shared = receiver_kem_keypair.decapsulate(&payload.kem_ciphertext)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&shared)
        .map_err(|e| IdentityError::Serialization(format!("AEAD init (decrypt): {e}")))?;
    let plaintext_bytes = cipher
        .decrypt(
            Nonce::from_slice(&payload.body_nonce),
            Payload {
                msg: &payload.body_ciphertext,
                aad,
            },
        )
        .map_err(|e| IdentityError::Serialization(format!("AEAD decrypt: {e}")))?;

    let plaintext: DmPlaintext = postcard::from_bytes(&plaintext_bytes)
        .map_err(|e| IdentityError::Serialization(format!("DM plaintext postcard decode: {e}")))?;
    Ok(plaintext)
}

// ─── Envelope helpers ──────────────────────────────────────────────────────

impl DmEnvelope {
    /// Domain-separated bytes to sign. Only depends on the fields covered
    /// by the signature — `signature` itself is excluded.
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        build_signed_bytes(
            self.protocol_version,
            &self.request_id,
            &self.sender_agent_id,
            &self.sender_machine_id,
            &self.recipient_agent_id,
            self.created_at_unix_ms,
            self.expires_at_unix_ms,
            &self.body,
        )
    }

    /// AAD used for the inner-payload AEAD. Only meaningful for
    /// `DmBody::Payload`; callers may still build it ahead of time for
    /// general use.
    #[must_use]
    pub fn aead_aad(&self) -> Vec<u8> {
        build_aead_aad(
            &self.request_id,
            &self.sender_agent_id,
            &self.recipient_agent_id,
            self.created_at_unix_ms,
        )
    }

    /// Serialize envelope with postcard for over-the-wire transport.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_stdvec(self)
            .map_err(|e| IdentityError::Serialization(format!("DM envelope postcard: {e}")))
    }

    /// Deserialize envelope from the wire. Enforces the envelope-size cap.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(IdentityError::Serialization(format!(
                "DM envelope exceeds MAX_ENVELOPE_BYTES ({} > {})",
                bytes.len(),
                MAX_ENVELOPE_BYTES
            )));
        }
        postcard::from_bytes(bytes)
            .map_err(|e| IdentityError::Serialization(format!("DM envelope decode: {e}")))
    }

    /// Dedupe key for this envelope.
    #[must_use]
    pub fn dedupe_key(&self) -> DedupeKey {
        DedupeKey::new(self.sender_agent_id, self.request_id)
    }

    /// Verify the origin-machine attestation (issue #213).
    ///
    /// - `Ok(None)` — no attestation (legacy pre-#213 peer): the caller
    ///   falls back to the #184 retained-binding check.
    /// - `Ok(Some(machine))` — fresh machine-key proof for this DM;
    ///   supersedes any retained binding.
    /// - `Err(_)` — present but invalid: hard drop, never fall back.
    ///
    /// Freshness is inherited from the envelope's timestamp-window check
    /// (the attestation mirrors `created_at`/`expires_at` exactly), so the
    /// caller MUST run `validate_timestamp_window` first — the inbox
    /// pipeline already does.
    pub fn verify_origin_attestation(
        &self,
    ) -> std::result::Result<Option<MachineId>, OriginAttestationError> {
        self.origin_attestation
            .as_ref()
            .map(|attestation| attestation.verify(self))
            .transpose()
    }
}

// ─── Envelope builder ──────────────────────────────────────────────────────

/// Sender-side helper that bundles the sequence of crypto operations for
/// constructing a fresh `DmEnvelope::Payload` — KEM encapsulation, AEAD
/// encryption, domain-separated signing.
///
/// Typed helpers that accept the required-at-call-site bytes. Integration
/// with `Agent` identity types is done by callers.
pub struct EnvelopeBuilder;

impl EnvelopeBuilder {
    /// Build an unsigned `DmBody::Payload` variant given the recipient's
    /// KEM public key and the user's plaintext payload.
    ///
    /// `created_at_unix_ms` binds the AEAD AD; the caller must pass the
    /// same value into the envelope's metadata.
    pub fn build_payload_body(
        request_id: &[u8; 16],
        sender_agent_id: &[u8; 32],
        recipient_agent_id: &[u8; 32],
        created_at_unix_ms: u64,
        payload: Vec<u8>,
        content_type: Option<String>,
        recipient_kem_pubkey_bytes: &[u8],
    ) -> Result<DmBody> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(IdentityError::Serialization(format!(
                "DM payload exceeds MAX_PAYLOAD_BYTES ({} > {})",
                payload.len(),
                MAX_PAYLOAD_BYTES
            )));
        }
        let plaintext = DmPlaintext {
            request_id: *request_id,
            payload,
            content_type,
        };
        let aad = build_aead_aad(
            request_id,
            sender_agent_id,
            recipient_agent_id,
            created_at_unix_ms,
        );
        let ciphertext = encrypt_payload(recipient_kem_pubkey_bytes, &plaintext, &aad)?;
        Ok(DmBody::Payload(ciphertext))
    }

    /// Build an `DmBody::Ack` variant.
    #[must_use]
    pub fn build_ack_body(acks_request_id: [u8; 16], outcome: DmAckOutcome) -> DmBody {
        DmBody::Ack(DmAckBody {
            acks_request_id,
            outcome,
        })
    }

    /// Build a fully-signed [`DmEnvelope`] from the raw send-site inputs.
    ///
    /// Wraps the five crypto ops every direct-DM send needs - KEM
    /// encapsulation, AEAD encryption, domain-separated signing-bytes
    /// build, ML-DSA-65 agent signature, and the #213 origin-machine
    /// attestation - behind one entry point. The `sign`
    /// closure receives the signing bytes and returns the agent signature; in
    /// production both `dm_send::send_via_gossip` and X0X-0070b's
    /// `try_relay_fallback` pass a closure backed by
    /// `gossip::SigningContext::sign`.
    ///
    /// `machine_keypair` MUST own `self_machine_id` — it signs the
    /// origin-machine attestation that lets zero-state receivers
    /// authenticate this DM's physical origin (issue #213).
    ///
    /// # Errors
    ///
    /// Returns [`DmError::EnvelopeConstruction`] if KEM encapsulation,
    /// AEAD encryption, signing-bytes serialisation, the `sign`
    /// closure, or the attestation signature fail — or if
    /// `machine_keypair` does not own `self_machine_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn build_payload_envelope<F>(
        request_id: [u8; 16],
        self_agent_id: &AgentId,
        self_machine_id: &MachineId,
        machine_keypair: &crate::identity::MachineKeypair,
        recipient_agent_id: &AgentId,
        recipient_kem_public_key: &[u8],
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        payload: Vec<u8>,
        sign: F,
    ) -> std::result::Result<DmEnvelope, DmError>
    where
        F: FnOnce(&[u8]) -> std::result::Result<Vec<u8>, String>,
    {
        if machine_keypair.machine_id() != *self_machine_id {
            return Err(DmError::EnvelopeConstruction(
                "machine keypair does not own self_machine_id".to_string(),
            ));
        }
        let body = Self::build_payload_body(
            &request_id,
            self_agent_id.as_bytes(),
            recipient_agent_id.as_bytes(),
            created_at_unix_ms,
            payload,
            None,
            recipient_kem_public_key,
        )
        .map_err(|e| DmError::EnvelopeConstruction(e.to_string()))?;
        let mut envelope = DmEnvelope {
            protocol_version: DM_PROTOCOL_VERSION,
            request_id,
            sender_agent_id: *self_agent_id.as_bytes(),
            sender_machine_id: *self_machine_id.as_bytes(),
            recipient_agent_id: *recipient_agent_id.as_bytes(),
            created_at_unix_ms,
            expires_at_unix_ms,
            body,
            signature: Vec::new(),
            origin_attestation: None,
        };
        let signed = envelope
            .signed_bytes()
            .map_err(|e| DmError::EnvelopeConstruction(e.to_string()))?;
        envelope.signature =
            sign(&signed).map_err(|e| DmError::EnvelopeConstruction(format!("sign: {e}")))?;
        // #213: fresh per-DM origin-machine proof. Placed after the agent
        // signature for clarity only — the attestation is independent of it.
        let mut attestation = DmOriginAttestation::for_envelope(
            &envelope,
            machine_keypair.public_key().as_bytes().to_vec(),
        );
        attestation.sign(machine_keypair)?;
        envelope.origin_attestation = Some(attestation);
        Ok(envelope)
    }
}

// ─── In-flight ACK tracking ────────────────────────────────────────────────

/// Map of request_id → oneshot::Sender that the inbox handler uses to wake
/// the sender task when an ACK arrives.
#[derive(Default)]
pub struct InFlightAcks {
    inner: Arc<dashmap::DashMap<[u8; 16], tokio::sync::oneshot::Sender<DmAckOutcome>>>,
}

impl Clone for InFlightAcks {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl InFlightAcks {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a waiter for `request_id`. Returns the receiver side of the
    /// oneshot; caller awaits it with their timeout.
    ///
    /// If a prior waiter exists for the same id (e.g. from an earlier
    /// retry that was already resolved), the existing waiter is silently
    /// replaced. This matches sender-retry semantics where only the most
    /// recent attempt's waiter is of interest.
    pub fn register(&self, request_id: [u8; 16]) -> tokio::sync::oneshot::Receiver<DmAckOutcome> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.inner.insert(request_id, tx);
        rx
    }

    /// Resolve a waiter for `request_id`. Returns true if a waiter was
    /// present, false otherwise (e.g. late ACK arriving after sender gave
    /// up).
    pub fn resolve(&self, request_id: &[u8; 16], outcome: DmAckOutcome) -> bool {
        if let Some((_, tx)) = self.inner.remove(request_id) {
            // If the receiver was dropped we silently swallow the send
            // error — caller already moved on.
            let _ = tx.send(outcome);
            true
        } else {
            false
        }
    }

    /// Cancel a waiter (sender gave up / retry-attempt abandoned).
    pub fn cancel(&self, request_id: &[u8; 16]) {
        self.inner.remove(request_id);
    }

    /// Diagnostic count of outstanding waiters.
    pub fn outstanding(&self) -> usize {
        self.inner.len()
    }
}

// ─── Convenience: unix-ms clock ────────────────────────────────────────────

/// Current unix-ms timestamp. Small convenience so callers don't repeat
/// the `SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64`
/// dance.
#[must_use]
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

// Keep a lint-safe reference to `AgentId` / `MachineId` types in case
// callers use the re-export pattern with `use crate::dm::*`.
#[allow(dead_code)]
fn _type_witness(_: AgentId, _: MachineId) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_agent_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn timestamp_window_accepts_valid() {
        let now = now_unix_ms();
        let created = now - 1000;
        let expires = now + 30_000;
        assert!(validate_timestamp_window(created, expires, now).is_ok());
    }

    #[test]
    fn timestamp_window_rejects_future_created_beyond_skew() {
        let now = now_unix_ms();
        let created = now + CLOCK_SKEW_TOLERANCE_MS + 1000;
        let expires = created + 30_000;
        assert_eq!(
            validate_timestamp_window(created, expires, now),
            Err(TimestampValidationError::FromFuture)
        );
    }

    #[test]
    fn timestamp_window_accepts_within_skew() {
        let now = now_unix_ms();
        let created = now + CLOCK_SKEW_TOLERANCE_MS - 100;
        let expires = created + 30_000;
        assert!(validate_timestamp_window(created, expires, now).is_ok());
    }

    #[test]
    fn timestamp_window_rejects_expired() {
        let now = now_unix_ms();
        let created = now - 60_000;
        let expires = now - 1000;
        assert_eq!(
            validate_timestamp_window(created, expires, now),
            Err(TimestampValidationError::Expired)
        );
    }

    #[test]
    fn timestamp_window_rejects_lifetime_over_max() {
        let now = now_unix_ms();
        let created = now;
        let expires = created + MAX_ENVELOPE_LIFETIME_MS + 1000;
        assert_eq!(
            validate_timestamp_window(created, expires, now),
            Err(TimestampValidationError::LifetimeExceedsMax)
        );
    }

    #[test]
    fn dedupe_cache_insert_and_lookup() {
        let cache = RecentDeliveryCache::with_defaults();
        let k = DedupeKey::new(dummy_agent_id(1), [9; 16]);
        assert!(cache.lookup(&k).is_none());
        cache.insert(k, DmAckOutcome::Accepted);
        let hit = cache.lookup(&k).expect("cache hit");
        assert_eq!(hit.outcome, DmAckOutcome::Accepted);
    }

    #[test]
    fn dedupe_cache_insert_claims_slot_exactly_once() {
        // The atomic-claim contract that prevents dual-path (primary inbox +
        // legacy bus) double-delivery: the first insert claims the slot
        // (returns true); any later insert of the same key returns false so the
        // racing task skips delivery and only re-ACKs.
        let cache = RecentDeliveryCache::with_defaults();
        let k = DedupeKey::new(dummy_agent_id(1), [9; 16]);
        assert!(
            cache.insert(k, DmAckOutcome::Accepted),
            "first insert must claim the slot"
        );
        assert!(
            !cache.insert(k, DmAckOutcome::Accepted),
            "second insert of the same key must not re-claim"
        );
        // A different key is independently claimable.
        let k2 = DedupeKey::new(dummy_agent_id(2), [9; 16]);
        assert!(cache.insert(k2, DmAckOutcome::Accepted));
    }

    #[test]
    fn dedupe_cache_ttl_expiry() {
        let cache = RecentDeliveryCache::new(Duration::from_millis(50), 100);
        let k = DedupeKey::new(dummy_agent_id(1), [9; 16]);
        cache.insert(k, DmAckOutcome::Accepted);
        std::thread::sleep(Duration::from_millis(100));
        assert!(cache.lookup(&k).is_none());
    }

    #[test]
    fn dedupe_cache_lru_eviction() {
        let cache = RecentDeliveryCache::new(Duration::from_secs(600), 3);
        for i in 0..5u8 {
            cache.insert(
                DedupeKey::new(dummy_agent_id(i), [i; 16]),
                DmAckOutcome::Accepted,
            );
        }
        assert_eq!(cache.len(), 3);
        // Oldest two should be evicted.
        assert!(cache
            .lookup(&DedupeKey::new(dummy_agent_id(0), [0; 16]))
            .is_none());
        assert!(cache
            .lookup(&DedupeKey::new(dummy_agent_id(1), [1; 16]))
            .is_none());
        // Newest three should be present.
        for i in 2..5u8 {
            assert!(cache
                .lookup(&DedupeKey::new(dummy_agent_id(i), [i; 16]))
                .is_some());
        }
    }

    #[test]
    fn kem_payload_round_trip() {
        let kp = AgentKemKeypair::generate().expect("keygen");
        let rid = [7u8; 16];
        let sender = dummy_agent_id(1);
        let recipient = dummy_agent_id(2);
        let now = now_unix_ms();
        let plaintext = DmPlaintext {
            request_id: rid,
            payload: b"hello direct".to_vec(),
            content_type: Some("text/plain".to_string()),
        };
        let aad = build_aead_aad(&rid, &sender, &recipient, now);
        let ct = encrypt_payload(&kp.public_bytes, &plaintext, &aad).expect("encrypt");
        let decrypted = decrypt_payload(&kp, &ct, &aad).expect("decrypt");
        assert_eq!(decrypted.request_id, rid);
        assert_eq!(decrypted.payload, b"hello direct");
        assert_eq!(decrypted.content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn kem_payload_aad_tamper_fails() {
        let kp = AgentKemKeypair::generate().expect("keygen");
        let rid = [7u8; 16];
        let sender = dummy_agent_id(1);
        let recipient = dummy_agent_id(2);
        let now = now_unix_ms();
        let plaintext = DmPlaintext {
            request_id: rid,
            payload: b"hi".to_vec(),
            content_type: None,
        };
        let aad = build_aead_aad(&rid, &sender, &recipient, now);
        let ct = encrypt_payload(&kp.public_bytes, &plaintext, &aad).expect("encrypt");
        // Flip one byte of AAD — decryption must fail.
        let mut bad_aad = aad.clone();
        bad_aad[0] ^= 1;
        assert!(decrypt_payload(&kp, &ct, &bad_aad).is_err());
    }

    #[test]
    fn inbox_topic_is_deterministic_and_unique() {
        let a = AgentId([1u8; 32]);
        let b = AgentId([2u8; 32]);
        let ta1 = dm_inbox_topic(&a);
        let ta2 = dm_inbox_topic(&a);
        let tb = dm_inbox_topic(&b);
        assert_eq!(ta1, ta2);
        assert_ne!(ta1, tb);
    }

    #[tokio::test]
    async fn build_payload_envelope_produces_verifiable_envelope() {
        // Why: X0X-0070b's `try_relay_fallback` and
        // `dm_send::send_via_gossip` both rely on this helper to produce
        // a fully signed envelope from raw inputs. The whole DM trust
        // model collapses if the returned envelope does not verify
        // against the sender's own ML-DSA-65 public key - pin it.
        use crate::gossip::SigningContext;
        use crate::groups::kem_envelope::AgentKemKeypair;
        use crate::identity::{AgentKeypair, MachineKeypair};

        let agent_kp = AgentKeypair::generate().expect("agent keypair");
        let machine_kp = MachineKeypair::generate().expect("machine keypair");
        let recipient_kem = AgentKemKeypair::generate().expect("recipient KEM keypair");
        let signing = SigningContext::from_keypair(&agent_kp);

        let sender = agent_kp.agent_id();
        let machine = machine_kp.machine_id();
        let recipient = AgentKeypair::generate()
            .expect("recipient agent keypair")
            .agent_id();
        let now = now_unix_ms();
        let request_id = [9u8; 16];

        let envelope = EnvelopeBuilder::build_payload_envelope(
            request_id,
            &sender,
            &machine,
            &machine_kp,
            &recipient,
            &recipient_kem.public_bytes,
            now,
            now + 60_000,
            b"hello-x0x-0070b".to_vec(),
            |bytes| signing.sign(bytes).map_err(|e| e.to_string()),
        )
        .expect("envelope build");

        assert_eq!(envelope.request_id, request_id);
        assert_eq!(envelope.sender_agent_id, *sender.as_bytes());
        assert_eq!(envelope.recipient_agent_id, *recipient.as_bytes());
        assert!(
            !envelope.signature.is_empty(),
            "build_payload_envelope must produce a non-empty signature"
        );
        // #213: the builder MUST attach a valid origin-machine attestation.
        let attested = envelope
            .verify_origin_attestation()
            .expect("attestation verifies")
            .expect("attestation present");
        assert_eq!(attested, machine);
        let signed_bytes = envelope.signed_bytes().expect("signed bytes");
        let sender_pub_bytes = agent_kp.to_bytes().0;
        let pubkey =
            ant_quic::MlDsaPublicKey::from_bytes(&sender_pub_bytes).expect("agent pubkey parse");
        let signature =
            ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&envelope.signature)
                .expect("signature parse");
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &pubkey,
            &signed_bytes,
            &signature,
        )
        .expect("envelope signature must verify against the sender's public key");
    }

    #[test]
    fn envelope_wire_round_trip() {
        let ack_body = EnvelopeBuilder::build_ack_body([3u8; 16], DmAckOutcome::Accepted);
        let env = DmEnvelope {
            protocol_version: DM_PROTOCOL_VERSION,
            request_id: [5u8; 16],
            sender_agent_id: dummy_agent_id(1),
            sender_machine_id: dummy_agent_id(11),
            recipient_agent_id: dummy_agent_id(2),
            created_at_unix_ms: now_unix_ms(),
            expires_at_unix_ms: now_unix_ms() + 120_000,
            body: ack_body,
            signature: vec![0u8; 64],
            origin_attestation: None,
        };
        let bytes = env.to_wire_bytes().expect("encode");
        let back = DmEnvelope::from_wire_bytes(&bytes).expect("decode");
        assert_eq!(back.request_id, env.request_id);
        assert_eq!(back.sender_agent_id, env.sender_agent_id);
        match back.body {
            DmBody::Ack(a) => {
                assert_eq!(a.acks_request_id, [3u8; 16]);
                assert_eq!(a.outcome, DmAckOutcome::Accepted);
            }
            DmBody::Payload(_) => panic!("expected Ack body"),
        }
    }

    #[test]
    fn envelope_oversized_rejected() {
        let bytes = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        assert!(DmEnvelope::from_wire_bytes(&bytes).is_err());
    }

    #[test]
    fn backoff_exponential_schedule() {
        let base = Duration::from_secs(10);
        let b = BackoffPolicy::ExponentialFromTimeout { factor: 2 };
        assert_eq!(b.delay(base, 0), Duration::from_secs(10));
        assert_eq!(b.delay(base, 1), Duration::from_secs(20));
        assert_eq!(b.delay(base, 2), Duration::from_secs(40));
    }

    #[test]
    fn adaptive_dm_attempt_timeout_uses_rtt_with_floor_and_ceiling() {
        assert_eq!(dm_attempt_timeout(Some(10)), Duration::from_millis(500));
        assert_eq!(dm_attempt_timeout(Some(50)), Duration::from_millis(800));
        assert_eq!(dm_attempt_timeout(None), Duration::from_secs(4));
        assert_eq!(dm_attempt_timeout(Some(0)), Duration::from_secs(4));
        assert_eq!(dm_attempt_timeout(Some(10_000)), Duration::from_secs(30));
    }

    #[test]
    fn default_dm_send_config_is_adaptive() {
        let cfg = DmSendConfig::default();
        assert_eq!(cfg.timeout_per_attempt, dm_attempt_timeout(None));
        assert!(matches!(
            cfg.backoff,
            BackoffPolicy::ExponentialFromTimeout { factor: 2 }
        ));
        assert_eq!(cfg.raw_quic_receive_ack_timeout, None);
        assert!(!cfg.stop_fallback_on_raw_error);
    }

    #[test]
    fn in_flight_acks_resolve_and_cancel() {
        let acks = InFlightAcks::new();
        let rid = [1u8; 16];
        let rx = acks.register(rid);
        assert!(acks.resolve(&rid, DmAckOutcome::Accepted));
        let received = tokio::runtime::Runtime::new().expect("rt").block_on(rx);
        assert_eq!(received.expect("ok"), DmAckOutcome::Accepted);
        // Second resolve → no-op.
        assert!(!acks.resolve(&rid, DmAckOutcome::Accepted));

        // Cancellation path.
        let rid2 = [2u8; 16];
        let _rx2 = acks.register(rid2);
        acks.cancel(&rid2);
        assert_eq!(acks.outstanding(), 0);
    }

    // ── Issue #213: origin-machine attestation ────────────────────────

    /// The pre-#213 envelope shape. Old receivers decode new wire bytes
    /// with THIS struct: postcard stops after `signature` and ignores the
    /// trailing attestation. Kept in sync with the historical shape — if
    /// `DmEnvelope` fields change, update this mirror.
    #[derive(Debug, Serialize, Deserialize)]
    struct DmEnvelopeLegacy {
        protocol_version: u16,
        request_id: [u8; 16],
        sender_agent_id: [u8; 32],
        sender_machine_id: [u8; 32],
        recipient_agent_id: [u8; 32],
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        body: DmBody,
        signature: Vec<u8>,
    }

    /// Build a fully-signed, attested payload envelope + the owning keys.
    fn attested_fixture() -> (DmEnvelope, crate::identity::AgentKeypair, crate::identity::MachineKeypair) {
        use crate::gossip::SigningContext;
        use crate::groups::kem_envelope::AgentKemKeypair;
        use crate::identity::{AgentKeypair, MachineKeypair};

        let agent_kp = AgentKeypair::generate().expect("agent keypair");
        let machine_kp = MachineKeypair::generate().expect("machine keypair");
        let recipient_kem = AgentKemKeypair::generate().expect("recipient KEM");
        let recipient = AgentKeypair::generate().expect("recipient").agent_id();
        let signing = SigningContext::from_keypair(&agent_kp);
        let now = now_unix_ms();
        let envelope = EnvelopeBuilder::build_payload_envelope(
            [7u8; 16],
            &agent_kp.agent_id(),
            &machine_kp.machine_id(),
            &machine_kp,
            &recipient,
            &recipient_kem.public_bytes,
            now,
            now + 60_000,
            b"attested".to_vec(),
            |bytes| signing.sign(bytes).map_err(|e| e.to_string()),
        )
        .expect("envelope build");
        (envelope, agent_kp, machine_kp)
    }

    #[test]
    fn attestation_verifies_and_returns_attested_machine() {
        let (envelope, _agent, machine) = attested_fixture();
        let attested = envelope
            .verify_origin_attestation()
            .expect("verify")
            .expect("present");
        assert_eq!(attested, machine.machine_id());
    }

    #[test]
    fn attestation_absent_decodes_as_none() {
        let env = DmEnvelope {
            protocol_version: DM_PROTOCOL_VERSION,
            request_id: [5u8; 16],
            sender_agent_id: dummy_agent_id(1),
            sender_machine_id: dummy_agent_id(11),
            recipient_agent_id: dummy_agent_id(2),
            created_at_unix_ms: now_unix_ms(),
            expires_at_unix_ms: now_unix_ms() + 120_000,
            body: EnvelopeBuilder::build_ack_body([3u8; 16], DmAckOutcome::Accepted),
            signature: vec![0u8; 64],
            origin_attestation: None,
        };
        assert_eq!(env.verify_origin_attestation(), Ok(None));
    }

    #[test]
    fn attestation_rejects_unsupported_version() {
        let (mut envelope, _agent, _machine) = attested_fixture();
        let attestation = envelope.origin_attestation.as_mut().expect("attested");
        attestation.attestation_version = DM_ORIGIN_ATTESTATION_VERSION + 1;
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(OriginAttestationError::UnsupportedVersion(
                DM_ORIGIN_ATTESTATION_VERSION + 1
            ))
        );
    }

    #[test]
    fn attestation_rejects_field_mismatch() {
        let (mut envelope, _agent, _machine) = attested_fixture();
        envelope.request_id = [8u8; 16]; // attestation still names [7; 16]
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(OriginAttestationError::EnvelopeMismatch)
        );
    }

    #[test]
    fn attestation_rejects_malformed_machine_key() {
        let (mut envelope, _agent, _machine) = attested_fixture();
        let attestation = envelope.origin_attestation.as_mut().expect("attested");
        attestation.machine_public_key = vec![0u8; 7];
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(OriginAttestationError::MalformedPublicKey)
        );
    }

    #[test]
    fn attestation_rejects_key_binding_mismatch() {
        use crate::identity::MachineKeypair;
        let (mut envelope, _agent, _machine) = attested_fixture();
        let other = MachineKeypair::generate().expect("other machine");
        let attestation = envelope.origin_attestation.as_mut().expect("attested");
        attestation.machine_public_key = other.public_key().as_bytes().to_vec();
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(OriginAttestationError::KeyBindingMismatch)
        );
    }

    #[test]
    fn attestation_rejects_bad_signature() {
        let (mut envelope, _agent, _machine) = attested_fixture();
        let attestation = envelope.origin_attestation.as_mut().expect("attested");
        // Valid-length, wrong-content signature.
        attestation.signature = vec![0u8; 3293];
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(OriginAttestationError::SignatureInvalid)
        );
        // Empty signature is also invalid.
        let attestation = envelope.origin_attestation.as_mut().expect("attested");
        attestation.signature = Vec::new();
        assert_eq!(
            envelope.verify_origin_attestation(),
            Err(OriginAttestationError::SignatureInvalid)
        );
    }

    /// Mixed-version: a NEW (attested) envelope MUST decode under the OLD
    /// struct shape — the old receiver skips the trailing attestation and
    /// the agent signature still verifies. This is the wire-level proof
    /// that the additive field does not break pre-#213 receivers.
    #[test]
    fn old_receiver_skips_attestation_field() {
        let (envelope, agent_kp, _machine) = attested_fixture();
        assert!(envelope.origin_attestation.is_some());
        let wire = envelope.to_wire_bytes().expect("encode");

        let legacy: DmEnvelopeLegacy =
            postcard::from_bytes(&wire).expect("old receivers must decode new envelopes");
        assert_eq!(legacy.request_id, envelope.request_id);
        assert_eq!(legacy.sender_machine_id, envelope.sender_machine_id);
        assert_eq!(legacy.signature, envelope.signature);

        // The agent signature scope is unchanged: verifying the legacy
        // decode against the legacy signed-bytes layout MUST succeed.
        let legacy_signed = {
            let body_bytes = postcard::to_stdvec(&legacy.body).expect("body");
            let mut out = Vec::new();
            out.extend_from_slice(b"x0x-dm-v1");
            out.extend_from_slice(&legacy.protocol_version.to_be_bytes());
            out.extend_from_slice(&legacy.request_id);
            out.extend_from_slice(&legacy.sender_agent_id);
            out.extend_from_slice(&legacy.sender_machine_id);
            out.extend_from_slice(&legacy.recipient_agent_id);
            out.extend_from_slice(&legacy.created_at_unix_ms.to_be_bytes());
            out.extend_from_slice(&legacy.expires_at_unix_ms.to_be_bytes());
            out.extend_from_slice(&body_bytes);
            out
        };
        let pubkey = ant_quic::MlDsaPublicKey::from_bytes(agent_kp.public_key().as_bytes())
            .expect("pubkey");
        let sig = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
            &legacy.signature,
        )
        .expect("sig");
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &pubkey,
            &legacy_signed,
            &sig,
        )
        .expect("old-shape signed bytes must verify against the agent key");
    }

    /// Mixed-version reverse: OLD wire bytes (no trailing attestation) MUST
    /// decode under the NEW struct with `origin_attestation == None`.
    #[test]
    fn new_receiver_tolerates_missing_attestation() {
        let legacy = DmEnvelopeLegacy {
            protocol_version: DM_PROTOCOL_VERSION,
            request_id: [9u8; 16],
            sender_agent_id: dummy_agent_id(3),
            sender_machine_id: dummy_agent_id(13),
            recipient_agent_id: dummy_agent_id(4),
            created_at_unix_ms: now_unix_ms(),
            expires_at_unix_ms: now_unix_ms() + 60_000,
            body: EnvelopeBuilder::build_ack_body([1u8; 16], DmAckOutcome::Accepted),
            signature: vec![0u8; 32],
        };
        let wire = postcard::to_stdvec(&legacy).expect("encode legacy");
        let decoded = DmEnvelope::from_wire_bytes(&wire)
            .expect("new receivers must decode old envelopes");
        assert_eq!(decoded.origin_attestation, None);
        assert_eq!(decoded.request_id, [9u8; 16]);
    }
}
