//! Direct messaging over gossip — envelope types, crypto, dedupe, and ACK
//! protocol. Implements the C design at `docs/design/dm-over-gossip.md`.
//!
//! Raw-QUIC direct-message path (in `src/direct.rs` + `src/network.rs`) is
//! preserved unchanged as the legacy/fallback path during the 0.18 overlap
//! release. This module adds the gossip-based path on top.

use crate::error::{IdentityError, Result};
use crate::groups::kem_envelope::{AgentKemKeypair, KEM_VARIANT};
use crate::identity::{AgentId, MachineId};
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

    /// True if this agent is subscribed to its gossip DM inbox topic. False
    /// means pre-0.18 / legacy-only — sender should fall back to the
    /// raw-QUIC path.
    pub gossip_inbox: bool,

    /// KEM algorithm identifier for payload encryption. For v1 always
    /// `"ML-KEM-768"`.
    pub kem_algorithm: String,

    /// Maximum envelope size (in bytes) this agent will accept.
    pub max_envelope_bytes: usize,
}

impl DmCapabilities {
    /// Capability advert for a fresh x0x 0.18+ agent.
    #[must_use]
    pub fn v1_gossip_ready() -> Self {
        Self {
            max_protocol_version: DM_PROTOCOL_VERSION,
            gossip_inbox: true,
            kem_algorithm: "ML-KEM-768".to_string(),
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
        }
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

    /// Catch-all for gossip transport errors not classified above.
    #[error("gossip transport error: {0}")]
    PublishFailed(String),
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
    /// New gossip-inbox path (C).
    GossipInbox,
    /// Legacy raw-QUIC direct-stream path. Still functional during the
    /// 0.18 overlap release.
    RawQuic,
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
}

impl Default for DmSendConfig {
    fn default() -> Self {
        Self {
            timeout_per_attempt: Duration::from_secs(10),
            max_retries: 3,
            backoff: BackoffPolicy::ExponentialFromTimeout { factor: 2 },
            require_gossip: false,
        }
    }
}

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
    /// Construct with the recommended defaults (5 min TTL, 10 000 entries).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(300), 10_000)
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

    /// Insert an outcome. If the key is already present, the existing
    /// `first_seen` is preserved (so TTL doesn't restart on re-delivery).
    pub fn insert(&self, key: DedupeKey, outcome: DmAckOutcome) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if inner.entries.contains_key(&key) {
            return;
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
    fn in_flight_acks_resolve_and_cancel() {
        let acks = InFlightAcks::new();
        let rid = [1u8; 16];
        let rx = acks.register(rid);
        assert!(acks.resolve(&rid, DmAckOutcome::Accepted));
        let received = tokio::runtime::Runtime::new()
            .expect("rt")
            .block_on(async move { rx.await });
        assert_eq!(received.expect("ok"), DmAckOutcome::Accepted);
        // Second resolve → no-op.
        assert!(!acks.resolve(&rid, DmAckOutcome::Accepted));

        // Cancellation path.
        let rid2 = [2u8; 16];
        let _rx2 = acks.register(rid2);
        acks.cancel(&rid2);
        assert_eq!(acks.outstanding(), 0);
    }
}
