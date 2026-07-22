//! History record types and the message-class taxonomy (ADR-0023 §4).
//!
//! Every stored surface is classified once, at the producer, as one of
//! [`MessageClass::Durable`], [`MessageClass::Replaceable`], or
//! [`MessageClass::Ephemeral`]. Ephemeral traffic never constructs a
//! [`HistoryRecord`] at all — the taxonomy exists so producers make the
//! decision explicitly, in code, exactly once.

use serde::{Deserialize, Serialize};

use crate::error::{HistoryError, HistoryResult};

/// Scope a history record belongs to (ADR-0023 §3 `scope_kind`/`scope_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// Direct-message conversation with one peer agent (hex `AgentId`).
    Dm(String),
    /// Named-group message stream (group stable id).
    Group(String),
    /// Application pub/sub topic that opted into recording.
    Topic(String),
}

impl Scope {
    /// Integer discriminant stored in the `scope_kind` column.
    #[must_use]
    pub fn kind(&self) -> i64 {
        match self {
            Scope::Dm(_) => 0,
            Scope::Group(_) => 1,
            Scope::Topic(_) => 2,
        }
    }

    /// The `scope_id` column value.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Scope::Dm(s) | Scope::Group(s) | Scope::Topic(s) => s,
        }
    }

    /// The canonical string form used by the REST API — the inverse of
    /// [`Scope::parse`] (`dm:<agent_hex>`, `group:<stable_id>`,
    /// `topic:<name>`).
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Scope::Dm(s) => format!("dm:{s}"),
            Scope::Group(s) => format!("group:{s}"),
            Scope::Topic(s) => format!("topic:{s}"),
        }
    }

    /// Parse the canonical string form used by the REST API
    /// (`dm:<agent_hex>`, `group:<stable_id>`, `topic:<name>`).
    pub fn parse(s: &str) -> HistoryResult<Self> {
        let (kind, id) = s
            .split_once(':')
            .ok_or_else(|| HistoryError::InvalidScope(s.to_string()))?;
        if id.is_empty() {
            return Err(HistoryError::InvalidScope(s.to_string()));
        }
        match kind {
            "dm" => Ok(Scope::Dm(id.to_string())),
            "group" => Ok(Scope::Group(id.to_string())),
            "topic" => Ok(Scope::Topic(id.to_string())),
            _ => Err(HistoryError::InvalidScope(s.to_string())),
        }
    }

    /// Reconstruct from stored `(scope_kind, scope_id)` columns.
    pub(crate) fn from_columns(kind: i64, id: String) -> HistoryResult<Self> {
        match kind {
            0 => Ok(Scope::Dm(id)),
            1 => Ok(Scope::Group(id)),
            2 => Ok(Scope::Topic(id)),
            other => Err(HistoryError::InvalidScope(format!(
                "unknown scope_kind {other}"
            ))),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::Dm(s) => write!(f, "dm:{s}"),
            Scope::Group(s) => write!(f, "group:{s}"),
            Scope::Topic(s) => write!(f, "topic:{s}"),
        }
    }
}

/// The ADR-0023 §4 message-class taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageClass {
    /// Appended to history, subject to retention.
    Durable,
    /// Latest-per-`replace_key` only (e.g. agent cards).
    Replaceable,
    /// Never written. Producers holding this class must not construct a
    /// record; the variant exists so classification is explicit.
    Ephemeral,
}

/// How this row's content reached the store (ADR-0023 §3 `provenance`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provenance {
    /// Inbound envelope that passed signature + trust gates; the verbatim
    /// signed artifact is stored and re-verifiable offline.
    VerifiedEnvelope,
    /// MLS-group plaintext obtained by a local application call to the
    /// secure encrypt/decrypt surfaces — no per-message author signature
    /// exists (ADR-0023 §3).
    LocalAppDecrypt,
    /// A message this node itself sent.
    LocalSend,
}

impl Provenance {
    pub(crate) fn as_i64(self) -> i64 {
        match self {
            Provenance::VerifiedEnvelope => 0,
            Provenance::LocalAppDecrypt => 1,
            Provenance::LocalSend => 2,
        }
    }

    pub(crate) fn from_i64(v: i64) -> HistoryResult<Self> {
        match v {
            0 => Ok(Provenance::VerifiedEnvelope),
            1 => Ok(Provenance::LocalAppDecrypt),
            2 => Ok(Provenance::LocalSend),
            other => Err(HistoryError::InvalidRecord(format!(
                "unknown provenance {other}"
            ))),
        }
    }
}

/// Message direction relative to this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Received from a peer.
    Inbound,
    /// Sent by this node.
    Outbound,
}

impl Direction {
    pub(crate) fn as_i64(self) -> i64 {
        match self {
            Direction::Inbound => 0,
            Direction::Outbound => 1,
        }
    }

    pub(crate) fn from_i64(v: i64) -> HistoryResult<Self> {
        match v {
            0 => Ok(Direction::Inbound),
            1 => Ok(Direction::Outbound),
            other => Err(HistoryError::InvalidRecord(format!(
                "unknown direction {other}"
            ))),
        }
    }
}

/// One durable (or replaceable) history row (ADR-0023 §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRecord {
    /// BLAKE3 of `signed_artifact` when present, else of `payload`.
    /// Dedupe key across redundant delivery channels.
    pub msg_id: [u8; 32],
    /// Conversation scope.
    pub scope: Scope,
    /// Hex `AgentId` of the author, when attributable.
    pub author_agent: Option<String>,
    /// Hex `MachineId` of the authoring machine, when known.
    pub author_machine: Option<String>,
    /// ML-DSA-65 public key bytes used at verify time.
    pub author_pubkey: Option<Vec<u8>>,
    /// Sender-claimed timestamp (unix ms).
    pub sent_at_ms: i64,
    /// Local receipt timestamp (unix ms) — authoritative for ordering.
    pub seen_at_ms: i64,
    /// Direction relative to this node.
    pub direction: Direction,
    /// MIME content type of `payload`; only `text/*` rows are FTS-indexed.
    pub content_type: String,
    /// Decrypted application payload — what a UI renders and search indexes.
    pub payload: Vec<u8>,
    /// Verbatim signed wire bytes (offline re-verification artifact).
    /// `None` only for unsigned rows (MLS `LocalAppDecrypt`).
    pub signed_artifact: Option<Vec<u8>>,
    /// ML-DSA-65 signature, verbatim. `None` for unsigned rows.
    pub signature: Option<Vec<u8>>,
    /// Domain-separation string used at verify time.
    pub sig_context: Option<String>,
    /// How the content reached the store.
    pub provenance: Provenance,
    /// Non-`None` marks the row replaceable, keyed by this string.
    pub replace_key: Option<String>,
}

impl HistoryRecord {
    /// Compute the dedupe id per ADR-0023 §3: BLAKE3 of the signed artifact
    /// when one exists, else BLAKE3 of the payload.
    #[must_use]
    pub fn compute_msg_id(signed_artifact: Option<&[u8]>, payload: &[u8]) -> [u8; 32] {
        match signed_artifact {
            Some(bytes) => *blake3::hash(bytes).as_bytes(),
            None => *blake3::hash(payload).as_bytes(),
        }
    }

    /// Dedupe id for an artifact-less locally-sent row.
    ///
    /// Outbound DMs on the raw-QUIC path never build a signed envelope, so
    /// there is no `signed_artifact`; `BLAKE3(payload)` alone would collapse
    /// two identical sends ("ok" twice) into one row. A per-send nonce keeps
    /// each logical send distinct while retries of the *same* logical send
    /// (which reuse the nonce) still dedupe.
    #[must_use]
    pub fn compute_local_send_msg_id(nonce: &[u8; 16], payload: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x-history-local-send-v1");
        hasher.update(nonce);
        hasher.update(payload);
        *hasher.finalize().as_bytes()
    }

    /// Dedupe id for an unsigned row salted by an epoch (MLS plaintext).
    ///
    /// `BLAKE3(salt-domain ‖ epoch ‖ payload)`: ciphertext replays within an
    /// epoch still dedupe, while identical plaintext sent in different
    /// epochs survives as distinct rows. Identical plaintext *within* one
    /// epoch still collapses — per-message MLS identity is a future
    /// wire-format change (ADR-0023 §3).
    #[must_use]
    pub fn compute_epoch_msg_id(epoch: u64, payload: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x-history-mls-epoch-v1");
        hasher.update(&epoch.to_le_bytes());
        hasher.update(payload);
        *hasher.finalize().as_bytes()
    }

    /// Validate internal consistency before write.
    pub fn validate(&self) -> HistoryResult<()> {
        if self.payload.is_empty() {
            return Err(HistoryError::InvalidRecord("empty payload".into()));
        }
        if self.signature.is_some() && self.signed_artifact.is_none() {
            return Err(HistoryError::InvalidRecord(
                "signature present without signed_artifact".into(),
            ));
        }
        // Artifact-less local sends carry a nonce-derived msg_id (see
        // `compute_local_send_msg_id`) that cannot be recomputed from the
        // row alone; every other row must match the canonical computation.
        let nonce_keyed_local_send =
            self.provenance == Provenance::LocalSend && self.signed_artifact.is_none();
        if !nonce_keyed_local_send {
            let expected = Self::compute_msg_id(self.signed_artifact.as_deref(), &self.payload);
            if expected != self.msg_id {
                return Err(HistoryError::InvalidRecord(
                    "msg_id does not match signed_artifact/payload".into(),
                ));
            }
        }
        Ok(())
    }

    /// True when the payload should be FTS-indexed.
    #[must_use]
    pub fn is_text(&self) -> bool {
        self.content_type.starts_with("text/")
    }
}
