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
    /// Dedupe key across redundant delivery channels.
    ///
    /// BLAKE3 of `signed_artifact` when present; otherwise a producer-chosen
    /// id (`compute_local_send_msg_id`, `compute_epoch_msg_id`, or BLAKE3 of
    /// `payload`). Unsigned MLS rows use the epoch helper — not an ADR-0029
    /// thread id.
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
    /// MIME content type of `payload`; `text/*` rows and recognized native
    /// channel-message JSON bodies are FTS-indexed.
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
    /// Canonical 64-lowercase-hex DM/group thread root, when supplied.
    ///
    /// Schema v3. No writer populates this yet; the canonical-form check
    /// lands with the DM thread-metadata parser that produces it.
    #[serde(default)]
    pub thread_root: Option<String>,
    /// Canonical direct parent. Meaningful only alongside [`Self::thread_root`].
    ///
    /// Schema v3, dormant — see [`Self::thread_root`].
    #[serde(default)]
    pub thread_parent: Option<String>,
    /// Authenticated outer transport sender for a durable typed ingress.
    /// This is distinct from `author_agent`, which names the artifact author
    /// and may legitimately differ when another member relays it.
    ///
    /// Schema v4. No writer populates this yet.
    #[serde(default)]
    pub ingress_sender_agent: Option<String>,
    /// Authenticated outer logical request id for durable typed ingress.
    /// Legacy, locally-authored, and non-typed records leave this unset.
    ///
    /// Schema v4, dormant — see [`Self::ingress_sender_agent`]. `validate`
    /// enforces that the two are set together or not at all.
    #[serde(default)]
    pub logical_request_id: Option<[u8; 16]>,
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

    /// Dedupe id for an unsigned MLS-plaintext row salted by group and epoch.
    ///
    /// `BLAKE3("x0x-history-mls-epoch-v2" ‖ u32_le(len(stable_id)) ‖
    /// stable_id ‖ u64_le(epoch) ‖ payload)`: identical plaintext in two
    /// groups whose epochs coincide no longer collapses (#276). Ciphertext
    /// replays within one group+epoch still dedupe. Epoch is a hash salt
    /// only — it is not persisted, and this is a new domain rather than an
    /// extension of v1.
    #[must_use]
    pub fn compute_epoch_msg_id(stable_id: &str, epoch: u64, payload: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x-history-mls-epoch-v2");
        let id_bytes = stable_id.as_bytes();
        let id_len = u32::try_from(id_bytes.len()).unwrap_or(u32::MAX);
        hasher.update(&id_len.to_le_bytes());
        hasher.update(id_bytes);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(payload);
        *hasher.finalize().as_bytes()
    }

    /// Validate internal consistency before write.
    pub fn validate(&self) -> HistoryResult<()> {
        if self.payload.is_empty() {
            return Err(HistoryError::InvalidRecord("empty payload".into()));
        }
        if self.ingress_sender_agent.is_some() != self.logical_request_id.is_some() {
            return Err(HistoryError::InvalidRecord(
                "durable typed ingress sender and logical request id must be set together".into(),
            ));
        }
        if self.signature.is_some() && self.signed_artifact.is_none() {
            return Err(HistoryError::InvalidRecord(
                "signature present without signed_artifact".into(),
            ));
        }
        // Artifact-less local sends carry a nonce-derived msg_id (see
        // `compute_local_send_msg_id`) that cannot be recomputed from the
        // row alone. Unsigned MLS `LocalAppDecrypt` rows similarly carry an
        // epoch+group-salted msg_id (`compute_epoch_msg_id`) that cannot be
        // recomputed because epoch is not a stored column. Every other row
        // must match the canonical computation.
        let opaque_unsigned = self.signed_artifact.is_none()
            && matches!(
                self.provenance,
                Provenance::LocalSend | Provenance::LocalAppDecrypt
            );
        if !opaque_unsigned {
            let expected = Self::compute_msg_id(self.signed_artifact.as_deref(), &self.payload);
            if expected != self.msg_id {
                return Err(HistoryError::InvalidRecord(
                    "msg_id does not match signed_artifact/payload".into(),
                ));
            }
        }
        Ok(())
    }

    /// True when the complete payload should be FTS-indexed as text.
    #[must_use]
    pub fn is_text(&self) -> bool {
        self.content_type.starts_with("text/")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn epoch_msg_id_is_stable_for_the_same_triple() {
        let a = HistoryRecord::compute_epoch_msg_id("group-a", 7, b"payload");
        let b = HistoryRecord::compute_epoch_msg_id("group-a", 7, b"payload");
        assert_eq!(
            a, b,
            "same group+epoch+payload must produce the same v2 msg_id"
        );
    }

    #[test]
    fn epoch_msg_id_differs_across_epochs() {
        let a = HistoryRecord::compute_epoch_msg_id("group-a", 1, b"same-payload");
        let b = HistoryRecord::compute_epoch_msg_id("group-a", 2, b"same-payload");
        assert_ne!(
            a, b,
            "same group+payload in different epochs must be distinct ids"
        );
    }

    #[test]
    fn epoch_msg_id_differs_across_groups_and_payloads() {
        let base = HistoryRecord::compute_epoch_msg_id("group-a", 3, b"payload");
        let other_group = HistoryRecord::compute_epoch_msg_id("group-b", 3, b"payload");
        let other_payload = HistoryRecord::compute_epoch_msg_id("group-a", 3, b"other");
        assert_ne!(
            base, other_group,
            "same epoch+payload in different groups must be distinct ids"
        );
        assert_ne!(
            base, other_payload,
            "same group+epoch with a different payload must be distinct ids"
        );
    }

    /// Without `u32_le(len(stable_id))`, these two encodings concatenate to
    /// the same byte string after the domain:
    /// ` "xy" ‖ u64_le(1) ‖ (u64_le(2) ‖ "hello") `
    /// vs ` ("xy" ‖ u64_le(1)) ‖ u64_le(2) ‖ "hello" `.
    /// The length prefix is what keeps them apart.
    #[test]
    fn epoch_msg_id_length_prefix_prevents_stable_id_glue() {
        let mut glued_payload = Vec::new();
        glued_payload.extend_from_slice(&2u64.to_le_bytes());
        glued_payload.extend_from_slice(b"hello");

        let epoch1 = 1u64.to_le_bytes();
        let mut glued_id = String::from("xy");
        glued_id.push_str(std::str::from_utf8(&epoch1).expect("le64(1) is valid UTF-8"));

        let mut unprefixed_a = Vec::new();
        unprefixed_a.extend_from_slice(b"xy");
        unprefixed_a.extend_from_slice(&1u64.to_le_bytes());
        unprefixed_a.extend_from_slice(&glued_payload);
        let mut unprefixed_b = Vec::new();
        unprefixed_b.extend_from_slice(glued_id.as_bytes());
        unprefixed_b.extend_from_slice(&2u64.to_le_bytes());
        unprefixed_b.extend_from_slice(b"hello");
        assert_eq!(
            unprefixed_a, unprefixed_b,
            "precondition: the two triples are a glue pair without the length prefix"
        );

        let a = HistoryRecord::compute_epoch_msg_id("xy", 1, &glued_payload);
        let b = HistoryRecord::compute_epoch_msg_id(&glued_id, 2, b"hello");
        assert_ne!(
            a, b,
            "v2 length-prefix must keep glued stable_id encodings distinct"
        );
    }
}
