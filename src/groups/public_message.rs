//! Public-group message primitive (Phase E).
//!
//! Design source of truth:
//! `docs/design/named-groups-full-model.md` §"Public groups" and
//! §"Secure enforcement / apply-side validation".
//!
//! A `GroupPublicMessage` is a signed, state-bound message for groups
//! whose `confidentiality == SignedPublic`. It carries:
//!
//! - the stable `group_id`,
//! - a binding to the group state at which it was authored
//!   (`state_hash_at_send`, `revision_at_send`),
//! - author identity (ML-DSA-65 public key + derived AgentId +
//!   optional user_id),
//! - the message payload,
//! - an ML-DSA-65 signature over the canonical message bytes.
//!
//! Receivers validate via [`validate_public_message`]:
//!
//! 1. `group_id` matches the intended group.
//! 2. Confidentiality is `SignedPublic`.
//! 3. Signature verifies under `author_public_key` and the derived
//!    AgentId matches `author_agent_id`.
//! 4. Author is not currently `Banned`.
//! 5. Write-access policy is satisfied:
//!    - `MembersOnly`: author is an active member.
//!    - `ModeratedPublic`: any non-banned author (moderators remove
//!      later; this is v1 best-effort).
//!    - `AdminOnly`: author is an active member with role ≥ Admin.
//!
//! Topic convention for transport:
//! `x0x.groups.public.{group_id}`.

use crate::groups::member::{GroupMember, GroupMemberState, GroupRole};
use crate::groups::policy::{GroupConfidentiality, GroupPolicy, GroupWriteAccess};
use crate::groups::state_commit::ApplyError;
use crate::identity::AgentKeypair;
use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaSignature,
};
use ant_quic::MlDsaPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain-separation tag for public-message signatures (v1 — no thread fields).
pub const PUBLIC_MESSAGE_DOMAIN: &[u8] = b"x0x.group.public-message.v1";

/// Domain-separation tag for threaded public-message signatures (v2).
///
/// Used when `thread_root` or `thread_parent` is set. Messages without thread
/// fields sign under `PUBLIC_MESSAGE_DOMAIN` and are byte-identical to v1.
pub const PUBLIC_MESSAGE_DOMAIN_V2: &[u8] = b"x0x.group.public-message.v2";

/// Topic-string prefix for public-group chat.
pub const PUBLIC_GROUP_TOPIC_PREFIX: &str = "x0x.groups.public";

/// Bounded size for a single public-message body (bytes). Prevents
/// single-message floods on the public topic.
pub const MAX_PUBLIC_MESSAGE_BYTES: usize = 64 * 1024;

/// Produce the topic string for a public group's message feed.
#[must_use]
pub fn public_topic_for(group_id: &str) -> String {
    format!("{PUBLIC_GROUP_TOPIC_PREFIX}.{group_id}")
}

/// Kind of public message. Start minimal for v1 — `Chat` covers the
/// open-community case and `Announcement` is the authority-signed
/// notice variant used by `public_announce` groups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GroupPublicMessageKind {
    /// Normal chat message.
    Chat,
    /// Announcement (intended for `AdminOnly` write-access groups).
    Announcement,
}

/// Signed, state-bound public-group message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPublicMessage {
    pub group_id: String,
    /// Group state-hash at which this message was authored (Phase D.3).
    pub state_hash_at_send: String,
    /// Group state-revision at which this message was authored.
    pub revision_at_send: u64,
    /// Hex agent_id of the author.
    pub author_agent_id: String,
    /// Hex ML-DSA-65 public key of the author (for standalone verify).
    pub author_public_key: String,
    /// Optional linked user_id (hex).
    #[serde(default)]
    pub author_user_id: Option<String>,
    #[serde(flatten)]
    pub kind: GroupPublicMessageKind,
    /// UTF-8 message body.
    pub body: String,
    /// Unix milliseconds at send time.
    pub timestamp: u64,
    /// `msg_id` of the thread's first message (hex, 64 chars). ADR-0029.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_root: Option<String>,
    /// `msg_id` of the direct parent in the thread (hex, 64 chars). ADR-0029.
    /// When present, `thread_root` must also be present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_parent: Option<String>,
    /// ADR-0039 rider provenance: present only when this message was sent
    /// through the owner's daemon by an API-key rider. The envelope rides
    /// INSIDE `signable_bytes()` — the daemon-agent signature over the
    /// message authenticates the attribution (gapcheck blocker 24: the
    /// provenance marker must be covered by the signed bytes). Additive and
    /// serde-defaulted, so pre-ADR-0039 messages (and older verifiers that
    /// drop the field) see the exact v1/v2 encoding when it is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rider_provenance: Option<RiderProvenance>,
    /// Hex ML-DSA-65 signature over `signable_bytes()`.
    pub signature: String,
}

/// Attribution envelope for a rider-sourced send (ADR-0039, review r3).
///
/// The daemon never holds the sub-agent's secret key, so it cannot — and
/// must not — sign *as* the sub-agent. The daemon's agent key signs the
/// message, and this envelope binds, inside those signed bytes, the
/// registered sub-agent on whose behalf the send was made — **backed by
/// a cryptographic delegation** ([`RiderDelegation`]) signed by the
/// sub-agent's OWN key: the daemon may only speak for sub-agents that
/// explicitly authorized THIS daemon, scoped to named groups and
/// expiring. Receivers verify the whole chain; the asserted
/// `sub_agent_id` string alone proves nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiderProvenance {
    /// Hex `AgentId` of the registered sub-agent on whose behalf the
    /// daemon sent (must match a `mode=rider` journal record and the
    /// delegation's certified subject).
    pub sub_agent_id: String,
    /// Opaque numeric id of the rider token that authorized the send.
    pub rider_token_id: u64,
    /// SHA-256 hex of the rider token (the hashed-at-rest identifier;
    /// the token secret is never placed on the wire).
    pub rider_token_hash: String,
    /// The granted scope this send used: the target group id.
    pub scope: String,
    /// The sub-agent-signed delegation authorizing THIS daemon. Required:
    /// provenance without a verifiable delegation is exactly the forgery
    /// vector and is rejected by receivers.
    pub delegation: RiderDelegation,
}

/// A delegation-to-daemon capability signed by the SUB-AGENT's key
/// (review r3, option B): `{sub_agent_id -> daemon_agent_id, scopes,
/// not_after}`. The harness signs it once, locally, when the rider token
/// is issued; the daemon stores it with the token and embeds it in every
/// rider message. Receivers verify: (i) the embedded owner certificate
/// is valid and binds the claimed `sub_agent_id`, (ii) the capability
/// signature verifies under that certificate's agent key, (iii) the
/// capability names the message's actual signer as the delegated
/// daemon, (iv) the target group is in the capability scopes, and
/// (v) the capability has not expired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiderDelegation {
    /// Base64 `AgentCertificate` storage bytes for the sub-agent — the
    /// self-contained trust anchor so receivers that have never seen the
    /// sub-agent can verify the chain without a blob-cache fetch
    /// (gapcheck 13: cache misses must not become fail-open pressure).
    pub cert_b64: String,
    /// Base64 canonical delegation bytes ([`rider_delegation_bytes`]).
    pub payload_b64: String,
    /// Hex ML-DSA-65 signature by the sub-agent key over the payload.
    pub signature: String,
}

/// Domain-separation tag for delegation capabilities.
pub const RIDER_DELEGATION_DOMAIN: &[u8] = b"x0x.rider-delegation.v1";

/// Canonical delegation bytes:
/// `domain || len(sub_agent_id) || sub_agent_id || len(daemon_agent_id)
/// || daemon_agent_id || scope_count(LE u32) || (len+id)* ||
/// not_after(LE u64)`.
///
/// Public so harnesses build the exact bytes they sign.
#[must_use]
pub fn rider_delegation_bytes(
    sub_agent_id: &str,
    daemon_agent_id: &str,
    scopes: &[String],
    not_after: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + sub_agent_id.len() + daemon_agent_id.len());
    buf.extend_from_slice(RIDER_DELEGATION_DOMAIN);
    push_len_prefixed_str(&mut buf, sub_agent_id);
    push_len_prefixed_str(&mut buf, daemon_agent_id);
    buf.extend_from_slice(&(scopes.len() as u32).to_le_bytes());
    for scope in scopes {
        push_len_prefixed_str(&mut buf, scope);
    }
    buf.extend_from_slice(&not_after.to_le_bytes());
    buf
}

fn push_len_prefixed_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// The parsed delegation claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiderDelegationClaim {
    pub sub_agent_id: String,
    pub daemon_agent_id: String,
    pub scopes: Vec<String>,
    pub not_after: u64,
}

/// Parse canonical delegation bytes back into a claim (mirrors
/// [`rider_delegation_bytes`]; rejects trailing garbage).
#[must_use]
pub fn parse_rider_delegation(payload: &[u8]) -> Option<RiderDelegationClaim> {
    let mut rest = payload;
    if rest.len() < RIDER_DELEGATION_DOMAIN.len()
        || &rest[..RIDER_DELEGATION_DOMAIN.len()] != RIDER_DELEGATION_DOMAIN
    {
        return None;
    }
    rest = &rest[RIDER_DELEGATION_DOMAIN.len()..];
    let sub_agent_id = take_len_prefixed_str(&mut rest)?;
    let daemon_agent_id = take_len_prefixed_str(&mut rest)?;
    let scope_count = u32::from_le_bytes(take_fixed(&mut rest, 4)?.try_into().ok()?) as usize;
    if scope_count > 64 {
        return None;
    }
    let mut scopes = Vec::with_capacity(scope_count);
    for _ in 0..scope_count {
        scopes.push(take_len_prefixed_str(&mut rest)?);
    }
    let not_after = u64::from_le_bytes(take_fixed(&mut rest, 8)?.try_into().ok()?);
    if !rest.is_empty() {
        return None;
    }
    Some(RiderDelegationClaim {
        sub_agent_id,
        daemon_agent_id,
        scopes,
        not_after,
    })
}

fn take_fixed<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if rest.len() < n {
        return None;
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Some(head)
}

fn take_len_prefixed_str(rest: &mut &[u8]) -> Option<String> {
    let len = u32::from_le_bytes(take_fixed(rest, 4)?.try_into().ok()?) as usize;
    if len > 512 {
        return None;
    }
    let bytes = take_fixed(rest, len)?;
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

/// Verify a rider provenance chain against the message's actual signer.
///
/// Returns the certified `sub_agent_id` on success. Checks, in order:
/// certificate decodes + verifies + binds the claimed sub-agent;
/// delegation payload parses and re-states the same subject; the
/// delegation signature verifies under the certificate's agent key; the
/// delegation names `author_agent_id` (the daemon that actually signed
/// the message) as the delegate; the capability is unexpired at
/// `now_unix`; and `scope` (the target group) is inside the capability
/// scopes. Every failure is a string reason for logs/403 bodies.
pub fn verify_rider_provenance(
    provenance: &RiderProvenance,
    author_agent_id: &str,
    scope: &str,

    now_unix: u64,
) -> Result<String, String> {
    use base64::Engine as _;
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(&provenance.delegation.cert_b64)
        .map_err(|_| "delegation certificate is not valid base64".to_string())?;
    let cert = crate::identity::AgentCertificate::from_storage_bytes(&cert_bytes)
        .map_err(|e| format!("delegation certificate does not decode: {e}"))?;
    cert.verify()
        .map_err(|_| "delegation certificate fails verification".to_string())?;
    let certified_sub = cert
        .agent_id()
        .map(|id| hex::encode(id.as_bytes()))
        .map_err(|_| "delegation certificate has no agent id".to_string())?;
    if certified_sub != provenance.sub_agent_id {
        return Err("provenance sub_agent_id does not match its certificate".to_string());
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&provenance.delegation.payload_b64)
        .map_err(|_| "delegation payload is not valid base64".to_string())?;
    let claim = parse_rider_delegation(&payload)
        .ok_or_else(|| "delegation payload does not parse".to_string())?;
    if claim.sub_agent_id != provenance.sub_agent_id {
        return Err("delegation subject differs from provenance".to_string());
    }
    if claim.daemon_agent_id != author_agent_id {
        return Err(format!(
            "delegation names daemon {daemon} but the message signer is {author_agent_id}",
            daemon = claim.daemon_agent_id
        ));
    }
    let sig_bytes = hex::decode(&provenance.delegation.signature)
        .map_err(|_| "delegation signature is not valid hex".to_string())?;
    let sig = MlDsaSignature::from_bytes(&sig_bytes)
        .map_err(|e| format!("delegation signature does not decode: {e:?}"))?;
    let agent_pub = MlDsaPublicKey::from_bytes(cert.agent_public_key())
        .map_err(|_| "certificate agent key does not parse".to_string())?;
    verify_with_ml_dsa(&agent_pub, &payload, &sig)
        .map_err(|_| "delegation is not signed by the sub-agent's key".to_string())?;
    if now_unix >= claim.not_after {
        return Err("delegation has expired".to_string());
    }
    if !claim.scopes.iter().any(|s| s == scope) {
        return Err("target group is not in the delegation scopes".to_string());
    }
    Ok(certified_sub)
}

/// Harness-side helper for the delegation flow (review r3): builds the
/// canonical capability bytes binding this keypair's agent id to
/// `daemon_agent_id` for `scopes` until `not_after`, and signs them
/// with the sub-agent key. Returns `(payload_b64, signature_hex)` for
/// the `delegation` field of `POST /owner/riders`.
///
/// # Errors
///
/// Returns [`ApplyError::InvalidSignature`] when ML-DSA signing fails.
pub fn sign_rider_delegation(
    sub_kp: &AgentKeypair,
    daemon_agent_id: &str,
    scopes: &[String],
    not_after: u64,
) -> Result<(String, String), ApplyError> {
    use base64::Engine as _;
    let sub_agent_id = hex::encode(sub_kp.agent_id().as_bytes());
    let payload = rider_delegation_bytes(&sub_agent_id, daemon_agent_id, scopes, not_after);
    let sig = sign_with_ml_dsa(sub_kp.secret_key(), &payload)
        .map_err(|e| ApplyError::InvalidSignature(format!("delegation sign: {e:?}")))?;
    Ok((
        base64::engine::general_purpose::STANDARD.encode(&payload),
        hex::encode(sig.as_bytes()),
    ))
}

impl GroupPublicMessage {
    /// Canonical bytes signed by the author to produce `signature`.
    ///
    /// Includes every field except `signature` itself.
    ///
    /// **Compatibility rule (ADR-0029):** when both `thread_root` and
    /// `thread_parent` are `None`, the output is byte-identical to the
    /// pre-threading v1 encoding (same domain, no thread suffix). When
    /// either field is `Some`, the v2 domain is used and both thread
    /// fields are appended length-prefixed after `timestamp` (absent ⇒
    /// empty string).
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let threaded = self.thread_root.is_some() || self.thread_parent.is_some();
        let mut buf = Vec::with_capacity(512 + self.body.len());
        buf.extend_from_slice(if threaded {
            PUBLIC_MESSAGE_DOMAIN_V2
        } else {
            PUBLIC_MESSAGE_DOMAIN
        });
        push_len_prefixed(&mut buf, self.group_id.as_bytes());
        push_len_prefixed(&mut buf, self.state_hash_at_send.as_bytes());
        buf.extend_from_slice(&self.revision_at_send.to_le_bytes());
        push_len_prefixed(&mut buf, self.author_agent_id.as_bytes());
        push_len_prefixed(&mut buf, self.author_public_key.as_bytes());
        push_len_prefixed(
            &mut buf,
            self.author_user_id.as_deref().unwrap_or("").as_bytes(),
        );
        // Kind — serialise with bincode for a deterministic, brief tag.
        let kind_bytes = bincode::serialize(&self.kind).unwrap_or_default();
        push_len_prefixed(&mut buf, &kind_bytes);
        push_len_prefixed(&mut buf, self.body.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        if threaded {
            push_len_prefixed(
                &mut buf,
                self.thread_root.as_deref().unwrap_or("").as_bytes(),
            );
            push_len_prefixed(
                &mut buf,
                self.thread_parent.as_deref().unwrap_or("").as_bytes(),
            );
        }
        // ADR-0039: rider provenance rides INSIDE the signed bytes (absent
        // ⇒ byte-identical legacy encoding, preserving the ADR-0029 rule
        // above). Review r3: the delegation capability (cert, payload,
        // signature) is part of those signed bytes too — the daemon's
        // signature authenticates the exact capability it acted on.
        if let Some(prov) = &self.rider_provenance {
            push_len_prefixed(&mut buf, prov.sub_agent_id.as_bytes());
            buf.extend_from_slice(&prov.rider_token_id.to_le_bytes());
            push_len_prefixed(&mut buf, prov.rider_token_hash.as_bytes());
            push_len_prefixed(&mut buf, prov.scope.as_bytes());
            push_len_prefixed(&mut buf, prov.delegation.cert_b64.as_bytes());
            push_len_prefixed(&mut buf, prov.delegation.payload_b64.as_bytes());
            push_len_prefixed(&mut buf, prov.delegation.signature.as_bytes());
        }
        buf
    }

    /// Stable message identity: lowercase hex of `BLAKE3(signable_bytes())`.
    ///
    /// 64 hex characters. Deterministic and recomputable by any verifier.
    /// Analogous to Nostr's `event.id`. ADR-0029.
    #[must_use]
    pub fn msg_id(&self) -> String {
        hex::encode(blake3::hash(&self.signable_bytes()).as_bytes())
    }

    /// Build and sign a new public message.
    ///
    /// Pass `thread_root` / `thread_parent` to produce a v2-domain threaded
    /// message (ADR-0029); both `None` produces a v1-compatible message.
    /// Pass `rider_provenance` to stamp ADR-0039 attribution inside the
    /// signed bytes (owner sends pass `None` and produce the exact legacy
    /// encoding).
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        group_id: String,
        state_hash_at_send: String,
        revision_at_send: u64,
        keypair: &AgentKeypair,
        author_user_id: Option<String>,
        kind: GroupPublicMessageKind,
        body: String,
        timestamp: u64,
        thread_root: Option<String>,
        thread_parent: Option<String>,
        rider_provenance: Option<RiderProvenance>,
    ) -> Result<Self, ApplyError> {
        let author_agent_id = hex::encode(keypair.agent_id().as_bytes());
        let author_public_key = hex::encode(keypair.public_key().as_bytes());
        let mut msg = Self {
            group_id,
            state_hash_at_send,
            revision_at_send,
            author_agent_id,
            author_public_key,
            author_user_id,
            kind,
            body,
            timestamp,
            thread_root,
            thread_parent,
            rider_provenance,
            signature: String::new(),
        };
        let sig = sign_with_ml_dsa(keypair.secret_key(), &msg.signable_bytes())
            .map_err(|e| ApplyError::InvalidSignature(format!("public-msg sign: {e:?}")))?;
        msg.signature = hex::encode(sig.as_bytes());
        Ok(msg)
    }

    /// Verify the message signature and the `author_agent_id` ↔ key
    /// binding. Does **not** perform authorisation checks — that is
    /// done in [`validate_public_message`] against the current group
    /// view.
    pub fn verify_signature(&self) -> Result<(), ApplyError> {
        if self.signature.is_empty() || self.author_public_key.is_empty() {
            return Err(ApplyError::InvalidSignature("missing signature".into()));
        }
        let pubkey_bytes = hex::decode(&self.author_public_key)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad pubkey hex: {e}")))?;
        let pubkey = MlDsaPublicKey::from_bytes(&pubkey_bytes)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad pubkey: {e:?}")))?;
        let derived = hex::encode(ant_quic::derive_peer_id_from_public_key(&pubkey).0);
        if derived != self.author_agent_id {
            return Err(ApplyError::InvalidSignature(format!(
                "author_agent_id {} != derived {}",
                self.author_agent_id, derived
            )));
        }
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad sig hex: {e}")))?;
        let sig = MlDsaSignature::from_bytes(&sig_bytes)
            .map_err(|e| ApplyError::InvalidSignature(format!("bad sig: {e:?}")))?;
        verify_with_ml_dsa(&pubkey, &self.signable_bytes(), &sig)
            .map_err(|e| ApplyError::InvalidSignature(format!("public-msg verify failed: {e:?}")))
    }
}

fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Validate that a thread field value is exactly 64 lowercase hex characters.
fn validate_thread_hex(field: &'static str, value: &str) -> Result<(), IngestError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(IngestError::InvalidThreadField {
            field,
            value: value.to_string(),
        })
    }
}

// ────────────────────────── Ingest validator ────────────────────────────

/// Errors from public-message ingest validation.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum IngestError {
    #[error("group_id mismatch: expected {expected}, got {got}")]
    GroupIdMismatch { expected: String, got: String },

    #[error("confidentiality mismatch: group is not SignedPublic")]
    ConfidentialityMismatch,

    #[error("message exceeds size bound ({size} > {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("author is banned in this group")]
    AuthorBanned,

    #[error("write-policy violation under {policy:?}: author lacks required role")]
    WritePolicyViolation { policy: GroupWriteAccess },

    /// A thread field value is not exactly 64 lowercase hex characters.
    #[error("invalid thread field '{field}': must be 64 lowercase hex chars, got '{value}'")]
    InvalidThreadField { field: &'static str, value: String },

    /// `thread_parent` is set but `thread_root` is absent.
    #[error("thread_parent requires thread_root to also be set")]
    ThreadParentWithoutRoot,

    /// A thread field references the message's own `msg_id`.
    #[error("thread field '{field}' must not equal the message's own msg_id")]
    ThreadSelfReference { field: &'static str },
}

/// Context passed to the ingest validator. Receivers build this from
/// their current `GroupInfo` view at apply-time.
#[derive(Debug, Clone)]
pub struct PublicIngestContext<'a> {
    pub group_id: &'a str,
    pub policy: &'a GroupPolicy,
    pub members_v2: &'a BTreeMap<String, GroupMember>,
}

/// Validate a public-group message against the current group view.
///
/// Returns `Ok(())` if the message should be accepted and cached;
/// returns `Err` with a deterministic reason otherwise. The validator
/// is pure and side-effect-free — it does not mutate any state.
pub fn validate_public_message(
    ctx: &PublicIngestContext<'_>,
    msg: &GroupPublicMessage,
) -> Result<(), IngestError> {
    // 1. group_id match
    if msg.group_id != ctx.group_id {
        return Err(IngestError::GroupIdMismatch {
            expected: ctx.group_id.to_string(),
            got: msg.group_id.clone(),
        });
    }

    // 2. confidentiality — SignedPublic only
    if ctx.policy.confidentiality != GroupConfidentiality::SignedPublic {
        return Err(IngestError::ConfidentialityMismatch);
    }

    // 3. bounded size
    if msg.body.len() > MAX_PUBLIC_MESSAGE_BYTES {
        return Err(IngestError::MessageTooLarge {
            size: msg.body.len(),
            max: MAX_PUBLIC_MESSAGE_BYTES,
        });
    }

    // 4. threading field structural checks (cheap, no crypto — run before
    //    signature verification so malformed gossip messages are rejected
    //    without paying ML-DSA-65 verify cost). ADR-0029.
    if let Some(root) = &msg.thread_root {
        validate_thread_hex("thread_root", root)?;
    }
    if let Some(parent) = &msg.thread_parent {
        validate_thread_hex("thread_parent", parent)?;
        // parent requires root
        if msg.thread_root.is_none() {
            return Err(IngestError::ThreadParentWithoutRoot);
        }
    }
    // Self-reference: thread_root/thread_parent must not equal the message's
    // own msg_id. Constructing a genuinely self-referential signed message
    // requires a BLAKE3 hash fixed-point, so this check is reachable only
    // for tampered messages whose signature would fail anyway — but it serves
    // as a cheap early reject before the expensive ML-DSA-65 verify.
    let own_id = msg.msg_id();
    if msg.thread_root.as_deref() == Some(own_id.as_str()) {
        return Err(IngestError::ThreadSelfReference {
            field: "thread_root",
        });
    }
    if msg.thread_parent.as_deref() == Some(own_id.as_str()) {
        return Err(IngestError::ThreadSelfReference {
            field: "thread_parent",
        });
    }
    // 5. signature + author binding
    msg.verify_signature()
        .map_err(|e| IngestError::InvalidSignature(format!("{e}")))?;

    // Review r3 (CRITICAL): rider provenance is only trustworthy behind
    // a SUB-AGENT-SIGNED delegation. Before treating the asserted
    // sub_agent_id as the acting principal, verify the full chain —
    // owner cert → sub-agent key → delegation → THIS message's signer —
    // or reject: any daemon can otherwise claim any member identity by
    // fabricating a provenance string.
    let acting_agent = match &msg.rider_provenance {
        None => msg.author_agent_id.as_str(),
        Some(prov) => {
            if prov.scope != ctx.group_id {
                return Err(IngestError::InvalidSignature(format!(
                    "rider provenance scope {scope} does not match target group {group}",
                    scope = prov.scope,
                    group = ctx.group_id
                )));
            }
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            verify_rider_provenance(prov, &msg.author_agent_id, &prov.scope, now_unix)
                .map_err(IngestError::InvalidSignature)?;
            // `verify_rider_provenance` proved the certified subject
            // equals the asserted id, so the assertion is now trusted.
            prov.sub_agent_id.as_str()
        }
    };

    // 7. banned authors rejected
    if let Some(member) = ctx.members_v2.get(acting_agent) {
        if member.state == GroupMemberState::Banned {
            return Err(IngestError::AuthorBanned);
        }
    }

    // 8. write-access policy enforcement
    let author_role = ctx
        .members_v2
        .get(acting_agent)
        .filter(|m| m.state == GroupMemberState::Active)
        .map(|m| m.role);

    match ctx.policy.write_access {
        GroupWriteAccess::MembersOnly => {
            if author_role.is_none() {
                return Err(IngestError::WritePolicyViolation {
                    policy: ctx.policy.write_access,
                });
            }
        }
        GroupWriteAccess::ModeratedPublic => {
            // Any non-banned author accepted at ingest; moderators
            // remove inappropriate posts later (out of v1 scope).
        }
        GroupWriteAccess::AdminOnly => match author_role {
            Some(r) if r.at_least(GroupRole::Admin) => {}
            _ => {
                return Err(IngestError::WritePolicyViolation {
                    policy: ctx.policy.write_access,
                });
            }
        },
    }

    Ok(())
}

// ─────────────────────────────── Tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::policy::{
        GroupAdmission, GroupDiscoverability, GroupPolicyPreset, GroupReadAccess,
    };

    fn make_kp() -> AgentKeypair {
        AgentKeypair::generate().unwrap()
    }

    fn active_member(hex_id: &str, role: GroupRole) -> GroupMember {
        GroupMember {
            agent_id: hex_id.to_string(),
            user_id: None,
            role,
            state: GroupMemberState::Active,
            display_name: None,
            joined_at: 0,
            updated_at: 0,
            added_by: None,
            removed_by: None,
            kem_public_key_b64: None,
            treekem_key_package_b64: None,
            treekem_key_package_hash: None,
            certificate: None,
            certificate_missing_since_ms: None,
        }
    }

    fn banned_member(hex_id: &str) -> GroupMember {
        let mut m = active_member(hex_id, GroupRole::Member);
        m.state = GroupMemberState::Banned;
        m
    }

    fn open_policy() -> GroupPolicy {
        GroupPolicyPreset::PublicOpen.to_policy()
    }

    fn announce_policy() -> GroupPolicy {
        GroupPolicyPreset::PublicAnnounce.to_policy()
    }

    fn build_signed_msg(
        kp: &AgentKeypair,
        group_id: &str,
        body: &str,
        kind: GroupPublicMessageKind,
    ) -> GroupPublicMessage {
        GroupPublicMessage::sign(
            group_id.to_string(),
            "state-hash-1".into(),
            1,
            kp,
            None,
            kind,
            body.to_string(),
            1_000,
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn public_topic_format() {
        assert_eq!(public_topic_for("abc123"), "x0x.groups.public.abc123");
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = make_kp();
        let msg = build_signed_msg(&kp, "g1", "hello", GroupPublicMessageKind::Chat);
        msg.verify_signature().unwrap();
    }

    #[test]
    fn verify_detects_body_tamper() {
        let kp = make_kp();
        let mut msg = build_signed_msg(&kp, "g1", "original", GroupPublicMessageKind::Chat);
        msg.body = "tampered".into();
        assert!(msg.verify_signature().is_err());
    }

    #[test]
    fn verify_detects_group_id_swap() {
        let kp = make_kp();
        let mut msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        msg.group_id = "g-different".into();
        assert!(msg.verify_signature().is_err());
    }

    #[test]
    fn verify_detects_kind_change() {
        let kp = make_kp();
        let mut msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        msg.kind = GroupPublicMessageKind::Announcement;
        assert!(msg.verify_signature().is_err());
    }

    #[test]
    fn verify_detects_author_swap() {
        let kp1 = make_kp();
        let kp2 = make_kp();
        let mut msg = build_signed_msg(&kp1, "g1", "x", GroupPublicMessageKind::Chat);
        msg.author_agent_id = hex::encode(kp2.agent_id().as_bytes());
        assert!(msg.verify_signature().is_err());
    }

    #[test]
    fn verify_detects_state_hash_tamper() {
        let kp = make_kp();
        let mut msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        msg.state_hash_at_send = "state-hash-tampered".into();
        assert!(msg.verify_signature().is_err());
    }

    #[test]
    fn verify_detects_revision_tamper() {
        let kp = make_kp();
        let mut msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        msg.revision_at_send = 99;
        assert!(msg.verify_signature().is_err());
    }

    #[test]
    fn verify_detects_timestamp_tamper() {
        let kp = make_kp();
        let mut msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        msg.timestamp = 42_424;
        assert!(msg.verify_signature().is_err());
    }

    #[test]
    fn verify_detects_user_id_tamper() {
        let kp = make_kp();
        let mut msg = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &kp,
            Some("deadbeef".into()),
            GroupPublicMessageKind::Chat,
            "x".into(),
            1_000,
            None,
            None,
            None,
        )
        .unwrap();
        msg.author_user_id = Some("cafebabe".into());
        assert!(msg.verify_signature().is_err());
    }

    #[test]
    fn ingest_rejects_group_id_mismatch() {
        let kp = make_kp();
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        let policy = open_policy();
        let members = BTreeMap::new();
        let ctx = PublicIngestContext {
            group_id: "g-different",
            policy: &policy,
            members_v2: &members,
        };
        assert!(matches!(
            validate_public_message(&ctx, &msg).unwrap_err(),
            IngestError::GroupIdMismatch { .. }
        ));
    }

    #[test]
    fn ingest_rejects_mls_encrypted_group() {
        let kp = make_kp();
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        let mut policy = open_policy();
        policy.confidentiality = GroupConfidentiality::MlsEncrypted;
        let members = BTreeMap::new();
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        assert!(matches!(
            validate_public_message(&ctx, &msg).unwrap_err(),
            IngestError::ConfidentialityMismatch
        ));
    }

    #[test]
    fn ingest_rejects_oversized_body() {
        let kp = make_kp();
        let huge = "a".repeat(MAX_PUBLIC_MESSAGE_BYTES + 1);
        let msg = build_signed_msg(&kp, "g1", &huge, GroupPublicMessageKind::Chat);
        let policy = open_policy();
        let members = BTreeMap::new();
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        assert!(matches!(
            validate_public_message(&ctx, &msg).unwrap_err(),
            IngestError::MessageTooLarge { .. }
        ));
    }

    #[test]
    fn ingest_members_only_accepts_active_member() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        let policy = open_policy(); // MembersOnly write_access
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), active_member(&hex_id, GroupRole::Member));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        validate_public_message(&ctx, &msg).unwrap();
    }

    #[test]
    fn ingest_members_only_rejects_non_member() {
        let kp = make_kp();
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        let policy = open_policy();
        let members = BTreeMap::new(); // author not present
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        let err = validate_public_message(&ctx, &msg).unwrap_err();
        assert!(matches!(err, IngestError::WritePolicyViolation { .. }));
    }

    /// Build a REAL sub-agent-signed delegation (the harness's job in
    /// production): owner cert over the sub key, capability signed by
    /// the sub key.
    fn make_delegation(
        sub_kp: &AgentKeypair,
        daemon_hex: &str,
        scopes: &[&str],
    ) -> RiderDelegation {
        use base64::Engine as _;
        let owner = crate::identity::UserKeypair::generate().unwrap();
        let cert = crate::identity::AgentCertificate::issue_for_public_key(
            &owner,
            sub_kp.public_key().as_bytes(),
            None,
        )
        .unwrap();
        let sub_hex = hex::encode(sub_kp.agent_id().as_bytes());
        let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
        let not_after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3_600;
        let payload = rider_delegation_bytes(&sub_hex, daemon_hex, &scopes, not_after);
        let sig = sign_with_ml_dsa(sub_kp.secret_key(), &payload).unwrap();
        RiderDelegation {
            cert_b64: base64::engine::general_purpose::STANDARD
                .encode(cert.to_storage_bytes().unwrap()),
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&payload),
            signature: hex::encode(sig.as_bytes()),
        }
    }

    #[test]
    fn ingest_enforces_policy_against_rider_provenance_sub_agent() {
        // WHY (review fix #1, receiver side): a daemon-signed rider
        // message must be authorized by the SUB-AGENT named in the
        // provenance envelope, never by the daemon author. The daemon
        // here IS an active member; the provenance sub-agent is not —
        // ingest must reject. With the sub-agent admitted, it passes.
        let daemon_kp = make_kp();
        let sub_kp = make_kp();
        let daemon_hex = hex::encode(daemon_kp.agent_id().as_bytes());
        let sub_hex = hex::encode(sub_kp.agent_id().as_bytes());
        let delegation = make_delegation(&sub_kp, &daemon_hex, &["g1"]);
        let msg = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &daemon_kp,
            None,
            GroupPublicMessageKind::Chat,
            "x".into(),
            1_000,
            None,
            None,
            Some(RiderProvenance {
                sub_agent_id: sub_hex.clone(),
                rider_token_id: 1,
                rider_token_hash: "ab".repeat(32),
                scope: "g1".into(),
                delegation,
            }),
        )
        .unwrap();
        let policy = open_policy(); // MembersOnly write_access

        // Daemon is a member, provenance sub-agent is NOT → reject.
        let mut members = BTreeMap::new();
        members.insert(
            daemon_hex.clone(),
            active_member(&daemon_hex, GroupRole::Admin),
        );
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        assert!(matches!(
            validate_public_message(&ctx, &msg),
            Err(IngestError::WritePolicyViolation { .. })
        ));

        // Admit the sub-agent as a plain member → accept.
        members.insert(sub_hex.clone(), active_member(&sub_hex, GroupRole::Member));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        validate_public_message(&ctx, &msg).unwrap();
    }

    #[test]
    fn ingest_admin_only_rider_provenance_needs_sub_agent_admin_role() {
        // WHY: same principle under AdminOnly — the DAEMON author's
        // admin role must not carry a rider whose sub-agent is a mere
        // member.
        let daemon_kp = make_kp();
        let sub_kp = make_kp();
        let daemon_hex = hex::encode(daemon_kp.agent_id().as_bytes());
        let sub_hex = hex::encode(sub_kp.agent_id().as_bytes());
        let delegation = make_delegation(&sub_kp, &daemon_hex, &["g1"]);
        let msg = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &daemon_kp,
            None,
            GroupPublicMessageKind::Chat,
            "x".into(),
            1_000,
            None,
            None,
            Some(RiderProvenance {
                sub_agent_id: sub_hex.clone(),
                rider_token_id: 1,
                rider_token_hash: "ab".repeat(32),
                scope: "g1".into(),
                delegation,
            }),
        )
        .unwrap();
        let mut policy = open_policy();
        policy.write_access = GroupWriteAccess::AdminOnly;
        let mut members = BTreeMap::new();
        members.insert(
            daemon_hex.clone(),
            active_member(&daemon_hex, GroupRole::Owner),
        );
        members.insert(sub_hex.clone(), active_member(&sub_hex, GroupRole::Member));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        assert!(matches!(
            validate_public_message(&ctx, &msg),
            Err(IngestError::WritePolicyViolation { .. })
        ));
    }

    #[test]
    fn ingest_rejects_unauthenticated_rider_provenance_forgery() {
        // WHY (review r3, the CRITICAL): a validly daemon-signed message
        // whose provenance CLAIMS a member sub-agent but is NOT backed
        // by that sub-agent's cryptographic delegation must be rejected.
        // Otherwise ANY daemon could impersonate any member/admin by
        // fabricating the provenance string. Three forgery shapes:
        // no delegation bytes at all, a delegation signed by a DIFFERENT
        // sub-agent's key, and a delegation naming another daemon.
        let daemon_kp = make_kp();
        let victim_kp = make_kp(); // the member identity being impersonated
        let attacker_kp = make_kp(); // signs the delegation
        let daemon_hex = hex::encode(daemon_kp.agent_id().as_bytes());
        let victim_hex = hex::encode(victim_kp.agent_id().as_bytes());
        let mut members = BTreeMap::new();
        members.insert(
            daemon_hex.clone(),
            active_member(&daemon_hex, GroupRole::Member),
        );
        members.insert(
            victim_hex.clone(),
            active_member(&victim_hex, GroupRole::Admin),
        );
        let policy = open_policy();

        // Forge 1: provenance with a delegation signed by the ATTACKER's
        // key while claiming the VICTIM sub-agent id.
        let attacker_delegation = make_delegation(&attacker_kp, &daemon_hex, &["g1"]);
        let forged = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &daemon_kp,
            None,
            GroupPublicMessageKind::Chat,
            "forged".into(),
            1_000,
            None,
            None,
            Some(RiderProvenance {
                sub_agent_id: victim_hex.clone(),
                rider_token_id: 1,
                rider_token_hash: "ab".repeat(32),
                scope: "g1".into(),
                delegation: attacker_delegation,
            }),
        )
        .unwrap();
        // The daemon signature is genuinely valid…
        forged.verify_signature().unwrap();
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        // …but ingest must reject the unauthenticated provenance.
        assert!(matches!(
            validate_public_message(&ctx, &forged),
            Err(IngestError::InvalidSignature(_))
        ));

        // Forge 2: a legitimate victim-signed delegation that names a
        // DIFFERENT daemon — this daemon is not the delegated signer.
        let other_daemon = make_kp();
        let other_daemon_hex = hex::encode(other_daemon.agent_id().as_bytes());
        let cross_delegation = make_delegation(&victim_kp, &other_daemon_hex, &["g1"]);
        let forged = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &daemon_kp,
            None,
            GroupPublicMessageKind::Chat,
            "forged 2".into(),
            1_000,
            None,
            None,
            Some(RiderProvenance {
                sub_agent_id: victim_hex.clone(),
                rider_token_id: 1,
                rider_token_hash: "ab".repeat(32),
                scope: "g1".into(),
                delegation: cross_delegation,
            }),
        )
        .unwrap();
        assert!(matches!(
            validate_public_message(&ctx, &forged),
            Err(IngestError::InvalidSignature(_))
        ));

        // Forge 3: victim-signed delegation scoped to a DIFFERENT group.
        let other_scope_delegation = make_delegation(&victim_kp, &daemon_hex, &["g-other"]);
        let forged = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &daemon_kp,
            None,
            GroupPublicMessageKind::Chat,
            "forged 3".into(),
            1_000,
            None,
            None,
            Some(RiderProvenance {
                sub_agent_id: victim_hex.clone(),
                rider_token_id: 1,
                rider_token_hash: "ab".repeat(32),
                scope: "g1".into(),
                delegation: other_scope_delegation,
            }),
        )
        .unwrap();
        assert!(matches!(
            validate_public_message(&ctx, &forged),
            Err(IngestError::InvalidSignature(_))
        ));

        // Control: a genuine victim-signed delegation to THIS daemon for
        // THIS group passes ingest (victim is an admin member).
        let genuine = make_delegation(&victim_kp, &daemon_hex, &["g1"]);
        let legit = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &daemon_kp,
            None,
            GroupPublicMessageKind::Chat,
            "legit".into(),
            1_000,
            None,
            None,
            Some(RiderProvenance {
                sub_agent_id: victim_hex.clone(),
                rider_token_id: 1,
                rider_token_hash: "ab".repeat(32),
                scope: "g1".into(),
                delegation: genuine,
            }),
        )
        .unwrap();
        validate_public_message(&ctx, &legit).unwrap();
    }

    #[test]
    fn ingest_rejects_banned_author() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        let policy = open_policy();
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), banned_member(&hex_id));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        assert!(matches!(
            validate_public_message(&ctx, &msg).unwrap_err(),
            IngestError::AuthorBanned
        ));
    }

    #[test]
    fn ingest_moderated_public_accepts_non_member() {
        let kp = make_kp();
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        let mut policy = open_policy();
        policy.write_access = GroupWriteAccess::ModeratedPublic;
        let members = BTreeMap::new();
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        validate_public_message(&ctx, &msg).unwrap();
    }

    #[test]
    fn ingest_moderated_public_rejects_banned() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        let mut policy = open_policy();
        policy.write_access = GroupWriteAccess::ModeratedPublic;
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), banned_member(&hex_id));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        assert!(matches!(
            validate_public_message(&ctx, &msg).unwrap_err(),
            IngestError::AuthorBanned
        ));
    }

    #[test]
    fn ingest_admin_only_rejects_plain_member() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Announcement);
        let policy = announce_policy();
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), active_member(&hex_id, GroupRole::Member));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        assert!(matches!(
            validate_public_message(&ctx, &msg).unwrap_err(),
            IngestError::WritePolicyViolation { .. }
        ));
    }

    #[test]
    fn ingest_admin_only_accepts_admin() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Announcement);
        let policy = announce_policy();
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), active_member(&hex_id, GroupRole::Admin));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        validate_public_message(&ctx, &msg).unwrap();
    }

    #[test]
    fn ingest_admin_only_accepts_owner() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        let msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Announcement);
        let policy = announce_policy();
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), active_member(&hex_id, GroupRole::Owner));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        validate_public_message(&ctx, &msg).unwrap();
    }

    #[test]
    fn public_open_preset_shape_is_signed_public() {
        let p = GroupPolicyPreset::PublicOpen.to_policy();
        assert_eq!(p.confidentiality, GroupConfidentiality::SignedPublic);
        assert_eq!(p.discoverability, GroupDiscoverability::PublicDirectory);
        assert_eq!(p.admission, GroupAdmission::OpenJoin);
        assert_eq!(p.read_access, GroupReadAccess::Public);
        assert_eq!(p.write_access, GroupWriteAccess::MembersOnly);
    }

    #[test]
    fn public_announce_preset_is_admin_only_write() {
        let p = GroupPolicyPreset::PublicAnnounce.to_policy();
        assert_eq!(p.write_access, GroupWriteAccess::AdminOnly);
        assert_eq!(p.read_access, GroupReadAccess::Public);
    }

    // ── ADR-0029 threading tests ─────────────────────────────────────────

    /// v1 byte-identity: a message without thread fields must produce
    /// signable_bytes starting with the v1 domain — no v2 suffix.
    #[test]
    fn v1_byte_identity_no_thread_fields() {
        let kp = make_kp();
        let msg = build_signed_msg(&kp, "g1", "hello", GroupPublicMessageKind::Chat);
        assert!(msg.thread_root.is_none());
        assert!(msg.thread_parent.is_none());
        let bytes = msg.signable_bytes();
        assert!(
            bytes.starts_with(PUBLIC_MESSAGE_DOMAIN),
            "non-threaded message must use v1 domain"
        );
        // Must NOT contain the v2 domain bytes anywhere in the prefix position
        assert!(!bytes.starts_with(PUBLIC_MESSAGE_DOMAIN_V2));
    }

    /// v2 domain: a threaded message uses the v2 domain.
    #[test]
    fn threaded_message_uses_v2_domain() {
        let kp = make_kp();
        let fake_root = "a".repeat(64);
        let msg = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &kp,
            None,
            GroupPublicMessageKind::Chat,
            "reply".into(),
            2_000,
            Some(fake_root.clone()),
            Some(fake_root),
            None,
        )
        .unwrap();
        let bytes = msg.signable_bytes();
        assert!(
            bytes.starts_with(PUBLIC_MESSAGE_DOMAIN_V2),
            "threaded message must use v2 domain"
        );
        assert!(!bytes.starts_with(PUBLIC_MESSAGE_DOMAIN));
    }

    /// Fail-closed: a threaded message verified with manually constructed
    /// v1-style bytes must fail (old-node simulation).
    #[test]
    fn threaded_message_fails_v1_verification() {
        let kp = make_kp();
        let fake_root = "b".repeat(64);
        let mut msg = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &kp,
            None,
            GroupPublicMessageKind::Chat,
            "reply".into(),
            3_000,
            Some(fake_root.clone()),
            Some(fake_root),
            None,
        )
        .unwrap();
        // Simulate an old node by stripping thread fields AFTER signing —
        // the signature was computed over v2 bytes but we now present v1 bytes.
        msg.thread_root = None;
        msg.thread_parent = None;
        // verify_signature recomputes v1 bytes (both None) — should fail.
        assert!(
            msg.verify_signature().is_err(),
            "stripping thread fields from a v2-signed message must fail"
        );
    }

    /// Tamper — adding thread fields to a v1-signed message fails.
    #[test]
    fn adding_thread_to_v1_message_fails() {
        let kp = make_kp();
        let mut msg = build_signed_msg(&kp, "g1", "original", GroupPublicMessageKind::Chat);
        msg.verify_signature().unwrap(); // baseline passes
        msg.thread_root = Some("c".repeat(64));
        assert!(
            msg.verify_signature().is_err(),
            "injecting thread_root into v1-signed message must fail"
        );
    }

    /// Tamper — clearing thread fields from a v2-signed message fails.
    #[test]
    fn clearing_thread_from_v2_message_fails() {
        let kp = make_kp();
        let fake_root = "d".repeat(64);
        let mut msg = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &kp,
            None,
            GroupPublicMessageKind::Chat,
            "post".into(),
            4_000,
            Some(fake_root.clone()),
            Some(fake_root),
            None,
        )
        .unwrap();
        msg.verify_signature().unwrap(); // baseline passes
        msg.thread_root = None;
        msg.thread_parent = None;
        assert!(
            msg.verify_signature().is_err(),
            "stripping thread fields from v2-signed message must fail"
        );
    }

    /// msg_id determinism: same inputs → same id.
    #[test]
    fn msg_id_is_deterministic() {
        let kp = make_kp();
        let msg = build_signed_msg(&kp, "g1", "hello", GroupPublicMessageKind::Chat);
        assert_eq!(msg.msg_id(), msg.msg_id(), "msg_id must be deterministic");
    }

    /// msg_id differs when body differs.
    #[test]
    fn msg_id_differs_on_different_body() {
        let kp = make_kp();
        let msg1 = build_signed_msg(&kp, "g1", "hello", GroupPublicMessageKind::Chat);
        let msg2 = build_signed_msg(&kp, "g1", "world", GroupPublicMessageKind::Chat);
        assert_ne!(msg1.msg_id(), msg2.msg_id());
    }

    /// msg_id is exactly 64 lowercase hex chars.
    #[test]
    fn msg_id_format() {
        let kp = make_kp();
        let msg = build_signed_msg(&kp, "g1", "test", GroupPublicMessageKind::Chat);
        let id = msg.msg_id();
        assert_eq!(id.len(), 64);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    /// Ingest: bad hex rejected.
    #[test]
    fn ingest_rejects_bad_thread_hex() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        // Build a valid v1 message then manually inject a bad thread_root.
        // Thread structural checks now run BEFORE signature verification, so
        // InvalidThreadField fires first (cheap reject, no crypto cost).
        let mut msg = build_signed_msg(&kp, "g1", "x", GroupPublicMessageKind::Chat);
        msg.thread_root = Some("not-hex".to_string()); // too short and not hex
        let policy = open_policy();
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), active_member(&hex_id, GroupRole::Member));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        assert!(matches!(
            validate_public_message(&ctx, &msg).unwrap_err(),
            IngestError::InvalidThreadField { .. }
        ));
    }

    /// Ingest: parent-without-root rejected (pre-signature structural check).
    #[test]
    fn ingest_rejects_parent_without_root() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        // Sign with root+parent, then strip root after signing.
        let fake_root = "e".repeat(64);
        let mut msg = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &kp,
            None,
            GroupPublicMessageKind::Chat,
            "reply".into(),
            5_000,
            Some(fake_root.clone()),
            Some(fake_root),
            None,
        )
        .unwrap();
        // Strip root — now parent is present without root.
        msg.thread_root = None;
        let policy = open_policy();
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), active_member(&hex_id, GroupRole::Member));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        // Thread structural checks run BEFORE signature verification.
        // ThreadParentWithoutRoot fires as a cheap early reject; the
        // tampered signature is never computed.
        assert!(matches!(
            validate_public_message(&ctx, &msg).unwrap_err(),
            IngestError::ThreadParentWithoutRoot
        ));
    }

    /// Ingest: orphan parent accepted (parent not known locally is fine).
    #[test]
    fn ingest_accepts_orphan_parent() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        let fake_root = "f".repeat(64);
        let fake_parent = "1".repeat(64);
        let msg = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &kp,
            None,
            GroupPublicMessageKind::Chat,
            "orphaned reply".into(),
            6_000,
            Some(fake_root),
            Some(fake_parent),
            None,
        )
        .unwrap();
        let policy = open_policy();
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), active_member(&hex_id, GroupRole::Member));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        // Must succeed — the parent not being locally known is fine (ADR-0028).
        validate_public_message(&ctx, &msg).unwrap();
    }

    /// Ingest: self-reference check is live pre-signature (after fix 2) and
    /// serves as a cheap early reject. Because `msg_id()` = BLAKE3(signable_bytes)
    /// and `signable_bytes` INCLUDES `thread_root`, a genuinely self-referential
    /// message requires a BLAKE3 fixed point (x = BLAKE3(f(x))) — computationally
    /// infeasible. When we set `thread_root = own_id` after signing, `msg_id()`
    /// changes (different input bytes), so the self-reference check does NOT fire;
    /// the tampered signature is what the validator rejects. This test verifies the
    /// end-to-end rejection and documents the hash-circularity property.
    #[test]
    fn ingest_rejects_self_reference() {
        let kp = make_kp();
        let hex_id = hex::encode(kp.agent_id().as_bytes());
        // Sign a non-threaded message first to get a stable msg_id.
        let base = build_signed_msg(&kp, "g1", "base", GroupPublicMessageKind::Chat);
        let base_id = base.msg_id();
        // Sign a threaded message with root = base_id. Its own msg_id is the
        // BLAKE3 of v2 signable bytes with thread_root=base_id.
        let mut msg = GroupPublicMessage::sign(
            "g1".into(),
            "state-hash-1".into(),
            1,
            &kp,
            None,
            GroupPublicMessageKind::Chat,
            "self ref".into(),
            7_000,
            Some(base_id.clone()),
            None,
            None,
        )
        .unwrap();
        // Capture own_id BEFORE tampering. After we set thread_root = own_id,
        // msg_id() will recompute from the new (tampered) signable_bytes and
        // produce a DIFFERENT value — the self-reference check passes; sig fails.
        let own_id = msg.msg_id();
        msg.thread_root = Some(own_id);
        let policy = open_policy();
        let mut members = BTreeMap::new();
        members.insert(hex_id.clone(), active_member(&hex_id, GroupRole::Member));
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        // Self-reference check is reachable only for messages whose signature
        // would fail anyway (BLAKE3 fixed-point property). Tampering thread_root
        // changes signable_bytes, so msg_id() ≠ old own_id and the self-reference
        // check does not fire; InvalidSignature is the actual early reject here.
        assert!(matches!(
            validate_public_message(&ctx, &msg).unwrap_err(),
            IngestError::InvalidSignature(_)
        ));
    }
}
