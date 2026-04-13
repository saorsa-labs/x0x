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

/// Domain-separation tag for public-message signatures.
pub const PUBLIC_MESSAGE_DOMAIN: &[u8] = b"x0x.group.public-message.v1";

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
    /// Hex ML-DSA-65 signature over `signable_bytes()`.
    pub signature: String,
}

impl GroupPublicMessage {
    /// Canonical bytes signed by the author to produce `signature`.
    ///
    /// Includes every field except `signature` itself.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512 + self.body.len());
        buf.extend_from_slice(PUBLIC_MESSAGE_DOMAIN);
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
        buf
    }

    /// Build and sign a new public message.
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

    // 4. signature + author binding
    msg.verify_signature()
        .map_err(|e| IngestError::InvalidSignature(format!("{e}")))?;

    // 5. banned authors rejected
    if let Some(member) = ctx.members_v2.get(&msg.author_agent_id) {
        if member.state == GroupMemberState::Banned {
            return Err(IngestError::AuthorBanned);
        }
    }

    // 6. write-access policy enforcement
    let author_role = ctx
        .members_v2
        .get(&msg.author_agent_id)
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
}
