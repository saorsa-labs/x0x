//! Phase E integration tests: public-group messaging.
//!
//! Pure Rust tests over the `public_message` module — no daemon
//! required. These prove the ingest truth-table across all write-access
//! policies plus all the signature / state binding invariants.

use std::collections::BTreeMap;
use x0x::groups::{
    public_message::IngestError, public_topic_for, validate_public_message, GroupMember,
    GroupMemberState, GroupPolicyPreset, GroupPublicMessage, GroupPublicMessageKind, GroupRole,
    GroupWriteAccess, PublicIngestContext, MAX_PUBLIC_MESSAGE_BYTES,
};
use x0x::identity::AgentKeypair;

fn active(hex_id: &str, role: GroupRole) -> GroupMember {
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

fn banned(hex_id: &str) -> GroupMember {
    let mut m = active(hex_id, GroupRole::Member);
    m.state = GroupMemberState::Banned;
    m
}

fn sign_msg(
    kp: &AgentKeypair,
    group_id: &str,
    body: &str,
    kind: GroupPublicMessageKind,
) -> GroupPublicMessage {
    GroupPublicMessage::sign(
        group_id.into(),
        "state-hash".into(),
        1,
        kp,
        None,
        kind,
        body.into(),
        1_000,
    )
    .unwrap()
}

#[test]
fn topic_format_is_stable() {
    assert_eq!(public_topic_for("g1"), "x0x.groups.public.g1");
    assert_eq!(public_topic_for("aabbccdd"), "x0x.groups.public.aabbccdd");
}

#[test]
fn sign_verify_end_to_end() {
    let kp = AgentKeypair::generate().unwrap();
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Chat);
    msg.verify_signature().unwrap();
}

#[test]
fn public_open_members_only_accepts_active_member() {
    let kp = AgentKeypair::generate().unwrap();
    let hex_id = hex::encode(kp.agent_id().as_bytes());
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Chat);
    let policy = GroupPolicyPreset::PublicOpen.to_policy();
    let mut members = BTreeMap::new();
    members.insert(hex_id.clone(), active(&hex_id, GroupRole::Member));
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    validate_public_message(&ctx, &msg).unwrap();
}

#[test]
fn public_open_rejects_non_member() {
    let kp = AgentKeypair::generate().unwrap();
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Chat);
    let policy = GroupPolicyPreset::PublicOpen.to_policy();
    let members = BTreeMap::new();
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    let err = validate_public_message(&ctx, &msg).unwrap_err();
    assert!(matches!(err, IngestError::WritePolicyViolation { .. }));
}

#[test]
fn banned_author_rejected_in_every_mode() {
    let kp = AgentKeypair::generate().unwrap();
    let hex_id = hex::encode(kp.agent_id().as_bytes());
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Chat);
    let mut members = BTreeMap::new();
    members.insert(hex_id.clone(), banned(&hex_id));

    for wa in [
        GroupWriteAccess::MembersOnly,
        GroupWriteAccess::ModeratedPublic,
        GroupWriteAccess::AdminOnly,
    ] {
        let mut policy = GroupPolicyPreset::PublicOpen.to_policy();
        policy.write_access = wa;
        let ctx = PublicIngestContext {
            group_id: "g1",
            policy: &policy,
            members_v2: &members,
        };
        let err = validate_public_message(&ctx, &msg).unwrap_err();
        assert!(
            matches!(err, IngestError::AuthorBanned),
            "banned rejection must come from AuthorBanned under {wa:?}"
        );
    }
}

#[test]
fn moderated_public_accepts_unknown_non_banned() {
    let kp = AgentKeypair::generate().unwrap();
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Chat);
    let mut policy = GroupPolicyPreset::PublicOpen.to_policy();
    policy.write_access = GroupWriteAccess::ModeratedPublic;
    let members = BTreeMap::new(); // author not in roster
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    validate_public_message(&ctx, &msg).unwrap();
}

#[test]
fn admin_only_rejects_plain_member() {
    let kp = AgentKeypair::generate().unwrap();
    let hex_id = hex::encode(kp.agent_id().as_bytes());
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Announcement);
    let policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    let mut members = BTreeMap::new();
    members.insert(hex_id.clone(), active(&hex_id, GroupRole::Member));
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    let err = validate_public_message(&ctx, &msg).unwrap_err();
    assert!(matches!(err, IngestError::WritePolicyViolation { .. }));
}

#[test]
fn admin_only_accepts_admin() {
    let kp = AgentKeypair::generate().unwrap();
    let hex_id = hex::encode(kp.agent_id().as_bytes());
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Announcement);
    let policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    let mut members = BTreeMap::new();
    members.insert(hex_id.clone(), active(&hex_id, GroupRole::Admin));
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    validate_public_message(&ctx, &msg).unwrap();
}

#[test]
fn admin_only_accepts_owner() {
    let kp = AgentKeypair::generate().unwrap();
    let hex_id = hex::encode(kp.agent_id().as_bytes());
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Announcement);
    let policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    let mut members = BTreeMap::new();
    members.insert(hex_id.clone(), active(&hex_id, GroupRole::Owner));
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    validate_public_message(&ctx, &msg).unwrap();
}

#[test]
fn mls_encrypted_rejects_public_message() {
    let kp = AgentKeypair::generate().unwrap();
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Chat);
    let policy = GroupPolicyPreset::PrivateSecure.to_policy(); // MlsEncrypted
    let members = BTreeMap::new();
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    let err = validate_public_message(&ctx, &msg).unwrap_err();
    assert!(matches!(err, IngestError::ConfidentialityMismatch));
}

#[test]
fn group_id_mismatch_rejected() {
    let kp = AgentKeypair::generate().unwrap();
    let msg = sign_msg(&kp, "g1", "hi", GroupPublicMessageKind::Chat);
    let policy = GroupPolicyPreset::PublicOpen.to_policy();
    let members = BTreeMap::new();
    let ctx = PublicIngestContext {
        group_id: "g-other",
        policy: &policy,
        members_v2: &members,
    };
    let err = validate_public_message(&ctx, &msg).unwrap_err();
    assert!(matches!(err, IngestError::GroupIdMismatch { .. }));
}

#[test]
fn tampered_body_breaks_signature() {
    let kp = AgentKeypair::generate().unwrap();
    let mut msg = sign_msg(&kp, "g1", "original", GroupPublicMessageKind::Chat);
    msg.body = "tampered".into();
    let policy = GroupPolicyPreset::PublicOpen.to_policy();
    let hex_id = hex::encode(kp.agent_id().as_bytes());
    let mut members = BTreeMap::new();
    members.insert(hex_id.clone(), active(&hex_id, GroupRole::Member));
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    let err = validate_public_message(&ctx, &msg).unwrap_err();
    assert!(matches!(err, IngestError::InvalidSignature(_)));
}

#[test]
fn oversized_body_rejected() {
    let kp = AgentKeypair::generate().unwrap();
    let huge = "a".repeat(MAX_PUBLIC_MESSAGE_BYTES + 1);
    let msg = sign_msg(&kp, "g1", &huge, GroupPublicMessageKind::Chat);
    let policy = GroupPolicyPreset::PublicOpen.to_policy();
    let members = BTreeMap::new();
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    let err = validate_public_message(&ctx, &msg).unwrap_err();
    assert!(matches!(err, IngestError::MessageTooLarge { .. }));
}

#[test]
fn author_swap_breaks_signature() {
    let kp1 = AgentKeypair::generate().unwrap();
    let kp2 = AgentKeypair::generate().unwrap();
    let mut msg = sign_msg(&kp1, "g1", "hi", GroupPublicMessageKind::Chat);
    msg.author_agent_id = hex::encode(kp2.agent_id().as_bytes());
    // Keep the original public_key so the derived != claimed AgentId
    // test trips.
    let policy = GroupPolicyPreset::PublicOpen.to_policy();
    let mut members = BTreeMap::new();
    let kp1_hex = hex::encode(kp1.agent_id().as_bytes());
    members.insert(kp1_hex.clone(), active(&kp1_hex, GroupRole::Member));
    let ctx = PublicIngestContext {
        group_id: "g1",
        policy: &policy,
        members_v2: &members,
    };
    let err = validate_public_message(&ctx, &msg).unwrap_err();
    assert!(matches!(err, IngestError::InvalidSignature(_)));
}
