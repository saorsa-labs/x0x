//! #1105: a SignedPublic member one commit behind can take the committer's
//! bootstrap head when that head is the next link. A snapshot that does not
//! chain is refused.

use super::super::{
    apply_signed_public_revision_catchup, now_millis_u64, signed_public_bootstrap_snapshot,
};

fn sealed_step(
    authority: &crate::identity::AgentKeypair,
    member_hex: &str,
) -> (crate::groups::GroupInfo, crate::groups::GroupInfo) {
    let authority_hex = hex::encode(authority.agent_id().as_bytes());
    let mut group = crate::groups::GroupInfo::with_policy(
        "Catch-up".to_string(),
        String::new(),
        authority.agent_id(),
        "ab".repeat(32),
        crate::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    group.add_member(
        member_hex.to_string(),
        crate::groups::GroupRole::Member,
        Some(authority_hex),
        None,
    );
    group
        .seal_commit(authority, now_millis_u64())
        .expect("first seal");
    let behind = group.clone();
    group.description = "renamed".to_string();
    group
        .seal_commit(authority, now_millis_u64().saturating_add(1))
        .expect("second seal");
    (behind, group)
}

#[test]
fn one_revision_bootstrap_advances_the_installed_group() {
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let member = crate::identity::AgentKeypair::generate().expect("member");
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let (mut behind, ahead) = sealed_step(&authority, &member_hex);
    behind
        .issued_invite_secrets
        .insert("local-invite".to_string());
    let snapshot = signed_public_bootstrap_snapshot(ahead.clone()).expect("snapshot");
    let sender = hex::encode(authority.agent_id().as_bytes());
    let updated = apply_signed_public_revision_catchup(&behind, &snapshot, &sender, &member_hex)
        .expect("chained head applies");
    assert_eq!(updated.state_revision, ahead.state_revision);
    assert_eq!(updated.state_hash, ahead.state_hash);
    assert_eq!(updated.description, "renamed");
    assert!(updated.issued_invite_secrets.contains("local-invite"));
    assert!(
        apply_signed_public_revision_catchup(&ahead, &snapshot, &sender, &member_hex).is_none()
    );
    assert!(
        apply_signed_public_revision_catchup(&behind, &snapshot, &member_hex, &member_hex)
            .is_none(),
        "a member who did not sign the head cannot install it"
    );
}

#[test]
fn a_two_revision_gap_is_not_a_catchup() {
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let member = crate::identity::AgentKeypair::generate().expect("member");
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let (behind, mut ahead) = sealed_step(&authority, &member_hex);
    ahead.description = "again".to_string();
    ahead
        .seal_commit(&authority, now_millis_u64().saturating_add(2))
        .expect("third seal");
    let snapshot = signed_public_bootstrap_snapshot(ahead).expect("snapshot");
    let sender = hex::encode(authority.agent_id().as_bytes());
    assert!(
        apply_signed_public_revision_catchup(&behind, &snapshot, &sender, &member_hex).is_none()
    );
}
