//! ADR-0016 Phase 1 Slice 4: invite issue authority and creator provenance.
//!
//! These tests keep the non-daemon invite contract gate-runnable. The helper
//! mirrors the daemon invite handler's role check, metadata snapshotting, and
//! per-issuer secret tracking without starting a mesh-backed `x0xd`.
//! Real-daemon coverage lives in
//! `non_creator_admin_invite_e2e_converges_through_real_daemons`.

use x0x::groups::invite::{SignedInvite, DEFAULT_EXPIRY_SECS};
use x0x::groups::{GroupInfo, GroupPolicyPreset, GroupRole};
use x0x::identity::AgentKeypair;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InviteIssueError {
    Forbidden(&'static str),
}

fn hex_id(kp: &AgentKeypair) -> String {
    hex::encode(kp.agent_id().as_bytes())
}

fn admin_group(creator_kp: &AgentKeypair, name: &str) -> GroupInfo {
    GroupInfo::with_policy(
        name.to_string(),
        "desc".into(),
        creator_kp.agent_id(),
        "aa".repeat(16),
        GroupPolicyPreset::PublicOpen.to_policy(),
    )
}

fn group_with_promoted_admin(creator: &AgentKeypair, admin: &AgentKeypair) -> GroupInfo {
    let mut info = admin_group(creator, "T");
    let creator_hex = hex_id(creator);
    let admin_hex = hex_id(admin);
    info.add_member(
        admin_hex,
        GroupRole::Admin,
        Some(creator_hex),
        Some("promoted admin".into()),
    );
    info.roster_revision = info.roster_revision.saturating_add(1);
    info.recompute_state_hash();
    info
}

fn require_admin_invite_semantics(
    info: &GroupInfo,
    actor_hex: &str,
) -> Result<(), InviteIssueError> {
    if info
        .caller_role(actor_hex)
        .is_some_and(|role| role.at_least(GroupRole::Admin))
    {
        Ok(())
    } else {
        Err(InviteIssueError::Forbidden("admin role required"))
    }
}

fn issue_invite_semantics(
    info: &mut GroupInfo,
    inviter: &AgentKeypair,
) -> Result<SignedInvite, InviteIssueError> {
    let inviter_hex = hex_id(inviter);
    require_admin_invite_semantics(info, &inviter_hex)?;

    let mut invite = SignedInvite::new(
        info.mls_group_id.clone(),
        info.name.clone(),
        &inviter.agent_id(),
        DEFAULT_EXPIRY_SECS,
    );
    invite.stable_group_id = Some(info.stable_group_id().to_string());
    invite.group_created_at = Some(info.created_at);
    invite.group_description = Some(info.description.clone());
    invite.policy = Some(info.policy.clone());
    invite.genesis_creation_nonce = info.genesis.as_ref().map(|g| g.creation_nonce.clone());
    invite.base_state_revision = Some(info.state_revision);
    invite.base_state_hash = Some(info.state_hash.clone());
    invite.base_members_v2 = Some(info.members_v2.clone());
    invite.base_prev_state_hash = info.prev_state_hash.clone();
    invite.secure_plane = Some(info.secure_plane);
    invite.base_secret_epoch = Some(info.secret_epoch);
    invite.base_security_binding = info.security_binding.clone();

    info.record_issued_invite(
        invite.invite_secret.clone(),
        invite.created_at,
        invite.expires_at,
        GroupRole::Member,
    );

    Ok(invite)
}

#[test]
fn invite_authority_promoted_non_creator_admin_issues_invite() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let creator_hex = hex_id(&creator);
    let admin_hex = hex_id(&admin);
    let mut info = group_with_promoted_admin(&creator, &admin);

    let invite = issue_invite_semantics(&mut info, &admin)
        .expect("promoted non-creator admin can issue invite");

    assert_eq!(invite.inviter, admin_hex);
    assert_eq!(
        invite
            .creator_agent_id_from_base_state()
            .expect("derive genesis creator from invite base state"),
        creator_hex
    );
    assert!(
        info.issued_invites.contains_key(&invite.invite_secret),
        "secret must be tracked on the issuing daemon/inviter"
    );
}

#[test]
fn invite_authority_plain_member_cannot_issue_invite() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let mut info = group_with_promoted_admin(&creator, &admin);
    info.add_member(
        hex_id(&member),
        GroupRole::Member,
        Some(hex_id(&creator)),
        None,
    );
    info.recompute_state_hash();

    let err = issue_invite_semantics(&mut info, &member).unwrap_err();

    assert_eq!(err, InviteIssueError::Forbidden("admin role required"));
    assert!(
        info.issued_invites.is_empty(),
        "rejected member must not mint or track an invite secret"
    );
}

#[test]
fn invite_authority_creator_issued_invite_still_uses_base_creator() {
    let creator = AgentKeypair::generate().unwrap();
    let creator_hex = hex_id(&creator);
    let mut info = admin_group(&creator, "T");

    let invite = issue_invite_semantics(&mut info, &creator)
        .expect("creator remains an admin and can issue invite");

    assert_eq!(invite.inviter, creator_hex);
    assert_eq!(
        invite
            .creator_agent_id_from_base_state()
            .expect("derive genesis creator from invite base state"),
        creator_hex
    );
    assert!(info.issued_invites.contains_key(&invite.invite_secret));
}
