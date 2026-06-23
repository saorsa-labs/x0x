//! ADR-0016 Phase 1 Slice 3: add/remove/ban membership authority.
//!
//! These tests keep the membership-authority contract gate-runnable without a
//! daemon. The REST-semantics helpers below mirror the daemon's role pre-check
//! and clone-first authoring shape; the gossip-apply helper mirrors the signed
//! state-commit validation path used by `x0xd` receivers.

use x0x::groups::state_commit::validate_apply;
use x0x::groups::{
    compute_policy_hash, compute_public_meta_hash, compute_roster_root, last_admin_precheck_error,
    last_admin_self_leave_precheck_error, ActionKind, ApplyContext, ApplyError, GroupInfo,
    GroupPolicyPreset, GroupRole, GroupStateCommit, LAST_ADMIN_PRECHECK_ERROR,
    LAST_ADMIN_SELF_LEAVE_PRECHECK_ERROR,
};
use x0x::identity::AgentKeypair;
use x0x::mls::SecureGroupPlane;

const MISSING_TREEKEM_KEY_PACKAGE: &str = "member is missing TreeKEM KeyPackage";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestError {
    Forbidden(&'static str),
    Conflict(&'static str),
    FailedDependency(&'static str),
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

fn group_with_admin_member_and_target(
    creator: &AgentKeypair,
    admin: &AgentKeypair,
    member: &AgentKeypair,
    target: &AgentKeypair,
) -> GroupInfo {
    let mut info = group_with_promoted_admin(creator, admin);
    let creator_hex = hex_id(creator);
    info.add_member(
        hex_id(member),
        GroupRole::Member,
        Some(creator_hex.clone()),
        None,
    );
    info.add_member(hex_id(target), GroupRole::Member, Some(creator_hex), None);
    info.roster_revision = info.roster_revision.saturating_add(1);
    info.recompute_state_hash();
    info
}

fn legacy_owner_with_promoted_admin(owner: &AgentKeypair, admin: &AgentKeypair) -> GroupInfo {
    let mut info = group_with_promoted_admin(owner, admin);
    info.set_member_role(&hex_id(owner), GroupRole::Owner);
    info.recompute_state_hash();
    info
}

fn require_admin_rest_semantics(info: &GroupInfo, actor_hex: &str) -> Result<(), RestError> {
    if info
        .caller_role(actor_hex)
        .is_some_and(|role| role.at_least(GroupRole::Admin))
    {
        Ok(())
    } else {
        Err(RestError::Forbidden("admin role required"))
    }
}

fn rest_add_member_semantics(
    info: &mut GroupInfo,
    actor: &AgentKeypair,
    target: &AgentKeypair,
) -> Result<GroupStateCommit, RestError> {
    let actor_hex = hex_id(actor);
    let target_hex = hex_id(target);
    require_admin_rest_semantics(info, &actor_hex)?;
    let mut next = info.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    next.add_member(
        target_hex,
        GroupRole::Member,
        Some(actor_hex),
        Some("added".into()),
    );
    let commit = next.seal_commit(actor, 2_000).expect("admin add seals");
    *info = next;
    Ok(commit)
}

fn rest_remove_member_semantics(
    info: &mut GroupInfo,
    actor: &AgentKeypair,
    target_hex: &str,
) -> Result<GroupStateCommit, RestError> {
    let actor_hex = hex_id(actor);
    require_admin_rest_semantics(info, &actor_hex)?;
    if let Some(error) = last_admin_precheck_error(info, |g| g.remove_member(target_hex, None)) {
        return Err(RestError::Conflict(error));
    }
    let mut next = info.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    next.remove_member(target_hex, Some(actor_hex));
    let commit = next.seal_commit(actor, 2_000).expect("admin remove seals");
    *info = next;
    Ok(commit)
}

fn rest_self_leave_semantics(
    info: &mut GroupInfo,
    actor: &AgentKeypair,
) -> Result<GroupStateCommit, RestError> {
    let actor_hex = hex_id(actor);
    if let Some(error) = last_admin_self_leave_precheck_error(info, &actor_hex) {
        return Err(RestError::Conflict(error));
    }
    let mut next = info.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    next.remove_member(&actor_hex, Some(actor_hex.clone()));
    let commit = next
        .seal_commit(actor, 2_000)
        .expect("non-last self-leave seals");
    *info = next;
    Ok(commit)
}

fn rest_ban_member_semantics(
    info: &mut GroupInfo,
    actor: &AgentKeypair,
    target_hex: &str,
) -> Result<GroupStateCommit, RestError> {
    let actor_hex = hex_id(actor);
    require_admin_rest_semantics(info, &actor_hex)?;
    if let Some(error) = last_admin_precheck_error(info, |g| g.ban_member(target_hex, None)) {
        return Err(RestError::Conflict(error));
    }
    let mut next = info.clone();
    next.roster_revision = next.roster_revision.saturating_add(1);
    next.ban_member(target_hex, Some(actor_hex));
    let commit = next.seal_commit(actor, 2_000).expect("admin ban seals");
    *info = next;
    Ok(commit)
}

fn rest_withdraw_semantics(
    info: &mut GroupInfo,
    actor: &AgentKeypair,
) -> Result<GroupStateCommit, RestError> {
    let actor_hex = hex_id(actor);
    require_admin_rest_semantics(info, &actor_hex)?;
    Ok(info
        .seal_withdrawal(actor, 2_000)
        .expect("admin withdrawal seals"))
}

fn treekem_ban_preflight_semantics(
    info: &GroupInfo,
    actor_hex: &str,
    target_hex: &str,
) -> Result<(), RestError> {
    require_admin_rest_semantics(info, actor_hex)?;
    if let Some(error) = last_admin_precheck_error(info, |g| g.ban_member(target_hex, None)) {
        return Err(RestError::Conflict(error));
    }
    if info
        .members_v2
        .get(target_hex)
        .and_then(|member| member.treekem_key_package_b64.as_ref())
        .is_none()
    {
        return Err(RestError::FailedDependency(MISSING_TREEKEM_KEY_PACKAGE));
    }
    Ok(())
}

fn craft_commit(
    parent: &GroupInfo,
    scratch: &GroupInfo,
    signer: &AgentKeypair,
    now_ms: u64,
) -> GroupStateCommit {
    GroupStateCommit::sign(
        parent.stable_group_id().to_string(),
        parent.state_revision + 1,
        Some(parent.state_hash.clone()),
        compute_roster_root(&scratch.members_v2),
        compute_policy_hash(&scratch.policy),
        compute_public_meta_hash(&scratch.public_meta()),
        scratch.security_binding.clone(),
        scratch.withdrawn,
        now_ms,
        signer,
    )
    .expect("sign crafted commit")
}

fn gossip_apply(
    replica: &GroupInfo,
    commit: &GroupStateCommit,
    action_kind: ActionKind,
    mutate: impl FnOnce(&mut GroupInfo),
) -> Result<GroupInfo, ApplyError> {
    let ctx = ApplyContext {
        current_state_hash: &replica.state_hash,
        current_revision: replica.state_revision,
        current_withdrawn: replica.withdrawn,
        members_v2: &replica.members_v2,
        group_id: replica.stable_group_id(),
    };
    validate_apply(&ctx, commit, action_kind)?;
    let mut next = replica.clone();
    mutate(&mut next);
    next.finalize_applied_commit(commit)?;
    Ok(next)
}

#[derive(Debug, PartialEq, Eq)]
enum GroupDeletedEventApplyError {
    ActorMismatch,
    NotWithdrawal,
    Commit(ApplyError),
}

fn apply_group_deleted_event(
    replica: &GroupInfo,
    revision: u64,
    actor: &str,
    commit: &GroupStateCommit,
) -> Result<GroupInfo, GroupDeletedEventApplyError> {
    if actor != commit.committed_by {
        return Err(GroupDeletedEventApplyError::ActorMismatch);
    }
    if !commit.withdrawn {
        return Err(GroupDeletedEventApplyError::NotWithdrawal);
    }
    gossip_apply(replica, commit, ActionKind::AdminOrHigher, |next| {
        next.roster_revision = revision.max(next.roster_revision);
        next.updated_at = commit.committed_at;
    })
    .map_err(GroupDeletedEventApplyError::Commit)
}

fn assert_self_leave_converges(mut authority: GroupInfo, actor: &AgentKeypair) {
    let replica = authority.clone();
    let actor_hex = hex_id(actor);

    let commit = rest_self_leave_semantics(&mut authority, actor).unwrap();

    assert_eq!(commit.committed_by, actor_hex);
    assert!(authority.members_v2[&actor_hex].is_removed());
    assert!(
        authority.active_admin_count() >= 1,
        "self-leave must leave another active admin"
    );

    let next = gossip_apply(&replica, &commit, ActionKind::MemberSelf, |next| {
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.remove_member(&actor_hex, Some(actor_hex.clone()));
    })
    .expect("self-leave applies through signed member-self path");

    assert_eq!(next.state_hash, authority.state_hash);
    assert!(next.members_v2[&actor_hex].is_removed());
}

fn assert_self_leave_conflict_preserves(mut info: GroupInfo, actor: &AgentKeypair) {
    let actor_hex = hex_id(actor);
    let before = info.clone();

    assert_eq!(
        rest_self_leave_semantics(&mut info, actor).unwrap_err(),
        RestError::Conflict(LAST_ADMIN_SELF_LEAVE_PRECHECK_ERROR)
    );

    assert_eq!(info.members_v2, before.members_v2);
    assert_eq!(info.roster_revision, before.roster_revision);
    assert_eq!(info.state_hash, before.state_hash);
    assert_eq!(info.caller_role(&actor_hex), before.caller_role(&actor_hex));
}

fn assert_signed_role_update_applies(new_role: GroupRole) {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let mut authority = group_with_admin_member_and_target(&creator, &admin, &member, &target);
    let replica = authority.clone();
    let target_hex = hex_id(&target);

    authority.roster_revision = authority.roster_revision.saturating_add(1);
    authority.set_member_role(&target_hex, new_role);
    let commit = authority
        .seal_commit(&admin, 2_000)
        .expect("admin authors role update");

    let next = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.set_member_role(&target_hex, new_role);
    })
    .expect("signed role update applies through gossip path");

    assert_eq!(next.state_hash, authority.state_hash);
    assert_eq!(next.members_v2[&target_hex].role, new_role);
}

#[test]
fn membership_authority_promoted_admin_adds_member_rest_semantics() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let mut info = group_with_promoted_admin(&creator, &admin);

    let commit = rest_add_member_semantics(&mut info, &admin, &target).unwrap();

    assert_eq!(commit.committed_by, hex_id(&admin));
    assert_eq!(info.caller_role(&hex_id(&target)), Some(GroupRole::Member));
}

#[test]
fn membership_authority_promoted_admin_adds_member_on_gossip_apply_path() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let mut authority = group_with_promoted_admin(&creator, &admin);
    let replica = authority.clone();
    let admin_hex = hex_id(&admin);
    let target_hex = hex_id(&target);

    authority.roster_revision = authority.roster_revision.saturating_add(1);
    authority.add_member(
        target_hex.clone(),
        GroupRole::Member,
        Some(admin_hex.clone()),
        None,
    );
    let commit = authority
        .seal_commit(&admin, 2_000)
        .expect("promoted admin authors add");

    let next = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.add_member(target_hex.clone(), GroupRole::Member, Some(admin_hex), None);
    })
    .expect("promoted admin add applies through signed role layer");

    assert_eq!(next.state_hash, authority.state_hash);
    assert_eq!(next.caller_role(&target_hex), Some(GroupRole::Member));
}

#[test]
fn membership_authority_promoted_admin_removes_member_rest_semantics() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let mut info = group_with_admin_member_and_target(&creator, &admin, &member, &target);
    let target_hex = hex_id(&target);

    let commit = rest_remove_member_semantics(&mut info, &admin, &target_hex).unwrap();

    assert_eq!(commit.committed_by, hex_id(&admin));
    assert!(info.members_v2[&target_hex].is_removed());
}

#[test]
fn membership_authority_promoted_admin_removes_member_on_gossip_apply_path() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let mut authority = group_with_admin_member_and_target(&creator, &admin, &member, &target);
    let replica = authority.clone();
    let admin_hex = hex_id(&admin);
    let target_hex = hex_id(&target);

    authority.roster_revision = authority.roster_revision.saturating_add(1);
    authority.remove_member(&target_hex, Some(admin_hex.clone()));
    let commit = authority
        .seal_commit(&admin, 2_000)
        .expect("promoted admin authors remove");

    let next = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.remove_member(&target_hex, Some(admin_hex));
    })
    .expect("promoted admin remove applies through signed role layer");

    assert_eq!(next.state_hash, authority.state_hash);
    assert!(next.members_v2[&target_hex].is_removed());
}

#[test]
fn membership_authority_promoted_admin_bans_member_rest_semantics() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let mut info = group_with_admin_member_and_target(&creator, &admin, &member, &target);
    let target_hex = hex_id(&target);

    let commit = rest_ban_member_semantics(&mut info, &admin, &target_hex).unwrap();

    assert_eq!(commit.committed_by, hex_id(&admin));
    assert!(info.members_v2[&target_hex].is_banned());
}

#[test]
fn membership_authority_promoted_admin_bans_member_on_gossip_apply_path() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let mut authority = group_with_admin_member_and_target(&creator, &admin, &member, &target);
    let replica = authority.clone();
    let admin_hex = hex_id(&admin);
    let target_hex = hex_id(&target);

    authority.roster_revision = authority.roster_revision.saturating_add(1);
    authority.ban_member(&target_hex, Some(admin_hex.clone()));
    let commit = authority
        .seal_commit(&admin, 2_000)
        .expect("promoted admin authors ban");

    let next = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.ban_member(&target_hex, Some(admin_hex));
    })
    .expect("promoted admin ban applies through signed role layer");

    assert_eq!(next.state_hash, authority.state_hash);
    assert!(next.members_v2[&target_hex].is_banned());
}

#[test]
fn membership_authority_promoted_admin_removes_legacy_owner_not_last_admin() {
    let owner = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let mut info = legacy_owner_with_promoted_admin(&owner, &admin);
    let owner_hex = hex_id(&owner);

    rest_remove_member_semantics(&mut info, &admin, &owner_hex).unwrap();

    assert!(info.members_v2[&owner_hex].is_removed());
    assert_eq!(info.caller_role(&hex_id(&admin)), Some(GroupRole::Admin));
}

#[test]
fn membership_authority_plain_member_self_leave_converges() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let info = group_with_admin_member_and_target(&creator, &admin, &member, &target);

    assert_self_leave_converges(info, &member);
}

#[test]
fn membership_authority_non_last_admin_self_leave_converges() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let info = group_with_promoted_admin(&creator, &admin);

    assert_self_leave_converges(info, &admin);
}

#[test]
fn membership_authority_creator_self_leave_converges_when_another_admin_remains() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let info = group_with_promoted_admin(&creator, &admin);

    assert_self_leave_converges(info, &creator);
}

#[test]
fn membership_authority_legacy_owner_self_leave_converges_when_admin_remains() {
    let owner = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let info = legacy_owner_with_promoted_admin(&owner, &admin);

    assert_self_leave_converges(info, &owner);
}

#[test]
fn membership_authority_non_creator_last_admin_self_leave_returns_409_and_does_not_mutate() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let creator_hex = hex_id(&creator);
    let admin_hex = hex_id(&admin);
    let mut info = group_with_promoted_admin(&creator, &admin);

    rest_remove_member_semantics(&mut info, &admin, &creator_hex).unwrap();
    assert!(info.members_v2[&creator_hex].is_removed());
    assert_eq!(info.caller_role(&admin_hex), Some(GroupRole::Admin));
    assert_eq!(info.active_admin_count(), 1);

    let before = info.clone();
    assert_eq!(
        rest_self_leave_semantics(&mut info, &admin).unwrap_err(),
        RestError::Conflict(LAST_ADMIN_SELF_LEAVE_PRECHECK_ERROR)
    );

    assert_eq!(info.members_v2, before.members_v2);
    assert_eq!(info.roster_revision, before.roster_revision);
    assert_eq!(info.state_hash, before.state_hash);
    assert_eq!(info.caller_role(&admin_hex), Some(GroupRole::Admin));
}

#[test]
fn membership_authority_creator_last_admin_self_leave_returns_409_and_does_not_mutate() {
    let creator = AgentKeypair::generate().unwrap();
    let info = admin_group(&creator, "T");

    assert_self_leave_conflict_preserves(info, &creator);
}

#[test]
fn membership_authority_legacy_owner_last_admin_self_leave_returns_409_and_does_not_mutate() {
    let owner = AgentKeypair::generate().unwrap();
    let mut info = admin_group(&owner, "T");
    info.set_member_role(&hex_id(&owner), GroupRole::Owner);
    info.recompute_state_hash();

    assert_self_leave_conflict_preserves(info, &owner);
}

#[test]
fn membership_authority_crafted_last_admin_self_leave_rejected_at_finalize() {
    let admin = AgentKeypair::generate().unwrap();
    let info = admin_group(&admin, "T");
    let admin_hex = hex_id(&admin);
    let mut scratch = info.clone();
    scratch.roster_revision = scratch.roster_revision.saturating_add(1);
    scratch.remove_member(&admin_hex, Some(admin_hex.clone()));
    let commit = craft_commit(&info, &scratch, &admin, 2_000);

    let err = gossip_apply(&info, &commit, ActionKind::MemberSelf, |next| {
        next.roster_revision = next.roster_revision.saturating_add(1);
        next.remove_member(&admin_hex, Some(admin_hex.clone()));
    })
    .unwrap_err();

    assert!(matches!(
        err,
        ApplyError::Invariant(ref msg)
            if msg == "post-mutation state would leave a live group with zero active admins"
    ));
}

#[test]
fn membership_authority_group_deleted_withdrawal_commit_applies_under_admin_authority() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let mut authority = group_with_promoted_admin(&creator, &admin);
    let replica = authority.clone();
    let event_revision = replica.roster_revision.saturating_add(1);

    let commit = rest_withdraw_semantics(&mut authority, &admin).unwrap();

    assert_eq!(commit.committed_by, hex_id(&admin));
    assert!(authority.withdrawn);

    let next = apply_group_deleted_event(&replica, event_revision, &hex_id(&admin), &commit)
        .expect("GroupDeleted withdrawal applies through signed admin path");
    assert!(next.withdrawn);
    assert_eq!(next.mls_group_id, replica.mls_group_id);
    assert_eq!(next.stable_group_id(), replica.stable_group_id());
    assert_eq!(next.members_v2, replica.members_v2);
    assert_eq!(next.state_hash, authority.state_hash);
}

#[test]
fn membership_authority_group_deleted_rejects_non_admin_signer_and_bad_commit() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let info = group_with_admin_member_and_target(
        &creator,
        &admin,
        &member,
        &AgentKeypair::generate().unwrap(),
    );
    let event_revision = info.roster_revision.saturating_add(1);

    let mut member_withdrawal = info.clone();
    member_withdrawal.withdrawn = true;
    let non_admin_commit = craft_commit(&info, &member_withdrawal, &member, 2_000);
    assert!(matches!(
        apply_group_deleted_event(&info, event_revision, &hex_id(&member), &non_admin_commit)
            .unwrap_err(),
        GroupDeletedEventApplyError::Commit(ApplyError::Unauthorized { .. })
    ));

    let mut authority = info.clone();
    let mut bad_commit = rest_withdraw_semantics(&mut authority, &admin).unwrap();
    bad_commit.signature = "00".to_string();
    assert!(matches!(
        apply_group_deleted_event(&info, event_revision, &hex_id(&admin), &bad_commit).unwrap_err(),
        GroupDeletedEventApplyError::Commit(ApplyError::InvalidSignature(_))
    ));
}

#[test]
fn membership_authority_promoted_admin_bans_legacy_owner_not_last_admin() {
    let owner = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let mut info = legacy_owner_with_promoted_admin(&owner, &admin);
    let owner_hex = hex_id(&owner);

    rest_ban_member_semantics(&mut info, &admin, &owner_hex).unwrap();

    assert!(info.members_v2[&owner_hex].is_banned());
    assert_eq!(info.caller_role(&hex_id(&admin)), Some(GroupRole::Admin));
}

#[test]
fn membership_authority_signed_role_update_apply_accepts_current_and_legacy_labels() {
    assert_signed_role_update_applies(GroupRole::Admin);
    assert_signed_role_update_applies(GroupRole::Member);
    assert_signed_role_update_applies(GroupRole::Moderator);
    assert_signed_role_update_applies(GroupRole::Guest);
}

#[test]
fn membership_authority_last_admin_remove_ban_demote_returns_exact_409_string() {
    let admin = AgentKeypair::generate().unwrap();
    let info = admin_group(&admin, "T");
    let admin_hex = hex_id(&admin);

    assert_eq!(
        last_admin_precheck_error(&info, |g| g.remove_member(&admin_hex, None)),
        Some(LAST_ADMIN_PRECHECK_ERROR)
    );
    assert_eq!(
        last_admin_precheck_error(&info, |g| g.ban_member(&admin_hex, None)),
        Some(LAST_ADMIN_PRECHECK_ERROR)
    );
    assert_eq!(
        last_admin_precheck_error(&info, |g| g.set_member_role(&admin_hex, GroupRole::Member)),
        Some(LAST_ADMIN_PRECHECK_ERROR)
    );
    assert_eq!(
        rest_remove_member_semantics(&mut info.clone(), &admin, &admin_hex).unwrap_err(),
        RestError::Conflict(LAST_ADMIN_PRECHECK_ERROR)
    );
    assert_eq!(
        rest_ban_member_semantics(&mut info.clone(), &admin, &admin_hex).unwrap_err(),
        RestError::Conflict(LAST_ADMIN_PRECHECK_ERROR)
    );
}

#[test]
fn membership_authority_plain_member_cannot_add_remove_ban_rest_semantics() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let mut info = group_with_admin_member_and_target(&creator, &admin, &member, &target);
    let before = info.state_hash.clone();

    assert_eq!(
        rest_add_member_semantics(
            &mut info.clone(),
            &member,
            &AgentKeypair::generate().unwrap()
        )
        .unwrap_err(),
        RestError::Forbidden("admin role required")
    );
    assert_eq!(
        rest_remove_member_semantics(&mut info.clone(), &member, &hex_id(&target)).unwrap_err(),
        RestError::Forbidden("admin role required")
    );
    assert_eq!(
        rest_ban_member_semantics(&mut info, &member, &hex_id(&target)).unwrap_err(),
        RestError::Forbidden("admin role required")
    );
    assert_eq!(
        info.state_hash, before,
        "forbidden REST pre-check must not mutate"
    );
}

#[test]
fn membership_authority_plain_member_cannot_add_remove_ban_on_gossip_apply_path() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let new_member = AgentKeypair::generate().unwrap();
    let info = group_with_admin_member_and_target(&creator, &admin, &member, &target);
    let member_hex = hex_id(&member);
    let target_hex = hex_id(&target);
    let new_member_hex = hex_id(&new_member);

    let mut add_scratch = info.clone();
    add_scratch.roster_revision = add_scratch.roster_revision.saturating_add(1);
    add_scratch.add_member(
        new_member_hex.clone(),
        GroupRole::Member,
        Some(member_hex.clone()),
        None,
    );
    let add_commit = craft_commit(&info, &add_scratch, &member, 2_000);
    assert!(matches!(
        gossip_apply(&info, &add_commit, ActionKind::AdminOrHigher, |next| {
            next.roster_revision = next.roster_revision.saturating_add(1);
            next.add_member(
                new_member_hex,
                GroupRole::Member,
                Some(member_hex.clone()),
                None,
            );
        })
        .unwrap_err(),
        ApplyError::Unauthorized { .. }
    ));

    let mut remove_scratch = info.clone();
    remove_scratch.roster_revision = remove_scratch.roster_revision.saturating_add(1);
    remove_scratch.remove_member(&target_hex, Some(member_hex.clone()));
    let remove_commit = craft_commit(&info, &remove_scratch, &member, 3_000);
    assert!(matches!(
        gossip_apply(&info, &remove_commit, ActionKind::AdminOrHigher, |next| {
            next.roster_revision = next.roster_revision.saturating_add(1);
            next.remove_member(&target_hex, Some(member_hex.clone()));
        })
        .unwrap_err(),
        ApplyError::Unauthorized { .. }
    ));

    let mut ban_scratch = info.clone();
    ban_scratch.roster_revision = ban_scratch.roster_revision.saturating_add(1);
    ban_scratch.ban_member(&target_hex, Some(member_hex.clone()));
    let ban_commit = craft_commit(&info, &ban_scratch, &member, 4_000);
    assert!(matches!(
        gossip_apply(&info, &ban_commit, ActionKind::AdminOrHigher, |next| {
            next.roster_revision = next.roster_revision.saturating_add(1);
            next.ban_member(&target_hex, Some(member_hex));
        })
        .unwrap_err(),
        ApplyError::Unauthorized { .. }
    ));
}

#[test]
fn membership_authority_treekem_ban_last_admin_precedes_missing_key_package() {
    let admin = AgentKeypair::generate().unwrap();
    let mut sole_admin = admin_group(&admin, "T");
    sole_admin.secure_plane = SecureGroupPlane::TreeKem;
    let admin_hex = hex_id(&admin);

    assert_eq!(
        treekem_ban_preflight_semantics(&sole_admin, &admin_hex, &admin_hex).unwrap_err(),
        RestError::Conflict(LAST_ADMIN_PRECHECK_ERROR)
    );

    let creator = AgentKeypair::generate().unwrap();
    let promoted = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let target = AgentKeypair::generate().unwrap();
    let mut non_last_admin =
        group_with_admin_member_and_target(&creator, &promoted, &member, &target);
    non_last_admin.secure_plane = SecureGroupPlane::TreeKem;

    assert_eq!(
        treekem_ban_preflight_semantics(&non_last_admin, &hex_id(&promoted), &hex_id(&target))
            .unwrap_err(),
        RestError::FailedDependency(MISSING_TREEKEM_KEY_PACKAGE)
    );
}
