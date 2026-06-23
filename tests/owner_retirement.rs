//! ADR-0016 Phase 1 Slice 2: owner retirement / flat Admin authority.
//!
//! These tests stay at the `GroupInfo` + state-commit layer so they run in
//! the normal cargo/nextest gates. The daemon REST handlers author through the
//! same `seal_commit` / `seal_withdrawal` seam, and the gossip receiver uses
//! the same validate → mirror mutation → finalize sequence exercised here.

use std::collections::BTreeMap;

use x0x::groups::state_commit::{compute_roster_root, validate_apply};
use x0x::groups::{
    ActionKind, ApplyContext, ApplyError, GroupInfo, GroupMember, GroupPolicyPreset, GroupRole,
    GroupStateCommit,
};
use x0x::identity::AgentKeypair;

const STABLE_OWNER_ID: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const STABLE_ADMIN_ID: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const STABLE_MEMBER_ID: &str = "3333333333333333333333333333333333333333333333333333333333333333";

const EXPECTED_LEGACY_OWNER_ROSTER_JSON_BLAKE3: &str =
    "333a5ebb8d5d9ab042dc2017e32a1760d6d5c8e13045ae00814cc31b8aa84c02";
const EXPECTED_LEGACY_OWNER_ROSTER_ROOT: &str =
    "082266e4717640a855bfb4284ecc0f99af19838569c62dd5013a9854bc5df62d";

fn hex_id(kp: &AgentKeypair) -> String {
    hex::encode(kp.agent_id().as_bytes())
}

fn admin_group(creator_kp: &AgentKeypair, name: &str) -> GroupInfo {
    GroupInfo::with_policy(
        name.to_string(),
        "desc".into(),
        creator_kp.agent_id(),
        "aa".repeat(16),
        GroupPolicyPreset::PublicRequestSecure.to_policy(),
    )
}

fn legacy_owner_group(owner_kp: &AgentKeypair, name: &str) -> GroupInfo {
    let mut info = admin_group(owner_kp, name);
    info.set_member_role(&hex_id(owner_kp), GroupRole::Owner);
    info.recompute_state_hash();
    info
}

fn legacy_mixed_role_group(
    owner_kp: &AgentKeypair,
    admin_kp: &AgentKeypair,
    member_kp: &AgentKeypair,
    name: &str,
) -> GroupInfo {
    let mut info = legacy_owner_group(owner_kp, name);
    let owner_hex = hex_id(owner_kp);
    let admin_hex = hex_id(admin_kp);
    let member_hex = hex_id(member_kp);

    info.add_member(
        admin_hex,
        GroupRole::Admin,
        Some(owner_hex.clone()),
        Some("admin".into()),
    );
    info.add_member(
        member_hex,
        GroupRole::Member,
        Some(owner_hex),
        Some("member".into()),
    );
    info.recompute_state_hash();
    info
}

fn stable_legacy_owner_roster() -> BTreeMap<String, GroupMember> {
    let mut roster = BTreeMap::new();
    roster.insert(
        STABLE_OWNER_ID.to_string(),
        GroupMember::new_owner(
            STABLE_OWNER_ID.to_string(),
            Some("legacy owner".into()),
            1_000,
        ),
    );
    roster.insert(
        STABLE_ADMIN_ID.to_string(),
        GroupMember {
            role: GroupRole::Admin,
            ..GroupMember::new_member(
                STABLE_ADMIN_ID.to_string(),
                Some("admin".into()),
                Some(STABLE_OWNER_ID.to_string()),
                2_000,
            )
        },
    );
    roster.insert(
        STABLE_MEMBER_ID.to_string(),
        GroupMember::new_member(
            STABLE_MEMBER_ID.to_string(),
            Some("member".into()),
            Some(STABLE_ADMIN_ID.to_string()),
            3_000,
        ),
    );
    roster
}

fn assert_commit_matches_group(group: &GroupInfo, commit: &GroupStateCommit) {
    assert_eq!(group.state_hash.as_str(), commit.state_hash.as_str());
    let roster_root = compute_roster_root(&group.members_v2);
    assert_eq!(roster_root.as_str(), commit.roster_root.as_str());
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

fn promote_admin(authority: &mut GroupInfo, creator: &AgentKeypair, admin: &AgentKeypair) {
    let creator_hex = hex_id(creator);
    let admin_hex = hex_id(admin);
    authority.add_member(
        admin_hex.clone(),
        GroupRole::Member,
        Some(creator_hex),
        None,
    );
    authority.set_member_role(&admin_hex, GroupRole::Admin);
}

fn seed_replica_with_promoted_admin(
    authority: &GroupInfo,
    creator: &AgentKeypair,
    admin: &AgentKeypair,
    add_admin_commit: &GroupStateCommit,
) -> GroupInfo {
    let mut replica = admin_group(creator, &authority.name);
    replica.genesis = authority.genesis.clone();
    replica.recompute_state_hash();
    promote_admin(&mut replica, creator, admin);
    replica
        .apply_commit(add_admin_commit, ActionKind::AdminOrHigher)
        .expect("replica accepts promoted-admin setup commit");
    replica
}

fn group_with_promoted_admin(
    creator: &AgentKeypair,
    admin: &AgentKeypair,
) -> (GroupInfo, GroupInfo) {
    let mut authority = admin_group(creator, "T");
    promote_admin(&mut authority, creator, admin);
    let add_admin_commit = authority
        .seal_commit(creator, 1_000)
        .expect("creator seeds promoted admin");
    let replica = seed_replica_with_promoted_admin(&authority, creator, admin, &add_admin_commit);
    (authority, replica)
}

#[test]
fn owner_retirement_genesis_seeds_admin_not_owner() {
    let creator = AgentKeypair::generate().unwrap();
    let info = admin_group(&creator, "T");
    let creator_hex = hex_id(&creator);
    let creator_member = info.members_v2.get(&creator_hex).unwrap();

    assert_eq!(creator_member.role, GroupRole::Admin);
    assert!(creator_member.is_active());
    assert!(info
        .members_v2
        .values()
        .all(|member| member.role != GroupRole::Owner));
}

#[test]
fn owner_retirement_role_assignment_accepts_only_admin_member_and_exact_errors() {
    assert_eq!(
        GroupRole::assignable_from_name("admin"),
        Ok(GroupRole::Admin)
    );
    assert_eq!(
        GroupRole::assignable_from_name("member"),
        Ok(GroupRole::Member)
    );
    assert_eq!(
        GroupRole::assignable_from_name("owner").unwrap_err(),
        "'owner' is a legacy role and cannot be assigned; valid roles: 'admin', 'member'"
    );
    assert_eq!(
        GroupRole::assignable_from_name("moderator").unwrap_err(),
        "role 'moderator' is reserved and cannot be assigned; valid roles: 'admin', 'member'"
    );
    assert_eq!(
        GroupRole::assignable_from_name("guest").unwrap_err(),
        "role 'guest' is reserved and cannot be assigned; valid roles: 'admin', 'member'"
    );
}

#[test]
fn owner_retirement_promoted_admin_updates_policy_on_gossip_apply_path() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let admin_hex = hex_id(&admin);
    let (mut authority, replica) = group_with_promoted_admin(&creator, &admin);

    assert!(authority
        .caller_role(&admin_hex)
        .is_some_and(|role| role.at_least(GroupRole::Admin)));
    authority.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    authority.policy_revision = authority.policy_revision.saturating_add(1);
    let commit = authority
        .seal_commit(&admin, 2_000)
        .expect("promoted admin can author policy commit");

    let next = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
        next.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
        next.policy_revision = next.policy_revision.saturating_add(1);
    })
    .expect("promoted admin policy update applies through role layer");

    assert_eq!(next.state_hash, authority.state_hash);
    assert_eq!(next.policy, authority.policy);
}

#[test]
fn owner_retirement_promoted_admin_changes_another_admin_role() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let creator_hex = hex_id(&creator);
    let admin_hex = hex_id(&admin);
    let (mut authority, replica) = group_with_promoted_admin(&creator, &admin);

    authority.set_member_role(&creator_hex, GroupRole::Member);
    authority.roster_revision = authority.roster_revision.saturating_add(1);
    let commit = authority
        .seal_commit(&admin, 2_000)
        .expect("admin can demote another admin while one admin remains");

    let next = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
        next.set_member_role(&creator_hex, GroupRole::Member);
        next.roster_revision = next.roster_revision.saturating_add(1);
    })
    .expect("role change applies through flat admin authority");

    assert_eq!(next.members_v2[&creator_hex].role, GroupRole::Member);
    assert_eq!(next.members_v2[&admin_hex].role, GroupRole::Admin);
    assert_eq!(next.state_hash, authority.state_hash);
}

#[test]
fn owner_retirement_promoted_admin_ends_group_on_gossip_apply_path() {
    let creator = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let (mut authority, replica) = group_with_promoted_admin(&creator, &admin);

    let commit = authority
        .seal_withdrawal(&admin, 2_000)
        .expect("promoted admin can author group-ending commit");
    assert!(commit.withdrawn);

    let next = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |_| {})
        .expect("promoted admin group-ending commit applies through role layer");

    assert!(next.withdrawn);
    assert_eq!(next.state_hash, authority.state_hash);
}

#[test]
fn owner_retirement_legacy_owner_still_satisfies_admin_or_higher() {
    let owner = AgentKeypair::generate().unwrap();
    let mut authority = legacy_owner_group(&owner, "T");
    let replica = legacy_owner_group(&owner, "T");

    authority.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    authority.policy_revision = authority.policy_revision.saturating_add(1);
    let commit = authority
        .seal_commit(&owner, 1_000)
        .expect("legacy owner can still author admin-or-higher commit");

    let next = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
        next.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
        next.policy_revision = next.policy_revision.saturating_add(1);
    })
    .expect("legacy owner validates as admin-or-higher");

    assert_eq!(next.state_hash, authority.state_hash);
}

#[test]
fn owner_retirement_legacy_owner_chain_replays_byte_for_byte() {
    let stability_roster = stable_legacy_owner_roster();
    let serialized_stability_roster =
        serde_json::to_vec(&stability_roster).expect("legacy owner roster serializes");
    let serialized_stability_roster_hash = blake3::hash(&serialized_stability_roster)
        .to_hex()
        .to_string();
    assert_eq!(
        serialized_stability_roster_hash,
        EXPECTED_LEGACY_OWNER_ROSTER_JSON_BLAKE3
    );
    assert_eq!(
        compute_roster_root(&stability_roster),
        EXPECTED_LEGACY_OWNER_ROSTER_ROOT
    );

    let owner = AgentKeypair::generate().unwrap();
    let admin = AgentKeypair::generate().unwrap();
    let member = AgentKeypair::generate().unwrap();
    let owner_hex = hex_id(&owner);
    let member_hex = hex_id(&member);
    let mut authority = legacy_mixed_role_group(&owner, &admin, &member, "Legacy T");
    let replica = legacy_mixed_role_group(&owner, &admin, &member, "Legacy T");

    assert_eq!(authority.members_v2[&owner_hex].role, GroupRole::Owner);
    assert_eq!(authority.members_v2[&member_hex].role, GroupRole::Member);
    assert_eq!(authority.state_hash, replica.state_hash);
    assert_eq!(
        compute_roster_root(&authority.members_v2),
        compute_roster_root(&replica.members_v2)
    );

    authority.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    authority.policy_revision = authority.policy_revision.saturating_add(1);
    let policy_commit = authority
        .seal_commit(&owner, 1_000)
        .expect("legacy owner authors policy update");
    assert_commit_matches_group(&authority, &policy_commit);

    let replayed_policy = gossip_apply(
        &replica,
        &policy_commit,
        ActionKind::AdminOrHigher,
        |next| {
            next.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
            next.policy_revision = next.policy_revision.saturating_add(1);
        },
    )
    .expect("legacy owner policy commit replays");
    assert_commit_matches_group(&replayed_policy, &policy_commit);
    assert_eq!(
        replayed_policy.members_v2[&owner_hex].role,
        GroupRole::Owner
    );

    authority.set_member_role(&member_hex, GroupRole::Admin);
    authority.roster_revision = authority.roster_revision.saturating_add(1);
    let role_commit = authority
        .seal_commit(&admin, 2_000)
        .expect("current admin authors role update while owner stays legacy");
    assert_eq!(
        role_commit.prev_state_hash.as_deref(),
        Some(policy_commit.state_hash.as_str())
    );
    assert_commit_matches_group(&authority, &role_commit);

    let replayed_role = gossip_apply(
        &replayed_policy,
        &role_commit,
        ActionKind::AdminOrHigher,
        |next| {
            next.set_member_role(&member_hex, GroupRole::Admin);
            next.roster_revision = next.roster_revision.saturating_add(1);
        },
    )
    .expect("admin role commit replays over legacy owner roster");
    assert_commit_matches_group(&replayed_role, &role_commit);
    assert_eq!(replayed_role.members_v2[&owner_hex].role, GroupRole::Owner);
    assert_eq!(replayed_role.members_v2[&member_hex].role, GroupRole::Admin);
}

#[test]
fn owner_retirement_legacy_owner_to_admin_normalization_validates() {
    let owner = AgentKeypair::generate().unwrap();
    let owner_hex = hex_id(&owner);
    let mut authority = legacy_owner_group(&owner, "T");
    let replica = legacy_owner_group(&owner, "T");

    authority.set_member_role(&owner_hex, GroupRole::Admin);
    authority.roster_revision = authority.roster_revision.saturating_add(1);
    let commit = authority
        .seal_commit(&owner, 1_000)
        .expect("owner to admin normalization keeps one admin");

    let next = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
        next.set_member_role(&owner_hex, GroupRole::Admin);
        next.roster_revision = next.roster_revision.saturating_add(1);
    })
    .expect("legacy owner to admin normalization applies");

    assert_eq!(next.members_v2[&owner_hex].role, GroupRole::Admin);
    assert_eq!(next.state_hash, authority.state_hash);
}
