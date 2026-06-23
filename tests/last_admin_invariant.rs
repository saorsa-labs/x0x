//! ADR-0016 R2: last-admin invariant at the state-commit choke-point.
//!
//! No commit may leave a live (non-withdrawn) group with zero active
//! members of rank ≥ Admin (legacy `Owner` counts as Admin). These tests
//! prove the invariant on **both delivery paths** at the `GroupInfo`
//! layer (no daemon required):
//!
//! 1. **Authoring** (`seal_commit` — every REST handler and the
//!    inviter-side `MemberJoined` flow seal through it): a mutation that
//!    strips the last active admin cannot be sealed into a commit.
//! 2. **Apply-side** (the daemon gossip pipeline: `validate_apply` →
//!    mirror mutation → `finalize_applied_commit`, exactly the sequence
//!    `apply_stateful_event_to_group` runs in `x0xd`): a crafted,
//!    correctly-signed zero-admin commit is rejected at the choke-point
//!    itself — not by any REST pre-check.
//! 3. The proposed post-mutation roster fed to the check hashes to the
//!    commit's `roster_root` (guards the computed-roster seam).
//! 4. Withdrawal (group-ending) commits are exempt — the last admin's
//!    exit valve stays open.

use x0x::groups::state_commit::validate_apply;
use x0x::groups::{
    compute_policy_hash, compute_public_meta_hash, compute_roster_root, ActionKind, ApplyContext,
    ApplyError, GroupInfo, GroupPolicyPreset, GroupRole, GroupStateCommit,
};
use x0x::identity::AgentKeypair;

fn hex_id(kp: &AgentKeypair) -> String {
    hex::encode(kp.agent_id().as_bytes())
}

/// Build a group whose sole member is `owner_kp` as legacy `Owner`.
fn build_owner_group(owner_kp: &AgentKeypair, name: &str) -> GroupInfo {
    let mut info = GroupInfo::with_policy(
        name.to_string(),
        "desc".into(),
        owner_kp.agent_id(),
        "aa".repeat(16),
        GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    let owner_hex = hex_id(owner_kp);
    info.set_member_role(&owner_hex, GroupRole::Owner);
    info.recompute_state_hash();
    info
}

/// Replica that shares the authority's genesis (mirrors what migration
/// from a well-known mls_group_id achieves in production).
fn replica_of(authority: &GroupInfo, owner_kp: &AgentKeypair, name: &str) -> GroupInfo {
    let mut replica = build_owner_group(owner_kp, name);
    replica.genesis = authority.genesis.clone();
    replica.recompute_state_hash();
    replica
}

/// Sign a commit over `scratch`'s (post-mutation) state, chained onto
/// `parent`'s current head — the adversarial equivalent of `seal_commit`
/// without its invariant guard.
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

/// Run the exact apply sequence the daemon's gossip pipeline runs in
/// `apply_stateful_event_to_group`: validate against the parent state,
/// mirror the mutation on a clone, then finalize against the commit.
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

// ── Authoring path: seal_commit refuses to mint zero-admin commits ──────

/// Why: the last admin must not be able to self-demote out of a live
/// group — the authoring choke-point is where REST-side acts are minted.
#[test]
fn last_admin_seal_rejects_demote_of_sole_admin() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    g.set_member_role(&hex_id(&owner), GroupRole::Member);
    let err = g.seal_commit(&owner, 1_000).unwrap_err();
    assert!(matches!(err, ApplyError::Invariant(_)), "got: {err}");
}

/// Why: removing the sole admin would orphan the group; the commit must
/// never come into existence.
#[test]
fn last_admin_seal_rejects_remove_of_sole_admin() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    g.remove_member(&hex_id(&owner), Some(hex_id(&owner)));
    let err = g.seal_commit(&owner, 1_000).unwrap_err();
    assert!(matches!(err, ApplyError::Invariant(_)), "got: {err}");
}

/// Why: a banned admin is not active — banning the sole admin must be
/// blocked exactly like removal.
#[test]
fn last_admin_seal_rejects_ban_of_sole_admin() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    g.ban_member(&hex_id(&owner), Some(hex_id(&owner)));
    let err = g.seal_commit(&owner, 1_000).unwrap_err();
    assert!(matches!(err, ApplyError::Invariant(_)), "got: {err}");
}

/// Why: ending the group is the last admin's exit valve (ADR-0016) — a
/// withdrawal commit from a sole-admin state must seal.
#[test]
fn last_admin_seal_allows_withdrawal_from_sole_admin_state() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    let commit = g.seal_withdrawal(&owner, 1_000).unwrap();
    assert!(commit.withdrawn);
    assert!(g.withdrawn);
}

/// Why: a sole legacy Owner self-normalising to Admin keeps the admin
/// count at 1 — the optional ADR-0016 normalization commit must seal.
#[test]
fn last_admin_seal_allows_owner_self_normalize_to_admin() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    g.set_member_role(&hex_id(&owner), GroupRole::Admin);
    let commit = g.seal_commit(&owner, 1_000).unwrap();
    assert_eq!(compute_roster_root(&g.members_v2), commit.roster_root);
}

/// Why: legacy `Owner` must count as Admin in mixed rosters — banning the
/// only `Admin`-ranked entry passes while an active Owner remains, and the
/// protection then re-engages for the Owner itself.
#[test]
fn last_admin_seal_counts_legacy_owner_in_mixed_roster() {
    let owner = AgentKeypair::generate().unwrap();
    let bob = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    g.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);
    g.set_member_role(&hex_id(&bob), GroupRole::Admin);
    let _ = g.seal_commit(&owner, 1_000).unwrap();

    // Banning admin bob is fine: the active legacy Owner still counts.
    g.ban_member(&hex_id(&bob), Some(hex_id(&owner)));
    let _ = g.seal_commit(&owner, 2_000).unwrap();

    // Now the Owner is the last admin-or-higher: removing it must fail.
    g.remove_member(&hex_id(&owner), Some(hex_id(&owner)));
    let err = g.seal_commit(&owner, 3_000).unwrap_err();
    assert!(matches!(err, ApplyError::Invariant(_)), "got: {err}");
}

// ── Apply path: the choke-point check itself (gossip-apply sequence) ────

/// Why: REST pre-checks are UX only — a correctly-signed, chain-valid
/// commit that encodes a zero-admin roster must be rejected by the
/// apply-side choke-point itself on the gossip delivery path.
#[test]
fn last_admin_gossip_apply_rejects_crafted_zero_admin_commit() {
    let owner = AgentKeypair::generate().unwrap();
    let owner_hex = hex_id(&owner);

    let authority = build_owner_group(&owner, "T");
    let replica = replica_of(&authority, &owner, "T");

    // Craft a self-removal of the sole admin: structurally valid, signed,
    // chains from the replica's head — only the invariant can stop it.
    let mut scratch = replica.clone();
    scratch.remove_member(&owner_hex, Some(owner_hex.clone()));
    let commit = craft_commit(&replica, &scratch, &owner, 1_000);

    let err = gossip_apply(&replica, &commit, ActionKind::MemberSelf, |next| {
        next.remove_member(&owner_hex, Some(owner_hex.clone()));
    })
    .unwrap_err();
    assert!(matches!(err, ApplyError::Invariant(_)), "got: {err}");
}

/// Why: a commit demoting the sole legacy Owner to plain member encodes a
/// zero-admin state — Owner gets no special pass at the choke-point.
#[test]
fn last_admin_gossip_apply_rejects_owner_demoted_to_member() {
    let owner = AgentKeypair::generate().unwrap();
    let owner_hex = hex_id(&owner);

    let authority = build_owner_group(&owner, "T");
    let replica = replica_of(&authority, &owner, "T");

    let mut scratch = replica.clone();
    scratch.set_member_role(&owner_hex, GroupRole::Member);
    let commit = craft_commit(&replica, &scratch, &owner, 1_000);

    let err = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
        next.set_member_role(&owner_hex, GroupRole::Member);
    })
    .unwrap_err();
    assert!(matches!(err, ApplyError::Invariant(_)), "got: {err}");
}

/// Why: preserving legacy Moderator/Guest replay must not weaken the
/// last-admin invariant — a validly signed role-update commit still cannot
/// turn the sole admin into any below-Admin role.
#[test]
fn last_admin_gossip_apply_rejects_owner_demoted_to_reserved_low_roles() {
    for role in [GroupRole::Moderator, GroupRole::Guest] {
        let owner = AgentKeypair::generate().unwrap();
        let owner_hex = hex_id(&owner);

        let authority = build_owner_group(&owner, "T");
        let replica = replica_of(&authority, &owner, "T");

        let mut scratch = replica.clone();
        scratch.set_member_role(&owner_hex, role);
        let commit = craft_commit(&replica, &scratch, &owner, 1_000);

        let err = gossip_apply(&replica, &commit, ActionKind::AdminOrHigher, |next| {
            next.set_member_role(&owner_hex, role);
        })
        .unwrap_err();
        assert!(
            matches!(err, ApplyError::Invariant(_)),
            "role {role:?} got: {err}"
        );
    }
}

/// Why: the exemption must hold at the choke-point too — a terminal
/// withdrawal commit applies even when its roster has zero active admins
/// (the exit valve is never sealed shut).
#[test]
fn last_admin_gossip_apply_allows_zero_admin_withdrawal_commit() {
    let owner = AgentKeypair::generate().unwrap();
    let owner_hex = hex_id(&owner);

    let authority = build_owner_group(&owner, "T");
    let replica = replica_of(&authority, &owner, "T");

    let mut scratch = replica.clone();
    scratch.remove_member(&owner_hex, Some(owner_hex.clone()));
    scratch.withdrawn = true;
    let commit = craft_commit(&replica, &scratch, &owner, 1_000);
    assert!(commit.withdrawn);

    let next = gossip_apply(&replica, &commit, ActionKind::MemberSelf, |next| {
        next.remove_member(&owner_hex, Some(owner_hex.clone()));
    })
    .unwrap();
    assert!(next.withdrawn);
}

/// Why: the invariant is evaluated over the proposed post-mutation roster
/// computed by the applier — that roster must hash to the signed commit's
/// `roster_root`, or the check would be validating a different state than
/// the one committed to.
#[test]
fn last_admin_proposed_roster_hashes_to_commit_roster_root() {
    let owner = AgentKeypair::generate().unwrap();
    let bob = AgentKeypair::generate().unwrap();

    let mut authority = build_owner_group(&owner, "T");
    authority.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);
    let c1 = authority.seal_commit(&owner, 1_000).unwrap();

    let mut replica = replica_of(&authority, &owner, "T");
    replica.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);
    replica
        .apply_commit(&c1, ActionKind::AdminOrHigher)
        .unwrap();

    // Authority removes bob (legal: the owner remains) and seals.
    authority.remove_member(&hex_id(&bob), Some(hex_id(&owner)));
    let c2 = authority.seal_commit(&owner, 2_000).unwrap();

    // The replica's proposed post-mutation roster — the exact map fed to
    // the invariant check — must hash to the commit's roster_root.
    let mut next = replica.clone();
    next.remove_member(&hex_id(&bob), Some(hex_id(&owner)));
    assert_eq!(
        compute_roster_root(&next.members_v2),
        c2.roster_root,
        "proposed roster must hash to the commit's roster_root"
    );
    next.finalize_applied_commit(&c2).unwrap();
    assert_eq!(next.state_hash, authority.state_hash);
}

/// Why: the invariant must be behavior-neutral for legal flows — a
/// non-admin member's removal converges through the same pipeline
/// untouched.
#[test]
fn last_admin_gossip_apply_allows_member_removal_with_admin_remaining() {
    let owner = AgentKeypair::generate().unwrap();
    let bob = AgentKeypair::generate().unwrap();

    let mut authority = build_owner_group(&owner, "T");
    authority.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);
    let c1 = authority.seal_commit(&owner, 1_000).unwrap();

    let mut replica = replica_of(&authority, &owner, "T");
    replica.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);
    replica
        .apply_commit(&c1, ActionKind::AdminOrHigher)
        .unwrap();

    authority.remove_member(&hex_id(&bob), Some(hex_id(&owner)));
    let c2 = authority.seal_commit(&owner, 2_000).unwrap();

    let next = gossip_apply(&replica, &c2, ActionKind::AdminOrHigher, |next| {
        next.remove_member(&hex_id(&bob), Some(hex_id(&owner)));
    })
    .unwrap();
    assert_eq!(next.state_hash, authority.state_hash);
}
