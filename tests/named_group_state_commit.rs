//! Phase D.3 integration tests: stable identity + evolving validity.
//!
//! These tests exercise the state-commit chain at the `GroupInfo` layer
//! (no daemon required). They prove:
//!
//! 1. The stable `group_id` from `GroupGenesis` is immutable across
//!    renames, role changes, and roster churn.
//! 2. `seal_commit` advances the chain with monotonic revisions and a
//!    `prev_state_hash` link.
//! 3. Every state-bearing field (policy, roster, public meta, security
//!    binding, withdrawal) is covered by `state_hash`.
//! 4. A replica `GroupInfo` that mirrors the mutations and then calls
//!    `apply_commit` reaches the same `state_hash` as the authority.
//! 5. Apply-side rejects stale commits, chain breaks, unauthorized
//!    actors, and post-withdrawal non-withdrawal actions.
//! 6. Signed `GroupCard` authority signature verifies end-to-end and
//!    `supersedes` orders correctly by revision.
//! 7. A withdrawal card has `withdrawn=true` and a higher revision than
//!    the previous public card.

use x0x::groups::{
    compute_policy_hash, compute_public_meta_hash, compute_roster_root, ActionKind, ApplyError,
    GroupDiscoverability, GroupInfo, GroupPolicyPreset, GroupRole, GroupStateCommit,
};
use x0x::identity::{AgentId, AgentKeypair};

fn agent_from_kp(kp: &AgentKeypair) -> AgentId {
    kp.agent_id()
}

fn hex_id(kp: &AgentKeypair) -> String {
    hex::encode(kp.agent_id().as_bytes())
}

/// Build an MlsEncrypted group whose sole Admin is `owner_kp`.
fn build_owner_group(owner_kp: &AgentKeypair, name: &str) -> GroupInfo {
    GroupInfo::with_policy(
        name.to_string(),
        "desc".into(),
        agent_from_kp(owner_kp),
        "aa".repeat(16), // mls_group_id — topic-derivation key
        GroupPolicyPreset::PublicRequestSecure.to_policy(),
    )
}

#[test]
fn stable_group_id_survives_rename() {
    let kp = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&kp, "Original");
    let stable = g.stable_group_id().to_string();

    // Rename + re-seal
    g.name = "Renamed".into();
    let _ = g.seal_commit(&kp, 1_000).unwrap();
    assert_eq!(
        g.stable_group_id(),
        stable,
        "rename must not change group_id"
    );

    g.description = "New description".into();
    g.tags = vec!["ai".into(), "rust".into()];
    let _ = g.seal_commit(&kp, 2_000).unwrap();
    assert_eq!(
        g.stable_group_id(),
        stable,
        "meta edit must not change group_id"
    );
}

#[test]
fn stable_group_id_survives_roster_changes() {
    let owner = AgentKeypair::generate().unwrap();
    let bob = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    let stable = g.stable_group_id().to_string();

    g.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);
    let _ = g.seal_commit(&owner, 1_000).unwrap();
    assert_eq!(g.stable_group_id(), stable);

    g.remove_member(&hex_id(&bob), Some(hex_id(&owner)));
    let _ = g.seal_commit(&owner, 2_000).unwrap();
    assert_eq!(g.stable_group_id(), stable);
}

#[test]
fn seal_commit_chain_monotonic() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");

    assert_eq!(g.state_revision, 0);
    let initial_hash = g.state_hash.clone();
    assert!(!initial_hash.is_empty());

    // Seal #1
    g.description = "x".into();
    let c1 = g.seal_commit(&owner, 1_000).unwrap();
    assert_eq!(c1.revision, 1);
    assert_eq!(c1.prev_state_hash.as_deref(), Some(initial_hash.as_str()));
    assert_eq!(g.state_revision, 1);
    assert_eq!(g.state_hash, c1.state_hash);
    c1.verify_structure().unwrap();

    // Seal #2
    g.description = "y".into();
    let c2 = g.seal_commit(&owner, 2_000).unwrap();
    assert_eq!(c2.revision, 2);
    assert_eq!(c2.prev_state_hash.as_deref(), Some(c1.state_hash.as_str()));
    assert_ne!(c2.state_hash, c1.state_hash);
    c2.verify_structure().unwrap();
}

#[test]
fn state_hash_covers_roster_changes() {
    let owner = AgentKeypair::generate().unwrap();
    let bob = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    let h0 = g.state_hash.clone();
    g.add_member(hex_id(&bob), GroupRole::Member, None, None);
    g.recompute_state_hash();
    assert_ne!(h0, g.state_hash);
}

#[test]
fn state_hash_covers_policy_changes() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    let h0 = g.state_hash.clone();
    g.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    g.recompute_state_hash();
    assert_ne!(h0, g.state_hash);
}

#[test]
fn state_hash_covers_public_meta_changes() {
    let owner = AgentKeypair::generate().unwrap();
    let g = build_owner_group(&owner, "T");
    let h0 = g.state_hash.clone();

    let mut renamed = g.clone();
    renamed.name = "Renamed".into();
    renamed.recompute_state_hash();
    assert_ne!(h0, renamed.state_hash, "name must affect state_hash");

    let mut described = g.clone();
    described.description = "New description".into();
    described.recompute_state_hash();
    assert_ne!(
        h0, described.state_hash,
        "description must affect state_hash"
    );

    let mut tagged = g.clone();
    tagged.tags = vec!["ai".into(), "rust".into()];
    tagged.recompute_state_hash();
    assert_ne!(h0, tagged.state_hash, "tags must affect state_hash");

    let mut avatar = g.clone();
    avatar.avatar_url = Some("https://example.invalid/avatar.png".into());
    avatar.recompute_state_hash();
    assert_ne!(h0, avatar.state_hash, "avatar must affect state_hash");

    let mut banner = g.clone();
    banner.banner_url = Some("https://example.invalid/banner.png".into());
    banner.recompute_state_hash();
    assert_ne!(h0, banner.state_hash, "banner must affect state_hash");
}

#[test]
fn state_hash_covers_ban_transition() {
    let owner = AgentKeypair::generate().unwrap();
    let bob = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    g.add_member(hex_id(&bob), GroupRole::Member, None, None);
    g.recompute_state_hash();
    let h = g.state_hash.clone();

    g.ban_member(&hex_id(&bob), Some(hex_id(&owner)));
    g.recompute_state_hash();
    assert_ne!(h, g.state_hash, "ban must affect state_hash");
}

#[test]
fn state_hash_covers_security_epoch_rotation() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    g.recompute_state_hash();
    let h0 = g.state_hash.clone();
    let _ = g.rotate_shared_secret();
    g.recompute_state_hash();
    assert_ne!(h0, g.state_hash, "GSS rotation must bump security_binding");
    assert!(g
        .security_binding
        .as_deref()
        .unwrap_or("")
        .contains("epoch=1"));
}

#[test]
fn state_hash_covers_withdrawal_transition() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    let h0 = g.state_hash.clone();

    g.withdrawn = true;
    g.recompute_state_hash();
    assert_ne!(h0, g.state_hash, "withdrawal must affect state_hash");
}

#[test]
fn replica_converges_via_apply_commit() {
    let owner = AgentKeypair::generate().unwrap();
    let bob = AgentKeypair::generate().unwrap();

    // Authority instance — performs the action and seals.
    let mut authority = build_owner_group(&owner, "T");
    authority.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);
    let commit = authority.seal_commit(&owner, 1_000).unwrap();

    // Replica instance — starts from same genesis, mirrors the mutation,
    // then applies the signed commit. After apply, state_hash must match.
    let mut replica = build_owner_group(&owner, "T");
    // Replica independently generated its own genesis nonce, so for this
    // test we copy genesis to match the authority (mirrors what migrate
    // from a well-known mls_group_id achieves in production).
    replica.genesis = authority.genesis.clone();
    replica.recompute_state_hash();
    replica.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);

    replica
        .apply_commit(&commit, ActionKind::AdminOrHigher)
        .unwrap();
    assert_eq!(replica.state_hash, authority.state_hash);
    assert_eq!(replica.state_revision, authority.state_revision);
}

#[test]
fn apply_commit_rejects_stale_revision() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    g.description = "x".into();
    let c1 = g.seal_commit(&owner, 1_000).unwrap();
    g.description = "y".into();
    let _c2 = g.seal_commit(&owner, 2_000).unwrap();

    // Replaying c1 (revision=1) on a group now at revision=2 must reject.
    let err = g.apply_commit(&c1, ActionKind::AdminOrHigher).unwrap_err();
    assert!(matches!(err, ApplyError::StaleRevision { .. }));
}

#[test]
fn apply_commit_rejects_chain_break() {
    let owner = AgentKeypair::generate().unwrap();
    let mut authority = build_owner_group(&owner, "T");
    authority.description = "x".into();
    let _c1 = authority.seal_commit(&owner, 1_000).unwrap();

    // Replica never saw c1 and is still at genesis. Authority produces c2
    // from its current state. Replica trying to apply c2 must reject —
    // prev_state_hash links to c1 which replica doesn't have.
    authority.description = "y".into();
    let c2 = authority.seal_commit(&owner, 2_000).unwrap();

    let mut replica = build_owner_group(&owner, "T");
    replica.genesis = authority.genesis.clone();
    replica.recompute_state_hash();

    let err = replica
        .apply_commit(&c2, ActionKind::AdminOrHigher)
        .unwrap_err();
    assert!(matches!(
        err,
        ApplyError::PrevHashMismatch { .. } | ApplyError::StaleRevision { .. }
    ));
}

#[test]
fn apply_commit_rejects_unauthorized_signer() {
    let owner = AgentKeypair::generate().unwrap();
    let bob = AgentKeypair::generate().unwrap();

    // Authority: owner creates group, adds Bob, seals commit #1.
    let mut authority = build_owner_group(&owner, "T");
    authority.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);
    let c1 = authority.seal_commit(&owner, 1_000).unwrap();

    // Replica: mirrors authority up to c1.
    let mut replica = build_owner_group(&owner, "T");
    replica.genesis = authority.genesis.clone();
    replica.recompute_state_hash();
    replica.add_member(hex_id(&bob), GroupRole::Member, Some(hex_id(&owner)), None);
    replica
        .apply_commit(&c1, ActionKind::AdminOrHigher)
        .unwrap();

    // Bob (Member) on his replica seals a forged policy change.
    replica.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    let forged = replica.seal_commit(&bob, 2_000).unwrap();

    // Authority tries to apply bob's forged commit as AdminOrHigher —
    // mirrors the mutation locally so chain+hash are consistent;
    // authority is still at revision 1.
    authority.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    let err = authority
        .apply_commit(&forged, ActionKind::AdminOrHigher)
        .unwrap_err();
    assert!(
        matches!(err, ApplyError::Unauthorized { .. }),
        "expected Unauthorized, got: {err}"
    );
}

#[test]
fn apply_commit_rejects_post_withdrawal_non_withdrawal() -> Result<(), Box<dyn std::error::Error>> {
    let owner = AgentKeypair::generate()?;
    let mut g = build_owner_group(&owner, "T");
    let _ = g.seal_withdrawal(&owner, 1_000)?;
    assert!(g.withdrawn);

    // Try to apply a new non-withdrawal admin action from the same signer —
    // must reject because the group is terminated.
    g.policy = GroupPolicyPreset::PublicAnnounce.to_policy();
    let commit = GroupStateCommit::sign(
        g.stable_group_id().to_string(),
        g.state_revision.saturating_add(1),
        Some(g.state_hash.clone()),
        compute_roster_root(&g.members_v2),
        compute_policy_hash(&g.policy),
        compute_public_meta_hash(&g.public_meta()),
        g.security_binding.clone(),
        false,
        2_000,
        &owner,
    );
    let commit = commit?;
    assert!(!commit.withdrawn);

    let result = g.apply_commit(&commit, ActionKind::AdminOrHigher);
    assert!(
        matches!(&result, Err(ApplyError::Withdrawn)),
        "expected Withdrawn, got: {result:?}"
    );
    Ok(())
}

#[test]
fn signed_card_verifies_across_peers() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "Public Group");
    g.tags = vec!["rust".into(), "ai".into()];
    g.recompute_state_hash();
    let card = g
        .to_signed_group_card(&owner)
        .unwrap()
        .expect("public group produces card");
    card.verify_signature().unwrap();
    assert!(!card.signature.is_empty());
    assert_eq!(card.authority_agent_id, hex_id(&owner));
    assert_eq!(card.group_id, g.stable_group_id());
    assert_eq!(card.state_hash, g.state_hash);
    assert!(!card.withdrawn);
}

#[test]
fn card_revisions_supersede_correctly() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "Public");
    let _ = g.seal_commit(&owner, 1_000).unwrap();
    let c_lo = g
        .to_signed_group_card(&owner)
        .unwrap()
        .expect("card at rev 1");

    g.description = "updated".into();
    let _ = g.seal_commit(&owner, 2_000).unwrap();
    let c_hi = g
        .to_signed_group_card(&owner)
        .unwrap()
        .expect("card at rev 2");

    c_lo.verify_signature().unwrap();
    c_hi.verify_signature().unwrap();
    assert!(c_hi.revision > c_lo.revision);
    assert!(c_hi.supersedes(&c_lo));
    assert!(!c_lo.supersedes(&c_hi));
}

#[test]
fn withdrawal_card_carries_withdrawn_and_higher_revision() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "Public");
    let _pre_commit = g.seal_commit(&owner, 1_000).unwrap();
    let pre_card = g
        .to_signed_group_card(&owner)
        .unwrap()
        .expect("public card pre-withdrawal");
    assert!(!pre_card.withdrawn);

    let withdrawal = g.seal_withdrawal(&owner, 2_000).unwrap();
    assert!(withdrawal.withdrawn);
    assert!(withdrawal.revision > pre_card.revision);

    // to_group_card now returns Some even though discoverability is
    // PublicDirectory — withdrawal cards are emitted for supersession
    // regardless of discoverability (but Hidden+!withdrawn still yields None).
    let withdraw_card = g
        .to_signed_group_card(&owner)
        .unwrap()
        .expect("withdrawal card");
    assert!(withdraw_card.withdrawn);
    withdraw_card.verify_signature().unwrap();
    assert!(withdraw_card.supersedes(&pre_card));
}

#[test]
fn hidden_non_withdrawn_group_does_not_produce_card() {
    let owner = AgentKeypair::generate().unwrap();
    let g = GroupInfo::new(
        "Hidden".into(),
        "".into(),
        agent_from_kp(&owner),
        "bb".repeat(16),
    );
    assert_eq!(g.policy.discoverability, GroupDiscoverability::Hidden);
    assert!(!g.withdrawn);
    assert!(g.to_group_card().is_none());
    assert!(g.to_signed_group_card(&owner).unwrap().is_none());
}

#[test]
fn compute_component_hashes_are_deterministic() {
    let owner = AgentKeypair::generate().unwrap();
    let g = build_owner_group(&owner, "T");
    let a = compute_roster_root(&g.members_v2);
    let b = compute_roster_root(&g.members_v2);
    assert_eq!(a, b);
    let p1 = compute_policy_hash(&g.policy);
    let p2 = compute_policy_hash(&g.policy);
    assert_eq!(p1, p2);
    let m1 = compute_public_meta_hash(&g.public_meta());
    let m2 = compute_public_meta_hash(&g.public_meta());
    assert_eq!(m1, m2);
}

#[test]
fn commit_signature_tampering_detected() {
    let owner = AgentKeypair::generate().unwrap();
    let mut g = build_owner_group(&owner, "T");
    let mut c = g.seal_commit(&owner, 1_000).unwrap();
    c.verify_structure().unwrap();

    // Tamper with revision — signature will no longer verify.
    c.revision = 99;
    assert!(c.verify_structure().is_err());
}
