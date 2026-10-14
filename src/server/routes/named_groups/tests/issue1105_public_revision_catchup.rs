//! #1105: a SignedPublic member one commit behind can take the committer's
//! bootstrap head when that head is the next link. A snapshot that does not
//! chain is refused.

use super::super::{
    apply_signed_public_revision_catchup, now_millis_u64, owner_axis_catchup_block,
    signed_public_bootstrap_snapshot, signed_public_catchup_decide,
    signed_public_catchup_extend_failure, OwnerAxisCatchupBlock,
};

fn apply_catchup(
    local: &crate::groups::GroupInfo,
    snapshot: &crate::groups::GroupInfo,
    sender: &str,
    member: &str,
) -> Option<crate::groups::GroupInfo> {
    apply_signed_public_revision_catchup(local, snapshot, sender, member, |_| false)
}

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
    let updated =
        apply_catchup(&behind, &snapshot, &sender, &member_hex).expect("chained head applies");
    assert_eq!(updated.state_revision, ahead.state_revision);
    assert_eq!(updated.state_hash, ahead.state_hash);
    assert_eq!(updated.description, "renamed");
    assert!(updated.issued_invite_secrets.contains("local-invite"));
    assert!(apply_catchup(&ahead, &snapshot, &sender, &member_hex).is_none());
    assert!(
        apply_catchup(&behind, &snapshot, &member_hex, &member_hex).is_none(),
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
    assert!(apply_catchup(&behind, &snapshot, &sender, &member_hex).is_none());
}

fn owner_certified_policy(owner: crate::identity::UserId) -> crate::groups::GroupPolicy {
    let mut policy = crate::groups::GroupPolicyPreset::PublicOpen.to_policy();
    policy.admission = crate::groups::GroupAdmission::OwnerCertified(owner);
    policy
}

fn seal_owner_certified(
    group: &mut crate::groups::GroupInfo,
    authority: &crate::identity::AgentKeypair,
    now_ms: u64,
) {
    let verdict =
        group.owner_cert_verdict(&crate::groups::owner_cert::OwnerCertEvidence::new(now_ms));
    group
        .seal_commit_with_owner_certs(authority, now_ms, &verdict)
        .expect("owner-certified seal");
}

#[test]
fn catchup_keeps_an_installed_owner_certified_axis() {
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let member = crate::identity::AgentKeypair::generate().expect("member");
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let owner = crate::identity::UserId([7; 32]);
    let mut group = crate::groups::GroupInfo::with_policy(
        "Catch-up".to_string(),
        String::new(),
        authority.agent_id(),
        "ab".repeat(32),
        owner_certified_policy(owner),
    );
    group.add_member(
        member_hex.clone(),
        crate::groups::GroupRole::Member,
        Some(hex::encode(authority.agent_id().as_bytes())),
        None,
    );
    seal_owner_certified(&mut group, &authority, now_millis_u64());
    let behind = group.clone();
    group.policy.admission = crate::groups::GroupAdmission::OpenJoin;
    group
        .seal_commit(&authority, now_millis_u64().saturating_add(1))
        .expect("open-join seal");
    let snapshot = signed_public_bootstrap_snapshot(group).expect("snapshot");
    let sender = hex::encode(authority.agent_id().as_bytes());
    assert!(
        apply_catchup(&behind, &snapshot, &sender, &member_hex).is_none(),
        "a signed next head must not replace OwnerCertified with OpenJoin"
    );

    let mut same_owner = behind.clone();
    same_owner.description = "renamed".to_string();
    seal_owner_certified(
        &mut same_owner,
        &authority,
        now_millis_u64().saturating_add(2),
    );
    let kept = signed_public_bootstrap_snapshot(same_owner).expect("same-owner snapshot");
    let updated =
        apply_catchup(&behind, &kept, &sender, &member_hex).expect("the same owner still chains");
    assert_eq!(
        updated.policy.admission.owner_certified_user_id(),
        Some(&owner)
    );
    assert_eq!(updated.description, "renamed");

    let other = crate::identity::UserId([8; 32]);
    let mut replaced = behind.clone();
    replaced.policy.admission = crate::groups::GroupAdmission::OwnerCertified(other);
    seal_owner_certified(
        &mut replaced,
        &authority,
        now_millis_u64().saturating_add(3),
    );
    let swapped = signed_public_bootstrap_snapshot(replaced).expect("other-owner snapshot");
    assert!(
        apply_catchup(&behind, &swapped, &sender, &member_hex).is_none(),
        "a signed next head must not replace the installed owner"
    );
}

fn owner_axis_pair(
    authority: &crate::identity::AgentKeypair,
    member_hex: &str,
) -> crate::groups::GroupInfo {
    let owner = crate::identity::UserId([7; 32]);
    let mut group = crate::groups::GroupInfo::with_policy(
        "Catch-up".to_string(),
        String::new(),
        authority.agent_id(),
        "ab".repeat(32),
        owner_certified_policy(owner),
    );
    group.add_member(
        member_hex.to_string(),
        crate::groups::GroupRole::Member,
        Some(hex::encode(authority.agent_id().as_bytes())),
        None,
    );
    seal_owner_certified(&mut group, authority, now_millis_u64());
    group
}

#[test]
fn catchup_refuses_a_revoked_newcomer_on_an_owner_axis() {
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let member = crate::identity::AgentKeypair::generate().expect("member");
    let newcomer = crate::identity::AgentKeypair::generate().expect("newcomer");
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let newcomer_hex = hex::encode(newcomer.agent_id().as_bytes());
    let sender = hex::encode(authority.agent_id().as_bytes());
    let behind = owner_axis_pair(&authority, &member_hex);
    let mut ahead = behind.clone();
    ahead.add_member(
        newcomer_hex.clone(),
        crate::groups::GroupRole::Member,
        Some(sender.clone()),
        None,
    );
    seal_owner_certified(&mut ahead, &authority, now_millis_u64().saturating_add(1));
    let snapshot = signed_public_bootstrap_snapshot(ahead).expect("snapshot");
    assert_eq!(
        owner_axis_catchup_block(&behind, &snapshot, |agent| agent == newcomer_hex),
        Some(OwnerAxisCatchupBlock::RevokedNewcomer),
        "ADR-0038 B1: a newcomer in the local revocation set is not a catch-up head"
    );
    assert!(
        apply_signed_public_revision_catchup(&behind, &snapshot, &sender, &member_hex, |agent| {
            agent == newcomer_hex
        })
        .is_none(),
        "catch-up must not install the revoked newcomer"
    );
    assert_eq!(
        owner_axis_catchup_block(&behind, &snapshot, |_| false),
        Some(OwnerAxisCatchupBlock::RosterChange),
        "the same head is also an active-roster change"
    );
}

#[test]
fn catchup_refuses_a_roster_change_from_a_mandate_required_committer() {
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let member = crate::identity::AgentKeypair::generate().expect("member");
    let newcomer = crate::identity::AgentKeypair::generate().expect("newcomer");
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let sender = hex::encode(authority.agent_id().as_bytes());
    let mut behind = owner_axis_pair(&authority, &member_hex);
    let capability = crate::groups::MandateCapabilityState {
        first_seen_ms: 1,
        refusals: 0,
        refusal_transition_counted: false,
    };
    assert!(
        capability.refusal_due(60, now_millis_u64()),
        "the committer is past the owner-mandate grace window"
    );
    behind.mandate_capability.insert(sender.clone(), capability);
    let mut roster_head = behind.clone();
    roster_head.add_member(
        hex::encode(newcomer.agent_id().as_bytes()),
        crate::groups::GroupRole::Member,
        Some(sender.clone()),
        None,
    );
    seal_owner_certified(
        &mut roster_head,
        &authority,
        now_millis_u64().saturating_add(1),
    );
    let roster_snapshot = signed_public_bootstrap_snapshot(roster_head).expect("roster snapshot");
    assert!(
        roster_snapshot.mandate_capability.is_empty(),
        "a bootstrap snapshot does not carry the owner mandate"
    );
    assert_eq!(
        owner_axis_catchup_block(&behind, &roster_snapshot, |_| false),
        Some(OwnerAxisCatchupBlock::RosterChange),
        "ADR-0064 §1b: a roster change from a mandate-required committer stays on the ordinary path"
    );
    assert!(
        apply_catchup(&behind, &roster_snapshot, &sender, &member_hex).is_none(),
        "catch-up must not install the roster head"
    );

    let mut metadata = behind.clone();
    metadata.description = "renamed".to_string();
    metadata.roster_revision = 100;
    metadata.policy_revision = 50;
    seal_owner_certified(
        &mut metadata,
        &authority,
        now_millis_u64().saturating_add(2),
    );
    metadata.roster_revision = 100;
    metadata.policy_revision = 50;
    let mut lagging = behind.clone();
    lagging.roster_revision = 4;
    lagging.policy_revision = 2;
    let metadata_snapshot = signed_public_bootstrap_snapshot(metadata).expect("metadata snapshot");
    assert_eq!(
        owner_axis_catchup_block(&lagging, &metadata_snapshot, |_| false),
        None,
        "a rename is not an active-roster change"
    );
    let updated = apply_catchup(&lagging, &metadata_snapshot, &sender, &member_hex)
        .expect("a metadata-only head still catches up");
    assert_eq!(updated.description, "renamed");
    assert_eq!(updated.roster_revision, 5, "roster clock adopts at most +1");
    assert_eq!(updated.policy_revision, 3, "policy clock adopts at most +1");
    assert!(
        updated.mandate_capability.contains_key(&sender),
        "local mandate observation stays on the installed group"
    );
}

fn installed_one_revision_group(
    authority: &crate::identity::AgentKeypair,
    member_hex: &str,
) -> crate::groups::GroupInfo {
    let mut group = crate::groups::GroupInfo::with_policy(
        "Catch-up".to_string(),
        String::new(),
        authority.agent_id(),
        "cd".repeat(32),
        crate::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    group.add_member(
        member_hex.to_string(),
        crate::groups::GroupRole::Member,
        Some(hex::encode(authority.agent_id().as_bytes())),
        None,
    );
    group
        .seal_commit(authority, now_millis_u64())
        .expect("seal");
    assert_eq!(
        group.state_revision, 1,
        "the lagging peer is one revision behind"
    );
    group
}

fn quarantine_marker(group: &crate::groups::GroupInfo) -> crate::groups::ForkQuarantine {
    let header = group.terminal_commit_header();
    crate::groups::ForkQuarantine {
        revision: group.state_revision,
        state_hash: group.state_hash.clone(),
        committed_by: "9e".repeat(32),
        observed_at_ms: 1_726_000_000_000,
        snapshot: crate::groups::ForkSnapshot {
            terminal_commit: header.clone(),
            conflicting_commit: header,
            classification: None,
        },
        no_anchor: true,
    }
}

#[tokio::test]
async fn catchup_send_holds_the_membership_lock_through_delivery() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let member = crate::identity::AgentKeypair::generate().expect("member");
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let group = installed_one_revision_group(state.agent.identity().agent_keypair(), &member_hex);
    let group_id = group.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), group);

    let pause_key =
        super::super::detached_send_test_seam::public_bootstrap_key(&group_id, &member_hex);
    let pause = super::super::detached_send_test_seam::arm(&pause_key);
    let task_state = std::sync::Arc::clone(&state);
    let task_group = group_id.clone();
    let author = member.agent_id();
    let send = tokio::spawn(async move {
        super::super::offer_signed_public_kv_catchup(&task_state, &task_group, 0, author).await;
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !pause.reached() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "catch-up did not reach delivery"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let lock = super::super::group_membership_lock(&state, &group_id).await;
    assert!(
        lock.try_lock().is_err(),
        "catch-up must hold the membership lock through delivery, or a quarantine can land and the copied snapshot still goes out"
    );
    drop(pause);
    send.await.expect("catch-up task");
}

#[tokio::test]
async fn catchup_withholds_a_quarantined_snapshot() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let member = crate::identity::AgentKeypair::generate().expect("member");
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let mut group =
        installed_one_revision_group(state.agent.identity().agent_keypair(), &member_hex);
    group.fork_quarantine = Some(quarantine_marker(&group));
    let group_id = group.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), group);

    let pause_key =
        super::super::detached_send_test_seam::public_bootstrap_key(&group_id, &member_hex);
    let pause = super::super::detached_send_test_seam::arm(&pause_key);
    super::super::offer_signed_public_kv_catchup(&state, &group_id, 0, member.agent_id()).await;
    assert!(
        !pause.reached(),
        "a quarantined group must not send the catch-up snapshot"
    );
}

#[test]
fn catchup_keeps_conflicting_local_key_material() {
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let member = crate::identity::AgentKeypair::generate().expect("member");
    let newcomer = crate::identity::AgentKeypair::generate().expect("newcomer");
    let member_hex = hex::encode(member.agent_id().as_bytes());
    let newcomer_hex = hex::encode(newcomer.agent_id().as_bytes());
    let authority_hex = hex::encode(authority.agent_id().as_bytes());
    let mut group = crate::groups::GroupInfo::with_policy(
        "Catch-up".to_string(),
        String::new(),
        authority.agent_id(),
        "ab".repeat(32),
        crate::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    group.add_member(
        member_hex.clone(),
        crate::groups::GroupRole::Member,
        Some(authority_hex.clone()),
        None,
    );
    group
        .seal_commit(&authority, now_millis_u64())
        .expect("first seal");
    let mut behind = group.clone();
    let local_member = behind
        .members_v2
        .get_mut(&member_hex)
        .expect("local member");
    local_member.kem_public_key_b64 = Some("local-kem".to_string());
    local_member.treekem_key_package_b64 = Some("local-package".to_string());
    local_member.treekem_key_package_hash = Some("local-hash".to_string());
    local_member.certificate_missing_since_ms = Some(11);
    let local_admin = behind
        .members_v2
        .get_mut(&authority_hex)
        .expect("local admin");
    local_admin.kem_public_key_b64 = Some("local-admin-kem".to_string());
    local_admin.certificate_missing_since_ms = Some(22);
    group.add_member(
        newcomer_hex.clone(),
        crate::groups::GroupRole::Member,
        Some(authority_hex.clone()),
        None,
    );
    group.description = "renamed".to_string();
    group
        .seal_commit(&authority, now_millis_u64().saturating_add(1))
        .expect("second seal");
    let mut snapshot = signed_public_bootstrap_snapshot(group).expect("snapshot");
    for (id, kem, package, hash, timer) in [
        (
            member_hex.as_str(),
            "remote-kem",
            "remote-package",
            "remote-hash",
            99,
        ),
        (
            authority_hex.as_str(),
            "remote-admin-kem",
            "remote-admin-package",
            "remote-admin-hash",
            77,
        ),
        (
            newcomer_hex.as_str(),
            "remote-newcomer-kem",
            "remote-newcomer-package",
            "remote-newcomer-hash",
            55,
        ),
    ] {
        let remote = snapshot.members_v2.get_mut(id).expect("snapshot member");
        remote.kem_public_key_b64 = Some(kem.to_string());
        remote.treekem_key_package_b64 = Some(package.to_string());
        remote.treekem_key_package_hash = Some(hash.to_string());
        remote.certificate_missing_since_ms = Some(timer);
    }
    let updated = apply_catchup(&behind, &snapshot, &authority_hex, &member_hex)
        .expect("a signed next head still applies when its local-only fields differ");
    let kept = updated
        .members_v2
        .get(&member_hex)
        .expect("retained member");
    assert_eq!(kept.kem_public_key_b64.as_deref(), Some("local-kem"));
    assert_eq!(
        kept.treekem_key_package_b64.as_deref(),
        Some("local-package")
    );
    assert_eq!(kept.treekem_key_package_hash.as_deref(), Some("local-hash"));
    assert_eq!(kept.certificate_missing_since_ms, Some(11));
    let kept_admin = updated
        .members_v2
        .get(&authority_hex)
        .expect("retained admin");
    assert_eq!(
        kept_admin.kem_public_key_b64.as_deref(),
        Some("local-admin-kem")
    );
    assert_eq!(kept_admin.certificate_missing_since_ms, Some(22));
    assert!(kept_admin.treekem_key_package_b64.is_none());
    assert!(kept_admin.treekem_key_package_hash.is_none());
    let added = updated.members_v2.get(&newcomer_hex).expect("new member");
    assert!(added.kem_public_key_b64.is_none());
    assert!(added.treekem_key_package_b64.is_none());
    assert!(added.treekem_key_package_hash.is_none());
    assert!(added.certificate_missing_since_ms.is_none());
    assert_eq!(updated.description, "renamed");
}

#[test]
fn catchup_send_cache_keeps_live_entries_when_full() {
    let mut guard = Vec::new();
    let now = std::time::Instant::now();
    for index in 0..super::super::SIGNED_PUBLIC_CATCHUP_SEND_LIMIT {
        assert!(
            super::super::signed_public_catchup_decide(&mut guard, &format!("group:{index}"), now),
            "a cache under the cap admits the peer"
        );
    }
    assert!(
        !super::super::signed_public_catchup_decide(&mut guard, "group:overflow", now),
        "a full cache must refuse a new peer instead of evicting a live one"
    );
    assert!(
        !signed_public_catchup_decide(&mut guard, "group:0", now),
        "the first peer is still inside the five-second throttle"
    );
    assert_eq!(guard.len(), super::super::SIGNED_PUBLIC_CATCHUP_SEND_LIMIT);
    signed_public_catchup_extend_failure(&mut guard, "group:0", now);
    assert!(
        !signed_public_catchup_decide(
            &mut guard,
            "group:0",
            now + std::time::Duration::from_secs(6),
        ),
        "a failed offer is not retried when the five-second throttle has elapsed"
    );
    assert!(
        signed_public_catchup_decide(
            &mut guard,
            "group:0",
            now + std::time::Duration::from_secs(31),
        ),
        "the failure backoff ends and the peer can be offered again"
    );
}

#[test]
fn catchup_queue_coalesces_and_caps_pending_work() {
    let mut pending = Vec::new();
    let author = crate::identity::AgentId([1; 32]);
    for revision in 0..super::super::SIGNED_PUBLIC_CATCHUP_QUEUE_CAP as u64 {
        assert!(super::super::reserve_signed_public_catchup_queue(
            &mut pending,
            "group",
            revision,
            author,
        ));
    }
    assert!(
        !super::super::reserve_signed_public_catchup_queue(&mut pending, "group", 0, author),
        "work already pending is coalesced"
    );
    assert!(
        !super::super::reserve_signed_public_catchup_queue(
            &mut pending,
            "group",
            1_000,
            crate::identity::AgentId([2; 32]),
        ),
        "a full queue refuses a new peer"
    );
    assert_eq!(pending.len(), super::super::SIGNED_PUBLIC_CATCHUP_QUEUE_CAP);
    super::super::release_signed_public_catchup_queue(&mut pending, "group", 0, author);
    assert!(super::super::reserve_signed_public_catchup_queue(
        &mut pending,
        "group",
        1_000,
        crate::identity::AgentId([2; 32]),
    ));
}

#[tokio::test]
async fn catchup_apply_does_not_ack_a_removal_a_stale_clone_replaces() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let victim = crate::identity::AgentKeypair::generate().expect("victim");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let authority_hex = hex::encode(authority.agent_id().as_bytes());
    let victim_hex = hex::encode(victim.agent_id().as_bytes());
    let mut group = crate::groups::GroupInfo::with_policy(
        "Catch-up".to_string(),
        String::new(),
        authority.agent_id(),
        "ef".repeat(32),
        crate::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    group.add_member(
        local_hex.clone(),
        crate::groups::GroupRole::Member,
        Some(authority_hex.clone()),
        None,
    );
    group.add_member(
        victim_hex.clone(),
        crate::groups::GroupRole::Member,
        Some(authority_hex.clone()),
        None,
    );
    group
        .seal_commit(&authority, now_millis_u64())
        .expect("installed seal");
    let behind = group.clone();
    let mut removal = group.clone();
    removal.remove_member(&victim_hex, Some(authority_hex.clone()));
    removal
        .seal_commit(&authority, now_millis_u64().saturating_add(1))
        .expect("removal seal");
    let snapshot = signed_public_bootstrap_snapshot(removal).expect("removal snapshot");
    let mut metadata = behind.clone();
    metadata.description = "local rename".to_string();
    metadata
        .seal_commit(&authority, now_millis_u64().saturating_add(2))
        .expect("metadata seal");
    let group_id = behind.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), behind);
    state
        .contacts
        .write()
        .await
        .set_trust(&authority.agent_id(), crate::contacts::TrustLevel::Trusted);

    let pause = crate::server::routes::public_group_bootstrap_outbox::catchup_apply_test_seam::arm(
        &group_id,
    );
    let lock = super::super::group_membership_lock(&state, &group_id).await;
    let guard = lock.lock().await;
    let task_state = std::sync::Arc::clone(&state);
    let task_snapshot = snapshot.clone();
    let sender = authority.agent_id();
    let admit = tokio::spawn(async move {
        crate::server::routes::public_group_bootstrap_outbox::admit_public_group_bootstrap(
            &task_state,
            sender,
            None,
            super::super::PublicGroupBootstrap {
                message_type: crate::server::routes::public_group_bootstrap_outbox::PUBLIC_GROUP_BOOTSTRAP_MESSAGE_TYPE
                    .to_string(),
                group: Box::new(task_snapshot),
            },
        )
        .await
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !pause.reached() && !admit.is_finished() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    super::super::persist_named_group_info(&state, &group_id, metadata.clone())
        .await
        .expect("stale metadata clone persists");
    drop(guard);
    drop(pause);
    let result = admit.await.expect("catch-up admission");
    let installed = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .expect("installed group")
        .clone();
    let victim_active = installed
        .members_v2
        .get(&victim_hex)
        .is_some_and(|member| member.is_active());
    let acknowledged = matches!(
        result,
        Ok(crate::dm_inbox::DmTypedPayloadCompletion::Inserted)
    );
    assert!(
        !(acknowledged && victim_active),
        "an acknowledged catch-up removal must not be replaced by the stale clone, acknowledged={acknowledged} victim_active={victim_active}"
    );
    if !acknowledged {
        assert_eq!(installed.state_hash, metadata.state_hash);
        assert!(
            victim_active,
            "the metadata update that held the membership lock keeps the member"
        );
    }
}

fn bootstrap_of(group: crate::groups::GroupInfo) -> super::super::PublicGroupBootstrap {
    super::super::PublicGroupBootstrap {
        message_type:
            crate::server::routes::public_group_bootstrap_outbox::PUBLIC_GROUP_BOOTSTRAP_MESSAGE_TYPE
                .to_string(),
        group: Box::new(group),
    }
}

async fn admit_from(
    state: &std::sync::Arc<crate::server::AppState>,
    sender: crate::identity::AgentId,
    group: crate::groups::GroupInfo,
) -> Result<crate::dm_inbox::DmTypedPayloadCompletion, String> {
    crate::server::routes::public_group_bootstrap_outbox::admit_public_group_bootstrap(
        state,
        sender,
        None,
        bootstrap_of(group),
    )
    .await
}

#[tokio::test]
async fn installed_admin_consent_catches_up_without_a_known_contact() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (behind, ahead) = sealed_step(&authority, &local_hex);
    let snapshot = signed_public_bootstrap_snapshot(ahead.clone()).expect("snapshot");
    let group_id = behind.stable_group_id().to_string();
    let behind_revision = behind.state_revision;
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), behind);
    let trust = state
        .contacts
        .read()
        .await
        .trust_level(&authority.agent_id());
    assert_eq!(
        trust,
        crate::contacts::TrustLevel::Unknown,
        "the fixture must not record the committer as a contact"
    );

    let result = admit_from(&state, authority.agent_id(), snapshot)
        .await
        .expect("local admin consent applies the next head");
    assert!(matches!(
        result,
        crate::dm_inbox::DmTypedPayloadCompletion::Inserted
    ));
    let installed = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .expect("installed group")
        .clone();
    assert_eq!(installed.state_revision, behind_revision.saturating_add(1));
    assert_eq!(installed.state_hash, ahead.state_hash);
    assert_eq!(installed.description, "renamed");
}

#[tokio::test]
async fn unknown_sender_cannot_install_a_new_public_group() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (_behind, ahead) = sealed_step(&authority, &local_hex);
    let snapshot = signed_public_bootstrap_snapshot(ahead).expect("snapshot");
    let group_id = snapshot.stable_group_id().to_string();

    let error = admit_from(&state, authority.agent_id(), snapshot)
        .await
        .expect_err("a stranger does not seed a group");
    assert_eq!(
        error,
        "public-group bootstrap sender is not a known contact"
    );
    assert!(
        state.named_groups.read().await.get(&group_id).is_none(),
        "the refused bootstrap must not install the group"
    );
}

#[tokio::test]
async fn installed_member_who_did_not_sign_has_no_catchup_consent() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let bystander = crate::identity::AgentKeypair::generate().expect("bystander");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let bystander_hex = hex::encode(bystander.agent_id().as_bytes());
    let (mut behind, ahead) = sealed_step(&authority, &local_hex);
    behind.add_member(
        bystander_hex,
        crate::groups::GroupRole::Member,
        Some(hex::encode(authority.agent_id().as_bytes())),
        None,
    );
    let snapshot = signed_public_bootstrap_snapshot(ahead).expect("snapshot");
    let group_id = behind.stable_group_id().to_string();
    let behind_hash = behind.state_hash.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), behind);

    let error = admit_from(&state, bystander.agent_id(), snapshot)
        .await
        .expect_err("a non-admin member is not catch-up consent");
    assert_eq!(
        error,
        "public-group bootstrap sender is not a known contact"
    );
    let installed = state
        .named_groups
        .read()
        .await
        .get(&group_id)
        .expect("installed group")
        .clone();
    assert_eq!(installed.state_hash, behind_hash);
}

async fn install_behind(
    state: &std::sync::Arc<crate::server::AppState>,
    behind: crate::groups::GroupInfo,
) -> (String, String) {
    let group_id = behind.stable_group_id().to_string();
    let hash = behind.state_hash.clone();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), behind);
    (group_id, hash)
}

async fn installed_hash(state: &std::sync::Arc<crate::server::AppState>, group_id: &str) -> String {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .expect("installed group")
        .state_hash
        .clone()
}

#[tokio::test]
async fn non_committer_admin_has_no_catchup_consent() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let other = crate::identity::AgentKeypair::generate().expect("other admin");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let other_hex = hex::encode(other.agent_id().as_bytes());
    let (mut behind, ahead) = sealed_step(&authority, &local_hex);
    behind.add_member(
        other_hex.clone(),
        crate::groups::GroupRole::Admin,
        Some(hex::encode(authority.agent_id().as_bytes())),
        None,
    );
    assert!(
        behind
            .caller_role(&other_hex)
            .is_some_and(|role| role.at_least(crate::groups::GroupRole::Admin)),
        "the non-committer must be an active local admin"
    );
    let snapshot = signed_public_bootstrap_snapshot(ahead).expect("snapshot");
    assert_ne!(
        snapshot
            .commit_log
            .last()
            .expect("retained head")
            .commit
            .committed_by,
        other_hex,
        "the retained head must be signed by someone else"
    );
    let (group_id, behind_hash) = install_behind(&state, behind).await;

    let error = admit_from(&state, other.agent_id(), snapshot)
        .await
        .expect_err("an admin who did not sign the head is not catch-up consent");
    assert_eq!(
        error,
        "public-group bootstrap sender is not a known contact"
    );
    assert_eq!(installed_hash(&state, &group_id).await, behind_hash);
}

#[tokio::test]
async fn admin_only_in_the_snapshot_has_no_catchup_consent() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let outsider = crate::identity::AgentKeypair::generate().expect("snapshot admin");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let outsider_hex = hex::encode(outsider.agent_id().as_bytes());
    let (behind, mut ahead) = sealed_step(&authority, &local_hex);
    assert!(
        behind.caller_role(&outsider_hex).is_none(),
        "the local roster must not list the snapshot admin"
    );
    ahead.add_member(
        outsider_hex.clone(),
        crate::groups::GroupRole::Admin,
        Some(hex::encode(authority.agent_id().as_bytes())),
        None,
    );
    ahead
        .seal_commit(&outsider, now_millis_u64().saturating_add(2))
        .expect("snapshot admin seals the retained head");
    let snapshot = signed_public_bootstrap_snapshot(ahead).expect("snapshot");
    assert_eq!(
        snapshot
            .commit_log
            .last()
            .expect("retained head")
            .commit
            .committed_by,
        outsider_hex
    );
    assert!(
        snapshot
            .caller_role(&outsider_hex)
            .is_some_and(|role| role.at_least(crate::groups::GroupRole::Admin)),
        "the snapshot roster must list the sender as an admin"
    );
    let (group_id, behind_hash) = install_behind(&state, behind).await;

    let error = admit_from(&state, outsider.agent_id(), snapshot)
        .await
        .expect_err("an admin who exists only in the snapshot is not catch-up consent");
    assert_eq!(
        error,
        "public-group bootstrap sender is not a known contact"
    );
    assert_eq!(installed_hash(&state, &group_id).await, behind_hash);
}

#[tokio::test]
async fn exact_frontier_from_a_non_contact_admin_is_not_consent() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (_behind, ahead) = sealed_step(&authority, &local_hex);
    let snapshot = signed_public_bootstrap_snapshot(ahead).expect("snapshot");
    let authority_hex = hex::encode(authority.agent_id().as_bytes());
    assert!(
        snapshot
            .caller_role(&authority_hex)
            .is_some_and(|role| role.at_least(crate::groups::GroupRole::Admin)),
        "the sender must be an admin on the exact frontier"
    );
    let (group_id, frontier_hash) = install_behind(&state, snapshot.clone()).await;

    let error = admit_from(&state, authority.agent_id(), snapshot)
        .await
        .expect_err("an exact frontier still needs a Known contact or a GroupInvite grant");
    assert_eq!(
        error,
        "public-group bootstrap sender is not a known contact"
    );
    assert_eq!(installed_hash(&state, &group_id).await, frontier_hash);
}

#[tokio::test]
async fn revoked_admin_is_refused_before_catchup_consent() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (behind, ahead) = sealed_step(&authority, &local_hex);
    let snapshot = signed_public_bootstrap_snapshot(ahead).expect("snapshot");
    let (group_id, behind_hash) = install_behind(&state, behind).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let record = crate::revocation::RevocationRecord::sign(
        crate::revocation::RevokedSubject::Agent(authority.agent_id()),
        authority.public_key(),
        authority.secret_key(),
        now,
        Some("catch-up consent must not apply".to_string()),
    )
    .expect("self-revocation");
    assert!(
        state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)
            .expect("revocation inserts"),
        "the admin revocation must be new"
    );

    let error = admit_from(&state, authority.agent_id(), snapshot)
        .await
        .expect_err("a revoked admin is refused before catch-up consent");
    assert_eq!(error, "public-group bootstrap sender is revoked");
    assert_eq!(installed_hash(&state, &group_id).await, behind_hash);
}

#[tokio::test]
async fn blocked_admin_cannot_catch_up() {
    let (state, _dir) = super::secure_endpoint_test_state().await.expect("state");
    let authority = crate::identity::AgentKeypair::generate().expect("authority");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (behind, ahead) = sealed_step(&authority, &local_hex);
    let snapshot = signed_public_bootstrap_snapshot(ahead).expect("snapshot");
    let (group_id, behind_hash) = install_behind(&state, behind).await;
    state
        .contacts
        .write()
        .await
        .set_trust(&authority.agent_id(), crate::contacts::TrustLevel::Blocked);
    assert!(
        state
            .contacts
            .read()
            .await
            .is_blocked(&authority.agent_id()),
        "the fixture must block the admin before admission"
    );

    let error = admit_from(&state, authority.agent_id(), snapshot)
        .await
        .expect_err("a Blocked admin must not pass catch-up consent");
    assert_eq!(
        error,
        "public-group bootstrap sender is not a known contact"
    );
    assert_eq!(installed_hash(&state, &group_id).await, behind_hash);
}
