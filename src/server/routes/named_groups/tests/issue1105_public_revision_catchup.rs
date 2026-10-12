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
        apply_signed_public_revision_catchup(&behind, &snapshot, &sender, &member_hex).is_none(),
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
    let updated = apply_signed_public_revision_catchup(&behind, &kept, &sender, &member_hex)
        .expect("the same owner still chains");
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
        apply_signed_public_revision_catchup(&behind, &swapped, &sender, &member_hex).is_none(),
        "a signed next head must not replace the installed owner"
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
    let updated =
        apply_signed_public_revision_catchup(&behind, &snapshot, &authority_hex, &member_hex)
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
        !super::super::signed_public_catchup_decide(&mut guard, "group:0", now),
        "the first peer is still inside the five-second throttle"
    );
    assert_eq!(guard.len(), super::super::SIGNED_PUBLIC_CATCHUP_SEND_LIMIT);
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
    while !pause.reached() && tokio::time::Instant::now() < deadline {
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
