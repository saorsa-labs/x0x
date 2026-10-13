//! #1113: a TreeKEM self-leave is only a roster removal until the lowest
//! active admin commits `remove_member`. ADR 0016 decision 6 names that
//! admin. ADR 0110's hand-off is still Proposed and is not what this tests.

use super::*;

struct LeaveFixture {
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
    group_id: String,
    member_id: x0x::identity::AgentId,
    member_kp: x0x::identity::AgentKeypair,
    leaver_group: x0x::mls::TreeKemMlsGroup,
    epoch_before: u64,
}

async fn two_member_treekem_group() -> Result<LeaveFixture> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let admin_id = state.agent.agent_id();
    let group_id = "cd".repeat(16);
    let group_id_bytes = hex::decode(&group_id)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
    let member_kp = x0x::identity::AgentKeypair::generate()?;
    let member_id = member_kp.agent_id();
    let member_hex = hex::encode(member_id.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &[9u8; 32])?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let added = admin_group.add_member(member_id, &kp_bytes)?;
    let leaver_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
    let epoch_before = admin_group.epoch();

    let mut info = x0x::groups::GroupInfo::new(
        "leave-rekey".to_string(),
        String::new(),
        admin_id,
        group_id.clone(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(hex::encode(admin_id.as_bytes())),
        None,
    );
    info.set_member_treekem_key_package(
        &member_hex,
        base64::engine::general_purpose::STANDARD.encode(&kp_bytes),
    );
    info.secret_epoch = epoch_before;
    info.security_binding = Some(format!("treekem:epoch={epoch_before}"));
    info.recompute_state_hash();

    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    state.treekem_groups.write().await.insert(
        group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(admin_group)),
    );

    Ok(LeaveFixture {
        state,
        _dir: dir,
        group_id,
        member_id,
        member_kp,
        leaver_group,
        epoch_before,
    })
}

/// 32 zero bytes sort below every real agent id. 32 `0xff` bytes sort above.
fn fixed_admin_hex(bytes: [u8; 32], local: &x0x::identity::AgentId, below: bool) -> String {
    let candidate = x0x::identity::AgentId(bytes);
    if below {
        assert!(
            candidate.as_bytes() < local.as_bytes(),
            "the fixed lower admin must sort below the local admin"
        );
    } else {
        assert!(
            candidate.as_bytes() > local.as_bytes(),
            "the fixed higher admin must sort above the local admin"
        );
    }
    hex::encode(bytes)
}

fn add_fixed_admin(
    info: &mut x0x::groups::GroupInfo,
    admin_id: x0x::identity::AgentId,
    admin_hex: String,
) -> String {
    info.add_member(
        admin_hex.clone(),
        x0x::groups::GroupRole::Admin,
        Some(hex::encode(admin_id.as_bytes())),
        None,
    );
    info.recompute_state_hash();
    admin_hex
}

fn add_lower_admin(info: &mut x0x::groups::GroupInfo, admin_id: x0x::identity::AgentId) -> String {
    let lower_hex = fixed_admin_hex([0u8; 32], &admin_id, true);
    add_fixed_admin(info, admin_id, lower_hex)
}

async fn signed_self_leave(fixture: &LeaveFixture) -> Result<NamedGroupMetadataEvent> {
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let groups = fixture.state.named_groups.read().await;
    let mut leaving = groups.get(&fixture.group_id).cloned().expect("group");
    drop(groups);
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision = leaving.roster_revision;
    leaving.remove_member(&member_hex, Some(member_hex.clone()));
    let commit = leaving.seal_commit(&fixture.member_kp, now_millis_u64())?;
    Ok(NamedGroupMetadataEvent::MemberRemoved {
        group_id: fixture.group_id.clone(),
        revision,
        actor: member_hex.clone(),
        agent_id: member_hex,
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    })
}

async fn live_treekem_group(
    state: &AppState,
    group_id: &str,
) -> Arc<tokio::sync::Mutex<x0x::mls::TreeKemMlsGroup>> {
    let map = state.treekem_groups.read().await;
    let group = map.get(group_id).cloned().expect("live treekem group");
    drop(map);
    group
}

async fn live_epoch(state: &AppState, group_id: &str) -> u64 {
    let group = live_treekem_group(state, group_id).await;
    let guard = group.lock().await;
    guard.epoch()
}

async fn encrypt(state: &AppState, group_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let group = live_treekem_group(state, group_id).await;
    let mut guard = group.lock().await;
    Ok(guard.encrypt_message(plaintext)?)
}

fn published_removal_commit(state: &AppState) -> Option<Vec<u8>> {
    let published = state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish recorder");
    published.iter().rev().find_map(|(_, bytes)| {
        let event = serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok()?;
        let NamedGroupMetadataEvent::MemberRemoved {
            treekem_commit_b64: Some(commit_b64),
            ..
        } = event
        else {
            return None;
        };
        base64::engine::general_purpose::STANDARD
            .decode(commit_b64)
            .ok()
    })
}

/// The lowest active admin, on applying the self-leave, advances the epoch.
/// The leaver's retained group cannot read the next epoch.
#[tokio::test]
async fn lowest_admin_rekey_locks_self_leaver_out_of_the_next_epoch() -> Result<()> {
    let mut fixture = two_member_treekem_group().await?;
    let before = encrypt(&fixture.state, &fixture.group_id, b"before-leave").await?;
    let opened = fixture
        .leaver_group
        .decrypt_message(&before)
        .expect("leaver still holds the pre-leave epoch");
    assert_eq!(opened, b"before-leave");

    let event = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, event, fixture.member_id, true, None)
            .await;
    assert!(
        applied.accepted,
        "self-leave must apply before the responsive rekey: {applied:?}"
    );

    let epoch_after = live_epoch(&fixture.state, &fixture.group_id).await;
    assert!(
        epoch_after > fixture.epoch_before,
        "lowest admin must advance the TreeKEM epoch on self-leave; before {}, after {epoch_after}",
        fixture.epoch_before
    );
    let commit = published_removal_commit(&fixture.state)
        .expect("responsive rekey must publish a TreeKEM removal commit");
    let process = fixture.leaver_group.process_commit(&commit);
    assert!(
        process.is_err(),
        "the leaver must not process the post-leave commit: {process:?}"
    );
    let after = encrypt(&fixture.state, &fixture.group_id, b"after-rekey").await?;
    let decrypted = fixture.leaver_group.decrypt_message(&after);
    assert!(
        decrypted.is_err(),
        "the leaver must not decrypt the next epoch: {decrypted:?}"
    );
    let survivors = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&after)?
    };
    assert_eq!(survivors, b"after-rekey");
    Ok(())
}

/// A higher admin updates the roster and does not rotate. The leaver keeps
/// the current epoch until the lowest admin commits.
#[tokio::test]
async fn higher_admin_does_not_rekey_a_self_leave() -> Result<()> {
    let mut fixture = two_member_treekem_group().await?;
    let admin_id = fixture.state.agent.agent_id();
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        add_lower_admin(info, admin_id);
    }
    let event = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, event, fixture.member_id, true, None)
            .await;
    assert!(
        applied.accepted,
        "roster self-leave must still apply: {applied:?}"
    );
    let epoch_after = live_epoch(&fixture.state, &fixture.group_id).await;
    assert_eq!(
        epoch_after, fixture.epoch_before,
        "a higher admin must not advance the epoch"
    );
    assert!(
        published_removal_commit(&fixture.state).is_none(),
        "a higher admin must not publish a TreeKEM removal"
    );
    let ciphertext = encrypt(&fixture.state, &fixture.group_id, b"still-same-epoch").await?;
    let opened = fixture.leaver_group.decrypt_message(&ciphertext)?;
    assert_eq!(opened, b"still-same-epoch");
    Ok(())
}

/// When the designated admin is no longer on the roster, the new lowest
/// admin's online pass commits the removal the earlier pass deferred.
#[tokio::test]
async fn online_pass_rekeys_after_the_designated_admin_is_gone() -> Result<()> {
    let mut fixture = two_member_treekem_group().await?;
    let admin_id = fixture.state.agent.agent_id();
    let lower_hex = {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        add_lower_admin(info, admin_id)
    };
    let event = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, event, fixture.member_id, true, None)
            .await;
    assert!(
        applied.accepted,
        "roster self-leave must apply: {applied:?}"
    );
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "the higher admin's apply must leave the epoch unchanged"
    );

    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.remove_member(&lower_hex, Some(hex::encode(admin_id.as_bytes())));
    }
    rekey_outstanding_treekem_self_leaves(&fixture.state).await;

    let epoch_after = live_epoch(&fixture.state, &fixture.group_id).await;
    assert!(
        epoch_after > fixture.epoch_before,
        "the new lowest admin must rekey on the online pass; before {}, after {epoch_after}",
        fixture.epoch_before
    );
    let after = encrypt(&fixture.state, &fixture.group_id, b"after-handoff").await?;
    let decrypted = fixture.leaver_group.decrypt_message(&after);
    assert!(
        decrypted.is_err(),
        "the leaver must not decrypt the epoch committed on the online pass: {decrypted:?}"
    );
    Ok(())
}

fn mark_incapable(state: &AppState, agent_id: &x0x::identity::AgentId) {
    state
        .named_group_test_recorders
        .incapable_self_leave_admins
        .lock()
        .expect("incapable admins")
        .push(*agent_id.as_bytes());
}

async fn stored_hash(state: &AppState, group_id: &str) -> String {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .expect("group")
        .state_hash
        .clone()
}

fn published_removal_event(state: &AppState) -> Option<NamedGroupMetadataEvent> {
    let published = state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish recorder");
    published.iter().rev().find_map(|(_, bytes)| {
        let event = serde_json::from_slice::<NamedGroupMetadataEvent>(bytes).ok()?;
        match &event {
            NamedGroupMetadataEvent::MemberRemoved {
                treekem_commit_b64: Some(_),
                ..
            } => Some(event),
            _ => None,
        }
    })
}

/// A roster that holds only the KeyPackage hash does not report the rekey
/// done. Restoring the bytes on the Removed member lets the next pass commit.
#[tokio::test]
async fn missing_key_package_defers_until_the_bytes_return() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let package = {
        let groups = fixture.state.named_groups.read().await;
        let info = groups.get(&fixture.group_id).expect("group");
        let member = info.members_v2.get(&member_hex).expect("member");
        assert!(member.treekem_key_package_hash.is_some());
        current_member_treekem_key_package(member).expect("package bytes")
    };
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        let member = info.members_v2.get_mut(&member_hex).expect("member");
        member.treekem_key_package_b64 = None;
    }
    let event = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, event, fixture.member_id, true, None)
            .await;
    assert!(
        applied.accepted,
        "the roster removal must apply: {applied:?}"
    );
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "a missing KeyPackage must defer the rekey"
    );
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.set_member_treekem_key_package(&member_hex, package);
    }
    rekey_outstanding_treekem_self_leaves(&fixture.state).await;
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "bytes on a Removed member must let the next pass commit"
    );
    Ok(())
}

/// A non-empty TreeKEM queue blocks the in-apply commit. The pass runs
/// after the queue is empty and extends the head that is current then.
#[tokio::test]
async fn queued_treekem_event_blocks_the_rekey_until_the_queue_is_empty() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let event = signed_self_leave(&fixture).await?;
    {
        let mut pending = fixture.state.treekem_pending_events.write().await;
        pending
            .entry(fixture.group_id.clone())
            .or_default()
            .push_back(PendingTreeKemMetadataEvent {
                event: event.clone(),
                sender: fixture.member_id,
                queued_at: std::time::Instant::now(),
            });
    }
    let applied =
        apply_named_group_metadata_event(&fixture.state, event, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "a queued TreeKEM event must block the in-apply rekey"
    );
    fixture.state.treekem_pending_events.write().await.clear();
    let hash_before = stored_hash(&fixture.state, &fixture.group_id).await;
    schedule_self_leave_rekey_if_idle(&fixture.state, &fixture.group_id).await;
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "the pass must commit once the queue is empty"
    );
    let hash_after = stored_hash(&fixture.state, &fixture.group_id).await;
    assert_ne!(
        hash_after, hash_before,
        "the rekey must extend the head that was current when the queue drained"
    );
    Ok(())
}

/// Demoting the designated admin through the role-update apply, not a
/// hand-built map edit, makes the next admin commit.
#[tokio::test]
async fn demotion_of_the_designated_admin_rekeys() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let admin_id = fixture.state.agent.agent_id();
    let lower_hex = {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        add_lower_admin(info, admin_id)
    };
    let leave = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, leave, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before
    );

    let actor = hex::encode(admin_id.as_bytes());
    let signing = fixture.state.agent.identity().agent_keypair();
    let (revision, commit) = {
        let groups = fixture.state.named_groups.read().await;
        let mut next = groups.get(&fixture.group_id).expect("group").clone();
        drop(groups);
        next.roster_revision = next.roster_revision.saturating_add(1);
        let revision = next.roster_revision;
        next.set_member_role(&lower_hex, x0x::groups::GroupRole::Member);
        let commit = next.seal_commit(signing, now_millis_u64())?;
        (revision, commit)
    };
    let role_event = NamedGroupMetadataEvent::MemberRoleUpdated {
        group_id: fixture.group_id.clone(),
        revision,
        actor,
        agent_id: lower_hex,
        role: x0x::groups::GroupRole::Member,
        commit: Some(commit),
    };
    let role_applied =
        apply_named_group_metadata_event(&fixture.state, role_event, admin_id, true, None).await;
    assert!(
        role_applied.accepted,
        "demotion must apply: {role_applied:?}"
    );
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "demoting the designated admin must run the rekey"
    );
    Ok(())
}

/// The lowest raw admin does not commit when the test marks that admin as
/// an old binary. The next eligible admin does.
#[tokio::test]
async fn old_lowest_admin_yields_to_the_next_eligible_admin() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let admin_id = fixture.state.agent.agent_id();
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        add_lower_admin(info, admin_id);
    }
    mark_incapable(&fixture.state, &x0x::identity::AgentId([0u8; 32]));
    let event = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, event, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "an incapable lower admin must not block an eligible higher admin"
    );
    Ok(())
}

/// The local admin is the lowest raw id and is marked incapable. A higher
/// eligible admin is the committer, so this daemon does not rekey.
#[tokio::test]
async fn incapable_lowest_admin_does_not_rekey() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let admin_id = fixture.state.agent.agent_id();
    mark_incapable(&fixture.state, &admin_id);
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        let higher = fixed_admin_hex([0xff; 32], &admin_id, false);
        add_fixed_admin(info, admin_id, higher);
    }
    let event = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, event, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "an incapable lowest admin must not commit"
    );
    Ok(())
}

/// A crash after the epoch is saved still has the removal event on disk.
/// Restart loads it back into the catch-up log.
#[tokio::test]
async fn restart_reloads_the_removal_event_saved_before_publish() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let event = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, event, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    assert!(published_removal_event(&fixture.state).is_some());
    fixture.state.treekem_event_log.write().await.clear();
    resume_durable_self_leave_rekeys(&fixture.state).await;
    let logs = fixture.state.treekem_event_log.read().await;
    let reloaded = logs.values().any(|events| {
        events.iter().any(|event| {
            matches!(
                event,
                NamedGroupMetadataEvent::MemberRemoved {
                    treekem_commit_b64: Some(_),
                    ..
                }
            )
        })
    });
    assert!(
        reloaded,
        "restart must reload the removal commit into the catch-up log"
    );
    Ok(())
}

/// A remaining member applies the published rekey and reaches the same
/// epoch and state hash as the committer.
#[tokio::test]
async fn remaining_member_converges_on_the_rekey() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let survivor_seed = [7u8; 32];
    let survivor_kp = x0x::identity::AgentKeypair::generate()?;
    let survivor_id = survivor_kp.agent_id();
    let survivor_hex = hex::encode(survivor_id.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(survivor_id, &survivor_seed)?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let welcome = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        let added = guard.add_member(survivor_id, &kp_bytes)?;
        added.welcome
    };
    let mut survivor = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &welcome)?;
    let survivor_snap = survivor.to_snapshot_bytes()?;
    let epoch = live_epoch(&fixture.state, &fixture.group_id).await;
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.add_member(
            survivor_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(fixture.state.agent.agent_id().as_bytes())),
            None,
        );
        info.set_member_treekem_key_package(
            &survivor_hex,
            base64::engine::general_purpose::STANDARD.encode(&kp_bytes),
        );
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();
    }
    let pre_leave = {
        let groups = fixture.state.named_groups.read().await;
        groups.get(&fixture.group_id).expect("group").clone()
    };
    let leave = signed_self_leave(&fixture).await?;
    let applied = apply_named_group_metadata_event(
        &fixture.state,
        leave.clone(),
        fixture.member_id,
        true,
        None,
    )
    .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    let committer_hash = stored_hash(&fixture.state, &fixture.group_id).await;
    let committer_epoch = live_epoch(&fixture.state, &fixture.group_id).await;
    let rekey = published_removal_event(&fixture.state).expect("rekey event");
    let commit_bytes = published_removal_commit(&fixture.state).expect("rekey commit");
    survivor
        .process_commit(&commit_bytes)
        .expect("the remaining member processes the rekey");
    assert_eq!(survivor.epoch(), committer_epoch);

    let (replica, _dir) = secure_endpoint_test_state().await?;
    replica
        .named_groups
        .write()
        .await
        .insert(fixture.group_id.clone(), pre_leave);
    let restored = x0x::mls::TreeKemMlsGroup::restore(&survivor_snap, survivor_id, &survivor_seed)?;
    replica.treekem_groups.write().await.insert(
        fixture.group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(restored)),
    );
    let replica_leave =
        apply_named_group_metadata_event(&replica, leave, fixture.member_id, true, None).await;
    assert!(
        replica_leave.accepted,
        "the replica must apply the self-leave: {replica_leave:?}"
    );
    let replica_rekey = apply_named_group_metadata_event(
        &replica,
        rekey,
        fixture.state.agent.agent_id(),
        true,
        None,
    )
    .await;
    assert!(
        replica_rekey.accepted,
        "the replica must apply the rekey: {replica_rekey:?}"
    );
    assert_eq!(
        stored_hash(&replica, &fixture.group_id).await,
        committer_hash,
        "the remaining member must reach the committer's state hash"
    );
    assert_eq!(
        live_epoch(&replica, &fixture.group_id).await,
        committer_epoch
    );
    Ok(())
}
