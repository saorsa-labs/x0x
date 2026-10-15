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
    two_member_treekem_group_with_id("cd".repeat(16)).await
}

async fn two_member_treekem_group_with_id(group_id: String) -> Result<LeaveFixture> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let admin_id = state.agent.agent_id();
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

fn publish_count(state: &AppState) -> usize {
    state
        .named_group_test_recorders
        .publish_bytes
        .lock()
        .expect("publish recorder")
        .len()
}

fn log_has_removal(event: &NamedGroupMetadataEvent, with_commit: bool) -> bool {
    match event {
        NamedGroupMetadataEvent::MemberRemoved {
            treekem_commit_b64, ..
        } => treekem_commit_b64.is_some() == with_commit,
        _ => false,
    }
}

fn add_active_peer(info: &mut x0x::groups::GroupInfo, peer: x0x::identity::AgentId) -> String {
    let peer_hex = hex::encode(peer.as_bytes());
    info.add_member(peer_hex.clone(), x0x::groups::GroupRole::Member, None, None);
    info.recompute_state_hash();
    peer_hex
}

fn empty_catchup(group_id: &str, truncated: bool) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.to_string(),
        events: Vec::new(),
        truncated,
        responder_state_hash: None,
    }
}

/// A truncated page stays open for that peer. Another peer's last page does
/// not seal. The same peer's last page does.
#[tokio::test]
async fn truncated_catchup_page_does_not_seal() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let peer = x0x::identity::AgentId([0xff; 32]);
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        add_active_peer(info, peer);
    }
    let leave = signed_self_leave(&fixture).await?;
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let truncated = TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: fixture.group_id.clone(),
        events: vec![leave],
        truncated: true,
        responder_state_hash: None,
    };
    // The transport sender is an active peer, not the leaver. The commit
    // signature is the author.
    handle_treekem_catchup_response(&fixture.state, &peer, true, truncated).await;
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "a truncated catch-up page must not seal the rekey"
    );
    {
        let groups = fixture.state.named_groups.read().await;
        let member = groups
            .get(&fixture.group_id)
            .and_then(|info| info.members_v2.get(&member_hex))
            .expect("leaver remains on the roster");
        assert_eq!(member.state, x0x::groups::GroupMemberState::Removed);
    }
    handle_treekem_catchup_response(
        &fixture.state,
        &fixture.state.agent.agent_id(),
        true,
        empty_catchup(&fixture.group_id, false),
    )
    .await;
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "another peer's terminal page must not close the open page stream"
    );
    handle_treekem_catchup_response(
        &fixture.state,
        &peer,
        true,
        empty_catchup(&fixture.group_id, false),
    )
    .await;
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "the same peer's last page must let the pass seal"
    );
    Ok(())
}

/// The in-apply path seals one leaf. A second live leaf is sealed by the
/// pass that runs after the membership guard drops.
#[tokio::test]
async fn second_live_leaf_is_sealed_after_the_in_apply_commit() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let extra_id = x0x::identity::AgentKeypair::generate()?.agent_id();
    let extra_hex = hex::encode(extra_id.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(extra_id, &[3u8; 32])?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.add_member(extra_id, &kp_bytes)?;
    }
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.add_member(
            extra_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(fixture.state.agent.agent_id().as_bytes())),
            None,
        );
        info.set_member_treekem_key_package(
            &extra_hex,
            base64::engine::general_purpose::STANDARD.encode(&kp_bytes),
        );
        let member = info.members_v2.get_mut(&extra_hex).expect("extra");
        member.state = x0x::groups::GroupMemberState::Removed;
        let epoch = {
            drop(groups);
            live_epoch(&fixture.state, &fixture.group_id).await
        };
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();
    }
    let epoch_before = live_epoch(&fixture.state, &fixture.group_id).await;
    let leave = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, leave, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await >= epoch_before.saturating_add(2),
        "both live removed leaves must be sealed, one in the apply and one after the guard drops"
    );
    Ok(())
}

/// Demotion through the role route, not the receive path, runs the pass.
#[tokio::test]
async fn demotion_route_rekeys_when_the_local_admin_becomes_designated() -> Result<()> {
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
        fixture.epoch_before,
        "the lower admin is designated, so this daemon must wait"
    );
    let response = update_member_role(
        State(Arc::clone(&fixture.state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((fixture.group_id.clone(), lower_hex)),
        Json(UpdateMemberRoleRequest {
            role: "member".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the role route must succeed"
    );
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "the role route must run the rekey after the guard drops"
    );
    Ok(())
}

/// A successful publish leaves the rekey off the republish list. Resume of a
/// state loaded from that disk still serves the predecessor and the rekey,
/// and it does not send the rekey again.
#[tokio::test]
async fn disk_restart_serves_predecessor_without_republish() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    fixture
        .state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let data_dir = fixture._dir.path().to_path_buf();
    let agent = Arc::clone(&fixture.state.agent);
    let leave = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, leave, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    let path = self_leave_rekey_outbox_path(&fixture.state, &fixture.group_id);
    let file = read_self_leave_rekey_outbox(&path).await;
    assert!(
        file.pending.is_empty(),
        "a successful publish must take the rekey off the republish list"
    );
    assert!(
        !file.served.is_empty(),
        "catch-up must still have the published rekey"
    );
    assert!(
        !file.predecessors.is_empty(),
        "catch-up must still have the roster-only self-leave"
    );
    let restarted = secure_endpoint_test_state_at(&data_dir, agent).await?;
    let named = restarted.named_groups.read().await.clone();
    let restored =
        restore_treekem_groups(&named, restarted.agent.as_ref(), &restarted.treekem_dir).await;
    *restarted.treekem_groups.write().await = restored;
    resume_durable_self_leave_rekeys(&restarted).await;
    assert_eq!(
        publish_count(&restarted),
        0,
        "restart must not send a rekey that was already published"
    );
    let logs = restarted.treekem_event_log.read().await;
    let events: Vec<_> = logs.values().flat_map(|events| events.iter()).collect();
    assert!(
        events.iter().any(|event| log_has_removal(event, false)),
        "restart must serve the predecessor self-leave"
    );
    assert!(
        events.iter().any(|event| log_has_removal(event, true)),
        "restart must serve the published rekey"
    );
    Ok(())
}

/// An outbox commit that is not in the stored chain is not published.
#[tokio::test]
async fn resume_drops_a_rekey_that_is_not_in_the_stored_chain() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    fixture
        .state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let leave = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, leave, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    let mut orphan = published_removal_event(&fixture.state).expect("rekey");
    if let NamedGroupMetadataEvent::MemberRemoved {
        revision,
        treekem_epoch,
        commit,
        ..
    } = &mut orphan
    {
        *revision = revision.saturating_add(9);
        *treekem_epoch = Some(treekem_epoch.unwrap_or(0).saturating_add(9));
        if let Some(commit) = commit.as_mut() {
            commit.state_hash = "not-in-the-stored-chain".to_string();
        }
    }
    remember_durable_self_leave_rekey(&fixture.state, &fixture.group_id, &orphan, None)
        .await
        .expect("orphan saved");
    let before = publish_count(&fixture.state);
    resume_durable_self_leave_rekeys(&fixture.state).await;
    assert_eq!(
        publish_count(&fixture.state),
        before,
        "resume must not publish a commit the stored chain does not hold"
    );
    let path = self_leave_rekey_outbox_path(&fixture.state, &fixture.group_id);
    let file = read_self_leave_rekey_outbox(&path).await;
    assert!(
        file.pending.iter().all(|event| {
            named_group_metadata_event_commit(event)
                .is_none_or(|commit| commit.state_hash != "not-in-the-stored-chain")
        }),
        "the unapplied commit must leave the republish list"
    );
    Ok(())
}

/// Two replicas of one tree apply one signed leave. Only the lower admin
/// commits. The higher admin applies that commit and reaches the same hash.
#[tokio::test]
async fn two_concurrent_admins_only_the_lower_id_commits() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let admin_b_kp = x0x::identity::AgentKeypair::generate()?;
    let id_b = admin_b_kp.agent_id();
    let (state_b, _dir_b) = secure_endpoint_test_state_with_key(admin_b_kp).await?;
    assert_eq!(state_b.agent.agent_id(), id_b);
    let id_a = fixture.state.agent.agent_id();
    let lower_is_a = id_a.as_bytes() < id_b.as_bytes();
    let b_hex = hex::encode(id_b.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(id_b, &[4u8; 32])?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let welcome = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        let added = guard.add_member(id_b, &kp_bytes)?;
        added.welcome
    };
    let admin_b_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &welcome)?;
    let epoch = live_epoch(&fixture.state, &fixture.group_id).await;
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.add_member(
            b_hex.clone(),
            x0x::groups::GroupRole::Admin,
            Some(hex::encode(id_a.as_bytes())),
            None,
        );
        info.set_member_treekem_key_package(
            &b_hex,
            base64::engine::general_purpose::STANDARD.encode(&kp_bytes),
        );
        info.secret_epoch = epoch;
        info.security_binding = Some(format!("treekem:epoch={epoch}"));
        info.recompute_state_hash();
    }
    let shared = {
        let groups = fixture.state.named_groups.read().await;
        groups.get(&fixture.group_id).expect("group").clone()
    };
    state_b
        .named_groups
        .write()
        .await
        .insert(fixture.group_id.clone(), shared);
    state_b.treekem_groups.write().await.insert(
        fixture.group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(admin_b_group)),
    );
    let leave = signed_self_leave(&fixture).await?;
    let epoch_before = live_epoch(&fixture.state, &fixture.group_id).await;
    let (applied_a, applied_b) = tokio::join!(
        apply_named_group_metadata_event(
            &fixture.state,
            leave.clone(),
            fixture.member_id,
            true,
            None
        ),
        apply_named_group_metadata_event(&state_b, leave, fixture.member_id, true, None),
    );
    assert!(
        applied_a.accepted,
        "admin A must apply the shared leave: {applied_a:?}"
    );
    assert!(
        applied_b.accepted,
        "admin B must apply the shared leave: {applied_b:?}"
    );
    let epoch_a = live_epoch(&fixture.state, &fixture.group_id).await;
    let epoch_b = live_epoch(&state_b, &fixture.group_id).await;
    let (committer, holder, committer_epoch) = if lower_is_a {
        assert!(epoch_a > epoch_before, "the lower admin must commit");
        assert_eq!(epoch_b, epoch_before, "the higher admin must hold off");
        (&fixture.state, &state_b, epoch_a)
    } else {
        assert!(epoch_b > epoch_before, "the lower admin must commit");
        assert_eq!(epoch_a, epoch_before, "the higher admin must hold off");
        (&state_b, &fixture.state, epoch_b)
    };
    let rekey = published_removal_event(committer).expect("the lower admin publishes one rekey");
    let committer_id = committer.agent.agent_id();
    let applied = apply_named_group_metadata_event(holder, rekey, committer_id, true, None).await;
    assert!(
        applied.accepted,
        "the higher admin must apply the shared rekey: {applied:?}"
    );
    assert_eq!(
        stored_hash(holder, &fixture.group_id).await,
        stored_hash(committer, &fixture.group_id).await,
        "both replicas must reach the committer's state hash"
    );
    assert_eq!(live_epoch(holder, &fixture.group_id).await, committer_epoch);
    Ok(())
}

async fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !ready() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// An older hash-only Removed seat must not be the only package request
/// while a later leaver still has a live leaf.
#[tokio::test]
async fn historical_hash_only_seat_does_not_block_the_live_leaver() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let old = x0x::identity::AgentId([0u8; 32]);
    let old_hex = hex::encode(old.as_bytes());
    let witness = x0x::identity::AgentId([0x11; 32]);
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        add_active_peer(info, witness);
        info.add_member(old_hex.clone(), x0x::groups::GroupRole::Member, None, None);
        info.set_member_treekem_key_package(&old_hex, "historical-package".to_string());
        let member = info.members_v2.get_mut(&old_hex).expect("old seat");
        member.state = x0x::groups::GroupMemberState::Removed;
        member.treekem_key_package_b64 = None;
        let leaver = info.members_v2.get_mut(&member_hex).expect("leaver");
        leaver.treekem_key_package_b64 = None;
        info.recompute_state_hash();
    }
    let leaver_pause = detached_send_test_seam::arm(
        &detached_send_test_seam::key_package_catchup_key(&fixture.group_id, &member_hex),
    );
    let old_pause = detached_send_test_seam::arm(
        &detached_send_test_seam::key_package_catchup_key(&fixture.group_id, &old_hex),
    );
    let leave = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, leave, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "missing bytes must defer the rekey"
    );
    wait_until(|| leaver_pause.reached()).await;
    assert!(
        leaver_pause.reached(),
        "the live leaver's package must be requested"
    );
    assert!(
        !old_pause.reached(),
        "a historical hash-only seat must not be the package request"
    );
    Ok(())
}

/// A failed outbox directory sync leaves the saved commit in place. The
/// retry installs that commit. It does not persist a second payload.
#[tokio::test]
async fn retry_after_outbox_sync_failure_reuses_the_saved_commit() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    fail_self_leave_outbox_write_number(2);
    skip_self_leave_rekey_ack(true);
    fixture
        .state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let leave = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, leave, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the roster leave must apply: {applied:?}");
    // The failed parent fsync rolls the tree back. The apply's follow-up
    // pass is the retry. It restores the saved snapshot. It does not
    // create a second TreeKEM commit.
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "the follow-up retry must install the saved commit"
    );
    let path = self_leave_rekey_outbox_path(&fixture.state, &fixture.group_id);
    let saved = read_self_leave_rekey_outbox(&path).await;
    assert!(
        !saved.predecessors.is_empty(),
        "the predecessor must be durable before the failed rekey write"
    );
    assert_eq!(
        saved.pending.len(),
        1,
        "one pending rekey must remain until the ack"
    );
    let pending = &saved.pending[0];
    let saved_bytes = match pending {
        NamedGroupMetadataEvent::MemberRemoved {
            treekem_commit_b64: Some(commit_b64),
            ..
        } => base64::engine::general_purpose::STANDARD.decode(commit_b64)?,
        _ => panic!("pending event must be the rekey"),
    };
    assert!(
        saved.committer_snapshots.is_empty(),
        "a durable epoch must not keep the post-commit private tree in the outbox"
    );
    let published = published_removal_commit(&fixture.state).expect("published bytes");
    assert_eq!(
        published, saved_bytes,
        "the published commit must be the saved commit, not a second payload"
    );
    let epoch_after = live_epoch(&fixture.state, &fixture.group_id).await;
    fail_self_leave_outbox_write_number(0);
    rekey_outstanding_treekem_self_leaves(&fixture.state).await;
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        epoch_after,
        "a later pass must not seal a second commit for the same leave"
    );
    let again = read_self_leave_rekey_outbox(&path).await;
    assert_eq!(again.pending.len(), 1, "the unacked rekey stays pending");
    skip_self_leave_rekey_ack(false);
    Ok(())
}

async fn publish_fault_leaves_rekey_pending(fault: &str) -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    fixture
        .state
        .named_group_test_recorders
        .metadata_publish_fault
        .lock()
        .expect("fault")
        .replace(fault.to_string());
    let leave = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, leave, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "the epoch is installed before publish"
    );
    let path = self_leave_rekey_outbox_path(&fixture.state, &fixture.group_id);
    let file = read_self_leave_rekey_outbox(&path).await;
    assert!(
        !file.pending.is_empty(),
        "{fault} must leave the rekey pending"
    );
    assert!(
        file.served.is_empty(),
        "{fault} must not mark the rekey published"
    );
    fixture
        .state
        .named_group_test_recorders
        .metadata_publish_fault
        .lock()
        .expect("fault")
        .take();
    fixture
        .state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let before = publish_count(&fixture.state);
    resume_durable_self_leave_rekeys(&fixture.state).await;
    assert!(
        publish_count(&fixture.state) > before,
        "resume must send a rekey that publish did not accept"
    );
    let after = read_self_leave_rekey_outbox(&path).await;
    assert!(
        after.pending.is_empty(),
        "a later successful publish must take the rekey off the republish list"
    );
    Ok(())
}

#[tokio::test]
async fn failed_publish_stays_pending() -> Result<()> {
    publish_fault_leaves_rekey_pending("transport").await
}

#[tokio::test]
async fn timed_out_publish_stays_pending() -> Result<()> {
    publish_fault_leaves_rekey_pending("timeout").await
}

/// Resume must not drop a pending rekey that the live path has saved and
/// not yet installed. The hash check runs under the membership lock.
#[tokio::test]
async fn resume_keeps_a_rekey_until_the_membership_lock_shows_it_stored() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    let leave = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, leave, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    let mut pending = published_removal_event(&fixture.state).expect("rekey");
    if let NamedGroupMetadataEvent::MemberRemoved { commit, .. } = &mut pending {
        if let Some(commit) = commit.as_mut() {
            commit.state_hash = "installed-while-resume-waits".to_string();
        }
    }
    remember_durable_self_leave_rekey(&fixture.state, &fixture.group_id, &pending, None)
        .await
        .expect("pending saved");
    let lock = group_membership_lock(&fixture.state, &fixture.group_id).await;
    let guard = lock.lock().await;
    let state = Arc::clone(&fixture.state);
    let group_id = fixture.group_id.clone();
    let resumed = tokio::spawn(async move {
        resume_durable_self_leave_rekeys(&state).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let path = self_leave_rekey_outbox_path(&fixture.state, &fixture.group_id);
    let mid = read_self_leave_rekey_outbox(&path).await;
    assert!(
        mid.pending.iter().any(|event| {
            named_group_metadata_event_commit(event)
                .is_some_and(|commit| commit.state_hash == "installed-while-resume-waits")
        }),
        "resume must not drop the event while the membership lock is held"
    );
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group");
        info.state_hash = "installed-while-resume-waits".to_string();
    }
    let before = publish_count(&fixture.state);
    drop(guard);
    resumed.await.expect("resume");
    assert!(
        publish_count(&fixture.state) > before,
        "resume must publish once the stored chain holds the commit"
    );
    Ok(())
}

#[cfg(unix)]
fn unix_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

/// The outbox holds the post-commit private tree at mode 0600. Persist
/// deletes that copy. A later wipe deletes the file.
#[tokio::test]
async fn outbox_private_tree_is_mode_0600_dropped_after_persist_and_wiped() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    skip_self_leave_rekey_ack(true);
    fixture
        .state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let leave = signed_self_leave(&fixture).await?;
    let applied =
        apply_named_group_metadata_event(&fixture.state, leave, fixture.member_id, true, None)
            .await;
    assert!(applied.accepted, "the leave must apply: {applied:?}");
    let path = self_leave_rekey_outbox_path(&fixture.state, &fixture.group_id);
    #[cfg(unix)]
    assert_eq!(unix_mode(&path), 0o600, "outbox_mode");
    let file = read_self_leave_rekey_outbox(&path).await;
    assert!(
        file.committer_snapshots.is_empty(),
        "persist must delete the outbox private tree"
    );
    #[cfg(unix)]
    {
        let live_snap = treekem_snapshot_path(&fixture.state.treekem_dir, &fixture.group_id);
        assert_eq!(unix_mode(&live_snap), 0o600, "live_snap_mode");
    }

    let pending = file.pending.first().expect("pending rekey").clone();
    let snapshot = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let guard = group.lock().await;
        guard.to_snapshot_bytes()?
    };
    remember_durable_self_leave_rekey(&fixture.state, &fixture.group_id, &pending, Some(&snapshot))
        .await?;
    #[cfg(unix)]
    assert_eq!(unix_mode(&path), 0o600, "crash-window outbox_mode");
    let parked = read_self_leave_rekey_outbox(&path).await;
    assert_eq!(parked.committer_snapshots.len(), 1);
    let saved_tree = base64::engine::general_purpose::STANDARD
        .decode(&parked.committer_snapshots[0].snapshot_b64)?;
    let group_id_bytes = hex::decode(&fixture.group_id)?;
    let seed = agent_treekem_seed(fixture.state.agent.as_ref(), &group_id_bytes);
    let mut restored =
        x0x::mls::TreeKemMlsGroup::restore(&saved_tree, fixture.state.agent.agent_id(), &seed)?;
    let ciphertext = encrypt(&fixture.state, &fixture.group_id, b"live").await?;
    let opened = restored
        .decrypt_message(&ciphertext)
        .expect("snapshot_decrypts_live");
    assert_eq!(opened, b"live");

    wipe_local_group_crypto_material(&fixture.state, &fixture.group_id, None, "test-wipe").await;
    assert!(
        !tokio::fs::try_exists(&path).await?,
        "after_wipe_outbox_snapshots"
    );
    skip_self_leave_rekey_ack(false);
    Ok(())
}

/// A member may relay an admin's signed removal. It may not attach its own
/// TreeKEM commit. The victim stays on the pre-rekey epoch, then the genuine
/// rekey installs and the leaver cannot read it.
#[tokio::test]
async fn relayed_removal_rejects_another_members_treekem_commit() -> Result<()> {
    let mut fixture = two_member_treekem_group().await?;
    let member_b_kp = x0x::identity::AgentKeypair::generate()?;
    let member_b = member_b_kp.agent_id();
    let (victim_state, _victim_dir) = secure_endpoint_test_state().await?;
    let victim_id = victim_state.agent.agent_id();

    let b_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_b, &[4u8; 32])?;
    let b_pkg = b_prepared.key_package_bytes().to_vec();
    let b_added = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.add_member(member_b, &b_pkg)?
    };
    fixture.leaver_group.process_commit(&b_added.commit)?;
    let mut member_b_group =
        x0x::mls::TreeKemMlsGroup::join_from_welcome(b_prepared, &b_added.welcome)?;

    let victim_seed = [5u8; 32];
    let victim_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(victim_id, &victim_seed)?;
    let victim_pkg = victim_prepared.key_package_bytes().to_vec();
    let victim_added = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.add_member(victim_id, &victim_pkg)?
    };
    fixture.leaver_group.process_commit(&victim_added.commit)?;
    member_b_group.process_commit(&victim_added.commit)?;
    let victim_group =
        x0x::mls::TreeKemMlsGroup::join_from_welcome(victim_prepared, &victim_added.welcome)?;

    let epoch_before = live_epoch(&fixture.state, &fixture.group_id).await;
    let b_hex = hex::encode(member_b.as_bytes());
    let victim_hex = hex::encode(victim_id.as_bytes());
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        let admin_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
        info.add_member(
            b_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.set_member_treekem_key_package(
            &b_hex,
            base64::engine::general_purpose::STANDARD.encode(&b_pkg),
        );
        info.add_member(
            victim_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
        info.set_member_treekem_key_package(
            &victim_hex,
            base64::engine::general_purpose::STANDARD.encode(&victim_pkg),
        );
        info.secret_epoch = epoch_before;
        info.security_binding = Some(format!("treekem:epoch={epoch_before}"));
        info.recompute_state_hash();
    }
    let shared = {
        let groups = fixture.state.named_groups.read().await;
        groups.get(&fixture.group_id).expect("group").clone()
    };
    victim_state
        .named_groups
        .write()
        .await
        .insert(fixture.group_id.clone(), shared);
    victim_state.treekem_groups.write().await.insert(
        fixture.group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(victim_group)),
    );

    let attacker_commit = member_b_group.update()?;
    let leave = signed_self_leave(&fixture).await?;
    fixture
        .state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let applied = apply_named_group_metadata_event(
        &fixture.state,
        leave.clone(),
        fixture.member_id,
        true,
        None,
    )
    .await;
    assert!(
        applied.accepted,
        "the admin must seal the leave: {applied:?}"
    );
    let victim_leave =
        apply_named_group_metadata_event(&victim_state, leave, fixture.member_id, true, None).await;
    assert!(
        victim_leave.accepted,
        "the victim must apply the roster leave: {victim_leave:?}"
    );
    assert_eq!(
        live_epoch(&victim_state, &fixture.group_id).await,
        epoch_before,
        "the roster leave must not advance the victim's epoch"
    );
    let genuine = published_removal_event(&fixture.state).expect("genuine rekey");
    let genuine_hash = named_group_metadata_event_commit(&genuine)
        .expect("signed commit")
        .state_hash
        .clone();
    let mut relayed = genuine.clone();
    if let NamedGroupMetadataEvent::MemberRemoved {
        treekem_commit_b64, ..
    } = &mut relayed
    {
        *treekem_commit_b64 =
            Some(base64::engine::general_purpose::STANDARD.encode(&attacker_commit));
    }
    let relayed_hash = named_group_metadata_event_commit(&relayed)
        .expect("signed commit")
        .state_hash
        .clone();
    assert_eq!(genuine_hash, relayed_hash, "roster_hash_equal");

    let admin_id = fixture.state.agent.agent_id();
    let rejected =
        apply_named_group_metadata_event(&victim_state, relayed, admin_id, true, None).await;
    assert!(
        !rejected.accepted,
        "a relayed TreeKEM commit from another member must be rejected: {rejected:?}"
    );
    assert_eq!(
        live_epoch(&victim_state, &fixture.group_id).await,
        epoch_before,
        "the victim must stay on the pre-rekey epoch"
    );

    let installed =
        apply_named_group_metadata_event(&victim_state, genuine, admin_id, true, None).await;
    assert!(
        installed.accepted,
        "the genuine rekey must still install: {installed:?}"
    );
    assert_eq!(
        live_epoch(&victim_state, &fixture.group_id).await,
        live_epoch(&fixture.state, &fixture.group_id).await
    );
    let ciphertext = encrypt(&fixture.state, &fixture.group_id, b"after-genuine").await?;
    let victim_opened = {
        let group = live_treekem_group(&victim_state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(victim_opened, b"after-genuine");
    assert!(
        fixture.leaver_group.decrypt_message(&ciphertext).is_err(),
        "the leaver must not read the victim's new traffic"
    );
    assert!(
        member_b_group.decrypt_message(&ciphertext).is_err(),
        "the other member's own update must not read the genuine epoch"
    );
    Ok(())
}

struct CatchupRelay {
    fixture: LeaveFixture,
    victim_state: Arc<AppState>,
    _victim_dir: tempfile::TempDir,
    member_b: x0x::identity::AgentId,
    attacker_commit: Vec<u8>,
    epoch_before: u64,
}

async fn catchup_relay_fixture() -> Result<CatchupRelay> {
    let mut fixture = two_member_treekem_group().await?;
    let member_b_kp = x0x::identity::AgentKeypair::generate()?;
    let member_b = member_b_kp.agent_id();
    let (victim_state, victim_dir) = secure_endpoint_test_state().await?;
    let victim_id = victim_state.agent.agent_id();

    let b_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_b, &[4u8; 32])?;
    let b_pkg = b_prepared.key_package_bytes().to_vec();
    let b_added = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.add_member(member_b, &b_pkg)?
    };
    fixture.leaver_group.process_commit(&b_added.commit)?;
    let mut member_b_group =
        x0x::mls::TreeKemMlsGroup::join_from_welcome(b_prepared, &b_added.welcome)?;

    let victim_prepared = x0x::mls::TreeKemMlsGroup::prepare_member(victim_id, &[5u8; 32])?;
    let victim_pkg = victim_prepared.key_package_bytes().to_vec();
    let victim_added = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.add_member(victim_id, &victim_pkg)?
    };
    fixture.leaver_group.process_commit(&victim_added.commit)?;
    member_b_group.process_commit(&victim_added.commit)?;
    let victim_group =
        x0x::mls::TreeKemMlsGroup::join_from_welcome(victim_prepared, &victim_added.welcome)?;

    let epoch_before = live_epoch(&fixture.state, &fixture.group_id).await;
    let b_hex = hex::encode(member_b.as_bytes());
    let victim_hex = hex::encode(victim_id.as_bytes());
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        let admin_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
        info.add_member(
            b_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.set_member_treekem_key_package(
            &b_hex,
            base64::engine::general_purpose::STANDARD.encode(&b_pkg),
        );
        info.add_member(
            victim_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
        info.set_member_treekem_key_package(
            &victim_hex,
            base64::engine::general_purpose::STANDARD.encode(&victim_pkg),
        );
        info.secret_epoch = epoch_before;
        info.security_binding = Some(format!("treekem:epoch={epoch_before}"));
        info.recompute_state_hash();
    }
    let shared = {
        let groups = fixture.state.named_groups.read().await;
        groups.get(&fixture.group_id).expect("group").clone()
    };
    victim_state
        .named_groups
        .write()
        .await
        .insert(fixture.group_id.clone(), shared);
    victim_state.treekem_groups.write().await.insert(
        fixture.group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(victim_group)),
    );
    let attacker_commit = member_b_group.update()?;
    Ok(CatchupRelay {
        fixture,
        victim_state,
        _victim_dir: victim_dir,
        member_b,
        attacker_commit,
        epoch_before,
    })
}

fn swap_treekem_commit(event: &NamedGroupMetadataEvent, commit: &[u8]) -> NamedGroupMetadataEvent {
    let mut relayed = event.clone();
    if let NamedGroupMetadataEvent::MemberRemoved {
        treekem_commit_b64, ..
    } = &mut relayed
    {
        *treekem_commit_b64 = Some(base64::engine::general_purpose::STANDARD.encode(commit));
    }
    relayed
}

async fn deliver_catchup(
    state: &Arc<AppState>,
    sender: &x0x::identity::AgentId,
    group_id: &str,
    event: NamedGroupMetadataEvent,
) {
    handle_treekem_catchup_response(
        state,
        sender,
        true,
        TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: group_id.to_string(),
            events: vec![event],
            truncated: false,
            responder_state_hash: None,
        },
    )
    .await;
}

async fn group_is_quarantined(state: &AppState, group_id: &str) -> bool {
    let groups = state.named_groups.read().await;
    groups.get(group_id).expect("group").is_fork_quarantined()
}

/// The admin remove route still seals `treekem:epoch=N`. A third party
/// cannot relay those bytes, substituted or genuine. The author can.
#[tokio::test]
async fn catchup_legacy_binding_stays_with_the_author() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    let member_hex = hex::encode(cast.fixture.member_id.as_bytes());
    cast.fixture
        .state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let response = remove_named_group_member(
        State(Arc::clone(&cast.fixture.state)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((cast.fixture.group_id.clone(), member_hex)),
    )
    .await
    .into_response();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the admin remove route must seal"
    );
    let genuine = published_removal_event(&cast.fixture.state).expect("legacy removal");
    let binding = named_group_metadata_event_commit(&genuine)
        .expect("signed commit")
        .security_binding
        .clone()
        .expect("legacy binding");
    assert!(
        binding.starts_with("treekem:epoch=") && !binding.contains(":commit="),
        "the admin remove route must keep the legacy binding, got {binding}"
    );
    let substituted = swap_treekem_commit(&genuine, &cast.attacker_commit);
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        substituted,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        cast.epoch_before,
        "a substituted legacy relay must not advance the epoch"
    );
    assert!(
        !group_is_quarantined(&cast.victim_state, &cast.fixture.group_id).await,
        "a rejected legacy relay must not quarantine the group"
    );
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        genuine.clone(),
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        cast.epoch_before,
        "a third party must not install a legacy TreeKEM commit"
    );
    deliver_catchup(
        &cast.victim_state,
        &cast.fixture.state.agent.agent_id(),
        &cast.fixture.group_id,
        genuine,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        live_epoch(&cast.fixture.state, &cast.fixture.group_id).await,
        "the author must still deliver the legacy removal"
    );
    let ciphertext = encrypt(&cast.fixture.state, &cast.fixture.group_id, b"author-epoch").await?;
    let victim_opened = {
        let group = live_treekem_group(&cast.victim_state, &cast.fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(victim_opened, b"author-epoch");
    assert!(
        cast.fixture
            .leaver_group
            .decrypt_message(&ciphertext)
            .is_err(),
        "the removed member must not read the author's new ciphertext"
    );
    Ok(())
}

/// A digest-bound rekey can be relayed. Substituted bytes cannot.
#[tokio::test]
async fn catchup_third_party_relays_a_digest_bound_rekey() -> Result<()> {
    let mut cast = catchup_relay_fixture().await?;
    cast.fixture
        .state
        .named_group_test_recorders
        .metadata_publish_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let leave = signed_self_leave(&cast.fixture).await?;
    let applied = apply_named_group_metadata_event(
        &cast.fixture.state,
        leave.clone(),
        cast.fixture.member_id,
        true,
        None,
    )
    .await;
    assert!(
        applied.accepted,
        "the admin must seal the leave: {applied:?}"
    );
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        leave,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        cast.epoch_before,
        "the roster leave must not advance the epoch"
    );
    let genuine = published_removal_event(&cast.fixture.state).expect("digest rekey");
    let binding = named_group_metadata_event_commit(&genuine)
        .expect("signed commit")
        .security_binding
        .clone()
        .expect("digest binding");
    assert!(
        binding.contains(":commit="),
        "the self-leave rekey must name the TreeKEM digest, got {binding}"
    );
    let substituted = swap_treekem_commit(&genuine, &cast.attacker_commit);
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        substituted,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        cast.epoch_before,
        "a substituted digest relay must not install"
    );
    assert!(
        !group_is_quarantined(&cast.victim_state, &cast.fixture.group_id).await,
        "a rejected digest relay must not quarantine the group"
    );
    deliver_catchup(
        &cast.victim_state,
        &cast.member_b,
        &cast.fixture.group_id,
        genuine,
    )
    .await;
    assert_eq!(
        live_epoch(&cast.victim_state, &cast.fixture.group_id).await,
        live_epoch(&cast.fixture.state, &cast.fixture.group_id).await,
        "a third party must relay the genuine digest-bound rekey"
    );
    let ciphertext = encrypt(&cast.fixture.state, &cast.fixture.group_id, b"digest-epoch").await?;
    let victim_opened = {
        let group = live_treekem_group(&cast.victim_state, &cast.fixture.group_id).await;
        let mut guard = group.lock().await;
        guard.decrypt_message(&ciphertext)?
    };
    assert_eq!(victim_opened, b"digest-epoch");
    assert!(
        cast.fixture
            .leaver_group
            .decrypt_message(&ciphertext)
            .is_err(),
        "the leaver must not read the relayed epoch"
    );
    Ok(())
}

async fn mark_leaver_removed(fixture: &LeaveFixture) {
    let member_hex = hex::encode(fixture.member_id.as_bytes());
    let mut groups = fixture.state.named_groups.write().await;
    let info = groups.get_mut(&fixture.group_id).expect("group");
    info.remove_member(&member_hex, Some(member_hex.clone()));
}

fn catchup_page(
    group_id: &str,
    truncated: bool,
    responder_state_hash: Option<String>,
) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.to_string(),
        events: Vec::new(),
        truncated,
        responder_state_hash,
    }
}

async fn saved_head(state: &AppState, group_id: &str) -> String {
    let groups = state.named_groups.read().await;
    groups.get(group_id).expect("group").state_hash.clone()
}

async fn encrypt_status(state: &AppState, group_id: &str) -> StatusCode {
    let payload = base64::engine::general_purpose::STANDARD.encode(b"secret");
    let (status, _) =
        super::super::treekem_group_encrypt(state, group_id, None, &payload, None).await;
    status
}

fn key_package_reply(
    group_id: &str,
    responder_state_hash: Option<String>,
) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.to_string(),
        events: vec![NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.to_string(),
            stable_group_id: None,
            member_agent_id: "not-a-member".to_string(),
            member_public_key_b64: String::new(),
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: String::new(),
            invite_secret: String::new(),
            ts_ms: 0,
            treekem_key_package_b64: None,
            kem_public_key_b64: None,
            kem_signature_b64: None,
            certificate_b64: None,
            recovery_authority_agent_id: None,
            recovery_authority_public_key_b64: None,
            recovery_authority_signature_b64: None,
            recovery_authority_commit: None,
            signature_b64: String::new(),
        }],
        truncated: false,
        responder_state_hash,
    }
}

async fn startup_with_witness(group_id: &str) -> Result<(LeaveFixture, x0x::identity::AgentId)> {
    let fixture = two_member_treekem_group_with_id(group_id.to_string()).await?;
    let admin_id = fixture.state.agent.agent_id();
    let witness = x0x::identity::AgentId([0xff; 32]);
    let witness_hex = fixed_admin_hex([0xff; 32], &admin_id, false);
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        add_fixed_admin(info, admin_id, witness_hex);
    }
    mark_leaver_removed(&fixture).await;
    Ok((fixture, witness))
}

/// Startup must not seal on a timer, an empty page, or a hash that is not
/// the local saved head. The matching head is the signal that permits the seal.
#[tokio::test]
async fn startup_seals_only_after_the_peer_reports_the_saved_head() -> Result<()> {
    // A distinct id: the catch-up gate is process-wide, and the other
    // tests in this module share "cd" * 16.
    let (fixture, witness) = startup_with_witness(&"ce".repeat(16)).await?;
    startup_self_leave_rekey(&fixture.state).await;
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "startup must not seal before the saved head is verified"
    );
    let head = saved_head(&fixture.state, &fixture.group_id).await;
    for page in [
        catchup_page(&fixture.group_id, false, None),
        catchup_page(
            &fixture.group_id,
            false,
            Some("newer-saved-head".to_string()),
        ),
        key_package_reply(&fixture.group_id, Some(head.clone())),
    ] {
        handle_treekem_catchup_response(&fixture.state, &witness, true, page).await;
        assert_eq!(
            live_epoch(&fixture.state, &fixture.group_id).await,
            fixture.epoch_before,
            "a page without the local saved head must not seal"
        );
    }
    let head = saved_head(&fixture.state, &fixture.group_id).await;
    handle_treekem_catchup_response(
        &fixture.state,
        &witness,
        true,
        catchup_page(&fixture.group_id, false, Some(head)),
    )
    .await;
    let epoch_after = live_epoch(&fixture.state, &fixture.group_id).await;
    assert!(
        epoch_after > fixture.epoch_before,
        "the matching saved head must let the designated admin seal; \
         before {}, after {epoch_after}",
        fixture.epoch_before
    );
    Ok(())
}

/// With no other active member, no peer can hold a later head. Startup seals
/// without a catch-up response and without a wait.
#[tokio::test]
async fn startup_seals_when_no_other_active_member_can_be_ahead() -> Result<()> {
    let fixture = two_member_treekem_group().await?;
    mark_leaver_removed(&fixture).await;
    startup_self_leave_rekey(&fixture.state).await;
    let epoch_after = live_epoch(&fixture.state, &fixture.group_id).await;
    assert!(
        epoch_after > fixture.epoch_before,
        "startup must seal when no other active member remains; before {}, after {epoch_after}",
        fixture.epoch_before
    );
    Ok(())
}

/// A restarted responder with an empty event log still reports its saved
/// head. That newer head must not let the committer seal.
#[tokio::test]
async fn cold_responder_newer_head_does_not_clear_the_startup_gate() -> Result<()> {
    let (responder, requester) = startup_with_witness(&"c1".repeat(16)).await?;
    {
        let mut groups = responder.state.named_groups.write().await;
        let info = groups.get_mut(&responder.group_id).expect("group");
        info.state_hash = "newer-saved-head".to_string();
    }
    handle_treekem_catchup_request(
        &responder.state,
        &requester,
        true,
        TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: responder.group_id.clone(),
            requester_agent_id: hex::encode(requester.as_bytes()),
            from_revision: 0,
            from_treekem_epoch: 0,
            current_state_hash: "older-head".to_string(),
            missing_prev_state_hash: None,
            target_member_id: None,
            limit: 8,
        },
    )
    .await;
    let recorded = responder
        .state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .last()
        .cloned()
        .expect("cold responder built a page");
    let page: TreeKemCatchupResponse = serde_json::from_slice(&recorded)?;
    assert!(page.events.is_empty(), "a cold log has no membership page");
    assert!(!page.truncated, "an empty cold log is a terminal page");
    assert_eq!(
        page.responder_state_hash.as_deref(),
        Some("newer-saved-head"),
        "the cold responder must report its saved head"
    );

    let (committer, witness) = startup_with_witness(&"c2".repeat(16)).await?;
    startup_self_leave_rekey(&committer.state).await;
    let mut foreign = page;
    foreign.group_id = committer.group_id.clone();
    handle_treekem_catchup_response(&committer.state, &witness, true, foreign).await;
    assert_eq!(
        live_epoch(&committer.state, &committer.group_id).await,
        committer.epoch_before,
        "a newer saved head must not clear the startup gate"
    );
    Ok(())
}

/// The last other active member can leave before answering. The roster fact
/// retires the obligation under the membership lock, and the epoch advances.
#[tokio::test]
async fn startup_seals_when_the_last_other_member_leaves_during_the_wait() -> Result<()> {
    let (fixture, witness) = startup_with_witness(&"c3".repeat(16)).await?;
    startup_self_leave_rekey(&fixture.state).await;
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "the wait must hold while the other member is still active"
    );
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.remove_member(
            &hex::encode(witness.as_bytes()),
            Some(hex::encode(fixture.state.agent.agent_id().as_bytes())),
        );
    }
    schedule_self_leave_rekey_if_idle(&fixture.state, &fixture.group_id).await;
    let epoch_after = live_epoch(&fixture.state, &fixture.group_id).await;
    assert!(
        epoch_after > fixture.epoch_before,
        "the last other member leaving must retire the wait and seal; \
         before {}, after {epoch_after}",
        fixture.epoch_before
    );
    Ok(())
}

/// A Removed row whose leaf is already gone must not arm the startup wait,
/// even when another active member remains.
#[tokio::test]
async fn historical_removed_row_does_not_open_the_startup_wait() -> Result<()> {
    let (fixture, _witness) = startup_with_witness(&"c4".repeat(16)).await?;
    let admin_id = fixture.state.agent.agent_id();
    let group_id_bytes = hex::decode(&fixture.group_id)?;
    let seed = super::super::agent_treekem_seed(fixture.state.agent.as_ref(), &group_id_bytes);
    let solo = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
    fixture.state.treekem_groups.write().await.insert(
        fixture.group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(solo)),
    );
    startup_self_leave_rekey(&fixture.state).await;
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        0,
        "a historical Removed row must not send startup catch-up"
    );
    assert_eq!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::OK,
        "a historical Removed row must not withhold ciphertext"
    );
    Ok(())
}

/// A failed startup send stays pending. Reconnect may retry inside the
/// per-peer bound. When that peer's three sends are spent, the wait ends
/// and the designated admin seals.
#[tokio::test]
async fn failed_startup_send_retries_within_a_bound_and_withholds_ciphertext() -> Result<()> {
    let (fixture, _witness) = startup_with_witness(&"c5".repeat(16)).await?;
    fixture
        .state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(false, std::sync::atomic::Ordering::SeqCst);
    startup_self_leave_rekey(&fixture.state).await;
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 1);
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "a failed send must not seal"
    );
    assert_eq!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::CONFLICT,
        "new ciphertext must be withheld while the live leaf remains"
    );
    retry_startup_self_leave_catchup(&fixture.state).await;
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 2);
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "a second failed send must not seal"
    );
    retry_startup_self_leave_catchup(&fixture.state).await;
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 3);
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "spending the per-peer send bound must end the wait and seal"
    );
    assert_ne!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::CONFLICT,
        "ciphertext must not stay withheld after the send bound"
    );
    retry_startup_self_leave_catchup(&fixture.state).await;
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        3,
        "the send bound must stop further catch-up requests"
    );
    Ok(())
}

/// Four other members each receive a startup ask. The old group-wide cap
/// stopped at three, so the fourth peer was never asked.
#[tokio::test]
async fn startup_asks_a_fourth_peer_and_reasks_a_peer_that_returns() -> Result<()> {
    let (fixture, _witness) = startup_with_witness(&"c7".repeat(16)).await?;
    let admin_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        for byte in [0x11u8, 0x22, 0x33] {
            let peer = x0x::identity::AgentId([byte; 32]);
            info.add_member(
                hex::encode(peer.as_bytes()),
                x0x::groups::GroupRole::Member,
                Some(admin_hex.clone()),
                None,
            );
        }
    }
    fixture
        .state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    startup_self_leave_rekey(&fixture.state).await;
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        4,
        "each of the four peers must be asked"
    );
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "the first ask must not seal"
    );
    assert_eq!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::CONFLICT
    );
    let late = x0x::identity::AgentId([0x44; 32]);
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.add_member(
            hex::encode(late.as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
    }
    retry_startup_self_leave_catchup(&fixture.state).await;
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        9,
        "the four peers are asked again and the returning peer is asked once"
    );
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "a peer that still has a send remaining must keep the wait open"
    );
    Ok(())
}

/// A request that leaves this process is not a completed catch-up. The gate
/// stays open until the saved head comes back.
#[tokio::test]
async fn sent_startup_request_without_a_response_keeps_the_gate() -> Result<()> {
    let (fixture, _witness) = startup_with_witness(&"c6".repeat(16)).await?;
    fixture
        .state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    startup_self_leave_rekey(&fixture.state).await;
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 1);
    let recorded = fixture
        .state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .clone();
    assert_eq!(
        recorded.last().map(Vec::as_slice),
        Some(fixture.group_id.as_bytes()),
        "the startup pass must send the catch-up request"
    );
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "a lost response must not seal"
    );
    assert_eq!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::CONFLICT,
        "a lost response must withhold ciphertext"
    );
    Ok(())
}

async fn add_removed_leaf_group(state: &Arc<AppState>, group_id: &str) -> Result<u64> {
    let admin_id = state.agent.agent_id();
    let group_id_bytes = hex::decode(group_id)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
    let member_kp = x0x::identity::AgentKeypair::generate()?;
    let member_id = member_kp.agent_id();
    let member_hex = hex::encode(member_id.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &[9u8; 32])?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let added = admin_group.add_member(member_id, &kp_bytes)?;
    let _leaver = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
    let epoch_before = admin_group.epoch();
    let mut info = x0x::groups::GroupInfo::new(
        "leave-rekey".to_string(),
        String::new(),
        admin_id,
        group_id.to_string(),
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
    info.remove_member(&member_hex, Some(member_hex.clone()));
    let witness_hex = fixed_admin_hex([0xff; 32], &admin_id, false);
    add_fixed_admin(&mut info, admin_id, witness_hex);
    info.secret_epoch = epoch_before;
    info.security_binding = Some(format!("treekem:epoch={epoch_before}"));
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
    state.treekem_groups.write().await.insert(
        group_id.to_string(),
        Arc::new(tokio::sync::Mutex::new(admin_group)),
    );
    Ok(epoch_before)
}

/// Both groups are gated before either send, so a live schedule cannot seal
/// the later group while the earlier group's request is in flight.
#[tokio::test]
async fn startup_gates_every_group_before_either_send() -> Result<()> {
    let (first, witness) = startup_with_witness(&"c8".repeat(16)).await?;
    let second_id = "c9".repeat(16);
    let second_epoch = add_removed_leaf_group(&first.state, &second_id).await?;
    self_leave_startup_hold_for_gate_install();
    schedule_self_leave_rekey_if_idle(&first.state, &second_id).await;
    assert_eq!(
        live_epoch(&first.state, &second_id).await,
        second_epoch,
        "a live rekey must not seal before startup installs the gates"
    );
    first
        .state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    startup_self_leave_rekey(&first.state).await;
    assert_eq!(
        live_epoch(&first.state, &first.group_id).await,
        first.epoch_before
    );
    assert_eq!(live_epoch(&first.state, &second_id).await, second_epoch);
    assert_eq!(self_leave_startup_send_count(&first.group_id), 1);
    assert_eq!(self_leave_startup_send_count(&second_id), 1);
    let recorded = first
        .state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .clone();
    let sent: Vec<String> = recorded
        .iter()
        .filter_map(|bytes| String::from_utf8(bytes.clone()).ok())
        .filter(|id| id == &first.group_id || id == &second_id)
        .collect();
    assert_eq!(
        sent,
        vec![first.group_id.clone(), second_id.clone()],
        "startup must send in sorted group-key order after both gates exist"
    );
    let head = saved_head(&first.state, &first.group_id).await;
    handle_treekem_catchup_response(
        &first.state,
        &witness,
        true,
        catchup_page(&first.group_id, false, Some(head)),
    )
    .await;
    assert!(live_epoch(&first.state, &first.group_id).await > first.epoch_before);
    assert_eq!(
        live_epoch(&first.state, &second_id).await,
        second_epoch,
        "clearing one group must not seal the other"
    );
    Ok(())
}

/// A peer who leaves before spending three sends must not block the seal
/// while another survivor remains. The survivor keeps the sends already spent.
#[tokio::test]
async fn departed_startup_peer_stops_blocking_while_a_survivor_remains() -> Result<()> {
    let (fixture, survivor) = startup_with_witness(&"d1".repeat(16)).await?;
    let departed = x0x::identity::AgentId([0x21; 32]);
    let admin_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.add_member(
            hex::encode(departed.as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
    }
    fixture
        .state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    startup_self_leave_rekey(&fixture.state).await;
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 2);
    let head = saved_head(&fixture.state, &fixture.group_id).await;
    handle_treekem_catchup_response(
        &fixture.state,
        &survivor,
        true,
        catchup_page(&fixture.group_id, false, Some(head)),
    )
    .await;
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "the departed peer must still block before the roster drops that row"
    );
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.remove_member(
            &hex::encode(departed.as_bytes()),
            Some(hex::encode(fixture.state.agent.agent_id().as_bytes())),
        );
    }
    for _ in 0..5 {
        retry_startup_self_leave_catchup(&fixture.state).await;
    }
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "a departed peer must not keep the wait open while a survivor remains"
    );
    assert_ne!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        1,
        "the survivor must keep the one send already spent"
    );
    Ok(())
}

/// B's matching head is kept while A's page stream is open. A's later
/// terminal page can then seal without a replay of B.
#[tokio::test]
async fn matching_head_is_kept_while_another_peers_page_is_open() -> Result<()> {
    let (fixture, peer_b) = startup_with_witness(&"d2".repeat(16)).await?;
    let peer_a = x0x::identity::AgentId([0x31; 32]);
    let admin_hex = hex::encode(fixture.state.agent.agent_id().as_bytes());
    {
        let mut groups = fixture.state.named_groups.write().await;
        let info = groups.get_mut(&fixture.group_id).expect("group");
        info.add_member(
            hex::encode(peer_a.as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(admin_hex),
            None,
        );
    }
    fixture
        .state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    startup_self_leave_rekey(&fixture.state).await;
    let head = saved_head(&fixture.state, &fixture.group_id).await;
    handle_treekem_catchup_response(
        &fixture.state,
        &peer_a,
        true,
        catchup_page(&fixture.group_id, true, Some(head.clone())),
    )
    .await;
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "a truncated page must not seal"
    );
    handle_treekem_catchup_response(
        &fixture.state,
        &peer_b,
        true,
        catchup_page(&fixture.group_id, false, Some(head.clone())),
    )
    .await;
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "B's head must not seal while A's page stream is open"
    );
    handle_treekem_catchup_response(
        &fixture.state,
        &peer_a,
        true,
        catchup_page(&fixture.group_id, false, Some(head)),
    )
    .await;
    assert!(
        live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before,
        "B's saved receipt must let the seal proceed when A's stream closes"
    );
    assert_ne!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::CONFLICT
    );
    Ok(())
}

/// The shared group-store protector withholds ciphertext while a startup
/// peer still blocks. REST already returns conflict. The ratchet must not move.
#[tokio::test]
async fn startup_hold_refuses_the_group_store_protector() -> Result<()> {
    let (fixture, _witness) = startup_with_witness(&"d3".repeat(16)).await?;
    fixture
        .state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(false, std::sync::atomic::Ordering::SeqCst);
    startup_self_leave_rekey(&fixture.state).await;
    assert_eq!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::CONFLICT
    );
    let before = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let guard = group.lock().await;
        guard.to_snapshot_bytes()?
    };
    let info = fixture
        .state
        .named_groups
        .read()
        .await
        .get(&fixture.group_id)
        .expect("group")
        .clone();
    let protector = crate::server::routes::stores::treekem_task_list_protector(
        &fixture.state,
        &fixture.group_id,
        &info,
    )
    .expect("shared TreeKEM protector");
    let signing =
        x0x::kv::AuthorSigning::from_keypair(fixture.state.agent.identity().agent_keypair())
            .expect("signing");
    let sealed = protector
        .seal_record(
            &signing,
            x0x::kv::KvMutationKind::Control,
            &x0x::kv::KvStoreId::new([9; 32]),
            b"withheld-control",
            false,
        )
        .await;
    assert!(
        matches!(
            sealed,
            Err(x0x::kv::KvError::SecureRecord(ref message)) if message.contains("withheld")
        ),
        "the protector must withhold the control record: {sealed:?}"
    );
    let after = {
        let group = live_treekem_group(&fixture.state, &fixture.group_id).await;
        let guard = group.lock().await;
        guard.to_snapshot_bytes()?
    };
    assert_eq!(
        before, after,
        "a withheld seal must not advance the ratchet the removed member can still read"
    );
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before
    );
    Ok(())
}

/// Two overlapping retries at two sends must not make a fourth helper call.
/// The third attempt is reserved before the helper is awaited.
#[tokio::test]
async fn overlapping_startup_retries_cannot_exceed_the_send_bound() -> Result<()> {
    let (fixture, _witness) = startup_with_witness(&"d4".repeat(16)).await?;
    fixture
        .state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    startup_self_leave_rekey(&fixture.state).await;
    retry_startup_self_leave_catchup(&fixture.state).await;
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 2);
    let helper_calls = |state: &AppState, group_id: &str| -> usize {
        state
            .named_group_test_recorders
            .catchup_responses
            .lock()
            .expect("catch-up recorder")
            .iter()
            .filter(|bytes| bytes.as_slice() == group_id.as_bytes())
            .count()
    };
    assert_eq!(helper_calls(&fixture.state, &fixture.group_id), 2);
    let pause = detached_send_test_seam::arm(&format!("treekem-catchup-page:{}", fixture.group_id));
    let state = Arc::clone(&fixture.state);
    let first = tokio::spawn(async move {
        retry_startup_self_leave_catchup(&state).await;
    });
    wait_until(|| pause.reached()).await;
    assert!(
        pause.reached(),
        "the third send must park inside the helper"
    );
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        3,
        "the attempt is reserved before the helper returns"
    );
    assert_eq!(helper_calls(&fixture.state, &fixture.group_id), 2);
    retry_startup_self_leave_catchup(&fixture.state).await;
    assert_eq!(
        helper_calls(&fixture.state, &fixture.group_id),
        2,
        "an overlapping retry must not send once the bound is reserved"
    );
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 3);
    drop(pause);
    first.await.expect("first retry");
    assert_eq!(helper_calls(&fixture.state, &fixture.group_id), 3);
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 3);
    Ok(())
}

async fn add_roster_peer(state: &AppState, group_id: &str, byte: u8) {
    let admin_hex = hex::encode(state.agent.agent_id().as_bytes());
    let mut groups = state.named_groups.write().await;
    let info = groups.get_mut(group_id).expect("group");
    info.add_member(
        hex::encode(x0x::identity::AgentId([byte; 32]).as_bytes()),
        x0x::groups::GroupRole::Member,
        Some(admin_hex),
        None,
    );
}

/// Wall-clock wait. `tokio::time::sleep` does not advance while the clock is paused.
async fn yield_until(mut ready: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !ready() && std::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
    ready()
}

/// One new roster peer before each of three timer passes must not freeze the
/// later peers below three asks. After the roster stops changing, the same
/// backoff spends what remains and the designated admin seals.
#[tokio::test]
async fn peers_added_across_backoff_passes_seal_once_every_budget_is_spent() -> Result<()> {
    let (fixture, _witness) = startup_with_witness(&"e1".repeat(16)).await?;
    fixture
        .state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    startup_self_leave_rekey(&fixture.state).await;
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        1,
        "startup asks the first peer once and arms the backoff"
    );
    retry_startup_self_leave_catchup(&fixture.state).await;
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        2,
        "the network-join retry spends the first peer's second attempt"
    );
    let armed = std::time::Instant::now();
    while armed.elapsed() < std::time::Duration::from_millis(50) {
        tokio::task::yield_now().await;
    }
    tokio::time::pause();

    add_roster_peer(&fixture.state, &fixture.group_id, 0x41).await;
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    assert!(
        yield_until(|| self_leave_startup_send_count(&fixture.group_id) >= 4).await,
        "the first timer pass must ask the new peer"
    );
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 4);

    add_roster_peer(&fixture.state, &fixture.group_id, 0x42).await;
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    assert!(
        yield_until(|| self_leave_startup_send_count(&fixture.group_id) >= 6).await,
        "the second timer pass must ask the peer added before it"
    );
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 6);

    add_roster_peer(&fixture.state, &fixture.group_id, 0x43).await;
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    assert!(
        yield_until(|| self_leave_startup_send_count(&fixture.group_id) >= 9).await,
        "three timer passes leave the newest peers short of three asks"
    );
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        9,
        "counts after three passes are A=3, B=3, C=2, D=1"
    );
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "remaining attempts must hold the old epoch"
    );
    assert_eq!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::CONFLICT,
        "REST encrypt stays 409 while a later peer still has an attempt"
    );

    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    assert!(
        yield_until(|| self_leave_startup_send_count(&fixture.group_id) >= 11).await,
        "a fixed roster must keep the backoff running"
    );
    assert_eq!(self_leave_startup_send_count(&fixture.group_id), 11);
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        fixture.epoch_before,
        "one peer still has an attempt, so the epoch must stay"
    );

    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    let sealed = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let spent = self_leave_startup_send_count(&fixture.group_id) == 12;
            let advanced =
                live_epoch(&fixture.state, &fixture.group_id).await > fixture.epoch_before;
            if spent && advanced {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            tokio::task::yield_now().await;
        }
    };
    assert!(
        sealed,
        "the fixed roster must seal once every eligible peer has spent three sends; sends {}, epoch {}",
        self_leave_startup_send_count(&fixture.group_id),
        live_epoch(&fixture.state, &fixture.group_id).await
    );
    assert_ne!(
        encrypt_status(&fixture.state, &fixture.group_id).await,
        StatusCode::CONFLICT,
        "ciphertext must not stay withheld after every attempt is spent"
    );
    let epoch_after = live_epoch(&fixture.state, &fixture.group_id).await;
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    let quiet = std::time::Instant::now();
    while quiet.elapsed() < std::time::Duration::from_millis(50) {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        self_leave_startup_send_count(&fixture.group_id),
        12,
        "a later interval must not ask a peer that has spent three sends"
    );
    assert_eq!(
        live_epoch(&fixture.state, &fixture.group_id).await,
        epoch_after
    );
    Ok(())
}
