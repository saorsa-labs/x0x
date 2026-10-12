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

fn add_lower_admin(info: &mut x0x::groups::GroupInfo, admin_id: x0x::identity::AgentId) -> String {
    let mut lower_hex = String::new();
    for _ in 0..64 {
        let candidate = x0x::identity::AgentKeypair::generate().expect("admin keypair");
        if candidate.agent_id().as_bytes() < admin_id.as_bytes() {
            lower_hex = hex::encode(candidate.agent_id().as_bytes());
            break;
        }
    }
    assert!(
        !lower_hex.is_empty(),
        "failed to draw an admin id below the local agent"
    );
    info.add_member(
        lower_hex.clone(),
        x0x::groups::GroupRole::Admin,
        Some(hex::encode(admin_id.as_bytes())),
        None,
    );
    info.recompute_state_hash();
    lower_hex
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
