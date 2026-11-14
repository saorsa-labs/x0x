#![cfg(test)]
//! #1540: the roster-only `MemberBanned` of a TreeKEM member that holds no
//! seat and no ratchet leaf. Before it, the ban route refused such a
//! target (no KeyPackage, no leaf to remove), and the S4 queued ban
//! retried until the target was seated again, so the rejoin window stayed
//! open. Red on main: the route answers an error and the receiver refuses
//! the event as `treekem_commit_b64_absent`.

use super::*;
use x0x::identity::AgentKeypair;

const GROUP: &str = "e1540e1540e1540e1540e1540e1540e1";

async fn body_of(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn ban(state: &Arc<AppState>, target_hex: &str) -> (StatusCode, serde_json::Value) {
    let owner =
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true });
    let response = ban_group_member(
        State(Arc::clone(state)),
        owner,
        Path((GROUP.to_string(), target_hex.to_string())),
    )
    .await
    .into_response();
    body_of(response).await
}

/// Seed `agent`'s current verified advert with `bits`.
fn seed_advert(state: &AppState, agent: &x0x::identity::AgentId, bits: u64) {
    let mut caps = x0x::dm::DmCapabilities::v1_gossip_ready(vec![42; 1184]);
    caps.application_registry = x0x::dm::CapabilityRegistry { version: 1, bits };
    assert!(state.agent.capability_store().insert(
        *agent,
        x0x::identity::MachineId([4; 32]),
        caps,
        x0x::dm::now_unix_ms(),
    ));
}

struct AdminFixture {
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
    witness: x0x::identity::AgentId,
    removed_hex: String,
    epoch: u64,
}

/// This node is the admin of a TreeKEM group with an Active witness W
/// (seated in the tree) and a member R whose row is `Removed`. With
/// `remove_leaf`, R's leaf was removed from the tree too; without it, R is
/// a roster-only self-leaver that still holds its leaf.
async fn admin_with_removed_member(remove_leaf: bool) -> Result<AdminFixture> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let admin_id = state.agent.agent_id();
    let admin_hex = hex::encode(admin_id.as_bytes());
    let group_id_bytes = hex::decode(GROUP)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut tree = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
    let witness = AgentKeypair::generate()?.agent_id();
    let removed = AgentKeypair::generate()?.agent_id();
    let witness_kp = x0x::mls::TreeKemMlsGroup::prepare_member(witness, &[7u8; 32])?
        .key_package_bytes()
        .to_vec();
    let removed_kp = x0x::mls::TreeKemMlsGroup::prepare_member(removed, &[8u8; 32])?
        .key_package_bytes()
        .to_vec();
    tree.add_member(witness, &witness_kp)?;
    tree.add_member(removed, &removed_kp)?;
    if remove_leaf {
        tree.remove_member_verified(removed, &removed_kp)?;
    }
    let epoch = tree.epoch();

    let mut info = x0x::groups::GroupInfo::new(
        "ban-1540".to_string(),
        String::new(),
        admin_id,
        GROUP.into(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    let witness_hex = hex::encode(witness.as_bytes());
    let removed_hex = hex::encode(removed.as_bytes());
    for (hex_id, kp) in [(&witness_hex, &witness_kp), (&removed_hex, &removed_kp)] {
        info.add_member(
            hex_id.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.set_member_treekem_key_package(hex_id, BASE64.encode(kp));
    }
    info.remove_member(&removed_hex, Some(admin_hex));
    info.secret_epoch = epoch;
    info.security_binding = Some(format!("treekem:epoch={epoch}"));
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(GROUP.to_string(), info);
    state
        .treekem_groups
        .write()
        .await
        .insert(GROUP.to_string(), Arc::new(tokio::sync::Mutex::new(tree)));
    Ok(AdminFixture {
        state,
        _dir: dir,
        witness,
        removed_hex,
        epoch,
    })
}

/// The admin bans R roster-only once every other Active member's advert
/// carries `roster_only_ban_v1`; before that the route answers the typed
/// `waiting_for_receiver_upgrade` naming W, and nothing changes.
#[tokio::test]
async fn a_leafless_member_is_banned_roster_only_behind_the_capability_gate() -> Result<()> {
    let f = admin_with_removed_member(true).await?;
    let witness_hex = hex::encode(f.witness.as_bytes());
    {
        let groups = f.state.named_groups.read().await;
        let info = groups.get(GROUP).expect("group");
        assert!(
            treekem_ban_is_roster_only(&f.state, GROUP, info, &f.removed_hex).await,
            "R holds no seat and no leaf"
        );
        assert!(
            !treekem_ban_is_roster_only(&f.state, GROUP, info, &witness_hex).await,
            "a seated member is never banned roster-only"
        );
    }

    // W's advert lacks the bit: the typed wait, no state change.
    seed_advert(
        &f.state,
        &f.witness,
        x0x::dm::CapabilityRegistry::current().bits
            & !x0x::dm::CapabilityRegistry::ROSTER_ONLY_BAN_V1,
    );
    let revision_before = f.state.named_groups.read().await[GROUP].roster_revision;
    let (status, body) = ban(&f.state, &f.removed_hex).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], ROSTER_ONLY_BAN_UPGRADE_WAIT);
    assert_eq!(body["members"], serde_json::json!([witness_hex]));
    {
        let groups = f.state.named_groups.read().await;
        let info = &groups[GROUP];
        assert_eq!(info.roster_revision, revision_before);
        assert!(!info.is_banned(&f.removed_hex));
    }

    // W upgrades: the ban is roster-only, with no epoch change.
    seed_advert(
        &f.state,
        &f.witness,
        x0x::dm::CapabilityRegistry::current().bits,
    );
    let (status, body) = ban(&f.state, &f.removed_hex).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["roster_only"], true);
    {
        let groups = f.state.named_groups.read().await;
        let info = &groups[GROUP];
        assert!(info.is_banned(&f.removed_hex), "R is banned");
        assert_eq!(info.roster_revision, revision_before + 1);
        assert_eq!(info.secret_epoch, f.epoch, "no epoch change");
        assert!(info.has_active_member(&witness_hex));
    }
    let group = f.state.treekem_groups.read().await[GROUP].clone();
    assert_eq!(group.lock().await.epoch(), f.epoch, "the tree did not move");
    Ok(())
}

/// #1898 review: a roster-only self-leaver that still holds its leaf is
/// never banned roster-only. The ban takes the full TreeKEM removal: the
/// epoch advances and the leaf is gone.
#[tokio::test]
async fn a_self_leaver_that_still_holds_a_leaf_gets_the_treekem_removal() -> Result<()> {
    let f = admin_with_removed_member(false).await?;
    {
        let groups = f.state.named_groups.read().await;
        let info = groups.get(GROUP).expect("group");
        assert!(
            !treekem_ban_is_roster_only(&f.state, GROUP, info, &f.removed_hex).await,
            "R still holds a leaf"
        );
    }
    let (status, body) = ban(&f.state, &f.removed_hex).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("roster_only").is_none(), "{body}");
    let group = f.state.treekem_groups.read().await[GROUP].clone();
    assert_eq!(
        group.lock().await.epoch(),
        f.epoch + 1,
        "the TreeKEM removal ran"
    );
    let groups = f.state.named_groups.read().await;
    assert!(groups[GROUP].is_banned(&f.removed_hex));
    Ok(())
}

/// #1898 review: with no evidence the ban is not roster-only. On a
/// joiner's tree the leaf map holds only its own leaf, so the admin's leaf
/// is unattributed (its row has no committed KeyPackage) and a removed R
/// with no KeyPackage reads `None`, which is never "no leaf". With R's
/// KeyPackage the tree itself answers `Some(false)`.
#[tokio::test]
async fn no_leaf_evidence_is_never_read_as_no_leaf() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let admin_id = AgentKeypair::generate()?.agent_id();
    let admin_hex = hex::encode(admin_id.as_bytes());
    let group_id_bytes = hex::decode(GROUP)?;
    let mut admin_tree =
        x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), admin_id, &[3u8; 32])?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(local, &seed)?;
    let local_kp = prepared.key_package_bytes().to_vec();
    let added = admin_tree.add_member(local, &local_kp)?;
    let local_tree = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
    state.treekem_groups.write().await.insert(
        GROUP.to_string(),
        Arc::new(tokio::sync::Mutex::new(local_tree)),
    );
    let removed_id = AgentKeypair::generate()?.agent_id();
    let removed_hex = hex::encode(removed_id.as_bytes());
    let mut info = x0x::groups::GroupInfo::new(
        "ban-1540".to_string(),
        String::new(),
        admin_id,
        GROUP.into(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    for id in [&local_hex, &removed_hex] {
        info.add_member(
            id.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
    }
    info.set_member_treekem_key_package(&local_hex, BASE64.encode(&local_kp));
    info.remove_member(&removed_hex, Some(admin_hex.clone()));
    assert!(
        !treekem_ban_is_roster_only(&state, GROUP, &info, &removed_hex).await,
        "no KeyPackage and an unattributed leaf: no evidence"
    );
    let stranger = hex::encode(AgentKeypair::generate()?.agent_id().as_bytes());
    assert!(
        !treekem_ban_is_roster_only(&state, GROUP, &info, &stranger).await,
        "a row-less target of a partly attributed tree: no evidence"
    );
    let removed_kp = x0x::mls::TreeKemMlsGroup::prepare_member(removed_id, &[8u8; 32])?
        .key_package_bytes()
        .to_vec();
    info.set_member_treekem_key_package(&removed_hex, BASE64.encode(&removed_kp));
    assert!(
        treekem_ban_is_roster_only(&state, GROUP, &info, &removed_hex).await,
        "the committed KeyPackage proves R holds no leaf"
    );
    Ok(())
}

/// A member applies the admin's roster-only ban of R: R holds no seat on
/// its roster and no leaf in its tree. The same event naming a seated
/// member is refused, so a roster-only ban never leaves a live leaf.
#[tokio::test]
async fn a_member_applies_the_roster_only_ban_of_a_leafless_member() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let admin_kp = AgentKeypair::generate()?;
    let admin_id = admin_kp.agent_id();
    let admin_hex = hex::encode(admin_id.as_bytes());
    let group_id_bytes = hex::decode(GROUP)?;

    // The admin's tree seats this node; R was never in it.
    let mut admin_tree =
        x0x::mls::TreeKemMlsGroup::create(group_id_bytes.clone(), admin_id, &[3u8; 32])?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(local, &seed)?;
    let local_kp = prepared.key_package_bytes().to_vec();
    let added = admin_tree.add_member(local, &local_kp)?;
    let local_tree = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
    let epoch = local_tree.epoch();

    let removed_id = AgentKeypair::generate()?.agent_id();
    let removed_hex = hex::encode(removed_id.as_bytes());
    let removed_kp = x0x::mls::TreeKemMlsGroup::prepare_member(removed_id, &[8u8; 32])?
        .key_package_bytes()
        .to_vec();
    let mut info = x0x::groups::GroupInfo::new(
        "ban-1540".to_string(),
        String::new(),
        admin_id,
        GROUP.into(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.add_member(
        local_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(admin_hex.clone()),
        None,
    );
    info.set_member_treekem_key_package(&local_hex, BASE64.encode(&local_kp));
    info.add_member(
        removed_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(admin_hex.clone()),
        None,
    );
    // R's committed KeyPackage lets this node's tree answer `Some(false)`.
    info.set_member_treekem_key_package(&removed_hex, BASE64.encode(&removed_kp));
    info.remove_member(&removed_hex, Some(admin_hex.clone()));
    info.secret_epoch = epoch;
    info.security_binding = Some(format!("treekem:epoch={epoch}"));
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(GROUP.to_string(), info.clone());
    state.treekem_groups.write().await.insert(
        GROUP.to_string(),
        Arc::new(tokio::sync::Mutex::new(local_tree)),
    );

    let roster_only_ban = |target: &str| -> Result<NamedGroupMetadataEvent> {
        let mut next = info.clone();
        next.roster_revision = next.roster_revision.saturating_add(1);
        let revision = next.roster_revision;
        next.ban_member(target, Some(admin_hex.clone()));
        let commit = next.seal_commit(&admin_kp, now_millis_u64())?;
        Ok(NamedGroupMetadataEvent::MemberBanned {
            group_id: GROUP.to_string(),
            revision,
            actor: admin_hex.clone(),
            agent_id: target.to_string(),
            secret_epoch: None,
            treekem_commit_b64: None,
            treekem_epoch: None,
            commit: Some(commit),
        })
    };

    // Naming this node's own seat (it holds a leaf): refused.
    let seated = apply_named_group_metadata_event(
        &state,
        roster_only_ban(&local_hex)?,
        admin_id,
        true,
        None,
    )
    .await;
    assert!(!seated.accepted, "a seated target is refused: {seated:?}");

    let applied = apply_named_group_metadata_event(
        &state,
        roster_only_ban(&removed_hex)?,
        admin_id,
        true,
        None,
    )
    .await;
    assert!(applied.accepted, "the roster-only ban applies: {applied:?}");
    let groups = state.named_groups.read().await;
    let after = &groups[GROUP];
    assert!(after.is_banned(&removed_hex));
    assert_eq!(after.secret_epoch, epoch, "no epoch change");
    assert!(after.has_active_member(&local_hex));
    Ok(())
}

#[test]
fn the_roster_only_ban_bit_is_seventeen_and_current() {
    assert_eq!(x0x::dm::CapabilityRegistry::ROSTER_ONLY_BAN_V1, 1 << 17);
    assert!(x0x::dm::CapabilityRegistry::current()
        .supports(x0x::dm::CapabilityRegistry::ROSTER_ONLY_BAN_V1));
}
