//! #646 (D13/W4): content-addressed base-roster fetch — invites past 20
//! Active+Banned roster members.
//!
//! A roster projection over [`x0x::groups::invite::MAX_INVITE_ROSTER_ENTRIES`]
//! no longer rides the link: the mint emits a v5 invite carrying the
//! projection's CONTENT ADDRESS (its roster root), and the joiner fetches
//! the projection from the inviter out of band, admitting it only when it
//! re-derives the signed root. These tests pin the mint shape, the serve
//! authorization and content addressing, the joiner-side delivery
//! verification, the reply's DM budget, and the join flow seeding its stub
//! from the fetched projection (assertions on the JOINER'S STATE — never
//! wire bytes).

use super::*;

use crate::groups::invite::{
    INVITE_VERSION_V4, INVITE_VERSION_V5, MAX_FETCHED_BASE_ROSTER_ENTRIES,
};
use crate::groups::state_commit::{
    roster_projection_digest_only, roster_root_of_projection, RosterMemberSnapshot,
};
use crate::identity::AgentKeypair;
use serde_json::json;

/// A fresh networkless daemon state.
async fn daemon_state() -> Result<(Arc<AppState>, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key(AgentKeypair::generate()?)
            .with_peer_cache_disabled()
            .with_contact_store_path(dir.path().join("contacts.json"))
            .build()
            .await?,
    );
    let state = secure_endpoint_test_state_at(dir.path(), agent).await?;
    Ok((state, dir))
}

/// Seed `extra_members` Active members (plus the local creator as Admin)
/// into a default-policy group on `state` and return the stored info.
async fn seed_group_with_members(
    state: &AppState,
    group_id: &str,
    extra_members: usize,
) -> x0x::groups::GroupInfo {
    let creator = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::with_policy(
        format!("group-{extra_members}"),
        String::new(),
        creator,
        group_id.to_string(),
        x0x::groups::policy::GroupPolicy::default(),
    );
    info.add_member(
        hex::encode(creator.as_bytes()),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    for i in 0..extra_members {
        info.add_member(
            format!("{i:064x}"),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(creator.as_bytes())),
            None,
        );
    }
    info.roster_revision += u64::try_from(extra_members).unwrap_or(0) + 1;
    info.state_revision = info.roster_revision;
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info.clone());
    info
}

/// Over the inline cap, the mint emits a v5 invite: no inline projection,
/// the projection's root as its content address, a verifying signature,
/// and a link whose size no longer grows with the roster. At or under the
/// cap the mint stays v4 — inline projection, no content address.
#[tokio::test]
async fn over_cap_mint_is_v5_content_addressed_within_budget() -> Result<()> {
    let (authority, _dir) = daemon_state().await?;

    // 50 Active members + the creator: past the inline cap of 20.
    let group_id = "aa".repeat(32);
    let info = seed_group_with_members(&authority, &group_id, 50).await;
    let (invite, link) = assemble_signed_v4_invite(&authority, &info, 3_600, None)
        .map_err(|e| anyhow::anyhow!("v5 mint failed: {e:?}"))?;
    assert_eq!(invite.version, INVITE_VERSION_V5);
    assert_eq!(invite.base_roster, None, "v5 carries no inline projection");
    let expected_root = roster_root_of_projection(&roster_projection_digest_only(&info.members_v2));
    assert_eq!(
        invite.base_roster_root.as_deref(),
        Some(expected_root.as_str())
    );
    assert_eq!(invite.verify_v4_signatures(), Ok(()));
    // A v5 link carries the fixed-size signing material (two inline
    // ML-DSA-65 keys + signatures ≈ 9.4 KiB of base64) but NO roster:
    // its size is roster-independent, far under the 40,960 B budget a
    // 21-member v4 link would overflow once wrapped.
    assert!(
        link.len() < 16 * 1024,
        "a v5 link is roster-size independent (got {} B)",
        link.len()
    );

    // At the inline cap the mint is BYTE-COMPATIBLE v4, exactly as before.
    let small_id = "bb".repeat(32);
    let small = seed_group_with_members(&authority, &small_id, 5).await;
    let (small_invite, _) = assemble_signed_v4_invite(&authority, &small, 3_600, None)
        .map_err(|e| anyhow::anyhow!("v4 mint failed: {e:?}"))?;
    assert_eq!(small_invite.version, INVITE_VERSION_V4);
    assert!(small_invite.base_roster.is_some());
    assert_eq!(small_invite.base_roster_root, None);
    assert_eq!(small_invite.verify_v4_signatures(), Ok(()));

    // Past the FETCH cap the mint refuses with the typed size refusal.
    let huge_id = "cc".repeat(32);
    let huge = seed_group_with_members(&authority, &huge_id, MAX_FETCHED_BASE_ROSTER_ENTRIES).await;
    match assemble_signed_v4_invite(&authority, &huge, 3_600, None) {
        Err(MintInviteError::TooLarge { field, size }) => {
            assert_eq!(field, "base_roster");
            assert_eq!(size, MAX_FETCHED_BASE_ROSTER_ENTRIES + 1);
        }
        other => panic!("expected TooLarge(base_roster), got {other:?}"),
    }
    Ok(())
}

/// The serve half: possession of a LIVE invite (hash of the raw secret)
/// authorizes; the projection is located by CONTENT ADDRESS — the live
/// roster, or a retained commit whose signed root matches — and anything
/// else is refused.
#[tokio::test]
async fn locate_served_base_roster_authorizes_and_content_addresses() -> Result<()> {
    let (authority, _dir) = daemon_state().await?;
    let group_id = "ad".repeat(32);
    let mut info = seed_group_with_members(&authority, &group_id, 30).await;
    let secret = "ab".repeat(32);
    let raw = hex::decode(&secret)?;
    let secret_hash = hex::encode(blake3::hash(&raw).as_bytes());
    info.record_issued_invite(secret.clone(), 1_000, 0, x0x::groups::GroupRole::Member);

    let live_projection = roster_projection_digest_only(&info.members_v2);
    let live_root = roster_root_of_projection(&live_projection);

    // Live root + live invite → the live projection.
    let served =
        base_roster_fetch::locate_served_base_roster(&info, &live_root, &secret_hash, 2_000)
            .expect("live root serves");
    assert_eq!(served, live_projection);

    // Wrong possession proof → nothing.
    let wrong_hash = hex::encode(blake3::hash(b"nope").as_bytes());
    assert!(
        base_roster_fetch::locate_served_base_roster(&info, &live_root, &wrong_hash, 2_000)
            .is_none()
    );

    // Consumed invite → nothing.
    let mut consumed = info.clone();
    consumed
        .consume_issued_invite(
            &secret,
            &"11".repeat(32),
            x0x::groups::GroupRole::Member,
            2_000_000,
            2_000_000,
        )
        .expect("consume");
    assert!(base_roster_fetch::locate_served_base_roster(
        &consumed,
        &live_root,
        &secret_hash,
        2_000
    )
    .is_none());

    // A root the live roster no longer matches is served from the
    // retained commit log (digest-only), keyed by the commit's SIGNED
    // roster_root.
    let retained_projection = live_projection.clone();
    let retained_root = live_root.clone();
    info.commit_log
        .push(x0x::groups::state_commit::RetainedCommit {
            commit: x0x::groups::state_commit::GroupStateCommit {
                group_id: info.stable_group_id().to_string(),
                revision: info.state_revision,
                prev_state_hash: None,
                roster_root: retained_root.clone(),
                policy_hash: String::new(),
                public_meta_hash: String::new(),
                security_binding: None,
                state_hash: "ee".repeat(32),
                withdrawn: false,
                committed_by: "11".repeat(32),
                committed_at: 1,
                signer_public_key: String::new(),
                signature: String::new(),
            },
            roster: retained_projection.clone(),
            meta: Some(info.public_meta()),
        });
    // Advance the live roster so its root moves off the retained one.
    info.add_member("ff".repeat(32), x0x::groups::GroupRole::Member, None, None);
    assert_ne!(
        roster_root_of_projection(&roster_projection_digest_only(&info.members_v2)),
        retained_root,
        "fixture: the live root must have moved"
    );
    let served =
        base_roster_fetch::locate_served_base_roster(&info, &retained_root, &secret_hash, 2_000)
            .expect("retained root serves from the commit log");
    assert_eq!(served, retained_projection);

    // An unknown root serves nothing.
    assert!(base_roster_fetch::locate_served_base_roster(
        &info,
        &"d1".repeat(32),
        &secret_hash,
        2_000
    )
    .is_none());
    Ok(())
}

/// Joiner-side delivery is content-verified: a reply that does not
/// re-derive its own root is dropped; a verified reply wakes the parked
/// join (or parks for one that has not asked yet).
#[tokio::test]
async fn deliver_verifies_content_wakes_waiter_and_parks_replies() -> Result<()> {
    let (joiner, _dir) = daemon_state().await?;
    let group_id = "ae".repeat(32);
    let roster: base_roster_fetch::BaseRosterProjection = (0..30)
        .map(|i| {
            (
                format!("{i:064x}"),
                RosterMemberSnapshot {
                    role: x0x::groups::GroupRole::Member,
                    state: x0x::groups::GroupMemberState::Active,
                    treekem_key_package_hash: None,
                    certificate_digest: None,
                    certificate: None,
                },
            )
        })
        .collect();
    let root = roster_root_of_projection(&roster);

    // Mismatching payload (claims another root) → dropped, nothing parked.
    base_roster_fetch::deliver_base_roster(&joiner, &group_id, &"d2".repeat(32), &roster);
    assert!(joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .is_empty());

    // Verified payload with no waiter → parked; a later obtain consumes it
    // without any network.
    base_roster_fetch::deliver_base_roster(&joiner, &group_id, &root, &roster);
    assert_eq!(
        joiner.base_roster_fetch_slots.lock().expect("slots").len(),
        1
    );
    let fetched = base_roster_fetch::obtain_base_roster(
        &joiner,
        joiner.agent.agent_id(),
        &group_id,
        &root,
        &hex::encode(blake3::hash(&[0u8; 32]).as_bytes()),
        std::time::Duration::from_millis(200),
    )
    .await
    .expect("parked reply satisfies the fetch");
    assert_eq!(fetched, roster);
    assert!(joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .is_empty());

    // A parked waiter is woken directly.
    let (sender, receiver) = tokio::sync::oneshot::channel();
    joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .insert(
            format!("{group_id}|{root}"),
            base_roster_fetch::BaseRosterSlot::Waiter(sender),
        );
    base_roster_fetch::deliver_base_roster(&joiner, &group_id, &root, &roster);
    let delivered = receiver.await.expect("waiter woken");
    assert_eq!(delivered, roster);
    Ok(())
}

/// The worst-case `BaseRoster` reply at the fetch entry cap fits the
/// gossip DM ceiling — the derivation [`MAX_FETCHED_BASE_ROSTER_ENTRIES`]
/// documents.
#[test]
fn base_roster_reply_fits_dm_budget() {
    let roster: BTreeMap<String, RosterMemberSnapshot> = (0..MAX_FETCHED_BASE_ROSTER_ENTRIES)
        .map(|i| {
            (
                format!("{i:064x}"),
                RosterMemberSnapshot {
                    role: x0x::groups::GroupRole::Moderator,
                    state: x0x::groups::GroupMemberState::Banned,
                    treekem_key_package_hash: Some("0f".repeat(32)),
                    certificate_digest: Some("5a".repeat(32)),
                    certificate: None,
                },
            )
        })
        .collect();
    let reply = JoinResultMessage::BaseRoster {
        group_id: "ab".repeat(32),
        roster_root: roster_root_of_projection(&roster),
        roster,
    };
    let payload = serde_json::to_vec(&reply).expect("serialize reply");
    assert!(
        payload.len() <= crate::dm::MAX_PAYLOAD_BYTES,
        "worst-case base-roster reply ({} B) must fit the {}-byte DM ceiling",
        payload.len(),
        crate::dm::MAX_PAYLOAD_BYTES
    );
}

/// End to end on the joiner: a v5 invite into a 50-member group seeds the
/// stub from the FETCHED projection — every base member seated, the
/// lineage anchored at the SIGNED root — through the real join route.
/// (The fetch is satisfied from a parked verified reply so the test stays
/// socket-free; the delivery/serve halves are pinned above.)
#[tokio::test]
async fn v5_join_seeds_stub_from_fetched_roster() -> Result<()> {
    let (authority, _dir_a) = daemon_state().await?;
    let group_id = "af".repeat(32);
    let info = seed_group_with_members(&authority, &group_id, 50).await;
    let (invite, link) = assemble_signed_v4_invite(&authority, &info, 3_600, None)
        .map_err(|e| anyhow::anyhow!("v5 mint failed: {e:?}"))?;
    assert_eq!(invite.version, INVITE_VERSION_V5);
    let signed_root = invite
        .base_roster_root
        .clone()
        .context("v5 content address")?;

    let (joiner, _dir_b) = daemon_state().await?;
    // The projection arrives (out of band) before the join asks: park the
    // verified copy the inviter would have served.
    let projection = roster_projection_digest_only(&info.members_v2);
    let stable_group_id = invite.stable_group_id.clone().context("stable id")?;
    base_roster_fetch::deliver_base_roster(&joiner, &stable_group_id, &signed_root, &projection);

    let response = join_group_via_invite(
        State(Arc::clone(&joiner)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let body = response_json(response).await?.1;
    assert_eq!(status, StatusCode::OK, "join must succeed: {body}");

    let stub = joiner
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .context("joiner stub installed")?;
    // Every one of the 51 base members is seated from the FETCHED
    // projection, plus the joiner's own (non-base) seat the install
    // records locally — the authority's commit confirms it later.
    assert_eq!(stub.members_v2.len(), 52, "all base members seated");
    for (id, snap) in &projection {
        let seat = stub
            .members_v2
            .get(id)
            .unwrap_or_else(|| panic!("base member {id} seated"));
        assert_eq!(seat.role, snap.role);
        assert_eq!(seat.state, snap.state);
    }
    // The stub re-derives the SIGNED root — the base the authority's
    // MemberAdded commit will chain from.
    assert_eq!(
        x0x::groups::state_commit::compute_roster_root(&stub.members_v2),
        signed_root
    );
    let lineage = stub.invite_lineage.context("lineage marker")?;
    assert_eq!(lineage.base_roster_root, signed_root);
    assert_eq!(lineage.base_hash, info.state_hash);
    Ok(())
}

/// Without any source for the projection (inviter unreachable, nothing
/// parked), a v5 join refuses with a typed RETRYABLE 503 and installs
/// nothing.
#[tokio::test]
async fn v5_join_without_roster_source_is_retryable_and_installs_nothing() -> Result<()> {
    let (authority, _dir_a) = daemon_state().await?;
    let group_id = "ba".repeat(32);
    let info = seed_group_with_members(&authority, &group_id, 50).await;
    let (_invite, link) = assemble_signed_v4_invite(&authority, &info, 3_600, None)
        .map_err(|e| anyhow::anyhow!("v5 mint failed: {e:?}"))?;

    let (joiner, _dir_b) = daemon_state().await?;
    let response = join_group_via_invite(
        State(Arc::clone(&joiner)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let body = response_json(response).await?.1;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .starts_with("base_roster_unavailable"),
        "typed retryable refusal, got {body}"
    );
    assert!(
        joiner.named_groups.read().await.is_empty(),
        "a deferred v5 join must install nothing"
    );
    Ok(())
}

/// A legacy-shaped (pre-#646) v4 link — no `base_roster_root` key at all —
/// still parses and joins through the unchanged inline path.
#[tokio::test]
async fn legacy_v4_link_without_new_field_still_joins_inline() -> Result<()> {
    let (authority, _dir_a) = daemon_state().await?;
    let group_id = "bc".repeat(32);
    let info = seed_group_with_members(&authority, &group_id, 5).await;
    let (invite, link) = assemble_signed_v4_invite(&authority, &info, 3_600, None)
        .map_err(|e| anyhow::anyhow!("v4 mint failed: {e:?}"))?;
    assert_eq!(invite.version, INVITE_VERSION_V4);
    // Pin the pre-#646 wire shape: the serialized v4 invite carries NO
    // `base_roster_root` key, so its JSON is byte-compatible with what a
    // pre-#646 node emits and expects.
    let json: serde_json::Value = serde_json::to_value(&invite)?;
    assert_eq!(json.get("base_roster_root"), None);

    let (joiner, _dir_b) = daemon_state().await?;
    let response = join_group_via_invite(
        State(Arc::clone(&joiner)),
        Json(JoinGroupRequest {
            invite: link,
            display_name: None,
            mode: None,
            expected_owner_user_id: None,
        }),
    )
    .await
    .into_response();
    let status = response.status();
    let body = response_json(response).await?.1;
    assert_eq!(status, StatusCode::OK, "v4 join unchanged: {body}");
    assert_eq!(body["ok"], json!(true));
    let stub = joiner
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .context("joiner stub installed")?;
    // 6 base members from the inline projection + the joiner's own seat.
    assert_eq!(stub.members_v2.len(), 7, "inline projection seated");
    Ok(())
}
