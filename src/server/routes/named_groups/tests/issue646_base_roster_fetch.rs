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

    // The exact boundaries (r4 test gap): 20 members mint v4, 21 mint v5,
    // 128 (the fetch cap itself) still mints v5.
    let at_cap_id = "cd".repeat(32);
    let at_cap = seed_group_with_members(&authority, &at_cap_id, 19).await; // +creator = 20
    let (at_cap_invite, _) = assemble_signed_v4_invite(&authority, &at_cap, 3_600, None)
        .map_err(|e| anyhow::anyhow!("at-cap mint failed: {e:?}"))?;
    assert_eq!(at_cap_invite.version, INVITE_VERSION_V4);
    let over_cap_id = "ce".repeat(32);
    let over_cap = seed_group_with_members(&authority, &over_cap_id, 20).await; // +creator = 21
    let (over_cap_invite, _) = assemble_signed_v4_invite(&authority, &over_cap, 3_600, None)
        .map_err(|e| anyhow::anyhow!("21-member mint failed: {e:?}"))?;
    assert_eq!(over_cap_invite.version, INVITE_VERSION_V5);
    let fetch_cap_id = "cf".repeat(32);
    let fetch_cap = seed_group_with_members(
        &authority,
        &fetch_cap_id,
        MAX_FETCHED_BASE_ROSTER_ENTRIES - 1,
    )
    .await; // +creator = 128
    let (fetch_cap_invite, _) = assemble_signed_v4_invite(&authority, &fetch_cap, 3_600, None)
        .map_err(|e| anyhow::anyhow!("128-member mint failed: {e:?}"))?;
    assert_eq!(fetch_cap_invite.version, INVITE_VERSION_V5);

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

/// The serve half (r4 blocker 1, D95 / A08:71): possession of a LIVE
/// invite (hash of the raw secret) authorizes EXACTLY the root that
/// invite signed at mint, for the requester it was addressed to, and a
/// Banned or Removed requester gets nothing — "a pre-member gets no other
/// kind and no other root."
#[tokio::test]
async fn locate_served_base_roster_authorizes_and_content_addresses() -> Result<()> {
    let (authority, _dir) = daemon_state().await?;
    let group_id = "ad".repeat(32);
    let mut info = seed_group_with_members(&authority, &group_id, 30).await;
    let requester = "9a".repeat(32);
    let secret = "ab".repeat(32);
    let raw = hex::decode(&secret)?;
    let secret_hash = hex::encode(blake3::hash(&raw).as_bytes());
    info.record_issued_invite(secret.clone(), 1_000, 0, x0x::groups::GroupRole::Member);

    let live_projection = roster_projection_digest_only(&info.members_v2);
    let live_root = roster_root_of_projection(&live_projection);

    // A v4-shaped record (no bound root) serves NOTHING, not even the
    // root it names.
    assert!(base_roster_fetch::locate_served_base_roster(
        &info,
        &requester,
        &live_root,
        &secret_hash,
        2_000
    )
    .is_refused());
    info.bind_issued_invite_base_roster_root(&secret, Some(live_root.clone()));

    // Live invite + the root IT signed → the live projection.
    let served = base_roster_fetch::locate_served_base_roster(
        &info,
        &requester,
        &live_root,
        &secret_hash,
        2_000,
    )
    .served()
    .expect("the invite's own root serves");
    assert_eq!(served, live_projection);

    // Wrong possession proof → nothing.
    let wrong_hash = hex::encode(blake3::hash(b"nope").as_bytes());
    assert!(base_roster_fetch::locate_served_base_roster(
        &info,
        &requester,
        &live_root,
        &wrong_hash,
        2_000
    )
    .is_refused());

    // Expired invite → nothing (r4 test gap).
    let mut expired = info.clone();
    expired
        .issued_invites
        .get_mut(&secret)
        .expect("record")
        .expires_at_secs = 1_500;
    assert!(base_roster_fetch::locate_served_base_roster(
        &expired,
        &requester,
        &live_root,
        &secret_hash,
        2_000
    )
    .is_refused());

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
        &requester,
        &live_root,
        &secret_hash,
        2_000
    )
    .is_refused());

    // An ADDRESSED invite is served only to its intended joiner (D95).
    let mut addressed = info.clone();
    let intended = "7b".repeat(32);
    addressed
        .issued_invites
        .get_mut(&secret)
        .expect("record")
        .intended_joiner = Some(intended.clone());
    assert!(
        base_roster_fetch::locate_served_base_roster(
            &addressed,
            &requester,
            &live_root,
            &secret_hash,
            2_000
        )
        .is_refused(),
        "a different requester gets nothing from an addressed invite"
    );
    assert!(base_roster_fetch::locate_served_base_roster(
        &addressed,
        &intended,
        &live_root,
        &secret_hash,
        2_000
    )
    .served()
    .is_some());

    // A Banned (or Removed) requester gets nothing, whatever it holds.
    let mut with_banned = info.clone();
    with_banned.add_member(
        requester.clone(),
        x0x::groups::GroupRole::Member,
        None,
        None,
    );
    with_banned
        .members_v2
        .get_mut(&requester)
        .expect("seat")
        .state = x0x::groups::GroupMemberState::Banned;
    assert!(
        base_roster_fetch::locate_served_base_roster(
            &with_banned,
            &requester,
            &live_root,
            &secret_hash,
            2_000
        )
        .is_refused(),
        "a Banned requester is refused"
    );

    // The invite's bound root stays serveable from the retained commit
    // log after the live roster moves on (digest-only) — but a DIFFERENT
    // root, even one a retained commit holds, is never served to this
    // invite (D95: no other root).
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
    let moved_live_root =
        roster_root_of_projection(&roster_projection_digest_only(&info.members_v2));
    assert_ne!(
        moved_live_root, retained_root,
        "fixture: the live root must have moved"
    );
    // Push the moved live roster into the commit log too, so a non-pinned
    // serve WOULD have something to give out for it.
    info.commit_log
        .push(x0x::groups::state_commit::RetainedCommit {
            commit: x0x::groups::state_commit::GroupStateCommit {
                group_id: info.stable_group_id().to_string(),
                revision: info.state_revision + 1,
                prev_state_hash: None,
                roster_root: moved_live_root.clone(),
                policy_hash: String::new(),
                public_meta_hash: String::new(),
                security_binding: None,
                state_hash: "ef".repeat(32),
                withdrawn: false,
                committed_by: "11".repeat(32),
                committed_at: 2,
                signer_public_key: String::new(),
                signature: String::new(),
            },
            roster: roster_projection_digest_only(&info.members_v2),
            meta: Some(info.public_meta()),
        });
    let served = base_roster_fetch::locate_served_base_roster(
        &info,
        &requester,
        &retained_root,
        &secret_hash,
        2_000,
    )
    .served()
    .expect("the invite's own root serves from the commit log");
    assert_eq!(served, retained_projection);
    assert!(
        base_roster_fetch::locate_served_base_roster(
            &info,
            &requester,
            &moved_live_root,
            &secret_hash,
            2_000
        )
        .is_refused(),
        "the CURRENT roster is a different root: this invite never unlocks it"
    );

    // An unknown root serves nothing.
    assert!(base_roster_fetch::locate_served_base_roster(
        &info,
        &requester,
        &"d1".repeat(32),
        &secret_hash,
        2_000
    )
    .is_refused());
    Ok(())
}

/// Joiner-side delivery (review r3, blocker 1): a reply that does not
/// re-derive its own root is dropped; a reply no join is waiting for is
/// dropped and NEVER cached; a reply from a peer that is not the waiting
/// join's inviter does not wake it; the inviter's reply does.
#[tokio::test]
async fn deliver_admits_only_the_expected_inviters_reply_and_caches_nothing() -> Result<()> {
    let (joiner, _dir) = daemon_state().await?;
    let group_id = "ae".repeat(32);
    let inviter = AgentId([4u8; 32]);
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
    base_roster_fetch::deliver_base_roster(&joiner, &inviter, &group_id, &"d2".repeat(32), &roster);
    assert!(joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .is_empty());

    // A verified payload NO join asked for is dropped, not cached.
    base_roster_fetch::deliver_base_roster(&joiner, &inviter, &group_id, &root, &roster);
    assert!(
        joiner
            .base_roster_fetch_slots
            .lock()
            .expect("slots")
            .is_empty(),
        "an unrequested reply must never be cached"
    );

    // A waiting join is woken ONLY by its own inviter.
    let (sender, mut receiver) = tokio::sync::oneshot::channel();
    joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .insert(
            format!("{group_id}|{root}"),
            vec![base_roster_fetch::BaseRosterWaiter::for_test(
                inviter, sender,
            )],
        );
    let outsider = AgentId([5u8; 32]);
    base_roster_fetch::deliver_base_roster(&joiner, &outsider, &group_id, &root, &roster);
    assert!(
        receiver.try_recv().is_err(),
        "a reply from a peer that is not the join's inviter must not wake it"
    );
    assert_eq!(
        joiner.base_roster_fetch_slots.lock().expect("slots").len(),
        1,
        "the join keeps waiting for its inviter"
    );
    base_roster_fetch::deliver_base_roster(&joiner, &inviter, &group_id, &root, &roster);
    let delivered = receiver.await.expect("the inviter's reply wakes the join");
    assert_eq!(
        delivered,
        base_roster_fetch::BaseRosterFetchReply::Served(roster.clone())
    );
    assert!(joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .is_empty());
    Ok(())
}

/// Review r3 blocker 1: the roster root does NOT commit
/// `treekem_key_package_hash`, so a served anchor is whatever the sender
/// chose — a fetched projection reaches the join with every anchor (and
/// certificate) STRIPPED, while still re-deriving the same root.
#[tokio::test]
async fn fetched_roster_key_package_anchors_are_stripped() -> Result<()> {
    let (joiner, _dir) = daemon_state().await?;
    let group_id = "cb".repeat(32);
    let inviter = AgentId([6u8; 32]);
    // The attacker-shaped payload: correct digests, forged anchors.
    let forged: base_roster_fetch::BaseRosterProjection = (0..5)
        .map(|i| {
            (
                format!("{i:064x}"),
                RosterMemberSnapshot {
                    role: x0x::groups::GroupRole::Member,
                    state: x0x::groups::GroupMemberState::Active,
                    treekem_key_package_hash: Some("4d".repeat(32)),
                    certificate_digest: None,
                    certificate: None,
                },
            )
        })
        .collect();
    // The root ignores the anchors, so the forged payload re-derives the
    // anchor-free root.
    let root = roster_root_of_projection(&forged);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .insert(
            format!("{group_id}|{root}"),
            vec![base_roster_fetch::BaseRosterWaiter::for_test(
                inviter, sender,
            )],
        );
    base_roster_fetch::deliver_base_roster(&joiner, &inviter, &group_id, &root, &forged);
    let base_roster_fetch::BaseRosterFetchReply::Served(delivered) =
        receiver.await.expect("reply delivered")
    else {
        panic!("served reply expected");
    };
    assert!(
        delivered
            .values()
            .all(|snap| snap.treekem_key_package_hash.is_none() && snap.certificate.is_none()),
        "a fetched projection must carry no key-package anchors"
    );
    assert_eq!(roster_root_of_projection(&delivered), root);
    Ok(())
}

/// Review r3 blocker 2: the re-seat mint population stays INLINE-v4 —
/// `check_reseat_invite` needs the signed inline roster — and past the
/// inline cap `sign_v4` refuses the oversize roster, so nothing is signed
/// or stored (pre-#646 behaviour). Only the ordinary mint
/// (`assemble_signed_v4_invite`, via `populate_invite_base_state`) goes
/// content-addressed.
#[tokio::test]
async fn reseat_mint_population_stays_inline_and_over_cap_sign_refuses() -> Result<()> {
    let (authority, _dir) = daemon_state().await?;
    let group_id = "cc".repeat(32);
    let info = seed_group_with_members(&authority, &group_id, 50).await;
    let subject = AgentId([7u8; 32]);
    let mut invite = x0x::groups::invite::SignedInvite::new(
        info.mls_group_id.clone(),
        info.name.clone(),
        &authority.agent.agent_id(),
        3_600,
    );
    crate::server::routes::identity::populate_invite_base_state_v4(
        &mut invite,
        &info,
        Some(subject),
    );
    assert_eq!(
        invite.version, INVITE_VERSION_V4,
        "the re-seat population must never mint a content-addressed invite"
    );
    assert_eq!(invite.base_roster_root, None);
    assert_eq!(
        invite.base_roster.as_ref().map(BTreeMap::len),
        Some(51),
        "the roster stays inline"
    );
    let err = invite
        .sign_v4(authority.agent.identity().agent_keypair(), None)
        .expect_err("an over-cap inline roster must refuse at sign");
    assert!(err.contains("base_roster"), "typed oversize refusal: {err}");
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
    // Stand in for the inviter's serve so the real join route runs
    // socket-free: the pre-seeded projection still has to re-derive the
    // SIGNED root inside the fetch, exactly like a served reply (the
    // delivery/serve halves are pinned by their own tests above).
    let projection = roster_projection_digest_only(&info.members_v2);
    let stable_group_id = invite.stable_group_id.clone().context("stable id")?;
    base_roster_fetch::preseed_fetched_projection_for_test(
        &stable_group_id,
        &signed_root,
        projection.clone(),
    );

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

/// Review r2 fix 1 (#1471): a v5 join whose fetch failed refuses BEFORE
/// the stale-row clear — a device holding an inert card-import stub gets
/// the retryable 503 with the stub byte-for-byte unchanged, so group
/// access keeps answering while the inviter is unreachable.
#[tokio::test]
async fn v5_refusal_leaves_inert_card_import_stub_unchanged() -> Result<()> {
    let (authority, _dir_a) = daemon_state().await?;
    let group_id = "be".repeat(32);
    let info = seed_group_with_members(&authority, &group_id, 50).await;
    let (invite, link) = assemble_signed_v4_invite(&authority, &info, 3_600, None)
        .map_err(|e| anyhow::anyhow!("v5 mint failed: {e:?}"))?;
    assert_eq!(invite.version, INVITE_VERSION_V5);

    let (joiner, _dir_b) = daemon_state().await?;
    let joiner_hex = hex::encode(joiner.agent.agent_id().as_bytes());
    let stub = super::issue1161_not_member_lineage::card_import_stub(
        authority.agent.agent_id(),
        &group_id,
        &joiner_hex,
    );
    let before = serde_json::to_value(&stub)?;
    joiner
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), stub);

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
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .starts_with("base_roster_unavailable"),
        "typed retryable refusal, got {body}"
    );
    let after = joiner
        .named_groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .context("the stub survives the retryable refusal")?;
    assert_eq!(
        serde_json::to_value(&after)?,
        before,
        "a refused invite leaves the row unchanged (#1471)"
    );
    Ok(())
}

/// Review r2 fix 2 (kept under the r3 model): a fetch attempt on a key
/// another join already waits on SHARES the waiter list — its own failure
/// (inviter unreachable here) removes only its own waiter, and the first
/// join's inviter still wakes the first join.
#[tokio::test]
async fn concurrent_fetch_keeps_the_first_joins_waiter() -> Result<()> {
    let (joiner, _dir) = daemon_state().await?;
    let group_id = "bf".repeat(32);
    let inviter_a = AgentId([1u8; 32]);
    let roster: base_roster_fetch::BaseRosterProjection = std::iter::once((
        "11".repeat(32),
        RosterMemberSnapshot {
            role: x0x::groups::GroupRole::Member,
            state: x0x::groups::GroupMemberState::Active,
            treekem_key_package_hash: None,
            certificate_digest: None,
            certificate: None,
        },
    ))
    .collect();
    let root = roster_root_of_projection(&roster);

    // First join's waiter, already parked on the key.
    let (sender_a, receiver_a) = tokio::sync::oneshot::channel();
    joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .insert(
            format!("{group_id}|{root}"),
            vec![base_roster_fetch::BaseRosterWaiter::for_test(
                inviter_a, sender_a,
            )],
        );

    // A second fetch on the same key: the networkless send fails, so it
    // errors out — and must take only ITS OWN waiter with it.
    let err = base_roster_fetch::obtain_base_roster(
        &joiner,
        AgentId([3u8; 32]),
        &group_id,
        &root,
        &hex::encode(blake3::hash(&[3u8; 32]).as_bytes()),
        std::time::Duration::from_millis(200),
    )
    .await
    .expect_err("networkless send cannot reach an inviter");
    assert_eq!(
        err,
        base_roster_fetch::ObtainBaseRosterError::Retryable("inviter unreachable")
    );
    // r4 test gap: the failed fetch's OWN waiter is gone (WaiterGuard on
    // the error exit); only the first join's waiter stays.
    assert_eq!(
        joiner
            .base_roster_fetch_slots
            .lock()
            .expect("slots")
            .get(&format!("{group_id}|{root}"))
            .map(Vec::len),
        Some(1),
        "exactly the first join's waiter survives"
    );

    // The first join's inviter still wakes the first join.
    base_roster_fetch::deliver_base_roster(&joiner, &inviter_a, &group_id, &root, &roster);
    let delivered = receiver_a
        .await
        .expect("the first join's waiter survives a concurrent fetch attempt");
    assert_eq!(
        delivered,
        base_roster_fetch::BaseRosterFetchReply::Served(roster.clone())
    );
    Ok(())
}

/// Review r2 item 4: a `BaseRosterFetch` whose sender is not the member it
/// names is consumed WITHOUT admitting a serve; the matching sender is
/// admitted (its ticket blocks a duplicate on this current-thread runtime).
#[tokio::test]
async fn dispatch_drops_base_roster_fetch_from_mismatched_sender() -> Result<()> {
    let (inviter, _dir) = daemon_state().await?;
    let group_id = "ca".repeat(32);
    let info = seed_group_with_members(&inviter, &group_id, 5).await;
    let stable = info.stable_group_id().to_string();
    let member = AgentId([9u8; 32]);
    let member_hex = hex::encode(member.as_bytes());
    // r4 item 5: authorization runs BEFORE the admission ticket, so the
    // control case needs a real live invite bound to the requested root.
    let live_root = roster_root_of_projection(&roster_projection_digest_only(&info.members_v2));
    let secret = "ab".repeat(32);
    let secret_hash = hex::encode(blake3::hash(&hex::decode(&secret)?).as_bytes());
    {
        let mut groups = inviter.named_groups.write().await;
        let info = groups.get_mut(&group_id).context("seeded group")?;
        info.record_issued_invite(secret.clone(), 1_000, 0, x0x::groups::GroupRole::Member);
        info.bind_issued_invite_base_roster_root(&secret, Some(live_root.clone()));
    }
    let fetch = || JoinResultMessage::BaseRosterFetch {
        group_id: group_id.clone(),
        member_agent_id: member_hex.clone(),
        roster_root: live_root.clone(),
        secret_hash: secret_hash.clone(),
    };

    // Mismatched sender: consumed, nothing admitted.
    let outsider = AgentId([8u8; 32]);
    assert!(dispatch_join_result_message(&inviter, &outsider, true, fetch()).await);
    assert_eq!(inviter.join_result_fetch_admission.in_flight(), 0);

    // Review r3 item 5: an UNVERIFIED sender gets no serve either.
    assert!(dispatch_join_result_message(&inviter, &member, false, fetch()).await);
    assert_eq!(inviter.join_result_fetch_admission.in_flight(), 0);

    // r4 item 5: a verified, matched sender WITHOUT a live invite for the
    // requested root is refused BEFORE any admission ticket is taken, so
    // it cannot hold a slot another member's fetch needs.
    let unauthorized = JoinResultMessage::BaseRosterFetch {
        group_id: group_id.clone(),
        member_agent_id: member_hex.clone(),
        roster_root: "00".repeat(32),
        secret_hash: "11".repeat(32),
    };
    assert!(dispatch_join_result_message(&inviter, &member, true, unauthorized).await);
    assert_eq!(inviter.join_result_fetch_admission.in_flight(), 0);

    // Control: the verified member IS admitted — the spawned serve's
    // ticket (unpolled on this current-thread runtime) blocks a duplicate
    // base-roster fetch, while a `FetchRequest` for the same (group,
    // member) keeps its OWN coalescing slot (review r3 item 5).
    assert!(dispatch_join_result_message(&inviter, &member, true, fetch()).await);
    assert!(inviter
        .join_result_fetch_admission
        .try_admit(
            &format!("base-roster|{}", join_result_key(&stable, &member_hex)),
            &stable
        )
        .is_err());
    let fetch_request_slot = inviter
        .join_result_fetch_admission
        .try_admit(&join_result_key(&stable, &member_hex), &stable)
        .expect("a FetchRequest for the same (group, member) is not displaced");
    drop(fetch_request_slot);
    Ok(())
}

/// Review r3 blocker 1: an UNVERIFIED `BaseRoster` reply never reaches the
/// waiting join, even from the right sender with the right root.
#[tokio::test]
async fn dispatch_drops_unverified_base_roster_reply() -> Result<()> {
    let (joiner, _dir) = daemon_state().await?;
    let group_id = "ce".repeat(32);
    let inviter = AgentId([2u8; 32]);
    let roster: base_roster_fetch::BaseRosterProjection = std::iter::once((
        "33".repeat(32),
        RosterMemberSnapshot {
            role: x0x::groups::GroupRole::Member,
            state: x0x::groups::GroupMemberState::Active,
            treekem_key_package_hash: None,
            certificate_digest: None,
            certificate: None,
        },
    ))
    .collect();
    let root = roster_root_of_projection(&roster);
    let (sender, mut receiver) = tokio::sync::oneshot::channel();
    joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .insert(
            format!("{group_id}|{root}"),
            vec![base_roster_fetch::BaseRosterWaiter::for_test(
                inviter, sender,
            )],
        );
    let reply = JoinResultMessage::BaseRoster {
        group_id: group_id.clone(),
        roster_root: root.clone(),
        roster: roster.clone(),
    };
    assert!(dispatch_join_result_message(&joiner, &inviter, false, reply).await);
    assert!(
        receiver.try_recv().is_err(),
        "an unverified reply must not wake the join"
    );
    assert_eq!(
        joiner.base_roster_fetch_slots.lock().expect("slots").len(),
        1,
        "the join keeps waiting"
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

/// r5 item 6: an AUTHORIZED request whose bound root is in neither the
/// live roster nor the retained commit log is `Unavailable` (terminal),
/// never the silent refusal; and a Removed requester is refused outright
/// (r5 test gaps).
#[tokio::test]
async fn pruned_root_is_unavailable_and_removed_requester_is_refused() -> Result<()> {
    let (authority, _dir) = daemon_state().await?;
    let group_id = "da".repeat(32);
    let mut info = seed_group_with_members(&authority, &group_id, 5).await;
    let requester = "9b".repeat(32);
    let secret = "cd".repeat(32);
    let secret_hash = hex::encode(blake3::hash(&hex::decode(&secret)?).as_bytes());
    info.record_issued_invite(secret.clone(), 1_000, 0, x0x::groups::GroupRole::Member);
    // Bind a root that nothing holds: the mint-time roster was pruned.
    let pruned_root = "ab".repeat(32);
    info.bind_issued_invite_base_roster_root(&secret, Some(pruned_root.clone()));
    assert!(
        base_roster_fetch::locate_served_base_roster(
            &info,
            &requester,
            &pruned_root,
            &secret_hash,
            2_000
        )
        .is_unavailable(),
        "an authorized request for a pruned root is TERMINAL, not silent"
    );
    // The same request with a Removed seat for the requester: refused.
    info.add_member(
        requester.clone(),
        x0x::groups::GroupRole::Member,
        None,
        None,
    );
    info.members_v2.get_mut(&requester).expect("seat").state =
        x0x::groups::GroupMemberState::Removed;
    assert!(
        base_roster_fetch::locate_served_base_roster(
            &info,
            &requester,
            &pruned_root,
            &secret_hash,
            2_000
        )
        .is_refused(),
        "a Removed requester is refused before anything else"
    );
    Ok(())
}

/// r5 item 6, joiner side: a verified `BaseRosterUnavailable` from the
/// join's own inviter wakes it terminally; from anyone else it is dropped.
#[tokio::test]
async fn unavailable_answer_wakes_only_the_inviters_waiter() -> Result<()> {
    let (joiner, _dir) = daemon_state().await?;
    let group_id = "db".repeat(32);
    let root = "ac".repeat(32);
    let inviter = AgentId([11u8; 32]);
    let (sender, mut receiver) = tokio::sync::oneshot::channel();
    joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .insert(
            format!("{group_id}|{root}"),
            vec![base_roster_fetch::BaseRosterWaiter::for_test(
                inviter, sender,
            )],
        );
    let outsider = AgentId([12u8; 32]);
    base_roster_fetch::deliver_base_roster_unavailable(&joiner, &outsider, &group_id, &root);
    assert!(
        receiver.try_recv().is_err(),
        "an outsider's terminal answer must not wake the join"
    );
    base_roster_fetch::deliver_base_roster_unavailable(&joiner, &inviter, &group_id, &root);
    assert_eq!(
        receiver.await.expect("the inviter's answer wakes the join"),
        base_roster_fetch::BaseRosterFetchReply::Unavailable
    );
    assert!(joiner
        .base_roster_fetch_slots
        .lock()
        .expect("slots")
        .is_empty());
    Ok(())
}

/// r5 blocker 2 (D129): a v5 joiner's stub holds NO key-package anchors
/// (the fetch strips them, since the roster root does not cover them), so
/// the self-rebind classification must treat an absent LOCAL anchor as
/// "unknown", not as "no package" — or every non-admin certificate
/// self-rebind in an anchored TreeKEM group is misread as an admin action
/// and refused on v5 joiners.
#[test]
fn v5_stub_accepts_anchored_self_rebind_link() {
    use x0x::groups::cert_rebind::is_self_rebind_link;
    let committer = format!("{:064x}", 1u32);
    // The group's REAL roster: >20 members, every seat anchored.
    let mut anchored: BTreeMap<String, RosterMemberSnapshot> = (0..25u32)
        .map(|i| {
            (
                format!("{i:064x}"),
                RosterMemberSnapshot {
                    role: x0x::groups::GroupRole::Member,
                    state: x0x::groups::GroupMemberState::Active,
                    treekem_key_package_hash: Some("3c".repeat(32)),
                    certificate_digest: Some("1a".repeat(32)),
                    certificate: None,
                },
            )
        })
        .collect();
    anchored
        .get_mut(&format!("{:064x}", 0u32))
        .expect("admin seat")
        .role = x0x::groups::GroupRole::Admin;
    // The v5 joiner's local predecessor: the SAME committed seats,
    // anchor-free (exactly what the fetch seeds).
    let stub: BTreeMap<String, RosterMemberSnapshot> = anchored
        .iter()
        .map(|(id, snap)| {
            let mut snap = snap.clone();
            snap.treekem_key_package_hash = None;
            (id.clone(), snap)
        })
        .collect();
    // A non-admin member renews its certificate: the link carries the
    // real anchors and the new digest.
    let mut link = anchored.clone();
    link.get_mut(&committer)
        .expect("committer")
        .certificate_digest = Some("2b".repeat(32));
    assert!(
        is_self_rebind_link(&stub, &link, &committer),
        "a v5 joiner must accept a valid D129 self-rebind link"
    );
    // Anything beyond the committer's own certificate still refuses.
    let mut tampered = link.clone();
    tampered
        .get_mut(&format!("{:064x}", 2u32))
        .expect("member")
        .role = x0x::groups::GroupRole::Admin;
    assert!(!is_self_rebind_link(&stub, &tampered, &committer));
    // An anchored LOCAL side still pins the committer's anchor.
    let mut anchor_moved = link.clone();
    anchor_moved
        .get_mut(&committer)
        .expect("committer")
        .treekem_key_package_hash = Some("4d".repeat(32));
    assert!(!is_self_rebind_link(&anchored, &anchor_moved, &committer));
    // And an anchored local side still pins every OTHER member's anchor.
    let mut other_anchor_moved = link.clone();
    other_anchor_moved
        .get_mut(&format!("{:064x}", 3u32))
        .expect("member")
        .treekem_key_package_hash = Some("4d".repeat(32));
    assert!(!is_self_rebind_link(
        &anchored,
        &other_anchor_moved,
        &committer
    ));
}
