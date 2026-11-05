//! #1623 (ADR 0109 §2 rule (b), §7 (b), D82): a pre-Welcome joiner applies
//! each catch-up page link of an armed attested sequence state-only, for
//! every link kind. Before the fix only `MemberAdded` had a pre-Welcome
//! state-only apply. A page link that carries a TreeKEM commit
//! (`MemberRemoved`, `MemberBanned`, `JoinRequestApproved`) was refused,
//! because the joiner has no TreeKEM group yet. The joiner then stayed in
//! its typed wait. The page here holds a role change, a rename and a
//! removal. Inert: no daemon, no network.

use super::*;
use x0x::identity::AgentKeypair;

const TREEKEM_EPOCH: u64 = 1;

/// A TreeKEM group at revision 1 that this node (pre-Welcome) is not seated
/// in, and three owner links after it: a role change, a rename and a
/// removal. Returns the base, the links and their page events.
fn pre_welcome_fixture(
    owner: &AgentKeypair,
) -> anyhow::Result<(
    x0x::groups::GroupInfo,
    Vec<x0x::groups::GroupStateCommit>,
    Vec<NamedGroupMetadataEvent>,
)> {
    let owner_hex = hex::encode(owner.agent_id().as_bytes());
    let admin_hex = "51".repeat(32);
    let promoted_hex = "52".repeat(32);
    let removed_hex = "53".repeat(32);
    let mut base = x0x::groups::GroupInfo::new(
        "issue1623-pre-welcome-page".to_string(),
        String::new(),
        owner.agent_id(),
        "1623".repeat(16),
    );
    base.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    for (member, role) in [
        (&admin_hex, x0x::groups::GroupRole::Admin),
        (&promoted_hex, x0x::groups::GroupRole::Member),
        (&removed_hex, x0x::groups::GroupRole::Member),
    ] {
        base.add_member(member.clone(), role, Some(owner_hex.clone()), None);
    }
    base.seal_commit(owner, 1_000)?;

    let mut ahead = base.clone();
    ahead.set_member_role(&promoted_hex, x0x::groups::GroupRole::Admin);
    let role_commit = ahead.seal_commit(owner, 2_000)?;
    ahead.name = "renamed".to_string();
    ahead.updated_at = 3_000;
    let rename_commit = ahead.seal_commit(owner, 3_000)?;
    ahead.remove_member(&removed_hex, Some(owner_hex.clone()));
    ahead.secret_epoch = TREEKEM_EPOCH;
    ahead.security_binding = Some(format!("treekem:epoch={TREEKEM_EPOCH}"));
    let removal_commit = ahead.seal_commit(owner, 4_000)?;

    let stable = base.stable_group_id().to_string();
    let events = vec![
        NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: stable.clone(),
            revision: role_commit.revision,
            actor: owner_hex.clone(),
            agent_id: promoted_hex,
            role: x0x::groups::GroupRole::Admin,
            commit: Some(role_commit.clone()),
        },
        NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: stable.clone(),
            revision: rename_commit.revision,
            actor: owner_hex.clone(),
            name: Some("renamed".to_string()),
            description: None,
            commit: Some(rename_commit.clone()),
        },
        NamedGroupMetadataEvent::MemberRemoved {
            group_id: stable,
            revision: removal_commit.revision,
            actor: owner_hex,
            agent_id: removed_hex,
            treekem_commit_b64: Some(BASE64.encode(b"issue1623-treekem-removal-commit")),
            treekem_epoch: Some(TREEKEM_EPOCH),
            secret_epoch: None,
            commit: Some(removal_commit.clone()),
        },
    ];
    Ok((
        base,
        vec![role_commit, rename_commit, removal_commit],
        events,
    ))
}

/// The owner-armed record (#846) for the joiner's stale-base gap: the
/// attested sequence is the three links, then the joiner's own terminal.
fn owner_armed_record(
    base: &x0x::groups::GroupInfo,
    links: &[x0x::groups::GroupStateCommit],
    owner: &AgentKeypair,
) -> x0x::groups::AnchoredGapRefusal {
    let terminal_revision = links
        .last()
        .map_or(base.state_revision, |link| link.revision)
        .saturating_add(1);
    let terminal_state_hash = "7e".repeat(32);
    let mut attested_chain_hashes: Vec<String> =
        links.iter().map(|link| link.state_hash.clone()).collect();
    attested_chain_hashes.push(terminal_state_hash.clone());
    x0x::groups::AnchoredGapRefusal {
        reason: "owner_attested_stale_base_gap".to_string(),
        head_revision: base.state_revision,
        head_state_hash: base.state_hash.clone(),
        terminal_revision,
        terminal_state_hash,
        committed_by: hex::encode(owner.agent_id().as_bytes()),
        occurrences: 1,
        first_observed_at_ms: 0,
        last_observed_at_ms: 0,
        attested_chain_hashes,
        by_reason: Default::default(),
    }
}

async fn install_stub(state: &AppState, stub: x0x::groups::GroupInfo) -> anyhow::Result<String> {
    let key = stub.mls_group_id.clone();
    state.named_groups.write().await.insert(key.clone(), stub);
    anyhow::ensure!(
        matches!(
            save_named_groups_checked(state).await?,
            AtomicWriteOutcome::Durable
        ),
        "the stub is durable"
    );
    Ok(key)
}

async fn deliver_page(
    state: &Arc<AppState>,
    key: &str,
    sender: &AgentKeypair,
    events: Vec<NamedGroupMetadataEvent>,
) {
    handle_treekem_catchup_response(
        state,
        &sender.agent_id(),
        &x0x::identity::MachineId([0x23; 32]),
        true,
        TreeKemCatchupResponse {
            message_type: "treekem_catchup_response".to_string(),
            group_id: key.to_string(),
            events,
            truncated: false,
            responder_state_hash: None,
        },
    )
    .await;
}

async fn head_of(state: &AppState, key: &str) -> Option<x0x::groups::GroupInfo> {
    state.named_groups.read().await.get(key).cloned()
}

/// Inside an armed attested sequence, every page link applies state-only on
/// the pre-Welcome joiner: the role change, the rename and the removal
/// that carries a TreeKEM commit. No TreeKEM group is created.
#[tokio::test]
async fn pre_welcome_page_applies_role_rename_and_removal_state_only() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let owner = AgentKeypair::generate()?;
    let (base, links, events) = pre_welcome_fixture(&owner)?;
    assert!(!base.has_active_member(&local), "a pre-Welcome joiner");
    let mut stub = base.clone();
    stub.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: base.state_revision,
        base_hash: base.state_hash.clone(),
        anchored_gap_refusal: Some(owner_armed_record(&base, &links, &owner)),
        ..Default::default()
    });
    let key = install_stub(&state, stub).await?;
    assert!(!state.treekem_groups.read().await.contains_key(&key));

    deliver_page(&state, &key, &owner, events).await;

    let head = head_of(&state, &key)
        .await
        .ok_or_else(|| anyhow::anyhow!("stub"))?;
    let removal = links.last().ok_or_else(|| anyhow::anyhow!("links"))?;
    assert_eq!(
        head.state_hash,
        removal.state_hash,
        "every page link applied: head at revision {} (base {}, role {}, rename {}, removal {})",
        head.state_revision,
        base.state_revision,
        links[0].revision,
        links[1].revision,
        removal.revision
    );
    assert_eq!(head.name, "renamed", "the rename applied");
    assert_eq!(
        head.caller_role(&"52".repeat(32)),
        Some(x0x::groups::GroupRole::Admin),
        "the role change applied"
    );
    assert!(
        !head.has_active_member(&"53".repeat(32)),
        "the removal applied state-only"
    );
    assert!(!head.has_active_member(&local), "still pre-Welcome");
    assert!(
        !state.treekem_groups.read().await.contains_key(&key),
        "no tree is taken from the chain"
    );
    Ok(())
}

/// Control: with no armed attested sequence the removal link is still
/// refused on a pre-Welcome joiner. Rule (b) needs the attestation.
#[tokio::test]
async fn pre_welcome_removal_without_armed_sequence_is_refused() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = AgentKeypair::generate()?;
    let (base, links, events) = pre_welcome_fixture(&owner)?;
    let key = install_stub(&state, base.clone()).await?;

    deliver_page(&state, &key, &owner, events).await;

    let head = head_of(&state, &key)
        .await
        .ok_or_else(|| anyhow::anyhow!("stub"))?;
    assert_eq!(
        head.state_hash, links[1].state_hash,
        "the role change and the rename apply by the ordinary path; the removal is refused (head revision {})",
        head.state_revision
    );
    assert!(head.has_active_member(&"53".repeat(32)));
    Ok(())
}
