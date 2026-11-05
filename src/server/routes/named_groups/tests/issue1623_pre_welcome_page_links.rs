//! #1623 (ADR 0109 §2 rule (b), §7 (b), D82): a pre-Welcome joiner applies
//! each link of an armed attested sequence state-only, for every link kind.
//! Before the fix only `MemberAdded` had a pre-Welcome state-only apply. A
//! link that carries a TreeKEM commit (`MemberRemoved`, `MemberBanned`,
//! `JoinRequestApproved`) was refused, because the joiner has no TreeKEM
//! group yet. The negative cases pin each guard of
//! `admit_pre_welcome_state_only_link`. Inert: no daemon, no network.

use super::*;
use x0x::groups::GroupInfo;
use x0x::identity::AgentKeypair;

const TREEKEM_EPOCH: u64 = 1;
const ADMIN: &str = "51";
const PROMOTED: &str = "52";
const REMOVED: &str = "53";
const BANNED: &str = "54";
const REQUESTER: &str = "55";
const REQUEST_ID: &str = "issue1623-request";
const KEY_PACKAGE_HASH: &str = "issue1623-key-package-hash";

fn agent(byte: &str) -> String {
    byte.repeat(32)
}

/// A TreeKEM group at revision 1 with a pending join request from
/// `REQUESTER`. This node is seated only when `local_seat` is set.
fn base_group(owner: &AgentKeypair, local_seat: Option<&str>) -> anyhow::Result<GroupInfo> {
    let owner_hex = hex::encode(owner.agent_id().as_bytes());
    let mut base = GroupInfo::new(
        "issue1623-pre-welcome-page".to_string(),
        String::new(),
        owner.agent_id(),
        "1623".repeat(16),
    );
    base.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    let mut seats = vec![
        (agent(ADMIN), x0x::groups::GroupRole::Admin),
        (agent(PROMOTED), x0x::groups::GroupRole::Member),
        (agent(REMOVED), x0x::groups::GroupRole::Member),
        (agent(BANNED), x0x::groups::GroupRole::Member),
    ];
    if let Some(local) = local_seat {
        seats.push((local.to_string(), x0x::groups::GroupRole::Member));
    }
    for (member, role) in seats {
        base.add_member(member, role, Some(owner_hex.clone()), None);
    }
    let mut request = x0x::groups::JoinRequest::new(
        base.stable_group_id().to_string(),
        agent(REQUESTER),
        None,
        500,
    );
    request.request_id = REQUEST_ID.to_string();
    set_join_request_created(&mut base, request, None);
    base.seal_commit(owner, 1_000)?;
    Ok(base)
}

/// Seal one owner link on `info` after `mutate`.
fn seal_link(
    info: &mut GroupInfo,
    owner: &AgentKeypair,
    at_ms: u64,
    mutate: impl FnOnce(&mut GroupInfo),
) -> anyhow::Result<x0x::groups::GroupStateCommit> {
    mutate(info);
    Ok(info.seal_commit(owner, at_ms)?)
}

/// The receiver's TreeKEM epoch fields for a link with a TreeKEM commit.
fn take_treekem_epoch(info: &mut GroupInfo) {
    info.secret_epoch = TREEKEM_EPOCH;
    info.security_binding = Some(format!("treekem:epoch={TREEKEM_EPOCH}"));
}

fn treekem_commit_b64() -> Option<String> {
    Some(BASE64.encode(b"issue1623-treekem-commit"))
}

fn removal_event(
    info: &GroupInfo,
    owner_hex: &str,
    commit: &x0x::groups::GroupStateCommit,
) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::MemberRemoved {
        group_id: info.stable_group_id().to_string(),
        revision: commit.revision,
        actor: owner_hex.to_string(),
        agent_id: agent(REMOVED),
        treekem_commit_b64: treekem_commit_b64(),
        treekem_epoch: Some(TREEKEM_EPOCH),
        secret_epoch: None,
        commit: Some(commit.clone()),
    }
}

/// One removal link after `base`, with its event.
fn removal_link(
    base: &GroupInfo,
    owner: &AgentKeypair,
    mutate_policy: bool,
) -> anyhow::Result<(x0x::groups::GroupStateCommit, NamedGroupMetadataEvent)> {
    let owner_hex = hex::encode(owner.agent_id().as_bytes());
    let mut ahead = base.clone();
    let commit = seal_link(&mut ahead, owner, 2_000, |next| {
        if mutate_policy {
            next.policy.discoverability = x0x::groups::GroupDiscoverability::PublicDirectory;
        }
        next.remove_member(&agent(REMOVED), Some(owner_hex.clone()));
        take_treekem_epoch(next);
    })?;
    let event = removal_event(base, &owner_hex, &commit);
    Ok((commit, event))
}

/// The owner-armed record (#846): `sequence`, then the joiner's terminal.
fn arm(stub: &mut GroupInfo, sequence: Vec<String>, owner: &AgentKeypair) {
    let terminal_revision = stub.state_revision + sequence.len() as u64 + 1;
    let terminal_state_hash = "7e".repeat(32);
    let mut attested_chain_hashes = sequence;
    attested_chain_hashes.push(terminal_state_hash.clone());
    stub.invite_lineage = Some(x0x::groups::InviteLineage {
        base_revision: stub.state_revision,
        base_hash: stub.state_hash.clone(),
        anchored_gap_refusal: Some(x0x::groups::AnchoredGapRefusal {
            reason: "owner_attested_stale_base_gap".to_string(),
            head_revision: stub.state_revision,
            head_state_hash: stub.state_hash.clone(),
            terminal_revision,
            terminal_state_hash,
            committed_by: hex::encode(owner.agent_id().as_bytes()),
            occurrences: 1,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            attested_chain_hashes,
            by_reason: Default::default(),
        }),
        ..Default::default()
    });
}

async fn install_stub(state: &AppState, stub: GroupInfo) -> anyhow::Result<String> {
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

/// Source: a catch-up page whose responder is the link's signer.
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

/// Source: a DM or gossip delivery from the signer, then the TreeKEM
/// replay that drains the queue (`treekem_not_ready` queues it first).
async fn deliver_direct(
    state: &Arc<AppState>,
    key: &str,
    sender: &AgentKeypair,
    event: NamedGroupMetadataEvent,
) {
    let _ = apply_named_group_metadata_event(state, event, sender.agent_id(), true, None).await;
    replay_pending_treekem_events(state, key, None).await;
}

async fn head_of(state: &AppState, key: &str) -> anyhow::Result<GroupInfo> {
    state
        .named_groups
        .read()
        .await
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("stub"))
}

async fn assert_no_tree(state: &AppState, key: &str) {
    assert!(
        !state.treekem_groups.read().await.contains_key(key),
        "no tree is taken from the chain"
    );
}

/// ADR 0109 §2: no epoch is taken from the chain; the signed binding stays.
fn assert_epoch_kept(head: &GroupInfo, base: &GroupInfo) {
    assert_ne!(
        base.secret_epoch, TREEKEM_EPOCH,
        "the link names another epoch"
    );
    assert_eq!(
        head.secret_epoch, base.secret_epoch,
        "no epoch from the chain"
    );
    let binding = format!("treekem:epoch={TREEKEM_EPOCH}");
    assert_eq!(head.security_binding.as_deref(), Some(binding.as_str()));
}

/// `deliver_direct`, with the `treekem.trace` text it produced. The test
/// runtime is current-thread, so only this delivery's events land here.
async fn refusal_trace(
    state: &Arc<AppState>,
    key: &str,
    sender: &AgentKeypair,
    event: NamedGroupMetadataEvent,
) -> String {
    #[derive(Clone, Default)]
    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("sink").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    deliver_direct(state, key, sender, event).await;
    drop(guard);
    let bytes = sink.0.lock().expect("sink").clone();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Inside an armed attested sequence, every page link applies state-only on
/// the pre-Welcome joiner: the role change, the rename and the removal
/// that carries a TreeKEM commit.
#[tokio::test]
async fn pre_welcome_page_applies_role_rename_and_removal_state_only() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let owner = AgentKeypair::generate()?;
    let owner_hex = hex::encode(owner.agent_id().as_bytes());
    let base = base_group(&owner, None)?;
    let stable = base.stable_group_id().to_string();
    let mut ahead = base.clone();
    let role = seal_link(&mut ahead, &owner, 2_000, |next| {
        next.set_member_role(&agent(PROMOTED), x0x::groups::GroupRole::Admin);
    })?;
    let rename = seal_link(&mut ahead, &owner, 3_000, |next| {
        next.name = "renamed".to_string();
    })?;
    let removal = seal_link(&mut ahead, &owner, 4_000, |next| {
        next.remove_member(&agent(REMOVED), Some(owner_hex.clone()));
        take_treekem_epoch(next);
    })?;
    let events = vec![
        NamedGroupMetadataEvent::MemberRoleUpdated {
            group_id: stable.clone(),
            revision: role.revision,
            actor: owner_hex.clone(),
            agent_id: agent(PROMOTED),
            role: x0x::groups::GroupRole::Admin,
            commit: Some(role.clone()),
        },
        NamedGroupMetadataEvent::GroupMetadataUpdated {
            group_id: stable,
            revision: rename.revision,
            actor: owner_hex.clone(),
            name: Some("renamed".to_string()),
            description: None,
            commit: Some(rename.clone()),
        },
        removal_event(&base, &owner_hex, &removal),
    ];
    let mut stub = base.clone();
    let sequence = [&role, &rename, &removal]
        .iter()
        .map(|link| link.state_hash.clone())
        .collect();
    arm(&mut stub, sequence, &owner);
    let key = install_stub(&state, stub).await?;

    deliver_page(&state, &key, &owner, events).await;

    let head = head_of(&state, &key).await?;
    assert_eq!(
        head.state_hash, removal.state_hash,
        "every page link applied: head at revision {} (base {}, role {}, rename {}, removal {})",
        head.state_revision, base.state_revision, role.revision, rename.revision, removal.revision
    );
    assert_eq!(head.name, "renamed", "the rename applied");
    assert_eq!(
        head.caller_role(&agent(PROMOTED)),
        Some(x0x::groups::GroupRole::Admin)
    );
    assert!(!head.has_active_member(&agent(REMOVED)));
    assert!(!head.has_active_member(&local), "still pre-Welcome");
    assert_epoch_kept(&head, &base);
    assert_no_tree(&state, &key).await;
    Ok(())
}

/// `MemberBanned`, from a catch-up page whose responder is the signer.
#[tokio::test]
async fn pre_welcome_page_applies_ban_state_only() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = AgentKeypair::generate()?;
    let owner_hex = hex::encode(owner.agent_id().as_bytes());
    let base = base_group(&owner, None)?;
    let mut ahead = base.clone();
    let ban = seal_link(&mut ahead, &owner, 2_000, |next| {
        next.ban_member(&agent(BANNED), Some(owner_hex.clone()));
        take_treekem_epoch(next);
    })?;
    let event = NamedGroupMetadataEvent::MemberBanned {
        group_id: base.stable_group_id().to_string(),
        revision: ban.revision,
        actor: owner_hex,
        agent_id: agent(BANNED),
        secret_epoch: None,
        treekem_commit_b64: treekem_commit_b64(),
        treekem_epoch: Some(TREEKEM_EPOCH),
        commit: Some(ban.clone()),
    };
    let mut stub = base.clone();
    arm(&mut stub, vec![ban.state_hash.clone()], &owner);
    let key = install_stub(&state, stub).await?;

    deliver_page(&state, &key, &owner, vec![event]).await;

    let head = head_of(&state, &key).await?;
    assert_eq!(
        head.state_hash, ban.state_hash,
        "the ban applied state-only"
    );
    assert!(head.is_banned(&agent(BANNED)));
    assert_epoch_kept(&head, &base);
    assert_no_tree(&state, &key).await;
    Ok(())
}

/// `JoinRequestApproved` for another requester, from a DM or gossip
/// delivery by the signer (then the TreeKEM queue replay).
#[tokio::test]
async fn pre_welcome_direct_applies_other_approval_state_only() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = AgentKeypair::generate()?;
    let owner_hex = hex::encode(owner.agent_id().as_bytes());
    let base = base_group(&owner, None)?;
    let mut ahead = base.clone();
    let revision = base.state_revision + 1;
    let approval = seal_link(&mut ahead, &owner, 2_000, |next| {
        set_join_request_approved(
            next,
            REQUEST_ID,
            &owner_hex,
            &agent(REQUESTER),
            revision,
            2_000,
        );
        next.set_member_treekem_key_package_hash(&agent(REQUESTER), KEY_PACKAGE_HASH.to_string());
        take_treekem_epoch(next);
    })?;
    let event = NamedGroupMetadataEvent::JoinRequestApproved {
        group_id: base.stable_group_id().to_string(),
        request_id: REQUEST_ID.to_string(),
        revision: approval.revision,
        actor: owner_hex,
        requester_agent_id: agent(REQUESTER),
        treekem_commit_b64: treekem_commit_b64(),
        treekem_welcome_b64: Some(BASE64.encode(b"issue1623-welcome-for-requester")),
        welcome_ref: None,
        treekem_epoch: Some(TREEKEM_EPOCH),
        treekem_key_package_hash: Some(KEY_PACKAGE_HASH.to_string()),
        commit: Some(approval.clone()),
    };
    let mut stub = base.clone();
    arm(&mut stub, vec![approval.state_hash.clone()], &owner);
    let key = install_stub(&state, stub).await?;

    deliver_direct(&state, &key, &owner, event).await;

    let head = head_of(&state, &key).await?;
    assert_eq!(
        head.state_hash, approval.state_hash,
        "the approval applied state-only"
    );
    assert!(head.has_active_member(&agent(REQUESTER)));
    assert_epoch_kept(&head, &base);
    assert_no_tree(&state, &key).await;
    Ok(())
}

/// Control: with no armed attested sequence the removal is refused.
#[tokio::test]
async fn pre_welcome_removal_without_armed_sequence_is_refused() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = AgentKeypair::generate()?;
    let base = base_group(&owner, None)?;
    let (_, event) = removal_link(&base, &owner, false)?;
    let key = install_stub(&state, base.clone()).await?;
    let trace = refusal_trace(&state, &key, &owner, event).await;
    assert!(trace.contains("pre_welcome_no_armed_sequence"), "{trace}");
    assert_eq!(head_of(&state, &key).await?.state_hash, base.state_hash);
    Ok(())
}

/// A ban with no armed sequence on a node with no Welcome is refused
/// with the rule (b) reason, not `treekem_group_missing`.
#[tokio::test]
async fn pre_welcome_ban_without_armed_sequence_is_refused() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = AgentKeypair::generate()?;
    let owner_hex = hex::encode(owner.agent_id().as_bytes());
    let base = base_group(&owner, None)?;
    let ban = seal_link(&mut base.clone(), &owner, 2_000, |next| {
        next.ban_member(&agent(BANNED), Some(owner_hex.clone()));
        take_treekem_epoch(next);
    })?;
    let event = NamedGroupMetadataEvent::MemberBanned {
        group_id: base.stable_group_id().to_string(),
        revision: ban.revision,
        actor: owner_hex,
        agent_id: agent(BANNED),
        secret_epoch: None,
        treekem_commit_b64: treekem_commit_b64(),
        treekem_epoch: Some(TREEKEM_EPOCH),
        commit: Some(ban),
    };
    let key = install_stub(&state, base.clone()).await?;
    let trace = refusal_trace(&state, &key, &owner, event).await;
    assert!(trace.contains("pre_welcome_no_armed_sequence"), "{trace}");
    assert!(trace.contains("pre_welcome_link_not_admitted"), "{trace}");
    assert_eq!(head_of(&state, &key).await?.state_hash, base.state_hash);
    Ok(())
}

/// Guard (a): a node that is Active on its roster but has no tree is not
/// pre-Welcome. The armed sequence does not let it skip the TreeKEM commit.
#[tokio::test]
async fn seated_node_without_tree_refuses_removal() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let owner = AgentKeypair::generate()?;
    let base = base_group(&owner, Some(&local))?;
    assert!(base.has_active_member(&local));
    let (removal, event) = removal_link(&base, &owner, false)?;
    let mut stub = base.clone();
    arm(&mut stub, vec![removal.state_hash.clone()], &owner);
    let key = install_stub(&state, stub).await?;
    let trace = refusal_trace(&state, &key, &owner, event).await;
    assert!(trace.contains("pre_welcome_local_seat_active"), "{trace}");
    assert_eq!(head_of(&state, &key).await?.state_hash, base.state_hash);
    assert_no_tree(&state, &key).await;
    Ok(())
}

/// Guard (b): a link that changes the policy hash is refused, even when
/// the armed sequence names it.
#[tokio::test]
async fn pre_welcome_removal_that_changes_policy_is_refused() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = AgentKeypair::generate()?;
    let base = base_group(&owner, None)?;
    let (removal, event) = removal_link(&base, &owner, true)?;
    assert_ne!(
        removal.policy_hash,
        x0x::groups::compute_policy_hash(&base.policy)
    );
    let mut stub = base.clone();
    arm(&mut stub, vec![removal.state_hash.clone()], &owner);
    let key = install_stub(&state, stub).await?;
    // The ordinary apply refuses it first (the state hash is recomputed
    // from the local policy), so the guard's own reason is read directly.
    let stub = head_of(&state, &key).await?;
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let verdict =
        admit_pre_welcome_state_only_link(&state, &stub, &mut stub.clone(), &event, &local).await;
    assert_eq!(verdict, Err("pre_welcome_policy_change"));
    deliver_direct(&state, &key, &owner, event).await;
    assert_eq!(head_of(&state, &key).await?.state_hash, base.state_hash);
    Ok(())
}

/// Guard (c): with the sequence ARMED, a link that is not its next hash is
/// refused. Delivered directly, so the page gate does not see it first.
#[tokio::test]
async fn pre_welcome_removal_outside_armed_sequence_is_refused() -> anyhow::Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = AgentKeypair::generate()?;
    let base = base_group(&owner, None)?;
    let (_, event) = removal_link(&base, &owner, false)?;
    let mut stub = base.clone();
    arm(&mut stub, vec!["5e".repeat(32)], &owner);
    let key = install_stub(&state, stub).await?;
    assert!(
        catchup_846_gate_armed(&head_of(&state, &key).await?),
        "armed"
    );
    let trace = refusal_trace(&state, &key, &owner, event).await;
    assert!(
        trace.contains("pre_welcome_outside_armed_sequence"),
        "{trace}"
    );
    assert_eq!(head_of(&state, &key).await?.state_hash, base.state_hash);
    Ok(())
}

/// Round 4: a real responder pages two links, one event per page, to a
/// pre-Welcome joiner. The joiner keeps its local epoch (ADR 0109 §2), so
/// its request names the head epoch from the signed binding; with the
/// local epoch the responder serves the applied link again and the joiner
/// stalls after the first link.
#[tokio::test]
async fn pre_welcome_joiner_pages_two_links_from_a_real_responder() -> anyhow::Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (responder, _responder_dir) = secure_endpoint_test_state().await?;
    let joiner_hex = hex::encode(joiner.agent.agent_id().as_bytes());
    let owner = AgentKeypair::generate()?;
    let owner_hex = hex::encode(owner.agent_id().as_bytes());
    let base = base_group(&owner, None)?;
    let mut ahead = base.clone();
    let mut links = Vec::new();
    for (epoch, member, at_ms) in [(1_u64, REMOVED, 2_000), (2, BANNED, 3_000)] {
        let commit = seal_link(&mut ahead, &owner, at_ms, |next| {
            next.remove_member(&agent(member), Some(owner_hex.clone()));
            next.secret_epoch = epoch;
            next.security_binding = Some(format!("treekem:epoch={epoch}"));
        })?;
        let mut event = removal_event(&base, &owner_hex, &commit);
        if let NamedGroupMetadataEvent::MemberRemoved {
            agent_id,
            treekem_epoch,
            ..
        } = &mut event
        {
            *agent_id = agent(member);
            *treekem_epoch = Some(epoch);
        }
        links.push((commit, event));
    }
    let mut stub = base.clone();
    let sequence = links.iter().map(|(c, _)| c.state_hash.clone()).collect();
    arm(&mut stub, sequence, &owner);
    let key = install_stub(&joiner, stub).await?;
    // The responder seats the joiner (so it serves it) and logs both links.
    let mut served = ahead.clone();
    served.add_member(
        joiner_hex.clone(),
        x0x::groups::GroupRole::Member,
        None,
        None,
    );
    install_stub(&responder, served).await?;
    let events = links.iter().map(|(_, e)| e.clone()).collect();
    responder
        .treekem_event_log
        .write()
        .await
        .insert(key.clone(), events);

    let terminal = links.last().map(|(c, _)| c.state_hash.clone());
    for _ in 0..4 {
        let head = head_of(&joiner, &key).await?;
        if Some(&head.state_hash) == terminal.as_ref() {
            break;
        }
        let cursor = (head.secret_epoch, head.security_binding.clone());
        let request = TreeKemCatchupRequest {
            message_type: "treekem_catchup_request".to_string(),
            group_id: key.clone(),
            requester_agent_id: joiner_hex.clone(),
            from_revision: head.state_revision,
            from_treekem_epoch: treekem_catchup_cursor_epoch(
                &joiner,
                std::slice::from_ref(&key),
                cursor,
            )
            .await,
            current_state_hash: head.state_hash.clone(),
            missing_prev_state_hash: None,
            target_member_id: None,
            limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
        };
        let machine = x0x::identity::MachineId([0x24; 32]);
        let recorder = &responder.named_group_test_recorders.catchup_responses;
        recorder.lock().expect("recorder").clear();
        handle_treekem_catchup_request(
            &responder,
            &joiner.agent.agent_id(),
            &machine,
            true,
            request,
        )
        .await;
        let payload = recorder.lock().expect("recorder").pop();
        let page: TreeKemCatchupResponse = serde_json::from_slice(&payload.unwrap_or_default())?;
        assert_eq!(page.events.len(), 1, "one event per page");
        deliver_page(&joiner, &key, &owner, page.events).await;
    }
    let head = head_of(&joiner, &key).await?;
    assert_eq!(
        Some(head.state_hash),
        terminal,
        "the joiner reached the final head"
    );
    assert_eq!(
        head.secret_epoch, base.secret_epoch,
        "no epoch from the chain"
    );
    assert_no_tree(&joiner, &key).await;
    Ok(())
}
