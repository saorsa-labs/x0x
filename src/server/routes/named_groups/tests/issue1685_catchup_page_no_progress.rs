//! #1685: a truncated catch-up page whose events cannot apply yet must
//! not re-request the next page at once. The H-S3-c/c2 shape: a
//! fork-stranded node's head does not link to the responder's fork
//! commits, so every served event is retained as pending
//! (`state_hash_gap`), the catch-up cursor does not move, and the
//! responder's page is a pure function of that cursor — the identical
//! request re-fetches the identical truncated page. The request/response
//! pair then hot-loops between the two peers (`#1685`: CPU spin, and a
//! paused tokio runtime never parks so virtual time cannot advance).
//! The page loop must stop with the typed reason
//! `truncated_page_no_progress` instead: the pending queue keeps its
//! events (requeue still runs; no state is hidden), and catch-up re-arms
//! when a later incoming event queues (the 5 s-throttled gap ask) or an
//! epoch-ahead signal asks again — there is no timer; a quiet group
//! stays idle. A page whose events were all already at or below the
//! cursor (a duplicate from a second peer, or a stale page) pages on:
//! the next ask carries a newer cursor and can still make progress.

use super::*;
use x0x::identity::AgentKeypair;

/// The stranded self-leave a fork responder serves past the local head:
/// its signed commit links from the responder's fork parent — a hash the
/// local head never had — so the event queues as `state_hash_gap` and
/// replay requeues it instead of applying it. `actor == agent_id ==
/// sender` with no TreeKEM payload is the authenticated queue shape.
fn fork_removal_page_event(
    group_id: &str,
    responder: &AgentKeypair,
    revision: u64,
) -> NamedGroupMetadataEvent {
    let responder_hex = hex::encode(responder.agent_id().as_bytes());
    let commit = x0x::groups::GroupStateCommit::sign(
        group_id.to_string(),
        revision,
        Some(format!("fork-prev-{revision}")),
        "fork-roster".to_string(),
        "policy".to_string(),
        "meta".to_string(),
        None,
        false,
        1,
        responder,
    )
    .expect("signed fork commit");
    NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.to_string(),
        revision,
        actor: responder_hex.clone(),
        agent_id: responder_hex,
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    }
}

/// A TreeKEM group whose local head sits at `head_revision`, with
/// `responder` as the only other (active) member — the fork-stranded
/// pair of row H-S3-c, reduced to its catch-up edge.
async fn fork_stranded_pair(
    group_id: &str,
    responder: &AgentKeypair,
) -> Result<(Arc<AppState>, tempfile::TempDir)> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let local = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::new(
        "issue1685".to_string(),
        String::new(),
        local,
        group_id.to_string(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    info.add_member(
        hex::encode(responder.agent_id().as_bytes()),
        x0x::groups::GroupRole::Member,
        Some(hex::encode(local.as_bytes())),
        None,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
    Ok((state, dir))
}

fn truncated_page(group_id: &str, event: NamedGroupMetadataEvent) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.to_string(),
        events: vec![event],
        truncated: true,
        responder_state_hash: Some("fork-head".to_string()),
    }
}

/// Every page re-request the response handler made, counted through the
/// `catchup_page_force_ok` seam (the same observation point the #1113
/// page-stream tests use).
fn page_requests(state: &AppState) -> usize {
    state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .len()
}

async fn pending_len(state: &AppState, group_id: &str) -> usize {
    state
        .treekem_pending_events
        .read()
        .await
        .get(group_id)
        .map(VecDeque::len)
        .unwrap_or(0)
}

async fn cursor(state: &AppState, group_id: &str) -> (u64, u64, String) {
    let groups = state.named_groups.read().await;
    let info = groups.get(group_id).expect("group");
    (
        info.state_revision,
        info.secret_epoch,
        info.state_hash.clone(),
    )
}

/// The #1685 hot loop's driving edge, as one bounded step: a truncated
/// page from the fork responder applies nothing (the event is queued,
/// replay requeues it) and leaves the cursor unmoved — so the handler
/// must NOT ask that peer for the next page. On main the re-request
/// fires at once; the identical page comes back, and under paused
/// virtual time the pair never idles.
#[tokio::test]
async fn a_no_progress_truncated_page_stops_the_page_re_request_loop() -> Result<()> {
    let group_id = "6a".repeat(32);
    let responder = AgentKeypair::generate()?;
    let (state, _dir) = fork_stranded_pair(&group_id, &responder).await?;
    let cursor_before = cursor(&state, &group_id).await;
    let event = fork_removal_page_event(&group_id, &responder, cursor_before.0 + 1);
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &clean_sender_machine(),
        true,
        truncated_page(&group_id, event),
    )
    .await;

    assert_eq!(
        pending_len(&state, &group_id).await,
        1,
        "the unappliable fork event stays queued (requeue ran; nothing was dropped to hide the loop)"
    );
    assert_eq!(
        cursor(&state, &group_id).await,
        cursor_before,
        "CONTROL: the stranded page really applied nothing"
    );
    assert_eq!(
        page_requests(&state),
        0,
        "#1685: a truncated page that moved no cursor must not re-request the identical next page"
    );
    Ok(())
}

/// The stop holds for a repeated identical page: nothing re-arms the
/// pair on its own, so the two peers go idle (a paused runtime can park
/// and advance virtual time) until new state arrives through another
/// path.
#[tokio::test]
async fn a_repeated_no_progress_page_keeps_the_loop_stopped() -> Result<()> {
    let group_id = "6b".repeat(32);
    let responder = AgentKeypair::generate()?;
    let (state, _dir) = fork_stranded_pair(&group_id, &responder).await?;
    let head = cursor(&state, &group_id).await;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    for _ in 0..3 {
        let event = fork_removal_page_event(&group_id, &responder, head.0 + 1);
        handle_treekem_catchup_response(
            &state,
            &responder.agent_id(),
            &clean_sender_machine(),
            true,
            truncated_page(&group_id, event),
        )
        .await;
    }

    assert_eq!(
        page_requests(&state),
        0,
        "#1685: repeated no-progress truncated pages never re-request; the pair idles instead of spinning"
    );
    assert_eq!(
        pending_len(&state, &group_id).await,
        1,
        "the pending queue holds its entry across the repeated pages"
    );
    Ok(())
}

/// The stop is a typed decision, not a silent drop: each no-progress
/// page records `(group, peer, reason)` with the
/// `truncated_page_no_progress` reason, and the pending entry stays
/// armed for the next convergence path.
#[tokio::test]
async fn the_no_progress_stop_is_typed_and_leaves_the_pending_queue_armed() -> Result<()> {
    let group_id = "6d".repeat(32);
    let responder = AgentKeypair::generate()?;
    let (state, _dir) = fork_stranded_pair(&group_id, &responder).await?;
    let head = cursor(&state, &group_id).await;
    let event = fork_removal_page_event(&group_id, &responder, head.0 + 1);
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &clean_sender_machine(),
        true,
        truncated_page(&group_id, event),
    )
    .await;

    let stops = state
        .named_group_test_recorders
        .catchup_page_stops
        .lock()
        .expect("page-stop recorder")
        .clone();
    assert_eq!(stops.len(), 1, "the stop is recorded once");
    assert_eq!(
        stops[0],
        (
            group_id.clone(),
            hex::encode(responder.agent_id().as_bytes()),
            "truncated_page_no_progress"
        ),
        "the stop names the group, the peer and the typed reason"
    );
    assert_eq!(
        pending_len(&state, &group_id).await,
        1,
        "the pending entry stays armed after the typed stop"
    );
    Ok(())
}

/// CONTROL (liveness): a truncated page that APPLIES moves the cursor,
/// so the next page request goes out at once — the stop must never slow
/// a converging multi-page stream. This holds on main and after the fix.
#[tokio::test]
async fn a_progressing_truncated_page_still_re_requests_the_next_page() -> Result<()> {
    let group_id = "6c".repeat(32);
    let (mut state, _dir) = secure_endpoint_test_state().await?;
    super::super::revocation_eviction::zero_restart_wait_for_test(&mut state);
    let admin_id = state.agent.agent_id();
    let group_id_bytes = hex::decode(&group_id)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
    let member_kp = AgentKeypair::generate()?;
    let member_id = member_kp.agent_id();
    let member_hex = hex::encode(member_id.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &[9u8; 32])?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let added = admin_group.add_member(member_id, &kp_bytes)?;
    let _leaver_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
    let epoch_before = admin_group.epoch();

    let mut info = x0x::groups::GroupInfo::new(
        "issue1685-progress".to_string(),
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

    // The member's signed self-leave, sealed on a clone of the live
    // head — the adjacent link the apply path accepts (the #1113
    // `signed_self_leave` shape).
    let mut leaving = {
        let groups = state.named_groups.read().await;
        groups.get(&group_id).cloned().expect("group")
    };
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision = leaving.roster_revision;
    leaving.remove_member(&member_hex, Some(member_hex.clone()));
    let commit = leaving.seal_commit(&member_kp, now_millis_u64())?;
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.clone(),
        revision,
        actor: member_hex.clone(),
        agent_id: member_hex,
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    let cursor_before = cursor(&state, &group_id).await;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    handle_treekem_catchup_response(
        &state,
        &member_id,
        &clean_sender_machine(),
        true,
        truncated_page(&group_id, event),
    )
    .await;

    assert_ne!(
        cursor(&state, &group_id).await,
        cursor_before,
        "CONTROL: the linked self-leave really applied"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "a truncated page that moved the cursor re-requests the next page at once"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_stops
            .lock()
            .expect("page-stop recorder")
            .is_empty(),
        "a progressing page never records a stop"
    );
    Ok(())
}

/// Review round 1 blocker (the second-peer duplicate): two peers asked
/// at the same cursor can both answer with a truncated page for the
/// same next revision. Whichever page applies first moves the cursor;
/// the other is then a page of events the local head is already at or
/// past. That duplicate page must NOT stop the stream — this peer's
/// next ask carries the NEW cursor and can still make progress, and
/// only this peer's own last page closes its page fence. The same
/// shape covers a stale page that lost a race to gossip.
#[tokio::test]
async fn a_stale_duplicate_page_keeps_paging() -> Result<()> {
    let group_id = "6e".repeat(32);
    let (mut state, _dir) = secure_endpoint_test_state().await?;
    super::super::revocation_eviction::zero_restart_wait_for_test(&mut state);
    let admin_id = state.agent.agent_id();
    let group_id_bytes = hex::decode(&group_id)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
    let member_kp = AgentKeypair::generate()?;
    let member_id = member_kp.agent_id();
    let member_hex = hex::encode(member_id.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &[9u8; 32])?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let added = admin_group.add_member(member_id, &kp_bytes)?;
    let _leaver_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
    let epoch_before = admin_group.epoch();

    let mut info = x0x::groups::GroupInfo::new(
        "issue1685-duplicate".to_string(),
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
    // The second responder: still an Active member after the leaver's
    // page applies, so its later duplicate page passes the member gate.
    let other = AgentKeypair::generate()?;
    let other_id = other.agent_id();
    info.add_member(
        hex::encode(other_id.as_bytes()),
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

    // The member's linked self-leave — the event both responders would
    // serve for the ask at the base cursor.
    let mut leaving = {
        let groups = state.named_groups.read().await;
        groups.get(&group_id).cloned().expect("group")
    };
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision = leaving.roster_revision;
    leaving.remove_member(&member_hex, Some(member_hex.clone()));
    let commit = leaving.seal_commit(&member_kp, now_millis_u64())?;
    let event = NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.clone(),
        revision,
        actor: member_hex.clone(),
        agent_id: member_hex,
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    let cursor_before = cursor(&state, &group_id).await;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // Peer A's page applies first and moves the cursor.
    handle_treekem_catchup_response(
        &state,
        &member_id,
        &clean_sender_machine(),
        true,
        truncated_page(&group_id, event.clone()),
    )
    .await;
    assert_ne!(
        cursor(&state, &group_id).await,
        cursor_before,
        "peer A's page applied first"
    );

    // Peer B's identical page is now a duplicate: nothing applies, the
    // cursor does not move, and every served event sits at the cursor.
    // It must still page on — its next ask carries the moved cursor.
    handle_treekem_catchup_response(
        &state,
        &other_id,
        &clean_sender_machine(),
        true,
        truncated_page(&group_id, event),
    )
    .await;
    assert_eq!(
        page_requests(&state),
        2,
        "the duplicate page keeps its peer's stream going (both pages re-request)"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_stops
            .lock()
            .expect("page-stop recorder")
            .is_empty(),
        "a duplicate page records no stop"
    );
    Ok(())
}
