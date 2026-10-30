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
//! when a later incoming event queues (the 5 s-throttled gap ask), an
//! epoch-ahead signal asks again, or a replay APPLIES a retained event
//! and re-arms this peer at the moved cursor (round 3, review
//! 5712505625). There is no timer; a quiet group whose gap never clears
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

/// A terminal (non-truncated) page — the responder's last page for the
/// ask. `events` may be empty: an empty reply is a terminal page.
fn terminal_page(group_id: &str, events: Vec<NamedGroupMetadataEvent>) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.to_string(),
        events,
        truncated: false,
        responder_state_hash: Some("terminal-head".to_string()),
    }
}

/// Every page-loop re-arm the response/replay path sent, through the
/// `catchup_page_rearms` seam: `(group, peer, reason)`.
fn rearm_requests(state: &AppState) -> Vec<(String, String, &'static str)> {
    state
        .named_group_test_recorders
        .catchup_page_rearms
        .lock()
        .expect("re-arm recorder")
        .clone()
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

/// The stop holds for a repeated identical page: no replay applies the
/// retained fork event, so nothing re-arms the pair on its own and the
/// two peers go idle (a paused runtime can park and advance virtual
/// time) until new state arrives through another path.
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
        "#1685: repeated no-progress pages re-request nothing (applied state is the only re-arm); the pair idles instead of spinning"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_stops
            .lock()
            .expect("page-stop recorder")
            .len(),
        3,
        "each repeated page records its own typed stop"
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

/// Review round 3 P1 (5712505625): the stop must not outlive its
/// premise. A truncated page stops on a still-new event that only lacks
/// its predecessor — a TEMPORARY dependency, unlike the fork shape.
/// When another member's page delivers the missing link and the replay
/// APPLIES the retained event, the stopped peer is asked for its next
/// page again (the re-arm), and that peer's page fence closes only when
/// its own terminal page arrives. At 9efb41f8 nothing re-asks the
/// stopped peer, so the still-open peer fence defers the self-leave
/// rekey for ever in a quiet group, even though the dependency cleared.
#[tokio::test]
async fn an_applied_replay_rearms_the_stopped_page_loop_to_the_terminal_page() -> Result<()> {
    let group_id = "70".repeat(32);
    let (mut state, _dir) = secure_endpoint_test_state().await?;
    super::super::revocation_eviction::zero_restart_wait_for_test(&mut state);
    let admin_id = state.agent.agent_id();
    let admin_hex = hex::encode(admin_id.as_bytes());
    let group_id_bytes = hex::decode(&group_id)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
    // Two leavers whose self-leaves chain: E1 (v1) is the dependency E2
    // (v2) waits for.
    let mut leavers = Vec::new();
    for seed in 0u8..2 {
        let kp = AgentKeypair::generate()?;
        let id = kp.agent_id();
        let hex_id = hex::encode(id.as_bytes());
        let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(id, &[9u8 + seed; 32])?;
        let kp_bytes = prepared.key_package_bytes().to_vec();
        let added = admin_group.add_member(id, &kp_bytes)?;
        let _leaver_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
        leavers.push((kp, hex_id, kp_bytes));
    }
    let epoch_before = admin_group.epoch();
    let (v1_kp, v1_hex, _) = &leavers[0];
    let (v2_kp, v2_hex, _) = &leavers[1];

    let mut info = x0x::groups::GroupInfo::new(
        "issue1685-rearm".to_string(),
        String::new(),
        admin_id,
        group_id.clone(),
    );
    info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    for (_, hex_id, kp_bytes) in &leavers {
        info.add_member(
            hex_id.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
        info.set_member_treekem_key_package(
            hex_id,
            base64::engine::general_purpose::STANDARD.encode(kp_bytes),
        );
    }
    // The two page responders: roster-only active members, like the
    // second responder in the duplicate-page test.
    let responder = AgentKeypair::generate()?;
    let responder_id = responder.agent_id();
    let responder_hex = hex::encode(responder_id.as_bytes());
    let helper = AgentKeypair::generate()?;
    let helper_id = helper.agent_id();
    let helper_hex = hex::encode(helper_id.as_bytes());
    for peer_hex in [&responder_hex, &helper_hex] {
        info.add_member(
            peer_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
    }
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
    let fence_ids = {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group");
        [
            group_id.clone(),
            info.mls_group_id.clone(),
            info.stable_group_id().to_string(),
        ]
    };

    // The two-link chain, sealed on one clone. `seal_commit` bumps the
    // clone's state_revision and recomputes its hash, so after E1's
    // seal the clone holds exactly the post-E1 head (revision R+1, hash
    // H1) that E2 must link from.
    let mut leaving = {
        let groups = state.named_groups.read().await;
        groups.get(&group_id).cloned().expect("group")
    };
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision1 = leaving.roster_revision;
    leaving.remove_member(v1_hex, Some(v1_hex.clone()));
    let commit1 = leaving.seal_commit(v1_kp, now_millis_u64())?;
    let event1 = NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.clone(),
        revision: revision1,
        actor: v1_hex.clone(),
        agent_id: v1_hex.clone(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit1),
    };
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision2 = leaving.roster_revision;
    leaving.remove_member(v2_hex, Some(v2_hex.clone()));
    let commit2 = leaving.seal_commit(v2_kp, now_millis_u64())?;
    let event2 = NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.clone(),
        revision: revision2,
        actor: v2_hex.clone(),
        agent_id: v2_hex.clone(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit2.clone()),
    };
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder's truncated page serves E2 before its
    //    predecessor: E2 queues as a revision gap, nothing applies, the
    //    cursor does not move — the typed stop. The responder's page
    //    fence stays open.
    handle_treekem_catchup_response(
        &state,
        &responder_id,
        &clean_sender_machine(),
        true,
        truncated_page(&group_id, event2.clone()),
    )
    .await;
    let stops = state
        .named_group_test_recorders
        .catchup_page_stops
        .lock()
        .expect("page-stop recorder")
        .clone();
    assert_eq!(stops.len(), 1, "the stuck page records one typed stop");
    assert_eq!(
        stops[0],
        (
            group_id.clone(),
            responder_hex.clone(),
            "truncated_page_no_progress"
        )
    );
    assert_eq!(
        page_requests(&state),
        0,
        "the stopped loop asks for no next page at the unmoved cursor"
    );
    assert_eq!(pending_len(&state, &group_id).await, 1, "E2 stays queued");
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "the stopped peer's page fence stays open after the stop"
    );

    // 2. The dependency clears: the helper's TERMINAL page delivers E1.
    //    E1 applies, the page handler's replay then applies the retained
    //    E2, and the stopped responder is re-armed — asked for its next
    //    page at the moved cursor. The helper's page was terminal, so
    //    the only page request is the re-arm.
    handle_treekem_catchup_response(
        &state,
        &helper_id,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    let head = cursor(&state, &group_id).await;
    assert_eq!(
        head.0, revision2,
        "E1 applied and the replay applied the retained E2 after it"
    );
    assert_eq!(
        head.2, commit2.state_hash,
        "the two-link chain reached the head E2 sealed"
    );
    assert_eq!(pending_len(&state, &group_id).await, 0, "the queue drained");
    assert_eq!(
        page_requests(&state),
        1,
        "the applied replay re-armed exactly one ask: the stopped responder's next page"
    );
    assert_eq!(
        rearm_requests(&state),
        vec![(group_id.clone(), responder_hex.clone(), "replay_applied")],
        "the re-arm is typed and names the stopped peer"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "the re-arm asks; only the peer's own terminal page closes its fence"
    );

    // 3. The re-armed ask returns the responder's terminal page: the
    //    fence closes on it (never on the re-arm) and the stream ends.
    handle_treekem_catchup_response(
        &state,
        &responder_id,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![]),
    )
    .await;
    assert!(
        !self_leave_rekey_fence_any_open(&fence_ids),
        "the terminal page closed the last open peer fence; the rekey pass is no longer deferred by it"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "the terminal page asks for nothing"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_stops
            .lock()
            .expect("page-stop recorder")
            .len(),
        1,
        "no new stop: the resumed stream ended on its terminal page"
    );
    assert_eq!(
        rearm_requests(&state).len(),
        1,
        "the terminal page retires the stopped-loop accounting without another re-arm"
    );
    Ok(())
}

/// Review round 3 P1 control: the re-arm is paid for by APPLIED state.
/// A replay that applies nothing (both peers' fork events stay gapped
/// for ever) must not re-arm any stopped peer, so a quiet group whose
/// gap never clears stays idle — the #1685 hot loop cannot return
/// through the re-arm path.
#[tokio::test]
async fn a_replay_that_applies_nothing_does_not_rearm_any_stopped_peer() -> Result<()> {
    let group_id = "71".repeat(32);
    let responder = AgentKeypair::generate()?;
    let helper = AgentKeypair::generate()?;
    let helper_id = helper.agent_id();
    let helper_hex = hex::encode(helper_id.as_bytes());
    let (state, _dir) = fork_stranded_pair(&group_id, &responder).await?;
    // The second responder needs an Active seat for its page to pass the
    // member gate.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group");
        let inviter = hex::encode(state.agent.agent_id().as_bytes());
        info.add_member(
            helper_hex,
            x0x::groups::GroupRole::Member,
            Some(inviter),
            None,
        );
    }
    let head = cursor(&state, &group_id).await;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // The responder stops on its own fork event.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &clean_sender_machine(),
        true,
        truncated_page(
            &group_id,
            fork_removal_page_event(&group_id, &responder, head.0 + 1),
        ),
    )
    .await;
    // The helper's page carries the helper's own fork event: nothing
    // applies, the replay requeues both events, and the helper stops
    // too. No applied state means no re-arm for either peer.
    handle_treekem_catchup_response(
        &state,
        &helper_id,
        &clean_sender_machine(),
        true,
        truncated_page(
            &group_id,
            fork_removal_page_event(&group_id, &helper, head.0 + 1),
        ),
    )
    .await;

    assert_eq!(
        page_requests(&state),
        0,
        "a replay that applied nothing re-arms no stopped peer"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm was recorded"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_stops
            .lock()
            .expect("page-stop recorder")
            .len(),
        2,
        "both fork pages recorded their own typed stop"
    );
    assert_eq!(
        pending_len(&state, &group_id).await,
        2,
        "both fork events stay queued — the gap never cleared"
    );
    Ok(())
}
