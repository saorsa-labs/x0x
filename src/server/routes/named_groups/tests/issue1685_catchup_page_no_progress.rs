//! #1685: a truncated catch-up page whose events cannot apply yet must
//! not re-request the next page at once. The H-S3-c/c2 shape: a
//! fork-stranded node's head does not link to the responder's fork
//! commits, so every served event is retained as pending
//! (`state_hash_gap`), the catch-up cursor does not move, and the
//! responder filters and sorts its page on the requester's cursor —
//! the identical request re-fetches the identical truncated page. The
//! request/response pair then hot-loops between the two peers
//! (`#1685`: CPU spin, and a paused tokio runtime never parks so
//! virtual time cannot advance). The page loop must stop with the typed
//! reason `truncated_page_no_progress` instead: the pending queue keeps
//! its events (requeue still runs; no state is hidden), and catch-up
//! re-arms when a later incoming event queues (the 5 s-throttled gap
//! ask), an epoch-ahead signal asks again, or a replay MOVES the
//! catch-up cursor (revision, TreeKEM epoch, state hash) and re-arms
//! this peer at the moved cursor through a DETACHED task spawned after
//! the replay fence drops (round 5, review at 5319f206 — an inline
//! re-arm on the serial catch-up listener would let one unreachable
//! stopped peer stall every group's catch-up). There is no timer; a
//! quiet group whose gap never clears stays idle. A page whose events
//! were all already at or below the cursor (a duplicate from a second
//! peer, or a stale page) pages on: the next ask carries a newer
//! cursor and can still make progress.
//!
//! Round 8 (Engineer ruling, 31 Oct 2026): the re-arm pre-check
//! decides on the two halves of the shared revocation gate separately.
//! Only a revoked AGENT or a lost Active seat retires a stopped peer
//! (row dropped, fence closed without its terminal page); a machine or
//! binding revocation on a member that keeps its Active seat, or a
//! pending revocation resync, DEFERS it — row armed, nothing sent,
//! fence open — so a live member's self-leave fence can never close
//! over a known gap.
//!
//! Round 9 (Engineer ruling, 31 Oct 2026): a machine or binding hold
//! still SENDS the deferred ask. The ask goes to the agent on the
//! existing page request (bounded sends) and the stopped row STAYS
//! ARMED — an answer from the held machine dies at the page gate, so a
//! row cleared on that send would strand the peer for ever — and only
//! a valid page from a clean machine closes the row and the fence
//! (`revocation_hold_ask_sent`; the reason stays `revocation_hold`
//! when every send failed). Only the resync defer stays silent. A
//! non-truncated reply also no longer skips its own sender in the
//! detached re-arm pass: the handler asks nothing for it (a terminal
//! page clears the row, a key-package reply keeps it), so the replay
//! it triggers may re-arm that sender when it moves the cursor.

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

/// Round 5: the re-arm runs on a detached task spawned after the replay
/// fence drops, so its observations (the ask, the retirement) land
/// shortly AFTER `handle_treekem_catchup_response` returns. Poll the
/// condition with a bound; under the current-thread test runtime the
/// sleeps yield to the detached task.
async fn eventually<F: Fn() -> bool>(condition: F) -> bool {
    for _ in 0..1000 {
        if condition() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    condition()
}

/// Insert a verified self-revocation of `device` (the device's own key,
/// as the #1616 tests do). D70: this denies the machine only — the
/// agent's portable seat stays, which is exactly the case round 8 must
/// DEFER, not retire (Engineer ruling, 31 Oct 2026).
async fn revoke_machine(state: &AppState, device: &x0x::identity::MachineKeypair) {
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Machine(device.machine_id()),
        device.public_key(),
        device.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign machine revocation");
    let revocation_set = state.agent.revocation_set();
    let mut set = revocation_set.write().await;
    assert!(set
        .verify_and_insert(record, None)
        .expect("machine self-revocation verifies"));
    assert!(set.is_machine_revoked(&device.machine_id()));
    assert!(!set.revocation_resync_required());
}

/// Insert a verified self-revocation of the AGENT (its own key, as the
/// ADR 0107 tests do). Round 8 (Engineer ruling, 31 Oct 2026): this is
/// the DEPARTED half of the shared gate — the portable agent itself is
/// revoked, so no machine of it can ever serve the terminal page, and
/// the pre-check retires the peer.
async fn revoke_agent(state: &AppState, agent: &AgentKeypair) {
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(agent.agent_id()),
        agent.public_key(),
        agent.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign agent revocation");
    let revocation_set = state.agent.revocation_set();
    let mut set = revocation_set.write().await;
    assert!(set
        .verify_and_insert(record, None)
        .expect("agent self-revocation verifies"));
    assert!(set.is_agent_revoked(&agent.agent_id()));
    assert!(!set.revocation_resync_required());
}

/// Retire the `(agent, machine)` pairing with an owner-signed ADR-0043
/// tombstone, the only legal authority for a binding subject (the #1622
/// staging). D70: this kills the pairing only — the agent's portable
/// seat stays Active, so round 8 must DEFER the peer, never retire it.
async fn retire_binding(
    state: &AppState,
    owner: &x0x::identity::UserKeypair,
    agent: &AgentKeypair,
    machine: &x0x::identity::MachineId,
) {
    let cert =
        x0x::identity::AgentCertificate::issue(owner, agent).expect("owner certificate for agent");
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::AgentMachineBinding(
            x0x::revocation::AgentMachineBinding {
                agent: agent.agent_id(),
                machine: *machine,
                move_epoch: 1,
            },
        ),
        owner.public_key(),
        owner.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign binding revocation");
    let revocation_set = state.agent.revocation_set();
    let mut set = revocation_set.write().await;
    assert!(set
        .verify_and_insert(record, Some(&cert))
        .expect("binding revocation verifies"));
    assert!(set.is_binding_revoked(&agent.agent_id(), machine));
    assert!(!set.is_agent_revoked(&agent.agent_id()));
    assert!(!set.revocation_resync_required());
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
    // Round 5: the re-arm ask is sent by a DETACHED task after the replay
    // fence drops, so it lands shortly after the page handler returned.
    assert!(
        eventually(|| !rearm_requests(&state).is_empty()).await,
        "the cursor-moving replay re-armed the stopped responder"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "the cursor-moving replay re-armed exactly one ask: the stopped responder's next page"
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

/// Review round 4 (Engineer ruling, 30 Oct 2026): the re-arm pre-check.
/// A stopped peer that leaves the authenticated roster before the
/// dependency clears can never deliver the terminal page that closes
/// its fence — the page handler drops a non-member's pages at the
/// member gate — so a re-arm ask for it would leave a page fence open
/// with no exit (ADR 0088 L2). The removal itself arrives as a retained
/// event (the responder's roster-only self-leave R, chained after the
/// stuck E2), and the replay that clears the dependency applies E2 and
/// R in one pass. That pass must retire the departed responder — no
/// re-arm ask, stopped-loop row dropped, page fence closed, the typed
/// `peer_departed` reason — through the round 5 detached re-arm task.
/// The helper that delivered the chain is not asked either (round 5,
/// finding 4): its own TERMINAL page ended its stream and retired its
/// row at the page handler, so the re-arm skip leaves nothing to ask.
/// That is the retirement main gives a departed peer's catch-up rows
/// (retain against the authenticated roster) applied to the re-arm. At
/// baf2d7ae the replay re-arms the removed responder too, so its fence
/// stays open for ever.
#[tokio::test]
async fn a_departed_stopped_peer_is_retired_not_rearmed() -> Result<()> {
    let group_id = "72".repeat(32);
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
        "issue1685-departed".to_string(),
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
    // The responder the re-arm pre-check must retire, plus the helper
    // that delivers the chain — the contrast proving the pre-check
    // separates a departed peer from a current member.
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

    // The three-link chain, sealed on one clone (the round 3 shape, one
    // link further): E2 waits for E1's head, and R — the responder's
    // own roster-only self-leave — waits for E2's head.
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
        commit: Some(commit2),
    };
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision3 = leaving.roster_revision;
    leaving.remove_member(&responder_hex, Some(responder_hex.clone()));
    let commit3 = leaving.seal_commit(&responder, now_millis_u64())?;
    let removal = NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.clone(),
        revision: revision3,
        actor: responder_hex.clone(),
        agent_id: responder_hex.clone(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit3.clone()),
    };
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder's truncated page serves E2 before its
    //    predecessor: E2 queues as a revision gap, nothing applies, the
    //    cursor does not move — the typed stop. The responder's page
    //    fence stays open and its stopped-loop row is armed.
    handle_treekem_catchup_response(
        &state,
        &responder_id,
        &clean_sender_machine(),
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        page_requests(&state),
        0,
        "the stopped loop asks for no next page at the unmoved cursor"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "CONTROL: the stopped peer's page fence is open before the removal"
    );
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the stopped peer's row is armed before the removal"
    );

    // 2. The removal reaches this node before the dependency clears: the
    //    helper's truncated page serves R, which also gaps on E2's
    //    missing head. R is retained, the helper's loop stops too, and
    //    the responder is still on the roster — only the events are
    //    queued, nothing has applied yet.
    handle_treekem_catchup_response(
        &state,
        &helper_id,
        &clean_sender_machine(),
        true,
        truncated_page(&group_id, removal),
    )
    .await;
    let mut stopped_before = vec![helper_hex.clone(), responder_hex.clone()];
    stopped_before.sort();
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        stopped_before,
        "both responders stopped while their gaps are outstanding"
    );
    assert_eq!(
        pending_len(&state, &group_id).await,
        2,
        "E2 and the responder's removal R stay queued behind E1"
    );

    // 3. The dependency clears: the helper's TERMINAL page delivers E1,
    //    and the page handler's replay applies the retained E2 and then
    //    R in one pass — the re-arm pass really runs, and the roster it
    //    consults no longer has the responder. The departed responder
    //    must NOT be re-armed; its row and fence are retired with the
    //    typed reason instead. The helper is not re-armed either: it is
    //    the page sender, so the coordinator skips it (round 5, finding
    //    4) — nobody is asked.
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
        head.0, revision3,
        "CONTROL: the replay applied E2 and R, so the re-arm pass ran against a roster without the responder"
    );
    assert_eq!(
        head.2, commit3.state_hash,
        "the chain reached the head R sealed — the responder's removal really applied"
    );
    assert_eq!(
        pending_len(&state, &group_id).await,
        0,
        "the queue drained through the applied replay"
    );
    // Round 5: the retirement runs on the detached re-arm task, so it
    // lands shortly after the page handler returned. The helper — the
    // sender whose TERMINAL page triggered the replay — is skipped by
    // the re-arm (round 5, finding 4): its own terminal page already
    // closed its fence and retired its stopped row, so nobody is asked
    // and the only detached work is the responder's retirement.
    assert!(
        eventually(|| {
            !state
                .named_group_test_recorders
                .catchup_page_departed
                .lock()
                .expect("departed recorder")
                .is_empty()
        })
        .await,
        "the detached re-arm task retired the departed responder"
    );
    assert_eq!(
        page_requests(&state),
        0,
        "#1685 round 4 + 5: nobody is re-armed — the removed responder is retired, and \
         the helper's own terminal page already ended its stream (at 5319f206 the \
         inline re-arm asked the helper too, on top of its terminal page)"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm: the sender's terminal page retired its own row, and the \
         departed responder is retired, not re-armed"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_departed
            .lock()
            .expect("departed recorder")
            .clone(),
        vec![(group_id.clone(), responder_hex.clone(), "peer_departed")],
        "the retirement is typed and names the departed peer"
    );
    assert!(
        !self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "#1685 round 4: the departed peer's page fence is closed, never left open"
    );
    assert!(
        !self_leave_rekey_fence_any_open(&fence_ids),
        "no page fence of the group stays open: the helper's terminal page closed its own, the responder's was retired"
    );
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "no stopped-loop row is left: the helper's terminal page cleared its own, the responder's retirement cleared the other"
    );
    Ok(())
}

/// The round 3 chain shape as one reusable setup for the round 5 tests:
/// a live TreeKEM admin head with two leavers whose self-leaves chain
/// (E2 waits for E1's head), a roster-only responder whose truncated
/// page serves E2 out of order, and a roster-only helper that can
/// deliver E1. `responder_device` names the machine the responder's
/// pages come from (a real device keypair when a test revokes it).
struct Issue1685ChainPair {
    state: Arc<AppState>,
    responder: AgentKeypair,
    responder_hex: String,
    responder_machine: MachineId,
    responder_device: Option<x0x::identity::MachineKeypair>,
    helper: AgentId,
    event1: NamedGroupMetadataEvent,
    event2: NamedGroupMetadataEvent,
    fence_ids: [String; 3],
}

async fn issue1685_chain_pair(
    group_id: &str,
    responder_device: Option<x0x::identity::MachineKeypair>,
) -> Result<Issue1685ChainPair> {
    let (mut state, _dir) = secure_endpoint_test_state().await?;
    super::super::revocation_eviction::zero_restart_wait_for_test(&mut state);
    let admin_id = state.agent.agent_id();
    let admin_hex = hex::encode(admin_id.as_bytes());
    let group_id_bytes = hex::decode(group_id)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
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

    let responder = AgentKeypair::generate()?;
    let responder_hex = hex::encode(responder.agent_id().as_bytes());
    let responder_machine = responder_device
        .as_ref()
        .map_or_else(clean_sender_machine, |device| device.machine_id());
    let helper = AgentKeypair::generate()?;

    let mut info = x0x::groups::GroupInfo::new(
        "issue1685-round5".to_string(),
        String::new(),
        admin_id,
        group_id.to_string(),
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
    for peer_kp in [&responder, &helper] {
        info.add_member(
            hex::encode(peer_kp.agent_id().as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(admin_hex.clone()),
            None,
        );
    }
    info.secret_epoch = epoch_before;
    info.security_binding = Some(format!("treekem:epoch={epoch_before}"));
    info.recompute_state_hash();
    let fence_ids = [
        group_id.to_string(),
        info.mls_group_id.clone(),
        info.stable_group_id().to_string(),
    ];
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
    state.treekem_groups.write().await.insert(
        group_id.to_string(),
        Arc::new(tokio::sync::Mutex::new(admin_group)),
    );

    let mut leaving = {
        let groups = state.named_groups.read().await;
        groups.get(group_id).cloned().expect("group")
    };
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision1 = leaving.roster_revision;
    leaving.remove_member(v1_hex, Some(v1_hex.clone()));
    let commit1 = leaving.seal_commit(v1_kp, now_millis_u64())?;
    let event1 = NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.to_string(),
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
        group_id: group_id.to_string(),
        revision: revision2,
        actor: v2_hex.clone(),
        agent_id: v2_hex.clone(),
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit2.clone()),
    };
    Ok(Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        responder_device,
        helper: helper.agent_id(),
        event1,
        event2,
        fence_ids,
    })
}

/// Review round 5, finding 1 (Claude REQUEST-CHANGES at 5319f206; the
/// Engineer ruling, 30 Oct 2026): the re-arm sends run DETACHED, never
/// inline on the serial catch-up listener. The responder stops on the
/// gapped E2; the helper's terminal page then delivers E1, the replay
/// applies E2, the cursor moves — and the re-arm ask for the responder
/// PARKS, the shape of an unreachable peer whose send cannot leave. The
/// page handler must still return and the replay fence must be free: at
/// 5319f206 the inline re-arm parked INSIDE the handler, so one
/// unreachable stopped peer stalled the one serial catch-up listener
/// (every group's pages wait behind it) and held the replay fence for
/// the whole send budget.
#[tokio::test]
async fn an_unreachable_stopped_peer_does_not_block_the_listener_or_hold_the_fence() -> Result<()> {
    let group_id = "08".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder's truncated page serves E2 before its
    //    predecessor: nothing applies, the cursor does not move — the
    //    typed stop, row armed.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(page_requests(&state), 0, "the stopped loop asks nobody");
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );

    // 2. The re-arm ask parks — the responder is unreachable in the
    //    send sense: the request cannot leave this node.
    let parked = detached_send_test_seam::arm(&format!("treekem-catchup-page:{group_id}"));
    let handler_state = Arc::clone(&state);
    let page_group = group_id.clone();
    let handled = tokio::time::timeout(std::time::Duration::from_secs(2), async move {
        handle_treekem_catchup_response(
            &handler_state,
            &helper,
            &clean_sender_machine(),
            true,
            terminal_page(&page_group, vec![event1]),
        )
        .await;
    })
    .await;
    assert!(
        handled.is_ok(),
        "#1685 round 5: the page handler returned while the stopped peer's re-arm send is \
         parked — one unreachable stopped peer must not stall the serial catch-up listener \
         (at 5319f206 the inline re-arm parked inside the handler)"
    );
    assert!(
        !self_leave_rekey_fence_replay_open(&group_id),
        "the replay fence dropped before any re-arm send started; the parked send cannot hold it"
    );
    assert!(
        eventually(|| parked.reached()).await,
        "the detached re-arm really asked the stopped peer — that ask is the parked send"
    );
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "the parked ask has not left, so the row stays armed (clear-on-success)"
    );
    drop(parked);
    assert!(
        eventually(|| !rearm_requests(&state).is_empty()).await,
        "the released re-arm completed off the listener"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "exactly one ask went out: the released re-arm"
    );
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "the successful re-arm cleared the row"
    );
    Ok(())
}

/// Review round 5, finding 2: the stopped row is cleared only once a
/// request WENT OUT. The responder stops on its own fork event; its own
/// next page then delivers a linked self-leave that applies and moves
/// the cursor, and the handler's own next-page ask parks (the request
/// cannot leave). The row must survive the parked ask — at 5319f206 the
/// row was cleared BEFORE the send, so a peer whose send never left was
/// never re-asked by a later replay.
#[tokio::test]
async fn a_next_page_ask_that_cannot_leave_keeps_the_stopped_row_armed() -> Result<()> {
    let group_id = "10".repeat(32);
    let (mut state, _dir) = secure_endpoint_test_state().await?;
    super::super::revocation_eviction::zero_restart_wait_for_test(&mut state);
    let admin_id = state.agent.agent_id();
    let group_id_bytes = hex::decode(&group_id)?;
    let seed = super::super::agent_treekem_seed(state.agent.as_ref(), &group_id_bytes);
    let mut admin_group = x0x::mls::TreeKemMlsGroup::create(group_id_bytes, admin_id, &seed)?;
    let member_kp = AgentKeypair::generate()?;
    let member_id = member_kp.agent_id();
    let member_hex = hex::encode(member_id.as_bytes());
    let prepared = x0x::mls::TreeKemMlsGroup::prepare_member(member_id, &[31u8; 32])?;
    let kp_bytes = prepared.key_package_bytes().to_vec();
    let added = admin_group.add_member(member_id, &kp_bytes)?;
    let _leaver_group = x0x::mls::TreeKemMlsGroup::join_from_welcome(prepared, &added.welcome)?;
    let epoch_before = admin_group.epoch();

    let responder = AgentKeypair::generate()?;
    let responder_id = responder.agent_id();
    let responder_hex = hex::encode(responder_id.as_bytes());
    let mut info = x0x::groups::GroupInfo::new(
        "issue1685-row-armed".to_string(),
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
    info.add_member(
        responder_hex.clone(),
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
    let fence_ids = [
        group_id.clone(),
        info.mls_group_id.clone(),
        info.stable_group_id().to_string(),
    ];
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    state.treekem_groups.write().await.insert(
        group_id.clone(),
        Arc::new(tokio::sync::Mutex::new(admin_group)),
    );

    // The member's linked self-leave, sealed on the current head (the
    // #1113 shape that applies at once).
    let mut leaving = {
        let groups = state.named_groups.read().await;
        groups.get(&group_id).cloned().expect("group")
    };
    leaving.roster_revision = leaving.roster_revision.saturating_add(1);
    let revision = leaving.roster_revision;
    leaving.remove_member(&member_hex, Some(member_hex.clone()));
    let commit = leaving.seal_commit(&member_kp, now_millis_u64())?;
    let leave = NamedGroupMetadataEvent::MemberRemoved {
        group_id: group_id.clone(),
        revision,
        actor: member_hex.clone(),
        agent_id: member_hex,
        treekem_commit_b64: None,
        treekem_epoch: None,
        secret_epoch: None,
        commit: Some(commit),
    };
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on its own fork event (row armed).
    let head = cursor(&state, &group_id).await;
    handle_treekem_catchup_response(
        &state,
        &responder_id,
        &clean_sender_machine(),
        true,
        truncated_page(
            &group_id,
            fork_removal_page_event(&group_id, &responder, head.0 + 1),
        ),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );

    // 2. The responder's own page delivers the linked self-leave: it
    //    applies and moves the cursor, and the handler's own next-page
    //    ask parks. The row must still be armed while the ask has not
    //    left.
    let parked = detached_send_test_seam::arm(&format!("treekem-catchup-page:{group_id}"));
    let handler_state = Arc::clone(&state);
    let handler_sender = responder_id;
    let handler_group = group_id.clone();
    let handler = tokio::spawn(async move {
        handle_treekem_catchup_response(
            &handler_state,
            &handler_sender,
            &clean_sender_machine(),
            true,
            truncated_page(&handler_group, leave),
        )
        .await;
    });
    assert!(
        eventually(|| parked.reached()).await,
        "the handler's own next-page ask is the parked send"
    );
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "#1685 round 5, finding 2: the row stays armed while the ask has not left (at \
         5319f206 it was cleared before the send)"
    );
    drop(parked);
    handler.await.expect("page handler task");
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "the ask that went out cleared the row"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "exactly one ask — the handler's own; the replay re-arm skipped the sender"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no re-arm ask: the sender is skipped (finding 4) and no other peer is stopped"
    );
    Ok(())
}

/// #1685 round 8 (Engineer ruling, 31 Oct 2026; Claude review at
/// e756545d, blocker 2, reversing round 5 finding 3), in its round 9
/// shape (Engineer ruling, 31 Oct 2026): a machine revocation
/// (ADR 0110 D70) denies the DEVICE only — the agent's portable seat
/// stays Active, and the agent can serve the terminal page from
/// another machine. The re-arm pre-check DEFERS the stopped peer —
/// never retires it — and round 9 sends the deferred ask to the agent
/// anyway (the existing page request, bounded sends) while the row
/// STAYS ARMED: an answer from the held machine dies at the page gate,
/// so a row cleared on that send would strand the peer; the fence
/// closes only on the agent's own valid answer from a clean machine.
/// An indefinite silent defer (the round 8 shape) kept a live member's
/// fence open and blocked the group's rekeys until a restart.
#[tokio::test]
async fn a_machine_revoked_stopped_peer_with_an_active_seat_is_deferred_with_the_ask_sent_not_retired(
) -> Result<()> {
    let group_id = "12".repeat(32);
    let device = x0x::identity::MachineKeypair::generate()?;
    let pair = issue1685_chain_pair(&group_id, Some(device)).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        responder_device,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2, paged from its own device; its row
    //    arms and its page fence opens.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "CONTROL: the responder's page fence is open"
    );

    // 2. D70: revoke the device only. The agent's seat stays Active —
    //    the roster alone cannot retire this peer.
    revoke_machine(&state, responder_device.as_ref().expect("device")).await;

    // 3. The helper's terminal page delivers E1; the replay applies E2
    //    and the cursor moves. The detached re-arm runs the pre-check
    //    against the recorded machine, DEFERS the responder — and round
    //    9 sends the deferred ask anyway.
    handle_treekem_catchup_response(
        &state,
        &helper,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    assert!(
        eventually(|| {
            !state
                .named_group_test_recorders
                .catchup_page_deferred
                .lock()
                .expect("deferred recorder")
                .is_empty()
        })
        .await,
        "the detached re-arm deferred the machine-revoked responder"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "#1685 round 9: the deferred ask went to the agent — the agent keeps its \
         Active seat, so it may answer from a clean machine (round 8 sent nothing)"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm was recorded: a hold defers, it is not a replay re-arm"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_departed
            .lock()
            .expect("departed recorder")
            .is_empty(),
        "the still-Active responder is NOT retired"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_deferred
            .lock()
            .expect("deferred recorder")
            .clone(),
        vec![(
            group_id.clone(),
            responder_hex.clone(),
            "revocation_hold_ask_sent"
        )],
        "the defer is typed and names the held peer, with the ask-sent reason"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "#1685 round 9: the held member's page fence stays OPEN — the ask is not an \
         answer; only the agent's valid page from a clean machine closes it"
    );
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "the stopped row stays armed, so the next cursor-moving replay retries"
    );
    Ok(())
}

/// #1685 round 8 (Engineer ruling, 31 Oct 2026), in its round 9 shape
/// (Engineer ruling, 31 Oct 2026): a binding revocation (#1622,
/// ADR 0110 D70) retires the `(agent, machine)` PAIRING only — the
/// agent's portable seat stays Active and the device stays clean, so
/// the agent can serve the terminal page from another machine. The
/// pre-check DEFERS the stopped peer, exactly as for a machine
/// revocation, and round 9 sends the deferred ask anyway with the row
/// left armed; the fence closes only on the agent's valid answer from
/// a machine the pairing still covers.
#[tokio::test]
async fn a_binding_revoked_stopped_peer_with_an_active_seat_is_deferred_with_its_ask_sent_not_retired(
) -> Result<()> {
    let group_id = "17".repeat(32);
    let device = x0x::identity::MachineKeypair::generate()?;
    let pair = issue1685_chain_pair(&group_id, Some(device)).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2, paged from the pairing's device.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );

    // 2. #1622: retire the pairing only, owner-signed. The agent's
    //    seat stays Active and the device stays clean.
    let owner = x0x::identity::UserKeypair::generate()?;
    retire_binding(&state, &owner, &responder, &responder_machine).await;

    // 3. The helper's terminal page delivers E1; the replay applies E2
    //    and the cursor moves. The pre-check DEFERS the responder — and
    //    round 9 sends the deferred ask anyway.
    handle_treekem_catchup_response(
        &state,
        &helper,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    assert!(
        eventually(|| {
            !state
                .named_group_test_recorders
                .catchup_page_deferred
                .lock()
                .expect("deferred recorder")
                .is_empty()
        })
        .await,
        "the detached re-arm deferred the binding-revoked responder"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "#1685 round 9: the deferred ask went to the agent — the pairing holds the \
         one device only, and the agent may answer from another (round 8 sent \
         nothing)"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_departed
            .lock()
            .expect("departed recorder")
            .is_empty(),
        "the still-Active responder is NOT retired"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm was recorded: a hold defers, it is not a replay re-arm"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_deferred
            .lock()
            .expect("deferred recorder")
            .clone(),
        vec![(
            group_id.clone(),
            responder_hex.clone(),
            "revocation_hold_ask_sent"
        )],
        "the defer is typed and names the held peer, with the ask-sent reason"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "the held member's page fence stays OPEN — it closes on the agent's own \
         terminal page from a clean machine, never on the pairing's retirement"
    );
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "the stopped row stays armed"
    );
    Ok(())
}

/// #1685 round 8 (Engineer ruling, 31 Oct 2026; Claude review at
/// e756545d, blocker 1): a pending revocation resync (#1116) is a
/// global, temporary hold, not a departure. If the re-arm pass runs
/// while the resync pends, every stopped peer of the group must be
/// DEFERRED — row armed, nothing sent, fence OPEN. Round 9 keeps this
/// the one SILENT defer: the resync holds the apply gate itself, so an
/// answer could not apply anyway, while a machine or binding hold now
/// sends its ask. At e756545d the
/// pre-check retired every stopped peer on the resync bit and closed
/// their fences for good, so `rekey_treekem_self_leaves` could seal a
/// self-leave rekey over a known gap. The cursor-moving replay that
/// spawns the pass cannot itself be staged under a resync — the apply
/// gate withholds every group metadata event while it pends
/// (`apply_metadata_event_withhold`, named_groups.rs), exactly why the
/// reviewer called the trigger plausible rather than proven — so the
/// test enters through the pass's own production entry
/// (`spawn_stopped_treekem_catchup_rearms`, what a cursor-moving replay
/// calls): the ruling is defense in depth for any cursor movement that
/// slips past the hold (a local mutation, then a replay).
#[tokio::test]
async fn a_resync_pending_stopped_peer_with_an_active_seat_is_deferred_not_retired() -> Result<()> {
    let group_id = "18".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2; its row arms and its fence opens.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );

    // 2. #1116: a quarantined carrier closes admission — the global,
    //    temporary hold (the #1577 staging).
    *state.agent.revocation_set().write().await =
        x0x::revocation::RevocationSet::quarantined_carrier(x0x::revocation::REVOCATION_CARRIER_V3);
    assert!(
        state
            .agent
            .revocation_set()
            .read()
            .await
            .revocation_resync_required(),
        "CONTROL: the resync hold is pending"
    );

    // 3. The re-arm pass runs against the resync-holding set. The
    //    responder keeps its Active seat, so it is DEFERRED.
    spawn_stopped_treekem_catchup_rearms(&state, &group_id, None);
    assert!(
        eventually(|| {
            !state
                .named_group_test_recorders
                .catchup_page_deferred
                .lock()
                .expect("deferred recorder")
                .is_empty()
        })
        .await,
        "the re-arm pass deferred the resync-held responder"
    );
    assert_eq!(
        page_requests(&state),
        0,
        "nothing is sent while the resync pends"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_deferred
            .lock()
            .expect("deferred recorder")
            .clone(),
        vec![(group_id.clone(), responder_hex.clone(), "revocation_hold")],
        "round 9: the resync defer stays SILENT — the reason keeps it distinguishable \
         from the machine/binding hold, which now records \
         \"revocation_hold_ask_sent\" for its sent ask"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_departed
            .lock()
            .expect("departed recorder")
            .is_empty(),
        "the resync-holding responder is NOT retired (at e756545d the resync bit \
         retired every stopped peer of the group)"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm was recorded"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "#1685 round 8: the held member's page fence stays OPEN — a resync is a \
         temporary hold, never a fence exit"
    );
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "the stopped row stays armed for the replay after the resync clears"
    );
    Ok(())
}

/// #1685 round 8, the retire half of the ruling: an AGENT revocation
/// retires the portable agent itself — no machine of it can ever serve
/// the terminal page. The pre-check retires the stopped peer (row
/// dropped, fence closed, typed `peer_departed`), exactly as round 4
/// ruled for a seatless peer (the round 4 test pins the roster side;
/// this pins the revoked-agent side). This side is green before round
/// 8 too: the narrowing must not lose the retirement.
#[tokio::test]
async fn an_agent_revoked_stopped_peer_is_retired_and_its_fence_closes() -> Result<()> {
    let group_id = "19".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2; its row arms and its fence opens.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "CONTROL: the responder's page fence is open"
    );

    // 2. Revoke the AGENT — the departed half of the shared gate. The
    //    roster is untouched; the gate alone retires the peer.
    revoke_agent(&state, &responder).await;

    // 3. The helper's terminal page delivers E1; the replay applies E2
    //    and the cursor moves. The pre-check RETIRES the responder.
    handle_treekem_catchup_response(
        &state,
        &helper,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    assert!(
        eventually(|| {
            !state
                .named_group_test_recorders
                .catchup_page_departed
                .lock()
                .expect("departed recorder")
                .is_empty()
        })
        .await,
        "the detached re-arm retired the agent-revoked responder"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_departed
            .lock()
            .expect("departed recorder")
            .clone(),
        vec![(group_id.clone(), responder_hex.clone(), "peer_departed")],
        "the retirement is typed and names the revoked peer"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_deferred
            .lock()
            .expect("deferred recorder")
            .is_empty(),
        "an agent revocation is a departure, not a hold"
    );
    assert_eq!(
        page_requests(&state),
        0,
        "the revoked responder is retired, not asked"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm was recorded"
    );
    assert!(
        !self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "the revoked peer's page fence is closed, never left open"
    );
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "the retirement dropped the stopped row"
    );
    Ok(())
}

/// #1685 round 7 (Claude review at 40455742, finding 1; Engineer
/// ruling, 30 Oct 2026): the departed retire closes the stopped peer's
/// page fence — here the group's LAST open one. Every rekey check that
/// ran before the retire saw that fence open (the replay's own pass is
/// batch-held inside the page handler; the terminal page's pass sees
/// this fence), so without a re-check AT the retire the responsive
/// rekey for the two applied self-leaves waits for the next trigger.
/// The retire must re-check, as the terminal page does after it closes
/// a peer fence. The fresh-attempt counter is the observation: the
/// rekey pass reached a fresh commit attempt at the retire. Whether
/// that attempt then seals at once or defers to its own rules (a
/// self-leaver's seal waits for the S4 row the periodic pass opens,
/// ADR 0110 §2) is the pass's decision at EVERY trigger — not this
/// fix's.
#[tokio::test]
async fn a_departed_retire_rechecks_the_self_leave_rekey_its_fence_close_released() -> Result<()> {
    let group_id = "16".repeat(32);
    let device = x0x::identity::MachineKeypair::generate()?;
    let pair = issue1685_chain_pair(&group_id, Some(device)).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);
    // The fresh-attempt counter is process-wide; drain it so the
    // CONTROL below cannot see another test's pass (Claude review at
    // e756545d, finding 6 — fine under nextest's process-per-test, flaky
    // under plain `cargo test`).
    let _ = take_fresh_self_leave_rekey_attempts();
    let epoch_before = cursor(&state, &group_id).await.1;

    // 1. The responder stops on E2, paged from its own device; its page
    //    fence opens.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "CONTROL: the stopped responder's page fence is open"
    );

    // 2. Revoke the responder's AGENT (round 8: the departed half of
    //    the shared gate — the roster is untouched, so the gate, not
    //    the roster, is what retires the responder). A machine
    //    revocation would now defer, not retire (round 8).
    revoke_agent(&state, &responder).await;

    // 3. The helper's terminal page delivers E1; the replay applies E2.
    //    Both leavers are Removed with tree leaves outstanding, so a
    //    responsive rekey is due — but no earlier trigger can run it:
    //    the applies sit inside the replay batch, the replay's own pass
    //    is batch-held, and the terminal page's pass sees the
    //    responder's fence still open.
    handle_treekem_catchup_response(
        &state,
        &helper,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    assert_eq!(
        pending_len(&state, &group_id).await,
        0,
        "the replay drained the queue"
    );
    assert_eq!(
        cursor(&state, &group_id).await.1,
        epoch_before,
        "CONTROL: no rekey committed yet — the responder's open fence defers every pass"
    );
    assert_eq!(
        take_fresh_self_leave_rekey_attempts(),
        0,
        "CONTROL: no rekey pass has reached a fresh commit attempt yet"
    );

    // 4. The detached retire closes the last fence and must re-check:
    //    the responsive rekey pass runs at the retire, not at the next
    //    trigger.
    assert!(
        eventually(|| {
            !state
                .named_group_test_recorders
                .catchup_page_departed
                .lock()
                .expect("departed recorder")
                .is_empty()
        })
        .await,
        "the detached re-arm retired the agent-revoked responder"
    );
    assert!(
        take_fresh_self_leave_rekey_attempts() > 0,
        "#1685 round 7: the retire's re-check ran the responsive rekey pass its fence close released"
    );
    assert!(
        !self_leave_rekey_fence_any_open(&fence_ids),
        "the retire closed the group's last open fence"
    );
    Ok(())
}

/// Review round 5, finding 4: no duplicate ask to the sender. The
/// responder stops on the gapped E2; its own next truncated page then
/// delivers E1, which applies, and the page handler's replay applies
/// E2 — the cursor moves twice. The re-arm that replay spawns must SKIP
/// the sender: the handler's own moved-cursor branch asks it, and one
/// peer must never hold two parallel page streams. At 5319f206 the
/// inline re-arm asked the responder first and the handler's branch
/// asked again — two asks, two page streams.
#[tokio::test]
async fn the_rearm_does_not_duplicate_the_page_senders_own_next_page_ask() -> Result<()> {
    let group_id = "14".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_machine,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2 (row armed).
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(page_requests(&state), 0, "the stopped loop asks nobody");

    // 2. The responder's own page delivers E1: it applies, the replay
    //    applies E2, the cursor moves. One ask total.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event1),
    )
    .await;
    assert_eq!(
        page_requests(&state),
        1,
        "#1685 round 5, finding 4: exactly one ask — the handler's own; at 5319f206 \
         the inline re-arm asked the sender too, and the handler asked again"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "the sender is never re-armed by its own page's replay"
    );
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "the ask that went out cleared the row"
    );
    // Settle: no late re-arm lands after the synchronous asserts.
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert_eq!(
        page_requests(&state),
        1,
        "no delayed second ask arrived either"
    );
    assert!(rearm_requests(&state).is_empty());
    Ok(())
}

/// Review round 5, finding 5: the re-arm trigger is CURSOR MOVEMENT, not
/// an accepted count. A `GroupCardPublished` from the local admin is
/// accepted by the replay (its apply touches only the card cache — no
/// signed commit, so the catch-up cursor cannot move). At 5319f206 the
/// accepted count alone fired the re-arm, which fetched the identical
/// page and stopped the peer again; after round 5 a replay that moved
/// no cursor re-arms nobody.
#[tokio::test]
async fn an_accepted_replay_that_moves_no_cursor_does_not_rearm() -> Result<()> {
    let group_id = "15".repeat(32);
    let responder = AgentKeypair::generate()?;
    let (state, _dir) = fork_stranded_pair(&group_id, &responder).await?;
    let fence_ids = {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group");
        [
            group_id.clone(),
            info.mls_group_id.clone(),
            info.stable_group_id().to_string(),
        ]
    };
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on its fork event (row armed).
    let head = cursor(&state, &group_id).await;
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
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![hex::encode(responder.agent_id().as_bytes())],
        "CONTROL: the responder's stopped row is armed"
    );

    // 2. Queue an ACCEPTED-but-cursor-neutral event: a signed group
    //    card from the local admin, whose apply only admits the card to
    //    the directory cache.
    {
        let mut groups = state.named_groups.write().await;
        groups
            .get_mut(&group_id)
            .expect("group")
            .policy
            .discoverability = x0x::groups::GroupDiscoverability::PublicDirectory;
    }
    let (stable, card) = {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group").clone();
        let keypair = state.agent.identity().agent_keypair();
        let mut card = info.to_group_card().expect("card");
        card.sign(keypair).expect("sign card");
        (info.stable_group_id().to_string(), card)
    };
    state.treekem_pending_events.write().await.insert(
        group_id.clone(),
        std::collections::VecDeque::from([PendingTreeKemMetadataEvent {
            event: NamedGroupMetadataEvent::GroupCardPublished {
                group_id: group_id.clone(),
                card,
            },
            sender: state.agent.agent_id(),
            queued_at: std::time::Instant::now(),
        }]),
    );
    let before = cursor(&state, &group_id).await;
    replay_pending_treekem_events(&state, &group_id, None).await;

    // 3. The card applied (accepted), the cursor did not move, so no
    //    re-arm may fire: the ask would carry the SAME cursor and
    //    re-fetch the identical page.
    assert!(
        state.group_card_cache.read().await.contains_key(&stable),
        "CONTROL: the queued card really applied (the replay accepted it)"
    );
    assert_eq!(
        cursor(&state, &group_id).await,
        before,
        "CONTROL: the accepted card moved the cursor nothing"
    );
    assert_eq!(
        page_requests(&state),
        0,
        "#1685 round 5, finding 5: an accepted replay that moved no cursor re-arms \
         nobody (at 5319f206 the accepted count alone fired the re-arm)"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm was recorded"
    );
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![hex::encode(responder.agent_id().as_bytes())],
        "the row stays armed: only a moved cursor can falsify the stop's premise"
    );
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert_eq!(page_requests(&state), 0, "no delayed re-arm arrived either");
    Ok(())
}

/// #1685 round 9 (Engineer ruling, 31 Oct 2026), the whole arc of the
/// ruling: a stopped peer a machine revocation holds is ASKED anyway,
/// and the agent's answer from a CLEAN machine — never the held
/// device — closes its row and its page fence. The responder stops on
/// the gapped E2 paged from its own device; the device is then revoked
/// (D70: the agent's Active seat stays). The cursor-moving replay's
/// detached re-arm sends the deferred ask and KEEPS the row armed, so
/// the ask cannot strand the peer; the agent then serves its terminal
/// page from a clean machine and the normal terminal path ends the
/// stream. Before round 9 the defer sent nothing, so a quiet group's
/// fence stayed open until a restart.
#[tokio::test]
async fn a_machine_held_stopped_peer_is_asked_anyway_and_its_clean_answer_closes_row_and_fence(
) -> Result<()> {
    let group_id = "1a".repeat(32);
    let device = x0x::identity::MachineKeypair::generate()?;
    let pair = issue1685_chain_pair(&group_id, Some(device)).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        responder_device,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2, paged from its own device: its row
    //    arms and its page fence opens.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "CONTROL: the responder's page fence is open"
    );

    // 2. D70: revoke the device only. The agent's seat stays Active, so
    //    the peer is held, not departed.
    revoke_machine(&state, responder_device.as_ref().expect("device")).await;

    // 3. The helper's terminal page delivers E1; the replay applies E2
    //    and the cursor moves. The detached re-arm holds the responder
    //    on the machine half — so round 9 SENDS the deferred ask to the
    //    agent and keeps the row armed.
    handle_treekem_catchup_response(
        &state,
        &helper,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    assert!(
        eventually(|| {
            !state
                .named_group_test_recorders
                .catchup_page_deferred
                .lock()
                .expect("deferred recorder")
                .is_empty()
        })
        .await,
        "the detached re-arm deferred the machine-held responder with its ask sent"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_deferred
            .lock()
            .expect("deferred recorder")
            .clone(),
        vec![(
            group_id.clone(),
            responder_hex.clone(),
            "revocation_hold_ask_sent"
        )],
        "the defer is typed with the ask-sent reason: a send left for the agent"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "#1685 round 9: the deferred ask went out — the agent keeps its Active \
         seat and may answer from a clean machine (round 8 sent nothing)"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_departed
            .lock()
            .expect("departed recorder")
            .is_empty(),
        "the held responder is NOT retired"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm: a hold defers, it is not a replay re-arm"
    );
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "#1685 round 9: the row STAYS ARMED after the ask — an answer from the \
         held machine dies at the page gate, so a row cleared on this send would \
         strand the peer for ever"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "#1685 round 9: the ask is not an answer — the fence stays open until a \
         valid page closes it"
    );

    // 4. The agent answers from a CLEAN machine. The page gate passes
    //    (the clean machine is not the revoked device), so the terminal
    //    page closes the row and the fence through the normal path.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![]),
    )
    .await;
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "the clean machine's terminal page cleared the armed row"
    );
    assert!(
        !self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "the clean machine's terminal page closed the peer fence"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "the terminal page asks for nothing: the stream ended on it"
    );
    Ok(())
}

/// #1685 round 9 pin (green before and after): the held machine cannot
/// answer its own deferred ask. A page from a machine the revocation
/// set holds dies at the page gate — before any fence, stopped-row or
/// recorder work — so the refused answer changes nothing: the row
/// stays armed for the next cursor-moving replay, the fence stays
/// open, no new ask fires and nothing new is recorded. The ask went to
/// the AGENT; only its clean machine may answer (the arc test above).
#[tokio::test]
async fn a_page_from_the_held_machine_itself_dies_at_the_page_gate() -> Result<()> {
    let group_id = "1b".repeat(32);
    let device = x0x::identity::MachineKeypair::generate()?;
    let pair = issue1685_chain_pair(&group_id, Some(device)).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        responder_device,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2, paged from its own device.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );

    // 2. D70: revoke the device only; the agent's seat stays Active.
    revoke_machine(&state, responder_device.as_ref().expect("device")).await;

    // 3. The helper's terminal page delivers E1; the replay applies E2,
    //    the cursor moves and the detached re-arm sends the deferred
    //    ask (row armed, fence open — the arc test's first half).
    handle_treekem_catchup_response(
        &state,
        &helper,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    assert!(
        eventually(|| {
            !state
                .named_group_test_recorders
                .catchup_page_deferred
                .lock()
                .expect("deferred recorder")
                .is_empty()
        })
        .await,
        "the detached re-arm deferred the machine-held responder with its ask sent"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "CONTROL: the deferred ask went out"
    );

    // 4. The HELD machine answers anyway. The page gate refuses it
    //    before any fence or row work, so nothing reacts.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        terminal_page(&group_id, vec![]),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "the gate-refused page left the armed row exactly as it was"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "the gate-refused page left the fence exactly as it was"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "#1685 round 9 pin: a page from the held machine dies at the page gate — \
         no new ask, no fence work, no reaction at all"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm was recorded"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_departed
            .lock()
            .expect("departed recorder")
            .is_empty(),
        "no retirement: the refused page is not a departure"
    );
    assert_eq!(
        state
            .named_group_test_recorders
            .catchup_page_deferred
            .lock()
            .expect("deferred recorder")
            .clone(),
        vec![(
            group_id.clone(),
            responder_hex.clone(),
            "revocation_hold_ask_sent"
        )],
        "exactly one defer record: the gate recorded nothing for the refused page"
    );
    Ok(())
}

/// #1685 round 9, the key-package reply fix: the page handler passes
/// the re-arm skip only for a TRUNCATED page's sender. The responder
/// stops on the gapped E2; E1 — the link E2 waits for — is queued
/// behind it; the responder then answers with a NON-truncated
/// key-package-shaped reply (every event of the page a
/// `MemberJoined`). The handler asks its sender nothing (the
/// key-package branch keeps every fence and row), but the reply's
/// replay applies E1 then E2 and MOVES the cursor, so the re-arm pass
/// must be allowed to re-arm the SENDER itself. Before round 9 the
/// unconditional skip left the armed sender unasked — its row stayed
/// armed with nobody left to clear or retire it. The `MemberJoined`
/// itself need not apply; only its shape and its replay matter.
#[tokio::test]
async fn a_key_package_reply_no_longer_skips_the_armed_sender_in_the_rearm_pass() -> Result<()> {
    let group_id = "1c".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2: the event queues behind its missing
    //    predecessor and the row arms.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );

    // 2. E1 — the link E2 waits for — queues behind it, authenticated
    //    as its own leaver: the sender the replay applies it as (the
    //    page path's relay rule resolved the same author for E2).
    let leaver1 = match &event1 {
        NamedGroupMetadataEvent::MemberRemoved { agent_id, .. } => {
            parse_agent_id_hex(agent_id).expect("the chain pair's E1 leaver agent id")
        }
        _ => unreachable!("the chain pair's E1 is a MemberRemoved"),
    };
    state
        .treekem_pending_events
        .write()
        .await
        .get_mut(&group_id)
        .expect("the stopped page queued E2")
        .push_back(PendingTreeKemMetadataEvent {
            event: event1,
            sender: leaver1,
            queued_at: std::time::Instant::now(),
        });

    // 3. The responder answers with a NON-truncated key-package-shaped
    //    reply: one MemberJoined for an unrelated stranger (an invite
    //    no roster ever issued), so every event of the page is a
    //    MemberJoined and the handler takes the key-package branch.
    let stranger = AgentKeypair::generate()?;
    let key_package_reply = TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.clone(),
        events: vec![NamedGroupMetadataEvent::MemberJoined {
            group_id: group_id.clone(),
            stable_group_id: None,
            member_agent_id: hex::encode(stranger.agent_id().as_bytes()),
            member_public_key_b64: base64::engine::general_purpose::STANDARD
                .encode(stranger.public_key().as_bytes()),
            role: x0x::groups::GroupRole::Member,
            display_name: None,
            inviter_agent_id: hex::encode(state.agent.agent_id().as_bytes()),
            invite_secret: format!("issue1685-round9-kp-{group_id}"),
            ts_ms: now_millis_u64(),
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
        responder_state_hash: Some("kp-reply-head".to_string()),
    };
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        key_package_reply,
    )
    .await;

    // 4. The reply's replay applied E1 then E2, so the cursor moved and
    //    the re-arm pass re-armed the sender itself (no skip for a
    //    non-truncated reply's sender).
    assert!(
        eventually(|| !rearm_requests(&state).is_empty()).await,
        "#1685 round 9: the key-package reply's replay re-armed its own sender \
         (before round 9 the skip left the armed sender unasked)"
    );
    assert_eq!(
        rearm_requests(&state),
        vec![(group_id.clone(), responder_hex.clone(), "replay_applied")],
        "the re-arm is typed and names the reply's own sender"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "exactly one ask went out: the sender's own re-arm"
    );
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "the ask that went out cleared the sender's row"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "the re-arm asks; only the responder's own terminal page closes its fence"
    );
    Ok(())
}

/// #1685 round 9 safety pin (round 8's race guard, finding 3 — green
/// before and after): while a detached re-arm task is parked at the
/// send seam, a racing no-progress page from the same peer arms a
/// FRESH row (a new stop instant). When the parked send then
/// completes, its clear-on-send compares the recorded stop instant and
/// must NOT wipe the fresh row — an unconditional clear would leave
/// the peer's fence open with no row: nothing would re-ask or retire
/// it.
#[tokio::test]
async fn a_fresh_stop_survives_the_parked_rearms_clear_on_send() -> Result<()> {
    let group_id = "1d".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2: the row arms at the FIRST stop
    //    instant.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );

    // 2. The re-arm ask parks at the send seam: the helper's terminal
    //    page delivers E1, the replay applies E2, the cursor moves, and
    //    the detached re-arm's send cannot leave.
    let parked = detached_send_test_seam::arm(&format!("treekem-catchup-page:{group_id}"));
    handle_treekem_catchup_response(
        &state,
        &helper,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    assert!(
        eventually(|| parked.reached()).await,
        "the detached re-arm's ask is the parked send"
    );
    assert!(
        treekem_page_rearm_inflight(&group_id, &responder_hex),
        "CONTROL: the (group, peer) re-arm claim is held while the send is parked"
    );

    // 3. While the send is parked, the responder stops AGAIN: a gapped
    //    truncated event at the moved head arms a FRESH row (a new stop
    //    instant) under the same machine.
    let head = cursor(&state, &group_id).await;
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(
            &group_id,
            fork_removal_page_event(&group_id, &responder, head.0 + 1),
        ),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "the racing page armed a FRESH row for the same peer"
    );

    // 4. Release the parked send: it succeeds, records its re-arm and
    //    clears only the row it saw — the fresh row survives the
    //    clear-on-send.
    drop(parked);
    assert!(
        eventually(|| !treekem_page_rearm_inflight(&group_id, &responder_hex)).await,
        "the released re-arm task finished and released its claim"
    );
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "#1685 round 8, finding 3: the clear-on-send matched the old stop instant \
         and did not wipe the fresh row the racing page armed"
    );
    assert_eq!(
        rearm_requests(&state),
        vec![(group_id.clone(), responder_hex.clone(), "replay_applied")],
        "the released send recorded exactly one typed re-arm"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "exactly one ask went out: the parked re-arm's own"
    );
    Ok(())
}

/// #1685 round 9 safety pin (round 8's finding 4 — green before and
/// after): the re-arm claim is keyed by the group's REGISTER key, so
/// the caller's two id spellings (register key or stable id) contend
/// for ONE claim. While the responder's re-arm task is parked at the
/// send seam, a second re-arm pass spawned under the STABLE id must
/// not start a second send task for the same peer: exactly one ask and
/// one typed re-arm — one page stream per peer.
#[tokio::test]
async fn one_rearm_task_per_peer_across_both_group_id_spellings() -> Result<()> {
    let group_id = "1e".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on E2 (row armed).
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );

    // 2. The re-arm ask parks at the send seam, so its task holds the
    //    register-keyed claim.
    let parked = detached_send_test_seam::arm(&format!("treekem-catchup-page:{group_id}"));
    handle_treekem_catchup_response(
        &state,
        &helper,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    assert!(
        eventually(|| parked.reached()).await,
        "the detached re-arm's ask is the parked send"
    );
    assert!(
        treekem_page_rearm_inflight(&group_id, &responder_hex),
        "CONTROL: the register-keyed claim is held while the send is parked"
    );

    // 3. A second re-arm pass under the OTHER spelling (the stable id)
    //    resolves the same register key, so the held claim must skip
    //    the peer. Give the second coordinator a moment to run while
    //    the first task still holds the claim.
    spawn_stopped_treekem_catchup_rearms(&state, &fence_ids[2], None);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        treekem_page_rearm_inflight(&group_id, &responder_hex),
        "CONTROL: the first task still holds its claim (its send is still parked)"
    );

    // 4. Release: exactly one ask and one typed re-arm in total — the
    //    stable-id pass never started a second send.
    drop(parked);
    assert!(
        eventually(|| !treekem_page_rearm_inflight(&group_id, &responder_hex)).await,
        "the released re-arm task finished and released its claim"
    );
    assert_eq!(
        page_requests(&state),
        1,
        "#1685 round 8, finding 4: one ask total — both id spellings contend for \
         one (group, peer) claim, so the second pass started no second send"
    );
    assert_eq!(
        rearm_requests(&state),
        vec![(group_id.clone(), responder_hex.clone(), "replay_applied")],
        "exactly one typed re-arm"
    );
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "the one ask that went out cleared the row"
    );
    Ok(())
}

/// #1685 round 9 safety pin (round 5's clear-on-success — green before
/// and after), the DETACHED half: when every send of a re-arm really
/// fails (the force-ok seam stays off, so the real send runs against
/// the unit-test state and fails), the bounded tries are all spent,
/// the stopped row STAYS armed and nothing is recorded — no typed
/// re-arm, no defer, no departure. The next replay that moves the
/// cursor retries the peer.
#[tokio::test]
async fn a_detached_rearm_that_cannot_send_keeps_the_row_armed_and_records_nothing() -> Result<()> {
    let group_id = "1f".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        helper,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    // No force_ok and no armed seam: every real send fails in the
    // unit-test state.

    // 1. The responder stops on E2 (row armed; the stop itself sends
    //    nothing).
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );
    assert_eq!(
        page_requests(&state),
        0,
        "CONTROL: the stopped loop asks nobody"
    );

    // 2. The helper's terminal page delivers E1; the replay applies E2
    //    and the cursor moves, so the detached re-arm runs — and every
    //    one of its bounded sends fails.
    let before = cursor(&state, &group_id).await;
    handle_treekem_catchup_response(
        &state,
        &helper,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![event1]),
    )
    .await;
    assert_ne!(
        cursor(&state, &group_id).await,
        before,
        "CONTROL: the replay really applied the retained E2"
    );
    assert!(
        eventually(|| !treekem_page_rearm_inflight(&group_id, &responder_hex)).await,
        "the failed re-arm task finished and released its claim"
    );
    // Settle: nothing may land after the task's exit either.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "#1685 round 5, finding 2: a re-arm whose every send failed keeps the row \
         armed, so the next cursor-moving replay retries the peer"
    );
    assert_eq!(page_requests(&state), 0, "no ask left");
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm was recorded"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_deferred
            .lock()
            .expect("deferred recorder")
            .is_empty(),
        "no defer record: this peer is not held, its sends failed"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_departed
            .lock()
            .expect("departed recorder")
            .is_empty(),
        "the responder keeps its Active seat: no departure"
    );
    Ok(())
}

/// #1685 round 9 safety pin (round 5, finding 2 — green before and
/// after), the INLINE half: a truncated page that MOVES the cursor
/// makes the handler itself ask for the next page. With the force-ok
/// seam off (every real send fails in the unit-test state), the inline
/// ask leaves nothing: no page request is recorded, the stream records
/// no stop (the page made progress), the two applied links drain the
/// queue, and the peer's page fence stays open — this peer still owes
/// its terminal page.
#[tokio::test]
async fn an_inline_next_page_ask_that_cannot_send_leaves_no_trace() -> Result<()> {
    let group_id = "21".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    // No force_ok and no armed seam: the real send path runs and fails
    // in the unit-test state.
    let before = cursor(&state, &group_id).await;

    // 1. The responder's ONE truncated page carries both links of the
    //    chain: E1 applies at the base head, then E2 applies at E1's
    //    head — the cursor moves inside the page, and the handler asks
    //    for the next page itself.
    let mut both = truncated_page(&group_id, event1);
    both.events.push(event2);
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        both,
    )
    .await;

    assert_ne!(
        cursor(&state, &group_id).await,
        before,
        "CONTROL: the page applied both links and moved the cursor"
    );
    assert_eq!(
        pending_len(&state, &group_id).await,
        0,
        "CONTROL: the queue drained through the applied links"
    );
    assert_eq!(
        page_requests(&state),
        0,
        "#1685 round 5, finding 2: the inline next-page ask that cannot leave \
         sends nothing (no forced ask ran; the row would stay armed for the next \
         replay)"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_stops
            .lock()
            .expect("page-stop recorder")
            .is_empty(),
        "a progressing page records no stop"
    );
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "no row armed: nothing stopped, and the failed inline ask clears nothing"
    );
    assert!(
        rearm_requests(&state).is_empty(),
        "no typed re-arm was recorded"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "the truncated page opened this peer's fence and the failed ask closes \
         nothing — this peer still owes its terminal page"
    );
    Ok(())
}

/// #1685 round 10 (P1 review threads 1 and 2 — the stale-ask page):
/// catch-up asks several peers at once from one cursor, so a peer's
/// truncated page can land only AFTER another peer's page advanced the
/// head past the cursor its own ask left from. That page serves
/// already-applied events plus a still-ahead unapplicable one, nothing
/// applies, and the arrival cursor equals the post-advance head — the
/// old no-progress test sampled the cursor at ARRIVAL, stopped this
/// peer's stream and left its page fence open with no retry, although
/// a fresh ask from the moved head would fetch a different page. The
/// stop must hold against the cursor the REQUEST left from: the page
/// pages on from the moved cursor, and its stream reaches the terminal
/// page that closes its fence (thread 2: self-leave rekey is not left
/// deferred behind a fence nothing will close).
#[tokio::test]
async fn a_truncated_page_answering_a_pre_advance_ask_pages_on_from_the_moved_cursor() -> Result<()>
{
    let group_id = "22".repeat(32);
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
        "issue1685-stale-ask".to_string(),
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
    // Peer B: the slow responder whose truncated page lands after peer
    // A's page advanced the head past the cursor B's ask left from.
    let other = AgentKeypair::generate()?;
    let other_id = other.agent_id();
    let other_hex = hex::encode(other_id.as_bytes());
    info.add_member(
        other_hex.clone(),
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
    let fence_ids = {
        let groups = state.named_groups.read().await;
        let info = groups.get(&group_id).expect("group");
        [
            group_id.clone(),
            info.mls_group_id.clone(),
            info.stable_group_id().to_string(),
        ]
    };

    // The member's linked self-leave — the event peer A's page applies
    // to advance the head while peer B's ask is in flight.
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
    let base_cursor = cursor(&state, &group_id).await;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The ask peer B's page will answer leaves from the base head.
    assert!(
        request_treekem_catchup_page(&state, &group_id, &other_id).await,
        "CONTROL: the recorded ask left"
    );
    assert_eq!(page_requests(&state), 1, "CONTROL: one ask went out");

    // 2. Peer A's page applies the linked self-leave and moves the head
    //    past the cursor B's ask left from (its own stream re-requests).
    handle_treekem_catchup_response(
        &state,
        &member_id,
        &clean_sender_machine(),
        true,
        truncated_page(&group_id, event),
    )
    .await;
    let moved_cursor = cursor(&state, &group_id).await;
    assert_ne!(
        moved_cursor, base_cursor,
        "CONTROL: peer A's page advanced the head"
    );
    assert_eq!(page_requests(&state), 2, "peer A's own stream re-requests");

    // 3. Peer B's truncated page arrives: its ahead event cannot apply
    //    (the fork shape), nothing else in it is new, and the cursor
    //    does not move — but its ask left from the base head, so the
    //    next ask carries the moved cursor and can still make
    //    progress. It must PAGE ON, not stop.
    handle_treekem_catchup_response(
        &state,
        &other_id,
        &clean_sender_machine(),
        true,
        truncated_page(
            &group_id,
            fork_removal_page_event(&group_id, &other, moved_cursor.0 + 1),
        ),
    )
    .await;
    assert_eq!(
        page_requests(&state),
        3,
        "the stale-ask page re-requests from the moved cursor instead of stopping"
    );
    assert!(
        state
            .named_group_test_recorders
            .catchup_page_stops
            .lock()
            .expect("page-stop recorder")
            .is_empty(),
        "a page answering a pre-advance ask records no stop"
    );
    assert!(
        treekem_page_stopped_peers(&fence_ids).is_empty(),
        "no row armed: the peer's stream never stopped"
    );

    // 4. The live stream reaches the terminal page that closes peer
    //    B's fence, so the open fence cannot defer self-leave rekey.
    handle_treekem_catchup_response(
        &state,
        &other_id,
        &clean_sender_machine(),
        true,
        terminal_page(&group_id, vec![]),
    )
    .await;
    assert!(
        !self_leave_rekey_fence_peer_open(&fence_ids, &other_hex),
        "peer B's terminal page closed its page fence"
    );
    Ok(())
}

/// #1685 round 10 (P1 review thread 3 — the resumed stream): the stop
/// leaves the peer's fence open and its premise dies wherever the
/// cursor next MOVES. Round 5 detected movement only inside a replay's
/// own drain window, so a dependency that arrived through the LISTENER
/// (a direct apply that runs no replay at all) moved the head with
/// nothing asking the stopped peer again — the open peer fence
/// deferred self-leave rekey indefinitely in a quiet group. The stop
/// now records a resumption baseline and every post-apply seam checks
/// it; the listener's own apply of the missing link must re-arm the
/// stopped peer from the moved cursor, and its ask is bounded and
/// typed like every re-arm.
#[tokio::test]
async fn a_listener_applied_advance_rearms_the_stopped_peer() -> Result<()> {
    let group_id = "23".repeat(32);
    let pair = issue1685_chain_pair(&group_id, None).await?;
    let Issue1685ChainPair {
        state,
        responder,
        responder_hex,
        responder_machine,
        event1,
        event2,
        fence_ids,
        ..
    } = pair;
    state
        .named_group_test_recorders
        .catchup_page_force_ok
        .store(true, std::sync::atomic::Ordering::SeqCst);

    // 1. The responder stops on the ahead event E2 (it only lacks E1):
    //    the row arms, the fence opens and the resumption baseline is
    //    recorded at this cursor.
    let base_cursor = cursor(&state, &group_id).await;
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        truncated_page(&group_id, event2),
    )
    .await;
    assert_eq!(
        treekem_page_stopped_peers(&fence_ids),
        vec![responder_hex.clone()],
        "CONTROL: the responder's stopped row is armed"
    );
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "CONTROL: the responder's page fence is open"
    );
    assert_eq!(pending_len(&state, &group_id).await, 1, "E2 stays queued");

    // 2. The missing link E1 arrives through the LISTENER — a direct
    //    apply that runs no replay, the round 10 gap. The head moves;
    //    the still-queued E2 is not replayed by it. (The author is the
    //    sender, the gossip shape of a self-leave: the page handler
    //    resolves the same author for its own applies.)
    let e1_author = verified_catchup_member_removed_author(&event1)
        .expect("E1 carries its authenticated author");
    let applied = apply_listener_metadata_event(&state, event1, e1_author, true, None).await;
    assert!(applied.is_some(), "CONTROL: the listener apply completed");
    assert_ne!(
        cursor(&state, &group_id).await,
        base_cursor,
        "CONTROL: E1 advanced the head"
    );
    assert_eq!(
        pending_len(&state, &group_id).await,
        1,
        "the listener apply replays nothing: E2 stays queued"
    );

    // 3. The movement is detected at the listener seam: the stopped
    //    peer is asked for its next page at the moved cursor (the
    //    typed re-arm), its row clears on the send, and its fence
    //    stays open until its own terminal page.
    assert!(
        eventually(|| rearm_requests(&state).len() == 1).await,
        "the listener-applied advance re-armed the stopped peer"
    );
    assert_eq!(
        rearm_requests(&state),
        vec![(group_id.clone(), responder_hex.clone(), "replay_applied")],
        "the re-arm names the group, the stopped peer and the typed reason"
    );
    assert!(
        eventually(|| treekem_page_stopped_peers(&fence_ids).is_empty()).await,
        "the successful re-arm ask cleared the stopped row"
    );

    // 4. The re-asked stream reaches its terminal page and closes the
    //    fence — the deferred self-leave rekey is unblocked.
    handle_treekem_catchup_response(
        &state,
        &responder.agent_id(),
        &responder_machine,
        true,
        terminal_page(&group_id, vec![]),
    )
    .await;
    assert!(
        !self_leave_rekey_fence_peer_open(&fence_ids, &responder_hex),
        "the resumed stream's terminal page closed the peer fence"
    );
    Ok(())
}
