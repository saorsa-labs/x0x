//! #1616 (ADR 0110 D70): a machine revocation denies that device only; the
//! portable agent keeps its Active seat until that agent itself is revoked.
//! Both TreeKEM catch-up handlers therefore refuse the QUIC-authenticated
//! sender machine of the direct message, on the same refusal paths the
//! #1577 agent-revocation gates use: the serve hands no page to a
//! machine-revoked requester, and the apply takes no page from a
//! machine-revoked responder. The machine id is threaded through
//! `dispatch_treekem_catchup_message`; no wire or public API change.

use super::*;
use x0x::identity::AgentKeypair;

/// Insert a verified self-revocation of `subject` (as the #1577 test does).
async fn revoke_agent(state: &AppState, subject: &AgentKeypair) {
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(subject.agent_id()),
        subject.public_key(),
        subject.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign revocation");
    let revocation_set = state.agent.revocation_set();
    assert!(revocation_set
        .write()
        .await
        .verify_and_insert(record, None)
        .expect("self-revocation verifies"));
}

/// Insert a verified self-revocation of `device` (the device's own key, as
/// the owner-trust tests do). D70: this denies the machine only.
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

fn catchup_request(group_id: &str, requester: &AgentId) -> TreeKemCatchupRequest {
    TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.to_string(),
        requester_agent_id: hex::encode(requester.as_bytes()),
        from_revision: 0,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: None,
        limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
    }
}

fn truncated_catchup(group_id: &str) -> TreeKemCatchupResponse {
    TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: group_id.to_string(),
        events: Vec::new(),
        truncated: true,
        responder_state_hash: None,
    }
}

fn recorded_pages(state: &AppState) -> usize {
    state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .len()
}

/// Seat `members` as Active members of a fresh group owned by the local
/// admin, as the #1577 test fabric does.
async fn seat_members(state: &AppState, group_id: &str, members: &[&AgentKeypair]) {
    let admin = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::new(
        "issue1616".to_string(),
        String::new(),
        admin,
        group_id.to_string(),
    );
    for member in members {
        info.add_member(
            hex::encode(member.agent_id().as_bytes()),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(admin.as_bytes())),
            None,
        );
    }
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
}

#[tokio::test]
async fn a_machine_revoked_requester_gets_no_pages_and_the_agent_gate_stands() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "16".repeat(16);
    let device_agent = AgentKeypair::generate()?;
    let active = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&device_agent, &active]).await;

    // CONTROL: an active member on a clean machine is served.
    handle_treekem_catchup_request(
        &state,
        &active.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &active.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        1,
        "an active member on a clean machine is served"
    );

    // D70: the device is revoked, the agent is not. The agent keeps its
    // Active seat, so only the machine gate can refuse the request — the
    // refusal the #1577 roster check could never make.
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;
    assert!(
        !state
            .agent
            .revocation_set()
            .read()
            .await
            .is_agent_revoked(&device_agent.agent_id()),
        "CONTROL: the device's agent is not revoked"
    );
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &device.machine_id(),
        true,
        catchup_request(&group_id, &device_agent.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        1,
        "a machine-revoked requester must not be served a catch-up page"
    );

    // The agent-only gate (#1577) still refuses once the agent itself is
    // revoked, even from a clean machine.
    revoke_agent(&state, &device_agent).await;
    handle_treekem_catchup_request(
        &state,
        &device_agent.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &device_agent.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        1,
        "an agent-revoked requester on a clean machine is still refused"
    );

    // A non-revoked requester is still served after both gates refused.
    handle_treekem_catchup_request(
        &state,
        &active.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &active.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        2,
        "a non-revoked requester is still served"
    );
    Ok(())
}

#[tokio::test]
async fn a_page_from_a_machine_revoked_responder_is_not_applied() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "26".repeat(16);
    let clean = AgentKeypair::generate()?;
    let device_agent = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&clean, &device_agent]).await;
    let fence_ids = [group_id.clone()];
    let clean_hex = hex::encode(clean.agent_id().as_bytes());
    let device_hex = hex::encode(device_agent.agent_id().as_bytes());

    // CONTROL: a truncated page from a clean active member opens that
    // peer's page fence (#1113) — the fabric reaches the apply.
    handle_treekem_catchup_response(
        &state,
        &clean.agent_id(),
        &clean_sender_machine(),
        true,
        truncated_catchup(&group_id),
    )
    .await;
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &clean_hex),
        "CONTROL: the clean responder's truncated page opens its fence"
    );

    // D70: the responder's device is revoked, its agent is not (still an
    // Active member). The refused page must leave the responder's fence
    // closed; the refusal, not the roster check, is what drops it.
    let device = x0x::identity::MachineKeypair::generate()?;
    revoke_machine(&state, &device).await;
    assert!(
        !state
            .agent
            .revocation_set()
            .read()
            .await
            .is_agent_revoked(&device_agent.agent_id()),
        "CONTROL: the responder's agent is not revoked"
    );
    handle_treekem_catchup_response(
        &state,
        &device_agent.agent_id(),
        &device.machine_id(),
        true,
        truncated_catchup(&group_id),
    )
    .await;
    assert!(
        !self_leave_rekey_fence_peer_open(&fence_ids, &device_hex),
        "a machine-revoked responder's page must not be applied"
    );
    Ok(())
}
