//! #1622 (ADR 0110 D70): a binding revocation retires one agent↔machine
//! pairing only — the portable agent keeps its Active seat and the device
//! stays clean, so neither the #1577 agent gate nor the #1616 machine gate
//! can refuse it. Both TreeKEM catch-up handlers therefore refuse the
//! pairing itself: the serve hands no page to a requester whose
//! (agent, machine) binding is revoked, and the apply takes no page from a
//! responder whose pairing is revoked. The pairing is the QUIC-authenticated
//! sender agent and machine of the direct message; no wire or public API
//! change.

use super::*;
use x0x::identity::AgentKeypair;

/// Retire the `(agent, machine)` pairing with an owner-signed ADR-0043
/// tombstone, the only legal authority for a binding subject (self-revocation
/// is structurally impossible). D70: this kills the pairing only.
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
        "issue1622".to_string(),
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
async fn a_binding_revoked_requester_gets_no_pages_and_only_the_pairing_is_dead() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "22".repeat(16);
    let moved = AgentKeypair::generate()?;
    let active = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&moved, &active]).await;

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

    // D70: the pairing is dead, the agent and the device each stay clean.
    // The agent keeps its Active seat, so only the binding gate can refuse
    // the request — the refusal neither #1577 nor #1616 could make.
    let owner = x0x::identity::UserKeypair::generate()?;
    let device = x0x::identity::MachineKeypair::generate()?;
    retire_binding(&state, &owner, &moved, &device.machine_id()).await;
    {
        let revocation_set = state.agent.revocation_set();
        let revoked = revocation_set.read().await;
        assert!(
            !revoked.is_agent_revoked(&moved.agent_id()),
            "CONTROL: the requester's agent is not revoked"
        );
        assert!(
            !revoked.is_machine_revoked(&device.machine_id()),
            "CONTROL: the requester's machine is not revoked"
        );
    }
    handle_treekem_catchup_request(
        &state,
        &moved.agent_id(),
        &device.machine_id(),
        true,
        catchup_request(&group_id, &moved.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        1,
        "a requester with a revoked agent-machine binding must not be served a catch-up page"
    );

    // D70: only the pairing is dead — the same agent on a clean machine is
    // still served.
    handle_treekem_catchup_request(
        &state,
        &moved.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &moved.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        2,
        "the agent keeps its seat: on a clean machine it is served"
    );
    Ok(())
}

#[tokio::test]
async fn a_page_from_a_binding_revoked_responder_is_not_applied() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "32".repeat(16);
    let clean = AgentKeypair::generate()?;
    let moved = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&clean, &moved]).await;
    let fence_ids = [group_id.clone()];
    let clean_hex = hex::encode(clean.agent_id().as_bytes());
    let moved_hex = hex::encode(moved.agent_id().as_bytes());

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

    // D70: the responder's pairing is dead; its agent is not revoked (still
    // an Active member) and its device is clean. The refused page must
    // leave the responder's fence closed; the refusal, not the roster
    // check, is what drops it.
    let owner = x0x::identity::UserKeypair::generate()?;
    let device = x0x::identity::MachineKeypair::generate()?;
    retire_binding(&state, &owner, &moved, &device.machine_id()).await;
    assert!(
        !state
            .agent
            .revocation_set()
            .read()
            .await
            .is_agent_revoked(&moved.agent_id()),
        "CONTROL: the responder's agent is not revoked"
    );
    handle_treekem_catchup_response(
        &state,
        &moved.agent_id(),
        &device.machine_id(),
        true,
        truncated_catchup(&group_id),
    )
    .await;
    assert!(
        !self_leave_rekey_fence_peer_open(&fence_ids, &moved_hex),
        "a responder with a revoked agent-machine binding must not have its page applied"
    );

    // D70: only the pairing is dead — the same responder on a clean machine
    // still applies.
    handle_treekem_catchup_response(
        &state,
        &moved.agent_id(),
        &clean_sender_machine(),
        true,
        truncated_catchup(&group_id),
    )
    .await;
    assert!(
        self_leave_rekey_fence_peer_open(&fence_ids, &moved_hex),
        "the responder keeps its seat: from a clean machine its page applies"
    );
    Ok(())
}
