//! #1657 (ADR 0110 §3; David's approval, 28 Oct 02:08 GMT): a catch-up
//! request from a machine-revoked or binding-revoked device gets a signed
//! typed refusal naming which revocation applies, instead of the interim
//! silent drop of #1577/#1616/#1622. The requester can stop re-asking and
//! surface the reason; non-revoked peers are served exactly as before, and
//! the agent-revocation and resync refusals keep the silent drop the
//! approval scoped this change away from. The refusal is recorded at the
//! refusal DECISION, before any egress, exactly as the page recorder is.

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
/// the #1616 test does). D70: this denies the machine only.
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

/// Retire the `(agent, machine)` pairing with an owner-signed ADR-0043
/// tombstone, the only legal authority for a binding subject, as the
/// #1622 test does. D70: this kills the pairing only.
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

fn recorded_pages(state: &AppState) -> usize {
    state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .len()
}

/// Every typed refusal the serve decided on, decoded.
fn recorded_refusals(state: &AppState) -> Vec<TreeKemCatchupRefusal> {
    state
        .named_group_test_recorders
        .catchup_refusals
        .lock()
        .expect("refusal recorder")
        .iter()
        .map(|payload| serde_json::from_slice(payload).expect("recorded refusal decodes"))
        .collect()
}

/// Seat `members` as Active members of a fresh group owned by the local
/// admin, as the #1577 test fabric does.
async fn seat_members(state: &AppState, group_id: &str, members: &[&AgentKeypair]) {
    let admin = state.agent.agent_id();
    let mut info = x0x::groups::GroupInfo::new(
        "issue1657".to_string(),
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
async fn a_machine_revoked_requester_gets_a_typed_refusal_naming_the_machine() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "57".repeat(16);
    let device_agent = AgentKeypair::generate()?;
    let active = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&device_agent, &active]).await;

    // CONTROL: an active member on a clean machine is served, and no
    // refusal exists to send it.
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
    assert!(
        recorded_refusals(&state).is_empty(),
        "CONTROL: a non-revoked requester gets no refusal"
    );

    // D70: the device is revoked, the agent is not. The serve refuses the
    // machine and answers with the typed refusal naming it — the silent
    // drop is gone.
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
        "a machine-revoked requester still gets no catch-up page"
    );
    let refusals = recorded_refusals(&state);
    assert_eq!(
        refusals.len(),
        1,
        "a machine-revoked requester gets exactly one typed refusal"
    );
    assert_eq!(
        refusals[0].message_type,
        TreeKemCatchupRefusal::MESSAGE_TYPE
    );
    assert_eq!(refusals[0].group_id(), group_id);
    assert_eq!(
        refusals[0].requester_agent_id(),
        hex::encode(device_agent.agent_id().as_bytes())
    );
    assert_eq!(
        refusals[0].reason,
        TreeKemCatchupRefusalReason::MachineRevoked,
        "the refusal names the machine revocation"
    );

    // The agent-only gate (#1577) keeps the silent drop the approval
    // scoped this change away from: no page, and no new refusal.
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
        "an agent-revoked requester is still refused"
    );
    assert_eq!(
        recorded_refusals(&state).len(),
        1,
        "the agent-revocation refusal stays a silent drop"
    );

    // A non-revoked requester is still served after the refusal.
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
        "a non-revoked requester is still served after the refusal"
    );
    Ok(())
}

#[tokio::test]
async fn a_binding_revoked_requester_gets_a_typed_refusal_naming_the_binding() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "58".repeat(16);
    let moved = AgentKeypair::generate()?;
    let active = AgentKeypair::generate()?;
    seat_members(&state, &group_id, &[&moved, &active]).await;

    // D70: the pairing alone is dead — agent and device each stay clean.
    // The serve refuses the pairing and answers with the typed refusal
    // naming the binding revocation.
    let owner = x0x::identity::UserKeypair::generate()?;
    let retired_machine = x0x::identity::MachineKeypair::generate()?.machine_id();
    retire_binding(&state, &owner, &moved, &retired_machine).await;
    handle_treekem_catchup_request(
        &state,
        &moved.agent_id(),
        &retired_machine,
        true,
        catchup_request(&group_id, &moved.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        0,
        "a binding-revoked requester gets no catch-up page"
    );
    let refusals = recorded_refusals(&state);
    assert_eq!(
        refusals.len(),
        1,
        "a binding-revoked requester gets exactly one typed refusal"
    );
    assert_eq!(
        refusals[0].message_type,
        TreeKemCatchupRefusal::MESSAGE_TYPE
    );
    assert_eq!(refusals[0].group_id(), group_id);
    assert_eq!(
        refusals[0].reason,
        TreeKemCatchupRefusalReason::BindingRevoked,
        "the refusal names the binding revocation"
    );

    // Pairing-scope control: the same agent on a clean machine is still
    // an Active member in good standing and is served, with no refusal.
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
        1,
        "the same agent on a clean machine is still served"
    );
    assert_eq!(
        recorded_refusals(&state).len(),
        1,
        "the clean pairing of the same agent gets no refusal"
    );
    Ok(())
}
