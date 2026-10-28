//! #1577 (ADR 0110 §3): `handle_treekem_catchup_request` served a catch-up
//! page to any active seat. A revoked target keeps its Active seat until
//! the S4 eviction commits, so the roster check alone admitted a revoked
//! requester, while `handle_treekem_catchup_response` already dropped a
//! revoked sender. The serve now refuses a revoked requester on that same
//! drop path: no membership page, no member-keyed reply, no gated carrier.
//! A pending revocation resync refuses every requester, fail-closed, as
//! the response handler does.

use super::*;
use x0x::identity::AgentKeypair;

/// Insert a verified self-revocation of `subject` (as `s4_key_delivery_1508`).
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

#[tokio::test]
async fn a_revoked_requester_gets_no_pages_and_an_active_member_still_does() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = state.agent.agent_id();
    let group_id = "7d".repeat(16);
    let revoked = AgentKeypair::generate()?;
    let active = AgentKeypair::generate()?;
    let mut info = x0x::groups::GroupInfo::new(
        "issue1577".to_string(),
        String::new(),
        admin,
        group_id.clone(),
    );
    for member in [&revoked, &active] {
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
        .insert(group_id.clone(), info);

    // CONTROL: both seats are Active, so the roster alone serves the page.
    handle_treekem_catchup_request(
        &state,
        &active.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &active.agent_id()),
    )
    .await;
    assert_eq!(recorded_pages(&state), 1, "an active member is served");

    // The revoked requester holds the same Active seat; only the serving
    // gate refuses it. The member-keyed reply path stays closed too.
    revoke_agent(&state, &revoked).await;
    handle_treekem_catchup_request(
        &state,
        &revoked.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &revoked.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        1,
        "a revoked requester must not be served a catch-up page"
    );

    // A pending revocation resync must refuse every requester (fail-closed,
    // as the response handler does): even the active member gets no page,
    // and serving resumes once the set is whole again.
    let revocation_set = state.agent.revocation_set();
    let whole_set = revocation_set.read().await.clone();
    *revocation_set.write().await = crate::revocation::RevocationSet::quarantined_carrier(
        crate::revocation::REVOCATION_CARRIER_V3,
    );
    assert!(
        revocation_set.read().await.revocation_resync_required(),
        "CONTROL: the quarantined carrier arms the resync hold"
    );
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
        "no page may leave while the revocation set needs a resync"
    );
    *revocation_set.write().await = whole_set;
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
        "an active member is served again once the resync hold clears"
    );
    Ok(())
}
