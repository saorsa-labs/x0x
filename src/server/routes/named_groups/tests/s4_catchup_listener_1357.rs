//! #1357 (ADR 0110 §2): the TreeKEM catch-up listener of one daemon both
//! serves catch-up requests and applies catch-up responses, one message at a
//! time. A served page is sent with the generic direct-message config: up to
//! 8 s for the raw receive ACK, then the gossip fallback with its own ACK
//! wait. When the requester is slow or unreachable (in the W3-H
//! late-observation RED: the revoked target B, whose links were being
//! closed), the listener waited in that send. The answers to the designated
//! admin's own head round stayed queued behind it, the round never
//! confirmed, and the ranked fallback sealed at its own T_obs + W instead.
//!
//! A serve must never hold the listener: the response that follows it is
//! applied while the slow page send still runs. The state has no network
//! node, so no test traffic leaves the process.

use super::*;

/// Upper bound for one listener step that must not wait for a page send.
const STEP: Duration = Duration::from_secs(2);

#[tokio::test]
async fn a_slow_page_send_does_not_hold_the_catchup_listener() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = state.agent.agent_id();
    let group_id = "5a".repeat(16);
    let requester = x0x::identity::AgentKeypair::generate()?.agent_id();
    let requester_hex = hex::encode(requester.as_bytes());
    let mut info = x0x::groups::GroupInfo::new(
        "s4-catchup-listener".to_string(),
        String::new(),
        admin,
        group_id.clone(),
    );
    info.add_member(
        requester_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(hex::encode(admin.as_bytes())),
        None,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    // The page send to this requester stops just before the transport, as
    // a send to an unreachable peer waits for its ACK.
    let parked = detached_send_test_seam::arm(&format!("treekem-catchup-serve:{requester_hex}"));
    let request = serde_json::to_vec(&TreeKemCatchupRequest {
        message_type: "treekem_catchup_request".to_string(),
        group_id: group_id.clone(),
        requester_agent_id: requester_hex.clone(),
        from_revision: 0,
        from_treekem_epoch: 0,
        current_state_hash: String::new(),
        missing_prev_state_hash: None,
        target_member_id: None,
        limit: TREEKEM_CATCHUP_RESPONSE_EVENT_CAP,
    })?;
    let step = tokio::time::timeout(
        STEP,
        dispatch_treekem_catchup_message(&state, &requester, true, &request),
    )
    .await;
    assert!(
        step.is_ok(),
        "the listener waited for the parked page send: the next catch-up \
         response (a head-round answer) would stay queued behind it"
    );
    assert_eq!(step.ok(), Some(true), "the listener keeps running");

    // The serve itself still runs and reaches the send.
    let deadline = tokio::time::Instant::now() + STEP;
    while !parked.reached() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(parked.reached(), "the request is still served");

    // A response that arrives while the page send is parked is applied
    // now (here an unknown group: the step returns at once).
    let response = serde_json::to_vec(&TreeKemCatchupResponse {
        message_type: "treekem_catchup_response".to_string(),
        group_id: "6b".repeat(16),
        events: Vec::new(),
        truncated: false,
        responder_state_hash: Some(String::new()),
    })?;
    let next = tokio::time::timeout(
        STEP,
        dispatch_treekem_catchup_message(&state, &requester, true, &response),
    )
    .await;
    assert_eq!(
        next.ok(),
        Some(true),
        "the next response is applied at once"
    );
    drop(parked);
    Ok(())
}
