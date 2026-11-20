#![cfg(test)]
//! #2004 (review of #2116): the TreeKEM catch-up handler answers nothing to
//! an Active seat whose committed certificate's S4 expiry is due, by the
//! same unconditional return as a revoked requester. The cached-add
//! fallback, which serves a recent joiner the handler does not yet seat,
//! must not serve it either: the owner-recovery seal can leave such a seat
//! its TreeKEM leaf for one epoch, and a page must not hand it that epoch.

use super::*;
use x0x::identity::{AgentKeypair, UserKeypair};

fn recorded_pages(state: &AppState) -> usize {
    state
        .named_group_test_recorders
        .catchup_responses
        .lock()
        .expect("catch-up recorder")
        .len()
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

fn member_added(group_id: &str, actor: &str, agent_hex: &str) -> NamedGroupMetadataEvent {
    NamedGroupMetadataEvent::MemberAdded {
        roster_certificates_b64: Vec::new(),
        group_id: group_id.to_string(),
        revision: 2,
        actor: actor.to_string(),
        agent_id: agent_hex.to_string(),
        display_name: None,
        treekem_commit_b64: None,
        treekem_welcome_b64: None,
        welcome_ref: None,
        treekem_epoch: None,
        treekem_key_package_hash: None,
        member_joined_recovery: None,
        member_recovery_history: Vec::new(),
        certificate_b64: None,
        owner_mandate: None,
        commit: None,
        reseat_mandate: None,
    }
}

fn now_unix() -> u64 {
    x0x::groups::owner_cert::restore_clock_now()
}

/// A seated member whose committed certificate expires at `not_after`.
fn certified_member(
    owner: &UserKeypair,
    agent: &AgentKeypair,
    admin_hex: &str,
    not_after: u64,
) -> x0x::groups::GroupMember {
    let cert =
        x0x::identity::AgentCertificate::issue_with_expiry(owner, agent, Some(not_after)).unwrap();
    let hex = hex::encode(agent.agent_id().as_bytes());
    let mut member =
        x0x::groups::GroupMember::new_member(hex, None, Some(admin_hex.to_string()), 1);
    member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
    member.certificate = Some(cert);
    member
}

#[tokio::test]
async fn a_due_expired_seat_gets_no_catchup_page_even_with_a_cached_add() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "20".repeat(32);
    let owner = UserKeypair::generate()?;
    let admin = state.agent.agent_id();
    let admin_hex = hex::encode(admin.as_bytes());
    let expired = AgentKeypair::generate()?;
    let not_due = AgentKeypair::generate()?;
    let mut info = x0x::groups::GroupInfo::new(
        "issue2004".to_string(),
        String::new(),
        admin,
        group_id.clone(),
    );
    for member in [
        certified_member(
            &owner,
            &expired,
            &admin_hex,
            now_unix().saturating_sub(2 * 3_600),
        ),
        certified_member(
            &owner,
            &not_due,
            &admin_hex,
            now_unix().saturating_sub(x0x::groups::eviction::EXPIRY_TOLERANCE_SECS - 120),
        ),
    ] {
        info.members_v2.insert(member.agent_id.clone(), member);
    }
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    // Both seats are recent joiners in the catch-up log, so only the
    // expiry return can stop the expired one.
    state.treekem_event_log.write().await.insert(
        group_id.clone(),
        vec![
            member_added(
                &group_id,
                &admin_hex,
                &hex::encode(expired.agent_id().as_bytes()),
            ),
            member_added(
                &group_id,
                &admin_hex,
                &hex::encode(not_due.agent_id().as_bytes()),
            ),
        ]
        .into(),
    );

    handle_treekem_catchup_request(
        &state,
        &expired.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &expired.agent_id()),
    )
    .await;
    assert_eq!(recorded_pages(&state), 0, "a due-expired seat gets no page");

    handle_treekem_catchup_request(
        &state,
        &not_due.agent_id(),
        &clean_sender_machine(),
        true,
        catchup_request(&group_id, &not_due.agent_id()),
    )
    .await;
    assert_eq!(
        recorded_pages(&state),
        1,
        "a seat inside tau is served as before"
    );
    state.agent.shutdown().await;
    Ok(())
}
