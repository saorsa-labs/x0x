//! #1575 (ADR 0108 §8 + D154): the local staging half of the join pending
//! notice. While a join attempt is held, the member that receives the
//! joiner's verified, attempt-bound join-result poll stages the typed
//! notice cause — `owner_certificate_pending` with the pending-seat count
//! on every `OwnerCertMemberPending` seal refusal (§8's S2 row), and
//! `no_eligible_admin` while verified revocations cover every admin seat
//! (D154, ADR 0110 §4). A staged Result or Refused for the same attempt
//! replaces the notice; a poll whose conditions no longer hold drops it.
//!
//! The engineer ruling of 27 Oct 2026 (PR #1639 review round 3) keeps the
//! D154 `no_eligible_admin` staging OFF until the notice-only rotation
//! slice lands: real joiners never send `attempt_evidence` in this slice,
//! so the evidence-bound arm is reachable only by a sender that mints its
//! own `MemberJoined`. The drop rules for an already-staged D154 notice
//! stay proven below against a directly staged row. The signed
//! `JoinPendingNotice`, the `JoinResultMessage::Pending` arm and the
//! joiner's `pending_cause` status field are proven in
//! `join_pending_notice_wire_1575`.

use super::*;
use x0x::identity::AgentKeypair;

/// Insert a verified self-revocation of `subject` (the #1508 shape).
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

/// A GSS group whose sole admin is `admin` (the creator), with this node
/// as an ordinary Active member. The joiner is NOT seated: it holds an
/// invite, not a seat.
async fn seed_group_with_local_member(state: &AppState, group_key: &str, admin: &AgentKeypair) {
    let admin_hex = hex::encode(admin.agent_id().as_bytes());
    let mut info = x0x::groups::GroupInfo::new(
        "1575".to_string(),
        String::new(),
        admin.agent_id(),
        group_key.to_string(),
    );
    info.migrate_from_v1();
    let _ = info.rotate_shared_secret();
    info.add_member(
        hex::encode(state.agent.agent_id().as_bytes()),
        x0x::groups::GroupRole::Member,
        Some(admin_hex.clone()),
        None,
    );
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_key.to_string(), info);
}

/// The joiner's join-result poll: verified, attempt-bound, refusal-capable
/// — with NO attempt evidence (#1628 review item 2's hole: a verified
/// sender that names itself reaches only the drop rules, never staging).
async fn poll_as_joiner(state: &Arc<AppState>, group_key: &str, joiner: &AgentId, attempt: &str) {
    handle_join_result_message(
        state,
        joiner,
        true,
        JoinResultMessage::FetchRequest {
            group_id: group_key.to_string(),
            member_agent_id: hex::encode(joiner.as_bytes()),
            from_revision: None,
            base_state_hash: None,
            accepts_refusal: true,
            accepts_control_blob_ref: false,
            attempt_id: Some(attempt.to_string()),
            accepts_pending_notice: true,
            held_notice_hash: None,
            notice_only: false,
            attempt_evidence: None,
        },
    )
    .await;
}

/// The joiner's D154-bound poll: the same fetch carrying the joiner's own
/// signed `MemberJoined` as `attempt_evidence`, whose blake3 IS the
/// attempt id.
async fn evidence_poll_as_joiner(
    state: &Arc<AppState>,
    group_key: &str,
    joiner: &AgentId,
    evidence: &NamedGroupMetadataEvent,
) -> String {
    let attempt = member_joined_event_attempt_id(evidence).expect("attempt id");
    handle_join_result_message(
        state,
        joiner,
        true,
        JoinResultMessage::FetchRequest {
            group_id: group_key.to_string(),
            member_agent_id: hex::encode(joiner.as_bytes()),
            from_revision: None,
            base_state_hash: None,
            accepts_refusal: true,
            accepts_control_blob_ref: false,
            attempt_id: Some(attempt.clone()),
            accepts_pending_notice: true,
            held_notice_hash: None,
            notice_only: false,
            attempt_evidence: Some(Box::new(evidence.clone())),
        },
    )
    .await;
    attempt
}

/// D154: while verified revocations cover every admin seat, the poll-side
/// staging for `no_eligible_admin` stays OFF (engineer ruling, 27 Oct 2026,
/// PR #1639 review round 3) — not even a verified, evidence-bound poll
/// stages it, because the evidence check proves only that the event is
/// self-consistently signed by the sender's own key, and a real joiner
/// never sends evidence in this slice. An eligible admin, an unverified
/// poll and a poll without verified evidence likewise stage nothing, and
/// the poll-time drop rules still run against a directly staged row.
#[tokio::test]
async fn no_eligible_admin_polls_stage_nothing_until_the_rotation_slice() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = AgentKeypair::generate()?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "75".repeat(32);
    seed_group_with_local_member(&state, &group_key, &admin).await;
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (_, _, _, evidence) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &inviter_hex,
        "1575-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&evidence).expect("attempt id");

    // Control (the behaviour main already has): with an eligible admin even
    // the evidence-bound poll stages nothing.
    evidence_poll_as_joiner(&state, &group_key, &joiner_id, &evidence).await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "no notice while an admin seat is eligible"
    );

    // An unverified evidence poll stages nothing even under the cover (§8's
    // pre-admission replies answer verified ingress only).
    revoke_agent(&state, &admin).await;
    {
        let attempt = attempt.clone();
        handle_join_result_message(
            &state,
            &joiner_id,
            false,
            JoinResultMessage::FetchRequest {
                group_id: group_key.clone(),
                member_agent_id: joiner_hex.clone(),
                from_revision: None,
                base_state_hash: None,
                accepts_refusal: true,
                accepts_control_blob_ref: false,
                attempt_id: Some(attempt.clone()),
                accepts_pending_notice: true,
                held_notice_hash: None,
                notice_only: false,
                attempt_evidence: Some(Box::new(evidence.clone())),
            },
        )
        .await;
        assert!(
            staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
            "no notice over unverified ingress"
        );
    }

    // #1628 review item 2: a verified poll that names the attempt but
    // carries NO evidence stages nothing — the sender cannot bind the
    // attempt to its own signed MemberJoined.
    poll_as_joiner(&state, &group_key, &joiner_id, &attempt).await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "no notice without verified attempt evidence"
    );

    // Engineer ruling, 27 Oct 2026: the verified, evidence-bound poll
    // stages NOTHING under the cover either — `no_eligible_admin` staging
    // is off until the D154 notice-only rotation slice lands, so a forged
    // MemberJoined buys no notice and no signing budget.
    evidence_poll_as_joiner(&state, &group_key, &joiner_id, &evidence).await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "no_eligible_admin staging is off until the rotation slice"
    );
    assert!(
        state
            .pending_join_notices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty(),
        "the evidence-bound poll staged nothing at all"
    );

    // The poll-time drop rules stay live against a directly staged row (the
    // shape the poll path staged before the ruling). A poll without an
    // attempt id is not attempt-bound: the row is left untouched.
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_NO_ELIGIBLE_ADMIN,
        JoinPendingNoticeDetail::default(),
        Some(inviter_hex.clone()),
    )
    .await;
    handle_join_result_message(
        &state,
        &joiner_id,
        true,
        JoinResultMessage::FetchRequest {
            group_id: group_key.clone(),
            member_agent_id: joiner_hex.clone(),
            from_revision: None,
            base_state_hash: None,
            accepts_refusal: true,
            accepts_control_blob_ref: false,
            attempt_id: None,
            accepts_pending_notice: true,
            held_notice_hash: None,
            notice_only: false,
            attempt_evidence: Some(Box::new(evidence.clone())),
        },
    )
    .await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_some(),
        "a poll without an attempt id does not touch the staged row"
    );

    // §8: a group that is gone (deleted here) drops its staged notice at
    // the next poll for the same attempt.
    state.named_groups.write().await.remove(&group_key);
    poll_as_joiner(&state, &group_key, &joiner_id, &attempt).await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "a deleted group drops the staged notice"
    );
    Ok(())
}

/// §8: the notice is dropped when its cause clears. A second, unrevoked
/// admin seat ends the cover, and the joiner's next poll drops the staged
/// notice. A banned joiner seat and a revoked joiner agent each drop it at
/// the next poll the same way. (The poll-side D154 staging is off until the
/// rotation slice, so the row is staged directly — the same shape the poll
/// path staged before the ruling.)
#[tokio::test]
async fn notice_clears_when_its_cause_clears() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = AgentKeypair::generate()?;
    let admin2 = AgentKeypair::generate()?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "76".repeat(32);
    seed_group_with_local_member(&state, &group_key, &admin).await;
    revoke_agent(&state, &admin).await;
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (_, _, _, evidence) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &inviter_hex,
        "1575-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&evidence).expect("attempt id");
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_NO_ELIGIBLE_ADMIN,
        JoinPendingNoticeDetail::default(),
        Some(inviter_hex.clone()),
    )
    .await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_some(),
        "staged under the cover"
    );

    // The cause clears: promote a second, unrevoked admin.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_key).expect("group kept");
        info.add_member(
            hex::encode(admin2.agent_id().as_bytes()),
            x0x::groups::GroupRole::Admin,
            Some(hex::encode(admin.agent_id().as_bytes())),
            None,
        );
        info.recompute_state_hash();
    }
    evidence_poll_as_joiner(&state, &group_key, &joiner_id, &evidence).await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "the notice is dropped once an admin is eligible again"
    );

    // A banned joiner seat drops the staged notice: seat the joiner, ban
    // it, restore the cover by revoking the second admin.
    revoke_agent(&state, &admin2).await;
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_key).expect("group kept");
        info.add_member(
            joiner_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(hex::encode(admin.agent_id().as_bytes())),
            None,
        );
        info.ban_member(&joiner_hex, Some(hex::encode(admin.agent_id().as_bytes())));
        info.recompute_state_hash();
    }
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_NO_ELIGIBLE_ADMIN,
        JoinPendingNoticeDetail::default(),
        Some(inviter_hex.clone()),
    )
    .await;
    evidence_poll_as_joiner(&state, &group_key, &joiner_id, &evidence).await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "a Banned seat drops the staged notice"
    );

    // A revoked joiner agent drops it the same way.
    revoke_agent(&state, &joiner).await;
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_key).expect("group kept");
        info.remove_member(&joiner_hex, Some(hex::encode(admin.agent_id().as_bytes())));
        info.recompute_state_hash();
    }
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_NO_ELIGIBLE_ADMIN,
        JoinPendingNoticeDetail::default(),
        Some(inviter_hex.clone()),
    )
    .await;
    evidence_poll_as_joiner(&state, &group_key, &joiner_id, &evidence).await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "a revoked joiner agent drops the staged notice"
    );
    Ok(())
}

/// §8: a staged Result or Refused for the same `(group, member, attempt)`
/// replaces the notice; a Result for a different attempt does not.
#[tokio::test]
async fn result_and_refusal_replace_the_staged_notice() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = AgentKeypair::generate()?;
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "77".repeat(32);
    let (_, _, _, joined_event) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &inviter_hex,
        "1575-secret",
        x0x::groups::GroupRole::Member,
    )?;
    seed_group_with_local_member(&state, &group_key, &admin).await;
    revoke_agent(&state, &admin).await;
    let attempt = member_joined_event_attempt_id(&joined_event).expect("attempt id");
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_NO_ELIGIBLE_ADMIN,
        JoinPendingNoticeDetail::default(),
        Some(inviter_hex.clone()),
    )
    .await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_some(),
        "staged under the cover"
    );

    // A Result for a DIFFERENT attempt keeps the notice (r7 item 6 shape).
    stage_join_result(
        &state,
        &group_key,
        &joiner_hex,
        NamedGroupMetadataEvent::GroupDeleted {
            group_id: group_key.clone(),
            actor: inviter_hex.clone(),
            revision: 1,
            commit: None,
        },
        None,
    )
    .await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_some(),
        "an attempt-less Result does not clear another attempt's notice"
    );

    // The attempt-less Result was a probe of the staging hook alone;
    // remove it (a staged Result for the member forbids notice staging at
    // the next poll, by the same §8 order).
    state
        .pending_join_results
        .write()
        .await
        .remove(&join_result_key(&group_key, &joiner_hex));

    // A Refused for the same attempt replaces it.
    stage_join_refusal(
        &state,
        &group_key,
        &joiner_hex,
        &joined_event,
        JoinRefusalReason::InviteExpired,
    )
    .await;
    let attempt_of_event = member_joined_event_attempt_id(&joined_event).expect("attempt id");
    assert_eq!(attempt, attempt_of_event, "the evidence binds the attempt");
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "a staged Refused replaces the notice"
    );

    // A Result for the SAME attempt replaces a freshly staged notice (the
    // refusal above is cleared first: §8 forbids staging beside it). The
    // poll-side D154 staging is off until the rotation slice, so the row is
    // staged directly.
    state
        .pending_join_refusals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&join_refusal_refusal_key(&group_key, &joiner_hex, &attempt));
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_NO_ELIGIBLE_ADMIN,
        JoinPendingNoticeDetail::default(),
        Some(inviter_hex.clone()),
    )
    .await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_some(),
        "re-staged for the same attempt"
    );
    stage_join_result(
        &state,
        &group_key,
        &joiner_hex,
        joined_event.clone(),
        Some(&attempt),
    )
    .await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "a staged Result replaces the notice"
    );
    Ok(())
}

/// §8's S2 row: every `OwnerCertMemberPending` seal refusal stages
/// `owner_certificate_pending` with the pending-seat count at once, while
/// the terminal refusal stays deadline-gated. Any other seal error stages
/// nothing.
#[tokio::test]
async fn owner_cert_pending_seal_refusal_stages_the_count_notice() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let joiner = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
    let group_key = "78".repeat(32);
    let (_, _, _, joined_event) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &inviter_hex,
        "1575-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&joined_event).expect("attempt id");

    // A different seal error stages nothing.
    stage_refusal_if_certificates_unobtainable(
        &state,
        &group_key,
        &joiner_hex,
        &joined_event,
        &x0x::groups::state_commit::ApplyError::StaleRevision { got: 2, have: 3 },
    )
    .await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "a non-pending seal error stages no notice"
    );

    let pending_seat = "ab".repeat(32);
    stage_refusal_if_certificates_unobtainable(
        &state,
        &group_key,
        &joiner_hex,
        &joined_event,
        &x0x::groups::state_commit::ApplyError::OwnerCertMemberPending {
            group_id: group_key.clone(),
            members: vec![pending_seat, "cd".repeat(32)],
        },
    )
    .await;
    let notice = staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt)
        .expect("the S2 notice is staged at once");
    assert_eq!(notice.0, "owner_certificate_pending");
    assert_eq!(notice.1, hex::encode(state.agent.agent_id().as_bytes()));
    assert_eq!(
        notice.2,
        JoinPendingNoticeDetail {
            count: Some(2),
            ..JoinPendingNoticeDetail::default()
        },
        "the detail counts the pending seats"
    );
    // The deadline-gated REFUSAL did not stage (CERT_EVIDENCE_DEADLINE_MS
    // has not passed for this attempt).
    let refusal_key = join_refusal_refusal_key(&group_key, &joiner_hex, &attempt);
    assert!(
        !state
            .pending_join_refusals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&refusal_key),
        "the terminal refusal stays deadline-gated"
    );
    Ok(())
}

/// §8 selection order (#1628 review item 1): a notice never sits beside a
/// staged refusal for the same attempt. A typed refusal terminalized first
/// (the deadline elapsed), then a seal retry whose `OwnerCertMemberPending`
/// path would stage the S2 notice — nothing stages, and the refusal stays
/// the only entry for the attempt.
#[tokio::test]
async fn no_notice_is_staged_beside_a_staged_refusal_for_the_attempt() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let joiner = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
    let group_key = "7c".repeat(32);
    let (_, _, _, joined_event) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &inviter_hex,
        "1575-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&joined_event).expect("attempt id");

    // The typed refusal terminalizes first (deadline path elided: stage it
    // directly, the deadline gate's own staging call).
    stage_join_refusal(
        &state,
        &group_key,
        &joiner_hex,
        &joined_event,
        JoinRefusalReason::CertificateEvidenceUnavailable,
    )
    .await;

    // A later seal retry refuses with OwnerCertMemberPending again: the S2
    // notice must NOT stage beside the refusal.
    stage_refusal_if_certificates_unobtainable(
        &state,
        &group_key,
        &joiner_hex,
        &joined_event,
        &x0x::groups::state_commit::ApplyError::OwnerCertMemberPending {
            group_id: group_key.clone(),
            members: vec!["ab".repeat(32)],
        },
    )
    .await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "no notice is staged beside the staged refusal"
    );
    assert!(
        state
            .pending_join_refusals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&join_refusal_refusal_key(&group_key, &joiner_hex, &attempt)),
        "the staged refusal is untouched"
    );
    Ok(())
}

/// §8's S2 row exit: `owner_certificate_pending` clears when the bytes
/// arrive (the seal succeeds) or the attempt ends — never on a poll that
/// merely finds an eligible admin, and not under the D154 cover either:
/// the poll-side D154 staging is off until the rotation slice (engineer
/// ruling, 27 Oct 2026), so the evidence-bound poll under the cover keeps
/// the S2 cause too.
#[tokio::test]
async fn owner_cert_pending_notice_survives_a_poll_with_an_eligible_admin() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = AgentKeypair::generate()?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_key = "79".repeat(32);
    let (_, _, _, joined_event) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &inviter_hex,
        "1575-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&joined_event).expect("attempt id");
    seed_group_with_local_member(&state, &group_key, &admin).await;

    stage_refusal_if_certificates_unobtainable(
        &state,
        &group_key,
        &joiner_hex,
        &joined_event,
        &x0x::groups::state_commit::ApplyError::OwnerCertMemberPending {
            group_id: group_key.clone(),
            members: vec!["ab".repeat(32)],
        },
    )
    .await;
    let notice = staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt)
        .expect("the S2 notice is staged");
    assert_eq!(notice.0, "owner_certificate_pending");

    // The joiner polls while the admin seat is still eligible. The S2
    // cause is owned by the seal path, so the poll must keep it — with or
    // without evidence (an evidence poll stages no D154 cause while an
    // admin is eligible).
    poll_as_joiner(&state, &group_key, &joiner_id, &attempt).await;
    evidence_poll_as_joiner(&state, &group_key, &joiner_id, &joined_event).await;
    let notice = staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt)
        .expect("the S2 notice survives the poll");
    assert_eq!(notice.0, "owner_certificate_pending");

    // A poll without evidence under the cover keeps the S2 notice too: the
    // D154 cause is evidence-bound (#1628 review item 2).
    revoke_agent(&state, &admin).await;
    poll_as_joiner(&state, &group_key, &joiner_id, &attempt).await;
    let notice = staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt)
        .expect("the S2 notice survives an evidence-less poll under the cover");
    assert_eq!(notice.0, "owner_certificate_pending");

    // Under the cover the evidence-bound poll KEEPS the S2 cause: the
    // D154 staging is off until the rotation slice (engineer ruling,
    // 27 Oct 2026), so the live-cause replacement is the rotation slice's
    // to re-enable.
    evidence_poll_as_joiner(&state, &group_key, &joiner_id, &joined_event).await;
    let notice = staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt)
        .expect("the S2 notice survives the evidence poll under the cover");
    assert_eq!(notice.0, "owner_certificate_pending");
    Ok(())
}

/// §8 Q3 bound (PR #1628 review item 1): the staged-notice map keeps the
/// staged refusals' 1024-entry cap, evicting the oldest notice first, so a
/// joiner-chosen attempt id cannot grow it without limit.
#[tokio::test]
async fn staged_notices_are_capped_like_the_staged_refusals() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner_hex = "aa".repeat(32);
    let group_key = "7a".repeat(32);
    let first_attempt = "attempt-00000";
    let last_attempt = format!("attempt-{:05}", JOIN_REFUSAL_MAX_ENTRIES as u64);
    for i in 0..=(JOIN_REFUSAL_MAX_ENTRIES as u64) {
        stage_join_pending_notice(
            &state,
            &group_key,
            &joiner_hex,
            &format!("attempt-{i:05}"),
            JOIN_PENDING_CAUSE_NO_ELIGIBLE_ADMIN,
            JoinPendingNoticeDetail::default(),
            None,
        )
        .await;
    }
    let notices = state
        .pending_join_notices
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(notices.len(), JOIN_REFUSAL_MAX_ENTRIES, "the cap holds");
    assert!(
        !notices.contains_key(&join_refusal_refusal_key(
            &group_key,
            &joiner_hex,
            first_attempt
        )),
        "the oldest notice was evicted"
    );
    assert!(
        notices.contains_key(&join_refusal_refusal_key(
            &group_key,
            &joiner_hex,
            &last_attempt
        )),
        "the newest notice was kept"
    );
    Ok(())
}

/// §8 selection order at the poll (PR #1628 review item 2): a staged
/// Refused for the attempt forbids staging a notice over it, even when the
/// fetch cannot be served the refusal (`accepts_refusal` false). The
/// re-check also covers the re-acquired critical section after the refusal
/// probe consumed the caller's guard — evidence-bound or not.
#[tokio::test]
async fn a_poll_stages_no_notice_over_a_staged_refusal() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = AgentKeypair::generate()?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let inviter_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_key = "7b".repeat(32);
    let (_, _, _, joined_event) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &inviter_hex,
        "1575-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&joined_event).expect("attempt id");
    seed_group_with_local_member(&state, &group_key, &admin).await;
    // The D154 cover holds and the fetch below carries verified evidence.
    // The poll-side staging is off until the rotation slice, so this also
    // guards the §8 re-check itself for the slice that re-enables it:
    // nothing stages over a staged refusal.
    revoke_agent(&state, &admin).await;
    stage_join_refusal(
        &state,
        &group_key,
        &joiner_hex,
        &joined_event,
        JoinRefusalReason::InviteExpired,
    )
    .await;

    // A fetch that cannot be served the refusal still must not stage a
    // notice over it: §8's order is Result, then Refused, then notice —
    // with or without evidence.
    handle_join_result_message(
        &state,
        &joiner_id,
        true,
        JoinResultMessage::FetchRequest {
            group_id: group_key.clone(),
            member_agent_id: joiner_hex.clone(),
            from_revision: None,
            base_state_hash: None,
            accepts_refusal: false,
            accepts_control_blob_ref: false,
            attempt_id: Some(attempt.clone()),
            accepts_pending_notice: true,
            held_notice_hash: None,
            notice_only: false,
            attempt_evidence: Some(Box::new(joined_event.clone())),
        },
    )
    .await;
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "no notice is staged over a staged Refused"
    );
    Ok(())
}

/// §8: a cause name is 1 to 64 bytes of `[a-z0-9_]`.
#[test]
fn join_pending_cause_names_keep_the_registry_shape() {
    for valid in [
        "no_eligible_admin",
        "owner_certificate_pending",
        "crypto_only_gap",
        "a",
        &"a".repeat(64),
    ] {
        assert!(valid_join_pending_cause(valid), "{valid}");
    }
    for invalid in [
        "",
        &"a".repeat(65),
        "Crypto",
        "crypto-only",
        "crypto gap",
        "crypto.gap",
    ] {
        assert!(!valid_join_pending_cause(invalid), "{invalid}");
    }
}
