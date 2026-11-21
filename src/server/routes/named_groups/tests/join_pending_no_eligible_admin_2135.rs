//! #2135 (ADR 0108 §8 authority staging, D154; ADR 0110 §4): a joiner
//! whose admission the authority withholds because no eligible admin
//! remains is told so with the typed cause `no_eligible_admin`, on its
//! existing join-result poll. Decided by the orchestrator session under
//! A15, 21 Nov 2026.
//!
//! Red before the fix: the withheld `MemberJoined` staged nothing, so the
//! joiner's poll got no answer and its attempt timed out with
//! `no_admission_result`.

#![cfg(test)]

use super::*;
use x0x::identity::AgentKeypair;

/// Insert a verified self-revocation of `subject`.
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

/// A current verified advert for `agent` that sets `join_pending_notice_v1`.
fn insert_notice_capable_advert(state: &Arc<AppState>, agent: &AgentId) {
    let mut capabilities = x0x::dm::DmCapabilities::pending();
    capabilities.application_registry = x0x::dm::CapabilityRegistry {
        version: 1,
        bits: x0x::dm::CapabilityRegistry::JOIN_PENDING_NOTICE_V1,
    };
    assert!(
        state.agent.capability_store().insert(
            *agent,
            x0x::identity::MachineId([7u8; 32]),
            capabilities,
            now_millis_u64() + 1_000,
        ),
        "the advert inserts"
    );
}

/// A PublicOpen group whose sole admin seat is this node (the creator),
/// with one live Member invite `invite_secret`.
async fn seed_inviter_group(state: &AppState, group_id: &str, invite_secret: &str) {
    let mut info = x0x::groups::GroupInfo::with_policy(
        "2135".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_id.to_string(),
        x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
    );
    info.record_issued_invite(
        invite_secret.to_string(),
        now_millis_u64() / 1_000,
        0,
        x0x::groups::GroupRole::Member,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);
    assert!(save_named_groups(state).await);
}

fn staged_notice_cause(
    state: &AppState,
    group_id: &str,
    joiner_hex: &str,
    attempt_id: &str,
) -> Option<(
    &'static str,
    JoinPendingNoticeDetail,
    String,
    Option<String>,
)> {
    state
        .pending_join_notices
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&join_refusal_refusal_key(group_id, joiner_hex, attempt_id))
        .map(|notice| {
            (
                notice.cause,
                notice.detail.clone(),
                notice.signer_agent_id.clone(),
                notice.inviter_agent_id.clone(),
            )
        })
}

/// The withheld admission stages `no_eligible_admin` (no detail, signed by
/// the authority itself), and the joiner's capable poll is served the
/// signed `Pending` arm with that cause and no member key. The control
/// group, with an eligible admin, admits the joiner and stages nothing.
#[tokio::test]
async fn a_withheld_admission_stages_and_serves_no_eligible_admin() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());

    // Control: an eligible admin admits the joiner; no notice is staged.
    let control = "d1".repeat(32);
    seed_inviter_group(&state, &control, "2135-control").await;
    let joiner = AgentKeypair::generate()?;
    let (joiner_id, joiner_hex, _, event) = signed_member_joined_event_for_test(
        &joiner,
        &control,
        &local_hex,
        "2135-control",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&event).expect("attempt id");
    let result =
        apply_named_group_metadata_event_inner(&state, event, joiner_id, true, true, None).await;
    assert!(result.accepted, "control: the joiner is admitted");
    assert!(
        staged_notice_cause(&state, &control, &joiner_hex, &attempt).is_none(),
        "control: an admitted attempt has no pending notice"
    );

    // Every admin seat is revoked: admission is withheld and the cause is
    // staged for the joiner's attempt.
    let group_id = "d2".repeat(32);
    seed_inviter_group(&state, &group_id, "2135-held").await;
    revoke_agent(&state, state.agent.identity().agent_keypair()).await;
    let joiner = AgentKeypair::generate()?;
    let (joiner_id, joiner_hex, _, event) = signed_member_joined_event_for_test(
        &joiner,
        &group_id,
        &local_hex,
        "2135-held",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&event).expect("attempt id");
    let result =
        apply_named_group_metadata_event_inner(&state, event, joiner_id, true, true, None).await;
    assert!(
        !result.accepted,
        "no admission while no eligible admin remains"
    );
    assert_eq!(
        staged_notice_cause(&state, &group_id, &joiner_hex, &attempt),
        Some((
            "no_eligible_admin",
            JoinPendingNoticeDetail::default(),
            local_hex.clone(),
            Some(local_hex.clone()),
        )),
        "the authority stages no_eligible_admin, with no detail, signed by itself"
    );

    insert_notice_capable_advert(&state, &joiner_id);
    let served = serve_staged_join_pending_notice(
        &state,
        &group_id,
        &joiner_hex,
        &attempt,
        &joiner_id,
        None,
        false,
    )
    .await
    .expect("a capable joiner is served the notice");
    let Ok(JoinResultMessage::Pending { notice }) = serde_json::from_slice(&served) else {
        panic!("the served payload is the Pending arm");
    };
    assert_eq!(notice.cause, "no_eligible_admin");
    assert_eq!(notice.detail, JoinPendingNoticeDetail::default());
    assert_eq!(notice.signer_agent_id, local_hex);
    assert_eq!(notice.attempt_id, attempt);
    assert!(
        notice.signer_public_key_b64.is_none(),
        "the authority's own notice carries no member key"
    );
    Ok(())
}

/// The notice is bound to an attempt the withhold alone stops: an invite
/// secret this node never issued, or an invite addressed to another agent,
/// gets no notice, so an invalid invite never learns the group's state.
#[tokio::test]
async fn an_attempt_that_would_be_refused_gets_no_notice() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "d3".repeat(32);
    seed_inviter_group(&state, &group_id, "2135-real").await;
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group seeded");
        info.record_issued_invite_v2(
            "2135-addressed".to_string(),
            now_millis_u64() / 1_000,
            0,
            x0x::groups::GroupRole::Member,
            Some("ab".repeat(32)),
            x0x::groups::InviteOrigin::Explicit,
            None,
        );
    }
    revoke_agent(&state, state.agent.identity().agent_keypair()).await;
    for secret in ["2135-never-issued", "2135-addressed"] {
        let joiner = AgentKeypair::generate()?;
        let (joiner_id, joiner_hex, _, event) = signed_member_joined_event_for_test(
            &joiner,
            &group_id,
            &local_hex,
            secret,
            x0x::groups::GroupRole::Member,
        )?;
        let attempt = member_joined_event_attempt_id(&event).expect("attempt id");
        let result =
            apply_named_group_metadata_event_inner(&state, event, joiner_id, true, true, None)
                .await;
        assert!(!result.accepted, "{secret}: not admitted");
        assert!(
            staged_notice_cause(&state, &group_id, &joiner_hex, &attempt).is_none(),
            "{secret}: no notice for an attempt that would be refused"
        );
    }
    Ok(())
}

/// The cause clears when an eligible admin returns: the next poll-time
/// evaluation drops the staged notice (§8: a notice is dropped when its
/// cause clears).
#[tokio::test]
async fn the_notice_drops_when_an_eligible_admin_returns() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "d4".repeat(32);
    seed_inviter_group(&state, &group_id, "2135-clear").await;
    revoke_agent(&state, state.agent.identity().agent_keypair()).await;
    let joiner = AgentKeypair::generate()?;
    let (joiner_id, joiner_hex, _, event) = signed_member_joined_event_for_test(
        &joiner,
        &group_id,
        &local_hex,
        "2135-clear",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&event).expect("attempt id");
    let _ =
        apply_named_group_metadata_event_inner(&state, event, joiner_id, true, true, None).await;
    assert!(staged_notice_cause(&state, &group_id, &joiner_hex, &attempt).is_some());

    // The poll keeps the notice while the cover holds.
    evaluate_polled_join_pending_notice(&state, &group_id, &joiner_hex, Some(&attempt), None).await;
    assert!(
        staged_notice_cause(&state, &group_id, &joiner_hex, &attempt).is_some(),
        "the poll keeps the notice while no admin is eligible"
    );

    // A second, unrevoked admin seat ends the cover.
    let admin = AgentKeypair::generate()?;
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_id).expect("group seeded");
        info.add_member(
            hex::encode(admin.agent_id().as_bytes()),
            x0x::groups::GroupRole::Admin,
            Some(local_hex.clone()),
            None,
        );
        info.recompute_state_hash();
    }
    evaluate_polled_join_pending_notice(&state, &group_id, &joiner_hex, Some(&attempt), None).await;
    assert!(
        staged_notice_cause(&state, &group_id, &joiner_hex, &attempt).is_none(),
        "the notice drops once an eligible admin returns"
    );
    Ok(())
}

/// Old peers keep working. The wire gains no field: a v0.46 joiner's fetch
/// (no §8 fields) still decodes and never asks for a notice, and the
/// `no_eligible_admin` notice has exactly the field set of every other
/// authority-signed notice (the optional member key is omitted).
#[test]
fn the_old_fetch_shape_decodes_and_the_notice_adds_no_field() -> Result<()> {
    let legacy = serde_json::json!({
        "type": "fetch_request",
        "group_id": "d5".repeat(32),
        "member_agent_id": "ef".repeat(32),
        "accepts_refusal": true,
        "attempt_id": "at2135",
    });
    let decoded: JoinResultMessage = serde_json::from_value(legacy)?;
    let JoinResultMessage::FetchRequest {
        accepts_pending_notice,
        held_notice_hash,
        notice_only,
        attempt_evidence,
        ..
    } = decoded
    else {
        panic!("the legacy fetch decodes as a FetchRequest");
    };
    assert!(
        !accepts_pending_notice,
        "a legacy joiner never asks for a notice"
    );
    assert!(held_notice_hash.is_none() && !notice_only && attempt_evidence.is_none());

    let notice_keys = |cause: &str, detail: JoinPendingNoticeDetail| -> Result<Vec<String>> {
        let notice = JoinPendingNotice {
            group_id: "g".to_string(),
            member_agent_id: "m".to_string(),
            signer_agent_id: "s".to_string(),
            attempt_id: "a".to_string(),
            cause: cause.to_string(),
            detail,
            issued_at_ms: 1,
            nonce: "n".to_string(),
            signature_b64: String::new(),
            signer_public_key_b64: None,
        };
        let value = serde_json::to_value(JoinResultMessage::Pending {
            notice: Box::new(notice),
        })?;
        let mut keys: Vec<String> = value["notice"]
            .as_object()
            .map(|object| object.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();
        Ok(keys)
    };
    assert_eq!(
        notice_keys("no_eligible_admin", JoinPendingNoticeDetail::default())?,
        notice_keys("authority_catching_up", JoinPendingNoticeDetail::default())?,
        "the no_eligible_admin notice has the existing wire fields only"
    );
    Ok(())
}
