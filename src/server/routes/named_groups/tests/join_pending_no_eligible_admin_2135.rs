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
    seed_inviter_group_with(state, group_id, invite_secret, |_| {}).await;
}

/// [`seed_inviter_group`], with `adjust` applied to the group before it
/// is stored.
async fn seed_inviter_group_with(
    state: &AppState,
    group_id: &str,
    invite_secret: &str,
    adjust: impl FnOnce(&mut x0x::groups::GroupInfo),
) {
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
    adjust(&mut info);
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

/// Apply `joiner`'s self-delivered `MemberJoined` for `invite_secret` to
/// the local inviter (after `adjust_event`), and return whether a
/// `no_eligible_admin` notice was staged for its attempt. The admission
/// itself must be withheld.
async fn withheld_join_staged_notice(
    state: &Arc<AppState>,
    group_id: &str,
    joiner: &AgentKeypair,
    invite_secret: &str,
    adjust_event: impl FnOnce(&mut NamedGroupMetadataEvent),
) -> Result<bool> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let (joiner_id, joiner_hex, _, mut event) = signed_member_joined_event_for_test(
        joiner,
        group_id,
        &local_hex,
        invite_secret,
        x0x::groups::GroupRole::Member,
    )?;
    adjust_event(&mut event);
    let attempt = member_joined_event_attempt_id(&event).expect("attempt id");
    let result = Box::pin(apply_named_group_metadata_event_inner(
        state, event, joiner_id, true, true, None,
    ))
    .await;
    assert!(!result.accepted, "{invite_secret}: not admitted");
    Ok(staged_notice_cause(state, group_id, &joiner_hex, &attempt).is_some())
}

/// A banned joiner holding a live, unaddressed invite gets no notice: the
/// normal path refuses a banned agent (#1149), so the notice would tell a
/// banned peer the group's admin state.
#[tokio::test]
async fn a_banned_joiner_gets_no_notice() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "d6".repeat(32);
    let joiner = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    seed_inviter_group_with(&state, &group_id, "2135-banned", |info| {
        info.ban_member(&joiner_hex, Some(local_hex.clone()));
    })
    .await;
    revoke_agent(&state, state.agent.identity().agent_keypair()).await;
    assert!(
        !withheld_join_staged_notice(&state, &group_id, &joiner, "2135-banned", |_| {}).await?,
        "a banned joiner gets no notice"
    );
    Ok(())
}

/// The #1941 hold: while the group's revocation of lost re-seat invites is
/// pending, a targeted invite's redemption is refused as unknown, so its
/// holder gets no notice. Control: the same invite with no hold pending
/// stages the notice.
#[tokio::test]
async fn the_1941_unpaired_invite_hold_gets_no_notice() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    revoke_agent(&state, state.agent.identity().agent_keypair()).await;
    for (group_id, held) in [("d7".repeat(32), false), ("d8".repeat(32), true)] {
        let joiner = AgentKeypair::generate()?;
        let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
        seed_inviter_group_with(&state, &group_id, "2135-unused", |info| {
            info.record_issued_invite_v2(
                "2135-targeted".to_string(),
                now_millis_u64() / 1_000,
                0,
                x0x::groups::GroupRole::Member,
                Some(joiner_hex.clone()),
                x0x::groups::InviteOrigin::Explicit,
                None,
            );
        })
        .await;
        if held {
            group_recovery::mark_revoke_pending_for_test(&state, &group_id).await;
        }
        assert_eq!(
            withheld_join_staged_notice(&state, &group_id, &joiner, "2135-targeted", |_| {})
                .await?,
            !held,
            "held = {held}: a notice only when the #1941 hold does not apply"
        );
    }
    Ok(())
}

/// In an `OwnerCertified` group a joiner whose certificate does not chain
/// to the owner, or who carries none and has no evidence (NoCertificate),
/// gets no notice. Control: a certificate the owner issued stages it.
#[tokio::test]
async fn an_uncertified_joiner_gets_no_notice() -> Result<()> {
    use base64::Engine as _;
    let (state, _dir) = secure_endpoint_test_state().await?;
    let owner = x0x::identity::UserKeypair::generate()?;
    let stranger = x0x::identity::UserKeypair::generate()?;
    let group_id = "d9".repeat(32);
    let owner_id = owner.user_id();
    seed_inviter_group_with(&state, &group_id, "2135-unused", |info| {
        info.policy.admission = x0x::groups::GroupAdmission::OwnerCertified(owner_id);
        for secret in ["2135-oc-valid", "2135-oc-foreign", "2135-oc-none"] {
            info.record_issued_invite(
                secret.to_string(),
                now_millis_u64() / 1_000,
                0,
                x0x::groups::GroupRole::Member,
            );
        }
    })
    .await;
    revoke_agent(&state, state.agent.identity().agent_keypair()).await;

    let with_certificate = |certificate: Option<String>| {
        move |event: &mut NamedGroupMetadataEvent| {
            if let NamedGroupMetadataEvent::MemberJoined {
                certificate_b64, ..
            } = event
            {
                *certificate_b64 = certificate;
            }
        }
    };
    let encode = |cert: &x0x::identity::AgentCertificate| -> Result<String> {
        Ok(BASE64.encode(bincode::serialize(cert)?))
    };

    let joiner = AgentKeypair::generate()?;
    let cert = encode(&x0x::identity::AgentCertificate::issue(&owner, &joiner)?)?;
    assert!(
        withheld_join_staged_notice(
            &state,
            &group_id,
            &joiner,
            "2135-oc-valid",
            with_certificate(Some(cert))
        )
        .await?,
        "control: an owner-issued certificate stages the notice"
    );

    let joiner = AgentKeypair::generate()?;
    let cert = encode(&x0x::identity::AgentCertificate::issue(&stranger, &joiner)?)?;
    assert!(
        !withheld_join_staged_notice(
            &state,
            &group_id,
            &joiner,
            "2135-oc-foreign",
            with_certificate(Some(cert))
        )
        .await?,
        "a certificate from another user gets no notice"
    );

    let joiner = AgentKeypair::generate()?;
    assert!(
        !withheld_join_staged_notice(
            &state,
            &group_id,
            &joiner,
            "2135-oc-none",
            with_certificate(None)
        )
        .await?,
        "no certificate and no evidence (NoCertificate) gets no notice"
    );
    Ok(())
}

/// A consumed invite and an expired invite get no notice: the normal path
/// refuses both with a typed refusal, so their holders never learn the
/// group's admin state.
#[tokio::test]
async fn a_consumed_or_expired_invite_gets_no_notice() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "da".repeat(32);
    let now_secs = now_millis_u64() / 1_000;
    seed_inviter_group_with(&state, &group_id, "2135-consumed", |info| {
        assert!(info
            .consume_issued_invite(
                "2135-consumed",
                &"ab".repeat(32),
                x0x::groups::GroupRole::Member,
                now_millis_u64(),
                now_millis_u64(),
            )
            .is_ok());
        info.record_issued_invite(
            "2135-expired".to_string(),
            now_secs.saturating_sub(120),
            now_secs.saturating_sub(60),
            x0x::groups::GroupRole::Member,
        );
    })
    .await;
    revoke_agent(&state, state.agent.identity().agent_keypair()).await;
    for secret in ["2135-consumed", "2135-expired"] {
        let joiner = AgentKeypair::generate()?;
        assert!(
            !withheld_join_staged_notice(&state, &group_id, &joiner, secret, |_| {}).await?,
            "{secret}: no notice"
        );
    }
    Ok(())
}

/// The normal path's two silent rejects are mirrored: a joiner that is
/// already Active and presents another live invite, and a TreeKEM join
/// with no key package, get no notice.
#[tokio::test]
async fn an_active_joiner_or_a_treekem_join_without_key_package_gets_no_notice() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    revoke_agent(&state, state.agent.identity().agent_keypair()).await;

    let group_id = "db".repeat(32);
    let joiner = AgentKeypair::generate()?;
    let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
    seed_inviter_group_with(&state, &group_id, "2135-second", |info| {
        info.add_member(
            joiner_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(local_hex.clone()),
            None,
        );
        info.recompute_state_hash();
    })
    .await;
    assert!(
        !withheld_join_staged_notice(&state, &group_id, &joiner, "2135-second", |_| {}).await?,
        "an already Active joiner gets no notice"
    );

    let group_id = "dc".repeat(32);
    seed_inviter_group_with(&state, &group_id, "2135-treekem", |info| {
        info.secure_plane = x0x::mls::SecureGroupPlane::TreeKem;
    })
    .await;
    let joiner = AgentKeypair::generate()?;
    assert!(
        !withheld_join_staged_notice(&state, &group_id, &joiner, "2135-treekem", |_| {}).await?,
        "a TreeKEM join with no key package gets no notice"
    );
    Ok(())
}

/// Old peers keep working: the fetch a released (v0.46) joiner sends has
/// no §8 fields. Decoded from its exact JSON and answered by the authority
/// while a `no_eligible_admin` notice is staged for that attempt (and the
/// joiner's advert even sets the capability bit), it builds no `Pending`
/// reply. Control: the notice is servable to a capable fetch.
#[tokio::test]
async fn a_released_joiners_fetch_gets_no_pending_reply() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "dd".repeat(32);
    seed_inviter_group(&state, &group_id, "2135-legacy").await;
    revoke_agent(&state, state.agent.identity().agent_keypair()).await;
    let joiner = AgentKeypair::generate()?;
    let (joiner_id, joiner_hex, _, event) = signed_member_joined_event_for_test(
        &joiner,
        &group_id,
        &local_hex,
        "2135-legacy",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&event).expect("attempt id");
    let _ =
        apply_named_group_metadata_event_inner(&state, event, joiner_id, true, true, None).await;
    insert_notice_capable_advert(&state, &joiner_id);
    assert!(
        serve_staged_join_pending_notice(
            &state,
            &group_id,
            &joiner_hex,
            &attempt,
            &joiner_id,
            None,
            false
        )
        .await
        .is_some(),
        "control: the staged notice is servable to a capable fetch"
    );

    let legacy = format!(
        r#"{{"type":"fetch_request","group_id":"{group_id}","member_agent_id":"{joiner_hex}","accepts_refusal":true,"attempt_id":"{attempt}"}}"#
    );
    let JoinResultMessage::FetchRequest {
        group_id: fetched_group,
        member_agent_id,
        attempt_id,
        accepts_pending_notice,
        held_notice_hash,
        notice_only,
        attempt_evidence,
        ..
    } = serde_json::from_str::<JoinResultMessage>(&legacy)?
    else {
        panic!("the released joiner's fetch decodes as a FetchRequest");
    };
    let built = answer_join_pending_notice_fetch(
        &state,
        &joiner_id,
        &fetched_group,
        &member_agent_id,
        attempt_id.as_deref(),
        attempt_evidence.as_deref(),
        accepts_pending_notice,
        held_notice_hash.as_deref(),
        notice_only,
        None,
    )
    .await;
    assert!(!built, "a released joiner's fetch builds no Pending reply");
    Ok(())
}
