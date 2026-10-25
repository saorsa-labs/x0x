//! #1575 (ADR 0108 §8, David's 25 Oct 2026 05:14 GMT ruling): the signed
//! wire half of the join pending notice — the `JoinPendingNotice` message
//! (ML-DSA-65 over canonical bytes, domain
//! `x0x.named_group.join_pending.v1`), the `JoinResultMessage::Pending`
//! arm, the four `FetchRequest` notice fields, the
//! `join_pending_notice_v1` capability gate, and `pending_cause` on
//! `GET /groups/:id/join-status`.
//!
//! On main none of these exist: the tests are a compile failure there
//! (no such types). Here they prove §8's behaviours: signature domain
//! separation; forged, replayed, stale and mis-bound notices refused;
//! a staged Result or Refused superseding any Pending; capability-gated
//! serving with `held_notice_hash` dedup; and the joiner's held cause on
//! join-status.

use super::*;
use x0x::identity::AgentKeypair;

/// An unsigned notice body with §8's ten fields.
fn notice_body(
    group_id: &str,
    member_agent_id: &str,
    signer_agent_id: &str,
    attempt_id: &str,
    cause: &str,
    detail: JoinPendingNoticeDetail,
    issued_at_ms: u64,
) -> JoinPendingNotice {
    JoinPendingNotice {
        group_id: group_id.to_string(),
        member_agent_id: member_agent_id.to_string(),
        signer_agent_id: signer_agent_id.to_string(),
        attempt_id: attempt_id.to_string(),
        cause: cause.to_string(),
        detail,
        issued_at_ms,
        nonce: "5757".to_string(),
        signature_b64: String::new(),
        signer_public_key_b64: None,
    }
}

/// Sign a notice body with `signer`'s ML-DSA-65 key over its canonical
/// bytes, returning the carrying body.
fn signed_notice(mut notice: JoinPendingNotice, signer: &AgentKeypair) -> JoinPendingNotice {
    use base64::Engine as _;
    let canonical = canonical_join_pending_notice_bytes(&notice);
    let sig =
        ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(signer.secret_key(), &canonical)
            .expect("sign notice");
    notice.signature_b64 = BASE64.encode(sig.as_bytes());
    notice
}

/// §8: the canonical bytes are the domain-tagged, length-prefixed layout —
/// same facts ⇒ same bytes, every signed field participates, and the
/// domain keeps notice bytes disjoint from refusal-receipt bytes.
#[test]
fn canonical_notice_bytes_carry_the_domain_and_every_field() {
    let detail = JoinPendingNoticeDetail {
        count: Some(2),
        ..JoinPendingNoticeDetail::default()
    };
    let notice = notice_body(
        "g",
        "m",
        "s",
        "a1",
        "owner_certificate_pending",
        detail.clone(),
        123,
    );
    let bytes = canonical_join_pending_notice_bytes(&notice);
    assert!(
        bytes.starts_with(b"x0x.named_group.join_pending.v1"),
        "the domain tags the canonical bytes"
    );
    assert_eq!(
        bytes,
        canonical_join_pending_notice_bytes(&notice_body(
            "g",
            "m",
            "s",
            "a1",
            "owner_certificate_pending",
            JoinPendingNoticeDetail {
                count: Some(2),
                ..JoinPendingNoticeDetail::default()
            },
            123,
        )),
        "same facts ⇒ same canonical bytes"
    );
    for changed in [
        notice_body(
            "g2",
            "m",
            "s",
            "a1",
            "owner_certificate_pending",
            detail.clone(),
            123,
        ),
        notice_body(
            "g",
            "m2",
            "s",
            "a1",
            "owner_certificate_pending",
            detail.clone(),
            123,
        ),
        notice_body(
            "g",
            "m",
            "s2",
            "a1",
            "owner_certificate_pending",
            detail.clone(),
            123,
        ),
        notice_body(
            "g",
            "m",
            "s",
            "a2",
            "owner_certificate_pending",
            detail.clone(),
            123,
        ),
        notice_body(
            "g",
            "m",
            "s",
            "a1",
            "no_eligible_admin",
            detail.clone(),
            123,
        ),
        notice_body(
            "g",
            "m",
            "s",
            "a1",
            "no_eligible_admin",
            JoinPendingNoticeDetail::default(),
            123,
        ),
        notice_body(
            "g",
            "m",
            "s",
            "a1",
            "owner_certificate_pending",
            JoinPendingNoticeDetail {
                revision: Some(7),
                ..JoinPendingNoticeDetail::default()
            },
            123,
        ),
        notice_body(
            "g",
            "m",
            "s",
            "a1",
            "owner_certificate_pending",
            detail.clone(),
            124,
        ),
    ] {
        assert_ne!(
            bytes,
            canonical_join_pending_notice_bytes(&changed),
            "every signed field participates in the canonical bytes"
        );
    }
    // The two domains never produce the same bytes for identical bodies.
    let mut refusal_layout = Vec::new();
    refusal_layout.extend_from_slice(JOIN_REFUSAL_DOMAIN);
    assert_ne!(
        bytes[JOIN_PENDING_NOTICE_DOMAIN.len()..],
        refusal_layout,
        "notice bytes are disjoint from refusal-receipt bytes"
    );
}

/// Seed a joiner-side fixture: this node becomes the JOINER, holding a
/// stub group (the invite-committed base state: the inviter and any D154
/// signer seated Active, the joiner itself not) and one pending attempt
/// pinned to the inviter's key.
async fn seed_joiner_attempt(
    state: &Arc<AppState>,
    group_key: &str,
    attempt_id: &str,
    inviter: &AgentKeypair,
    member_signer: &AgentKeypair,
) -> (String, String) {
    let joiner_hex = hex::encode(state.agent.agent_id().as_bytes());
    let inviter_hex = hex::encode(inviter.agent_id().as_bytes());
    let signer_hex = hex::encode(member_signer.agent_id().as_bytes());
    let mut info = x0x::groups::GroupInfo::new(
        "1575w".to_string(),
        String::new(),
        inviter.agent_id(),
        group_key.to_string(),
    );
    info.migrate_from_v1();
    let _ = info.rotate_shared_secret();
    info.add_member(
        inviter_hex.clone(),
        x0x::groups::GroupRole::Admin,
        None,
        None,
    );
    info.add_member(signer_hex, x0x::groups::GroupRole::Member, None, None);
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_key.to_string(), info);
    let stable = {
        let groups = state.named_groups.read().await;
        groups
            .get(group_key)
            .expect("stub installed")
            .stable_group_id()
            .to_string()
    };
    record_expected_join_result_inviter(state, join_result_key(&stable, &joiner_hex), inviter_hex);
    use base64::Engine as _;
    state
        .pending_join_attempts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            join_result_key(&stable, &joiner_hex),
            PendingJoinAttempt {
                attempt_id: attempt_id.to_string(),
                local_group_key: group_key.to_string(),
                invite_fingerprint: "1575w".to_string(),
                invite_group_id: stable,
                inviter_public_key_b64: BASE64.encode(inviter.public_key().as_bytes()),
                stored_resend: None,
                polls: Vec::new(),
                tasks: Vec::new(),
                listener_token: None,
                held_pending_notice: None,
            },
        );
    (group_key.to_string(), attempt_id.to_string())
}

/// §8 Joiner: the acceptance checklist. A notice signed by the pinned
/// authority is held; forged (another key), replayed past the lifetime,
/// future-skewed, mis-bound (another attempt or member), unverified and
/// domain-swapped signatures are refused; the D154 member-signed cause is
/// held only from an Active stub-roster seat; older notices are ignored.
#[tokio::test]
async fn joiner_holds_only_verified_current_notices() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let inviter = AgentKeypair::generate()?;
    let member_signer = AgentKeypair::generate()?;
    let group_key = "7d".repeat(32);
    let attempt_id = "at1575w1".to_string();
    seed_joiner_attempt(&state, &group_key, &attempt_id, &inviter, &member_signer).await;
    let joiner_hex = hex::encode(state.agent.agent_id().as_bytes());
    let inviter_hex = hex::encode(inviter.agent_id().as_bytes());
    let detail = JoinPendingNoticeDetail {
        count: Some(2),
        ..JoinPendingNoticeDetail::default()
    };
    let now = now_millis_u64();

    // Unverified ingress is refused even with a perfect signature.
    let good = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            detail.clone(),
            now,
        ),
        &inviter,
    );
    assert!(
        !verify_and_hold_join_pending_notice(&state, false, &good).await,
        "no notice over unverified ingress"
    );

    // The pinned authority's notice is held.
    assert!(
        verify_and_hold_join_pending_notice(&state, true, &good).await,
        "the authority-signed notice is held"
    );
    {
        let attempts = state
            .pending_join_attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let held = attempts
            .values()
            .find_map(|attempt| attempt.held_pending_notice.clone())
            .expect("held");
        assert_eq!(held.cause, "owner_certificate_pending");
        assert_eq!(held.detail, detail);
        assert_eq!(held.signer_agent_id, inviter_hex);
    }

    // A FORGED signature (a different key) is refused, and the held
    // notice survives it.
    let forger = AgentKeypair::generate()?;
    let forged = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            detail.clone(),
            now + 1_000,
        ),
        &forger,
    );
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &forged).await,
        "a forged signature is refused"
    );

    // Domain separation end to end: the same signer over the SAME layout
    // under the refusal-receipt domain does not verify as a notice.
    let mut swapped = notice_body(
        &group_key,
        &joiner_hex,
        &inviter_hex,
        &attempt_id,
        "owner_certificate_pending",
        detail.clone(),
        now + 2_000,
    );
    {
        use base64::Engine as _;
        let canonical = canonical_join_pending_notice_bytes(&swapped);
        let mut refusal_domain_bytes =
            Vec::with_capacity(JOIN_REFUSAL_DOMAIN.len() + canonical.len());
        refusal_domain_bytes.extend_from_slice(JOIN_REFUSAL_DOMAIN);
        refusal_domain_bytes.extend_from_slice(&canonical[JOIN_PENDING_NOTICE_DOMAIN.len()..]);
        let sig = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
            inviter.secret_key(),
            &refusal_domain_bytes,
        )
        .expect("sign swapped-domain bytes");
        swapped.signature_b64 = BASE64.encode(sig.as_bytes());
    }
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &swapped).await,
        "a signature over refusal-domain bytes does not verify as a notice"
    );

    // A REPLAY past the 10-minute lifetime is refused, and so is a notice
    // dated too far ahead (§8 freshness).
    let stale = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            detail.clone(),
            now.saturating_sub(PENDING_JOIN_RESULT_TTL.as_millis() as u64 + 1),
        ),
        &inviter,
    );
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &stale).await,
        "a replayed notice past the lifetime is refused"
    );
    let future = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            detail.clone(),
            now + 301_000,
        ),
        &inviter,
    );
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &future).await,
        "a notice dated beyond the 300 s future skew is refused"
    );

    // A notice for ANOTHER attempt never moves this one.
    let other_attempt = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            "another-attempt",
            "owner_certificate_pending",
            detail.clone(),
            now + 3_000,
        ),
        &inviter,
    );
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &other_attempt).await,
        "a notice bound to another attempt is refused"
    );

    // D154: a member-signed `no_eligible_admin` notice from an Active
    // stub-roster seat is held (newer replaces the held authority notice).
    let signer_hex = hex::encode(member_signer.agent_id().as_bytes());
    let mut member_signed = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &signer_hex,
            &attempt_id,
            "no_eligible_admin",
            JoinPendingNoticeDetail::default(),
            now + 4_000,
        ),
        &member_signer,
    );
    use base64::Engine as _;
    member_signed.signer_public_key_b64 =
        Some(BASE64.encode(member_signer.public_key().as_bytes()));
    assert!(
        verify_and_hold_join_pending_notice(&state, true, &member_signed).await,
        "a member-signed D154 notice from an Active seat is held"
    );

    // The same signer with a non-D154 cause is refused (only the pinned
    // authority may sign any other cause).
    let mut other_cause = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &signer_hex,
            &attempt_id,
            "owner_certificate_pending",
            detail.clone(),
            now + 5_000,
        ),
        &member_signer,
    );
    other_cause.signer_public_key_b64 = Some(BASE64.encode(member_signer.public_key().as_bytes()));
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &other_cause).await,
        "a non-D154 cause from a signer other than the pinned authority is refused"
    );

    // A member-signed notice whose signer lost the Active stub-roster seat
    // is refused.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_key).expect("group kept");
        info.remove_member(&signer_hex, None);
        info.recompute_state_hash();
    }
    let mut gone_seat = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &signer_hex,
            &attempt_id,
            "no_eligible_admin",
            JoinPendingNoticeDetail::default(),
            now + 6_000,
        ),
        &member_signer,
    );
    gone_seat.signer_public_key_b64 = Some(BASE64.encode(member_signer.public_key().as_bytes()));
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &gone_seat).await,
        "a member-signed notice with no Active stub-roster seat is refused"
    );

    // §8 newest-first: an OLDER authority notice never displaces the held
    // newer one.
    let older = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            detail,
            now + 1_500,
        ),
        &inviter,
    );
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &older).await,
        "an older notice is ignored"
    );
    Ok(())
}

/// §8 serving: the staged notice is served as `Pending` ONLY to a joiner
/// whose current verified advert sets `join_pending_notice_v1`, once per
/// change (`held_notice_hash` dedup, cached signature), never beside a
/// staged Result or Refused, and a notice-only request is answered with
/// the member-signed D154 cause alone.
#[tokio::test]
async fn notice_serving_is_capability_gated_and_once_per_change() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let inviter = AgentKeypair::generate()?;
    let group_key = "7e".repeat(32);
    let (_, _, _, joined_event) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &hex::encode(state.agent.agent_id().as_bytes()),
        "1575w-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&joined_event).expect("attempt id");
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
        JoinPendingNoticeDetail {
            count: Some(2),
            ..JoinPendingNoticeDetail::default()
        },
        Some(hex::encode(inviter.agent_id().as_bytes())),
    )
    .await;

    // No advert at all: nothing served.
    assert!(
        serve_staged_join_pending_notice(
            &state,
            &group_key,
            &joiner_hex,
            &attempt,
            &joiner_id,
            None,
            false,
        )
        .await
        .is_none(),
        "an unknown advert serves nothing"
    );

    // A current verified advert WITHOUT the bit: nothing served.
    insert_verified_advert(&state, &joiner_id, 0).await;
    assert!(
        serve_staged_join_pending_notice(
            &state,
            &group_key,
            &joiner_hex,
            &attempt,
            &joiner_id,
            None,
            false,
        )
        .await
        .is_none(),
        "an advert without join_pending_notice_v1 serves nothing"
    );

    // With the bit: the Pending arm is served and decodes.
    insert_verified_advert(
        &state,
        &joiner_id,
        x0x::dm::CapabilityRegistry::JOIN_PENDING_NOTICE_V1,
    )
    .await;
    let served = serve_staged_join_pending_notice(
        &state,
        &group_key,
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
    assert_eq!(notice.cause, "owner_certificate_pending");
    assert_eq!(notice.detail.count, Some(2));
    assert_eq!(
        notice.signer_agent_id,
        hex::encode(state.agent.agent_id().as_bytes())
    );
    assert!(
        notice.signer_public_key_b64.is_none(),
        "the authority-signed S2 cause carries no signer key"
    );

    // The signature verifies and is CACHED (the same bytes re-serve).
    let signer_key = ant_quic::MlDsaPublicKey::from_bytes(
        state
            .agent
            .identity()
            .agent_keypair()
            .public_key()
            .as_bytes(),
    )
    .expect("local key");
    let canonical = canonical_join_pending_notice_bytes(&notice);
    use base64::Engine as _;
    let sig = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(
        &BASE64.decode(&notice.signature_b64).expect("sig"),
    )
    .expect("sig");
    assert!(
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&signer_key, &canonical, &sig)
            .is_ok(),
        "the served notice verifies under the signer's key"
    );
    let again = serve_staged_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        &joiner_id,
        None,
        false,
    )
    .await
    .expect("re-served without a held hash");
    let Ok(JoinResultMessage::Pending {
        notice: again_notice,
    }) = serde_json::from_slice(&again)
    else {
        panic!("re-served Pending");
    };
    assert_eq!(
        again_notice.signature_b64, notice.signature_b64,
        "the lazy signature is cached until the cause or detail changes"
    );

    // held_notice_hash dedup: the joiner already holds exactly these
    // canonical bytes — nothing is sent.
    let held = join_pending_notice_hash(&notice);
    assert!(
        serve_staged_join_pending_notice(
            &state,
            &group_key,
            &joiner_hex,
            &attempt,
            &joiner_id,
            Some(&held),
            false,
        )
        .await
        .is_none(),
        "a joiner holding the notice's hash is re-served nothing"
    );

    // A notice-only request is answered with the D154 cause alone — never
    // the S2 cause.
    assert!(
        serve_staged_join_pending_notice(
            &state,
            &group_key,
            &joiner_hex,
            &attempt,
            &joiner_id,
            None,
            true,
        )
        .await
        .is_none(),
        "a notice-only request never answers the S2 cause"
    );

    // §8 order: a staged Refused for the attempt replaces the notice, so
    // nothing Pending can be served; the same for a staged Result.
    stage_join_refusal(
        &state,
        &group_key,
        &joiner_hex,
        &joined_event,
        JoinRefusalReason::InviteExpired,
    )
    .await;
    assert!(
        serve_staged_join_pending_notice(
            &state,
            &group_key,
            &joiner_hex,
            &attempt,
            &joiner_id,
            None,
            false,
        )
        .await
        .is_none(),
        "a staged Refused supersedes the Pending notice"
    );
    // Clear the refusal so the notice can restage, then prove the Result
    // arm supersedes it too.
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
        JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
        JoinPendingNoticeDetail {
            count: Some(1),
            ..JoinPendingNoticeDetail::default()
        },
        Some(hex::encode(inviter.agent_id().as_bytes())),
    )
    .await;
    stage_join_result(
        &state,
        &group_key,
        &joiner_hex,
        joined_event.clone(),
        Some(&attempt),
    )
    .await;
    assert!(
        serve_staged_join_pending_notice(
            &state,
            &group_key,
            &joiner_hex,
            &attempt,
            &joiner_id,
            None,
            false,
        )
        .await
        .is_none(),
        "a staged Result supersedes the Pending notice"
    );
    Ok(())
}

/// §8 (D154): a notice-only fetch stages the member-signed cause through
/// the handler exactly like a normal evidence-bound poll, and — being
/// notice-only — never probes the staged refusal.
#[tokio::test]
async fn notice_only_polls_stage_the_d154_cause() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let admin = AgentKeypair::generate()?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "7f".repeat(32);
    let mut info = x0x::groups::GroupInfo::new(
        "1575w".to_string(),
        String::new(),
        admin.agent_id(),
        group_key.to_string(),
    );
    info.migrate_from_v1();
    let _ = info.rotate_shared_secret();
    info.add_member(
        hex::encode(state.agent.agent_id().as_bytes()),
        x0x::groups::GroupRole::Member,
        None,
        None,
    );
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), info);
    // D154 cover: every admin seat revoked.
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(admin.agent_id()),
        admin.public_key(),
        admin.secret_key(),
        now_millis_u64() / 1_000,
        Some("test".to_string()),
    )
    .expect("sign revocation");
    assert!(state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, None)
        .expect("self-revocation verifies"));
    let (_, _, _, evidence) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &hex::encode(state.agent.agent_id().as_bytes()),
        "1575w-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&evidence).expect("attempt id");

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
            attempt_id: Some(attempt.clone()),
            accepts_pending_notice: true,
            held_notice_hash: None,
            notice_only: true,
            attempt_evidence: Some(Box::new(evidence)),
        },
    )
    .await;
    let notice = staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt)
        .expect("the notice-only evidence-bound poll stages the D154 notice");
    assert_eq!(notice.0, "no_eligible_admin");
    Ok(())
}

/// §8: `GET /groups/:id/join-status` shows `pending_cause` while the
/// attempt is pending and holds a verified notice; an unknown
/// well-formed cause displays as `unrecognized_cause` with the raw name;
/// with no held notice the field is null.
#[tokio::test]
async fn join_status_reports_the_held_pending_cause() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let inviter = AgentKeypair::generate()?;
    let member_signer = AgentKeypair::generate()?;
    let group_key = "731".repeat(10);
    let attempt_id = "at1575w2".to_string();
    let _ = seed_joiner_attempt(&state, &group_key, &attempt_id, &inviter, &member_signer).await;
    let joiner_hex = hex::encode(state.agent.agent_id().as_bytes());
    let inviter_hex = hex::encode(inviter.agent_id().as_bytes());
    let now = now_millis_u64();

    // No held notice: pending, but pending_cause is null.
    let (code, body) = join_status_body(&state, &group_key).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["join_state"], "pending_authority_commit");
    assert!(
        body.get("pending_cause")
            .is_none_or(|cause| cause.is_null()),
        "no pending_cause without a held notice"
    );

    // Hold an authority-signed notice: pending_cause carries §8's shape.
    let notice = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            JoinPendingNoticeDetail {
                count: Some(3),
                ..JoinPendingNoticeDetail::default()
            },
            now,
        ),
        &inviter,
    );
    let issued = notice.issued_at_ms;
    assert!(verify_and_hold_join_pending_notice(&state, true, &notice).await);
    let (code, body) = join_status_body(&state, &group_key).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["join_state"], "pending_authority_commit");
    assert_eq!(body["pending_cause"]["cause"], "owner_certificate_pending");
    assert_eq!(body["pending_cause"]["detail"]["count"], 3);
    assert_eq!(body["pending_cause"]["issued_at_ms"], issued);
    assert_eq!(body["pending_cause"]["signer_agent_id"], inviter_hex);

    // An unknown well-formed cause is displayed as unrecognized_cause with
    // the raw name — never a decode failure (§8).
    let unknown = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "future_slice_cause",
            JoinPendingNoticeDetail::default(),
            now + 1_000,
        ),
        &inviter,
    );
    assert!(verify_and_hold_join_pending_notice(&state, true, &unknown).await);
    let (_code, body) = join_status_body(&state, &group_key).await;
    assert_eq!(body["pending_cause"]["cause"], "unrecognized_cause");
    assert_eq!(body["pending_cause"]["raw_cause"], "future_slice_cause");
    Ok(())
}

/// A current VERIFIED advert for `agent` whose registry carries exactly
/// `bits`. Each insert mints a strictly newer signed timestamp, so the
/// store's last-write-wins ordering accepts the sequence.
static ADVERT_TS_BUMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
async fn insert_verified_advert(state: &Arc<AppState>, agent: &AgentId, bits: u64) {
    let mut capabilities = x0x::dm::DmCapabilities::pending();
    capabilities.application_registry = x0x::dm::CapabilityRegistry { version: 1, bits };
    let created_at =
        now_millis_u64() + 1_000 + ADVERT_TS_BUMP.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    assert!(
        state.agent.capability_store().insert(
            *agent,
            x0x::identity::MachineId([7u8; 32]),
            capabilities,
            created_at,
        ),
        "the advert inserts"
    );
}
