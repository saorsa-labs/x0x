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
//! join-status. The PR #1639 review round 3 additions: a notice-only
//! fetch never yields a Result or Refused and never admits or seats; the
//! unknown-advert capability refresh publishes only for a staged notice,
//! through the single-flight registry; and a notice past its issued-at
//! lifetime is not served.

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
    // The nonce and the detail digests participate too — the two fields the
    // per-field sweep above cannot reach (every body there shares one
    // nonce and no digests).
    let mut other_nonce = notice_body(
        "g",
        "m",
        "s",
        "a1",
        "owner_certificate_pending",
        detail.clone(),
        123,
    );
    other_nonce.nonce = "5758".to_string();
    assert_ne!(
        bytes,
        canonical_join_pending_notice_bytes(&other_nonce),
        "the nonce participates in the canonical bytes"
    );
    let with_digests = notice_body(
        "g",
        "m",
        "s",
        "a1",
        "owner_certificate_pending",
        JoinPendingNoticeDetail {
            digests: vec!["ab".repeat(64)],
            ..detail.clone()
        },
        123,
    );
    assert_ne!(
        bytes,
        canonical_join_pending_notice_bytes(&with_digests),
        "the detail digests participate in the canonical bytes"
    );
    // Frozen vector (PR #1639 review round 3): the exact canonical bytes
    // for a fixed body — any layout change (field order, prefix width,
    // domain) breaks this line. Decoded by hand once: the domain tag, then
    // the length-prefixed group/member/signer/attempt/cause strings, the
    // presence-byte count, the absent revision, the empty digests vector,
    // the u64-BE issued_at_ms (123) and the length-prefixed nonce "5757".
    assert_eq!(
        hex::encode(&bytes),
        "7830782e6e616d65645f67726f75702e6a6f696e5f70656e64696e672e7631\
         0000000167000000016d0000000173000000026131000000196f776e65725f\
         63657274696669636174655f70656e64696e67010000000200000000000000\
         00000000007b0000000435373537"
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

    // A notice past its lifetime is refused BEFORE anything is held, so the
    // freshness check alone carries the rejection — the newest-first rule
    // below has nothing to compare against yet (PR #1639 review round 3:
    // the replay case further down is also older than the held notice, so
    // it alone could not prove the freshness check).
    let stale_first = signed_notice(
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
        !verify_and_hold_join_pending_notice(&state, true, &stale_first).await,
        "a stale notice is refused with nothing held (freshness carries it)"
    );

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

    // D154 (review finding 1): a member-signed `no_eligible_admin` notice
    // is DROPPED in this slice. The joiner polls only its authority, so one
    // can arrive only unsolicited; §8's "Current notice" rule keeps the
    // authority's notice current while it polls, and the D154 notice-only
    // rotation slice owns member-signed acceptance. The held authority
    // notice survives.
    let signer_hex = hex::encode(member_signer.agent_id().as_bytes());
    use base64::Engine as _;
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
    member_signed.signer_public_key_b64 =
        Some(BASE64.encode(member_signer.public_key().as_bytes()));
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &member_signed).await,
        "an unsolicited member-signed D154 notice is dropped in this slice"
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
        assert_eq!(
            held.signer_agent_id, inviter_hex,
            "the held notice is still the authority's"
        );
    }

    // §8 newest-first: a NEWER authority notice replaces the held one, and
    // an OLDER one is then ignored.
    let newer = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            detail.clone(),
            now + 5_000,
        ),
        &inviter,
    );
    assert!(
        verify_and_hold_join_pending_notice(&state, true, &newer).await,
        "a newer authority notice replaces the held one"
    );
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

/// §8 (D154, PR #1639 review round 3, finding 2): a notice-only fetch
/// never yields a Result or a Refused and cannot admit or seat. With a
/// staged Result for the member AND a retained owner-certificate join the
/// shielded retry would consume, the notice-only poll sends nothing (both
/// egress gates stay closed) and leaves both untouched. The normal fetch
/// beside it proves both observables are live: it runs the retry (the
/// malformed retention is removed) and serves the staged Result. The
/// poll-side D154 staging is off until the rotation slice (engineer
/// ruling, 27 Oct 2026), so nothing stages either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notice_only_fetches_never_yield_a_result_or_seat_a_member() -> Result<()> {
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
    // Seat the joiner Active so the eligibility re-check on the staged
    // Result below would PASS: if the notice-only early return were gone,
    // the fetch would fall through and SERVE that Result (caught by the
    // armed `join_result` egress gate).
    info.add_member(
        joiner_hex.clone(),
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
    let (_, _, _, evidence) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &hex::encode(state.agent.agent_id().as_bytes()),
        "1575w-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&evidence).expect("attempt id");
    // A staged Result for the member — the terminal admission answer the
    // fall-through path would serve, roster and all.
    stage_join_result(
        &state,
        &group_key,
        &joiner_hex,
        evidence.clone(),
        Some(&attempt),
    )
    .await;
    // A retained owner-certificate join whose member id does not parse: the
    // shielded retry removes exactly this shape when it runs (a run also
    // re-applies retained events, which can seat).
    let malformed_member = "zz-not-an-agent-id";
    state.owner_cert_pending_joins.write().await.insert(
        join_result_key(&group_key, malformed_member),
        PendingOwnerCertJoin {
            group_id: group_key.clone(),
            event_group_key: group_key.clone(),
            member_agent_id: malformed_member.to_string(),
            event: evidence.clone(),
            retained_at: std::time::Instant::now(),
        },
    );

    // The notice-only fetch: verified, evidence-bound, refusal-capable —
    // every temptation — sends NOTHING and runs neither the retry nor the
    // Result lookup.
    let armed_result = join_egress_test_barrier::arm(&joiner_hex, "join_result");
    let armed_response = join_egress_test_barrier::arm(&joiner_hex, "join_result_response");
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
            attempt_evidence: Some(Box::new(evidence.clone())),
        },
    )
    .await;
    assert!(
        !armed_result.gate.reached(),
        "a notice-only fetch never yields a Result"
    );
    assert!(
        !armed_response.gate.reached(),
        "a notice-only fetch never yields a Refused (or any other reply)"
    );
    drop(armed_result);
    drop(armed_response);
    assert!(
        state
            .owner_cert_pending_joins
            .read()
            .await
            .contains_key(&join_result_key(&group_key, malformed_member)),
        "a notice-only fetch skips the owner-certificate retry (no admit, no seat)"
    );
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt).is_none(),
        "nothing stages on a notice-only fetch until the rotation slice"
    );

    // Control: the SAME fetch shape without notice_only runs the retry (the
    // malformed retention is removed) and serves the staged Result (the
    // egress gate is reached, then released).
    let armed_result = join_egress_test_barrier::arm(&joiner_hex, "join_result");
    let control_state = Arc::clone(&state);
    let control_joiner = joiner_id;
    let control_group = group_key.clone();
    let control_attempt = attempt.clone();
    let control = tokio::spawn(async move {
        handle_join_result_message(
            &control_state,
            &control_joiner,
            true,
            JoinResultMessage::FetchRequest {
                group_id: control_group.clone(),
                member_agent_id: hex::encode(control_joiner.as_bytes()),
                from_revision: None,
                base_state_hash: None,
                accepts_refusal: true,
                accepts_control_blob_ref: false,
                attempt_id: Some(control_attempt),
                accepts_pending_notice: true,
                held_notice_hash: None,
                notice_only: false,
                attempt_evidence: None,
            },
        )
        .await;
    });
    let mut control_reached = false;
    for _ in 0..200 {
        if armed_result.gate.reached() {
            control_reached = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        control_reached,
        "the control fetch reaches the Result send point"
    );
    drop(armed_result);
    control.await.expect("the control fetch completes");
    assert!(
        !state
            .owner_cert_pending_joins
            .read()
            .await
            .contains_key(&join_result_key(&group_key, malformed_member)),
        "the control fetch runs the owner-certificate retry"
    );
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
    assert!(
        body["pending_cause"].get("raw_cause").is_none(),
        "raw_cause is omitted for a known cause"
    );

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

/// PR #1639 review round 2 (blocking): the `Pending` reply must be SENT
/// outside the group's membership critical section — a direct send waits
/// out its full ack timeout and would stall every other lock user (seat
/// applies, seals, other joiners' fetches) for that group. The payload is
/// built under the lock (local work + the one lazy signature, like the
/// refusal path), the lock is released, and only then does the send run.
/// The deterministic proof parks the handler at the send point through the
/// egress test barrier and takes the group's membership mutex while it is
/// parked: with the send under the lock, `try_lock` fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pending_reply_is_sent_outside_the_membership_section() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "732".repeat(10);
    let admin = AgentKeypair::generate()?;
    {
        let mut info = x0x::groups::GroupInfo::new(
            "1575w".to_string(),
            String::new(),
            admin.agent_id(),
            group_key.clone(),
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
    }
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
            count: Some(1),
            ..JoinPendingNoticeDetail::default()
        },
        None,
    )
    .await;
    insert_verified_advert(
        &state,
        &joiner_id,
        x0x::dm::CapabilityRegistry::JOIN_PENDING_NOTICE_V1,
    )
    .await;

    let armed = join_egress_test_barrier::arm(&joiner_hex, "join_pending_notice");
    let handler_state = Arc::clone(&state);
    let handler_joiner = joiner_id;
    let handler_group = group_key.clone();
    let handler = tokio::spawn(async move {
        handle_join_result_message(
            &handler_state,
            &handler_joiner,
            true,
            JoinResultMessage::FetchRequest {
                group_id: handler_group.clone(),
                member_agent_id: joiner_hex.clone(),
                from_revision: None,
                base_state_hash: None,
                accepts_refusal: true,
                accepts_control_blob_ref: false,
                attempt_id: Some(attempt.clone()),
                accepts_pending_notice: true,
                held_notice_hash: None,
                notice_only: false,
                attempt_evidence: None,
            },
        )
        .await;
    });
    // Wait until the handler is parked AT the send point.
    let mut parked_at_send = false;
    for _ in 0..200 {
        if armed.gate.reached() {
            parked_at_send = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        parked_at_send,
        "the handler never reached the notice send point"
    );
    // While the send is pending, the group's membership mutex must be FREE.
    let membership_arc = group_membership_lock_for_known_group(&state, &group_key)
        .await
        .expect("the group has a membership lock");
    let lock_free_while_sending = membership_arc.try_lock().is_ok();
    drop(armed);
    handler
        .await
        .expect("the handler completes once the gate releases");
    assert!(
        lock_free_while_sending,
        "the Pending reply send held the group's membership critical section"
    );
    Ok(())
}

/// §8 (D154, #1628 review item 2, PR #1639 review round 3): the
/// attempt-evidence check rejects a mismatched group, a mismatched member,
/// an attempt id that is not the event's blake3 and a tampered signature;
/// only the joiner's own signed `MemberJoined` bound to this group, member
/// and attempt verifies. The check proves exactly §8's minimum — the event
/// is self-consistently signed by the sender's own key — and no more,
/// which is why the D154 staging stays off until the rotation slice binds
/// the evidence to a real invite or attempt.
#[test]
fn attempt_evidence_verification_rejects_mismatches() -> Result<()> {
    let inviter = AgentKeypair::generate()?;
    let joiner = AgentKeypair::generate()?;
    let other = AgentKeypair::generate()?;
    let group_key = "734".repeat(10);
    let inviter_hex = hex::encode(inviter.agent_id().as_bytes());
    let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
    let (_, _, _, evidence) = signed_member_joined_event_for_test(
        &joiner,
        &group_key,
        &inviter_hex,
        "1575w-secret",
        x0x::groups::GroupRole::Member,
    )?;
    let attempt = member_joined_event_attempt_id(&evidence).expect("attempt id");

    // The joiner's own evidence verifies and names the inviter.
    assert_eq!(
        verified_join_attempt_evidence(&group_key, &joiner_hex, &attempt, &evidence),
        Some(inviter_hex.clone()),
        "the joiner's own signed event is evidence"
    );
    // A different group.
    assert_eq!(
        verified_join_attempt_evidence(&"72".repeat(32), &joiner_hex, &attempt, &evidence),
        None,
        "an event for another group is not evidence here"
    );
    // A different member.
    assert_eq!(
        verified_join_attempt_evidence(
            &group_key,
            &hex::encode(other.agent_id().as_bytes()),
            &attempt,
            &evidence
        ),
        None,
        "another member's event is not evidence"
    );
    // An attempt id that is not the event's blake3.
    assert_eq!(
        verified_join_attempt_evidence(&group_key, &joiner_hex, "not-the-attempt", &evidence),
        None,
        "the attempt id must be the event's blake3"
    );
    // A tampered signature: the attempt id is the blake3 of the canonical
    // bytes AND the raw signature, so any tamper breaks the binding.
    let mut tampered = evidence.clone();
    match &mut tampered {
        NamedGroupMetadataEvent::MemberJoined { signature_b64, .. } => {
            let mut bytes = signature_b64.clone().into_bytes();
            let last = bytes.last_mut().expect("non-empty signature");
            *last = if *last == b'A' { b'B' } else { b'A' };
            *signature_b64 = String::from_utf8(bytes).expect("utf8");
        }
        _ => panic!("the evidence is a MemberJoined"),
    }
    assert_eq!(
        verified_join_attempt_evidence(&group_key, &joiner_hex, &attempt, &tampered),
        None,
        "a tampered signature does not verify"
    );
    Ok(())
}

/// §8 (PR #1639 review round 3, finding 4): a staged notice is served only
/// inside its issued-at lifetime. A restage refreshes the staging clock but
/// never `issued_at_ms`, so a notice whose issued-at clock has run past the
/// 10-minute lifetime is not served even though its row is young — the
/// joiner would drop it as stale.
#[tokio::test]
async fn a_notice_past_its_issued_lifetime_is_not_served() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "735".repeat(10);
    let attempt = "at1575-lifetime".to_string();
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
        JoinPendingNoticeDetail::default(),
        None,
    )
    .await;
    insert_verified_advert(
        &state,
        &joiner_id,
        x0x::dm::CapabilityRegistry::JOIN_PENDING_NOTICE_V1,
    )
    .await;
    // A young row whose issued-at clock is past the lifetime: backdate
    // `issued_at_ms` only (the staging clock stays fresh — exactly the
    // refire shape, where every poll restages the row but the joiner's
    // freshness clock keeps running).
    {
        let mut notices = state
            .pending_join_notices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        notices
            .get_mut(&join_refusal_refusal_key(&group_key, &joiner_hex, &attempt))
            .expect("staged notice")
            .issued_at_ms =
            now_millis_u64().saturating_sub(PENDING_JOIN_RESULT_TTL.as_millis() as u64 + 1);
    }
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
        "a notice past its issued-at lifetime is not served"
    );
    Ok(())
}

/// §8 (PR #1639 review round 3, finding 1): an unknown advert refreshes
/// through the shared single-flight registry ONLY when a notice for the
/// fetched attempt is actually staged — a verified fetch for an unknown
/// group, or a known group with no staged notice, publishes nothing on the
/// targeted capability request topic. With a staged notice the refresh
/// fires once, and immediate re-polls inside the single-flight window
/// publish nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_capability_refresh_publishes_only_for_a_staged_notice() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let loopback_addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    // Hermetic plane (the hs_f2 pattern): loopback bind, no bootstrap, no
    // mDNS, no port mapping, a network id unique to this run — the node
    // has nothing to dial and nothing to discover.
    let network_id = format!(
        "1575-refresh-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let agent = Arc::new(
        Agent::builder()
            .with_machine_key(dir.path().join("machine.key"))
            .with_agent_key_path(dir.path().join("agent.key"))
            .with_agent_cert_path(dir.path().join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(dir.path().join("contacts.json"))
            .with_network_config(x0x::network::NetworkConfig {
                bind_addr: Some(loopback_addr),
                bootstrap_nodes: Vec::new(),
                port_mapping_enabled: false,
                mdns_enabled: false,
                network_id: Some(network_id),
                ..x0x::network::NetworkConfig::default()
            })
            .build()
            .await?,
    );
    agent.join_network().await?;
    let state = secure_endpoint_test_state_at(dir.path(), Arc::clone(&agent)).await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "733".repeat(10);
    let attempt = "at1575-refresh".to_string();

    let mut requests = state
        .agent
        .subscribe(crate::dm_capability::DM_CAPABILITY_TARGETED_REQUEST_TOPIC)
        .await?;
    // Let the local subscription activate before the first fetch.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let fetch = |state: &Arc<AppState>, group_id: String| {
        let state = Arc::clone(state);
        let joiner_hex = joiner_hex.clone();
        let attempt = attempt.clone();
        async move {
            handle_join_result_message(
                &state,
                &joiner_id,
                true,
                JoinResultMessage::FetchRequest {
                    group_id,
                    member_agent_id: joiner_hex,
                    from_revision: None,
                    base_state_hash: None,
                    accepts_refusal: true,
                    accepts_control_blob_ref: false,
                    attempt_id: Some(attempt),
                    accepts_pending_notice: true,
                    held_notice_hash: None,
                    notice_only: false,
                    attempt_evidence: None,
                },
            )
            .await;
        }
    };

    // An unknown group with no staged notice: the fetch publishes nothing.
    fetch(&state, "71".repeat(32)).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), requests.recv())
            .await
            .is_err(),
        "an unknown-group fetch publishes no capability request"
    );

    // A known group with no staged notice: still nothing.
    {
        let admin = AgentKeypair::generate()?;
        let mut info = x0x::groups::GroupInfo::new(
            "1575w".to_string(),
            String::new(),
            admin.agent_id(),
            group_key.clone(),
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
    }
    fetch(&state, group_key.clone()).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), requests.recv())
            .await
            .is_err(),
        "a fetch with no staged notice publishes no capability request"
    );

    // A staged notice: the refresh fires exactly once through the
    // single-flight registry, and immediate re-polls inside the flight
    // window publish nothing more.
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
        JoinPendingNoticeDetail::default(),
        None,
    )
    .await;
    fetch(&state, group_key.clone()).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(3), requests.recv())
            .await
            .is_ok(),
        "a staged notice refreshes the joiner's advert"
    );
    fetch(&state, group_key.clone()).await;
    fetch(&state, group_key).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), requests.recv())
            .await
            .is_err(),
        "re-polls inside the single-flight window publish nothing more"
    );
    Ok(())
}
