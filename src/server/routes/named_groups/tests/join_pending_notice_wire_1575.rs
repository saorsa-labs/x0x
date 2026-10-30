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
//! lifetime is not served. The PR #1639 review round 4 additions: the
//! `accepts_pending_notice` gate, a serve-then-verify round trip, the
//! cached-signature restage, the isolated ML-DSA evidence check, and the
//! pinned admitted exchange for the `Pending` reply (a ban during
//! delivery withholds it).

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
    // The two domains are different byte strings (the disjointness the
    // signature domains rely on), and the full-length domain-swapped
    // candidate — the refusal domain in front of the notice body's
    // suffix — is never the notice's canonical bytes (PR #1639 review
    // round 4: the old check compared a bare domain constant with a full
    // body, so it could never match).
    assert_ne!(
        JOIN_PENDING_NOTICE_DOMAIN, JOIN_REFUSAL_DOMAIN,
        "the notice and refusal domains are disjoint byte strings"
    );
    let mut domain_swapped = Vec::new();
    domain_swapped.extend_from_slice(JOIN_REFUSAL_DOMAIN);
    domain_swapped.extend_from_slice(&bytes[JOIN_PENDING_NOTICE_DOMAIN.len()..]);
    assert_ne!(
        domain_swapped, bytes,
        "the same body under the refusal domain is not the notice's canonical bytes"
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
/// future-skewed, mis-bound (another attempt, member or group),
/// unverified and domain-swapped signatures are refused; a member-signed
/// D154 cause is DROPPED in this slice (the joiner polls only its
/// authority; the notice-only rotation slice owns member-signed
/// acceptance); a notice not STRICTLY newer than the held one is ignored
/// (PR #1639 review round 4: the wrong member, the wrong group and the
/// same-age replay).
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

    // PR #1639 review round 4: a notice naming ANOTHER member — signed by
    // the pinned inviter, all other fields correct — never moves this
    // joiner, and neither does one for ANOTHER group (the attempt
    // registry holds no entry under that (group, member) pair). The held
    // notice survives both.
    let other_member_hex = hex::encode(member_signer.agent_id().as_bytes());
    let wrong_member = signed_notice(
        notice_body(
            &group_key,
            &other_member_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            detail.clone(),
            now + 3_500,
        ),
        &inviter,
    );
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &wrong_member).await,
        "a notice bound to another member is refused"
    );
    let other_group_key = "741".repeat(10);
    let wrong_group = signed_notice(
        notice_body(
            &other_group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            detail.clone(),
            now + 3_600,
        ),
        &inviter,
    );
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &wrong_group).await,
        "a notice bound to another group is refused"
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

    // PR #1639 review round 4: the newest-first rule is STRICTLY newer —
    // a replay with the SAME `issued_at_ms` as the held notice (but a
    // different detail) is ignored too (`held.issued_at_ms >=
    // notice.issued_at_ms`), so a replayed timestamp cannot smuggle a
    // changed detail in. The held detail stays the previous one.
    let same_age = signed_notice(
        notice_body(
            &group_key,
            &joiner_hex,
            &inviter_hex,
            &attempt_id,
            "owner_certificate_pending",
            JoinPendingNoticeDetail {
                count: Some(9),
                ..JoinPendingNoticeDetail::default()
            },
            now + 5_000,
        ),
        &inviter,
    );
    assert!(
        !verify_and_hold_join_pending_notice(&state, true, &same_age).await,
        "a same-age notice is ignored — only a strictly newer one replaces the held notice"
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
            held.detail.count,
            Some(2),
            "the held detail stays the previous one"
        );
    }
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
    // arm supersedes it too. PR #1639 review round 4 (Claude's minor
    // finding): the first serve above spent the per-joiner sign token,
    // so without a fresh limiter the serve below would be throttled away
    // and the assertion would pass even if `stage_join_result` stopped
    // dropping the notice — with the limiter reset the serve is
    // reachable, so the assertion carries the supersession alone.
    state
        .pending_join_refusals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&join_refusal_refusal_key(&group_key, &joiner_hex, &attempt));
    *state
        .join_pending_notice_sign_limiter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = JoinRefusalSignLimiter::default();
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

/// §8 (PR #1639 review round 4): the fetch's `accepts_pending_notice`
/// bit gates the serve BEFORE anything else in the notice half — a
/// verified, attempt-matching fetch from a joiner whose advert DOES set
/// `join_pending_notice_v1`, with a staged notice for the exact attempt,
/// still gets no `Pending` reply when the fetch says it does not accept
/// one. The egress barrier proves the negative: the exchange point is
/// never reached, and the staged notice row survives untouched (the
/// joiner retries when it becomes capable).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepts_pending_notice_false_gets_no_notice_even_with_the_bit_set() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "736".repeat(10);
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
    let handler_attempt = attempt.clone();
    let handler = tokio::spawn(async move {
        handle_join_result_message(
            &handler_state,
            &handler_joiner,
            true,
            JoinResultMessage::FetchRequest {
                group_id: handler_group.clone(),
                member_agent_id: hex::encode(handler_joiner.as_bytes()),
                from_revision: None,
                base_state_hash: None,
                accepts_refusal: true,
                accepts_control_blob_ref: false,
                attempt_id: Some(handler_attempt),
                accepts_pending_notice: false,
                held_notice_hash: None,
                notice_only: false,
                attempt_evidence: None,
            },
        )
        .await;
    });
    let mut finished = false;
    for _ in 0..500 {
        if handler.is_finished() {
            finished = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        finished,
        "the fetch completed without parking at the notice exchange point"
    );
    assert!(
        !armed.gate.reached(),
        "a fetch that does not accept pending notices never starts one"
    );
    drop(armed);
    handler.await.expect("the handler completes");
    assert!(
        staged_join_pending_notice(&state, &group_key, &joiner_hex, &attempt)
            .is_some_and(|(cause, _, _)| cause == JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING),
        "the staged notice row is untouched by an incapable fetch"
    );
    Ok(())
}

/// §8 (PR #1639 review round 4): a full serve-then-verify round trip
/// across two nodes. The member state stages the notice and serves the
/// signed `Pending` arm; the joiner state dispatches that exact arm and
/// HOLDS it. Every joiner-side check runs for real: the member is the
/// local agent, the attempt id matches, the signer is the key pinned
/// from the invite (its derived id equals `signer_agent_id`), the
/// ML-DSA-65 signature verifies over the canonical bytes, and
/// `issued_at_ms` is strictly newer than nothing. The joiner's
/// join-status then reports the held cause.
#[tokio::test]
async fn a_served_notice_round_trips_to_a_held_joiner_notice() -> Result<()> {
    let (member_state, _member_dir) = secure_endpoint_test_state().await?;
    let (joiner_state, _joiner_dir) = secure_endpoint_test_state().await?;
    let inviter_hex = hex::encode(member_state.agent.agent_id().as_bytes());
    let joiner_hex = hex::encode(joiner_state.agent.agent_id().as_bytes());
    let joiner_id = joiner_state.agent.agent_id();
    let group_key = "737".repeat(10);
    let attempt_id = "at1575r4rt".to_string();
    // The stub's D154 signer seat is part of the joiner fixture; this
    // slice never accepts its signature (see the drop case above).
    let stub_signer = AgentKeypair::generate()?;
    seed_joiner_attempt(
        &joiner_state,
        &group_key,
        &attempt_id,
        member_state.agent.identity().agent_keypair(),
        &stub_signer,
    )
    .await;
    // The attempt registry is keyed by the invite's STABLE group id, so
    // the notice must carry that id, not the local registry key.
    let stable = {
        let groups = joiner_state.named_groups.read().await;
        groups
            .get(&group_key)
            .expect("the joiner stub names the group")
            .stable_group_id()
            .to_string()
    };
    stage_join_pending_notice(
        &member_state,
        &stable,
        &joiner_hex,
        &attempt_id,
        JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
        JoinPendingNoticeDetail {
            count: Some(2),
            ..JoinPendingNoticeDetail::default()
        },
        Some(inviter_hex.clone()),
    )
    .await;
    insert_verified_advert(
        &member_state,
        &joiner_id,
        x0x::dm::CapabilityRegistry::JOIN_PENDING_NOTICE_V1,
    )
    .await;
    let served = serve_staged_join_pending_notice(
        &member_state,
        &stable,
        &joiner_hex,
        &attempt_id,
        &joiner_id,
        None,
        false,
    )
    .await
    .expect("the member state serves the staged notice");
    let Ok(JoinResultMessage::Pending { notice }) = serde_json::from_slice(&served) else {
        panic!("the served payload is the Pending arm");
    };
    assert_eq!(
        notice.signer_agent_id, inviter_hex,
        "the served notice is signed by the member state's agent (the pinned inviter)"
    );

    // The joiner dispatches the exact wire body its member state built.
    handle_join_result_message(
        &joiner_state,
        &member_state.agent.agent_id(),
        true,
        JoinResultMessage::Pending { notice },
    )
    .await;
    {
        let attempts = joiner_state
            .pending_join_attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let held = attempts
            .values()
            .find_map(|attempt| attempt.held_pending_notice.clone())
            .expect("the joiner holds the served notice");
        assert_eq!(held.cause, "owner_certificate_pending");
        assert_eq!(held.detail.count, Some(2));
    }
    let (code, body) = join_status_body(&joiner_state, &group_key).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["join_state"], "pending_authority_commit");
    assert_eq!(body["pending_cause"]["cause"], "owner_certificate_pending");
    Ok(())
}

/// §8 (PR #1639 review round 4): a restage of the SAME cause and detail
/// is the same notice — `issued_at_ms` stays pinned at the first staging
/// and the cached signature survives, so the re-serve runs through the
/// cache with NO limiter token (the test drains the global bucket first;
/// a non-cached re-serve would be throttled away and return nothing).
#[tokio::test]
async fn a_same_cause_restage_keeps_issued_at_ms_and_the_cached_signature() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "738".repeat(10);
    let attempt = "at1575r4cache".to_string();
    let detail = JoinPendingNoticeDetail {
        count: Some(4),
        ..JoinPendingNoticeDetail::default()
    };
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
        detail.clone(),
        None,
    )
    .await;
    insert_verified_advert(
        &state,
        &joiner_id,
        x0x::dm::CapabilityRegistry::JOIN_PENDING_NOTICE_V1,
    )
    .await;
    let first = serve_staged_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        &joiner_id,
        None,
        false,
    )
    .await
    .expect("the first capable serve signs the notice");
    let Ok(JoinResultMessage::Pending {
        notice: first_notice,
    }) = serde_json::from_slice(&first)
    else {
        panic!("the first serve is the Pending arm");
    };
    let pinned_issued_at_ms = first_notice.issued_at_ms;
    let pinned_signature_b64 = first_notice.signature_b64.clone();

    // Drain the global bucket with distinct fake pairs: the first serve
    // spent one token, so the next real reserve is refused.
    {
        let mut limiter = state
            .join_pending_notice_sign_limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for i in 0..JOIN_REFUSAL_GLOBAL_BUDGET {
            let _ = limiter.reserve(
                &format!("r4-drain-group-{i}"),
                &format!("r4-drain-member-{i}"),
            );
        }
        assert!(
            !limiter.reserve("r4-drain-probe-group", "r4-drain-probe-member"),
            "the global sign bucket is drained"
        );
    }

    // The restage of the same cause and detail only refreshes the TTL
    // window: the pinned issued-at clock and the cached signature stay.
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
        detail,
        None,
    )
    .await;
    {
        let notices = state
            .pending_join_notices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let row = notices
            .get(&join_refusal_refusal_key(&group_key, &joiner_hex, &attempt))
            .expect("the restaged row");
        assert_eq!(
            row.issued_at_ms, pinned_issued_at_ms,
            "a same-cause restage keeps the pinned issued_at_ms"
        );
        assert!(
            row.cached.is_some(),
            "a same-cause restage keeps the cached signature"
        );
    }
    let second = serve_staged_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        &joiner_id,
        None,
        false,
    )
    .await
    .expect("the cached path re-serves with no token");
    let Ok(JoinResultMessage::Pending {
        notice: second_notice,
    }) = serde_json::from_slice(&second)
    else {
        panic!("the re-serve is the Pending arm");
    };
    assert_eq!(
        second_notice.issued_at_ms, pinned_issued_at_ms,
        "the re-served notice carries the pinned issued_at_ms"
    );
    assert_eq!(
        second_notice.signature_b64, pinned_signature_b64,
        "the re-served notice carries the cached signature"
    );
    Ok(())
}

/// §8 (PR #1639 review round 4): the evidence check's ML-DSA
/// verification fails ON ITS OWN. `attempt_evidence_verification_
/// rejects_mismatches` reaches the signature only through a tampered
/// attempt id, so the isolated case is built here: the event names the
/// joiner and the group with the joiner's own public key (so the derived
/// id check passes) and carries an attempt id derived exactly as
/// `member_joined_event_attempt_id` does over the SAME canonical bytes
/// (so the attempt-id binding passes), but the signature is made with a
/// DIFFERENT key's secret key. Only the ML-DSA verification can reject
/// it — and it does.
#[test]
fn attempt_evidence_signature_verification_fails_on_its_own() -> Result<()> {
    let joiner = AgentKeypair::generate()?;
    let wrong_signer = AgentKeypair::generate()?;
    let inviter = AgentKeypair::generate()?;
    let group_key = "739".repeat(10);
    let joiner_hex = hex::encode(joiner.agent_id().as_bytes());
    let inviter_hex = hex::encode(inviter.agent_id().as_bytes());
    use base64::Engine as _;
    let member_public_key_b64 = BASE64.encode(joiner.public_key().as_bytes());
    let ts_ms = now_millis_u64();
    // The canonical bytes exactly as `signed_member_joined_event_for_test`
    // builds them: same field order, same stable-id alias, same role.
    let canonical = canonical_member_joined_bytes(
        &group_key,
        Some(group_key.as_str()),
        &joiner_hex,
        &member_public_key_b64,
        x0x::groups::GroupRole::Member,
        None,
        &inviter_hex,
        "1575w-secret",
        ts_ms,
        None,
    );
    // The wrong key signs those bytes; the attempt id is derived exactly
    // as the production derivation does (blake3 over the canonical bytes
    // concatenated with the raw signature).
    let wrong_sig = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        wrong_signer.secret_key(),
        &canonical,
    )
    .expect("sign with the wrong key");
    let raw_sig = wrong_sig.as_bytes().to_vec();
    let attempt = member_joined_attempt_id(&canonical, &raw_sig);
    let evidence = NamedGroupMetadataEvent::MemberJoined {
        group_id: group_key.clone(),
        stable_group_id: Some(group_key.clone()),
        member_agent_id: joiner_hex.clone(),
        member_public_key_b64,
        role: x0x::groups::GroupRole::Member,
        display_name: None,
        inviter_agent_id: inviter_hex,
        invite_secret: "1575w-secret".to_string(),
        ts_ms,
        treekem_key_package_b64: None,
        kem_public_key_b64: None,
        kem_signature_b64: None,
        certificate_b64: None,
        recovery_authority_agent_id: None,
        recovery_authority_public_key_b64: None,
        recovery_authority_signature_b64: None,
        recovery_authority_commit: None,
        signature_b64: BASE64.encode(&raw_sig),
    };
    // Precondition 1: the attempt-id binding passes over THESE bytes
    // (the last check before the signature).
    assert_eq!(
        member_joined_event_attempt_id(&evidence),
        Some(attempt.clone()),
        "the attempt id is the event's own derivation"
    );
    // Precondition 2: the signature bytes are a VALID ML-DSA signature —
    // under the wrong key. So the rejection below cannot come from a
    // malformed signature.
    let wrong_key = ant_quic::MlDsaPublicKey::from_bytes(wrong_signer.public_key().as_bytes())
        .expect("wrong signer key");
    let parsed_sig = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&raw_sig)
        .expect("the signature decodes");
    assert!(
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &wrong_key,
            &canonical,
            &parsed_sig
        )
        .is_ok(),
        "the signature is valid under the wrong signer's key"
    );
    // The isolated check: group, member, derived id and attempt id all
    // hold, so this None is the ML-DSA verification alone.
    assert_eq!(
        verified_join_attempt_evidence(&group_key, &joiner_hex, &attempt, &evidence),
        None,
        "an event signed by another key fails the ML-DSA check on its own"
    );
    Ok(())
}

/// §8 (PR #1639 review round 4, pinned-sender fix happy path): the
/// `Pending` reply leaves in ONE admitted pinned single exchange — the
/// same discipline every join artifact takes. The transport witness
/// records `pinned_single_exchange`, the exchange ends with the in-process
/// stand-in's admitted marker, and the egress witness records the
/// admitted write. Exactly one exchange runs: no retry, no second
/// transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pending_reply_rides_the_pinned_admitted_exchange() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "73a".repeat(10);
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
                member_agent_id: hex::encode(handler_joiner.as_bytes()),
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
    let mut parked_at_exchange = false;
    for _ in 0..200 {
        if armed.gate.reached() {
            parked_at_exchange = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        parked_at_exchange,
        "the handler never reached the pinned exchange"
    );
    drop(armed);
    handler
        .await
        .expect("the handler completes once the gate releases");

    // (i) The exchange was handed to the pinned single-exchange
    // transport — and to it alone (exactly one row for this kind).
    {
        let transports = state
            .named_group_test_recorders
            .join_artifact_transports
            .lock()
            .expect("transport witness");
        let rows: Vec<_> = transports
            .iter()
            .filter(|(to, kind, _)| to == &joiner_hex && *kind == "join_pending_notice")
            .collect();
        assert_eq!(
            rows.len(),
            1,
            "exactly one join_pending_notice exchange started (no retry, no second transport)"
        );
        assert_eq!(
            rows[0].2, "pinned_single_exchange",
            "the Pending reply rides the pinned single exchange"
        );
    }
    // (ii) The exchange ended admitted (the in-process stand-in's marker).
    {
        let outcomes = state
            .named_group_test_recorders
            .join_artifact_outcomes
            .lock()
            .expect("outcome witness");
        assert!(
            outcomes.iter().any(|(to, kind, err)| {
                to == &joiner_hex
                    && *kind == "join_pending_notice"
                    && err.contains(x0x::dm::PINNED_STANDIN_ADMITTED)
            }),
            "the exchange was admitted and reported as the stand-in write"
        );
    }
    // (iii) The admitted write is an egress witness for the group.
    {
        let egress = state
            .named_group_test_recorders
            .join_artifact_egress
            .lock()
            .expect("egress witness");
        assert!(
            egress.iter().any(|(to, group, kind)| to == &joiner_hex
                && group == &group_key
                && *kind == "join_pending_notice"),
            "the admitted exchange is recorded as egress for the group"
        );
    }
    Ok(())
}

/// §8 (PR #1639 review round 4, pinned-sender fix withhold path): a ban
/// that lands WHILE the reply's exchange is parked (payload built,
/// admission not yet run) withholds the `Pending` reply. The admission
/// pre-phase re-runs §8's serving conditions under the group's membership
/// lock, sees the Banned seat, and refuses the exchange: the outcome
/// carries the admission-refused marker (NOT the admitted stand-in), no
/// egress is recorded (nothing was written), and the transport row shows
/// the exchange WAS attempted. Before the fix the reply rode the generic
/// DM sender, which wrote with no §8 check at the seam — a ban could not
/// stop it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ban_during_delivery_withholds_the_pending_reply() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "73b".repeat(10);
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
                member_agent_id: hex::encode(handler_joiner.as_bytes()),
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
    let mut parked_at_exchange = false;
    for _ in 0..200 {
        if armed.gate.reached() {
            parked_at_exchange = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        parked_at_exchange,
        "the handler never reached the pinned exchange"
    );
    // While the exchange is parked (the payload is built, the admission
    // has not run), ban the joiner. The admission pre-phase re-takes the
    // membership lock and re-runs §8's serving conditions: the Banned
    // seat refuses the reply.
    {
        let mut groups = state.named_groups.write().await;
        if let Some(info) = groups.get_mut(&group_key) {
            info.ban_member(&joiner_hex, None);
        }
    }
    drop(armed);
    handler
        .await
        .expect("the handler completes once the gate releases");

    // (i) The exchange ended refused by the admission — and was never
    // admitted (no stand-in write).
    {
        let outcomes = state
            .named_group_test_recorders
            .join_artifact_outcomes
            .lock()
            .expect("outcome witness");
        assert!(
            outcomes.iter().any(|(to, kind, err)| {
                to == &joiner_hex
                    && *kind == "join_pending_notice"
                    && err.contains(x0x::dm::PINNED_ADMISSION_REFUSED)
            }),
            "the banned joiner's exchange reports the admission refusal"
        );
        assert!(
            !outcomes.iter().any(|(to, kind, err)| {
                to == &joiner_hex
                    && *kind == "join_pending_notice"
                    && err.contains(x0x::dm::PINNED_STANDIN_ADMITTED)
            }),
            "nothing was written to the banned joiner"
        );
    }
    // (ii) No egress witness: no admitted write happened.
    {
        let egress = state
            .named_group_test_recorders
            .join_artifact_egress
            .lock()
            .expect("egress witness");
        assert!(
            !egress
                .iter()
                .any(|(to, _, kind)| to == &joiner_hex && *kind == "join_pending_notice"),
            "the withheld reply left no egress witness"
        );
    }
    // (iii) The exchange WAS attempted — the refusal came from its
    // admission, not from the exchange never starting.
    {
        let transports = state
            .named_group_test_recorders
            .join_artifact_transports
            .lock()
            .expect("transport witness");
        assert!(
            transports.iter().any(|(to, kind, transport)| {
                to == &joiner_hex
                    && *kind == "join_pending_notice"
                    && *transport == "pinned_single_exchange"
            }),
            "the pinned single exchange ran and its admission refused it"
        );
    }
    Ok(())
}

/// §8 (PR #1639 review round 4, seam hardening): the seam half of the
/// `Pending` reply's admission — the synchronous final check at the
/// transport write — withholds after a mid-delivery change the pre-phase
/// could no longer see. Each leg serves the current row, opens its
/// admission (the pre-phase admits; the seam returns true — the control),
/// then mutates the world exactly as it could change during a real
/// delivery: a restage that changes the notice withholds the stale bytes;
/// a Result staged during delivery closes the seam and a restaged row
/// does not reopen it while the Result is fresh; and a BAN that lands
/// during delivery stops the write. Every seam check runs with `try_*`
/// locks (the `SeamAdmission` contract), exercised here uncontended;
/// contention withholds is the fail-closed reading of the same code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_seam_recheck_withholds_mid_delivery_changes() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "73c".repeat(10);
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
    insert_verified_advert(
        &state,
        &joiner_id,
        x0x::dm::CapabilityRegistry::JOIN_PENDING_NOTICE_V1,
    )
    .await;

    // Each leg stages `count`, serves the CURRENT row, opens its admission
    // (the pre-phase admits and the seam's FnOnce call returns true — the
    // control), and hands back a callable mirror of the same seam check
    // (`SeamAdmission` is FnOnce: one call per physical exchange) for the
    // leg's mutation. A restage that changes the notice moves
    // `issued_at_ms`, so a later leg must serve its own bytes; the limiter
    // reset keeps every leg's sign inside a fresh window.
    let seam_after = |count: u32| {
        let state = Arc::clone(&state);
        let group_key = group_key.clone();
        let joiner_hex = joiner_hex.clone();
        let attempt = attempt.clone();
        async move {
            *state
                .join_pending_notice_sign_limiter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                JoinRefusalSignLimiter::default();
            stage_join_pending_notice(
                &state,
                &group_key,
                &joiner_hex,
                &attempt,
                JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
                JoinPendingNoticeDetail {
                    count: Some(count),
                    ..JoinPendingNoticeDetail::default()
                },
                None,
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
            .expect("the eligible world serves its staged notice");
            let admission =
                join_pending_notice_admission(&state, &group_key, &joiner_hex, &attempt, &served);
            let seam = admission()
                .await
                .expect("the pre-phase admits the eligible world");
            assert!(seam(), "an unchanged world admits at the seam");
            let Ok(JoinResultMessage::Pending { notice }) = serde_json::from_slice(&served) else {
                panic!("the served payload is the Pending arm");
            };
            let served_hash = join_pending_notice_hash(&notice);
            move || {
                join_pending_notice_seam_admissible(
                    &state,
                    &group_key,
                    &joiner_hex,
                    &attempt,
                    &served_hash,
                )
            }
        }
    };

    // (i) The row re-resolve: a restage that changes the notice changes
    // the canonical bytes; the seam resolves the staged row again and
    // withholds the stale reply (no Result, no ban — the bytes alone).
    let seam_one = seam_after(1).await;
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
        None,
    )
    .await;
    assert!(
        !seam_one(),
        "a restaged notice withholds the stale bytes at the seam"
    );

    // (ii) The control the withheld leg needs: the CURRENT row's own
    // freshly served bytes (deterministic nonce, pinned issued_at_ms)
    // admit at the seam.
    let seam_two = seam_after(2).await;
    assert!(
        seam_two(),
        "the current row's own served bytes admit at the seam"
    );

    // (iii) A Result staged DURING delivery closes the seam, and a
    // restaged notice row does not reopen it while the Result is fresh —
    // §8's selection order (Result before notice) holds at the write.
    stage_join_result(
        &state,
        &group_key,
        &joiner_hex,
        joined_event.clone(),
        Some(&attempt),
    )
    .await;
    assert!(
        !seam_two(),
        "a Result staged during delivery closes the seam"
    );
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
        None,
    )
    .await;
    assert!(
        !seam_two(),
        "a restaged row does not reopen the seam while the Result is fresh"
    );

    // (iv) With the terminal answer gone, a fresh serve reopens the seam;
    // a BAN landed during delivery — the last mutation the pre-phase
    // could miss — stops the write.
    state
        .pending_join_results
        .write()
        .await
        .remove(&join_result_key(&group_key, &joiner_hex));
    let seam_four = seam_after(2).await;
    {
        let mut groups = state.named_groups.write().await;
        if let Some(info) = groups.get_mut(&group_key) {
            info.ban_member(&joiner_hex, None);
        }
    }
    assert!(
        !seam_four(),
        "a mid-delivery ban stops the write at the seam"
    );
    Ok(())
}
