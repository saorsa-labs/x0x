//! #1575 (PR #1639 review round 4): the limiter half of the join pending
//! notice signature. The `join_pending_notice_sign_limiter` token is
//! RESERVED BEFORE the ML-DSA run — the round-3 order signed first and
//! discarded the signature when throttled, so an exhausted budget still
//! paid the signing cost — and a failed signature REFUNDS the token. These
//! tests pin the spend facts both reviewers demanded: one token per
//! (group, member) per 30 s window and 20 per minute globally, both
//! checked BEFORE any ML-DSA work; a refunded token spendable again,
//! exactly once; a cached re-serve spends nothing; and the cache
//! write-back re-checks the staged row after the signature, so a restage
//! in the gap leaves the cache empty.

use super::*;
use x0x::identity::AgentKeypair;

/// PR #1639 review round 4: one token per joiner per 30 s window. The
/// first capable serve signs; a restage that changes the detail (new
/// canonical bytes, `cached = None`) must sign again, and the per-joiner
/// window stops the serve BEFORE ML-DSA runs — the armed sign gate stays
/// unreached. After the limiter is reset, the serve signs the new bytes
/// and the signature differs.
#[tokio::test]
async fn the_notice_sign_limiter_spends_one_token_per_joiner_per_window() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "74".repeat(16);
    let attempt = "at1575-lim1".to_string();

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
    .expect("the first capable serve signs and serves the notice");
    let Ok(JoinResultMessage::Pending { notice }) = serde_json::from_slice(&served) else {
        panic!("the served payload is the Pending arm");
    };
    let first_signature = notice.signature_b64;

    // A changed detail replaces the row with `cached = None`, so the next
    // serve must SIGN again — and the member window (30 s) stops it before
    // any ML-DSA work.
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
    let armed = join_egress_test_barrier::arm(&joiner_hex, "join_pending_notice_sign");
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
        "the per-joiner 30 s window withholds the second sign"
    );
    assert!(
        !armed.gate.reached(),
        "the throttle runs BEFORE the ML-DSA sign — nothing was signed"
    );
    drop(armed);

    // A fresh limiter opens the window again: the restaged bytes are
    // signed anew, and a hedged ML-DSA signature over different canonical
    // bytes always differs from the first.
    *state
        .join_pending_notice_sign_limiter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = JoinRefusalSignLimiter::default();
    let reserved = serve_staged_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        &joiner_id,
        None,
        false,
    )
    .await
    .expect("a fresh window serves the restaged notice");
    let Ok(JoinResultMessage::Pending {
        notice: fresh_notice,
    }) = serde_json::from_slice(&reserved)
    else {
        panic!("the re-served payload is the Pending arm");
    };
    assert_eq!(fresh_notice.detail.count, Some(2));
    assert_ne!(
        fresh_notice.signature_b64, first_signature,
        "the restaged bytes get a fresh signature"
    );
    Ok(())
}

/// PR #1639 review round 4 (the fails-before-passes-after proof for the
/// reserve-before-sign order): 20 distinct joiners each take one global
/// token and are served (the crypto dependencies build at opt-level 3, so
/// the 20 signs and keygens finish far inside the 3 s refill step); the
/// 21st distinct joiner — staged, capable, `cached = None` — is served
/// NOTHING with the sign gate unreached. Under the round-3 order (sign
/// first, then throttle) this serve would have reached the gate and paid
/// for a signature it then threw away.
#[tokio::test]
async fn an_exhausted_global_budget_does_no_signing() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_key = "75".repeat(16);
    for i in 0..JOIN_REFUSAL_GLOBAL_BUDGET {
        let joiner = AgentKeypair::generate()?;
        let joiner_id = joiner.agent_id();
        let joiner_hex = hex::encode(joiner_id.as_bytes());
        let attempt = format!("at1575-lim2-{i}");
        stage_join_pending_notice(
            &state,
            &group_key,
            &joiner_hex,
            &attempt,
            JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
            JoinPendingNoticeDetail {
                count: Some(i),
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
            .is_some(),
            "distinct joiner {i} drains one global token and is served"
        );
    }

    // The 21st distinct joiner: staged, capable, nothing cached. The only
    // fact that can stop this serve is the empty global bucket, and it
    // must stop it BEFORE the ML-DSA run.
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let attempt = format!("at1575-lim2-{JOIN_REFUSAL_GLOBAL_BUDGET}");
    stage_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        JOIN_PENDING_CAUSE_OWNER_CERTIFICATE_PENDING,
        JoinPendingNoticeDetail {
            count: Some(JOIN_REFUSAL_GLOBAL_BUDGET),
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
    let armed = join_egress_test_barrier::arm(&joiner_hex, "join_pending_notice_sign");
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
        "an exhausted global budget serves nothing"
    );
    assert!(
        !armed.gate.reached(),
        "an exhausted budget signs nothing — the reserve runs before ML-DSA"
    );
    drop(armed);
    Ok(())
}

/// PR #1639 review round 4: `refund` gives back exactly what `reserve`
/// took — the per-member entry is dropped, so the next reserve for the
/// pair starts clean, and ONE global token returns. The global half runs
/// on its own fresh limiter so the bucket starts at the full 20-token
/// budget (the member half above ends one token down).
#[test]
fn a_refunded_token_is_spendable_again() {
    let mut limiter = JoinRefusalSignLimiter::default();
    assert!(limiter.reserve("g", "m1"));
    assert!(
        !limiter.reserve("g", "m1"),
        "the member window holds the pair for the full 30 s"
    );
    limiter.refund("g", "m1");
    assert!(
        limiter.reserve("g", "m1"),
        "a refunded token is spendable again at once"
    );

    // The global half: a full budget drains on 20 distinct members, a
    // 21st is stopped, and one refund returns EXACTLY one token.
    let mut limiter = JoinRefusalSignLimiter::default();
    for i in 0..JOIN_REFUSAL_GLOBAL_BUDGET {
        assert!(
            limiter.reserve("g", &format!("m{i}")),
            "distinct member {i} takes one global token"
        );
    }
    assert!(
        !limiter.reserve("g", "m21st"),
        "the 21st distinct member finds the global bucket empty"
    );
    limiter.refund("g", "m5");
    assert!(
        limiter.reserve("g", "m5"),
        "the refund dropped the member entry and returned one global token"
    );
    assert!(
        !limiter.reserve("g", "m22nd"),
        "exactly one token came back — the next new pair is still stopped"
    );
}

/// PR #1639 review round 4: the cache write-back re-checks the staged row
/// AFTER the signature. The serve is parked at the
/// `join_pending_notice_sign` gate — after ML-DSA, before the write-back,
/// holding no mutex there — the row is restaged with a changed detail, and
/// the gate is released: the serve returns the OLD signed bytes and the
/// row keeps `cached = None` (the hash re-check skipped the cache because
/// the row changed in the gap). A fresh serve then signs the new bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cache_write_back_rechecks_the_row_after_signing() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "76".repeat(16);
    let attempt = "at1575-lim4".to_string();
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

    let armed = join_egress_test_barrier::arm(&joiner_hex, "join_pending_notice_sign");
    let serve_state = Arc::clone(&state);
    let serve_group = group_key.clone();
    let serve_member = joiner_hex.clone();
    let serve_attempt = attempt.clone();
    let serve_joiner = joiner_id;
    let serve_task = tokio::spawn(async move {
        serve_staged_join_pending_notice(
            &serve_state,
            &serve_group,
            &serve_member,
            &serve_attempt,
            &serve_joiner,
            None,
            false,
        )
        .await
    });
    // The park sits AFTER a successful sign and BEFORE the cache
    // write-back; it holds no mutex there.
    let mut parked_after_sign = false;
    for _ in 0..200 {
        if armed.gate.reached() {
            parked_after_sign = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        parked_after_sign,
        "the serve never reached the sign park point"
    );

    // Replace the row while the serve is parked: a changed detail is a
    // different notice (different canonical bytes, cached = None).
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

    drop(armed);
    let served = serve_task
        .await
        .expect("the parked serve completes once the gate releases")
        .expect("the serve returns the old signed bytes");
    let Ok(JoinResultMessage::Pending { notice }) = serde_json::from_slice(&served) else {
        panic!("the parked serve returned the Pending arm");
    };
    assert_eq!(
        notice.detail.count,
        Some(1),
        "the parked serve returned the OLD bytes"
    );

    // The write-back hash re-check saw the changed row: no cache entry
    // was written.
    {
        let notices = state
            .pending_join_notices
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let row = notices
            .get(&join_refusal_refusal_key(&group_key, &joiner_hex, &attempt))
            .expect("the restaged row");
        assert!(
            row.cached.is_none(),
            "the write-back skipped the cache — the row changed in the gap"
        );
    }

    // A fresh window serves the NEW bytes, freshly signed.
    *state
        .join_pending_notice_sign_limiter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = JoinRefusalSignLimiter::default();
    let reserved = serve_staged_join_pending_notice(
        &state,
        &group_key,
        &joiner_hex,
        &attempt,
        &joiner_id,
        None,
        false,
    )
    .await
    .expect("a fresh window serves the new row");
    let Ok(JoinResultMessage::Pending {
        notice: fresh_notice,
    }) = serde_json::from_slice(&reserved)
    else {
        panic!("the re-served payload is the Pending arm");
    };
    assert_eq!(
        fresh_notice.detail.count,
        Some(2),
        "the new row is served with fresh, newly signed bytes"
    );
    Ok(())
}

/// PR #1639 review round 4: a cached re-serve spends no token. The first
/// serve signs and caches; the global bucket is then drained directly
/// (the first serve spent one of the 20 tokens, so the drain takes the
/// remaining 19 and then stops); the SAME row is served again with an
/// empty bucket and still answers, with the cached signature byte for
/// byte — the cached path never consults the limiter.
#[tokio::test]
async fn a_cached_re_serve_spends_no_token() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let joiner = AgentKeypair::generate()?;
    let joiner_id = joiner.agent_id();
    let joiner_hex = hex::encode(joiner_id.as_bytes());
    let group_key = "77".repeat(16);
    let attempt = "at1575-lim5".to_string();
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
    .expect("the first serve signs and caches the signature");
    let Ok(JoinResultMessage::Pending { notice }) = serde_json::from_slice(&served) else {
        panic!("the served payload is the Pending arm");
    };
    let first_signature = notice.signature_b64;

    // Drain the global bucket: fresh ("drain", m<i>) pairs, so only the
    // global side can stop them. The first serve spent one token, so the
    // drain takes the other 19 and then finds the bucket empty.
    {
        let mut limiter = state
            .join_pending_notice_sign_limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut drained = 0;
        while limiter.reserve("drain", &format!("m{drained}")) {
            drained += 1;
        }
        assert_eq!(
            drained,
            JOIN_REFUSAL_GLOBAL_BUDGET - 1,
            "the earlier serve spent one token; the drain empties the rest"
        );
    }

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
    .expect("a cached re-serve answers with an empty global bucket");
    let Ok(JoinResultMessage::Pending {
        notice: again_notice,
    }) = serde_json::from_slice(&again)
    else {
        panic!("the re-served payload is the Pending arm");
    };
    assert_eq!(
        again_notice.signature_b64, first_signature,
        "the cached path returns the cached signature without consulting the limiter"
    );
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
