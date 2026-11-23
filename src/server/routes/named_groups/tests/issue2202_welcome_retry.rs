#![cfg(test)]
//! #2202: a re-added member whose TreeKEM Welcome fetch failed stayed
//! broken for good. Its own seal arrived and was verified, the Welcome
//! fetch over the direct path timed out, the apply was rejected, the join
//! poll timed out and its finalizer removed the pending stub. The authority
//! kept the seat `Active`; the member had no group (404) and nothing asked
//! again.
//!
//! ADR 0107's in-process fixture: the authority seals J1's add at r+1 and
//! J2's at r+2, each Welcome by reference. J1's own result carries no
//! intervening link, so its stub stays a pending, non-durable stub (shape
//! B, the soak's case); J2's carries J1's link, which makes its row durable
//! first (shape A). The direct-path fault is injected per Welcome id; the
//! poll deadline is the finalizer the poll runs; the retry worker is driven
//! by `tick_at` with an explicit wall-clock time. Inert: no agent joins a
//! network.

use super::super::welcome_retry::{self, RetryState, MAX_REARMS};
use super::super::{welcome_fetch_fault, JoinAttemptOutcome, JoinFinalizeGuard};
use super::adr0107_stuck_join_rearm as f;
use super::*;

struct Joiner {
    state: Arc<AppState>,
    attempt: String,
    welcome_id: String,
    name: &'static str,
    kp: (Vec<u8>, Vec<u8>),
}

fn j1(s: &f::Fixture) -> Joiner {
    Joiner {
        state: Arc::clone(&s.j1),
        attempt: s.j1_attempt.clone(),
        welcome_id: f::welcome_id_of(&s.j1_add).expect("J1's Welcome is staged by reference"),
        name: "j1",
        kp: s.j1_kp.clone(),
    }
}

fn j2(s: &f::Fixture) -> Joiner {
    Joiner {
        state: Arc::clone(&s.j2),
        attempt: s.j2_attempt.clone(),
        welcome_id: f::welcome_id_of(&s.j2_add).expect("J2's Welcome is staged by reference"),
        name: "j2",
        kp: s.j2_kp.clone(),
    }
}

/// The authority serves the joiner's staged result for `attempt` (Welcome
/// by reference), and the joiner applies it while the direct path drops
/// the Welcome.
async fn deliver_with_failed_welcome(
    s: &f::Fixture,
    j: &Joiner,
    joiner: &Arc<AppState>,
    attempt: &str,
) -> anyhow::Result<()> {
    let from = f::remnant_revision(joiner, &s.group_key).await;
    let served = f::serve_result(&s.authority, joiner, &s.stable, attempt, from)
        .await
        .ok_or_else(|| anyhow::anyhow!("the authority serves the staged result"))?;
    welcome_fetch_fault::inject(&j.welcome_id, 1);
    f::deliver(joiner, &s.authority_id, served, attempt).await;
    anyhow::ensure!(
        !f::keyed(joiner, &s.group_key).await,
        "a failed Welcome fetch installs no keys"
    );
    Ok(())
}

/// The authority serves the result for `attempt` and streams the Welcome
/// through the real guarded transfer; the joiner applies it.
async fn deliver_with_welcome(
    s: &f::Fixture,
    j: &Joiner,
    joiner: &Arc<AppState>,
    attempt: &str,
) -> anyhow::Result<()> {
    let from = f::remnant_revision(joiner, &s.group_key).await;
    let served = f::serve_result(&s.authority, joiner, &s.stable, attempt, from)
        .await
        .ok_or_else(|| anyhow::anyhow!("the authority serves the staged result"))?;
    anyhow::ensure!(
        f::serve_welcome(&s.authority, joiner, &s.stable, &j.welcome_id).await,
        "the authority streams the original Welcome"
    );
    let served = f::with_pulled_welcome(&s.authority, joiner, &s.stable, served).await;
    f::deliver(joiner, &s.authority_id, served, attempt).await;
    Ok(())
}

/// The poll deadline of `attempt`, as the poll's own finalizer runs it.
async fn finish(s: &f::Fixture, joiner: &AppState, attempt: &str, outcome: JoinAttemptOutcome) {
    super::super::finalize_join_attempt(
        joiner,
        &s.group_key,
        &s.stable,
        &f::hex_of(joiner),
        attempt,
        outcome,
        JoinFinalizeGuard::Unlocked,
    )
    .await;
}

async fn time_out(s: &f::Fixture, joiner: &AppState, attempt: &str) {
    finish(s, joiner, attempt, JoinAttemptOutcome::TimedOut).await;
}

fn live_attempt(s: &f::Fixture, joiner: &AppState) -> Option<String> {
    f::attempt_of(joiner, &s.stable).map(|(id, _)| id)
}

async fn retry(joiner: &AppState, s: &f::Fixture) -> Option<welcome_retry::RetryRecord> {
    welcome_retry::record_for(joiner, &s.stable).await
}

async fn join_status(joiner: &AppState, s: &f::Fixture) -> (StatusCode, serde_json::Value) {
    super::super::join_status_body(joiner, &s.group_key).await
}

fn outcome_of(joiner: &AppState, s: &f::Fixture) -> Option<(&'static str, Option<&'static str>)> {
    joiner
        .last_join_outcomes
        .lock()
        .expect("outcomes")
        .get(&s.group_key)
        .map(|o| (o.outcome, o.reason))
}

fn stub_pending(joiner: &AppState, s: &f::Fixture) -> bool {
    joiner
        .pending_join_stubs
        .lock()
        .expect("stubs")
        .contains(&s.group_key)
}

/// The first failure: the joiner's verified seal arrives, its Welcome
/// fetch fails, and the attempt's poll deadline passes. Returns the
/// wall-clock time of the failure.
async fn fail_first_attempt(s: &f::Fixture, j: &Joiner) -> anyhow::Result<u64> {
    let t0 = super::super::now_millis_u64();
    deliver_with_failed_welcome(s, j, &j.state, &j.attempt).await?;
    let record = retry(&j.state, s)
        .await
        .ok_or_else(|| anyhow::anyhow!("[{}] the failed fetch left a retry record", j.name))?;
    anyhow::ensure!(record.state == RetryState::Retrying && record.rearms == 0);
    anyhow::ensure!(record.welcome_id == j.welcome_id);
    anyhow::ensure!(record.sealer_agent_id == f::hex_of(&s.authority));
    time_out(s, &j.state, &j.attempt).await;
    anyhow::ensure!(
        f::local_state(&j.state, &s.group_key).await == "not_member",
        "[{}] the timeout keeps the stub the Welcome retry owns",
        j.name
    );
    Ok(t0)
}

/// WHY (#2202, the fault chain): the Welcome fetch fails twice and then
/// succeeds; the member ends seated with a live ratchet, with no new
/// invite, no new membership commit and no new staging on the authority.
/// Shape B (J1, the soak's case: a pending stub) and shape A (J2, a row
/// made durable by its carry) both recover. Red before the fix: the
/// timeout removed J1's stub and nothing re-armed either join.
#[tokio::test]
async fn welcome_fetch_failing_twice_then_succeeding_ends_seated_with_keys() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = f::build(dir.path()).await?;
    for j in [j1(&s), j2(&s)] {
        let ctx = j.name;
        let authority_revision = f::remnant_revision(&s.authority, &s.group_key).await;
        let staged_at = f::staged(&s.authority, &s.stable, &f::hex_of(&j.state))
            .await
            .map(|p| p.created_at);
        let t0 = fail_first_attempt(&s, &j).await?;
        assert_eq!(
            outcome_of(&j.state, &s),
            Some((
                "timed_out",
                Some(super::super::JOIN_WELCOME_FETCH_FAILED_REASON)
            )),
            "[{ctx}] the timeout names the failed Welcome fetch"
        );

        welcome_retry::tick_at(&j.state, t0 + 6_000).await;
        assert!(
            !stub_pending(&j.state, &s),
            "[{ctx}] the worker made the stub durable"
        );
        let attempt1 = live_attempt(&s, &j.state).expect("the worker re-armed the join");
        assert_ne!(attempt1, j.attempt);
        assert_eq!(retry(&j.state, &s).await.map(|r| r.rearms), Some(1));
        deliver_with_failed_welcome(&s, &j, &j.state, &attempt1).await?;
        time_out(&s, &j.state, &attempt1).await;
        assert_eq!(
            f::local_state(&j.state, &s.group_key).await,
            "not_member",
            "[{ctx}] a failed re-arm keeps the durable remnant"
        );
        welcome_retry::tick_at(&j.state, t0 + 7_000).await;
        assert!(
            live_attempt(&s, &j.state).is_none(),
            "[{ctx}] the back-off holds"
        );

        welcome_retry::tick_at(&j.state, t0 + 6_000 + 16_000).await;
        let attempt2 = live_attempt(&s, &j.state).expect("the worker re-armed again");
        assert_eq!(retry(&j.state, &s).await.map(|r| r.rearms), Some(2));
        deliver_with_welcome(&s, &j, &j.state, &attempt2).await?;
        assert_eq!(f::local_state(&j.state, &s.group_key).await, "active");
        assert!(
            f::keyed(&j.state, &s.group_key).await,
            "[{ctx}] the original Welcome installed a live TreeKEM ratchet"
        );
        welcome_retry::tick_at(&j.state, t0 + 30_000).await;
        assert!(
            retry(&j.state, &s).await.is_none(),
            "[{ctx}] a seated, keyed member has no retry record"
        );
        assert_eq!(
            f::remnant_revision(&s.authority, &s.group_key).await,
            authority_revision,
            "[{ctx}] recovery needed no new membership commit"
        );
        let staged_after = f::staged(&s.authority, &s.stable, &f::hex_of(&j.state))
            .await
            .map(|p| p.created_at);
        assert!(
            staged_after.is_none() || staged_after == staged_at,
            "[{ctx}] a retry never restages or extends the authority's result"
        );
    }
    Ok(())
}

/// WHY (#2202, the stuck case): the authority lists the member `Active`
/// and the member had no group, with nothing retrying. Now the member
/// keeps a typed, visible row (join-status 200 with `welcome_retry`) and
/// repairs itself. Red before the fix: join-status answered 404.
#[tokio::test]
async fn owner_active_member_without_group_is_visible_and_repairs_itself() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = f::build(dir.path()).await?;
    let j = j1(&s);
    let t0 = fail_first_attempt(&s, &j).await?;
    assert!(
        s.authority
            .named_groups
            .read()
            .await
            .get(&s.group_key)
            .is_some_and(|info| info.has_active_member(&f::hex_of(&j.state))),
        "the authority lists J1 Active"
    );
    let (code, body) = join_status(&j.state, &s).await;
    assert_eq!(
        code,
        StatusCode::OK,
        "the member keeps its group row: {body}"
    );
    assert_eq!(body["welcome_retry"]["state"], "retrying", "{body}");
    assert_eq!(body["welcome_retry"]["rearms"], 0, "{body}");
    assert_eq!(
        body["last_join_outcome"]["reason"],
        super::super::JOIN_WELCOME_FETCH_FAILED_REASON,
        "{body}"
    );

    welcome_retry::tick_at(&j.state, t0 + 6_000).await;
    let attempt = live_attempt(&s, &j.state).expect("the member asks again");
    deliver_with_welcome(&s, &j, &j.state, &attempt).await?;
    assert_eq!(f::local_state(&j.state, &s.group_key).await, "active");
    assert!(f::keyed(&j.state, &s.group_key).await);
    welcome_retry::tick_at(&j.state, t0 + 7_000).await;
    let (_, body) = join_status(&j.state, &s).await;
    assert!(body["welcome_retry"].is_null(), "{body}");
    Ok(())
}

/// WHY (#2202, restart): the record and the stub are durable, so a joiner
/// restarted between the failure and the re-arm resumes the retry and
/// installs the original Welcome.
#[tokio::test]
async fn a_restart_between_failure_and_rearm_resumes_the_retry() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = f::build(dir.path()).await?;
    let j = j1(&s);
    let t0 = fail_first_attempt(&s, &j).await?;
    // Before the first back-off: the tick only makes the stub durable.
    welcome_retry::tick_at(&j.state, t0 + 1_000).await;
    assert!(live_attempt(&s, &j.state).is_none());
    let file = s.dir.join(j.name).join(welcome_retry::WELCOME_RETRY_FILE);
    assert!(file.exists(), "the retry record is on disk");

    let restarted = f::device(&s.dir, j.name, f::keypair(&j.kp)?).await?;
    assert_eq!(
        f::local_state(&restarted, &s.group_key).await,
        "not_member",
        "the stub survived the restart"
    );
    let record = retry(&restarted, &s)
        .await
        .expect("the restarted joiner loaded the retry record");
    assert_eq!(record.state, RetryState::Retrying);
    welcome_retry::tick_at(&restarted, t0 + 6_000).await;
    let attempt = live_attempt(&s, &restarted).expect("the restarted joiner re-arms");
    deliver_with_welcome(&s, &j, &restarted, &attempt).await?;
    assert_eq!(f::local_state(&restarted, &s.group_key).await, "active");
    assert!(f::keyed(&restarted, &s.group_key).await);
    welcome_retry::tick_at(&restarted, t0 + 7_000).await;
    assert!(retry(&restarted, &s).await.is_none());
    assert!(!file.exists(), "the file is removed with its last record");
    Ok(())
}

/// WHY (#2202, remove + re-add): a failed attempt followed by the owner's
/// remove-member and a new invite seats the member with keys. The new
/// invite starts a new attempt, which forgets the retry; the kept stub is
/// cleared as any remnant whose new base does not seat the joiner.
#[tokio::test]
async fn a_failed_attempt_then_remove_and_readd_seats_the_member() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = f::build(dir.path()).await?;
    let j = j1(&s);
    let t0 = fail_first_attempt(&s, &j).await?;
    welcome_retry::tick_at(&j.state, t0 + 1_000).await;
    assert!(retry(&j.state, &s).await.is_some());

    let removed = remove_named_group_member(
        State(Arc::clone(&s.authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((s.group_key.clone(), f::hex_of(&j.state))),
    )
    .await
    .into_response();
    assert!(removed.status().is_success(), "{}", removed.status());
    let (status, body, attempt) = f::redeem_fresh_invite(&s, &j.state, &s.authority).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        f::join_state_of(&body),
        "pending_authority_commit",
        "{body}"
    );
    assert!(
        retry(&j.state, &s).await.is_none(),
        "the new invite's attempt forgot the old retry"
    );
    let attempt = attempt.expect("the re-add registered a new attempt");
    let Some((_, Some(joined))) = f::attempt_of(&j.state, &s.stable) else {
        anyhow::bail!("the ordinary join stored its MemberJoined");
    };
    assert!(
        apply_named_group_metadata_event(
            &s.authority,
            joined,
            j.state.agent.agent_id(),
            true,
            None
        )
        .await
        .accepted,
        "the authority re-admits the removed device"
    );
    let staged_add = f::staged(&s.authority, &s.stable, &f::hex_of(&j.state))
        .await
        .expect("re-admission staged")
        .event;
    let readd = Joiner {
        welcome_id: f::welcome_id_of(&staged_add).expect("welcome ref"),
        ..j1(&s)
    };
    deliver_with_welcome(&s, &readd, &j.state, &attempt).await?;
    welcome_retry::tick_at(&j.state, t0 + 60_000).await;
    assert_eq!(f::local_state(&j.state, &s.group_key).await, "active");
    assert!(f::keyed(&j.state, &s.group_key).await);
    assert!(retry(&j.state, &s).await.is_none());
    Ok(())
}

/// WHY (#2202, authorization unchanged): a member removed from the roster
/// can still run the retry, but the authority's ADR 0107 serving guard
/// gives it neither the result nor the Welcome, so it never gains keys.
/// The retry ends `lost` once the Welcome's lifetime has passed.
#[tokio::test]
async fn a_member_not_on_the_roster_gets_no_welcome_through_the_retry() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = f::build(dir.path()).await?;
    let j = j1(&s);
    let t0 = fail_first_attempt(&s, &j).await?;
    let removed = remove_named_group_member(
        State(Arc::clone(&s.authority)),
        axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true }),
        Path((s.group_key.clone(), f::hex_of(&j.state))),
    )
    .await
    .into_response();
    assert!(removed.status().is_success(), "{}", removed.status());

    welcome_retry::tick_at(&j.state, t0 + 6_000).await;
    let attempt = live_attempt(&s, &j.state).expect("the joiner does not know it was removed");
    let from = f::remnant_revision(&j.state, &s.group_key).await;
    assert!(
        f::serve_result(&s.authority, &j.state, &s.stable, &attempt, from)
            .await
            .is_none(),
        "no join result for a member not on the roster"
    );
    assert!(
        !f::serve_welcome(&s.authority, &j.state, &s.stable, &j.welcome_id).await,
        "no Welcome for a member not on the roster"
    );
    time_out(&s, &j.state, &attempt).await;
    assert!(!f::keyed(&j.state, &s.group_key).await);

    let ttl = super::super::PENDING_WELCOME_TTL.as_millis() as u64;
    welcome_retry::tick_at(&j.state, t0 + ttl + 1_000).await;
    let record = retry(&j.state, &s).await.expect("record kept for status");
    assert_eq!(record.state, RetryState::Lost);
    assert_eq!(
        record.lost_reason.as_deref(),
        Some("welcome_lifetime_passed")
    );
    assert!(
        live_attempt(&s, &j.state).is_none(),
        "a lost retry re-arms nothing"
    );
    assert!(!f::keyed(&j.state, &s.group_key).await);
    Ok(())
}

/// WHY (#2202, refusal): a re-armed attempt that the authority refuses
/// ends the retry `lost` at once; it is not re-armed again.
#[tokio::test]
async fn an_authority_refusal_ends_the_retry() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = f::build(dir.path()).await?;
    let j = j1(&s);
    let t0 = fail_first_attempt(&s, &j).await?;
    welcome_retry::tick_at(&j.state, t0 + 6_000).await;
    let attempt = live_attempt(&s, &j.state).expect("re-armed");
    finish(&s, &j.state, &attempt, JoinAttemptOutcome::Refused).await;
    welcome_retry::tick_at(&j.state, t0 + 60_000).await;
    let record = retry(&j.state, &s).await.expect("record kept for status");
    assert_eq!(record.state, RetryState::Lost);
    assert_eq!(record.lost_reason.as_deref(), Some("authority_refused"));
    assert!(live_attempt(&s, &j.state).is_none());
    Ok(())
}

/// WHY (#2202, bounded): every re-arm fails; after `MAX_REARMS` the retry
/// ends in the typed `lost` state, names the remedy on join-status and
/// re-arms nothing more.
#[tokio::test]
async fn bounded_retries_end_in_a_typed_lost_state_with_a_remedy() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let s = f::build(dir.path()).await?;
    let j = j1(&s);
    let t0 = fail_first_attempt(&s, &j).await?;
    let mut now = t0;
    for round in 1..=MAX_REARMS {
        now += 61_000;
        welcome_retry::tick_at(&j.state, now).await;
        let attempt = live_attempt(&s, &j.state)
            .unwrap_or_else(|| panic!("re-arm {round} registered an attempt"));
        deliver_with_failed_welcome(&s, &j, &j.state, &attempt).await?;
        time_out(&s, &j.state, &attempt).await;
    }
    now += 61_000;
    welcome_retry::tick_at(&j.state, now).await;
    assert!(live_attempt(&s, &j.state).is_none());
    let record = retry(&j.state, &s).await.expect("record kept for status");
    assert_eq!(record.state, RetryState::Lost);
    assert_eq!(record.rearms, MAX_REARMS);
    assert_eq!(record.lost_reason.as_deref(), Some("rearms_exhausted"));
    let (code, body) = join_status(&j.state, &s).await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["welcome_retry"]["state"], "lost", "{body}");
    assert_eq!(
        body["welcome_retry"]["reason"], "rearms_exhausted",
        "{body}"
    );
    assert_eq!(
        body["welcome_retry"]["remedy"],
        welcome_retry::LOST_REMEDY,
        "{body}"
    );
    now += 120_000;
    welcome_retry::tick_at(&j.state, now).await;
    assert!(live_attempt(&s, &j.state).is_none(), "lost is terminal");
    assert!(!f::keyed(&j.state, &s.group_key).await);
    Ok(())
}
