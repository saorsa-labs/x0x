#![cfg(test)]
//! #2120, daemon level: when the group's creator holds its own expired
//! committed certificate, the owner-recovery seal is refused as
//! `OwnerCertMemberPending`: the creator is held, never evicted. A second
//! verdict over fresh evidence classes that hold. Digest-pending, the wait
//! is typed at once: it names the creator and the remedy, the owner
//! re-certifying the creator. In grace (a digest announced for the
//! creator, its bytes not resolved here), the wait stays bare for the
//! missing-evidence grace counted from the first such refusal, then is
//! typed too.
//!
//! [`super::recovery_fixture`]'s group (sole admin A revoked, this node
//! the certified Member the mandate names) gets a different creator C, a
//! seated Member whose certificate expired two hours ago.

use super::*;

const CREATOR_WAIT: &str = "waiting_for_creator_certificate_renewal";

/// A certified Member seat for `agent`; `not_after` sets its certificate
/// expiry, and `None` seats it with a digest but no certificate bytes.
fn seat_member(
    state: &Arc<AppState>,
    info: &mut GroupInfo,
    agent: &x0x::identity::AgentKeypair,
    not_after: Option<u64>,
) -> String {
    let owner = state.agent.identity().user_keypair().unwrap();
    let cert = x0x::identity::AgentCertificate::issue_with_expiry(owner, agent, not_after).unwrap();
    let hex = hex::encode(agent.agent_id().as_bytes());
    let mut member = x0x::groups::GroupMember::new_member(hex.clone(), None, None, 1);
    member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
    if not_after.is_some() {
        member.certificate = Some(cert);
    }
    info.members_v2.insert(hex.clone(), member);
    hex
}

/// Store `info`, sign the recovery mandate for this node, and run one
/// commit attempt. Returns the stable id and the mandate's `next_at`
/// before the attempt.
async fn commit_attempt(state: &Arc<AppState>, info: &mut GroupInfo) -> (String, Instant) {
    info.recompute_state_hash();
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(stable.clone(), info.clone());
    let owner = state.agent.identity().user_keypair().unwrap();
    let local_hex = hex::encode(state.agent.identity().agent_keypair().agent_id().as_bytes());
    let (status, Json(body)) = sign_recovery_mandate(state, owner, &stable, &local_hex).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    sync_head(state, info).await;
    let before = pending_field(state, &stable, |p| p.next_at).await;
    try_commit(state, &stable).await;
    (stable, before)
}

async fn pending_field<T>(
    state: &Arc<AppState>,
    stable: &str,
    read: impl FnOnce(&PendingMandate) -> T,
) -> T {
    let inner = state.revocation_evictions.inner.lock().await;
    read(
        inner
            .orc
            .pending
            .get(stable)
            .expect("the mandate stays held while the seal refuses"),
    )
}

/// The seal refusal recorded its wait: a commit attempt that returned
/// before the seal leaves `next_at` where the mandate put it.
async fn assert_seal_refusal_recorded(state: &Arc<AppState>, stable: &str, before: Instant) {
    let after = pending_field(state, stable, |p| p.next_at).await;
    assert!(
        after >= before + ORC_COMMIT_RETRY,
        "the seal refusal set the retry time"
    );
}

/// #2120: the creator's own expired certificate refuses the recovery seal,
/// and the wait names the creator and the remedy.
#[tokio::test]
async fn an_expired_creator_certificate_keeps_a_typed_wait_naming_the_creator() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let creator = x0x::identity::AgentKeypair::generate().unwrap();
    let expired = now_unix().saturating_sub(2 * 3_600);
    let creator_hex = seat_member(&state, &mut info, &creator, Some(expired));
    info.creator = creator.agent_id();
    assert!(
        info.creator_expired_certificate_hold(&creator_hex, now_unix()),
        "precondition: the creator's seat is held on its own expired certificate"
    );
    let (stable, before) = commit_attempt(&state, &mut info).await;
    assert_seal_refusal_recorded(&state, &stable, before).await;

    let inner = state.revocation_evictions.inner.lock().await;
    let pending = inner
        .orc
        .pending
        .get(&stable)
        .expect("the mandate stays held while the seal refuses");
    let wait = pending.wait.as_ref().expect("the wait is typed, not bare");
    assert_eq!(wait.0, CREATOR_WAIT);
    assert_eq!(wait.1, vec![*creator.agent_id().as_bytes()]);
    drop(inner);

    let status = status_json(&state, &stable).await;
    let promoted = &status["promoted_member"];
    assert_eq!(promoted["state"], CREATOR_WAIT);
    assert_eq!(promoted["named"], serde_json::json!([creator_hex]));
    assert_eq!(promoted["remedy"], "owner_recertifies_creator");
    state.agent.shutdown().await;
}

/// #2120: a digest-pending hold on a seat that is not the creator (its
/// committed digest is known, its certificate bytes are not) ends when the
/// bytes arrive, so it keeps the bare `mandate_received` with no remedy.
/// The fixture's creator is the revoked admin the recovery removes, so the
/// refusal reaches the creator check with no creator seat.
#[tokio::test]
async fn a_digest_pending_seat_that_is_not_the_creator_keeps_the_bare_wait() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let member = x0x::identity::AgentKeypair::generate().unwrap();
    let member_hex = seat_member(&state, &mut info, &member, None);
    let (stable, before) = commit_attempt(&state, &mut info).await;
    let stored = state.named_groups.read().await[&stable].clone();
    let evidence =
        crate::server::routes::named_groups::owner_cert_seal_evidence(&state, &stored).await;
    assert!(
        stored
            .clone()
            .owner_cert_verdict(&evidence)
            .digest_pending()
            .contains(&member_hex),
        "the seat is digest-pending, so the seal is refused as OwnerCertMemberPending"
    );
    assert_seal_refusal_recorded(&state, &stable, before).await;
    assert!(
        pending_field(&state, &stable, |p| p.creator_pending_since.is_none()).await,
        "the refusal does not hold the creator"
    );
    assert_bare_wait(&state, &stable).await;
    state.agent.shutdown().await;
}

/// #2120: a group whose creator holds no seat at all: a refusal never names
/// the creator, so the wait stays bare.
#[tokio::test]
async fn a_group_without_a_creator_seat_keeps_the_bare_wait() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    info.creator = x0x::identity::AgentKeypair::generate().unwrap().agent_id();
    let member = x0x::identity::AgentKeypair::generate().unwrap();
    seat_member(&state, &mut info, &member, None);
    let (stable, before) = commit_attempt(&state, &mut info).await;
    assert_seal_refusal_recorded(&state, &stable, before).await;
    assert!(
        pending_field(&state, &stable, |p| p.creator_pending_since.is_none()).await,
        "no creator seat, no creator hold"
    );
    assert_bare_wait(&state, &stable).await;
    state.agent.shutdown().await;
}

/// #2120: a creator with a digest announced and its bytes not resolved here
/// is in grace. The wait stays bare across retries for the missing-evidence
/// grace, counted from the first creator-hold refusal (the retries do not
/// restart it), then is typed: a fetch that never completes does not hide
/// the remedy.
#[tokio::test]
async fn an_in_grace_creator_gets_the_typed_wait_after_the_grace() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let creator = x0x::identity::AgentKeypair::generate().unwrap();
    let creator_hex = seat_member(
        &state,
        &mut info,
        &creator,
        Some(now_unix().saturating_sub(2 * 3_600)),
    );
    info.creator = creator.agent_id();
    let owner = state.agent.identity().user_keypair().unwrap();
    let renewed = x0x::identity::AgentCertificate::issue(owner, &creator).unwrap();
    announce(&state, &creator, None, Some(renewed_digest(&renewed))).await;
    let (stable, before) = commit_attempt(&state, &mut info).await;
    assert_seal_refusal_recorded(&state, &stable, before).await;
    let since = pending_field(&state, &stable, |p| p.creator_pending_since).await;
    assert!(
        since.is_some(),
        "the first creator-hold refusal is recorded"
    );
    assert_bare_wait(&state, &stable).await;

    // The test clock is paused (`sync_head`). Each retry advances it, which
    // also lets the recovery worker run its own attempt; either way the
    // grace start must not move.
    let grace =
        Duration::from_secs(x0x::groups::owner_cert::OWNER_CERT_MISSING_EVIDENCE_GRACE_SECS);
    let retry = |advance: Duration| {
        let state = Arc::clone(&state);
        let stable = stable.clone();
        async move {
            tokio::time::advance(advance).await;
            try_commit(&state, &stable).await;
        }
    };
    retry(Duration::from_secs(1)).await;
    assert_eq!(
        pending_field(&state, &stable, |p| p.creator_pending_since).await,
        since,
        "a retry does not restart the grace"
    );
    assert_bare_wait(&state, &stable).await;
    retry(grace - Duration::from_secs(2)).await;
    assert_bare_wait(&state, &stable).await;

    retry(Duration::from_secs(1)).await;
    let wait = pending_field(&state, &stable, |p| p.wait.clone()).await;
    assert_eq!(
        wait,
        Some((CREATOR_WAIT, vec![*creator.agent_id().as_bytes()])),
        "past the grace the wait is typed"
    );
    let status = status_json(&state, &stable).await;
    assert_eq!(
        status["promoted_member"]["named"],
        serde_json::json!([creator_hex])
    );
    assert_eq!(
        status["promoted_member"]["remedy"],
        "owner_recertifies_creator"
    );
    state.agent.shutdown().await;
}

/// #2120: the promoted member is itself the creator, held on its own
/// expired certificate. No creator wait can arise: the owner's mandate
/// check refuses a promoted member whose own certificate does not verify
/// (`recovery_member_ineligible`), so nothing is held and no seal runs.
/// The owner names another member, or re-certifies this one first.
#[tokio::test]
async fn a_promoted_member_that_is_the_held_creator_is_refused_at_the_mandate() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let local = state.agent.identity().agent_keypair();
    let local_hex = seat_member(
        &state,
        &mut info,
        local,
        Some(now_unix().saturating_sub(2 * 3_600)),
    );
    info.creator = local.agent_id();
    info.recompute_state_hash();
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(stable.clone(), info.clone());
    let owner = state.agent.identity().user_keypair().unwrap();
    let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "recovery_member_ineligible", "{body}");
    assert!(
        !state
            .revocation_evictions
            .inner
            .lock()
            .await
            .orc
            .pending
            .contains_key(&stable),
        "no mandate is held, so no wait exists"
    );
    state.agent.shutdown().await;
}

/// #2120: once the owner re-certifies the creator and the renewed
/// certificate resolves here, the next recovery attempt (the retry the
/// worker runs) commits, and the typed wait is gone with the mandate.
#[tokio::test]
async fn the_typed_wait_clears_once_the_owner_recertifies_the_creator() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let creator = x0x::identity::AgentKeypair::generate().unwrap();
    seat_member(
        &state,
        &mut info,
        &creator,
        Some(now_unix().saturating_sub(2 * 3_600)),
    );
    info.creator = creator.agent_id();
    let (stable, _) = commit_attempt(&state, &mut info).await;
    {
        let inner = state.revocation_evictions.inner.lock().await;
        let wait = inner.orc.pending.get(&stable).and_then(|p| p.wait.clone());
        assert_eq!(
            wait.map(|w| w.0),
            Some(CREATOR_WAIT),
            "precondition: the typed creator wait"
        );
    }

    let owner = state.agent.identity().user_keypair().unwrap();
    let renewed = x0x::identity::AgentCertificate::issue(owner, &creator).unwrap();
    let digest = renewed_digest(&renewed);
    announce(&state, &creator, Some(renewed), Some(digest)).await;
    try_commit(&state, &stable).await;

    let inner = state.revocation_evictions.inner.lock().await;
    assert!(
        !inner.orc.pending.contains_key(&stable),
        "the recovery committed, so no wait is left"
    );
    drop(inner);
    let local_hex = hex::encode(state.agent.identity().agent_keypair().agent_id().as_bytes());
    assert_eq!(
        state.named_groups.read().await[&stable].members_v2[&local_hex].role,
        x0x::groups::GroupRole::Admin,
        "the recovery seated the promoted member as Admin"
    );
    let status = status_json(&state, &stable).await;
    assert!(
        status["promoted_member"].is_null(),
        "no promoted-member wait in the status: {status}"
    );
    state.agent.shutdown().await;
}

async fn assert_bare_wait(state: &Arc<AppState>, stable: &str) {
    let inner = state.revocation_evictions.inner.lock().await;
    let pending = inner
        .orc
        .pending
        .get(stable)
        .expect("the mandate stays held while the seal refuses");
    assert!(
        pending.wait.is_none(),
        "the wait stays bare: {:?}",
        pending.wait
    );
    drop(inner);
    let status = status_json(state, stable).await;
    let promoted = &status["promoted_member"];
    assert_eq!(promoted["state"], "mandate_received");
    assert!(promoted.get("remedy").is_none(), "no remedy: {promoted}");
}

fn renewed_digest(cert: &x0x::identity::AgentCertificate) -> [u8; 32] {
    x0x::announce_v3::cert_digest(&cert.user_id().ok(), &Some(cert.clone()))
}

/// Seed the identity-discovery cache as a verified announce does: the
/// announced digest, and the certificate once it has resolved here.
async fn announce(
    state: &Arc<AppState>,
    agent: &x0x::identity::AgentKeypair,
    cert: Option<x0x::identity::AgentCertificate>,
    digest: Option<[u8; 32]>,
) {
    let agent_id = agent.agent_id();
    state.agent.identity_discovery_cache().write().await.insert(
        agent_id,
        x0x::DiscoveredAgent {
            agent_id,
            machine_id: x0x::identity::MachineId([0u8; 32]),
            user_id: cert.as_ref().and_then(|c| c.user_id().ok()),
            self_name: None,
            addresses: Vec::new(),
            announced_at: 0,
            last_seen: 0,
            machine_public_key: Vec::new(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: cert.as_ref().and_then(|c| c.not_after()),
            agent_certificate: cert,
            agent_public_key: Vec::new(),
            cert_digest: digest,
        },
    );
}

/// #2120: the creator-hold class from the verdict's classes and its
/// evidence clock. The certificate is expired only past `not_after` plus
/// the 300 s clock skew: at `not_after + 300` nothing holds, at
/// `not_after + 301` a digest-pending creator is held and an in-grace one
/// is fetching. A creator in neither class, or one that is not pending,
/// is not held.
#[test]
fn the_creator_hold_class_follows_the_verdict_and_the_skew_edge() {
    let owner = x0x::identity::UserKeypair::generate().unwrap();
    let creator = x0x::identity::AgentKeypair::generate().unwrap();
    let creator_hex = hex::encode(creator.agent_id().as_bytes());
    let not_after = 1_800_000_000;
    let cert =
        x0x::identity::AgentCertificate::issue_with_expiry(&owner, &creator, Some(not_after))
            .unwrap();
    let mut info = GroupInfo::new(
        "creator".to_string(),
        String::new(),
        creator.agent_id(),
        "c2".repeat(16),
    );
    info.policy.admission = x0x::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
    let mut member = x0x::groups::GroupMember::new_member(creator_hex.clone(), None, None, 1);
    member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
    member.certificate = Some(cert);
    info.members_v2.insert(creator_hex.clone(), member);
    let pending = vec![creator_hex.clone()];
    let skew = x0x::identity::EXPIRY_CLOCK_SKEW_SECS;
    assert_eq!(skew, 300);

    assert_eq!(
        creator_hold_class(&info, &pending, &[], not_after + skew),
        None
    );
    assert_eq!(
        creator_hold_class(&info, &pending, &[], not_after + skew + 1),
        Some(CreatorHold::Held)
    );
    assert_eq!(
        creator_hold_class(&info, &[], &pending, not_after + skew + 1),
        Some(CreatorHold::Fetching)
    );
    assert_eq!(
        creator_hold_class(&info, &[], &[], not_after + skew + 1),
        None
    );
    assert_eq!(
        creator_hold_class(&info, &["aa".repeat(32)], &[], not_after + skew + 1),
        None,
        "another digest-pending seat does not hold the creator"
    );
}
