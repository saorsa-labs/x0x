#![cfg(test)]
//! #2120, daemon level: when the group's creator holds its own expired
//! committed certificate, the owner-recovery seal is refused as
//! `OwnerCertMemberPending` (the creator is held digest-pending, never
//! evicted). That hold does not end by itself, so the promoted member's
//! wait is typed: it names the creator and the remedy, the owner
//! re-certifying the creator.
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

async fn commit_attempt(state: &Arc<AppState>, info: &mut GroupInfo) -> String {
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
    try_commit(state, &stable).await;
    stable
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
    let stable = commit_attempt(&state, &mut info).await;

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

/// #2120: a grace hold on a seat that is not the creator still ends by
/// itself (the certificate fetch lands), so it keeps the bare
/// `mandate_received` with no remedy.
#[tokio::test]
async fn a_grace_hold_on_another_seat_keeps_the_bare_wait() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let member = x0x::identity::AgentKeypair::generate().unwrap();
    seat_member(&state, &mut info, &member, None);
    let stable = commit_attempt(&state, &mut info).await;

    let inner = state.revocation_evictions.inner.lock().await;
    let pending = inner
        .orc
        .pending
        .get(&stable)
        .expect("the mandate stays held while the seal refuses");
    assert!(pending.wait.is_none(), "a grace hold keeps the bare wait");
    drop(inner);

    let status = status_json(&state, &stable).await;
    let promoted = &status["promoted_member"];
    assert_eq!(promoted["state"], "mandate_received");
    assert!(promoted.get("remedy").is_none(), "no remedy: {promoted}");
    state.agent.shutdown().await;
}

/// #2120: the wait builder names the creator only when the creator is
/// among the pending seats and is held on its own expired certificate.
#[test]
fn the_creator_wait_needs_a_pending_held_creator() {
    let owner = x0x::identity::UserKeypair::generate().unwrap();
    let creator = x0x::identity::AgentKeypair::generate().unwrap();
    let creator_hex = hex::encode(creator.agent_id().as_bytes());
    let mut info = GroupInfo::new(
        "creator".to_string(),
        String::new(),
        creator.agent_id(),
        "c2".repeat(16),
    );
    info.policy.admission = x0x::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
    let seat = |not_after: u64| {
        let cert =
            x0x::identity::AgentCertificate::issue_with_expiry(&owner, &creator, Some(not_after))
                .unwrap();
        let mut member = x0x::groups::GroupMember::new_member(creator_hex.clone(), None, None, 1);
        member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
        member.certificate = Some(cert);
        member
    };
    let pending = vec![creator_hex.clone()];

    info.members_v2
        .insert(creator_hex.clone(), seat(now_unix().saturating_sub(7_200)));
    assert_eq!(
        held_creator_wait(&info, &pending),
        Some((CREATOR_WAIT, vec![*creator.agent_id().as_bytes()]))
    );
    assert_eq!(
        held_creator_wait(&info, &["aa".repeat(32)]),
        None,
        "the creator is not among the pending seats"
    );

    info.members_v2
        .insert(creator_hex.clone(), seat(now_unix().saturating_add(7_200)));
    assert_eq!(
        held_creator_wait(&info, &pending),
        None,
        "a creator with a valid certificate is not held"
    );
}
