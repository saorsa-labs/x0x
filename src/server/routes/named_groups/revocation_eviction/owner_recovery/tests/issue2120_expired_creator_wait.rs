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

/// #2120: a digest-pending hold on a seat that is not the creator (its
/// committed digest is known, its certificate bytes are not) ends when the
/// bytes arrive, so it keeps the bare `mandate_received` with no remedy.
#[tokio::test]
async fn a_digest_pending_seat_that_is_not_the_creator_keeps_the_bare_wait() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let member = x0x::identity::AgentKeypair::generate().unwrap();
    seat_member(&state, &mut info, &member, None);
    let stable = commit_attempt(&state, &mut info).await;
    assert_bare_wait(&state, &stable).await;
    state.agent.shutdown().await;
}

/// #2120: a creator whose renewal fetch is in flight (its new digest is
/// announced, the certificate has not resolved here) is in grace, not
/// held. Its renewal is under way, so the wait stays bare and does not
/// tell the owner to re-certify.
#[tokio::test]
async fn a_creator_renewal_in_flight_keeps_the_bare_wait() {
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
    assert!(
        info.creator_expired_certificate_hold(&creator_hex, now_unix()),
        "precondition: the creator's committed certificate is expired"
    );
    let stable = commit_attempt(&state, &mut info).await;
    assert_bare_wait(&state, &stable).await;
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
    let stable = commit_attempt(&state, &mut info).await;
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

/// #2120: the wait builder names the creator only when the creator is
/// digest-pending and is held on its own expired certificate.
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
        held_creator_wait(&info, &pending, now_unix()),
        Some((CREATOR_WAIT, vec![*creator.agent_id().as_bytes()]))
    );
    assert_eq!(
        held_creator_wait(&info, &["aa".repeat(32)], now_unix()),
        None,
        "the creator is not digest-pending"
    );

    info.members_v2
        .insert(creator_hex.clone(), seat(now_unix().saturating_add(7_200)));
    assert_eq!(
        held_creator_wait(&info, &pending, now_unix()),
        None,
        "a creator with a valid certificate is not held"
    );
}
