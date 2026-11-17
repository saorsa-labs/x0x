//! #1973, daemon level: the owner-recovery commit must not deadlock
//! while another revoked member is still seated (the ADR-0038 seal
//! check).
//!
//! [`super::recovery_fixture`]'s group (sole admin A revoked, this node
//! the certified Member the mandate names) gains a second seated member
//! E whose own agent revocation this node holds verified. E's eviction
//! is an S4 row that waits for an eligible admin, and the recovery is
//! the only commit that can seat one, so an all-clean ADR-0038 seal
//! refusal naming E leaves the two waits on each other forever (#1973).
//! The recovery seal tolerates exactly the seated, below-Admin members
//! with a verified revocation (ADR 0110 §4b(1)); each of them keeps its
//! own transition under the admin this recovery seats.

use super::*;

/// One certified member seat for `agent`, mirroring the fixture's own
/// seats.
fn seat(
    owner: &x0x::identity::UserKeypair,
    agent: &x0x::identity::AgentKeypair,
) -> x0x::groups::GroupMember {
    let cert = x0x::identity::AgentCertificate::issue(owner, agent).unwrap();
    let hex = hex::encode(agent.agent_id().as_bytes());
    let mut member = x0x::groups::GroupMember::new_member(hex, None, None, 1);
    member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
    member.certificate = Some(cert);
    member
}

/// A seated member whose own self-revocation this node holds verified.
async fn seat_revoked_member(
    state: &Arc<AppState>,
    info: &mut GroupInfo,
    agent: &x0x::identity::AgentKeypair,
) {
    let member = seat(state.agent.identity().user_keypair().unwrap(), agent);
    let hex = member.agent_id.clone();
    info.members_v2.insert(hex.clone(), member);
    info.recompute_state_hash();
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(stable, info.clone());
    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(agent.agent_id()),
        agent.public_key(),
        agent.secret_key(),
        1,
        None,
    )
    .unwrap();
    assert!(state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, None)
        .unwrap());
}

/// #1973: the recovery commits while the revoked member E is still
/// seated; E keeps its Active seat for its own S4 row (ADR 0110 §4b(1):
/// nothing else changes), and the admin this recovery seats is the one
/// that row waits for.
#[tokio::test]
async fn owner_recovery_commits_while_a_revoked_member_is_seated() {
    let (_dir, state, mut info, admin_hex) = recovery_fixture().await;
    let owner = state.agent.identity().user_keypair().unwrap();
    let local = state.agent.identity().agent_keypair();
    let local_hex = hex::encode(local.agent_id().as_bytes());
    let member_e = x0x::identity::AgentKeypair::generate().unwrap();
    let e_hex = hex::encode(member_e.agent_id().as_bytes());
    seat_revoked_member(&state, &mut info, &member_e).await;
    let stable = info.stable_group_id().to_string();

    let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    sync_head(&state, &info).await;
    try_commit(&state, &stable).await;

    let committed = state
        .named_groups
        .read()
        .await
        .get(&stable)
        .cloned()
        .unwrap();
    assert_eq!(
        committed.members_v2[&local_hex].role,
        x0x::groups::GroupRole::Admin,
        "the promoted member takes the admin seat"
    );
    assert_eq!(
        committed.members_v2[&admin_hex].state,
        x0x::groups::GroupMemberState::Removed,
        "the revoked admin is removed"
    );
    assert_eq!(
        committed.members_v2[&e_hex].state,
        x0x::groups::GroupMemberState::Active,
        "E keeps its seat: its eviction is E's own S4 row"
    );
    assert_eq!(committed.state_revision, info.state_revision + 1);
    state.agent.shutdown().await;
}

/// #1973 (the second defect): a recovery seal refusal that still names
/// members keeps a typed wait naming them, not the bare
/// `mandate_received`. The seated member's certificate expired long
/// ago; expiry is not a tolerated revocation, so the ADR-0038 refusal
/// stands, and the promoted member's status names that member with
/// `waiting_for_member_eviction`.
#[tokio::test]
async fn a_standing_seal_refusal_keeps_a_typed_wait_naming_the_members() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let owner = state.agent.identity().user_keypair().unwrap();
    let local = state.agent.identity().agent_keypair();
    let local_hex = hex::encode(local.agent_id().as_bytes());
    let expired = x0x::identity::AgentKeypair::generate().unwrap();
    let expired_hex = hex::encode(expired.agent_id().as_bytes());
    // Two hours past expiry: beyond the 300 s expiry clock skew, and a
    // definitive failure (no fetch in flight, so no grace).
    let not_after = now_unix().saturating_sub(2 * 3_600);
    let cert = x0x::identity::AgentCertificate::issue_with_expiry(owner, &expired, Some(not_after))
        .unwrap();
    let mut member = x0x::groups::GroupMember::new_member(expired_hex.clone(), None, None, 1);
    member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
    member.certificate = Some(cert);
    info.members_v2.insert(expired_hex.clone(), member);
    info.recompute_state_hash();
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(stable.clone(), info.clone());

    let (status, Json(body)) = sign_recovery_mandate(&state, owner, &stable, &local_hex).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    sync_head(&state, &info).await;
    try_commit(&state, &stable).await;

    let inner = state.revocation_evictions.inner.lock().await;
    let pending = inner
        .orc
        .pending
        .get(&stable)
        .expect("the mandate stays held while the seal refuses");
    let wait = pending.wait.as_ref().expect("the wait is typed, not bare");
    assert_eq!(
        wait.0,
        x0x::groups::eviction::WaitingCause::WaitingForMemberEviction.as_str()
    );
    assert_eq!(wait.1, vec![*expired.agent_id().as_bytes()]);
    drop(inner);
    state.agent.shutdown().await;
}
