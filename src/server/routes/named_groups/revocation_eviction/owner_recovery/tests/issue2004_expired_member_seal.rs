#![cfg(test)]
//! #2004, daemon level: the owner-recovery commit must not deadlock while
//! a below-Admin member whose certificate's S4 expiry is due is still
//! seated, and the recovery epoch must never be written to that member.
//!
//! [`super::recovery_fixture`]'s group (sole admin A revoked, this node
//! the certified Member the mandate names) gains a member E whose
//! committed certificate expired past τ. E's expiry row waits for an
//! eligible admin, and only the recovery can seat one. The recovery seal
//! tolerates E (it keeps its leaf for one epoch, and its own expiry row
//! removes it next), and the owner-recovery egress refuses E.

use super::*;

/// A certified member seat for `agent` whose certificate expires at
/// `not_after`.
fn seat_with_expiry(
    state: &Arc<AppState>,
    info: &mut GroupInfo,
    agent: &x0x::identity::AgentKeypair,
    not_after: u64,
) -> String {
    let owner = state.agent.identity().user_keypair().unwrap();
    let cert =
        x0x::identity::AgentCertificate::issue_with_expiry(owner, agent, Some(not_after)).unwrap();
    let hex = hex::encode(agent.agent_id().as_bytes());
    let mut member = x0x::groups::GroupMember::new_member(hex.clone(), None, None, 1);
    member.certificate_digest = Some(x0x::groups::owner_cert::certificate_digest_hex(&cert));
    member.certificate = Some(cert);
    info.members_v2.insert(hex.clone(), member);
    info.recompute_state_hash();
    hex
}

async fn install(state: &Arc<AppState>, info: &GroupInfo) {
    state
        .named_groups
        .write()
        .await
        .insert(info.stable_group_id().to_string(), info.clone());
}

/// Two hours past `not_after`: past τ (300 s), so the expiry row is due.
fn long_expired() -> u64 {
    now_unix().saturating_sub(2 * 3_600)
}

/// Expired by the calendar but still inside τ: the expiry row is not due
/// yet, so nothing may treat the seat as expired.
fn inside_tolerance() -> u64 {
    now_unix().saturating_sub(x0x::groups::eviction::EXPIRY_TOLERANCE_SECS - 120)
}

/// #2004: the recovery commits while E's expired seat is still seated;
/// E keeps its Active seat for its own S4 expiry row.
#[tokio::test]
async fn owner_recovery_commits_while_an_expired_member_is_seated() {
    let (_dir, state, mut info, admin_hex) = recovery_fixture().await;
    let owner = state.agent.identity().user_keypair().unwrap();
    let local_hex = hex::encode(state.agent.identity().agent_keypair().agent_id().as_bytes());
    let member_e = x0x::identity::AgentKeypair::generate().unwrap();
    let e_hex = seat_with_expiry(&state, &mut info, &member_e, long_expired());
    install(&state, &info).await;
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
        "E keeps its seat: its eviction is E's own S4 expiry row"
    );
    assert_eq!(committed.state_revision, info.state_revision + 1);
    state.agent.shutdown().await;
}

/// #2004: the scope builder collects a below-Admin seat whose expiry is
/// due, and not one that is still inside τ (the S4 expiry row's own
/// rule), nor an expired Admin seat.
#[tokio::test]
async fn the_recovery_seal_scope_collects_only_due_expired_below_admin_seats() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let due = x0x::identity::AgentKeypair::generate().unwrap();
    let due_hex = seat_with_expiry(&state, &mut info, &due, long_expired());
    let not_due = x0x::identity::AgentKeypair::generate().unwrap();
    let not_due_hex = seat_with_expiry(&state, &mut info, &not_due, inside_tolerance());
    let admin = x0x::identity::AgentKeypair::generate().unwrap();
    let admin_hex = seat_with_expiry(&state, &mut info, &admin, long_expired());
    if let Some(seat) = info.members_v2.get_mut(&admin_hex) {
        seat.role = x0x::groups::GroupRole::Admin;
    }
    info.recompute_state_hash();
    install(&state, &info).await;

    let scope = super::super::super::owner_recovery_seal_scope(&state, &info).await;
    assert_eq!(scope.expired_members, BTreeSet::from([due_hex]));
    assert!(!scope.expired_members.contains(&not_due_hex));
    assert!(!scope.expired_members.contains(&admin_hex));
    state.agent.shutdown().await;
}

/// #2004: the owner-recovery egress never writes to a seat whose expiry
/// is due, so the recovery epoch's path secrets cannot reach the leaf it
/// keeps for one epoch. A seat still inside τ is served as before.
#[tokio::test]
async fn the_recovery_egress_refuses_only_a_due_expired_seat() {
    let (_dir, state, mut info, _admin_hex) = recovery_fixture().await;
    let due = x0x::identity::AgentKeypair::generate().unwrap();
    seat_with_expiry(&state, &mut info, &due, long_expired());
    let not_due = x0x::identity::AgentKeypair::generate().unwrap();
    seat_with_expiry(&state, &mut info, &not_due, inside_tolerance());
    install(&state, &info).await;

    assert!(
        !recovery_write_allowed(&state, &info, &due.agent_id()).await,
        "a due-expired seat gets no recovery frame"
    );
    assert!(
        recovery_write_allowed(&state, &info, &not_due.agent_id()).await,
        "a seat inside τ is not cut off early"
    );
    state.agent.shutdown().await;
}
