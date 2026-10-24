//! ADR 0110 §4a and §4b(2): the self-rebind route
//! `POST /groups/:id/members/:agent_id/certificate/rebind`.
//!
//! These drive the real route handler against a real daemon state with an
//! `OwnerCertified` group seeded in the roster map: a refusal for another
//! agent's seat, the cutoff refusal `rebind_window_closed` with the seat
//! agent's `waiting_for_admin_rebind` naming the designated admin, the
//! receiver-upgrade refusal while another member's capability is unknown,
//! and a committed self-rebind that changes only the seat's certificate.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;
use crate::groups::cert_rebind as cr;
use revocation_eviction::rebind::{REBIND_WINDOW_CLOSED, WAITING_FOR_ADMIN_REBIND};
use x0x::groups::policy::GroupAdmission;
use x0x::identity::{AgentCertificate, AgentKeypair, UserKeypair};

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn owner_actor() -> axum::extract::Extension<crate::server::rider_auth::ActorContext> {
    axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true })
}

/// Seed an `OwnerCertified` group whose local seat (an admin, the creator)
/// holds a committed certificate expiring at `local_not_after`. When
/// `other_admin` is given it is seated as a second admin with a long-lived
/// certificate. Returns the storage key.
async fn seed_group(
    state: &AppState,
    owner: &UserKeypair,
    local_not_after: u64,
    other_admin: Option<&AgentKeypair>,
) -> String {
    let local_kp = state.agent.identity().agent_keypair();
    let mut info = x0x::groups::GroupInfo::new(
        "rebind".to_string(),
        "adr 0110 §4a".to_string(),
        state.agent.agent_id(),
        "cd".repeat(16),
    );
    info.policy.admission = GroupAdmission::OwnerCertified(owner.user_id());
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    cr::install_certificate(
        &mut info,
        &local_hex,
        AgentCertificate::issue_with_expiry(owner, local_kp, Some(local_not_after))
            .expect("local cert"),
    );
    if let Some(admin) = other_admin {
        let admin_hex = hex::encode(admin.agent_id().as_bytes());
        let mut member =
            x0x::groups::GroupMember::new_member(admin_hex.clone(), None, Some(local_hex), 1);
        member.role = x0x::groups::GroupRole::Admin;
        info.members_v2.insert(admin_hex.clone(), member);
        cr::install_certificate(
            &mut info,
            &admin_hex,
            AgentCertificate::issue_with_expiry(owner, admin, Some(unix_now() + 86_400))
                .expect("admin cert"),
        );
    }
    info.recompute_state_hash();
    let key = info.mls_group_id.clone();
    state.named_groups.write().await.insert(key.clone(), info);
    key
}

fn renewal_b64(owner: &UserKeypair, agent: &AgentKeypair, not_after: u64) -> String {
    let cert = AgentCertificate::issue_with_expiry(owner, agent, Some(not_after)).expect("renewal");
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(cert.to_storage_bytes().expect("storage"))
}

async fn call(
    state: &Arc<AppState>,
    group: &str,
    agent_hex: &str,
    certificate: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let body = certificate.map(|certificate| {
        Json(
            serde_json::from_value::<revocation_eviction::rebind::RebindCertificateRequest>(
                serde_json::json!({ "certificate": certificate }),
            )
            .expect("request"),
        )
    });
    let (status, Json(value)) = revocation_eviction::rebind::rebind_member_certificate(
        State(Arc::clone(state)),
        owner_actor(),
        Path((group.to_string(), agent_hex.to_string())),
        body,
    )
    .await;
    (status, value)
}

#[tokio::test]
async fn self_rebind_route_refuses_another_agents_seat() {
    let (state, _dir) = secure_endpoint_test_state().await.expect("state");
    let owner = UserKeypair::generate().expect("owner");
    let group = seed_group(&state, &owner, unix_now() + 86_400, None).await;
    let other = hex::encode([7u8; 32]);
    let (status, body) = call(&state, &group, &other, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "rebind_signer_ineligible");
}

#[tokio::test]
async fn self_rebind_after_the_cutoff_hands_off_and_waits_for_the_admin() {
    let (state, _dir) = secure_endpoint_test_state().await.expect("state");
    let owner = UserKeypair::generate().expect("owner");
    let admin = AgentKeypair::generate().expect("admin");
    // `not_after − τ` is already in the past: the window is closed.
    let not_after = unix_now() + 60;
    let group = seed_group(&state, &owner, not_after, Some(&admin)).await;
    // The local seat is not the only admin and the other admin is not
    // expired, so §4b(2) does not apply.
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let renewal = renewal_b64(
        &owner,
        state.agent.identity().agent_keypair(),
        unix_now() + 86_400,
    );
    let (status, body) = call(&state, &group, &local_hex, Some(renewal)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], REBIND_WINDOW_CLOSED);
    assert_eq!(body["state"], WAITING_FOR_ADMIN_REBIND);
    let admin_hex = hex::encode(admin.agent_id().as_bytes());
    assert_eq!(body["designated_admin"], admin_hex);
    // GET /groups/:id shows the wait, naming the designated admin.
    let info = state
        .named_groups
        .read()
        .await
        .get(&group)
        .cloned()
        .expect("group");
    let status = revocation_eviction::group_status_json(&state, &info).await;
    let waits = &status.certificate_rebind["waiting_for_admin_rebind"];
    assert_eq!(waits[0]["cause"], WAITING_FOR_ADMIN_REBIND);
    assert_eq!(waits[0]["designated_admin"], admin_hex);
    // The seat is unchanged: nothing was committed.
    assert_eq!(info.state_revision, 0);
}

#[tokio::test]
async fn self_rebind_is_off_while_a_member_capability_is_unknown() {
    let (state, _dir) = secure_endpoint_test_state().await.expect("state");
    let owner = UserKeypair::generate().expect("owner");
    let admin = AgentKeypair::generate().expect("admin");
    let group = seed_group(&state, &owner, unix_now() + 86_400, Some(&admin)).await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let renewal = renewal_b64(
        &owner,
        state.agent.identity().agent_keypair(),
        unix_now() + 2 * 86_400,
    );
    let (status, body) = call(&state, &group, &local_hex, Some(renewal)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "waiting_for_receiver_upgrade");
    assert_eq!(body["named"][0], hex::encode(admin.agent_id().as_bytes()));
}

#[tokio::test]
async fn self_rebind_before_the_cutoff_changes_only_the_certificate() {
    let (mut state, _dir) = secure_endpoint_test_state().await.expect("state");
    // The restart sync wait has elapsed; only the per-group head sync
    // (§2) holds the seal.
    Arc::get_mut(&mut state)
        .expect("the fresh test state is not shared yet")
        .revocation_evictions =
        revocation_eviction::S4Runtime::new(x0x::groups::eviction::S4Timing {
            restart_sync_wait: std::time::Duration::ZERO,
            ..x0x::groups::eviction::S4Timing::default()
        });
    let owner = UserKeypair::generate().expect("owner");
    let group = seed_group(&state, &owner, unix_now() + 86_400, None).await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let before = state
        .named_groups
        .read()
        .await
        .get(&group)
        .cloned()
        .expect("group");
    let renewal = renewal_b64(
        &owner,
        state.agent.identity().agent_keypair(),
        unix_now() + 2 * 86_400,
    );
    // §2: no head round has run for the group yet, so the route seals
    // nothing and holds the rebind (#1508 Codex P1 F3).
    let (status, body) = call(&state, &group, &local_hex, Some(renewal.clone())).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "waiting_for_head_sync");
    // One worker iteration: the pass opens the head round (no other
    // holder, so it is synced at once) and the rebind step commits.
    revocation_eviction::revocation_eviction_pass(&state).await;
    revocation_eviction::rebind::drive(&state).await;
    let after = state
        .named_groups
        .read()
        .await
        .get(&group)
        .cloned()
        .expect("group");
    assert_eq!(after.state_revision, before.state_revision + 1);
    let (old, new) = (
        &before.members_v2[&local_hex],
        &after.members_v2[&local_hex],
    );
    assert_eq!(old.role, new.role);
    assert_eq!(old.state, new.state);
    assert_ne!(old.certificate_digest, new.certificate_digest);
    assert_eq!(after.secret_epoch, before.secret_epoch);
    // A second self-rebind with the same certificate is not later.
    let (status, body) = call(&state, &group, &local_hex, Some(renewal)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "rebind_not_later");
}

/// #1533 Codex P2 (ADR 0110 §1a, §4b(2)): the every-admin-expired
/// exception needs every admin, this one too, actually expired on this
/// node's clock (`not_after + τ`). A sole admin whose certificate expires
/// in 60 s is past its cutoff but still eligible: it hands the renewal to
/// the admins (there is none) and never gets the relaxed D76 rule, which
/// would strand a member whose capability is unknown.
#[tokio::test]
async fn an_unexpired_sole_admin_gets_no_every_admin_expired_exception() {
    let (mut state, _dir) = secure_endpoint_test_state().await.expect("state");
    Arc::get_mut(&mut state)
        .expect("the fresh test state is not shared yet")
        .revocation_evictions =
        revocation_eviction::S4Runtime::new(x0x::groups::eviction::S4Timing {
            restart_sync_wait: std::time::Duration::ZERO,
            ..x0x::groups::eviction::S4Timing::default()
        });
    let owner = UserKeypair::generate().expect("owner");
    // Past the cutoff `not_after − τ`, before `not_after` itself.
    let group = seed_group(&state, &owner, unix_now() + 60, None).await;
    // An ordinary member whose capability is unknown (no advert).
    let member = AgentKeypair::generate().expect("member");
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group).expect("group");
        let member_hex = hex::encode(member.agent_id().as_bytes());
        info.members_v2.insert(
            member_hex.clone(),
            x0x::groups::GroupMember::new_member(
                member_hex.clone(),
                None,
                Some(local_hex.clone()),
                1,
            ),
        );
        cr::install_certificate(
            info,
            &member_hex,
            AgentCertificate::issue_with_expiry(&owner, &member, Some(unix_now() + 86_400))
                .expect("member cert"),
        );
        info.recompute_state_hash();
    }
    let renewal = renewal_b64(
        &owner,
        state.agent.identity().agent_keypair(),
        unix_now() + 86_400,
    );
    let (status, body) = call(&state, &group, &local_hex, Some(renewal)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], REBIND_WINDOW_CLOSED, "{body}");
    assert_eq!(body["state"], WAITING_FOR_ADMIN_REBIND);
    // One worker iteration commits nothing: no rebind is held.
    revocation_eviction::revocation_eviction_pass(&state).await;
    revocation_eviction::rebind::drive(&state).await;
    let info = state
        .named_groups
        .read()
        .await
        .get(&group)
        .cloned()
        .expect("group");
    assert_eq!(info.state_revision, 0, "the unknown member is not stranded");
}

/// Seed `agent` in the discovery cache with `cert` as its announced
/// certificate.
async fn announce(state: &AppState, agent: &AgentKeypair, cert: AgentCertificate) {
    let machine = x0x::identity::MachineKeypair::generate().expect("machine");
    state
        .agent
        .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
            agent_id: agent.agent_id(),
            machine_id: machine.machine_id(),
            user_id: cert.user_id().ok(),
            addresses: Vec::new(),
            announced_at: unix_now(),
            last_seen: unix_now(),
            machine_public_key: machine.public_key().as_bytes().to_vec(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: AgentCertificate::not_after(&cert),
            agent_certificate: Some(cert),
            cert_digest: None,
            agent_public_key: agent.public_key().as_bytes().to_vec(),
            self_name: None,
        })
        .await;
}

/// #1508 rc20 (W3-H `s4_certificate_rebind` run (6), INFRA at 2e73321): after
/// the designated admin's post-cutoff rebind, the seat's agent still
/// announces its expired first certificate. The egress member check
/// refused that seat (`CertificateVerdictFailed(Expired)`), so the rebind
/// frame never reached it. The rebind admission also judges the seat by
/// the roster's committed renewal, and still refuses a seat whose
/// committed certificate is expired.
#[tokio::test]
async fn the_rebind_admission_judges_the_rebound_seat_by_its_committed_renewal() {
    let (state, _dir) = secure_endpoint_test_state().await.expect("state");
    let owner = UserKeypair::generate().expect("owner");
    let group = seed_group(&state, &owner, unix_now() + 86_400, None).await;
    let seat = AgentKeypair::generate().expect("seat");
    let seat_hex = hex::encode(seat.agent_id().as_bytes());
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    // Past `not_after + τ`, so the expiry tolerance does not admit it.
    let expired = AgentCertificate::issue_with_expiry(&owner, &seat, Some(unix_now() - 1000))
        .expect("expired");
    let renewal = AgentCertificate::issue_with_expiry(&owner, &seat, Some(unix_now() + 86_400))
        .expect("renewal");
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group).expect("group");
        info.members_v2.insert(
            seat_hex.clone(),
            x0x::groups::GroupMember::new_member(seat_hex.clone(), None, Some(local_hex), 1),
        );
        cr::install_certificate(info, &seat_hex, renewal);
        info.recompute_state_hash();
    }
    announce(&state, &seat, expired.clone()).await;

    assert!(
        join_artifact_member_check(&state, &group, &seat_hex)
            .await
            .is_err(),
        "the ordinary check follows the stale, expired announce"
    );
    assert!(
        join_artifact_member_check_with(&state, &group, &seat_hex, true)
            .await
            .is_ok(),
        "the rebind admission admits the seat on its committed renewal"
    );

    // A committed certificate that is itself expired is still refused.
    {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group).expect("group");
        cr::install_certificate(info, &seat_hex, expired);
        info.recompute_state_hash();
    }
    assert!(
        join_artifact_member_check_with(&state, &group, &seat_hex, true)
            .await
            .is_err(),
        "an expired committed certificate is refused"
    );
}
