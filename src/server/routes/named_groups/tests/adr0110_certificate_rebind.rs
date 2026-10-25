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

/// #1357 rc21 fixture: the local daemon holds the owner key `U` (seed
/// `owner_seed`) and starts on an `agent.cert` that `U` issued with
/// `not_after`, as a W3-H Home device does. Returns the state, its data
/// directory, `U`, and the agent keypair (a copy) for building renewals.
async fn expiring_device_state(
    owner_seed: [u8; 32],
    not_after: u64,
) -> (Arc<AppState>, tempfile::TempDir, UserKeypair, AgentKeypair) {
    let dir = tempfile::tempdir().expect("dir");
    let data_dir = dir.path();
    let owner = UserKeypair::from_seed(&owner_seed).expect("owner");
    let agent = AgentKeypair::generate().expect("agent");
    let agent_bytes = x0x::storage::serialize_agent_keypair(&agent).expect("agent bytes");
    let first =
        AgentCertificate::issue_with_expiry(&owner, &agent, Some(not_after)).expect("first");
    x0x::storage::save_agent_certificate_to(&first, data_dir.join("agent.cert"))
        .await
        .expect("save first cert");
    let built = Arc::new(
        Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(agent)
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_user_key(UserKeypair::from_seed(&owner_seed).expect("owner"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await
            .expect("agent"),
    );
    assert_eq!(
        built
            .agent_certificate()
            .and_then(AgentCertificate::not_after),
        Some(not_after),
        "the daemon starts on its expiring certificate"
    );
    let state = secure_endpoint_test_state_at(data_dir, built)
        .await
        .expect("state");
    let copy = x0x::storage::deserialize_agent_keypair(&agent_bytes).expect("agent copy");
    (state, dir, owner, copy)
}

async fn cert_on_disk(dir: &tempfile::TempDir) -> AgentCertificate {
    x0x::storage::load_agent_certificate_from(dir.path().join("agent.cert"))
        .await
        .expect("agent.cert")
}

/// #1357 rc21 (ADR 0110 §4a run (6); Engineer call 24 Oct 2026): after the
/// cutoff the route hands B's renewal to the admin, and B itself now uses
/// that renewal: `agent.cert` holds it (so a restart keeps it) and the
/// identity announces it. Before rc21 B kept its first certificate until a
/// restart, so after `not_after` no peer's pinned send reached B and the
/// admin's rebind frame never arrived.
#[tokio::test]
async fn rc21_post_cutoff_self_rebind_adopts_the_daemons_own_renewal() {
    let first_not_after = unix_now() + 60;
    let (state, dir, owner, agent) = expiring_device_state([0x57u8; 32], first_not_after).await;
    let admin = AgentKeypair::generate().expect("admin");
    let group = seed_group(&state, &owner, first_not_after, Some(&admin)).await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let renewed_not_after = unix_now() + 86_400;
    let renewal = renewal_b64(&owner, &agent, renewed_not_after);
    let (status, body) = call(&state, &group, &local_hex, Some(renewal)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], REBIND_WINDOW_CLOSED, "{body}");
    assert_eq!(
        state
            .agent
            .agent_certificate()
            .and_then(AgentCertificate::not_after),
        Some(renewed_not_after),
        "the daemon uses its renewal at once"
    );
    assert_eq!(
        cert_on_disk(&dir).await.not_after(),
        Some(renewed_not_after)
    );
    // The committed seat is unchanged: only the admin commits after the
    // cutoff.
    let info = state
        .named_groups
        .read()
        .await
        .get(&group)
        .cloned()
        .expect("group");
    assert_eq!(info.state_revision, 0);
    assert_eq!(
        cr::committed_certificate(&info.members_v2[&local_hex])
            .and_then(AgentCertificate::not_after),
        Some(first_not_after)
    );
    // A restart loads the renewal from `agent.cert`.
    let agent_bytes = x0x::storage::serialize_agent_keypair(&agent).expect("agent bytes");
    let restarted = Agent::builder()
        .with_machine_key(dir.path().join("machine.key"))
        .with_agent_key(x0x::storage::deserialize_agent_keypair(&agent_bytes).expect("agent"))
        .with_agent_cert_path(dir.path().join("agent.cert"))
        .with_user_key(UserKeypair::from_seed(&[0x57u8; 32]).expect("owner"))
        .with_peer_cache_disabled()
        .with_contact_store_path(dir.path().join("contacts-restarted.json"))
        .build()
        .await
        .expect("restarted agent");
    assert_eq!(
        restarted
            .agent_certificate()
            .and_then(AgentCertificate::not_after),
        Some(renewed_not_after)
    );
}

/// #1357 rc21 guards: a renewal is adopted only for this daemon's own
/// agent, from the same user, unexpired, verified, and strictly later than
/// the certificate in use; it never downgrades. Every refusal leaves
/// memory and `agent.cert` unchanged.
#[tokio::test]
async fn rc21_own_renewal_adoption_refuses_older_foreign_and_downgrade() {
    use x0x::identity::CertificateRenewalRefusal as Refusal;
    use x0x::CertificateRenewalAdoption as Adoption;
    let first_not_after = unix_now() + 3_600;
    let (state, dir, owner, agent) = expiring_device_state([0x58u8; 32], first_not_after).await;
    let refused = |result: x0x::error::Result<Adoption>| match result.expect("no io error") {
        Adoption::Refused(refusal) => refusal,
        Adoption::Adopted => panic!("adopted a renewal that must be refused"),
    };
    let unchanged = async |state: &Arc<AppState>| {
        assert_eq!(
            state
                .agent
                .agent_certificate()
                .and_then(AgentCertificate::not_after),
            Some(first_not_after)
        );
        assert_eq!(cert_on_disk(&dir).await.not_after(), Some(first_not_after));
    };
    // Older and equal expiry.
    let older =
        AgentCertificate::issue_with_expiry(&owner, &agent, Some(first_not_after - 60)).unwrap();
    assert_eq!(
        refused(state.agent.adopt_own_certificate_renewal(&older).await),
        Refusal::NotLater
    );
    let equal = AgentCertificate::issue_with_expiry(&owner, &agent, Some(first_not_after)).unwrap();
    assert_eq!(
        refused(state.agent.adopt_own_certificate_renewal(&equal).await),
        Refusal::NotLater
    );
    unchanged(&state).await;
    // Another agent's certificate, even from the same owner.
    let stranger = AgentKeypair::generate().unwrap();
    let foreign =
        AgentCertificate::issue_with_expiry(&owner, &stranger, Some(first_not_after + 60)).unwrap();
    assert_eq!(
        refused(state.agent.adopt_own_certificate_renewal(&foreign).await),
        Refusal::ForeignAgent
    );
    // This agent's certificate from another user.
    let other_owner = UserKeypair::generate().unwrap();
    let other_user =
        AgentCertificate::issue_with_expiry(&other_owner, &agent, Some(first_not_after + 60))
            .unwrap();
    assert_eq!(
        refused(state.agent.adopt_own_certificate_renewal(&other_user).await),
        Refusal::ForeignUser
    );
    // A forged expiry: the signature covers `not_after`.
    let mut storage =
        AgentCertificate::issue_with_expiry(&owner, &agent, Some(first_not_after + 60))
            .unwrap()
            .to_storage_bytes()
            .unwrap();
    let forged_not_after = (first_not_after + 120).to_le_bytes();
    let at = storage
        .windows(8)
        .rposition(|w| w == (first_not_after + 60).to_le_bytes())
        .expect("not_after bytes");
    storage[at..at + 8].copy_from_slice(&forged_not_after);
    let forged = AgentCertificate::from_storage_bytes(&storage).expect("decodes");
    assert_eq!(forged.not_after(), Some(first_not_after + 120));
    assert_eq!(
        refused(state.agent.adopt_own_certificate_renewal(&forged).await),
        Refusal::InvalidSignature
    );
    unchanged(&state).await;
    // A later renewal is adopted; a non-expiring one after it too; then no
    // expiring certificate replaces the non-expiring one.
    let later =
        AgentCertificate::issue_with_expiry(&owner, &agent, Some(first_not_after + 60)).unwrap();
    assert_eq!(
        state
            .agent
            .adopt_own_certificate_renewal(&later)
            .await
            .unwrap(),
        Adoption::Adopted
    );
    assert_eq!(cert_on_disk(&dir).await, later);
    let forever = AgentCertificate::issue_with_expiry(&owner, &agent, None).unwrap();
    assert_eq!(
        state
            .agent
            .adopt_own_certificate_renewal(&forever)
            .await
            .unwrap(),
        Adoption::Adopted
    );
    let after_forever =
        AgentCertificate::issue_with_expiry(&owner, &agent, Some(unix_now() + 10 * 86_400))
            .unwrap();
    assert_eq!(
        refused(
            state
                .agent
                .adopt_own_certificate_renewal(&after_forever)
                .await
        ),
        Refusal::NotLater
    );
    assert_eq!(state.agent.agent_certificate(), Some(&forever));
    assert_eq!(cert_on_disk(&dir).await, forever);
}
