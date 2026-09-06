// #491 RT-2: HTTP 409 coverage for BOTH leave arms via a TEST ROUTER
// wrapping the production leave_group handler (not the full production
// router with auth middleware). In-process oneshot — no socket/network.
// The shared fixture calls Agent::builder().build() without network
// config (no QUIC endpoint, no socket bind); gossip publish paths
// no-op with gossip_runtime=None.
#![cfg(test)]

use super::super::*;
use crate::server::rider_auth::ActorContext;
use std::sync::Arc;
use tower::ServiceExt as _;

/// Build an OWNED state (user key) with a group that has a digest-only
/// member seat (pending certificate resolution), then DELETE it through
/// a test router wrapping the production leave_group handler.
async fn owned_state_with_pending_member(
    dir: &std::path::Path,
    secure_plane: crate::mls::SecureGroupPlane,
) -> Arc<crate::server::AppState> {
    let user = crate::identity::UserKeypair::from_seed(&[0x52; 32]).unwrap();
    let agent = Arc::new(
        crate::Agent::builder()
            .with_machine_key(dir.join("machine.key"))
            .with_agent_key_path(dir.join("agent.key"))
            .with_agent_cert_path(dir.join("agent.cert"))
            .with_user_key(user)
            .with_peer_cache_disabled()
            .with_contact_store_path(dir.join("contacts.json"))
            .build()
            .await
            .unwrap(),
    );
    let state = tests::secure_endpoint_test_state_at(dir, agent)
        .await
        .unwrap();

    let owner = state.agent.identity().user_keypair().unwrap().user_id();
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = "aa52".repeat(8);

    let policy = crate::groups::GroupPolicy {
        admission: crate::groups::GroupAdmission::OwnerCertified(owner),
        ..Default::default()
    };
    let mut group = crate::groups::GroupInfo::with_policy(
        "Home".to_string(),
        String::new(),
        crate::identity::AgentId([1; 32]),
        group_id.clone(),
        policy,
    );
    group.secure_plane = secure_plane;
    group.state_revision = 1;
    group.state_hash = "h1".to_string();
    group.roster_revision = 1;
    // The constructor auto-seeds the creator into members_v2; remove it
    // so the roster contains ONLY the members we explicitly manage.
    let creator_hex = hex::encode(crate::identity::AgentId([1; 32]).as_bytes());
    group.members_v2.remove(&creator_hex);
    group.members_v2.insert(
        local_hex.clone(),
        crate::groups::GroupMember::new_admin(local_hex.clone(), None, 1),
    );
    let pending_hex = format!("{:02x}", 0xbb).repeat(32);
    let mut pending_member = crate::groups::GroupMember::new_admin(pending_hex.clone(), None, 1);
    pending_member.certificate = None;
    pending_member.certificate_digest = Some("cafe".repeat(16));
    group.members_v2.insert(pending_hex, pending_member);

    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), group);
    state
}

/// Test router wrapping the production `leave_group` handler with a
/// durable-owner ActorContext extension (bypasses the auth middleware;
/// the handler itself is the production code under test).
fn leave_router(state: &Arc<crate::server::AppState>) -> axum::Router {
    axum::Router::new()
        .route("/groups/:id", axum::routing::delete(leave_group))
        .layer(axum::Extension(ActorContext::Owner { durable: true }))
        .with_state(Arc::clone(state))
}

async fn delete_group(
    state: &Arc<crate::server::AppState>,
    group_id: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    let app = leave_router(state);
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::DELETE)
                .uri(format!("/groups/{group_id}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();
    (status, body)
}

/// RT-2a: TreeKEM arm — DELETE on an owner-certified TreeKEM group with
/// a digest-only member returns 409 CONFLICT with the specific
/// pending-certificate message (not just any 409, not 500).
#[tokio::test]
async fn n491_rt2_treekem_leave_409_pending_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let state =
        owned_state_with_pending_member(dir.path(), crate::mls::SecureGroupPlane::TreeKem).await;
    let group_id = "aa52".repeat(8);

    let (status, body) = delete_group(&state, &group_id).await;

    assert_eq!(
        status,
        axum::http::StatusCode::CONFLICT,
        "TreeKEM leave must return 409 on pending certificate; got {status}, body: {body}"
    );
    let error_msg = body["error"].as_str().unwrap_or_default();
    assert!(
        error_msg.contains("pending certificate resolution"),
        "409 body must identify the pending-certificate condition; got: {error_msg}"
    );
}

/// RT-2b: non-TreeKEM (GSS) arm — same digest-only shape, same typed 409
/// with the pending-certificate message.
#[tokio::test]
async fn n491_rt2_gss_leave_409_pending_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let state =
        owned_state_with_pending_member(dir.path(), crate::mls::SecureGroupPlane::Gss).await;
    let group_id = "aa52".repeat(8);

    let (status, body) = delete_group(&state, &group_id).await;

    assert_eq!(
        status,
        axum::http::StatusCode::CONFLICT,
        "GSS leave must return 409 on pending certificate; got {status}, body: {body}"
    );
    let error_msg = body["error"].as_str().unwrap_or_default();
    assert!(
        error_msg.contains("pending certificate resolution"),
        "409 body must identify the pending-certificate condition; got: {error_msg}"
    );
}

/// NEGATIVE CONTROL: a member with a VALID SETTLED certificate (the
/// cert's actual agent ID used consistently as roster key and member
/// agent_id) does NOT trigger the 409 pending-certificate path. A real
/// second agent keypair is generated, the owner issues a certificate,
/// and the roster seat is keyed by the CERT's agent ID (not a fabricated
/// hex string). The leave proceeds past the seal without the
/// pending-certificate refusal.
#[tokio::test]
async fn n491_rt2_settled_certificate_member_not_409() {
    let dir = tempfile::tempdir().unwrap();
    let state =
        owned_state_with_pending_member(dir.path(), crate::mls::SecureGroupPlane::Gss).await;

    // Generate a real second agent and issue a cert from the owner.
    let user_kp = state.agent.identity().user_keypair().unwrap();
    let member_kp = crate::identity::AgentKeypair::generate().unwrap();
    let cert = crate::identity::AgentCertificate::issue(user_kp, &member_kp).unwrap();
    let cert_digest = crate::groups::owner_cert::certificate_digest_hex(&cert);
    // The CERT's agent_id is the real member identity.
    let real_member_hex = hex::encode(cert.agent_id().unwrap().as_bytes());
    // Prove the cert verifies for this agent.
    assert!(
        cert.agent_id().is_ok() && cert.user_id().is_ok(),
        "cert must verify (agent_id + user_id extractable)"
    );

    let group_id = "aa52".repeat(8);
    let fabricated_hex = format!("{:02x}", 0xbb).repeat(32);
    {
        let mut groups = state.named_groups.write().await;
        if let Some(info) = groups.get_mut(&group_id) {
            // Remove the fabricated digest-only member.
            info.members_v2.remove(&fabricated_hex);
            // Insert a member keyed by the CERT's real agent ID, with the
            // certificate bytes and matching digest — a settled seat.
            let mut settled =
                crate::groups::GroupMember::new_admin(real_member_hex.clone(), None, 1);
            settled.certificate = Some(cert);
            settled.certificate_digest = Some(cert_digest);
            info.members_v2.insert(real_member_hex.clone(), settled);
        }
    }

    let (status, body) = delete_group(&state, &group_id).await;

    // The settled member must NOT trigger the pending-certificate refusal.
    // With the leaver removed and the remaining member's cert settled, the
    // seal must succeed (or fail for a named non-pending reason). We
    // require a SPECIFIC valid outcome: 200 (successful leave) — not
    // just "any non-409".
    let _error_msg = body["error"].as_str().unwrap_or_default();
    assert!(
        status == axum::http::StatusCode::OK,
        "settled-certificate member: leave must succeed (200), not the 409 \
         pending-certificate refusal; got {status}, body: {body}"
    );
    assert!(
        body["ok"].as_bool().unwrap_or(false) || !body["left"].is_null(),
        "successful leave response must carry ok=true or left=...; got: {body}"
    );
}
