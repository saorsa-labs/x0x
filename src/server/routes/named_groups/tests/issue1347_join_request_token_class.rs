//! #1347: one token class for the join-request admin task.
//!
//! `GET /groups/:id/requests`, `POST /groups/:id/requests/:rid/approve` and
//! `POST /groups/:id/requests/:rid/reject` must take the same token class.
//! That class is the class of every other membership change (add, remove,
//! role, ban, invite): a durable or a session bearer, and the durable API
//! token on a Home or an owner-certified group (the central Home fence).
//!
//! The tests go through the real auth middleware. The session token is
//! minted by `POST /auth/session` with the durable token, as the GUI gets
//! it. The agent is offline and the daemon state is in a temp dir.

use super::adr0028_direct_controls::offer_predecessor_obligation_via_real_path;
use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

const ROUTES: [&str; 3] = ["list", "approve", "reject"];

/// The production paths, with the production handlers and middleware.
fn admin_task_router(state: &Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route(
            "/auth/session",
            axum::routing::post(crate::server::auth::create_session),
        )
        .route(
            "/groups/:id/requests",
            axum::routing::get(list_join_requests),
        )
        .route(
            "/groups/:id/requests/:request_id/approve",
            axum::routing::post(approve_join_request),
        )
        .route(
            "/groups/:id/requests/:request_id/reject",
            axum::routing::post(reject_join_request),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(Arc::clone(state))
}

async fn send(
    app: &axum::Router,
    request: Request<Body>,
) -> Result<(StatusCode, serde_json::Value)> {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .unwrap_or_else(|never| match never {});
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Ok((status, body))
}

/// Mint a session token the way `x0x gui` does: `POST /auth/session` with
/// the durable token.
async fn mint_session(app: &axum::Router, durable: &str) -> Result<String> {
    let (status, body) = send(
        app,
        Request::post("/auth/session")
            .header("authorization", format!("Bearer {durable}"))
            .body(Body::empty())?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "mint a session: {body}");
    let token = body["session_token"]
        .as_str()
        .expect("the mint returns session_token")
        .to_string();
    assert_ne!(token, durable, "a session token is not the durable token");
    Ok(token)
}

struct Fixture {
    group_id: String,
    approve_id: String,
    reject_id: String,
}

/// A GSS group with the local agent as its admin and two pending join
/// requests. Each request has a real ADR 0028 predecessor obligation, so
/// an approve can complete. `home` adds Home metadata, which puts the
/// group behind the central Home fence.
async fn seed_group(state: &AppState, suffix: &str, home: bool) -> Result<Fixture> {
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let group_id = format!("issue1347-{suffix}");
    let mut info = x0x::groups::GroupInfo::with_policy(
        format!("join-request token class {suffix}"),
        String::new(),
        state.agent.agent_id(),
        group_id.clone(),
        x0x::groups::GroupPolicyPreset::PrivateSecure.to_policy(),
    );
    info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        format!("issue1347-stable-{suffix}"),
        local_hex.clone(),
        info.created_at,
        String::new(),
    ));
    info.secure_plane = x0x::mls::SecureGroupPlane::Gss;
    if home {
        info.home = Some(x0x::groups::HomeMetadata {
            primary_agent: local_hex.clone(),
            placements: std::collections::BTreeMap::new(),
            provisioned_at_ms: 1,
        });
    }
    let approve_kp = x0x::identity::AgentKeypair::generate()?;
    let reject_kp = x0x::identity::AgentKeypair::generate()?;
    let approve_req = x0x::groups::JoinRequest::new(
        group_id.clone(),
        hex::encode(approve_kp.agent_id().as_bytes()),
        None,
        now_millis_u64(),
    );
    let reject_req = x0x::groups::JoinRequest::new(
        group_id.clone(),
        hex::encode(reject_kp.agent_id().as_bytes()),
        None,
        now_millis_u64(),
    );
    let approve_id = approve_req.request_id.clone();
    let reject_id = reject_req.request_id.clone();
    info.join_requests.insert(approve_id.clone(), approve_req);
    info.join_requests.insert(reject_id.clone(), reject_req);
    info.recompute_state_hash();
    assert_eq!(
        group_access::is_home_or_owner_certified(&info),
        home,
        "fixture: the Home fence covers exactly the Home group"
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    offer_predecessor_obligation_via_real_path(state, &group_id, &approve_id, &approve_kp).await;
    offer_predecessor_obligation_via_real_path(state, &group_id, &reject_id, &reject_kp).await;
    Ok(Fixture {
        group_id,
        approve_id,
        reject_id,
    })
}

/// Run the whole admin task with one bearer: list, approve one request,
/// reject the other. The answers are in [`ROUTES`] order.
async fn run_admin_task(
    app: &axum::Router,
    fixture: &Fixture,
    bearer: &str,
) -> Result<[(StatusCode, serde_json::Value); 3]> {
    let auth = format!("Bearer {bearer}");
    let group = &fixture.group_id;
    let list = send(
        app,
        Request::get(format!("/groups/{group}/requests"))
            .header("authorization", auth.clone())
            .body(Body::empty())?,
    )
    .await?;
    let approve = send(
        app,
        Request::post(format!(
            "/groups/{group}/requests/{}/approve",
            fixture.approve_id
        ))
        .header("authorization", auth.clone())
        .body(Body::empty())?,
    )
    .await?;
    let reject = send(
        app,
        Request::post(format!(
            "/groups/{group}/requests/{}/reject",
            fixture.reject_id
        ))
        .header("authorization", auth)
        .body(Body::empty())?,
    )
    .await?;
    Ok([list, approve, reject])
}

async fn request_status(
    state: &AppState,
    group_id: &str,
    request_id: &str,
) -> Option<x0x::groups::JoinRequestStatus> {
    state
        .named_groups
        .read()
        .await
        .get(group_id)
        .and_then(|info| info.join_requests.get(request_id))
        .map(|request| request.status)
}

/// On an ordinary group a minted session token and the durable token get
/// the same answer on each of the three routes, and both complete the
/// task: the list shows the queue, the approve seats, the reject refuses.
#[tokio::test]
async fn ordinary_group_session_and_durable_tokens_get_one_answer() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let app = admin_task_router(&state);
    let durable = state.api_token.clone();
    let session = mint_session(&app, &durable).await?;

    let by_session = seed_group(&state, "ordinary-session", false).await?;
    let by_durable = seed_group(&state, "ordinary-durable", false).await?;
    let session_answers = run_admin_task(&app, &by_session, &session).await?;
    let durable_answers = run_admin_task(&app, &by_durable, &durable).await?;

    for (route, (session_answer, durable_answer)) in ROUTES
        .iter()
        .zip(session_answers.iter().zip(durable_answers.iter()))
    {
        assert_eq!(
            session_answer.0, durable_answer.0,
            "{route}: one token class, so the session token and the durable token get the \
             same status; session {session_answer:?}, durable {durable_answer:?}"
        );
        assert_eq!(
            session_answer.0,
            StatusCode::OK,
            "{route}: an ordinary-group admin task completes with a session token: \
             {session_answer:?}"
        );
    }
    for answers in [&session_answers, &durable_answers] {
        assert_eq!(
            answers[0].1["requests"].as_array().map(Vec::len),
            Some(2),
            "the list shows both pending requests: {:?}",
            answers[0].1
        );
    }
    for fixture in [&by_session, &by_durable] {
        assert_eq!(
            request_status(&state, &fixture.group_id, &fixture.approve_id).await,
            Some(x0x::groups::JoinRequestStatus::Approved),
            "{}: the approve is applied",
            fixture.group_id
        );
        assert_eq!(
            request_status(&state, &fixture.group_id, &fixture.reject_id).await,
            Some(x0x::groups::JoinRequestStatus::Rejected),
            "{}: the reject is applied",
            fixture.group_id
        );
    }
    Ok(())
}

/// On a Home group a minted session token gets the same typed 403 on all
/// three routes and changes nothing. The durable token completes the task.
#[tokio::test]
async fn home_group_refuses_a_session_token_alike_on_all_three_routes() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let app = admin_task_router(&state);
    let durable = state.api_token.clone();
    let session = mint_session(&app, &durable).await?;
    let fixture = seed_group(&state, "home", true).await?;

    let session_answers = run_admin_task(&app, &fixture, &session).await?;
    for (route, answer) in ROUTES.iter().zip(session_answers.iter()) {
        assert_eq!(
            answer.0,
            StatusCode::FORBIDDEN,
            "{route}: a session token is refused on a Home: {answer:?}"
        );
        assert!(
            answer.1["error"]
                .as_str()
                .is_some_and(|error| error.contains("durable API token")),
            "{route}: the refusal names the durable API token: {answer:?}"
        );
        assert_eq!(
            answer.1, session_answers[0].1,
            "{route}: one token class, so the refusal body is the same on all three routes"
        );
    }
    for request_id in [&fixture.approve_id, &fixture.reject_id] {
        assert_eq!(
            request_status(&state, &fixture.group_id, request_id).await,
            Some(x0x::groups::JoinRequestStatus::Pending),
            "a refused session token leaves request {request_id} pending"
        );
    }

    let durable_answers = run_admin_task(&app, &fixture, &durable).await?;
    for (route, answer) in ROUTES.iter().zip(durable_answers.iter()) {
        assert_eq!(
            answer.0,
            StatusCode::OK,
            "{route}: the durable token completes the Home admin task: {answer:?}"
        );
    }
    assert_eq!(
        durable_answers[0].1["requests"].as_array().map(Vec::len),
        Some(2),
        "the durable list shows both pending requests: {:?}",
        durable_answers[0].1
    );
    assert_eq!(
        request_status(&state, &fixture.group_id, &fixture.approve_id).await,
        Some(x0x::groups::JoinRequestStatus::Approved),
    );
    assert_eq!(
        request_status(&state, &fixture.group_id, &fixture.reject_id).await,
        Some(x0x::groups::JoinRequestStatus::Rejected),
    );
    Ok(())
}
