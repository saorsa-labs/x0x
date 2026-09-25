use super::*;
use axum::body::Body;
use axum::http::Request;
use axum::routing::get;
use tower::ServiceExt as _;

async fn read(
    app: &axum::Router,
    path: &str,
    token: Option<&str>,
) -> Result<(StatusCode, serde_json::Value)> {
    let mut request = Request::get(path);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app.clone().oneshot(request.body(Body::empty())?).await?;
    response_json(response).await
}

#[tokio::test]
async fn named_group_reads_enforce_session_membership_through_auth_middleware() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "issue821-known";
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let foreign_creator = x0x::identity::AgentId([0x82; 32]);
    let foreign_hex = hex::encode(foreign_creator.as_bytes());
    let info = x0x::groups::GroupInfo::new(
        "private details".to_string(),
        "do not leak".to_string(),
        foreign_creator,
        group_id.to_string(),
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.to_string(), info);

    let app = axum::Router::new()
        .route("/groups/:id", get(get_named_group))
        .route("/groups/:id/members", get(get_named_group_members))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::auth_middleware,
        ))
        .with_state(Arc::clone(&state));
    let session = state.sessions.issue(std::time::Instant::now());
    let rider = {
        let mut tokens = state.rider_tokens.lock().await;
        tokens
            .issue(
                "83".repeat(32),
                vec![group_id.to_string()],
                None,
                60,
                "84".repeat(32),
                None,
                None,
                crate::server::rider_auth::unix_now_secs(),
            )
            .await?
            .0
    };
    let detail = format!("/groups/{group_id}");
    let members = format!("{detail}/members");

    for path in [&detail, &members] {
        let (status, _) = read(&app, path, None).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        let (status, _) = read(&app, path, Some(&rider)).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "rider {path}");
        let (status, body) = read(&app, path, Some(&session)).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        assert_eq!(body["reason"], "group_membership_required");
        assert!(body.get("members").is_none(), "{path}: {body}");
        let (status, body) = read(&app, path, Some(&state.api_token)).await?;
        assert_eq!(status, StatusCode::OK, "durable {path}: {body}");
        assert_eq!(body["group_id"], group_id);
    }
    let (_, durable_detail) = read(&app, &detail, Some(&state.api_token)).await?;
    assert_eq!(durable_detail["description"], "do not leak");
    assert!(durable_detail.get("invite_lineage").is_some());
    assert!(durable_detail.get("fork_quarantine").is_some());

    for suffix in ["", "/members"] {
        let path = format!("/groups/issue821-unknown{suffix}");
        let (status, _) = read(&app, &path, Some(&session)).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }

    record_expected_join_result_inviter(
        state.as_ref(),
        join_result_key(group_id, &local_hex),
        foreign_hex,
    );
    let (status, body) = read(&app, &detail, Some(&session)).await?;
    assert_eq!(status, StatusCode::OK, "pending detail: {body}");
    assert_eq!(
        body,
        serde_json::json!({
            "ok": true,
            "group_id": group_id,
            "membership_state": "pending_authority_commit",
        })
    );
    let (status, body) = read(&app, &members, Some(&session)).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "pending roster: {body}");
    assert_eq!(body["reason"], "group_membership_required");

    state
        .named_groups
        .write()
        .await
        .get_mut(group_id)
        .expect("group")
        .add_member(local_hex, x0x::groups::GroupRole::Member, None, None);
    for path in [&detail, &members] {
        let (status, body) = read(&app, path, Some(&session)).await?;
        assert_eq!(status, StatusCode::OK, "active {path}: {body}");
        assert!(body.get("members").is_some(), "active {path}: {body}");
    }
    Ok(())
}
