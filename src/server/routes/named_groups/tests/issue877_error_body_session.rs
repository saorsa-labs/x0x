use super::*;
use axum::body::Body;
use axum::http::{Method, Request};
use axum::routing::post;
use tower::ServiceExt as _;

const GROUP: &str = "issue877-contested";

fn router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/groups/:id/send", post(send_group_public_message))
        .route("/groups/:id/secure/encrypt", post(secure_group_encrypt))
        .route("/groups/:id/secure/decrypt", post(secure_group_decrypt))
        .route("/groups/:id/secure/reseal", post(secure_group_reseal))
        .route(
            "/history",
            axum::routing::delete(crate::server::routes::history::history_purge),
        )
        .route(
            "/task-lists",
            post(crate::server::routes::tasks::create_task_list),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::auth_middleware,
        ))
        .with_state(state)
}

async fn call(
    app: &axum::Router,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value)> {
    call_method(app, Method::POST, path, token, body).await
}

async fn call_method(
    app: &axum::Router,
    method: Method,
    path: &str,
    token: &str,
    body: serde_json::Value,
) -> Result<(StatusCode, serde_json::Value)> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body)?))?;
    response_json(app.clone().oneshot(request).await?).await
}

#[tokio::test]
async fn issue877_nonmember_session_cannot_read_quarantine_error_body() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let foreign = x0x::identity::AgentId([0x87; 32]);
    let mut info = x0x::groups::GroupInfo::new(
        "private roster".into(),
        "do not leak".into(),
        foreign,
        GROUP.into(),
    );
    let clean_epoch = info.lifecycle_epoch_token();
    let header = info.terminal_commit_header();
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: 9,
        state_hash: info.state_hash.clone(),
        committed_by: hex::encode(foreign.as_bytes()),
        observed_at_ms: 1_788_091_300_000,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: header.clone(),
            conflicting_commit: header,
            classification: None,
        },
        no_anchor: true,
    });
    state.named_groups.write().await.insert(GROUP.into(), info);
    let app = router(Arc::clone(&state));
    let session = state.sessions.issue(std::time::Instant::now());
    let session_actor = crate::server::rider_auth::ActorContext::Owner { durable: false };
    let (status, late) = reject_fork_quarantine_installed_before_effect_for_actor(
        &state,
        GROUP,
        Some(&clean_epoch),
        Some(&session_actor),
    )
    .await
    .expect("new marker must refuse at late recheck");
    assert_eq!(status, StatusCode::FORBIDDEN, "{late:?}");
    assert_eq!(late.0["reason"], "group_membership_required");
    assert!(late.0.get("fork_quarantine").is_none());
    let durable_actor = crate::server::rider_auth::ActorContext::Owner { durable: true };
    let (status, late) = reject_fork_quarantine_installed_before_effect_for_actor(
        &state,
        GROUP,
        Some(&clean_epoch),
        Some(&durable_actor),
    )
    .await
    .expect("durable operator also sees late marker");
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(late.0["fork_quarantine"]["revision"], 9);
    let cases = [
        ("send", serde_json::json!({ "body": "private content" })),
        (
            "secure/encrypt",
            serde_json::json!({ "payload_b64": "cA==" }),
        ),
        (
            "secure/decrypt",
            serde_json::json!({ "ciphertext_b64": "Yw==", "nonce_b64": "" }),
        ),
        (
            "secure/reseal",
            serde_json::json!({ "recipient": hex::encode(foreign.as_bytes()) }),
        ),
    ];

    for (suffix, body) in &cases {
        let path = format!("/groups/{GROUP}/{suffix}");
        let (status, denied) = call(&app, &path, &session, body.clone()).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {denied}");
        assert_eq!(
            denied["reason"], "group_membership_required",
            "{path}: {denied}"
        );
        assert!(denied.get("fork_quarantine").is_none(), "{path}: {denied}");
        assert!(
            !denied.to_string().contains("1788091300000"),
            "{path}: {denied}"
        );

        let (status, durable) = call(&app, &path, &state.api_token, body.clone()).await?;
        assert_eq!(status, StatusCode::CONFLICT, "durable {path}: {durable}");
        assert_eq!(
            durable["reason"], "fork_quarantined",
            "durable {path}: {durable}"
        );
        assert_eq!(durable["fork_quarantine"]["revision"], 9);
    }
    let rider = state
        .rider_tokens
        .lock()
        .await
        .issue(
            "83".repeat(32),
            vec![GROUP.to_string()],
            None,
            60,
            "84".repeat(32),
            None,
            None,
            crate::server::rider_auth::unix_now_secs(),
        )
        .await?
        .0;
    for (suffix, body) in &cases[..2] {
        let path = format!("/groups/{GROUP}/{suffix}");
        let (status, rider_body) = call(&app, &path, &rider, body.clone()).await?;
        assert_eq!(status, StatusCode::CONFLICT, "rider {path}: {rider_body}");
        assert_eq!(rider_body["fork_quarantine"]["revision"], 9);
    }

    let (status, unknown) = call(
        &app,
        "/groups/issue877-unknown/send",
        &session,
        serde_json::json!({"body":"x"}),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{unknown}");
    assert!(unknown.get("fork_quarantine").is_none());

    let cross_module = [
        (
            Method::DELETE,
            format!("/history?scope=group:{GROUP}"),
            serde_json::json!({}),
        ),
        (
            Method::POST,
            "/task-lists".to_string(),
            serde_json::json!({"name":"no mutation", "topic":format!("x0x.group.{GROUP}.symphony.inbox")}),
        ),
    ];
    for (method, path, body) in &cross_module {
        let (status, denied) =
            call_method(&app, method.clone(), path, &session, body.clone()).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {denied}");
        assert_eq!(denied["reason"], "group_membership_required");
        assert!(denied.get("fork_quarantine").is_none());
        let (status, durable) =
            call_method(&app, method.clone(), path, &state.api_token, body.clone()).await?;
        assert_eq!(status, StatusCode::CONFLICT, "durable {path}: {durable}");
        assert_eq!(durable["fork_quarantine"]["revision"], 9);
    }
    assert!(!state
        .task_lists
        .read()
        .await
        .contains_key(&format!("x0x.group.{GROUP}.symphony.inbox")));

    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    state
        .named_groups
        .write()
        .await
        .get_mut(GROUP)
        .expect("group")
        .add_member(
            local_hex.clone(),
            x0x::groups::GroupRole::Member,
            None,
            None,
        );
    state
        .named_groups
        .write()
        .await
        .get_mut(GROUP)
        .expect("group")
        .members_v2
        .get_mut(&local_hex)
        .expect("member")
        .state = x0x::groups::GroupMemberState::Pending;
    for (suffix, body) in &cases {
        let path = format!("/groups/{GROUP}/{suffix}");
        let (status, denied) = call(&app, &path, &session, body.clone()).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "pending {path}: {denied}");
        assert_eq!(denied["reason"], "group_membership_required");
        assert!(denied.get("fork_quarantine").is_none());
    }
    state
        .named_groups
        .write()
        .await
        .get_mut(GROUP)
        .expect("group")
        .members_v2
        .get_mut(&local_hex)
        .expect("member")
        .state = x0x::groups::GroupMemberState::Active;
    for (suffix, body) in &cases {
        let path = format!("/groups/{GROUP}/{suffix}");
        let (status, active) = call(&app, &path, &session, body.clone()).await?;
        assert_eq!(status, StatusCode::CONFLICT, "active {path}: {active}");
        assert_eq!(active["reason"], "fork_quarantined");
        assert_eq!(active["fork_quarantine"]["revision"], 9);
    }
    Ok(())
}

/// The request enters on a clean roster. The test hook installs the marker
/// immediately before the send path's final publish check, so only that late
/// path can produce the refusal.
#[tokio::test]
async fn issue877_late_send_refusal_redacts_for_nonmember_session() -> Result<()> {
    const LATE_GROUP: &str = "issue877-late-send";
    let plane = format!("issue877-late-{}", rand::random::<u32>());
    let (state, _dir) = networked_test_state(&plane).await?;
    let foreign = x0x::identity::AgentId([0x87; 32]);
    let mut policy = x0x::groups::GroupPolicyPreset::PublicOpen.to_policy();
    policy.write_access = x0x::groups::GroupWriteAccess::ModeratedPublic;
    let info = x0x::groups::GroupInfo::with_policy(
        "late send".into(),
        String::new(),
        foreign,
        LATE_GROUP.into(),
        policy,
    );
    state
        .named_groups
        .write()
        .await
        .insert(LATE_GROUP.into(), info);
    let app = router(Arc::clone(&state));
    let session = state.sessions.issue(std::time::Instant::now());
    let path = format!("/groups/{LATE_GROUP}/send");
    let body = serde_json::json!({"body":"must not publish"});
    let publishes_before = state
        .agent
        .gossip_stats()
        .map(|s| s.publish_zero_fanout)
        .unwrap_or(0);

    for (token, expected) in [
        (&session, StatusCode::FORBIDDEN),
        (&state.api_token, StatusCode::CONFLICT),
    ] {
        assert!(!state
            .named_groups
            .read()
            .await
            .get(LATE_GROUP)
            .expect("group")
            .is_fork_quarantined());
        let guard = send_recheck_barrier::install(
            LATE_GROUP,
            Box::new(|groups| {
                let info = groups.get_mut(LATE_GROUP).expect("group");
                let header = info.terminal_commit_header();
                info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
                    revision: 4_242,
                    state_hash: info.state_hash.clone(),
                    committed_by: "ff".repeat(32),
                    observed_at_ms: 1_788_091_300_000,
                    snapshot: x0x::groups::ForkSnapshot {
                        terminal_commit: header.clone(),
                        conflicting_commit: header,
                        classification: None,
                    },
                    no_anchor: true,
                });
            }),
        );
        let (status, response) = call(&app, &path, token, body.clone()).await?;
        drop(guard);
        assert_eq!(status, expected, "{response}");
        assert!(response.get("msg_id").is_none(), "{response}");
        if expected == StatusCode::FORBIDDEN {
            assert_eq!(response["reason"], "group_membership_required");
            assert!(response.get("fork_quarantine").is_none(), "{response}");
            assert!(!response.to_string().contains("4242"), "{response}");
        } else {
            assert_eq!(response["reason"], "fork_quarantined");
            assert_eq!(response["fork_quarantine"]["revision"], 4_242);
        }
        assert!(state
            .named_groups
            .read()
            .await
            .get(LATE_GROUP)
            .expect("group")
            .is_fork_quarantined());
        assert_eq!(
            state
                .agent
                .gossip_stats()
                .map(|s| s.publish_zero_fanout)
                .unwrap_or(0),
            publishes_before,
            "late refusal must not publish"
        );
        state
            .named_groups
            .write()
            .await
            .get_mut(LATE_GROUP)
            .expect("group")
            .fork_quarantine = None;
    }
    state.agent.shutdown().await;
    Ok(())
}
