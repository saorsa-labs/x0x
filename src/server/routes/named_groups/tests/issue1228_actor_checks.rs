//! #1228: session tokens must not clear fork quarantine or drive legacy
//! MLS routes. Display-name requires an active seat of any role.
//! Cancelling a join request is limited to an owner. #1347: the
//! join-request list takes the class of approve and reject (the Home
//! fence); `issue1347_join_request_token_class` tests all three.

use super::super::super::groups::{
    add_mls_member, create_mls_group, create_mls_welcome, get_mls_group, list_mls_groups,
    mls_decrypt, mls_encrypt, remove_mls_member, AddMlsMemberRequest, CreateMlsGroupRequest,
    CreateWelcomeRequest, MlsDecryptRequest, MlsEncryptRequest,
};
use super::*;

fn session() -> crate::server::rider_auth::ActorContext {
    crate::server::rider_auth::ActorContext::Owner { durable: false }
}

fn durable() -> crate::server::rider_auth::ActorContext {
    crate::server::rider_auth::ActorContext::Owner { durable: true }
}

fn rider() -> crate::server::rider_auth::ActorContext {
    crate::server::rider_auth::ActorContext::Rider {
        sub_agent_id: "aa".repeat(32),
        token_id: 1,
        token_hash: "hash".to_string(),
        groups: Vec::new(),
    }
}

async fn json_response(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let body = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body"),
    )
    .unwrap_or(serde_json::Value::Null);
    (status, body)
}

fn group_with_local_role(
    state: &AppState,
    id: &str,
    role: x0x::groups::GroupRole,
) -> x0x::groups::GroupInfo {
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let mut info = x0x::groups::GroupInfo::new(
        id.to_string(),
        "desc".to_string(),
        state.agent.agent_id(),
        id.to_string(),
    );
    info.add_member(local, role, None, None);
    info
}

/// A session token is refused before the marker is touched. The durable
/// owner can clear it with force and a reason.
#[tokio::test]
async fn session_token_cannot_clear_fork_quarantine() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "ab".repeat(32);
    let mut info = x0x::groups::GroupInfo::new(
        "quarantined".to_string(),
        "desc".to_string(),
        state.agent.agent_id(),
        group_id.clone(),
    );
    let header = info.terminal_commit_header();
    info.fork_quarantine = Some(x0x::groups::ForkQuarantine {
        revision: 1,
        state_hash: info.state_hash.clone(),
        committed_by: hex::encode(state.agent.agent_id().as_bytes()),
        observed_at_ms: 1,
        snapshot: x0x::groups::ForkSnapshot {
            terminal_commit: header.clone(),
            conflicting_commit: header,
            classification: None,
        },
        no_anchor: true,
    });
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    let session_req: ClearQuarantineRequest =
        serde_json::from_value(serde_json::json!({ "force": true, "reason": "session attempt" }))?;
    let (status, body) = json_response(
        clear_group_quarantine(
            State(Arc::clone(&state)),
            Extension(session()),
            Path(group_id.clone()),
            Json(session_req),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("durable API token"),
        "{body}"
    );
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .is_some_and(|info| info.fork_quarantine.is_some()),
        "a refused session clear must leave the marker"
    );

    let durable_req: ClearQuarantineRequest = serde_json::from_value(
        serde_json::json!({ "force": true, "reason": "operator confirmed the split" }),
    )?;
    let (status, body) = json_response(
        clear_group_quarantine(
            State(Arc::clone(&state)),
            Extension(durable()),
            Path(group_id.clone()),
            Json(durable_req),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .is_some_and(|info| info.fork_quarantine.is_none()),
        "the durable owner clear removes the marker: {body}"
    );
    Ok(())
}

/// #1347: the join-request list takes the Home fence, as approve and
/// reject do. A session token lists an ordinary group's requests with an
/// admin seat. On a Home the session token is refused and the durable
/// owner lists.
#[tokio::test]
async fn session_token_lists_join_requests_only_outside_a_home() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let ordinary_id = "cd".repeat(32);
    let home_id = "ce".repeat(32);
    let local = hex::encode(state.agent.agent_id().as_bytes());
    for (group_id, home) in [(&ordinary_id, false), (&home_id, true)] {
        let mut info = group_with_local_role(&state, group_id, x0x::groups::GroupRole::Admin);
        if home {
            info.home = Some(x0x::groups::HomeMetadata {
                primary_agent: local.clone(),
                placements: std::collections::BTreeMap::new(),
                provisioned_at_ms: 1,
            });
        }
        let request = x0x::groups::JoinRequest::new(group_id.clone(), "ee".repeat(32), None, 1);
        info.join_requests
            .insert(request.request_id.clone(), request);
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info);
    }
    let list = |actor, group_id: &String| {
        list_join_requests(
            State(Arc::clone(&state)),
            Extension(actor),
            Path(group_id.clone()),
            group_access::GroupAccess::for_handler_tests(local.clone()),
        )
    };

    let (status, body) = json_response(list(session(), &ordinary_id).await.into_response()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["requests"].as_array().map(Vec::len), Some(1), "{body}");

    let (status, body) = json_response(list(session(), &home_id).await.into_response()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("durable API token"),
        "{body}"
    );

    let (status, body) = json_response(list(durable(), &home_id).await.into_response()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["requests"].as_array().map(Vec::len), Some(1), "{body}");
    Ok(())
}

/// A rider cannot cancel the daemon's join request. A session owner is
/// not refused by that actor gate: a missing group is still a 404.
#[tokio::test]
async fn rider_cannot_cancel_a_join_request() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "ef".repeat(32);
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let mut info = group_with_local_role(&state, &group_id, x0x::groups::GroupRole::Member);
    let request = x0x::groups::JoinRequest::new(group_id.clone(), local, None, 1);
    let request_id = request.request_id.clone();
    info.join_requests.insert(request_id.clone(), request);
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    let (status, body) = json_response(
        cancel_join_request(
            State(Arc::clone(&state)),
            Extension(rider()),
            Path((group_id.clone(), request_id.clone())),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .and_then(|info| info.join_requests.get(&request_id))
            .is_some_and(|request| request.status == x0x::groups::JoinRequestStatus::Pending),
        "a rider cancel must leave the request pending"
    );

    let (status, body) = json_response(
        cancel_join_request(
            State(Arc::clone(&state)),
            Extension(session()),
            Path(("missing-group".to_string(), "missing-request".to_string())),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    Ok(())
}

/// A caller with no seat cannot set a display name. A member seat can.
#[tokio::test]
async fn display_name_requires_an_active_seat() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let outsider_id = "11".repeat(32);
    let member_id = "22".repeat(32);
    let local = hex::encode(state.agent.agent_id().as_bytes());
    let other = x0x::identity::AgentKeypair::generate().expect("keypair");
    {
        let mut groups = state.named_groups.write().await;
        groups.insert(
            outsider_id.clone(),
            x0x::groups::GroupInfo::new(
                "outsider".to_string(),
                "desc".to_string(),
                other.agent_id(),
                outsider_id.clone(),
            ),
        );
        groups.insert(
            member_id.clone(),
            group_with_local_role(&state, &member_id, x0x::groups::GroupRole::Member),
        );
    }

    let (status, body) = json_response(
        set_group_display_name(
            State(Arc::clone(&state)),
            Path(outsider_id.clone()),
            Json(SetDisplayNameRequest {
                name: "Outsider".to_string(),
            }),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("active seat")),
        "{body}"
    );
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&outsider_id)
            .is_some_and(|info| info.display_name(&local) != "Outsider"),
        "a non-member must not store the name"
    );

    let (status, body) = json_response(
        set_group_display_name(
            State(Arc::clone(&state)),
            Path(member_id.clone()),
            Json(SetDisplayNameRequest {
                name: "Ada".to_string(),
            }),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        state
            .named_groups
            .read()
            .await
            .get(&member_id)
            .map(|info| info.display_name(&local)),
        Some("Ada".to_string())
    );
    Ok(())
}

/// Every legacy MLS route refuses a session token before it touches a group.
#[tokio::test]
async fn session_token_cannot_use_legacy_mls_routes() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let id = "33".repeat(32);
    let (status, body) = json_response(
        create_mls_group(
            State(Arc::clone(&state)),
            Extension(session()),
            Json(CreateMlsGroupRequest {
                group_id: Some(id.clone()),
            }),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, _) = json_response(
        list_mls_groups(State(Arc::clone(&state)), Extension(session()))
            .await
            .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = json_response(
        get_mls_group(
            State(Arc::clone(&state)),
            Extension(session()),
            Path(id.clone()),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = json_response(
        add_mls_member(
            State(Arc::clone(&state)),
            Extension(session()),
            Path(id.clone()),
            Json(AddMlsMemberRequest {
                agent_id: "44".repeat(32),
            }),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = json_response(
        remove_mls_member(
            State(Arc::clone(&state)),
            Extension(session()),
            Path((id.clone(), "44".repeat(32))),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = mls_encrypt(
        State(Arc::clone(&state)),
        Extension(session()),
        Path(id.clone()),
        Json(MlsEncryptRequest {
            payload: BASE64.encode(b"secret"),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = mls_decrypt(
        State(Arc::clone(&state)),
        Extension(session()),
        Path(id.clone()),
        Json(MlsDecryptRequest {
            ciphertext: BASE64.encode(b"cipher"),
            epoch: 0,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = json_response(
        create_mls_welcome(
            State(Arc::clone(&state)),
            Extension(session()),
            Path(id),
            Json(CreateWelcomeRequest {
                agent_id: "44".repeat(32),
            }),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        state.mls_groups.read().await.is_empty(),
        "a session token must not create an MLS group"
    );
    Ok(())
}

/// The durable owner can create a legacy MLS group and then list it.
#[tokio::test]
async fn durable_owner_can_create_and_list_an_mls_group() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let id = "55".repeat(32);
    let (status, body) = json_response(
        create_mls_group(
            State(Arc::clone(&state)),
            Extension(durable()),
            Json(CreateMlsGroupRequest {
                group_id: Some(id.clone()),
            }),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = json_response(
        list_mls_groups(State(Arc::clone(&state)), Extension(session()))
            .await
            .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = json_response(
        list_mls_groups(State(Arc::clone(&state)), Extension(durable()))
            .await
            .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = body["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .any(|group| group["group_id"] == id);
    assert!(listed, "durable list missing {id}: {body}");

    let (status, body) = json_response(
        get_mls_group(
            State(Arc::clone(&state)),
            Extension(durable()),
            Path(id.clone()),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["group_id"], id);

    let member = "66".repeat(32);
    let (status, body) = json_response(
        add_mls_member(
            State(Arc::clone(&state)),
            Extension(durable()),
            Path(id.clone()),
            Json(AddMlsMemberRequest {
                agent_id: member.clone(),
            }),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = json_response(
        create_mls_welcome(
            State(Arc::clone(&state)),
            Extension(durable()),
            Path(id.clone()),
            Json(CreateWelcomeRequest {
                agent_id: member.clone(),
            }),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = json_response(
        remove_mls_member(
            State(Arc::clone(&state)),
            Extension(durable()),
            Path((id, member)),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

/// A session owner can cancel the daemon's own pending join request.
#[tokio::test]
async fn session_owner_can_cancel_its_own_join_request() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "77".repeat(32);
    let local = hex::encode(state.agent.agent_id().as_bytes());
    // The creator stays an active admin. A member-only roster cannot seal:
    // a live group must keep one active admin.
    let mut info = x0x::groups::GroupInfo::new(
        group_id.clone(),
        "desc".to_string(),
        state.agent.agent_id(),
        group_id.clone(),
    );
    let request = x0x::groups::JoinRequest::new(group_id.clone(), local, None, 1);
    let request_id = request.request_id.clone();
    info.join_requests.insert(request_id.clone(), request);
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);

    let (status, body) = json_response(
        cancel_join_request(
            State(Arc::clone(&state)),
            Extension(session()),
            Path((group_id.clone(), request_id.clone())),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .and_then(|info| info.join_requests.get(&request_id))
            .is_some_and(|request| request.status == x0x::groups::JoinRequestStatus::Cancelled),
        "the session owner cancel must mark the request cancelled: {body}"
    );
    Ok(())
}

/// A minted session token is refused by auth middleware before a malformed
/// body is parsed. #1347: on an ordinary group the list takes a session
/// token and the durable token alike.
#[tokio::test]
async fn minted_session_token_is_refused_before_the_body() -> Result<()> {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "88".repeat(32);
    state.named_groups.write().await.insert(
        group_id.clone(),
        group_with_local_role(&state, &group_id, x0x::groups::GroupRole::Admin),
    );
    let session = state.sessions.issue(std::time::Instant::now());
    let durable_token = state.api_token.clone();
    let app = axum::Router::new()
        .route(
            "/groups/:id/quarantine/clear",
            axum::routing::post(clear_group_quarantine),
        )
        .route(
            "/groups/:id/requests",
            axum::routing::get(list_join_requests),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(Arc::clone(&state));

    let response = app
        .clone()
        .oneshot(
            Request::post(format!("/groups/{group_id}/quarantine/clear"))
                .header("authorization", format!("Bearer {session}"))
                .header("content-type", "application/json")
                .body(Body::from("not-json"))
                .expect("body builds"),
        )
        .await
        .unwrap_or_else(|never| match never {});
    let (status, body) = json_response(response).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("durable")),
        "a malformed body must still be the durable 403: {body}"
    );

    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/groups/{group_id}/requests"))
                .header("authorization", format!("Bearer {session}"))
                .body(Body::empty())
                .expect("body builds"),
        )
        .await
        .unwrap_or_else(|never| match never {});
    let (status, body) = json_response(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["requests"].as_array().map(Vec::len), Some(0), "{body}");

    let response = app
        .oneshot(
            Request::get(format!("/groups/{group_id}/requests"))
                .header("authorization", format!("Bearer {durable_token}"))
                .body(Body::empty())
                .expect("body builds"),
        )
        .await
        .unwrap_or_else(|never| match never {});
    let (status, body) = json_response(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["requests"].as_array().map(Vec::len), Some(0), "{body}");
    Ok(())
}

fn open_envelope_test_body(state: &AppState) -> Result<serde_json::Value> {
    let group_id = "issue1228-open-envelope";
    let recipient = hex::encode(state.agent.agent_id().as_bytes());
    let aad = secure_share_aad(group_id, &recipient, 7);
    let (kem_ct, nonce, aead_ct) = x0x::groups::kem_envelope::seal_group_secret_to_recipient(
        &state.agent_kem_keypair.public_bytes,
        &aad,
        &[7_u8; 32],
    )?;
    Ok(serde_json::json!({
        "group_id": group_id,
        "recipient": recipient,
        "secret_epoch": 7,
        "kem_ciphertext_b64": BASE64.encode(kem_ct),
        "aead_nonce_b64": BASE64.encode(nonce),
        "aead_ciphertext_b64": BASE64.encode(aead_ct),
    }))
}

async fn post_open_envelope(
    app: axum::Router,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let mut request = axum::http::Request::post("/groups/secure/open-envelope")
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = request
        .body(axum::body::Body::from(body.to_string()))
        .expect("request builds");
    let response = app
        .oneshot(request)
        .await
        .unwrap_or_else(|never| match never {});
    json_response(response).await
}

/// Exercise the production middleware with real issued credentials and the
/// real handler. No listener or network transport is started by this fixture.
#[tokio::test]
async fn issue1228_open_envelope_middleware_refuses_scoped_tokens_before_body() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    assert!(state.agent.network().is_none(), "fixture must stay inert");
    let session_token = state.sessions.issue(std::time::Instant::now());
    let (rider_token, _) = state
        .rider_tokens
        .lock()
        .await
        .issue(
            "aa".repeat(32),
            vec!["issue1228-open-envelope".to_string()],
            None,
            60,
            "bb".repeat(32),
            None,
            None,
            crate::server::rider_auth::unix_now_secs(),
        )
        .await?;
    let app = axum::Router::new()
        .route(
            "/groups/secure/open-envelope",
            axum::routing::post(secure_open_envelope_adversarial),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
        .with_state(Arc::clone(&state));
    let valid_body = open_envelope_test_body(&state)?.to_string();

    for (token, error) in [
        (session_token.as_str(), "requires the durable API token"),
        (rider_token.as_str(), "rider tokens are denied"),
    ] {
        for request_body in ["not-json", valid_body.as_str()] {
            let (status, body) = post_open_envelope(app.clone(), Some(token), request_body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert!(
                body["error"]
                    .as_str()
                    .is_some_and(|text| text.contains(error)),
                "expected the actor refusal before parsing or opening: {body}"
            );
            assert!(body.get("secret_b64").is_none(), "{body}");
        }
    }
    for token in [None, Some("not-a-token")] {
        let (status, body) = post_open_envelope(app.clone(), token, "not-json").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    // The durable credential reaches parsing and can open a correctly sealed
    // envelope, so the refusal above is not a blanket-deny or bad fixture.
    let (status, _) = post_open_envelope(app.clone(), Some(&state.api_token), "not-json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = post_open_envelope(app.clone(), Some(&state.api_token), &valid_body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["opened"], true, "{body}");
    assert_eq!(body["secret_b64"], BASE64.encode([7_u8; 32]), "{body}");

    // Owner authority does not bypass the envelope's AAD authentication.
    let mut wrong_aad = serde_json::from_str::<serde_json::Value>(&valid_body)?;
    wrong_aad["recipient"] = serde_json::Value::String("cc".repeat(32));
    let (status, body) =
        post_open_envelope(app, Some(&state.api_token), &wrong_aad.to_string()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["opened"], false, "{body}");
    assert!(body.get("secret_b64").is_none(), "{body}");
    Ok(())
}

/// Bypass auth middleware and inject each actor directly. The handler must
/// independently refuse session/rider actors even for a decryptable envelope.
#[tokio::test]
async fn issue1228_open_envelope_handler_requires_durable_owner() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    assert!(state.agent.network().is_none(), "fixture must stay inert");
    let request_body = open_envelope_test_body(&state)?.to_string();
    for (actor, is_durable) in [(session(), false), (rider(), false), (durable(), true)] {
        let app = axum::Router::new()
            .route(
                "/groups/secure/open-envelope",
                axum::routing::post(secure_open_envelope_adversarial),
            )
            .layer(Extension(actor))
            .with_state(Arc::clone(&state));
        let (status, body) = post_open_envelope(app, None, &request_body).await;
        if is_durable {
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["secret_b64"], BASE64.encode([7_u8; 32]), "{body}");
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            assert!(
                body["error"]
                    .as_str()
                    .is_some_and(|error| error.contains("durable API token")),
                "{body}"
            );
            assert!(body.get("secret_b64").is_none(), "{body}");
        }
    }
    Ok(())
}
