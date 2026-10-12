//! #1228: session tokens must not clear fork quarantine, list join
//! requests, or drive legacy MLS routes. Display-name requires an admin
//! seat. Cancelling a join request is limited to an owner.

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

/// A session token cannot list join requests. The durable owner, holding
/// an admin seat, can.
#[tokio::test]
async fn session_token_cannot_list_join_requests() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group_id = "cd".repeat(32);
    let mut info = group_with_local_role(&state, &group_id, x0x::groups::GroupRole::Admin);
    let request = x0x::groups::JoinRequest::new(group_id.clone(), "ee".repeat(32), None, 1);
    let request_id = request.request_id.clone();
    info.join_requests.insert(request_id, request);
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    let local = hex::encode(state.agent.agent_id().as_bytes());

    let (status, body) = json_response(
        list_join_requests(
            State(Arc::clone(&state)),
            Extension(session()),
            Path(group_id.clone()),
            group_access::GroupAccess::for_handler_tests(local.clone()),
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

    let (status, body) = json_response(
        list_join_requests(
            State(Arc::clone(&state)),
            Extension(durable()),
            Path(group_id),
            group_access::GroupAccess::for_handler_tests(local),
        )
        .await
        .into_response(),
    )
    .await;
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

/// A member seat cannot set a display name. An admin seat can.
#[tokio::test]
async fn display_name_requires_admin_seat() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let member_id = "11".repeat(32);
    let admin_id = "22".repeat(32);
    let local = hex::encode(state.agent.agent_id().as_bytes());
    {
        let mut groups = state.named_groups.write().await;
        groups.insert(
            member_id.clone(),
            group_with_local_role(&state, &member_id, x0x::groups::GroupRole::Member),
        );
        groups.insert(
            admin_id.clone(),
            group_with_local_role(&state, &admin_id, x0x::groups::GroupRole::Admin),
        );
    }

    let (status, body) = json_response(
        set_group_display_name(
            State(Arc::clone(&state)),
            Path(member_id.clone()),
            Json(SetDisplayNameRequest {
                name: "Member".to_string(),
            }),
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
            .get(&member_id)
            .is_some_and(|info| info.display_name(&local) != "Member"),
        "a member seat must not store the name"
    );

    let (status, body) = json_response(
        set_group_display_name(
            State(Arc::clone(&state)),
            Path(admin_id.clone()),
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
            .get(&admin_id)
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
    Ok(())
}
