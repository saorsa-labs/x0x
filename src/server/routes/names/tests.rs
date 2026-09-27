//! Route tests for ADR-0074 §1 names: every `/names` route is wired and
//! answers its contract, resolution pins and survives a daemon restart, a
//! signed card binds an owner petname once, and `POST /forwards` accepts a
//! `machine:` name (slice 2: the forwarder checks the pinned machine).

use super::*;
use axum::body::to_bytes;
use axum::http::Request;
use axum::routing::{delete, get, post};
use tower::ServiceExt;

fn names_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/names", get(names_list))
        .route("/names/resolve", post(names_resolve))
        .route("/names/owners", post(names_owner_bind))
        .route("/names/owners/:label", delete(names_owner_unbind))
        .route("/names/machines", post(names_machine_label))
        .route("/names/pins/:name", delete(names_unpin))
        .route("/forwards", post(super::super::connect::forward_add))
        .route(
            "/agent/card/import",
            post(super::super::identity::import_agent_card),
        )
        .with_state(state)
}

async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> anyhow::Result<(StatusCode, serde_json::Value)> {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .extension(ActorContext::Owner { durable: true })
        .body(axum::body::Body::from(if body.is_null() {
            String::new()
        } else {
            body.to_string()
        }))?;
    let resp = app.clone().oneshot(req).await?;
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await?;
    Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
}

/// An owned install whose own agent announces the self-name `Studio`.
async fn owned_state(data_dir: &std::path::Path, seed: [u8; 32]) -> anyhow::Result<Arc<AppState>> {
    let agent = Arc::new(
        crate::Agent::builder()
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key_path(data_dir.join("agent.key"))
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_user_key(crate::identity::UserKeypair::from_seed(&seed)?)
            .with_contact_store_path(data_dir.join("contacts.json"))
            .build()
            .await?,
    );
    agent.set_self_name(Some("Studio".to_string()));
    super::super::named_groups::tests::secure_endpoint_test_state_at(data_dir, agent).await
}

/// WHY: every `/names` route is wired and answers the ADR-0074 §1
/// contract: petnames bind once and never rebind, an unknown owner label
/// fails, a machine label needs an active grant, and pins can be dropped.
#[tokio::test]
async fn names_routes_wired() -> anyhow::Result<()> {
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let app = names_router(Arc::clone(&state));
    let bob = "bb".repeat(32);

    let (status, body) = send(&app, "GET", "/names", serde_json::Value::Null).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["owners"], serde_json::json!([]));

    let (status, body) = send(
        &app,
        "POST",
        "/names/owners",
        serde_json::json!({ "label": "bob", "user_id": bob }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["bound"], true);
    let (status, body) = send(
        &app,
        "POST",
        "/names/owners",
        serde_json::json!({ "label": "bob", "user_id": "cc".repeat(32) }),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "rebind refused: {body}");
    assert_eq!(body["code"], "pin_mismatch");
    let (status, body) = send(&app, "GET", "/names", serde_json::Value::Null).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["owners"][0]["label"], "bob");
    assert_eq!(body["owners"][0]["user_id"], bob, "first bind kept");

    // Unknown owner label, unknown agent, bad grammar, hex passthrough.
    for (name, want, code) in [
        ("studio.nobody", StatusCode::NOT_FOUND, "unknown_name"),
        ("studio.bob", StatusCode::NOT_FOUND, "unknown_name"),
        ("studio.me", StatusCode::NOT_FOUND, "unknown_name"),
        ("Studio.bob", StatusCode::BAD_REQUEST, "invalid_name"),
        ("me.bob", StatusCode::BAD_REQUEST, "reserved_label"),
    ] {
        let (status, body) = send(
            &app,
            "POST",
            "/names/resolve",
            serde_json::json!({ "name": name }),
        )
        .await?;
        assert_eq!(status, want, "{name}: {body}");
        assert_eq!(body["code"], code, "{name}: {body}");
    }
    let (status, body) = send(
        &app,
        "POST",
        "/names/resolve",
        serde_json::json!({ "name": "ab".repeat(32) }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["agent_id"], "ab".repeat(32));

    // A shared-machine label needs an active grant from that owner.
    let (status, body) = send(
        &app,
        "POST",
        "/names/machines",
        serde_json::json!({ "name": "machine:box.bob", "machine_id": "dd".repeat(32) }),
    )
    .await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "unverified_owner");
    let (status, body) = send(
        &app,
        "POST",
        "/names/machines",
        serde_json::json!({ "name": "machine:box.me", "machine_id": "dd".repeat(32) }),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "own machines are synced: {body}"
    );

    let (status, _) = send(
        &app,
        "POST",
        "/names/resolve",
        serde_json::json!({ "name": "studio.bob", "bogus": 1 }),
    )
    .await?;
    assert!(status.is_client_error(), "unknown field must be rejected");

    let (status, body) = send(
        &app,
        "DELETE",
        "/names/pins/agent:studio.bob",
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = send(&app, "DELETE", "/names/owners/bob", serde_json::Value::Null).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = send(&app, "DELETE", "/names/owners/bob", serde_json::Value::Null).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

/// WHY: API round trip plus "names persist by default": `studio.me`
/// resolves to the owner's own certified agent, pins at first use, and the
/// pin is still there (not re-pinned) after a daemon restart.
#[tokio::test]
async fn resolve_pins_own_agent_and_the_pin_survives_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let seed = [0x42; 32];
    let local_agent;
    {
        let state = owned_state(dir.path(), seed).await?;
        local_agent = hex::encode(state.agent.agent_id().as_bytes());
        let app = names_router(Arc::clone(&state));
        let (status, body) = send(
            &app,
            "POST",
            "/names/resolve",
            serde_json::json!({ "name": "studio.me" }),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["name"], "agent:studio.me");
        assert_eq!(body["kind"], "agent");
        assert_eq!(body["agent_id"], local_agent);
        assert_eq!(body["newly_pinned"], true);
        // A machine name is not an agent name: no enrolled machine here.
        let (status, body) = send(
            &app,
            "POST",
            "/names/resolve",
            serde_json::json!({ "name": "machine:studio.me" }),
        )
        .await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }
    let state = owned_state(dir.path(), seed).await?;
    let app = names_router(Arc::clone(&state));
    let (status, body) = send(&app, "GET", "/names", serde_json::Value::Null).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pins"][0]["name"], "agent:studio.me");
    assert_eq!(body["pins"][0]["id"], local_agent);
    let (status, body) = send(
        &app,
        "POST",
        "/names/resolve",
        serde_json::json!({ "name": "agent:studio.me" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["newly_pinned"], false, "pinned before the restart");
    Ok(())
}

/// WHY (slice 2 lifts slice 1's interim refusal): `forward add` now
/// accepts a `machine:` name — allowed ONLY because the forwarder checks
/// that every stream reaches the pinned MachineId (see
/// `forward::tests::machine_name_forward_to_the_wrong_machine_is_refused_at_the_peer_check`).
/// It passes the syntax check and reaches the forwarder (409 here: connect
/// is disabled in the test daemon) instead of the old 400. Malformed peers
/// are still refused first.
#[tokio::test]
async fn forward_add_accepts_machine_names() -> anyhow::Result<()> {
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let app = names_router(Arc::clone(&state));
    let body = |peer: &str| {
        serde_json::json!({
            "local_addr": "127.0.0.1:18022",
            "peer_agent": peer,
            "target_host": "127.0.0.1",
            "target_port": 22,
        })
    };
    for peer in [
        "machine:studio.me".to_string(),
        "agent:studio.me".to_string(),
        "ab".repeat(32),
    ] {
        let (status, json) = send(&app, "POST", "/forwards", body(&peer)).await?;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{peer} reaches the forwarder: {json}"
        );
    }
    let (status, json) = send(&app, "POST", "/forwards", body("Not A Name")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    assert_eq!(json["code"], "invalid_name", "{json}");
    Ok(())
}

fn signed_card(owner: &crate::identity::UserKeypair, owner_name: &str) -> anyhow::Result<String> {
    let kp = crate::identity::AgentKeypair::generate()?;
    let mut card =
        x0x::groups::card::AgentCard::new("bot".to_string(), &kp.agent_id(), &"ee".repeat(32));
    card.user_id = Some(hex::encode(owner.user_id().as_bytes()));
    card.owner_name = Some(owner_name.to_string());
    card.sign(&kp)?;
    Ok(card.to_link())
}

/// WHY: importing a signed card binds its `owner_name` as a petname at
/// first bind; a later card claiming the same owner name for a different
/// key never rebinds it.
#[tokio::test]
async fn signed_card_import_binds_owner_petname_once() -> anyhow::Result<()> {
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let app = names_router(Arc::clone(&state));
    let bob = crate::identity::UserKeypair::generate()?;
    let impostor = crate::identity::UserKeypair::generate()?;

    let (status, json) = send(
        &app,
        "POST",
        "/agent/card/import",
        serde_json::json!({ "card": signed_card(&bob, "Bob Smith")? }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["owner_label"]["label"], "bob-smith", "{json}");
    assert_eq!(json["owner_label"]["status"], "bound", "{json}");

    let (status, json) = send(
        &app,
        "POST",
        "/agent/card/import",
        serde_json::json!({ "card": signed_card(&impostor, "Bob Smith")? }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["owner_label"]["status"], "conflict", "{json}");
    let binding = state.names.owner("bob-smith").await?;
    assert_eq!(
        binding.map(|b| b.user_id),
        Some(bob.user_id()),
        "the first bind stands"
    );
    Ok(())
}
