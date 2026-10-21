//! Route tests for ADR-0074 §1 names: every `/names` route is wired and
//! answers its contract, resolution pins and survives a daemon restart, a
//! certified card binds an owner petname once, and `POST /forwards` refuses a
//! `machine:` name (fail closed until slice 2).

use super::*;
use axum::body::to_bytes;
use axum::http::Request;
use axum::routing::{delete, get, post};
use tower::ServiceExt;

/// The fixture's durable API token (`secure_endpoint_test_state_at`
/// hard-codes `"test-token"`).
const DURABLE: &str = "test-token";

fn names_router(state: Arc<AppState>) -> axum::Router {
    names_router_inner(state, false)
}

fn names_router_with_auth(state: Arc<AppState>) -> axum::Router {
    names_router_inner(state, true)
}

fn names_router_inner(state: Arc<AppState>, with_auth: bool) -> axum::Router {
    let router = axum::Router::new()
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
        );
    let router = if with_auth {
        router.layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            crate::server::auth::auth_middleware,
        ))
    } else {
        router
    };
    router.with_state(state)
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
    send_req(app, req).await
}

async fn send_req(
    app: &axum::Router,
    req: Request<axum::body::Body>,
) -> anyhow::Result<(StatusCode, serde_json::Value)> {
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

/// WHY: fail closed until slice 2 — `forward add` must refuse a `machine:`
/// name (400, before any other check), while hex still reaches the normal
/// path (409 here: connect is disabled in the test daemon).
#[tokio::test]
async fn forward_add_refuses_machine_names() -> anyhow::Result<()> {
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
    let (status, json) = send(&app, "POST", "/forwards", body("machine:studio.me")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    assert_eq!(json["code"], "machine_target_unsupported", "{json}");
    let (status, json) = send(&app, "POST", "/forwards", body("Not A Name")).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
    let (status, json) = send(&app, "POST", "/forwards", body(&"ab".repeat(32))).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "hex reaches the forwarder: {json}"
    );
    let (status, json) = send(&app, "POST", "/forwards", body("agent:studio.me")).await?;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "agent names are accepted: {json}"
    );
    Ok(())
}

/// A signed agent card claiming `owner`'s user id and display name.
/// Returns `(card_link, agent_keypair)` so callers can issue a matching
/// [`crate::identity::AgentCertificate`] and seed discovery.
fn signed_card(
    owner: &crate::identity::UserKeypair,
    owner_name: &str,
) -> anyhow::Result<(String, crate::identity::AgentKeypair)> {
    let kp = crate::identity::AgentKeypair::generate()?;
    let mut card =
        x0x::groups::card::AgentCard::new("bot".to_string(), &kp.agent_id(), &"ee".repeat(32));
    card.user_id = Some(hex::encode(owner.user_id().as_bytes()));
    card.owner_name = Some(owner_name.to_string());
    card.sign(&kp)?;
    Ok((card.to_link(), kp))
}

async fn seed_agent_cert(
    state: &AppState,
    agent_kp: &crate::identity::AgentKeypair,
    cert: crate::identity::AgentCertificate,
) {
    let now = unix_now_secs();
    let machine = crate::identity::MachineId([0xee; 32]);
    state
        .agent
        .insert_discovered_agent_for_testing(crate::DiscoveredAgent {
            self_name: None,
            agent_id: agent_kp.agent_id(),
            machine_id: machine,
            user_id: cert.user_id().ok(),
            addresses: Vec::new(),
            announced_at: now,
            last_seen: now,
            machine_public_key: Vec::new(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: cert.not_after(),
            agent_certificate: Some(cert),
            agent_public_key: agent_kp.public_key().as_bytes().to_vec(),
            cert_digest: None,
        })
        .await;
}

/// WHY: a forged squat (signed card, bare `user_id`, no Bob-issued cert)
/// must not freeze Bob's label. An honest Bob-certified agent binds once;
/// a later impostor claiming the same owner name never rebinds it.
#[tokio::test]
async fn signed_card_import_binds_owner_petname_once() -> anyhow::Result<()> {
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let app = names_router(Arc::clone(&state));
    let bob = crate::identity::UserKeypair::generate()?;
    let impostor = crate::identity::UserKeypair::generate()?;

    // Forged squat: signed card claims Bob without a Bob-issued cert.
    let (squat_link, _) = signed_card(&bob, "Bob Smith")?;
    let (status, json) = send(
        &app,
        "POST",
        "/agent/card/import",
        serde_json::json!({ "card": squat_link }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(
        json["owner_label"]["status"], "unverified_owner",
        "bare user_id must not bind: {json}"
    );
    assert!(
        state.names.owner("bob-smith").await?.is_none(),
        "forged squat must leave Bob's label unbound"
    );

    // Honest: Bob issues a cert for the agent; seed it; durable import binds.
    let (honest_link, honest_kp) = signed_card(&bob, "Bob Smith")?;
    let cert = crate::identity::AgentCertificate::issue(&bob, &honest_kp)?;
    seed_agent_cert(&state, &honest_kp, cert).await;
    let (status, json) = send(
        &app,
        "POST",
        "/agent/card/import",
        serde_json::json!({ "card": honest_link }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["owner_label"]["label"], "bob-smith", "{json}");
    assert_eq!(json["owner_label"]["status"], "bound", "{json}");

    // Impostor: own cert + same owner_name → conflict; first bind stands.
    let (impostor_link, impostor_kp) = signed_card(&impostor, "Bob Smith")?;
    let impostor_cert = crate::identity::AgentCertificate::issue(&impostor, &impostor_kp)?;
    seed_agent_cert(&state, &impostor_kp, impostor_cert).await;
    let (status, json) = send(
        &app,
        "POST",
        "/agent/card/import",
        serde_json::json!({ "card": impostor_link }),
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

/// Import a certified card at `trust_level` and assert the petname is absent.
async fn assert_card_import_writes_no_owner_label(trust_level: &str) -> anyhow::Result<()> {
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let app = names_router(Arc::clone(&state));
    let bob = crate::identity::UserKeypair::generate()?;
    let (link, kp) = signed_card(&bob, "Bob Smith")?;
    let cert = crate::identity::AgentCertificate::issue(&bob, &kp)?;
    seed_agent_cert(&state, &kp, cert).await;
    let (status, json) = send(
        &app,
        "POST",
        "/agent/card/import",
        serde_json::json!({ "card": link, "trust_level": trust_level }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert!(
        json["owner_label"].is_null(),
        "{trust_level} import must return null: {json}"
    );
    let (owners, pins) = state.names.snapshot().await?;
    assert!(
        owners.is_empty() && pins.is_empty(),
        "{trust_level} import must write nothing: owners={owners:?} pins={pins:?}"
    );
    Ok(())
}

/// WHY: card-import binding is Known or Trusted only. An Unknown card
/// returns null and writes no petname.
#[tokio::test]
async fn unknown_card_import_returns_null_and_writes_nothing() -> anyhow::Result<()> {
    assert_card_import_writes_no_owner_label("unknown").await
}

/// WHY: a Blocked contact's card must not freeze an owner label. The
/// import returns null and writes nothing.
#[tokio::test]
async fn blocked_card_import_returns_null_and_writes_nothing() -> anyhow::Result<()> {
    assert_card_import_writes_no_owner_label("blocked").await
}

/// WHY (PR #1494 RC6): a card-import retry must not report `existing` while
/// the post-rename directory fsync is still failing. The retry goes through
/// `bind_owner`, so the storage error stays visible until sync succeeds.
#[tokio::test]
async fn card_import_retry_reports_fsync_error_until_durability_confirms() -> anyhow::Result<()> {
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let app = names_router(Arc::clone(&state));
    let bob = crate::identity::UserKeypair::generate()?;
    let (link, kp) = signed_card(&bob, "Bob Smith")?;
    let cert = crate::identity::AgentCertificate::issue(&bob, &kp)?;
    seed_agent_cert(&state, &kp, cert).await;
    let path = x0x::names::NameStore::path_in(&state.data_dir);
    let seam = crate::storage::arm_fail_parent_dir_fsync_for_testing(&path);
    let body = serde_json::json!({ "card": link, "trust_level": "known" });

    let (status, json) = send(&app, "POST", "/agent/card/import", body.clone()).await?;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["owner_label"]["status"], "store_error", "{json}");
    assert!(
        json["owner_label"]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not confirmed"),
        "{json}"
    );
    assert_eq!(
        state.names.owner("bob-smith").await?.map(|b| b.user_id),
        Some(bob.user_id()),
        "memory keeps the binding after the rename"
    );

    let (status, retry) = send(&app, "POST", "/agent/card/import", body.clone()).await?;
    assert_eq!(status, StatusCode::OK, "{retry}");
    assert_eq!(retry["owner_label"]["status"], "store_error", "{retry}");
    assert_ne!(
        retry["owner_label"]["status"], "existing",
        "retry must not hide the fsync error: {retry}"
    );

    drop(seam);
    let (status, confirmed) = send(&app, "POST", "/agent/card/import", body).await?;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    assert_eq!(
        confirmed["owner_label"]["status"], "existing",
        "{confirmed}"
    );
    assert_eq!(
        confirmed["owner_label"]["label"], "bob-smith",
        "{confirmed}"
    );
    assert_eq!(
        state.names.owner("bob-smith").await?.map(|b| b.user_id),
        Some(bob.user_id())
    );
    Ok(())
}

/// WHY: ADR 0074 §1 (a deliberately narrower reading). Trusted binds once,
/// the same as Known
/// (covered by `signed_card_import_binds_owner_petname_once`). A later
/// different user at Trusted onto the same label is `conflict` and does
/// not rebind.
#[tokio::test]
async fn trusted_card_import_binds_owner_petname_once() -> anyhow::Result<()> {
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let app = names_router(Arc::clone(&state));
    let bob = crate::identity::UserKeypair::generate()?;
    let impostor = crate::identity::UserKeypair::generate()?;

    let (honest_link, honest_kp) = signed_card(&bob, "Bob Smith")?;
    let cert = crate::identity::AgentCertificate::issue(&bob, &honest_kp)?;
    seed_agent_cert(&state, &honest_kp, cert).await;
    let (status, json) = send(
        &app,
        "POST",
        "/agent/card/import",
        serde_json::json!({ "card": honest_link, "trust_level": "trusted" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["owner_label"]["label"], "bob-smith", "{json}");
    assert_eq!(json["owner_label"]["status"], "bound", "{json}");
    assert_eq!(
        state.names.owner("bob-smith").await?.map(|b| b.user_id),
        Some(bob.user_id()),
        "Trusted stores the petname"
    );

    let (impostor_link, impostor_kp) = signed_card(&impostor, "Bob Smith")?;
    let impostor_cert = crate::identity::AgentCertificate::issue(&impostor, &impostor_kp)?;
    seed_agent_cert(&state, &impostor_kp, impostor_cert).await;
    let (status, json) = send(
        &app,
        "POST",
        "/agent/card/import",
        serde_json::json!({ "card": impostor_link, "trust_level": "trusted" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["owner_label"]["status"], "conflict", "{json}");
    assert_eq!(
        state.names.owner("bob-smith").await?.map(|b| b.user_id),
        Some(bob.user_id()),
        "the first bind stands"
    );
    Ok(())
}

/// WHY: ADR-0074 §1 — session and rider tokens must not mutate `/names*`,
/// must not `POST /forwards` (resolve pins), and must not bind via card
/// import (import may still 200 for contacts). Driven through the REAL
/// `auth_middleware`; the handler-side durable gate is checked too.
#[tokio::test]
async fn names_and_forwards_refuse_session_and_rider_tokens() -> anyhow::Result<()> {
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let app = names_router_with_auth(Arc::clone(&state));
    let session = state.sessions.issue(std::time::Instant::now());
    let rider = {
        let mut store = state.rider_tokens.lock().await;
        let (token, _record) = store
            .issue(
                "aa".repeat(32),
                Vec::new(),
                None,
                60,
                String::new(),
                None,
                None,
                crate::server::rider_auth::unix_now_secs(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("rider token issue: {e}"))?;
        token
    };

    let forward_body = serde_json::json!({
        "local_addr": "127.0.0.1:18022",
        "peer_agent": "ab".repeat(32),
        "target_host": "127.0.0.1",
        "target_port": 22,
    })
    .to_string();
    let surfaces = [
        ("GET", "/names".to_string(), String::new()),
        (
            "POST",
            "/names/resolve".to_string(),
            serde_json::json!({ "name": "studio.me" }).to_string(),
        ),
        (
            "POST",
            "/names/owners".to_string(),
            serde_json::json!({ "label": "bob", "user_id": "bb".repeat(32) }).to_string(),
        ),
        ("DELETE", "/names/owners/bob".to_string(), String::new()),
        (
            "POST",
            "/names/machines".to_string(),
            serde_json::json!({
                "name": "machine:box.bob",
                "machine_id": "dd".repeat(32)
            })
            .to_string(),
        ),
        (
            "DELETE",
            "/names/pins/agent:studio.bob".to_string(),
            String::new(),
        ),
        ("POST", "/forwards".to_string(), forward_body),
    ];
    for (method, path, body) in &surfaces {
        for (who, bearer) in [("session", session.as_str()), ("rider", rider.as_str())] {
            let req = Request::builder()
                .method(*method)
                .uri(path.as_str())
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.clone()))?;
            let (status, json) = send_req(&app, req).await?;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{who} {method} {path}: {json}"
            );
        }
        let req = Request::builder()
            .method(*method)
            .uri(path.as_str())
            .header("authorization", format!("Bearer {DURABLE}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.clone()))?;
        let (status, json) = send_req(&app, req).await?;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "durable {method} {path} must clear the gate: {json}"
        );
    }

    // Card import: session may import contacts but must not bind.
    let bob = crate::identity::UserKeypair::generate()?;
    let (card_link, agent_kp) = signed_card(&bob, "Bob Smith")?;
    let cert = crate::identity::AgentCertificate::issue(&bob, &agent_kp)?;
    seed_agent_cert(&state, &agent_kp, cert).await;
    let import_body = serde_json::json!({ "card": card_link }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/agent/card/import")
        .header("authorization", format!("Bearer {session}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(import_body.clone()))?;
    let (status, json) = send_req(&app, req).await?;
    assert_eq!(status, StatusCode::OK, "session import contacts: {json}");
    assert!(
        json["owner_label"].is_null(),
        "session must not bind: {json}"
    );
    assert!(
        state.names.owner("bob-smith").await?.is_none(),
        "names store unchanged after session import"
    );

    // Defense in depth: handler refuses a non-durable actor even if a
    // future router wiring skipped the middleware.
    let bare = names_router(Arc::clone(&state));
    let req = Request::builder()
        .method("POST")
        .uri("/forwards")
        .header("content-type", "application/json")
        .extension(ActorContext::Owner { durable: false })
        .body(axum::body::Body::from(
            serde_json::json!({
                "local_addr": "127.0.0.1:18022",
                "peer_agent": "ab".repeat(32),
                "target_host": "127.0.0.1",
                "target_port": 22,
            })
            .to_string(),
        ))?;
    let (status, json) = send_req(&bare, req).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
    Ok(())
}
