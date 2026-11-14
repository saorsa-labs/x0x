//! Route tests for ADR-0074 §1 names: every `/names` route is wired and
//! answers its contract, resolution pins and survives a daemon restart, a
//! certified card binds an owner petname once, and `POST /forwards` accepts a
//! `machine:` name (slice 2: the forwarder checks the pinned machine).

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
        .route("/names/accept", post(names_accept))
        .route("/names/suggestions/:label", delete(names_dismiss))
        .route("/forwards", post(super::super::connect::forward_add))
        .route(
            "/forwards/:local_addr",
            delete(super::super::connect::forward_remove),
        )
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

/// WHY: ADR 0079 §2 — the grant-names suggestion surface is wired: a
/// stranger's defaults show up as a suggestion in `GET /names`, `POST
/// /names/accept` applies them (owner petname + machine pin, source
/// `grant`) and removes the suggestion, a second accept is 404, and
/// `DELETE /names/suggestions/:label` drops a pending one. Conflicts are
/// reported in `GET /names`.
#[tokio::test]
async fn grant_names_routes_wired() -> anyhow::Result<()> {
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let app = names_router(Arc::clone(&state));
    let bob = UserId([0xbb; 32]);
    let machine = MachineId([0xdd; 32]);
    let defaults = x0x::names::GrantNameDefaults {
        owner: bob,
        owner_name: Some("Bob Smith".to_string()),
        machines: vec![(machine, "Studio Mac".to_string())],
        verified_hosts: std::collections::BTreeSet::new(),
    };

    // A stranger's grant yields a suggestion, never a binding.
    let applied = state.names.apply_grant_names(&defaults, false, 1).await?;
    assert!(applied.suggested, "{applied:?}");
    assert!(!applied.owner_bound, "{applied:?}");
    let (status, body) = send(&app, "GET", "/names", serde_json::Value::Null).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["owners"], serde_json::json!([]));
    assert_eq!(body["suggestions"][0]["label"], "bob-smith", "{body}");
    assert_eq!(
        body["suggestions"][0]["machines"][0]["machine_name"],
        "Studio Mac"
    );

    // Accept applies the defaults and removes the suggestion.
    let (status, body) = send(
        &app,
        "POST",
        "/names/accept",
        serde_json::json!({ "label": "bob-smith" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["owner_bound"], true, "{body}");
    assert_eq!(body["machine_pins"][0], "machine:studio-mac.bob-smith");
    let (status, body) = send(&app, "GET", "/names", serde_json::Value::Null).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["owners"][0]["label"], "bob-smith");
    assert_eq!(body["owners"][0]["source"], "grant");
    assert_eq!(body["suggestions"], serde_json::json!([]), "{body}");
    assert_eq!(body["pins"][0]["name"], "machine:studio-mac.bob-smith");
    assert_eq!(body["pins"][0]["source"], "grant");

    // A second accept of the same label is gone.
    let (status, body) = send(
        &app,
        "POST",
        "/names/accept",
        serde_json::json!({ "label": "bob-smith" }),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // A conflicting later default is reported, not applied.
    let other = x0x::names::GrantNameDefaults {
        owner: UserId([0xcc; 32]),
        owner_name: Some("Bob Smith".to_string()),
        machines: Vec::new(),
        verified_hosts: std::collections::BTreeSet::new(),
    };
    let applied = state.names.apply_grant_names(&other, true, 2).await?;
    assert_eq!(applied.conflicts, 1, "{applied:?}");
    let (status, body) = send(&app, "GET", "/names", serde_json::Value::Null).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["conflicts"][0]["case"], "label_taken", "{body}");
    assert_eq!(body["conflicts"][0]["label"], "bob-smith");

    // Dismiss drops a pending suggestion; a missing one is 404.
    let carol = x0x::names::GrantNameDefaults {
        owner: UserId([0xee; 32]),
        owner_name: Some("Carol".to_string()),
        machines: Vec::new(),
        verified_hosts: std::collections::BTreeSet::new(),
    };
    state.names.apply_grant_names(&carol, false, 3).await?;
    let (status, body) = send(
        &app,
        "DELETE",
        "/names/suggestions/carol",
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["removed"], true);
    let (status, _) = send(
        &app,
        "DELETE",
        "/names/suggestions/carol",
        serde_json::Value::Null,
    )
    .await?;
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
/// must not `POST /forwards` (resolve pins), must not `DELETE /forwards`
/// (that removes the owner's record), and must not bind via card
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
                Vec::new(),
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
        (
            "POST",
            "/names/accept".to_string(),
            serde_json::json!({ "label": "bob" }).to_string(),
        ),
        (
            "DELETE",
            "/names/suggestions/bob".to_string(),
            String::new(),
        ),
        ("POST", "/forwards".to_string(), forward_body),
        (
            "DELETE",
            "/forwards/127.0.0.1:18022".to_string(),
            String::new(),
        ),
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

    let req = Request::builder()
        .method("DELETE")
        .uri("/forwards/127.0.0.1:18022")
        .extension(ActorContext::Owner { durable: false })
        .body(axum::body::Body::empty())?;
    let (status, json) = send_req(&bare, req).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "handler delete gate: {json}");
    Ok(())
}

/// WHY: DELETE /forwards/:local_addr removes the owner's persisted record.
/// A session or rider token is refused. The durable owner deletes it.
#[tokio::test]
async fn forward_delete_refuses_session_and_rider_and_accepts_durable_owner() -> anyhow::Result<()>
{
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
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
                Vec::new(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("rider token issue: {e}"))?;
        token
    };
    let agent = Arc::clone(&state.agent);
    let mut state = Arc::into_inner(state).expect("test state is unique before the router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    drop(listener);
    let spec = x0x::forward::ForwardSpec {
        local_addr: addr,
        peer_agent: x0x::identity::AgentId([0x55; 32]),
        target_host: "127.0.0.1".to_string(),
        target_port: 9,
    };
    let binding = x0x::forward::ForwardBinding {
        name: None,
        kind: x0x::names::NameKind::Agent,
        pinned_machine: Some(x0x::identity::MachineId([0x11; 32])),
        persistent: true,
    };
    assert!(state.forwards.remember(&spec, &binding).await?);
    let policy = Arc::new(x0x::connect::ConnectPolicy::default());
    let diagnostics = Arc::new(x0x::connect::ConnectDiagnostics::new(policy.summary()));
    let forwarder = Arc::new(
        x0x::forward::ForwardService::new(agent, policy, diagnostics, true)
            .map_err(|e| anyhow::anyhow!("forwarder: {e}"))?,
    );
    forwarder
        .add_forward_with(spec, binding)
        .await
        .map_err(|e| anyhow::anyhow!("bind: {e}"))?;
    state.forward_service = Some(Arc::clone(&forwarder));
    let state = Arc::new(state);
    let path = format!("/forwards/{addr}");
    let app = names_router_with_auth(Arc::clone(&state));

    for (who, bearer) in [("session", session.as_str()), ("rider", rider.as_str())] {
        let req = Request::builder()
            .method("DELETE")
            .uri(&path)
            .header("authorization", format!("Bearer {bearer}"))
            .body(axum::body::Body::empty())?;
        let (status, json) = send_req(&app, req).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{who} delete: {json}");
    }
    assert_eq!(
        state.forwards.records().await?.len(),
        1,
        "a refused delete must leave the persisted forward"
    );
    assert!(
        forwarder.forward_at(addr).is_some(),
        "a refused delete must leave the listener"
    );

    let req = Request::builder()
        .method("DELETE")
        .uri(&path)
        .header("authorization", format!("Bearer {DURABLE}"))
        .body(axum::body::Body::empty())?;
    let (status, json) = send_req(&app, req).await?;
    assert_eq!(status, StatusCode::OK, "durable owner delete: {json}");
    assert_eq!(json["removed"], true, "{json}");
    assert!(state.forwards.records().await?.is_empty());
    assert!(forwarder.forward_at(addr).is_none());
    forwarder.shutdown();
    Ok(())
}

async fn add_contact(
    state: &AppState,
    agent: x0x::identity::AgentId,
    level: x0x::contacts::TrustLevel,
) {
    state
        .agent
        .contacts()
        .write()
        .await
        .add(x0x::contacts::Contact {
            agent_id: agent,
            trust_level: level,
            label: None,
            added_at: 0,
            last_seen: None,
            identity_type: Default::default(),
            machines: Vec::new(),
            dm_capabilities: None,
        });
}

/// WHY (#1826 review, LOW; ADR 0079 §2 contact gate): an owner is a
/// contact only through a Known or Trusted contact agent whose cached
/// certificate chains to that owner. No contact, a Blocked contact, a
/// contact certified by another user and a revoked contact agent all say
/// no.
#[tokio::test]
async fn owner_contact_gate_needs_a_live_known_or_trusted_certified_agent() -> anyhow::Result<()> {
    use x0x::contacts::TrustLevel;
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let bob = crate::identity::UserKeypair::generate()?;
    let carol = crate::identity::UserKeypair::generate()?;
    let bob_agent = crate::identity::AgentKeypair::generate()?;
    seed_agent_cert(
        &state,
        &bob_agent,
        crate::identity::AgentCertificate::issue(&bob, &bob_agent)?,
    )
    .await;

    assert!(
        !owner_is_known_or_trusted_contact(&state, bob.user_id()).await,
        "no contact"
    );
    add_contact(&state, bob_agent.agent_id(), TrustLevel::Blocked).await;
    assert!(
        !owner_is_known_or_trusted_contact(&state, bob.user_id()).await,
        "a Blocked contact is not a contact"
    );
    add_contact(&state, bob_agent.agent_id(), TrustLevel::Known).await;
    assert!(
        owner_is_known_or_trusted_contact(&state, bob.user_id()).await,
        "a Known certified contact"
    );
    assert!(
        !owner_is_known_or_trusted_contact(&state, carol.user_id()).await,
        "the contact's certificate chains to Bob, not Carol"
    );
    add_contact(&state, bob_agent.agent_id(), TrustLevel::Trusted).await;
    assert!(owner_is_known_or_trusted_contact(&state, bob.user_id()).await);

    let record = x0x::revocation::RevocationRecord::sign(
        x0x::revocation::RevokedSubject::Agent(bob_agent.agent_id()),
        bob_agent.public_key(),
        bob_agent.secret_key(),
        unix_now_secs(),
        None,
    )?;
    state
        .agent
        .revocation_set()
        .write()
        .await
        .verify_and_insert(record, None)?;
    assert!(
        !owner_is_known_or_trusted_contact(&state, bob.user_id()).await,
        "a revoked contact agent is not evidence"
    );
    Ok(())
}

/// WHY (#1826 review, LOW): the daemon's share-grant route sends a
/// `x0x-sharegrant-v2\0` payload to the v2 handler (the names apply) and a
/// v1 payload to the v1 handler (the same grant is a Duplicate).
#[tokio::test]
async fn share_grant_dispatch_routes_v2_and_v1_payloads() -> anyhow::Result<()> {
    use x0x::dm_inbox::{DmTypedPayload, DmTypedPayloadCompletion};
    use x0x::share_grant::names::{GrantMachineName, GrantNames, ShareGrantV2};
    use x0x::share_grant::{Grantee, ShareCap, ShareGrant};
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let bob = crate::identity::UserKeypair::generate()?;
    let bob_agent = crate::identity::AgentKeypair::generate()?;
    seed_agent_cert(
        &state,
        &bob_agent,
        crate::identity::AgentCertificate::issue(&bob, &bob_agent)?,
    )
    .await;
    add_contact(
        &state,
        bob_agent.agent_id(),
        x0x::contacts::TrustLevel::Known,
    )
    .await;
    state
        .agent
        .install_share_grant_store(Arc::new(x0x::share_grant::ShareGrantStore::in_memory(
            state.agent.agent_id(),
            state.agent.user_id(),
        )));
    let now = unix_now_secs();
    let grant = ShareGrant::sign(
        &bob,
        [0x5a; 32],
        Grantee::Agent(state.agent.agent_id()),
        vec![bob_agent.agent_id()],
        vec![ShareCap::Dm],
        now - 60,
        now + 3600,
    )?;
    let envelope = ShareGrantV2::sign(
        &bob,
        grant.clone(),
        GrantNames {
            owner_name: Some("Bob Smith".to_string()),
            machines: vec![GrantMachineName {
                machine_id: crate::identity::MachineId([0x99; 32]),
                machine_name: "Far Box".to_string(),
            }],
        },
    )?;
    let typed = |payload: Vec<u8>| DmTypedPayload {
        sender: bob_agent.agent_id(),
        machine_id: crate::identity::MachineId([0xee; 32]),
        payload,
        verified: true,
        trust_decision: None,
        received_at_unix_ms: 0,
        request_id: [0x01; 16],
        completion: None,
    };

    let outcome =
        crate::server::dispatch_share_grant_typed(&state, typed(envelope.to_dm_payload()?)).await;
    assert_eq!(outcome, Ok(DmTypedPayloadCompletion::Inserted));
    assert_eq!(
        state.names.owner("bob-smith").await?.map(|b| b.user_id),
        Some(bob.user_id()),
        "v2 applied the owner name"
    );
    // Machine 0x99 hosts no discovered agent of the grant: held, not pinned.
    assert!(state
        .names
        .get_pin("machine:far-box.bob-smith")
        .await?
        .is_none());
    assert!(state.names.pending().await?.0.contains_key("bob-smith"));

    let outcome =
        crate::server::dispatch_share_grant_typed(&state, typed(grant.to_dm_payload()?)).await;
    assert_eq!(outcome, Ok(DmTypedPayloadCompletion::Duplicate), "v1 route");
    Ok(())
}

/// WHY (#1826 ZCode review, test gap 3; ADR 0079 §2): the positive path of
/// the hosting gate through the daemon's share-grant route. A granted
/// agent in the discovery cache, whose certificate chains to the grant
/// owner and whose machine binding is recorded, makes its machine a
/// verified host, so the route pins that machine's default. A second
/// granted agent that is only in the discovery cache (no machine binding)
/// gives no host: its machine's default in the same grant is only
/// suggested.
#[tokio::test]
async fn share_grant_dispatch_pins_a_machine_default_with_real_hosting_evidence(
) -> anyhow::Result<()> {
    use x0x::dm_inbox::{DmTypedPayload, DmTypedPayloadCompletion};
    use x0x::share_grant::names::{GrantMachineName, GrantNames, ShareGrantV2};
    use x0x::share_grant::{Grantee, ShareCap, ShareGrant};
    let (state, _dir) =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
    let bob = crate::identity::UserKeypair::generate()?;
    let bob_agent = crate::identity::AgentKeypair::generate()?;
    // `seed_agent_cert` announces Bob's certified agent on machine 0xee and
    // records its machine binding.
    let host = crate::identity::MachineId([0xee; 32]);
    seed_agent_cert(
        &state,
        &bob_agent,
        crate::identity::AgentCertificate::issue(&bob, &bob_agent)?,
    )
    .await;
    // A second certified agent of Bob: a discovery entry on machine 0x77
    // with no machine binding in any authority store.
    let unbound_agent = crate::identity::AgentKeypair::generate()?;
    let unbound = crate::identity::MachineId([0x77; 32]);
    let now = unix_now_secs();
    let unbound_cert = crate::identity::AgentCertificate::issue(&bob, &unbound_agent)?;
    state.agent.identity_discovery_cache.write().await.insert(
        unbound_agent.agent_id(),
        crate::DiscoveredAgent {
            self_name: None,
            agent_id: unbound_agent.agent_id(),
            machine_id: unbound,
            user_id: Some(bob.user_id()),
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
            cert_not_after: unbound_cert.not_after(),
            agent_certificate: Some(unbound_cert),
            agent_public_key: unbound_agent.public_key().as_bytes().to_vec(),
            cert_digest: None,
        },
    );
    add_contact(
        &state,
        bob_agent.agent_id(),
        x0x::contacts::TrustLevel::Known,
    )
    .await;
    state
        .agent
        .install_share_grant_store(Arc::new(x0x::share_grant::ShareGrantStore::in_memory(
            state.agent.agent_id(),
            state.agent.user_id(),
        )));
    let granted = vec![bob_agent.agent_id(), unbound_agent.agent_id()];
    let grant = ShareGrant::sign(
        &bob,
        [0x5b; 32],
        Grantee::Agent(state.agent.agent_id()),
        granted.clone(),
        vec![ShareCap::Dm],
        now - 60,
        now + 3600,
    )?;
    assert_eq!(
        state.agent.verified_grant_hosts(&grant).await,
        std::collections::BTreeSet::from([host.0]),
        "only the bound machine of a certified granted agent is a host"
    );

    // A grant from another owner listing the same agents gets no host: the
    // agents' certificates do not chain to that owner.
    let carol = crate::identity::UserKeypair::generate()?;
    let foreign = ShareGrant::sign(
        &carol,
        [0x5c; 32],
        Grantee::Agent(state.agent.agent_id()),
        granted,
        vec![ShareCap::Dm],
        now - 60,
        now + 3600,
    )?;
    assert!(state.agent.verified_grant_hosts(&foreign).await.is_empty());

    let mut machines = vec![
        GrantMachineName {
            machine_id: host,
            machine_name: "Studio Mac".to_string(),
        },
        GrantMachineName {
            machine_id: unbound,
            machine_name: "Far Box".to_string(),
        },
    ];
    machines.sort_by_key(|m| m.machine_id.0);
    let envelope = ShareGrantV2::sign(
        &bob,
        grant,
        GrantNames {
            owner_name: Some("Bob Smith".to_string()),
            machines,
        },
    )?;
    let outcome = crate::server::dispatch_share_grant_typed(
        &state,
        DmTypedPayload {
            sender: bob_agent.agent_id(),
            machine_id: host,
            payload: envelope.to_dm_payload()?,
            verified: true,
            trust_decision: None,
            received_at_unix_ms: 0,
            request_id: [0x02; 16],
            completion: None,
        },
    )
    .await;
    assert_eq!(outcome, Ok(DmTypedPayloadCompletion::Inserted));
    let pin = state
        .names
        .get_pin("machine:studio-mac.bob-smith")
        .await?
        .expect("the hosted machine's default is pinned");
    assert_eq!(pin.id, host.0);
    assert_eq!(pin.owner, bob.user_id());
    assert!(
        state
            .names
            .get_pin("machine:far-box.bob-smith")
            .await?
            .is_none(),
        "a machine without hosting evidence is not pinned"
    );
    let (suggestions, _) = state.names.pending().await?;
    assert_eq!(
        suggestions.get("bob-smith").map(|s| s.machines.clone()),
        Some(vec![(unbound, "Far Box".to_string())]),
        "it is held for the local owner"
    );
    Ok(())
}
