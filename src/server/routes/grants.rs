//! Route handlers for ADR-0070 §2 share grants (`category: "grants"` in
//! `src/api/mod.rs`): issue, list and revoke grants this install's owner
//! signed, and list grants this install received.
//!
//! Every route is owner/durable-token only. `auth_middleware` refuses
//! session bearers and riders before any extractor runs
//! (`requires_durable_owner`); the handlers re-check as defense in depth.

use super::super::api_error;
use super::super::rider_auth::ActorContext;
use super::super::state::AppState;
use crate as x0x;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use x0x::identity::{AgentId, UserId};
use x0x::share_grant::{GrantNames, GrantRole, Grantee, ShareCap, ShareGrantError};

const DURABLE_REQUIRED: &str =
    "share-grant management requires the durable API token (not a session or rider token)";

fn forbidden() -> Response {
    api_error(StatusCode::FORBIDDEN, DURABLE_REQUIRED).into_response()
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_id32(field: &str, raw: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(raw).map_err(|e| format!("{field}: invalid hex: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("{field}: expected 32 bytes (64 hex chars)"))
}

fn bad_request(msg: String) -> Response {
    api_error(StatusCode::BAD_REQUEST, msg).into_response()
}

fn grant_error(err: &ShareGrantError) -> Response {
    let status = match err {
        ShareGrantError::Invalid(_)
        | ShareGrantError::BadSignature(_)
        | ShareGrantError::Malformed(_)
        | ShareGrantError::Expired => StatusCode::BAD_REQUEST,
        ShareGrantError::NotForUs | ShareGrantError::Conflict => StatusCode::CONFLICT,
        ShareGrantError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    api_error(status, err.to_string()).into_response()
}

/// `POST /grants` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct GrantIssueRequest {
    /// Grantee user id (hex). Exactly one of `grantee_user` /
    /// `grantee_agent`.
    #[serde(default)]
    grantee_user: Option<String>,
    /// Grantee agent id (hex), for a grantee with no user identity.
    #[serde(default)]
    grantee_agent: Option<String>,
    /// This owner's agents to share (hex, non-empty).
    agents: Vec<String>,
    /// Capabilities: `"dm"`, `"exec"`, `"group_invite"`, `"call"`,
    /// `{"connect":{"ports":[22]}}`.
    caps: Vec<ShareCap>,
    /// Unix seconds the grant starts (default: now).
    #[serde(default)]
    not_before: Option<u64>,
    /// Unix seconds the grant ends. Exactly one of `expiry` / `ttl_secs`.
    #[serde(default)]
    expiry: Option<u64>,
    /// Lifetime from `not_before`, in seconds.
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// Extra agents (hex) to deliver the grant to, beyond the grantee's
    /// known agents and the shared agents' daemons.
    #[serde(default)]
    deliver_to: Vec<String>,
    /// ADR-0079: include the owner-signed names section (owner name and
    /// the names of machines hosting the shared agents) for grantee agents
    /// that advertise support (default `true`). `false` (CLI `--no-names`)
    /// sends this grant as v1 to everyone.
    #[serde(default)]
    include_names: Option<bool>,
}

/// GET /grants — grants this install's owner issued, with status.
pub(in crate::server) async fn grants_list(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    list_role(&state, GrantRole::Issued).await
}

/// GET /grants/received — grants naming this install as grantee.
pub(in crate::server) async fn grants_received(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    list_role(&state, GrantRole::Received).await
}

async fn list_role(state: &AppState, role: GrantRole) -> Response {
    let Some(store) = state.agent.share_grant_store() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "share-grant store not installed",
        )
        .into_response();
    };
    let now = unix_now_secs();
    // ADR-0079 §2: received grants show their pending name suggestion and
    // any `default_conflict` they raised.
    let (suggestions, conflicts) = if role == GrantRole::Received {
        state.names.defaults_snapshot().await.unwrap_or_default()
    } else {
        (Vec::new(), Vec::new())
    };
    let mut views = Vec::new();
    for grant in store.grants(role) {
        let revoked = state.agent.is_share_grant_revoked(&grant).await;
        let mut view = grant.to_view(now, revoked);
        if role == GrantRole::Received {
            view["name_suggestion"] = suggestions
                .iter()
                .find(|s| s.grant_id == grant.grant_id)
                .map_or(
                    serde_json::Value::Null,
                    x0x::names::OwnerSuggestion::to_json,
                );
            view["default_conflict"] = serde_json::json!(conflicts
                .iter()
                .filter(|c| c.grant_id == grant.grant_id)
                .map(x0x::names::DefaultConflict::to_json)
                .collect::<Vec<_>>());
        }
        views.push(view);
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "grants": views,
            "store_error": store.load_error(),
            "outbox_error": state
                .agent
                .share_grant_outbox()
                .and_then(|outbox| outbox.load_error().map(str::to_string)),
        })),
    )
        .into_response()
}

/// POST /grants — sign a grant with the owner key, store it, and deliver it
/// by durable DM to the grantee's known agents and to each shared agent's
/// daemon. `delivery` reports each recipient (delivered = its durable ACK
/// arrived). A failed delivery does not undo the grant; a shared agent's
/// daemon that did not receive it simply grants nothing (fail closed).
pub(in crate::server) async fn grants_issue(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<GrantIssueRequest>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    if state.agent.identity().user_keypair().is_none() {
        return api_error(
            StatusCode::CONFLICT,
            "share grants need an owner identity (user key) on this install",
        )
        .into_response();
    }
    let grantee = match (&req.grantee_user, &req.grantee_agent) {
        (Some(user), None) => match parse_id32("grantee_user", user) {
            Ok(id) => Grantee::User(UserId(id)),
            Err(msg) => return bad_request(msg),
        },
        (None, Some(agent)) => match parse_id32("grantee_agent", agent) {
            Ok(id) => Grantee::Agent(AgentId(id)),
            Err(msg) => return bad_request(msg),
        },
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "set exactly one of grantee_user / grantee_agent",
            )
            .into_response()
        }
    };
    let mut agents = Vec::with_capacity(req.agents.len());
    for raw in &req.agents {
        match parse_id32("agents", raw) {
            Ok(id) => agents.push(AgentId(id)),
            Err(msg) => return bad_request(msg),
        }
    }
    let mut deliver_to = Vec::with_capacity(req.deliver_to.len());
    for raw in &req.deliver_to {
        match parse_id32("deliver_to", raw) {
            Ok(id) => deliver_to.push(AgentId(id)),
            Err(msg) => return bad_request(msg),
        }
    }
    let not_before = req.not_before.unwrap_or_else(unix_now_secs);
    let expiry = match (req.expiry, req.ttl_secs) {
        (Some(expiry), None) => expiry,
        (None, Some(ttl)) => not_before.saturating_add(ttl),
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "set exactly one of expiry / ttl_secs (grants must expire)",
            )
            .into_response()
        }
    };
    let grant = match state
        .agent
        .issue_share_grant(grantee, agents, req.caps, not_before, expiry)
        .await
    {
        Ok(grant) => grant,
        Err(err) => return grant_error(&err),
    };
    let recipients = state
        .agent
        .share_grant_recipients(&grant, &deliver_to)
        .await;
    let names = if req.include_names.unwrap_or(true) {
        grant_names(&state, &grant).await
    } else {
        None
    };
    let names_included = names.is_some();
    let delivery = state
        .agent
        .deliver_share_grant_with_names(&grant, &recipients, names)
        .await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "grant": grant.to_view(unix_now_secs(), false),
            "names_included": names_included,
            "delivery": delivery,
        })),
    )
        .into_response()
}

/// ADR-0079 §1: the names section for `grant` — this install's
/// `human_name` and the synced names of the owner's enrolled machines that
/// host a shared agent. `None` when nothing qualifies.
async fn grant_names(state: &AppState, grant: &x0x::share_grant::ShareGrant) -> Option<GrantNames> {
    let owner_name = state.profile.read().await.human_name.clone();
    let devices = state.owner_sync.as_ref().map(|s| &**s.store());
    state
        .agent
        .share_grant_names_for(grant, owner_name.as_deref(), devices)
        .await
}

/// Handle one delivered share grant (v1 or ADR-0079 v2) for the daemon's
/// durable typed-DM route. The grant is verified and stored first; for a
/// v2 envelope received as grantee, the verified names are then applied to
/// the name store as defaults (contact gate: Known/Trusted owners bind
/// directly, strangers become suggestions). Only then is the completion
/// resolved: `Ok` (the v2 ACK) means the grant is durably stored. A
/// name-store failure is logged and does not withhold the ACK — the names
/// are defaults and the grant itself is stored.
pub(in crate::server) async fn handle_share_grant_delivery(
    state: &AppState,
    typed: x0x::dm_inbox::DmTypedPayload,
) -> Option<serde_json::Value> {
    let x0x::dm_inbox::DmTypedPayload {
        sender,
        payload,
        completion,
        ..
    } = typed;
    let store = state.agent.share_grant_store();
    let revocations = state.agent.revocation_set();
    let receipt = x0x::share_grant::receive_share_grant_payload(
        store.as_deref(),
        Some(&*revocations),
        &payload,
    )
    .await;
    let mut report = None;
    if let Ok(receipt) = &receipt {
        if let (Some(GrantRole::Received), Some(names)) = (receipt.role, &receipt.names) {
            report = Some(apply_grant_names(state, &receipt.grant, names).await);
        }
    }
    let result = receipt.map(|r| r.outcome);
    x0x::share_grant::log_share_grant_receipt(&sender, &result);
    if let Some(completion) = completion {
        let _ = completion.send(result);
    }
    report
}

/// Apply a received grant's verified names as defaults; returns the
/// grant-receipt result (`default_conflict` included).
pub(in crate::server) async fn apply_grant_names(
    state: &AppState,
    grant: &x0x::share_grant::ShareGrant,
    names: &GrantNames,
) -> serde_json::Value {
    let trusted = state.agent.share_grant_owner_is_contact(&grant.owner).await;
    match state
        .names
        .apply_grant_defaults(
            grant.grant_id,
            grant.owner,
            names,
            trusted,
            state.agent.user_id(),
            unix_now_secs(),
        )
        .await
    {
        Ok(report) => {
            let json = report.to_json();
            tracing::info!(
                grant = %grant.id_hex(),
                owner_trusted = trusted,
                names = %json,
                "share grant names applied as defaults"
            );
            json
        }
        Err(e) => {
            tracing::warn!(grant = %grant.id_hex(), "share grant names not applied: {e}");
            serde_json::json!({ "status": "name_store_error", "error": e.to_string() })
        }
    }
}

/// DELETE /grants/:id — revoke a grant with the owner key. Effective locally
/// at once; gossiped on `x0x.revocation.v3`. Answers success only once the
/// revocation and the removal of the grant's queued redeliveries (#926) are
/// durable; otherwise `503` (retry is idempotent).
pub(in crate::server) async fn grants_revoke(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    let grant_id = match parse_id32("id", &id) {
        Ok(id) => id,
        Err(msg) => return bad_request(msg),
    };
    if state.agent.identity().user_keypair().is_none() {
        return api_error(
            StatusCode::CONFLICT,
            "revoking a grant needs the owner key on this install",
        )
        .into_response();
    }
    let known = state
        .agent
        .share_grant_store()
        .is_some_and(|store| store.issued(&grant_id).is_some());
    match state.agent.revoke_share_grant(grant_id, None).await {
        Ok(_record) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "grant_id": hex::encode(grant_id),
                "revoked": true,
                "known": known,
            })),
        )
            .into_response(),
        Err(err) => grant_error(&err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::{delete, get};
    use tower::ServiceExt;

    const DURABLE: &str = "test-token";

    fn grants_router(state: Arc<AppState>, with_auth: bool) -> axum::Router {
        let router = axum::Router::new()
            .route("/grants", get(grants_list).post(grants_issue))
            .route("/grants/received", get(grants_received))
            .route("/grants/:id", delete(grants_revoke));
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
        req: Request<axum::body::Body>,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let resp = app.clone().oneshot(req).await?;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
    }

    fn owner_req(
        method: &str,
        path: &str,
        body: &str,
    ) -> anyhow::Result<Request<axum::body::Body>> {
        Ok(Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .extension(ActorContext::Owner { durable: true })
            .body(axum::body::Body::from(body.to_string()))?)
    }

    fn issue_body() -> String {
        serde_json::json!({
            "grantee_user": "bb".repeat(32),
            "agents": ["aa".repeat(32)],
            "caps": ["dm", {"connect": {"ports": [22]}}],
            "ttl_secs": 3600,
        })
        .to_string()
    }

    /// WHY: every `/grants` route is wired and answers the ADR-0070 §2
    /// contract on an ownerless install: lists work (empty), issuing and
    /// revoking are refused (only an owner key can sign or revoke a grant),
    /// a malformed body or id is a client error, and a grant must expire.
    #[tokio::test]
    async fn grant_routes_wired() -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        state.agent.install_share_grant_store(Arc::new(
            x0x::share_grant::ShareGrantStore::in_memory(state.agent.agent_id(), None),
        ));
        let app = grants_router(Arc::clone(&state), false);

        for path in ["/grants", "/grants/received"] {
            let (status, body) = send(&app, owner_req("GET", path, "")?).await?;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
            assert_eq!(body["grants"], serde_json::json!([]), "{path}: {body}");
        }
        let (status, body) = send(&app, owner_req("POST", "/grants", &issue_body())?).await?;
        assert_eq!(status, StatusCode::CONFLICT, "ownerless issue: {body}");
        let (status, _) = send(
            &app,
            owner_req("POST", "/grants", r#"{"agents":[],"caps":[],"bogus":1}"#)?,
        )
        .await?;
        assert!(status.is_client_error(), "unknown field must be rejected");
        let (status, body) = send(
            &app,
            owner_req("DELETE", &format!("/grants/{}", "cc".repeat(32)), "")?,
        )
        .await?;
        assert_eq!(status, StatusCode::CONFLICT, "ownerless revoke: {body}");
        let (status, _) = send(&app, owner_req("DELETE", "/grants/not-hex", "")?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        Ok(())
    }

    /// WHY: grants decide who reaches the owner's agents; a session or rider
    /// token must never read, issue or revoke them.
    #[tokio::test]
    async fn grant_routes_refuse_session_and_rider_tokens() -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let app = grants_router(Arc::clone(&state), true);
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
        let surfaces = [
            ("GET", "/grants".to_string(), String::new()),
            ("GET", "/grants/received".to_string(), String::new()),
            ("POST", "/grants".to_string(), issue_body()),
            (
                "DELETE",
                format!("/grants/{}", "cc".repeat(32)),
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
                let (status, json) = send(&app, req).await?;
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
            let (status, json) = send(&app, req).await?;
            assert_ne!(
                status,
                StatusCode::FORBIDDEN,
                "durable {method} {path} must clear the gate: {json}"
            );
        }
        Ok(())
    }
}
