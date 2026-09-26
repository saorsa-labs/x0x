//! Route handlers for ADR-0070 §3 ACL management (`category: "acl"` in
//! `src/api/mod.rs`): list/add/remove API-managed connect and exec ACL
//! entries over the operator TOML floor, and hot reload.
//!
//! Every route is owner/durable-token only. `auth_middleware` refuses
//! session bearers and riders before any extractor runs
//! (`requires_durable_owner`); the handlers re-check as defense in depth.

use super::super::acl_admin::AclAdminError;
use super::super::api_error;
use super::super::rider_auth::ActorContext;
use super::super::state::AppState;
use crate as x0x;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::sync::Arc;
use x0x::connect::ConnectAclEntrySpec;
use x0x::exec::ExecAclEntrySpec;

const DURABLE_REQUIRED: &str =
    "ACL management requires the durable API token (not a session or rider token)";

fn forbidden() -> Response {
    api_error(StatusCode::FORBIDDEN, DURABLE_REQUIRED).into_response()
}

fn admin_result(result: Result<serde_json::Value, AclAdminError>) -> Response {
    match result {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(err) => {
            let status = match &err {
                AclAdminError::BadRequest(_) => StatusCode::BAD_REQUEST,
                AclAdminError::Conflict(_) => StatusCode::CONFLICT,
                AclAdminError::NotFound(_) => StatusCode::NOT_FOUND,
                AclAdminError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            api_error(status, err.to_string()).into_response()
        }
    }
}

fn install_has_owner(state: &AppState) -> bool {
    state.agent.identity().user_keypair().is_some()
}

/// GET /acl/connect — floor (`origin: "file"`) and API (`origin: "api"`)
/// connect ACL entries, effective summary, and reload status.
pub(in crate::server) async fn acl_connect_list(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    (StatusCode::OK, Json(state.acl_admin.list_connect().await)).into_response()
}

/// POST /acl/connect — add one API-managed connect ACL entry. The body is
/// the `[[connect.allow]]` TOML entry schema as JSON, validated by the
/// same parser.
pub(in crate::server) async fn acl_connect_add(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Json(spec): Json<ConnectAclEntrySpec>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    let has_owner = install_has_owner(&state);
    admin_result(state.acl_admin.add_connect(spec, has_owner).await)
}

/// DELETE /acl/connect/:id — remove an API-managed connect entry. Floor
/// entries answer `409`.
pub(in crate::server) async fn acl_connect_remove(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    admin_result(state.acl_admin.remove_connect(&id).await)
}

/// GET /acl/exec — floor and API exec ACL entries, effective summary, and
/// reload status.
pub(in crate::server) async fn acl_exec_list(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    (StatusCode::OK, Json(state.acl_admin.list_exec().await)).into_response()
}

/// POST /acl/exec — add one API-managed exec ACL entry (the
/// `[[exec.allow]]` TOML entry schema as JSON).
pub(in crate::server) async fn acl_exec_add(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Json(spec): Json<ExecAclEntrySpec>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    let has_owner = install_has_owner(&state);
    admin_result(state.acl_admin.add_exec(spec, has_owner).await)
}

/// DELETE /acl/exec/:id — remove an API-managed exec entry. Floor entries
/// answer `409`.
pub(in crate::server) async fn acl_exec_remove(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(id): Path<String>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    admin_result(state.acl_admin.remove_exec(&id).await)
}

/// POST /acl/reload — re-read both TOML floors and API overlays. `200`
/// when both planes applied; `422` when any plane was rejected (that plane
/// keeps its last good ACL; see `/diagnostics/{connect,exec}`).
pub(in crate::server) async fn acl_reload(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    let report = state.acl_admin.reload().await;
    let status = if report.ok {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        Json(serde_json::to_value(report).unwrap_or_default()),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::{delete, get, post};
    use tower::ServiceExt;

    /// The fixture's durable API token (`secure_endpoint_test_state_at`
    /// hard-codes `"test-token"`).
    const DURABLE: &str = "test-token";

    fn acl_router(state: Arc<AppState>, with_auth: bool) -> axum::Router {
        let router = axum::Router::new()
            .route("/acl/connect", get(acl_connect_list).post(acl_connect_add))
            .route("/acl/connect/:id", delete(acl_connect_remove))
            .route("/acl/exec", get(acl_exec_list).post(acl_exec_add))
            .route("/acl/exec/:id", delete(acl_exec_remove))
            .route("/acl/reload", post(acl_reload));
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

    fn pair_entry() -> String {
        serde_json::json!({
            "agent_id": "aa".repeat(32),
            "machine_id": "bb".repeat(32),
            "targets": ["127.0.0.1:22"],
        })
        .to_string()
    }

    /// WHY: every `/acl/*` route is wired to its handler and answers with
    /// the ADR-0070 §3 contract on a daemon whose floors are disabled: the
    /// listing works, an add is refused (API entries never enable a plane
    /// the operator's file leaves off), a schema typo is rejected by the
    /// TOML parser's `deny_unknown_fields`, an unknown id is 404, and a
    /// reload of an unchanged exec floor succeeds.
    #[tokio::test]
    async fn acl_routes_wired() -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let app = acl_router(Arc::clone(&state), false);

        for path in ["/acl/connect", "/acl/exec"] {
            let (status, body) = send(&app, owner_req("GET", path, "")?).await?;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
            assert_eq!(body["enabled"], serde_json::json!(false), "{path}: {body}");
            assert!(body["entries"].is_array(), "{path}: {body}");
        }

        let (status, body) = send(&app, owner_req("POST", "/acl/connect", &pair_entry())?).await?;
        assert_eq!(status, StatusCode::CONFLICT, "disabled floor: {body}");
        let disabled = state.acl_admin.effective_connect().await;
        assert!(!disabled.enabled(), "a refused add must not enable connect");

        let typo = serde_json::json!({
            "agent_id": "aa".repeat(32),
            "machine_id": "bb".repeat(32),
            "comands": [{ "argv": ["uptime"] }],
        })
        .to_string();
        let (status, _body) = send(&app, owner_req("POST", "/acl/exec", &typo)?).await?;
        assert!(
            status.is_client_error(),
            "a misspelled field must be rejected, got {status}"
        );

        let (status, body) = send(
            &app,
            owner_req("DELETE", "/acl/connect/api-0011223344556677", "")?,
        )
        .await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let (status, body) = send(
            &app,
            owner_req("DELETE", "/acl/exec/api-0011223344556677", "")?,
        )
        .await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        let (_status, body) = send(&app, owner_req("POST", "/acl/reload", "")?).await?;
        assert_eq!(
            body["exec"]["ok"],
            serde_json::json!(true),
            "unchanged exec floor reloads: {body}"
        );
        assert!(body["connect"].is_object(), "{body}");
        Ok(())
    }

    /// WHY: ADR-0070 §3 — "rider and session tokens are refused". The ACL
    /// decides who may connect/exec, so a 10-minute browser session or a
    /// scoped rider must never read or widen it. Driven through the REAL
    /// `auth_middleware`; the handler-side gate is checked directly too.
    #[tokio::test]
    async fn acl_routes_refuse_session_and_rider_tokens() -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let app = acl_router(Arc::clone(&state), true);
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
            ("GET", "/acl/connect".to_string(), String::new()),
            ("POST", "/acl/connect".to_string(), pair_entry()),
            (
                "DELETE",
                "/acl/connect/api-0011223344556677".to_string(),
                String::new(),
            ),
            ("GET", "/acl/exec".to_string(), String::new()),
            (
                "DELETE",
                "/acl/exec/api-0011223344556677".to_string(),
                String::new(),
            ),
            ("POST", "/acl/reload".to_string(), String::new()),
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

        // Defense in depth: the handler refuses a non-durable actor even
        // if a future router wiring skipped the middleware.
        let bare = acl_router(Arc::clone(&state), false);
        let req = Request::builder()
            .method("POST")
            .uri("/acl/reload")
            .extension(ActorContext::Owner { durable: false })
            .body(axum::body::Body::empty())?;
        let (status, json) = send(&bare, req).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
        Ok(())
    }

    /// WHY: a `principal = "owner"` entry only means something with ADR-0070
    /// slice-1 owner trust; an install without an owner identity has none,
    /// so the API refuses the entry rather than store an inert grant.
    #[tokio::test]
    async fn acl_owner_entry_refused_without_owner_identity() -> anyhow::Result<()> {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        assert!(!install_has_owner(&state), "fixture is ownerless");
        let app = acl_router(Arc::clone(&state), false);
        let owner_entry = serde_json::json!({
            "principal": "owner",
            "targets": ["127.0.0.1:22"],
        })
        .to_string();
        let (status, body) = send(&app, owner_req("POST", "/acl/connect", &owner_entry)?).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("owner identity"),
            "{body}"
        );
        Ok(())
    }
}
