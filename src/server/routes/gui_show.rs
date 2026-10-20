//! `POST /gui/show` — ADR 0083 slice 1 (local show).
//!
//! Validates the view grammar, applies `[gui_show] local_enabled`, the block
//! list and the rate limit, then either pushes a `gui.show` WS event
//! (`navigated`) or opens a fresh session URL (`opened`). The response never
//! contains a URL or session token.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::super::api_error;
use super::super::sse::SseEvent;
use super::super::state::AppState;
use crate::gui::{
    new_request_id, origin_banner, short_id_hex, view_route, GuiShowOutcome, GuiShowRequest,
    GuiShowResponse, PendingGuiShow,
};

/// POST /gui/show
pub(in crate::server) async fn gui_show(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GuiShowRequest>,
) -> Response {
    let machine_id = hex::encode(state.agent.machine_id().as_bytes());
    let request_id = new_request_id();

    // Slice 1: only local (absent / null target). Remote is #1394.
    if let Some(target) = req.target_machine.as_deref() {
        if !target.is_empty() {
            return json_outcome(GuiShowOutcome::Refused, machine_id, request_id);
        }
    }

    let cfg = state.gui_show.config();
    if !cfg.local_enabled {
        return json_outcome(GuiShowOutcome::Disabled, machine_id, request_id);
    }

    let parsed = match view_route::parse(&req.view) {
        Ok(v) => v,
        Err(_) => {
            return json_outcome(GuiShowOutcome::InvalidView, machine_id, request_id);
        }
    };
    let route = parsed.as_route();

    let agent_id = state.agent.agent_id();
    if state.gui_show.is_blocked(&agent_id) {
        return json_outcome(GuiShowOutcome::Refused, machine_id, request_id);
    }

    let now = Instant::now();
    if !state.gui_show.try_rate_limit(&agent_id, now) {
        return json_outcome(GuiShowOutcome::RateLimited, machine_id, request_id);
    }

    let (agent_label, machine_label) = resolve_banner_labels(&state).await;
    let banner = origin_banner(&agent_label, &machine_label, false);
    let agent_hex = hex::encode(agent_id.as_bytes());

    let has_ws = !state.ws_sessions.read().await.is_empty();
    if has_ws {
        let _ = state.broadcast_tx.send(SseEvent {
            event_type: "gui.show".to_string(),
            data: json!({
                "view": route,
                "banner": banner,
                "agent_id": agent_hex,
                "machine_id": machine_id,
                "rider": false,
                "request_id": request_id,
            }),
        });
        return json_outcome(GuiShowOutcome::Navigated, machine_id, request_id);
    }

    // Mint a fresh session; never put the durable token in the URL.
    let session = state.sessions.issue(Instant::now());
    let loopback = loopback_api_addr(state.api_address);
    let url = format!(
        "http://{}:{}/gui?token={session}#/{route}",
        loopback.ip(),
        loopback.port()
    );
    if state.gui_show.open_url(&url) {
        state.gui_show.set_pending(PendingGuiShow {
            view: route,
            banner,
            agent_id: agent_hex,
            machine_id: machine_id.clone(),
            rider: false,
            request_id: request_id.clone(),
            created_at: Instant::now(),
        });
        json_outcome(GuiShowOutcome::Opened, machine_id, request_id)
    } else {
        json_outcome(GuiShowOutcome::NoDisplay, machine_id, request_id)
    }
}

fn json_outcome(outcome: GuiShowOutcome, machine_id: String, request_id: String) -> Response {
    (
        StatusCode::OK,
        Json(GuiShowResponse {
            outcome,
            machine_id,
            request_id,
        }),
    )
        .into_response()
}

fn loopback_api_addr(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_loopback() {
        addr
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    }
}

async fn resolve_banner_labels(state: &AppState) -> (String, String) {
    let profile = state.profile.read().await;
    let agent_hex = hex::encode(state.agent.agent_id().as_bytes());
    let machine_hex = hex::encode(state.agent.machine_id().as_bytes());
    let agent_label = profile
        .display_name
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| profile.human_name.clone().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| short_id_hex(&agent_hex));
    let machine_label = profile
        .machine_name
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| short_id_hex(&machine_hex));
    (agent_label, machine_label)
}

/// POST /gui/show/block — add an agent to the local `gui_show_blocked` list.
///
/// Not in the public registry; used by the GUI origin-banner control over the
/// session-authenticated loopback plane.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct GuiShowBlockRequest {
    agent_id: String,
}

pub(in crate::server) async fn gui_show_block(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GuiShowBlockRequest>,
) -> Response {
    let bytes = match hex::decode(req.agent_id.trim()) {
        Ok(b) => b,
        Err(_) => {
            return api_error(StatusCode::BAD_REQUEST, "agent_id must be hex").into_response();
        }
    };
    let arr: [u8; 32] = match bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "agent_id must be 32 bytes (64 hex chars)",
            )
            .into_response();
        }
    };
    state.gui_show.block_agent(&crate::identity::AgentId(arr));
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::{CapturingOpener, GuiShowConfig};
    use crate::server::routes::named_groups::tests::secure_endpoint_test_state;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::post;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn router(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route("/gui/show", post(gui_show))
            .route("/gui/show/block", post(gui_show_block))
            .with_state(state)
    }

    async fn post_show(
        app: &axum::Router,
        body: serde_json::Value,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let req = Request::builder()
            .method("POST")
            .uri("/gui/show")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))?;
        let resp = app.clone().oneshot(req).await?;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
    }

    fn install_capturing_opener(state: &Arc<AppState>) -> CapturingOpener {
        let cap = CapturingOpener::new();
        state
            .gui_show
            .replace_opener_for_test(Arc::new(cap.clone()));
        cap
    }

    #[tokio::test]
    async fn durable_show_people_opened_without_token_or_url() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        let outcome = body["outcome"].as_str().unwrap_or("");
        assert!(
            outcome == "opened" || outcome == "navigated",
            "expected opened|navigated, got {body}"
        );
        assert!(body.get("token").is_none(), "must not leak token: {body}");
        assert!(body.get("url").is_none(), "must not leak url: {body}");
        assert!(body.get("session_token").is_none());
        let body_str = body.to_string();
        assert!(
            !body_str.contains("http://"),
            "response must not contain a URL: {body_str}"
        );
        if outcome == "opened" {
            let urls = cap.urls.lock().unwrap();
            assert_eq!(urls.len(), 1);
            assert!(urls[0].contains("/gui?token="));
            assert!(urls[0].contains("#/people"));
            assert!(
                !urls[0].contains("test-token"),
                "durable token must not appear"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn invalid_views_do_not_invoke_opener() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        let hex = "ab".repeat(16);
        for view in [
            "https://evil.example",
            "../x",
            "dm/zz",
            &format!("groups/{hex}/unknownapp"),
        ] {
            let (status, body) = post_show(&app, json!({ "view": view })).await?;
            assert_eq!(status, StatusCode::OK, "view={view}");
            assert_eq!(body["outcome"], "invalid_view", "view={view} body={body}");
        }
        assert!(
            cap.urls.lock().unwrap().is_empty(),
            "opener must not run for invalid_view"
        );
        Ok(())
    }

    #[tokio::test]
    async fn local_disabled_gives_disabled() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        install_capturing_opener(&state);
        state.gui_show.set_config(GuiShowConfig {
            local_enabled: false,
            remote_enabled: true,
        });
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "disabled");
        Ok(())
    }

    #[tokio::test]
    async fn fourth_burst_request_is_rate_limited() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        for i in 0..3 {
            let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
            assert_eq!(status, StatusCode::OK, "req {i}");
            let o = body["outcome"].as_str().unwrap_or("");
            assert!(
                o == "opened" || o == "navigated" || o == "no_display",
                "req {i}: {body}"
            );
        }
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "rate_limited", "{body}");
        Ok(())
    }

    #[tokio::test]
    async fn open_ws_session_yields_navigated_and_gui_show_event() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        {
            let mut sessions = state.ws_sessions.write().await;
            sessions.insert(
                "test-session".to_string(),
                crate::server::ws::test_ws_session("test-session"),
            );
        }
        let mut rx = state.broadcast_tx.subscribe();
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "network" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "navigated", "{body}");
        assert!(
            cap.urls.lock().unwrap().is_empty(),
            "must not open a window"
        );
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("event")
            .expect("recv");
        assert_eq!(event.event_type, "gui.show");
        assert_eq!(event.data["view"], "network");
        assert!(
            event.data["banner"]
                .as_str()
                .unwrap_or("")
                .starts_with("Opened by "),
            "banner={}",
            event.data["banner"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn registry_lists_gui_show() {
        assert!(
            crate::api::ENDPOINTS
                .iter()
                .any(|e| e.path == "/gui/show" && matches!(e.method, crate::api::Method::Post)),
            "POST /gui/show must be registered"
        );
        assert_eq!(
            crate::api::ENDPOINTS
                .iter()
                .find(|e| e.path == "/gui/show")
                .map(|e| e.cli_name),
            Some("show")
        );
    }
}
