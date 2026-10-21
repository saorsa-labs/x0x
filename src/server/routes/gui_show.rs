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
    // ADR 0083 §5: a blocked sender is refused. Slice 1's requester is this
    // daemon's agent, and that agent is not exempt.
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

    let has_gui = state
        .ws_sessions
        .read()
        .await
        .values()
        .any(super::super::ws::WsSession::is_visible_gui);
    if has_gui {
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
    // Queue the banner before the opener so a browser that connects during
    // the launch wait still receives it. A failed launch drops that entry.
    let session = state.sessions.issue(Instant::now());
    let url = show_loopback_url(state.api_address, &session, &route);
    state.gui_show.enqueue_pending(PendingGuiShow {
        view: route,
        banner,
        agent_id: agent_hex,
        machine_id: machine_id.clone(),
        rider: false,
        request_id: request_id.clone(),
        session_token: session.clone(),
        created_at: Instant::now(),
    });
    let state_for_open = Arc::clone(&state);
    let opened = tokio::task::spawn_blocking(move || state_for_open.gui_show.open_url(&url))
        .await
        .unwrap_or_default();
    if opened {
        json_outcome(GuiShowOutcome::Opened, machine_id, request_id)
    } else {
        state.gui_show.drop_pending_for_session(&session);
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

/// Browser URL for a fresh GUI session.
///
/// `SocketAddr`'s display form brackets an IPv6 host (`[::1]:port`). Formatting
/// the IP and port separately emits `http://::1:port/`, which URL parsers reject.
fn show_loopback_url(api: SocketAddr, session: &str, route: &str) -> String {
    let addr = loopback_api_addr(api);
    format!("http://{addr}/gui?token={session}#/{route}")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::{CapturingOpener, GuiShowConfig, ShowOpener};
    use crate::server::routes::named_groups::tests::secure_endpoint_test_state;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::post;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn router(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route("/gui/show", post(gui_show))
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
                crate::server::ws::test_gui_ws_session("test-session"),
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
    async fn agent_ws_does_not_suppress_opening_the_browser() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        {
            let mut sessions = state.ws_sessions.write().await;
            sessions.insert(
                "agent-ws".to_string(),
                crate::server::ws::test_ws_session("agent-ws"),
            );
            sessions.insert(
                "agent-direct".to_string(),
                crate::server::ws::test_ws_session("agent-direct"),
            );
        }
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "opened",
            "an agent /ws or /ws/direct socket is not a visible GUI: {body}"
        );
        let urls = cap.urls.lock().unwrap();
        assert_eq!(urls.len(), 1, "the browser must still be opened");
        assert!(
            urls[0].contains("gui=1") || urls[0].contains("/gui?token="),
            "opened url={}",
            urls[0]
        );
        Ok(())
    }

    #[tokio::test]
    async fn blocking_the_daemon_agent_refuses_local_show() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        state.gui_show.block_agent(&state.agent.agent_id());
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "refused",
            "ADR 0083 §5 refuses a blocked sender, including this daemon's agent: {body}"
        );
        assert!(
            cap.urls.lock().unwrap().is_empty(),
            "a blocked sender must not open a window"
        );
        Ok(())
    }

    #[test]
    fn ipv6_loopback_url_brackets_the_host() {
        let addr: std::net::SocketAddr = "[::1]:12700".parse().expect("ipv6 loopback");
        let url = show_loopback_url(addr, "sess", "people");
        assert_eq!(url, "http://[::1]:12700/gui?token=sess#/people");
        assert!(
            !url.contains("http://::1:"),
            "an unbracketed IPv6 URL does not parse: {url}"
        );
        let v4: std::net::SocketAddr = "127.0.0.1:12700".parse().expect("ipv4 loopback");
        assert_eq!(
            show_loopback_url(v4, "sess", "network"),
            "http://127.0.0.1:12700/gui?token=sess#/network"
        );
    }

    #[tokio::test]
    async fn opener_failure_is_no_display() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        *cap.succeed.lock().expect("succeed flag") = false;
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "no_display", "{body}");
        let urls = cap.urls.lock().expect("urls");
        assert_eq!(urls.len(), 1, "the opener still receives the URL");
        let token = urls[0]
            .split("token=")
            .nth(1)
            .unwrap_or("")
            .split(['&', '#'])
            .next()
            .unwrap_or("")
            .to_string();
        drop(urls);
        assert!(
            !token.is_empty(),
            "the failed launch still minted a session"
        );
        assert!(
            state
                .gui_show
                .take_pending_for_session(&token, std::time::Instant::now())
                .is_none(),
            "a failed opener must drop the banner it queued"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pending_banner_is_queued_before_the_opener_runs() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let saw = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let weak = Arc::downgrade(&state);
        let queued = saw.clone();
        struct Probe {
            saw: Arc<std::sync::atomic::AtomicBool>,
            check: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        }
        impl ShowOpener for Probe {
            fn open(&self, url: &str) -> bool {
                self.saw
                    .store((self.check)(url), std::sync::atomic::Ordering::SeqCst);
                true
            }
        }
        state.gui_show.replace_opener_for_test(Arc::new(Probe {
            saw: queued,
            check: Arc::new(move |url: &str| {
                let Some(state) = weak.upgrade() else {
                    return false;
                };
                let Some(token) = url.split("token=").nth(1) else {
                    return false;
                };
                let token = token.split(['&', '#']).next().unwrap_or("");
                !token.is_empty() && state.gui_show.has_pending_session(token)
            }),
        }));
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "opened", "{body}");
        assert!(
            saw.load(std::sync::atomic::Ordering::SeqCst),
            "the banner must already be queued while the opener runs"
        );
        Ok(())
    }

    #[tokio::test]
    async fn hidden_gui_tab_does_not_suppress_opening_the_browser() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        {
            let mut sessions = state.ws_sessions.write().await;
            sessions.insert(
                "hidden-gui".to_string(),
                crate::server::ws::test_gui_ws_session("hidden-gui"),
            );
            sessions
                .get_mut("hidden-gui")
                .expect("session")
                .set_visible_gui(false);
        }
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "opened",
            "a hidden tab is not a live GUI: {body}"
        );
        assert_eq!(cap.urls.lock().unwrap().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn two_shows_before_the_browser_connects_keep_both_pending() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        let (status_a, body_a) = post_show(&app, json!({ "view": "people" })).await?;
        let (status_b, body_b) = post_show(&app, json!({ "view": "network" })).await?;
        assert_eq!(status_a, StatusCode::OK);
        assert_eq!(status_b, StatusCode::OK);
        assert_eq!(body_a["outcome"], "opened", "{body_a}");
        assert_eq!(body_b["outcome"], "opened", "{body_b}");
        let urls = cap.urls.lock().unwrap();
        assert_eq!(urls.len(), 2, "both shows must open a window: {urls:?}");
        let token = |url: &str| {
            url.split("token=")
                .nth(1)
                .unwrap_or("")
                .split(['&', '#'])
                .next()
                .unwrap_or("")
                .to_string()
        };
        let token_a = token(&urls[0]);
        let token_b = token(&urls[1]);
        assert_ne!(token_a, token_b, "each window has its own session");
        drop(urls);
        let now = std::time::Instant::now();
        let first = state
            .gui_show
            .take_pending_for_session(&token_a, now)
            .expect("first show still pending");
        let second = state
            .gui_show
            .take_pending_for_session(&token_b, now)
            .expect("second show still pending");
        assert_eq!(first.view, "people");
        assert_eq!(second.view, "network");
        assert!(
            state
                .gui_show
                .take_pending_for_session("not-a-gui-session", now)
                .is_none(),
            "an arbitrary socket must not receive either banner"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stop_then_reload_reenables_local_show() -> anyhow::Result<()> {
        let (state, dir) = secure_endpoint_test_state().await?;
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[gui_show]\nlocal_enabled = true\nremote_enabled = true\n",
        )?;
        state.gui_show.set_config_path(Some(path.clone()));
        state
            .gui_show
            .disable_local_show()
            .map_err(|error| anyhow::anyhow!(error))?;
        let app = router(Arc::clone(&state));
        install_capturing_opener(&state);
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "disabled", "{body}");
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        let text = std::fs::read_to_string(&path)?;
        assert!(text.contains("local_enabled = false"), "{text}");
        std::fs::write(
            &path,
            text.replace("local_enabled = false", "local_enabled = true"),
        )?;
        state
            .gui_show
            .reload_from_disk()
            .map_err(|error| anyhow::anyhow!(error))?;
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "opened", "{body}");
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        Ok(())
    }

    #[tokio::test]
    async fn stop_without_a_config_file_disables_show_and_creates_no_config() -> anyhow::Result<()>
    {
        let (state, dir) = secure_endpoint_test_state().await?;
        state
            .gui_show
            .disable_local_show()
            .map_err(|error| anyhow::anyhow!(error))?;
        assert!(!state.gui_show.config().local_enabled);
        assert!(dir
            .path()
            .join(crate::gui::show::LOCAL_SHOW_STOP_FILE)
            .is_file());
        assert!(
            !dir.path().join("config.toml").exists(),
            "stop must not invent a daemon config"
        );
        let app = router(Arc::clone(&state));
        install_capturing_opener(&state);
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "disabled", "{body}");
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        assert!(body.get("session_token").is_none(), "{body}");
        Ok(())
    }

    #[tokio::test]
    async fn acl_reload_reports_gui_config_read_and_toml_errors() -> anyhow::Result<()> {
        let (state, dir) = secure_endpoint_test_state().await?;
        state.gui_show.set_config(GuiShowConfig {
            local_enabled: true,
            remote_enabled: true,
        });
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[gui_show]\nlocal_enabled = \n")?;
        state.gui_show.set_config_path(Some(path));
        let app = axum::Router::new()
            .route("/acl/reload", post(super::super::acl_reload))
            .with_state(Arc::clone(&state));

        let (status, body) = post_reload(&app).await?;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["ok"], json!(false), "{body}");
        let error = body["gui_show"]["error"].as_str().unwrap_or("");
        assert!(error.contains("failed to parse GUI config"), "{body}");
        assert!(
            state.gui_show.config().local_enabled,
            "a TOML error must not replace the last good config"
        );

        state
            .gui_show
            .set_config_path(Some(dir.path().join("missing.toml")));
        let (status, body) = post_reload(&app).await?;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["ok"], json!(false), "{body}");
        let error = body["gui_show"]["error"].as_str().unwrap_or("");
        assert!(error.contains("failed to read GUI config"), "{body}");
        assert!(state.gui_show.config().local_enabled);
        Ok(())
    }

    async fn post_reload(app: &axum::Router) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let req = Request::builder()
            .method("POST")
            .uri("/acl/reload")
            .extension(crate::server::rider_auth::ActorContext::Owner { durable: true })
            .body(axum::body::Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
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
