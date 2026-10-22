//! `POST /gui/show` — ADR 0083 slice 1 (local show).
//!
//! Validates the view grammar, applies `[gui_show] local_enabled`, the block
//! list and the rate limit, then either queues a `gui.show` frame on a
//! visible tab (`navigated`) or opens a fresh session URL (`opened`).
//! `navigated` is returned only when that tab's GUI session is still valid
//! and its outbound queue accepts the frame. The response never contains a
//! URL or session token.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::super::state::AppState;
use super::super::ws::GuiShowFrame;
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

    // Deliver on the tab's own queue. A broadcast would return before the
    // forwarder runs, and a full queue there drops the frame and closes
    // the socket. Reconnect does not replay that broadcast. The socket
    // outlives the session token, so the token is checked here, before
    // the frame is queued.
    let show = GuiShowFrame {
        view: route.clone(),
        banner: banner.clone(),
        agent_id: agent_hex.clone(),
        machine_id: machine_id.clone(),
        rider: false,
        request_id: request_id.clone(),
    };
    let decided_at = Instant::now();
    let accepted = {
        let sessions = state.ws_sessions.read().await;
        let mut accepted = false;
        for session in sessions.values() {
            if session
                .try_accept_gui_show(&show, |token| state.sessions.is_valid(token, decided_at))
            {
                accepted = true;
            }
        }
        accepted
    };
    if accepted {
        return json_outcome(GuiShowOutcome::Navigated, machine_id, request_id);
    }

    // Mint a fresh session; never put the durable token in the URL.
    // Queue the banner before the opener so a browser that connects during
    // the launch wait still receives it. A failed launch drops that entry
    // and revokes the session so the token is not valid.
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
    // The launch runs on the blocking pool. That pool cannot be aborted, and
    // the opener lock used to queue every launch behind the previous wait.
    // Track the launch, and give it only the opener and the stop flag: it
    // must not keep this `AppState` (and the Agent and database) alive.
    let Some(opener) = state.gui_show.opener_for_launch() else {
        state.sessions.revoke(&session);
        state.gui_show.drop_pending_for_session(&session);
        return json_outcome(GuiShowOutcome::NoDisplay, machine_id, request_id);
    };
    let stop = state.gui_show.open_stop_flag();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let admitted = state.spawn_detached(async move {
        let opened = tokio::task::spawn_blocking(move || {
            if stop.load(std::sync::atomic::Ordering::Acquire) {
                false
            } else {
                opener.open_until(&url, &stop)
            }
        })
        .await
        .unwrap_or(false);
        let _ = tx.send(opened);
    });
    if !admitted {
        state.sessions.revoke(&session);
        state.gui_show.drop_pending_for_session(&session);
        return json_outcome(GuiShowOutcome::NoDisplay, machine_id, request_id);
    }
    let opened = rx.await.unwrap_or(false);
    if opened {
        json_outcome(GuiShowOutcome::Opened, machine_id, request_id)
    } else {
        state.sessions.revoke(&session);
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
    use serde_json::json;
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
    async fn open_ws_session_yields_navigated_when_the_queue_accepts() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let token = state.sessions.issue(Instant::now());
        let probe = {
            let mut sessions = state.ws_sessions.write().await;
            crate::server::ws::insert_visible_gui_with_queue(
                &mut sessions,
                "test-session",
                4,
                0,
                &token,
            )
        };
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "network" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "navigated", "{body}");
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        assert!(
            cap.urls.lock().unwrap().is_empty(),
            "must not open a window"
        );
        let shows = probe.gui_shows();
        assert_eq!(shows.len(), 1, "{shows:?}");
        assert_eq!(shows[0].0, "network");
        assert!(
            shows[0].1.starts_with("Opened by "),
            "banner={}",
            shows[0].1
        );
        Ok(())
    }

    #[tokio::test]
    async fn saturated_live_tab_does_not_report_navigated() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let token = state.sessions.issue(Instant::now());
        let probe = {
            let mut sessions = state.ws_sessions.write().await;
            crate::server::ws::insert_visible_gui_with_queue(
                &mut sessions,
                "saturated",
                1,
                1,
                &token,
            )
        };
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "opened",
            "a full live-tab queue is not a navigation: {body}"
        );
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        let urls = cap.urls.lock().unwrap();
        assert_eq!(
            urls.len(),
            1,
            "the browser must open when the frame is not queued"
        );
        assert!(urls[0].contains("#/people"), "{}", urls[0]);
        drop(urls);
        assert!(
            probe.gui_shows().is_empty(),
            "the saturated queue must not contain the show frame"
        );
        Ok(())
    }

    #[tokio::test]
    async fn expired_visible_tab_does_not_report_navigated() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let token = state.sessions.issue(Instant::now());
        let probe = {
            let mut sessions = state.ws_sessions.write().await;
            crate::server::ws::insert_visible_gui_with_queue(
                &mut sessions,
                "expired-tab",
                4,
                0,
                &token,
            )
        };
        state.sessions.expire_for_test(&token);
        assert!(
            !state.sessions.is_live_for_test(&token, Instant::now()),
            "the fixture must be an expired GUI session"
        );
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "opened",
            "an expired visible tab is not a navigation: {body}"
        );
        assert!(
            probe.gui_shows().is_empty(),
            "the expired tab must not be told to navigate"
        );
        let urls = cap.urls.lock().unwrap();
        assert_eq!(urls.len(), 1, "the browser must open");
        assert!(urls[0].contains("#/people"), "{}", urls[0]);
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
        assert!(
            !state
                .sessions
                .is_live_for_test(&token, std::time::Instant::now()),
            "a failed opener must revoke the session it minted"
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
        let original = "[gui_show]\nlocal_enabled = true\nremote_enabled = true\n";
        std::fs::write(&path, original)?;
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
        assert_eq!(
            std::fs::read_to_string(&path)?,
            original,
            "stop leaves the daemon config unchanged"
        );
        assert!(dir
            .path()
            .join(crate::gui::show::LOCAL_SHOW_STOP_FILE)
            .is_file());
        std::fs::write(&path, original)?;
        state
            .gui_show
            .reload_from_disk()
            .map_err(|error| anyhow::anyhow!(error))?;
        assert!(dir
            .path()
            .join(crate::gui::show::LOCAL_SHOW_STOP_FILE)
            .is_file());
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "disabled", "{body}");
        std::fs::remove_file(dir.path().join(crate::gui::show::LOCAL_SHOW_STOP_FILE))?;
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
    async fn acl_reload_returns_only_the_acl_report() -> anyhow::Result<()> {
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
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("gui_show").is_none(), "{body}");
        assert_eq!(body["ok"], json!(true), "{body}");
        assert!(
            state.gui_show.config().local_enabled,
            "a TOML error keeps the last good config"
        );
        assert!(state.gui_show.config().remote_enabled);

        state
            .gui_show
            .set_config_path(Some(dir.path().join("missing.toml")));
        let (status, body) = post_reload(&app).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("gui_show").is_none(), "{body}");
        assert_eq!(body["ok"], json!(true), "{body}");
        assert!(state.gui_show.config().local_enabled);
        assert!(state.gui_show.config().remote_enabled);
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

    /// Three slow opens used to share one mutex and an `Arc<AppState>` on
    /// the blocking pool. Shutdown's 2s grace then returned while those
    /// launches still held the Agent and the database.
    #[tokio::test]
    async fn concurrent_opens_finish_at_shutdown_without_holding_state() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::Duration;

        struct Release(Arc<AtomicBool>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        struct SlowOpen {
            entered: Arc<AtomicUsize>,
            in_flight: Arc<AtomicUsize>,
            release: Arc<AtomicBool>,
        }
        impl SlowOpen {
            fn park(&self, stop: &AtomicBool) -> bool {
                self.in_flight.fetch_add(1, Ordering::SeqCst);
                self.entered.fetch_add(1, Ordering::SeqCst);
                // One wait with no stop check. A drain that joins this launch
                // is still inside it. A drain that does not track it returns
                // during the wait.
                std::thread::sleep(Duration::from_millis(200));
                while !stop.load(Ordering::Acquire) && !self.release.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(20));
                }
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                false
            }
        }
        impl ShowOpener for SlowOpen {
            fn open(&self, _url: &str) -> bool {
                self.park(&AtomicBool::new(false))
            }
            fn open_until(&self, _url: &str, stop: &AtomicBool) -> bool {
                self.park(stop)
            }
        }

        let (state, _dir) = secure_endpoint_test_state().await?;
        let entered = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let _release_on_drop = Release(Arc::clone(&release));
        state.gui_show.replace_opener_for_test(Arc::new(SlowOpen {
            entered: Arc::clone(&entered),
            in_flight: Arc::clone(&in_flight),
            release: Arc::clone(&release),
        }));
        let baseline = Arc::strong_count(&state);
        let app = router(Arc::clone(&state));
        let mut joins = Vec::new();
        for _ in 0..3 {
            let app = app.clone();
            joins.push(tokio::spawn(async move {
                let _ = post_show(&app, json!({ "view": "people" })).await;
            }));
        }
        let ready = tokio::time::timeout(Duration::from_secs(1), async {
            while entered.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            ready.is_ok(),
            "three launches did not run together; entered={}",
            entered.load(Ordering::SeqCst)
        );
        for join in &joins {
            join.abort();
        }
        for join in joins {
            let _ = join.await;
        }
        drop(app);
        tokio::task::yield_now().await;
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            3,
            "aborting the HTTP handlers stopped the browser opens"
        );
        assert_eq!(
            Arc::strong_count(&state),
            baseline,
            "an in-flight browser open still holds AppState"
        );
        let started = Instant::now();
        crate::server::drain_server_tasks(&state, Vec::new()).await;
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            0,
            "browser opens outlived the shutdown drain"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown waited out the serialized opens: {:?}",
            started.elapsed()
        );
        Ok(())
    }
}
