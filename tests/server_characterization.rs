//! Phase 0 — characterization (golden) tests for Issue #110.
//!
//! These tests pin the **observable HTTP/SSE behaviour** of the current
//! `x0xd` binary so the upcoming bin→lib extraction (`x0x::server::serve`)
//! can be proven to change nothing the wire can see. They are the regression
//! oracle: every assertion here records behaviour that EXISTS on `main` today
//! and MUST survive the move unchanged. If one of these starts failing during
//! the refactor, the refactor — not the test — is wrong.
//!
//! All tests are `#[ignore]` (they spawn a real daemon), matching the
//! `daemon_api_integration.rs` convention. Run the oracle with:
//!
//! ```text
//! cargo nextest run --all-features --test server_characterization --run-ignored all
//! ```
//!
//! Scope notes (fail-loud, Rule 12):
//! - SSE tests pin the handshake contract (200 + `text/event-stream`), which
//!   is the part the bin→lib move can break; per-event payload framing is
//!   already covered by the functional WS/SSE tests in
//!   `daemon_api_integration.rs` and is not re-asserted here.
//! - `--doctor` and `--check-updates` are intentionally NOT exercised: both
//!   perform network I/O, which would make the oracle non-hermetic/flaky.
//!   `--check` and `--version` cover the "CLI-only flag does not start a
//!   server" contract without touching the network.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use reqwest::header::CONTENT_TYPE;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

async fn daemon() -> DaemonFixture {
    DaemonFixture::start("char").await
}

fn c() -> reqwest::Client {
    DaemonFixture::client(Duration::from_secs(10))
}

fn ca(d: &DaemonFixture) -> reqwest::Client {
    d.authed_client(Duration::from_secs(10))
}

// ===========================================================================
// Auth matrix — exemptions
// ===========================================================================

/// `/health` is auth-exempt: liveness probes (and the test harness) hit it
/// without a token. If the move re-gated it, every probe would start 401ing.
#[tokio::test]
#[ignore]
async fn health_is_auth_exempt() {
    let d = daemon().await;
    let resp = c().get(d.url("/health")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
}

/// `/constitution*` is auth-exempt (public, browser-fetchable resources).
/// Asserting "not 401 and not a 5xx" pins the exemption without coupling to
/// the exact 2xx/redirect status of the resource.
#[tokio::test]
#[ignore]
async fn constitution_is_auth_exempt() {
    let d = daemon().await;
    let resp = c().get(d.url("/constitution")).send().await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "/constitution must remain auth-exempt"
    );
    assert!(
        !resp.status().is_server_error(),
        "/constitution must not 5xx (got {})",
        resp.status()
    );
}

/// CORS preflight `OPTIONS` is exempt from bearer auth — browsers send it
/// without an `Authorization` header. The guard is "not 401"; routing may
/// still answer 2xx/405, but auth must never block the preflight.
#[tokio::test]
#[ignore]
async fn options_preflight_bypasses_auth() {
    let d = daemon().await;
    let resp = c()
        .request(Method::OPTIONS, d.url("/status"))
        .send()
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "OPTIONS preflight must bypass auth"
    );
}

// ===========================================================================
// Auth matrix — protected endpoints
// ===========================================================================

/// Control endpoints require a bearer token. Without one, `/status` is 401
/// AND the body is the JSON error envelope clients parse — a move to an
/// empty/plaintext 401 would break consumers, so the shape is pinned.
#[tokio::test]
#[ignore]
async fn protected_endpoint_requires_bearer() {
    let d = daemon().await;
    let resp = c().get(d.url("/status")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].is_string(),
        "401 must carry a JSON `error` field, got {body}"
    );
}

/// A wrong bearer token is rejected (not merely a missing one).
#[tokio::test]
#[ignore]
async fn invalid_bearer_rejected() {
    let d = daemon().await;
    let resp = c()
        .get(d.url("/status"))
        .header(reqwest::header::AUTHORIZATION, "Bearer not-the-real-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// Auth matrix — `?token=` query parameter (EventSource / WebSocket clients)
// ===========================================================================

/// Every path on the `accepts_query_token` allow-list must authenticate via
/// `?token=` (browsers' `EventSource`/`WebSocket` can't set headers). For
/// each path we prove BOTH halves of the contract: with no credential it is
/// 401, and with a valid query token it is NOT 401 (the exact non-401 status
/// is protocol-specific — 200 for SSE/GUI, an upgrade error for raw WS GETs —
/// so we only assert the auth decision). A relocation that drops any single
/// path from the allow-list fails here.
#[tokio::test]
#[ignore]
async fn query_token_authenticates_every_allowlisted_path() {
    let d = daemon().await;
    // Mirror of `accepts_query_token` in src/bin/x0xd.rs.
    let paths = [
        "/gui",
        "/gui/",
        "/ws",
        "/ws/direct",
        "/events",
        "/direct/events",
        "/peers/events",
        "/presence/events",
    ];
    for path in paths {
        let no_token = c().get(d.url(path)).send().await.unwrap();
        assert_eq!(
            no_token.status(),
            StatusCode::UNAUTHORIZED,
            "{path} with no credential must be 401"
        );
        let with_token = c()
            .get(format!("{}?token={}", d.url(path), d.api_token()))
            .send()
            .await
            .unwrap();
        assert_ne!(
            with_token.status(),
            StatusCode::UNAUTHORIZED,
            "{path}?token= must authenticate (got 401)"
        );
    }
}

/// `?token=` must authenticate ONLY the SSE/WS allow-list — never ordinary
/// control endpoints. If it leaked to `/status`, `/agent`, or `/shutdown`,
/// any URL-logging proxy would capture a credential that grants control.
/// (Auth runs before routing, so `GET /shutdown?token=` is rejected at the
/// auth layer and never reaches the POST handler — safe to assert.)
#[tokio::test]
#[ignore]
async fn query_token_rejected_on_control_endpoints() {
    let d = daemon().await;
    for path in ["/status", "/agent", "/shutdown"] {
        let url = format!("{}?token={}", d.url(path), d.api_token());
        let resp = c().get(url).send().await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "GET {path}?token= must NOT authenticate a control endpoint"
        );
    }
    // Method-specific guard: the real control verb is POST /shutdown. A query
    // token must not authenticate it (else a logged URL could stop the daemon).
    // Current behaviour rejects at the auth layer, so the daemon stays up.
    let posted = c()
        .post(format!("{}?token={}", d.url("/shutdown"), d.api_token()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        posted.status(),
        StatusCode::UNAUTHORIZED,
        "POST /shutdown?token= must NOT authenticate"
    );
    // And the daemon must still be alive afterwards.
    let health = c().get(d.url("/health")).send().await.unwrap();
    assert_eq!(health.status(), StatusCode::OK, "daemon must survive");
}

// ===========================================================================
// SSE handshake contract
// ===========================================================================

/// All four SSE endpoints (authenticated) open `200 text/event-stream`. A
/// relocation that returns plain JSON for a stream — or wires the handler to
/// a non-streaming response — breaks `EventSource` clients; pinning the
/// content-type on every stream catches that.
#[tokio::test]
#[ignore]
async fn sse_endpoints_open_as_event_stream() {
    let d = daemon().await;
    for path in [
        "/events",
        "/direct/events",
        "/peers/events",
        "/presence/events",
    ] {
        let resp = ca(&d).get(d.url(path)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path} should be 200");
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.starts_with("text/event-stream"),
            "{path} must be text/event-stream, got {ct:?}"
        );
    }
}

// ===========================================================================
// Positive route + AppState wiring
// ===========================================================================

/// Representative authenticated reads must succeed with their real payloads.
/// This is the counter-weight to the auth tests: it proves the router still
/// has these routes AND that `AppState`/the `Agent` are wired in — a move
/// that authenticates correctly but hands handlers a broken state, or omits
/// route groups, fails here rather than silently shipping.
#[tokio::test]
#[ignore]
async fn authenticated_core_routes_serve_real_payloads() {
    let d = daemon().await;

    let status: Value = ca(&d)
        .get(d.url("/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["ok"], true);
    assert_eq!(
        status["agent_id"].as_str().map(str::len),
        Some(64),
        "/status must expose a 64-hex agent_id (state wired)"
    );

    let agent: Value = ca(&d)
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(agent["agent_id"].is_string() && agent["machine_id"].is_string());

    // GUI bootstrap is HTML served from the same router.
    let gui = ca(&d).get(d.url("/gui")).send().await.unwrap();
    assert_eq!(gui.status(), StatusCode::OK);
    let ct = gui
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(ct.contains("text/html"), "/gui must serve HTML, got {ct:?}");
}

/// `/constitution` and `/constitution/json` are public AND serve their exact
/// content types (`text/markdown`, `application/json`). The prefix-based
/// exemption means BOTH must stay reachable and correctly typed — asserting
/// the content type (not just "not 401") catches a route regressing to 404.
#[tokio::test]
#[ignore]
async fn constitution_endpoints_public_with_content_types() {
    let d = daemon().await;

    let md = c().get(d.url("/constitution")).send().await.unwrap();
    assert_eq!(md.status(), StatusCode::OK);
    let md_ct = md
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        md_ct.starts_with("text/markdown"),
        "/constitution must be text/markdown, got {md_ct:?}"
    );

    let json = c().get(d.url("/constitution/json")).send().await.unwrap();
    assert_eq!(json.status(), StatusCode::OK);
    let json_ct = json
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        json_ct.starts_with("application/json"),
        "/constitution/json must be application/json, got {json_ct:?}"
    );
}

// ===========================================================================
// CORS layer + body limit (middleware that must survive the move)
// ===========================================================================

/// A real CORS preflight from a loopback origin is answered with an
/// `access-control-allow-origin` header; a non-loopback origin is NOT. Pins
/// that the loopback-only `CorsLayer` is present and ordered correctly (the
/// daemon API is a local control plane — external origins must not access it).
#[tokio::test]
#[ignore]
async fn cors_preflight_allows_loopback_rejects_external() {
    let d = daemon().await;

    let allowed = c()
        .request(Method::OPTIONS, d.url("/status"))
        .header("Origin", "http://127.0.0.1")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();
    assert!(
        allowed
            .headers()
            .contains_key("access-control-allow-origin"),
        "loopback origin preflight must be allowed by CORS"
    );

    let rejected = c()
        .request(Method::OPTIONS, d.url("/status"))
        .header("Origin", "http://evil.example")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();
    assert!(
        !rejected
            .headers()
            .contains_key("access-control-allow-origin"),
        "external origin must NOT receive CORS allow-origin"
    );
}

/// The 1 MiB `DefaultBodyLimit` rejects oversized bodies with 413 before the
/// handler runs. Dropping that layer in the move is an observable regression
/// (and a DoS foot-gun), so it is pinned.
#[tokio::test]
#[ignore]
async fn oversized_body_is_rejected_413() {
    let d = daemon().await;
    let big = "x".repeat(2 * 1024 * 1024); // 2 MiB > 1 MiB limit
    let body = serde_json::json!({ "payload_b64": big });
    let resp = ca(&d)
        .post(d.url("/agent/sign"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "body over 1 MiB must be 413, got {}",
        resp.status()
    );
}

// ===========================================================================
// Input handling
// ===========================================================================

/// Malformed JSON on a JSON endpoint is a client error (400), never a 5xx or
/// a panic. Guards against a moved handler losing its JSON extractor and
/// starting to 500 (or crash) on bad input.
#[tokio::test]
#[ignore]
async fn malformed_json_body_is_client_error() {
    let d = daemon().await;
    let resp = ca(&d)
        .post(d.url("/agent/sign"))
        .header(CONTENT_TYPE, "application/json")
        .body("{ this is not valid json")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "malformed JSON must be 400, not {}",
        resp.status()
    );
}

// ===========================================================================
// Shutdown + file lifecycle
// ===========================================================================

/// `POST /shutdown` (authenticated) stops the daemon gracefully, removes the
/// `api.port` file, and leaves `api-token` in place. Token persistence is
/// deliberate: clients keep their credential across daemon restarts. (Pins
/// the EXACT current behaviour — only the port file is removed on stop.)
#[tokio::test]
#[ignore]
async fn shutdown_stops_daemon_removes_port_file_keeps_token() {
    let mut d = daemon().await;
    assert!(
        d.port_file().exists(),
        "api.port should exist while running"
    );
    assert!(
        d.token_file().exists(),
        "api-token should exist while running"
    );

    // Graceful shutdown drains in-flight requests, so the response completes:
    // current behaviour is a 200 JSON ack.
    let resp = ca(&d).post(d.url("/shutdown")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "POST /shutdown acks 200");

    // Poll for exit (30s window — matches the integration-test convention,
    // which was widened for slow CI).
    let mut status = None;
    for _ in 0..300 {
        if let Ok(Some(s)) = d.try_wait() {
            status = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let status = status.expect("daemon did not exit after POST /shutdown");
    assert!(
        status.success(),
        "graceful shutdown must exit cleanly, got {status:?}"
    );

    assert!(
        !d.port_file().exists(),
        "api.port must be removed on graceful shutdown"
    );
    assert!(
        d.token_file().exists(),
        "api-token must PERSIST across shutdown (not removed)"
    );
}

/// On Unix the `api-token` file is mode 0600 — the bearer token is a
/// process-control credential and must not be world/group readable.
#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn api_token_file_is_0600() {
    use std::os::unix::fs::PermissionsExt;
    let d = daemon().await;
    let meta = std::fs::metadata(d.token_file()).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "api-token must be 0600, got {mode:o}");
}

/// The API token is stable across a restart that reuses the same data dir:
/// a daemon brought back up reads the persisted token rather than minting a
/// new one, so previously-issued client credentials keep working.
#[tokio::test]
#[ignore]
async fn api_token_stable_across_restart_same_data_dir() {
    let name = unique_name("tokrestart");
    let _ident = IdentityGuard(identity_dir_for(&name));
    let dir = tempfile::TempDir::new().unwrap();

    let mut first = spawn_with_data_dir(&name, dir.path());
    let token1 = read_token(dir.path());
    // Graceful stop so the data dir is reused cleanly.
    let _ = reqwest::Client::new()
        .post(format!("http://{}/shutdown", first.addr))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token1}"))
        .send()
        .await;
    // The restart must be REAL: the first daemon has to be gone (its graceful
    // shutdown also removes api.port, so the second spawn can't read a stale
    // one). Fail loudly rather than silently testing a still-running daemon.
    let first_exited = wait_for_exit(&mut first.child, Duration::from_secs(30));
    if !first_exited {
        let _ = first.child.kill();
        let _ = first.child.wait();
        panic!("first daemon did not exit; restart not proven");
    }

    let mut second = spawn_with_data_dir(&name, dir.path());
    let token2 = read_token(dir.path());

    // Prove the persisted token actually authenticates the fresh daemon.
    let authed = reqwest::Client::new()
        .get(format!("http://{}/status", second.addr))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token1}"))
        .send()
        .await
        .map(|r| r.status());
    let _ = second.child.kill();
    let _ = second.child.wait();

    assert_eq!(token1, token2, "api-token must be stable across restart");
    assert_eq!(
        authed.ok(),
        Some(StatusCode::OK),
        "persisted token must authenticate the restarted daemon"
    );
}

// ===========================================================================
// Startup failure surfacing
// ===========================================================================

/// A startup bind failure (API port already in use) exits the process rather
/// than hanging or orphaning background tasks. Phase 2 will tighten this so
/// the failure surfaces as `Err` from `serve()`; today it must at least exit.
#[tokio::test]
#[ignore]
async fn bind_failure_exits_without_hanging() {
    // Occupy a loopback port for the duration of the test.
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = blocker.local_addr().unwrap().port();

    let name = unique_name("bindfail");
    let _ident = IdentityGuard(identity_dir_for(&name));
    let dir = tempfile::TempDir::new().unwrap();
    let mut child = spawn_with_api_addr(&name, dir.path(), &format!("127.0.0.1:{port}"));

    let exited = wait_for_exit(&mut child, Duration::from_secs(15));
    assert!(exited, "daemon must exit on bind failure, not hang");
    let status = child.try_wait().unwrap().unwrap();
    assert!(
        !status.success(),
        "bind failure must be a non-success exit, got {status:?}"
    );
    assert!(
        !dir.path().join("api.port").exists(),
        "no api.port should be written when bind fails"
    );
}

// ===========================================================================
// CLI-only flags must NOT start a server
// ===========================================================================

/// `--check` validates config and exits — it must never bind the API or
/// write `api.port`. This is the contract that keeps CLI-only flows in the
/// bin (not in `serve()`) after the extraction.
#[tokio::test]
#[ignore]
async fn check_flag_does_not_start_server() {
    let name = unique_name("checkflag");
    let _ident = IdentityGuard(identity_dir_for(&name));
    let dir = tempfile::TempDir::new().unwrap();
    let cfg = write_config(&name, dir.path(), "127.0.0.1:0");

    let mut child = Command::new(x0xd_bin())
        .arg("--config")
        .arg(&cfg)
        .arg("--check")
        .arg("--skip-update-check")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let exited = wait_for_exit(&mut child, Duration::from_secs(20));
    let _ = child.kill();
    assert!(exited, "--check must exit, not run a server");
    assert!(
        !dir.path().join("api.port").exists(),
        "--check must not bind the API / write api.port"
    );
}

/// `--version` prints and exits immediately without any server side effects.
#[tokio::test]
#[ignore]
async fn version_flag_does_not_start_server() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut child = Command::new(x0xd_bin())
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(dir.path())
        .spawn()
        .unwrap();
    let exited = wait_for_exit(&mut child, Duration::from_secs(10));
    let _ = child.kill();
    assert!(exited, "--version must exit immediately");
    assert!(!dir.path().join("api.port").exists());
}

// ===========================================================================
// Local spawn helpers (for tests that need a fixed data dir / api address)
// ===========================================================================

fn x0xd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_x0xd"))
}

fn unique_name(tag: &str) -> String {
    format!("char-{tag}-{}", rand::random::<u32>())
}

fn identity_dir_for(name: &str) -> PathBuf {
    dirs::home_dir()
        .expect("home dir")
        .join(format!(".x0x-{name}"))
}

/// Removes the per-instance identity dir (`~/.x0x-<name>`) on drop so custom
/// spawns don't leak key material into the developer's home directory.
struct IdentityGuard(PathBuf);
impl Drop for IdentityGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_config(name: &str, data_dir: &std::path::Path, api_address: &str) -> PathBuf {
    let cfg = data_dir.join("config.toml");
    let body = format!(
        "bind_address = \"0.0.0.0:0\"\napi_address = \"{api}\"\ndata_dir = \"{dir}\"\nlog_level = \"warn\"\nbootstrap_peers = []\ninstance_name = \"{name}\"\n",
        api = api_address,
        dir = data_dir.display(),
    );
    std::fs::write(&cfg, body).unwrap();
    cfg
}

struct Spawned {
    child: Child,
    addr: String,
}

fn spawn_with_api_addr(name: &str, data_dir: &std::path::Path, api_address: &str) -> Child {
    let cfg = write_config(name, data_dir, api_address);
    Command::new(x0xd_bin())
        .arg("--config")
        .arg(&cfg)
        .arg("--skip-update-check")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn spawn_with_data_dir(name: &str, data_dir: &std::path::Path) -> Spawned {
    let child = spawn_with_api_addr(name, data_dir, "127.0.0.1:0");
    let addr = wait_for_port(data_dir, Duration::from_secs(30));
    Spawned { child, addr }
}

fn wait_for_port(data_dir: &std::path::Path, timeout: Duration) -> String {
    let port_file = data_dir.join("api.port");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(s) = std::fs::read_to_string(&port_file) {
            let t = s.trim();
            if t.parse::<std::net::SocketAddr>().is_ok() {
                return t.to_string();
            }
            if let Ok(p) = t.parse::<u16>() {
                return format!("127.0.0.1:{p}");
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for api.port in {}", data_dir.display());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read_token(data_dir: &std::path::Path) -> String {
    let token_file = data_dir.join("api-token");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(s) = std::fs::read_to_string(&token_file) {
            let t = s.trim().to_string();
            if !t.is_empty() {
                return t;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for api-token in {}", data_dir.display());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        if std::time::Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
