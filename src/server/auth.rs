//! Authentication, CORS-origin predicates, and session-token store.
//!
//! Extracted from `server/mod.rs` (#125 / WS1.4) as the first decomposition
//! move. The decision logic lives in [`authorize`], a pure function that both
//! the real middleware and the unit tests call — there is no test-only shim
//! mirroring production control flow.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sha2::{Digest, Sha256};

use super::state::AppState;

// ── The pure authorization decision ──────────────────────────────────────

/// Pure authorization decision for the local control plane.
///
/// Both [`auth_middleware`] (production) and the auth-matrix unit tests call
/// this — there is no test-only mirror. Returning `Ok(())` means the request
/// may proceed; `Err(StatusCode::UNAUTHORIZED)` means reject.
///
/// Semantics (must stay byte-identical to the pre-extraction `auth_middleware`):
///
/// 1. `OPTIONS` (CORS preflight) → `Ok`
/// 2. [`is_auth_exempt_path`] (`/health`, `/constitution*`) → `Ok`
/// 3. Bearer header: durable token via [`ct_eq`] **or** session token via
///    [`SessionStore::is_valid`] → `Ok`
/// 4. [`accepts_query_token`] paths: **session** token in `?token=` only —
///    the durable token is **never** accepted in a query string (#127/WS1.6).
/// 5. otherwise → `Err(UNAUTHORIZED)`
pub(super) fn authorize(
    path: &str,
    method: &Method,
    header_token: Option<&str>,
    query_token: Option<&str>,
    api_token: &str,
    sessions: &SessionStore,
    now: Instant,
) -> Result<(), StatusCode> {
    // (1) CORS preflight: browsers send OPTIONS without auth headers.
    if method == Method::OPTIONS {
        return Ok(());
    }
    // (2) Exempt: health check + public constitution resources.
    if is_auth_exempt_path(path) {
        return Ok(());
    }
    // (3) Authorization: Bearer header (works everywhere).
    // Accepts either the durable API token OR a short-lived session token
    // (#127 / WS1.6) — browser clients use the session token after exchange.
    if let Some(token) = header_token {
        if ct_eq(token, api_token) || sessions.is_valid(token, now) {
            return Ok(());
        }
    }
    // (4) `?token=` query param, only on browser-only endpoints.
    // ONLY session tokens are valid here — the durable API token is never
    // accepted in a query string (#127 / WS1.6), eliminating the history /
    // Referer / HAR leak surface for the long-lived secret.
    if accepts_query_token(path) {
        if let Some(token) = query_token {
            if sessions.is_valid(token, now) {
                return Ok(());
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

// ── Middleware (thin extraction layer over `authorize`) ──────────────────

/// Extract the bearer token from an `Authorization: Bearer <token>` header.
fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|t| t.to_string())
}

/// Extract the first `?token=<value>` from a raw query string.
///
/// Mirrors the original split-on-`&` + strip-prefix behaviour: no URL
/// decoding is performed (the token is opaque hex/nonce bytes).
fn extract_query_token(query: Option<&str>) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        if let Some(token) = pair.strip_prefix("token=") {
            return Some(token.to_string());
        }
    }
    None
}

/// Bearer-token authentication middleware.
///
/// Thin wrapper around [`authorize`]: extracts the header/query tokens into
/// owned strings (no request borrows survive across `next.run(req).await`),
/// delegates the decision, and maps the result to either the next layer or a
/// 401 JSON error.
pub(super) async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let header_token = extract_bearer(req.headers());
    let query_token = extract_query_token(req.uri().query());
    let now = Instant::now();

    match authorize(
        &path,
        &method,
        header_token.as_deref(),
        query_token.as_deref(),
        &state.api_token,
        &state.sessions,
        now,
    ) {
        Ok(()) => next.run(req).await,
        Err(status) => (
            status,
            Json(serde_json::json!({
                "error": "missing or invalid Authorization: Bearer token"
            })),
        )
            .into_response(),
    }
}

/// `POST /auth/session` — exchange the durable API token for a short-lived
/// browser session token (#127 / WS1.6).
///
/// Requires the **durable** bearer token specifically — a session token
/// cannot mint or refresh another session (no privilege amplification). The
/// returned session token is the only kind accepted via `?token=` query
/// strings on browser endpoints (WS/SSE), keeping the durable secret out of
/// URLs entirely.
pub(super) async fn create_session(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    // auth_middleware already validated *some* bearer token (durable or
    // session). This handler additionally requires the durable token: a
    // session bearer cannot mint sessions.
    let is_durable = extract_bearer(req.headers()).is_some_and(|t| ct_eq(&t, &state.api_token));

    if !is_durable {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "durable API token required to mint a session"
            })),
        )
            .into_response();
    }

    let token = state.sessions.issue(Instant::now());
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "session_token": token,
            "expires_in": SESSION_TOKEN_TTL_SECS,
        })),
    )
        .into_response()
}

// ── Policy predicates ────────────────────────────────────────────────────

fn is_auth_exempt_path(path: &str) -> bool {
    path == "/health" || path.starts_with("/constitution")
}

fn accepts_query_token(path: &str) -> bool {
    matches!(
        path,
        "/gui"
            | "/gui/"
            | "/ws"
            | "/ws/direct"
            | "/events"
            | "/direct/events"
            | "/peers/events"
            | "/presence/events"
    )
}

// ── CORS-origin predicates ───────────────────────────────────────────────

pub(super) fn is_allowed_loopback_origin(origin: &HeaderValue) -> bool {
    origin
        .to_str()
        .ok()
        .is_some_and(is_allowed_loopback_origin_str)
}

fn is_allowed_loopback_origin_str(origin: &str) -> bool {
    let Some(authority) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };
    if authority.is_empty() || authority.contains('/') || authority.contains('@') {
        return false;
    }

    let Some(host) = origin_host_without_port(authority) else {
        return false;
    };
    // Literal loopback IPs only. The `localhost` hostname is intentionally rejected:
    // its resolution can be redirected (/etc/hosts, split-horizon DNS, OSes that map it
    // off-loopback), so it is not a trustworthy origin for the local control plane.
    matches!(host, "127.0.0.1" | "::1")
}

fn origin_host_without_port(authority: &str) -> Option<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once(']')?;
        if port.is_empty() || valid_origin_port(port.strip_prefix(':')?) {
            Some(host)
        } else {
            None
        }
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            Some(_) => return None,
            None => (authority, None),
        };
        if port.is_none_or(valid_origin_port) {
            Some(host)
        } else {
            None
        }
    }
}

fn valid_origin_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

// ── Constant-time comparison ─────────────────────────────────────────────

/// Constant-time comparison of two secret token strings.
///
/// Both sides are SHA-256 hashed first so the comparison is over fixed-length
/// 32-byte digests — this avoids any length-timing argument and keeps the
/// comparison constant-time regardless of the input lengths. Used on every
/// bearer-token and session-token validation path (#127 / WS1.6).
fn ct_eq(a: &str, b: &str) -> bool {
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    use subtle::ConstantTimeEq;
    ha.ct_eq(&hb).into()
}

// ── Session-token store ──────────────────────────────────────────────────

/// Lifetime of a browser session token issued by `POST /auth/session`.
pub(super) const SESSION_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
/// Same value in seconds, surfaced in the `expires_in` JSON field.
const SESSION_TOKEN_TTL_SECS: u64 = 10 * 60;

/// A single issued browser session token, stored as a SHA-256 digest.
///
/// Only the digest is retained so a memory dump cannot recover live tokens;
/// validation hashes the candidate and scans with [`subtle::ConstantTimeEq`].
struct AuthSession {
    token_hash: [u8; 32],
    expires_at: Instant,
}

/// In-memory store of short-lived browser session tokens (#127 / WS1.6).
///
/// Session tokens are the *only* tokens accepted via `?token=` query strings
/// on browser endpoints (WS/SSE); the durable API token is never valid in a
/// query string. The store uses a `std::sync::Mutex` because the critical
/// sections are trivial (hash + linear scan + prune) and never cross an await.
pub(super) struct SessionStore {
    sessions: StdMutex<Vec<AuthSession>>,
    ttl: Duration,
}

impl SessionStore {
    pub(super) fn new(ttl: Duration) -> Self {
        Self {
            sessions: StdMutex::new(Vec::new()),
            ttl,
        }
    }

    /// Issue a fresh session token, store its digest, and return the raw token
    /// to hand to the client. `now` is injected so expiry can be unit-tested
    /// without sleeping.
    fn issue(&self, now: Instant) -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let session = AuthSession {
            token_hash: Sha256::digest(token.as_bytes()).into(),
            expires_at: now + self.ttl,
        };
        if let Ok(mut guard) = self.sessions.lock() {
            guard.push(session);
            // Bound the store: lazy-prune expired entries on every issue so a
            // flood of session mints cannot grow the vector without bound.
            guard.retain(|s| s.expires_at > now);
        }
        token
    }

    /// Validate a candidate token: constant-time compare against every active
    /// session digest, pruning expired entries along the way. Returns `true`
    /// only if an unexpired entry matches.
    fn is_valid(&self, token: &str, now: Instant) -> bool {
        use subtle::ConstantTimeEq;
        let candidate = Sha256::digest(token.as_bytes());
        let Ok(mut guard) = self.sessions.lock() else {
            return false;
        };
        // Prune expired first (fail-closed: an expired token is never valid).
        guard.retain(|s| s.expires_at > now);
        guard.iter().any(|s| candidate.ct_eq(&s.token_hash).into())
    }
}

// ── Token load/generate ──────────────────────────────────────────────────

/// Load or generate an API bearer token.
///
/// Reads from `<data_dir>/api-token`. If the file does not exist, generates a
/// random 32-byte hex token and writes it with 0600 permissions.
pub(super) async fn load_or_generate_api_token(
    data_dir: &std::path::Path,
) -> anyhow::Result<String> {
    let token_path = data_dir.join("api-token");

    // Try to load existing token
    if token_path.exists() {
        let token = tokio::fs::read_to_string(&token_path)
            .await
            .context("failed to read api-token")?
            .trim()
            .to_string();
        if token.len() >= 32 {
            tracing::info!("API token loaded from {}", token_path.display());
            return Ok(token);
        }
    }

    // Generate new token
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);

    tokio::fs::write(&token_path, &token)
        .await
        .context("failed to write api-token")?;

    // Set permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&token_path, perms)
            .await
            .context("failed to set api-token permissions")?;
    }

    tracing::info!("API token generated at {}", token_path.display());
    Ok(token)
}

use anyhow::Context as _;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, Method, StatusCode};

    // ========================================================================
    // #125 / WS1.4 — auth-matrix tests.
    //
    // These tests call the REAL `authorize()` pure function directly — no
    // test-only shim, no in-process router, no daemon. The durable-in-query→401
    // property (and the entire matrix) is guaranteed by the same code that
    // runs in production.
    // ========================================================================

    /// Durable API token the tests treat as valid. Mirrors `state.api_token`.
    const TEST_API_TOKEN: &str = "x0x-test-auth-matrix-token";

    /// HTTP method each protected route is registered under in production, so
    /// the accept tests exercise the same method the real router would see.
    fn matrix_method(path: &str) -> Method {
        if path == "/agent/sign" || path == "/agent/verify" {
            Method::POST
        } else {
            Method::GET
        }
    }

    /// Helper: run `authorize` for a protected path and return the result.
    fn authorize_protected(
        path: &str,
        header_token: Option<&str>,
        query_token: Option<&str>,
        sessions: &SessionStore,
    ) -> Result<(), StatusCode> {
        authorize(
            path,
            &matrix_method(path),
            header_token,
            query_token,
            TEST_API_TOKEN,
            sessions,
            Instant::now(),
        )
    }

    // -- Protected endpoints: representative sample + /agent/sign + /agent/verify.

    #[test]
    fn auth_matrix_protected_endpoints_reject_without_token() {
        let sessions = SessionStore::new(SESSION_TOKEN_TTL);
        for path in ["/status", "/agent", "/agent/sign", "/agent/verify"] {
            assert_eq!(
                authorize_protected(path, None, None, &sessions),
                Err(StatusCode::UNAUTHORIZED),
                "{path} without a token must be 401"
            );
        }
    }

    #[test]
    fn auth_matrix_protected_endpoints_reject_wrong_token() {
        let sessions = SessionStore::new(SESSION_TOKEN_TTL);
        for path in ["/status", "/agent", "/agent/sign", "/agent/verify"] {
            assert_eq!(
                authorize_protected(path, Some("not-the-real-token"), None, &sessions),
                Err(StatusCode::UNAUTHORIZED),
                "{path} with a wrong bearer must be 401"
            );
        }
    }

    #[test]
    fn auth_matrix_protected_endpoints_accept_correct_token() {
        let sessions = SessionStore::new(SESSION_TOKEN_TTL);
        for path in ["/status", "/agent", "/agent/sign", "/agent/verify"] {
            assert!(
                authorize_protected(path, Some(TEST_API_TOKEN), None, &sessions).is_ok(),
                "{path} with the correct bearer must pass (Ok)"
            );
        }
    }

    #[test]
    fn auth_matrix_protected_endpoints_accept_session_bearer() {
        // #127 / WS1.6: a short-lived session token in the Bearer header is
        // accepted on protected endpoints too (browser clients use it after
        // exchange, so REST calls work without the durable secret).
        let sessions = SessionStore::new(SESSION_TOKEN_TTL);
        let now = Instant::now();
        let session = sessions.issue(now);
        for path in ["/status", "/agent", "/agent/sign", "/agent/verify"] {
            assert!(
                authorize_protected(path, Some(&session), None, &sessions).is_ok(),
                "{path} with a session bearer must pass (Ok)"
            );
        }
    }

    // -- Auth-exempt public paths: served without any token.

    #[test]
    fn auth_matrix_exempt_paths_serve_without_token() {
        let sessions = SessionStore::new(SESSION_TOKEN_TTL);
        for path in ["/health", "/constitution", "/constitution/json"] {
            assert!(
                authorize(
                    path,
                    &Method::GET,
                    None,
                    None,
                    TEST_API_TOKEN,
                    &sessions,
                    Instant::now()
                )
                .is_ok(),
                "{path} is auth-exempt and must pass without a token"
            );
        }
    }

    // -- Browser-only endpoints: session `?token=` accepted, durable rejected.

    #[test]
    fn auth_matrix_browser_endpoints_accept_query_token() {
        // #127 / WS1.6: only a short-lived SESSION token is accepted via
        // ?token= on browser endpoints (WS/SSE/GUI). The durable token must
        // never appear in a URL.
        let sessions = SessionStore::new(SESSION_TOKEN_TTL);
        let now = Instant::now();
        let session = sessions.issue(now);
        for path in [
            "/gui",
            "/gui/",
            "/ws",
            "/ws/direct",
            "/events",
            "/direct/events",
            "/peers/events",
            "/presence/events",
        ] {
            assert!(
                authorize(
                    path,
                    &Method::GET,
                    None,
                    Some(&session),
                    TEST_API_TOKEN,
                    &sessions,
                    now
                )
                .is_ok(),
                "{path}?token=<session> is a browser endpoint and must accept the session token"
            );
        }
    }

    #[test]
    fn auth_matrix_browser_endpoints_reject_durable_query_token() {
        // #127 / WS1.6 — the headline security property: the durable API
        // token in a query string is REJECTED, even on browser endpoints that
        // accept ?token=. Only session tokens are valid in URLs. This is what
        // keeps the long-lived secret out of history/Referer/HAR.
        let sessions = SessionStore::new(SESSION_TOKEN_TTL);
        let now = Instant::now();
        for path in ["/gui", "/ws", "/ws/direct", "/events", "/peers/events"] {
            assert_eq!(
                authorize(
                    path,
                    &Method::GET,
                    None,
                    Some(TEST_API_TOKEN),
                    TEST_API_TOKEN,
                    &sessions,
                    now
                ),
                Err(StatusCode::UNAUTHORIZED),
                "{path}?token=<durable> must be 401 — durable tokens are never valid in a query string"
            );
        }
    }

    #[test]
    fn auth_matrix_query_token_rejected_on_protected_paths() {
        // A query token must NOT authenticate non-browser endpoints — that
        // would leak the credential via history/Referer/HAR.
        let sessions = SessionStore::new(SESSION_TOKEN_TTL);
        let now = Instant::now();
        for path in ["/status", "/agent/sign", "/agent/verify"] {
            assert_eq!(
                authorize(
                    path,
                    &matrix_method(path),
                    None,
                    Some(TEST_API_TOKEN),
                    TEST_API_TOKEN,
                    &sessions,
                    now
                ),
                Err(StatusCode::UNAUTHORIZED),
                "{path}?token= must reject (not a browser endpoint)"
            );
        }
    }

    // -- CORS preflight exemption: OPTIONS bypasses auth.

    #[test]
    fn auth_matrix_options_preflight_bypasses_auth() {
        // Browsers cannot attach auth headers to a CORS preflight; the
        // middleware must pass OPTIONS through even on a protected path.
        let sessions = SessionStore::new(SESSION_TOKEN_TTL);
        assert!(
            authorize(
                "/status",
                &Method::OPTIONS,
                None,
                None,
                TEST_API_TOKEN,
                &sessions,
                Instant::now()
            )
            .is_ok(),
            "OPTIONS preflight must bypass bearer auth"
        );
    }

    // -- CORS-origin predicate tests (was router-based; now pure-predicate).
    //
    // The CorsLayer in `serve()` is wired with `is_allowed_loopback_origin`.
    // These tests pin the predicate directly — the layer just echoes whatever
    // the predicate decides.

    #[test]
    fn cors_origin_allows_only_literal_loopback_ips() {
        for origin in [
            "http://127.0.0.1",
            "http://127.0.0.1:12700",
            "http://[::1]",
            "http://[::1]:12700",
        ] {
            assert!(
                is_allowed_loopback_origin_str(origin),
                "expected literal loopback IP origin to be allowed: {origin}"
            );
        }

        for origin in [
            // `localhost` hostname is rejected — resolution can be redirected.
            "http://localhost",
            "http://localhost:12700",
            "https://localhost",
            // spoofed / non-loopback
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "http://[::1].evil.example",
            "http://evil.localhost",
            "http://localhost@evil.example",
            "http://localhost:bad",
            "ftp://localhost",
            "null",
        ] {
            assert!(
                !is_allowed_loopback_origin_str(origin),
                "expected non-IP-loopback origin to be rejected: {origin}"
            );
        }
    }

    #[test]
    fn cors_origin_allows_loopback_header_values() {
        // The HeaderValue entry point (used by the CorsLayer predicate).
        for origin in [
            "http://127.0.0.1",
            "http://127.0.0.1:12700",
            "http://[::1]",
            "http://[::1]:12700",
        ] {
            let hv = HeaderValue::from_str(origin).expect("valid header value");
            assert!(
                is_allowed_loopback_origin(&hv),
                "CORS predicate must allow literal loopback origin: {origin}"
            );
        }
    }

    #[test]
    fn cors_origin_rejects_localhost_header_value() {
        let hv = HeaderValue::from_str("http://localhost:12700").expect("valid header value");
        assert!(
            !is_allowed_loopback_origin(&hv),
            "CORS predicate must reject localhost origin"
        );
    }

    // -- Auth-exempt / query-token path predicates.

    #[test]
    fn gui_requires_auth_but_accepts_query_token_bootstrap() {
        assert!(!is_auth_exempt_path("/gui"));
        assert!(!is_auth_exempt_path("/gui/"));
        assert!(accepts_query_token("/gui"));
        assert!(accepts_query_token("/gui/"));
        assert!(accepts_query_token("/peers/events"));
        assert!(accepts_query_token("/presence/events"));
    }

    // ========================================================================
    // #127 / WS1.6 — SessionStore + constant-time-compare unit tests.
    //
    // The session store is pure over an injected `Instant` (no sleeps, no
    // daemon), so expiry and pruning are fully deterministic.
    // ========================================================================

    #[test]
    fn session_store_issues_and_validates_a_token() {
        let store = SessionStore::new(SESSION_TOKEN_TTL);
        let now = Instant::now();
        let token = store.issue(now);
        assert!(token.len() >= 32, "session token must be opaque hex");
        assert!(
            store.is_valid(&token, now),
            "a freshly-issued token must validate"
        );
        assert!(
            !store.is_valid("not-a-real-token", now),
            "a wrong token must not validate",
        );
    }

    #[test]
    fn session_store_token_expires_after_ttl() {
        let store = SessionStore::new(SESSION_TOKEN_TTL);
        let t0 = Instant::now();
        let token = store.issue(t0);
        assert!(store.is_valid(&token, t0));
        // One nanosecond before expiry: still valid.
        let just_before = t0 + SESSION_TOKEN_TTL - Duration::from_nanos(1);
        assert!(
            store.is_valid(&token, just_before),
            "token must be valid right up to the TTL boundary",
        );
        // One nanosecond after expiry: invalid (fail-closed).
        let just_after = t0 + SESSION_TOKEN_TTL + Duration::from_nanos(1);
        assert!(
            !store.is_valid(&token, just_after),
            "token must be invalid past the TTL",
        );
    }

    #[test]
    fn session_store_prunes_expired_entries_on_validate() {
        // Pruning is lazy (on issue/validate) so the Vec cannot grow without
        // bound even if clients never explicitly revoke.
        let store = SessionStore::new(SESSION_TOKEN_TTL);
        let t0 = Instant::now();
        let dead = store.issue(t0); // expires at t0 + TTL
        let alive = store.issue(t0); // same expiry, but we validate after pruning
                                     // Advance well past TTL: both should be pruned.
        let far_future = t0 + SESSION_TOKEN_TTL * 10;
        assert!(!store.is_valid(&dead, far_future));
        assert!(!store.is_valid(&alive, far_future));
        // A new token issued at far_future must still work.
        let fresh = store.issue(far_future);
        assert!(store.is_valid(&fresh, far_future));
    }

    #[test]
    fn ct_eq_is_constant_time_and_correct() {
        // Correctness: equal strings compare equal, different do not.
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        // Different lengths never panic and compare unequal.
        assert!(!ct_eq("abc", "ab"));
        assert!(!ct_eq("", "abc"));
        // Empty vs empty is equal.
        assert!(ct_eq("", ""));
    }

    // -- Token extraction helpers (middleware plumbing).

    #[test]
    fn extract_bearer_strips_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer my-secret"),
        );
        assert_eq!(extract_bearer(&headers).as_deref(), Some("my-secret"));
    }

    #[test]
    fn extract_bearer_returns_none_without_header() {
        let headers = HeaderMap::new();
        assert!(extract_bearer(&headers).is_none());
    }

    #[test]
    fn extract_query_token_finds_first() {
        assert_eq!(
            extract_query_token(Some("foo=bar&token=abc&baz=qux")).as_deref(),
            Some("abc")
        );
        assert_eq!(
            extract_query_token(Some("token=first&token=second")).as_deref(),
            Some("first")
        );
        assert!(extract_query_token(Some("no_token_here")).is_none());
        assert!(extract_query_token(None).is_none());
    }
}
