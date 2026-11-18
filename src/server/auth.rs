//! Authentication, CORS-origin predicates, and session-token store.
//!
//! Extracted from `server/mod.rs` (#125 / WS1.4) as the first decomposition
//! move. The decision logic lives in [`authorize`], a pure function that both
//! the real middleware and the unit tests call — there is no test-only shim
//! mirroring production control flow.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, SystemTime};

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
/// 5. `POST /auth/session/refresh` and `POST /auth/session/revoke` only: a
///    bearer **session** token that lapsed, while its session is inside the
///    idle timeout → `Ok`
/// 6. otherwise → `Err(UNAUTHORIZED)`
pub(super) fn authorize(
    path: &str,
    method: &Method,
    header_token: Option<&str>,
    query_token: Option<&str>,
    api_token: &str,
    sessions: &SessionStore,
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
        if ct_eq(token, api_token) || sessions.is_valid(token) {
            return Ok(());
        }
    }
    // (4) `?token=` query param, only on browser-only endpoints.
    // ONLY session tokens are valid here — the durable API token is never
    // accepted in a query string (#127 / WS1.6), eliminating the history /
    // Referer / HAR leak surface for the long-lived secret.
    if accepts_query_token(path) {
        if let Some(token) = query_token {
            if sessions.is_valid(token) {
                return Ok(());
            }
        }
    }
    // (5) A lapsed session token reaches refresh and revoke and nothing else.
    // Revoke also takes a token a refresh just replaced, so a sign-out that
    // lost the race to a refresh still ends the session.
    if method == Method::POST {
        if let Some(token) = header_token {
            if path == SESSION_REFRESH_PATH && sessions.is_refreshable(token) {
                return Ok(());
            }
            if path == SESSION_REVOKE_PATH && sessions.is_revocable(token) {
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

/// Issue #1094 defence in depth for the rider scratch rows: when an
/// admitted path addresses a `/stores/:id/*` topic whose store is OPEN,
/// that store must be group-bound (sealed or group-signed). A personal
/// store created at a scratch-shaped topic never admits a rider. An
/// unopened topic passes — the handler answers its ordinary 404. The
/// non-`/stores` scratch row (`POST /groups/:id/stores`) also passes:
/// its handler re-runs the admission on the resolved group binding.
async fn scratch_store_group_bound(state: &AppState, path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/stores/") else {
        return true;
    };
    let Some(id_enc) = rest.split('/').next() else {
        return false;
    };
    let Some(store_id) = super::rider_auth::percent_decode_segment(id_enc) else {
        return false;
    };
    let handle = { state.kv_stores.read().await.get(&store_id).cloned() };
    match handle {
        Some(handle) => handle.is_encrypted().await || handle.is_group_signed().await,
        None => true,
    }
}

/// Bearer-token authentication middleware.
///
/// Thin wrapper around [`authorize`]: extracts the header/query tokens into
/// owned strings (no request borrows survive across `next.run(req).await`),
/// delegates the decision, and maps the result to either the next layer or a
/// 401 JSON error.
///
/// # ADR-0039 actor resolution
///
/// After the owner-token checks fail, the presented **bearer** token is
/// matched against the rider-token store (blocker 21/22). A live rider
/// token becomes [`ActorContext::Rider`] — but only on the
/// deny-by-default rider route set; every other route answers `403`
/// before any handler runs. Riders are bearer-only: a rider token in a
/// `?token=` query string is rejected exactly like any other non-session
/// query token. Unknown/expired/revoked tokens stay `401`.
///
/// The resolved [`ActorContext`] is inserted into the request extensions
/// so rider-aware handlers (`/groups/:id/send`,
/// `/groups/:id/secure/encrypt`, `GET /history`) can consult it; every
/// other handler ignores it and keeps deriving identity from
/// `state.agent` as before.
pub(super) async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let header_token = extract_bearer(req.headers());
    let query_token = extract_query_token(req.uri().query());

    // Review fix #4: distinguish the DURABLE token (full authority,
    // including owner-admin acts) from a short-lived browser session
    // bearer (read-only principal). The durable check re-uses the same
    // constant-time comparison as `authorize`.
    let durable = header_token
        .as_deref()
        .is_some_and(|token| ct_eq(token, &state.api_token));

    let owner_ok = authorize(
        &path,
        &method,
        header_token.as_deref(),
        query_token.as_deref(),
        &state.api_token,
        &state.sessions,
    )
    .is_ok();

    if owner_ok {
        // Issue #446 (review round 2): owner-act surfaces require the
        // DURABLE token at the route layer — BEFORE extractors, so a
        // session bearer gets the typed 403 whatever the body looks
        // like. Handler-side gates remain as defense-in-depth.
        if requires_durable_owner(&method, &path) && !durable {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": format!(
                        "{path} requires the durable API token (not a session token)"
                    )
                })),
            )
                .into_response();
        }
        let mut req = req;
        req.extensions_mut()
            .insert(super::rider_auth::ActorContext::Owner { durable });
        return next.run(req).await;
    }

    // Rider fallback: bearer header only, never a query string.
    if let Some(token) = header_token.as_deref() {
        let now_unix = super::rider_auth::unix_now_secs();
        let rider = {
            let store = state.rider_tokens.lock().await;
            store.validate(token, now_unix)
        };
        if let Some(rider) = rider {
            // Review fix #2: the sub-agent's ADR-0018 revocation is
            // checked on EVERY request, not only at token revocation
            // time — a rider token cannot survive revocation of its
            // agent even if the token-sweep write failed.
            let agent_revoked = state.agent.revocation_records().await.iter().any(|record| {
                record.subject_kind() == "agent" && record.subject_hex() == rider.sub_agent_id
            });
            if agent_revoked {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "rider token rejected: sub-agent is revoked"
                    })),
                )
                    .into_response();
            }
            let allowed = super::rider_auth::rider_route_allowed(&method, &path, &rider.scopes)
                || (super::rider_auth::rider_scratch_route_allowed(
                    &method,
                    &path,
                    &rider.scopes,
                    &rider.groups,
                ) && scratch_store_group_bound(&state, &path).await);
            if !allowed {
                if method == axum::http::Method::POST && path == "/gui/show" {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(super::rider_auth::missing_gui_show_scope_body()),
                    )
                        .into_response();
                }
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "rider tokens are denied on this route (ADR-0039 deny-by-default)"
                    })),
                )
                    .into_response();
            }
            let actor = super::rider_auth::ActorContext::Rider {
                sub_agent_id: rider.sub_agent_id,
                token_id: rider.token_id,
                token_hash: rider.token_hash,
                groups: rider.groups,
                scopes: rider.scopes,
            };
            let mut req = req;
            req.extensions_mut().insert(actor);
            return next.run(req).await;
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "error": "missing or invalid Authorization: Bearer token"
        })),
    )
        .into_response()
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

    let token = state.sessions.issue();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "session_token": token,
            "expires_in": SESSION_TOKEN_TTL_SECS,
            "idle_timeout_secs": state.sessions.idle_timeout().as_secs(),
        })),
    )
        .into_response()
}

/// Optional body of `POST /auth/session/refresh`.
#[derive(Debug, Default, serde::Deserialize)]
struct SessionRefreshRequest {
    /// Milliseconds since the last user input in the client. Absent means
    /// a background refresh, which does not extend the session.
    #[serde(default)]
    idle_ms: Option<u64>,
}

/// Largest refresh body read; the only field is one integer.
const SESSION_REFRESH_BODY_LIMIT: usize = 1024;

/// `POST /auth/session/refresh` — swap a browser session token for a fresh
/// one (#893).
///
/// Accepts **only** a session bearer that is live, or lapsed while its
/// session is inside the idle timeout. The durable token is refused (it
/// keeps using `POST /auth/session`), and rider tokens never reach this
/// handler (ADR-0039 deny-by-default route set). The new token is an
/// ordinary session token, with the same authority as the one it replaces.
/// The body may carry `idle_ms`, the time since the last user input; only
/// that moves the session's last activity. A session with no activity for
/// the idle timeout is refused, and the user re-opens the GUI with
/// `x0x gui`. The presented token is revoked in the same critical section
/// (no overlap window).
pub(super) async fn refresh_session(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let Some(bearer) = extract_bearer(req.headers()) else {
        return session_refresh_refused(StatusCode::UNAUTHORIZED, "session bearer token required");
    };
    if ct_eq(&bearer, &state.api_token) {
        return session_refresh_refused(
            StatusCode::FORBIDDEN,
            "session refresh requires a session token; mint one with POST /auth/session",
        );
    }
    let Ok(body) = axum::body::to_bytes(req.into_body(), SESSION_REFRESH_BODY_LIMIT).await else {
        return session_refresh_refused(StatusCode::BAD_REQUEST, "refresh body is too large");
    };
    let request = if body.iter().all(u8::is_ascii_whitespace) {
        SessionRefreshRequest::default()
    } else {
        match serde_json::from_slice::<SessionRefreshRequest>(&body) {
            Ok(request) => request,
            Err(_) => {
                return session_refresh_refused(
                    StatusCode::BAD_REQUEST,
                    "refresh body must be JSON like {\"idle_ms\": 1200}",
                )
            }
        }
    };
    let idle = request.idle_ms.map(Duration::from_millis);
    match state.sessions.refresh(&bearer, idle) {
        Ok(token) => {
            // The GUI may refresh before the socket reconnects. The pending
            // banner and any hidden socket still holding this token must
            // follow the new token, or the view opens with no origin banner.
            state.gui_show.rebind_pending_session(&bearer, &token);
            super::ws::rebind_gui_ws_tokens(&state, &bearer, &token).await;
            // A hidden tab refreshes during bootstrap. Visibility comes from
            // a live GUI socket, not from this refresh.
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "session_token": token,
                    "expires_in": SESSION_TOKEN_TTL_SECS,
                    "idle_timeout_secs": state.sessions.idle_timeout().as_secs(),
                })),
            )
                .into_response()
        }
        Err(SessionRefreshError::Unknown) => session_refresh_refused(
            StatusCode::UNAUTHORIZED,
            "session token is invalid or expired; reopen with `x0x gui`",
        ),
        Err(SessionRefreshError::IdleTimeout) => session_refresh_refused(
            StatusCode::UNAUTHORIZED,
            "session ended after inactivity; reopen with `x0x gui`",
        ),
    }
}

/// `POST /auth/session/revoke` — end the caller's own browser session.
///
/// Ends the whole session the bearer belongs to, every token of its
/// lineage. Accepts a session bearer that refresh would accept (live, or
/// lapsed inside the idle timeout) or one a refresh just replaced; the
/// durable token is refused, since it is not a session. Open WebSocket and
/// SSE streams of the session are not closed: they were authenticated at
/// connect. The token stops working at once, and a pending GUI
/// show bound to it is dropped. No other session is touched.
pub(super) async fn revoke_session(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let Some(bearer) = extract_bearer(req.headers()) else {
        return session_refresh_refused(StatusCode::UNAUTHORIZED, "session bearer token required");
    };
    if ct_eq(&bearer, &state.api_token) {
        return session_refresh_refused(
            StatusCode::FORBIDDEN,
            "session revoke requires a session token; the durable token is not a session",
        );
    }
    let revoked = state.sessions.revoke(&bearer);
    if revoked {
        state.gui_show.drop_pending_for_session(&bearer);
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "revoked": revoked })),
    )
        .into_response()
}

fn session_refresh_refused(status: StatusCode, error: &str) -> Response {
    (status, Json(serde_json::json!({ "error": error }))).into_response()
}

// ── Policy predicates ────────────────────────────────────────────────────

/// Does the request carry a valid owner bearer — the durable API token or
/// a live session token in the `Authorization` header?
///
/// This is exactly the token check [`authorize`] step (3) applies to
/// authenticated routes. The `/health` detail gate (David's ruling of
/// 20 Oct 2026 on the #1480 M2 question) reuses it, so "an authenticated
/// caller" means the same thing on both surfaces and the two checks
/// cannot drift. Rider tokens do not authenticate here: they are a
/// scoped, deny-by-default principal, not the local owner.
pub(in crate::server) fn has_valid_owner_bearer(
    headers: &axum::http::HeaderMap,
    api_token: &str,
    sessions: &SessionStore,
) -> bool {
    extract_bearer(headers)
        .is_some_and(|token| ct_eq(&token, api_token) || sessions.is_valid(&token))
}

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

/// Issue #446 (review round 2): the COMPLETE route table of owner-act
/// surfaces that require the DURABLE API token at the ROUTE layer —
/// enforced by [`auth_middleware`] BEFORE any extractor or handler
/// runs, so a session bearer gets the typed `403` regardless of body
/// validity (a malformed JSON body cannot leak an extraction error in
/// front of the authorization decision). Handler-side
/// `is_durable_owner()` gates remain as defense-in-depth and for
/// direct-handler wiring.
///
/// `POST /announce` is deliberately absent: its gate is body-conditional
/// (`include_user_identity`) and stays in the handler. `POST
/// /direct/send` and WS `SendDirect` carry arbitrary DM payloads; their
/// exec-prefix egress check is likewise payload-conditional and lives
/// in the handlers.
pub(super) fn requires_durable_owner(method: &Method, path: &str) -> bool {
    // ADR-0070 §3: every ACL management surface — reads included — is
    // owner/durable-token only; session bearers and riders are refused.
    if is_acl_admin_path(path) {
        return true;
    }
    // ADR-0070 §2: share grants decide who reaches the owner's agents;
    // every method is owner/durable-token only.
    if is_grants_path(path) {
        return true;
    }
    // ADR-0074 §1: owner petnames are editable only by the local owner, and
    // resolving pins a name; every names route is durable-token only.
    if is_names_path(path) {
        return true;
    }
    // #1228: legacy MLS control is an owner act on every method. The
    // quarantine clear is an owner act too. #1347: the join-request list,
    // approve and reject are NOT in this table. Their class depends on the
    // group (the Home fence), so the handlers decide it, not this layer.
    if is_legacy_mls_group_path(path) {
        return true;
    }
    match *method {
        Method::POST => {
            matches!(
                path,
                "/agent/sign"
                    | "/exec/run"
                    | "/exec/cancel"
                    | "/shutdown"
                    | "/sync/devices/enroll"
                    | "/home/rename"
                    | "/home/seat"
                    | "/upgrade/apply"
                    // #1376 / D190: the local hold clear re-admits a held
                    // release, an owner act like the apply itself.
                    | "/upgrade/clear-hold"
                    // #1228: opening an envelope exposes a raw group secret.
                    | "/groups/secure/open-envelope"
                    // ADR 0116 §4: the runtime history trim.
                    | "/history/retain"
                    // ADR-0074 §1: named forwards resolve (and pin) a name.
                    | "/forwards"
                    // #1392: David approved 22 Oct 2026 13:30 BST. An owner
                    // token must be the durable API token. A GUI session
                    // bearer is refused here. A rider is not an owner
                    // token; `gui:show` admission is the rider scope check.
                    | "/gui/show"
            ) || is_two_segment_action(path, "delegate")
                || is_group_quarantine_clear(path)
        }
        // DELETE /forwards/:local_addr removes the owner's persisted
        // forward. Session and rider tokens must not reach it. GET
        // /forwards stays readable.
        Method::DELETE => is_sync_device_path(path) || is_forward_addr_path(path),
        // ADR 0116 §3: the local history policy, with its counters and the
        // fork-quarantine pins, is an owner-only read.
        Method::GET => path == "/history/policy",
        _ => false,
    }
}

/// `true` for the ADR-0070 §3 ACL routes: `/acl/reload`, `/acl/connect`,
/// `/acl/exec`, and `/acl/{connect,exec}/<nonempty-id>`.
fn is_acl_admin_path(path: &str) -> bool {
    if path == "/acl/reload" {
        return true;
    }
    ["/acl/connect", "/acl/exec"].iter().any(|base| {
        path == *base
            || path
                .strip_prefix(base)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|id| !id.is_empty() && !id.contains('/'))
    })
}

/// `true` for the ADR-0070 §2 grant routes: `/grants` and
/// `/grants/<nonempty-segment>` (including `/grants/received`).
fn is_grants_path(path: &str) -> bool {
    path == "/grants"
        // #1094 D1/D2: reading or writing a store through this install's
        // received grants.
        || path.starts_with("/grants/data/")
        || path
            .strip_prefix("/grants/")
            .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// `true` for the ADR-0074 §1 name routes: `/names`, `/names/resolve`,
/// `/names/owners`, `/names/machines`, `/names/accept`, and
/// `/names/{owners,pins,suggestions}/<segment>`.
fn is_names_path(path: &str) -> bool {
    if matches!(
        path,
        "/names" | "/names/resolve" | "/names/owners" | "/names/machines" | "/names/accept"
    ) {
        return true;
    }
    ["/names/owners/", "/names/pins/", "/names/suggestions/"]
        .iter()
        .any(|base| {
            path.strip_prefix(base)
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
        })
}

/// `true` for exactly `/groups/<nonempty-id>/quarantine/clear`.
fn is_group_quarantine_clear(path: &str) -> bool {
    match path.strip_prefix("/groups/") {
        Some(rest) => {
            let mut segs = rest.split('/');
            segs.next().is_some_and(|id| !id.is_empty())
                && segs.next() == Some("quarantine")
                && segs.next() == Some("clear")
                && segs.next().is_none()
        }
        None => false,
    }
}

/// `true` for `/mls/groups` and every path under it.
fn is_legacy_mls_group_path(path: &str) -> bool {
    path == "/mls/groups" || path.starts_with("/mls/groups/")
}

/// `true` for exactly `/groups/<nonempty-id>/delegate`.
fn is_two_segment_action(path: &str, action: &str) -> bool {
    match path.strip_prefix("/groups/") {
        Some(rest) => {
            let mut segs = rest.split('/');
            segs.next().is_some_and(|id| !id.is_empty())
                && segs.next() == Some(action)
                && segs.next().is_none()
        }
        None => false,
    }
}

/// `true` for exactly `/forwards/<nonempty-local-addr>` (one path segment).
fn is_forward_addr_path(path: &str) -> bool {
    match path.strip_prefix("/forwards/") {
        Some(addr) => !addr.is_empty() && !addr.contains('/'),
        None => false,
    }
}

/// `true` for exactly `/sync/devices/<nonempty-machine-id>`.
fn is_sync_device_path(path: &str) -> bool {
    match path.strip_prefix("/sync/devices/") {
        Some(id) => !id.is_empty() && !id.contains('/'),
        None => false,
    }
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
pub(crate) const SESSION_TOKEN_TTL: Duration = Duration::from_secs(10 * 60);
/// Same value in seconds, surfaced in the `expires_in` JSON field.
const SESSION_TOKEN_TTL_SECS: u64 = 10 * 60;
/// Default idle timeout of a browser session, in minutes.
pub const DEFAULT_GUI_IDLE_TIMEOUT_MINUTES: u64 = 60;
/// Largest accepted idle timeout, in minutes (24 h).
pub const MAX_GUI_IDLE_TIMEOUT_MINUTES: u64 = 24 * 60;
const SESSION_REFRESH_PATH: &str = "/auth/session/refresh";
const SESSION_REVOKE_PATH: &str = "/auth/session/revoke";

/// Check a configured idle timeout and turn it into a [`Duration`].
///
/// # Errors
///
/// Returns a message when `minutes` is 0 or above
/// [`MAX_GUI_IDLE_TIMEOUT_MINUTES`].
pub fn gui_idle_timeout(minutes: u64) -> Result<Duration, String> {
    if minutes == 0 || minutes > MAX_GUI_IDLE_TIMEOUT_MINUTES {
        return Err(format!(
            "gui_idle_timeout_minutes must be 1..={MAX_GUI_IDLE_TIMEOUT_MINUTES}, got {minutes}"
        ));
    }
    Ok(Duration::from_secs(minutes * 60))
}

/// Wall-clock source of a [`SessionStore`]. Production reads
/// [`SystemTime::now`]; tests inject a manual clock.
pub(super) type SessionClock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// Replaced tokens remembered for revoke, at most this many.
const MAX_RETIRED_TOKENS: usize = 4096;

/// A single issued browser session token, stored as a SHA-256 digest.
///
/// Only the digest is retained so a memory dump cannot recover live tokens;
/// validation hashes the candidate and scans with [`subtle::ConstantTimeEq`].
///
/// Times are wall-clock, not [`std::time::Instant`]: a monotonic clock stops
/// while the machine is suspended, and a session must age during sleep.
struct AuthSession {
    token_hash: [u8; 32],
    /// One session from mint to end; refreshed tokens inherit it, and
    /// revoke ends every token of it.
    lineage: u64,
    expires_at: SystemTime,
    /// Last user activity of this session. Refreshed tokens inherit it;
    /// only a refresh that reports user input moves it.
    last_activity: SystemTime,
}

/// A token that a refresh replaced. It opens nothing, but it can still
/// revoke its session: a sign-out that raced a refresh holds only this.
struct RetiredToken {
    token_hash: [u8; 32],
    lineage: u64,
    until: SystemTime,
}

#[derive(Default)]
struct SessionTable {
    live: Vec<AuthSession>,
    retired: std::collections::VecDeque<RetiredToken>,
}

/// Why [`SessionStore::refresh`] refused.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SessionRefreshError {
    /// Not a known session token (never issued, revoked, or already
    /// refreshed).
    Unknown,
    /// The session had no user activity for the idle timeout.
    IdleTimeout,
}

/// In-memory store of short-lived browser session tokens (#127 / WS1.6).
///
/// Session tokens are the *only* tokens accepted via `?token=` query strings
/// on browser endpoints (WS/SSE); the durable API token is never valid in a
/// query string. The store uses a `std::sync::Mutex` because the critical
/// sections are trivial (hash + linear scan + prune) and never cross an await.
///
/// A session ends when it has had no user activity for `idle_timeout`.
/// There is no cap on total lifetime.
pub(super) struct SessionStore {
    table: StdMutex<SessionTable>,
    ttl: Duration,
    idle_timeout: Duration,
    clock: SessionClock,
    /// Latest time the store has seen. A wall clock stepped backward reads
    /// as this until it catches up, so a step cannot extend a session.
    high_water: StdMutex<SystemTime>,
    next_lineage: std::sync::atomic::AtomicU64,
}

fn hash_matches(candidate: &[u8], stored: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(candidate.ct_eq(stored))
}

impl SessionStore {
    pub(super) fn new(ttl: Duration, idle_timeout: Duration) -> Self {
        Self::with_clock(ttl, idle_timeout, Arc::new(SystemTime::now))
    }

    pub(super) fn with_clock(ttl: Duration, idle_timeout: Duration, clock: SessionClock) -> Self {
        Self {
            table: StdMutex::new(SessionTable::default()),
            ttl,
            idle_timeout,
            clock,
            high_water: StdMutex::new(SystemTime::UNIX_EPOCH),
            next_lineage: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub(super) fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    fn now(&self) -> SystemTime {
        let wall = (self.clock)();
        let Ok(mut seen) = self.high_water.lock() else {
            return wall;
        };
        if wall > *seen {
            *seen = wall;
        }
        *seen
    }

    fn active_at(&self, session: &AuthSession, now: SystemTime) -> bool {
        now.duration_since(session.last_activity)
            .is_ok_and(|idle| idle < self.idle_timeout)
    }

    fn prune(&self, table: &mut SessionTable, now: SystemTime) {
        table.live.retain(|s| self.active_at(s, now));
        table.retired.retain(|r| r.until > now);
    }

    /// Issue a fresh session token, store its digest, and return the raw token
    /// to hand to the client. A mint is user activity and starts a lineage.
    pub(super) fn issue(&self) -> String {
        let now = self.now();
        let lineage = self
            .next_lineage
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (token, session) = self.new_session(now, now, lineage);
        if let Ok(mut table) = self.table.lock() {
            table.live.push(session);
            // Bound the store: lazy-prune idle entries on every issue so a
            // flood of session mints cannot grow it without bound.
            self.prune(&mut table, now);
        }
        token
    }

    /// Generate a raw token plus its stored entry, expiring `ttl` from `now`.
    fn new_session(
        &self,
        now: SystemTime,
        last_activity: SystemTime,
        lineage: u64,
    ) -> (String, AuthSession) {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let session = AuthSession {
            token_hash: Sha256::digest(token.as_bytes()).into(),
            lineage,
            expires_at: now.checked_add(self.ttl).unwrap_or(now),
            last_activity,
        };
        (token, session)
    }

    /// Replace a session token with a fresh one (#893). The token may have
    /// lapsed, but the session must be inside the idle timeout.
    ///
    /// The idle check uses the activity recorded before this call, so a
    /// claim cannot revive a session that already timed out. `idle` is the
    /// client's time since its last user input; it moves `last_activity` to
    /// `now - idle` when that is later, and never past `now`. `None` (a
    /// background refresh) leaves it alone. The presented token is removed
    /// in the same critical section, so it stops working at once.
    pub(super) fn refresh(
        &self,
        token: &str,
        idle: Option<Duration>,
    ) -> Result<String, SessionRefreshError> {
        let now = self.now();
        let candidate = Sha256::digest(token.as_bytes());
        let mut table = self
            .table
            .lock()
            .map_err(|_| SessionRefreshError::Unknown)?;
        let index = table
            .live
            .iter()
            .position(|s| hash_matches(&candidate, &s.token_hash))
            .ok_or(SessionRefreshError::Unknown)?;
        let session = table.live.swap_remove(index);
        self.prune(&mut table, now);
        if !self.active_at(&session, now) {
            return Err(SessionRefreshError::IdleTimeout);
        }
        let claimed = idle.and_then(|idle| now.checked_sub(idle));
        let last_activity = match claimed {
            Some(at) if at > session.last_activity => at.min(now),
            _ => session.last_activity,
        };
        if table.retired.len() >= MAX_RETIRED_TOKENS {
            table.retired.pop_front();
        }
        table.retired.push_back(RetiredToken {
            token_hash: session.token_hash,
            lineage: session.lineage,
            until: now.checked_add(self.idle_timeout).unwrap_or(now),
        });
        let (fresh, session) = self.new_session(now, last_activity, session.lineage);
        table.live.push(session);
        Ok(fresh)
    }

    /// End the whole session `token` belongs to: every token of its
    /// lineage stops working. `token` may be live, lapsed, or one a refresh
    /// just replaced. Returns whether a live token was removed.
    pub(super) fn revoke(&self, token: &str) -> bool {
        let now = self.now();
        let candidate = Sha256::digest(token.as_bytes());
        let Ok(mut table) = self.table.lock() else {
            return false;
        };
        self.prune(&mut table, now);
        let lineage = table
            .live
            .iter()
            .find(|s| hash_matches(&candidate, &s.token_hash))
            .map(|s| s.lineage)
            .or_else(|| {
                table
                    .retired
                    .iter()
                    .find(|r| hash_matches(&candidate, &r.token_hash))
                    .map(|r| r.lineage)
            });
        let Some(lineage) = lineage else {
            return false;
        };
        let before = table.live.len();
        table.live.retain(|s| s.lineage != lineage);
        table.retired.retain(|r| r.lineage != lineage);
        table.live.len() < before
    }

    /// Recorded last activity of a live token's session (tests only).
    #[cfg(test)]
    fn last_activity(&self, token: &str) -> Option<SystemTime> {
        let candidate = Sha256::digest(token.as_bytes());
        let table = self.table.lock().ok()?;
        table
            .live
            .iter()
            .find(|s| hash_matches(&candidate, &s.token_hash))
            .map(|s| s.last_activity)
    }

    /// Number of stored live and lapsed tokens (tests only).
    #[cfg(test)]
    fn live_len(&self) -> usize {
        self.table.lock().map(|t| t.live.len()).unwrap_or(0)
    }

    /// Validate a candidate token: constant-time compare against every active
    /// session digest, pruning idle entries along the way. Returns `true`
    /// only if an unexpired entry of an active session matches.
    ///
    /// `POST /gui/show` calls this at the navigate decision. A WebSocket
    /// stays up after the token expires, and visibility alone is not a
    /// live GUI session.
    pub(super) fn is_valid(&self, token: &str) -> bool {
        let now = self.now();
        let candidate = Sha256::digest(token.as_bytes());
        let Ok(mut table) = self.table.lock() else {
            return false;
        };
        self.prune(&mut table, now);
        table
            .live
            .iter()
            .any(|s| s.expires_at > now && hash_matches(&candidate, &s.token_hash))
    }

    /// Whether `token` belongs to a session inside the idle timeout, live
    /// or lapsed. Only `POST /auth/session/refresh` and
    /// `POST /auth/session/revoke` may use this.
    fn is_refreshable(&self, token: &str) -> bool {
        let now = self.now();
        let candidate = Sha256::digest(token.as_bytes());
        let Ok(mut table) = self.table.lock() else {
            return false;
        };
        self.prune(&mut table, now);
        table
            .live
            .iter()
            .any(|s| hash_matches(&candidate, &s.token_hash))
    }

    /// Whether `token` may call `POST /auth/session/revoke`: it is
    /// refreshable, or a refresh replaced it and its session is still live.
    fn is_revocable(&self, token: &str) -> bool {
        let now = self.now();
        let candidate = Sha256::digest(token.as_bytes());
        let Ok(mut table) = self.table.lock() else {
            return false;
        };
        self.prune(&mut table, now);
        let lineage = table
            .live
            .iter()
            .find(|s| hash_matches(&candidate, &s.token_hash))
            .map(|s| s.lineage)
            .or_else(|| {
                table
                    .retired
                    .iter()
                    .find(|r| hash_matches(&candidate, &r.token_hash))
                    .map(|r| r.lineage)
            });
        lineage.is_some_and(|lineage| table.live.iter().any(|s| s.lineage == lineage))
    }

    /// Whether `token` is a live session.
    #[cfg(test)]
    pub(super) fn is_live_for_test(&self, token: &str) -> bool {
        self.is_valid(token)
    }

    /// Lapse one session token. The session stays inside the idle timeout.
    #[cfg(test)]
    pub(super) fn expire_for_test(&self, token: &str) {
        let candidate = Sha256::digest(token.as_bytes());
        let past = self.now();
        let Ok(mut table) = self.table.lock() else {
            return;
        };
        for session in table.live.iter_mut() {
            if hash_matches(&candidate, &session.token_hash) {
                session.expires_at = past;
            }
        }
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
    /// The default idle timeout (60 min).
    const IDLE: Duration = Duration::from_secs(DEFAULT_GUI_IDLE_TIMEOUT_MINUTES * 60);
    const MIN: Duration = Duration::from_secs(60);

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
        )
    }

    // -- Protected endpoints: representative sample + /agent/sign + /agent/verify.

    #[test]
    fn auth_matrix_protected_endpoints_reject_without_token() {
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
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
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
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
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
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
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        let session = sessions.issue();
        for path in ["/status", "/agent", "/agent/verify"] {
            assert!(
                authorize_protected(path, Some(&session), None, &sessions).is_ok(),
                "{path} with a session bearer must pass (Ok)"
            );
        }
    }

    #[test]
    fn auth_matrix_owner_act_routes_invert_the_session_assertion() {
        // Issue #446 (review rounds 2+3): the ORIGINAL assertion — "a
        // session bearer must pass /agent/sign (Ok)" — INVERTED.
        //
        // This test pins the PURE layer only: the COMPLETE durable-owner
        // route table plus lookalike negatives. The end-to-end proof
        // (session → typed 403 through the REAL `auth_middleware`, rider
        // → 403, durable → passes) lives in
        // `routes::identity::owner_act_tests::owner_act_matrix_universal`,
        // which drives the production middleware itself — no test-only
        // reimplementation of the decision anywhere.
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        let session = sessions.issue();
        for (method, path) in [
            (Method::POST, "/agent/sign"),
            (Method::POST, "/exec/run"),
            (Method::POST, "/exec/cancel"),
            (Method::POST, "/shutdown"),
            (Method::POST, "/sync/devices/enroll"),
            (
                Method::DELETE,
                "/sync/devices/00112233445566778899aabbccddeeff",
            ),
            (Method::POST, "/groups/some-group/delegate"),
            (Method::POST, "/home/rename"),
            (Method::POST, "/home/seat"),
            (Method::POST, "/upgrade/apply"),
            (Method::POST, "/upgrade/clear-hold"),
            (Method::POST, "/gui/show"),
        ] {
            // The route is classified durable-owner…
            assert!(
                requires_durable_owner(&method, path),
                "{method} {path} must be classified durable-owner"
            );
            // …the session bearer is still a VALID bearer (`authorize`
            // decides bearer validity only) — the refusal is the
            // middleware's route classification, asserted end-to-end in
            // the identity matrix test.
            assert!(
                authorize(
                    path,
                    &method,
                    Some(&session),
                    None,
                    TEST_API_TOKEN,
                    &sessions
                )
                .is_ok(),
                "{method} {path}: session bearer is a valid bearer"
            );
        }
        // Lookalikes must NOT be classified (deny-by-default table):
        for (method, path) in [
            (Method::GET, "/agent/sign"),
            (Method::POST, "/agent/sign/extra"),
            (Method::POST, "/groups/some-group/delegate/x"),
            (Method::POST, "/groups/delegate"),
            (Method::DELETE, "/sync/devices/with/extra"),
            (Method::GET, "/exec/sessions"),
            (Method::GET, "/sync/devices"),
            (Method::PATCH, "/groups/some-group"),
            (Method::PATCH, "/groups/some-group/policy"),
        ] {
            assert!(
                !requires_durable_owner(&method, path),
                "{method} {path} must NOT be classified durable-owner"
            );
        }
    }

    // -- Auth-exempt public paths: served without any token.

    #[test]
    fn auth_matrix_exempt_paths_serve_without_token() {
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        for path in ["/health", "/constitution", "/constitution/json"] {
            assert!(
                authorize(path, &Method::GET, None, None, TEST_API_TOKEN, &sessions).is_ok(),
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
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        let session = sessions.issue();
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
                    &sessions
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
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        for path in ["/gui", "/ws", "/ws/direct", "/events", "/peers/events"] {
            assert_eq!(
                authorize(
                    path,
                    &Method::GET,
                    None,
                    Some(TEST_API_TOKEN),
                    TEST_API_TOKEN,
                    &sessions),
                Err(StatusCode::UNAUTHORIZED),
                "{path}?token=<durable> must be 401 — durable tokens are never valid in a query string"
            );
        }
    }

    #[test]
    fn auth_matrix_query_token_rejected_on_protected_paths() {
        // A query token must NOT authenticate non-browser endpoints — that
        // would leak the credential via history/Referer/HAR.
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        for path in ["/status", "/agent/sign", "/agent/verify"] {
            assert_eq!(
                authorize(
                    path,
                    &matrix_method(path),
                    None,
                    Some(TEST_API_TOKEN),
                    TEST_API_TOKEN,
                    &sessions
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
        let sessions = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        assert!(
            authorize(
                "/status",
                &Method::OPTIONS,
                None,
                None,
                TEST_API_TOKEN,
                &sessions
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
    // #127 / WS1.6 — SessionStore unit tests.
    //
    // The store reads an injected wall clock (no sleeps, no daemon), so
    // expiry, idle timeout and clock steps are fully deterministic.
    // ========================================================================

    #[derive(Clone)]
    struct TestClock(Arc<StdMutex<SystemTime>>);

    impl TestClock {
        fn new() -> Self {
            let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
            Self(Arc::new(StdMutex::new(start)))
        }
        fn now(&self) -> SystemTime {
            *self.0.lock().unwrap()
        }
        fn set(&self, at: SystemTime) {
            *self.0.lock().unwrap() = at;
        }
        fn advance(&self, by: Duration) {
            let at = self.now() + by;
            self.set(at);
        }
        fn back(&self, by: Duration) {
            let at = self.now() - by;
            self.set(at);
        }
        fn store(&self, idle: Duration) -> SessionStore {
            let clock = self.clone();
            SessionStore::with_clock(SESSION_TOKEN_TTL, idle, Arc::new(move || clock.now()))
        }
    }

    fn authorize_refresh(store: &SessionStore, token: &str) -> bool {
        authorize(
            SESSION_REFRESH_PATH,
            &Method::POST,
            Some(token),
            None,
            TEST_API_TOKEN,
            store,
        )
        .is_ok()
    }

    fn authorize_revoke(store: &SessionStore, token: &str) -> bool {
        authorize(
            SESSION_REVOKE_PATH,
            &Method::POST,
            Some(token),
            None,
            TEST_API_TOKEN,
            store,
        )
        .is_ok()
    }

    fn authorize_agent(store: &SessionStore, token: &str) -> bool {
        authorize(
            "/agent",
            &Method::GET,
            Some(token),
            None,
            TEST_API_TOKEN,
            store,
        )
        .is_ok()
    }

    #[test]
    fn session_store_issues_and_validates_a_token() {
        let store = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        let token = store.issue();
        assert!(token.len() >= 32, "session token must be opaque hex");
        assert!(
            store.is_valid(&token),
            "a freshly-issued token must validate"
        );
        assert!(
            !store.is_valid("not-a-real-token"),
            "a wrong token must not validate",
        );
    }

    #[test]
    fn session_store_token_expires_after_ttl() {
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let t0 = clock.now();
        let token = store.issue();
        clock.set(t0 + SESSION_TOKEN_TTL - Duration::from_nanos(1));
        assert!(store.is_valid(&token), "valid right up to the TTL boundary");
        clock.set(t0 + SESSION_TOKEN_TTL);
        assert!(!store.is_valid(&token), "invalid at the TTL (fail-closed)");
    }

    #[test]
    fn session_store_prunes_idle_entries() {
        // Pruning is lazy (on issue/validate) so the Vec cannot grow without
        // bound even if clients never explicitly revoke.
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let dead = store.issue();
        clock.advance(IDLE);
        assert!(!authorize_refresh(&store, &dead));
        let fresh = store.issue();
        assert!(store.is_valid(&fresh));
        assert_eq!(store.live_len(), 1, "the idle entry is pruned");
    }

    // -- #893 sliding refresh with an idle timeout.

    #[test]
    fn session_refresh_rotates_token_and_carries_last_activity() {
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let t0 = clock.now();
        let first = store.issue();
        assert_eq!(store.last_activity(&first), Some(t0), "a mint is activity");
        clock.advance(8 * MIN);
        let second = store.refresh(&first, None).expect("live session refreshes");
        assert_ne!(first, second, "refresh must mint a new token");
        assert_eq!(store.last_activity(&second), Some(t0));
        assert!(
            !store.is_valid(&first),
            "the replaced token must stop working immediately (no overlap)"
        );
        assert!(store.is_valid(&second));
        clock.advance(SESSION_TOKEN_TTL - Duration::from_nanos(1));
        assert!(store.is_valid(&second), "a full TTL from the refresh");
        assert_eq!(
            store.refresh(&first, None),
            Err(SessionRefreshError::Unknown)
        );
    }

    #[test]
    fn active_session_survives_well_past_twelve_hours() {
        // Refresh every 8 min (as the GUI does), with input 1 min earlier.
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let t0 = clock.now();
        let mut token = store.issue();
        while clock.now() < t0 + Duration::from_secs(36 * 60 * 60) {
            clock.advance(8 * MIN);
            token = store
                .refresh(&token, Some(MIN))
                .expect("an active session refreshes");
            assert_eq!(store.last_activity(&token), Some(clock.now() - MIN));
        }
        assert!(store.is_valid(&token));
        assert!(authorize_agent(&store, &token));
    }

    #[test]
    fn background_refreshes_do_not_extend_an_idle_session() {
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let t0 = clock.now();
        let mut token = store.issue();
        while clock.now() + 8 * MIN < t0 + IDLE {
            clock.advance(8 * MIN);
            token = store
                .refresh(&token, None)
                .expect("inside the idle timeout");
            assert_eq!(store.last_activity(&token), Some(t0));
        }
        // A claim of input older than the recorded activity changes nothing.
        clock.advance(MIN);
        let stale = clock.now().duration_since(t0).unwrap() + MIN;
        token = store
            .refresh(&token, Some(stale))
            .expect("inside the idle timeout");
        assert_eq!(store.last_activity(&token), Some(t0));

        // The token is unexpired at the limit, but the session is idle.
        assert!(t0 + IDLE < clock.now() + SESSION_TOKEN_TTL);
        clock.set(t0 + IDLE - Duration::from_nanos(1));
        assert!(store.is_valid(&token));
        clock.set(t0 + IDLE);
        assert!(!store.is_valid(&token), "idle ends a live token");
        assert!(!authorize_agent(&store, &token));
        assert!(!authorize_refresh(&store, &token));
    }

    #[test]
    fn refresh_at_the_idle_limit_reports_the_timeout() {
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let t0 = clock.now();
        let token = store.issue();
        clock.advance(55 * MIN);
        let token = store
            .refresh(&token, None)
            .expect("inside the idle timeout");
        clock.set(t0 + IDLE);
        assert_eq!(
            store.refresh(&token, None),
            Err(SessionRefreshError::IdleTimeout)
        );
    }

    #[test]
    fn idle_session_is_refused_even_with_a_fresh_activity_claim() {
        // The check uses the recorded activity, so a claim made after the
        // limit cannot revive the session.
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let t0 = clock.now();
        let token = store.issue();
        clock.advance(5 * MIN);
        let refreshed = store.refresh(&token, None).expect("live refresh");
        clock.set(t0 + IDLE);
        assert_eq!(
            store.refresh(&refreshed, Some(Duration::ZERO)),
            Err(SessionRefreshError::IdleTimeout)
        );
        assert_eq!(
            store.refresh(&refreshed, Some(Duration::ZERO)),
            Err(SessionRefreshError::Unknown),
            "the timed-out session is gone"
        );
    }

    #[test]
    fn wall_clock_jump_past_the_idle_limit_ends_the_session() {
        // A suspended machine wakes with the wall clock far ahead. The
        // session must count the sleep, on every path.
        for path in ["live refresh", "lapsed refresh", "agent", "revoke"] {
            let clock = TestClock::new();
            let store = clock.store(IDLE);
            let token = store.issue();
            if path == "lapsed refresh" {
                clock.advance(20 * MIN);
                assert!(authorize_refresh(&store, &token), "lapsed, inside idle");
            }
            clock.advance(8 * 60 * MIN);
            assert!(!store.is_valid(&token), "{path}");
            assert!(!authorize_agent(&store, &token), "{path}");
            assert!(!authorize_refresh(&store, &token), "{path}");
            assert!(!authorize_revoke(&store, &token), "{path}");
            assert!(
                store.refresh(&token, Some(Duration::ZERO)).is_err(),
                "{path}: a fresh claim cannot revive a slept session"
            );
        }
    }

    #[test]
    fn wall_clock_step_backward_freezes_store_time() {
        // The store's time never goes back: a backward step freezes it
        // until the wall clock catches up, so the step cannot buy time
        // beyond its own size, and cannot be repeated to gain more.
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let t0 = clock.now();
        let token = store.issue();
        clock.advance(50 * MIN);
        let token = store.refresh(&token, None).expect("inside idle");
        clock.back(2 * MIN);
        assert!(
            store.is_valid(&token),
            "a small step back keeps the session"
        );
        clock.advance(MIN);
        let token = store.refresh(&token, None).expect("still inside idle");
        // Store time is still t0 + 50 min: the activity record is unchanged
        // and the new token expires from that time, not from the wall.
        assert_eq!(store.last_activity(&token), Some(t0));
        clock.back(5 * MIN);
        clock.set(t0 + IDLE - Duration::from_nanos(1));
        assert!(store.is_valid(&token));
        clock.set(t0 + IDLE);
        assert!(!store.is_valid(&token), "expiry at the original wall time");
        assert!(!authorize_refresh(&store, &token));
    }

    #[test]
    fn revoke_with_a_replaced_token_ends_the_whole_session() {
        // Sign out raced a refresh: the refresh won, and revoke presents
        // the token it replaced.
        let store = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        let old = store.issue();
        let other = store.issue();
        let new = store.refresh(&old, None).expect("refresh");
        assert!(
            !authorize_refresh(&store, &old),
            "a replaced token cannot refresh"
        );
        assert!(
            authorize_revoke(&store, &old),
            "a replaced token can revoke"
        );
        assert!(store.revoke(&old));
        assert!(!store.is_valid(&new), "the refresh winner is dead");
        assert!(!authorize_refresh(&store, &new));
        assert!(store.refresh(&new, None).is_err());
        assert!(!authorize_revoke(&store, &old), "the session is gone");
        assert!(store.is_valid(&other), "another session is untouched");
        assert_eq!(store.live_len(), 1);
    }

    #[test]
    fn revoke_then_refresh_leaves_no_live_token() {
        let store = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        let old = store.issue();
        let newer = store.refresh(&old, None).expect("refresh");
        assert!(store.revoke(&newer));
        assert_eq!(
            store.refresh(&newer, None),
            Err(SessionRefreshError::Unknown)
        );
        assert_eq!(store.refresh(&old, None), Err(SessionRefreshError::Unknown));
        assert_eq!(store.live_len(), 0);
    }

    #[test]
    fn concurrent_refresh_and_revoke_end_the_session_in_either_order() {
        use std::sync::Barrier;
        use std::thread;
        for _ in 0..64 {
            let store = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
            let token = store.issue();
            let barrier = Barrier::new(2);
            let (refreshed, _) = thread::scope(|s| {
                let h1 = s.spawn(|| {
                    barrier.wait();
                    store.refresh(&token, Some(Duration::ZERO))
                });
                let h2 = s.spawn(|| {
                    barrier.wait();
                    store.revoke(&token)
                });
                (h1.join().unwrap(), h2.join().unwrap())
            });
            if let Ok(new) = refreshed {
                assert!(!store.is_valid(&new), "the refresh winner must be dead");
            }
            assert_eq!(store.live_len(), 0, "no live token in the lineage");
        }
    }

    #[test]
    fn activity_claim_never_moves_last_activity_past_now() {
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let token = store.issue();
        clock.advance(5 * MIN);
        let t1 = clock.now();
        let token = store
            .refresh(&token, Some(Duration::ZERO))
            .expect("refresh");
        assert_eq!(store.last_activity(&token), Some(t1));
        clock.advance(MIN);
        let t2 = clock.now();
        let token = store
            .refresh(&token, Some(Duration::from_millis(u64::MAX)))
            .expect("an impossible claim is ignored, not an error");
        assert_eq!(store.last_activity(&token), Some(t1));
        let token = store
            .refresh(&token, Some(Duration::from_secs(30)))
            .expect("refresh");
        assert_eq!(
            store.last_activity(&token),
            Some(t2 - Duration::from_secs(30))
        );
        assert!(store.last_activity(&token).is_some_and(|at| at <= t2));
    }

    #[test]
    fn configured_idle_timeout_is_honoured_and_bad_values_rejected() {
        assert_eq!(
            gui_idle_timeout(0),
            Err(format!(
                "gui_idle_timeout_minutes must be 1..={MAX_GUI_IDLE_TIMEOUT_MINUTES}, got 0"
            ))
        );
        assert!(gui_idle_timeout(MAX_GUI_IDLE_TIMEOUT_MINUTES + 1).is_err());
        assert_eq!(gui_idle_timeout(1), Ok(MIN));
        assert_eq!(
            gui_idle_timeout(MAX_GUI_IDLE_TIMEOUT_MINUTES),
            Ok(Duration::from_secs(24 * 60 * 60))
        );
        assert_eq!(gui_idle_timeout(DEFAULT_GUI_IDLE_TIMEOUT_MINUTES), Ok(IDLE));

        let idle = gui_idle_timeout(15).expect("valid");
        let clock = TestClock::new();
        let store = clock.store(idle);
        assert_eq!(store.idle_timeout(), idle);
        let t0 = clock.now();
        let token = store.issue();
        store.expire_for_test(&token);
        clock.set(t0 + 15 * MIN - Duration::from_nanos(1));
        assert!(authorize_refresh(&store, &token));
        clock.set(t0 + 15 * MIN);
        assert!(!authorize_refresh(&store, &token));
    }

    #[test]
    fn session_refresh_refuses_unknown_and_durable_tokens() {
        let store = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        let token = store.issue();
        // The durable token is not in the session store, so the store can
        // never turn it into a session (the handler also refuses it first).
        assert_eq!(
            store.refresh(TEST_API_TOKEN, Some(Duration::ZERO)),
            Err(SessionRefreshError::Unknown)
        );
        assert!(store.revoke(&token));
        assert!(!store.revoke(&token));
        assert_eq!(
            store.refresh(&token, Some(Duration::ZERO)),
            Err(SessionRefreshError::Unknown),
            "a revoked token cannot refresh"
        );
    }

    #[test]
    fn lapsed_session_reaches_only_refresh_and_revoke() {
        // A laptop that slept 30 min recovers.
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let t0 = clock.now();
        let hidden = store.issue();
        clock.set(t0 + 30 * MIN);

        assert!(!store.is_valid(&hidden), "a lapsed token is not live");
        for (method, path, header, query) in [
            (Method::GET, "/agent", Some(hidden.as_str()), None),
            (Method::POST, "/auth/session", Some(hidden.as_str()), None),
            (
                Method::GET,
                SESSION_REVOKE_PATH,
                Some(hidden.as_str()),
                None,
            ),
            (
                Method::POST,
                "/auth/session/revoke/x",
                Some(hidden.as_str()),
                None,
            ),
            (
                Method::GET,
                SESSION_REFRESH_PATH,
                Some(hidden.as_str()),
                None,
            ),
            (Method::GET, "/ws/direct", None, Some(hidden.as_str())),
            (
                Method::POST,
                SESSION_REFRESH_PATH,
                None,
                Some(hidden.as_str()),
            ),
            (
                Method::POST,
                SESSION_REVOKE_PATH,
                None,
                Some(hidden.as_str()),
            ),
        ] {
            assert_eq!(
                authorize(path, &method, header, query, TEST_API_TOKEN, &store),
                Err(StatusCode::UNAUTHORIZED),
                "{method} {path}: a lapsed token opens only refresh and revoke"
            );
        }
        assert!(authorize_refresh(&store, &hidden));
        assert!(authorize_revoke(&store, &hidden));

        let fresh = store
            .refresh(&hidden, Some(Duration::ZERO))
            .expect("refresh inside the idle timeout");
        assert!(store.is_valid(&fresh));
        assert_eq!(store.last_activity(&fresh), Some(t0 + 30 * MIN));
        assert!(!authorize_refresh(&store, &hidden));
        assert_eq!(
            store.refresh(&hidden, None),
            Err(SessionRefreshError::Unknown),
            "a lapsed token is swapped once"
        );
    }

    #[test]
    fn lapsed_session_can_be_revoked() {
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let hidden = store.issue();
        clock.advance(20 * MIN);
        assert!(authorize_revoke(&store, &hidden));
        assert!(store.revoke(&hidden));
        assert!(
            !authorize_refresh(&store, &hidden),
            "revoked: not refreshable"
        );
        assert!(!authorize_revoke(&store, &hidden));
    }

    #[test]
    fn lapsed_session_is_refused_at_the_idle_timeout() {
        // A laptop that slept 2 h must sign in again.
        let clock = TestClock::new();
        let store = clock.store(IDLE);
        let t0 = clock.now();
        let hidden = store.issue();
        for late in [t0 + IDLE, t0 + 120 * MIN] {
            clock.set(late);
            assert!(!authorize_refresh(&store, &hidden));
            for (method, path) in [(Method::GET, "/agent"), (Method::POST, "/auth/session")] {
                assert_eq!(
                    authorize(path, &method, Some(&hidden), None, TEST_API_TOKEN, &store),
                    Err(StatusCode::UNAUTHORIZED)
                );
            }
        }
        assert_eq!(
            store.refresh(&hidden, Some(Duration::ZERO)),
            Err(SessionRefreshError::Unknown),
            "the idle session was pruned"
        );
    }

    #[test]
    fn concurrent_lapsed_refresh_one_wins() {
        use std::sync::Barrier;
        use std::thread;

        let store = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        let token = store.issue();
        store.expire_for_test(&token);
        let barrier = Barrier::new(2);

        let (r1, r2) = thread::scope(|s| {
            let h1 = s.spawn(|| {
                barrier.wait();
                store.refresh(&token, Some(Duration::ZERO))
            });
            let h2 = s.spawn(|| {
                barrier.wait();
                store.refresh(&token, Some(Duration::ZERO))
            });
            (h1.join().unwrap(), h2.join().unwrap())
        });

        let winner = match (r1, r2) {
            (Ok(tok), Err(SessionRefreshError::Unknown)) => tok,
            (Err(SessionRefreshError::Unknown), Ok(tok)) => tok,
            (a, b) => panic!("expected one Ok and one Unknown, got {a:?} and {b:?}"),
        };
        assert!(store.is_valid(&winner));
    }

    #[test]
    fn refreshed_session_has_the_same_authority_as_the_original() {
        // A refreshed token is an ordinary session bearer: accepted on
        // protected routes and browser query-token routes, still classified
        // non-durable on owner-act routes (the middleware 403s it there).
        let store = SessionStore::new(SESSION_TOKEN_TTL, IDLE);
        let first = store.issue();
        let refreshed = store.refresh(&first, None).expect("refresh");
        for (path, header, query) in [
            ("/agent", Some(refreshed.as_str()), None),
            ("/ws/direct", None, Some(refreshed.as_str())),
        ] {
            assert!(
                authorize(path, &Method::GET, header, query, TEST_API_TOKEN, &store).is_ok(),
                "{path}: refreshed session must authorize like the original"
            );
        }
        assert!(
            !ct_eq(&refreshed, TEST_API_TOKEN),
            "a refreshed session must never be the durable token"
        );
        assert!(requires_durable_owner(&Method::POST, "/agent/sign"));
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

    #[test]
    fn acl_routes_require_durable_owner_for_every_method() {
        // ADR-0070 §3: ACL management — including listing, which reveals
        // who may connect/exec — is durable-owner only. A session bearer
        // must not read or edit it, whatever the method.
        for method in [Method::GET, Method::POST, Method::DELETE] {
            for path in [
                "/acl/connect",
                "/acl/exec",
                "/acl/reload",
                "/acl/connect/api-0011223344556677",
                "/acl/exec/file-0011223344556677",
            ] {
                assert!(
                    requires_durable_owner(&method, path),
                    "{method} {path} must be durable-owner"
                );
            }
        }
        for path in [
            "/acl",
            "/acl/connect/",
            "/acl/connect/a/b",
            "/aclx/connect",
            "/acl/connectx",
        ] {
            assert!(!is_acl_admin_path(path), "{path} must not be classified");
        }
    }

    /// ADR 0116 §3: `GET /history/policy` is owner-only, enforced at the
    /// route layer like the other durable-owner surfaces. The other history
    /// reads keep their existing tiers.
    #[test]
    fn history_policy_requires_durable_owner_and_other_history_reads_do_not() {
        assert!(requires_durable_owner(&Method::GET, "/history/policy"));
        for path in [
            "/history",
            "/history/stats",
            "/history/scopes",
            "/history/search",
        ] {
            assert!(
                !requires_durable_owner(&Method::GET, path),
                "GET {path} keeps its tier"
            );
        }
    }

    /// ADR 0116 §4: the runtime trim needs the durable token (sessions and
    /// riders get 403 at the route layer). Other history POST/DELETE paths
    /// keep their tiers.
    #[test]
    fn history_retain_requires_durable_owner() {
        assert!(requires_durable_owner(&Method::POST, "/history/retain"));
        assert!(!requires_durable_owner(&Method::GET, "/history/retain"));
        assert!(!requires_durable_owner(&Method::DELETE, "/history"));
    }

    #[test]
    fn issue1228_owner_acts_require_the_durable_token_before_the_body() {
        let group = "ab".repeat(32);
        let request = "cd".repeat(16);
        assert!(requires_durable_owner(
            &Method::POST,
            &format!("/groups/{group}/quarantine/clear")
        ));
        assert!(requires_durable_owner(&Method::GET, "/mls/groups"));
        assert!(requires_durable_owner(
            &Method::POST,
            &format!("/mls/groups/{group}/welcome")
        ));
        assert!(requires_durable_owner(
            &Method::DELETE,
            &format!("/mls/groups/{group}/members/{request}")
        ));
        // #1347: the join-request list, approve and reject take one
        // group-dependent class (the Home fence in the handlers), so none
        // of them is durable-owner at the route layer.
        assert!(!requires_durable_owner(
            &Method::GET,
            &format!("/groups/{group}/requests")
        ));
        assert!(!requires_durable_owner(
            &Method::POST,
            &format!("/groups/{group}/requests/{request}/approve")
        ));
        assert!(!requires_durable_owner(
            &Method::POST,
            &format!("/groups/{group}/requests/{request}/reject")
        ));
        assert!(!requires_durable_owner(
            &Method::DELETE,
            &format!("/groups/{group}/requests/{request}")
        ));
        assert!(!requires_durable_owner(
            &Method::POST,
            &format!("/groups/{group}/requests")
        ));
        assert!(!requires_durable_owner(
            &Method::PUT,
            &format!("/groups/{group}/display-name")
        ));
    }

    #[test]
    fn grant_routes_require_durable_owner_for_every_method() {
        // ADR-0070 §2: listing grants reveals who may reach the owner's
        // agents; issuing/revoking changes it. Durable-owner only.
        for method in [Method::GET, Method::POST, Method::DELETE] {
            for path in ["/grants", "/grants/received", "/grants/00ff"] {
                assert!(
                    requires_durable_owner(&method, path),
                    "{method} {path} must be durable-owner"
                );
            }
        }
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            for path in ["/grants/data/aa/bb/scratch", "/grants/data/aa/bb/scratch/k"] {
                assert!(
                    requires_durable_owner(&method, path),
                    "{method} {path} must be durable-owner"
                );
            }
        }
        for path in ["/grant", "/grants/", "/grants/a/b", "/grantsx"] {
            assert!(!is_grants_path(path), "{path} must not be classified");
        }
    }

    #[test]
    fn name_routes_require_durable_owner_for_every_method() {
        // ADR-0074 §1: petnames are editable only by the local owner and a
        // resolve pins; a session or rider token must reach none of them.
        for method in [Method::GET, Method::POST, Method::DELETE] {
            for path in [
                "/names",
                "/names/resolve",
                "/names/owners",
                "/names/machines",
                "/names/owners/bob",
                "/names/pins/agent:studio.bob",
                "/names/accept",
                "/names/suggestions/bob-smith",
            ] {
                assert!(
                    requires_durable_owner(&method, path),
                    "{method} {path} must require the durable token"
                );
            }
        }
        for path in [
            "/name",
            "/names/",
            "/namesx",
            "/names/owners/",
            "/names/pins/a/b",
            "/names/accept/x",
            "/names/suggestions/",
            "/names/suggestions/a/b",
        ] {
            assert!(!is_names_path(path), "{path} must not be classified");
        }
    }

    #[test]
    fn forward_add_and_delete_require_durable_owner() {
        // ADR-0074 §1: POST /forwards resolves a peer name and pins it at
        // first use. DELETE /forwards/:local_addr removes the owner's
        // persisted record. Session and rider bearers must not reach
        // either. GET /forwards stays readable. Card import stays
        // session-reachable (contacts only; bind is gated in the handler).
        assert!(requires_durable_owner(&Method::POST, "/forwards"));
        assert!(requires_durable_owner(
            &Method::DELETE,
            "/forwards/127.0.0.1:8022"
        ));
        assert!(requires_durable_owner(
            &Method::DELETE,
            "/forwards/[::1]:8022"
        ));
        assert!(!requires_durable_owner(&Method::GET, "/forwards"));
        assert!(!requires_durable_owner(&Method::DELETE, "/forwards"));
        assert!(!requires_durable_owner(
            &Method::DELETE,
            "/forwards/127.0.0.1:8022/extra"
        ));
        assert!(!requires_durable_owner(&Method::POST, "/agent/card/import"));
    }

    #[test]
    fn gui_show_requires_durable_owner() {
        // #1392: David approved 22 Oct 2026 13:30 BST. POST /gui/show
        // requires the durable owner token. GET /gui stays a browser surface.
        assert!(requires_durable_owner(&Method::POST, "/gui/show"));
        assert!(!requires_durable_owner(&Method::GET, "/gui"));
        assert!(!requires_durable_owner(&Method::GET, "/gui/"));
        assert!(!requires_durable_owner(&Method::POST, "/gui"));
        assert!(!requires_durable_owner(&Method::GET, "/gui/show"));
    }
}
