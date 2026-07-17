//! Route handlers (`category: "exec"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use crate as x0x;
use super::super::{api_error, bad_request, parse_agent_id_hex};
use super::super::state::AppState;
use std::sync::Arc;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;

/// POST /exec/run request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct ExecRunRequest {
    /// Target agent ID as 64-character hex string.
    agent_id: String,
    /// Exact argv vector. Never interpreted by a shell.
    argv: Vec<String>,
    /// Optional base64 stdin payload.
    #[serde(default)]
    stdin_b64: Option<String>,
    /// Optional timeout in milliseconds. Remote ACL caps apply.
    #[serde(default)]
    timeout_ms: Option<u32>,
    /// Requester-controlled CWD is rejected in v1 unless future ACL support is added.
    #[serde(default)]
    cwd: Option<String>,
}

/// POST /exec/cancel request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct ExecCancelRequest {
    /// Request ID as 32 hex chars.
    request_id: String,
    /// Optional target agent ID. If omitted, the local pending-session table is used.
    #[serde(default)]
    agent_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Exec handlers
// ---------------------------------------------------------------------------

/// POST /exec/run — run a strictly allowlisted command on a remote daemon.
pub(in crate::server) async fn exec_run(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ExecRunRequest>,
) -> axum::response::Response {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
    };
    if req.argv.is_empty() {
        return bad_request("argv must not be empty").into_response();
    }
    let stdin = match req.stdin_b64.as_deref() {
        Some(encoded) => match BASE64.decode(encoded) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                return bad_request(format!("invalid stdin_b64: {e}")).into_response();
            }
        },
        None => None,
    };
    let options = x0x::exec::ExecRunOptions {
        argv: req.argv,
        stdin,
        timeout_ms: req.timeout_ms,
        cwd: req.cwd,
    };
    match state.exec_service.run_remote(agent_id, options).await {
        Ok(result) => {
            let denial_reason = result.denial_reason.map(|r| r.as_str());
            let warnings: Vec<&'static str> = result.warnings.iter().map(|w| w.as_str()).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "request_id": result.request_id.to_hex(),
                    "code": result.code,
                    "signal": result.signal,
                    "duration_ms": result.duration_ms,
                    "stdout_b64": BASE64.encode(&result.stdout),
                    "stderr_b64": BASE64.encode(&result.stderr),
                    "stdout_bytes_total": result.stdout_bytes_total,
                    "stderr_bytes_total": result.stderr_bytes_total,
                    "truncated": result.truncated,
                    "denial_reason": denial_reason,
                    "warnings": warnings,
                })),
            )
                .into_response()
        }
        Err(e) => {
            let status = match e {
                x0x::exec::service::ExecServiceError::Protocol(_) => StatusCode::BAD_REQUEST,
                x0x::exec::service::ExecServiceError::Timeout => StatusCode::GATEWAY_TIMEOUT,
                x0x::exec::service::ExecServiceError::ResponseChannelClosed => {
                    StatusCode::BAD_GATEWAY
                }
                x0x::exec::service::ExecServiceError::Transport(_)
                | x0x::exec::service::ExecServiceError::Denied(_) => StatusCode::BAD_GATEWAY,
            };
            (
                status,
                Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// POST /exec/cancel — cancel an in-flight exec request originated by this daemon.
pub(in crate::server) async fn exec_cancel(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ExecCancelRequest>,
) -> axum::response::Response {
    let request_id = match x0x::exec::ExecRequestId::from_hex(&req.request_id) {
        Ok(id) => id,
        Err(e) => {
            return bad_request(e.to_string()).into_response();
        }
    };
    let target = match req.agent_id.as_deref() {
        Some(agent_hex) => match parse_agent_id_hex(agent_hex) {
            Ok(id) => Some(id),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "ok": false, "error": e })),
                )
                    .into_response();
            }
        },
        None => None,
    };
    match state.exec_service.cancel_remote(request_id, target).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response(),
        Err(e) => api_error(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// GET /exec/sessions — list local pending client sessions and remote active sessions.
pub(in crate::server) async fn exec_sessions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.exec_service.sessions_snapshot().await)
}

/// GET /diagnostics/exec — exec counters, active sessions, and safe ACL summary.
pub(in crate::server) async fn exec_diagnostics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.exec_service.diagnostics_snapshot().await)
}
