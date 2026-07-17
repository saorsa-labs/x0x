//! Route handlers (`category: "connect"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use crate as x0x;
use super::super::api_error;
use super::super::state::AppState;
use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

// ── Tailnet forwarding (#132 T6) ──────────────────────────────────────────

/// POST /forwards — register a local port forward.
#[derive(serde::Deserialize)]
pub(in crate::server) struct ForwardAddRequest {
    /// Local bind, e.g. `127.0.0.1:8022`.
    local_addr: String,
    /// Peer agent id (hex).
    peer_agent: String,
    /// Loopback target host on the peer (numeric IP).
    target_host: String,
    /// Loopback target port.
    target_port: u16,
}

pub(in crate::server) async fn forward_add(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ForwardAddRequest>,
) -> impl IntoResponse {
    use x0x::forward::ForwardSpec;
    use x0x::identity::AgentId;
    let Some(forwarder) = state.forward_service.as_ref() else {
        return api_error(
            StatusCode::CONFLICT,
            "connect forwarding is disabled (no connect ACL loaded)".to_string(),
        )
        .into_response();
    };
    let local_addr: SocketAddr = match req.local_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            return api_error(StatusCode::BAD_REQUEST, format!("local_addr: {e}")).into_response()
        }
    };
    if !local_addr.ip().is_loopback() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "local_addr must be loopback (Phase 1)".to_string(),
        )
        .into_response();
    }
    let peer_agent_bytes = match x0x::exec::acl::parse_agent_id(&req.peer_agent) {
        Ok(id) => id,
        Err(e) => {
            return api_error(StatusCode::BAD_REQUEST, format!("peer_agent: {e}")).into_response()
        }
    };
    let spec = ForwardSpec {
        local_addr,
        peer_agent: peer_agent_bytes,
        target_host: req.target_host,
        target_port: req.target_port,
    };
    let peer_agent: AgentId = spec.peer_agent;
    match forwarder.add_forward(spec).await {
        Ok(bound) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "local_addr": bound.to_string(),
                "peer_agent": hex::encode(peer_agent.as_bytes()),
            })),
        )
            .into_response(),
        Err(e) => api_error(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// GET /forwards — list registered forwards.
pub(in crate::server) async fn forward_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let forwards: Vec<serde_json::Value> = state
        .forward_service
        .as_ref()
        .map(|f| {
            f.list_forwards()
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "local_addr": s.local_addr.to_string(),
                        "peer_agent": s.peer_agent_hex(),
                        "target_host": s.target_host,
                        "target_port": s.target_port,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "forwards": forwards })),
    )
}

/// DELETE /forwards/:local_addr — tear down a forward by its local bind addr.
pub(in crate::server) async fn forward_remove(
    State(state): State<Arc<AppState>>,
    Path(local_addr): Path<String>,
) -> impl IntoResponse {
    let Some(forwarder) = state.forward_service.as_ref() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "ok": false, "removed": false })),
        );
    };
    let Ok(addr): Result<SocketAddr, _> = local_addr.parse() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "removed": false })),
        );
    };
    let removed = forwarder.remove_forward(addr);
    let status = if removed {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    (
        status,
        Json(serde_json::json!({ "ok": removed, "removed": removed })),
    )
}

/// GET /streams — active forward-stream count + connect-ACL counters.
pub(in crate::server) async fn streams_diagnostics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (active, connect_failed) = state
        .forward_service
        .as_ref()
        .map(|f| {
            (
                f.diagnostics().active_streams(),
                f.diagnostics().connect_failed(),
            )
        })
        .unwrap_or((0, 0));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active_streams": active,
            "connect_failed": connect_failed,
            "connect": state.connect_diagnostics.snapshot(),
        })),
    )
}

/// GET /diagnostics/connect — connect-ACL policy summary and stream counters.
///
/// Returns the [`x0x::connect::ConnectDiagnosticsSnapshot`]: enabled flag,
/// loaded-from path, allow-entry count, cumulative allow/deny counters, and
/// per-reason denial breakdown. Counters reflect live forwards when connect
/// is enabled (forwarder shipped in #183) and read 0 when it is disabled; the
/// ACL summary is always populated.
pub(in crate::server) async fn connect_diagnostics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.connect_diagnostics.snapshot())
}
