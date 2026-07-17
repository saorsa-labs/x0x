//! Route handlers (`category: "presence"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use crate as x0x;
use super::super::{api_error, bad_request};
use super::super::state::AppState;
use super::discovery::discovered_agent_entry;
use std::sync::Arc;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

/// Query parameters for presence endpoints that accept TTL and timeout.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct PresenceQueryParams {
    /// FOAF hop count (default: 3).
    #[serde(default = "default_foaf_ttl")]
    ttl: u8,
    /// Query timeout in milliseconds (default: 5000).
    #[serde(default = "default_foaf_timeout_ms")]
    timeout_ms: u64,
}

fn default_foaf_ttl() -> u8 {
    3
}

fn default_foaf_timeout_ms() -> u64 {
    5000
}

/// GET /presence
pub(in crate::server) async fn presence(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.presence().await {
        Ok(agents) => {
            let entries: Vec<String> = agents.iter().map(|a| hex::encode(a.as_bytes())).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "agents": entries })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /presence/online
///
/// List all agents currently online (network view: all non-blocked agents from
/// the local discovery cache).
pub(in crate::server) async fn presence_online(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.online_agents().await {
        Ok(agents) => {
            let contacts = state.agent.contacts().read().await;
            let filtered = x0x::presence::filter_by_trust(
                agents,
                &contacts,
                x0x::presence::PresenceVisibility::Network,
            );
            let entries: Vec<_> = filtered.into_iter().map(discovered_agent_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "agents": entries })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /presence/foaf?ttl=3&timeout_ms=5000
///
/// FOAF random-walk discovery of nearby agents (social view: Trusted + Known only).
pub(in crate::server) async fn presence_foaf(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PresenceQueryParams>,
) -> impl IntoResponse {
    match state
        .agent
        .discover_agents_foaf(params.ttl, params.timeout_ms)
        .await
    {
        Ok(agents) => {
            let contacts = state.agent.contacts().read().await;
            let filtered = x0x::presence::filter_by_trust(
                agents,
                &contacts,
                x0x::presence::PresenceVisibility::Social,
            );
            let entries: Vec<_> = filtered.into_iter().map(discovered_agent_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "agents": entries })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /presence/find/:id?ttl=3&timeout_ms=5000
///
/// Find a specific agent by hex-encoded AgentId via FOAF random walk.
pub(in crate::server) async fn presence_find(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<PresenceQueryParams>,
) -> impl IntoResponse {
    let bytes = match hex::decode(&id) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return bad_request("invalid agent id (expected 64 hex chars)");
        }
    };
    let agent_id = x0x::identity::AgentId(bytes);
    match state
        .agent
        .discover_agent_by_id(agent_id, params.ttl, params.timeout_ms)
        .await
    {
        Ok(Some(agent)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "agent": discovered_agent_entry(agent) })),
        ),
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "agent": null })),
        ),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /presence/status/:id
///
/// Local cache lookup for a specific agent — no network I/O.
pub(in crate::server) async fn presence_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let bytes = match hex::decode(&id) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return bad_request("invalid agent id (expected 64 hex chars)");
        }
    };
    let agent_id = x0x::identity::AgentId(bytes);
    let cached = state.agent.cached_agent(&agent_id).await;
    let online = cached.is_some();
    let entry = cached.map(discovered_agent_entry);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "online": online, "agent": entry })),
    )
}
