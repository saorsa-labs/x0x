//! Route handlers (`category: "discovery"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::state::AppState;
use super::super::{api_error, bad_request, not_found, parse_agent_id_hex};
use crate as x0x;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Discovered identity entry from gossip announcements.
#[derive(Debug, Serialize)]
pub(in crate::server) struct DiscoveredAgentEntry {
    pub(in crate::server) agent_id: String,
    pub(in crate::server) machine_id: String,
    pub(in crate::server) user_id: Option<String>,
    pub(in crate::server) addresses: Vec<String>,
    pub(in crate::server) announced_at: u64,
    pub(in crate::server) last_seen: u64,
}

/// Discovered machine endpoint entry from machine announcements.
#[derive(Debug, Serialize)]
pub(in crate::server) struct DiscoveredMachineEntry {
    pub(in crate::server) machine_id: String,
    pub(in crate::server) addresses: Vec<String>,
    pub(in crate::server) announced_at: u64,
    pub(in crate::server) last_seen: u64,
    pub(in crate::server) nat_type: Option<String>,
    pub(in crate::server) can_receive_direct: Option<bool>,
    pub(in crate::server) is_relay: Option<bool>,
    pub(in crate::server) is_coordinator: Option<bool>,
    pub(in crate::server) agent_ids: Vec<String>,
    pub(in crate::server) user_ids: Vec<String>,
}

/// GET /agents/discovered
/// Query parameters for `GET /agents/discovered`.
#[derive(Deserialize, Default)]
pub(in crate::server) struct DiscoveredAgentsQuery {
    /// When `true`, return all cache entries including stale (TTL-expired).
    #[serde(default)]
    pub(in crate::server) unfiltered: bool,
}

/// Query parameters for `GET /agents/discovered/:agent_id`.
#[derive(Deserialize, Default)]
pub(in crate::server) struct DiscoveredAgentQuery {
    /// When `true`, wait up to 10 s for the agent to announce on its shard
    /// topic before returning `404`. Useful for finding agents that joined
    /// recently and may not be in cache yet.
    #[serde(default)]
    pub(in crate::server) wait: bool,
}

pub(in crate::server) fn discovered_agent_entry(
    agent: x0x::DiscoveredAgent,
) -> DiscoveredAgentEntry {
    DiscoveredAgentEntry {
        agent_id: hex::encode(agent.agent_id.as_bytes()),
        machine_id: hex::encode(agent.machine_id.as_bytes()),
        user_id: agent.user_id.map(|id| hex::encode(id.as_bytes())),
        addresses: agent.addresses.into_iter().map(|a| a.to_string()).collect(),
        announced_at: agent.announced_at,
        last_seen: agent.last_seen,
    }
}

pub(in crate::server) fn discovered_machine_entry(
    machine: x0x::DiscoveredMachine,
) -> DiscoveredMachineEntry {
    DiscoveredMachineEntry {
        machine_id: hex::encode(machine.machine_id.as_bytes()),
        addresses: machine
            .addresses
            .into_iter()
            .map(|a| a.to_string())
            .collect(),
        announced_at: machine.announced_at,
        last_seen: machine.last_seen,
        nat_type: machine.nat_type,
        can_receive_direct: machine.can_receive_direct,
        is_relay: machine.is_relay,
        is_coordinator: machine.is_coordinator,
        agent_ids: machine
            .agent_ids
            .into_iter()
            .map(|id| hex::encode(id.as_bytes()))
            .collect(),
        user_ids: machine
            .user_ids
            .into_iter()
            .map(|id| hex::encode(id.as_bytes()))
            .collect(),
    }
}

pub(in crate::server) async fn discovered_agents(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DiscoveredAgentsQuery>,
) -> impl IntoResponse {
    let result = if query.unfiltered {
        state.agent.discovered_agents_unfiltered().await
    } else {
        state.agent.discovered_agents().await
    };
    match result {
        Ok(agents) => {
            let entries: Vec<DiscoveredAgentEntry> =
                agents.into_iter().map(discovered_agent_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "agents": entries })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /agents/discovered/:agent_id[?wait=true]
pub(in crate::server) async fn discovered_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    Query(params): Query<DiscoveredAgentQuery>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    if params.wait {
        // Active lookup: subscribe to agent's shard, wait up to 10 s.
        match state.agent.find_agent(agent_id).await {
            Ok(Some(addrs)) => {
                // Return the full discovered_agent entry if available, else
                // synthesise a minimal response from the address list.
                return match state.agent.discovered_agent(agent_id).await {
                    Ok(Some(agent)) => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "ok": true,
                            "agent": discovered_agent_entry(agent),
                        })),
                    ),
                    _ => (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "ok": true,
                            "agent": {
                                "agent_id": agent_id_hex,
                                "addresses": addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                            }
                        })),
                    ),
                };
            }
            Ok(None) => {
                return not_found("agent not found within timeout");
            }
            Err(e) => {
                return api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}"));
            }
        }
    }

    match state.agent.discovered_agent(agent_id).await {
        Ok(Some(agent)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "agent": discovered_agent_entry(agent),
            })),
        ),
        Ok(None) => not_found("agent not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /agents/:agent_id/machine
pub(in crate::server) async fn machine_for_agent_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    match state.agent.machine_for_agent(agent_id).await {
        Ok(Some(machine)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "agent_id": agent_id_hex,
                "machine": discovered_machine_entry(machine),
            })),
        ),
        Ok(None) => not_found("agent machine not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /users/:user_id/agents
pub(in crate::server) async fn agents_by_user_handler(
    State(state): State<Arc<AppState>>,
    Path(user_id_hex): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user_id_bytes = match hex::decode(&user_id_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return bad_request("invalid user_id: expected 64 hex characters");
        }
    };
    let user_id = x0x::identity::UserId(user_id_bytes);
    match state.agent.find_agents_by_user(user_id).await {
        Ok(agents) => {
            let entries: Vec<DiscoveredAgentEntry> =
                agents.into_iter().map(discovered_agent_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "user_id": user_id_hex,
                    "agents": entries,
                })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

// ---------------------------------------------------------------------------
// Contact handlers
// ---------------------------------------------------------------------------

/// POST /agents/find/:agent_id — actively search for an agent (3-stage: cache → shard → rendezvous).
pub(in crate::server) async fn find_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    match state.agent.find_agent(agent_id).await {
        Ok(Some(addrs)) => {
            let addr_strs: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "found": true, "addresses": addr_strs })),
            )
        }
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "found": false })),
        ),
        Err(e) => {
            tracing::error!("find_agent failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "search failed")
        }
    }
}

/// GET /agents/reachability/:agent_id — check reachability before connecting.
pub(in crate::server) async fn agent_reachability(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    match state.agent.reachability(&agent_id).await {
        Some(info) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "likely_direct": info.likely_direct(),
                "needs_coordination": info.needs_coordination(),
                "is_relay": info.is_relay(),
                "is_coordinator": info.is_coordinator(),
                "addresses": info.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>()
            })),
        ),
        None => not_found("agent not in discovery cache"),
    }
}

// ---------------------------------------------------------------------------
// Contact trust extension handlers
// ---------------------------------------------------------------------------
