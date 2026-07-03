//! Machine route handlers (`category: "machines"`) for the x0x daemon:
//! `/machines/discovered`, `/users/:user_id/machines`,
//! `/contacts/:agent_id/machines` CRUD and pin/unpin.
//!
//! Extracted verbatim from `server/mod.rs` (#125 / WS1.4 routes-1).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate as x0x;

use super::super::state::AppState;
use super::super::{
    api_error, bad_request, discovered_machine_entry, not_found, parse_agent_id_hex,
    parse_machine_id_hex, DiscoveredAgentQuery, DiscoveredAgentsQuery, DiscoveredMachineEntry,
};
use crate::contacts::MachineRecord;
use crate::identity::MachineId;

/// POST /contacts/:agent_id/machines request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct AddMachineRequest {
    /// Machine ID as 64-character hex string.
    machine_id: String,
    /// Optional human-readable label.
    label: Option<String>,
    /// Whether to pin this machine immediately.
    #[serde(default)]
    pinned: bool,
}

/// Machine record entry for API responses.
#[derive(Debug, Serialize)]
pub(in crate::server) struct MachineEntry {
    machine_id: String,
    label: Option<String>,
    first_seen: u64,
    last_seen: u64,
    pinned: bool,
}

/// GET /machines/discovered
pub(in crate::server) async fn discovered_machines(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DiscoveredAgentsQuery>,
) -> impl IntoResponse {
    let result = if query.unfiltered {
        state.agent.discovered_machines_unfiltered().await
    } else {
        state.agent.discovered_machines().await
    };
    match result {
        Ok(machines) => {
            let entries: Vec<DiscoveredMachineEntry> =
                machines.into_iter().map(discovered_machine_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "machines": entries })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /machines/discovered/:machine_id
pub(in crate::server) async fn discovered_machine(
    State(state): State<Arc<AppState>>,
    Path(machine_id_hex): Path<String>,
    Query(params): Query<DiscoveredAgentQuery>,
) -> impl IntoResponse {
    let machine_id = match parse_machine_id_hex(&machine_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    if params.wait {
        match state.agent.find_machine(machine_id, 10).await {
            Ok(Some(machine)) => {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "ok": true,
                        "machine": discovered_machine_entry(machine),
                    })),
                );
            }
            Ok(None) => {
                return not_found("machine not found within timeout");
            }
            Err(e) => {
                return api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}"));
            }
        }
    }

    match state.agent.discovered_machine(machine_id).await {
        Ok(Some(machine)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "machine": discovered_machine_entry(machine),
            })),
        ),
        Ok(None) => not_found("machine not found"),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /users/:user_id/machines
pub(in crate::server) async fn machines_by_user_handler(
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
    match state.agent.find_machines_by_user(user_id).await {
        Ok(machines) => {
            let entries: Vec<DiscoveredMachineEntry> =
                machines.into_iter().map(discovered_machine_entry).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "user_id": user_id_hex,
                    "machines": entries,
                })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /contacts/:agent_id/machines — list machine records for a contact.
pub(in crate::server) async fn list_machines(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
    };

    let store = state.contacts.read().await;
    let entries: Vec<MachineEntry> = store
        .machines(&agent_id)
        .iter()
        .map(|m| MachineEntry {
            machine_id: hex::encode(m.machine_id.0),
            label: m.label.clone(),
            first_seen: m.first_seen,
            last_seen: m.last_seen,
            pinned: m.pinned,
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "machines": entries })),
    )
        .into_response()
}

/// POST /contacts/:agent_id/machines — add a machine record for a contact.
pub(in crate::server) async fn add_machine(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    Json(req): Json<AddMachineRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
    };

    let machine_bytes = match hex::decode(&req.machine_id) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return bad_request("machine_id must be a 64-character hex string").into_response();
        }
    };
    let machine_id = MachineId(machine_bytes);

    let record = MachineRecord::new(machine_id, req.label.clone());
    let mut store = state.contacts.write().await;
    let is_new = store.add_machine(&agent_id, record);

    if req.pinned {
        store.pin_machine(&agent_id, &machine_id);
    }

    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let entry = MachineEntry {
        machine_id: hex::encode(machine_id.0),
        label: req.label,
        first_seen: store
            .machines(&agent_id)
            .iter()
            .find(|m| m.machine_id == machine_id)
            .map(|m| m.first_seen)
            .unwrap_or(0),
        last_seen: store
            .machines(&agent_id)
            .iter()
            .find(|m| m.machine_id == machine_id)
            .map(|m| m.last_seen)
            .unwrap_or(0),
        pinned: req.pinned,
    };

    (
        status,
        Json(serde_json::json!({ "ok": true, "machine": entry })),
    )
        .into_response()
}

/// DELETE /contacts/:agent_id/machines/:machine_id — remove a machine record.
pub(in crate::server) async fn delete_machine(
    State(state): State<Arc<AppState>>,
    Path((agent_id_hex, machine_id_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&agent_id_hex) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            )
                .into_response();
        }
    };

    let machine_bytes = match hex::decode(&machine_id_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return bad_request("machine_id must be a 64-character hex string").into_response();
        }
    };
    let machine_id = MachineId(machine_bytes);

    let removed = state
        .contacts
        .write()
        .await
        .remove_machine(&agent_id, &machine_id);
    if removed {
        (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
    } else {
        not_found("machine not found").into_response()
    }
}

/// POST /contacts/:agent_id/machines/:machine_id/pin — pin a machine for identity verification.
pub(in crate::server) async fn pin_machine(
    State(state): State<Arc<AppState>>,
    Path((agent_id_hex, machine_id_hex)): Path<(String, String)>,
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

    let machine_bytes = match hex::decode(&machine_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return bad_request("invalid machine_id hex");
        }
    };
    let machine_id = MachineId(machine_bytes);

    let mut store = state.contacts.write().await;
    let pinned = store.pin_machine(&agent_id, &machine_id);

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "pinned": pinned })),
    )
}

/// DELETE /contacts/:agent_id/machines/:machine_id/pin — unpin a machine.
pub(in crate::server) async fn unpin_machine(
    State(state): State<Arc<AppState>>,
    Path((agent_id_hex, machine_id_hex)): Path<(String, String)>,
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

    let machine_bytes = match hex::decode(&machine_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return bad_request("invalid machine_id hex");
        }
    };
    let machine_id = MachineId(machine_bytes);

    let mut store = state.contacts.write().await;
    let unpinned = store.unpin_machine(&agent_id, &machine_id);

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "unpinned": unpinned })),
    )
}
