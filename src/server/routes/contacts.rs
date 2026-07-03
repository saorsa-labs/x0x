//! Contact route handlers (`category: "contacts"`) for the x0x daemon:
//! `/contacts` CRUD, `/contacts/trust`, `/contacts/:agent_id/revoke`,
//! `/contacts/:agent_id/revocations`.
//!
//! Extracted verbatim from `server/mod.rs` (#125 / WS1.4 routes-1).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate as x0x;

use super::super::state::AppState;
use super::super::{not_found, parse_agent_id_hex};
use crate::contacts::{IdentityType, TrustLevel};

/// POST /contacts request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct AddContactRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
    /// Trust level: "blocked", "unknown", "known", or "trusted".
    /// Defaults to "known" when omitted.
    #[serde(default = "default_trust_level")]
    trust_level: String,
    /// Optional human-readable label.
    label: Option<String>,
}

pub(in crate::server) fn default_trust_level() -> String {
    "known".to_string()
}

/// PATCH /contacts/:agent_id request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct UpdateContactRequest {
    /// New trust level: "blocked", "unknown", "known", or "trusted".
    trust_level: Option<String>,
    /// New identity type: "anonymous", "known", "trusted", or "pinned".
    identity_type: Option<String>,
}

/// POST /contacts/trust request body (quick trust shorthand).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct QuickTrustRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
    /// Trust level: "blocked", "unknown", "known", or "trusted".
    level: String,
}

/// GET /contacts — list all contacts with trust levels.
pub(in crate::server) async fn list_contacts(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let store = state.contacts.read().await;
    let entries: Vec<ContactEntry> = store
        .list()
        .into_iter()
        .map(|c| ContactEntry {
            agent_id: hex::encode(c.agent_id.0),
            trust_level: c.trust_level.to_string(),
            label: c.label.clone(),
            added_at: c.added_at,
            last_seen: c.last_seen,
        })
        .collect();
    Json(serde_json::json!({ "ok": true, "contacts": entries }))
}

/// POST /contacts — add a new contact.
pub(in crate::server) async fn add_contact(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddContactRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let trust_level: TrustLevel = match req.trust_level.parse() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let contact = x0x::contacts::Contact {
        agent_id,
        trust_level,
        label: req.label,
        added_at: now,
        last_seen: None,
        identity_type: x0x::contacts::IdentityType::default(),
        machines: Vec::new(),
        dm_capabilities: None,
    };

    state.contacts.write().await.add(contact);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "ok": true, "agent_id": hex::encode(agent_id.0) })),
    )
}

/// PATCH /contacts/:agent_id — update trust level and/or identity type for a contact.
pub(in crate::server) async fn update_contact(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    Json(req): Json<UpdateContactRequest>,
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

    let mut store = state.contacts.write().await;

    if let Some(ref tl_str) = req.trust_level {
        let trust_level: TrustLevel = match tl_str.parse() {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "ok": false, "error": e })),
                );
            }
        };
        store.set_trust(&agent_id, trust_level);
    }

    if let Some(ref it_str) = req.identity_type {
        let identity_type: IdentityType = match it_str.parse() {
            Ok(t) => t,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "ok": false, "error": e })),
                );
            }
        };
        store.set_identity_type(&agent_id, identity_type);
    }

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// DELETE /contacts/:agent_id — remove a contact.
pub(in crate::server) async fn delete_contact(
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

    let removed = state.contacts.write().await.remove(&agent_id);
    if removed.is_some() {
        (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
    } else {
        not_found("contact not found")
    }
}

/// POST /contacts/trust — quick trust shorthand.
pub(in crate::server) async fn quick_trust(
    State(state): State<Arc<AppState>>,
    Json(req): Json<QuickTrustRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let trust_level: TrustLevel = match req.level.parse() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    state
        .contacts
        .write()
        .await
        .set_trust(&agent_id, trust_level);

    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// POST /contacts/:agent_id/revoke — permanently revoke an agent's key.
pub(in crate::server) async fn revoke_contact(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    Json(req): Json<RevokeContactRequest>,
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

    let mut store = state.contacts.write().await;
    store.revoke(&agent_id, &req.reason);
    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// GET /contacts/:agent_id/revocations — list revocation records.
pub(in crate::server) async fn list_revocations(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let store = state.contacts.read().await;
    let revocations: Vec<serde_json::Value> = store
        .revocations()
        .iter()
        .map(|r| {
            serde_json::json!({
                "agent_id": hex::encode(r.agent_id.0),
                "reason": r.reason,
                "timestamp": r.timestamp,
                "revoker_id": r.revoker_id.map(|id| hex::encode(id.0))
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "revocations": revocations })),
    )
}

/// Contact entry for API responses.
#[derive(Debug, Serialize)]
pub(in crate::server) struct ContactEntry {
    agent_id: String,
    trust_level: String,
    label: Option<String>,
    added_at: u64,
    last_seen: Option<u64>,
}

/// POST /contacts/:agent_id/revoke request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct RevokeContactRequest {
    /// Reason for revocation.
    reason: String,
}
