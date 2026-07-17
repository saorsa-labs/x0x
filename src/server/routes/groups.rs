//! Route handlers (`category: "groups"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use crate as x0x;
use super::super::{
    api_error, bad_request, decode_base64_payload, not_found, parse_agent_id_hex,
    secure_group_effect_response_after_terminality_recheck,
};
use super::super::state::AppState;
use std::sync::Arc;
use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;

/// POST /mls/groups request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateMlsGroupRequest {
    /// Optional group ID as hex string. Random if omitted.
    pub(in crate::server) group_id: Option<String>,
}

/// POST /mls/groups/:id/members request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct AddMlsMemberRequest {
    /// Agent ID as 64-character hex string.
    pub(in crate::server) agent_id: String,
}

/// POST /mls/groups/:id/encrypt request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct MlsEncryptRequest {
    /// Base64-encoded plaintext.
    pub(in crate::server) payload: String,
}

/// POST /mls/groups/:id/decrypt request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct MlsDecryptRequest {
    /// Base64-encoded ciphertext.
    pub(in crate::server) ciphertext: String,
    /// Epoch used for encryption.
    pub(in crate::server) epoch: u64,
}

/// POST /mls/groups/:id/welcome request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct CreateWelcomeRequest {
    /// Invitee agent ID as hex string.
    pub(in crate::server) agent_id: String,
}

/// POST /mls/groups — create a new MLS group.
pub(in crate::server) async fn create_mls_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateMlsGroupRequest>,
) -> impl IntoResponse {
    let group_id_bytes = match req.group_id {
        Some(hex_str) => match hex::decode(&hex_str) {
            Ok(bytes) => bytes,
            Err(e) => {
                return bad_request(format!("invalid hex: {e}"));
            }
        },
        None => {
            let mut bytes = vec![0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes
        }
    };

    let agent_id = state.agent.agent_id();
    let group_id_hex = hex::encode(&group_id_bytes);

    match x0x::mls::MlsGroup::new(group_id_bytes, agent_id).await {
        Ok(group) => {
            let epoch = group.current_epoch();
            let members: Vec<String> = group
                .members()
                .keys()
                .map(|id| hex::encode(id.as_bytes()))
                .collect();

            state
                .mls_groups
                .write()
                .await
                .insert(group_id_hex.clone(), group);
            save_mls_groups(&state).await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "ok": true,
                    "group_id": group_id_hex,
                    "epoch": epoch,
                    "members": members
                })),
            )
        }
        Err(e) => {
            tracing::error!("operation failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// GET /mls/groups — list all MLS groups.
pub(in crate::server) async fn list_mls_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let groups = state.mls_groups.read().await;
    let entries: Vec<serde_json::Value> = groups
        .iter()
        .map(|(id, group)| {
            serde_json::json!({
                "group_id": id,
                "epoch": group.current_epoch(),
                "member_count": group.members().len()
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "groups": entries })),
    )
}

/// GET /mls/groups/:id — get details of a specific MLS group.
pub(in crate::server) async fn get_mls_group(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return not_found("group not found");
    };

    let members: Vec<String> = group
        .members()
        .keys()
        .map(|id| hex::encode(id.as_bytes()))
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "group_id": id,
            "epoch": group.current_epoch(),
            "members": members
        })),
    )
}

/// POST /mls/groups/:id/members — add a member to a group.
pub(in crate::server) async fn add_mls_member(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AddMlsMemberRequest>,
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

    let mut groups = state.mls_groups.write().await;
    let Some(group) = groups.get_mut(&id) else {
        return not_found("group not found");
    };

    // add_member() auto-applies the commit internally (increments epoch).
    // Do NOT call apply_commit() again — it would fail with epoch mismatch.
    match group.add_member(agent_id).await {
        Ok(_commit) => {
            let resp = (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "epoch": group.current_epoch(),
                    "member_count": group.members().len()
                })),
            );
            drop(groups);
            save_mls_groups(&state).await;
            resp
        }
        Err(e) => {
            tracing::error!("add_mls_member failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "operation failed")
        }
    }
}

/// DELETE /mls/groups/:id/members/:agent_id — remove a member from a group.
pub(in crate::server) async fn remove_mls_member(
    State(state): State<Arc<AppState>>,
    Path((id, agent_id_hex)): Path<(String, String)>,
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

    let mut groups = state.mls_groups.write().await;
    let Some(group) = groups.get_mut(&id) else {
        return not_found("group not found");
    };

    // remove_member() auto-applies the commit internally.
    match group.remove_member(agent_id).await {
        Ok(_commit) => {
            let resp = (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "epoch": group.current_epoch(),
                    "member_count": group.members().len()
                })),
            );
            drop(groups);
            save_mls_groups(&state).await;
            resp
        }
        Err(e) => {
            tracing::error!("remove_mls_member failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// POST /mls/groups/:id/encrypt — encrypt data with group key.
pub(in crate::server) async fn mls_encrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<MlsEncryptRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let plaintext = match decode_base64_payload(&req.payload) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return not_found("group not found");
    };

    let (cipher, epoch) = match make_mls_cipher(group) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    match cipher.encrypt(&plaintext, &[], epoch) {
        Ok(ciphertext) => {
            drop(groups);
            secure_group_effect_response_after_terminality_recheck(
                state.as_ref(),
                &id,
                Some(&id),
                serde_json::json!({
                "ok": true,
                "ciphertext": BASE64.encode(&ciphertext),
                "epoch": epoch
                }),
            )
            .await
        }
        Err(e) => {
            tracing::error!("mls_encrypt failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "encryption failed")
        }
    }
}

/// POST /mls/groups/:id/decrypt — decrypt data with group key.
pub(in crate::server) async fn mls_decrypt(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<MlsDecryptRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let ciphertext = match decode_base64_payload(&req.ciphertext) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return not_found("group not found");
    };

    let (cipher, _epoch) = match make_mls_cipher(group) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    match cipher.decrypt(&ciphertext, &[], req.epoch) {
        Ok(plaintext) => {
            drop(groups);
            secure_group_effect_response_after_terminality_recheck(
                state.as_ref(),
                &id,
                Some(&id),
                serde_json::json!({
                "ok": true,
                "payload": BASE64.encode(&plaintext)
                }),
            )
            .await
        }
        Err(e) => {
            tracing::error!("mls_decrypt failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "decryption failed")
        }
    }
}

// ---------------------------------------------------------------------------
// Agent discovery & connectivity handlers
// ---------------------------------------------------------------------------

/// POST /mls/groups/:id/welcome — generate a welcome message for a new member.
pub(in crate::server) async fn create_mls_welcome(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<CreateWelcomeRequest>,
) -> impl IntoResponse {
    let invitee = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let groups = state.mls_groups.read().await;
    let Some(group) = groups.get(&id) else {
        return not_found("group not found");
    };

    match x0x::mls::MlsWelcome::create(group, &invitee) {
        Ok(welcome) => {
            let welcome_bytes = match bincode::serialize(&welcome) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("welcome serialization failed: {e}");
                    return api_error(StatusCode::INTERNAL_SERVER_ERROR, "serialization failed");
                }
            };

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "welcome": BASE64.encode(&welcome_bytes),
                    "group_id": id,
                    "epoch": welcome.epoch()
                })),
            )
        }
        Err(e) => {
            tracing::error!("create_mls_welcome failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "welcome creation failed")
        }
    }
}

// ---------------------------------------------------------------------------
// Constitution handlers
// ---------------------------------------------------------------------------

/// Derive an MLS cipher from a group's current key schedule.
fn make_mls_cipher(
    group: &x0x::mls::MlsGroup,
) -> Result<(x0x::mls::MlsCipher, u64), (StatusCode, Json<serde_json::Value>)> {
    let key_schedule = x0x::mls::MlsKeySchedule::from_group(group).map_err(|e| {
        tracing::error!("MLS key derivation failed: {e}");
        api_error(StatusCode::INTERNAL_SERVER_ERROR, "key derivation failed")
    })?;
    let cipher = x0x::mls::MlsCipher::new(
        key_schedule.encryption_key().to_vec(),
        key_schedule.base_nonce().to_vec(),
    );
    Ok((cipher, group.current_epoch()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TreeKEM join-result and Welcome blob pull handling
// ---------------------------------------------------------------------------

/// MLS groups are session-scoped — no persistence (saorsa-mls groups not serializable).
pub(in crate::server) async fn save_mls_groups(_state: &AppState) {
    // MLS groups backed by saorsa-mls are not serializable.
    // They are recreated each session.
}
