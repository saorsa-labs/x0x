//! ADR-0039 owner routes: sub-agent registry issuance/revocation and the
//! rider-token lifecycle.
//!
//! - `POST /owner/agents/issue` — the owner key signs an
//!   [`AgentCertificate`] over a harness-submitted agent PUBLIC key. The
//!   daemon never sees the secret (gapcheck blocker 20); the record
//!   lands in the ADR-0036 issuance journal with `mode=acp|rider` and an
//!   optional label, and the full certificate bytes are retained so a
//!   later revocation can present the exact ADR-0018 authority evidence.
//! - `DELETE /owner/agents/:id` — ADR-0018 issuer-revocation: the owner
//!   key signs a `RevokedSubject::Agent` record carrying the retained
//!   certificate, then every rider token bound to that agent is revoked.
//! - `POST /owner/riders` / `GET /owner/riders` /
//!   `DELETE /owner/riders/:id` — rider-token lifecycle (blocker 24):
//!   hashed at rest, expiring, revocable, per registered sub-agent.
//!
//! All five are owner-only by construction: the deny-by-default rider
//! predicate in the auth middleware returns `403` for riders on every
//! `/owner/*` route before any handler runs.

use super::super::state::AppState;
use super::super::{api_error, parse_agent_id_hex};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Deserialize;
use std::sync::Arc;

use crate::profile::{CertMode, IssuedCertRecord};

/// Request body for `POST /owner/agents/issue`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct IssueAgentRequest {
    /// Hex ML-DSA-65 PUBLIC key of the harness-generated agent keypair.
    /// The secret never leaves the harness.
    agent_public_key: String,
    /// Hosting mode: `"acp"` (default) or `"rider"`.
    #[serde(default)]
    mode: Option<String>,
    /// Optional operator label for the roster.
    #[serde(default)]
    label: Option<String>,
    /// Optional certificate expiry (unix seconds).
    #[serde(default)]
    not_after: Option<u64>,
}

/// POST /owner/agents/issue — certify a harness-owned sub-agent key.
///
/// `409` without an owner key; `400` for a malformed key or mode. The
/// journal append is part of the request contract (this endpoint IS the
/// registry writer), so a failed append fails the request.
pub(in crate::server) async fn owner_agents_issue(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IssueAgentRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(user_kp) = state.agent.identity().user_keypair() else {
        return owner_missing();
    };
    let mode = match req.mode.as_deref() {
        None | Some("acp") => CertMode::Acp,
        Some("rider") => CertMode::Rider,
        Some(other) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                format!("unknown mode {other:?} (expected 'acp' or 'rider')"),
            );
        }
    };
    let key_bytes = match hex::decode(req.agent_public_key.trim()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "agent_public_key must be hex-encoded ML-DSA-65 public key bytes",
            );
        }
    };
    let cert = match crate::identity::AgentCertificate::issue_for_public_key(
        user_kp,
        &key_bytes,
        req.not_after,
    ) {
        Ok(cert) => cert,
        Err(e) => {
            return api_error(StatusCode::BAD_REQUEST, format!("issuance rejected: {e}"));
        }
    };
    let agent_hex = hex::encode(
        cert.agent_id()
            .map_or_else(|_| [0u8; 32], |id| *id.as_bytes()),
    );
    let owner = user_kp.user_id();

    let record = IssuedCertRecord::from_cert_with_mode(&owner, &cert, mode, req.label.clone());
    let Some(record) = record else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to build issuance journal record",
        );
    };
    let Some(journal_path) = state
        .agent
        .cert_journal_path()
        .map(std::path::Path::to_path_buf)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no certificate journal configured for this install",
        );
    };
    if let Err(e) = IssuedCertRecord::append(&journal_path, &record).await {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to append issuance journal: {e}"),
        );
    }

    let storage_b64 = cert
        .to_storage_bytes()
        .map(|bytes| BASE64.encode(bytes))
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "agent_id": agent_hex,
            "mode": match mode { CertMode::Acp => "acp", CertMode::Rider => "rider" },
            "label": req.label,
            "certificate": {
                "agent_public_key": hex::encode(&key_bytes),
                "user_public_key": hex::encode(cert.user_public_key_bytes()),
                "issued_at": cert.issued_at(),
                "not_after": cert.not_after(),
                "signature": hex::encode(cert.signature_bytes()),
                "storage_b64": storage_b64,
            },
        })),
    )
}

/// The shared `409` body for owner-less installs.
fn owner_missing() -> (StatusCode, Json<serde_json::Value>) {
    api_error(
        StatusCode::CONFLICT,
        "no owner: this daemon has no user identity (run `x0x user-id create`)",
    )
}

/// Request body for `DELETE /owner/agents/:id`.
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct RevokeAgentRequest {
    #[serde(default)]
    reason: Option<String>,
}

/// DELETE /owner/agents/:id — revoke a registered sub-agent (ADR-0018
/// issuer-revocation path).
///
/// The owner key signs a revocation for `RevokedSubject::Agent(target)`
/// with the retained certificate as the authority evidence; the record
/// persists to `revocations.bin` and gossips exactly like any other
/// revocation. All rider tokens bound to the agent are revoked in the
/// same stroke. `404` when the agent is not on this owner's journal;
/// `409` when no retained certificate exists (e.g. the daemon's own
/// agent — use `/identity/revoke` — or pre-ADR-0039 lines).
pub(in crate::server) async fn owner_agents_revoke(
    State(state): State<Arc<AppState>>,
    Path(agent_id_hex): Path<String>,
    body: Option<Json<RevokeAgentRequest>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(user_kp) = state.agent.identity().user_keypair() else {
        return owner_missing();
    };
    let Ok(agent_id) = parse_agent_id_hex(&agent_id_hex) else {
        return api_error(StatusCode::BAD_REQUEST, "agent id must be 64 hex chars");
    };
    let owner_hex = hex::encode(user_kp.user_id().as_bytes());
    let target_hex = hex::encode(agent_id.as_bytes());

    // Locate the newest retained certificate for this agent on this
    // owner's journal.
    let Some(journal_path) = state
        .agent
        .cert_journal_path()
        .map(std::path::Path::to_path_buf)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no certificate journal configured for this install",
        );
    };
    let records = IssuedCertRecord::load(&journal_path).await;
    let mut on_roster = false;
    let mut retained: Option<IssuedCertRecord> = None;
    for record in records {
        if record.user_id != owner_hex || record.agent_id != target_hex {
            continue;
        }
        on_roster = true;
        if record.cert_b64.is_some()
            && retained
                .as_ref()
                .is_none_or(|best| record.issued_at >= best.issued_at)
        {
            retained = Some(record);
        }
    }
    if !on_roster {
        return api_error(
            StatusCode::NOT_FOUND,
            "agent is not on this owner's issuance journal",
        );
    }
    let Some(record) = retained else {
        return api_error(
            StatusCode::CONFLICT,
            "no retained certificate for this agent — issuer revocation requires the exact certificate (agent.cert holders: use /identity/revoke)",
        );
    };
    let Some(cert_bytes) = record
        .cert_b64
        .as_deref()
        .and_then(|b64| BASE64.decode(b64).ok())
    else {
        return api_error(
            StatusCode::CONFLICT,
            "retained certificate bytes are unreadable",
        );
    };
    let cert = match crate::identity::AgentCertificate::from_storage_bytes(&cert_bytes) {
        Ok(cert) => cert,
        Err(e) => {
            return api_error(
                StatusCode::CONFLICT,
                format!("retained certificate does not decode: {e}"),
            );
        }
    };
    let cert_valid = cert.verify().is_ok()
        && cert.user_id().is_ok_and(|uid| uid == user_kp.user_id())
        && cert.agent_id().is_ok_and(|aid| aid == agent_id);
    if !cert_valid {
        return api_error(
            StatusCode::CONFLICT,
            "retained certificate fails verification against the owner and target agent",
        );
    }

    let reason = body.and_then(|Json(req)| req.reason);
    if let Err(e) = state.agent.revoke_as_owner(&cert, reason).await {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("owner revocation failed: {e}"),
        );
    }
    let rider_tokens_revoked = state
        .rider_tokens
        .lock()
        .await
        .revoke_for_agent(&target_hex, crate::server::rider_auth::unix_now_secs())
        .await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "agent_id": target_hex,
            "revoked": true,
            "rider_tokens_revoked": rider_tokens_revoked,
        })),
    )
}

/// Request body for `POST /owner/riders`.
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct IssueRiderRequest {
    /// Hex AgentId of a registered `mode=rider` sub-agent.
    sub_agent_id: String,
    /// Explicitly granted named-group ids (Home is always granted).
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    label: Option<String>,
    /// Token lifetime in seconds (default 7 days, max 90 days).
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// POST /owner/riders — issue a scoped rider token for a registered
/// rider-mode sub-agent (blocker 24 lifecycle).
///
/// The token secret is returned exactly once; only its SHA-256 hash is
/// stored. `404` when the sub-agent is not registered in rider mode;
/// `409` when it has been revoked.
pub(in crate::server) async fn owner_riders_issue(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IssueRiderRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(user_kp) = state.agent.identity().user_keypair() else {
        return owner_missing();
    };
    let Ok(sub_agent) = parse_agent_id_hex(req.sub_agent_id.trim()) else {
        return api_error(StatusCode::BAD_REQUEST, "sub_agent_id must be 64 hex chars");
    };
    let target_hex = hex::encode(sub_agent.as_bytes());
    let owner_hex = hex::encode(user_kp.user_id().as_bytes());

    let Some(journal_path) = state
        .agent
        .cert_journal_path()
        .map(std::path::Path::to_path_buf)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no certificate journal configured for this install",
        );
    };
    let mut registered_rider = false;
    for record in IssuedCertRecord::load(&journal_path).await {
        if record.user_id == owner_hex
            && record.agent_id == target_hex
            && record.mode == CertMode::Rider
        {
            registered_rider = true;
        }
    }
    if !registered_rider {
        return api_error(
            StatusCode::NOT_FOUND,
            "sub_agent_id is not a registered rider-mode agent (POST /owner/agents/issue first)",
        );
    }
    if state
        .agent
        .revocation_records()
        .await
        .iter()
        .any(|record| record.subject_kind() == "agent" && record.subject_hex() == target_hex)
    {
        return api_error(StatusCode::CONFLICT, "sub-agent is revoked");
    }

    // Normalize the group grant list: dedupe in order, bounded.
    let mut groups: Vec<String> = Vec::new();
    for group in req.groups {
        let group = group.trim().to_string();
        if group.is_empty() || group.len() > 128 {
            return api_error(
                StatusCode::BAD_REQUEST,
                "group ids must be 1-128 chars, non-empty after trimming",
            );
        }
        if !groups.contains(&group) {
            groups.push(group);
        }
        if groups.len() > crate::server::rider_auth::RIDER_MAX_GROUPS {
            return api_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "at most {} groups may be granted per rider token",
                    crate::server::rider_auth::RIDER_MAX_GROUPS
                ),
            );
        }
    }
    let ttl = req
        .ttl_secs
        .unwrap_or(crate::server::rider_auth::RIDER_DEFAULT_TTL_SECS)
        .clamp(1, crate::server::rider_auth::RIDER_MAX_TTL_SECS);

    let now = crate::server::rider_auth::unix_now_secs();
    let issued = state
        .rider_tokens
        .lock()
        .await
        .issue(
            target_hex.clone(),
            groups.clone(),
            req.label.clone(),
            ttl,
            now,
        )
        .await;
    let (token, record) = match issued {
        Ok(issued) => issued,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to persist rider token: {e}"),
            );
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            // One-time secret: never retrievable again.
            "token": token,
            "token_id": record.token_id,
            "sub_agent_id": target_hex,
            "groups": groups,
            "label": req.label,
            "issued_at_unix": record.issued_at,
            "expires_at_unix": record.expires_at,
        })),
    )
}

/// GET /owner/riders — list rider-token records (no secrets).
pub(in crate::server) async fn owner_riders_list(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.agent.identity().user_keypair().is_none() {
        return owner_missing();
    }
    let riders = state.rider_tokens.lock().await.list();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "riders": riders.iter().map(|record| serde_json::json!({
                "token_id": record.token_id,
                "sub_agent_id": record.sub_agent_id,
                "groups": record.groups,
                "label": record.label,
                "issued_at_unix": record.issued_at,
                "expires_at_unix": record.expires_at,
                "revoked_at_unix": record.revoked_at,
            })).collect::<Vec<_>>(),
        })),
    )
}

/// DELETE /owner/riders/:id — revoke one rider token. The token fails
/// validation on the very next request (no restart, no cache).
pub(in crate::server) async fn owner_riders_revoke(
    State(state): State<Arc<AppState>>,
    Path(token_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if state.agent.identity().user_keypair().is_none() {
        return owner_missing();
    }
    let Ok(token_id) = token_id.trim().parse::<u64>() else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "token id must be a positive integer",
        );
    };
    let revoked = state
        .rider_tokens
        .lock()
        .await
        .revoke(token_id, crate::server::rider_auth::unix_now_secs())
        .await;
    if !revoked {
        return api_error(StatusCode::NOT_FOUND, "unknown rider token id");
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "token_id": token_id,
            "revoked": true,
        })),
    )
}
