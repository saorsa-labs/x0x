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
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<IssueAgentRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Review fix #4: certifying a sub-agent is an owner-ADMIN act —
    // the durable API token is required; a browser session bearer
    // cannot mint owner-signed certificates.
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "owner-admin endpoints require the durable API token (not a session token)",
        );
    }
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
    // Review fix #5: the journal append is a read-modify-write — hold
    // the install-wide journal lock so concurrent issuances cannot
    // interleave and lose lines.
    let journal_guard = state.cert_journal_lock.lock().await;
    if let Err(e) = IssuedCertRecord::append(&journal_path, &record).await {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to append issuance journal: {e}"),
        );
    }
    drop(journal_guard);

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

/// Decode a journal record's retained certificate bytes, if readable.
fn decode_retained_cert(record: &IssuedCertRecord) -> Option<crate::identity::AgentCertificate> {
    let bytes = record
        .cert_b64
        .as_deref()
        .and_then(|b64| BASE64.decode(b64).ok())?;
    crate::identity::AgentCertificate::from_storage_bytes(&bytes).ok()
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
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Path(agent_id_hex): Path<String>,
    body: Option<Json<RevokeAgentRequest>>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "owner-admin endpoints require the durable API token (not a session token)",
        );
    }
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
    // Review fix #3: the token sweep is persist-or-fail. The cert-level
    // revocation above is already durable, and the middleware checks
    // agent revocation on every rider request, so a failed sweep write
    // is fenced twice over — surface it as 500 rather than reporting a
    // success that did not happen.
    let swept = state
        .rider_tokens
        .lock()
        .await
        .revoke_for_agent(&target_hex, crate::server::rider_auth::unix_now_secs())
        .await;
    let rider_tokens_revoked = match swept {
        Ok(n) => n,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("agent revoked but rider-token sweep did not persist: {e}"),
            );
        }
    };

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
    /// Explicitly granted named-group ids. Home is NOT implicitly granted
    /// (rider_auth review r4): it is delegated like any other group, or
    /// not reachable at all.
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    label: Option<String>,
    /// Token lifetime in seconds (default 7 days, max 90 days).
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// The sub-agent-signed delegation capability (review r3, option B)
    /// — REQUIRED: without it the daemon could assert any sub-agent and
    /// receivers would have no proof.
    delegation: Option<DelegationWire>,
}

/// The harness-supplied delegation capability: canonical payload bytes
/// plus the sub-agent key's signature. The daemon contributes the
/// certificate bytes from its journal when storing.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct DelegationWire {
    payload_b64: String,
    signature: String,
}

/// Verify a harness-submitted delegation capability (review r3,
/// option B) and assemble the storable [`RiderDelegation`] with the
/// certificate bytes from the journal record.
///
/// Checks: payload parses; subject is the target sub-agent; delegate is
/// THIS daemon; scopes are exactly the requested groups; the capability
/// is unexpired; and the signature verifies under the sub-agent's
/// certified agent key.
#[allow(clippy::too_many_arguments)]
fn verify_delegation_wire(
    del: &DelegationWire,
    cert: &crate::identity::AgentCertificate,
    journal_record: &IssuedCertRecord,
    target_hex: &str,
    daemon_hex: &str,
    groups: &[String],
    now: u64,
) -> Result<crate::groups::RiderDelegation, String> {
    use base64::Engine as _;
    let payload = BASE64
        .decode(del.payload_b64.trim())
        .map_err(|_| "delegation payload_b64 is invalid base64".to_string())?;
    let claim = crate::groups::parse_rider_delegation(&payload)
        .ok_or_else(|| "delegation payload does not parse".to_string())?;
    if claim.sub_agent_id != target_hex {
        return Err("delegation subject differs from sub_agent_id".to_string());
    }
    if claim.daemon_agent_id != daemon_hex {
        return Err(format!(
            "delegation names daemon {other} but this daemon is {daemon_hex}",
            other = claim.daemon_agent_id
        ));
    }
    let mut requested = groups.to_vec();
    requested.sort();
    let mut delegated = claim.scopes.clone();
    delegated.sort();
    if delegated != requested {
        return Err("delegation scopes must equal the requested group grants".to_string());
    }
    if now >= claim.not_after {
        return Err("delegation is already expired".to_string());
    }
    let sig_bytes = hex::decode(del.signature.trim())
        .map_err(|_| "delegation signature is invalid hex".to_string())?;
    let sig = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&sig_bytes)
        .map_err(|e| format!("delegation signature does not decode: {e:?}"))?;
    let agent_pub = ant_quic::MlDsaPublicKey::from_bytes(cert.agent_public_key())
        .map_err(|_| "certificate agent key does not parse".to_string())?;
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&agent_pub, &payload, &sig)
        .map_err(|_| "delegation is not signed by the sub-agent's certified key".to_string())?;
    let cert_b64 = journal_record
        .cert_b64
        .clone()
        .ok_or_else(|| "journal record lacks retained certificate bytes".to_string())?;
    Ok(crate::groups::RiderDelegation {
        cert_b64,
        payload_b64: del.payload_b64.trim().to_string(),
        signature: del.signature.trim().to_string(),
    })
}

/// POST /owner/riders — issue a scoped rider token for a registered
/// rider-mode sub-agent (blocker 24 lifecycle).
///
/// The token secret is returned exactly once; only its SHA-256 hash is
/// stored. `404` when the sub-agent is not registered in rider mode;
/// `409` when it has been revoked. Review fix #2: the retained
/// certificate is verified (signature, owner binding, expiry) at
/// issuance and its digest + expiry are BOUND into the token, so a
/// token can never precede or outlive its certificate.
pub(in crate::server) async fn owner_riders_issue(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<IssueRiderRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "owner-admin endpoints require the durable API token (not a session token)",
        );
    }
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
    // Locate the newest rider-mode record WITH retained certificate
    // bytes, then verify the certificate itself.
    let mut retained: Option<IssuedCertRecord> = None;
    {
        let _journal_guard = state.cert_journal_lock.lock().await;
        for record in IssuedCertRecord::load(&journal_path).await {
            if record.user_id == owner_hex
                && record.agent_id == target_hex
                && record.mode == CertMode::Rider
                && record.cert_b64.is_some()
                && retained
                    .as_ref()
                    .is_none_or(|best| record.issued_at >= best.issued_at)
            {
                retained = Some(record);
            }
        }
    }
    let Some(record) = retained else {
        return api_error(
            StatusCode::NOT_FOUND,
            "sub_agent_id is not a registered rider-mode agent with a retained certificate (POST /owner/agents/issue first)",
        );
    };
    // Review fix #2: verify the bound certificate before minting.
    let now = crate::server::rider_auth::unix_now_secs();
    let cert = decode_retained_cert(&record);
    let cert_ok = cert.as_ref().is_some_and(|cert| {
        cert.verify().is_ok()
            && cert.user_id().is_ok_and(|uid| uid == user_kp.user_id())
            && cert.agent_id().is_ok_and(|aid| aid == sub_agent)
            && !cert.is_expired(now)
    });
    let Some(cert) = cert else {
        return api_error(
            StatusCode::CONFLICT,
            "retained certificate bytes are unreadable",
        );
    };
    if !cert_ok {
        return api_error(
            StatusCode::CONFLICT,
            "retained certificate fails verification or has expired",
        );
    }
    let cert_digest = record.cert_digest.clone();
    let cert_not_after = cert.not_after();

    if state
        .agent
        .revocation_records()
        .await
        .iter()
        .any(|rec| rec.subject_kind() == "agent" && rec.subject_hex() == target_hex)
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

    // Review r3 (option B): verify the sub-agent-signed delegation and
    // bind it into the token. The capability must name THIS daemon as
    // the delegate, cover exactly the requested group scopes, be signed
    // by the sub-agent's certified key, and expire in the future.
    let Some(del) = req.delegation else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "delegation is required: sign rider_delegation_bytes(sub, daemon, scopes, not_after) with the sub-agent key",
        );
    };
    let delegation = match verify_delegation_wire(
        &del,
        &cert,
        &record,
        &target_hex,
        &hex::encode(state.agent.agent_id().as_bytes()),
        &groups,
        now,
    ) {
        Ok(delegation) => delegation,
        Err(reason) => return api_error(StatusCode::BAD_REQUEST, reason),
    };
    let ttl = req
        .ttl_secs
        .unwrap_or(crate::server::rider_auth::RIDER_DEFAULT_TTL_SECS)
        .clamp(1, crate::server::rider_auth::RIDER_MAX_TTL_SECS);

    // Review r5: the delegation must not outlive its certificate or its
    // token — cap not_after at min(cert.not_after, token expiry) and
    // refuse longer capabilities.
    let token_expires_at = now.saturating_add(ttl);
    let cap = cert_not_after.unwrap_or(u64::MAX).min(token_expires_at);
    if let Some(claim) = parse_delegation_claim(&delegation) {
        if claim.not_after > cap {
            return api_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "delegation not_after ({}) outlives min(cert expiry, token expiry) ({cap}) — sign a shorter capability",
                    claim.not_after
                ),
            );
        }
    }

    let issued = state
        .rider_tokens
        .lock()
        .await
        .issue(
            target_hex.clone(),
            groups.clone(),
            req.label.clone(),
            ttl,
            cert_digest,
            cert_not_after,
            Some(delegation),
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

/// Parse the claim back out of an assembled delegation (issuance-cap
/// check, review r5). `None` if the stored payload does not parse —
/// impossible for a just-verified delegation, but refuse silently-safe.
fn parse_delegation_claim(
    delegation: &crate::groups::RiderDelegation,
) -> Option<crate::groups::RiderDelegationClaim> {
    use base64::Engine as _;
    let payload = BASE64.decode(&delegation.payload_b64).ok()?;
    crate::groups::parse_rider_delegation(&payload)
}

/// GET /owner/riders — list rider-token records (no secrets). Durable
/// owner only (review fix #4): token ids and grant shapes are
/// administrative metadata.
pub(in crate::server) async fn owner_riders_list(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
) -> (StatusCode, Json<serde_json::Value>) {
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "owner-admin endpoints require the durable API token (not a session token)",
        );
    }
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
                "cert_digest": record.cert_digest,
                "revoked_at_unix": record.revoked_at,
            })).collect::<Vec<_>>(),
        })),
    )
}

/// DELETE /owner/riders/:id — revoke one rider token. The token fails
/// validation on the very next request (no restart, no cache).
/// Review fix #3: revocation is persist-or-fail — `revoked: true` is
/// only ever reported for a DURABLE revocation; a failed disk write
/// yields `500` and the token stays live everywhere.
pub(in crate::server) async fn owner_riders_revoke(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Path(token_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "owner-admin endpoints require the durable API token (not a session token)",
        );
    }
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
    match revoked {
        Ok(false) => api_error(StatusCode::NOT_FOUND, "unknown rider token id"),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("revocation did not persist: {e}"),
        ),
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "token_id": token_id,
                "revoked": true,
            })),
        ),
    }
}
