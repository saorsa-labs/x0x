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
use super::super::{api_error, api_error_with_reason, parse_agent_id_hex};
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
    let durability_error = match state.agent.revoke_as_owner(&cert, reason).await {
        Ok(_) => None,
        Err(e @ crate::error::IdentityError::Storage(_)) => Some(e),
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("owner revocation failed: {e}"),
            );
        }
    };
    // A Storage error follows application/publication. Sweep rider
    // tokens before reporting the durability failure, so retirement
    // also fences them durably even while v1 is blocked.
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

    if let Some(e) = durability_error {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("owner revocation applied and published; not durable; rider tokens swept: {e}"),
        );
    }

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
    /// Rider-token scopes. Empty is the default. The only defined value
    /// is `gui:show`. This is not the group `delegation` scope list.
    #[serde(default)]
    scopes: Vec<String>,
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
    // Reject an unknown scope before any certificate lookup or disk write.
    let scopes = match crate::server::rider_auth::parse_rider_scopes(&req.scopes) {
        Ok(scopes) => scopes,
        Err(scope) => {
            return api_error_with_reason(
                StatusCode::BAD_REQUEST,
                format!("unknown rider scope: {scope}"),
                "unknown_scope",
            );
        }
    };
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
            scopes,
        )
        .await;
    let (token, record) = match issued {
        Ok(issued) => issued,
        Err(crate::server::rider_auth::IssueRiderError::UnknownScope(scope)) => {
            return api_error_with_reason(
                StatusCode::BAD_REQUEST,
                format!("unknown rider scope: {scope}"),
                "unknown_scope",
            );
        }
        Err(crate::server::rider_auth::IssueRiderError::Persist(error)) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to persist rider token: {error}"),
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
            "scopes": record.scopes,
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
                "scopes": record.scopes,
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

/// Request body for `POST /owner/devices/:machine_id/lose`.
#[derive(Debug, Default, Deserialize)]
pub(in crate::server) struct LoseDeviceRequest {
    /// Reason stored in each new revocation record.
    #[serde(default)]
    reason: Option<String>,
    /// Act on a machine that this owner has no record of.
    #[serde(default)]
    force: bool,
}

/// The `owner_key_warning` field of a lose-device answer. The daemon holds
/// no record of which machines hold the owner key, so the answer always
/// carries it.
const LOSE_DEVICE_OWNER_KEY_WARNING: &str = "This action does not protect your owner key (user.key). If the lost machine held it, whoever has the machine can act as you: certify new agents, sign grants and enroll devices. x0x cannot replace an owner key today. Treat the owner identity as compromised, create a new one and tell your contacts.";

/// The `note` field of a lose-device answer.
const LOSE_DEVICE_NOTE: &str = "Each listed agent can no longer act from this machine. An agent pinned to this machine is revoked, with its rider tokens. A roaming agent keeps its identity and its rider tokens: if its key was on this machine, revoke it with DELETE /owner/agents/:id. A rider token that was on this machine still works on the daemon that issued it: revoke it there with DELETE /owner/riders/:id (x0x owner riders revoke). The machine key is not revoked. An agent that you certify later is not covered: run this action again after you certify it. An agent in agents_without_placement has no placement record on this daemon and is not covered: if it ran on this machine, revoke it with DELETE /owner/agents/:id.";

/// Serializes lose-device calls in this process, so that the repeat check
/// and the signing are one step and two calls at once sign one record.
static LOSE_DEVICE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One row of this owner's placement ledger: agent, placement epoch and
/// the machine the agent is pinned to.
type LedgerRow = (
    crate::identity::AgentId,
    u64,
    Option<crate::identity::MachineId>,
);

/// This owner's agents on the placement ledger, in agent-id order, and the
/// certified agents that have no placement record here.
///
/// The placement cache also holds the agents of OTHER owners (activation
/// bundles from gossip). A row is this owner's only when the owner
/// certified the agent (it is on the roster) and the placement record
/// names this owner's key. This owner has no authority over any other row.
async fn owner_ledger(state: &Arc<AppState>) -> (Vec<LedgerRow>, Vec<String>) {
    let Some(owner) = state.agent.identity().user_keypair() else {
        return (Vec::new(), Vec::new());
    };
    let owner_key = owner.public_key().as_bytes();
    let roster: std::collections::BTreeSet<String> = state
        .agent
        .owner_issued_certificates()
        .await
        .into_iter()
        .map(|cert| cert.agent_id)
        .collect();
    let mut rows: Vec<LedgerRow> = {
        let move_state = state.agent.move_state();
        let view = move_state.read().await;
        view.placement_view()
            .values()
            .filter(|record| {
                record.owner_public_key == owner_key
                    && roster.contains(&hex::encode(record.agent_id.as_bytes()))
            })
            .map(|record| {
                (
                    record.agent_id,
                    record.placement_epoch,
                    record.placement.pinned_machine(),
                )
            })
            .collect()
    };
    rows.sort_by_key(|(agent, _, _)| agent.0);
    // A binding tombstone needs a placement epoch, so the action cannot
    // cover an agent with no row; the answer names it for the operator.
    let without_placement = roster
        .into_iter()
        .filter(|agent_hex| {
            !rows
                .iter()
                .any(|(agent, _, _)| hex::encode(agent.as_bytes()) == *agent_hex)
        })
        .collect();
    (rows, without_placement)
}

/// The answer text for one lose-device revocation step. A step that failed
/// or is not durable clears `complete`.
fn revocation_outcome(
    result: crate::error::Result<crate::revocation::RevocationRecord>,
    complete: &mut bool,
) -> String {
    match result {
        Ok(_) => "revoked".to_string(),
        Err(e @ crate::error::IdentityError::Storage(_)) => {
            *complete = false;
            format!("revoked, not durable: {e}")
        }
        Err(e) => {
            *complete = false;
            format!("failed: {e}")
        }
    }
}

/// POST /owner/devices/:machine_id/lose — the lost-device action (#1108,
/// #891).
///
/// It uses only record kinds that released daemons enforce:
///
/// 1. for each agent that this owner certified and that has a placement
///    record signed by this owner, an owner-signed binding tombstone
///    `(agent, machine)` at the agent's placement epoch. The placement
///    cache also holds other owners' agents; those are not touched;
/// 2. for each agent pinned to the machine, an owner-signed agent
///    revocation, and a sweep of that agent's rider tokens;
/// 3. removal of the machine from the owner device set.
///
/// A certified agent with no placement record on this daemon (an ACP agent
/// whose machine was never confirmed) gets no tombstone; the answer lists
/// it in `agents_without_placement`.
///
/// A repeat call makes no new record; calls run one at a time in this
/// process. The machine key is not revoked: no
/// evidence that other peers can check ties a machine to its owner (see
/// `docs/design/owner-machine-revocation.md`).
///
/// `403` without the durable token. `409` with no owner key, or when the
/// machine is the one this daemon runs on. `404` when the owner has no
/// record of the machine and `force` is not set. `500` with the same body
/// when a step failed or a record is not durable.
pub(in crate::server) async fn owner_device_lose(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Path(machine_hex): Path<String>,
    body: Option<Json<LoseDeviceRequest>>,
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
    let machine = hex::decode(&machine_hex)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .map(crate::identity::MachineId);
    let Some(machine) = machine else {
        return api_error(StatusCode::BAD_REQUEST, "machine id must be 64 hex chars");
    };
    if machine == state.agent.machine_id() {
        return api_error(
            StatusCode::CONFLICT,
            "this is the machine this daemon runs on: run lose-device on another of your devices, or revoke this machine with POST /identity/revoke",
        );
    }
    let request = body.map(|Json(request)| request).unwrap_or_default();
    // One call at a time: the repeat check and the signing are one step.
    let _one_call = LOSE_DEVICE_LOCK.lock().await;

    let enrolled = match state.owner_sync.as_ref() {
        Some(sync) => sync
            .store()
            .enrolled_devices()
            .await
            .iter()
            .any(|enrollment| enrollment.machine_id == machine.0),
        None => false,
    };
    // The 404 gate reads the ledger as it is, before the mint below writes.
    let known = enrolled || {
        let (held, _) = owner_ledger(&state).await;
        let set = state.agent.revocation_set();
        let set = set.read().await;
        held.iter().any(|(agent, _, pinned)| {
            *pinned == Some(machine) || set.is_binding_revoked(agent, &machine)
        })
    };
    if !known && !request.force {
        return api_error(
            StatusCode::NOT_FOUND,
            "this owner has no record of that machine (not enrolled, no agent pinned to it, no earlier tombstone); send {\"force\": true} to act anyway",
        );
    }

    // Bring the placement ledger up to date. A refused mint must not stop
    // a lost-device action: go on with the ledger as it is, and report it.
    let placement_mint_error = match state.agent.move_mint_placements().await {
        Ok(_) => None,
        Err(e) => {
            tracing::warn!("lose-device: placement mint refused, using the held ledger: {e}");
            Some(e.to_string())
        }
    };
    let (agents, agents_without_placement) = owner_ledger(&state).await;
    // What the set held before this call: (binding tombstone, agent revoked).
    let before: Vec<(bool, bool)> = {
        let set = state.agent.revocation_set();
        let set = set.read().await;
        agents
            .iter()
            .map(|(agent, _, _)| {
                (
                    set.is_binding_revoked(agent, &machine),
                    set.is_agent_revoked(agent),
                )
            })
            .collect()
    };

    let mut complete = true;
    let mut rows = Vec::with_capacity(agents.len());
    for ((agent, epoch, pinned), (binding_before, agent_before)) in agents.iter().zip(before) {
        let agent_hex = hex::encode(agent.as_bytes());
        let binding = if binding_before {
            "already_revoked".to_string()
        } else {
            revocation_outcome(
                state
                    .agent
                    .revoke_binding(agent, &machine, *epoch, request.reason.clone())
                    .await,
                &mut complete,
            )
        };
        let pinned_here = *pinned == Some(machine);
        let mut rider_tokens_revoked = 0usize;
        let mut rider_token_sweep_error: Option<String> = None;
        let agent_state = if !pinned_here {
            "kept".to_string()
        } else {
            let outcome = if agent_before {
                "already_revoked".to_string()
            } else {
                revocation_outcome(
                    state
                        .agent
                        .revoke_agent_as_owner(agent, request.reason.clone())
                        .await,
                    &mut complete,
                )
            };
            match state
                .rider_tokens
                .lock()
                .await
                .revoke_for_agent(&agent_hex, crate::server::rider_auth::unix_now_secs())
                .await
            {
                Ok(count) => rider_tokens_revoked = count,
                Err(e) => {
                    complete = false;
                    rider_token_sweep_error = Some(e.to_string());
                }
            }
            outcome
        };
        rows.push(serde_json::json!({
            "agent_id": agent_hex,
            "placement": if pinned.is_some() { "pinned" } else { "roaming" },
            "pinned_to_this_machine": pinned_here,
            "binding": binding,
            "agent": agent_state,
            "rider_tokens_revoked": rider_tokens_revoked,
            "rider_token_sweep_error": rider_token_sweep_error,
        }));
    }

    let device_enrollment = match state.owner_sync.as_ref() {
        None => "no_device_set".to_string(),
        Some(sync) => match sync.store().unenroll(&machine).await {
            Ok(true) => {
                sync.kick();
                "removed".to_string()
            }
            Ok(false) => "not_enrolled".to_string(),
            Err(e) => {
                complete = false;
                format!("failed: {e}")
            }
        },
    };

    // A repeat must be able to make a record durable that an earlier
    // call left "revoked, not durable": that row is `already_revoked`
    // now and signs nothing, so the store write is done here, every time.
    // A store that was quarantined as unreadable stays blocked until it
    // is rebuilt or resynced (#1116); the answer then names that cause.
    let store_write_error = match state.agent.persist_identity_revocation_stores().await {
        Ok(()) => None,
        Err(e) => {
            complete = false;
            Some(e.to_string())
        }
    };

    let status = if complete {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (
        status,
        Json(serde_json::json!({
            "ok": complete,
            "store_write_error": store_write_error,
            "machine_id": hex::encode(machine.as_bytes()),
            "agents": rows,
            "agents_without_placement": agents_without_placement,
            "placement_mint_error": placement_mint_error,
            "device_enrollment": device_enrollment,
            "machine_key_revoked": false,
            // No record says which machines hold `user.key`. A machine in
            // the owner device set normally does.
            "owner_key_on_device": if enrolled { "likely" } else { "unknown" },
            "owner_key_warning": LOSE_DEVICE_OWNER_KEY_WARNING,
            "covers_agents_certified_later": false,
            "note": LOSE_DEVICE_NOTE,
        })),
    )
}

/// One machine row in the `GET /owner/machines` census (#1383).
#[derive(Debug, serde::Serialize)]
pub(in crate::server) struct OwnerMachineEntry {
    machine_id: String,
    enrolled_at_ms: u64,
    expires_at_ms: Option<u64>,
    last_session_ms: Option<u64>,
    last_session_ok: Option<bool>,
    is_this_machine: bool,
}

/// GET /owner/machines — the #1167 M1 owner's machine census over owner-sync
/// (#1383, David's 20 Oct 2026 ruling: additive local API, no wire change).
/// One row per enrolled device with its last-sync status; the local daemon's
/// version and version/policy digest ride in `this_machine`. Remote
/// per-machine versions stay absent until an approved announcement change
/// carries the digest on the wire — this surface changes no announcement and
/// adds no capability bit. `409` when no owner identity (and therefore no
/// sync service) is configured, mirroring `GET /sync/devices`.
pub(in crate::server) async fn owner_machines(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(sync) = state.owner_sync.as_ref() else {
        return api_error(StatusCode::CONFLICT, "no owner identity configured");
    };
    let Some(owner) = state.agent.identity().user_keypair() else {
        return api_error(StatusCode::CONFLICT, "no owner identity configured");
    };
    let this_machine = state.agent.machine_id();
    let version = env!("CARGO_PKG_VERSION");
    let digest = super::network::version_policy_digest(version, &state.update_config);
    let statuses = sync.store().session_statuses().await;
    let mut machines: Vec<OwnerMachineEntry> = sync
        .store()
        .enrolled_devices()
        .await
        .into_iter()
        .map(|enrollment| {
            let status = statuses.get(&enrollment.machine_id);
            OwnerMachineEntry {
                machine_id: hex::encode(enrollment.machine_id),
                enrolled_at_ms: enrollment.enrolled_at_ms,
                expires_at_ms: enrollment.expires_at_ms,
                last_session_ms: status.map(|s| s.last_session_ms),
                last_session_ok: status.map(|s| s.last_session_ok),
                is_this_machine: enrollment.machine_id == this_machine.0,
            }
        })
        .collect();
    machines.sort_by(|a, b| a.machine_id.cmp(&b.machine_id));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "owner_user_id": hex::encode(owner.user_id().0),
            "this_machine": {
                "machine_id": hex::encode(this_machine.0),
                "version": version,
                "version_policy_digest": digest,
            },
            "machines": machines,
        })),
    )
}

#[cfg(test)]
mod revocation_persistence_tests {
    use super::*;
    use crate::server::rider_auth::{ActorContext, RiderTokenStore, RIDER_TOKENS_FILE};

    #[tokio::test]
    async fn blocked_owner_revocation_still_sweeps_rider_tokens_1116() {
        let dir = tempfile::tempdir().unwrap();
        let state =
            super::super::identity::revocation_persistence_tests::state_at(dir.path()).await;
        // Issue a real rider certificate through the owner route, so the
        // retained authority evidence and roster are the production shape.
        let sub_agent = crate::identity::AgentKeypair::generate().unwrap();
        let target = hex::encode(sub_agent.agent_id().as_bytes());
        let (status, _) = owner_agents_issue(
            State(Arc::clone(&state)),
            axum::extract::Extension(ActorContext::Owner { durable: true }),
            Json(IssueAgentRequest {
                agent_public_key: hex::encode(sub_agent.public_key().as_bytes()),
                mode: Some("rider".to_string()),
                label: None,
                not_after: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let now = crate::server::rider_auth::unix_now_secs();
        let (_, token) = state
            .rider_tokens
            .lock()
            .await
            .issue(
                target.clone(),
                vec![],
                None,
                60,
                "digest".to_string(),
                None,
                None,
                now,
                Vec::new(),
            )
            .await
            .unwrap();
        let path = dir.path().join("revocations.bin");
        tokio::fs::write(&path, b"unreadable v1").await.unwrap();
        let (status, Json(body)) = owner_agents_revoke(
            State(Arc::clone(&state)),
            axum::extract::Extension(ActorContext::Owner { durable: true }),
            Path(target.clone()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body
            .to_string()
            .contains("applied and published; not durable"));
        assert!(state
            .agent
            .revocation_set()
            .read()
            .await
            .is_agent_revoked(&sub_agent.agent_id()));
        assert!(state
            .rider_tokens
            .lock()
            .await
            .list()
            .iter()
            .any(|record| { record.token_id == token.token_id && record.revoked_at.is_some() }));
        let reloaded = RiderTokenStore::load(dir.path().join(RIDER_TOKENS_FILE)).await;
        assert!(reloaded
            .list()
            .iter()
            .any(|record| { record.token_id == token.token_id && record.revoked_at.is_some() }));
        assert_ne!(
            tokio::fs::read(&path).await.ok().as_deref(),
            Some(b"unreadable v1".as_slice()),
            "the live path no longer holds the corrupt payload"
        );
        state.agent.shutdown().await;
    }
}

#[cfg(test)]
mod owner_machines_tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;

    /// #1383: the census lists every enrolled device with its last-sync
    /// status and carries THIS machine's version + version/policy digest.
    /// Local only: remote rows never claim a version until an approved
    /// announcement change carries the digest on the wire.
    #[tokio::test]
    async fn owner_machines_lists_enrolled_devices_and_local_digest() {
        let dir = tempfile::tempdir().unwrap();
        let user =
            crate::identity::UserKeypair::from_seed(&[0x4D; 32]).expect("deterministic user key");
        let agent = Arc::new(
            crate::Agent::builder()
                .with_identity_dir(dir.path().join("identity"))
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key(crate::identity::AgentKeypair::generate().unwrap())
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_user_key(user)
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .with_network_config(crate::network::NetworkConfig {
                    bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                    bootstrap_nodes: Vec::new(),
                    mdns_enabled: false,
                    port_mapping_enabled: false,
                    ..Default::default()
                })
                .build()
                .await
                .unwrap(),
        );
        let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
            dir.path(),
            Arc::clone(&agent),
        )
        .await
        .unwrap();
        let owner_kp = state
            .agent
            .identity()
            .user_keypair()
            .expect("owned state has a user key");
        let sync = state.owner_sync.as_ref().expect("owned state wires sync");
        let this_machine = state.agent.machine_id();
        let other_machine = crate::identity::MachineId([0x07; 32]);
        sync.store()
            .enroll(
                crate::owner_sync::OwnerEnrollment::sign(this_machine, owner_kp, 1_000, None)
                    .unwrap(),
            )
            .await
            .unwrap();
        sync.store()
            .enroll(
                crate::owner_sync::OwnerEnrollment::sign(
                    other_machine,
                    owner_kp,
                    2_000,
                    Some(9_000),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let app = Router::new()
            .route("/owner/machines", get(owner_machines))
            .with_state(Arc::clone(&state));
        let response = app
            .oneshot(Request::get("/owner/machines").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["owner_user_id"], hex::encode(owner_kp.user_id().0));
        assert_eq!(
            body["this_machine"]["machine_id"],
            hex::encode(this_machine.0)
        );
        assert_eq!(body["this_machine"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            body["this_machine"]["version_policy_digest"],
            super::super::network::version_policy_digest(
                env!("CARGO_PKG_VERSION"),
                &state.update_config
            )
        );
        let machines = body["machines"].as_array().expect("machines array");
        assert_eq!(machines.len(), 2, "both enrollments are censused");
        let other_row = machines
            .iter()
            .find(|m| m["machine_id"] == hex::encode(other_machine.0))
            .expect("other machine row");
        assert_eq!(other_row["enrolled_at_ms"], 2_000);
        assert_eq!(other_row["expires_at_ms"], 9_000);
        assert_eq!(other_row["is_this_machine"], false);
        assert!(
            other_row.get("version").is_none(),
            "remote rows carry no version until an approved wire change"
        );
        let this_row = machines
            .iter()
            .find(|m| m["is_this_machine"] == true)
            .expect("this machine row");
        assert_eq!(this_row["machine_id"], hex::encode(this_machine.0));

        agent.shutdown().await;
    }

    /// #1383: an ownerless install has no sync service, so the census
    /// answers `409` exactly like `GET /sync/devices`.
    #[tokio::test]
    async fn owner_machines_conflicts_without_owner_identity() {
        let dir = tempfile::tempdir().unwrap();
        let agent = Arc::new(
            crate::Agent::builder()
                .with_identity_dir(dir.path().join("identity"))
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key(crate::identity::AgentKeypair::generate().unwrap())
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .with_network_config(crate::network::NetworkConfig {
                    bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                    bootstrap_nodes: Vec::new(),
                    mdns_enabled: false,
                    port_mapping_enabled: false,
                    ..Default::default()
                })
                .build()
                .await
                .unwrap(),
        );
        let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
            dir.path(),
            Arc::clone(&agent),
        )
        .await
        .unwrap();
        assert!(
            state.owner_sync.is_none(),
            "ownerless state wires no sync service"
        );
        let app = Router::new()
            .route("/owner/machines", get(owner_machines))
            .with_state(state);
        let response = app
            .oneshot(Request::get("/owner/machines").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        agent.shutdown().await;
    }
}

/// Request body for `POST /owner/groups/:id/recovery-mandate`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct RecoveryMandateRequest {
    /// Hex agent ID of the Active certified member to promote to Admin.
    promoted_agent_id: String,
}

/// POST /owner/groups/:id/recovery-mandate — ADR 0110 §4b(1).
///
/// For an `OwnerCertified` group (Home included) whose Admin-or-higher
/// Active seats all hold verified Agent-subject revocations, the owner's
/// user key U signs an `OwnerRecoveryMandateV1` that names the group, its
/// current head, each revoked admin with its revocation record hashes, and
/// one promoted member with its committed certificate digest. The daemon
/// sends it to that member, gated on `owner_recovery_v1`, and returns
/// `202` with `waiting_for_recovery_member`. Only a node that holds U's
/// key can sign (`409` otherwise); typed `recovery_*` refusals are `409`
/// (`403` for `recovery_signer_not_owner`).
pub(in crate::server) async fn owner_group_recovery_mandate(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Path(group_id): Path<String>,
    Json(req): Json<RecoveryMandateRequest>,
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
    super::named_groups::sign_recovery_mandate(&state, user_kp, &group_id, &req.promoted_agent_id)
        .await
}

#[cfg(test)]
mod owner_recovery_mandate_tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::post, Router};
    use tower::ServiceExt;

    async fn post_mandate(
        state: &Arc<AppState>,
        durable: bool,
        group_id: &str,
        promoted: &str,
    ) -> (StatusCode, serde_json::Value) {
        let app = Router::new()
            .route(
                "/owner/groups/:id/recovery-mandate",
                post(owner_group_recovery_mandate),
            )
            .layer(axum::Extension(
                crate::server::rider_auth::ActorContext::Owner { durable },
            ))
            .with_state(Arc::clone(state));
        let body = serde_json::json!({ "promoted_agent_id": promoted }).to_string();
        let response = app
            .oneshot(
                Request::post(format!("/owner/groups/{group_id}/recovery-mandate"))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// ADR 0110 §4b(1): the owner route refuses while an eligible admin
    /// remains (`recovery_not_needed`) and refuses a session token; once
    /// every admin holds a verified revocation it signs a mandate naming
    /// the revoked admin and the promoted member, and the owner node shows
    /// `waiting_for_recovery_member`.
    #[tokio::test]
    async fn owner_group_recovery_mandate_signs_only_when_every_admin_is_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let user =
            crate::identity::UserKeypair::from_seed(&[0x5E; 32]).expect("deterministic user key");
        let agent = Arc::new(
            crate::Agent::builder()
                .with_identity_dir(dir.path().join("identity"))
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key(crate::identity::AgentKeypair::generate().unwrap())
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_user_key(user)
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .with_network_config(crate::network::NetworkConfig {
                    bind_addr: Some("127.0.0.1:0".parse().unwrap()),
                    bootstrap_nodes: Vec::new(),
                    mdns_enabled: false,
                    port_mapping_enabled: false,
                    ..Default::default()
                })
                .build()
                .await
                .unwrap(),
        );
        let state = crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(
            dir.path(),
            Arc::clone(&agent),
        )
        .await
        .unwrap();
        let owner = state.agent.identity().user_keypair().unwrap();
        let admin = crate::identity::AgentKeypair::generate().unwrap();
        let local = state.agent.identity().agent_keypair();
        let seat = |agent: &crate::identity::AgentKeypair, role: crate::groups::GroupRole| {
            let cert = crate::identity::AgentCertificate::issue(owner, agent).unwrap();
            let id = hex::encode(agent.agent_id().as_bytes());
            let mut member = crate::groups::GroupMember::new_member(id, None, None, 1);
            member.role = role;
            member.certificate_digest =
                Some(crate::groups::owner_cert::certificate_digest_hex(&cert));
            member.certificate = Some(cert);
            member
        };
        let mut info = crate::groups::GroupInfo::new(
            "recovery".to_string(),
            String::new(),
            admin.agent_id(),
            "cd".repeat(16),
        );
        info.policy.admission =
            crate::groups::policy::GroupAdmission::OwnerCertified(owner.user_id());
        info.policy.confidentiality = crate::groups::policy::GroupConfidentiality::SignedPublic;
        info.members_v2.clear();
        for member in [
            seat(&admin, crate::groups::GroupRole::Admin),
            seat(local, crate::groups::GroupRole::Member),
        ] {
            info.members_v2.insert(member.agent_id.clone(), member);
        }
        info.recompute_state_hash();
        let group_id = info.stable_group_id().to_string();
        state
            .named_groups
            .write()
            .await
            .insert(group_id.clone(), info.clone());
        let local_hex = hex::encode(local.agent_id().as_bytes());

        let (status, body) = post_mandate(&state, false, &group_id, &local_hex).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (status, body) = post_mandate(&state, true, &group_id, &local_hex).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"], "recovery_not_needed");

        let record = crate::revocation::RevocationRecord::sign(
            crate::revocation::RevokedSubject::Agent(admin.agent_id()),
            admin.public_key(),
            admin.secret_key(),
            1,
            None,
        )
        .unwrap();
        assert!(state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)
            .unwrap());

        let stranger = hex::encode([0x11; 32]);
        let (status, body) = post_mandate(&state, true, &group_id, &stranger).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"], "recovery_member_ineligible");

        let (status, body) = post_mandate(&state, true, &group_id, &local_hex).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["state"], "waiting_for_recovery_member");
        assert_eq!(body["promoted_member"], local_hex);
        assert_eq!(
            body["revoked_admins"],
            serde_json::json!([hex::encode(admin.agent_id().as_bytes())])
        );
        assert_eq!(body["parent_head"], info.state_hash);
        state.agent.shutdown().await;
    }
}

#[cfg(test)]
mod rider_scope_mint_tests {
    use super::*;
    use crate::server::routes::named_groups::tests::secure_endpoint_test_state;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::post;
    use tower::ServiceExt;

    #[tokio::test]
    async fn unknown_rider_scope_is_400_and_not_persisted() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let app = axum::Router::new()
            .route("/owner/riders", post(owner_riders_issue))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        let req = Request::builder()
            .method("POST")
            .uri("/owner/riders")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({
                    "sub_agent_id": "aa".repeat(32),
                    "scopes": ["not-a-scope"],
                    "delegation": {"payload_b64": "YQ==", "signature": "00"}
                })
                .to_string(),
            ))?;
        let resp = app.oneshot(req).await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(resp.into_body(), 1 << 20).await?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["reason"], "unknown_scope");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("not-a-scope"),
            "{body}"
        );
        assert!(state.rider_tokens.lock().await.list().is_empty());
        Ok(())
    }
}

#[cfg(test)]
mod lose_device_tests {
    //! #1108 / #891: the lost-device action, through the real handler.
    use super::*;
    use crate::identity::{AgentCertificate, AgentId, AgentKeypair, MachineId, UserKeypair};
    use crate::key_move::{Placement, PlacementAuthority, PlacementRecord};
    use crate::revocation::RevocationSet;
    use crate::server::rider_auth::ActorContext;

    const LOST: MachineId = MachineId([0x51; 32]);

    async fn owned_state(dir: &std::path::Path) -> Arc<AppState> {
        super::super::identity::revocation_persistence_tests::state_at(dir).await
    }

    /// Certify a new sub-agent through the real issue route.
    async fn issue(state: &Arc<AppState>, mode: &str) -> AgentKeypair {
        let agent = AgentKeypair::generate().unwrap();
        let (status, _) = owner_agents_issue(
            State(Arc::clone(state)),
            axum::extract::Extension(ActorContext::Owner { durable: true }),
            Json(IssueAgentRequest {
                agent_public_key: hex::encode(agent.public_key().as_bytes()),
                mode: Some(mode.to_string()),
                label: None,
                not_after: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "issue {mode} agent");
        agent
    }

    /// Record an owner-signed placement that pins `agent` to `machine`.
    async fn pin(state: &Arc<AppState>, agent: &AgentKeypair, machine: MachineId) {
        let owner = state.agent.identity().user_keypair().unwrap();
        let cert = AgentCertificate::issue(owner, agent).unwrap();
        let record = PlacementRecord::sign(
            agent.agent_id(),
            owner.public_key().as_bytes(),
            Placement::Pinned(machine),
            0,
            1_800_000_000,
            owner.secret_key(),
        )
        .unwrap();
        let move_state = state.agent.move_state();
        let cached = move_state
            .write()
            .await
            .cache_placement(record, PlacementAuthority::cert_issuer(&cert).unwrap())
            .unwrap();
        assert!(cached, "placement cached");
    }

    async fn enroll(state: &Arc<AppState>, machine: MachineId) {
        let owner = state.agent.identity().user_keypair().unwrap();
        state
            .owner_sync
            .as_ref()
            .expect("owned state has a device set")
            .store()
            .enroll(crate::owner_sync::OwnerEnrollment::sign(machine, owner, 1_000, None).unwrap())
            .await
            .unwrap();
    }

    async fn lose(
        state: &Arc<AppState>,
        durable: bool,
        machine_hex: &str,
        force: bool,
    ) -> (StatusCode, serde_json::Value) {
        let (status, Json(body)) = owner_device_lose(
            State(Arc::clone(state)),
            axum::extract::Extension(ActorContext::Owner { durable }),
            Path(machine_hex.to_string()),
            Some(Json(LoseDeviceRequest {
                reason: Some("lost laptop".to_string()),
                force,
            })),
        )
        .await;
        (status, body)
    }

    /// What another peer holds after it receives this daemon's records:
    /// each record must verify again from the record and its certificate.
    async fn peer_view(state: &Arc<AppState>) -> RevocationSet {
        let set = state.agent.revocation_set();
        let set = set.read().await;
        let mut peer = RevocationSet::new();
        for (record, cert) in set.records_with_certs() {
            peer.verify_and_insert(record.clone(), cert)
                .expect("a peer verifies every record");
        }
        peer
    }

    fn row<'a>(body: &'a serde_json::Value, agent: &AgentId) -> &'a serde_json::Value {
        let hex = hex::encode(agent.as_bytes());
        body["agents"]
            .as_array()
            .expect("agents array")
            .iter()
            .find(|row| row["agent_id"] == hex)
            .unwrap_or_else(|| panic!("no row for {hex} in {body}"))
    }

    /// WHY: when a device is lost, every agent this owner certified must
    /// stop working from that device, on every peer. An agent pinned to
    /// the device has its key there, so that agent is revoked. A roaming
    /// agent keeps its identity for the owner's other devices. Another
    /// owner's agent on the same machine is not this owner's to stop.
    #[tokio::test]
    async fn lose_device_stops_owner_agents_on_that_machine() {
        let dir = tempfile::tempdir().unwrap();
        let state = owned_state(dir.path()).await;
        let local = state.agent.agent_id();
        let rider = issue(&state, "rider").await;
        let pinned = issue(&state, "acp").await;
        pin(&state, &pinned, LOST).await;
        // An ACP agent whose machine this daemon never confirmed.
        let unplaced = issue(&state, "acp").await;
        enroll(&state, LOST).await;

        // Another owner's agent that also runs on the lost machine.
        let other_owner = UserKeypair::generate().unwrap();
        let foreign = AgentKeypair::generate().unwrap();
        let _foreign_cert = AgentCertificate::issue(&other_owner, &foreign).unwrap();

        let (status, body) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["machine_id"], hex::encode(LOST.0));
        assert_eq!(body["device_enrollment"], "removed");
        assert_eq!(body["machine_key_revoked"], false);
        assert_eq!(body["covers_agents_certified_later"], false);
        // The owner key is the limit that matters most: the answer must
        // say it, and must not claim to know where the key is.
        assert_eq!(body["owner_key_on_device"], "likely", "enrolled device");
        assert!(body["owner_key_warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("user.key")));
        assert_eq!(body["agents"].as_array().unwrap().len(), 3, "{body}");
        // The action cannot cover an agent with no placement record, so
        // it must name that agent and not report silent success for it.
        assert_eq!(
            body["agents_without_placement"],
            serde_json::json!([hex::encode(unplaced.agent_id().as_bytes())]),
            "{body}"
        );

        let local_row = row(&body, &local);
        assert_eq!(local_row["placement"], "roaming");
        assert_eq!(local_row["binding"], "revoked");
        assert_eq!(local_row["agent"], "kept");
        let rider_row = row(&body, &rider.agent_id());
        assert_eq!(rider_row["binding"], "revoked");
        assert_eq!(rider_row["agent"], "kept");
        let pinned_row = row(&body, &pinned.agent_id());
        assert_eq!(pinned_row["pinned_to_this_machine"], true);
        assert_eq!(pinned_row["binding"], "revoked");
        assert_eq!(pinned_row["agent"], "revoked");

        let peer = peer_view(&state).await;
        // Every owner agent is refused on the lost machine.
        assert!(peer.is_binding_revoked(&local, &LOST));
        assert!(peer.is_binding_revoked(&rider.agent_id(), &LOST));
        assert!(peer.is_binding_revoked(&pinned.agent_id(), &LOST));
        // The agent whose key was on the device is dead everywhere.
        assert!(peer.is_agent_revoked(&pinned.agent_id()));
        // The roaming agent still works from the owner's other machines.
        assert!(!peer.is_agent_revoked(&local));
        assert!(!peer.is_binding_revoked(&local, &state.agent.machine_id()));
        assert!(!peer.is_agent_revoked(&rider.agent_id()));
        // Another owner's agent on that machine is not touched.
        assert!(!peer.is_agent_revoked(&foreign.agent_id()));
        assert!(!peer.is_binding_revoked(&foreign.agent_id(), &LOST));
        // The machine key itself is not revoked (design note, option A).
        assert!(!peer.is_machine_revoked(&LOST));

        let devices = state
            .owner_sync
            .as_ref()
            .unwrap()
            .store()
            .enrolled_devices()
            .await;
        assert!(devices.iter().all(|device| device.machine_id != LOST.0));
        state.agent.shutdown().await;
    }

    /// WHY: an operator in a hurry runs the action twice. A repeat must
    /// succeed and must not sign new records, because the revocation set
    /// has no size limit (#1857).
    #[tokio::test]
    async fn lose_device_twice_makes_no_new_record() {
        let dir = tempfile::tempdir().unwrap();
        let state = owned_state(dir.path()).await;
        let pinned = issue(&state, "acp").await;
        pin(&state, &pinned, LOST).await;
        enroll(&state, LOST).await;

        let (status, _) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::OK);
        let held = state.agent.all_revocation_records().await.len();

        let (status, body) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["device_enrollment"], "not_enrolled");
        for row in body["agents"].as_array().unwrap() {
            assert_eq!(row["binding"], "already_revoked", "{row}");
        }
        assert_eq!(row(&body, &pinned.agent_id())["agent"], "already_revoked");
        assert_eq!(state.agent.all_revocation_records().await.len(), held);
        state.agent.shutdown().await;
    }

    /// WHY: the action covers the agents that exist when it runs. The
    /// answer says so, and a second run covers an agent certified later.
    #[tokio::test]
    async fn an_agent_certified_later_needs_a_second_run() {
        let dir = tempfile::tempdir().unwrap();
        let state = owned_state(dir.path()).await;
        enroll(&state, LOST).await;
        let (status, body) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["covers_agents_certified_later"], false);
        assert!(body["note"].as_str().unwrap().contains("certify later"));

        let later = issue(&state, "rider").await;
        assert!(
            !peer_view(&state)
                .await
                .is_binding_revoked(&later.agent_id(), &LOST),
            "the first run cannot cover an agent that did not exist"
        );

        let (status, body) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(row(&body, &later.agent_id())["binding"], "revoked");
        assert_eq!(
            row(&body, &state.agent.agent_id())["binding"],
            "already_revoked"
        );
        assert!(peer_view(&state)
            .await
            .is_binding_revoked(&later.agent_id(), &LOST));
        state.agent.shutdown().await;
    }

    /// WHY: this is an owner-key signing act, so a 10-minute session token
    /// must not do it. A wrong id must not sign tombstones by accident,
    /// and the machine the daemon runs on has its own route.
    #[tokio::test]
    async fn lose_device_refuses_wrong_callers_and_wrong_targets() {
        let dir = tempfile::tempdir().unwrap();
        let state = owned_state(dir.path()).await;
        enroll(&state, LOST).await;
        let lost_hex = hex::encode(LOST.0);

        let (status, _) = lose(&state, false, &lost_hex, false).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "session token");

        let (status, _) = lose(&state, true, "zz", false).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "bad machine id");

        let own_hex = hex::encode(state.agent.machine_id().0);
        let (status, _) = lose(&state, true, &own_hex, true).await;
        assert_eq!(status, StatusCode::CONFLICT, "the daemon's own machine");

        let unknown_hex = hex::encode([0x77u8; 32]);
        let (status, _) = lose(&state, true, &unknown_hex, false).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "unknown machine");
        assert!(
            state.agent.all_revocation_records().await.is_empty(),
            "no refused call signed a record"
        );

        let (status, body) = lose(&state, true, &unknown_hex, true).await;
        assert_eq!(status, StatusCode::OK, "force: {body}");
        assert_eq!(body["device_enrollment"], "not_enrolled");
        assert_eq!(body["owner_key_on_device"], "unknown", "never enrolled");
        state.agent.shutdown().await;
    }

    /// WHY: the placement cache also holds the agents of other owners
    /// (activation bundles arrive by gossip). This owner has no authority
    /// over them. If the action tried to stop them, every call would fail
    /// and answer 500 for ever, on an emergency route.
    #[tokio::test]
    async fn another_owners_agent_in_the_placement_cache_is_not_touched() {
        let dir = tempfile::tempdir().unwrap();
        let state = owned_state(dir.path()).await;
        enroll(&state, LOST).await;

        // Another owner's agent, pinned to the lost machine, in the cache.
        let other_owner = UserKeypair::generate().unwrap();
        let foreign = AgentKeypair::generate().unwrap();
        let foreign_cert = AgentCertificate::issue(&other_owner, &foreign).unwrap();
        let record = PlacementRecord::sign(
            foreign.agent_id(),
            other_owner.public_key().as_bytes(),
            Placement::Pinned(LOST),
            0,
            1_800_000_000,
            other_owner.secret_key(),
        )
        .unwrap();
        {
            let move_state = state.agent.move_state();
            let mut move_state = move_state.write().await;
            assert!(move_state
                .cache_placement(
                    record,
                    PlacementAuthority::cert_issuer(&foreign_cert).unwrap()
                )
                .unwrap());
            assert!(move_state.placement(&foreign.agent_id()).is_some());
        }

        let (status, body) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true);
        let foreign_hex = hex::encode(foreign.agent_id().as_bytes());
        assert!(
            body["agents"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["agent_id"] != foreign_hex),
            "{body}"
        );
        assert_eq!(body["agents_without_placement"], serde_json::json!([]));
        let peer = peer_view(&state).await;
        assert!(!peer.is_binding_revoked(&foreign.agent_id(), &LOST));
        assert!(!peer.is_agent_revoked(&foreign.agent_id()));
        assert!(peer.is_binding_revoked(&state.agent.agent_id(), &LOST));
        state.agent.shutdown().await;
    }

    /// WHY: when a record is in force but could not be written to disk,
    /// the operator must see which step to repeat. The answer is 500 with
    /// the same body, and the other steps still run.
    #[tokio::test]
    async fn a_record_that_is_not_durable_gives_500_and_names_the_step() {
        let dir = tempfile::tempdir().unwrap();
        let state = owned_state(dir.path()).await;
        enroll(&state, LOST).await;
        // The binding store cannot be read, so the daemon cannot write it.
        tokio::fs::write(dir.path().join("revocations-v2.bin"), b"unreadable")
            .await
            .unwrap();

        let (status, body) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["ok"], false);
        let local_row = row(&body, &state.agent.agent_id());
        assert!(
            local_row["binding"]
                .as_str()
                .is_some_and(|text| text.starts_with("revoked, not durable")),
            "{body}"
        );
        // The record is in force in memory, and the next step still ran.
        assert!(state
            .agent
            .revocation_set()
            .read()
            .await
            .is_binding_revoked(&state.agent.agent_id(), &LOST));
        assert_eq!(body["device_enrollment"], "removed");

        // The operator repeats the call. The tombstone is held, so the row
        // signs nothing. The daemon tries the store write again, and the
        // answer says exactly why it still fails: an unreadable store is
        // quarantined and is not written until it is rebuilt or resynced
        // (A03, #1116). The answer must not claim success.
        let (status, body) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["ok"], false);
        assert_eq!(
            row(&body, &state.agent.agent_id())["binding"],
            "already_revoked"
        );
        assert!(
            body["store_write_error"]
                .as_str()
                .is_some_and(|cause| cause.contains("quarantined")),
            "{body}"
        );
        assert!(state
            .agent
            .revocation_set()
            .read()
            .await
            .is_binding_revoked(&state.agent.agent_id(), &LOST));
        state.agent.shutdown().await;
    }

    /// WHY: an agent pinned to the lost machine had its key there, and a
    /// rider token for that agent may have been there too. The action
    /// revokes the agent, so its rider tokens must stop working as well.
    #[tokio::test]
    async fn lose_device_revokes_the_rider_tokens_of_a_pinned_agent() {
        let dir = tempfile::tempdir().unwrap();
        let state = owned_state(dir.path()).await;
        let pinned = issue(&state, "acp").await;
        pin(&state, &pinned, LOST).await;
        enroll(&state, LOST).await;
        let pinned_hex = hex::encode(pinned.agent_id().as_bytes());
        let now = crate::server::rider_auth::unix_now_secs();
        let (_, token) = state
            .rider_tokens
            .lock()
            .await
            .issue(
                pinned_hex.clone(),
                vec![],
                None,
                600,
                "digest".to_string(),
                None,
                None,
                now,
                Vec::new(),
            )
            .await
            .unwrap();
        let live = |records: Vec<crate::server::rider_auth::RiderTokenRecord>| {
            records
                .iter()
                .any(|record| record.token_id == token.token_id && record.revoked_at.is_none())
        };
        assert!(live(state.rider_tokens.lock().await.list()), "live before");

        let (status, body) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let pinned_row = row(&body, &pinned.agent_id());
        assert_eq!(pinned_row["agent"], "revoked");
        assert_eq!(pinned_row["rider_tokens_revoked"], 1, "{body}");
        assert_eq!(
            pinned_row["rider_token_sweep_error"],
            serde_json::Value::Null
        );
        assert!(
            !live(state.rider_tokens.lock().await.list()),
            "the token is revoked in the store that checks it"
        );
        let reloaded = crate::server::rider_auth::RiderTokenStore::load(
            dir.path()
                .join(crate::server::rider_auth::RIDER_TOKENS_FILE),
        )
        .await;
        assert!(!live(reloaded.list()), "and on disk");
        state.agent.shutdown().await;
    }

    /// A discovery-cache entry for `agent` that carries `cert`.
    async fn discover_with_cert(state: &Arc<AppState>, agent: AgentId, cert: AgentCertificate) {
        let now = crate::server::rider_auth::unix_now_secs();
        state
            .agent
            .insert_discovered_agent_for_testing(crate::DiscoveredAgent {
                agent_id: agent,
                machine_id: LOST,
                user_id: None,
                addresses: Vec::new(),
                announced_at: now,
                last_seen: now,
                machine_public_key: Vec::new(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                cert_not_after: None,
                agent_certificate: Some(cert),
                cert_digest: None,
                agent_public_key: Vec::new(),
                self_name: None,
            })
            .await;
    }

    /// WHY: one agent key can hold certificates from two owners. The
    /// discovery cache can hold the OTHER owner's certificate. The action
    /// must use the certificate this owner issued (its journal), as
    /// `DELETE /owner/agents/:id` does, or it fails where that route works.
    #[tokio::test]
    async fn an_agent_that_another_owner_also_certified_is_still_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let state = owned_state(dir.path()).await;
        let pinned = issue(&state, "acp").await;
        pin(&state, &pinned, LOST).await;
        enroll(&state, LOST).await;
        let other_owner = UserKeypair::generate().unwrap();
        let foreign_cert = AgentCertificate::issue(&other_owner, &pinned).unwrap();
        discover_with_cert(&state, pinned.agent_id(), foreign_cert).await;

        let (status, body) = lose(&state, true, &hex::encode(LOST.0), false).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let pinned_row = row(&body, &pinned.agent_id());
        assert_eq!(pinned_row["binding"], "revoked", "{body}");
        assert_eq!(pinned_row["agent"], "revoked", "{body}");
        assert!(peer_view(&state).await.is_agent_revoked(&pinned.agent_id()));
        state.agent.shutdown().await;
    }

    /// WHY: the owner has authority over an agent only through a
    /// certificate that this owner issued. With no certificate, or with
    /// one from another owner, the call must fail with a clear cause and
    /// must sign nothing.
    #[tokio::test]
    async fn owner_revocation_by_id_needs_this_owners_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let state = owned_state(dir.path()).await;

        let unknown = AgentKeypair::generate().unwrap();
        let error = state
            .agent
            .revoke_agent_as_owner(&unknown.agent_id(), None)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("no certificate known"),
            "{error}"
        );

        let other_owner = UserKeypair::generate().unwrap();
        let foreign = AgentKeypair::generate().unwrap();
        let foreign_cert = AgentCertificate::issue(&other_owner, &foreign).unwrap();
        discover_with_cert(&state, foreign.agent_id(), foreign_cert).await;
        let error = state
            .agent
            .revoke_agent_as_owner(&foreign.agent_id(), None)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("not issued by this owner"),
            "{error}"
        );
        assert!(state.agent.all_revocation_records().await.is_empty());
        state.agent.shutdown().await;
    }
}
