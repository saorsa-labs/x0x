//! Route handlers for ADR-0074 §1 names (`category: "names"` in
//! `src/api/mod.rs`): list owner petnames and pins, resolve a name (pinning
//! it at first use), bind or remove an owner petname, label a shared
//! machine, and drop a pin so the owner can re-pin.
//!
//! Every route is owner/durable-token only: petnames are "editable only by
//! the local owner" (ADR-0074 §1), and resolving pins a name. The auth
//! middleware refuses session bearers and riders before any extractor runs
//! (`requires_durable_owner`); the handlers re-check as defense in depth.
//!
//! Resolution adds no trust: it maps a name to an id; every gate still
//! applies to whatever the caller does with that id.

use super::super::rider_auth::ActorContext;
use super::super::state::AppState;
use crate as x0x;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use x0x::identity::{MachineId, UserId};
use x0x::names::{BindOutcome, BindSource, NameError, NameRef, PeerRef, Resolved};

const DURABLE_REQUIRED: &str =
    "name management requires the durable API token (not a session or rider token)";

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "ok": false, "error": DURABLE_REQUIRED })),
    )
        .into_response()
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_id32(field: &str, raw: &str) -> Result<[u8; 32], NameError> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(raw, &mut out)
        .map_err(|e| NameError::Invalid(format!("{field}: expected 64 hex chars: {e}")))?;
    Ok(out)
}

/// HTTP status for a refused name.
pub(in crate::server) fn name_error_status(err: &NameError) -> StatusCode {
    match err {
        NameError::Invalid(_) | NameError::Reserved(_) | NameError::MachineTargetUnsupported(_) => {
            StatusCode::BAD_REQUEST
        }
        NameError::UnknownName(_) => StatusCode::NOT_FOUND,
        NameError::UnverifiedOwner(_) => StatusCode::UNPROCESSABLE_ENTITY,
        NameError::AmbiguousName { .. }
        | NameError::AmbiguousKind(_)
        | NameError::PinMismatch { .. } => StatusCode::CONFLICT,
        NameError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// A refused name as a REST response: `{ok:false, error, code, …}` with
/// the candidates (ambiguous) or both ids (pin mismatch).
pub(in crate::server) fn name_error(err: &NameError) -> Response {
    let mut body = serde_json::json!({
        "ok": false,
        "error": err.to_string(),
        "code": err.code(),
    });
    match err {
        NameError::AmbiguousName { candidates, .. } => {
            body["candidates"] = serde_json::json!(candidates);
        }
        NameError::PinMismatch {
            pinned, current, ..
        } => {
            body["pinned"] = serde_json::json!(pinned);
            body["current"] = serde_json::json!(current);
        }
        _ => {}
    }
    (name_error_status(err), Json(body)).into_response()
}

/// Resolve `name` against this daemon's local state, pinning at first use.
pub(in crate::server) async fn resolve(
    state: &AppState,
    name: &NameRef,
) -> Result<Resolved, NameError> {
    let devices = state.owner_sync.as_ref().map(|s| &**s.store());
    state.agent.resolve_name(&state.names, devices, name).await
}

fn resolved_json(resolved: &Resolved) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "name": resolved.name,
        "kind": resolved.kind.as_str(),
        "owner_user_id": hex::encode(resolved.owner.as_bytes()),
        "agent_id": resolved.agent_id.map(|a| hex::encode(a.as_bytes())),
        "machine_id": resolved.machine_id.map(|m| hex::encode(m.as_bytes())),
        "newly_pinned": resolved.newly_pinned,
    })
}

fn source_str(source: BindSource) -> &'static str {
    match source {
        BindSource::Card => "card",
        BindSource::Manual => "manual",
        BindSource::FirstUse => "first_use",
    }
}

/// GET /names — owner petnames and pins.
pub(in crate::server) async fn names_list(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    let (owners, pins) = match state.names.snapshot().await {
        Ok(snapshot) => snapshot,
        Err(e) => return name_error(&e),
    };
    let owners: Vec<serde_json::Value> = owners
        .iter()
        .map(|(label, b)| {
            serde_json::json!({
                "label": label,
                "user_id": hex::encode(b.user_id.as_bytes()),
                "bound_at": b.bound_at,
                "source": source_str(b.source),
            })
        })
        .collect();
    let pins: Vec<serde_json::Value> = pins
        .iter()
        .map(|(name, p)| {
            serde_json::json!({
                "name": name,
                "id": hex::encode(p.id),
                "owner_user_id": hex::encode(p.owner.as_bytes()),
                "pinned_at": p.pinned_at,
                "source": source_str(p.source),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "owners": owners, "pins": pins })),
    )
        .into_response()
}

/// `POST /names/resolve` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct NameResolveRequest {
    /// `[agent:|machine:]<label>.<owner>`, or a hex agent id.
    name: String,
}

/// POST /names/resolve — resolve a name locally; pins it at first use.
pub(in crate::server) async fn names_resolve(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<NameResolveRequest>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    let name = match PeerRef::parse(&req.name) {
        Ok(PeerRef::Hex(agent)) => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "name": serde_json::Value::Null,
                    "kind": "agent",
                    "agent_id": hex::encode(agent.as_bytes()),
                    "newly_pinned": false,
                })),
            )
                .into_response();
        }
        Ok(PeerRef::Name(name)) => name,
        Err(e) => return name_error(&e),
    };
    match resolve(&state, &name).await {
        Ok(resolved) => (StatusCode::OK, Json(resolved_json(&resolved))).into_response(),
        Err(e) => name_error(&e),
    }
}

/// `POST /names/owners` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct NameOwnerBindRequest {
    /// The owner petname (DNS label; not `me`, `agent` or `machine`).
    label: String,
    /// The owner's user id (hex).
    user_id: String,
}

/// POST /names/owners — bind an owner petname (frozen at first bind).
pub(in crate::server) async fn names_owner_bind(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<NameOwnerBindRequest>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    let user = match parse_id32("user_id", &req.user_id) {
        Ok(bytes) => UserId(bytes),
        Err(e) => return name_error(&e),
    };
    if state.agent.user_id() == Some(user) {
        return name_error(&NameError::Invalid(
            "that user id is this install's owner; it is always `me`".into(),
        ));
    }
    match state
        .names
        .bind_owner(&req.label, user, BindSource::Manual, unix_now_secs())
        .await
    {
        Ok(outcome) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "label": req.label,
                "user_id": hex::encode(user.as_bytes()),
                "bound": outcome == BindOutcome::Inserted,
            })),
        )
            .into_response(),
        Err(e) => name_error(&e),
    }
}

/// DELETE /names/owners/:label — remove an owner petname and its pins.
pub(in crate::server) async fn names_owner_unbind(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(label): Path<String>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    match state.names.unbind_owner(&label).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "removed": true })),
        )
            .into_response(),
        Ok(false) => name_error(&NameError::UnknownName(format!(
            "owner label {label:?} is not bound"
        ))),
        Err(e) => name_error(&e),
    }
}

/// `POST /names/machines` body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct NameMachineLabelRequest {
    /// `machine:<label>.<owner>` (owner is a bound petname, not `me`).
    name: String,
    /// The shared machine (hex).
    machine_id: String,
}

/// POST /names/machines — label a machine shared with this install by a
/// received ShareGrant. Refused unless it hosts a granted agent now.
pub(in crate::server) async fn names_machine_label(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<NameMachineLabelRequest>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    let name = match NameRef::parse(&req.name) {
        Ok(name) => name,
        Err(e) => return name_error(&e),
    };
    let machine = match parse_id32("machine_id", &req.machine_id) {
        Ok(bytes) => MachineId(bytes),
        Err(e) => return name_error(&e),
    };
    match state
        .agent
        .label_shared_machine(&state.names, &name, machine)
        .await
    {
        Ok(outcome) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "name": name.to_string(),
                "machine_id": hex::encode(machine.as_bytes()),
                "pinned": outcome == BindOutcome::Inserted,
            })),
        )
            .into_response(),
        Err(e) => name_error(&e),
    }
}

/// DELETE /names/pins/:name — drop a pin so the name re-pins at next use.
pub(in crate::server) async fn names_unpin(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(name): Path<String>,
) -> Response {
    if !actor.is_durable_owner() {
        return forbidden();
    }
    match state.names.unpin(&name).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "removed": true })),
        )
            .into_response(),
        Ok(false) => name_error(&NameError::UnknownName(format!("no pin for {name}"))),
        Err(e) => name_error(&e),
    }
}

/// ADR-0074 §1: bind an owner petname from an imported card.
///
/// Only a **signed** (already verified) card that carries both `user_id`
/// and `owner_name`, for a contact that is not `Blocked`, binds; the label
/// is the card's `owner_name` as a DNS label ([`x0x::names::label_from_display`]).
/// A user that already has a label, or the local owner (always `me`), binds
/// nothing. A label already bound to a different user is left untouched
/// and reported as `conflict` (frozen at first bind). The import itself
/// never fails because of naming. Returns `null` when nothing applied.
pub(in crate::server) async fn bind_owner_from_card(
    state: &AppState,
    card: &x0x::groups::card::AgentCard,
    trust: x0x::contacts::TrustLevel,
) -> serde_json::Value {
    if card.signature.is_none() || trust == x0x::contacts::TrustLevel::Blocked {
        return serde_json::Value::Null;
    }
    let (Some(user_hex), Some(owner_name)) = (&card.user_id, &card.owner_name) else {
        return serde_json::Value::Null;
    };
    let Ok(user) = parse_id32("user_id", user_hex).map(UserId) else {
        return serde_json::Value::Null;
    };
    if state.agent.user_id() == Some(user) {
        return serde_json::Value::Null;
    }
    match state.names.label_for(&user).await {
        Ok(Some(label)) => {
            return serde_json::json!({ "label": label, "status": "existing" });
        }
        Ok(None) => {}
        Err(e) => return serde_json::json!({ "status": "store_error", "error": e.to_string() }),
    }
    let Some(label) = x0x::names::label_from_display(owner_name) else {
        return serde_json::json!({ "status": "unusable_owner_name" });
    };
    match state
        .names
        .bind_owner(&label, user, BindSource::Card, unix_now_secs())
        .await
    {
        Ok(_) => serde_json::json!({ "label": label, "status": "bound" }),
        Err(NameError::PinMismatch { .. }) => {
            serde_json::json!({ "label": label, "status": "conflict" })
        }
        Err(e) => serde_json::json!({ "status": "store_error", "error": e.to_string() }),
    }
}

#[cfg(test)]
mod tests;
