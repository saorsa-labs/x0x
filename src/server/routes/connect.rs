//! Route handlers (`category: "connect"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::api_error;
use super::super::state::AppState;
use crate as x0x;
use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use std::net::SocketAddr;
use std::sync::Arc;

// ── Tailnet forwarding (#132 T6) ──────────────────────────────────────────

/// POST /forwards — register a local port forward.
#[derive(serde::Deserialize)]
pub(in crate::server) struct ForwardAddRequest {
    /// Local bind, e.g. `127.0.0.1:8022`.
    local_addr: String,
    /// Peer: hex agent id, or an ADR-0074 name (`[agent:|machine:]<label>.<owner>`).
    /// A machine name pins the `MachineId` every stream must reach.
    peer_agent: String,
    /// Loopback target host on the peer (numeric IP).
    target_host: String,
    /// Loopback target port.
    target_port: u16,
    /// ADR-0074 §2 (Q3): forwards persist in `forwards.json` by default;
    /// `true` keeps this one in memory only.
    #[serde(default)]
    ephemeral: bool,
}

fn forward_error(status: StatusCode, code: &str, error: String) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": error, "code": code })),
    )
        .into_response()
}

fn store_error_response(e: &x0x::forward::store::ForwardStoreError) -> axum::response::Response {
    use x0x::forward::store::ForwardStoreError;
    let (status, code) = match e {
        ForwardStoreError::Unusable(_) | ForwardStoreError::Write(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "forward_store")
        }
        ForwardStoreError::Full => (StatusCode::CONFLICT, "forward_store_full"),
        ForwardStoreError::Unpinned(_) => (StatusCode::CONFLICT, "machine_unknown"),
        ForwardStoreError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid_forward"),
    };
    forward_error(status, code, e.to_string())
}

pub(in crate::server) async fn forward_add(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ForwardAddRequest>,
) -> impl IntoResponse {
    use x0x::forward::ForwardSpec;
    use x0x::names::{NameKind, PeerRef};
    // Syntax first, before any state is consulted.
    let peer = match PeerRef::parse(&req.peer_agent) {
        Ok(peer) => peer,
        Err(e) => return super::names::name_error(&e),
    };
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
    // ADR-0074 §1: a name resolves locally (pinned at first use). An agent
    // name gives the agent; a machine name gives the agent its daemon
    // announces AND the MachineId every stream must reach. Resolution adds
    // no trust: the stream still passes the identity gate and the peer's
    // connect ACL.
    let (peer_agent, name, kind, machine_pin) = match peer {
        PeerRef::Hex(id) => (id, None, NameKind::Agent, None),
        PeerRef::Name(name) => {
            let resolved = match super::names::resolve(&state, &name).await {
                Ok(resolved) => resolved,
                Err(e) => return super::names::name_error(&e),
            };
            match x0x::names::forward_target(&resolved, &name) {
                Ok((agent, machine)) => (agent, Some(resolved.name), resolved.kind, machine),
                Err(e) => return super::names::name_error(&e),
            }
        }
    };
    // ADR-0074 §1/§2: a persisted forward is pinned to a machine. For an
    // agent target that is the machine the agent is bound to now (the one
    // its streams would open to); an ephemeral agent forward stays
    // unpinned, as before.
    let pinned_machine = match machine_pin {
        Some(machine) => Some(machine),
        None if !req.ephemeral => state
            .agent
            .cached_agent(&peer_agent)
            .await
            .map(|d| d.machine_id),
        None => None,
    };
    let spec = ForwardSpec {
        local_addr,
        peer_agent,
        target_host: req.target_host,
        target_port: req.target_port,
        name: name.clone(),
        kind,
        pinned_machine,
        persistent: !req.ephemeral,
    };
    // Refuse a persistent forward the store cannot take BEFORE binding.
    if let Err(e) = state.forwards.check(&spec) {
        return store_error_response(&e);
    }
    let bound = match forwarder.add_forward(spec.clone()).await {
        Ok(bound) => bound,
        Err(e) => return api_error(StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    };
    let mut registered = spec;
    registered.local_addr = bound;
    if let Err(e) = state.forwards.remember(&registered).await {
        // Not durable: do not leave a forward running that the caller was
        // told failed.
        forwarder.remove_forward(bound);
        return store_error_response(&e);
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "local_addr": bound.to_string(),
            "peer_agent": hex::encode(peer_agent.as_bytes()),
            "name": name,
            "kind": kind.as_str(),
            "pinned_machine_id": pinned_machine.map(|m| hex::encode(m.as_bytes())),
            "persistent": registered.persistent,
        })),
    )
        .into_response()
}

fn forward_json(status: &x0x::forward::ForwardStatus) -> serde_json::Value {
    let s = &status.spec;
    serde_json::json!({
        "local_addr": s.local_addr.to_string(),
        "peer_agent": s.peer_agent_hex(),
        "target_host": s.target_host,
        "target_port": s.target_port,
        "name": s.name,
        "kind": s.kind.as_str(),
        "pinned_machine_id": s.pinned_machine.map(|m| hex::encode(m.as_bytes())),
        "persistent": s.persistent,
        "enabled": status.error.is_none(),
        "error": status.error,
    })
}

/// GET /forwards — list registered forwards, including restored forwards
/// that are down (`enabled: false` with an `error`).
pub(in crate::server) async fn forward_list(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let forwards: Vec<serde_json::Value> = state
        .forward_service
        .as_ref()
        .map(|f| f.list_forwards().iter().map(forward_json).collect())
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "forwards": forwards,
            "store_error": state.forwards.load_error(),
        })),
    )
}

/// DELETE /forwards/:local_addr — tear down a forward by its local bind
/// addr and delete its persisted record.
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
    // Forget the durable record first, so a deleted forward never comes
    // back at the next start. A store failure leaves the running forward
    // in place and reports it.
    let persistent = forwarder.forward_at(addr).is_none_or(|s| s.persistent);
    let forgotten = if persistent {
        match state.forwards.forget(addr).await {
            Ok(forgotten) => forgotten,
            Err(e) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "ok": false,
                        "removed": false,
                        "error": e.to_string(),
                        "code": "forward_store",
                    })),
                );
            }
        }
    } else {
        false
    };
    let removed = forwarder.remove_forward(addr) || forgotten;
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

/// How often restored forwards that are down are re-resolved and re-bound.
pub(in crate::server) const FORWARD_RESTORE_RETRY_SECS: u64 = 10;

/// Bring one persisted forward up, or register it as down with the reason
/// (ADR-0074 §2). Its name is re-resolved through the name store, where the
/// pin applies; it only comes up on exactly its pinned ids.
async fn restore_one(
    state: &AppState,
    forwarder: &x0x::forward::ForwardService,
    record: &x0x::forward::store::ForwardRecord,
) -> bool {
    let resolution = match &record.name {
        None => None,
        Some(raw) => Some(match x0x::names::NameRef::parse(raw) {
            Ok(name) => super::names::resolve(state, &name).await,
            Err(e) => Err(e),
        }),
    };
    let spec = match x0x::forward::store::restore_decision(record, resolution) {
        Ok(spec) => spec,
        Err(reason) => {
            tracing::warn!(
                target: "x0x::forward",
                forward = %record.id,
                %reason,
                "persisted forward stays down"
            );
            forwarder.add_disabled(record.to_spec(), reason);
            return false;
        }
    };
    match forwarder.add_forward(spec.clone()).await {
        Ok(_) => true,
        Err(e) => {
            let reason = format!("bind_failed: {e}");
            tracing::warn!(
                target: "x0x::forward",
                forward = %record.id,
                %reason,
                "persisted forward stays down"
            );
            forwarder.add_disabled(spec, reason);
            false
        }
    }
}

/// Restore every persisted forward that is not already listening. Returns
/// how many are still down. Never fails: a corrupt store restores nothing
/// (and is reported by `GET /forwards`), a bad record stays down.
pub(in crate::server) async fn restore_forwards(state: &AppState) -> usize {
    let Some(forwarder) = state.forward_service.as_ref() else {
        return 0;
    };
    let records = match state.forwards.records().await {
        Ok(records) => records,
        Err(e) => {
            tracing::warn!(target: "x0x::forward", "persisted forwards not restored: {e}");
            return 0;
        }
    };
    let listening: std::collections::BTreeSet<SocketAddr> = forwarder
        .list_forwards()
        .iter()
        .filter(|f| f.error.is_none())
        .map(|f| f.spec.local_addr)
        .collect();
    let mut down = 0;
    for record in records {
        if listening.contains(&record.local_addr) {
            continue;
        }
        if !restore_one(state, forwarder, &record).await {
            down += 1;
        }
    }
    down
}

/// GET /streams — active forward-stream count, live streams with their
/// authority (ADR-0074 §4), teardown and connect-ACL counters.
pub(in crate::server) async fn streams_diagnostics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let forward = state.forward_service.as_ref();
    let diag = forward.map(|f| f.diagnostics());
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active_streams": diag.map_or(0, |d| d.active_streams()),
            "connect_failed": diag.map_or(0, |d| d.connect_failed()),
            "machine_mismatch": diag.map_or(0, |d| d.machine_mismatch()),
            "torn_down_reauth": diag.map_or(0, |d| d.torn_down_reauth()),
            "torn_down_reasons": diag.map(|d| d.torn_down_reasons()).unwrap_or_default(),
            "live": forward.map(|f| f.live_streams()).unwrap_or_default(),
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
pub(in crate::server) async fn connect_diagnostics_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    Json(state.connect_diagnostics.snapshot())
}
