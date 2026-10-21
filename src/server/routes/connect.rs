//! Route handlers (`category: "connect"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.
//!
//! `POST /forwards` and `DELETE /forwards/:local_addr` are owner/durable-token
//! only. Adding a forward resolves (and pins) a name; deleting one removes
//! the owner's persisted record. The auth middleware refuses session
//! bearers and riders before any extractor runs
//! (`requires_durable_owner`); the handlers re-check as defense in depth.

use super::super::api_error;
use super::super::rider_auth::ActorContext;
use super::super::state::AppState;
use crate as x0x;
use anyhow::Result;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::net::SocketAddr;
use std::sync::Arc;

const DURABLE_REQUIRED: &str =
    "name management requires the durable API token (not a session or rider token)";

/// `GET /forwards` `error` for a saved record when connect is disabled.
///
/// The daemon has no forwarder, so the record cannot listen. The text
/// starts with the `connect_disabled` code, the same shape as `name_changed`
/// and `bind_failed`.
const CONNECT_DISABLED_REASON: &str =
    "connect_disabled: connect forwarding is disabled (no connect ACL loaded)";

fn durable_forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "ok": false, "error": DURABLE_REQUIRED })),
    )
        .into_response()
}

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
        ForwardStoreError::Unusable(_)
        | ForwardStoreError::Write(_)
        | ForwardStoreError::Unconfirmed(_) => (StatusCode::SERVICE_UNAVAILABLE, "forward_store"),
        ForwardStoreError::Full => (StatusCode::CONFLICT, "forward_store_full"),
        ForwardStoreError::Unpinned(_) => (StatusCode::CONFLICT, "machine_unknown"),
        ForwardStoreError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid_forward"),
    };
    forward_error(status, code, e.to_string())
}

pub(in crate::server) async fn forward_add(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<ForwardAddRequest>,
) -> impl IntoResponse {
    use x0x::forward::{ForwardBinding, ForwardSpec};
    use x0x::names::{NameKind, PeerRef};
    if !actor.is_durable_owner() {
        return durable_forbidden();
    }
    // Syntax first, before any state is consulted.
    let peer = match PeerRef::parse_forward_peer(&req.peer_agent) {
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
    // agent target that is the machine `gate_peer_outbound_at` would dial
    // (confirmed route, otherwise the authority machine) — not the raw
    // discovery cache. An ephemeral agent forward stays unpinned.
    let pinned_machine = match machine_pin {
        Some(machine) => Some(machine),
        None if !req.ephemeral => state.agent.outbound_dial_machine(&peer_agent).await,
        None => None,
    };
    let spec = ForwardSpec {
        local_addr,
        peer_agent,
        target_host: req.target_host,
        target_port: req.target_port,
    };
    let binding = ForwardBinding {
        name: name.clone(),
        kind,
        pinned_machine,
        persistent: !req.ephemeral,
    };
    let bound = match commit_forward(&state.forwards, forwarder, spec, binding).await {
        Ok(bound) => bound,
        Err(CommitError::Store(e)) => return store_error_response(&e),
        Err(CommitError::Bind(e)) => {
            return api_error(StatusCode::BAD_GATEWAY, e.to_string()).into_response()
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "local_addr": bound.to_string(),
            "peer_agent": hex::encode(peer_agent.as_bytes()),
            "name": name,
            "kind": kind.as_str(),
            "pinned_machine_id": pinned_machine.map(|m| hex::encode(m.as_bytes())),
            "persistent": !req.ephemeral,
        })),
    )
        .into_response()
}

#[derive(Debug)]
enum CommitError {
    Store(x0x::forward::store::ForwardStoreError),
    Bind(x0x::error::NetworkError),
}

/// Bind `spec` and make the store match it, holding the forward lifecycle
/// lock so this cannot interleave with restore or remove.
///
/// The lock, the listener, and the store write run on a transaction the
/// caller cannot cancel. Dropping the caller's future detaches that
/// transaction. It stays in the forwarder's shutdown registry and keeps
/// the lock until the listener and the saved record describe the same
/// forward. Shutdown drains the transaction before it cancels listeners,
/// so the transaction cannot publish a listener after shutdown returns.
/// Cancelling between the bind and the rename therefore cannot leave the
/// new listener up while the old target stays in `forwards.json`.
///
/// An ephemeral spec deletes any durable record at the bound address, so a
/// disabled persistent forward replaced by `--ephemeral` cannot return on
/// restart. The socket is bound before the save and does not accept until
/// the save succeeds. A store failure before the rename drops that socket
/// (and puts a disabled entry back when that is what the bind replaced).
/// A connection already accepted on that listener is dropped with it.
/// A failure after the rename starts accepting and leaves the listener in
/// place: the new file is already on disk, so tearing the listener down
/// would let a restart bring the forward back. An unreadable store does
/// not block an ephemeral add — there is no usable record to delete.
async fn commit_forward(
    store: &Arc<x0x::forward::store::ForwardStore>,
    forwarder: &Arc<x0x::forward::ForwardService>,
    spec: x0x::forward::ForwardSpec,
    binding: x0x::forward::ForwardBinding,
) -> Result<SocketAddr, CommitError> {
    if let Err(e) = store.check(&spec, &binding) {
        return Err(CommitError::Store(e));
    }
    let store = Arc::clone(store);
    let forwarder = Arc::clone(forwarder);
    let task_forwarder = Arc::clone(&forwarder);
    match forwarder
        .run_transaction(async move {
            commit_forward_locked(&store, &task_forwarder, spec, binding).await
        })
        .await
    {
        Ok(result) => result,
        Err(error) => Err(CommitError::Store(
            x0x::forward::store::ForwardStoreError::Write(error.to_string()),
        )),
    }
}

async fn commit_forward_locked(
    store: &x0x::forward::store::ForwardStore,
    forwarder: &x0x::forward::ForwardService,
    spec: x0x::forward::ForwardSpec,
    binding: x0x::forward::ForwardBinding,
) -> Result<SocketAddr, CommitError> {
    let _ops = store.lock_ops().await;
    let previous = forwarder
        .list_forward_status()
        .into_iter()
        .find(|status| status.spec.local_addr == spec.local_addr);
    let allocating = spec.local_addr.port() == 0;
    let mut allocations = 0u32;
    let bound = loop {
        allocations += 1;
        if allocations > 8 {
            forwarder.release_allocation_holds();
            return Err(CommitError::Bind(
                x0x::error::NetworkError::ConnectionFailed(
                    "could not allocate a port that is not a saved forward".to_string(),
                ),
            ));
        }
        match forwarder.bind_forward(spec.clone(), binding.clone()).await {
            Err(error) if allocating && x0x::forward::is_port_allocation_collision(&error) => {
                continue;
            }
            Err(error) => {
                forwarder.release_allocation_holds();
                return Err(CommitError::Bind(error));
            }
            Ok(bound) if allocating => {
                // An unreadable store has no saved ports. An ephemeral add
                // already skips the record update in that case, so the
                // allocation must not fail closed on `records()` either.
                if binding.persistent || store.load_error().is_none() {
                    let saved = match store.records().await {
                        Ok(records) => records,
                        Err(error) => {
                            forwarder.remove_forward(bound);
                            forwarder.release_allocation_holds();
                            return Err(CommitError::Store(error));
                        }
                    };
                    if saved.iter().any(|record| record.local_addr == bound) {
                        forwarder.remove_forward(bound);
                        if let Ok(hold) = tokio::net::TcpListener::bind(bound).await {
                            forwarder.hold_allocation(hold);
                        }
                        continue;
                    }
                }
                break bound;
            }
            Ok(bound) => break bound,
        }
    };
    forwarder.release_allocation_holds();
    let mut registered = spec;
    registered.local_addr = bound;
    let persisted = if binding.persistent {
        store.remember(&registered, &binding).await.map(|_| ())
    } else if store.load_error().is_some() {
        Ok(())
    } else {
        store.forget(bound).await.map(|_| ())
    };
    if let Err(e) = persisted {
        // After the rename the new bytes are the store. Accept, and keep
        // the listener, so a restart cannot resurrect a forward this
        // handler tore down.
        if e.durability_unconfirmed() {
            forwarder.start_accept(bound).map_err(CommitError::Bind)?;
            return Err(CommitError::Store(e));
        }
        forwarder.remove_forward(bound);
        if let Some(prev) = previous.filter(|status| status.spec.local_addr == bound) {
            if let Some(reason) = prev.error {
                forwarder.add_disabled(prev.spec, prev.binding, reason);
            }
        }
        return Err(CommitError::Store(e));
    }
    forwarder.start_accept(bound).map_err(CommitError::Bind)?;
    Ok(bound)
}

fn forward_json(status: &x0x::forward::ForwardStatus) -> serde_json::Value {
    let s = &status.spec;
    let binding = &status.binding;
    serde_json::json!({
        "local_addr": s.local_addr.to_string(),
        "peer_agent": s.peer_agent_hex(),
        "target_host": s.target_host,
        "target_port": s.target_port,
        "name": binding.name,
        "kind": binding.kind.as_str(),
        "pinned_machine_id": binding.pinned_machine.map(|m| hex::encode(m.as_bytes())),
        "persistent": binding.persistent,
        "enabled": status.error.is_none(),
        "error": status.error,
    })
}

fn disabled_saved_json(record: &x0x::forward::store::ForwardRecord) -> serde_json::Value {
    serde_json::json!({
        "local_addr": record.local_addr.to_string(),
        "peer_agent": hex::encode(record.pinned_agent_id.as_bytes()),
        "target_host": record.target_host,
        "target_port": record.target_port,
        "name": record.name,
        "kind": record.kind.as_str(),
        "pinned_machine_id": hex::encode(record.pinned_machine_id.as_bytes()),
        "persistent": true,
        "enabled": false,
        "error": CONNECT_DISABLED_REASON,
    })
}

async fn disabled_saved_forwards(
    store: &x0x::forward::store::ForwardStore,
) -> Vec<serde_json::Value> {
    match store.records().await {
        Ok(records) => records.iter().map(disabled_saved_json).collect(),
        Err(_) => Vec::new(),
    }
}

/// GET /forwards — list registered forwards, including restored forwards
/// that are down (`enabled: false` with an `error`).
///
/// No forwarder means connect is disabled. Saved records are still listed,
/// each with `enabled` false and an `error` that starts with
/// `connect_disabled`. An unreadable store stays an empty list;
/// `store_error` carries the load failure.
pub(in crate::server) async fn forward_list(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let forwards: Vec<serde_json::Value> = match state.forward_service.as_ref() {
        Some(forwarder) => forwarder
            .list_forward_status()
            .iter()
            .map(forward_json)
            .collect(),
        None => disabled_saved_forwards(&state.forwards).await,
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "forwards": forwards,
            "store_error": state.forwards.load_error(),
        })),
    )
}

/// DELETE /forwards/:local_addr — tear down a forward by its local bind
/// addr and delete its persisted record. Durable-owner only: a session
/// or rider token must not delete the owner's forwards.
///
/// Connect disabled (no ACL) leaves no forwarder after restart. The saved
/// record is still deleted. `POST /forwards` stays `409` in that state:
/// there is no listener to bind.
pub(in crate::server) async fn forward_remove(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Path(local_addr): Path<String>,
) -> impl IntoResponse {
    if !actor.is_durable_owner() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": DURABLE_REQUIRED })),
        );
    }
    let Ok(addr): Result<SocketAddr, _> = local_addr.parse() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "removed": false })),
        );
    };
    // Forget the durable record first, including one hidden behind an
    // ephemeral in-memory entry, so a deleted forward never comes back at
    // the next start. A store failure leaves the running forward in place
    // and reports it. No forwarder means connect is disabled: delete the
    // saved record anyway.
    let removed = match forget_forward(&state.forwards, state.forward_service.as_ref(), addr).await
    {
        Ok(removed) => removed,
        // The rename already dropped the record. A running listener is
        // stopped too. Durability is still unconfirmed, so this is not
        // success, and it is not the pre-rename failure that leaves a
        // listener up.
        Err(e) if e.durability_unconfirmed() => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "ok": false,
                    "removed": true,
                    "error": e.to_string(),
                    "code": "forward_store",
                })),
            );
        }
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
    };
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

/// Delete the saved forward at `addr`.
///
/// `forwarder` is absent when connect is disabled. The saved record is
/// still removed, and there is no listener to stop. A present forwarder
/// goes through [`remove_persisted`].
async fn forget_forward(
    store: &Arc<x0x::forward::store::ForwardStore>,
    forwarder: Option<&Arc<x0x::forward::ForwardService>>,
    addr: SocketAddr,
) -> Result<bool, x0x::forward::store::ForwardStoreError> {
    match forwarder {
        Some(forwarder) => remove_persisted(store, forwarder, addr).await,
        None => store.forget(addr).await,
    }
}

/// Delete the durable record at `addr` and the in-memory forward, holding
/// the lifecycle lock for both. The record is removed even when the live
/// entry is ephemeral, unless the store did not load: an unreadable file
/// must not block teardown of a live ephemeral forward, and it is never
/// overwritten. A persistent live entry stays until the rename publishes
/// the deletion. A pre-rename failure leaves it up.
///
/// Like [`commit_forward`], the lock and both steps run on a transaction
/// the caller cannot cancel. The transaction stays in the forwarder's
/// shutdown registry, so a dropped request cannot delete the saved record
/// and leave the listener, or the reverse, and shutdown drains it before
/// listeners are cancelled.
///
/// A failure before the rename leaves the listener in place. A failure
/// after the rename (`Unconfirmed`) has already removed the record from
/// memory and from the file: the listener is removed too, and the error
/// still reports that durability is not confirmed.
async fn remove_persisted(
    store: &Arc<x0x::forward::store::ForwardStore>,
    forwarder: &Arc<x0x::forward::ForwardService>,
    addr: SocketAddr,
) -> Result<bool, x0x::forward::store::ForwardStoreError> {
    let store = Arc::clone(store);
    let forwarder = Arc::clone(forwarder);
    let task_forwarder = Arc::clone(&forwarder);
    match forwarder
        .run_transaction(
            async move { remove_persisted_locked(&store, &task_forwarder, addr).await },
        )
        .await
    {
        Ok(result) => result,
        Err(error) => Err(x0x::forward::store::ForwardStoreError::Write(
            error.to_string(),
        )),
    }
}

async fn remove_persisted_locked(
    store: &x0x::forward::store::ForwardStore,
    forwarder: &x0x::forward::ForwardService,
    addr: SocketAddr,
) -> Result<bool, x0x::forward::store::ForwardStoreError> {
    let _ops = store.lock_ops().await;
    let live_persistent = forwarder
        .list_forward_status()
        .into_iter()
        .any(|status| status.spec.local_addr == addr && status.binding.persistent);
    if store.load_error().is_some() && !live_persistent {
        return Ok(forwarder.remove_forward(addr));
    }
    match store.forget(addr).await {
        Ok(forgotten) => Ok(forwarder.remove_forward(addr) || forgotten),
        Err(error) if error.durability_unconfirmed() => {
            forwarder.remove_forward(addr);
            Err(error)
        }
        Err(error) => Err(error),
    }
}

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
    install_restored(forwarder, record, resolution).await
}

async fn install_restored(
    forwarder: &x0x::forward::ForwardService,
    record: &x0x::forward::store::ForwardRecord,
    resolution: Option<Result<x0x::names::Resolved, x0x::names::NameError>>,
) -> bool {
    let (spec, binding) = match x0x::forward::store::restore_decision(record, resolution) {
        Ok(parts) => parts,
        Err(reason) => {
            tracing::warn!(
                target: "x0x::forward",
                forward = %record.id,
                %reason,
                "persisted forward stays down"
            );
            forwarder.add_disabled(record.to_spec(), record.binding(), reason);
            return false;
        }
    };
    match forwarder
        .add_forward_with(spec.clone(), binding.clone())
        .await
    {
        Ok(_) => true,
        Err(e) => {
            let reason = format!("bind_failed: {e}");
            tracing::warn!(
                target: "x0x::forward",
                forward = %record.id,
                %reason,
                "persisted forward stays down"
            );
            forwarder.add_disabled(spec, binding, reason);
            false
        }
    }
}

/// Copy persisted forwards under the lifecycle lock and install each one
/// before the lock is released. `on_record` returns whether the forward is
/// listening.
async fn restore_holding<F, Fut>(
    store: &x0x::forward::store::ForwardStore,
    forwarder: &x0x::forward::ForwardService,
    mut on_record: F,
) -> usize
where
    F: FnMut(&x0x::forward::store::ForwardRecord) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let session = match store.begin_restore().await {
        Ok(session) => session,
        Err(e) => {
            tracing::warn!(target: "x0x::forward", "persisted forwards not restored: {e}");
            return 0;
        }
    };
    let listening: std::collections::BTreeSet<SocketAddr> = forwarder
        .list_forward_status()
        .iter()
        .filter(|f| f.error.is_none())
        .map(|f| f.spec.local_addr)
        .collect();
    let mut down = 0;
    for record in &session.records {
        if listening.contains(&record.local_addr) {
            continue;
        }
        if !on_record(record).await {
            down += 1;
        }
    }
    down
}

/// Restore every persisted forward that is not already listening. Returns
/// how many are still down. Never fails: a corrupt store restores nothing
/// (and is reported by `GET /forwards`), a bad record stays down. Shutdown
/// that has closed admission restores nothing.
///
/// The install runs as one forward transaction, so shutdown can drain it
/// before it cancels listeners. A restore that is still between records
/// when shutdown starts cannot bind a listener after shutdown returns.
pub(in crate::server) async fn restore_forwards(state: &Arc<AppState>) -> usize {
    let Some(forwarder) = state.forward_service.clone() else {
        return 0;
    };
    let state = Arc::clone(state);
    let installing = Arc::clone(&forwarder);
    let store = Arc::clone(&state.forwards);
    restore_in_transaction(forwarder, store, move |record| {
        let record = record.clone();
        let state = Arc::clone(&state);
        let forwarder = Arc::clone(&installing);
        async move { restore_one(state.as_ref(), &forwarder, &record).await }
    })
    .await
}

/// Install `on_record` on the forwarder's transaction registry.
async fn restore_in_transaction<F, Fut>(
    forwarder: Arc<x0x::forward::ForwardService>,
    store: Arc<x0x::forward::store::ForwardStore>,
    on_record: F,
) -> usize
where
    F: FnMut(&x0x::forward::store::ForwardRecord) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = bool> + Send + 'static,
{
    let installing = Arc::clone(&forwarder);
    match forwarder
        .run_transaction(async move { restore_holding(&store, &installing, on_record).await })
        .await
    {
        Ok(down) => down,
        Err(error) => {
            tracing::warn!(target: "x0x::forward", "persisted forwards not restored: {error}");
            0
        }
    }
}

/// GET /streams — active forward-stream count + connect-ACL counters.
pub(in crate::server) async fn streams_diagnostics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let (active, connect_failed, machine_mismatch) = state
        .forward_service
        .as_ref()
        .map(|f| {
            (
                f.diagnostics().active_streams(),
                f.diagnostics().connect_failed(),
                f.diagnostics().machine_mismatch(),
            )
        })
        .unwrap_or((0, 0, 0));
    let socks_denied = state
        .socks_service
        .as_ref()
        .map(x0x::socks::SocksService::denied_count)
        .unwrap_or(0);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active_streams": active,
            "connect_failed": connect_failed,
            "machine_mismatch": machine_mismatch,
            "socks_denied": socks_denied,
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

#[cfg(test)]
mod tests {
    use super::*;
    use x0x::connect::{ConnectDiagnostics, ConnectPolicy};
    use x0x::forward::store::ForwardStore;
    use x0x::forward::{ForwardBinding, ForwardService, ForwardSpec};
    use x0x::identity::{AgentId, MachineId};
    use x0x::names::NameKind;

    async fn offline_agent() -> (Arc<x0x::Agent>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let agent = Arc::new(
            x0x::Agent::builder()
                .with_identity_dir(dir.path())
                .with_machine_key(dir.path().join("machine.key"))
                .with_agent_key_path(dir.path().join("agent.key"))
                .with_user_key_path(dir.path().join("user.key"))
                .with_agent_cert_path(dir.path().join("agent.cert"))
                .with_contact_store_path(dir.path().join("contacts.json"))
                .with_peer_cache_disabled()
                .build()
                .await
                .expect("offline agent"),
        );
        (agent, dir)
    }

    fn open_forwarder(agent: Arc<x0x::Agent>) -> Arc<ForwardService> {
        let policy = Arc::new(ConnectPolicy::default());
        let diagnostics = Arc::new(ConnectDiagnostics::new(policy.summary()));
        Arc::new(
            ForwardService::new(Arc::clone(&agent), policy, diagnostics, true).expect("forwarder"),
        )
    }

    fn discovered(agent: AgentId, machine: MachineId) -> x0x::DiscoveredAgent {
        x0x::DiscoveredAgent {
            agent_id: agent,
            machine_id: machine,
            user_id: None,
            addresses: Vec::new(),
            announced_at: 1,
            last_seen: 1,
            machine_public_key: Vec::new(),
            nat_type: None,
            can_receive_direct: None,
            is_relay: None,
            is_coordinator: None,
            reachable_via: Vec::new(),
            relay_candidates: Vec::new(),
            cert_not_after: None,
            agent_certificate: None,
            cert_digest: None,
            agent_public_key: Vec::new(),
            self_name: None,
        }
    }

    async fn free_loopback() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        addr
    }

    async fn assert_port_released(addr: SocketAddr) {
        let start = std::time::Instant::now();
        loop {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    drop(listener);
                    return;
                }
                Err(error) => {
                    if start.elapsed() > std::time::Duration::from_secs(2) {
                        panic!("listener still bound at {addr}: {error}");
                    }
                    tokio::task::yield_now().await;
                }
            }
        }
    }

    async fn wait_transactions_closed(forwarder: &ForwardService) {
        let start = std::time::Instant::now();
        while !forwarder.transactions_closed() {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("forward admission did not close");
            }
            tokio::task::yield_now().await;
        }
    }

    #[derive(Clone)]
    struct Reg {
        spec: ForwardSpec,
        binding: ForwardBinding,
    }

    fn hex_spec(addr: SocketAddr) -> Reg {
        Reg {
            spec: ForwardSpec {
                local_addr: addr,
                peer_agent: AgentId([0x55; 32]),
                target_host: "127.0.0.1".to_string(),
                target_port: 9,
            },
            binding: ForwardBinding {
                name: None,
                kind: NameKind::Agent,
                pinned_machine: Some(MachineId([0x11; 32])),
                persistent: true,
            },
        }
    }

    async fn remember_reg(
        store: &ForwardStore,
        reg: &Reg,
    ) -> Result<bool, x0x::forward::store::ForwardStoreError> {
        store.remember(&reg.spec, &reg.binding).await
    }

    /// WHY: a persisted agent forward must pin the machine the outbound
    /// gate would dial. An unconfirmed discovery route is not that machine
    /// when an authority store names another one, and a zero route is not
    /// a dial target at all.
    #[tokio::test]
    async fn persistent_agent_pin_uses_authorized_machine_not_cached_route() {
        let (agent, _dir) = offline_agent().await;
        let peer = AgentId([0x41; 32]);
        let cached = MachineId([0xC1; 32]);
        let authority = MachineId([0xA1; 32]);
        agent
            .insert_discovered_agent_for_testing(discovered(peer, cached))
            .await;
        // The discovery seed also writes both authority stores at `cached`.
        // Move them onto `authority` and leave the cache route stale, so
        // nothing confirms that route.
        agent
            .announced_machine_bindings_for_testing()
            .write()
            .await
            .record_announcement(peer, authority, 20, None, None);
        agent
            .record_authenticated_binding_for_testing(peer, authority, 20)
            .await;
        assert_eq!(
            agent.outbound_dial_machine(&peer).await,
            Some(authority),
            "unconfirmed cache machine {cached:?} must not win over {authority:?}"
        );

        let zero_peer = AgentId([0x42; 32]);
        agent
            .insert_discovered_agent_for_testing(discovered(zero_peer, MachineId([0; 32])))
            .await;
        agent
            .record_authenticated_binding_for_testing(zero_peer, authority, 10)
            .await;
        assert_eq!(
            agent.outbound_dial_machine(&zero_peer).await,
            None,
            "a zero cached machine is not a dial target"
        );
    }

    /// WHY: a delete that arrives after restore has copied `forwards.json`
    /// and before it binds must not be overwritten by that stale copy.
    #[tokio::test]
    async fn deletion_during_restore_does_not_reopen() {
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(ForwardStore::load(ForwardStore::path_in(dir.path())).await);
        let addr = free_loopback().await;
        assert!(remember_reg(&store, &hex_spec(addr))
            .await
            .expect("remember"));

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        store.arm_restore_pause(Arc::clone(&entered), Arc::clone(&release));

        let store_restore = Arc::clone(&store);
        let forwarder_restore = Arc::clone(&forwarder);
        let restore = tokio::spawn(async move {
            restore_holding(&store_restore, &forwarder_restore, |record| {
                let record = record.clone();
                let forwarder = Arc::clone(&forwarder_restore);
                async move { install_restored(&forwarder, &record, None).await }
            })
            .await
        });
        entered.notified().await;
        assert!(
            store.ops_try_lock().is_none(),
            "restore must still hold the lifecycle lock after copying records"
        );
        assert_eq!(store.records().await.expect("records").len(), 1);

        let store_remove = Arc::clone(&store);
        let forwarder_remove = Arc::clone(&forwarder);
        let remove =
            tokio::spawn(
                async move { remove_persisted(&store_remove, &forwarder_remove, addr).await },
            );
        release.notify_one();
        let down = restore.await.expect("restore task");
        let removed = remove.await.expect("remove task").expect("forget");
        assert!(removed, "delete removes the forward restore just opened");
        assert_eq!(down, 0, "the stale copy did open, then delete won");
        assert!(
            forwarder.forward_at(addr).is_none(),
            "deleted forward must not stay open"
        );
        assert!(store.records().await.expect("records").is_empty());

        let forwarder_again = Arc::clone(&forwarder);
        let again = restore_holding(&store, &forwarder, |record| {
            let record = record.clone();
            let forwarder = Arc::clone(&forwarder_again);
            async move { install_restored(&forwarder, &record, None).await }
        })
        .await;
        assert_eq!(again, 0);
        assert!(
            forwarder.forward_at(addr).is_none(),
            "a later restore must not reopen the deleted forward"
        );
    }

    /// WHY: replacing a disabled persistent forward with `--ephemeral` must
    /// delete the durable record. Otherwise delete reports success against
    /// the ephemeral entry and the old target returns on restart.
    #[tokio::test]
    async fn ephemeral_replacement_deletes_disabled_persistent_record() {
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let store = Arc::new(ForwardStore::load(path.clone()).await);
        let addr = free_loopback().await;
        let mut persistent = hex_spec(addr);
        persistent.spec.target_port = 59991;
        assert!(remember_reg(&store, &persistent).await.expect("remember"));
        forwarder.add_disabled(
            persistent.spec.clone(),
            persistent.binding.clone(),
            "name_changed: test".to_string(),
        );

        let mut ephemeral = persistent.clone();
        ephemeral.binding.persistent = false;
        ephemeral.binding.pinned_machine = None;
        ephemeral.spec.target_port = 7;
        let bound = commit_forward(&store, &forwarder, ephemeral.spec, ephemeral.binding)
            .await
            .expect("ephemeral add");
        assert_eq!(bound, addr);
        assert!(
            store.records().await.expect("records").is_empty(),
            "the disabled persistent record must leave disk"
        );
        let live = forwarder
            .forward_status_at(addr)
            .expect("ephemeral is registered");
        assert!(!live.binding.persistent);
        assert_eq!(live.spec.target_port, 7);
        forwarder.shutdown();

        let (agent, _agent_dir) = offline_agent().await;
        let restarted = open_forwarder(agent);
        let store = Arc::new(ForwardStore::load(path).await);
        assert!(store.records().await.expect("records").is_empty());
        let forwarder_restore = Arc::clone(&restarted);
        let down = restore_holding(&store, &restarted, |record| {
            let record = record.clone();
            let forwarder = Arc::clone(&forwarder_restore);
            async move { install_restored(&forwarder, &record, None).await }
        })
        .await;
        assert_eq!(down, 0);
        assert!(
            restarted.forward_at(addr).is_none(),
            "restart must not bring back the replaced target"
        );
        restarted.shutdown();
    }

    /// WHY: cancelling the add after the listener is up and before the
    /// rename must not leave that listener running against the old saved
    /// target. The transaction task is detached from the cancelled caller
    /// and finishes the delete, so a restart does not bring the old forward
    /// back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_during_ephemeral_replacement_finishes_the_saved_delete() {
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let store = Arc::new(ForwardStore::load(path.clone()).await);
        let addr = free_loopback().await;
        let mut persistent = hex_spec(addr);
        persistent.spec.target_port = 59991;
        assert!(remember_reg(&store, &persistent).await.expect("remember"));
        forwarder.add_disabled(
            persistent.spec.clone(),
            persistent.binding.clone(),
            "name_changed: test".to_string(),
        );

        let mut ephemeral = persistent.clone();
        ephemeral.binding.persistent = false;
        ephemeral.binding.pinned_machine = None;
        ephemeral.spec.target_port = 7;
        let pause = x0x::storage::arm_durable_rename_pause_for_testing(&path);
        let store_add = Arc::clone(&store);
        let forwarder_add = Arc::clone(&forwarder);
        let add = tokio::spawn(async move {
            commit_forward(
                &store_add,
                &forwarder_add,
                ephemeral.spec,
                ephemeral.binding,
            )
            .await
        });
        let start = std::time::Instant::now();
        while !x0x::storage::durable_rename_pause_entered_for_testing(&path) {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("rename did not reach the cancellation point");
            }
            tokio::task::yield_now().await;
        }
        let live = forwarder
            .forward_status_at(addr)
            .expect("listener is already up");
        assert!(!live.binding.persistent);
        assert_eq!(live.spec.target_port, 7);
        let saved = std::fs::read_to_string(&path).expect("forwards.json");
        assert!(
            saved.contains("59991"),
            "the old target is still the saved record while the rename is paused: {saved}"
        );
        assert!(
            store.ops_try_lock().is_none(),
            "the transaction still holds the lifecycle lock"
        );

        add.abort();
        let aborted = add.await.expect_err("the request task must be cancelled");
        assert!(aborted.is_cancelled());
        drop(pause);

        let start = std::time::Instant::now();
        loop {
            let saved_records = store.records().await.expect("records");
            let live = forwarder.forward_status_at(addr);
            if saved_records.is_empty()
                && matches!(
                    &live,
                    Some(status) if !status.binding.persistent && status.spec.target_port == 7
                )
            {
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!(
                    "aborted add left live and saved forwards split: saved={saved_records:?} live={live:?}"
                );
            }
            tokio::task::yield_now().await;
        }
        let reloaded = ForwardStore::load(path).await;
        assert!(reloaded.load_error().is_none());
        assert!(
            reloaded.records().await.expect("disk").is_empty(),
            "restart must not bring back the replaced target"
        );
        forwarder.shutdown();
    }

    /// WHY: a directory fsync that fails after the rename has already
    /// published the new `forwards.json`. An add keeps the listener:
    /// removing it would let a restart resurrect the forward. A delete is
    /// the other direction. The record is already gone from memory and from
    /// the file, so the listener is removed too, and the error still
    /// reports that durability is not confirmed. That is not a pre-rename
    /// failure, which leaves the listener up.
    #[tokio::test]
    async fn after_rename_failure_keeps_listener_until_durability_is_confirmed() {
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let store = Arc::new(ForwardStore::load(path.clone()).await);
        let addr = free_loopback().await;
        let reg = hex_spec(addr);

        let seam = x0x::storage::arm_fail_parent_dir_fsync_for_testing(&path);
        let err = commit_forward(&store, &forwarder, reg.spec.clone(), reg.binding.clone())
            .await
            .expect_err("add must not ACK");
        assert!(
            matches!(
                err,
                CommitError::Store(ref e) if e.durability_unconfirmed()
            ),
            "{err:?}"
        );
        assert!(
            forwarder.forward_at(addr).is_some(),
            "the listener stays; restart would otherwise resurrect it"
        );
        assert_eq!(store.records().await.expect("records").len(), 1);
        let disk = ForwardStore::load(path.clone()).await;
        assert_eq!(disk.records().await.expect("disk").len(), 1);

        // The port is already bound, so the durability retry is the store
        // write, not a second bind.
        let retry = store
            .remember(&reg.spec, &reg.binding)
            .await
            .expect_err("retry under the fault must not ACK");
        assert!(retry.durability_unconfirmed());
        assert!(forwarder.forward_at(addr).is_some());

        let deleted = remove_persisted(&store, &forwarder, addr)
            .await
            .expect_err("delete must not ACK while the fsync fault is armed");
        assert!(deleted.durability_unconfirmed());
        assert!(
            forwarder.forward_at(addr).is_none(),
            "a post-rename delete removes the listener and still reports unconfirmed durability"
        );
        assert_port_released(addr).await;
        assert!(store.records().await.expect("records").is_empty());
        let disk = ForwardStore::load(path.clone()).await;
        assert!(
            disk.records().await.expect("disk").is_empty(),
            "the renamed file no longer has the forward"
        );

        drop(seam);
        let removed = remove_persisted(&store, &forwarder, addr)
            .await
            .expect("durability retry");
        assert!(
            !removed,
            "the listener was already removed; the retry only confirms durability"
        );
        assert!(forwarder.forward_at(addr).is_none());
        let disk = ForwardStore::load(path).await;
        assert!(disk.records().await.expect("disk").is_empty());
        forwarder.shutdown();
    }

    /// WHY: shutdown used to return while restore or add was still between
    /// its await points. That work then bound a listener with a fresh
    /// cancellation token, so the port stayed open after shutdown. Admission
    /// closes first, the in-flight transaction is drained, and the listener
    /// it published is dropped before shutdown returns.
    #[tokio::test]
    async fn shutdown_during_restore_and_add_releases_the_listener() {
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let store = Arc::new(ForwardStore::load(path.clone()).await);

        let restore_addr = free_loopback().await;
        assert!(remember_reg(&store, &hex_spec(restore_addr))
            .await
            .expect("remember"));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        store.arm_restore_pause(Arc::clone(&entered), Arc::clone(&release));
        let store_restore = Arc::clone(&store);
        let forwarder_restore = Arc::clone(&forwarder);
        let forwarder_install = Arc::clone(&forwarder);
        let restore = tokio::spawn(async move {
            restore_in_transaction(forwarder_restore, store_restore, move |record| {
                let record = record.clone();
                let forwarder = Arc::clone(&forwarder_install);
                async move { install_restored(&forwarder, &record, None).await }
            })
            .await
        });
        entered.notified().await;
        let shutting_down = Arc::clone(&forwarder);
        let shutdown = tokio::spawn(async move {
            shutting_down.shutdown_and_release().await;
        });
        wait_transactions_closed(&forwarder).await;
        release.notify_one();
        restore.await.expect("restore task");
        shutdown.await.expect("shutdown task");
        assert_port_released(restore_addr).await;

        // A second forwarder: shutdown above closed the first one's admission.
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let add_addr = free_loopback().await;
        let pause = x0x::storage::arm_durable_rename_pause_for_testing(&path);
        let store_add = Arc::clone(&store);
        let forwarder_add = Arc::clone(&forwarder);
        let reg = hex_spec(add_addr);
        let add = tokio::spawn(async move {
            commit_forward(&store_add, &forwarder_add, reg.spec, reg.binding).await
        });
        let start = std::time::Instant::now();
        while !x0x::storage::durable_rename_pause_entered_for_testing(&path) {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("add did not reach the rename");
            }
            tokio::task::yield_now().await;
        }
        assert!(
            forwarder.forward_at(add_addr).is_some(),
            "the add has already bound the listener"
        );
        let shutting_down = Arc::clone(&forwarder);
        let shutdown = tokio::spawn(async move {
            shutting_down.shutdown_and_release().await;
        });
        wait_transactions_closed(&forwarder).await;
        drop(pause);
        let added = add.await.expect("add task");
        shutdown.await.expect("shutdown task");
        assert!(
            added.is_ok(),
            "the drained add finishes its store write: {added:?}"
        );
        assert_port_released(add_addr).await;
    }

    #[tokio::test]
    async fn shutdown_abandons_a_stalled_store_write() {
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let store = Arc::new(ForwardStore::load(path.clone()).await);
        let addr = free_loopback().await;
        let pause = x0x::storage::arm_durable_rename_pause_for_testing(&path);
        let store_add = Arc::clone(&store);
        let forwarder_add = Arc::clone(&forwarder);
        let reg = hex_spec(addr);
        let add = tokio::spawn(async move {
            commit_forward(&store_add, &forwarder_add, reg.spec, reg.binding).await
        });
        let start = std::time::Instant::now();
        while !x0x::storage::durable_rename_pause_entered_for_testing(&path) {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("add did not reach the rename");
            }
            tokio::task::yield_now().await;
        }
        let started = std::time::Instant::now();
        let report = forwarder.shutdown_and_release().await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(4),
            "shutdown must not wait out a stalled store write: {elapsed:?}"
        );
        assert!(
            report.abandoned_transactions >= 1,
            "the stalled transaction is reported: {report:?}"
        );
        assert_port_released(addr).await;
        drop(pause);
        let _ = add.await;
    }

    #[tokio::test]
    async fn allocated_port_does_not_erase_a_saved_forward() {
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let store = Arc::new(ForwardStore::load(path).await);
        let saved_addr = free_loopback().await;
        let saved = hex_spec(saved_addr);
        assert!(remember_reg(&store, &saved).await.expect("remember saved"));
        forwarder.add_disabled(saved.spec, saved.binding, "name_changed".to_string());
        let fresh = free_loopback().await;
        forwarder.script_binds_for_test(vec![saved_addr, fresh]);
        let spec = hex_spec(SocketAddr::from(([127, 0, 0, 1], 0)));
        let bound = commit_forward(&store, &forwarder, spec.spec, spec.binding)
            .await
            .expect("allocation skips the saved port");
        assert_eq!(bound, fresh);
        let records = store.records().await.expect("records");
        assert!(
            records.iter().any(|record| record.local_addr == saved_addr),
            "the saved forward is still on disk: {records:?}"
        );
        assert!(records.iter().any(|record| record.local_addr == fresh));
        let listed = forwarder.list_forward_status();
        assert!(
            listed
                .iter()
                .any(|status| { status.spec.local_addr == saved_addr && status.error.is_some() }),
            "the disabled forward stays listed: {listed:?}"
        );
        assert!(listed
            .iter()
            .any(|status| status.spec.local_addr == fresh && status.error.is_none()));
    }

    /// WHY: an unreadable `forwards.json` must not block `--ephemeral` adds
    /// or deletion of a live ephemeral forward. Persistent adds, and
    /// deletion of a live persistent forward, stay fail-closed, and the
    /// corrupt file is never overwritten.
    #[tokio::test]
    async fn corrupt_store_still_adds_and_deletes_ephemeral_forwards() {
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let original = b"{not json".to_vec();
        std::fs::write(&path, &original).expect("write corrupt store");
        let store = Arc::new(ForwardStore::load(path.clone()).await);
        assert!(store.load_error().is_some());

        let addr = free_loopback().await;
        let mut ephemeral = hex_spec(addr);
        ephemeral.binding.persistent = false;
        ephemeral.binding.pinned_machine = None;
        let bound = commit_forward(&store, &forwarder, ephemeral.spec, ephemeral.binding)
            .await
            .expect("ephemeral add against a corrupt store");
        assert_eq!(bound, addr);
        assert!(forwarder.forward_at(addr).is_some());
        assert_eq!(std::fs::read(&path).expect("read"), original);

        let removed = remove_persisted(&store, &forwarder, addr)
            .await
            .expect("delete live ephemeral");
        assert!(removed);
        assert!(forwarder.forward_at(addr).is_none());
        assert_eq!(std::fs::read(&path).expect("read"), original);

        let persistent = hex_spec(addr);
        let err = commit_forward(&store, &forwarder, persistent.spec, persistent.binding)
            .await
            .expect_err("persistent add stays fail-closed");
        assert!(matches!(
            err,
            CommitError::Store(x0x::forward::store::ForwardStoreError::Unusable(_))
        ));
        assert!(forwarder.forward_at(addr).is_none());
        assert_eq!(std::fs::read(&path).expect("read"), original);

        let addr_persistent = free_loopback().await;
        let live = hex_spec(addr_persistent);
        forwarder
            .add_forward_with(live.spec, live.binding)
            .await
            .expect("register a persistent listener without the store");
        let err = remove_persisted(&store, &forwarder, addr_persistent)
            .await
            .expect_err("a persistent forward stays until the file can be updated");
        assert!(matches!(
            err,
            x0x::forward::store::ForwardStoreError::Unusable(_)
        ));
        assert!(forwarder.forward_at(addr_persistent).is_some());
        assert_eq!(std::fs::read(&path).expect("read"), original);
        forwarder.shutdown();
    }

    /// WHY: port 0 reads the saved record list to avoid taking a saved
    /// forward's port. That read must not turn an unreadable `forwards.json`
    /// into a 503 for `--ephemeral`, and it must not remove the listener
    /// just bound. The corrupt file stays byte-for-byte.
    #[tokio::test]
    async fn corrupt_store_still_allocates_an_ephemeral_port() {
        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let original = b"{not json".to_vec();
        std::fs::write(&path, &original).expect("write corrupt store");
        let store = Arc::new(ForwardStore::load(path.clone()).await);
        assert!(store.load_error().is_some());

        let mut ephemeral = hex_spec("127.0.0.1:0".parse().expect("unbound loopback"));
        ephemeral.binding.persistent = false;
        ephemeral.binding.pinned_machine = None;
        let bound = commit_forward(&store, &forwarder, ephemeral.spec, ephemeral.binding)
            .await
            .expect("ephemeral :0 add against a corrupt store");
        assert_ne!(bound.port(), 0);
        assert!(forwarder.forward_at(bound).is_some());
        assert_eq!(std::fs::read(&path).expect("read"), original);
        forwarder.shutdown();
    }

    /// WHY: a restart has to bind the saved port again, with the pin the
    /// name still resolves to. Reloading the file is not that listener.
    #[tokio::test]
    async fn restored_named_forward_listens_with_its_pin() {
        let (agent, _dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let addr = free_loopback().await;
        let mut spec = hex_spec(addr);
        spec.binding.name = Some("machine:box.me".to_string());
        spec.binding.kind = NameKind::Machine;
        {
            let store = ForwardStore::load(path.clone()).await;
            assert!(remember_reg(&store, &spec).await.expect("save"));
        }
        let store = ForwardStore::load(path).await;
        let records = store.records().await.expect("records");
        let record = records.first().expect("saved forward");
        let resolved = x0x::names::Resolved {
            name: "machine:box.me".to_string(),
            kind: NameKind::Machine,
            owner: x0x::identity::UserId([0x33; 32]),
            agent_id: Some(AgentId([0x55; 32])),
            machine_id: Some(MachineId([0x11; 32])),
            newly_pinned: false,
        };
        assert!(
            install_restored(&forwarder, record, Some(Ok(resolved))).await,
            "restore must bind the saved forward"
        );
        let listed = forwarder.list_forward_status();
        assert!(
            listed.iter().any(|status| {
                status.spec.local_addr == addr
                    && status.binding.pinned_machine == Some(MachineId([0x11; 32]))
                    && status.error.is_none()
            }),
            "the restored forward is listening with its pin: {listed:?}"
        );
        tokio::net::TcpStream::connect(addr)
            .await
            .expect("the restored listener accepts a local client");
        forwarder.shutdown();
    }

    /// WHY: disabling connect and restarting leaves no forwarder. DELETE
    /// must still remove the saved record. Returning 409 before `forget`
    /// leaves the record in `forwards.json`.
    #[tokio::test]
    async fn disabled_connect_restart_still_deletes_saved_forward() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let addr = "127.0.0.1:18022".parse().expect("addr");
        {
            let store = ForwardStore::load(path.clone()).await;
            assert!(remember_reg(&store, &hex_spec(addr)).await.expect("save"));
        }
        let store = Arc::new(ForwardStore::load(path.clone()).await);
        assert_eq!(store.records().await.expect("loaded").len(), 1);
        let removed = forget_forward(&store, None, addr)
            .await
            .expect("delete with no forwarder");
        assert!(removed, "the saved record must be removed");
        let restarted = ForwardStore::load(path).await;
        assert!(
            restarted.records().await.expect("reloaded").is_empty(),
            "a later start must not see the deleted forward"
        );
    }

    /// WHY: a client can complete the TCP handshake while the save is still
    /// in progress. The old accept loop took that connection and kept
    /// forwarding after the save failed. The save failure must leave no
    /// listener and must reset that connection.
    #[tokio::test]
    async fn failed_save_resets_a_connection_accepted_during_the_save() {
        use tokio::io::AsyncReadExt;

        let (agent, _agent_dir) = offline_agent().await;
        let forwarder = open_forwarder(agent);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let store = Arc::new(ForwardStore::load(path.clone()).await);
        let addr = free_loopback().await;
        let reg = hex_spec(addr);
        let _accepted = forwarder.arm_accepted_connection_pause_for_testing();
        let pause = x0x::storage::arm_durable_rename_pause_for_testing(&path);
        let store_add = Arc::clone(&store);
        let forwarder_add = Arc::clone(&forwarder);
        let add = tokio::spawn(async move {
            commit_forward(&store_add, &forwarder_add, reg.spec, reg.binding).await
        });
        let start = std::time::Instant::now();
        while !x0x::storage::durable_rename_pause_entered_for_testing(&path) {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("save did not reach the rename");
            }
            tokio::task::yield_now().await;
        }
        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("client connects while the save is paused");
        let mut buf = [0u8; 1];
        match tokio::time::timeout(std::time::Duration::from_millis(50), client.read(&mut buf))
            .await
        {
            Err(_) => {}
            other => panic!("connection closed before the save failed: {other:?}"),
        }
        let start = std::time::Instant::now();
        while !forwarder.accepted_connection_pause_entered_for_testing() {
            if start.elapsed() > std::time::Duration::from_millis(500) {
                break;
            }
            tokio::task::yield_now().await;
        }
        let removed_tmp = delete_durable_tmp(dir.path());
        assert!(
            removed_tmp > 0,
            "the paused save must still be holding its temp file"
        );
        drop(pause);
        let err = add.await.expect("add task").expect_err("save must fail");
        assert!(
            matches!(err, CommitError::Store(ref e) if !e.durability_unconfirmed()),
            "a failure before the rename must roll the listener back: {err:?}"
        );
        assert!(
            forwarder.forward_at(addr).is_none(),
            "the failed save must not leave a forward registered"
        );
        assert!(
            store.records().await.expect("records").is_empty(),
            "the failed save must not leave a record"
        );
        match tokio::time::timeout(std::time::Duration::from_millis(500), client.read(&mut buf))
            .await
        {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("failed save still forwarded {n} bytes"),
            Err(_) => panic!("connection accepted during the failed save is still open"),
        }
        assert_eq!(
            forwarder.diagnostics().active_streams(),
            0,
            "an accepted connection must not keep forwarding after the save fails"
        );
        assert_port_released(addr).await;
        forwarder.shutdown();
    }

    fn delete_durable_tmp(dir: &std::path::Path) -> usize {
        let mut removed = 0;
        for entry in std::fs::read_dir(dir).expect("store dir") {
            let entry = entry.expect("dir entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".forwards.json.") && name.ends_with(".tmp") {
                std::fs::remove_file(entry.path()).expect("remove temp file");
                removed += 1;
            }
        }
        removed
    }

    /// WHY: disabling connect and restarting leaves no forwarder. The saved
    /// record must still appear in the list, marked down, and delete must
    /// remove it from that list.
    #[tokio::test]
    async fn disabled_connect_lists_saved_forward_then_deletes_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ForwardStore::path_in(dir.path());
        let addr = "127.0.0.1:18023".parse().expect("addr");
        let reg = hex_spec(addr);
        {
            let store = ForwardStore::load(path.clone()).await;
            assert!(remember_reg(&store, &reg).await.expect("save"));
        }
        let store = Arc::new(ForwardStore::load(path.clone()).await);
        let listed = disabled_saved_forwards(&store).await;
        assert_eq!(listed.len(), 1, "{listed:?}");
        let forward = &listed[0];
        assert_eq!(forward["local_addr"], addr.to_string());
        assert_eq!(forward["enabled"], false);
        assert_eq!(forward["error"], CONNECT_DISABLED_REASON);
        assert_eq!(forward["persistent"], true);
        assert_eq!(forward["target_port"], reg.spec.target_port);
        assert_eq!(
            forward["peer_agent"],
            hex::encode(reg.spec.peer_agent.as_bytes())
        );
        assert_eq!(
            forward["pinned_machine_id"],
            hex::encode(reg.binding.pinned_machine.expect("pin").as_bytes())
        );

        let removed = forget_forward(&store, None, addr)
            .await
            .expect("delete with no forwarder");
        assert!(removed);
        assert!(
            disabled_saved_forwards(&store).await.is_empty(),
            "the list must be empty after delete"
        );
        let restarted = ForwardStore::load(path).await;
        assert!(restarted.records().await.expect("reloaded").is_empty());
    }
}
