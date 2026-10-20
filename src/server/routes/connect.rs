//! Route handlers (`category: "connect"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.
//!
//! `POST /forwards` is owner/durable-token only: a named peer resolves
//! (and pins) locally. The auth middleware refuses session bearers and
//! riders before any extractor runs (`requires_durable_owner`); the
//! handler re-checks as defense in depth.

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
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<ForwardAddRequest>,
) -> impl IntoResponse {
    use x0x::forward::ForwardSpec;
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
        name: name.clone(),
        kind,
        pinned_machine,
        persistent: !req.ephemeral,
    };
    let bound = match commit_forward(&state.forwards, forwarder, spec).await {
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
/// An ephemeral spec deletes any durable record at the bound address, so a
/// disabled persistent forward replaced by `--ephemeral` cannot return on
/// restart. A store failure removes the listener just bound (and puts a
/// disabled entry back when that is what the bind replaced).
async fn commit_forward(
    store: &x0x::forward::store::ForwardStore,
    forwarder: &x0x::forward::ForwardService,
    spec: x0x::forward::ForwardSpec,
) -> Result<SocketAddr, CommitError> {
    if let Err(e) = store.check(&spec) {
        return Err(CommitError::Store(e));
    }
    let _ops = store.lock_ops().await;
    let previous = forwarder
        .list_forwards()
        .into_iter()
        .find(|status| status.spec.local_addr == spec.local_addr);
    let bound = forwarder
        .add_forward(spec.clone())
        .await
        .map_err(CommitError::Bind)?;
    let mut registered = spec;
    registered.local_addr = bound;
    let persisted = if registered.persistent {
        store.remember(&registered).await.map(|_| ())
    } else {
        store.forget(bound).await.map(|_| ())
    };
    if let Err(e) = persisted {
        forwarder.remove_forward(bound);
        if let Some(prev) = previous.filter(|status| status.spec.local_addr == bound) {
            if let Some(reason) = prev.error {
                forwarder.add_disabled(prev.spec, reason);
            }
        }
        return Err(CommitError::Store(e));
    }
    Ok(bound)
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
    // Forget the durable record first, including one hidden behind an
    // ephemeral in-memory entry, so a deleted forward never comes back at
    // the next start. A store failure leaves the running forward in place
    // and reports it.
    let removed = match remove_persisted(&state.forwards, forwarder, addr).await {
        Ok(removed) => removed,
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

/// Delete the durable record at `addr` and the in-memory forward, holding
/// the lifecycle lock for both. The record is removed even when the live
/// entry is ephemeral.
async fn remove_persisted(
    store: &x0x::forward::store::ForwardStore,
    forwarder: &x0x::forward::ForwardService,
    addr: SocketAddr,
) -> Result<bool, x0x::forward::store::ForwardStoreError> {
    let _ops = store.lock_ops().await;
    let forgotten = store.forget(addr).await?;
    Ok(forwarder.remove_forward(addr) || forgotten)
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
        .list_forwards()
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
/// (and is reported by `GET /forwards`), a bad record stays down.
pub(in crate::server) async fn restore_forwards(state: &AppState) -> usize {
    let Some(forwarder) = state.forward_service.as_ref() else {
        return 0;
    };
    restore_holding(&state.forwards, forwarder, |record| {
        let record = record.clone();
        async move { restore_one(state, forwarder, &record).await }
    })
    .await
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
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active_streams": active,
            "connect_failed": connect_failed,
            "machine_mismatch": machine_mismatch,
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
    use x0x::forward::{ForwardService, ForwardSpec};
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

    fn hex_spec(addr: SocketAddr) -> ForwardSpec {
        ForwardSpec {
            local_addr: addr,
            peer_agent: AgentId([0x55; 32]),
            target_host: "127.0.0.1".to_string(),
            target_port: 9,
            name: None,
            kind: NameKind::Agent,
            pinned_machine: Some(MachineId([0x11; 32])),
            persistent: true,
        }
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
        assert!(store.remember(&hex_spec(addr)).await.expect("remember"));

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
        let store = ForwardStore::load(path.clone()).await;
        let addr = free_loopback().await;
        let mut persistent = hex_spec(addr);
        persistent.target_port = 59991;
        assert!(store.remember(&persistent).await.expect("remember"));
        forwarder.add_disabled(persistent.clone(), "name_changed: test".to_string());

        let mut ephemeral = persistent.clone();
        ephemeral.persistent = false;
        ephemeral.pinned_machine = None;
        ephemeral.target_port = 7;
        let bound = commit_forward(&store, &forwarder, ephemeral)
            .await
            .expect("ephemeral add");
        assert_eq!(bound, addr);
        assert!(
            store.records().await.expect("records").is_empty(),
            "the disabled persistent record must leave disk"
        );
        let live = forwarder.forward_at(addr).expect("ephemeral is registered");
        assert!(!live.persistent);
        assert_eq!(live.target_port, 7);
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
}
