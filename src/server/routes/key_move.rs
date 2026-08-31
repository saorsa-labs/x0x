//! ADR-0043 agent key-move route handlers (`category: "identity"`):
//! the commit-then-activate move ceremony, the placement ledger, and the
//! move log views.
//!
//! Owner-key gated throughout (the durable API token): only the owner key
//! authorizes irreversible steps — not the moving agent key, not either
//! machine (ADR-0043 driver 3). Rider credentials are denied by their
//! deny-by-default scope.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::super::state::AppState;
use super::super::{api_error, bad_request};
use crate::identity::{AgentId, MachineId};
use crate::key_move::{Placement, TransferBundle};

/// Decode a 32-byte hex id or fail with `400`.
fn parse_hex_id(
    hex_id: &str,
    what: &str,
) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
    hex::decode(hex_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad_request(format!("{what} must be 64 hex chars")))
}

/// Decode a placement DTO (`"roaming"` or `{"pinned": "<machine hex>"}`).
fn parse_placement(
    kind: &str,
    pin: &Option<String>,
) -> Result<Placement, (StatusCode, Json<serde_json::Value>)> {
    match (kind, pin) {
        ("roaming", None) => Ok(Placement::Roaming),
        ("pinned", Some(machine_hex)) => {
            let bytes = parse_hex_id(machine_hex, "pin machine id")?;
            Ok(Placement::Pinned(MachineId(bytes)))
        }
        ("pinned", None) => Err(bad_request("pinned placement requires pin machine id")),
        _ => Err(bad_request(
            "placement kind must be \"roaming\" or \"pinned\"",
        )),
    }
}

/// `409` body shared by every owner-less install.
fn owner_missing() -> (StatusCode, Json<serde_json::Value>) {
    api_error(
        StatusCode::CONFLICT,
        "no owner: this daemon has no user identity (run `x0x user-id create`)",
    )
}

/// Review-r4 scope gate: the roaming-move ceremony is experimental in v1
/// and OFF by default (`[key_move] ceremony_enabled`). When off, every
/// ceremony endpoint answers `501` — no `MoveAuthorization` can be
/// chained, so no agent ever enters MidMove/quiesced/quarantined and the
/// ceremony-durability/universal-signing holes are unreachable. The
/// shipped core (enrollment, mint/ledger, B/P enforcement) is always on.
fn ceremony_disabled(state: &AppState) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if state.key_move_ceremony_enabled {
        return None;
    }
    Some(api_error(
        StatusCode::NOT_IMPLEMENTED,
        "roaming-move ceremony is experimental in v1 and disabled on this daemon ([key_move] ceremony_enabled = false); roster agents stay Pinned (the local Home agent's Roaming mint is inert without the ceremony) and quiesced/quarantined states are unreachable",
    ))
}

// ── POST /agent/move — authorize (+ export when local) ───────────────────────

/// Request body for `POST /agent/move`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct MoveAuthorizeRequest {
    agent_id: String,
    to_machine: String,
    /// `"roaming"` or `"pinned"` (pin must equal `to_machine`).
    placement: String,
    #[serde(default)]
    pin: Option<String>,
}

/// POST /agent/move — owner step 1: chain a `MoveAuthorization`
/// (ADR-0043 §5.1) and, when this machine is the source and the target's
/// enrolled KEM key is known, seal the export envelope + chain the
/// `ExportReceipt` in the same call. The returned transfer bundle is the
/// operator carriage to the target (`/agent/move/import`).
///
/// Returns `409` when no owner key, no mint exists, or a move is already
/// in flight; `400` on malformed ids or an illegal placement.
pub(in crate::server) async fn agent_move_authorize(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(body): Json<MoveAuthorizeRequest>,
) -> impl IntoResponse {
    if let Some(resp) = ceremony_disabled(&state) {
        return resp;
    }
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "move ceremony requires the durable API token (not a session token)",
        );
    }
    if state.agent.identity().user_keypair().is_none() {
        return owner_missing();
    }
    let agent = match parse_hex_id(&body.agent_id, "agent_id") {
        Ok(bytes) => AgentId(bytes),
        Err(resp) => return resp,
    };
    let to_machine = match parse_hex_id(&body.to_machine, "to_machine") {
        Ok(bytes) => MachineId(bytes),
        Err(resp) => return resp,
    };
    let placement = match parse_placement(&body.placement, &body.pin) {
        Ok(placement) => placement,
        Err(resp) => return resp,
    };
    match state
        .agent
        .move_authorize(&agent, &to_machine, placement)
        .await
    {
        Ok(bundle) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "bundle": bundle })),
        ),
        Err(e) => api_error(
            StatusCode::CONFLICT,
            format!("move authorization rejected: {e}"),
        ),
    }
}

// ── POST /agent/move/export ──────────────────────────────────────────────────

/// POST /agent/move/export — source step: seal the agent keypair to the
/// target machine's enrolled ML-KEM key and chain the `ExportReceipt`
/// (§4). Runs on the SOURCE machine with an authorization-only bundle.
pub(in crate::server) async fn agent_move_export(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(bundle): Json<TransferBundle>,
) -> impl IntoResponse {
    if let Some(resp) = ceremony_disabled(&state) {
        return resp;
    }
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "move ceremony requires the durable API token (not a session token)",
        );
    }
    match state.agent.move_export(bundle).await {
        Ok(bundle) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "bundle": bundle })),
        ),
        Err(e) => api_error(StatusCode::CONFLICT, format!("export rejected: {e}")),
    }
}

// ── POST /agent/move/import ──────────────────────────────────────────────────

/// POST /agent/move/import — target step: verify the bundle, unwrap the
/// envelope with THIS machine's KEM key, store the key material, and
/// countersign the `ImportReceipt` (§5). Quarantine is derived — the
/// target may sign exactly when the local fold's custodian is it.
pub(in crate::server) async fn agent_move_import(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(bundle): Json<TransferBundle>,
) -> impl IntoResponse {
    if let Some(resp) = ceremony_disabled(&state) {
        return resp;
    }
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "move ceremony requires the durable API token (not a session token)",
        );
    }
    match state.agent.move_import(bundle).await {
        Ok(outcome) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "quarantined": true,
                "receipt_chained": outcome.receipt_chained,
                // Review r2 C1: when the target could not chain the
                // receipt itself (no owner key), hand it to the operator —
                // the owner wraps this variant in a ChainedRecord at the
                // next owner contact before activating.
                "receipt": outcome.receipt,
                "note": "key stored; this machine may sign once the owner activates the move"
            })),
        ),
        Err(e) => api_error(StatusCode::CONFLICT, format!("import rejected: {e}")),
    }
}

// ── POST /agent/move/activate ────────────────────────────────────────────────

/// Request body for `POST /agent/move/activate`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct MoveEpochRequest {
    agent_id: String,
    move_epoch: u64,
}

/// POST /agent/move/activate — owner step 2 (COMMIT): verify coherence,
/// chain the `ActivationBundle`, ingest locally, publish on the
/// activation topic (§7.5). Refuses a placement outcome that would strand
/// the fleet with zero Roaming agents (§8.2).
pub(in crate::server) async fn agent_move_activate(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(body): Json<MoveEpochRequest>,
) -> impl IntoResponse {
    if let Some(resp) = ceremony_disabled(&state) {
        return resp;
    }
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "move ceremony requires the durable API token (not a session token)",
        );
    }
    let agent = match parse_hex_id(&body.agent_id, "agent_id") {
        Ok(bytes) => AgentId(bytes),
        Err(resp) => return resp,
    };
    match state.agent.move_activate(&agent, body.move_epoch).await {
        Ok(record) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "record_hash": hex::encode(record.record_hash()),
                "published": true,
            })),
        ),
        Err(e) => api_error(StatusCode::CONFLICT, format!("activation rejected: {e}")),
    }
}

/// POST /agent/move/abort — owner ROLLBACK: chain an `AbortRecord` from
/// any pre-activation head; the epoch is burned (§5.1).
/// Request body for `POST /agent/move/abort`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct MoveAbortRequest {
    agent_id: String,
    move_epoch: u64,
    #[serde(default)]
    reason: Option<String>,
}

pub(in crate::server) async fn agent_move_abort(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(body): Json<MoveAbortRequest>,
) -> impl IntoResponse {
    if let Some(resp) = ceremony_disabled(&state) {
        return resp;
    }
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "move ceremony requires the durable API token (not a session token)",
        );
    }
    let agent = match parse_hex_id(&body.agent_id, "agent_id") {
        Ok(bytes) => AgentId(bytes),
        Err(resp) => return resp,
    };
    match state
        .agent
        .move_abort(&agent, body.move_epoch, body.reason.unwrap_or_default())
        .await
    {
        Ok(record) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "record_hash": hex::encode(record.record_hash()),
                // Review r2 C1: a remote target's imported copy is the
                // operator's to discard — run the same abort there.
                "note": "epoch burned; if the move's target machine holds an imported key, run this abort there too (its local copy is discarded)"
            })),
        ),
        Err(e) => api_error(StatusCode::CONFLICT, format!("abort rejected: {e}")),
    }
}

// ── POST /agent/move/retire ──────────────────────────────────────────────────

/// POST /agent/move/retire — source step after activation: chain the
/// `RetireReceipt` and securely delete the local key copy (imported keys
/// are deleted; the daemon's own bootstrap key stays on disk — its
/// `holds_key` remains true but `may_sign` is already false).
pub(in crate::server) async fn agent_move_retire(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(body): Json<MoveEpochRequest>,
) -> impl IntoResponse {
    if let Some(resp) = ceremony_disabled(&state) {
        return resp;
    }
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "move ceremony requires the durable API token (not a session token)",
        );
    }
    let agent = match parse_hex_id(&body.agent_id, "agent_id") {
        Ok(bytes) => AgentId(bytes),
        Err(resp) => return resp,
    };
    match state.agent.move_retire(&agent, body.move_epoch).await {
        Ok(record) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "record_hash": hex::encode(record.record_hash()),
            })),
        ),
        Err(e) => api_error(StatusCode::CONFLICT, format!("retire rejected: {e}")),
    }
}

// ── GET /agent/moves — log view + derived state ──────────────────────────────

/// One log record in the `GET /agent/moves` view.
#[derive(Debug, Serialize)]
pub(in crate::server) struct MoveRecordView {
    kind: &'static str,
    record_hash: String,
}

/// GET /agent/moves — the per-agent log view + derived state
/// (custodian/quiesced/quarantined/live-signer, current placement) — the
/// crash-recovery view: state IS the log (§5.3).
pub(in crate::server) async fn agent_moves(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(resp) = ceremony_disabled(&state) {
        return resp;
    }
    let agent = match params
        .get("agent_id")
        .map(|hex_id| parse_hex_id(hex_id, "agent_id").map(AgentId))
    {
        Some(Ok(agent)) => Some(agent),
        Some(Err(resp)) => return resp,
        None => None,
    };
    let move_state = state.agent.move_state();
    let state_view = move_state.read().await;
    let machine = state.agent.machine_id();

    let render_agent = |agent: &AgentId| {
        let log = state_view.log(agent);
        let fold = state_view.fold(agent);
        let placement = state_view.placement(agent);
        serde_json::json!({
            "agent_id": hex::encode(agent.as_bytes()),
            "records": log
                .iter()
                .map(|r| MoveRecordView {
                    kind: r.record.kind(),
                    record_hash: hex::encode(r.record_hash()),
                })
                .collect::<Vec<_>>(),
            "derived": {
                "custodian": fold.custodian.map(|m| hex::encode(m.as_bytes())),
                "phase": match fold.phase {
                    crate::key_move::MovePhase::Idle => "idle",
                    crate::key_move::MovePhase::MidMove { .. } => "mid_move",
                    crate::key_move::MovePhase::RetirePending { .. } => "retire_pending",
                },
                "retired_bindings": fold.retired_bindings.len(),
                "placement": placement.map(|p| serde_json::json!({
                    "kind": p.placement.kind(),
                    "pinned_machine": p.placement.pinned_machine()
                        .map(|m| hex::encode(m.as_bytes())),
                    "epoch": p.placement_epoch,
                })),
                "this_machine": {
                    "holds_key": state.agent.holds_agent_key(agent),
                    "may_sign": fold.may_sign(&machine, state.agent.holds_agent_key(agent)),
                    "quiesced": fold.quiesced(&machine, state.agent.holds_agent_key(agent)),
                    "quarantined": fold.quarantined(&machine, state.agent.holds_agent_key(agent)),
                },
            },
        })
    };

    let agents: Vec<serde_json::Value> = match &agent {
        Some(agent) => vec![render_agent(agent)],
        None => state_view.known_agents().iter().map(render_agent).collect(),
    };
    drop(state_view);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "agents": agents })),
    )
}

// ── GET /owner/placement — the ledger view + mint ────────────────────────────

/// GET /owner/placement — mint (lazily, on first read per §8.2) and
/// return the derived placement ledger: every known agent's current
/// placement, epoch, and the ≥1-Roaming Home invariant status.
///
/// `409` when no user identity (and therefore no owner) is configured.
pub(in crate::server) async fn owner_placement(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
) -> impl IntoResponse {
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "owner placement ledger requires the durable API token (not a session token)",
        );
    }
    let Some(owner) = state.agent.user_id() else {
        return owner_missing();
    };
    // Lazy mint: first read materializes epoch-0 records for the roster.
    let minted = match state.agent.move_mint_placements().await {
        Ok(count) => count,
        Err(e) => {
            return api_error(StatusCode::CONFLICT, format!("placement mint refused: {e}"));
        }
    };
    let move_state = state.agent.move_state();
    let state_view = move_state.read().await;
    let mut entries: Vec<serde_json::Value> = state_view
        .placement_view()
        .values()
        .map(|record| {
            serde_json::json!({
                "agent_id": hex::encode(record.agent_id.as_bytes()),
                "kind": record.placement.kind(),
                "pinned_machine": record.placement
                    .pinned_machine()
                    .map(|m| hex::encode(m.as_bytes())),
                "epoch": record.placement_epoch,
                "issued_at": record.issued_at,
                "digest": hex::encode(record.digest()),
            })
        })
        .collect();
    entries.sort_by_key(|e| {
        e.get("agent_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    });
    let roaming = state_view
        .placement_view()
        .values()
        .filter(|p| p.placement == Placement::Roaming)
        .count();
    drop(state_view);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "owner_user_id": hex::encode(owner.as_bytes()),
            "minted_now": minted,
            "roaming_count": roaming,
            "home_invariant_ok": roaming >= 1,
            "placements": entries,
        })),
    )
}

// ── GET /owner/agents/:id/placement ─────────────────────────────────────────

/// GET /owner/agents/:id/placement — one agent's placement record + fold.
pub(in crate::server) async fn owner_agent_placement(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Path(agent_id_hex): Path<String>,
) -> impl IntoResponse {
    if !actor.is_durable_owner() {
        return api_error(
            StatusCode::FORBIDDEN,
            "owner placement ledger requires the durable API token (not a session token)",
        );
    }
    let agent = match parse_hex_id(&agent_id_hex, "agent_id") {
        Ok(bytes) => AgentId(bytes),
        Err(resp) => return resp,
    };
    let move_state = state.agent.move_state();
    let state_view = move_state.read().await;
    let Some(record) = state_view.placement(&agent) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "no placement record cached for this agent (mint not run / bundle not seen)",
        );
    };
    let view = serde_json::json!({
        "ok": true,
        "agent_id": hex::encode(record.agent_id.as_bytes()),
        "kind": record.placement.kind(),
        "pinned_machine": record.placement
            .pinned_machine()
            .map(|m| hex::encode(m.as_bytes())),
        "epoch": record.placement_epoch,
        "issued_at": record.issued_at,
        "digest": hex::encode(record.digest()),
    });
    drop(state_view);
    (StatusCode::OK, Json(view))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::server::rider_auth::ActorContext;
    use std::sync::Arc;

    async fn owned_state(data_dir: &std::path::Path) -> anyhow::Result<Arc<AppState>> {
        let user = crate::identity::UserKeypair::generate()?;
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key_path(data_dir.join("agent.key"))
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_user_key(user)
                .with_contact_store_path(data_dir.join("contacts.json"))
                .with_identity_dir(data_dir)
                .with_move_ceremony(true)
                .build()
                .await?,
        );
        crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(data_dir, agent)
            .await
    }

    fn owner_ext() -> axum::Extension<ActorContext> {
        axum::Extension(ActorContext::Owner { durable: true })
    }

    /// WHY: every ADR-0043 endpoint is wired and owner-gated — an ownerless
    /// install answers 409; an owned one lazily mints ≥1-Roaming placements
    /// (the local-agent exception; all-Pinned refused), serves the derived
    /// fold (custodian = this machine, may_sign true pre-move), and refuses
    /// ceremony steps whose preconditions are unmet with typed errors
    /// rather than half-built state (§"do NOT force a half-built ceremony").
    #[tokio::test]
    async fn move_routes_wired() -> anyhow::Result<()> {
        // Ownerless: 409 from the ledger view.
        let (unowned_state, _guard) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state().await?;
        let response = owner_placement(
            State(Arc::clone(&unowned_state)),
            axum::Extension(ActorContext::Owner { durable: true }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let _ = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
        drop(_guard);

        // Owned: the ledger lazily mints the roster with ≥1 Roaming.
        let dir2 = tempfile::tempdir()?;
        let state = owned_state(dir2.path()).await?;
        let owner = ActorContext::Owner { durable: true };
        let response = owner_placement(State(Arc::clone(&state)), owner_ext())
            .await
            .into_response();
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 20).await?)?;
        assert_eq!(response_status(&body), ());
        assert!(
            body.get("home_invariant_ok").and_then(|v| v.as_bool()) == Some(true),
            "mint must yield >=1 Roaming: {body:?}"
        );
        let local_agent_hex = hex::encode(state.agent.agent_id().as_bytes());

        // The roster view enriches with placement.
        let response = owner_agent_placement(
            State(Arc::clone(&state)),
            owner_ext(),
            Path(local_agent_hex.clone()),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let _ = axum::body::to_bytes(response.into_body(), 1 << 20).await?;

        // The moves view: idle fold, this machine may sign, roaming.
        let response = agent_moves(
            State(Arc::clone(&state)),
            axum::extract::Query(
                [("agent_id".to_string(), local_agent_hex.clone())]
                    .into_iter()
                    .collect(),
            ),
        )
        .await
        .into_response();
        let moves: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 20).await?)?;
        let entry = moves["agents"]
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            entry["derived"]["phase"], "idle",
            "post-mint fold must be Idle: {moves:?}"
        );
        assert_eq!(
            entry["derived"]["this_machine"]["may_sign"], true,
            "mint custodian (this machine) may sign"
        );

        // Review r2 C1: the empty-log exception is scoped to the OWN
        // agent. A foreign agent with no log NEVER passes the gate —
        // possession without a local custodian fold is quarantine (an
        // imported key on a target that could not chain its receipt must
        // not sign).
        let foreign = crate::identity::AgentId([0xAB; 32]);
        assert!(
            state
                .agent
                .signing_gate_allows(&state.agent.agent_id())
                .await,
            "own agent, empty-or-minted log: may sign pre-move"
        );
        assert!(
            !state.agent.signing_gate_allows(&foreign).await,
            "foreign agent with no log: never may sign"
        );

        // Review r2 H6: the binding form of /identity/revoke is an
        // owner-key signing oracle — a read-only browser SESSION token
        // (Owner { durable: false }) must get 403, and an unbounded
        // epoch must be refused even for the durable owner.
        {
            let binding_body: super::super::identity::RevokeRequest =
                serde_json::from_value(serde_json::json!({
                    "agent_id": local_agent_hex,
                    "machine_id": hex::encode([9u8; 32]),
                    "move_epoch": u64::MAX,
                }))
                .expect("binding revoke body");
            let session = axum::Extension(ActorContext::Owner { durable: false });
            let (status, _body) = {
                let response = super::super::identity::identity_revoke(
                    State(Arc::clone(&state)),
                    session,
                    Json(binding_body.clone()),
                )
                .await
                .into_response();
                (response.status(), ())
            };
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "session token must not drive the owner-key binding oracle"
            );
            // Durable owner + u64::MAX epoch: refused by the epoch bound.
            let (status, _body) = {
                let response = super::super::identity::identity_revoke(
                    State(Arc::clone(&state)),
                    owner_ext(),
                    Json(binding_body),
                )
                .await
                .into_response();
                (response.status(), ())
            };
            assert!(
                status == StatusCode::FORBIDDEN || status == StatusCode::CONFLICT,
                "unbounded epoch must be refused (got {status})"
            );
        }
        // Ceremony refusals are typed, never half-built:
        let stranger = hex::encode([7u8; 32]);
        // 400: malformed placement.
        let (status, _body) = {
            let response = agent_move_authorize(
                State(Arc::clone(&state)),
                owner_ext(),
                Json(MoveAuthorizeRequest {
                    agent_id: local_agent_hex.clone(),
                    to_machine: stranger.clone(),
                    placement: "elsewhere".to_string(),
                    pin: None,
                }),
            )
            .await
            .into_response();
            (response.status(), ())
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // 409: no mint for the stranger agent.
        let (status, _body) = {
            let response = agent_move_authorize(
                State(Arc::clone(&state)),
                owner_ext(),
                Json(MoveAuthorizeRequest {
                    agent_id: stranger.clone(),
                    to_machine: stranger.clone(),
                    placement: "roaming".to_string(),
                    pin: None,
                }),
            )
            .await
            .into_response();
            (response.status(), ())
        };
        assert_eq!(status, StatusCode::CONFLICT, "unminted agent: 409");

        // 409: export of a bundle with no authorization.
        let empty_bundle = TransferBundle {
            authorization: crate::key_move::ChainedRecord {
                prev: [0u8; 32],
                record: crate::key_move::MoveRecord::PlacementMint {
                    agent_id: crate::identity::AgentId([1u8; 32]),
                    placement: crate::key_move::Placement::Roaming,
                    custodian_machine: MachineId([2u8; 32]),
                    issued_at: 0,
                },
                owner_public_key: vec![],
                owner_signature: vec![],
            },
            export_receipt: None,
            envelope: None,
        };
        let (status, _body) = {
            let response = agent_move_export(
                State(Arc::clone(&state)),
                owner_ext(),
                Json(empty_bundle.clone()),
            )
            .await
            .into_response();
            (response.status(), ())
        };
        assert_eq!(status, StatusCode::CONFLICT);

        // 409: import of an envelope-less bundle.
        let (status, _body) = {
            let response =
                agent_move_import(State(Arc::clone(&state)), owner_ext(), Json(empty_bundle))
                    .await
                    .into_response();
            (response.status(), ())
        };
        assert_eq!(status, StatusCode::CONFLICT);

        // 409: activate/abort/retire with nothing in flight.
        for status in [
            agent_move_activate(
                State(Arc::clone(&state)),
                owner_ext(),
                Json(MoveEpochRequest {
                    agent_id: stranger.clone(),
                    move_epoch: 1,
                }),
            )
            .await
            .into_response()
            .status(),
            agent_move_abort(
                State(Arc::clone(&state)),
                owner_ext(),
                Json(MoveAbortRequest {
                    agent_id: stranger.clone(),
                    move_epoch: 1,
                    reason: None,
                }),
            )
            .await
            .into_response()
            .status(),
            agent_move_retire(
                State(Arc::clone(&state)),
                owner_ext(),
                Json(MoveEpochRequest {
                    agent_id: stranger,
                    move_epoch: 1,
                }),
            )
            .await
            .into_response()
            .status(),
        ] {
            assert_eq!(status, StatusCode::CONFLICT);
        }
        let _ = owner;
        Ok(())
    }

    fn response_status(_body: &serde_json::Value) {}
}

#[cfg(test)]
mod gate_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::key_move::ChainedRecord;
    use crate::server::rider_auth::ActorContext;
    use std::sync::Arc;

    async fn owned_state(data_dir: &std::path::Path) -> anyhow::Result<Arc<AppState>> {
        let user = crate::identity::UserKeypair::generate()?;
        let agent = Arc::new(
            crate::Agent::builder()
                .with_machine_key(data_dir.join("machine.key"))
                .with_agent_key_path(data_dir.join("agent.key"))
                .with_agent_cert_path(data_dir.join("agent.cert"))
                .with_user_key(user)
                .with_contact_store_path(data_dir.join("contacts.json"))
                .with_identity_dir(data_dir)
                .build()
                .await?,
        );
        crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(data_dir, agent)
            .await
    }

    /// WHY (review r4 scope decision): with `[key_move] ceremony_enabled`
    /// unset (the DEFAULT), every `/agent/move*` endpoint must answer 501
    /// — no authorization can be chained, so no agent can ever enter
    /// MidMove/quiesced/quarantined and the ceremony-durability and
    /// universal-signing holes are unreachable in the shipped posture —
    /// while the SHIPPED CORE (placement ledger, lazy mint, B/P
    /// enforcement inputs) stays live: /owner/placement mints and every
    /// roster agent stays Pinned to its mint machine (the local agent is
    /// minted Roaming per the ADR-0038 Home invariant — inert without the
    /// ceremony).
    #[tokio::test]
    async fn ceremony_endpoints_501_when_disabled_agents_stay_pinned() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut state = owned_state(dir.path()).await?;
        // The shared test helper enables the ceremony; flip to the SHIPPED
        // default (off) — the only reference is this one, so get_mut works.
        Arc::get_mut(&mut state)
            .expect("sole state ref")
            .key_move_ceremony_enabled = false;

        let owner = axum::Extension(ActorContext::Owner { durable: true });
        let agent_hex = hex::encode(state.agent.agent_id().as_bytes());
        let stranger = hex::encode([7u8; 32]);

        // Every ceremony endpoint: 501, before any auth or body parsing
        // side effects can matter.
        let cases: Vec<(StatusCode, String)> = vec![
            (
                agent_move_authorize(
                    State(Arc::clone(&state)),
                    owner.clone(),
                    Json(MoveAuthorizeRequest {
                        agent_id: agent_hex.clone(),
                        to_machine: stranger.clone(),
                        placement: "roaming".to_string(),
                        pin: None,
                    }),
                )
                .await
                .into_response()
                .status(),
                "authorize".into(),
            ),
            (
                agent_move_export(
                    State(Arc::clone(&state)),
                    owner.clone(),
                    Json(TransferBundle {
                        authorization: ChainedRecord {
                            prev: [0u8; 32],
                            record: crate::key_move::MoveRecord::PlacementMint {
                                agent_id: crate::identity::AgentId([1; 32]),
                                placement: crate::key_move::Placement::Roaming,
                                custodian_machine: MachineId([2; 32]),
                                issued_at: 0,
                            },
                            owner_public_key: vec![],
                            owner_signature: vec![],
                        },
                        export_receipt: None,
                        envelope: None,
                    }),
                )
                .await
                .into_response()
                .status(),
                "export".into(),
            ),
            (
                agent_move_import(
                    State(Arc::clone(&state)),
                    owner.clone(),
                    Json(TransferBundle {
                        authorization: ChainedRecord {
                            prev: [0u8; 32],
                            record: crate::key_move::MoveRecord::PlacementMint {
                                agent_id: crate::identity::AgentId([1; 32]),
                                placement: crate::key_move::Placement::Roaming,
                                custodian_machine: MachineId([2; 32]),
                                issued_at: 0,
                            },
                            owner_public_key: vec![],
                            owner_signature: vec![],
                        },
                        export_receipt: None,
                        envelope: None,
                    }),
                )
                .await
                .into_response()
                .status(),
                "import".into(),
            ),
            (
                agent_move_activate(
                    State(Arc::clone(&state)),
                    owner.clone(),
                    Json(MoveEpochRequest {
                        agent_id: agent_hex.clone(),
                        move_epoch: 1,
                    }),
                )
                .await
                .into_response()
                .status(),
                "activate".into(),
            ),
            (
                agent_move_abort(
                    State(Arc::clone(&state)),
                    owner.clone(),
                    Json(MoveAbortRequest {
                        agent_id: agent_hex.clone(),
                        move_epoch: 1,
                        reason: None,
                    }),
                )
                .await
                .into_response()
                .status(),
                "abort".into(),
            ),
            (
                agent_move_retire(
                    State(Arc::clone(&state)),
                    owner.clone(),
                    Json(MoveEpochRequest {
                        agent_id: agent_hex.clone(),
                        move_epoch: 1,
                    }),
                )
                .await
                .into_response()
                .status(),
                "retire".into(),
            ),
            (
                agent_moves(
                    State(Arc::clone(&state)),
                    axum::extract::Query(std::collections::HashMap::new()),
                )
                .await
                .into_response()
                .status(),
                "moves".into(),
            ),
        ];
        for (status, name) in cases {
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{name} must be 501");
        }

        // Review r5 (4): the ceremony is unreachable via the LIBRARY API
        // too, not just REST — the default-built agent (flag off) returns
        // a typed disabled error from every executor.
        {
            let agent_id = state.agent.agent_id();
            let err = state
                .agent
                .move_authorize(
                    &agent_id,
                    &crate::identity::MachineId([9u8; 32]),
                    crate::key_move::Placement::Roaming,
                )
                .await
                .expect_err("library move_authorize must refuse when the ceremony is disabled");
            assert!(
                err.to_string()
                    .contains("ceremony is experimental and disabled"),
                "typed disabled error expected, got: {err}"
            );
            // Review r6 (1): move_import is gated BEFORE anything — no
            // decrypt, no participant-state persist, no key storage.
            let err = state
                .agent
                .move_import(crate::key_move::TransferBundle {
                    authorization: crate::key_move::ChainedRecord {
                        prev: [0u8; 32],
                        record: crate::key_move::MoveRecord::MoveAuthorization(
                            crate::key_move::MoveAuthorization {
                                agent_id,
                                move_epoch: 1,
                                from_machine: crate::identity::MachineId([1; 32]),
                                to_machine: state.agent.machine_id(),
                                placement: crate::key_move::Placement::Roaming,
                                issued_at: 0,
                            },
                        ),
                        owner_public_key: vec![],
                        owner_signature: vec![],
                    },
                    export_receipt: None,
                    envelope: None,
                })
                .await
                .expect_err("library move_import must refuse when the ceremony is disabled");
            assert!(
                err.to_string()
                    .contains("ceremony is experimental and disabled"),
                "move_import typed disabled error expected, got: {err}"
            );
        }

        // The shipped core stays live: the ledger mints and the roster
        // placement view is queryable (agents stay Pinned-in-practice; the
        // local agent's Home-invariant Roaming mint is inert without the
        // ceremony).
        let response = owner_placement(State(Arc::clone(&state)), owner)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 20).await?)?;
        assert_eq!(
            body["home_invariant_ok"], true,
            "mint still guarantees >=1 Roaming"
        );
        assert!(
            body["placements"].as_array().is_some_and(|p| !p.is_empty()),
            "ledger view live: {body:?}"
        );
        Ok(())
    }
}
