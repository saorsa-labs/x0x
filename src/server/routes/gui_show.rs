//! `POST /gui/show` — ADR 0083 local show, and remote show (slice 3).
//!
//! Validates the view grammar, applies `[gui_show] local_enabled`, the block
//! list and the rate limit, then either queues a `gui.show` frame on a
//! visible tab (`navigated`) or opens a fresh session URL (`opened`).
//! `navigated` is returned only when that tab's GUI session is still valid
//! and its outbound queue accepts the frame. The response never contains a
//! URL or session token.
//!
//! An absent, null, or empty `target_machine` stays on this machine.
//! `active` and a 64-hex machine id are slice 3. The remote branch builds
//! its JSON directly so the local body stays `GuiShowResponse`.
//!
//! An owner token must be the durable API token. A GUI session bearer is
//! refused. A rider bearer is admitted only when the token carries
//! `gui:show`. `auth_middleware` applies that check. The handler repeats
//! it for tests that call the handler without middleware.
//!
//! After admission, a rider show uses that token's `sub_agent_id` for the
//! block list, the rate limit, the origin banner, and the outgoing
//! `agent_id`. The daemon's own agent stays the sender for a durable owner
//! token. Stop then blocks that rider, or turns local show off only when
//! the sender is this daemon. A rider banner names `gui_show_blocked.json`
//! and a daemon restart. A local banner names `gui_show_local_disabled`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::super::rider_auth::{admit_gui_show, ActorContext, AdmitGuiShow};
use super::super::state::AppState;
use super::super::ws::GuiShowFrame;
use crate::gui::{
    new_request_id, origin_banner, short_id_hex, view_route, GuiShowOutcome, GuiShowRequest,
    GuiShowResponse, PendingGuiShow,
};
use crate::identity::{AgentId, MachineId, UserId};
use crate::owner_sync::OwnerSyncStore;

/// Second sentence for a show opened by another owner agent.
///
/// Stop for that agent writes `gui_show_blocked.json`. The sentence does
/// not call the sender a rider.
const REMOTE_SHOW_REENABLE: &str = "Remove this agent's id from gui_show_blocked.json in the data directory and restart the daemon to allow shows from this agent again.";

/// `reason` when the target has no verified `gui_show_v1` advert.
const TARGET_NEEDS_UPGRADE: &str = "target_needs_upgrade";

/// How `target_machine` is spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetKind {
    /// Absent or empty.
    Local,
    /// The exact string `active`.
    Active,
    /// 32-byte machine id.
    Explicit([u8; 32]),
    /// Not `active` and not 64 hex characters.
    Invalid,
}

/// What the originator does with a classified target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteTargetDecision {
    /// Display on this daemon. Send no DM.
    LocalDisplay,
    /// Ask enrolled machines which GUI was visible.
    QueryActive,
    /// Send a show to this other machine.
    Remote([u8; 32]),
    /// Do not send.
    Refused,
}

/// Classify `target_machine`. Empty is local. `active` is exact.
pub(crate) fn classify_target(raw: &str) -> TargetKind {
    if raw.is_empty() {
        return TargetKind::Local;
    }
    if raw == "active" {
        return TargetKind::Active;
    }
    match decode_machine_id(raw) {
        Some(id) => TargetKind::Explicit(id),
        None => TargetKind::Invalid,
    }
}

/// `true` only for a current verified advert that sets the bit.
pub(crate) fn capability_allows(supports: Option<bool>) -> bool {
    matches!(supports, Some(true))
}

/// Enrollment gate for an explicit machine, then local versus remote.
///
/// `enrolled` is the result of `OwnerSyncStore::is_enrolled`. No owner, or
/// a machine that is not enrolled, is [`RemoteTargetDecision::Refused`].
pub(crate) fn remote_target_decision(
    kind: TargetKind,
    has_owner: bool,
    enrolled: bool,
    local_machine: &[u8; 32],
) -> RemoteTargetDecision {
    match kind {
        TargetKind::Local => RemoteTargetDecision::LocalDisplay,
        TargetKind::Active => RemoteTargetDecision::QueryActive,
        TargetKind::Invalid => RemoteTargetDecision::Refused,
        TargetKind::Explicit(id) => {
            if !has_owner || !enrolled {
                RemoteTargetDecision::Refused
            } else if &id == local_machine {
                RemoteTargetDecision::LocalDisplay
            } else {
                RemoteTargetDecision::Remote(id)
            }
        }
    }
}

fn decode_machine_id(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 {
        return None;
    }
    let bytes = hex::decode(raw).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

fn parse_request_id(hex_id: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_id).ok()?;
    <[u8; 16]>::try_from(bytes).ok()
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// POST /gui/show
pub(in crate::server) async fn gui_show(
    State(state): State<Arc<AppState>>,
    Extension(actor): Extension<ActorContext>,
    Json(req): Json<GuiShowRequest>,
) -> Response {
    // David approved 22 Oct 2026 13:30 BST (#1392) for owner tokens: a GUI
    // session bearer stays a durable-token 403. A rider is admitted only
    // with `gui:show`. This is the same check as the middleware.
    let rider = match admit_gui_show(&actor) {
        AdmitGuiShow::Allow { rider } => rider,
        AdmitGuiShow::Forbidden(body) => {
            return (StatusCode::FORBIDDEN, Json(body)).into_response();
        }
    };

    let machine_id = hex::encode(state.agent.machine_id().as_bytes());
    let request_id = new_request_id();
    let target = req.target_machine.as_deref().unwrap_or("");
    // Absent, null, and empty stay on the local path, including its
    // durable-token rule (already applied) and its rate-limit bucket.
    if matches!(classify_target(target), TargetKind::Local) {
        return local_show(&state, &actor, rider, &req.view, machine_id, request_id).await;
    }
    remote_show(
        &state, &actor, rider, &req.view, target, machine_id, request_id,
    )
    .await
}

/// Local show. `target_machine` is absent, empty, or `active` selected
/// this machine. Remote sends do not call this, so they do not spend the
/// local rate-limit bucket.
async fn local_show(
    state: &AppState,
    actor: &ActorContext,
    rider: bool,
    view: &str,
    machine_id: String,
    request_id: String,
) -> Response {
    let cfg = state.gui_show.config();
    if !cfg.local_enabled {
        return json_outcome(GuiShowOutcome::Disabled, machine_id, request_id);
    }

    let parsed = match view_route::parse(view) {
        Ok(v) => v,
        Err(_) => {
            return json_outcome(GuiShowOutcome::InvalidView, machine_id, request_id);
        }
    };
    let route = parsed.as_route();

    // ADR 0083 §5 keys the block list, the rate limit, the banner, and Stop
    // on the requesting agent. A rider's requesting agent is the
    // authenticated `sub_agent_id`, not this daemon. A bad id is refused
    // here so it cannot fall back onto the daemon's identity.
    let Some(sender) = show_sender(state, actor) else {
        return json_outcome(GuiShowOutcome::Refused, machine_id, request_id);
    };
    if state.gui_show.is_blocked(&sender) {
        return json_outcome(GuiShowOutcome::Refused, machine_id, request_id);
    }

    let now = Instant::now();
    if !state.gui_show.try_rate_limit(&sender, now) {
        return json_outcome(GuiShowOutcome::RateLimited, machine_id, request_id);
    }

    let agent_hex = hex::encode(sender.as_bytes());
    let (agent_label, machine_label) = resolve_banner_labels(state, &agent_hex, rider).await;
    let banner = origin_banner(&agent_label, &machine_label, rider);
    let outcome = display_show(
        state,
        route,
        banner,
        agent_hex,
        &machine_id,
        rider,
        &request_id,
    )
    .await;
    json_outcome(outcome, machine_id, request_id)
}

/// Navigate a live tab, or open a loopback GUI URL on this machine.
///
/// Local show and [`deliver_remote_show`] both use this path.
async fn display_show(
    state: &AppState,
    route: String,
    banner: String,
    agent_hex: String,
    machine_id: &str,
    rider: bool,
    request_id: &str,
) -> GuiShowOutcome {
    // Deliver on the tab's own queue. A broadcast would return before the
    // forwarder runs, and a full queue there drops the frame and closes
    // the socket. Reconnect does not replay that broadcast. The socket
    // outlives the session token, so the token is checked here, before
    // the frame is queued.
    let show = GuiShowFrame {
        view: route.clone(),
        banner: banner.clone(),
        agent_id: agent_hex.clone(),
        machine_id: machine_id.to_string(),
        rider,
        request_id: request_id.to_string(),
    };
    let decided_at = Instant::now();
    let accepted = {
        let sessions = state.ws_sessions.read().await;
        let mut accepted = false;
        for session in sessions.values() {
            if session
                .try_accept_gui_show(&show, |token| state.sessions.is_valid(token, decided_at))
            {
                accepted = true;
            }
        }
        accepted
    };
    if accepted {
        return GuiShowOutcome::Navigated;
    }

    // Mint a fresh session; never put the durable token in the URL.
    // Queue the banner before the opener so a browser that connects during
    // the launch wait still receives it. A failed launch drops that entry
    // and revokes the session so the token is not valid.
    let session = state.sessions.issue(Instant::now());
    let url = show_loopback_url(state.api_address, &session, &route);
    state.gui_show.enqueue_pending(PendingGuiShow {
        view: route,
        banner,
        agent_id: agent_hex,
        machine_id: machine_id.to_string(),
        rider,
        request_id: request_id.to_string(),
        session_token: session.clone(),
        created_at: Instant::now(),
    });
    // The launch runs on the blocking pool. That pool cannot be aborted, and
    // the opener lock used to queue every launch behind the previous wait.
    // Track the launch, and give it only the opener and the stop flag: it
    // must not keep this `AppState` (and the Agent and database) alive.
    let Some(opener) = state.gui_show.opener_for_launch() else {
        state.sessions.revoke(&session);
        state.gui_show.drop_pending_for_session(&session);
        return GuiShowOutcome::NoDisplay;
    };
    let stop = state.gui_show.open_stop_flag();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let admitted = state.spawn_detached(async move {
        let opened = tokio::task::spawn_blocking(move || {
            if stop.load(std::sync::atomic::Ordering::Acquire) {
                false
            } else {
                opener.open_until(&url, &stop)
            }
        })
        .await
        .unwrap_or(false);
        let _ = tx.send(opened);
    });
    if !admitted {
        state.sessions.revoke(&session);
        state.gui_show.drop_pending_for_session(&session);
        return GuiShowOutcome::NoDisplay;
    }
    let opened = rx.await.unwrap_or(false);
    if opened {
        GuiShowOutcome::Opened
    } else {
        state.sessions.revoke(&session);
        state.gui_show.drop_pending_for_session(&session);
        GuiShowOutcome::NoDisplay
    }
}

/// Target-side display after the receive path has checked trust,
/// `remote_enabled`, replay, freshness, the block list, and the rate limit.
///
/// Parses `view` again. A grammar failure is [`GuiShowOutcome::InvalidView`]
/// and does not open a window. `request_id` is the 32-character hex id
/// stored on the frame. Names in the banner are resolved on this machine.
pub(crate) async fn deliver_remote_show(
    state: &AppState,
    sender: AgentId,
    sender_machine: MachineId,
    view: &str,
    via_rider: bool,
    request_id: &str,
) -> GuiShowOutcome {
    let parsed = match view_route::parse(view) {
        Ok(route) => route,
        Err(_) => return GuiShowOutcome::InvalidView,
    };
    let (banner, rider) = remote_show_banner(state, &sender, &sender_machine, via_rider).await;
    let machine_hex = hex::encode(sender_machine.as_bytes());
    display_show(
        state,
        parsed.as_route(),
        banner,
        hex::encode(sender.as_bytes()),
        &machine_hex,
        rider,
        request_id,
    )
    .await
}

/// Banner text for one inbound remote show.
///
/// `via_rider` uses the rider sentence. This daemon's own agent uses the
/// local sentence. Any other sender names `gui_show_blocked.json` and does
/// not use the word rider.
async fn remote_show_banner(
    state: &AppState,
    sender: &AgentId,
    sender_machine: &MachineId,
    via_rider: bool,
) -> (String, bool) {
    let sender_hex = hex::encode(sender.as_bytes());
    let machine_hex = hex::encode(sender_machine.as_bytes());
    if via_rider {
        let machine_label = short_id_hex(&machine_hex);
        return (
            origin_banner(&short_id_hex(&sender_hex), &machine_label, true),
            true,
        );
    }
    if *sender == state.agent.agent_id() {
        let (agent_label, machine_label) = resolve_banner_labels(state, &sender_hex, false).await;
        return (origin_banner(&agent_label, &machine_label, false), false);
    }
    let banner = format!(
        "Opened by {} on {}. {REMOTE_SHOW_REENABLE}",
        short_id_hex(&sender_hex),
        short_id_hex(&machine_hex)
    );
    (banner, false)
}

/// Originator path once `target_machine` is present and non-empty.
async fn remote_show(
    state: &AppState,
    actor: &ActorContext,
    rider: bool,
    view: &str,
    target: &str,
    local_hex: String,
    request_id: String,
) -> Response {
    // Grammar fails on this daemon. Nothing is sent.
    let parsed = match view_route::parse(view) {
        Ok(route) => route,
        Err(_) => {
            return remote_json(
                GuiShowOutcome::InvalidView,
                local_hex,
                request_id,
                None,
                None,
            );
        }
    };
    let route = parsed.as_route();
    let local_machine = state.agent.machine_id();
    let kind = classify_target(target);
    let owner = state.agent.owner_trust().local_owner();
    let decision = match kind {
        TargetKind::Explicit(id) => {
            let enrolled = explicit_is_enrolled(state, owner.as_ref(), &MachineId(id)).await;
            remote_target_decision(
                TargetKind::Explicit(id),
                owner.is_some(),
                enrolled,
                local_machine.as_bytes(),
            )
        }
        other => remote_target_decision(other, owner.is_some(), false, local_machine.as_bytes()),
    };
    match decision {
        RemoteTargetDecision::LocalDisplay => {
            local_show(state, actor, rider, &route, local_hex, request_id).await
        }
        RemoteTargetDecision::Refused => {
            let machine_hex = match kind {
                TargetKind::Explicit(id) => hex::encode(id),
                _ => local_hex,
            };
            remote_json(GuiShowOutcome::Refused, machine_hex, request_id, None, None)
        }
        RemoteTargetDecision::QueryActive => {
            show_active(state, actor, rider, route, local_hex, request_id).await
        }
        RemoteTargetDecision::Remote(id) => {
            show_explicit(state, MachineId(id), route, rider, request_id).await
        }
    }
}

/// `OwnerSyncStore::is_enrolled` for one explicit machine.
///
/// The store is the one `OwnerSyncService` installs on owner trust. No
/// owner, or no store, is not enrolled.
async fn explicit_is_enrolled(
    state: &AppState,
    owner: Option<&UserId>,
    machine: &MachineId,
) -> bool {
    let Some(owner) = owner else {
        return false;
    };
    let Some(store) = owner_device_store(state) else {
        return false;
    };
    store.is_enrolled(machine, owner).await
}

/// Device set shared with owner trust.
///
/// `OwnerTrust::device_store` is private. Daemon startup installs this
/// same `Arc` with `Agent::install_owner_device_store`.
fn owner_device_store(state: &AppState) -> Option<Arc<OwnerSyncStore>> {
    state
        .owner_sync
        .as_ref()
        .map(|service| Arc::clone(service.store()))
}

async fn show_explicit(
    state: &AppState,
    machine: MachineId,
    route: String,
    rider: bool,
    request_id: String,
) -> Response {
    let target_hex = hex::encode(machine.as_bytes());
    let Some(agent) = show_peer(state, &machine).await else {
        return remote_json(
            GuiShowOutcome::Refused,
            target_hex,
            request_id,
            Some(TARGET_NEEDS_UPGRADE),
            None,
        );
    };
    send_show_and_wait(state, agent, target_hex, route, rider, request_id).await
}

async fn show_active(
    state: &AppState,
    actor: &ActorContext,
    rider: bool,
    route: String,
    local_hex: String,
    request_id: String,
) -> Response {
    use crate::gui::remote::{
        select_active, ActiveChoice, ActivityCandidate, GuiActivityBody, RESULT_WAIT,
    };

    let local_machine = state.agent.machine_id();
    let mut candidates = vec![ActivityCandidate {
        machine_id: local_machine.0,
        last_gui_visible_at: state.gui_show.last_gui_visible_at(),
        remote_enabled: true,
    }];
    let mut peers = HashMap::new();
    let mut waits = Vec::new();
    let deadline = tokio::time::Instant::now() + RESULT_WAIT;
    for machine in enrolled_remote_machines(state, &local_machine).await {
        let Some(agent) = activity_peer(state, &machine).await else {
            candidates.push(quiet_candidate(machine.0));
            continue;
        };
        let Some(qid) = parse_request_id(&new_request_id()) else {
            candidates.push(quiet_candidate(machine.0));
            continue;
        };
        let query = GuiActivityBody::Query { request_id: qid };
        let Some(payload) = query.to_dm_payload() else {
            candidates.push(quiet_candidate(machine.0));
            continue;
        };
        // Register before send so a fast reply is not lost.
        let rx = state.gui_show.remote_hub().wait_activity(qid);
        if send_gui_dm(state, &agent, payload, qid).await.is_err() {
            candidates.push(quiet_candidate(machine.0));
            continue;
        }
        peers.insert(machine.0, agent);
        waits.push((machine.0, rx));
    }
    let replies = futures::future::join_all(waits.into_iter().map(|(machine, rx)| async move {
        let body = match tokio::time::timeout_at(deadline, rx).await {
            Ok(Ok(body)) => Some(body),
            _ => None,
        };
        (machine, body)
    }))
    .await;
    for (machine, body) in replies {
        let (last_gui_visible_at, remote_enabled) = match body {
            Some(GuiActivityBody::Reply {
                last_gui_visible_at,
                remote_enabled: true,
                ..
            }) => (last_gui_visible_at, true),
            Some(GuiActivityBody::Reply { .. }) => (None, false),
            Some(GuiActivityBody::Query { .. }) | None => (None, true),
        };
        candidates.push(ActivityCandidate {
            machine_id: machine,
            last_gui_visible_at,
            remote_enabled,
        });
    }
    match select_active(unix_secs(), &candidates) {
        ActiveChoice::None { candidates: ids } => remote_json(
            GuiShowOutcome::NoActiveMachine,
            local_hex,
            request_id,
            None,
            Some(ids),
        ),
        ActiveChoice::Machine(id) if id == local_machine.0 => {
            local_show(state, actor, rider, &route, local_hex, request_id).await
        }
        ActiveChoice::Machine(id) => {
            let target_hex = hex::encode(id);
            let Some(agent) = peers.get(&id).copied() else {
                return remote_json(
                    GuiShowOutcome::Refused,
                    target_hex,
                    request_id,
                    Some(TARGET_NEEDS_UPGRADE),
                    None,
                );
            };
            send_show_and_wait(state, agent, target_hex, route, rider, request_id).await
        }
    }
}

/// A machine `select_active` can list but cannot choose.
fn quiet_candidate(machine_id: [u8; 32]) -> crate::gui::remote::ActivityCandidate {
    crate::gui::remote::ActivityCandidate {
        machine_id,
        last_gui_visible_at: None,
        remote_enabled: true,
    }
}

async fn enrolled_remote_machines(state: &AppState, local: &MachineId) -> Vec<MachineId> {
    let Some(owner) = state.agent.owner_trust().local_owner() else {
        return Vec::new();
    };
    let Some(store) = owner_device_store(state) else {
        return Vec::new();
    };
    let mut machines = Vec::new();
    for record in store.enrolled_devices().await {
        if record.machine_id == local.0 {
            continue;
        }
        let machine = MachineId(record.machine_id);
        if store.is_enrolled(&machine, &owner).await {
            machines.push(machine);
        }
    }
    machines.sort_by_key(|machine| machine.0);
    machines.dedup();
    machines
}

async fn discovered_agents(state: &AppState, machine: &MachineId) -> Vec<AgentId> {
    let cache = state.agent.identity_discovery_cache();
    let cache = cache.read().await;
    cache
        .iter()
        .filter(|(_, found)| found.machine_id == *machine)
        .map(|(id, _)| *id)
        .collect()
}

/// Online enrolled machine that advertises `gui_show_v1`.
///
/// No address, an offline agent, or a missing bit leaves the machine in
/// the candidate list with no timestamp.
async fn activity_peer(state: &AppState, machine: &MachineId) -> Option<AgentId> {
    let agents = discovered_agents(state, machine).await;
    for agent in agents {
        if state.agent.is_agent_connected(&agent).await && agent_can_show(state, &agent) {
            return Some(agent);
        }
    }
    None
}

/// Agent on `machine` whose verified advert allows a show.
///
/// Prefers a connected agent. An offline agent with the bit is still
/// returned so the send can time out as `unconfirmed`.
async fn show_peer(state: &AppState, machine: &MachineId) -> Option<AgentId> {
    let agents = discovered_agents(state, machine).await;
    let mut offline = None;
    for agent in agents {
        if !agent_can_show(state, &agent) {
            continue;
        }
        if state.agent.is_agent_connected(&agent).await {
            return Some(agent);
        }
        if offline.is_none() {
            offline = Some(agent);
        }
    }
    offline
}

fn agent_can_show(state: &AppState, agent: &AgentId) -> bool {
    let supports = state
        .agent
        .capability_store()
        .verified_registry_supports(agent, crate::dm::CapabilityRegistry::GUI_SHOW_V1);
    capability_allows(supports)
}

async fn send_show_and_wait(
    state: &AppState,
    agent: AgentId,
    target_hex: String,
    route: String,
    via_rider: bool,
    request_id: String,
) -> Response {
    use crate::gui::remote::{GuiShowDmRequest, RESULT_WAIT};

    if !agent_can_show(state, &agent) {
        return remote_json(
            GuiShowOutcome::Refused,
            target_hex,
            request_id,
            Some(TARGET_NEEDS_UPGRADE),
            None,
        );
    }
    let Some(bytes) = parse_request_id(&request_id) else {
        return remote_json(
            GuiShowOutcome::Unconfirmed,
            target_hex,
            request_id,
            None,
            None,
        );
    };
    let body = GuiShowDmRequest {
        request_id: bytes,
        view: route,
        issued_at: unix_secs(),
        via_rider,
    };
    let Some(payload) = body.to_dm_payload() else {
        return remote_json(
            GuiShowOutcome::Unconfirmed,
            target_hex,
            request_id,
            None,
            None,
        );
    };
    let deadline = tokio::time::Instant::now() + RESULT_WAIT;
    // Register before send so a fast result is not lost.
    let rx = state.gui_show.remote_hub().wait_show(bytes);
    if send_gui_dm(state, &agent, payload, bytes).await.is_err() {
        return remote_json(
            GuiShowOutcome::Unconfirmed,
            target_hex,
            request_id,
            None,
            None,
        );
    }
    match tokio::time::timeout_at(deadline, rx).await {
        Ok(Ok(result)) => remote_json(result.outcome, target_hex, request_id, None, None),
        _ => remote_json(
            GuiShowOutcome::Unconfirmed,
            target_hex,
            request_id,
            None,
            None,
        ),
    }
}

async fn send_gui_dm(
    state: &AppState,
    to: &AgentId,
    payload: Vec<u8>,
    logical_request_id: [u8; 16],
) -> Result<(), crate::dm::DmError> {
    let config = crate::dm::DmSendConfig {
        max_retries: 0,
        require_durable_app_ack: false,
        logical_request_id: Some(logical_request_id),
        ..crate::dm::DmSendConfig::default()
    };
    state
        .agent
        .send_direct_with_config(to, payload, config)
        .await
        .map(|_| ())
}

fn remote_json(
    outcome: GuiShowOutcome,
    machine_id: String,
    request_id: String,
    reason: Option<&str>,
    candidates: Option<Vec<String>>,
) -> Response {
    let mut body = serde_json::json!({
        "outcome": outcome,
        "machine_id": machine_id,
        "request_id": request_id,
    });
    if let Some(object) = body.as_object_mut() {
        if let Some(reason) = reason {
            object.insert(
                "reason".to_string(),
                serde_json::Value::String(reason.to_string()),
            );
        }
        if let Some(candidates) = candidates {
            object.insert("candidates".to_string(), serde_json::json!(candidates));
        }
    }
    (StatusCode::OK, Json(body)).into_response()
}

fn json_outcome(outcome: GuiShowOutcome, machine_id: String, request_id: String) -> Response {
    (
        StatusCode::OK,
        Json(GuiShowResponse {
            outcome,
            machine_id,
            request_id,
        }),
    )
        .into_response()
}

fn loopback_api_addr(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_loopback() {
        addr
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    }
}

/// Browser URL for a fresh GUI session.
///
/// `SocketAddr`'s display form brackets an IPv6 host (`[::1]:port`). Formatting
/// the IP and port separately emits `http://::1:port/`, which URL parsers reject.
fn show_loopback_url(api: SocketAddr, session: &str, route: &str) -> String {
    let addr = loopback_api_addr(api);
    format!("http://{addr}/gui?token={session}#/{route}")
}

/// Requesting agent for one admitted show.
///
/// A durable owner acts as this daemon. A rider acts as the token's
/// `sub_agent_id`. `None` means that id is not a 32-byte agent id.
fn show_sender(state: &AppState, actor: &ActorContext) -> Option<AgentId> {
    match actor {
        ActorContext::Owner { .. } => Some(state.agent.agent_id()),
        ActorContext::Rider { sub_agent_id, .. } => {
            super::super::parse_agent_id_hex(sub_agent_id).ok()
        }
    }
}

async fn resolve_banner_labels(
    state: &AppState,
    sender_hex: &str,
    rider: bool,
) -> (String, String) {
    let profile = state.profile.read().await;
    let machine_hex = hex::encode(state.agent.machine_id().as_bytes());
    // The profile names this daemon. A rider has no entry there, so the
    // banner uses the sender's short id (ADR 0083 §5).
    let agent_label = if rider {
        short_id_hex(sender_hex)
    } else {
        profile
            .display_name
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| profile.human_name.clone().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| short_id_hex(sender_hex))
    };
    let machine_label = profile
        .machine_name
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| short_id_hex(&machine_hex));
    (agent_label, machine_label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::{CapturingOpener, GuiShowConfig, ShowOpener};
    use crate::server::routes::named_groups::tests::secure_endpoint_test_state;
    use axum::body::to_bytes;
    use axum::http::Request;
    use axum::routing::post;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn router(state: Arc<AppState>) -> axum::Router {
        // Behaviour tests call the handler as the durable owner. The auth
        // test below drives the real middleware and the non-durable actors.
        axum::Router::new()
            .route("/gui/show", post(gui_show))
            .layer(Extension(ActorContext::Owner { durable: true }))
            .with_state(state)
    }

    async fn post_show(
        app: &axum::Router,
        body: serde_json::Value,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let req = Request::builder()
            .method("POST")
            .uri("/gui/show")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))?;
        let resp = app.clone().oneshot(req).await?;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
    }

    fn install_capturing_opener(state: &Arc<AppState>) -> CapturingOpener {
        let cap = CapturingOpener::new();
        state
            .gui_show
            .replace_opener_for_test(Arc::new(cap.clone()));
        cap
    }

    #[tokio::test]
    async fn durable_show_people_opened_without_token_or_url() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        let outcome = body["outcome"].as_str().unwrap_or("");
        assert!(
            outcome == "opened" || outcome == "navigated",
            "expected opened|navigated, got {body}"
        );
        assert!(body.get("token").is_none(), "must not leak token: {body}");
        assert!(body.get("url").is_none(), "must not leak url: {body}");
        assert!(body.get("session_token").is_none());
        let body_str = body.to_string();
        assert!(
            !body_str.contains("http://"),
            "response must not contain a URL: {body_str}"
        );
        if outcome == "opened" {
            let urls = cap.urls.lock().unwrap();
            assert_eq!(urls.len(), 1);
            assert!(urls[0].contains("/gui?token="));
            assert!(urls[0].contains("#/people"));
            assert!(
                !urls[0].contains("test-token"),
                "durable token must not appear"
            );
        }
        Ok(())
    }

    async fn post_show_as(
        app: &axum::Router,
        bearer: &str,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let req = Request::builder()
            .method("POST")
            .uri("/gui/show")
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({ "view": "people" }).to_string(),
            ))?;
        let resp = app.clone().oneshot(req).await?;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
    }

    /// David approved 22 Oct 2026 13:30 BST (#1392). A GUI session bearer
    /// is refused with the durable-token 403. A scopeless rider is
    /// `missing_scope`. The durable owner token is accepted.
    #[tokio::test]
    async fn gui_show_refuses_session_and_rider_accepts_durable_owner() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = axum::Router::new()
            .route("/gui/show", post(gui_show))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));

        let session = state.sessions.issue(Instant::now());
        let (status, body) = post_show_as(&app, &session).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "GUI session bearer must be refused: {body}"
        );
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("durable API token"),
            "session 403 must name the durable requirement: {body}"
        );

        let rider = {
            let mut store = state.rider_tokens.lock().await;
            let (token, _record) = store
                .issue(
                    "aa".repeat(32),
                    Vec::new(),
                    None,
                    60,
                    String::new(),
                    None,
                    None,
                    crate::server::rider_auth::unix_now_secs(),
                    Vec::new(),
                )
                .await?;
            token
        };
        let (status, body) = post_show_as(&app, &rider).await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "scopeless rider token must be refused: {body}"
        );
        assert_eq!(body["reason"], "missing_scope", "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("gui:show"),
            "scopeless rider 403 must name gui:show: {body}"
        );

        // The handler repeats the same check when middleware is absent.
        for actor in [
            ActorContext::Owner { durable: false },
            ActorContext::Rider {
                sub_agent_id: "aa".repeat(32),
                token_id: 1,
                token_hash: "hash".to_string(),
                groups: Vec::new(),
                scopes: Vec::new(),
            },
        ] {
            let session_bearer = matches!(actor, ActorContext::Owner { .. });
            let bare = axum::Router::new()
                .route("/gui/show", post(gui_show))
                .layer(Extension(actor))
                .with_state(Arc::clone(&state));
            let (status, body) = post_show_as(&bare, "not-a-token").await?;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
            if session_bearer {
                assert!(
                    body["error"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("durable API token"),
                    "handler 403 must name the durable requirement: {body}"
                );
            } else {
                assert_eq!(body["reason"], "missing_scope", "{body}");
            }
        }

        assert!(
            cap.urls.lock().expect("opener lock").is_empty(),
            "a refused caller must not open a browser"
        );

        let (status, body) = post_show_as(&app, "test-token").await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "durable owner token must be accepted: {body}"
        );
        let outcome = body["outcome"].as_str().unwrap_or("");
        assert!(
            outcome == "opened" || outcome == "navigated",
            "durable owner token must reach the handler: {body}"
        );
        Ok(())
    }

    /// A rider whose token carries `gui:show` gets a token-free show response.
    #[tokio::test]
    async fn gui_show_scope_rider_response_has_no_token_or_url() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let tab = state.sessions.issue(Instant::now());
        let probe = {
            let mut sessions = state.ws_sessions.write().await;
            crate::server::ws::insert_visible_gui_with_queue(&mut sessions, "rider-tab", 4, 0, &tab)
        };
        let app = axum::Router::new()
            .route("/gui/show", post(gui_show))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        let rider = {
            let mut store = state.rider_tokens.lock().await;
            let (token, _) = store
                .issue(
                    "aa".repeat(32),
                    Vec::new(),
                    None,
                    60,
                    String::new(),
                    None,
                    None,
                    crate::server::rider_auth::unix_now_secs(),
                    vec!["gui:show".to_string()],
                )
                .await?;
            token
        };
        let (status, body) = post_show_as(&app, &rider).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "navigated", "{body}");
        let keys = body.as_object().expect("object");
        assert_eq!(keys.len(), 3, "{body}");
        assert!(keys.contains_key("outcome") && keys.contains_key("machine_id"));
        assert!(
            keys.contains_key("request_id"),
            "show response must not carry a token or url: {body}"
        );
        let raw = body.to_string();
        assert!(!raw.contains(&rider), "{raw}");
        assert!(
            !raw.contains("session_token") && !raw.contains("http"),
            "{raw}"
        );
        let shows = probe.gui_shows();
        let rider_short = short_id_hex(&"aa".repeat(32));
        let daemon_short = short_id_hex(&hex::encode(state.agent.agent_id().as_bytes()));
        assert!(
            shows.len() == 1 && shows[0].1.contains("(rider)") && shows[0].1.contains(&rider_short),
            "origin banner must name this rider: {shows:?}"
        );
        assert!(
            !shows[0].1.contains(&daemon_short),
            "origin banner must not name the daemon: {shows:?}"
        );
        assert!(cap.urls.lock().expect("opener lock").is_empty());
        Ok(())
    }

    fn auth_router(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route("/gui/show", post(gui_show))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::server::auth::auth_middleware,
            ))
            .with_state(state)
    }

    async fn issue_gui_show_rider(state: &AppState, sub_agent_id: &str) -> anyhow::Result<String> {
        let mut store = state.rider_tokens.lock().await;
        let (token, _) = store
            .issue(
                sub_agent_id.to_string(),
                Vec::new(),
                None,
                60,
                String::new(),
                None,
                None,
                crate::server::rider_auth::unix_now_secs(),
                vec!["gui:show".to_string()],
            )
            .await?;
        Ok(token)
    }

    fn session_token_from_show_url(url: &str) -> String {
        url.split("token=")
            .nth(1)
            .unwrap_or("")
            .split(['&', '#'])
            .next()
            .unwrap_or("")
            .to_string()
    }

    async fn opened_pending(
        app: &axum::Router,
        state: &AppState,
        cap: &CapturingOpener,
        bearer: &str,
    ) -> anyhow::Result<crate::gui::PendingGuiShow> {
        let before = cap.urls.lock().expect("urls").len();
        let (status, body) = post_show_as(app, bearer).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "opened", "{body}");
        let urls = cap.urls.lock().expect("urls");
        assert_eq!(urls.len(), before + 1, "the show must open one browser");
        let token = session_token_from_show_url(&urls[before]);
        drop(urls);
        Ok(state
            .gui_show
            .take_pending_for_session(&token, Instant::now())
            .expect("the opened show queues its banner before the browser connects"))
    }

    /// Two riders keep separate sender ids. Stop on one rider blocks that
    /// rider. It does not turn local show off, and the other rider and the
    /// durable owner can still show.
    #[tokio::test]
    async fn separate_riders_are_blocked_and_attributed_apart_from_the_daemon() -> anyhow::Result<()>
    {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = auth_router(Arc::clone(&state));
        let rider_a = "aa".repeat(32);
        let rider_b = "bb".repeat(32);
        let token_a = issue_gui_show_rider(&state, &rider_a).await?;
        let token_b = issue_gui_show_rider(&state, &rider_b).await?;
        let daemon_hex = hex::encode(state.agent.agent_id().as_bytes());

        let pending_a = opened_pending(&app, &state, &cap, &token_a).await?;
        assert_eq!(pending_a.agent_id, rider_a);
        assert_ne!(pending_a.agent_id, daemon_hex);
        assert!(pending_a.rider);
        assert!(pending_a.banner.contains("(rider)"));
        assert!(pending_a.banner.contains(&short_id_hex(&rider_a)));
        assert!(!pending_a.banner.contains(&short_id_hex(&daemon_hex)));
        assert!(
            pending_a.banner.contains(crate::gui::RIDER_SHOW_REENABLE),
            "rider recovery must name the block file: {}",
            pending_a.banner
        );
        assert!(
            pending_a.banner.contains("gui_show_blocked.json"),
            "rider recovery must name the block file: {}",
            pending_a.banner
        );
        assert!(
            pending_a.banner.contains("restart the daemon"),
            "the block list loads at daemon start: {}",
            pending_a.banner
        );
        assert!(
            !pending_a.banner.contains("gui_show_local_disabled"),
            "deleting the local marker does not unblock this rider: {}",
            pending_a.banner
        );

        // The GUI Stop control sends `gui.block` with this frame's agent id.
        // That id is not the daemon, so production Stop adds it to the block
        // list and leaves local show on (`ws` `GuiBlock`).
        let blocked =
            super::super::super::parse_agent_id_hex(&pending_a.agent_id).expect("rider agent id");
        state.gui_show.block_agent(&blocked);
        assert!(state.gui_show.config().local_enabled);
        assert!(!state.gui_show.is_blocked(&state.agent.agent_id()));

        let urls_after_stop = cap.urls.lock().expect("urls").len();
        let (status, body) = post_show_as(&app, &token_a).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "refused", "{body}");
        assert_eq!(cap.urls.lock().expect("urls").len(), urls_after_stop);

        let pending_b = opened_pending(&app, &state, &cap, &token_b).await?;
        assert_eq!(pending_b.agent_id, rider_b);
        assert!(pending_b.banner.contains(&short_id_hex(&rider_b)));
        assert!(!pending_b.banner.contains(&short_id_hex(&rider_a)));

        let pending_owner = opened_pending(&app, &state, &cap, "test-token").await?;
        assert_eq!(pending_owner.agent_id, daemon_hex);
        assert!(!pending_owner.rider);
        assert!(!pending_owner.banner.contains("(rider)"));
        assert!(
            pending_owner.banner.contains("gui_show_local_disabled"),
            "owner Stop still names the local marker: {}",
            pending_owner.banner
        );
        assert!(
            !pending_owner.banner.contains("gui_show_blocked.json"),
            "owner Stop must not send the human to the block file: {}",
            pending_owner.banner
        );
        Ok(())
    }

    /// Each rider spends its own burst. The daemon's quota stays available.
    #[tokio::test]
    async fn rider_burst_does_not_spend_the_daemon_or_another_rider() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = auth_router(Arc::clone(&state));
        let token_a = issue_gui_show_rider(&state, &"aa".repeat(32)).await?;
        let token_b = issue_gui_show_rider(&state, &"cc".repeat(32)).await?;

        for i in 0..3 {
            let pending = opened_pending(&app, &state, &cap, &token_a).await?;
            assert_eq!(pending.agent_id, "aa".repeat(32), "show {i}");
        }
        let urls = cap.urls.lock().expect("urls").len();
        let (status, body) = post_show_as(&app, &token_a).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "rate_limited", "{body}");
        assert_eq!(cap.urls.lock().expect("urls").len(), urls);

        let owner = opened_pending(&app, &state, &cap, "test-token").await?;
        assert_eq!(
            owner.agent_id,
            hex::encode(state.agent.agent_id().as_bytes())
        );
        let other = opened_pending(&app, &state, &cap, &token_b).await?;
        assert_eq!(other.agent_id, "cc".repeat(32));

        let (status, body) = post_show_as(&app, &token_a).await?;
        assert_eq!(body["outcome"], "rate_limited", "{status} {body}");
        Ok(())
    }

    /// A `gui:show` token whose `sub_agent_id` is not an agent id is refused.
    /// It must not open a browser as the daemon.
    #[tokio::test]
    async fn rider_with_a_bad_sub_agent_id_is_refused() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = auth_router(Arc::clone(&state));
        let token = issue_gui_show_rider(&state, "not-an-agent-id").await?;
        let (status, body) = post_show_as(&app, &token).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "refused", "{body}");
        assert!(cap.urls.lock().expect("urls").is_empty());
        let owner = opened_pending(&app, &state, &cap, "test-token").await?;
        assert_eq!(
            owner.agent_id,
            hex::encode(state.agent.agent_id().as_bytes())
        );
        Ok(())
    }

    #[tokio::test]
    async fn invalid_views_do_not_invoke_opener() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        let hex = "ab".repeat(16);
        for view in [
            "https://evil.example",
            "../x",
            "dm/zz",
            &format!("groups/{hex}/unknownapp"),
        ] {
            let (status, body) = post_show(&app, json!({ "view": view })).await?;
            assert_eq!(status, StatusCode::OK, "view={view}");
            assert_eq!(body["outcome"], "invalid_view", "view={view} body={body}");
        }
        assert!(
            cap.urls.lock().unwrap().is_empty(),
            "opener must not run for invalid_view"
        );
        Ok(())
    }

    #[tokio::test]
    async fn local_disabled_gives_disabled() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        install_capturing_opener(&state);
        state.gui_show.set_config(GuiShowConfig {
            local_enabled: false,
            remote_enabled: true,
        });
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "disabled");
        Ok(())
    }

    #[tokio::test]
    async fn fourth_burst_request_is_rate_limited() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        for i in 0..3 {
            let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
            assert_eq!(status, StatusCode::OK, "req {i}");
            let o = body["outcome"].as_str().unwrap_or("");
            assert!(
                o == "opened" || o == "navigated" || o == "no_display",
                "req {i}: {body}"
            );
        }
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "rate_limited", "{body}");
        Ok(())
    }

    #[tokio::test]
    async fn open_ws_session_yields_navigated_when_the_queue_accepts() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let token = state.sessions.issue(Instant::now());
        let probe = {
            let mut sessions = state.ws_sessions.write().await;
            crate::server::ws::insert_visible_gui_with_queue(
                &mut sessions,
                "test-session",
                4,
                0,
                &token,
            )
        };
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "network" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "navigated", "{body}");
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        assert!(
            cap.urls.lock().unwrap().is_empty(),
            "must not open a window"
        );
        let shows = probe.gui_shows();
        assert_eq!(shows.len(), 1, "{shows:?}");
        assert_eq!(shows[0].0, "network");
        assert!(
            shows[0].1.starts_with("Opened by "),
            "banner={}",
            shows[0].1
        );
        Ok(())
    }

    #[tokio::test]
    async fn saturated_live_tab_does_not_report_navigated() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let token = state.sessions.issue(Instant::now());
        let probe = {
            let mut sessions = state.ws_sessions.write().await;
            crate::server::ws::insert_visible_gui_with_queue(
                &mut sessions,
                "saturated",
                1,
                1,
                &token,
            )
        };
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "opened",
            "a full live-tab queue is not a navigation: {body}"
        );
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        let urls = cap.urls.lock().unwrap();
        assert_eq!(
            urls.len(),
            1,
            "the browser must open when the frame is not queued"
        );
        assert!(urls[0].contains("#/people"), "{}", urls[0]);
        drop(urls);
        assert!(
            probe.gui_shows().is_empty(),
            "the saturated queue must not contain the show frame"
        );
        Ok(())
    }

    #[tokio::test]
    async fn expired_visible_tab_does_not_report_navigated() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let token = state.sessions.issue(Instant::now());
        let probe = {
            let mut sessions = state.ws_sessions.write().await;
            crate::server::ws::insert_visible_gui_with_queue(
                &mut sessions,
                "expired-tab",
                4,
                0,
                &token,
            )
        };
        state.sessions.expire_for_test(&token);
        assert!(
            !state.sessions.is_live_for_test(&token, Instant::now()),
            "the fixture must be an expired GUI session"
        );
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "opened",
            "an expired visible tab is not a navigation: {body}"
        );
        assert!(
            probe.gui_shows().is_empty(),
            "the expired tab must not be told to navigate"
        );
        let urls = cap.urls.lock().unwrap();
        assert_eq!(urls.len(), 1, "the browser must open");
        assert!(urls[0].contains("#/people"), "{}", urls[0]);
        Ok(())
    }

    #[tokio::test]
    async fn agent_ws_does_not_suppress_opening_the_browser() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        {
            let mut sessions = state.ws_sessions.write().await;
            sessions.insert(
                "agent-ws".to_string(),
                crate::server::ws::test_ws_session("agent-ws"),
            );
            sessions.insert(
                "agent-direct".to_string(),
                crate::server::ws::test_ws_session("agent-direct"),
            );
        }
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "opened",
            "an agent /ws or /ws/direct socket is not a visible GUI: {body}"
        );
        let urls = cap.urls.lock().unwrap();
        assert_eq!(urls.len(), 1, "the browser must still be opened");
        assert!(
            urls[0].contains("gui=1") || urls[0].contains("/gui?token="),
            "opened url={}",
            urls[0]
        );
        Ok(())
    }

    #[tokio::test]
    async fn blocking_the_daemon_agent_refuses_local_show() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        state.gui_show.block_agent(&state.agent.agent_id());
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "refused",
            "ADR 0083 §5 refuses a blocked sender, including this daemon's agent: {body}"
        );
        assert!(
            cap.urls.lock().unwrap().is_empty(),
            "a blocked sender must not open a window"
        );
        Ok(())
    }

    #[test]
    fn ipv6_loopback_url_brackets_the_host() {
        let addr: std::net::SocketAddr = "[::1]:12700".parse().expect("ipv6 loopback");
        let url = show_loopback_url(addr, "sess", "people");
        assert_eq!(url, "http://[::1]:12700/gui?token=sess#/people");
        assert!(
            !url.contains("http://::1:"),
            "an unbracketed IPv6 URL does not parse: {url}"
        );
        let v4: std::net::SocketAddr = "127.0.0.1:12700".parse().expect("ipv4 loopback");
        assert_eq!(
            show_loopback_url(v4, "sess", "network"),
            "http://127.0.0.1:12700/gui?token=sess#/network"
        );
    }

    #[tokio::test]
    async fn opener_failure_is_no_display() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        *cap.succeed.lock().expect("succeed flag") = false;
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "no_display", "{body}");
        let urls = cap.urls.lock().expect("urls");
        assert_eq!(urls.len(), 1, "the opener still receives the URL");
        let token = urls[0]
            .split("token=")
            .nth(1)
            .unwrap_or("")
            .split(['&', '#'])
            .next()
            .unwrap_or("")
            .to_string();
        drop(urls);
        assert!(
            !token.is_empty(),
            "the failed launch still minted a session"
        );
        assert!(
            state
                .gui_show
                .take_pending_for_session(&token, std::time::Instant::now())
                .is_none(),
            "a failed opener must drop the banner it queued"
        );
        assert!(
            !state
                .sessions
                .is_live_for_test(&token, std::time::Instant::now()),
            "a failed opener must revoke the session it minted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pending_banner_is_queued_before_the_opener_runs() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let saw = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let weak = Arc::downgrade(&state);
        let queued = saw.clone();
        struct Probe {
            saw: Arc<std::sync::atomic::AtomicBool>,
            check: Arc<dyn Fn(&str) -> bool + Send + Sync>,
        }
        impl ShowOpener for Probe {
            fn open(&self, url: &str) -> bool {
                self.saw
                    .store((self.check)(url), std::sync::atomic::Ordering::SeqCst);
                true
            }
        }
        state.gui_show.replace_opener_for_test(Arc::new(Probe {
            saw: queued,
            check: Arc::new(move |url: &str| {
                let Some(state) = weak.upgrade() else {
                    return false;
                };
                let Some(token) = url.split("token=").nth(1) else {
                    return false;
                };
                let token = token.split(['&', '#']).next().unwrap_or("");
                !token.is_empty() && state.gui_show.has_pending_session(token)
            }),
        }));
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["outcome"], "opened", "{body}");
        assert!(
            saw.load(std::sync::atomic::Ordering::SeqCst),
            "the banner must already be queued while the opener runs"
        );
        Ok(())
    }

    #[tokio::test]
    async fn hidden_gui_tab_does_not_suppress_opening_the_browser() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        {
            let mut sessions = state.ws_sessions.write().await;
            sessions.insert(
                "hidden-gui".to_string(),
                crate::server::ws::test_gui_ws_session("hidden-gui"),
            );
            sessions
                .get_mut("hidden-gui")
                .expect("session")
                .set_visible_gui(false);
        }
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["outcome"], "opened",
            "a hidden tab is not a live GUI: {body}"
        );
        assert_eq!(cap.urls.lock().unwrap().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn two_shows_before_the_browser_connects_keep_both_pending() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        let (status_a, body_a) = post_show(&app, json!({ "view": "people" })).await?;
        let (status_b, body_b) = post_show(&app, json!({ "view": "network" })).await?;
        assert_eq!(status_a, StatusCode::OK);
        assert_eq!(status_b, StatusCode::OK);
        assert_eq!(body_a["outcome"], "opened", "{body_a}");
        assert_eq!(body_b["outcome"], "opened", "{body_b}");
        let urls = cap.urls.lock().unwrap();
        assert_eq!(urls.len(), 2, "both shows must open a window: {urls:?}");
        let token = |url: &str| {
            url.split("token=")
                .nth(1)
                .unwrap_or("")
                .split(['&', '#'])
                .next()
                .unwrap_or("")
                .to_string()
        };
        let token_a = token(&urls[0]);
        let token_b = token(&urls[1]);
        assert_ne!(token_a, token_b, "each window has its own session");
        drop(urls);
        let now = std::time::Instant::now();
        let first = state
            .gui_show
            .take_pending_for_session(&token_a, now)
            .expect("first show still pending");
        let second = state
            .gui_show
            .take_pending_for_session(&token_b, now)
            .expect("second show still pending");
        assert_eq!(first.view, "people");
        assert_eq!(second.view, "network");
        assert!(
            state
                .gui_show
                .take_pending_for_session("not-a-gui-session", now)
                .is_none(),
            "an arbitrary socket must not receive either banner"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stop_then_reload_reenables_local_show() -> anyhow::Result<()> {
        let (state, dir) = secure_endpoint_test_state().await?;
        let path = dir.path().join("config.toml");
        let original = "[gui_show]\nlocal_enabled = true\nremote_enabled = true\n";
        std::fs::write(&path, original)?;
        state.gui_show.set_config_path(Some(path.clone()));
        state
            .gui_show
            .disable_local_show()
            .map_err(|error| anyhow::anyhow!(error))?;
        let app = router(Arc::clone(&state));
        install_capturing_opener(&state);
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "disabled", "{body}");
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        assert_eq!(
            std::fs::read_to_string(&path)?,
            original,
            "stop leaves the daemon config unchanged"
        );
        assert!(dir
            .path()
            .join(crate::gui::show::LOCAL_SHOW_STOP_FILE)
            .is_file());
        std::fs::write(&path, original)?;
        state
            .gui_show
            .reload_from_disk()
            .map_err(|error| anyhow::anyhow!(error))?;
        assert!(dir
            .path()
            .join(crate::gui::show::LOCAL_SHOW_STOP_FILE)
            .is_file());
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "disabled", "{body}");
        std::fs::remove_file(dir.path().join(crate::gui::show::LOCAL_SHOW_STOP_FILE))?;
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "opened", "{body}");
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        Ok(())
    }

    #[tokio::test]
    async fn stop_without_a_config_file_disables_show_and_creates_no_config() -> anyhow::Result<()>
    {
        let (state, dir) = secure_endpoint_test_state().await?;
        state
            .gui_show
            .disable_local_show()
            .map_err(|error| anyhow::anyhow!(error))?;
        assert!(!state.gui_show.config().local_enabled);
        assert!(dir
            .path()
            .join(crate::gui::show::LOCAL_SHOW_STOP_FILE)
            .is_file());
        assert!(
            !dir.path().join("config.toml").exists(),
            "stop must not invent a daemon config"
        );
        let app = router(Arc::clone(&state));
        install_capturing_opener(&state);
        let (status, body) = post_show(&app, json!({ "view": "people" })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "disabled", "{body}");
        assert!(body.get("url").is_none(), "{body}");
        assert!(body.get("token").is_none(), "{body}");
        assert!(body.get("session_token").is_none(), "{body}");
        Ok(())
    }

    #[tokio::test]
    async fn acl_reload_returns_only_the_acl_report() -> anyhow::Result<()> {
        let (state, dir) = secure_endpoint_test_state().await?;
        state.gui_show.set_config(GuiShowConfig {
            local_enabled: true,
            remote_enabled: true,
        });
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[gui_show]\nlocal_enabled = \n")?;
        state.gui_show.set_config_path(Some(path));
        let app = axum::Router::new()
            .route("/acl/reload", post(super::super::acl_reload))
            .with_state(Arc::clone(&state));

        let (status, body) = post_reload(&app).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("gui_show").is_none(), "{body}");
        assert_eq!(body["ok"], json!(true), "{body}");
        assert!(
            state.gui_show.config().local_enabled,
            "a TOML error keeps the last good config"
        );
        assert!(state.gui_show.config().remote_enabled);

        state
            .gui_show
            .set_config_path(Some(dir.path().join("missing.toml")));
        let (status, body) = post_reload(&app).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("gui_show").is_none(), "{body}");
        assert_eq!(body["ok"], json!(true), "{body}");
        assert!(state.gui_show.config().local_enabled);
        assert!(state.gui_show.config().remote_enabled);
        Ok(())
    }

    async fn post_reload(app: &axum::Router) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let req = Request::builder()
            .method("POST")
            .uri("/acl/reload")
            .extension(crate::server::rider_auth::ActorContext::Owner { durable: true })
            .body(axum::body::Body::empty())?;
        let resp = app.clone().oneshot(req).await?;
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await?;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or_default()))
    }

    #[tokio::test]
    async fn registry_lists_gui_show() {
        assert!(
            crate::api::ENDPOINTS
                .iter()
                .any(|e| e.path == "/gui/show" && matches!(e.method, crate::api::Method::Post)),
            "POST /gui/show must be registered"
        );
        assert_eq!(
            crate::api::ENDPOINTS
                .iter()
                .find(|e| e.path == "/gui/show")
                .map(|e| e.cli_name),
            Some("show")
        );
    }

    #[test]
    fn classify_target_splits_local_active_explicit_and_invalid() {
        assert_eq!(classify_target(""), TargetKind::Local);
        assert_eq!(classify_target("active"), TargetKind::Active);
        assert_eq!(classify_target("Active"), TargetKind::Invalid);
        let id = "ab".repeat(32);
        let bytes = hex::decode(&id).unwrap();
        assert_eq!(
            classify_target(&id),
            TargetKind::Explicit(bytes.try_into().unwrap())
        );
        assert_eq!(classify_target(&"ab".repeat(31)), TargetKind::Invalid);
        assert_eq!(classify_target(&"zz".repeat(32)), TargetKind::Invalid);
    }

    #[test]
    fn capability_allows_only_some_true() {
        assert!(capability_allows(Some(true)));
        assert!(!capability_allows(Some(false)));
        assert!(!capability_allows(None));
    }

    #[test]
    fn remote_target_decision_refuses_an_unenrolled_explicit_machine() {
        let local = [1_u8; 32];
        let other = [2_u8; 32];
        assert_eq!(
            remote_target_decision(TargetKind::Explicit(other), true, false, &local),
            RemoteTargetDecision::Refused
        );
        assert_eq!(
            remote_target_decision(TargetKind::Explicit(other), false, true, &local),
            RemoteTargetDecision::Refused
        );
        assert_eq!(
            remote_target_decision(TargetKind::Explicit(other), false, false, &local),
            RemoteTargetDecision::Refused
        );
        assert_eq!(
            remote_target_decision(TargetKind::Explicit(other), true, true, &local),
            RemoteTargetDecision::Remote(other)
        );
        assert_eq!(
            remote_target_decision(TargetKind::Explicit(local), true, true, &local),
            RemoteTargetDecision::LocalDisplay
        );
        assert_eq!(
            remote_target_decision(TargetKind::Invalid, true, true, &local),
            RemoteTargetDecision::Refused
        );
        assert_eq!(
            remote_target_decision(TargetKind::Active, false, false, &local),
            RemoteTargetDecision::QueryActive
        );
    }

    #[tokio::test]
    async fn null_and_empty_target_stay_on_the_local_response() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        for body in [
            json!({ "view": "people", "target_machine": null }),
            json!({ "view": "people", "target_machine": "" }),
        ] {
            let (status, body) = post_show(&app, body).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            let outcome = body["outcome"].as_str().unwrap_or("");
            assert!(
                outcome == "opened" || outcome == "navigated" || outcome == "no_display",
                "{body}"
            );
            let parsed: GuiShowResponse =
                serde_json::from_value(body.clone()).expect("local body is GuiShowResponse");
            assert_eq!(parsed.request_id.len(), 32);
            assert!(body.get("reason").is_none(), "{body}");
            assert!(body.get("candidates").is_none(), "{body}");
        }
        Ok(())
    }

    /// `active` with no visible GUI and an empty device set lists this
    /// machine and does not open a window.
    #[tokio::test]
    async fn active_with_no_visible_gui_is_no_active_machine() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        assert!(state.gui_show.last_gui_visible_at().is_none());
        assert!(state.owner_sync.is_none());
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(
            &app,
            json!({ "view": "people", "target_machine": "active" }),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "no_active_machine", "{body}");
        assert!(body.get("reason").is_none(), "{body}");
        let local = hex::encode(state.agent.machine_id().as_bytes());
        let candidates = body["candidates"]
            .as_array()
            .expect("no_active_machine lists candidates");
        assert!(
            candidates
                .iter()
                .any(|id| id.as_str() == Some(local.as_str())),
            "{body}"
        );
        assert!(body.get("url").is_none(), "{body}");
        assert!(!body.to_string().contains("http"));
        assert!(cap.urls.lock().unwrap().is_empty());
        Ok(())
    }

    /// A GUI that was just visible is the active machine, so `active` shows
    /// here. Removing `select_active` (or ignoring the local stamp) leaves
    /// this as `no_active_machine`.
    #[tokio::test]
    async fn active_uses_the_local_visibility_stamp() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        state.gui_show.note_gui_visible(now);
        let app = router(Arc::clone(&state));
        let (status, body) = post_show(
            &app,
            json!({ "view": "people", "target_machine": "active" }),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let outcome = body["outcome"].as_str().unwrap_or("");
        assert!(outcome == "opened" || outcome == "navigated", "{body}");
        assert!(body.get("candidates").is_none(), "{body}");
        assert!(body.get("reason").is_none(), "{body}");
        assert!(!body.to_string().contains("http"));
        assert!(!cap.urls.lock().unwrap().is_empty() || outcome == "navigated");
        Ok(())
    }

    /// Missing, negative, and positive `gui_show_v1` adverts. Removing the
    /// bit test in `agent_can_show` makes the first two asserts fail.
    #[tokio::test]
    async fn missing_gui_show_capability_is_not_a_send_target() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let agent = AgentId([0xAB; 32]);
        let machine = MachineId([0xCD; 32]);
        assert!(
            !agent_can_show(&state, &agent),
            "no verified advert is target_needs_upgrade"
        );

        let mut caps = crate::dm::DmCapabilities::pending();
        caps.application_registry = crate::dm::CapabilityRegistry {
            version: 1,
            bits: crate::dm::CapabilityRegistry::current().bits
                & !crate::dm::CapabilityRegistry::GUI_SHOW_V1,
        };
        let now_ms = unix_secs().saturating_mul(1000);
        assert!(state
            .agent
            .capability_store()
            .insert(agent, machine, caps.clone(), now_ms));
        assert!(
            !agent_can_show(&state, &agent),
            "an advert without gui_show_v1 is target_needs_upgrade"
        );

        caps.application_registry.bits |= crate::dm::CapabilityRegistry::GUI_SHOW_V1;
        assert!(state.agent.capability_store().insert(
            agent,
            machine,
            caps,
            now_ms.saturating_add(1)
        ));
        assert!(
            agent_can_show(&state, &agent),
            "a current advert with the bit may be sent"
        );
        Ok(())
    }

    /// A 64-hex id that is not enrolled is refused. The opener does not run.
    #[tokio::test]
    async fn explicit_machine_that_is_not_enrolled_is_refused() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        let id = "cd".repeat(32);
        let (status, body) =
            post_show(&app, json!({ "view": "people", "target_machine": id })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "refused", "{body}");
        assert!(body.get("reason").is_none(), "{body}");
        assert!(body.get("candidates").is_none(), "{body}");
        assert_eq!(body["machine_id"], id, "{body}");
        assert!(cap.urls.lock().unwrap().is_empty());
        let bad = "not-a-machine";
        let (status, body) =
            post_show(&app, json!({ "view": "people", "target_machine": bad })).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["outcome"], "refused", "{body}");
        assert!(cap.urls.lock().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn remote_target_rejects_a_url_view_without_opening() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let app = router(Arc::clone(&state));
        for target in ["active", "cd".repeat(32).as_str()] {
            let (status, body) = post_show(
                &app,
                json!({ "view": "https://evil.example", "target_machine": target }),
            )
            .await?;
            assert_eq!(status, StatusCode::OK, "{target} {body}");
            assert_eq!(body["outcome"], "invalid_view", "{target} {body}");
            assert!(body.get("reason").is_none(), "{body}");
            assert!(body.get("candidates").is_none(), "{body}");
            assert!(!body.to_string().contains("http://"));
        }
        assert!(cap.urls.lock().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn deliver_remote_show_rejects_a_url_and_names_a_remote_agent() -> anyhow::Result<()> {
        let (state, _dir) = secure_endpoint_test_state().await?;
        let cap = install_capturing_opener(&state);
        let request_id = "ab".repeat(16);
        let sender = AgentId([0x11; 32]);
        let machine = MachineId([0x22; 32]);
        let outcome = deliver_remote_show(
            &state,
            sender,
            machine,
            "https://evil.example",
            false,
            &request_id,
        )
        .await;
        assert_eq!(outcome, GuiShowOutcome::InvalidView);
        assert!(cap.urls.lock().unwrap().is_empty());

        let outcome =
            deliver_remote_show(&state, sender, machine, "people", false, &request_id).await;
        assert_eq!(outcome, GuiShowOutcome::Opened);
        let token = {
            let urls = cap.urls.lock().unwrap();
            assert_eq!(urls.len(), 1);
            assert!(urls[0].contains("#/people"));
            assert!(!urls[0].contains(&request_id));
            session_token_from_show_url(&urls[0])
        };
        let pending = state
            .gui_show
            .take_pending_for_session(&token, Instant::now())
            .expect("banner queued");
        assert_eq!(pending.request_id, request_id);
        assert!(pending.banner.starts_with("Opened by "));
        assert!(pending.banner.contains(REMOTE_SHOW_REENABLE));
        assert!(!pending.banner.contains("rider"));
        assert!(!pending.banner.contains("http"));
        assert!(!pending.rider);

        let rider_outcome =
            deliver_remote_show(&state, sender, machine, "network", true, &request_id).await;
        assert_eq!(rider_outcome, GuiShowOutcome::Opened);
        let token = {
            let urls = cap.urls.lock().unwrap();
            session_token_from_show_url(urls.last().unwrap())
        };
        let pending = state
            .gui_show
            .take_pending_for_session(&token, Instant::now())
            .expect("rider banner queued");
        assert!(pending.banner.contains("(rider)"));
        assert!(pending.banner.contains(crate::gui::RIDER_SHOW_REENABLE));
        assert!(pending.rider);

        let daemon = state.agent.agent_id();
        let local_machine = state.agent.machine_id();
        let local_outcome = deliver_remote_show(
            &state,
            daemon,
            local_machine,
            "settings",
            false,
            &request_id,
        )
        .await;
        assert_eq!(local_outcome, GuiShowOutcome::Opened);
        let token = {
            let urls = cap.urls.lock().unwrap();
            session_token_from_show_url(urls.last().unwrap())
        };
        let pending = state
            .gui_show
            .take_pending_for_session(&token, Instant::now())
            .expect("local banner queued");
        assert!(pending.banner.contains("gui_show_local_disabled"));
        assert!(!pending.banner.contains("gui_show_blocked.json"));
        assert!(!pending.rider);
        Ok(())
    }

    /// Three slow opens used to share one mutex and an `Arc<AppState>` on
    /// the blocking pool. Shutdown's 2s grace then returned while those
    /// launches still held the Agent and the database.
    #[tokio::test]
    async fn concurrent_opens_finish_at_shutdown_without_holding_state() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::Duration;

        struct Release(Arc<AtomicBool>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        struct SlowOpen {
            entered: Arc<AtomicUsize>,
            in_flight: Arc<AtomicUsize>,
            release: Arc<AtomicBool>,
        }
        impl SlowOpen {
            fn park(&self, stop: &AtomicBool) -> bool {
                self.in_flight.fetch_add(1, Ordering::SeqCst);
                self.entered.fetch_add(1, Ordering::SeqCst);
                // One wait with no stop check. A drain that joins this launch
                // is still inside it. A drain that does not track it returns
                // during the wait.
                std::thread::sleep(Duration::from_millis(200));
                while !stop.load(Ordering::Acquire) && !self.release.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(20));
                }
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                false
            }
        }
        impl ShowOpener for SlowOpen {
            fn open(&self, _url: &str) -> bool {
                self.park(&AtomicBool::new(false))
            }
            fn open_until(&self, _url: &str, stop: &AtomicBool) -> bool {
                self.park(stop)
            }
        }

        let (state, _dir) = secure_endpoint_test_state().await?;
        let entered = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let _release_on_drop = Release(Arc::clone(&release));
        state.gui_show.replace_opener_for_test(Arc::new(SlowOpen {
            entered: Arc::clone(&entered),
            in_flight: Arc::clone(&in_flight),
            release: Arc::clone(&release),
        }));
        let baseline = Arc::strong_count(&state);
        let app = router(Arc::clone(&state));
        let mut joins = Vec::new();
        for _ in 0..3 {
            let app = app.clone();
            joins.push(tokio::spawn(async move {
                let _ = post_show(&app, json!({ "view": "people" })).await;
            }));
        }
        let ready = tokio::time::timeout(Duration::from_secs(1), async {
            while entered.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            ready.is_ok(),
            "three launches did not run together; entered={}",
            entered.load(Ordering::SeqCst)
        );
        for join in &joins {
            join.abort();
        }
        for join in joins {
            let _ = join.await;
        }
        drop(app);
        tokio::task::yield_now().await;
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            3,
            "aborting the HTTP handlers stopped the browser opens"
        );
        assert_eq!(
            Arc::strong_count(&state),
            baseline,
            "an in-flight browser open still holds AppState"
        );
        let started = Instant::now();
        crate::server::drain_server_tasks(&state, Vec::new()).await;
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            0,
            "browser opens outlived the shutdown drain"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown waited out the serialized opens: {:?}",
            started.elapsed()
        );
        Ok(())
    }
}
