//! Route handlers (`category: "calls"` in `src/api/mod.rs`) — ADR-0073
//! slice 1: call lifecycle only, no media.
//!
//! The pure state machine and the access-control gates live in
//! [`crate::calls`]; this module owns the daemon I/O: REST handlers, the
//! inbound DM listener, the missed-call sweeper, and the `call.incoming` /
//! `call.state` broadcasts on `/events` (and, via `ws.rs`, `/ws`).

use super::super::sse::SseEvent;
use super::super::state::AppState;
use super::super::{api_error, parse_agent_id_hex};
use crate::calls::{CallError, CallEvent, CallFrame, CallRefusal, CallRegistry, MediaKinds};
use crate::identity::AgentId;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

/// How often the sweeper checks for unanswered invites.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// POST /calls request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::server) struct CallCreateRequest {
    /// Callee agent ID as 64-character hex string.
    agent_id: String,
    /// Request video as well as audio.
    #[serde(default)]
    video: bool,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Broadcast call events on the daemon event channel (`/events` SSE; the
/// `/ws` sessions forward the same `call.*` events).
pub(in crate::server) fn broadcast_call_events(state: &AppState, events: Vec<CallEvent>) {
    for event in events {
        let data = serde_json::to_value(event.snapshot()).unwrap_or(serde_json::Value::Null);
        let _ = state.broadcast_tx.send(SseEvent {
            event_type: event.event_type().to_string(),
            data,
        });
    }
}

/// Send one lifecycle frame to `peer` over the voice DM channel.
async fn send_frame(state: &AppState, peer: &AgentId, frame: &CallFrame) -> Result<(), String> {
    let payload = frame.encode().map_err(|e| e.to_string())?;
    state
        .agent
        .send_direct(peer, payload)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn refusal_response(refusal: CallRefusal) -> axum::response::Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "ok": false,
            "error": "callee does not pass the trust / connect-ACL gates",
            "reason": refusal,
        })),
    )
        .into_response()
}

fn call_error_response(err: &CallError) -> axum::response::Response {
    let status = match err {
        CallError::NotFound => StatusCode::NOT_FOUND,
        CallError::InvalidState(_) => StatusCode::CONFLICT,
        CallError::TooManyCalls => StatusCode::TOO_MANY_REQUESTS,
    };
    api_error(status, err.to_string()).into_response()
}

fn call_response(status: StatusCode, call: serde_json::Value) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({ "ok": true, "call": call })),
    )
        .into_response()
}

/// POST /calls — ring an agent (audio, optionally video).
pub(in crate::server) async fn call_create(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CallCreateRequest>,
) -> axum::response::Response {
    let callee = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e).into_response(),
    };
    if let Err(refusal) = state.agent.call_gate_outbound(&callee).await {
        return refusal_response(refusal);
    }
    let media = MediaKinds {
        audio: true,
        video: req.video,
    };
    let started = state
        .calls
        .lock()
        .await
        .start_outgoing(callee, media, now_ms());
    let (invite, events) = match started {
        Ok(v) => v,
        Err(e) => return call_error_response(&e),
    };
    broadcast_call_events(&state, events);
    let call_id = invite.call_id().to_owned();
    if let Err(e) = send_frame(&state, &callee, &invite).await {
        let events = state.calls.lock().await.fail(&call_id, now_ms());
        broadcast_call_events(&state, events);
        return api_error(
            StatusCode::BAD_GATEWAY,
            format!("invite not delivered: {e}"),
        )
        .into_response();
    }
    let snap = state.calls.lock().await.get(&call_id);
    call_response(
        StatusCode::CREATED,
        serde_json::to_value(snap).unwrap_or(serde_json::Value::Null),
    )
}

/// GET /calls — retained calls (newest first) plus gate/lifecycle counters.
pub(in crate::server) async fn call_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let reg = state.calls.lock().await;
    Json(serde_json::json!({
        "ok": true,
        "calls": reg.list(),
        "stats": reg.stats(),
    }))
}

/// GET /calls/:id — one call.
pub(in crate::server) async fn call_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.calls.lock().await.get(&id) {
        Some(snap) => call_response(
            StatusCode::OK,
            serde_json::to_value(snap).unwrap_or(serde_json::Value::Null),
        ),
        None => call_error_response(&CallError::NotFound),
    }
}

/// Which local action a lifecycle route performs.
#[derive(Clone, Copy)]
enum Action {
    Accept,
    Reject,
    Hangup,
}

async fn lifecycle(state: Arc<AppState>, id: String, action: Action) -> axum::response::Response {
    // Accept re-checks the caller against the gates: trust may have been
    // revoked while the call was ringing (ADR-0073 decision 4 — no bypass).
    if matches!(action, Action::Accept) {
        let peer = match state.calls.lock().await.get(&id) {
            Some(snap) => snap.peer,
            None => return call_error_response(&CallError::NotFound),
        };
        let Ok(peer) = parse_agent_id_hex(&peer) else {
            return call_error_response(&CallError::NotFound);
        };
        if let Err(refusal) = state.agent.call_gate_outbound(&peer).await {
            return refusal_response(refusal);
        }
    }
    let result = {
        let mut reg = state.calls.lock().await;
        let now = now_ms();
        match action {
            Action::Accept => reg.accept(&id, now),
            Action::Reject => reg.reject(&id, now),
            Action::Hangup => reg.hangup(&id, now),
        }
    };
    let (peer, frame, events) = match result {
        Ok(v) => v,
        Err(e) => return call_error_response(&e),
    };
    broadcast_call_events(&state, events);
    let delivered = send_frame(&state, &peer, &frame).await;
    if let (Action::Accept, Err(e)) = (action, &delivered) {
        let events = state.calls.lock().await.fail(&id, now_ms());
        broadcast_call_events(&state, events);
        return api_error(
            StatusCode::BAD_GATEWAY,
            format!("accept not delivered: {e}"),
        )
        .into_response();
    }
    // Reject/hangup are final locally whether or not the peer hears it;
    // the peer's own timeout or next frame reconciles.
    let snap = state.calls.lock().await.get(&id);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "call": snap,
            "delivered": delivered.is_ok(),
        })),
    )
        .into_response()
}

/// POST /calls/:id/accept — answer a ringing incoming call.
pub(in crate::server) async fn call_accept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    lifecycle(state, id, Action::Accept).await
}

/// POST /calls/:id/reject — decline a ringing incoming call.
pub(in crate::server) async fn call_reject(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    lifecycle(state, id, Action::Reject).await
}

/// POST /calls/:id/hangup — end (or cancel) a call.
pub(in crate::server) async fn call_hangup(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    lifecycle(state, id, Action::Hangup).await
}

/// Background task: consume `x0x_call_*` frames from the DM channel.
///
/// Invites and accepts are gated with [`crate::Agent::call_gate_inbound`]
/// before [`CallRegistry::on_invite`] / `on_remote_frame` see them; a
/// refused invite never rings. Reject/hangup only ever END a call the
/// same peer is already party to, so they are not gated (a peer revoked
/// mid-call can still hang up).
pub(in crate::server) async fn run_call_listener(state: Arc<AppState>) {
    let mut rx = state.agent.subscribe_direct();
    while let Some(msg) = rx.recv().await {
        let Some(frame) = CallFrame::decode(&msg.payload) else {
            continue;
        };
        let gated = matches!(frame, CallFrame::Invite { .. } | CallFrame::Accept { .. });
        let gate = if gated {
            state
                .agent
                .call_gate_inbound(&msg.sender, &msg.machine_id, msg.verified)
                .await
        } else {
            Ok(())
        };
        let now = now_ms();
        let (events, reply) = match &frame {
            CallFrame::Invite { call_id, media } => {
                if let Err(refusal) = gate {
                    tracing::debug!(
                        target: "x0x::calls",
                        caller = %hex::encode(msg.sender.as_bytes()),
                        reason = ?refusal,
                        "call invite refused at gate (did not ring)"
                    );
                }
                let events = state
                    .calls
                    .lock()
                    .await
                    .on_invite(msg.sender, gate, call_id, *media, now);
                (events, None)
            }
            _ if gate.is_err() => continue,
            other => {
                let out = state
                    .calls
                    .lock()
                    .await
                    .on_remote_frame(msg.sender, other, now);
                (out.events, out.reply)
            }
        };
        broadcast_call_events(&state, events);
        if let Some(reply) = reply {
            if let Err(e) = send_frame(&state, &msg.sender, &reply).await {
                tracing::debug!(target: "x0x::calls", error = %e, "call reply not delivered");
            }
        }
    }
}

/// Background task: end unanswered invites as `missed` after 30 s and
/// tell the callee of our own unanswered invites to stop ringing.
pub(in crate::server) async fn run_call_sweeper(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        let (events, frames) = state.calls.lock().await.expire(now_ms());
        broadcast_call_events(&state, events);
        for (peer, frame) in frames {
            if let Err(e) = send_frame(&state, &peer, &frame).await {
                tracing::debug!(target: "x0x::calls", error = %e, "missed-call hangup not delivered");
            }
        }
    }
}

/// A fresh registry for [`AppState`].
pub(in crate::server) fn new_registry() -> tokio::sync::Mutex<CallRegistry> {
    tokio::sync::Mutex::new(CallRegistry::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    // WHY: `POST /calls` is a public REST contract (ADR-0073 §3):
    // `agent_id` required, `video` optional (default false), unknown
    // fields rejected rather than silently ignored.
    #[test]
    fn create_request_json_shape() {
        let req: CallCreateRequest =
            serde_json::from_str(&format!(r#"{{"agent_id":"{}"}}"#, "ab".repeat(32)))
                .expect("minimal body");
        assert!(!req.video);
        let req: CallCreateRequest = serde_json::from_str(&format!(
            r#"{{"agent_id":"{}","video":true}}"#,
            "ab".repeat(32)
        ))
        .expect("video body");
        assert!(req.video);
        assert!(serde_json::from_str::<CallCreateRequest>(r#"{"video":true}"#).is_err());
        assert!(serde_json::from_str::<CallCreateRequest>(&format!(
            r#"{{"agent_id":"{}","media":"x"}}"#,
            "ab".repeat(32)
        ))
        .is_err());
    }

    // WHY: a refused outbound call tells the caller which gate refused it
    // with a stable machine-readable `reason`.
    #[tokio::test]
    async fn refusal_response_shape() {
        let resp = refusal_response(CallRefusal::Untrusted);
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["ok"], false);
        assert_eq!(v["reason"], "untrusted");
        assert!(v["error"].is_string());
    }

    #[test]
    fn call_errors_map_to_statuses() {
        assert_eq!(
            call_error_response(&CallError::NotFound).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call_error_response(&CallError::InvalidState(crate::calls::CallState::Ended)).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            call_error_response(&CallError::TooManyCalls).status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
