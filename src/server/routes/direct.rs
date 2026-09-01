//! Route handlers (`category: "direct"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::state::AppState;
use super::super::{
    api_error, decode_base64_payload, forbidden, parse_agent_id_hex, parse_machine_id_hex,
};
use crate as x0x;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use x0x::contacts::TrustLevel;

pub(in crate::server) fn direct_message_send_config() -> x0x::dm::DmSendConfig {
    // Generic daemon/UI DMs should only return success after the inbox path
    // observes the recipient ACK. Callers that intentionally want
    // fire-and-forget gossip can pass `require_gossip_ack: false`.
    //
    // The raw-QUIC fallback (taken whenever the recipient's gossip-inbox
    // capability advert has not converged yet — always the case in the first
    // seconds after boot) must use ant-quic's receive-pipeline ACK. A
    // fire-and-forget raw send into a connection that is being superseded
    // reports Ok while the bytes are lost, the retry machinery never fires,
    // and the recipient's app never sees the message (the dogfood
    // group_join / hop-DM 25s-timeout black hole).
    x0x::dm::DmSendConfig {
        timeout_per_attempt: Duration::from_secs(8),
        prefer_raw_quic_if_connected: true,
        raw_quic_receive_ack_timeout: Some(Duration::from_secs(8)),
        ..x0x::dm::DmSendConfig::default()
    }
}

/// POST /agents/connect request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct ConnectAgentRequest {
    /// Agent ID as 64-character hex string.
    agent_id: String,
}

/// POST /machines/connect request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct ConnectMachineRequest {
    /// Machine ID as 64-character hex string.
    machine_id: String,
}

/// POST /direct/send request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct DirectSendRequest {
    /// Target agent ID as 64-character hex string.
    pub(in crate::server) agent_id: String,
    /// Base64-encoded payload.
    pub(in crate::server) payload: String,
    /// Prefer the raw-QUIC path when a live direct connection exists.
    ///
    /// Ignored by a durable send: raw QUIC yields a transport receipt, which
    /// can never certify the recipient's durable commit (see
    /// `require_durable_app_ack`).
    #[serde(default)]
    pub(in crate::server) prefer_raw_quic_if_connected: Option<bool>,
    /// Optional raw-QUIC receive-pipeline ACK timeout for the message itself.
    #[serde(default)]
    pub(in crate::server) raw_quic_receive_ack_ms: Option<u64>,
    /// If true, do not fall back to gossip-inbox after a preferred raw-QUIC
    /// failure.
    #[serde(default)]
    pub(in crate::server) stop_fallback_on_raw_error: bool,
    /// If true, require gossip-inbox delivery and reject recipients without a
    /// gossip DM capability.
    #[serde(default)]
    pub(in crate::server) require_gossip: bool,
    /// **Removed** (ADR 0030 §4). Setting this field in any form is a 400.
    ///
    /// Typed as a raw value rather than `Option<bool>` deliberately: the
    /// contract is "this field is gone", so `"require_gossip_ack": "maybe"`
    /// must answer the same documented 400 as `false` does, not an opaque
    /// deserialization rejection from the JSON extractor.
    #[serde(default)]
    pub(in crate::server) require_gossip_ack: Option<serde_json::Value>,
    /// Optional opt-in: after the DM path accepts the message, probe the
    /// recipient's ant-quic receive pipeline for liveness with this timeout.
    /// This does not force the message itself onto raw-QUIC receive-ACK.
    #[serde(default)]
    pub(in crate::server) require_ack_ms: Option<u64>,
    /// ADR 0030 §4 opt-out. This product surface is durable-by-default:
    /// omitting the field selects `true`, so `ok: true` means the recipient
    /// durably committed the message and completed local dispatch. Pass
    /// `false` for v1 semantics (`ok: true` means "accepted for delivery"),
    /// which is what a caller does when reaching a peer that has not upgraded
    /// matters more than the stronger receipt.
    #[serde(default)]
    pub(in crate::server) require_durable_app_ack: Option<bool>,
    /// Caller-supplied idempotency key for this logical send (ADR 0030 §4).
    ///
    /// 1–128 chars of `[a-z0-9]`, `-`, `_`, `.`, `:`. Resending the same token
    /// to the same recipient is *the same request*: the recipient re-ACKs the
    /// original commit instead of storing a second copy. Reusing it for
    /// different bytes is a 409 `idempotency_conflict`.
    #[serde(default)]
    pub(in crate::server) logical_id: Option<String>,
}

/// A request the route refuses before any send is attempted, carrying the
/// exact wire contract (`error` code + `detail`) the caller sees.
#[derive(Debug)]
struct DirectSendRequestRejection {
    status: StatusCode,
    code: &'static str,
    detail: String,
}

impl DirectSendRequestRejection {
    fn into_response(self) -> (StatusCode, Json<serde_json::Value>) {
        (
            self.status,
            Json(serde_json::json!({
                "ok": false,
                "error": self.code,
                "detail": self.detail,
            })),
        )
    }
}

fn direct_send_config_for_request(
    req: &DirectSendRequest,
    self_agent_id: x0x::identity::AgentId,
    recipient: x0x::identity::AgentId,
) -> Result<x0x::dm::DmSendConfig, DirectSendRequestRejection> {
    // ADR 0030 §4: `require_gossip_ack` is removed from the product surface,
    // and removal is announced, not silent. Accepting it as a no-op would let
    // a caller keep believing it selected fire-and-forget while every send
    // blocked on an ACK — the exact silent-degradation class ADR 0025 forbids.
    if req.require_gossip_ack.is_some() {
        return Err(DirectSendRequestRejection {
            status: StatusCode::BAD_REQUEST,
            code: "require_gossip_ack_removed",
            detail: "require_gossip_ack was removed in ADR 0030 §4; use \
                     require_durable_app_ack to choose receipt semantics"
                .to_string(),
        });
    }

    let mut config = direct_message_send_config();
    if let Some(prefer_raw_quic_if_connected) = req.prefer_raw_quic_if_connected {
        config.prefer_raw_quic_if_connected = prefer_raw_quic_if_connected;
    }
    config.stop_fallback_on_raw_error = req.stop_fallback_on_raw_error;
    config.require_gossip = req.require_gossip;
    // ADR 0030 §4 product tier: durable unless the caller opts out.
    config.require_durable_app_ack = req.require_durable_app_ack.unwrap_or(true);
    if let Some(raw_ack_ms) = req.raw_quic_receive_ack_ms {
        config.raw_quic_receive_ack_timeout = Some(std::time::Duration::from_millis(
            raw_ack_ms.clamp(100, 30_000),
        ));
    }
    if let Some(raw_logical_id) = &req.logical_id {
        let logical_id = x0x::dm::DmLogicalId::parse(raw_logical_id).map_err(|detail| {
            DirectSendRequestRejection {
                status: StatusCode::BAD_REQUEST,
                code: "invalid_logical_id",
                detail,
            }
        })?;
        // `logical_id` only means something under durable semantics: the
        // recipient's binding and durable-history checks are what recognise a
        // retry and answer `idempotency_conflict`. A v1 send carries the
        // derived id on the wire but nothing on the receiver consults it, so
        // accepting the combination would hand back an idempotency guarantee
        // that does not exist. Refuse instead of documenting a silent no-op —
        // a caller who asked for at-least-once retry identity and got
        // fire-and-forget has no way to notice.
        if !config.require_durable_app_ack {
            return Err(DirectSendRequestRejection {
                status: StatusCode::BAD_REQUEST,
                code: "logical_id_requires_durable_ack",
                detail: "logical_id has no effect without durable delivery; \
                         remove require_durable_app_ack: false or drop logical_id"
                    .to_string(),
            });
        }
        config.logical_request_id = Some(logical_id.request_id(self_agent_id, recipient));
    }
    Ok(config)
}

/// POST /agents/connect — connect to a discovered agent.
pub(in crate::server) async fn connect_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectAgentRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    // Apply a 60-second overall timeout to prevent indefinite hangs when
    // the agent has multiple unreachable addresses (each with its own 30s
    // QUIC timeout).
    let connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        state.agent.connect_to_agent(&agent_id),
    )
    .await;

    match connect_result {
        Ok(Ok(outcome)) => {
            let (outcome_str, addr) = match outcome {
                x0x::connectivity::ConnectOutcome::Direct(a) => ("Direct", Some(a.to_string())),
                x0x::connectivity::ConnectOutcome::Coordinated(a) => {
                    ("Coordinated", Some(a.to_string()))
                }
                x0x::connectivity::ConnectOutcome::AlreadyConnected => ("AlreadyConnected", None),
                x0x::connectivity::ConnectOutcome::Unreachable => ("Unreachable", None),
                x0x::connectivity::ConnectOutcome::NotFound => ("NotFound", None),
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "outcome": outcome_str,
                    "addr": addr
                })),
            )
        }
        Ok(Err(e)) => {
            tracing::error!("connect_agent failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "connection failed")
        }
        Err(_elapsed) => {
            tracing::warn!(
                "connect_agent timed out after 60s for agent {}",
                req.agent_id
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "outcome": "Unreachable",
                    "addr": null
                })),
            )
        }
    }
}

/// POST /machines/connect — connect to a discovered machine.
pub(in crate::server) async fn connect_machine(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectMachineRequest>,
) -> impl IntoResponse {
    let machine_id = match parse_machine_id_hex(&req.machine_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    let connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        state.agent.connect_to_machine(&machine_id),
    )
    .await;

    match connect_result {
        Ok(Ok(outcome)) => {
            let (outcome_str, addr) = match outcome {
                x0x::connectivity::ConnectOutcome::Direct(a) => ("Direct", Some(a.to_string())),
                x0x::connectivity::ConnectOutcome::Coordinated(a) => {
                    ("Coordinated", Some(a.to_string()))
                }
                x0x::connectivity::ConnectOutcome::AlreadyConnected => ("AlreadyConnected", None),
                x0x::connectivity::ConnectOutcome::Unreachable => ("Unreachable", None),
                x0x::connectivity::ConnectOutcome::NotFound => ("NotFound", None),
            };
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "outcome": outcome_str,
                    "addr": addr
                })),
            )
        }
        Ok(Err(e)) => {
            tracing::error!("connect_machine failed: {e}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "connection failed")
        }
        Err(_elapsed) => {
            tracing::warn!(
                "connect_machine timed out after 60s for machine {}",
                req.machine_id
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "outcome": "Unreachable",
                    "addr": null
                })),
            )
        }
    }
}

/// POST /direct/send — send a direct message to a connected agent.
pub(in crate::server) async fn direct_send(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
    Json(req): Json<DirectSendRequest>,
) -> impl IntoResponse {
    let agent_id = match parse_agent_id_hex(&req.agent_id) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": e })),
            );
        }
    };

    // Request-shape validation precedes trust and payload handling: a removed
    // or malformed field is refused unconditionally, so a caller debugging the
    // 400 never has to wonder whether trust state changed the answer.
    let send_config = match direct_send_config_for_request(&req, state.agent.agent_id(), agent_id) {
        Ok(config) => config,
        Err(rejection) => return rejection.into_response(),
    };

    // Check trust level before sending — reject blocked agents
    {
        let contacts = state.contacts.read().await;
        if let Some(contact) = contacts.get(&agent_id) {
            if contact.trust_level == TrustLevel::Blocked {
                return forbidden("agent is blocked");
            }
        }
    }

    let payload = match decode_base64_payload(&req.payload) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // Issue #446 (review round 2): exec frames ride DMs behind the
    // reserved `x0x-exec-v1\0` prefix and the receiver routes them
    // straight into the exec service. Crafting that prefix through this
    // generic egress would bypass the durable-owner gate on
    // /exec/run|cancel — so reserved exec payloads require the durable
    // owner HERE too. The legitimate exec client path
    // (`ExecService::send_frame`) calls the Agent API directly and is
    // unaffected.
    if payload.starts_with(x0x::exec::EXEC_DM_PREFIX) && !actor.is_durable_owner() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "reserved exec payloads via /direct/send require the durable API token (not a session token)"
            })),
        );
    }

    match state
        .agent
        .send_direct_with_config(&agent_id, payload, send_config)
        .await
    {
        Ok(receipt) => {
            let path_str = match receipt.path {
                x0x::dm::DmPath::Loopback => "loopback",
                x0x::dm::DmPath::GossipInbox => "gossip_inbox",
                x0x::dm::DmPath::RawQuic => "raw_quic",
                x0x::dm::DmPath::RawQuicAcked => "raw_quic_acked",
                x0x::dm::DmPath::Relayed { .. } => "relayed",
            };
            tracing::debug!(
                target: "dm.trace",
                stage = "accepted_at_api",
                request_id = %hex::encode(receipt.request_id),
                recipient = %hex::encode(agent_id.as_bytes()),
                path = path_str,
                retries_used = receipt.retries_used,
            );
            // Optional post-send liveness confirmation via ant-quic's
            // `probe_peer` primitive. Proves the peer's receive pipeline is
            // alive; it does NOT prove this specific message was delivered
            // (the DM envelope may have been re-broadcast through the caps
            // topic even when raw_quic was the chosen path).
            let ack_result = if let Some(ack_ms) = req.require_ack_ms {
                let ack_timeout = std::time::Duration::from_millis(ack_ms.clamp(100, 30_000));
                if let Some(network) = state.agent.network() {
                    // Resolve AgentId → MachineId via discovery cache, then
                    // reinterpret the 32 bytes as an ant_quic PeerId (they
                    // are the same hash by construction — see CLAUDE.md).
                    let discovered = state.agent.discovered_agent(agent_id).await.ok().flatten();
                    if let Some(rec) = discovered {
                        let peer_id = ant_quic::PeerId(rec.machine_id.0);
                        match network.probe_peer(peer_id, ack_timeout).await {
                            Some(Ok(rtt)) => Some(serde_json::json!({
                                "ok": true,
                                "rtt_ms": rtt.as_millis() as u64,
                            })),
                            Some(Err(e)) => Some(serde_json::json!({
                                "ok": false,
                                "error": format!("probe failed: {e}"),
                            })),
                            None => Some(serde_json::json!({
                                "ok": false,
                                "error": "network node not running",
                            })),
                        }
                    } else {
                        Some(serde_json::json!({
                            "ok": false,
                            "error": "agent not in discovery cache (peer_id unknown)",
                        }))
                    }
                } else {
                    Some(serde_json::json!({
                        "ok": false,
                        "error": "network not initialized",
                    }))
                }
            } else {
                None
            };
            let snap = state.agent.direct_messaging().diagnostics_snapshot();
            let mut body = serde_json::json!({
                "ok": true,
                "path": path_str,
                "retries_used": receipt.retries_used,
                "request_id": hex::encode(receipt.request_id),
                "require_ack": ack_result,
            });
            attach_recipient_ack_diagnostics(
                &mut body,
                snap.last_ack_publish_ms,
                snap.stats.ack_publish_route_failed,
            );
            (StatusCode::OK, Json(body))
        }
        Err(e) => {
            let (status, err_kind) = match &e {
                x0x::dm::DmError::RecipientRejected { .. } => {
                    (StatusCode::FORBIDDEN, "recipient_rejected")
                }
                x0x::dm::DmError::RecipientKeyUnavailable(_) => {
                    (StatusCode::NOT_FOUND, "recipient_key_unavailable")
                }
                // Issue #188: the cached capability advert / contact card is
                // not converged (or corrupt) — transient, safe to retry. 409,
                // NOT 400: the request itself was well-formed.
                x0x::dm::DmError::RecipientKeyInvalid(_) => {
                    (StatusCode::CONFLICT, "recipient_key_invalid")
                }
                // ADR 0030 §2: the caller demanded durable application-ACK
                // semantics and the recipient has no current v2 capability
                // advert. 409 rather than 400 — the request was well-formed,
                // the peer state is not what it requires — and never a silent
                // downgrade. Callers retry, surface "peer needs upgrade", or
                // resend with `require_durable_app_ack = false`.
                x0x::dm::DmError::AckSemanticsUnavailable(_) => {
                    (StatusCode::CONFLICT, "recipient_ack_semantics_unavailable")
                }
                // ADR 0030 §1: the recipient holds this `logical_id` bound to
                // different bytes. 409 like the line above, but the caller's
                // repair is the opposite — not "retry / upgrade the peer" but
                // "you reused an idempotency key; pick a new one or resend the
                // original bytes". Retrying this one is guaranteed to fail.
                x0x::dm::DmError::IdempotencyConflict(_) => {
                    (StatusCode::CONFLICT, "idempotency_conflict")
                }
                x0x::dm::DmError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
                x0x::dm::DmError::PeerLikelyOffline { .. } => {
                    (StatusCode::BAD_GATEWAY, "peer_likely_offline")
                }
                x0x::dm::DmError::PeerDisconnected { .. } => {
                    (StatusCode::BAD_GATEWAY, "peer_disconnected")
                }
                x0x::dm::DmError::ReceiverBackpressured { .. } => {
                    (StatusCode::SERVICE_UNAVAILABLE, "receiver_backpressured")
                }
                x0x::dm::DmError::LocalGossipUnavailable(_) => {
                    (StatusCode::SERVICE_UNAVAILABLE, "local_gossip_unavailable")
                }
                // Local envelope build/crypto failure (signing, AEAD, KEM
                // encap, serialization). A well-formed client request cannot
                // cause this — it is a server fault, never a 400 (issue #188).
                x0x::dm::DmError::EnvelopeConstruction(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "envelope_construction")
                }
                x0x::dm::DmError::PayloadTooLarge { .. } => {
                    (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
                }
                x0x::dm::DmError::NoConnectivity(_) => {
                    (StatusCode::SERVICE_UNAVAILABLE, "no_connectivity")
                }
                x0x::dm::DmError::PublishFailed(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "publish_failed")
                }
                x0x::dm::DmError::NoRelayCandidate => {
                    (StatusCode::SERVICE_UNAVAILABLE, "no_relay_candidate")
                }
                x0x::dm::DmError::RelayBuildFailed(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "relay_build_failed")
                }
            };
            tracing::error!("direct_send failed ({err_kind}): {e}");
            let snap = state.agent.direct_messaging().diagnostics_snapshot();
            let timeout_stages = matches!(e, x0x::dm::DmError::Timeout { .. })
                .then_some(snap.last_durable_send)
                .flatten();
            let mut body = dm_error_body(err_kind, &e, timeout_stages);
            if matches!(e, x0x::dm::DmError::Timeout { .. }) {
                attach_recipient_ack_diagnostics(
                    &mut body,
                    snap.last_ack_publish_ms,
                    snap.stats.ack_publish_route_failed,
                );
            }
            (status, Json(body))
        }
    }
}

/// GET /direct/connections — list connected agents.
pub(in crate::server) async fn direct_connections(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let connected = state.agent.connected_agents().await;
    let dm = state.agent.direct_messaging();

    let mut entries = Vec::new();
    for agent_id in &connected {
        let machine_id = dm
            .get_machine_id(agent_id)
            .await
            .map(|m| hex::encode(m.as_bytes()));
        entries.push(serde_json::json!({
            "agent_id": hex::encode(agent_id.as_bytes()),
            "machine_id": machine_id
        }));
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "connections": entries })),
    )
}

// ---------------------------------------------------------------------------
// MLS group encryption handlers
//
// NOTE: Groups are persisted to <data_dir>/mls_groups.bin on every
// mutation (create, add/remove member). Loaded on startup.
//
// NOTE: Group operations have no ownership model — any caller on the local
// socket can modify any group. This is acceptable because x0xd listens on
// localhost only, so all callers are implicitly the local agent.
// ---------------------------------------------------------------------------

/// Build the `/direct/send` error JSON. Timeout 504s also export the #336
/// phase-1 stage timers so a slow send names which of the three stages
/// consumed the budget. Status and `error`/`detail` stay unchanged.
fn dm_error_body(
    err_kind: &str,
    e: &x0x::dm::DmError,
    timeout_stages: Option<x0x::dm::DurableSendStages>,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "ok": false,
        "error": err_kind,
        "detail": e.to_string(),
    });
    if let Some(stages) = timeout_stages {
        body["strict_gate_ms"] = serde_json::json!(stages.strict_gate_ms);
        body["publish_ms"] = serde_json::json!(stages.publish_ms);
        body["ack_wait_ms"] = serde_json::json!(stages.ack_wait_ms);
        body["elapsed_ms"] = serde_json::json!(stages.elapsed_ms);
        body["budget_stage"] = serde_json::json!(stages.budget_stage());
    }
    body
}

/// C5c: recipient ACK-publish diagnostics the Tester captures on every
/// durable 200 and 504. `last_ack_publish_ms` is null until a v2 ACK has
/// been published on this daemon.
fn attach_recipient_ack_diagnostics(
    body: &mut serde_json::Value,
    last_ack_publish_ms: Option<u64>,
    ack_publish_route_failed: u64,
) {
    body["last_ack_publish_ms"] = serde_json::json!(last_ack_publish_ms);
    body["ack_publish_route_failed"] = serde_json::json!(ack_publish_route_failed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_message_send_config_prefers_receive_acked_raw_quic() {
        let config = direct_message_send_config();
        assert!(config.require_gossip_ack);
        assert!(config.prefer_raw_quic_if_connected);
        // Raw-QUIC preference must be loss-detecting (receive-pipeline ACK), or
        // a send into a superseded connection reports Ok, the retry never
        // fires, and the recipient's app never sees the message.
        assert_eq!(
            config.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );
    }

    fn test_agent_id(byte: u8) -> x0x::identity::AgentId {
        x0x::identity::AgentId([byte; 32])
    }

    fn parse_request(value: serde_json::Value) -> DirectSendRequest {
        serde_json::from_value(value).expect("direct-send request should deserialize")
    }

    fn config_for(value: serde_json::Value) -> Result<x0x::dm::DmSendConfig, StatusCode> {
        direct_send_config_for_request(&parse_request(value), test_agent_id(1), test_agent_id(2))
            .map_err(|rejection| rejection.status)
    }

    fn config_ok(value: serde_json::Value) -> x0x::dm::DmSendConfig {
        config_for(value).expect("request should be accepted")
    }

    #[test]
    fn direct_send_request_preserves_raw_quic_default_unless_explicitly_overridden() {
        assert!(
            config_ok(serde_json::json!({ "agent_id": "00".repeat(32), "payload": "" }))
                .prefer_raw_quic_if_connected
        );
        assert!(
            !config_ok(serde_json::json!({
                "agent_id": "00".repeat(32),
                "payload": "",
                "prefer_raw_quic_if_connected": false
            }))
            .prefer_raw_quic_if_connected
        );
    }

    /// ADR 0030 §4: this product surface promises a durable receipt unless the
    /// caller says otherwise. The whole bug class this ADR exists to kill is a
    /// product believing `ok: true` meant "committed" when it meant "enqueued";
    /// defaulting to `false` here would restore it while the docs claimed
    /// otherwise.
    #[test]
    fn product_rest_sends_are_durable_unless_the_caller_opts_out() {
        assert!(
            config_ok(serde_json::json!({ "agent_id": "00".repeat(32), "payload": "" }))
                .require_durable_app_ack,
            "omitting require_durable_app_ack must select the product default (true)"
        );
        assert!(
            !config_ok(serde_json::json!({
                "agent_id": "00".repeat(32),
                "payload": "",
                "require_durable_app_ack": false
            }))
            .require_durable_app_ack,
            "an explicit false is the documented opt-out and must reach the config"
        );
    }

    /// ADR 0030 §4 classifies WS and daemon control-plane sends as the internal
    /// tier. They share `direct_message_send_config` with this route, so the
    /// product default must live in the request-scoped builder — flipping it in
    /// the shared helper would silently make every welcome blob and TreeKEM
    /// message a strict send, which v0.37.0 already showed causes livelock.
    #[test]
    fn the_shared_internal_send_config_stays_v1() {
        assert!(!direct_message_send_config().require_durable_app_ack);
    }

    /// ADR 0030 §4 requires the removal of `require_gossip_ack` to be
    /// *announced*. Accepting it as a no-op is the failure mode the ADR names
    /// explicitly: a caller asking for fire-and-forget would get a blocking
    /// durable send and no signal that its request was reinterpreted.
    #[test]
    fn require_gossip_ack_is_rejected_in_any_form_not_silently_accepted() {
        for value in [
            serde_json::json!(false),
            serde_json::json!(true),
            serde_json::json!("maybe"),
        ] {
            let rejection = direct_send_config_for_request(
                &parse_request(serde_json::json!({
                    "agent_id": "00".repeat(32),
                    "payload": "",
                    "require_gossip_ack": value
                })),
                test_agent_id(1),
                test_agent_id(2),
            )
            .expect_err("setting the removed field must be refused");
            assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
            assert_eq!(rejection.code, "require_gossip_ack_removed");
        }

        assert!(
            config_for(serde_json::json!({ "agent_id": "00".repeat(32), "payload": "" })).is_ok(),
            "omitting the field is the correct way to send and must stay accepted"
        );
        // An explicit JSON null asks for nothing, exactly like omission, and
        // serde treats it that way for every other optional field on this
        // body. Rejecting it would punish clients that serialize their whole
        // struct with nulls rather than clients that still want the old
        // behaviour.
        assert!(config_for(serde_json::json!({
            "agent_id": "00".repeat(32),
            "payload": "",
            "require_gossip_ack": null
        }))
        .is_ok());
    }

    /// The point of `logical_id` is that a retry — including one issued by a
    /// different process after a restart — resolves to the *same* wire request
    /// id, so the recipient re-ACKs rather than storing a second copy. A
    /// derivation that mixed in time, randomness, or payload bytes would look
    /// fine in a single-shot test and silently deliver duplicates in the field.
    #[test]
    fn logical_id_derives_a_stable_request_id_bound_to_the_directed_pair() {
        let request = |logical_id: &str, payload: &str| {
            parse_request(serde_json::json!({
                "agent_id": "00".repeat(32),
                "payload": payload,
                "logical_id": logical_id
            }))
        };
        let derive = |logical_id: &str, payload: &str, recipient: u8| {
            direct_send_config_for_request(
                &request(logical_id, payload),
                test_agent_id(1),
                test_agent_id(recipient),
            )
            .expect("valid logical_id should be accepted")
            .logical_request_id
            .expect("a logical_id must populate logical_request_id")
        };

        let first = derive("order-42", "", 2);
        assert_eq!(
            first,
            derive("order-42", "aGVsbG8=", 2),
            "the same token to the same peer is one logical request whatever the bytes"
        );
        assert_ne!(
            first,
            derive("order-43", "", 2),
            "distinct tokens must not collide"
        );
        assert_ne!(
            first,
            derive("order-42", "", 3),
            "one token fanned out to two peers must not share a sender-side ACK waiter"
        );

        assert!(
            config_ok(serde_json::json!({ "agent_id": "00".repeat(32), "payload": "" }))
                .logical_request_id
                .is_none(),
            "omitting logical_id must keep the fresh-random-id behaviour"
        );
    }

    /// ADR 0030 slice 4 review: `logical_id` is only honoured by the durable
    /// receiver path, so pairing it with the opt-out would hand back an
    /// at-least-once retry identity that nothing enforces. Refused rather than
    /// documented as a no-op — a caller who asked for idempotency and silently
    /// got fire-and-forget has no way to discover it until duplicates appear.
    #[test]
    fn a_logical_id_without_durable_delivery_is_refused_not_ignored() {
        let rejection = direct_send_config_for_request(
            &parse_request(serde_json::json!({
                "agent_id": "00".repeat(32),
                "payload": "",
                "logical_id": "order-42",
                "require_durable_app_ack": false
            })),
            test_agent_id(1),
            test_agent_id(2),
        )
        .expect_err("logical_id with the durable opt-out must be refused");
        assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
        assert_eq!(rejection.code, "logical_id_requires_durable_ack");

        // Each half alone stays valid — the refusal is about the combination.
        assert!(config_for(serde_json::json!({
            "agent_id": "00".repeat(32),
            "payload": "",
            "logical_id": "order-42"
        }))
        .is_ok());
        assert!(config_for(serde_json::json!({
            "agent_id": "00".repeat(32),
            "payload": "",
            "require_durable_app_ack": false
        }))
        .is_ok());
    }

    /// A rejected token must not reach the send path at all: silently dropping
    /// an unusable `logical_id` would hand the caller a fresh random id and the
    /// at-least-once retry identity they asked for would not exist.
    #[test]
    fn a_malformed_logical_id_is_refused_rather_than_ignored() {
        for bad in ["", "Order-42", "order 42", "order/42", &"a".repeat(129)] {
            let rejection = direct_send_config_for_request(
                &parse_request(serde_json::json!({
                    "agent_id": "00".repeat(32),
                    "payload": "",
                    "logical_id": bad
                })),
                test_agent_id(1),
                test_agent_id(2),
            )
            .err()
            .unwrap_or_else(|| panic!("logical_id {bad:?} must be refused"));
            assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
            assert_eq!(rejection.code, "invalid_logical_id");
        }
        assert!(config_for(serde_json::json!({
            "agent_id": "00".repeat(32),
            "payload": "",
            "logical_id": &"a".repeat(128)
        }))
        .is_ok());
    }

    /// #336 phase 1: a timeout 504 must keep status/`error`/`detail` and
    /// name which of the three stages ate the budget.
    #[test]
    fn timeout_504_body_exports_stage_timers_without_changing_detail() {
        let stages = x0x::dm::DurableSendStages {
            strict_gate_ms: 12_000,
            publish_ms: 500,
            ack_wait_ms: 4_500,
            elapsed_ms: 17_000,
        };
        let err = x0x::dm::DmError::Timeout {
            retries: 1,
            elapsed: Duration::from_secs(16),
        };
        let mut body = dm_error_body("timeout", &err, Some(stages));
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"], "timeout");
        assert_eq!(
            body["detail"], "timed out after 1 retries over 16s",
            "detail must stay the existing Display contract"
        );
        assert_eq!(body["strict_gate_ms"], 12_000);
        assert_eq!(body["publish_ms"], 500);
        assert_eq!(body["ack_wait_ms"], 4_500);
        assert_eq!(body["elapsed_ms"], 17_000);
        assert_eq!(body["budget_stage"], "strict_gate_ms");
        attach_recipient_ack_diagnostics(&mut body, Some(12), 3);
        assert_eq!(body["last_ack_publish_ms"], 12);
        assert_eq!(body["ack_publish_route_failed"], 3);

        let bare = x0x::dm::DmError::Timeout {
            retries: 1,
            elapsed: Duration::from_secs(16),
        };
        let bare_body = dm_error_body("timeout", &bare, None);
        assert!(bare_body.get("strict_gate_ms").is_none());
        assert_eq!(bare_body["error"], "timeout");
    }

    #[test]
    fn c5c_ack_diagnostics_are_present_on_200_and_504_bodies() {
        let mut ok = serde_json::json!({ "ok": true, "path": "gossip_inbox" });
        attach_recipient_ack_diagnostics(&mut ok, None, 0);
        assert_eq!(ok["last_ack_publish_ms"], serde_json::Value::Null);
        assert_eq!(ok["ack_publish_route_failed"], 0);

        let err = x0x::dm::DmError::Timeout {
            retries: 1,
            elapsed: Duration::from_secs(16),
        };
        let mut timeout = dm_error_body("timeout", &err, None);
        attach_recipient_ack_diagnostics(&mut timeout, Some(7), 1);
        assert_eq!(timeout["last_ack_publish_ms"], 7);
        assert_eq!(timeout["ack_publish_route_failed"], 1);
        assert_eq!(timeout["error"], "timeout");
    }

    // ── ADR-0016 R2: REST pre-check (exact §3 string + status code) ─────
}
