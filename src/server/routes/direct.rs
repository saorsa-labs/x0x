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
    agent_id: String,
    /// Base64-encoded payload.
    payload: String,
    /// Prefer the raw-QUIC path when a live direct connection exists.
    #[serde(default)]
    prefer_raw_quic_if_connected: bool,
    /// Optional raw-QUIC receive-pipeline ACK timeout for the message itself.
    #[serde(default)]
    raw_quic_receive_ack_ms: Option<u64>,
    /// If true, do not fall back to gossip-inbox after a preferred raw-QUIC
    /// failure.
    #[serde(default)]
    stop_fallback_on_raw_error: bool,
    /// If true, require gossip-inbox delivery and reject recipients without a
    /// gossip DM capability.
    #[serde(default)]
    require_gossip: bool,
    /// If set, override whether gossip-inbox sends wait for the recipient's
    /// inbox ACK before returning success. When omitted, the daemon default is
    /// used.
    #[serde(default)]
    require_gossip_ack: Option<bool>,
    /// Optional opt-in: after the DM path accepts the message, probe the
    /// recipient's ant-quic receive pipeline for liveness with this timeout.
    /// This does not force the message itself onto raw-QUIC receive-ACK.
    #[serde(default)]
    require_ack_ms: Option<u64>,
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

    let mut send_config = direct_message_send_config();
    send_config.prefer_raw_quic_if_connected = req.prefer_raw_quic_if_connected;
    send_config.stop_fallback_on_raw_error = req.stop_fallback_on_raw_error;
    send_config.require_gossip = req.require_gossip;
    if let Some(require_gossip_ack) = req.require_gossip_ack {
        send_config.require_gossip_ack = require_gossip_ack;
    }
    if let Some(raw_ack_ms) = req.raw_quic_receive_ack_ms {
        send_config.raw_quic_receive_ack_timeout = Some(std::time::Duration::from_millis(
            raw_ack_ms.clamp(100, 30_000),
        ));
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
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "path": path_str,
                    "retries_used": receipt.retries_used,
                    "request_id": hex::encode(receipt.request_id),
                    "require_ack": ack_result,
                })),
            )
        }
        Err(e) => {
            let (status, err_kind) = match &e {
                x0x::dm::DmError::RecipientRejected { .. } => {
                    (StatusCode::FORBIDDEN, "recipient_rejected")
                }
                x0x::dm::DmError::RecipientKeyUnavailable(_) => {
                    (StatusCode::NOT_FOUND, "recipient_key_unavailable")
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
                x0x::dm::DmError::EnvelopeConstruction(_) => {
                    (StatusCode::BAD_REQUEST, "envelope_construction")
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
            (
                status,
                Json(serde_json::json!({
                    "ok": false,
                    "error": err_kind,
                    "detail": e.to_string(),
                })),
            )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_message_send_config_requires_gossip_ack_by_default() {
        let config = direct_message_send_config();
        assert!(config.require_gossip_ack);
        // Raw-QUIC fallback must be loss-detecting (receive-pipeline ACK), or
        // a send into a superseded connection reports Ok, the retry never
        // fires, and the recipient's app never sees the message.
        assert_eq!(
            config.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );
    }

    // ── ADR-0016 R2: REST pre-check (exact §3 string + status code) ─────
}
