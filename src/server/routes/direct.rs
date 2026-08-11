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
    // Internal daemon protocols retain their existing v1-compatible raw
    // transport policy. Product DMs additionally require the v2 application
    // ACK in `direct_product_send_config` below.
    x0x::dm::DmSendConfig {
        timeout_per_attempt: Duration::from_secs(8),
        prefer_raw_quic_if_connected: true,
        raw_quic_receive_ack_timeout: Some(Duration::from_secs(8)),
        ..x0x::dm::DmSendConfig::default()
    }
}

fn direct_product_send_config() -> x0x::dm::DmSendConfig {
    // Product/UI success is strict: the live path carries the signed/encrypted
    // v2 envelope over raw QUIC, but only the recipient's authenticated ACK
    // after history commit and app dispatch qualifies. The same envelope is
    // the bounded gossip fallback, so transport receive-ACK is never mistaken
    // for product delivery.
    x0x::dm::DmSendConfig {
        timeout_per_attempt: Duration::from_secs(8),
        require_gossip: false,
        require_gossip_ack: true,
        require_durable_app_ack: true,
        prefer_raw_quic_if_connected: true,
        raw_quic_receive_ack_timeout: Some(Duration::from_secs(8)),
        stop_fallback_on_raw_error: false,
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
    /// Optional canonical 64-lowercase-hex thread root.
    #[serde(default)]
    pub(in crate::server) thread_root: Option<String>,
    /// Optional canonical direct parent; requires `thread_root`.
    #[serde(default)]
    pub(in crate::server) thread_parent: Option<String>,
    /// Optional canonical idempotency key supplied by the application.
    #[serde(default)]
    pub(in crate::server) logical_id: Option<String>,
    /// Prefer the raw-QUIC path when a live direct connection exists.
    #[serde(default)]
    pub(in crate::server) prefer_raw_quic_if_connected: Option<bool>,
    /// Optional total send deadline. This bounds raw receive-pipeline ACK
    /// retries, connection repair/reissue, and any gossip fallback.
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
    /// If set, override whether gossip-inbox sends wait for the recipient's
    /// inbox ACK before returning success. When omitted, the daemon default is
    /// used.
    #[serde(default)]
    pub(in crate::server) require_gossip_ack: Option<bool>,
    /// Optional opt-in: after the DM path accepts the message, probe the
    /// recipient's ant-quic receive pipeline for liveness with this timeout.
    /// This does not force the message itself onto raw-QUIC receive-ACK.
    #[serde(default)]
    pub(in crate::server) require_ack_ms: Option<u64>,
}

fn direct_send_config_for_request(req: &DirectSendRequest) -> x0x::dm::DmSendConfig {
    let mut config = direct_product_send_config();
    if let Some(prefer_raw_quic_if_connected) = req.prefer_raw_quic_if_connected {
        config.prefer_raw_quic_if_connected = prefer_raw_quic_if_connected;
    }
    config.stop_fallback_on_raw_error = req.stop_fallback_on_raw_error;
    if req.require_gossip {
        config.require_gossip = true;
        config.prefer_raw_quic_if_connected = false;
    }
    // `require_gossip_ack: false` was a legacy publish-only escape hatch. It
    // remains accepted on the wire for compatibility but cannot weaken the
    // product endpoint's authenticated v2 completion contract.
    let _legacy_require_gossip_ack = req.require_gossip_ack;
    if let Some(raw_ack_ms) = req.raw_quic_receive_ack_ms {
        let timeout = std::time::Duration::from_millis(raw_ack_ms.clamp(100, 30_000));
        config.timeout_per_attempt = timeout;
        config.raw_quic_receive_ack_timeout = Some(timeout);
    }
    config
}

fn direct_metadata_for_request(
    req: &DirectSendRequest,
) -> Result<(Option<x0x::dm::DmThreadMeta>, Option<x0x::dm::DmLogicalId>), String> {
    let thread_meta =
        x0x::dm::DmThreadMeta::from_hex(req.thread_root.as_deref(), req.thread_parent.as_deref())?;
    let logical_id = req
        .logical_id
        .as_deref()
        .map(x0x::dm::DmLogicalId::parse)
        .transpose()?;
    Ok((thread_meta, logical_id))
}

fn direct_send_error_status(error: &x0x::dm::DmError) -> (StatusCode, &'static str) {
    match error {
        x0x::dm::DmError::RecipientRejected { .. } => (StatusCode::FORBIDDEN, "recipient_rejected"),
        x0x::dm::DmError::RecipientKeyUnavailable(_) => {
            (StatusCode::NOT_FOUND, "recipient_key_unavailable")
        }
        // Issue #188: the cached capability advert / contact card is not
        // converged (or is corrupt). This is transient and safe to retry.
        x0x::dm::DmError::RecipientKeyInvalid(_) => (StatusCode::CONFLICT, "recipient_key_invalid"),
        x0x::dm::DmError::AckSemanticsUnavailable(_) => {
            (StatusCode::CONFLICT, "recipient_ack_semantics_unavailable")
        }
        x0x::dm::DmError::HistoryCommitFailed(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "history_commit_failed")
        }
        x0x::dm::DmError::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
        x0x::dm::DmError::PeerLikelyOffline { .. } => {
            (StatusCode::BAD_GATEWAY, "peer_likely_offline")
        }
        x0x::dm::DmError::PeerDisconnected { .. } => (StatusCode::BAD_GATEWAY, "peer_disconnected"),
        x0x::dm::DmError::ReceiverBackpressured { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "receiver_backpressured")
        }
        x0x::dm::DmError::LocalGossipUnavailable(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "local_gossip_unavailable")
        }
        // Local envelope build/crypto failure (signing, AEAD, KEM encap,
        // serialization). A well-formed request cannot cause this.
        x0x::dm::DmError::EnvelopeConstruction(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "envelope_construction")
        }
        x0x::dm::DmError::PayloadTooLarge { .. } => {
            (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
        }
        x0x::dm::DmError::NoConnectivity(_) => (StatusCode::SERVICE_UNAVAILABLE, "no_connectivity"),
        x0x::dm::DmError::PublishFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "publish_failed"),
        x0x::dm::DmError::NoRelayCandidate => {
            (StatusCode::SERVICE_UNAVAILABLE, "no_relay_candidate")
        }
        x0x::dm::DmError::RelayBuildFailed(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "relay_build_failed")
        }
    }
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

    let (thread_meta, logical_id) = match direct_metadata_for_request(&req) {
        Ok(metadata) => metadata,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": error })),
            );
        }
    };

    let send_config = direct_send_config_for_request(&req);

    match state
        .agent
        .send_direct_with_config_and_thread(
            &agent_id,
            payload,
            send_config,
            thread_meta,
            logical_id,
        )
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
            let (status, err_kind) = direct_send_error_status(&e);
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
    fn direct_product_send_config_prefers_strict_bounded_raw_envelope() {
        let config = direct_product_send_config();
        assert!(config.require_gossip_ack);
        assert!(!config.require_gossip);
        assert!(config.require_durable_app_ack);
        assert!(config.prefer_raw_quic_if_connected);
        assert_eq!(
            config.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );
        assert!(!config.stop_fallback_on_raw_error);
    }

    #[test]
    fn direct_metadata_validates_thread_ancestry_and_logical_id() {
        let root = "ab".repeat(32);
        let req: DirectSendRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "11".repeat(32),
            "payload": "aGk=",
            "thread_root": root,
            "thread_parent": "cd".repeat(32),
            "logical_id": "550e8400-e29b-41d4-a716-446655440000"
        }))
        .expect("deserialize direct request");
        let (thread, logical) = direct_metadata_for_request(&req).expect("valid metadata");
        let thread = thread.expect("thread metadata");
        assert_eq!(thread.thread_root_hex(), "ab".repeat(32));
        assert_eq!(thread.thread_parent_hex(), Some("cd".repeat(32)));
        assert_eq!(
            logical.expect("logical id").as_str(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn direct_metadata_rejects_parent_without_root_and_noncanonical_ids() {
        let parent_only: DirectSendRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "11".repeat(32),
            "payload": "aGk=",
            "thread_parent": "cd".repeat(32)
        }))
        .expect("deserialize parent-only request");
        assert!(direct_metadata_for_request(&parent_only).is_err());

        let uppercase_root: DirectSendRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "11".repeat(32),
            "payload": "aGk=",
            "thread_root": "AB".repeat(32)
        }))
        .expect("deserialize uppercase request");
        assert!(direct_metadata_for_request(&uppercase_root).is_err());

        let bad_logical: DirectSendRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "11".repeat(32),
            "payload": "aGk=",
            "logical_id": "not canonical"
        }))
        .expect("deserialize bad logical request");
        assert!(direct_metadata_for_request(&bad_logical).is_err());
    }

    #[test]
    fn omitted_direct_send_request_is_raw_preferred_and_cannot_weaken_fallback_ack() {
        let omitted: DirectSendRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "00".repeat(32),
            "payload": ""
        }))
        .expect("minimal direct-send request should deserialize");
        let omitted_config = direct_send_config_for_request(&omitted);
        assert!(omitted_config.require_durable_app_ack);
        assert!(omitted_config.prefer_raw_quic_if_connected);
        assert!(omitted_config.require_gossip_ack);
        assert_eq!(
            omitted_config.raw_quic_receive_ack_timeout,
            Some(Duration::from_secs(8))
        );

        let legacy_requested: DirectSendRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "00".repeat(32),
            "payload": "",
            "prefer_raw_quic_if_connected": false,
            "raw_quic_receive_ack_ms": 375,
            "require_gossip": true,
            "require_gossip_ack": false,
            "stop_fallback_on_raw_error": true
        }))
        .expect("legacy direct-send knobs should still deserialize");
        let config = direct_send_config_for_request(&legacy_requested);
        assert!(config.require_durable_app_ack);
        assert!(config.require_gossip);
        assert!(config.require_gossip_ack);
        assert!(!config.prefer_raw_quic_if_connected);
        assert!(config.stop_fallback_on_raw_error);
        assert_eq!(
            config.raw_quic_receive_ack_timeout,
            Some(Duration::from_millis(375))
        );
    }

    #[test]
    fn direct_send_timeout_is_http_gateway_timeout() {
        let error = x0x::dm::DmError::Timeout {
            retries: 0,
            elapsed: Duration::from_millis(300),
        };
        assert_eq!(
            direct_send_error_status(&error),
            (StatusCode::GATEWAY_TIMEOUT, "timeout")
        );
    }

    // ── ADR-0016 R2: REST pre-check (exact §3 string + status code) ─────
}
