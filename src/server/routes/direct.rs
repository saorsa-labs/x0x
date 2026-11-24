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

use super::direct_outbox::{
    now_unix_ms, CancelOutcome, DirectSendObligation, DirectSendOptions, DirectSendOutbox,
    DirectSendReceipt, EnqueueOutcome, LedgerReceipt, DIRECT_SEND_MAX_HORIZON_MS,
};

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
        // #2187: the product path keeps its pre-#2187 dial for the preferred
        // raw attempt, bounded by the receive-ACK timeout below.
        dial_for_raw_quic: true,
        raw_quic_receive_ack_timeout: Some(x0x::dm::DEFAULT_RAW_QUIC_RECEIVE_ACK_TIMEOUT),
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
    /// #1109: deliver durably until this unix-ms deadline. When set, the
    /// route stores the send and answers 202 `outcome: "queued"`; a worker
    /// sends it (and holds a cold recipient) until the recipient's durable
    /// ACK, an error a retry cannot repair, or the deadline. Requires
    /// durable semantics and a `logical_id`; at most 24 h ahead.
    #[serde(default)]
    pub(in crate::server) deliver_until_ms: Option<u64>,
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

/// The request options that shape the send config. A queued send (#1109)
/// stores them, so its worker builds the config this route would build.
fn direct_send_options(req: &DirectSendRequest) -> DirectSendOptions {
    DirectSendOptions {
        prefer_raw_quic_if_connected: req.prefer_raw_quic_if_connected,
        raw_quic_receive_ack_ms: req.raw_quic_receive_ack_ms,
        stop_fallback_on_raw_error: req.stop_fallback_on_raw_error,
        require_gossip: req.require_gossip,
    }
}

/// The `/direct/send` config for `options`, before any `logical_id`.
pub(super) fn send_config_from_options(
    options: &DirectSendOptions,
    require_durable_app_ack: bool,
) -> x0x::dm::DmSendConfig {
    let mut config = direct_message_send_config();
    if let Some(prefer_raw_quic_if_connected) = options.prefer_raw_quic_if_connected {
        config.prefer_raw_quic_if_connected = prefer_raw_quic_if_connected;
    }
    config.stop_fallback_on_raw_error = options.stop_fallback_on_raw_error;
    config.require_gossip = options.require_gossip;
    config.require_durable_app_ack = require_durable_app_ack;
    if let Some(raw_ack_ms) = options.raw_quic_receive_ack_ms {
        config.raw_quic_receive_ack_timeout = Some(std::time::Duration::from_millis(
            raw_ack_ms.clamp(100, 30_000),
        ));
    }
    config
}

/// #1109: check `deliver_until_ms` against the validated config. Returns
/// the deadline and the request id derived from `logical_id`; `Ok(None)`
/// when the field is absent (the synchronous send runs as before).
fn deliver_until_for_request(
    req: &DirectSendRequest,
    config: &x0x::dm::DmSendConfig,
    now_ms: u64,
) -> Result<Option<(u64, [u8; 16])>, DirectSendRequestRejection> {
    let Some(deliver_until_ms) = req.deliver_until_ms else {
        return Ok(None);
    };
    let refuse = |code: &'static str, detail: String| DirectSendRequestRejection {
        status: StatusCode::BAD_REQUEST,
        code,
        detail,
    };
    if !config.require_durable_app_ack {
        return Err(refuse(
            "deliver_until_requires_durable",
            "deliver_until_ms needs durable delivery; remove require_durable_app_ack: false"
                .to_string(),
        ));
    }
    // `logical_request_id` is set exactly when a valid `logical_id` was given.
    let Some(request_id) = config.logical_request_id else {
        return Err(refuse(
            "deliver_until_requires_logical_id",
            "deliver_until_ms needs a logical_id: it is the key of the queued send \
             and of GET /direct/receipts/{logical_id}"
                .to_string(),
        ));
    };
    if deliver_until_ms <= now_ms {
        return Err(refuse(
            "deliver_until_passed",
            format!("deliver_until_ms {deliver_until_ms} is not after now ({now_ms})"),
        ));
    }
    if deliver_until_ms - now_ms > DIRECT_SEND_MAX_HORIZON_MS {
        return Err(refuse(
            "deliver_until_too_far",
            format!(
                "deliver_until_ms is more than {DIRECT_SEND_MAX_HORIZON_MS} ms (24 h) after now"
            ),
        ));
    }
    Ok(Some((deliver_until_ms, request_id)))
}

/// #1109: the obligation a validated queued send stores. `deadline` is
/// `(deliver_until_ms, request_id)` from [`deliver_until_for_request`].
fn queued_obligation(
    logical_id: &str,
    options: DirectSendOptions,
    recipient: x0x::identity::AgentId,
    payload: Vec<u8>,
    (deliver_until_ms, request_id): (u64, [u8; 16]),
    now_ms: u64,
) -> DirectSendObligation {
    DirectSendObligation {
        recipient: hex::encode(recipient.as_bytes()),
        logical_id: logical_id.to_string(),
        request_id: hex::encode(request_id),
        payload,
        deliver_until_ms,
        first_seen_ms: now_ms,
        retry_count: 0,
        next_retry_at_ms: 0,
        last_error: None,
        options,
    }
}

/// #1109: store `obligation` and answer 202 `outcome: "queued"` (or the
/// same 202 for a repeat of a held send). `ledger` is what the DM receipt
/// ledger knows about its request id.
async fn queue_direct_send(
    outbox: &DirectSendOutbox,
    obligation: DirectSendObligation,
    ledger: LedgerReceipt,
) -> (StatusCode, Json<serde_json::Value>) {
    if obligation.payload.len() > x0x::dm::MAX_PAYLOAD_BYTES {
        return DirectSendRequestRejection {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "payload_too_large",
            detail: format!(
                "DM payload exceeds MAX_PAYLOAD_BYTES ({} > {})",
                obligation.payload.len(),
                x0x::dm::MAX_PAYLOAD_BYTES
            ),
        }
        .into_response();
    }
    let body = serde_json::json!({
        "ok": true,
        "outcome": "queued",
        "logical_id": obligation.logical_id,
        "agent_id": obligation.recipient,
        "request_id": obligation.request_id,
        "deliver_until_ms": obligation.deliver_until_ms,
    });
    let logical_id = obligation.logical_id.clone();
    let rejection = |status, code, detail| DirectSendRequestRejection {
        status,
        code,
        detail,
    };
    let held_until = match outbox.enqueue(obligation, ledger).await {
        EnqueueOutcome::Queued => None,
        EnqueueOutcome::AlreadyQueued { deliver_until_ms } => Some(deliver_until_ms),
        EnqueueOutcome::Conflict => {
            return rejection(
                StatusCode::CONFLICT,
                "idempotency_conflict",
                format!(
                    "logical_id {logical_id} is already queued or delivered to this \
                     recipient with different bytes"
                ),
            )
            .into_response();
        }
        EnqueueOutcome::Full => {
            return rejection(
                StatusCode::TOO_MANY_REQUESTS,
                "outbox_full",
                "the durable send outbox is full for this recipient or daemon; retry later"
                    .to_string(),
            )
            .into_response();
        }
        EnqueueOutcome::NotDurable(detail) => {
            return rejection(
                StatusCode::SERVICE_UNAVAILABLE,
                "outbox_not_durable",
                format!(
                    "the send is held and may still be sent, but its durability is not \
                     confirmed (directory fsync failed): {detail}; check \
                     GET /direct/receipts/{logical_id} or cancel it"
                ),
            )
            .into_response();
        }
        EnqueueOutcome::WriteFailed(detail) => {
            return rejection(
                StatusCode::INTERNAL_SERVER_ERROR,
                "outbox_write_failed",
                detail,
            )
            .into_response();
        }
        EnqueueOutcome::InFlight => {
            return rejection(
                StatusCode::CONFLICT,
                "send_in_flight",
                format!(
                    "an attempt for logical_id {logical_id} to this recipient is in flight; \
                     retry after it ends"
                ),
            )
            .into_response();
        }
    };
    let mut body = body;
    if let Some(held_until) = held_until {
        body["deliver_until_ms"] = serde_json::json!(held_until);
    }
    (StatusCode::ACCEPTED, Json(body))
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

    // ADR 0030 §4 product tier: durable unless the caller opts out.
    let mut config = send_config_from_options(
        &direct_send_options(req),
        req.require_durable_app_ack.unwrap_or(true),
    );
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
    let durable = send_config.require_durable_app_ack;
    let now_ms = now_unix_ms();
    let deadline = match deliver_until_for_request(&req, &send_config, now_ms) {
        Ok(deadline) => deadline,
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
    // The three gui-show prefixes are signed by this daemon on
    // `POST /gui/show` only. A session bearer, a rider, and the durable
    // owner token are all refused here.
    if x0x::gui::remote::classify_prefix(&payload).is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": x0x::gui::remote::GENERIC_SEND_REFUSAL
            })),
        );
    }

    if payload.starts_with(x0x::exec::EXEC_DM_PREFIX) && !actor.is_durable_owner() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "reserved exec payloads via /direct/send require the durable API token (not a session token)"
            })),
        );
    }

    // #1109: a send with a deadline is stored and sent by the worker.
    if let Some(deadline) = deadline {
        let obligation = queued_obligation(
            req.logical_id.as_deref().unwrap_or_default(),
            direct_send_options(&req),
            agent_id,
            payload,
            deadline,
            now_ms,
        );
        let ledger = LedgerReceipt::of(&state.agent.dm_inflight_acks(), &deadline.1);
        return queue_direct_send(&state.direct_send_outbox, obligation, ledger).await;
    }

    match state
        .agent
        .send_direct_with_config_with_provenance(&agent_id, payload, send_config)
        .await
    {
        Ok((receipt, observed_ack_ingress)) => {
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
                    // are the same hash by construction — see AGENTS.md).
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
            // #461: observed ingress of the transport that actually carried
            // the winning durable ACK, when known. Optional: absent for
            // publish-only/unknown outcomes; `path` above remains the send
            // strategy.
            if let Some(ingress) = observed_ack_ingress {
                body["observed_ack_ingress"] = serde_json::json!(match ingress {
                    x0x::dm::DmAckIngress::DirectTyped => "direct_typed",
                    x0x::dm::DmAckIngress::Subscription => "subscription",
                });
            }
            attach_recipient_ack_diagnostics(
                &mut body,
                snap.last_ack_publish_ms,
                snap.stats.ack_publish_route_failed,
            );
            (StatusCode::OK, Json(body))
        }
        Err(e) => {
            let (status, err_kind) = dm_error_status_code(&e);
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
                if durable {
                    attach_ack_unknown(&mut body, req.logical_id.as_deref());
                }
            }
            (status, Json(body))
        }
    }
}

/// The HTTP status and stable error code `/direct/send` answers for a
/// send error. The #1109 worker records the same code for a failed
/// queued send.
pub(super) fn dm_error_status_code(e: &x0x::dm::DmError) -> (StatusCode, &'static str) {
    match e {
        x0x::dm::DmError::RecipientRejected { .. } => (StatusCode::FORBIDDEN, "recipient_rejected"),
        // ADR-0043 §9: the local B/P gate denied the resolved
        // (agent, machine) pairing; nothing was sent. A policy
        // refusal, not a server fault, so 403 and not 500.
        x0x::dm::DmError::RecipientPairingDenied { .. } => {
            (StatusCode::FORBIDDEN, "recipient_pairing_denied")
        }
        // ADR 0110 §3 (D70; #1597 item 4): the recipient's resolved
        // machine is revoked; that device is denied, nothing was
        // sent, and the agent keeps its seat. A policy refusal.
        x0x::dm::DmError::RecipientMachineRevoked { .. } => {
            (StatusCode::FORBIDDEN, "recipient_machine_revoked")
        }
        x0x::dm::DmError::RecipientKeyUnavailable(_) => {
            (StatusCode::NOT_FOUND, "recipient_key_unavailable")
        }
        // Issue #188: the cached capability advert / contact card is
        // not converged (or corrupt) — transient, safe to retry. 409,
        // NOT 400: the request itself was well-formed.
        x0x::dm::DmError::RecipientKeyInvalid(_) => (StatusCode::CONFLICT, "recipient_key_invalid"),
        // ADR 0030 §2: the caller demanded durable application-ACK
        // semantics and the recipient has no current v2 capability
        // advert. 409 rather than 400 — the request was well-formed,
        // the peer state is not what it requires — and never a silent
        // downgrade. Callers retry, surface "peer needs upgrade", or
        // resend with `require_durable_app_ack = false`.
        x0x::dm::DmError::RecipientUndiscovered(_) => {
            // #1091: a discovery gap, not missing key material —
            // retryable once the peer re-announces (seconds with
            // the reconnect-triggered re-announce).
            (StatusCode::SERVICE_UNAVAILABLE, "recipient_undiscovered")
        }
        x0x::dm::DmError::RecipientUpgradeRequired { .. } => {
            (StatusCode::CONFLICT, "recipient_upgrade_required")
        }
        // #1158: an obligation-carrying typed payload and no
        // current verified capability advert. Nothing was sent;
        // retry after the recipient's advert arrives.
        x0x::dm::DmError::RecipientCapabilityPending { .. } => {
            (StatusCode::CONFLICT, "recipient_capability_pending")
        }
        x0x::dm::DmError::RecipientCapabilityUnavailable { .. } => {
            (StatusCode::CONFLICT, "recipient_capability_unavailable")
        }
        x0x::dm::DmError::AckSemanticsUnavailable(_) => {
            (StatusCode::CONFLICT, "recipient_ack_semantics_unavailable")
        }
        // ADR 0030 §1: the recipient holds this `logical_id` bound to
        // different bytes. 409 like the line above, but the caller's
        // repair is the opposite — not "retry / upgrade the peer" but
        // "you reused an idempotency key; pick a new one or resend the
        // original bytes". Retrying this one is guaranteed to fail.
        x0x::dm::DmError::IdempotencyConflict(_) => (StatusCode::CONFLICT, "idempotency_conflict"),
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
        // Local envelope build/crypto failure (signing, AEAD, KEM
        // encap, serialization). A well-formed client request cannot
        // cause this — it is a server fault, never a 400 (issue #188).
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
/// #1109: a durable send that ran out of budget did not learn the outcome.
/// The recipient may hold the message; `outcome: "ack_unknown"` says so, and
/// `logical_id` (when the caller supplied one) is the key for
/// `GET /direct/receipts/{logical_id}`, which reports a late ACK.
fn attach_ack_unknown(body: &mut serde_json::Value, logical_id: Option<&str>) {
    body["outcome"] = serde_json::json!("ack_unknown");
    body["logical_id"] = serde_json::json!(logical_id);
}

/// Query string of `GET /direct/receipts/{logical_id}`.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct DirectReceiptQuery {
    /// Recipient agent id (64 hex). A logical id is scoped to one directed
    /// pair, so the recipient is part of the key.
    pub(in crate::server) agent_id: String,
}

/// #1109: one receipt lookup: the response body, its keys, and the DM
/// ledger status the body reports.
#[derive(Debug)]
struct ReceiptLookup {
    body: serde_json::Value,
    recipient: x0x::identity::AgentId,
    request_id: [u8; 16],
    ledger: LedgerReceipt,
}

/// #1109: the response body for one receipt lookup, or the refusal.
fn direct_receipt_body(
    raw_logical_id: &str,
    raw_agent_id: &str,
    self_agent_id: x0x::identity::AgentId,
    acks: &x0x::dm::InFlightAcks,
) -> Result<ReceiptLookup, DirectSendRequestRejection> {
    let logical_id = x0x::dm::DmLogicalId::parse(raw_logical_id).map_err(|detail| {
        DirectSendRequestRejection {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_logical_id",
            detail,
        }
    })?;
    let recipient =
        parse_agent_id_hex(raw_agent_id).map_err(|detail| DirectSendRequestRejection {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_agent_id",
            detail,
        })?;
    let request_id = logical_id.request_id(self_agent_id, recipient);
    let ledger = LedgerReceipt::of(acks, &request_id);
    let body = serde_json::json!({
        "ok": true,
        "logical_id": logical_id.as_str(),
        "agent_id": hex::encode(recipient.as_bytes()),
        "request_id": hex::encode(request_id),
        "status": ledger.status.as_str(),
    });
    Ok(ReceiptLookup {
        body,
        recipient,
        request_id,
        ledger,
    })
}

/// #1109: overlay the durable outbox's answer (`queued`, `expired`,
/// `failed` with `error`) on a receipt body.
fn apply_queued_receipt(body: &mut serde_json::Value, receipt: DirectSendReceipt) {
    body["status"] = serde_json::json!(receipt.status);
    if let Some(error) = receipt.error {
        body["error"] = serde_json::json!(error);
    }
    if let Some(digest) = receipt.payload_digest {
        body["payload_digest"] = serde_json::json!(hex::encode(digest));
    }
}

/// GET /direct/receipts/{logical_id}?agent_id=<hex> — #1109: what this daemon
/// knows about a durable send it made under `logical_id` to `agent_id`:
/// `delivered`, `delivered_late`, `pending` or `unknown`, and for a queued
/// send (`deliver_until_ms`) also `queued`, `expired` or `failed` (with
/// `error`). Records live for ten minutes after the send resolved or gave
/// up; a held obligation reads `queued` until it leaves the outbox, across
/// a restart.
pub(in crate::server) async fn direct_receipt(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(logical_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<DirectReceiptQuery>,
) -> impl IntoResponse {
    let acks = state.agent.dm_inflight_acks();
    match direct_receipt_body(&logical_id, &query.agent_id, state.agent.agent_id(), &acks) {
        Ok(mut lookup) => {
            let receipt = state
                .direct_send_outbox
                .receipt(&lookup.recipient, &lookup.request_id, lookup.ledger)
                .await;
            apply_queued_receipt(&mut lookup.body, receipt);
            (StatusCode::OK, Json(lookup.body))
        }
        Err(rejection) => rejection.into_response(),
    }
}

/// DELETE /direct/receipts/{logical_id}?agent_id=<hex> — #1109: cancel a
/// queued send. The held obligation is removed and its receipt reads
/// `cancelled`; 404 `not_queued` when none is held. An attempt already in
/// flight is not recalled.
pub(in crate::server) async fn direct_cancel(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(logical_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<DirectReceiptQuery>,
) -> impl IntoResponse {
    let acks = state.agent.dm_inflight_acks();
    match direct_receipt_body(&logical_id, &query.agent_id, state.agent.agent_id(), &acks) {
        Ok(lookup) => cancel_queued_send(&state.direct_send_outbox, lookup).await,
        Err(rejection) => rejection.into_response(),
    }
}

/// #1109: cancel the held obligation named by `lookup`.
async fn cancel_queued_send(
    outbox: &DirectSendOutbox,
    mut lookup: ReceiptLookup,
) -> (StatusCode, Json<serde_json::Value>) {
    match outbox.cancel(&lookup.recipient, &lookup.request_id).await {
        CancelOutcome::Cancelled => {
            lookup.body["status"] = serde_json::json!("cancelled");
            (StatusCode::OK, Json(lookup.body))
        }
        CancelOutcome::NotHeld => DirectSendRequestRejection {
            status: StatusCode::NOT_FOUND,
            code: "not_queued",
            detail: "no queued send is held under this logical_id for this agent".to_string(),
        }
        .into_response(),
        CancelOutcome::NotDurable(detail) => DirectSendRequestRejection {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "outbox_not_durable",
            detail: format!(
                "the cancel could not be recorded durably ({detail}); the send is still \
                 held and may still go out; retry the cancel"
            ),
        }
        .into_response(),
        CancelOutcome::InFlight => DirectSendRequestRejection {
            status: StatusCode::CONFLICT,
            code: "send_in_flight",
            detail: "an attempt is in flight and cannot be recalled; retry after it ends"
                .to_string(),
        }
        .into_response(),
    }
}

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
    /// N12 round 2 pin: the static production-prefix table the raw dispatch
    /// consults before the DM inbox exists must cover every prefix the
    /// inbox registers in `start_dm_inbox_when_gossip_ready` — including
    /// the server-layer bootstrap prefix, whose literal the crate-level
    /// table repeats (dm_inbox cannot import from the server layer). A
    /// future route added to the inbox must be added to the table too.
    #[test]
    fn production_typed_prefix_table_covers_every_inbox_route_prefix() {
        for prefix in [
            x0x::exec::EXEC_DM_PREFIX,
            x0x::dm_inbox::GROUP_PREDECESSOR_RELAY_DM_PREFIX,
            x0x::share_grant::SHARE_GRANT_DM_PREFIX,
            x0x::history::classify::GROUP_PUBLIC_MESSAGE_DM_PREFIX,
            x0x::history::classify::KV_STORE_DELTA_DM_PREFIX,
            crate::server::routes::public_group_bootstrap_outbox::PUBLIC_GROUP_BOOTSTRAP_DM_PREFIX,
        ] {
            let mut payload = prefix.to_vec();
            payload.extend_from_slice(b"pin");
            assert!(
                x0x::dm_inbox::recognized_production_typed_prefix(&payload),
                "the static table must recognize the production prefix {:?}",
                String::from_utf8_lossy(prefix)
            );
        }
        // And nothing else: a random ordinary payload is not a protocol frame.
        assert!(!x0x::dm_inbox::recognized_production_typed_prefix(
            b"just an ordinary DM"
        ));
    }

    use super::*;

    #[test]
    fn direct_message_send_config_prefers_receive_acked_raw_quic() {
        let config = direct_message_send_config();
        assert!(config.require_gossip_ack);
        assert!(config.prefer_raw_quic_if_connected);
        // #2187: the product path dials for its preferred raw attempt.
        assert!(config.dial_for_raw_quic);
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

    /// #1815 Greptile P2: `POST /direct/send` maps a denied (agent, machine)
    /// pairing to HTTP 403 with `ok: false` and the stable error code
    /// `recipient_pairing_denied`. Clients use this response to tell a
    /// policy refusal apart from a server fault. The lib test
    /// `send_direct_reports_a_denied_pairing_as_recipient_pairing_denied`
    /// pins the typed `DmError`; this test pins the HTTP mapping.
    #[tokio::test]
    async fn direct_send_denied_pairing_is_403_recipient_pairing_denied() {
        use base64::Engine as _;

        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("test state");
        let recipient = x0x::identity::AgentKeypair::generate().expect("recipient keygen");
        let machine = x0x::identity::MachineKeypair::generate().expect("machine keygen");
        let now = x0x::dm::now_unix_ms() / 1_000;
        state
            .agent
            .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
                self_name: None,
                cert_digest: None,
                agent_id: recipient.agent_id(),
                machine_id: machine.machine_id(),
                user_id: None,
                addresses: Vec::new(),
                announced_at: now,
                last_seen: now,
                machine_public_key: machine.public_key().as_bytes().to_vec(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                cert_not_after: None,
                agent_certificate: None,
                agent_public_key: Vec::new(),
            })
            .await;
        // Check B: retire the (recipient, machine) binding.
        assert!(state
            .agent
            .revocation_set()
            .write()
            .await
            .union_bundle_retired(&[x0x::revocation::AgentMachineBinding {
                agent: recipient.agent_id(),
                machine: machine.machine_id(),
                move_epoch: 1,
            }]));

        let response = direct_send(
            State(Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Json(DirectSendRequest {
                agent_id: hex::encode(recipient.agent_id().as_bytes()),
                payload: base64::engine::general_purpose::STANDARD.encode(b"denied"),
                prefer_raw_quic_if_connected: None,
                raw_quic_receive_ack_ms: None,
                stop_fallback_on_raw_error: false,
                require_gossip: false,
                require_gossip_ack: None,
                require_ack_ms: None,
                require_durable_app_ack: None,
                logical_id: None,
                deliver_until_ms: None,
            }),
        )
        .await
        .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("decode response body");
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
        assert_eq!(body["ok"], false, "body: {body}");
        assert_eq!(body["error"], "recipient_pairing_denied", "body: {body}");
    }

    /// #1597 item 4 (ADR 0110 §3, D70): `POST /direct/send` to an agent
    /// whose machine is revoked answers HTTP 403 with the stable error code
    /// `recipient_machine_revoked`, which names the machine revocation
    /// (a binding revocation keeps `recipient_pairing_denied`). The lib
    /// test `send_direct_reports_a_revoked_machine_as_recipient_machine_revoked`
    /// pins the typed `DmError` through the real revocation path (eviction
    /// included); this test pins only the HTTP mapping, so it inserts the
    /// record into the set directly and keeps the discovery entry.
    #[tokio::test]
    async fn direct_send_to_a_revoked_machine_is_403_recipient_machine_revoked() {
        use base64::Engine as _;

        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("test state");
        let recipient = x0x::identity::AgentKeypair::generate().expect("recipient keygen");
        let machine = x0x::identity::MachineKeypair::generate().expect("machine keygen");
        let now = x0x::dm::now_unix_ms() / 1_000;
        state
            .agent
            .insert_discovered_agent_for_testing(x0x::DiscoveredAgent {
                self_name: None,
                cert_digest: None,
                agent_id: recipient.agent_id(),
                machine_id: machine.machine_id(),
                user_id: None,
                addresses: Vec::new(),
                announced_at: now,
                last_seen: now,
                machine_public_key: machine.public_key().as_bytes().to_vec(),
                nat_type: None,
                can_receive_direct: None,
                is_relay: None,
                is_coordinator: None,
                reachable_via: Vec::new(),
                relay_candidates: Vec::new(),
                cert_not_after: None,
                agent_certificate: None,
                agent_public_key: Vec::new(),
            })
            .await;
        let record = x0x::revocation::RevocationRecord::sign(
            x0x::revocation::RevokedSubject::Machine(machine.machine_id()),
            machine.public_key(),
            machine.secret_key(),
            1_000,
            None,
        )
        .expect("sign");
        assert!(state
            .agent
            .revocation_set()
            .write()
            .await
            .verify_and_insert(record, None)
            .expect("a machine self-revocation verifies"));

        let response = direct_send(
            State(Arc::clone(&state)),
            axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner {
                durable: true,
            }),
            Json(DirectSendRequest {
                agent_id: hex::encode(recipient.agent_id().as_bytes()),
                payload: base64::engine::general_purpose::STANDARD.encode(b"revoked"),
                prefer_raw_quic_if_connected: None,
                raw_quic_receive_ack_ms: None,
                stop_fallback_on_raw_error: false,
                require_gossip: false,
                require_gossip_ack: None,
                require_ack_ms: None,
                require_durable_app_ack: None,
                logical_id: None,
                deliver_until_ms: None,
            }),
        )
        .await
        .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("decode response body");
        assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
        assert_eq!(body["ok"], false, "body: {body}");
        assert_eq!(body["error"], "recipient_machine_revoked", "body: {body}");
    }

    // ── ADR-0016 R2: REST pre-check (exact §3 string + status code) ─────

    /// #1109: a durable 504 says the outcome is unknown and carries the
    /// caller's logical id, the key for the receipt query.
    #[test]
    fn issue1109_durable_timeout_body_says_ack_unknown() {
        let err = x0x::dm::DmError::Timeout {
            retries: 1,
            elapsed: Duration::from_secs(16),
        };
        let mut body = dm_error_body("timeout", &err, None);
        attach_ack_unknown(&mut body, Some("order-42"));
        assert_eq!(body["error"], "timeout");
        assert_eq!(body["outcome"], "ack_unknown");
        assert_eq!(body["logical_id"], "order-42");
        let mut anonymous = dm_error_body("timeout", &err, None);
        attach_ack_unknown(&mut anonymous, None);
        assert!(anonymous["logical_id"].is_null());
    }

    /// #1109: the receipt query derives the same request id as the send
    /// (logical id bound to this sender and the named recipient) and reports
    /// a late ACK recorded after the send gave up.
    #[test]
    fn issue1109_receipt_query_reports_a_late_ack_by_logical_id() {
        let me = test_agent_id(1);
        let peer = test_agent_id(2);
        let peer_hex = hex::encode(peer.as_bytes());
        let config = direct_send_config_for_request(
            &parse_request(serde_json::json!({
                "agent_id": peer_hex,
                "payload": "aGk=",
                "logical_id": "order-42",
            })),
            me,
            peer,
        )
        .expect("valid request");
        let rid = config
            .logical_request_id
            .expect("logical id derives a request id");
        let acks = x0x::dm::InFlightAcks::new();
        let query = |acks: &x0x::dm::InFlightAcks| {
            direct_receipt_body("order-42", &peer_hex, me, acks)
                .expect("valid query")
                .body
        };
        assert_eq!(query(&acks)["status"], "unknown");
        let machine = x0x::identity::MachineId([9; 32]);
        let _rx =
            acks.register_for_protocol(rid, x0x::dm::DM_PROTOCOL_DURABLE_ACK, peer, Some(machine));
        assert_eq!(query(&acks)["status"], "pending");
        acks.abandon(&rid);
        assert_eq!(query(&acks)["status"], "pending");
        assert!(!acks.resolve_for_protocol(
            &rid,
            x0x::dm::DM_PROTOCOL_DURABLE_ACK,
            peer,
            machine,
            x0x::dm::DmAckOutcome::Accepted,
        ));
        let body = query(&acks);
        assert_eq!(body["status"], "delivered_late");
        assert_eq!(body["request_id"], hex::encode(rid));
        assert_eq!(body["logical_id"], "order-42");
        // The same token to another recipient is another request.
        let other = hex::encode(test_agent_id(3).as_bytes());
        let elsewhere = direct_receipt_body("order-42", &other, me, &acks)
            .expect("valid")
            .body;
        assert_eq!(elsewhere["status"], "unknown");
    }

    /// #1109: malformed keys are refused, not answered `unknown`.
    #[test]
    fn issue1109_receipt_query_refuses_bad_keys() {
        let acks = x0x::dm::InFlightAcks::new();
        let peer_hex = hex::encode(test_agent_id(2).as_bytes());
        let bad_id = direct_receipt_body("Order 42", &peer_hex, test_agent_id(1), &acks)
            .expect_err("uppercase and space are not a logical id");
        assert_eq!(bad_id.status, StatusCode::BAD_REQUEST);
        assert_eq!(bad_id.code, "invalid_logical_id");
        let bad_agent = direct_receipt_body("order-42", "zz", test_agent_id(1), &acks)
            .expect_err("not an agent id");
        assert_eq!(bad_agent.status, StatusCode::BAD_REQUEST);
        assert_eq!(bad_agent.code, "invalid_agent_id");
    }

    fn deliver_until_check(
        value: serde_json::Value,
        now_ms: u64,
    ) -> Result<Option<u64>, &'static str> {
        let req = parse_request(value);
        let config = direct_send_config_for_request(&req, test_agent_id(1), test_agent_id(2))
            .expect("request validation passes");
        deliver_until_for_request(&req, &config, now_ms)
            .map(|deadline| {
                deadline.map(|(until, rid)| {
                    assert_eq!(config.logical_request_id, Some(rid));
                    until
                })
            })
            .map_err(|rejection| {
                assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
                rejection.code
            })
    }

    /// WHY: #1109 S1 refuses each unusable `deliver_until_ms` with its own
    /// 400 code, and a send without the field keeps the synchronous path.
    #[test]
    fn issue1109_deliver_until_refusals_are_typed_400s() {
        let now = 1_800_000_000_000u64;
        let base = |extra: serde_json::Value| {
            let mut body = serde_json::json!({
                "agent_id": hex::encode(test_agent_id(2).as_bytes()),
                "payload": "aGVsbG8=",
            });
            if let (Some(body), Some(extra)) = (body.as_object_mut(), extra.as_object()) {
                body.extend(extra.clone());
            }
            body
        };
        assert_eq!(
            deliver_until_check(base(serde_json::json!({})), now),
            Ok(None)
        );
        assert_eq!(
            deliver_until_check(
                base(
                    serde_json::json!({"deliver_until_ms": now + 1_000, "require_durable_app_ack": false})
                ),
                now
            ),
            Err("deliver_until_requires_durable")
        );
        assert_eq!(
            deliver_until_check(
                base(serde_json::json!({"deliver_until_ms": now + 1_000})),
                now
            ),
            Err("deliver_until_requires_logical_id")
        );
        assert_eq!(
            deliver_until_check(
                base(serde_json::json!({"deliver_until_ms": now, "logical_id": "order-1"})),
                now
            ),
            Err("deliver_until_passed")
        );
        assert_eq!(
            deliver_until_check(
                base(serde_json::json!({
                    "deliver_until_ms": now + DIRECT_SEND_MAX_HORIZON_MS + 1,
                    "logical_id": "order-1"
                })),
                now
            ),
            Err("deliver_until_too_far")
        );
        assert_eq!(
            deliver_until_check(
                base(serde_json::json!({
                    "deliver_until_ms": now + DIRECT_SEND_MAX_HORIZON_MS,
                    "logical_id": "order-1"
                })),
                now
            ),
            Ok(Some(now + DIRECT_SEND_MAX_HORIZON_MS))
        );
    }

    /// WHY: #1109 S1's 202 names the queued send's keys; a repeat with the
    /// same bytes is the same 202 and stores nothing new; other bytes under
    /// the same key are a 409 `idempotency_conflict`.
    #[tokio::test]
    async fn issue1109_queued_send_answers_202_idempotently_and_409_on_conflict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outbox = DirectSendOutbox::new(dir.path().join("direct_send_outbox.json"));
        let (me, peer) = (test_agent_id(1), test_agent_id(2));
        let now = 1_800_000_000_000u64;
        let until = now + 60_000;
        let req = parse_request(serde_json::json!({
            "agent_id": hex::encode(peer.as_bytes()),
            "payload": "aGVsbG8=",
            "logical_id": "order-9",
            "deliver_until_ms": until,
        }));
        let rid = direct_send_config_for_request(&req, me, peer)
            .expect("valid")
            .logical_request_id
            .expect("logical id derives a request id");
        let queue = |payload: &'static [u8], at: u64| {
            let obligation = queued_obligation(
                "order-9",
                direct_send_options(&req),
                peer,
                payload.to_vec(),
                (until, rid),
                at,
            );
            queue_direct_send(&outbox, obligation, no_ledger_record())
        };
        let (status, Json(body)) = queue(b"hello", now).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            body,
            serde_json::json!({
                "ok": true,
                "outcome": "queued",
                "logical_id": "order-9",
                "agent_id": hex::encode(peer.as_bytes()),
                "request_id": hex::encode(rid),
                "deliver_until_ms": until,
            })
        );
        let (status, Json(repeat)) = queue(b"hello", now + 5).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(repeat, body);
        assert_eq!(outbox.snapshot().await.len(), 1);
        let (status, Json(conflict)) = queue(b"other", now + 10).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(conflict["error"], "idempotency_conflict");
        assert_eq!(outbox.snapshot().await.len(), 1);
        let receipt = outbox.receipt(&peer, &rid, no_ledger_record()).await;
        assert_eq!(receipt.status, "queued");
    }

    fn no_ledger_record() -> LedgerReceipt {
        LedgerReceipt {
            status: x0x::dm::DmReceiptStatus::Unknown,
            digest: None,
            machine: None,
        }
    }

    /// WHY: #1109 `DELETE /direct/receipts/{logical_id}` removes a held
    /// send and answers `cancelled`; with none held it is 404 `not_queued`.
    #[tokio::test]
    async fn issue1109_cancel_removes_a_queued_send_and_404s_when_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outbox = DirectSendOutbox::new(dir.path().join("direct_send_outbox.json"));
        let (me, peer) = (test_agent_id(1), test_agent_id(2));
        let now = 1_800_000_000_000u64;
        let req = parse_request(serde_json::json!({
            "agent_id": hex::encode(peer.as_bytes()),
            "payload": "aGVsbG8=",
            "logical_id": "order-10",
            "deliver_until_ms": now + 60_000,
        }));
        let rid = direct_send_config_for_request(&req, me, peer)
            .expect("valid")
            .logical_request_id
            .expect("logical id derives a request id");
        let obligation = queued_obligation(
            "order-10",
            direct_send_options(&req),
            peer,
            b"hello".to_vec(),
            (now + 60_000, rid),
            now,
        );
        let (status, _) = queue_direct_send(&outbox, obligation, no_ledger_record()).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let acks = x0x::dm::InFlightAcks::new();
        let peer_hex = hex::encode(peer.as_bytes());
        let lookup = || direct_receipt_body("order-10", &peer_hex, me, &acks).expect("valid");
        let (status, Json(body)) = cancel_queued_send(&outbox, lookup()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "cancelled");
        assert_eq!(body["request_id"], hex::encode(rid));
        assert!(outbox.snapshot().await.is_empty());
        let (status, Json(body)) = cancel_queued_send(&outbox, lookup()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_queued");
        let receipt = outbox.receipt(&peer, &rid, no_ledger_record()).await;
        assert_eq!(receipt.status, "cancelled");
    }

    /// WHY: #1109 blocking a contact through the contacts API removes the
    /// queued sends to it, so they are never attempted.
    #[tokio::test]
    async fn issue1109_blocking_a_contact_drops_its_queued_sends() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("test state");
        let peer = test_agent_id(7);
        let rid = x0x::dm::DmLogicalId::parse("order-11")
            .expect("valid")
            .request_id(state.agent.agent_id(), peer);
        let obligation = queued_obligation(
            "order-11",
            DirectSendOptions::default(),
            peer,
            b"hello".to_vec(),
            (now_unix_ms() + 60_000, rid),
            now_unix_ms(),
        );
        let (status, _) =
            queue_direct_send(&state.direct_send_outbox, obligation, no_ledger_record()).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        state
            .contacts
            .write()
            .await
            .set_trust(&peer, TrustLevel::Blocked);
        super::super::contacts::sync_contact_relationship(&state, peer).await;
        assert!(state.direct_send_outbox.snapshot().await.is_empty());
        let receipt = state
            .direct_send_outbox
            .receipt(&peer, &rid, no_ledger_record())
            .await;
        assert_eq!(receipt.status, "failed");
        assert_eq!(receipt.error.as_deref(), Some("recipient_blocked"));
    }
}
