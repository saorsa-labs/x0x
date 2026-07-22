//! Route handlers (`category: "messaging"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::sse::SseEvent;
use super::super::state::AppState;
use super::super::{api_error, bad_request, not_found};
use crate as x0x;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;
use std::sync::Arc;
use x0x::logging::LogHexId;

/// Record one verified message from an opted-in topic (ADR-0023 §4).
///
/// Pub/sub messages carry no re-serializable signed artifact at this layer,
/// so rows are artifact-less; `msg_id = BLAKE3(payload)` collapses redundant
/// gossip deliveries of the same bytes. Unverified messages are never
/// recorded (history stores communication the node accepted).
fn record_topic_message(
    history: &x0x::history::HistoryHandle,
    topic: &str,
    msg: &x0x::gossip::PubSubMessage,
) {
    if !msg.verified || msg.payload.is_empty() {
        return;
    }
    let payload: Vec<u8> = msg.payload.to_vec();
    let content_type = if payload.first() == Some(&b'{')
        && serde_json::from_slice::<serde_json::Value>(&payload).is_ok()
    {
        "application/json"
    } else if std::str::from_utf8(&payload).is_ok() {
        "text/plain"
    } else {
        "application/octet-stream"
    };
    let now = i64::try_from(x0x::dm::now_unix_ms()).unwrap_or(i64::MAX);
    history.record(x0x::history::HistoryRecord {
        msg_id: x0x::history::HistoryRecord::compute_msg_id(None, &payload),
        scope: x0x::history::Scope::Topic(topic.to_string()),
        author_agent: msg.sender.as_ref().map(|s| hex::encode(s.as_bytes())),
        author_machine: None,
        author_pubkey: msg.sender_public_key.clone(),
        sent_at_ms: now,
        seen_at_ms: now,
        direction: x0x::history::Direction::Inbound,
        content_type: content_type.to_string(),
        payload,
        signed_artifact: None,
        signature: None,
        sig_context: None,
        provenance: x0x::history::Provenance::VerifiedEnvelope,
        replace_key: None,
    });
}

/// A live REST `/subscribe` stream tracked so `DELETE /subscribe/:id` can stop it.
pub(in crate::server) struct RestSubscription {
    /// Topic the subscription the subscription is for (retained for diagnostics/logging).
    topic: String,
    /// Forwarder task draining the gossip subscription into the SSE broadcast.
    /// Aborting it drops the underlying `Subscription`, which releases the
    /// gossip topic ref-count and ends delivery — without this, an
    /// unsubscribed stream would keep forwarding messages to SSE forever.
    forwarder: tokio::task::JoinHandle<()>,
}

/// POST /publish request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct PublishRequest {
    topic: String,
    /// Base64-encoded payload.
    payload: String,
}

/// POST /subscribe request body.
#[derive(Debug, Deserialize)]
pub(in crate::server) struct SubscribeRequest {
    topic: String,
}

/// POST /publish
pub(in crate::server) async fn publish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PublishRequest>,
) -> impl IntoResponse {
    // Reject empty topic
    if req.topic.is_empty() {
        return bad_request("topic must not be empty");
    }

    // Decode base64 payload
    let payload = match BASE64.decode(&req.payload) {
        Ok(p) => p,
        Err(e) => {
            return bad_request(format!(
                "invalid base64 in payload field: {e}. \
                         The payload must be base64-encoded \
                         (e.g., use `echo -n \"hello\" | base64`)"
            ));
        }
    };

    match state.agent.publish(&req.topic, payload).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// POST /subscribe
pub(in crate::server) async fn subscribe(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubscribeRequest>,
) -> impl IntoResponse {
    match state.agent.subscribe(&req.topic).await {
        Ok(sub) => {
            let id = format!("{:016x}", rand::random::<u64>());
            // Spawn background task to forward messages to SSE broadcast
            let broadcast_tx = state.broadcast_tx.clone();
            let topic = req.topic.clone();
            let mut recv_sub = sub;
            let sub_id = id.clone();
            // ADR-0023 §4 topic opt-in: record this topic's verified traffic
            // when `[history] record_topics` lists it (local ingest option).
            let history = if state.history_record_topics.contains(&req.topic) {
                state.agent.history().cloned()
            } else {
                None
            };
            let forwarder = tokio::spawn(async move {
                while let Some(msg) = recv_sub.recv().await {
                    if let Some(history) = history.as_ref() {
                        record_topic_message(history, &topic, &msg);
                    }
                    tracing::info!(
                        topic = %topic,
                        sub_id = %sub_id,
                        payload_len = msg.payload.len(),
                        "[5/6 x0xd] received from subscriber channel, broadcasting to SSE"
                    );
                    let event = SseEvent {
                        event_type: "message".to_string(),
                        data: serde_json::json!({
                            "subscription_id": sub_id,
                            "topic": topic,
                            "payload": BASE64.encode(&msg.payload),
                            "sender": msg.sender.map(|s| hex::encode(s.0)),
                            "verified": msg.verified,
                            "trust_level": msg.trust_level.map(|t| t.to_string()),
                        }),
                    };
                    match broadcast_tx.send(event) {
                        Ok(n) => tracing::info!(
                            topic = %topic,
                            receivers = n,
                            "[5/6 x0xd] broadcast sent to {n} SSE receivers"
                        ),
                        Err(_) => tracing::warn!(
                            topic = %LogHexId::topic(&topic),
                            "[5/6 x0xd] broadcast send failed (no SSE receivers)"
                        ),
                    }
                }
            });

            // Track the forwarder task so the DELETE handler can abort it.
            // Aborting drops the underlying `Subscription`, releasing the
            // gossip topic ref-count and stopping SSE delivery.
            let mut subs = state.subscriptions.write().await;
            subs.insert(
                id.clone(),
                RestSubscription {
                    topic: req.topic.clone(),
                    forwarder,
                },
            );

            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "subscription_id": id })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// DELETE /subscribe/:id
pub(in crate::server) async fn unsubscribe(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut subs = state.subscriptions.write().await;
    if let Some(sub) = subs.remove(&id) {
        // Stop the forwarder task. Dropping its `Subscription` releases the
        // gossip topic ref-count and ends message delivery for this stream.
        sub.forwarder.abort();
        tracing::info!(
            sub_id = %id,
            topic = %sub.topic,
            "unsubscribed: forwarder aborted, gossip subscription released"
        );
        (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
    } else {
        not_found("subscription not found")
    }
}
