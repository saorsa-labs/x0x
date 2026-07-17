//! SSE (Server-Sent Events) handlers for the x0x daemon.
//!
//! Extracted from `server/mod.rs` (#125 / WS1.4) as a mechanical move:
//! the `/events`, `/presence/events`, `/direct/events`, and `/peers/events`
//! stream handlers plus the `SseEvent` broadcast type. Handlers are
//! `pub(super)` — wired into the router by the parent module.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Serialize;

use super::api_error;
use super::routes::{discovered_agent_entry, DiscoveredAgentEntry};
use super::state::AppState;

/// SSE event broadcast to connected clients.
#[derive(Debug, Clone, Serialize)]
pub(super) struct SseEvent {
    /// Event type: "message", "peer:connected", "peer:disconnected".
    #[serde(rename = "type")]
    pub(super) event_type: String,
    /// Event payload (JSON value).
    pub(super) data: serde_json::Value,
}

/// GET /events — Server-Sent Events stream.
pub(super) async fn events_sse(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    tracing::info!("[6/6 x0xd] SSE client connected to /events");
    let mut rx = state.broadcast_tx.subscribe();
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    tracing::info!("[6/6 x0xd] SSE client closing due to daemon shutdown");
                    break;
                }
                result = rx.recv() => {
                    match result {
                        Ok(event) => {
                            tracing::info!(
                                event_type = %event.event_type,
                                "[6/6 x0xd] SSE delivering event to client"
                            );
                            let data = serde_json::to_string(&event).unwrap_or_default();
                            yield Ok(Event::default().event(event.event_type).data(data));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(skipped, "[6/6 x0xd] SSE client lagged behind broadcast stream");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    };
    Sse::new(stream)
}

/// GET /presence/events
///
/// Server-Sent Events stream of presence online/offline events.
/// Each event is a JSON object: `{"event":"online"|"offline","agent_id":"<hex>"}`.
///
/// We derive events from the same discovery cache that powers `/presence/online`
/// so this stream reflects what local callers actually see as "online".
pub(super) async fn presence_events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let stream = async_stream::stream! {
        use std::collections::HashMap;

        let mut previous: HashMap<String, DiscoveredAgentEntry> = HashMap::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = interval.tick() => {
                    let current_entries: Vec<DiscoveredAgentEntry> = match state.agent.discovered_agents().await {
                        Ok(agents) => agents.into_iter().map(discovered_agent_entry).collect(),
                        Err(_) => Vec::new(),
                    };

                    let current: HashMap<String, DiscoveredAgentEntry> = current_entries
                        .into_iter()
                        .map(|entry| (entry.agent_id.clone(), entry))
                        .collect();

                    for (agent_id, entry) in &current {
                        if !previous.contains_key(agent_id) {
                            let reachable = Some(!entry.addresses.is_empty());
                            let data = serde_json::json!({
                                "event": "online",
                                "agent_id": agent_id,
                                "reachable": reachable
                            })
                            .to_string();
                            yield Ok::<Event, std::convert::Infallible>(
                                Event::default().event("presence").data(data),
                            );
                        }
                    }

                    for agent_id in previous.keys() {
                        if !current.contains_key(agent_id) {
                            let data = serde_json::json!({
                                "event": "offline",
                                "agent_id": agent_id
                            })
                            .to_string();
                            yield Ok::<Event, std::convert::Infallible>(
                                Event::default().event("presence").data(data),
                            );
                        }
                    }

                    previous = current;
                }
            }
        }
    };
    Sse::new(stream)
}

/// Serialize a received [`crate::direct::DirectMessage`] into the JSON
/// payload carried by the `/direct/events` SSE `direct_message` event.
///
/// Issue #120: `observed_origin` is inserted only when the message carries
/// the opt-in coarsened origin token — when the token is absent the output
/// is byte-identical to the pre-#120 shape (the key never appears, not even
/// as `null`). The token never reaches gossip, announcements, or `/peers`.
fn direct_message_event_data(msg: &crate::direct::DirectMessage) -> serde_json::Value {
    let mut data = serde_json::json!({
        "sender": hex::encode(msg.sender.as_bytes()),
        "machine_id": hex::encode(msg.machine_id.as_bytes()),
        "payload": BASE64.encode(&msg.payload),
        "received_at": msg.received_at,
        "verified": msg.verified,
        "trust_decision": msg.trust_decision.as_ref().map(|d| d.to_string())
    });
    if let Some(origin) = &msg.observed_origin {
        if let (Some(obj), Ok(value)) = (data.as_object_mut(), serde_json::to_value(origin)) {
            obj.insert("observed_origin".to_string(), value);
        }
    }
    data
}

/// GET /direct/events — SSE stream of incoming direct messages.
pub(super) async fn direct_events_sse(
    State(state): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    tracing::info!("[6/6 x0xd] SSE client connected to /direct/events");
    let mut rx = state.agent.subscribe_direct();
    let mut shutdown_rx = state.shutdown_notify.subscribe();

    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    tracing::info!("[6/6 x0xd] direct SSE client closing due to daemon shutdown");
                    break;
                }
                maybe_msg = rx.recv() => {
                    let Some(msg) = maybe_msg else {
                        break;
                    };
                    tracing::debug!(
                        target: "dm.trace",
                        stage = "inbound_sse_yielded",
                        sender = %hex::encode(msg.sender.as_bytes()),
                        machine_id = %hex::encode(msg.machine_id.as_bytes()),
                        bytes = msg.payload.len(),
                    );
                    let data = direct_message_event_data(&msg);
                    let event = Event::default()
                        .event("direct_message")
                        .data(data.to_string());
                    yield Ok(event);
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    )
}

/// GET /peers/events — SSE stream of ant-quic 0.27.1 `PeerLifecycleEvent`s.
///
/// Emits `Established`, `Replaced`, `Closing`, `Closed`, `ReaderExited`
/// transitions for every peer this node has a connection to. Useful for
/// dashboards and the Chrome/Dioxus/Apple harness proof runs.
pub(super) async fn peer_events_handler(
    State(state): State<Arc<AppState>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized")
            .into_response();
    };
    let Some(mut rx) = network.subscribe_all_peer_events().await else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network node not running")
            .into_response();
    };
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                r = rx.recv() => {
                    match r {
                        Ok((peer, ev)) => {
                            let payload = serde_json::json!({
                                "peer_id": hex::encode(peer.0),
                                "event": format!("{ev:?}"),
                                "at_ms": std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as u64)
                                    .unwrap_or(0),
                            });
                            let data = serde_json::to_string(&payload).unwrap_or_default();
                            yield Ok::<_, std::convert::Infallible>(
                                Event::default().event("peer-lifecycle").data(data));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
            }
        }
    };
    Sse::new(stream).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectivity::ObservedOrigin;
    use crate::direct::DirectMessage;
    use crate::identity::{AgentId, MachineId};

    fn dm_with_origin(origin: Option<ObservedOrigin>) -> DirectMessage {
        let mut msg = DirectMessage::new(
            AgentId([0x8a; 32]),
            MachineId([0xb2; 32]),
            b"hello".to_vec(),
        );
        msg.received_at = 1_774_860_000;
        msg.verified = true;
        msg.observed_origin = origin;
        msg
    }

    #[test]
    fn direct_message_event_data_is_byte_identical_without_origin() {
        // Issue #120 acceptance: with the token absent (the default — the
        // daemon has not opted in) the serialized event is byte-identical to
        // the pre-#120 shape. No `observed_origin` key, not even as null.
        let data = direct_message_event_data(&dm_with_origin(None));
        let s = data.to_string();
        assert!(
            !s.contains("observed_origin"),
            "absent token must not serialize: {s}"
        );
        assert_eq!(
            s,
            format!(
                "{{\"machine_id\":\"{}\",\"payload\":\"aGVsbG8=\",\"received_at\":1774860000,\"sender\":\"{}\",\"trust_decision\":null,\"verified\":true}}",
                hex::encode([0xb2; 32]),
                hex::encode([0x8a; 32]),
            )
        );
    }

    #[test]
    fn direct_message_event_data_inserts_masked_origin_when_present() {
        // Opted-in nodes emit the masked token on the DM-receive event;
        // relayed observation => direct=false, CGNAT => cgnat=true.
        let origin = ObservedOrigin {
            observed_prefix: "203.0.113.0/24".to_string(),
            direct: false,
            cgnat: true,
        };
        let data = direct_message_event_data(&dm_with_origin(Some(origin)));
        assert_eq!(
            data["observed_origin"],
            serde_json::json!({
                "observed_prefix": "203.0.113.0/24",
                "direct": false,
                "cgnat": true
            })
        );
        // The pre-existing fields are untouched by the insertion.
        assert_eq!(data["payload"], "aGVsbG8=");
        assert_eq!(data["verified"], true);
        assert_eq!(data["received_at"], 1_774_860_000);
        assert!(data["trust_decision"].is_null());
    }
}
