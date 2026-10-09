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
        thread_root: None,
        thread_parent: None,
        ingress_sender_agent: None,
        logical_request_id: None,
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
            let sub_id = id.clone();
            // ADR-0023 §4 topic opt-in: record this topic's verified traffic
            // when `[history] record_topics` lists it (local ingest option).
            let history = if state.history_record_topics.contains(&req.topic) {
                state.agent.history().cloned()
            } else {
                None
            };
            // #1288 row 2: admit under the same lock the shutdown drain
            // takes. The drain cancels `shutdown_started` before that take,
            // so a subscribe that has not inserted yet does not spawn a
            // forwarder the drain will not join. The forwarder clones
            // `HistoryHandle` for an opted-in topic and would otherwise
            // keep `history.db` locked after `shutdown_and_wait`.
            let mut subs = state.subscriptions.write().await;
            if state.shutdown_started.is_cancelled() {
                return api_error(StatusCode::SERVICE_UNAVAILABLE, "daemon is shutting down");
            }
            let mut recv_sub = sub;
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

            // Track the forwarder task so the DELETE handler can abort it
            // and the shutdown drain can join it. Aborting drops the
            // underlying `Subscription`, releasing the gossip topic
            // ref-count and stopping SSE delivery.
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
    let removed = {
        let mut subs = state.subscriptions.write().await;
        subs.remove(&id)
    };
    if let Some(sub) = removed {
        // Stop the forwarder and wait until it has dropped its
        // `HistoryHandle`. Aborting without joining would detach the task,
        // and an opted-in topic would keep `history.db` locked.
        let topic = sub.topic;
        let forwarder = sub.forwarder;
        forwarder.abort();
        let _ = forwarder.await;
        tracing::info!(
            sub_id = %id,
            topic = %topic,
            "unsubscribed: forwarder aborted, gossip subscription released"
        );
        (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
    } else {
        not_found("subscription not found")
    }
}

/// Take every REST `/subscribe` forwarder for the shutdown drain.
///
/// The caller must have cancelled `AppState::shutdown_started` first.
/// `subscribe` checks that token under this map's write lock, so a
/// subscribe either inserted its forwarder before this take or it does
/// not spawn one.
pub(in crate::server) async fn take_rest_subscribe_forwarders(
    state: &AppState,
) -> Vec<tokio::task::JoinHandle<()>> {
    std::mem::take(&mut *state.subscriptions.write().await)
        .into_values()
        .map(|sub| sub.forwarder)
        .collect()
}

#[cfg(test)]
mod tests {
    //! #1288 row 2: a REST `/subscribe` forwarder for a topic listed in
    //! `[history] record_topics` clones the agent's `HistoryHandle` and so
    //! holds `history.db`. The stream stays open until DELETE. Shutdown
    //! must release that owner when `shutdown_and_wait` returns, so an
    //! immediate same-dir relaunch can open `history.db`.

    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::Json;

    use super::super::super::state::AppState;
    use super::{subscribe, SubscribeRequest};
    use crate::Agent;

    /// Bound on one daemon start or shutdown.
    const LIFECYCLE: Duration = Duration::from_secs(60);
    /// Topic listed in `[history] record_topics` for this test.
    const TOPIC: &str = "issue1288.row2.subscribe";

    fn loopback_daemon_config(
        root: &std::path::Path,
        tag: &str,
    ) -> Result<crate::server::DaemonConfig> {
        Ok(serde_json::from_value(serde_json::json!({
            "bind_address": "127.0.0.1:0",
            "api_address": "127.0.0.1:0",
            "data_dir": root.join("data"),
            "identity_dir": root.join("identity"),
            "bootstrap_peers": [],
            "mdns_enabled": false,
            "port_mapping_enabled": false,
            "network_id": format!(
                "x0x.test.1288.row2.{tag}.{}.{:08x}",
                std::process::id(),
                rand::random::<u32>()
            ),
            "history": {
                "enabled": true,
                "record_topics": [TOPIC]
            }
        }))?)
    }

    fn loopback_daemon_options() -> crate::server::ServeOptions {
        crate::server::ServeOptions {
            skip_update_check: true,
            cli_no_port_mapping: true,
            cli_disable_peer_cache: true,
            self_update_enabled: false,
            ..crate::server::ServeOptions::default()
        }
    }

    struct Daemon {
        _root: tempfile::TempDir,
        config: crate::server::DaemonConfig,
        handle: crate::server::ServerHandle,
        state_weak: std::sync::Weak<AppState>,
        agent_weak: std::sync::Weak<Agent>,
    }

    #[derive(Debug)]
    struct ShutdownOutcome {
        /// Strong counts of the AppState and the Agent when
        /// `shutdown_and_wait` returned.
        at_return: (usize, usize),
        /// The same-dir relaunch, which opens `history.db`.
        relaunch: std::result::Result<(), String>,
    }

    async fn start_daemon(tag: &str) -> Result<(Daemon, Arc<AppState>)> {
        let root = tempfile::tempdir()?;
        let config = loopback_daemon_config(root.path(), tag)?;
        let handle = tokio::time::timeout(
            LIFECYCLE,
            crate::server::serve_with_options(config.clone(), loopback_daemon_options()),
        )
        .await
        .context("daemon starts within 60 s")??;
        let state = handle.test_state.upgrade().context("live daemon state")?;
        let daemon = Daemon {
            _root: root,
            config,
            handle,
            state_weak: Arc::downgrade(&state),
            agent_weak: Arc::downgrade(&state.agent),
        };
        Ok((daemon, state))
    }

    impl Daemon {
        /// Shut the daemon down, read both strong counts as soon as
        /// `shutdown_and_wait` returns, and relaunch on the same directories
        /// at once. The caller must have dropped its own AppState handles.
        async fn stop_and_relaunch(self) -> Result<ShutdownOutcome> {
            let Daemon {
                _root,
                config,
                handle,
                state_weak,
                agent_weak,
            } = self;
            tokio::time::timeout(LIFECYCLE, handle.shutdown_and_wait())
                .await
                .context("shutdown returns within 60 s")?
                .context("shutdown")?;
            let at_return = (state_weak.strong_count(), agent_weak.strong_count());
            let relaunch = match tokio::time::timeout(
                LIFECYCLE,
                crate::server::serve_with_options(config, loopback_daemon_options()),
            )
            .await
            {
                Err(_) => Err("the relaunch did not return within 60 s".to_string()),
                Ok(Err(e)) => Err(format!("{e:#}")),
                Ok(Ok(relaunched)) => {
                    tokio::time::timeout(LIFECYCLE, relaunched.shutdown_and_wait())
                        .await
                        .map_err(|_| "the relaunched daemon did not stop within 60 s".to_string())
                        .and_then(|stopped| stopped.map_err(|e| format!("{e:#}")))
                }
            };
            Ok(ShutdownOutcome {
                at_return,
                relaunch,
            })
        }
    }

    async fn response_json(
        response: axum::response::Response,
    ) -> Result<(StatusCode, serde_json::Value)> {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .context("read response body")?;
        let body = serde_json::from_slice(&bytes).context("decode response body")?;
        Ok((status, body))
    }

    /// A REST `/subscribe` on a `record_topics` topic is still open at
    /// shutdown. The AppState and Agent are gone when `shutdown_and_wait`
    /// returns, and the same-dir relaunch opens `history.db`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn issue1288_rest_subscribe_open_at_shutdown_releases_owner() -> Result<()> {
        let (daemon, state) = start_daemon("subscribe").await?;
        assert!(
            state.agent.history().is_some(),
            "the daemon opened history, so the forwarder can clone HistoryHandle"
        );
        assert!(
            state
                .history_record_topics
                .iter()
                .any(|topic| topic == TOPIC),
            "record_topics must list {TOPIC} so the forwarder holds history.db"
        );

        let response = subscribe(
            State(Arc::clone(&state)),
            Json(SubscribeRequest {
                topic: TOPIC.to_string(),
            }),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "POST /subscribe: {body}");
        let id = body["subscription_id"]
            .as_str()
            .context("subscription_id")?
            .to_string();
        {
            let subs = state.subscriptions.read().await;
            let registered = subs.get(&id).context("the subscription is registered")?;
            assert!(
                !registered.forwarder.is_finished(),
                "the forwarder is still running at shutdown"
            );
        }
        drop(state);

        let outcome = daemon.stop_and_relaunch().await?;
        assert_eq!(
            outcome.at_return,
            (0, 0),
            "REST /subscribe: the AppState and Agent strong counts must be 0 when \
             shutdown_and_wait returns (outcome: {outcome:?})"
        );
        assert!(
            outcome.relaunch.is_ok(),
            "REST /subscribe: a same-dir relaunch must open history.db (outcome: {outcome:?})"
        );
        Ok(())
    }
}
