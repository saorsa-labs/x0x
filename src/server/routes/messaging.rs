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

/// A live REST `/subscribe` stream.
///
/// The shutdown drain owns `forwarder` until that task is finished.
/// `DELETE /subscribe/:id` aborts the task and waits for it, but it does
/// not take the `JoinHandle` out of the subscriptions map. A cancelled
/// DELETE drops only its abort handle and this completion receiver. The
/// drain still finds the task and joins it, so the task drops its
/// `HistoryHandle` before `shutdown_and_wait` returns.
pub(in crate::server) struct RestSubscription {
    /// Topic the subscription is for (retained for diagnostics and tests).
    topic: String,
    /// Forwarder task draining the gossip subscription into the SSE broadcast.
    /// Aborting it drops the underlying `Subscription`, which releases the
    /// gossip topic ref-count and ends delivery. The map keeps this handle
    /// until the task is finished.
    forwarder: tokio::task::JoinHandle<()>,
    /// Becomes `true` once the forwarder has dropped the owners it captured,
    /// including `HistoryHandle` for an opted-in topic. DELETE waits on a
    /// clone. The subscriptions map keeps `forwarder` until the task is
    /// finished (`AbortHandle::is_finished`).
    released: tokio::sync::watch::Receiver<bool>,
}

/// Sends the forwarder completion signal when the forwarder task drops it.
///
/// `send(true)` runs from `Drop`, including when shutdown or DELETE aborts
/// the task. DELETE treats that signal as a wake-up only. It returns after
/// the task is finished, which is after the future and its `HistoryHandle`
/// are dropped.
struct ForwarderReleased(Option<tokio::sync::watch::Sender<bool>>);

impl Drop for ForwarderReleased {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(true);
        }
    }
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
            let (release_tx, released) = tokio::sync::watch::channel(false);
            let mut recv_sub = sub;
            let forwarder = tokio::spawn(async move {
                // First local. Its drop sends the completion signal. DELETE
                // also waits until the task is finished, which is after this
                // future — and the `HistoryHandle` it captured — is dropped.
                let _released = ForwarderReleased(Some(release_tx));
                // Test-only. A blocking pause is not an await, so abort does
                // not finish this task until the pause ends and `recv` is
                // polled. The DELETE tests use that to hold `HistoryHandle`.
                #[cfg(test)]
                tests::rest_forwarder_test_pause::wait(&topic);
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

            // The map keeps the JoinHandle until the task is finished.
            // DELETE aborts through an abort handle and waits on
            // `released`. The shutdown drain takes whatever is still here.
            subs.insert(
                id.clone(),
                RestSubscription {
                    topic: req.topic.clone(),
                    forwarder,
                    released,
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
    // The subscriptions map keeps the `JoinHandle` until the task is
    // finished. This request holds an abort handle and a completion
    // receiver only. If the request is cancelled while it waits, dropping
    // those does not detach the task, and the shutdown drain still joins it.
    let (topic, abort, mut released) = {
        let subs = state.subscriptions.read().await;
        let Some(sub) = subs.get(&id) else {
            return not_found("subscription not found");
        };
        sub.forwarder.abort();
        (
            sub.topic.clone(),
            sub.forwarder.abort_handle(),
            sub.released.clone(),
        )
    };
    #[cfg(test)]
    tests::rest_forwarder_test_pause::delete_waiting(&topic);
    // `RecvError` means the sender dropped during task teardown. Either
    // result means the forwarder has started dropping its owners. Wait
    // until the task is finished so those owners are gone before this
    // handler removes the map entry or returns.
    let _ = released.wait_for(|done| *done).await;
    while !abort.is_finished() {
        tokio::task::yield_now().await;
    }
    {
        let mut subs = state.subscriptions.write().await;
        subs.remove(&id);
    }
    tracing::info!(
        sub_id = %id,
        topic = %topic,
        "unsubscribed: forwarder aborted, gossip subscription released"
    );
    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
}

/// Take every REST `/subscribe` forwarder for the shutdown drain.
///
/// The caller must have cancelled `AppState::shutdown_started` first.
/// `subscribe` checks that token under this map's write lock, so a
/// subscribe either inserted its forwarder before this take or it does
/// not spawn one.
///
/// `DELETE /subscribe/:id` leaves each `JoinHandle` here until that task
/// is finished. A DELETE cancelled during its wait does not remove the
/// task, so this take still joins it.
pub(in crate::server) async fn take_rest_subscribe_forwarders(
    state: &AppState,
) -> Vec<tokio::task::JoinHandle<()>> {
    let taken: Vec<RestSubscription> = std::mem::take(&mut *state.subscriptions.write().await)
        .into_values()
        .collect();
    #[cfg(test)]
    tests::rest_forwarder_test_pause::forwarders_taken(
        &taken
            .iter()
            .map(|sub| sub.topic.clone())
            .collect::<Vec<_>>(),
    );
    taken.into_iter().map(|sub| sub.forwarder).collect()
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
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::Json;

    use super::super::super::state::AppState;
    use super::{subscribe, unsubscribe, SubscribeRequest};
    use crate::Agent;

    /// Bound on one daemon start or shutdown.
    const LIFECYCLE: Duration = Duration::from_secs(60);
    /// Topic listed in `[history] record_topics` for this test.
    const TOPIC: &str = "issue1288.row2.subscribe";
    /// Distinct topic so the DELETE pause cannot stall the other tests.
    const DELETE_TOPIC: &str = "issue1288.row2.delete";
    /// Distinct topic for the cancelled-DELETE drain control.
    const DELETE_CANCEL_TOPIC: &str = "issue1288.row2.delete-cancel";

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
                "record_topics": [TOPIC, DELETE_TOPIC, DELETE_CANCEL_TOPIC]
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

    /// Once shutdown has cancelled `shutdown_started`, `POST /subscribe`
    /// is refused and leaves no registered forwarder.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn issue1288_subscribe_after_shutdown_started_registers_nothing() -> Result<()> {
        let (daemon, state) = start_daemon("closed").await?;
        state.shutdown_started.cancel();

        let response = subscribe(
            State(Arc::clone(&state)),
            Json(SubscribeRequest {
                topic: TOPIC.to_string(),
            }),
        )
        .await
        .into_response();
        let (status, body) = response_json(response).await?;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "subscribe after shutdown starts must be refused: {body}"
        );
        assert!(
            state.subscriptions.read().await.is_empty(),
            "a refused subscribe must leave no registered forwarder"
        );
        drop(state);

        let outcome = daemon.stop_and_relaunch().await?;
        assert_eq!(
            outcome.at_return,
            (0, 0),
            "refused subscribe: owners must be gone when shutdown returns (outcome: {outcome:?})"
        );
        assert!(
            outcome.relaunch.is_ok(),
            "refused subscribe: a same-dir relaunch must open history.db (outcome: {outcome:?})"
        );
        Ok(())
    }

    /// `DELETE /subscribe/:id` returns only after the forwarder task has
    /// finished. The forwarder is held in a blocking pause, so abort cannot
    /// complete it until that pause ends.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn issue1288_delete_subscribe_returns_after_forwarder_finishes() -> Result<()> {
        let pause = rest_forwarder_test_pause::arm(DELETE_TOPIC);
        let (daemon, state) = start_daemon("delete").await?;
        let response = subscribe(
            State(Arc::clone(&state)),
            Json(SubscribeRequest {
                topic: DELETE_TOPIC.to_string(),
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !pause.entered() {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "the forwarder did not reach its pause"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let abort = {
            let subs = state.subscriptions.read().await;
            subs.get(&id)
                .context("the subscription is registered")?
                .forwarder
                .abort_handle()
        };

        let mut pending = tokio::spawn({
            let state = Arc::clone(&state);
            let id = id.clone();
            async move { unsubscribe(State(state), Path(id)).await.into_response() }
        });
        let early = tokio::time::timeout(Duration::from_millis(300), &mut pending).await;
        assert!(
            early.is_err(),
            "DELETE returned while the forwarder was still paused"
        );
        assert!(
            !abort.is_finished(),
            "the forwarder finished before DELETE was released to join it"
        );

        drop(pause);
        let response = pending.await.context("DELETE task")?;
        let (status, body) = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "DELETE /subscribe: {body}");
        assert!(
            abort.is_finished(),
            "DELETE returned before the forwarder finished"
        );
        assert!(
            !state.subscriptions.read().await.contains_key(&id),
            "DELETE left the subscription registered"
        );
        drop(state);

        let outcome = daemon.stop_and_relaunch().await?;
        assert_eq!(
            outcome.at_return,
            (0, 0),
            "DELETE: owners must be gone when shutdown returns (outcome: {outcome:?})"
        );
        assert!(
            outcome.relaunch.is_ok(),
            "DELETE: a same-dir relaunch must open history.db (outcome: {outcome:?})"
        );
        Ok(())
    }

    /// `DELETE /subscribe/:id` is cancelled while the forwarder still holds
    /// `HistoryHandle`. The subscriptions map must still contain that task.
    /// The shutdown drain must not finish until the pause ends, and the
    /// same-dir relaunch must then open `history.db`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn issue1288_cancelled_delete_drain_waits_for_owner() -> Result<()> {
        let pause = rest_forwarder_test_pause::arm(DELETE_CANCEL_TOPIC);
        let (daemon, state) = start_daemon("delete-cancel").await?;
        let response = subscribe(
            State(Arc::clone(&state)),
            Json(SubscribeRequest {
                topic: DELETE_CANCEL_TOPIC.to_string(),
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !pause.entered() {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "the forwarder did not reach its pause"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let abort = {
            let subs = state.subscriptions.read().await;
            subs.get(&id)
                .context("the subscription is registered")?
                .forwarder
                .abort_handle()
        };

        let delete_waiting = rest_forwarder_test_pause::arm_delete_wait(DELETE_CANCEL_TOPIC);
        let mut pending = tokio::spawn({
            let state = Arc::clone(&state);
            let id = id.clone();
            async move { unsubscribe(State(state), Path(id)).await.into_response() }
        });
        tokio::time::timeout(Duration::from_secs(5), delete_waiting.notified())
            .await
            .context("DELETE did not reach its wait while the forwarder was paused")?;
        pending.abort();
        let stopped = tokio::time::timeout(Duration::from_secs(5), &mut pending)
            .await
            .context("cancelled DELETE did not stop")?
            .expect_err("cancelled DELETE must not complete as a normal response");
        assert!(
            stopped.is_cancelled(),
            "DELETE failed instead of being cancelled: {stopped:?}"
        );
        assert!(
            state.subscriptions.read().await.contains_key(&id),
            "cancelled DELETE removed the server-owned forwarder"
        );
        assert!(
            !abort.is_finished(),
            "the forwarder finished while its cleanup was still held"
        );

        let drain_took = rest_forwarder_test_pause::arm_drain_took(DELETE_CANCEL_TOPIC);
        drop(state);
        let Daemon {
            _root,
            config,
            handle,
            state_weak,
            agent_weak,
        } = daemon;
        let mut shutdown = tokio::spawn(async move { handle.shutdown_and_wait().await });
        tokio::time::timeout(LIFECYCLE, drain_took)
            .await
            .context("the drain did not take the forwarder while it still held history.db")?
            .context("drain-took signal dropped")?;
        assert!(
            !shutdown.is_finished(),
            "the drain finished before the forwarder released history.db"
        );

        drop(pause);
        tokio::time::timeout(LIFECYCLE, &mut shutdown)
            .await
            .context("shutdown returns within 60 s after the forwarder is released")?
            .context("shutdown task")?
            .context("shutdown")?;
        let at_return = (state_weak.strong_count(), agent_weak.strong_count());
        assert_eq!(
            at_return,
            (0, 0),
            "cancelled DELETE: owners must be gone when shutdown returns"
        );
        let relaunch = match tokio::time::timeout(
            LIFECYCLE,
            crate::server::serve_with_options(config, loopback_daemon_options()),
        )
        .await
        {
            Err(_) => Err("the relaunch did not return within 60 s".to_string()),
            Ok(Err(e)) => Err(format!("{e:#}")),
            Ok(Ok(relaunched)) => tokio::time::timeout(LIFECYCLE, relaunched.shutdown_and_wait())
                .await
                .map_err(|_| "the relaunched daemon did not stop within 60 s".to_string())
                .and_then(|stopped| stopped.map_err(|e| format!("{e:#}"))),
        };
        assert!(
            relaunch.is_ok(),
            "cancelled DELETE: a same-dir relaunch must open history.db ({relaunch:?})"
        );
        Ok(())
    }

    /// Blocking pause for one forwarder topic. Abort cannot finish the task
    /// while it is inside [`Pause::wait`], because that wait is not an await.
    ///
    /// Pauses, DELETE-wait signals and drain-took signals are keyed by topic
    /// so the row-2 tests can run in parallel.
    pub(super) mod rest_forwarder_test_pause {
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Condvar, LazyLock, Mutex};

        struct Pause {
            topic: String,
            entered: AtomicBool,
            release: Mutex<bool>,
            cv: Condvar,
        }

        static ARMED: LazyLock<Mutex<HashMap<String, Arc<Pause>>>> =
            LazyLock::new(|| Mutex::new(HashMap::new()));
        static DELETE_WAITING: LazyLock<Mutex<HashMap<String, Arc<tokio::sync::Notify>>>> =
            LazyLock::new(|| Mutex::new(HashMap::new()));
        static DRAIN_TOOK: LazyLock<Mutex<HashMap<String, tokio::sync::oneshot::Sender<()>>>> =
            LazyLock::new(|| Mutex::new(HashMap::new()));

        pub(super) struct Armed {
            pause: Arc<Pause>,
        }

        pub(super) fn arm(topic: &str) -> Armed {
            let pause = Arc::new(Pause {
                topic: topic.to_string(),
                entered: AtomicBool::new(false),
                release: Mutex::new(false),
                cv: Condvar::new(),
            });
            ARMED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(topic.to_string(), Arc::clone(&pause));
            Armed { pause }
        }

        /// Fires once `DELETE /subscribe/:id` has aborted the forwarder and
        /// is waiting for it, and has not yet removed the map entry.
        pub(super) fn arm_delete_wait(topic: &str) -> Arc<tokio::sync::Notify> {
            let notify = Arc::new(tokio::sync::Notify::new());
            DELETE_WAITING
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(topic.to_string(), Arc::clone(&notify));
            notify
        }

        /// Fires when the shutdown drain takes a forwarder for `topic`.
        pub(super) fn arm_drain_took(topic: &str) -> tokio::sync::oneshot::Receiver<()> {
            let (tx, rx) = tokio::sync::oneshot::channel();
            DRAIN_TOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(topic.to_string(), tx);
            rx
        }

        impl Armed {
            pub(super) fn entered(&self) -> bool {
                self.pause.entered.load(Ordering::SeqCst)
            }
        }

        impl Drop for Armed {
            fn drop(&mut self) {
                {
                    let mut go = self
                        .pause
                        .release
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *go = true;
                    self.pause.cv.notify_all();
                }
                let mut slot = ARMED
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if slot
                    .get(&self.pause.topic)
                    .is_some_and(|p| Arc::ptr_eq(p, &self.pause))
                {
                    slot.remove(&self.pause.topic);
                }
            }
        }

        pub(in super::super) fn wait(topic: &str) {
            let pause = {
                let slot = ARMED
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                slot.get(topic).map(Arc::clone)
            };
            let Some(pause) = pause else {
                return;
            };
            pause.entered.store(true, Ordering::SeqCst);
            let mut go = pause
                .release
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*go {
                go = pause
                    .cv
                    .wait(go)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }

        pub(in super::super) fn delete_waiting(topic: &str) {
            if let Some(notify) = DELETE_WAITING
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(topic)
            {
                notify.notify_one();
            }
        }

        pub(in super::super) fn forwarders_taken(topics: &[String]) {
            let mut waiting = DRAIN_TOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for topic in topics {
                if let Some(tx) = waiting.remove(topic) {
                    let _ = tx.send(());
                }
            }
        }
    }
}
