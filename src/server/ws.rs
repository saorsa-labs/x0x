//! WebSocket handlers and per-session outbound-queue machinery for the x0x
//! daemon (WS1.1 / #122).
//!
//! Extracted from `server/mod.rs` (#125 / WS1.4) as a mechanical move: the
//! `/ws` and `/ws/direct` upgrade handlers, the `/ws/sessions` and
//! `/diagnostics/ws` endpoints, the bounded outbound queue with its
//! drop-vs-close feeder policies, the writer loop, the keepalive pinger, and
//! their deterministic unit tests. Handlers and the types named by
//! `state::AppState` are `pub(super)`; everything else is private.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::contacts::TrustLevel;

use super::routes::direct_message_send_config;
use super::state::AppState;
use super::{decode_base64_payload, parse_agent_id_hex};

/// Per-WebSocket-outbound-queue observability counters (WS1.1 / #122).
///
/// The per-session outbound queue is bounded (`WS_OUTBOUND_CAPACITY`). Two
/// feeder policies are distinguished and counted separately:
///
/// - topic/control/error frames are dropped on a full queue
///   (`ws_outbound_dropped`);
/// - DM/keepalive frames close the slow-consumer session
///   (`ws_slow_consumer_closes`).
///
/// Surfaced via `GET /diagnostics/ws`.
#[derive(Debug, Default)]
pub(super) struct WsOutboundStats {
    /// Topic / control / error frames dropped because the per-session outbound
    /// queue was full. Topic data is re-obtainable via gossip; dropping is safe.
    ws_outbound_dropped: AtomicU64,
    /// Sessions closed with WS code 1013 ("try again later") because a
    /// DM/keepalive feeder hit a full outbound queue — the session reader is
    /// stalled. Counted once per session.
    ws_slow_consumer_closes: AtomicU64,
}

/// State for a single WebSocket connection.
pub(super) struct WsSession {
    /// Unique session identifier (UUID v4).
    id: String,
    /// Topics this session subscribed to.
    subscribed_topics: HashSet<String>,
    /// Whether this session receives direct messages.
    receives_direct: bool,
    /// Per-topic forwarder tasks for this session (aborted on unsubscribe/cleanup).
    topic_forwarders: HashMap<String, tokio::task::JoinHandle<()>>,
}

/// Shared state for a single gossip topic subscription shared across WS sessions.
pub(super) struct SharedTopicState {
    /// Broadcast channel that all WS sessions for this topic tap.
    channel: broadcast::Sender<WsOutbound>,
    /// Session IDs currently subscribed to this topic.
    subscribers: HashSet<String>,
    /// Gossip forwarder task handle (aborted when last subscriber leaves).
    forwarder: tokio::task::JoinHandle<()>,
}

/// Server → Client WebSocket message.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
enum WsOutbound {
    #[serde(rename = "connected")]
    Connected {
        session_id: String,
        agent_id: String,
    },
    #[serde(rename = "message")]
    Message {
        topic: String,
        payload: String,
        origin: Option<String>,
    },
    #[serde(rename = "direct_message")]
    DirectMessage {
        sender: String,
        machine_id: String,
        payload: String,
        received_at: u64,
        verified: bool,
        trust_decision: Option<String>,
        /// Issue #120: opt-in coarsened origin token. Entirely absent
        /// (never `null`) unless the daemon opted in via
        /// `observed_prefix_enabled` AND the message arrived over the live
        /// point-to-point transport connection with a maskable observed
        /// address. Never gossiped, never announced, never on `/peers`.
        #[serde(skip_serializing_if = "Option::is_none")]
        observed_origin: Option<crate::connectivity::ObservedOrigin>,
    },
    #[serde(rename = "subscribed")]
    Subscribed { topics: Vec<String> },
    #[serde(rename = "unsubscribed")]
    Unsubscribed { topics: Vec<String> },
    #[serde(rename = "pong")]
    Pong,
    /// ADR-0023 backfill-then-live marker: everything before this frame on
    /// `topic` came from the durable store; everything after is live.
    #[serde(rename = "live")]
    Live { topic: String },
    #[serde(rename = "error")]
    Error { message: String },
}

/// Client → Server WebSocket command.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WsInbound {
    #[serde(rename = "subscribe")]
    Subscribe {
        topics: Vec<String>,
        /// ADR-0023 §7: optional stored-history backfill before the live
        /// stream. Additive — absent means live-only (legacy behaviour).
        #[serde(default)]
        backfill: Option<WsBackfill>,
    },
    #[serde(rename = "unsubscribe")]
    Unsubscribe { topics: Vec<String> },
    #[serde(rename = "publish")]
    Publish { topic: String, payload: String },
    #[serde(rename = "send_direct")]
    SendDirect { agent_id: String, payload: String },
    #[serde(rename = "ping")]
    Ping,
}

/// Backfill request carried on `Subscribe` (ADR-0023 §7).
#[derive(Debug, Clone, Copy, Deserialize)]
struct WsBackfill {
    /// Max stored rows to replay per topic (server clamps like `/history`).
    #[serde(default)]
    limit: usize,
}

// ---------------------------------------------------------------------------
// WS outbound queue capacity + slow-consumer policy (WS1.1 / #122)
// ---------------------------------------------------------------------------
//
// The per-session outbound queue (`mpsc::channel`) is the only thing between
// the daemon's remote-driven feeders and the local WS socket writer. It MUST
// be bounded: a stalled local reader plus a remote topic/DM flood would grow
// daemon memory without bound. Capacity 1024 is large enough that a healthy
// client never sees a drop, yet small enough that a stalled reader is detected
// promptly (the keepalive pinger tries every KEEPALIVE_INTERVAL_SECS to enqueue
// a Pong and closes the session on Full — so a stalled reader is closed within
// ~one keepalive interval regardless of topic/DM flow).
//
// Feeder policy on a Full queue, by frame class:
//   - topic / control / error frames  → drop + count `ws_outbound_dropped`
//     (topic data is re-obtainable via gossip; control frames are best-effort)
//   - direct-message / keepalive      → close the session with WS 1013
//     (DMs to WS are fire-and-forget — see `DirectSubscriberQueue` in
//     src/direct.rs, capacity 8192 drop-oldest; there is no retaining inbox
//     behind `subscribe_direct`, so fail-loud is the correct policy).

/// Bound on the per-WS-session outbound queue. See module notes above.
const WS_OUTBOUND_CAPACITY: usize = 1024;

/// WS close code for a slow-consumer session close ("try again later").
const WS_SLOW_CONSUMER_CLOSE_CODE: u16 = 1013;
/// Reason string sent in the WS close frame for a slow-consumer close.
const WS_SLOW_CONSUMER_CLOSE_REASON: &str = "slow consumer";

/// GET /ws — upgrade to WebSocket (general purpose).
pub(super) async fn ws_handler(
    ws: axum::extract::WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state, false, None))
}

/// Query parameters for `GET /ws/direct` (ADR-0023 §7 backfill).
#[derive(Debug, Deserialize)]
pub(super) struct DirectWsParams {
    /// Replay up to N stored DM rows (all `dm:` scopes, oldest→newest)
    /// before the `live` marker and the live stream.
    backfill: Option<usize>,
}

/// GET /ws/direct — upgrade to WebSocket (auto-subscribes to direct messages).
pub(super) async fn ws_direct_handler(
    ws: axum::extract::WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<DirectWsParams>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state, true, params.backfill))
}

/// GET /ws/sessions — list active WebSocket sessions.
pub(super) async fn ws_sessions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions = state.ws_sessions.read().await;
    let entries: Vec<serde_json::Value> = sessions
        .values()
        .map(|s| {
            serde_json::json!({
                "session_id": s.id,
                "subscribed_topics": s.subscribed_topics.iter().collect::<Vec<_>>(),
                "receives_direct": s.receives_direct,
            })
        })
        .collect();

    // Shared subscription stats
    let topics = state.ws_topics.read().await;
    let shared: HashMap<&str, usize> = topics
        .iter()
        .map(|(topic, ts)| (topic.as_str(), ts.subscribers.len()))
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "sessions": entries,
            "shared_subscriptions": shared
        })),
    )
}

/// Build the `/diagnostics/ws` JSON payload from the live counters. Pure over
/// the stats so the counter→payload mapping is unit-testable without an
/// `AppState` fixture.
fn ws_diagnostics_payload(stats: &WsOutboundStats) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "ws_outbound_capacity": WS_OUTBOUND_CAPACITY,
        "ws_outbound_dropped": stats.ws_outbound_dropped.load(Ordering::Relaxed),
        "ws_slow_consumer_closes": stats.ws_slow_consumer_closes.load(Ordering::Relaxed),
    })
}

/// GET /diagnostics/ws — WebSocket outbound-queue health (WS1.1 / #122).
///
/// Surfaces the bounded outbound queue capacity and the two feeder-policy
/// counters: `ws_outbound_dropped` (topic/control frames dropped on a full
/// queue) and `ws_slow_consumer_closes` (sessions closed with WS 1013 because a
/// DM/keepalive feeder hit a full queue — the reader was stalled).
pub(super) async fn ws_diagnostics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(ws_diagnostics_payload(&state.ws_outbound_stats)),
    )
}

// ---------------------------------------------------------------------------
// WS outbound feeder policies (WS1.1 / #122)
// ---------------------------------------------------------------------------
//
// The bounded outbound queue distinguishes two feeder policies by frame class.
// Both are pure over the channel + counters, so the drop-vs-close decision is
// unit-testable without a daemon.

/// A WS close frame for a slow-consumer session close (code 1013, "try again
/// later"). Extracted as a pure helper so the close payload is unit-testable.
fn slow_consumer_close_message() -> axum::extract::ws::Message {
    axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
        code: WS_SLOW_CONSUMER_CLOSE_CODE,
        reason: WS_SLOW_CONSUMER_CLOSE_REASON.into(),
    }))
}

/// Feeder policy for topic / control / error frames: on a Full outbound queue,
/// drop the frame and increment `ws_outbound_dropped` (topic data is
/// re-obtainable via gossip; control frames are best-effort). Never closes the
/// session. Returns `true` while the channel is open (feeder should continue),
/// `false` once it has closed (feeder should stop).
fn feed_droppable(tx: &mpsc::Sender<WsOutbound>, msg: WsOutbound, stats: &WsOutboundStats) -> bool {
    match tx.try_send(msg) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            stats.ws_outbound_dropped.fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// Feeder policy for direct-message / keepalive frames: on a Full outbound
/// queue, the session reader is stalled — trigger a slow-consumer close (WS
/// 1013). The close is counted at most once per session via
/// `slow_close_counted` (DM and keepalive feeders may both observe Full in the
/// same window). Returns `true` while the channel is open and not full, `false`
/// once the feeder should stop (channel closed, OR slow-consumer close fired).
fn feed_critical(
    tx: &mpsc::Sender<WsOutbound>,
    msg: WsOutbound,
    stats: &WsOutboundStats,
    slow_close: &tokio_util::sync::CancellationToken,
    slow_close_counted: &AtomicBool,
) -> bool {
    match tx.try_send(msg) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            // Count-once: only the first feeder to observe Full counts the
            // slow-consumer close and cancels the token.
            if slow_close_counted
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                stats
                    .ws_slow_consumer_closes
                    .fetch_add(1, Ordering::Relaxed);
            }
            slow_close.cancel();
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// The WS writer loop: drains `outbound_rx` and serializes each frame to the
/// socket via `ws_tx` (a [`futures::Sink`] over `Message`). Races BOTH frame
/// arrival and each socket send against the slow-consumer token (the writer may
/// be blocked in `send` flushing to a stalled socket when the queue fills
/// behind it). On slow-close it attempts a WS Close(1013) with a 2s flush
/// budget, then exits even if it cannot flush.
///
/// Generic over `Sink<Message>` (axum's split WS sender is a `SplitSink` that
/// implements `Sink<Message>`) so the slow-close behavior is unit-testable with
/// a fake sink — no real socket required.
async fn run_ws_writer<S, E>(
    outbound_rx: &mut mpsc::Receiver<WsOutbound>,
    ws_tx: &mut S,
    slow_close: &tokio_util::sync::CancellationToken,
) where
    S: futures::Sink<axum::extract::ws::Message, Error = E> + Unpin,
{
    use futures::SinkExt;
    let mut need_close = false;
    loop {
        let msg = tokio::select! {
            biased;
            _ = slow_close.cancelled() => {
                need_close = true;
                break;
            }
            msg = outbound_rx.recv() => match msg {
                Some(m) => m,
                None => break, // all senders dropped / session tearing down
            },
        };
        let json = match serde_json::to_string(&msg) {
            Ok(j) => j,
            Err(_) => continue,
        };
        // Race the socket send against slow-close: the writer may be stuck
        // here when the queue fills behind it.
        tokio::select! {
            biased;
            _ = slow_close.cancelled() => {
                need_close = true;
                break;
            }
            res = ws_tx.send(axum::extract::ws::Message::Text(json)) => {
                if res.is_err() {
                    break;
                }
            }
        }
    }
    if need_close {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            ws_tx.send(slow_consumer_close_message()),
        )
        .await;
    }
}

/// Core WebSocket connection lifecycle.
async fn handle_ws_connection(
    socket: axum::extract::ws::WebSocket,
    state: Arc<AppState>,
    direct_mode: bool,
    direct_backfill: Option<usize>,
) {
    use axum::extract::ws::Message;
    use futures::StreamExt as FutStreamExt;

    let session_id = uuid::Uuid::new_v4().to_string();
    let (mut ws_tx, mut ws_rx) = socket.split();
    // WS1.1: bounded outbound queue (was the only unbounded channel in
    // production). A stalled local reader plus a remote flood can no longer
    // grow daemon memory without bound.
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<WsOutbound>(WS_OUTBOUND_CAPACITY);
    // Per-session slow-consumer close token. A DM/keepalive feeder that hits a
    // Full outbound queue cancels this token; the writer then sends a WS
    // Close(1013) and the reader loop breaks so teardown runs.
    let slow_close = tokio_util::sync::CancellationToken::new();
    // Count-once guard: DM and keepalive feeders may both observe Full in the
    // same window; only the first should count a slow-consumer close.
    let slow_close_counted = Arc::new(AtomicBool::new(false));
    let stats = Arc::clone(&state.ws_outbound_stats);

    // Register session
    let session = WsSession {
        id: session_id.clone(),
        subscribed_topics: HashSet::new(),
        receives_direct: direct_mode,
        topic_forwarders: HashMap::new(),
    };
    state
        .ws_sessions
        .write()
        .await
        .insert(session_id.clone(), session);

    tracing::info!(session_id = %session_id, direct_mode, "WebSocket session opened");

    // Send "connected" frame (control frame: drop-on-full, never close).
    let agent_id = hex::encode(state.agent.agent_id().as_bytes());
    feed_droppable(
        &outbound_tx,
        WsOutbound::Connected {
            session_id: session_id.clone(),
            agent_id,
        },
        &stats,
    );

    // Spawn writer task: outbound_rx → ws_tx. Races BOTH the frame arrival and
    // each socket send against the slow-consumer token — the writer may be
    // blocked in `ws_tx.send()` flushing to a stalled socket when the queue
    // fills behind it, so the token must interrupt the send too, not just the
    // recv. On slow-close it sends a WS Close(1013) with a short flush timeout,
    // then exits even if the close frame cannot flush (the reader is stalled).
    let writer_session_id = session_id.clone();
    let writer_slow_close = slow_close.clone();
    let mut writer = tokio::spawn(async move {
        run_ws_writer(&mut outbound_rx, &mut ws_tx, &writer_slow_close).await;
        tracing::debug!(session_id = %writer_session_id, "WebSocket writer stopped");
    });

    // If direct mode, spawn a forwarder for direct messages
    let direct_handle = if direct_mode {
        // Live tap FIRST (ADR-0023 seam rule), then the optional stored
        // backfill, then the `live` marker, then the live forwarder.
        let mut direct_rx = state.agent.subscribe_direct();
        let mut dm_backfill_hashes: Option<std::collections::HashSet<[u8; 32]>> = None;
        if let Some(limit) = direct_backfill {
            if let Some(history) = state.agent.history() {
                let store = Arc::clone(history.store());
                let q = crate::history::HistoryQuery {
                    scope_kind: Some(crate::history::Scope::Dm(String::new()).kind()),
                    limit,
                    ..Default::default()
                };
                match tokio::task::spawn_blocking(move || store.query(&q)).await {
                    Ok(Ok(mut rows)) => {
                        rows.reverse(); // newest-first → oldest-first replay
                        let mut hashes = std::collections::HashSet::new();
                        for row in &rows {
                            let r = &row.record;
                            hashes.insert(*blake3::hash(&r.payload).as_bytes());
                            let out = WsOutbound::DirectMessage {
                                sender: r.author_agent.clone().unwrap_or_default(),
                                machine_id: r.author_machine.clone().unwrap_or_default(),
                                payload: BASE64.encode(&r.payload),
                                received_at: u64::try_from(r.seen_at_ms).unwrap_or_default(),
                                verified: matches!(
                                    r.provenance,
                                    crate::history::Provenance::VerifiedEnvelope
                                ),
                                trust_decision: None,
                                observed_origin: None,
                            };
                            // Backfill frames are droppable: the store still
                            // holds them and `/history` can re-serve them.
                            if !feed_droppable(&outbound_tx, out, &stats) {
                                break;
                            }
                        }
                        dm_backfill_hashes = Some(hashes);
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(session_id = %session_id, "direct WS backfill query failed: {e}");
                    }
                    Err(e) => {
                        tracing::warn!(session_id = %session_id, "direct WS backfill join failed: {e}");
                    }
                }
            }
            // Marker is unconditional once backfill was requested.
            feed_droppable(
                &outbound_tx,
                WsOutbound::Live {
                    topic: "direct".to_string(),
                },
                &stats,
            );
        }
        let tx = outbound_tx.clone();
        let sid = session_id.clone();
        let dm_stats = Arc::clone(&stats);
        let dm_slow_close = slow_close.clone();
        let dm_counted = Arc::clone(&slow_close_counted);
        Some(tokio::spawn(async move {
            let mut dedupe = dm_backfill_hashes;
            while let Some(msg) = direct_rx.recv().await {
                if let Some(set) = dedupe.as_mut() {
                    let h = *blake3::hash(&msg.payload).as_bytes();
                    if set.remove(&h) {
                        if set.is_empty() {
                            dedupe = None;
                        }
                        continue;
                    }
                    dedupe = None;
                }
                let out = WsOutbound::DirectMessage {
                    sender: hex::encode(msg.sender.as_bytes()),
                    machine_id: hex::encode(msg.machine_id.as_bytes()),
                    payload: BASE64.encode(&msg.payload),
                    received_at: msg.received_at,
                    verified: msg.verified,
                    trust_decision: msg.trust_decision.map(|d| d.to_string()),
                    observed_origin: msg.observed_origin,
                };
                // DMs are fire-and-forget (DirectSubscriberQueue, drop-oldest,
                // 8192 deep — no retaining inbox behind subscribe_direct), so a
                // full outbound queue means the reader is stalled: close 1013.
                if !feed_critical(&tx, out, &dm_stats, &dm_slow_close, &dm_counted) {
                    break;
                }
            }
            tracing::debug!(session_id = %sid, "Direct message forwarder stopped");
        }))
    } else {
        None
    };

    // Spawn keepalive pinger (30s interval). The keepalive is the reliable
    // slow-consumer detector: every interval it tries to enqueue a Pong and,
    // on a Full queue, closes the session — so a stalled reader is closed
    // within ~one interval regardless of topic/DM flow.
    let keepalive_tx = outbound_tx.clone();
    let ka_stats = Arc::clone(&stats);
    let ka_slow_close = slow_close.clone();
    let ka_counted = Arc::clone(&slow_close_counted);
    let keepalive = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if !feed_critical(
                &keepalive_tx,
                WsOutbound::Pong,
                &ka_stats,
                &ka_slow_close,
                &ka_counted,
            ) {
                break;
            }
        }
    });

    // Reader loop: ws_rx → dispatch commands
    let mut shutdown_rx = state.shutdown_notify.subscribe();
    let reader_slow_close = slow_close.clone();
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                tracing::info!(session_id = %session_id, "Closing WebSocket session due to daemon shutdown");
                break;
            }
            _ = reader_slow_close.cancelled() => {
                tracing::info!(
                    session_id = %session_id,
                    "Closing WebSocket session: slow consumer (outbound queue saturated)"
                );
                break;
            }
            maybe_msg = futures::StreamExt::next(&mut ws_rx) => {
                let Some(Ok(msg)) = maybe_msg else {
                    break;
                };
                match msg {
                    Message::Text(text) => {
                        handle_ws_command(&state, &session_id, &text, &outbound_tx, &stats).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    // Cleanup: remove session, abort per-session forwarders
    let subscribed_topics =
        if let Some(session) = state.ws_sessions.write().await.remove(&session_id) {
            let mut subscribed_topics = session.subscribed_topics;
            for (topic, handle) in session.topic_forwarders {
                subscribed_topics.insert(topic);
                handle.abort();
            }
            subscribed_topics
        } else {
            HashSet::new()
        };

    // Clean up shared subscriptions for topics where this was the last WS subscriber
    for topic in &subscribed_topics {
        cleanup_ws_topic_if_empty(&state, topic, &session_id).await;
    }

    // Retire the feeders and drop the last outbound sender so the writer can
    // observe channel closure and exit on its own.
    keepalive.abort();
    if let Some(h) = direct_handle {
        h.abort();
    }
    drop(outbound_tx);
    // Give the writer a bounded grace period instead of aborting it outright:
    // on a slow-consumer close it is inside its 2s Close(1013) flush budget,
    // and an immediate abort tears the socket down before the documented
    // close frame can ever reach the (possibly now-draining) client — the
    // #149 stalled-reader harness observed a raw connection reset instead of
    // the 1013. Any other writer exits promptly once the senders are gone.
    let _ = tokio::time::timeout(Duration::from_secs(3), &mut writer).await;
    writer.abort();

    tracing::info!(session_id = %session_id, "WebSocket session closed");
}

/// Remove a session from a shared topic subscription; clean up if last subscriber.
async fn cleanup_ws_topic_if_empty(state: &AppState, topic: &str, session_id: &str) {
    let mut ws_topics = state.ws_topics.write().await;
    let should_remove = if let Some(ts) = ws_topics.get_mut(topic) {
        ts.subscribers.remove(session_id);
        ts.subscribers.is_empty()
    } else {
        false
    };
    if should_remove {
        if let Some(ts) = ws_topics.remove(topic) {
            ts.forwarder.abort();
            tracing::debug!(
                topic,
                "Cleaned up shared WS subscription (last subscriber left)"
            );
        }
    }
}

/// Dispatch an inbound WebSocket JSON command.
async fn handle_ws_command(
    state: &AppState,
    session_id: &str,
    text: &str,
    tx: &mpsc::Sender<WsOutbound>,
    stats: &WsOutboundStats,
) {
    let cmd: WsInbound = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            feed_droppable(
                tx,
                WsOutbound::Error {
                    message: format!("invalid command: {e}"),
                },
                stats,
            );
            return;
        }
    };

    match cmd {
        WsInbound::Ping => {
            feed_droppable(tx, WsOutbound::Pong, stats);
        }

        WsInbound::Subscribe { topics, backfill } => {
            // Shared fan-out: one gossip subscription per topic, broadcast to all WS sessions
            let mut handles = Vec::new();
            let already_subscribed = {
                let sessions = state.ws_sessions.read().await;
                let Some(session) = sessions.get(session_id) else {
                    return;
                };
                session.subscribed_topics.clone()
            };
            let mut requested_topics = HashSet::new();
            const MAX_WS_TOPICS_PER_SESSION: usize = 64;
            for topic in &topics {
                // #195: per-session topic cap — an authenticated client could
                // otherwise spawn an unbounded number of per-topic forwarder
                // tasks (one gossip sub + broadcast + forward task each).
                if already_subscribed.len() + requested_topics.len() >= MAX_WS_TOPICS_PER_SESSION {
                    tracing::warn!(
                        target: "x0x::ws",
                        cap = MAX_WS_TOPICS_PER_SESSION,
                        "WS Subscribe per-session topic cap reached — ignoring further topics"
                    );
                    break;
                }
                if !requested_topics.insert(topic.clone()) || already_subscribed.contains(topic) {
                    continue;
                }

                let broadcast_rx = {
                    let mut ws_topics = state.ws_topics.write().await;
                    if let Some(ts) = ws_topics.get_mut(topic) {
                        // Existing shared channel — just subscribe and track
                        ts.subscribers.insert(session_id.to_string());
                        ts.channel.subscribe()
                    } else {
                        // First WS subscriber — create gossip sub + broadcast + forwarder
                        let (broadcast_tx, broadcast_rx) = broadcast::channel::<WsOutbound>(256);
                        let mut subscribers = HashSet::new();
                        subscribers.insert(session_id.to_string());

                        let forwarder =
                            if let Ok(mut gossip_sub) = state.agent.subscribe(topic).await {
                                let btx = broadcast_tx.clone();
                                let topic_clone = topic.clone();
                                tokio::spawn(async move {
                                    while let Some(msg) = gossip_sub.recv().await {
                                        let out = WsOutbound::Message {
                                            topic: topic_clone.clone(),
                                            payload: BASE64.encode(&msg.payload),
                                            origin: msg.sender.map(|s| hex::encode(s.as_bytes())),
                                        };
                                        let _ = btx.send(out);
                                    }
                                })
                            } else {
                                tokio::spawn(async {}) // no-op if subscribe failed
                            };

                        ws_topics.insert(
                            topic.clone(),
                            SharedTopicState {
                                channel: broadcast_tx,
                                subscribers,
                                forwarder,
                            },
                        );
                        broadcast_rx
                    }
                };

                // ADR-0023 backfill-then-live: the live tap (broadcast_rx,
                // obtained ABOVE) is established before the store query runs
                // — the seam rule. Stored frames are fed first, then the
                // `live` marker; frames that raced into the broadcast buffer
                // during the query are deduped by payload hash below.
                let mut backfill_hashes: Option<std::collections::HashSet<[u8; 32]>> = None;
                if let Some(spec) = backfill.as_ref() {
                    if let Some(history) = state.agent.history() {
                        let store = Arc::clone(history.store());
                        let q = crate::history::HistoryQuery {
                            scope: Some(crate::history::Scope::Topic(topic.clone())),
                            limit: spec.limit,
                            ..Default::default()
                        };
                        match tokio::task::spawn_blocking(move || store.query(&q)).await {
                            Ok(Ok(mut rows)) => {
                                // query returns newest-first; emit oldest-first.
                                rows.reverse();
                                let mut hashes = std::collections::HashSet::new();
                                for row in &rows {
                                    let r = &row.record;
                                    hashes.insert(*blake3::hash(&r.payload).as_bytes());
                                    let out = WsOutbound::Message {
                                        topic: topic.clone(),
                                        payload: BASE64.encode(&r.payload),
                                        origin: r.author_agent.clone(),
                                    };
                                    if !feed_droppable(tx, out, stats) {
                                        break;
                                    }
                                }
                                backfill_hashes = Some(hashes);
                            }
                            Ok(Err(e)) => {
                                tracing::warn!(topic = %topic, "WS backfill query failed: {e}");
                            }
                            Err(e) => {
                                tracing::warn!(topic = %topic, "WS backfill join failed: {e}");
                            }
                        }
                    }
                    // The marker is emitted even when the store is disabled
                    // or empty so clients can rely on its presence whenever
                    // they requested backfill.
                    feed_droppable(
                        tx,
                        WsOutbound::Live {
                            topic: topic.clone(),
                        },
                        stats,
                    );
                }

                // Per-session forwarder: broadcast channel → session outbound
                let tx_clone = tx.clone();
                let fwd_stats = Arc::clone(&state.ws_outbound_stats);
                let handle = tokio::spawn(async move {
                    let mut rx = broadcast_rx;
                    // Dedupe frames already delivered by backfill: drop live
                    // frames whose payload hash matches a backfilled row,
                    // each at most once; stop checking on first miss (the
                    // stream has passed the backfill horizon).
                    let mut dedupe = backfill_hashes;
                    loop {
                        match rx.recv().await {
                            Ok(msg) => {
                                if let Some(set) = dedupe.as_mut() {
                                    if let WsOutbound::Message { payload, .. } = &msg {
                                        match BASE64.decode(payload) {
                                            Ok(bytes) => {
                                                let h = *blake3::hash(&bytes).as_bytes();
                                                if set.remove(&h) {
                                                    if set.is_empty() {
                                                        dedupe = None;
                                                    }
                                                    continue;
                                                }
                                                dedupe = None;
                                            }
                                            Err(_) => {
                                                dedupe = None;
                                            }
                                        }
                                    }
                                }
                                // Topic frames are droppable on a full queue
                                // (re-obtainable via gossip); never close.
                                if !feed_droppable(&tx_clone, msg, &fwd_stats) {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!("WS session lagged, skipped {n} messages");
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
                handles.push((topic.clone(), handle));
            }

            // Store handles in session for cleanup
            let mut orphaned_handles = Vec::new();
            {
                let mut sessions = state.ws_sessions.write().await;
                if let Some(session) = sessions.get_mut(session_id) {
                    for (topic, handle) in handles {
                        session.subscribed_topics.insert(topic.clone());
                        if let Some(previous) = session.topic_forwarders.insert(topic, handle) {
                            previous.abort();
                        }
                    }
                } else {
                    orphaned_handles = handles;
                }
            }
            for (topic, handle) in orphaned_handles {
                handle.abort();
                cleanup_ws_topic_if_empty(state, &topic, session_id).await;
            }

            feed_droppable(tx, WsOutbound::Subscribed { topics }, stats);
        }

        WsInbound::Unsubscribe { topics } => {
            let mut handles = Vec::new();
            let mut topics_to_cleanup = Vec::new();
            if let Some(session) = state.ws_sessions.write().await.get_mut(session_id) {
                let mut requested_topics = HashSet::new();
                for t in &topics {
                    if !requested_topics.insert(t.clone()) {
                        continue;
                    }
                    let removed_subscription = session.subscribed_topics.remove(t);
                    if let Some(handle) = session.topic_forwarders.remove(t) {
                        handles.push(handle);
                        topics_to_cleanup.push(t.clone());
                    } else if removed_subscription {
                        topics_to_cleanup.push(t.clone());
                    }
                }
            }
            for handle in handles {
                handle.abort();
            }
            for topic in &topics_to_cleanup {
                cleanup_ws_topic_if_empty(state, topic, session_id).await;
            }
            feed_droppable(tx, WsOutbound::Unsubscribed { topics }, stats);
        }

        WsInbound::Publish { topic, payload } => {
            let bytes = match decode_base64_payload(&payload) {
                Ok(b) => b,
                Err(_) => {
                    feed_droppable(
                        tx,
                        WsOutbound::Error {
                            message: "invalid base64 in payload".to_string(),
                        },
                        stats,
                    );
                    return;
                }
            };

            if let Err(e) = state.agent.publish(&topic, bytes).await {
                tracing::error!("ws publish failed: {e}");
                feed_droppable(
                    tx,
                    WsOutbound::Error {
                        message: "publish failed".to_string(),
                    },
                    stats,
                );
            }
        }

        WsInbound::SendDirect { agent_id, payload } => {
            let aid = match parse_agent_id_hex(&agent_id) {
                Ok(id) => id,
                Err(e) => {
                    feed_droppable(tx, WsOutbound::Error { message: e }, stats);
                    return;
                }
            };

            // Trust check — reject blocked agents (matches REST /direct/send behavior)
            {
                let contacts = state.contacts.read().await;
                if let Some(contact) = contacts.get(&aid) {
                    if contact.trust_level == TrustLevel::Blocked {
                        feed_droppable(
                            tx,
                            WsOutbound::Error {
                                message: "agent is blocked".to_string(),
                            },
                            stats,
                        );
                        return;
                    }
                }
            }

            let bytes = match decode_base64_payload(&payload) {
                Ok(b) => b,
                Err(_) => {
                    feed_droppable(
                        tx,
                        WsOutbound::Error {
                            message: "invalid base64 in payload".to_string(),
                        },
                        stats,
                    );
                    return;
                }
            };

            if let Err(e) = state
                .agent
                .send_direct_with_config(&aid, bytes, direct_message_send_config())
                .await
            {
                tracing::error!("ws send_direct failed: {e}");
                feed_droppable(
                    tx,
                    WsOutbound::Error {
                        message: "send failed".to_string(),
                    },
                    stats,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Embedded GUI
// ---------------------------------------------------------------------------

/// The embedded GUI HTML, compiled into the binary.
const GUI_HTML: &str = include_str!("../gui/x0x-gui.html");

/// GET /gui — serve the embedded GUI shell.
pub(super) async fn serve_gui() -> impl IntoResponse {
    axum::response::Html(render_gui_html())
}

fn render_gui_html() -> String {
    GUI_HTML.replace("<!-- X0X_TOKEN_INJECTION_POINT -->", "")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // #122 / WS1.1 — WS outbound queue feeder-policy unit tests.
    //
    // The bounded-queue drop-vs-close decision is pure over the channel +
    // counters, so it is fully deterministic and daemon-free. These are the
    // CI-gating regression net for the slow-consumer policy.
    // ========================================================================

    #[tokio::test]
    async fn feed_droppable_sends_and_keeps_feeder_alive_when_room() {
        let (tx, mut rx) = mpsc::channel::<WsOutbound>(4);
        let stats = WsOutboundStats::default();
        assert!(
            feed_droppable(&tx, WsOutbound::Pong, &stats),
            "feeder must continue when the queue has room"
        );
        assert!(rx.recv().await.is_some(), "frame must actually be enqueued");
        assert_eq!(
            stats.ws_outbound_dropped.load(Ordering::Relaxed),
            0,
            "nothing dropped when there is room"
        );
    }

    #[tokio::test]
    async fn feed_droppable_drops_and_counts_when_full() {
        // Capacity 1: fill it, then the next droppable frame must be dropped +
        // counted, and the feeder must stay alive (topic data is re-obtainable).
        let (tx, _rx) = mpsc::channel::<WsOutbound>(1);
        let stats = WsOutboundStats::default();
        assert!(feed_droppable(&tx, WsOutbound::Pong, &stats)); // fills the slot
        assert!(
            feed_droppable(&tx, WsOutbound::Pong, &stats),
            "droppable feeder must stay alive on a full queue (drop, don't close)"
        );
        assert_eq!(
            stats.ws_outbound_dropped.load(Ordering::Relaxed),
            1,
            "the dropped frame must be counted"
        );
    }

    // ========================================================================
    // Issue #120 — WS `direct_message` observed-origin serialization.
    // ========================================================================

    fn ws_dm_frame(observed_origin: Option<crate::connectivity::ObservedOrigin>) -> WsOutbound {
        WsOutbound::DirectMessage {
            sender: hex::encode([0x8a; 32]),
            machine_id: hex::encode([0xb2; 32]),
            payload: "aGVsbG8=".to_string(),
            received_at: 1_774_860_000,
            verified: true,
            trust_decision: None,
            observed_origin,
        }
    }

    #[test]
    fn ws_direct_message_frame_is_byte_identical_without_origin() {
        // Issue #120 acceptance: default-off (no token) wire bytes are
        // identical to the pre-#120 frame — no `observed_origin` key, not
        // even as null.
        let s = serde_json::to_string(&ws_dm_frame(None)).expect("serialize frame");
        assert!(
            !s.contains("observed_origin"),
            "absent token must not serialize: {s}"
        );
        assert_eq!(
            s,
            format!(
                "{{\"type\":\"direct_message\",\"sender\":\"{}\",\"machine_id\":\"{}\",\"payload\":\"aGVsbG8=\",\"received_at\":1774860000,\"verified\":true,\"trust_decision\":null}}",
                hex::encode([0x8a; 32]),
                hex::encode([0xb2; 32]),
            )
        );
    }

    #[test]
    fn ws_direct_message_frame_carries_masked_origin_when_present() {
        // Opted-in nodes emit the masked token; relayed => direct=false,
        // CGNAT => cgnat=true.
        let origin = crate::connectivity::ObservedOrigin {
            observed_prefix: "2001:db8::/48".to_string(),
            direct: false,
            cgnat: true,
        };
        let v = serde_json::to_value(ws_dm_frame(Some(origin))).expect("serialize frame");
        assert_eq!(
            v["observed_origin"],
            serde_json::json!({
                "observed_prefix": "2001:db8::/48",
                "direct": false,
                "cgnat": true
            })
        );
        assert_eq!(v["type"], "direct_message");
        assert_eq!(v["payload"], "aGVsbG8=");
    }

    #[tokio::test]
    async fn feed_droppable_stops_without_counting_when_closed() {
        let (tx, rx) = mpsc::channel::<WsOutbound>(4);
        let stats = WsOutboundStats::default();
        drop(rx); // close the channel
        assert!(
            !feed_droppable(&tx, WsOutbound::Pong, &stats),
            "feeder must stop when the channel has closed"
        );
        assert_eq!(
            stats.ws_outbound_dropped.load(Ordering::Relaxed),
            0,
            "a closed channel is not a drop and must not be counted"
        );
    }

    #[tokio::test]
    async fn feed_critical_sends_and_keeps_feeder_alive_when_room() {
        let (tx, mut rx) = mpsc::channel::<WsOutbound>(4);
        let stats = WsOutboundStats::default();
        let slow_close = tokio_util::sync::CancellationToken::new();
        let counted = Arc::new(AtomicBool::new(false));
        assert!(
            feed_critical(&tx, WsOutbound::Pong, &stats, &slow_close, &counted),
            "feeder must continue when the queue has room"
        );
        assert!(rx.recv().await.is_some());
        assert!(
            !slow_close.is_cancelled(),
            "must not close on a healthy queue"
        );
        assert_eq!(stats.ws_slow_consumer_closes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn feed_critical_closes_slow_consumer_and_counts_once_on_full() {
        // A full queue on the critical (DM/keepalive) path means the reader is
        // stalled: cancel the slow-close token, count once, and stop the feeder.
        let (tx, _rx) = mpsc::channel::<WsOutbound>(1);
        let stats = WsOutboundStats::default();
        let slow_close = tokio_util::sync::CancellationToken::new();
        let counted = Arc::new(AtomicBool::new(false));
        assert!(feed_critical(
            &tx,
            WsOutbound::Pong,
            &stats,
            &slow_close,
            &counted
        ));
        assert!(
            !feed_critical(&tx, WsOutbound::Pong, &stats, &slow_close, &counted),
            "critical feeder must stop on a full queue (close the session)"
        );
        assert!(
            slow_close.is_cancelled(),
            "slow-close token must fire when the critical path hits a full queue"
        );
        assert_eq!(
            stats.ws_slow_consumer_closes.load(Ordering::Relaxed),
            1,
            "a slow-consumer close must be counted exactly once"
        );
        assert!(
            counted.load(Ordering::SeqCst),
            "the count-once guard must be set after the first full"
        );
    }

    #[tokio::test]
    async fn feed_critical_counts_at_most_once_across_racing_feeders() {
        // DM and keepalive feeders may both observe Full in the same window.
        // The second feeder to hit Full must NOT double-count the close.
        let (tx, _rx) = mpsc::channel::<WsOutbound>(1);
        let stats = WsOutboundStats::default();
        let slow_close = tokio_util::sync::CancellationToken::new();
        let counted = Arc::new(AtomicBool::new(false));
        // First critical fills the slot.
        assert!(feed_critical(
            &tx,
            WsOutbound::Pong,
            &stats,
            &slow_close,
            &counted
        ));
        // Second observes Full -> counts + cancels.
        assert!(!feed_critical(
            &tx,
            WsOutbound::Pong,
            &stats,
            &slow_close,
            &counted
        ));
        // Third (a racing feeder re-checking) must NOT increment again even
        // though the queue is still full — the guard already fired.
        assert!(!feed_critical(
            &tx,
            WsOutbound::Pong,
            &stats,
            &slow_close,
            &counted
        ));
        assert_eq!(
            stats.ws_slow_consumer_closes.load(Ordering::Relaxed),
            1,
            "concurrent DM+keepalive Full must count the close exactly once"
        );
    }

    #[tokio::test]
    async fn feed_critical_stops_without_counting_when_closed() {
        // A closed channel is a normal teardown (writer dropped the receiver),
        // NOT a slow consumer — must not count a slow-consumer close.
        let (tx, rx) = mpsc::channel::<WsOutbound>(4);
        let stats = WsOutboundStats::default();
        let slow_close = tokio_util::sync::CancellationToken::new();
        let counted = Arc::new(AtomicBool::new(false));
        drop(rx);
        assert!(
            !feed_critical(&tx, WsOutbound::Pong, &stats, &slow_close, &counted),
            "feeder must stop when the channel has closed"
        );
        assert!(
            !slow_close.is_cancelled(),
            "a closed channel must not trigger a slow-consumer close"
        );
        assert_eq!(
            stats.ws_slow_consumer_closes.load(Ordering::Relaxed),
            0,
            "a closed channel must not be counted as a slow-consumer close"
        );
    }

    #[test]
    fn slow_consumer_close_message_is_code_1013() {
        // The close payload is pure; pin that the writer sends 1013 ("try again
        // later") with the documented reason, not a generic 1011/1000.
        match slow_consumer_close_message() {
            axum::extract::ws::Message::Close(Some(frame)) => {
                assert_eq!(
                    frame.code, WS_SLOW_CONSUMER_CLOSE_CODE,
                    "close code must be 1013 (try again later)"
                );
                assert_eq!(
                    frame.reason.as_ref(),
                    WS_SLOW_CONSUMER_CLOSE_REASON,
                    "close reason must be the documented slow-consumer string"
                );
            }
            other => panic!("expected a Close(Some(..)) frame, got {other:?}"),
        }
    }

    #[test]
    fn ws_diagnostics_payload_exposes_capacity_and_counters() {
        // The /diagnostics/ws payload is built from the live atomics; pin the
        // counter field mapping so a drop and a close both surface correctly.
        let stats = WsOutboundStats::default();
        stats.ws_outbound_dropped.fetch_add(7, Ordering::Relaxed);
        stats
            .ws_slow_consumer_closes
            .fetch_add(3, Ordering::Relaxed);
        let payload = ws_diagnostics_payload(&stats);
        assert_eq!(payload["ok"], true);
        assert_eq!(
            payload["ws_outbound_capacity"],
            serde_json::json!(WS_OUTBOUND_CAPACITY)
        );
        assert_eq!(payload["ws_outbound_dropped"], 7);
        assert_eq!(payload["ws_slow_consumer_closes"], 3);
    }

    // ========================================================================
    // #122 / WS1.1 — writer-loop slow-close behavior (deterministic).
    //
    // The writer loop is extracted into `run_ws_writer`, generic over
    // `Sink<Message>`, so its slow-consumer close behavior is unit-testable
    // with a fake sink — no real socket or daemon required. The literal
    // OS/TCP stalled-reader integration was found not viable (the multi-layer
    // gossip->broadcast->outbound->TCP buffering prevents the mpsc queue from
    // filling via any external flood; see PR body), so these deterministic
    // tests are the CI-gating coverage for the writer.
    // ========================================================================

    /// A fake `Sink<Message>` for writer-loop tests: records every frame and
    /// can be made to stall (return `Pending`) on Text frames, simulating a
    /// stalled socket the writer is blocked flushing to.
    #[derive(Default)]
    struct TestSink {
        sent: Vec<axum::extract::ws::Message>,
        /// When true, flushing a Text frame never completes (simulates a
        /// stalled socket write). Close frames still flush.
        block_text: bool,
    }

    impl futures::Sink<axum::extract::ws::Message> for TestSink {
        type Error = std::convert::Infallible;
        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn start_send(
            self: std::pin::Pin<&mut Self>,
            msg: axum::extract::ws::Message,
        ) -> Result<(), Self::Error> {
            // TestSink is Unpin (all fields Unpin), so get_mut is sound.
            self.get_mut().sent.push(msg);
            Ok(())
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            let this = self.get_mut();
            let last_is_text = this
                .sent
                .last()
                .map(|m| matches!(m, axum::extract::ws::Message::Text(_)))
                .unwrap_or(false);
            if this.block_text && last_is_text {
                // Stalled: the Text frame cannot flush (client not reading).
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(Ok(()))
            }
        }
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.poll_flush(cx)
        }
    }

    /// On slow-close during idle (nothing to flush), the writer must send a
    /// Close(1013) and exit promptly — never hang.
    #[tokio::test]
    async fn run_ws_writer_sends_close_1013_on_slow_close_during_idle() {
        let (_tx, mut rx) = mpsc::channel::<WsOutbound>(4);
        let mut sink = TestSink {
            block_text: false,
            ..Default::default()
        };
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let exited = tokio::time::timeout(
            Duration::from_secs(2),
            run_ws_writer(&mut rx, &mut sink, &token),
        )
        .await
        .is_ok();
        assert!(exited, "writer must exit promptly on slow-close, not hang");
        assert!(
            sink.sent.iter().any(|m| matches!(
                m,
                axum::extract::ws::Message::Close(Some(f)) if f.code == WS_SLOW_CONSUMER_CLOSE_CODE
            )),
            "writer must send a Close(1013) on slow-close, got {:?}",
            sink.sent
        );
    }

    /// On slow-close while BLOCKED flushing a Text frame (stalled socket), the
    /// writer must abandon the in-flight send, attempt a Close(1013), and exit —
    /// proving the slow-close token interrupts an in-flight send, not just the
    /// recv. This is the case the literal integration test could not reproduce
    /// (the mpsc queue never fills via external flood).
    #[tokio::test]
    async fn run_ws_writer_abandons_blocked_send_and_closes_on_slow_close() {
        let (tx, mut rx) = mpsc::channel::<WsOutbound>(4);
        tx.send(WsOutbound::Pong).await.expect("enqueue frame");
        drop(tx);
        let mut sink = TestSink {
            block_text: true,
            ..Default::default()
        };
        let token = tokio_util::sync::CancellationToken::new();

        // Run the writer concurrently with a delayed cancel. The writer pulls
        // the frame, serializes to Text, and stalls in poll_flush. After a beat
        // the token cancels; the writer abandons the send, sends Close(1013),
        // and exits. (tokio::join! polls both on one task — no 'static needed.)
        let cancel_after = async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            token.cancel();
        };
        let exited = tokio::join!(
            async {
                tokio::time::timeout(
                    Duration::from_secs(3),
                    run_ws_writer(&mut rx, &mut sink, &token),
                )
                .await
            },
            cancel_after
        )
        .0
        .is_ok();
        assert!(
            exited,
            "writer must exit after slow-close even with a blocked send"
        );
        assert!(
            sink.sent
                .iter()
                .any(|m| matches!(m, axum::extract::ws::Message::Text(_))),
            "writer should have attempted the Text send (then stalled)"
        );
        assert!(
            sink.sent.iter().any(|m| matches!(
                m,
                axum::extract::ws::Message::Close(Some(f)) if f.code == WS_SLOW_CONSUMER_CLOSE_CODE
            )),
            "writer must attempt a Close(1013) after abandoning the blocked send"
        );
    }

    #[test]
    fn rendered_gui_does_not_disclose_api_token() {
        let html = render_gui_html();

        assert!(!html.contains("super-secret-api-token"));
        assert!(!html.contains("X0X_TOKEN"));
    }
}
