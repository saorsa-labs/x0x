//! WebSocket deep integration tests.
//!
//! Tests WebSocket connection lifecycle, pub/sub via WS, direct messaging,
//! session tracking, message ordering, and concurrent clients.
//!
//! All tests require a running x0xd daemon cluster.
//! Run with: cargo nextest run --test ws_integration -- --ignored
//!
//! Prerequisites: cargo build --release --bin x0xd

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

async fn daemon() -> DaemonFixture {
    DaemonFixture::start("ws-test").await
}

fn client_with_auth(d: &DaemonFixture) -> reqwest::Client {
    d.authed_client(Duration::from_secs(10))
}

// ---------------------------------------------------------------------------
// WebSocket helper
// ---------------------------------------------------------------------------

async fn ws_connect(
    d: &DaemonFixture,
    path: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let (ws, _) = tokio_tungstenite::connect_async(&d.ws_url(path).await)
        .await
        .expect("WS connect failed");
    ws
}

async fn ws_recv_text(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    timeout_secs: u64,
) -> Option<String> {
    let deadline = Duration::from_secs(timeout_secs);
    match tokio::time::timeout(deadline, ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => Some(t.to_string()),
        _ => None,
    }
}

async fn ws_send(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: &str,
) {
    ws.send(Message::Text(msg.into()))
        .await
        .expect("WS send failed");
}

async fn ws_subscribe_topic(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    topic: &str,
) {
    ws_send(
        ws,
        &format!(r#"{{"type":"subscribe","topics":["{topic}"]}}"#),
    )
    .await;

    for _ in 0..5 {
        let msg = ws_recv_text(ws, 5)
            .await
            .expect("should receive subscription confirmation");
        let frame: Value = serde_json::from_str(&msg).expect("parse subscription confirmation");
        match frame["type"].as_str() {
            Some("subscribed") => return,
            Some("pong") | Some("connected") => continue,
            _ => panic!("unexpected subscription frame: {msg}"),
        }
    }

    panic!("did not receive subscribed frame after subscribe command");
}

async fn ws_unsubscribe_topic(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    topic: &str,
) {
    ws_send(
        ws,
        &format!(r#"{{"type":"unsubscribe","topics":["{topic}"]}}"#),
    )
    .await;

    let mut confirmed = false;
    for _ in 0..5 {
        let Some(msg) = ws_recv_text(ws, 5).await else {
            break;
        };
        let Ok(frame) = serde_json::from_str::<Value>(&msg) else {
            continue;
        };
        match frame["type"].as_str() {
            Some("unsubscribed") => {
                confirmed = true;
                break;
            }
            Some("pong") | Some("connected") => continue,
            _ => {}
        }
    }

    assert!(confirmed, "did not receive unsubscribed frame");
}

async fn ws_recv_topic_message(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    topic: &str,
    timeout_secs: u64,
) -> Option<Value> {
    tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    let Ok(frame) = serde_json::from_str::<Value>(&text) else {
                        continue;
                    };
                    if frame["type"].as_str() == Some("message")
                        && frame["topic"].as_str() == Some(topic)
                    {
                        return Some(frame);
                    }
                }
                Some(Ok(_)) => {}
                _ => return None,
            }
        }
    })
    .await
    .unwrap_or(None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// WebSocket connection returns a "connected" message with session_id.
#[tokio::test]
#[ignore]
async fn ws_connection_lifecycle() {
    let d = daemon().await;
    let mut ws = ws_connect(&d, "/ws").await;

    let msg = ws_recv_text(&mut ws, 5)
        .await
        .expect("should receive connected msg");
    let frame: Value = serde_json::from_str(&msg).expect("parse JSON");
    assert_eq!(
        frame["type"], "connected",
        "first message should be 'connected'"
    );
    assert!(frame["session_id"].is_string(), "should have session_id");

    // Clean close
    ws.close(None).await.expect("close");
}

/// Ping-pong works.
#[tokio::test]
#[ignore]
async fn ws_ping_pong() {
    let d = daemon().await;
    let mut ws = ws_connect(&d, "/ws").await;

    // Consume connected message
    let _ = ws_recv_text(&mut ws, 5).await;

    // Send ping
    ws_send(&mut ws, r#"{"type":"ping"}"#).await;

    let msg = ws_recv_text(&mut ws, 5).await.expect("should receive pong");
    let frame: Value = serde_json::from_str(&msg).expect("parse JSON");
    assert_eq!(frame["type"], "pong");

    ws.close(None).await.expect("close");
}

/// Subscribe to a topic via WS, publish via REST, receive via WS.
#[tokio::test]
#[ignore]
async fn ws_subscribe_publish_receive() {
    let d = daemon().await;
    let client = client_with_auth(&d);
    let mut ws = ws_connect(&d, "/ws").await;

    // Consume connected message
    let _ = ws_recv_text(&mut ws, 5).await;

    // Subscribe via WS
    let topic = format!("ws-test-{}", rand::random::<u32>());
    ws_subscribe_topic(&mut ws, &topic).await;

    // Publish via REST
    let payload =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"hello-ws-test");
    let resp = client
        .post(d.url("/publish"))
        .json(&json!({"topic": topic, "payload": payload}))
        .send()
        .await
        .expect("publish");
    assert_eq!(resp.status(), 200);

    // Receive via WS
    let recv_msg = ws_recv_text(&mut ws, 10).await;
    assert!(
        recv_msg.is_some(),
        "should receive published message via WS"
    );

    ws.close(None).await.expect("close");
}

/// Unsubscribe removes only that session's topic forwarder; duplicate subscribe is idempotent.
#[tokio::test]
#[ignore]
async fn ws_unsubscribe_stops_forwarder_and_repeat_subscribe_is_idempotent() {
    let d = daemon().await;
    let client = client_with_auth(&d);
    let topic = format!("unsubscribe-test-{}", rand::random::<u32>());

    let mut unsubscribed = ws_connect(&d, "/ws").await;
    let _ = ws_recv_text(&mut unsubscribed, 5).await;
    ws_subscribe_topic(&mut unsubscribed, &topic).await;
    ws_subscribe_topic(&mut unsubscribed, &topic).await;

    let mut subscribed = ws_connect(&d, "/ws").await;
    let _ = ws_recv_text(&mut subscribed, 5).await;
    ws_subscribe_topic(&mut subscribed, &topic).await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let first_payload =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"first");
    let first_status = client
        .post(d.url("/publish"))
        .json(&json!({"topic": &topic, "payload": &first_payload}))
        .send()
        .await
        .ok()
        .map(|resp| resp.status().as_u16());
    assert_eq!(first_status, Some(200));

    let first = ws_recv_topic_message(&mut unsubscribed, &topic, 10).await;
    assert_eq!(
        first.as_ref().and_then(|frame| frame["payload"].as_str()),
        Some(first_payload.as_str())
    );
    assert!(
        ws_recv_topic_message(&mut unsubscribed, &topic, 1)
            .await
            .is_none(),
        "repeat subscribe delivered a duplicate message"
    );
    let _ = ws_recv_topic_message(&mut subscribed, &topic, 10).await;

    ws_unsubscribe_topic(&mut unsubscribed, &topic).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let second_payload =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"second");
    let second_status = client
        .post(d.url("/publish"))
        .json(&json!({"topic": &topic, "payload": &second_payload}))
        .send()
        .await
        .ok()
        .map(|resp| resp.status().as_u16());
    assert_eq!(second_status, Some(200));

    let second = ws_recv_topic_message(&mut subscribed, &topic, 10).await;
    assert_eq!(
        second.as_ref().and_then(|frame| frame["payload"].as_str()),
        Some(second_payload.as_str())
    );
    assert!(
        ws_recv_topic_message(&mut unsubscribed, &topic, 1)
            .await
            .is_none(),
        "unsubscribed session received a topic message"
    );

    unsubscribed.close(None).await.ok();
    subscribed.close(None).await.ok();
}

/// Session shows up in /ws/sessions while connected.
#[tokio::test]
#[ignore]
async fn ws_session_tracking() {
    let d = daemon().await;
    let client = client_with_auth(&d);

    // Get initial session count
    let initial: Value = client
        .get(d.url("/ws/sessions"))
        .send()
        .await
        .expect("sessions")
        .json()
        .await
        .expect("parse");

    let initial_count = initial
        .as_array()
        .or_else(|| initial["sessions"].as_array())
        .map_or(0, |a| a.len());

    // Connect WS
    let mut ws = ws_connect(&d, "/ws").await;
    let _ = ws_recv_text(&mut ws, 5).await;

    // Small delay for session registration
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check session count increased
    let after: Value = client
        .get(d.url("/ws/sessions"))
        .send()
        .await
        .expect("sessions")
        .json()
        .await
        .expect("parse");

    let after_count = after
        .as_array()
        .or_else(|| after["sessions"].as_array())
        .map_or(0, |a| a.len());

    assert!(
        after_count > initial_count,
        "session count should increase: before={initial_count}, after={after_count}"
    );

    // Close and verify cleanup
    ws.close(None).await.expect("close");
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let final_resp: Value = client
        .get(d.url("/ws/sessions"))
        .send()
        .await
        .expect("sessions")
        .json()
        .await
        .expect("parse");

    let final_count = final_resp
        .as_array()
        .or_else(|| final_resp["sessions"].as_array())
        .map_or(0, |a| a.len());

    assert!(
        final_count <= initial_count,
        "session count should decrease after close: initial={initial_count}, final={final_count}"
    );
}

/// WS without auth token is rejected.
#[tokio::test]
#[ignore]
async fn ws_requires_auth() {
    let d = daemon().await;
    // Connect without token
    let url = format!("ws://{}/ws", d.api_addr());
    let result = tokio_tungstenite::connect_async(&url).await;

    // Should either fail to connect, close immediately, or get an auth error frame.
    match result {
        Err(_) => {} // Expected — connection rejected
        Ok((mut ws, _)) => {
            let (rejected, observed) =
                match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                    Err(_) => (false, "no frame before timeout".to_string()),
                    Ok(None) => (true, "connection closed".to_string()),
                    Ok(Some(Err(err))) => (true, format!("read error: {err}")),
                    Ok(Some(Ok(Message::Close(_)))) => (true, "close frame".to_string()),
                    Ok(Some(Ok(Message::Text(text)))) => {
                        let frame = serde_json::from_str::<Value>(&text);
                        let is_error = matches!(
                            frame.as_ref().ok().and_then(|frame| frame["type"].as_str()),
                            Some("error")
                        );
                        (is_error, format!("text frame: {text}"))
                    }
                    Ok(Some(Ok(frame))) => (false, format!("non-error frame: {frame:?}")),
                };
            ws.close(None).await.ok();
            assert!(
                rejected,
                "unauthenticated websocket accepted connection without closing or sending an auth error: {observed}"
            );
        }
    }
}

/// Direct WebSocket endpoint receives direct messages.
#[tokio::test]
#[ignore]
async fn ws_direct_endpoint() {
    let d = daemon().await;
    let mut ws = ws_connect(&d, "/ws/direct").await;

    let msg = ws_recv_text(&mut ws, 5)
        .await
        .expect("should receive connected msg");
    let frame: Value = serde_json::from_str(&msg).expect("parse JSON");
    assert_eq!(
        frame["type"], "connected",
        "/ws/direct should send connected message"
    );

    ws.close(None).await.expect("close");
}

/// Multiple WS clients on same topic all receive messages.
#[tokio::test]
#[ignore]
async fn ws_concurrent_subscribers() {
    let d = daemon().await;
    let client = client_with_auth(&d);
    let topic = format!("concurrent-test-{}", rand::random::<u32>());
    let n_clients = 5;
    let n_messages = 3;

    // Connect N clients and subscribe to same topic
    let mut clients = Vec::new();
    for _ in 0..n_clients {
        let mut ws = ws_connect(&d, "/ws").await;
        let _ = ws_recv_text(&mut ws, 5).await; // consume connected
        ws_subscribe_topic(&mut ws, &topic).await;
        clients.push(ws);
    }

    // Small delay for subscriptions to propagate
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Publish N messages via REST
    let mut expected_payloads = Vec::new();
    for i in 0..n_messages {
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("msg-{i}").as_bytes(),
        );
        expected_payloads.push(payload.clone());
        client
            .post(d.url("/publish"))
            .json(&json!({"topic": &topic, "payload": payload}))
            .send()
            .await
            .expect("publish");
    }

    // Each client should receive all messages
    expected_payloads.sort();
    for (idx, ws) in clients.iter_mut().enumerate() {
        let mut received_payloads = Vec::new();
        for _ in 0..n_messages {
            let Some(frame) = ws_recv_topic_message(ws, &topic, 5).await else {
                break;
            };
            let payload = frame["payload"].as_str().map(str::to_owned);
            assert!(
                payload.is_some(),
                "Client {idx} received topic message without payload: {frame}"
            );
            if let Some(payload) = payload {
                received_payloads.push(payload);
            }
        }
        received_payloads.sort();
        assert_eq!(
            received_payloads, expected_payloads,
            "Client {idx} should receive all published payloads exactly once"
        );
        assert!(
            ws_recv_topic_message(ws, &topic, 1).await.is_none(),
            "Client {idx} received more than {n_messages} topic messages"
        );
    }

    // Clean up
    for mut ws in clients {
        ws.close(None).await.ok();
    }
}

/// Messages published in order arrive in order (FIFO per topic).
#[tokio::test]
#[ignore]
async fn ws_message_ordering() {
    let d = daemon().await;
    let client = client_with_auth(&d);
    let topic = format!("order-test-{}", rand::random::<u32>());

    let mut ws = ws_connect(&d, "/ws").await;
    let _ = ws_recv_text(&mut ws, 5).await; // connected
    ws_subscribe_topic(&mut ws, &topic).await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Publish messages with sequential payloads
    let n = 10;
    for i in 0..n {
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("seq-{i:04}").as_bytes(),
        );
        client
            .post(d.url("/publish"))
            .json(&json!({"topic": &topic, "payload": payload}))
            .send()
            .await
            .expect("publish");
    }

    let expected_payloads = (0..n).map(|i| format!("seq-{i:04}")).collect::<Vec<_>>();
    let mut received_payloads = Vec::with_capacity(n);
    for idx in 0..n {
        let Some(frame) = ws_recv_topic_message(&mut ws, &topic, 10).await else {
            break;
        };
        let decoded = frame["payload"]
            .as_str()
            .and_then(|payload| {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload).ok()
            })
            .and_then(|bytes| String::from_utf8(bytes).ok());
        assert!(
            decoded.is_some(),
            "ordered message {idx} should contain a base64 UTF-8 payload: {frame}"
        );
        if let Some(decoded) = decoded {
            received_payloads.push(decoded);
        }
    }

    assert_eq!(
        received_payloads, expected_payloads,
        "received payloads should match the published FIFO sequence"
    );
    assert!(
        ws_recv_topic_message(&mut ws, &topic, 1).await.is_none(),
        "received more than {n} ordered topic messages"
    );

    ws.close(None).await.expect("close");
}

// ---------------------------------------------------------------------------
// WS1.1 stalled-reader harness (#149, follow-up to #147 / #122)
// ---------------------------------------------------------------------------

/// Read the WS outbound counters from `GET /diagnostics/ws`.
async fn ws_outbound_counters(client: &reqwest::Client, d: &DaemonFixture) -> (u64, u64) {
    let v: Value = client
        .get(d.url("/diagnostics/ws"))
        .send()
        .await
        .expect("GET /diagnostics/ws")
        .json()
        .await
        .expect("parse /diagnostics/ws");
    (
        v["ws_outbound_dropped"]
            .as_u64()
            .expect("ws_outbound_dropped field"),
        v["ws_slow_consumer_closes"]
            .as_u64()
            .expect("ws_slow_consumer_closes field"),
    )
}

/// A local WS client that stops draining its socket must not grow daemon
/// memory without bound.
///
/// WHY: the per-session outbound queue is the daemon's only memory bound
/// against a misbehaving local client — one that completes the handshake,
/// subscribes, then never reads another frame while topic traffic keeps
/// flowing. PR #147 bounded the queue (`WS_OUTBOUND_CAPACITY=1024`) with two
/// feeder policies (topic frames drop-with-counter; DM/keepalive frames close
/// the session with WS 1013) and pinned both with unit tests against fakes.
/// This test is the deferred end-to-end leg (#149): it proves the policy
/// actually fires against a REAL stalled socket.
///
/// The documented obstacle (issue #149): no external frame flood can fill the
/// bounded queue on its own — the `gossip → broadcast(256) → outbound(1024) →
/// writer → TCP` pipeline absorbs any burst unless the writer itself is stuck
/// flushing to a stalled socket. So the harness uses a cooperating stalled
/// reader: `tokio-tungstenite` only reads from the TCP socket when the stream
/// is polled, so after subscribing the client simply never polls `ws.next()`.
/// The kernel recv buffer fills, the TCP window closes, the daemon's writer
/// blocks in `ws_tx.send()`, and the queue fills behind it.
///
/// End-to-end assertions:
/// 1. `ws_outbound_dropped` climbs (topic frames dropped on the Full queue);
/// 2. the 30s keepalive pinger — the reliable detector — closes the session,
///    incrementing `ws_slow_consumer_closes` exactly once, within a bounded
///    wall-clock window;
/// 3. once the client resumes draining, it receives the WS Close frame
///    carrying 1013 "Try Again Later" — the documented, client-visible
///    contract (this caught a real bug: session cleanup used to abort the
///    writer mid-flush, so the 1013 never reached the wire and clients only
///    ever saw a raw connection reset);
/// 4. the session is removed from `/ws/sessions` (resources reclaimed).
///
/// ~60-90s wall clock (dominated by the 30s keepalive cadence), hence the
/// `--ignored` integration tier.
#[tokio::test]
#[ignore]
async fn ws_stalled_reader_fills_queue_and_closes_1013() {
    let d = daemon().await;
    let client = client_with_auth(&d);
    let topic = format!("stall-test-{}", rand::random::<u32>());

    let mut ws = ws_connect(&d, "/ws").await;
    let connected = ws_recv_text(&mut ws, 5).await.expect("connected frame");
    let frame: Value = serde_json::from_str(&connected).expect("parse connected");
    let session_id = frame["session_id"]
        .as_str()
        .expect("session_id in connected frame")
        .to_string();
    ws_subscribe_topic(&mut ws, &topic).await;

    let (base_dropped, base_closes) = ws_outbound_counters(&client, &d).await;

    // ── STALL: from here on the client never polls `ws`, so nothing is read
    // from the socket. Large payloads (~22KB per frame after base64+JSON)
    // saturate the kernel buffers quickly so the writer blocks after a few
    // frames instead of a few thousand.
    let payload = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [b'x'; 16 * 1024],
    );

    // Publish until the per-session queue observes Full (drops counted).
    // Kernel buffers absorb a few frames and the mpsc holds 1024, so >1100
    // frames are needed; REST publishes run in concurrent waves because a
    // single serial publish round-trip is far too slow to beat the deadline.
    let fill_deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    let mut dropped = base_dropped;
    let mut published: u32 = 0;
    while dropped <= base_dropped {
        assert!(
            tokio::time::Instant::now() < fill_deadline,
            "outbound queue never filled: published {published} frames, \
             ws_outbound_dropped still {dropped} (baseline {base_dropped})"
        );
        let wave: Vec<_> = (0..64)
            .map(|_| {
                client
                    .post(d.url("/publish"))
                    .json(&json!({"topic": &topic, "payload": &payload}))
                    .send()
            })
            .collect();
        for resp in futures::future::join_all(wave).await {
            let resp = resp.expect("publish");
            assert_eq!(resp.status(), 200, "publish #{published} failed");
            published += 1;
        }
        (dropped, _) = ws_outbound_counters(&client, &d).await;
    }
    assert!(
        dropped > base_dropped,
        "ws_outbound_dropped must climb once the queue is full"
    );

    // ── The keepalive pinger (30s cadence) is the detector: its feed_critical
    // hits the Full queue and closes the session. Bounded window: one full
    // interval plus slack.
    let close_deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut closes = base_closes;
    while closes <= base_closes {
        assert!(
            tokio::time::Instant::now() < close_deadline,
            "slow-consumer close did not fire within 45s of queue saturation \
             (ws_slow_consumer_closes still {closes}, baseline {base_closes})"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        (_, closes) = ws_outbound_counters(&client, &d).await;
    }
    assert_eq!(
        closes,
        base_closes + 1,
        "slow-consumer close must be counted exactly once per session"
    );

    // ── Resume draining: the kernel-buffered backlog flushes first, then the
    // writer's Close(1013) (it holds a 2s flush budget and cleanup grants a
    // bounded grace period before aborting it, so the close frame reaches the
    // wire once the client drains — the client-visible contract).
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut close_code: Option<u16> = None;
    while tokio::time::Instant::now() < drain_deadline {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Close(close_frame)))) => {
                close_code = close_frame.as_ref().map(|f| u16::from(f.code));
                break;
            }
            Ok(Some(Ok(_))) => continue, // buffered backlog frames
            Ok(Some(Err(e))) => panic!(
                "stalled session must end with a Close(1013) frame, \
                 not an abrupt socket error: {e}"
            ),
            Ok(None) => panic!("stalled session must end with a Close(1013) frame, not EOF"),
            Err(_) => break, // stream open and quiet — deadline loop decides
        }
    }
    assert_eq!(
        close_code,
        Some(1013),
        "slow-consumer close must reach the client as WS 1013 Try Again Later"
    );
    eprintln!(
        "stalled reader: published={published} dropped={} close_code={close_code:?}",
        dropped - base_dropped
    );

    // ── The session must be gone from /ws/sessions (resources reclaimed).
    let sessions_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let v: Value = client
            .get(d.url("/ws/sessions"))
            .send()
            .await
            .expect("GET /ws/sessions")
            .json()
            .await
            .expect("parse /ws/sessions");
        let still_present = v["sessions"]
            .as_array()
            .expect("sessions array")
            .iter()
            .any(|s| s["session_id"].as_str() == Some(session_id.as_str()));
        if !still_present {
            break;
        }
        assert!(
            tokio::time::Instant::now() < sessions_deadline,
            "stalled session {session_id} still registered after slow-consumer close"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
