//! Tests for `local:` topic routing (issue #89).
//!
//! Topics prefixed `local:` are same-daemon IPC: delivered to subscribers
//! attached to the same x0xd instance, never gossipped to remote mesh
//! peers. These tests prove both halves — local delivery works through
//! the public daemon surfaces, and a connected remote peer subscribed to
//! the same topic name receives nothing.
//!
//! All tests are `#[ignore]` — they boot real x0xd daemons.
//! Run with: cargo nextest run --test local_topics -- --ignored
//! Before running: cargo build --release --bin x0xd

use base64::Engine;
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

#[path = "harness/src/cluster.rs"]
mod cluster;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(instance: &cluster::AgentInstance) -> Ws {
    let (ws, _) = tokio_tungstenite::connect_async(&instance.ws_url("/ws"))
        .await
        .expect("WS connect failed");
    ws
}

async fn ws_send(ws: &mut Ws, msg: &str) {
    ws.send(Message::Text(msg.into()))
        .await
        .expect("WS send failed");
}

async fn ws_recv_text(ws: &mut Ws, timeout_secs: u64) -> Option<String> {
    match tokio::time::timeout(Duration::from_secs(timeout_secs), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => Some(t.to_string()),
        _ => None,
    }
}

/// Subscribe to a topic over WS and wait for the confirmation frame.
async fn ws_subscribe(ws: &mut Ws, topic: &str) {
    ws_send(
        ws,
        &format!(r#"{{"type":"subscribe","topics":["{topic}"]}}"#),
    )
    .await;
    for _ in 0..5 {
        if let Some(frame) = ws_recv_text(ws, 5).await {
            let v: serde_json::Value = serde_json::from_str(&frame).unwrap_or_default();
            if v["type"] == "subscribed" {
                return;
            }
        }
    }
    panic!("did not receive subscribed confirmation for {topic}");
}

/// Wait until a WS frame mentioning `needle` arrives, or time out.
async fn ws_saw(ws: &mut Ws, needle: &str, timeout_secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        if let Some(frame) = ws_recv_text(ws, 2).await {
            if frame.contains(needle) {
                return true;
            }
        }
    }
    false
}

#[tokio::test]
#[ignore]
async fn local_topic_delivers_to_same_daemon_subscriber_only() {
    let pair = cluster::pair().await;
    let topic = "local:my-app/events";
    let marker = format!("local-marker-{}", rand::random::<u32>());
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(marker.as_bytes());

    // Both daemons subscribe to the SAME local: topic name.
    let mut alice_ws = ws_connect(&pair.alice).await;
    let mut bob_ws = ws_connect(&pair.bob).await;
    ws_subscribe(&mut alice_ws, topic).await;
    ws_subscribe(&mut bob_ws, topic).await;

    // Alice publishes on the local topic.
    let r = pair
        .alice
        .post(
            "/publish",
            serde_json::json!({ "topic": topic, "payload": payload_b64 }),
        )
        .await;
    assert!(r.status().is_success(), "publish on local: topic succeeds");

    // Alice's own subscriber receives it...
    assert!(
        ws_saw(&mut alice_ws, &payload_b64, 10).await,
        "same-daemon subscriber must receive the local: message"
    );

    // ...but Bob — a connected remote peer subscribed to the identical
    // topic name — must receive nothing: local: topics are never
    // gossipped (issue #89).
    assert!(
        !ws_saw(&mut bob_ws, &payload_b64, 8).await,
        "local: message leaked to a remote mesh peer"
    );
}

#[tokio::test]
#[ignore]
async fn local_topic_fans_out_to_multiple_local_subscribers() {
    let pair = cluster::pair().await;
    let topic = "local:fanout/check";
    let marker = format!("fanout-{}", rand::random::<u32>());
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(marker.as_bytes());

    // Two independent subscribers on the same daemon (the multi-process
    // app pattern local: topics exist for).
    let mut sub1 = ws_connect(&pair.alice).await;
    let mut sub2 = ws_connect(&pair.alice).await;
    ws_subscribe(&mut sub1, topic).await;
    ws_subscribe(&mut sub2, topic).await;

    let r = pair
        .alice
        .post(
            "/publish",
            serde_json::json!({ "topic": topic, "payload": payload_b64 }),
        )
        .await;
    assert!(r.status().is_success());

    assert!(
        ws_saw(&mut sub1, &payload_b64, 10).await,
        "first local subscriber must receive the message"
    );
    assert!(
        ws_saw(&mut sub2, &payload_b64, 10).await,
        "second local subscriber must receive the message (fan-out)"
    );
}
