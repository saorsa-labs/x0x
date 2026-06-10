//! Gossip messaging CLI commands.

use crate::cli::{print_value, DaemonClient, OutputFormat};
use anyhow::Result;
use base64::Engine;

/// `x0x publish` — POST /publish
pub async fn publish(client: &DaemonClient, topic: &str, payload: &str) -> Result<()> {
    client.ensure_running().await?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    let body = serde_json::json!({
        "topic": topic,
        "payload": encoded,
    });
    let resp = client.post("/publish", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x subscribe` — POST /subscribe + stream /events
pub async fn subscribe(client: &DaemonClient, topic: &str) -> Result<()> {
    client.ensure_running().await?;

    // Create subscription.
    let body = serde_json::json!({ "topic": topic });
    let sub_resp = client.post("/subscribe", &body).await?;
    let sub_id = sub_resp
        .get("subscription_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    eprintln!("Subscribed to '{topic}' (id: {sub_id}). Streaming events... (Ctrl+C to stop)");

    // Stream SSE events.
    stream_sse(client, "/events").await?;

    // Cleanup: unsubscribe.
    let _ = client.delete(&format!("/subscribe/{sub_id}")).await;
    Ok(())
}

/// `x0x unsubscribe` — DELETE /subscribe/:id
pub async fn unsubscribe(client: &DaemonClient, id: &str) -> Result<()> {
    client.run_delete(&format!("/subscribe/{id}")).await
}

/// `x0x events` — stream GET /events
pub async fn events(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    eprintln!("Streaming events... (Ctrl+C to stop)");
    stream_sse(client, "/events").await
}

/// Stream SSE events from a path, printing each data line to stdout.
async fn stream_sse(client: &DaemonClient, path: &str) -> Result<()> {
    use futures::StreamExt;

    let resp = client.get_stream(path).await?;
    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        // Parse SSE frames: split on double newline.
        while let Some(pos) = buffer.find("\n\n") {
            let frame = buffer[..pos].to_string();
            buffer = buffer[pos + 2..].to_string();

            for line in frame.lines() {
                if let Some(data) = line.strip_prefix("data: ") {
                    match client.format() {
                        OutputFormat::Json => println!("{data}"),
                        OutputFormat::Text => {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(data) {
                                print_value(OutputFormat::Text, &val);
                            } else {
                                println!("{data}");
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::DaemonClient;

    use crate::cli::commands::test_support::start_mock_server;
    async fn start_sse_server(body: &'static str) -> (String, tokio::sync::oneshot::Sender<()>) {
        let app = axum::Router::new().fallback(move |_req: axum::extract::Request| async move {
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .body(axum::body::Body::from(body))
                .unwrap()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async {
                    rx.await.ok();
                })
                .await
                .ok();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (format!("http://{}", addr), tx)
    }

    #[tokio::test]
    async fn publish_returns_mock_response() {
        let mock_resp = serde_json::json!({"ok": true, "topic": "test-topic"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = publish(&client, "test-topic", "hello").await;
        assert!(result.is_ok(), "publish should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn unsubscribe_returns_mock_response() {
        let mock_resp = serde_json::json!({"ok": true, "subscription_id": "sub-1"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = unsubscribe(&client, "sub-1").await;
        assert!(result.is_ok(), "unsubscribe should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn events_streams_json_sse_frame() {
        let (url, _shutdown) =
            start_sse_server("data: {\"topic\":\"test\",\"payload\":\"aGVsbG8=\"}\n\n").await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = events(&client).await;
        assert!(result.is_ok(), "events should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn events_streams_text_sse_frame() {
        let (url, _shutdown) = start_sse_server("data: plain event\n\n").await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Text).unwrap();
        let result = events(&client).await;
        assert!(result.is_ok(), "events should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn stream_sse_handles_split_frames_and_ignores_non_data_lines() {
        let (url, _shutdown) =
            start_sse_server("event: message\ndata: {\"ok\":true}\n\n: comment\n\n").await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Text).unwrap();
        let result = stream_sse(&client, "/events").await;
        assert!(result.is_ok(), "stream_sse should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn subscribe_returns_mock_response() {
        let mock_resp = serde_json::json!({"topics": ["test-topic"]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = subscribe(&client, "test-topic").await;
        assert!(result.is_ok(), "subscribe should succeed: {:?}", result);
    }
}
