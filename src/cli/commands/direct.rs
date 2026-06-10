//! Direct messaging CLI commands.

use crate::cli::{print_value, DaemonClient, OutputFormat};
use anyhow::Result;
use base64::Engine;

/// `x0x direct connect` — POST /agents/connect
pub async fn connect(client: &DaemonClient, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "agent_id": agent_id });
    let resp = client.post("/agents/connect", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x direct send` — POST /direct/send
///
/// `require_ack_ms` opts into a post-send peer-liveness probe: after the
/// envelope has been handed to the DM path, x0xd calls ant-quic
/// `probe_peer` against the recipient's MachineId with the given timeout
/// and includes the RTT (or the failure reason) in the response under
/// `require_ack`. This does NOT prove the specific message was delivered;
/// it proves the peer's receive pipeline is live when the call returned.
pub async fn send(
    client: &DaemonClient,
    agent_id: &str,
    message: &str,
    require_ack_ms: Option<u64>,
) -> Result<()> {
    client.ensure_running().await?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(message.as_bytes());
    let mut body = serde_json::json!({
        "agent_id": agent_id,
        "payload": encoded,
    });
    if let Some(ms) = require_ack_ms {
        body["require_ack_ms"] = serde_json::json!(ms);
    }
    let resp = client.post("/direct/send", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x direct connections` — GET /direct/connections
pub async fn connections(client: &DaemonClient) -> Result<()> {
    client.run_get("/direct/connections").await
}

/// `x0x direct events` — stream GET /direct/events
pub async fn events(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    eprintln!("Streaming direct messages... (Ctrl+C to stop)");

    use futures::StreamExt;

    let resp = client.get_stream("/direct/events").await?;
    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

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
    #[tokio::test]
    async fn connect_returns_mock_response() {
        let mock_resp = serde_json::json!({"outcome": "Connected"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = connect(&client, &"aa".repeat(32)).await;
        assert!(result.is_ok(), "connect should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn send_returns_mock_response_without_ack() {
        let mock_resp = serde_json::json!({"ok": true, "path": "gossip_inbox"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = send(&client, &"aa".repeat(32), "hello", None).await;
        assert!(result.is_ok(), "send should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn send_returns_mock_response_with_ack_probe() {
        let mock_resp = serde_json::json!({"ok": true, "require_ack": {"ok": true, "rtt_ms": 12}});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = send(&client, &"aa".repeat(32), "hello", Some(500)).await;
        assert!(result.is_ok(), "send with ack should succeed: {:?}", result);
    }

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
    async fn events_streams_json_sse_frame() {
        let (url, _shutdown) = start_sse_server("data: {\"message\":\"hello\"}\n\n").await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = events(&client).await;
        assert!(result.is_ok(), "events should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn events_streams_text_sse_frame() {
        let (url, _shutdown) = start_sse_server("data: plain text\n\n").await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Text).unwrap();
        let result = events(&client).await;
        assert!(result.is_ok(), "events should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn connections_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = connections(&client).await;
        assert!(result.is_ok(), "connections should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn events_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = events(&client).await;
        assert!(result.is_ok(), "events should succeed: {:?}", result);
    }
}
