//! WebSocket CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x ws` — GET /ws (diagnostic: prints the WebSocket URL).
///
/// The WebSocket protocol is `ws://<host>/ws` with the API token in the
/// `Authorization: Bearer <token>` header or `?token=<token>` query parameter.
pub async fn general(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let base = client.base_url();
    let ws_base = base
        .strip_prefix("http://")
        .map(|rest| format!("ws://{rest}"))
        .or_else(|| {
            base.strip_prefix("https://")
                .map(|rest| format!("wss://{rest}"))
        })
        .unwrap_or_else(|| base.to_string());
    let url = format!("{ws_base}/ws");
    match client.format() {
        crate::cli::OutputFormat::Json => {
            print_value(
                client.format(),
                &serde_json::json!({ "ok": true, "url": url, "protocol": "ws" }),
            );
        }
        crate::cli::OutputFormat::Text => {
            println!("WebSocket URL: {url}");
            println!("Authorization: Bearer <api-token>");
        }
    }
    Ok(())
}

/// `x0x ws sessions` — GET /ws/sessions
pub async fn sessions(client: &DaemonClient) -> Result<()> {
    client.run_get("/ws/sessions").await
}

/// `x0x ws direct` — GET /ws/direct (diagnostic: prints the WebSocket URL).
///
/// The WebSocket protocol is `ws://<host>/ws/direct` with the API token
/// in the `Authorization: Bearer <token>` header or `?token=<token>`
/// query parameter. This command prints the concrete URL a client
/// should open — there is no stdout HTTP response body to render.
pub async fn direct(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let base = client.base_url();
    let ws_base = base
        .strip_prefix("http://")
        .map(|rest| format!("ws://{rest}"))
        .or_else(|| {
            base.strip_prefix("https://")
                .map(|rest| format!("wss://{rest}"))
        })
        .unwrap_or_else(|| base.to_string());
    let url = format!("{ws_base}/ws/direct");
    match client.format() {
        crate::cli::OutputFormat::Json => {
            print_value(
                client.format(),
                &serde_json::json!({ "ok": true, "url": url, "protocol": "ws" }),
            );
        }
        crate::cli::OutputFormat::Text => {
            println!("WebSocket URL: {url}");
            println!("Authorization: Bearer <api-token>");
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
    async fn sessions_returns_mock_response() {
        let mock_resp = serde_json::json!({"sessions": [{"id": "session-1"}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = sessions(&client).await;
        assert!(result.is_ok(), "sessions should succeed: {:?}", result);
    }
}
