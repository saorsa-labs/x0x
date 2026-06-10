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
    client.ensure_running().await?;
    let resp = client.get("/ws/sessions").await?;
    print_value(client.format(), &resp);
    Ok(())
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

    /// Start a mock axum server that returns the given JSON for any request.
    #[allow(dead_code)]
    async fn start_mock_server(
        response_json: serde_json::Value,
    ) -> (String, tokio::sync::oneshot::Sender<()>) {
        use std::sync::Arc;

        let json = Arc::new(response_json);
        let app = axum::Router::new().fallback(move |_req: axum::extract::Request| {
            let json = Arc::clone(&json);
            async move {
                let body = serde_json::to_vec(&*json).unwrap();
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }
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
    async fn sessions_returns_mock_response() {
        let mock_resp = serde_json::json!({"sessions": [{"id": "session-1"}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = sessions(&client).await;
        assert!(result.is_ok(), "sessions should succeed: {:?}", result);
    }
}
