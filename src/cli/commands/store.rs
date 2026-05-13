//! `x0x store` subcommands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x store list` — GET /stores.
pub async fn list(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/stores").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x store create` — POST /stores.
pub async fn create(client: &DaemonClient, name: &str, topic: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "name": name, "topic": topic });
    let resp = client.post("/stores", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x store join` — POST /stores/:id/join.
pub async fn join(client: &DaemonClient, topic: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({});
    let resp = client.post(&format!("/stores/{topic}/join"), &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x store keys` — GET /stores/:id/keys.
pub async fn keys(client: &DaemonClient, store_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/stores/{store_id}/keys")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x store put` — PUT /stores/:id/:key.
pub async fn put(
    client: &DaemonClient,
    store_id: &str,
    key: &str,
    value: &str,
    content_type: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    use base64::Engine;
    let value_b64 = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
    let mut body = serde_json::json!({ "value": value_b64 });
    if let Some(ct) = content_type {
        body["content_type"] = serde_json::Value::String(ct.to_string());
    }
    let resp = client
        .put(&format!("/stores/{store_id}/{key}"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x store get` — GET /stores/:id/:key.
pub async fn get(client: &DaemonClient, store_id: &str, key: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/stores/{store_id}/{key}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x store rm` — DELETE /stores/:id/:key.
pub async fn rm(client: &DaemonClient, store_id: &str, key: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.delete(&format!("/stores/{store_id}/{key}")).await?;
    print_value(client.format(), &resp);
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
    async fn list_returns_mock_response() {
        let mock_resp = serde_json::json!({"stores": [{"name": "test-store"}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = list(&client).await;
        assert!(result.is_ok(), "list should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn keys_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = keys(&client, "store-1").await;
        assert!(result.is_ok(), "keys should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn get_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = get(&client, "store-1", "my-key").await;
        assert!(result.is_ok(), "get should succeed: {:?}", result);
    }
}
