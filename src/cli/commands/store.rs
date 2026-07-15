//! `x0x store` subcommands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x store list` — GET /stores.
pub async fn list(client: &DaemonClient) -> Result<()> {
    client.run_get("/stores").await
}

/// `x0x store create` — POST /stores.
///
/// `policy` is the optional access policy: `"signed"` (default) or
/// `"append_only"` (existing keys immutable, even to the owner).
pub async fn create(
    client: &DaemonClient,
    name: &str,
    topic: &str,
    policy: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = serde_json::json!({ "name": name, "topic": topic });
    if let Some(p) = policy {
        body["policy"] = serde_json::Value::String(p.to_string());
    }
    let resp = client.post("/stores", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x store join` — POST /stores/:id/join.
///
/// `owner` is the REQUIRED hex-encoded AgentId of the authoritative owner
/// (the anchor). The joiner accepts the owner's deltas and writes iff it is
/// the owner. The daemon rejects a join without an anchor (422 owner_required).
pub async fn join(client: &DaemonClient, topic: &str, owner: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "expected_owner": owner });
    let resp = client.post(&format!("/stores/{topic}/join"), &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x store keys` — GET /stores/:id/keys.
pub async fn keys(client: &DaemonClient, store_id: &str) -> Result<()> {
    client.run_get(&format!("/stores/{store_id}/keys")).await
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
    client.run_get(&format!("/stores/{store_id}/{key}")).await
}

/// `x0x store rm` — DELETE /stores/:id/:key.
pub async fn rm(client: &DaemonClient, store_id: &str, key: &str) -> Result<()> {
    client
        .run_delete(&format!("/stores/{store_id}/{key}"))
        .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::DaemonClient;

    use crate::cli::commands::test_support::start_mock_server;
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
