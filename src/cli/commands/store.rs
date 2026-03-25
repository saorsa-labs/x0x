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
