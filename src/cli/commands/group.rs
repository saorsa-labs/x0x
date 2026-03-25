//! `x0x group` subcommands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x group list` — GET /groups.
pub async fn list(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/groups").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group create` — POST /groups.
pub async fn create(
    client: &DaemonClient,
    name: &str,
    description: Option<&str>,
    display_name: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = serde_json::json!({ "name": name });
    if let Some(desc) = description {
        body["description"] = serde_json::Value::String(desc.to_string());
    }
    if let Some(dn) = display_name {
        body["display_name"] = serde_json::Value::String(dn.to_string());
    }
    let resp = client.post("/groups", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group info` — GET /groups/:id.
pub async fn info(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/groups/{group_id}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group invite` — POST /groups/:id/invite.
pub async fn invite(client: &DaemonClient, group_id: &str, expiry_secs: u64) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "expiry_secs": expiry_secs });
    let resp = client
        .post(&format!("/groups/{group_id}/invite"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group join` — POST /groups/join.
pub async fn join(
    client: &DaemonClient,
    invite_link: &str,
    display_name: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = serde_json::json!({ "invite": invite_link });
    if let Some(dn) = display_name {
        body["display_name"] = serde_json::Value::String(dn.to_string());
    }
    let resp = client.post("/groups/join", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group set-name` — PUT /groups/:id/display-name.
pub async fn set_name(client: &DaemonClient, group_id: &str, name: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "name": name });
    let resp = client
        .put(&format!("/groups/{group_id}/display-name"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x group leave` — DELETE /groups/:id.
pub async fn leave(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.delete(&format!("/groups/{group_id}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}
