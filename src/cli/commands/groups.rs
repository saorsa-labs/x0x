//! MLS group encryption CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;
use base64::Engine;

/// `x0x groups [list]` — GET /mls/groups
pub async fn list(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/mls/groups").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x groups create` — POST /mls/groups
pub async fn create(client: &DaemonClient, id: Option<&str>) -> Result<()> {
    client.ensure_running().await?;
    let body = match id {
        Some(group_id) => serde_json::json!({ "group_id": group_id }),
        None => serde_json::json!({}),
    };
    let resp = client.post("/mls/groups", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x groups get` — GET /mls/groups/:id
pub async fn get(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/mls/groups/{group_id}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x groups add-member` — POST /mls/groups/:id/members
pub async fn add_member(client: &DaemonClient, group_id: &str, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "agent_id": agent_id });
    let resp = client
        .post(&format!("/mls/groups/{group_id}/members"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x groups remove-member` — DELETE /mls/groups/:id/members/:agent_id
pub async fn remove_member(client: &DaemonClient, group_id: &str, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .delete(&format!("/mls/groups/{group_id}/members/{agent_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x groups encrypt` — POST /mls/groups/:id/encrypt
pub async fn encrypt(client: &DaemonClient, group_id: &str, payload: &str) -> Result<()> {
    client.ensure_running().await?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    let body = serde_json::json!({ "payload": encoded });
    let resp = client
        .post(&format!("/mls/groups/{group_id}/encrypt"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x groups decrypt` — POST /mls/groups/:id/decrypt
pub async fn decrypt(
    client: &DaemonClient,
    group_id: &str,
    ciphertext: &str,
    epoch: u64,
) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "ciphertext": ciphertext,
        "epoch": epoch,
    });
    let resp = client
        .post(&format!("/mls/groups/{group_id}/decrypt"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x groups welcome` — POST /mls/groups/:id/welcome
pub async fn welcome(client: &DaemonClient, group_id: &str, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "agent_id": agent_id });
    let resp = client
        .post(&format!("/mls/groups/{group_id}/welcome"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}
