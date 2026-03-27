//! Machine record management CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x machines list` — GET /contacts/:agent_id/machines
pub async fn list(client: &DaemonClient, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .get(&format!("/contacts/{agent_id}/machines"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines add` — POST /contacts/:agent_id/machines
pub async fn add(client: &DaemonClient, agent_id: &str, machine_id: &str, pin: bool) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "machine_id": machine_id,
        "pinned": pin,
    });
    let resp = client
        .post(&format!("/contacts/{agent_id}/machines"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines remove` — DELETE /contacts/:agent_id/machines/:machine_id
pub async fn remove(client: &DaemonClient, agent_id: &str, machine_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .delete(&format!("/contacts/{agent_id}/machines/{machine_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines pin` — POST /contacts/:agent_id/machines/:machine_id/pin
pub async fn pin(client: &DaemonClient, agent_id: &str, machine_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .post_empty(&format!("/contacts/{agent_id}/machines/{machine_id}/pin"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines unpin` — DELETE /contacts/:agent_id/machines/:machine_id/pin
pub async fn unpin(client: &DaemonClient, agent_id: &str, machine_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .delete(&format!("/contacts/{agent_id}/machines/{machine_id}/pin"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}
