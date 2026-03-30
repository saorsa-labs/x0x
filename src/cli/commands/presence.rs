//! Presence CLI commands — wrappers around the `/presence/*` REST endpoints.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x presence online` — GET /presence/online
///
/// Lists all online agents from the local discovery cache (network view:
/// includes all non-blocked agents).
pub async fn online(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/presence/online").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x presence foaf` — GET /presence/foaf?ttl=N&timeout_ms=N
///
/// Performs a FOAF random-walk query and returns the social view (Trusted +
/// Known contacts only).
pub async fn foaf(client: &DaemonClient, ttl: u8, timeout_ms: u64) -> Result<()> {
    client.ensure_running().await?;
    let ttl_str = ttl.to_string();
    let timeout_str = timeout_ms.to_string();
    let resp = client
        .get_query("/presence/foaf", &[("ttl", &ttl_str), ("timeout_ms", &timeout_str)])
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x presence find <id>` — GET /presence/find/:id
///
/// Locates a specific agent by hex-encoded AgentId via FOAF random walk.
pub async fn find(client: &DaemonClient, id: &str, ttl: u8, timeout_ms: u64) -> Result<()> {
    client.ensure_running().await?;
    let ttl_str = ttl.to_string();
    let timeout_str = timeout_ms.to_string();
    let resp = client
        .get_query(
            &format!("/presence/find/{id}"),
            &[("ttl", &ttl_str), ("timeout_ms", &timeout_str)],
        )
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x presence status <id>` — GET /presence/status/:id
///
/// Checks local cache for an agent by hex-encoded AgentId. No network I/O.
pub async fn status(client: &DaemonClient, id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/presence/status/{id}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}
