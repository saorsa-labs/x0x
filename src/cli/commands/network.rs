//! Network and status CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x health` — GET /health
pub async fn health(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/health").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x status` — GET /status
pub async fn status(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let mut resp = client.get("/status").await?;
    let encoder = four_word_networking::IdentityEncoder::new();
    super::identity::inject_identity_words(&encoder, &mut resp);
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x peers` — GET /peers
pub async fn peers(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/peers").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x presence` — GET /presence
pub async fn presence(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/presence").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x network status` — GET /network/status
pub async fn network_status(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/network/status").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x network cache` — GET /network/bootstrap-cache
pub async fn bootstrap_cache(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/network/bootstrap-cache").await?;
    print_value(client.format(), &resp);
    Ok(())
}
