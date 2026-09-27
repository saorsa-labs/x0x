//! `x0x forward add|list|rm` + `x0x streams` — tailnet port-forwarding (#132 T6).

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x forward add --local 127.0.0.1:PORT --peer <hex|name> --target 127.0.0.1 --target-port N [--ephemeral]`
///
/// Registers a local loopback listener that tunnels to a peer's loopback
/// service. The forward persists across daemon restarts unless `ephemeral`.
pub async fn add(
    client: &DaemonClient,
    local_addr: &str,
    peer: &str,
    target_host: &str,
    target_port: u16,
    ephemeral: bool,
) -> Result<()> {
    client.ensure_running().await?;
    let body = add_body(local_addr, peer, target_host, target_port, ephemeral);
    let resp = client.post("/forwards", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// The `POST /forwards` body `x0x forward add` sends.
fn add_body(
    local_addr: &str,
    peer: &str,
    target_host: &str,
    target_port: u16,
    ephemeral: bool,
) -> serde_json::Value {
    serde_json::json!({
        "local_addr": local_addr,
        "peer_agent": peer,
        "target_host": target_host,
        "target_port": target_port,
        "ephemeral": ephemeral,
    })
}

/// `x0x forward list` — list registered forwards.
pub async fn list(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/forwards").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x forward rm <127.0.0.1:PORT>` — tear down a forward by local bind addr.
pub async fn remove(client: &DaemonClient, local_addr: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.delete(&format!("/forwards/{local_addr}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x streams` — active and live forward streams, teardown and
/// connect-ACL counters.
pub async fn streams(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/streams").await?;
    print_value(client.format(), &resp);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::add_body;

    #[test]
    fn add_body_shape_is_stable() {
        // The REST body the CLI sends — pinned so a daemon handler change
        // can't silently drift from what the CLI emits.
        let body = add_body("127.0.0.1:8022", "machine:box.me", "::1", 22, false);
        assert_eq!(body["target_port"], 22);
        assert_eq!(body["local_addr"], "127.0.0.1:8022");
        assert_eq!(body["peer_agent"], "machine:box.me");
        assert_eq!(body["target_host"], "::1");
        // WHY (ADR-0074 Q3): persistence is the default; only
        // `--ephemeral` opts a forward out, and it must reach the wire.
        assert_eq!(body["ephemeral"], false);
        let body = add_body("127.0.0.1:8022", "machine:box.me", "::1", 22, true);
        assert_eq!(body["ephemeral"], true);
    }
}
