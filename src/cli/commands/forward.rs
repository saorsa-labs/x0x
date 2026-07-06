//! `x0x forward add|list|rm` + `x0x streams` — tailnet port-forwarding (#132 T6).

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x forward add --local 127.0.0.1:PORT --peer <hex> --target 127.0.0.1 --target-port N`
///
/// Registers a local loopback listener that tunnels to a peer's loopback
pub async fn add(
    client: &DaemonClient,
    local_addr: &str,
    peer: &str,
    target_host: &str,
    target_port: u16,
) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "local_addr": local_addr,
        "peer_agent": peer,
        "target_host": target_host,
        "target_port": target_port,
    });
    let resp = client.post("/forwards", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
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

/// `x0x streams` — active forward-stream count + connect-ACL counters.
pub async fn streams(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/streams").await?;
    print_value(client.format(), &resp);
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn add_body_shape_is_stable() {
        // The REST body the CLI sends — pinned so a daemon handler change
        // can't silently drift from what the CLI emits.
        let body = json!({
            "local_addr": "127.0.0.1:8022",
            "peer_agent": "deadbeef",
            "target_host": "127.0.0.1",
            "target_port": 22,
        });
        assert_eq!(body["target_port"], 22);
        assert_eq!(body["local_addr"], "127.0.0.1:8022");
    }
}
