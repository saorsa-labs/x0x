//! Presence CLI commands — wrappers around the `/presence/*` REST endpoints.

use crate::cli::DaemonClient;
use anyhow::Result;

/// `x0x presence online` — GET /presence/online
///
/// Lists all online agents from the local discovery cache (network view:
/// includes all non-blocked agents).
pub async fn online(client: &DaemonClient) -> Result<()> {
    client.run_get("/presence/online").await
}

/// `x0x presence foaf` — GET /presence/foaf?ttl=N&timeout_ms=N
///
/// Performs a FOAF random-walk query and returns the social view (Trusted +
/// Known contacts only).
pub async fn foaf(client: &DaemonClient, ttl: u8, timeout_ms: u64) -> Result<()> {
    let ttl_str = ttl.to_string();
    let timeout_str = timeout_ms.to_string();
    client
        .run_get_query(
            "/presence/foaf",
            &[("ttl", &ttl_str), ("timeout_ms", &timeout_str)],
        )
        .await
}

/// `x0x presence find <id>` — GET /presence/find/:id
///
/// Locates a specific agent by hex-encoded AgentId via FOAF random walk.
pub async fn find(client: &DaemonClient, id: &str, ttl: u8, timeout_ms: u64) -> Result<()> {
    let ttl_str = ttl.to_string();
    let timeout_str = timeout_ms.to_string();
    client
        .run_get_query(
            &format!("/presence/find/{id}"),
            &[("ttl", &ttl_str), ("timeout_ms", &timeout_str)],
        )
        .await
}

/// `x0x presence status <id>` — GET /presence/status/:id
///
/// Checks local cache for an agent by hex-encoded AgentId. No network I/O.
pub async fn status(client: &DaemonClient, id: &str) -> Result<()> {
    client.run_get(&format!("/presence/status/{id}")).await
}

/// `x0x presence events` — GET /presence/events (SSE stream).
///
/// Streams presence online/offline events as they happen. Each line on
/// stdout is a raw SSE event from the daemon. The command runs until
/// the daemon closes the stream or the user presses Ctrl+C.
pub async fn events(client: &DaemonClient) -> Result<()> {
    use futures::StreamExt as _;
    client.ensure_running().await?;
    let resp = client.get_stream("/presence/events").await?;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| anyhow::anyhow!("stream error: {e}"))?;
        let s = String::from_utf8_lossy(&bytes);
        print!("{s}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::DaemonClient;

    use crate::cli::commands::test_support::start_mock_server;
    #[tokio::test]
    async fn online_returns_mock_response() {
        let mock_resp = serde_json::json!({"agents": [{"agent_id": "abc123", "online": true}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = online(&client).await;
        assert!(result.is_ok(), "online should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn status_returns_mock_response() {
        let mock_resp = serde_json::json!({"agents": [{"agent_id": "abc123", "online": true}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = status(&client, "abc123").await;
        assert!(result.is_ok(), "status should succeed: {:?}", result);
    }
}
