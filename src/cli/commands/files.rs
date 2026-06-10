//! File transfer CLI commands (Milestone 2).

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;
use sha2::Digest;
use std::path::Path;

/// `x0x send-file` — POST /files/send
pub async fn send_file(client: &DaemonClient, agent_id: &str, path: &Path) -> Result<()> {
    client.ensure_running().await?;

    if !path.exists() {
        anyhow::bail!("File not found: {}", path.display());
    }

    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unnamed".to_string());

    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();

    // Compute SHA-256.
    let contents = std::fs::read(path)?;
    let hash = sha2::Digest::finalize(sha2::Sha256::new_with_prefix(&contents));
    let sha256 = hex::encode(hash);

    let canonical = path.canonicalize()?;
    let body = serde_json::json!({
        "agent_id": agent_id,
        "filename": filename,
        "size": size,
        "sha256": sha256,
        "path": canonical.to_string_lossy(),
    });

    let resp = client.post("/files/send", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x receive-file` — watch for incoming transfers and list pending ones.
pub async fn receive_file(
    client: &DaemonClient,
    _accept_from: Option<&str>,
    _output_dir: Option<&Path>,
) -> Result<()> {
    client.ensure_running().await?;
    // Show pending incoming transfers.
    let resp = client.get("/files/transfers").await?;
    let transfers = resp
        .get("transfers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let pending: Vec<_> = transfers
        .iter()
        .filter(|t| {
            t.get("direction")
                .and_then(|v| v.as_str())
                .is_some_and(|d| d == "Receiving")
                && t.get("status")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s == "Pending")
        })
        .collect();

    if pending.is_empty() {
        println!("No pending incoming transfers.");
    } else {
        println!("{} pending incoming transfer(s):", pending.len());
        for t in &pending {
            let id = t.get("transfer_id").and_then(|v| v.as_str()).unwrap_or("?");
            let name = t.get("filename").and_then(|v| v.as_str()).unwrap_or("?");
            let size = t.get("total_size").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("  {id}  {name}  ({size} bytes)");
        }
        println!("\nAccept with: x0x accept-file <transfer_id>");
        println!("Reject with: x0x reject-file <transfer_id> [--reason <text>]");
    }
    Ok(())
}

/// `x0x transfers` — GET /files/transfers
pub async fn transfers(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/files/transfers").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x transfer-status` — GET /files/transfers/:id
pub async fn transfer_status(client: &DaemonClient, transfer_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .get(&format!("/files/transfers/{transfer_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x accept-file` — POST /files/accept/:id
pub async fn accept_file(client: &DaemonClient, transfer_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .post_empty(&format!("/files/accept/{transfer_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x reject-file` — POST /files/reject/:id
pub async fn reject_file(
    client: &DaemonClient,
    transfer_id: &str,
    reason: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "reason": reason.unwrap_or("rejected by user"),
    });
    let resp = client
        .post(&format!("/files/reject/{transfer_id}"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::DaemonClient;

    /// Start a mock axum server that returns the given JSON for any request.
    #[allow(dead_code)]
    async fn start_mock_server(
        response_json: serde_json::Value,
    ) -> (String, tokio::sync::oneshot::Sender<()>) {
        use std::sync::Arc;

        let json = Arc::new(response_json);
        let app = axum::Router::new().fallback(move |_req: axum::extract::Request| {
            let json = Arc::clone(&json);
            async move {
                let body = serde_json::to_vec(&*json).unwrap();
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async {
                    rx.await.ok();
                })
                .await
                .ok();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        (format!("http://{}", addr), tx)
    }

    #[tokio::test]
    async fn send_file_posts_metadata_for_existing_file() {
        let mock_resp = serde_json::json!({"transfer_id": "tx-1", "status": "queued"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("hello.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let result = send_file(&client, &"aa".repeat(32), &file_path).await;
        assert!(result.is_ok(), "send_file should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn send_file_rejects_missing_file() {
        let mock_resp = serde_json::json!({"ok": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.bin");

        let result = send_file(&client, &"aa".repeat(32), &missing).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("File not found"));
    }

    #[tokio::test]
    async fn receive_file_handles_no_pending_transfers() {
        let mock_resp = serde_json::json!({"transfers": []});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

        let result = receive_file(&client, None, None).await;
        assert!(result.is_ok(), "receive_file should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn receive_file_filters_pending_incoming_transfers() {
        let mock_resp = serde_json::json!({
            "transfers": [
                {"transfer_id": "recv-1", "filename": "in.txt", "total_size": 42, "direction": "Receiving", "status": "Pending"},
                {"transfer_id": "send-1", "filename": "out.txt", "total_size": 7, "direction": "Sending", "status": "Pending"},
                {"transfer_id": "done-1", "filename": "done.txt", "total_size": 9, "direction": "Receiving", "status": "Completed"}
            ]
        });
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

        let result = receive_file(&client, Some(&"aa".repeat(32)), Some(Path::new("/tmp"))).await;
        assert!(result.is_ok(), "receive_file should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn transfers_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = transfers(&client).await;
        assert!(result.is_ok(), "transfers should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn transfer_status_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = transfer_status(&client, "transfer-123").await;
        assert!(
            result.is_ok(),
            "transfer_status should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn accept_file_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = accept_file(&client, "transfer-123").await;
        assert!(result.is_ok(), "accept_file should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn reject_file_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = reject_file(&client, "transfer-123", Some("too-large")).await;
        assert!(result.is_ok(), "reject_file should succeed: {:?}", result);
    }
}
