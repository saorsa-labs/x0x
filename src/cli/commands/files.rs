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

    let body = serde_json::json!({
        "agent_id": agent_id,
        "filename": filename,
        "size": size,
        "sha256": sha256,
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
