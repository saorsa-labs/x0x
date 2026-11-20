//! `x0x report` (#1354 slice 2): ask the daemon to build a redacted
//! problem-report bundle. The bundle is stored in the daemon's data
//! directory and is not sent anywhere.

use anyhow::Result;

use crate::cli::DaemonClient;

/// `x0x report` — `POST /report`, then print the daemon's answer (the
/// bundle path, size and log-line counts).
pub async fn create(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let response = client.post_empty("/report").await?;
    crate::cli::print_value(client.format(), &response);
    Ok(())
}
