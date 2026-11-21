//! `x0x report` (#1354): ask the daemon to build a redacted problem-report
//! bundle. The bundle is stored in the daemon's data directory; with
//! `--deliver-to`, a sent copy is also queued to that owner device.

use anyhow::Result;

use crate::cli::DaemonClient;

/// `x0x report [--deliver-to <agent_id>]` — `POST /report`, then print the
/// daemon's answer (the bundle path, size, log-line counts and delivery).
pub async fn create(client: &DaemonClient, deliver_to: Option<&str>) -> Result<()> {
    client.ensure_running().await?;
    let response = match deliver_to {
        Some(agent_id) => {
            client
                .post("/report", &serde_json::json!({ "deliver_to": agent_id }))
                .await?
        }
        None => client.post_empty("/report").await?,
    };
    crate::cli::print_value(client.format(), &response);
    Ok(())
}
