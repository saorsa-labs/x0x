//! `x0x show` — POST /gui/show (ADR 0083).
//!
//! `--on <64-hex machine id | active>` is slice 3 and is sent as
//! `target_machine`. Absent `--on` stays a local show.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;
use serde_json::json;

/// `x0x show <view> [--on <machine|active>]` — POST /gui/show.
///
/// Absent `--on` posts only `view`, which shows on this machine. `--on`
/// posts that value as `target_machine` (`active` or a 64-hex machine id).
/// A rider bearer that carries `gui:show` is admitted by the daemon on
/// this same body.
pub async fn show(client: &DaemonClient, view: &str, on: Option<&str>) -> Result<()> {
    client.ensure_running().await?;
    let mut body = json!({ "view": view });
    if let Some(target) = on {
        body["target_machine"] = json!(target);
    }
    let resp = client.post("/gui/show", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::commands::test_support::start_mock_server;
    use crate::cli::DaemonClient;

    #[tokio::test]
    async fn show_posts_view_body() {
        let mock_resp = serde_json::json!({
            "outcome": "opened",
            "machine_id": "aa".repeat(32),
            "request_id": "bb".repeat(16),
        });
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        show(&client, "people", None).await.unwrap();
    }

    #[tokio::test]
    async fn show_on_posts_target_machine() {
        let mock_resp = serde_json::json!({
            "outcome": "no_active_machine",
            "machine_id": "aa".repeat(32),
            "request_id": "bb".repeat(16),
            "candidates": ["aa".repeat(32)],
        });
        let (url, _shutdown, captured) =
            crate::cli::commands::test_support::start_capturing_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        show(&client, "people", Some("active")).await.unwrap();
        let machine = "cd".repeat(32);
        show(&client, "network", Some(&machine)).await.unwrap();
        let captured = captured.lock().unwrap();
        let shows: Vec<_> = captured
            .iter()
            .filter(|(path, _)| path == "/gui/show")
            .collect();
        assert_eq!(shows.len(), 2);
        assert_eq!(
            shows[0].1,
            serde_json::json!({"view": "people", "target_machine": "active"})
        );
        assert_eq!(
            shows[1].1,
            serde_json::json!({"view": "network", "target_machine": machine})
        );
    }
}
