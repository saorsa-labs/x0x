//! `x0x show` — POST /gui/show (ADR 0083 slice 1).

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;
use serde_json::json;

/// `x0x show <view> [--on <machine|active>]` — POST /gui/show.
///
/// Slice 1 is local only: omit `--on`. A remote target is refused by the
/// daemon until slice 3 (#1394).
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
}
