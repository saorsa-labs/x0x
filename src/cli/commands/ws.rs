//! WebSocket CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x ws sessions` — GET /ws/sessions
pub async fn sessions(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/ws/sessions").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x ws direct` — GET /ws/direct (diagnostic: prints the WebSocket URL).
///
/// The WebSocket protocol is `ws://<host>/ws/direct` with the API token
/// in the `Authorization: Bearer <token>` header or `?token=<token>`
/// query parameter. This command prints the concrete URL a client
/// should open — there is no stdout HTTP response body to render.
pub async fn direct(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let base = client.base_url();
    let ws_base = base
        .strip_prefix("http://")
        .map(|rest| format!("ws://{rest}"))
        .or_else(|| {
            base.strip_prefix("https://")
                .map(|rest| format!("wss://{rest}"))
        })
        .unwrap_or_else(|| base.to_string());
    let url = format!("{ws_base}/ws/direct");
    match client.format() {
        crate::cli::OutputFormat::Json => {
            print_value(
                client.format(),
                &serde_json::json!({ "ok": true, "url": url, "protocol": "ws" }),
            );
        }
        crate::cli::OutputFormat::Text => {
            println!("WebSocket URL: {url}");
            println!("Authorization: Bearer <api-token>");
        }
    }
    Ok(())
}
