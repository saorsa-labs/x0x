//! `x0x call` — call lifecycle control (ADR-0073 slice 1). The CLI never
//! carries media; media plays in the GUI, whose URL is printed.

use crate::cli::{print_value, DaemonClient, OutputFormat};
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct CallCreateBody<'a> {
    agent_id: &'a str,
    video: bool,
}

/// Print where media for a call will play (the embedded GUI). The
/// `call/<id>` deep link arrives with the GUI call view (#893 / a later
/// ADR-0073 slice); until then the GUI root is printed.
fn print_gui_hint(client: &DaemonClient) {
    if !matches!(client.format(), OutputFormat::Json) {
        eprintln!(
            "Media plays in the GUI: {}/gui (open with `x0x gui`)",
            client.base_url()
        );
    }
}

/// `x0x call <agent> [--video]` — POST /calls.
pub async fn create(client: &DaemonClient, agent_id: &str, video: bool) -> Result<()> {
    let resp = client
        .post("/calls", &CallCreateBody { agent_id, video })
        .await?;
    print_value(client.format(), &resp);
    print_gui_hint(client);
    Ok(())
}

/// `x0x call list` — GET /calls.
pub async fn list(client: &DaemonClient) -> Result<()> {
    let resp = client.get("/calls").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x call show <id>` — GET /calls/:id.
pub async fn show(client: &DaemonClient, id: &str) -> Result<()> {
    let resp = client.get(&format!("/calls/{id}")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x call accept|reject|hangup <id>` — `POST /calls/:id/<action>`.
pub async fn action(client: &DaemonClient, id: &str, action: &str) -> Result<()> {
    let resp = client.post_empty(&format!("/calls/{id}/{action}")).await?;
    print_value(client.format(), &resp);
    if action == "accept" {
        print_gui_hint(client);
    }
    Ok(())
}
