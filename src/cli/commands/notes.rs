//! `x0x notes` subcommands (ADR 0081): collaborative notes in a group's
//! sealed `notes` store.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x notes list` — GET /groups/:id/notes.
pub async fn list(client: &DaemonClient, group_id: &str) -> Result<()> {
    client.run_get(&format!("/groups/{group_id}/notes")).await
}

/// `x0x notes create` — POST /groups/:id/notes.
pub async fn create(client: &DaemonClient, group_id: &str, title: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "title": title });
    let resp = client
        .post(&format!("/groups/{group_id}/notes"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x notes get` — GET /groups/:id/notes/:note.
pub async fn get(client: &DaemonClient, group_id: &str, note_id: &str) -> Result<()> {
    client
        .run_get(&format!("/groups/{group_id}/notes/{note_id}"))
        .await
}

/// `x0x notes save` — PUT /groups/:id/notes/:note.
///
/// `base_version` is the `version` from the last read; a stale or unknown
/// base is refused (409) rather than merged in this slice.
pub async fn save(
    client: &DaemonClient,
    group_id: &str,
    note_id: &str,
    text: &str,
    base_version: &str,
) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "text": text, "base_version": base_version });
    let resp = client
        .put(&format!("/groups/{group_id}/notes/{note_id}"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}
