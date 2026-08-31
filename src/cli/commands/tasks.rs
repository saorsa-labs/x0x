//! Collaborative task list CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x tasks [list]` — GET /task-lists
pub async fn list(client: &DaemonClient) -> Result<()> {
    client.run_get("/task-lists").await
}

/// `x0x tasks create` — POST /task-lists
pub async fn create(client: &DaemonClient, name: &str, topic: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "name": name,
        "topic": topic,
    });
    let resp = client.post("/task-lists", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x tasks show` — GET /task-lists/:id/tasks
pub async fn show(client: &DaemonClient, list_id: &str) -> Result<()> {
    client
        .run_get(&format!("/task-lists/{list_id}/tasks"))
        .await
}

/// `x0x tasks add` — POST /task-lists/:id/tasks
pub async fn add(
    client: &DaemonClient,
    list_id: &str,
    title: &str,
    description: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = serde_json::json!({ "title": title });
    if let Some(desc) = description {
        body["description"] = serde_json::Value::String(desc.to_string());
    }
    let resp = client
        .post(&format!("/task-lists/{list_id}/tasks"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x tasks claim/complete` — PATCH /task-lists/:id/tasks/:tid
pub async fn update(
    client: &DaemonClient,
    list_id: &str,
    task_id: &str,
    action: &str,
    fence_token: Option<&str>,
    delegation: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = serde_json::json!({ "action": action });
    if let Some(token) = fence_token {
        body["fence_token"] = serde_json::json!(token);
    }
    if let Some(digest) = delegation {
        body["delegation"] = serde_json::json!(digest);
    }
    let resp = client
        .patch(&format!("/task-lists/{list_id}/tasks/{task_id}"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::DaemonClient;

    use crate::cli::commands::test_support::{start_capturing_mock_server, start_mock_server};

    /// WHY (review r2, finding 2): help-text probes cannot prove the
    /// dispatch actually serializes a field — capture the wire body.
    #[tokio::test]
    async fn update_serializes_fence_token_and_delegation() {
        let (url, _shutdown, captured) =
            start_capturing_mock_server(serde_json::json!({"ok": true})).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        update(
            &client,
            "list-1",
            "task-9",
            "claim",
            Some("10520818218540711462:1"),
            Some("deadbeef"),
        )
        .await
        .unwrap();
        let (path, body) = captured.lock().unwrap().last().cloned().unwrap();
        assert_eq!(path, "/task-lists/list-1/tasks/task-9");
        assert_eq!(body["action"], "claim");
        assert_eq!(body["fence_token"], "10520818218540711462:1");
        assert_eq!(body["delegation"], "deadbeef");
    }
    #[tokio::test]
    async fn list_returns_mock_response() {
        let mock_resp = serde_json::json!({"task_lists": [{"name": "test-list"}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = list(&client).await;
        assert!(result.is_ok(), "list should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn show_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = show(&client, "list-1").await;
        assert!(result.is_ok(), "show should succeed: {:?}", result);
    }
}
