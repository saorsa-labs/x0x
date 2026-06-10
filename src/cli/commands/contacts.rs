//! Contact and trust management CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x contacts [list]` — GET /contacts
pub async fn list(client: &DaemonClient) -> Result<()> {
    client.run_get("/contacts").await
}

/// `x0x contacts add` — POST /contacts
pub async fn add(
    client: &DaemonClient,
    agent_id: &str,
    trust: &str,
    label: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = serde_json::json!({
        "agent_id": agent_id,
        "trust_level": trust,
    });
    if let Some(l) = label {
        body["label"] = serde_json::Value::String(l.to_string());
    }
    let resp = client.post("/contacts", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x contacts update` — PATCH /contacts/:agent_id
pub async fn update(
    client: &DaemonClient,
    agent_id: &str,
    trust: Option<&str>,
    identity_type: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = serde_json::Map::new();
    if let Some(t) = trust {
        body.insert(
            "trust_level".to_string(),
            serde_json::Value::String(t.to_string()),
        );
    }
    if let Some(it) = identity_type {
        body.insert(
            "identity_type".to_string(),
            serde_json::Value::String(it.to_string()),
        );
    }
    let resp = client
        .patch(&format!("/contacts/{agent_id}"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x contacts remove` — DELETE /contacts/:agent_id
pub async fn remove(client: &DaemonClient, agent_id: &str) -> Result<()> {
    client.run_delete(&format!("/contacts/{agent_id}")).await
}

/// `x0x contacts revoke` — POST /contacts/:agent_id/revoke
pub async fn revoke(client: &DaemonClient, agent_id: &str, reason: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "reason": reason });
    let resp = client
        .post(&format!("/contacts/{agent_id}/revoke"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x contacts revocations` — GET /contacts/:agent_id/revocations
pub async fn revocations(client: &DaemonClient, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .get(&format!("/contacts/{agent_id}/revocations"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x trust set` — POST /contacts/trust
pub async fn trust_set(client: &DaemonClient, agent_id: &str, level: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "agent_id": agent_id,
        "level": level,
    });
    let resp = client.post("/contacts/trust", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x trust evaluate` — POST /trust/evaluate
pub async fn trust_evaluate(client: &DaemonClient, agent_id: &str, machine_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "agent_id": agent_id,
        "machine_id": machine_id,
    });
    let resp = client.post("/trust/evaluate", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::DaemonClient;

    use crate::cli::commands::test_support::start_mock_server;
    #[tokio::test]
    async fn list_returns_mock_response() {
        let mock_resp =
            serde_json::json!({"contacts": [{"agent_id": "abc123", "trust_level": "high"}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = list(&client).await;
        assert!(result.is_ok(), "list should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn revocations_returns_mock_response() {
        let mock_resp =
            serde_json::json!({"contacts": [{"agent_id": "abc123", "trust_level": "high"}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = revocations(&client, "abc123").await;
        assert!(result.is_ok(), "revocations should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn trust_evaluate_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = trust_evaluate(&client, "agent-123", "machine-456").await;
        assert!(
            result.is_ok(),
            "trust_evaluate should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn add_returns_mock_response() {
        let mock_resp = serde_json::json!({"ok": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = add(&client, "agent-123", "trusted", Some("my-friend")).await;
        assert!(result.is_ok(), "add should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn update_returns_mock_response() {
        let mock_resp = serde_json::json!({"ok": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = update(&client, "agent-123", Some("known"), None).await;
        assert!(result.is_ok(), "update should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn remove_returns_mock_response() {
        let mock_resp = serde_json::json!({"ok": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = remove(&client, "agent-123").await;
        assert!(result.is_ok(), "remove should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn revoke_returns_mock_response() {
        let mock_resp = serde_json::json!({"ok": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = revoke(&client, "agent-123", "no longer needed").await;
        assert!(result.is_ok(), "revoke should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn trust_set_returns_mock_response() {
        let mock_resp = serde_json::json!({"ok": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = trust_set(&client, "agent-123", "trusted").await;
        assert!(result.is_ok(), "trust_set should succeed: {:?}", result);
    }
}
