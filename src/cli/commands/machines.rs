//! Machine record management CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x machines discovered` — GET /machines/discovered
pub async fn discovered(client: &DaemonClient, unfiltered: bool) -> Result<()> {
    client.ensure_running().await?;
    let resp = if unfiltered {
        client
            .get_query("/machines/discovered", &[("unfiltered", "true")])
            .await?
    } else {
        client.get("/machines/discovered").await?
    };
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines get` — GET /machines/discovered/:machine_id
pub async fn get_discovered(client: &DaemonClient, machine_id: &str, wait: bool) -> Result<()> {
    client.ensure_running().await?;
    let path = format!("/machines/discovered/{machine_id}");
    let resp = if wait {
        client.get_query(&path, &[("wait", "true")]).await?
    } else {
        client.get(&path).await?
    };
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines by-user` — GET /users/:user_id/machines
pub async fn by_user(client: &DaemonClient, user_id: &str) -> Result<()> {
    client.run_get(&format!("/users/{user_id}/machines")).await
}

/// `x0x machines connect` — POST /machines/connect
pub async fn connect(client: &DaemonClient, machine_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({ "machine_id": machine_id });
    let resp = client.post("/machines/connect", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines list` — GET /contacts/:agent_id/machines
pub async fn list(client: &DaemonClient, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .get(&format!("/contacts/{agent_id}/machines"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines add` — POST /contacts/:agent_id/machines
pub async fn add(client: &DaemonClient, agent_id: &str, machine_id: &str, pin: bool) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "machine_id": machine_id,
        "pinned": pin,
    });
    let resp = client
        .post(&format!("/contacts/{agent_id}/machines"), &body)
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines remove` — DELETE /contacts/:agent_id/machines/:machine_id
pub async fn remove(client: &DaemonClient, agent_id: &str, machine_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .delete(&format!("/contacts/{agent_id}/machines/{machine_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines pin` — POST /contacts/:agent_id/machines/:machine_id/pin
pub async fn pin(client: &DaemonClient, agent_id: &str, machine_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .post_empty(&format!("/contacts/{agent_id}/machines/{machine_id}/pin"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x machines unpin` — DELETE /contacts/:agent_id/machines/:machine_id/pin
pub async fn unpin(client: &DaemonClient, agent_id: &str, machine_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .delete(&format!("/contacts/{agent_id}/machines/{machine_id}/pin"))
        .await?;
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
    async fn discovered_returns_mock_response() {
        let mock_resp = serde_json::json!({"machines": [{"machine_id": "abc123"}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = discovered(&client, false).await;
        assert!(result.is_ok(), "discovered should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn get_discovered_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = get_discovered(&client, "machine-1", false).await;
        assert!(
            result.is_ok(),
            "get_discovered should succeed: {:?}",
            result
        );
    }
    #[tokio::test]
    async fn by_user_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = by_user(&client, "user-1").await;
        assert!(result.is_ok(), "by_user should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn list_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = list(&client, "agent-1").await;
        assert!(result.is_ok(), "list should succeed: {:?}", result);
    }
}
