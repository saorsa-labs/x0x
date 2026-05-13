//! Agent discovery CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x agents [list]` — GET /agents/discovered
pub async fn list(client: &DaemonClient, unfiltered: bool) -> Result<()> {
    client.ensure_running().await?;
    let resp = if unfiltered {
        client
            .get_query("/agents/discovered", &[("unfiltered", "true")])
            .await?
    } else {
        client.get("/agents/discovered").await?
    };
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agents get` — GET /agents/discovered/:agent_id
pub async fn get(client: &DaemonClient, agent_id: &str, wait: Option<u64>) -> Result<()> {
    client.ensure_running().await?;
    let path = format!("/agents/discovered/{agent_id}");
    let resp = if let Some(secs) = wait {
        client
            .get_query(&path, &[("wait", &secs.to_string())])
            .await?
    } else {
        client.get(&path).await?
    };
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agents find` — POST /agents/find/:agent_id
pub async fn find(client: &DaemonClient, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .post_empty(&format!("/agents/find/{agent_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agents reachability` — GET /agents/reachability/:agent_id
pub async fn reachability(client: &DaemonClient, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client
        .get(&format!("/agents/reachability/{agent_id}"))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agents machine` — GET /agents/:agent_id/machine
pub async fn machine(client: &DaemonClient, agent_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/agents/{agent_id}/machine")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agents by-user` — GET /users/:user_id/agents
pub async fn by_user(client: &DaemonClient, user_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/users/{user_id}/agents")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::DaemonClient;

    /// Start a mock axum server that returns the given JSON for any request.
    #[allow(dead_code)]
    async fn start_mock_server(
        response_json: serde_json::Value,
    ) -> (String, tokio::sync::oneshot::Sender<()>) {
        use std::sync::Arc;

        let json = Arc::new(response_json);
        let app = axum::Router::new().fallback(move |_req: axum::extract::Request| {
            let json = Arc::clone(&json);
            async move {
                let body = serde_json::to_vec(&*json).unwrap();
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async {
                    rx.await.ok();
                })
                .await
                .ok();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        (format!("http://{}", addr), tx)
    }

    #[tokio::test]
    async fn list_returns_mock_response() {
        let mock_resp =
            serde_json::json!({"agents": [{"agent_id": "abc123", "addresses": ["1.2.3.4:5483"]}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = list(&client, false).await;
        assert!(result.is_ok(), "list should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn get_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = get(&client, "agent-123", None::<u64>).await;
        assert!(result.is_ok(), "get should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn find_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = find(&client, "agent-123").await;
        assert!(result.is_ok(), "find should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn reachability_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = reachability(&client, "agent-123").await;
        assert!(result.is_ok(), "reachability should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn machine_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = machine(&client, "agent-123").await;
        assert!(result.is_ok(), "machine should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn by_user_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = by_user(&client, "user-123").await;
        assert!(result.is_ok(), "by_user should succeed: {:?}", result);
    }
}
