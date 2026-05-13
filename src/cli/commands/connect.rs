//! Connect to an agent by 4-word location words.

use crate::cli::{print_value, DaemonClient};
use anyhow::{bail, Context, Result};
use four_word_networking::FourWordAdaptiveEncoder;

/// `x0x connect <words...>` — decode location words to IP:port and connect.
pub async fn connect(client: &DaemonClient, words: &[String]) -> Result<()> {
    if words.len() != 4 {
        bail!(
            "location words require exactly 4 words (got {})",
            words.len()
        );
    }

    client.ensure_running().await?;

    let addr_encoder =
        FourWordAdaptiveEncoder::new().context("failed to initialise address encoder")?;

    let words_str = words.join(" ");
    let addr = addr_encoder
        .decode(&words_str)
        .context("failed to decode location words — check spelling")?;

    eprintln!("Decoded location: {addr}");

    // Search discovered agents for one with a matching address.
    let resp = client
        .get_query("/agents/discovered", &[("unfiltered", "true")])
        .await?;

    let empty = vec![];
    let agents = resp.as_array().unwrap_or(&empty);

    let mut found_agent_id: Option<String> = None;
    for agent in agents {
        let addrs = agent
            .get("addresses")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let matches = addrs.iter().any(|a| a.as_str() == Some(addr.as_str()));
        if matches {
            if let Some(id) = agent.get("agent_id").and_then(|v| v.as_str()) {
                found_agent_id = Some(id.to_string());
                break;
            }
        }
    }

    let agent_id = match found_agent_id {
        Some(id) => id,
        None => {
            bail!(
                "no discovered agent at {addr}. \
                 Make sure the target agent has announced on the gossip network \
                 and appears in `x0x agents list`."
            );
        }
    };

    let id_encoder = four_word_networking::IdentityEncoder::new();
    let identity = id_encoder
        .encode_hex(&agent_id)
        .map(|w| w.to_string())
        .unwrap_or_default();

    eprintln!("Found agent: {identity} ({agent_id})");
    eprintln!("Connecting...");

    let body = serde_json::json!({ "agent_id": agent_id });
    let resp = client.post("/agents/connect", &body).await?;
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
    async fn connect_rejects_wrong_word_count() {
        let mock_resp = serde_json::json!({"agents": []});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        // 1 word should fail validation before any HTTP call
        let result = connect(&client, &["hello".to_string()]).await;
        assert!(result.is_err(), "connect with 1 word should fail");
        let err = format!("{:?}", result);
        assert!(
            err.contains("4 words"),
            "error should mention 4 words: {err}"
        );
    }

    #[tokio::test]
    async fn connect_rejects_zero_words() {
        let mock_resp = serde_json::json!({"agents": []});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = connect(&client, &[]).await;
        assert!(result.is_err(), "connect with 0 words should fail");
    }

    #[tokio::test]
    async fn connect_with_valid_words_and_matching_agent() {
        // Use the FourWordAdaptiveEncoder to encode a known address,
        // then decode those words to get valid input for the connect function.
        let addr_encoder = FourWordAdaptiveEncoder::new().unwrap();
        let test_addr = "192.168.1.1:5483";
        let words_str = addr_encoder.encode(test_addr).unwrap();
        let words: Vec<String> = words_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(words.len(), 4, "should produce 4 words");

        // Mock server returns an agent with matching address
        let mock_resp = serde_json::json!([{
            "agent_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "addresses": [test_addr]
        }]);
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = connect(&client, &words).await;
        assert!(result.is_ok(), "connect should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn connect_with_valid_words_no_matching_agent() {
        let addr_encoder = FourWordAdaptiveEncoder::new().unwrap();
        let test_addr = "10.0.0.1:5483";
        let words_str = addr_encoder.encode(test_addr).unwrap();
        let words: Vec<String> = words_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        // Mock server returns empty agents list
        let mock_resp = serde_json::json!([]);
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = connect(&client, &words).await;
        assert!(result.is_err(), "connect should fail when no agent matches");
    }
}
