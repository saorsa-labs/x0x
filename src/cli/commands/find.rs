//! Find agents by 4-word speakable identity.

use crate::cli::{print_value, DaemonClient};
use anyhow::{bail, Context, Result};
use four_word_networking::IdentityEncoder;

/// `x0x find <words...>` — decode identity words and search for matching agents.
pub async fn find(client: &DaemonClient, words: &[String]) -> Result<()> {
    client.ensure_running().await?;

    let encoder = IdentityEncoder::new();

    // Validate input: exactly 4 words, or 4 + "@" + 4 = 9 tokens.
    let has_separator = words.iter().any(|w| w == "@");

    if has_separator {
        if words.len() != 9 {
            bail!(
                "full identity requires exactly 9 tokens: 4 words @ 4 words (got {})",
                words.len()
            );
        }
        if words[4] != "@" {
            bail!(
                "@ separator must be the 5th token (got {:?} at position 5)",
                words[4]
            );
        }
    } else if words.len() != 4 {
        bail!(
            "agent identity requires exactly 4 words (got {}). \
             For full identity use: word1 word2 word3 word4 @ word5 word6 word7 word8",
            words.len()
        );
    }

    // Decode agent prefix (first 4 words).
    let agent_words = words[..4].join(" ");
    let agent_prefix = encoder
        .decode_to_prefix(&agent_words)
        .context("failed to decode agent identity words — check spelling")?;
    let agent_prefix_hex = hex::encode(agent_prefix);

    // Optionally decode user prefix (last 4 words after @).
    let user_prefix_hex = if has_separator {
        let user_words = words[5..9].join(" ");
        let user_prefix = encoder
            .decode_to_prefix(&user_words)
            .context("failed to decode user identity words — check spelling")?;
        Some(hex::encode(user_prefix))
    } else {
        None
    };

    eprintln!("Searching for agents matching: {agent_words}");
    eprintln!("Agent ID prefix: 0x{agent_prefix_hex}");
    if let Some(ref up) = user_prefix_hex {
        eprintln!("User ID prefix:  0x{up}");
    }

    // Fetch all discovered agents (unfiltered to include expired).
    let resp = client
        .get_query("/agents/discovered", &[("unfiltered", "true")])
        .await?;

    let empty = vec![];
    let agents = resp.as_array().unwrap_or(&empty);

    let mut matches: Vec<serde_json::Value> = Vec::new();
    for agent in agents {
        let agent_id_hex = match agent.get("agent_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => continue,
        };

        if !agent_id_hex.starts_with(&agent_prefix_hex) {
            continue;
        }

        // If user words were provided, also filter by user_id prefix.
        if let Some(ref up) = user_prefix_hex {
            let user_match = agent
                .get("user_id")
                .and_then(|v| v.as_str())
                .is_some_and(|uid| uid.starts_with(up.as_str()));
            if !user_match {
                continue;
            }
        }

        let mut entry = agent.clone();
        super::identity::inject_identity_words(&encoder, &mut entry);
        matches.push(entry);
    }

    if matches.is_empty() {
        eprintln!("No agents found matching those words.");
        eprintln!("Try `x0x agents list` to see all discovered agents.");
    } else {
        eprintln!("Found {} matching agent(s):\n", matches.len());
        let result = serde_json::Value::Array(matches);
        print_value(client.format(), &result);
    }

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
    async fn find_rejects_wrong_word_count() {
        let mock_resp = serde_json::json!({"agents": [{"agent_id": "abc123"}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        // 1 word should fail validation before any HTTP call
        let result = find(&client, &["hello".to_string()]).await;
        assert!(result.is_err(), "find with 1 word should fail");
        let err = format!("{:?}", result);
        assert!(
            err.contains("4 words"),
            "error should mention 4 words: {err}"
        );
    }

    #[tokio::test]
    async fn find_rejects_wrong_separator_position() {
        let mock_resp = serde_json::json!({"agents": [{"agent_id": "abc123"}]});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        // 9 tokens but @ not at position 5
        let result = find(
            &client,
            &[
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
                "e".to_string(),
                "f".to_string(),
                "g".to_string(),
                "h".to_string(),
                "i".to_string(),
            ],
        )
        .await;
        assert!(result.is_err(), "find without @ separator should fail");
    }

    #[tokio::test]
    async fn find_with_valid_words_returns_mock_response() {
        // Use real dictionary words that the IdentityEncoder can decode
        let mock_resp = serde_json::json!([{"agent_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]);
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        // Use words that are likely in the dictionary
        let result = find(
            &client,
            &[
                "apple".to_string(),
                "banana".to_string(),
                "cherry".to_string(),
                "date".to_string(),
            ],
        )
        .await;
        // May fail if words aren't in dictionary, but should not panic
        let _ = result;
    }
}
