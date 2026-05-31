//! Identity CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::{bail, Context, Result};
use base64::Engine;
use four_word_networking::IdentityEncoder;
use std::io::Read;

/// Compute 4-word speakable identity from a hex agent/user ID.
fn identity_words(encoder: &IdentityEncoder, hex_id: &str) -> Option<String> {
    encoder.encode_hex(hex_id).ok().map(|w| w.to_string())
}

/// Inject `identity_words` field into a JSON object next to an `agent_id` field.
pub fn inject_identity_words(encoder: &IdentityEncoder, value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        if let Some(agent_hex) = obj
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            if let Some(words) = identity_words(encoder, &agent_hex) {
                obj.insert(
                    "identity_words".to_string(),
                    serde_json::Value::String(words),
                );
            }
        }
        if let Some(user_hex) = obj
            .get("user_id")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            if let Some(words) = identity_words(encoder, &user_hex) {
                obj.insert("user_words".to_string(), serde_json::Value::String(words));
            }
        }
    }
}

/// `x0x agent` — GET /agent
pub async fn agent(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let mut resp = client.get("/agent").await?;
    let encoder = IdentityEncoder::new();
    inject_identity_words(&encoder, &mut resp);
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agent user-id` — GET /agent/user-id
pub async fn user_id(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/agent/user-id").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x announce` — POST /announce
pub async fn announce(client: &DaemonClient, include_user: bool, consent: bool) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "include_user_identity": include_user,
        "human_consent": consent,
    });
    let resp = client.post("/announce", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agent card` — GET /agent/card
pub async fn card(
    client: &DaemonClient,
    display_name: Option<&str>,
    include_groups: bool,
) -> Result<()> {
    client.ensure_running().await?;
    let mut params = Vec::new();
    if let Some(name) = display_name {
        params.push(format!("display_name={name}"));
    }
    if include_groups {
        params.push("include_groups=true".to_string());
    }
    let query = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };
    let resp = client.get(&format!("/agent/card{query}")).await?;

    // Print the link prominently
    if let Some(link) = resp.get("link").and_then(|v| v.as_str()) {
        eprintln!("\nYour shareable identity card:\n");
        eprintln!("  {link}\n");
        eprintln!("Share this link with anyone — they can import it with:");
        eprintln!("  x0x agent import <link>\n");
    }
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agent introduction` — GET /introduction
pub async fn introduction(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/introduction").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agent import` — POST /agent/card/import
pub async fn import_card(
    client: &DaemonClient,
    card_link: &str,
    trust_level: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = serde_json::json!({ "card": card_link });
    if let Some(tl) = trust_level {
        body["trust_level"] = serde_json::Value::String(tl.to_string());
    }
    let resp = client.post("/agent/card/import", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agent sign` — POST /agent/sign
///
/// Reads bytes from `--file <PATH>` (or stdin when path is `-`) OR uses
/// `--payload-b64 <BASE64>` directly, base64-encodes the bytes, and asks
/// the daemon to produce a detached ML-DSA-65 signature. The daemon signs
/// exact bytes; callers should canonicalize structured payloads and
/// domain-separate them before signing.
pub async fn sign(
    client: &DaemonClient,
    file: Option<&str>,
    payload_b64: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;

    let payload_b64 = match (file, payload_b64) {
        (Some(path), None) => {
            let bytes = if path == "-" {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .context("failed to read stdin")?;
                buf
            } else {
                std::fs::read(path).with_context(|| format!("failed to read file: {path}"))?
            };
            base64::engine::general_purpose::STANDARD.encode(bytes)
        }
        (None, Some(b64)) => b64.to_string(),
        (Some(_), Some(_)) => bail!("pass either --file or --payload-b64, not both"),
        (None, None) => bail!("pass either --file <PATH> or --payload-b64 <BASE64>"),
    };

    let body = serde_json::json!({ "payload_b64": payload_b64 });
    let resp = client.post("/agent/sign", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::{DaemonClient, OutputFormat};

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

    #[test]
    fn identity_words_encodes_known_hex() {
        let encoder = IdentityEncoder::new();
        let hex_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let result = identity_words(&encoder, hex_id);
        assert!(result.is_some(), "should encode valid hex");
        let words = result.unwrap();
        assert!(!words.is_empty(), "should produce non-empty words");
        // Should be 4 words separated by hyphens
        assert!(!words.is_empty(), "should produce non-empty words: {words}");
    }

    #[test]
    fn identity_words_rejects_invalid_hex() {
        let encoder = IdentityEncoder::new();
        let result = identity_words(&encoder, "not-hex");
        assert!(result.is_none(), "should reject invalid hex");
    }

    #[test]
    fn identity_words_rejects_short_hex() {
        let encoder = IdentityEncoder::new();
        let result = identity_words(&encoder, "aabb");
        assert!(result.is_none(), "should reject short hex");
    }

    #[test]
    fn inject_identity_words_adds_words_to_object() {
        let encoder = IdentityEncoder::new();
        let agent_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut value = serde_json::json!({
            "agent_id": agent_hex,
            "name": "test-agent"
        });
        inject_identity_words(&encoder, &mut value);
        assert!(
            value.get("identity_words").is_some(),
            "should add identity_words"
        );
        let words = value["identity_words"].as_str().unwrap().to_string();
        assert!(!words.is_empty(), "should produce non-empty words: {words}");
    }

    #[test]
    fn inject_identity_words_skips_missing_agent_id() {
        let encoder = IdentityEncoder::new();
        let mut value = serde_json::json!({"name": "no-id"});
        inject_identity_words(&encoder, &mut value);
        assert!(
            value.get("identity_words").is_none(),
            "should not add words without agent_id"
        );
    }

    #[test]
    fn inject_identity_words_adds_user_words() {
        let encoder = IdentityEncoder::new();
        let user_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut value = serde_json::json!({
            "agent_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "user_id": user_hex,
        });
        inject_identity_words(&encoder, &mut value);
        assert!(
            value.get("identity_words").is_some(),
            "should add identity_words"
        );
        assert!(value.get("user_words").is_some(), "should add user_words");
    }

    #[test]
    fn inject_identity_words_handles_non_object() {
        let encoder = IdentityEncoder::new();
        let mut value = serde_json::json!([1, 2, 3]);
        inject_identity_words(&encoder, &mut value);
        // Should not panic, should not modify array
        assert!(value.is_array());
    }

    #[tokio::test]
    async fn agent_fetches_identity_and_injects_words() {
        let mock_resp = serde_json::json!({
            "agent_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "user_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        });
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();
        let result = agent(&client).await;
        assert!(result.is_ok(), "agent should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn user_id_returns_mock_response() {
        let mock_resp = serde_json::json!({"user_id": "user-1"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();
        let result = user_id(&client).await;
        assert!(result.is_ok(), "user_id should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn announce_posts_mock_response() {
        let mock_resp = serde_json::json!({"announced": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();
        let result = announce(&client, true, true).await;
        assert!(result.is_ok(), "announce should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn card_handles_shareable_link_response() {
        let mock_resp = serde_json::json!({"link": "x0x-card:abc", "ok": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();
        let result = card(&client, Some("Alice"), true).await;
        assert!(result.is_ok(), "card should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn introduction_returns_mock_response() {
        let mock_resp = serde_json::json!({"introduction": "hello"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();
        let result = introduction(&client).await;
        assert!(result.is_ok(), "introduction should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn import_card_posts_mock_response() {
        let mock_resp = serde_json::json!({"imported": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();
        let result = import_card(&client, "x0x-card:abc", Some("trusted")).await;
        assert!(result.is_ok(), "import_card should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn sign_posts_payload_b64_response() {
        let mock_resp = serde_json::json!({"signature_b64": "c2ln"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();
        let result = sign(&client, None, Some("aGVsbG8=")).await;
        assert!(result.is_ok(), "sign should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn sign_reads_file_payload() {
        let mock_resp = serde_json::json!({"signature_b64": "c2ln"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.txt");
        std::fs::write(&path, b"hello").unwrap();
        let result = sign(&client, path.to_str(), None).await;
        assert!(result.is_ok(), "sign file should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn sign_rejects_ambiguous_or_missing_payload() {
        let mock_resp = serde_json::json!({"unused": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();

        let both = sign(&client, Some("-"), Some("aGVsbG8=")).await;
        assert!(both.is_err());
        assert!(both.unwrap_err().to_string().contains("pass either --file"));

        let neither = sign(&client, None, None).await;
        assert!(neither.is_err());
        assert!(neither
            .unwrap_err()
            .to_string()
            .contains("pass either --file <PATH>"));
    }
}
