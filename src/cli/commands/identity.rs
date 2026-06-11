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
    client.run_get("/agent/user-id").await
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
    // Build the query with reqwest's encoder so a `display_name` containing
    // spaces, `&`, or `=` is percent-encoded rather than corrupting the query.
    let mut query: Vec<(&str, &str)> = Vec::new();
    if let Some(name) = display_name {
        query.push(("display_name", name));
    }
    if include_groups {
        query.push(("include_groups", "true"));
    }
    let resp = client.get_query("/agent/card", &query).await?;

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
    client.run_get("/introduction").await
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
/// exact bytes; callers should canonicalize structured payloads. Pass
/// `--domain <STRING>` to sign `domain || 0x00 || payload` for
/// cross-protocol replay protection (issue #90).
pub async fn sign(
    client: &DaemonClient,
    file: Option<&str>,
    payload_b64: Option<&str>,
    domain: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;

    let payload_b64 = payload_b64_from_args(file, payload_b64)?;

    let mut body = serde_json::json!({ "payload_b64": payload_b64 });
    if let Some(domain) = domain {
        body["domain"] = serde_json::Value::String(domain.to_string());
    }
    let resp = client.post("/agent/sign", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agent verify` — POST /agent/verify
///
/// Verifies a detached ML-DSA-65 signature against a caller-supplied
/// public key. The payload comes from `--file <PATH>` (or stdin when the
/// path is `-`) OR `--payload-b64 <BASE64>`, exactly as for `sign`. Pass
/// `--domain <STRING>` when the signature was produced with domain
/// separation (`domain || 0x00 || payload`, issue #90). Verification is
/// stateless — the daemon uses only the supplied public material.
///
/// Exit status: 0 when the signature is valid; non-zero when it is not
/// (the daemon reports `valid: false`) or on malformed input.
pub async fn verify(
    client: &DaemonClient,
    file: Option<&str>,
    payload_b64: Option<&str>,
    signature_b64: &str,
    public_key_b64: &str,
    domain: Option<&str>,
) -> Result<()> {
    // Usage errors (missing/ambiguous payload args) must win over daemon
    // reachability, so validate local inputs before probing the daemon.
    let payload_b64 = payload_b64_from_args(file, payload_b64)?;

    client.ensure_running().await?;

    let mut body = serde_json::json!({
        "payload_b64": payload_b64,
        "signature_b64": signature_b64,
        "public_key_b64": public_key_b64,
    });
    if let Some(domain) = domain {
        body["domain"] = serde_json::Value::String(domain.to_string());
    }
    let resp = client.post("/agent/verify", &body).await?;
    print_value(client.format(), &resp);
    if resp.get("valid").and_then(|v| v.as_bool()) != Some(true) {
        bail!("signature verification failed");
    }
    Ok(())
}

/// Resolve the payload for `sign`/`verify` from `--file <PATH>` (with `-`
/// meaning stdin) or `--payload-b64 <BASE64>`, returning base64 bytes.
fn payload_b64_from_args(file: Option<&str>, payload_b64: Option<&str>) -> Result<String> {
    match (file, payload_b64) {
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
            Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        (None, Some(b64)) => Ok(b64.to_string()),
        (Some(_), Some(_)) => bail!("pass either --file or --payload-b64, not both"),
        (None, None) => bail!("pass either --file <PATH> or --payload-b64 <BASE64>"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::{DaemonClient, OutputFormat};

    use crate::cli::commands::test_support::{start_capturing_mock_server, start_mock_server};
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
        let result = sign(&client, None, Some("aGVsbG8="), None).await;
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
        let result = sign(&client, path.to_str(), None, None).await;
        assert!(result.is_ok(), "sign file should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn sign_rejects_ambiguous_or_missing_payload() {
        let mock_resp = serde_json::json!({"unused": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();

        let both = sign(&client, Some("-"), Some("aGVsbG8="), None).await;
        assert!(both.is_err());
        assert!(both.unwrap_err().to_string().contains("pass either --file"));

        let neither = sign(&client, None, None, None).await;
        assert!(neither.is_err());
        assert!(neither
            .unwrap_err()
            .to_string()
            .contains("pass either --file <PATH>"));
    }

    /// Regression: `card` must percent-encode `display_name`, so a name with
    /// spaces and `&` cannot corrupt the query string. Captures the raw
    /// request URI on a mock server and asserts the value round-trips.
    #[tokio::test]
    async fn card_url_encodes_display_name() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_for_handler = Arc::clone(&captured);

        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let captured = Arc::clone(&captured_for_handler);
            async move {
                *captured.lock().await = Some(req.uri().to_string());
                axum::response::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from("{\"ok\":true}"))
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

        let url = format!("http://{addr}");
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();
        let result = card(&client, Some("Alice & Bob"), false).await;
        assert!(result.is_ok(), "card should succeed: {result:?}");

        let uri = captured.lock().await.clone().expect("request captured");
        // The literal "Alice & Bob" must be encoded, never appearing raw with
        // a bare `&` that would split into a second query parameter.
        assert!(
            uri.contains("display_name=Alice"),
            "expected encoded display_name in {uri}"
        );
        assert!(
            !uri.contains("display_name=Alice & Bob"),
            "raw space/ampersand leaked into query: {uri}"
        );
        assert!(
            uri.contains("%26") || uri.contains("Alice%20%26%20Bob") || uri.contains("Alice+%26"),
            "ampersand was not percent-encoded: {uri}"
        );
        drop(tx);
    }

    #[tokio::test]
    async fn verify_posts_full_body_to_verify_endpoint() {
        let mock_resp = serde_json::json!({
            "ok": true, "valid": true, "algorithm": "x0x.agent-sign.v1.ml-dsa-65"
        });
        let (url, _shutdown, captured) = start_capturing_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();

        let result = verify(
            &client,
            None,
            Some("aGVsbG8="),
            "c2ln",
            "cGs=",
            Some("x0x.test.v1"),
        )
        .await;
        assert!(result.is_ok(), "verify should succeed: {:?}", result);

        let captured = captured.lock().unwrap();
        let (_, body) = captured
            .iter()
            .find(|(path, _)| path == "/agent/verify")
            .expect("a request must be POSTed to /agent/verify");
        assert_eq!(body["payload_b64"], "aGVsbG8=");
        assert_eq!(body["signature_b64"], "c2ln");
        assert_eq!(body["public_key_b64"], "cGs=");
        assert_eq!(body["domain"], "x0x.test.v1");
    }

    #[tokio::test]
    async fn verify_omits_domain_when_not_passed() {
        let mock_resp = serde_json::json!({"ok": true, "valid": true});
        let (url, _shutdown, captured) = start_capturing_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();

        let result = verify(&client, None, Some("aGVsbG8="), "c2ln", "cGs=", None).await;
        assert!(result.is_ok(), "verify should succeed: {:?}", result);

        let captured = captured.lock().unwrap();
        let (_, body) = captured
            .iter()
            .find(|(path, _)| path == "/agent/verify")
            .expect("a request must be POSTed to /agent/verify");
        assert!(
            body.get("domain").is_none(),
            "request must not contain a domain field when none was passed"
        );
    }

    #[tokio::test]
    async fn verify_fails_when_daemon_reports_invalid() {
        // The daemon's 200 + valid:false is a result, not an HTTP error —
        // but for scripts the CLI exit code must still reflect it.
        let mock_resp = serde_json::json!({
            "ok": true, "valid": false, "algorithm": "x0x.agent-sign.v1.ml-dsa-65"
        });
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();

        let result = verify(&client, None, Some("aGVsbG8="), "c2ln", "cGs=", None).await;
        assert!(result.is_err(), "valid:false must map to a non-zero exit");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("signature verification failed"));
    }

    #[tokio::test]
    async fn verify_rejects_ambiguous_or_missing_payload() {
        let mock_resp = serde_json::json!({"unused": true});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), OutputFormat::Json).unwrap();

        let both = verify(&client, Some("-"), Some("aGVsbG8="), "c2ln", "cGs=", None).await;
        assert!(both.is_err());
        assert!(both.unwrap_err().to_string().contains("pass either --file"));

        let neither = verify(&client, None, None, "c2ln", "cGs=", None).await;
        assert!(neither.is_err());
        assert!(neither
            .unwrap_err()
            .to_string()
            .contains("pass either --file <PATH>"));
    }

    #[tokio::test]
    async fn verify_arg_errors_win_over_unreachable_daemon() {
        // No server listening: if verify probed the daemon before validating
        // its arguments, this would surface a connectivity error instead of
        // the usage error.
        let client =
            DaemonClient::new(None, Some("http://127.0.0.1:9"), OutputFormat::Json).unwrap();
        let neither = verify(&client, None, None, "c2ln", "cGs=", None).await;
        assert!(neither.is_err());
        assert!(neither
            .unwrap_err()
            .to_string()
            .contains("pass either --file <PATH>"));
    }
}
