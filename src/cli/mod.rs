//! CLI infrastructure for the `x0x` command-line tool.
//!
//! Provides `DaemonClient` for communicating with a running `x0xd` daemon,
//! output formatting, and all command implementations.

pub mod commands;

use anyhow::{Context, Result};
use serde::Serialize;
use std::time::Duration;

/// Output format for CLI responses.
#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    /// Human-readable text output.
    Text,
    /// Raw JSON output.
    Json,
}

/// HTTP client for talking to a running x0xd daemon.
pub struct DaemonClient {
    client: reqwest::Client,
    base_url: String,
    format: OutputFormat,
    /// API bearer token for authentication.
    api_token: Option<String>,
}

impl DaemonClient {
    /// Create a new client, discovering the daemon address and API token.
    ///
    /// Priority: `api_override` > port file for `name` > default port file > `127.0.0.1:12700`.
    pub fn new(
        name: Option<&str>,
        api_override: Option<&str>,
        format: OutputFormat,
    ) -> Result<Self> {
        let data_dir = dirs::data_dir().context("cannot determine data directory")?;
        let dir_name = match name {
            Some(n) => format!("x0x-{n}"),
            None => "x0x".to_string(),
        };

        let base_url = if let Some(api) = api_override {
            if api.starts_with("http://") || api.starts_with("https://") {
                api.to_string()
            } else {
                format!("http://{api}")
            }
        } else {
            Self::discover_api(name, &data_dir, &dir_name)?
        };

        // Read API token.
        // Priority: X0X_API_TOKEN env var > data directory file.
        // When --api overrides the address, the local token file may not match
        // the target daemon — the env var is the escape hatch.
        let api_token = std::env::var("X0X_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .or_else(|| {
                let token_path = data_dir.join(&dir_name).join("api-token");
                std::fs::read_to_string(&token_path)
                    .ok()
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
            });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url,
            format,
            api_token,
        })
    }

    fn discover_api(
        name: Option<&str>,
        data_dir: &std::path::Path,
        dir_name: &str,
    ) -> Result<String> {
        let port_file = data_dir.join(dir_name).join("api.port");
        if port_file.exists() {
            let addr = std::fs::read_to_string(&port_file)
                .context("failed to read port file")?
                .trim()
                .to_string();
            if !addr.is_empty() {
                return Ok(format!("http://{addr}"));
            }
        }

        if let Some(instance_name) = name {
            anyhow::bail!(
                "Named instance '{instance_name}' is not running. Start it with: x0x --name {instance_name} start"
            );
        }

        Ok("http://127.0.0.1:12700".to_string())
    }

    /// Build a request with the API token attached.
    fn auth_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(ref token) = self.api_token {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(reqwest::header::AUTHORIZATION, val);
            }
        }
        headers
    }

    /// Check if daemon is reachable. Returns an error with a helpful message if not.
    pub async fn ensure_running(&self) -> Result<()> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .timeout(Duration::from_secs(2))
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => Ok(()),
            _ => anyhow::bail!("Daemon is not running. Start it with: x0x start"),
        }
    }

    /// Send a GET request.
    pub async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let resp = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .send()
            .await
            .context("request failed — is x0xd running?")?;
        self.handle_response(resp).await
    }

    /// Send a GET request with query parameters.
    pub async fn get_query(&self, path: &str, query: &[(&str, &str)]) -> Result<serde_json::Value> {
        let resp = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .query(query)
            .send()
            .await
            .context("request failed")?;
        self.handle_response(resp).await
    }

    /// Send a POST request with a JSON body.
    pub async fn post<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .json(body)
            .send()
            .await
            .context("request failed")?;
        self.handle_response(resp).await
    }

    /// Send a POST request with no body.
    pub async fn post_empty(&self, path: &str) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .send()
            .await
            .context("request failed")?;
        self.handle_response(resp).await
    }

    /// Send a PATCH request with a JSON body.
    pub async fn patch<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<serde_json::Value> {
        let resp = self
            .client
            .patch(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .json(body)
            .send()
            .await
            .context("request failed")?;
        self.handle_response(resp).await
    }

    /// Send a PUT request with a JSON body.
    pub async fn put<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<serde_json::Value> {
        let resp = self
            .client
            .put(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .json(body)
            .send()
            .await
            .context("request failed")?;
        self.handle_response(resp).await
    }

    /// Send a DELETE request.
    pub async fn delete(&self, path: &str) -> Result<serde_json::Value> {
        let resp = self
            .client
            .delete(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .send()
            .await
            .context("request failed")?;
        self.handle_response(resp).await
    }

    /// Get a streaming response (for SSE).
    pub async fn get_stream(&self, path: &str) -> Result<reqwest::Response> {
        let resp = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .timeout(Duration::from_secs(86400)) // 24h for streaming
            .send()
            .await
            .context("request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let msg = body
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error");
            anyhow::bail!("{} (HTTP {})", msg, status.as_u16());
        }
        Ok(resp)
    }

    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        let status = resp.status();
        let text = resp.text().await.context("failed to read response body")?;
        let body = if text.trim().is_empty() {
            serde_json::json!({ "ok": status.is_success() })
        } else {
            serde_json::from_str(&text).context("failed to parse response")?
        };

        if !status.is_success() {
            let msg = body
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error");
            anyhow::bail!("{} (HTTP {})", msg, status.as_u16());
        }

        Ok(body)
    }

    /// Get the output format.
    pub fn format(&self) -> OutputFormat {
        self.format
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the API bearer token, when one was discovered.
    pub fn api_token(&self) -> Option<&str> {
        self.api_token.as_deref()
    }
}

/// Print a JSON value according to the output format.
pub fn print_value(format: OutputFormat, value: &serde_json::Value) {
    match format {
        OutputFormat::Json => {
            if let Ok(s) = serde_json::to_string_pretty(value) {
                println!("{s}");
            }
        }
        OutputFormat::Text => {
            print_value_text(value, 0);
        }
    }
}

fn print_value_text(value: &serde_json::Value, indent: usize) {
    let pad = " ".repeat(indent);
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                match val {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        println!("{pad}{key}:");
                        print_value_text(val, indent + 2);
                    }
                    _ => {
                        println!("{pad}{key}: {}", format_scalar(val));
                    }
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                print_value_text(item, indent);
                if indent == 0 && !arr.is_empty() {
                    println!();
                }
            }
        }
        _ => println!("{pad}{}", format_scalar(value)),
    }
}

fn format_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// Print an error message to stderr.
pub fn print_error(msg: &str) {
    eprintln!("error: {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_scalar_string() {
        assert_eq!(
            format_scalar(&serde_json::Value::String("hello".into())),
            "hello"
        );
    }

    #[test]
    fn format_scalar_number() {
        assert_eq!(format_scalar(&serde_json::json!(42)), "42");
        assert_eq!(format_scalar(&serde_json::json!(2.71)), "2.71");
    }

    #[test]
    fn format_scalar_bool() {
        assert_eq!(format_scalar(&serde_json::Value::Bool(true)), "true");
        assert_eq!(format_scalar(&serde_json::Value::Bool(false)), "false");
    }

    #[test]
    fn format_scalar_null() {
        assert_eq!(format_scalar(&serde_json::Value::Null), "null");
    }

    #[test]
    fn format_scalar_object_falls_through() {
        let obj = serde_json::json!({"key": "val"});
        let s = format_scalar(&obj);
        assert!(!s.is_empty());
    }

    #[test]
    fn output_format_debug_clone_copy() {
        let fmt = OutputFormat::Text;
        let _fmt2 = fmt; // Copy
        let _fmt3 = fmt; // Copy again
        assert!(matches!(fmt, OutputFormat::Text));
        assert!(matches!(OutputFormat::Json, OutputFormat::Json));
    }

    #[test]
    fn daemon_client_new_defaults_to_localhost() {
        // Without a running daemon, this should fail gracefully
        let result = DaemonClient::new(None, None, OutputFormat::Text);
        // Should either succeed (if port file exists) or fail with a clear error
        match result {
            Ok(client) => {
                assert!(
                    client.base_url().contains("127.0.0.1")
                        || client.base_url().contains("localhost")
                );
            }
            Err(e) => {
                let msg = format!("{e}");
                assert!(!msg.is_empty());
            }
        }
    }

    #[test]
    fn daemon_client_uses_api_override() {
        let client = DaemonClient::new(None, Some("192.168.1.1:9999"), OutputFormat::Json).unwrap();
        assert_eq!(client.base_url(), "http://192.168.1.1:9999");
        assert!(matches!(client.format(), OutputFormat::Json));
    }

    #[test]
    fn daemon_client_uses_http_api_override() {
        let client =
            DaemonClient::new(None, Some("http://10.0.0.1:8080"), OutputFormat::Text).unwrap();
        assert_eq!(client.base_url(), "http://10.0.0.1:8080");
    }

    #[test]
    fn daemon_client_named_instance_no_port_file() {
        // Named instance without a port file should fail with a helpful message
        let result = DaemonClient::new(Some("nonexistent-test-instance"), None, OutputFormat::Text);
        if let Err(e) = result {
            let msg = format!("{e}");
            assert!(msg.contains("nonexistent-test-instance"), "msg: {msg}");
        }
        // Ok path tolerated — port file may exist if a real daemon is running
    }

    #[test]
    fn print_value_json_output() {
        let val = serde_json::json!({"key": "value"});
        // Should not panic
        print_value(OutputFormat::Json, &val);
    }

    #[test]
    fn print_value_text_output() {
        let val = serde_json::json!({"key": "value"});
        print_value(OutputFormat::Text, &val);
    }

    #[test]
    fn print_value_text_nested() {
        let val = serde_json::json!({"outer": {"inner": "deep"}});
        print_value(OutputFormat::Text, &val);
    }

    #[test]
    fn print_value_text_array() {
        let val = serde_json::json!([{"a": 1}, {"b": 2}]);
        print_value(OutputFormat::Text, &val);
    }

    #[test]
    fn ensure_running_fails_without_daemon() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let client = DaemonClient::new(None, Some("127.0.0.1:1"), OutputFormat::Text).unwrap();
            let result = client.ensure_running().await;
            assert!(result.is_err());
            let msg = format!("{}", result.unwrap_err());
            assert!(
                msg.contains("Daemon is not running")
                    || msg.contains("Connection refused")
                    || msg.contains("request failed"),
                "msg: {msg}"
            );
        });
    }
}
