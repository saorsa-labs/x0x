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
    /// `--dump-request` [dev]: print the wire request instead of sending it.
    dump: bool,
}

/// Read the daemon's bearer token from its effective data directory.
fn read_api_token_in(data_dir: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(data_dir.join("api-token"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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
            .or_else(|| read_api_token_in(&data_dir.join(&dir_name)));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url,
            format,
            api_token,
            dump: false,
        })
    }

    /// Enable `--dump-request` mode: every verb prints
    /// `{"method","path","body"}` (body is the query pairs for GETs) and
    /// returns a synthetic `{"ok":true}` without contacting any daemon.
    /// The dispatch-to-wire parity tests drive this so request SHAPES are
    /// provable for every command, no daemon required.
    pub fn dump_requests(mut self, dump: bool) -> Self {
        self.dump = dump;
        self
    }

    /// Emit one dumped request and return the synthetic response.
    fn emit_dump(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        println!(
            "{}",
            serde_json::json!({
                "method": method,
                "path": path,
                "body": body.unwrap_or(serde_json::Value::Null),
            })
        );
        Ok(serde_json::json!({ "ok": true }))
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
        if self.dump {
            return Ok(());
        }
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
        if self.dump {
            return self.emit_dump("GET", path, None);
        }
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
        if self.dump {
            let body = serde_json::Map::from_iter(
                query.iter().map(|(k, v)| ((*k).to_string(), json_str(v))),
            );
            return self.emit_dump("GET", path, Some(serde_json::Value::Object(body)));
        }
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
        if self.dump {
            let value = serde_json::to_value(body).context("dump: serialize body")?;
            return self.emit_dump("POST", path, Some(value));
        }
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
        if self.dump {
            return self.emit_dump("POST", path, None);
        }
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
        if self.dump {
            let value = serde_json::to_value(body).context("dump: serialize body")?;
            return self.emit_dump("PATCH", path, Some(value));
        }
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
        if self.dump {
            let value = serde_json::to_value(body).context("dump: serialize body")?;
            return self.emit_dump("PUT", path, Some(value));
        }
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
    /// Send a DELETE request with a JSON body.
    ///
    /// A handful of REST endpoints (e.g. `DELETE /owner/agents/:id`) accept
    /// an optional body alongside the path; axum's `Option<Json<T>>`
    /// extractor reads it only when a body is present.
    pub async fn delete_with_body<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<serde_json::Value> {
        if self.dump {
            let value = serde_json::to_value(body).context("dump: serialize body")?;
            return self.emit_dump("DELETE", path, Some(value));
        }
        let resp = self
            .client
            .delete(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .json(body)
            .send()
            .await
            .context("request failed")?;
        self.handle_response(resp).await
    }

    /// Send a DELETE request.
    pub async fn delete(&self, path: &str) -> Result<serde_json::Value> {
        if self.dump {
            return self.emit_dump("DELETE", path, None);
        }
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
        if self.dump {
            // Emit the request shape, then stop: there is no daemon to
            // stream from and no Response to fabricate.
            let _ = self.emit_dump("GET", path, None)?;
            anyhow::bail!("--dump-request: streaming stopped after request dump");
        }
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
            return Err(error_from_body(status, &body));
        }
        Ok(resp)
    }

    /// #477: GET that returns the parsed body even for non-2xx (the
    /// join-status 404 carries the terminal outcome).
    pub async fn get_with_error_body(&self, path: &str) -> Result<serde_json::Value> {
        if self.dump {
            return self.emit_dump("GET", path, None);
        }
        let resp = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .headers(self.auth_headers())
            .send()
            .await
            .context("request failed — is x0xd running?")?;
        let status = resp.status();
        let text = resp.text().await.context("failed to read response body")?;
        let body: serde_json::Value = if text.trim().is_empty() {
            serde_json::json!({ "status": status.as_u16() })
        } else {
            serde_json::from_str(&text).context("failed to parse response")?
        };
        // #477 (r3 item 5): ONLY 404 passes through with its body (the
        // join-status terminal shape); every other non-2xx is an error so
        // auth/server failures never print as terminal outcomes.
        if status.is_success() || status.as_u16() == 404 {
            let mut body = body;
            if let serde_json::Value::Object(map) = &mut body {
                map.entry("status".to_string())
                    .or_insert(serde_json::Value::from(status.as_u16()));
            }
            return Ok(body);
        }
        Err(error_from_body(status, &body))
    }

    async fn handle_response(&self, resp: reqwest::Response) -> Result<serde_json::Value> {
        response_body(resp, None).await
    }

    /// Send the request of an operation that older daemons may lack
    /// (ADR 0116 §5), and return the response body.
    ///
    /// `body` is sent as JSON for every method except GET. Errors are those
    /// of [`Self::get`] and [`Self::post`], except that a 404 reports an
    /// unsupported operation: see [`NewerOperation`].
    pub async fn request_newer(
        &self,
        op: &NewerOperation,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let body = match op.method {
            crate::api::Method::Get => None,
            _ => body,
        };
        if self.dump {
            return self.emit_dump(&op.method.to_string(), op.path, body.cloned());
        }
        let method = match op.method {
            crate::api::Method::Get => reqwest::Method::GET,
            crate::api::Method::Post => reqwest::Method::POST,
            crate::api::Method::Put => reqwest::Method::PUT,
            crate::api::Method::Patch => reqwest::Method::PATCH,
            crate::api::Method::Delete => reqwest::Method::DELETE,
        };
        let mut request = self
            .client
            .request(method, format!("{}{}", self.base_url, op.path))
            .headers(self.auth_headers());
        if let Some(body) = body {
            request = request.json(body);
        }
        let resp = request
            .send()
            .await
            .context("request failed — is x0xd running?")?;
        response_body(resp, Some(op)).await
    }

    /// Ensure the daemon is running, send the request of an operation that
    /// older daemons may lack, and print the response.
    pub async fn run_newer(
        &self,
        op: &NewerOperation,
        body: Option<&serde_json::Value>,
    ) -> Result<()> {
        self.ensure_running().await?;
        let resp = self.request_newer(op, body).await?;
        print_value(self.format, &resp);
        Ok(())
    }

    /// Ensure the daemon is running, send a GET, and print the response.
    ///
    /// Collapses the `ensure_running -> get -> print_value` shape shared by the
    /// trivial read-only commands into a single call.
    pub async fn run_get(&self, path: &str) -> Result<()> {
        self.ensure_running().await?;
        let resp = self.get(path).await?;
        print_value(self.format, &resp);
        Ok(())
    }

    /// Ensure the daemon is running, send a GET with query params, and print.
    pub async fn run_get_query(&self, path: &str, query: &[(&str, &str)]) -> Result<()> {
        self.ensure_running().await?;
        let resp = self.get_query(path, query).await?;
        print_value(self.format, &resp);
        Ok(())
    }

    /// Ensure the daemon is running, send a DELETE, and print the response.
    pub async fn run_delete(&self, path: &str) -> Result<()> {
        self.ensure_running().await?;
        let resp = self.delete(path).await?;
        print_value(self.format, &resp);
        Ok(())
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

/// `serde_json::Value::String` helper for the dump-mode query map.
fn json_str(v: &str) -> serde_json::Value {
    serde_json::Value::String(v.to_string())
}

/// A daemon operation that older `x0xd` releases do not serve.
///
/// ADR 0116 §5: older local API servers do not offer the new history
/// endpoints, and a client must report an unsupported operation. It must
/// not fall back to SQL. An older daemon has no route for the operation,
/// so it answers 404, usually with an empty body.
/// [`DaemonClient::run_newer`] reports that 404 as an unsupported operation
/// that names the command and says the daemon predates it. Every other
/// status keeps its usual error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewerOperation {
    /// The CLI command, as typed (`x0x history policy`).
    pub command: &'static str,
    /// The route's method.
    pub method: crate::api::Method,
    /// The route's path.
    pub path: &'static str,
}

impl NewerOperation {
    /// The error for a daemon that predates this operation. The daemon's
    /// own `error` sentence, when its 404 body has one, is kept.
    fn unsupported(&self, body: Option<&serde_json::Value>) -> anyhow::Error {
        let daemon = body
            .and_then(|b| b.get("error"))
            .and_then(|e| e.as_str())
            .map(|e| format!(": {e}"))
            .unwrap_or_default();
        anyhow::anyhow!(
            "unsupported operation: `{}` needs {} {}, and this x0xd predates it \
             (HTTP 404{daemon}). Upgrade x0xd to use this command.",
            self.command,
            self.method,
            self.path,
        )
    }
}

/// Read a daemon response: its JSON body on success, an error otherwise.
///
/// `newer` names an operation that older daemons may lack; see
/// [`NewerOperation`].
async fn response_body(
    resp: reqwest::Response,
    newer: Option<&NewerOperation>,
) -> Result<serde_json::Value> {
    let status = resp.status();
    let text = resp.text().await.context("failed to read response body")?;
    // ADR 0116 §5: an older daemon has no route for a newer operation. Its
    // 404 may be empty, JSON or neither, so map it before parsing.
    if let Some(op) = newer {
        if status == reqwest::StatusCode::NOT_FOUND {
            let parsed = serde_json::from_str::<serde_json::Value>(&text).ok();
            return Err(op.unsupported(parsed.as_ref()));
        }
    }
    let body = if text.trim().is_empty() {
        serde_json::json!({ "ok": status.is_success() })
    } else {
        serde_json::from_str(&text).context("failed to parse response")?
    };

    if !status.is_success() {
        return Err(error_from_body(status, &body));
    }

    Ok(body)
}

/// Build an `anyhow::Error` from a non-success HTTP status and its JSON body.
///
/// Reads the `error` field from the body when present, falling back to
/// `"unknown error"`, and appends the numeric status code.
///
/// ADR-0066 §5: when the body also carries a machine-readable `reason`
/// (e.g. the 409 `fork_quarantined` refusal), print it alongside the
/// human sentence. A CLI user needs the explanation and the remedy, and
/// an operator scripting against the CLI needs the stable code — showing
/// only one of the two loses information the response deliberately
/// separated.
fn error_from_body(status: reqwest::StatusCode, body: &serde_json::Value) -> anyhow::Error {
    let msg = body
        .get("error")
        .and_then(|e| e.as_str())
        .unwrap_or("unknown error");
    match body.get("reason").and_then(|r| r.as_str()) {
        Some(reason) => anyhow::anyhow!("{} (HTTP {}, reason: {})", msg, status.as_u16(), reason),
        None => anyhow::anyhow!("{} (HTTP {})", msg, status.as_u16()),
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
    fn read_api_token_uses_daemon_filename() {
        let dir = tempfile::tempdir().expect("temp dir");
        let x0x_dir = dir.path().join("x0x");
        std::fs::create_dir_all(&x0x_dir).expect("create x0x dir");
        std::fs::write(x0x_dir.join("api-token"), "test-token\n").expect("write token");
        assert_eq!(
            read_api_token_in(&dir.path().join("x0x")).as_deref(),
            Some("test-token")
        );
    }

    #[test]
    fn read_api_token_returns_none_without_token_file() {
        // An isolated data dir with no token file means no configured token
        let dir = tempfile::tempdir().expect("temp dir");
        let result = read_api_token_in(&dir.path().join("x0x"));
        assert!(
            result.is_none(),
            "should return None without a configured token"
        );
    }

    #[test]
    fn read_api_token_ignores_empty_token_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let x0x_dir = dir.path().join("x0x");
        std::fs::create_dir_all(&x0x_dir).expect("create x0x dir");
        std::fs::write(x0x_dir.join("api-token"), "  \n").expect("write token file");

        let result = read_api_token_in(&dir.path().join("x0x"));
        assert!(result.is_none(), "whitespace-only token must be ignored");
    }

    /// WHY (ADR-0066 §5, CLI surface): a CLI user's only view of a
    /// refusal is this line. R5 removed the warn-only window on the
    /// condition that the user learns why and what to do, so the printed
    /// text must carry the prose sentence and its remedy — a raw status
    /// code, or the bare machine code, leaves an operator with a
    /// permanent unexplained failure. The `reason` is printed alongside
    /// rather than instead: scripts match the code, humans read the
    /// sentence, and showing one without the other loses information the
    /// response body deliberately separated.
    #[test]
    fn fork_quarantine_refusal_prints_the_sentence_the_remedy_and_the_code() {
        let body = serde_json::json!({
            "ok": false,
            "reason": "fork_quarantined",
            "error": "group is fork-quarantined on this node: authenticated fork evidence at \
                      revision 7 means the roster is contested, so this operation is refused \
                      here. It clears when an owner-anchored commit advances past revision 7, \
                      or immediately with the manual clear POST /groups/:id/quarantine/clear \
                      (CLI: `x0x groups quarantine clear abcd`).",
            "fork_quarantine": { "clear_with": "POST /groups/:id/quarantine/clear" },
        });
        let rendered = error_from_body(reqwest::StatusCode::CONFLICT, &body).to_string();
        assert!(
            rendered.contains("fork-quarantined") && rendered.contains("contested"),
            "the human sentence reaches the terminal: {rendered}"
        );
        assert!(
            rendered.contains("x0x groups quarantine clear"),
            "the remedy reaches the terminal, not just a status code: {rendered}"
        );
        assert!(
            rendered.contains("reason: fork_quarantined"),
            "the stable machine code is still visible for scripted callers: {rendered}"
        );
    }

    /// A body without a `reason` keeps the pre-ADR-0066 single-clause
    /// rendering — the new clause is additive, so every other error the
    /// CLI prints is byte-identical.
    #[test]
    fn error_without_reason_renders_unchanged() {
        let body = serde_json::json!({ "ok": false, "error": "group not found" });
        assert_eq!(
            error_from_body(reqwest::StatusCode::NOT_FOUND, &body).to_string(),
            "group not found (HTTP 404)"
        );
    }

    /// An operation older daemons lack, for the ADR 0116 §5 tests below.
    const NEWER_PROBE: NewerOperation = NewerOperation {
        command: "x0x history policy",
        method: crate::api::Method::Get,
        path: "/history/policy",
    };

    /// A canned daemon response: no socket, no process.
    fn canned(status: u16, body: &'static str) -> reqwest::Response {
        reqwest::Response::from(
            axum::http::Response::builder()
                .status(status)
                .body(body)
                .expect("canned response"),
        )
    }

    async fn rendered_error(
        status: u16,
        body: &'static str,
        newer: Option<&NewerOperation>,
    ) -> String {
        response_body(canned(status, body), newer)
            .await
            .expect_err("a non-2xx status is an error")
            .to_string()
    }

    fn assert_unsupported(rendered: &str) {
        assert!(
            rendered.contains("unsupported operation")
                && rendered.contains("`x0x history policy`")
                && rendered.contains("GET /history/policy")
                && rendered.contains("predates"),
            "a 404 must name the operation and say the daemon predates it: {rendered}"
        );
        assert!(
            !rendered.contains("unknown error"),
            "a 404 must not print as an unknown error: {rendered}"
        );
    }

    /// WHY (ADR 0116 §5, Codex E r1 P2): an older daemon has no route for a
    /// new history operation, so axum answers an empty 404. The client must
    /// report an unsupported operation, not `unknown error (HTTP 404)`.
    #[tokio::test]
    async fn adr0116_unsupported_empty_404_names_the_operation() {
        assert_unsupported(&rendered_error(404, "", Some(&NEWER_PROBE)).await);
    }

    /// A JSON 404 (a daemon with a JSON fallback, or a proxy) maps the same
    /// way. The daemon's own sentence is kept, not dropped.
    #[tokio::test]
    async fn adr0116_unsupported_json_404_names_the_operation() {
        let rendered = rendered_error(
            404,
            r#"{"ok":false,"error":"no such route"}"#,
            Some(&NEWER_PROBE),
        )
        .await;
        assert_unsupported(&rendered);
        assert!(rendered.contains("no such route"), "{rendered}");
    }

    /// A non-JSON 404 body (an HTML or plain-text page from something in
    /// front of the daemon) is still an unsupported operation, not a parse
    /// failure.
    #[tokio::test]
    async fn adr0116_unsupported_non_json_404_names_the_operation() {
        assert_unsupported(&rendered_error(404, "Not Found", Some(&NEWER_PROBE)).await);
    }

    /// Control: every other status keeps exactly the error it had before,
    /// so auth, conflict and server failures are never reported as an old
    /// daemon.
    #[tokio::test]
    async fn adr0116_unsupported_leaves_other_statuses_unchanged() {
        let cases: [(u16, &'static str, &str); 5] = [
            (401, "", "unknown error (HTTP 401)"),
            (
                403,
                r#"{"ok":false,"error":"durable API token required"}"#,
                "durable API token required (HTTP 403)",
            ),
            (
                409,
                r#"{"ok":false,"error":"another history retention operation is running","reason":"history_retention_busy"}"#,
                "another history retention operation is running (HTTP 409, reason: history_retention_busy)",
            ),
            (
                500,
                r#"{"ok":false,"error":"history store failed"}"#,
                "history store failed (HTTP 500)",
            ),
            (400, r#"{"ok":false,"error":"bad body"}"#, "bad body (HTTP 400)"),
        ];
        for (status, body, expected) in cases {
            assert_eq!(
                rendered_error(status, body, Some(&NEWER_PROBE)).await,
                expected,
                "HTTP {status} with a newer operation"
            );
            assert_eq!(
                rendered_error(status, body, None).await,
                expected,
                "HTTP {status} without one"
            );
        }
    }

    /// Control: the mapping is opt-in per operation. A 404 for any other
    /// command keeps its existing rendering, and success bodies pass
    /// through unchanged.
    #[tokio::test]
    async fn adr0116_unsupported_mapping_is_opt_in_per_operation() {
        assert_eq!(
            rendered_error(404, "", None).await,
            "unknown error (HTTP 404)"
        );
        assert_eq!(
            rendered_error(404, r#"{"ok":false,"error":"group not found"}"#, None).await,
            "group not found (HTTP 404)"
        );
        let ok = response_body(canned(200, r#"{"ok":true,"n":1}"#), Some(&NEWER_PROBE))
            .await
            .expect("2xx is a body");
        assert_eq!(ok, serde_json::json!({ "ok": true, "n": 1 }));
    }

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
