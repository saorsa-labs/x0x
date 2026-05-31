use crate::cli::{print_value, DaemonClient, OutputFormat};
use anyhow::{Context, Result};
use base64::Engine as _;
use serde::Serialize;
use std::io::Write as _;
use std::path::Path;

#[derive(Serialize)]
struct ExecRunBody<'a> {
    agent_id: &'a str,
    argv: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    stdin_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u32>,
}

#[derive(Serialize)]
struct ExecCancelBody<'a> {
    request_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<&'a str>,
}

/// `x0x exec <agent> -- <argv...>` — POST /exec/run.
pub async fn run(
    client: &DaemonClient,
    agent_id: &str,
    argv: &[String],
    timeout_secs: Option<u32>,
    stdin_file: Option<&Path>,
) -> Result<()> {
    if argv.is_empty() {
        anyhow::bail!(
            "usage: x0x exec <agent_id> [--timeout <secs>] [--stdin-file <path>] -- <argv...>"
        );
    }
    let stdin_b64 = match stdin_file {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("failed to read stdin file {}", path.display()))?;
            Some(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        None => None,
    };
    let body = ExecRunBody {
        agent_id,
        argv,
        stdin_b64,
        timeout_ms: timeout_secs.map(|s| s.saturating_mul(1000)),
    };
    let resp = client.post("/exec/run", &body).await?;
    if matches!(client.format(), OutputFormat::Json) {
        print_value(client.format(), &resp);
        return Ok(());
    }

    if let Some(stderr_b64) = resp.get("stderr_b64").and_then(|v| v.as_str()) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(stderr_b64)
            .context("invalid stderr_b64 in daemon response")?;
        std::io::stderr().write_all(&bytes)?;
    }
    if let Some(stdout_b64) = resp.get("stdout_b64").and_then(|v| v.as_str()) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(stdout_b64)
            .context("invalid stdout_b64 in daemon response")?;
        std::io::stdout().write_all(&bytes)?;
    }
    if let Some(reason) = resp.get("denial_reason").and_then(|v| v.as_str()) {
        anyhow::bail!("remote exec denied: {reason}");
    }
    if let Some(signal) = resp.get("signal").and_then(|v| v.as_i64()) {
        anyhow::bail!("remote exec terminated by signal {signal}");
    }
    if let Some(code) = resp.get("code").and_then(|v| v.as_i64()) {
        if code != 0 {
            anyhow::bail!("remote exec exited with code {code}");
        }
    }
    Ok(())
}

/// `x0x exec --cancel <request_id>` — POST /exec/cancel.
pub async fn cancel(client: &DaemonClient, request_id: &str, agent_id: Option<&str>) -> Result<()> {
    let body = ExecCancelBody {
        request_id,
        agent_id,
    };
    let resp = client.post("/exec/cancel", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x exec sessions` — GET /exec/sessions.
pub async fn sessions(client: &DaemonClient) -> Result<()> {
    let resp = client.get("/exec/sessions").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x diagnostics exec` — GET /diagnostics/exec.
pub async fn diagnostics(client: &DaemonClient) -> Result<()> {
    let resp = client.get("/diagnostics/exec").await?;
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
    async fn run_rejects_empty_argv_before_http() {
        let mock_resp = serde_json::json!({"status": "unused"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = run(&client, &"aa".repeat(32), &[], None, None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("usage: x0x exec"));
    }

    #[tokio::test]
    async fn run_posts_json_response() {
        let mock_resp = serde_json::json!({"request_id": "req-1", "code": 0});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let argv = vec!["echo".to_string(), "ok".to_string()];
        let result = run(&client, &"aa".repeat(32), &argv, Some(2), None).await;
        assert!(result.is_ok(), "run should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn run_reads_stdin_file_and_posts_json_response() {
        let mock_resp = serde_json::json!({"request_id": "req-2", "code": 0});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let stdin_path = dir.path().join("stdin.txt");
        std::fs::write(&stdin_path, b"stdin bytes").unwrap();
        let argv = vec!["cat".to_string()];
        let result = run(&client, &"aa".repeat(32), &argv, None, Some(&stdin_path)).await;
        assert!(
            result.is_ok(),
            "run with stdin file should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn run_errors_when_stdin_file_missing() {
        let mock_resp = serde_json::json!({"status": "unused"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let missing = tempfile::tempdir().unwrap().path().join("missing.txt");
        let argv = vec!["cat".to_string()];
        let result = run(&client, &"aa".repeat(32), &argv, None, Some(&missing)).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to read stdin file"));
    }

    #[tokio::test]
    async fn run_text_mode_reports_denial_signal_and_nonzero_exit() {
        for (resp, expected) in [
            (
                serde_json::json!({"denial_reason": "exec_disabled"}),
                "remote exec denied",
            ),
            (serde_json::json!({"signal": 15}), "terminated by signal 15"),
            (serde_json::json!({"code": 7}), "exited with code 7"),
        ] {
            let (url, _shutdown) = start_mock_server(resp).await;
            let client =
                DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Text).unwrap();
            let argv = vec!["echo".to_string(), "ok".to_string()];
            let result = run(&client, &"aa".repeat(32), &argv, None, None).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains(expected));
        }
    }

    #[tokio::test]
    async fn run_text_mode_rejects_invalid_stdout_base64() {
        let mock_resp = serde_json::json!({"stdout_b64": "%%%"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Text).unwrap();
        let argv = vec!["echo".to_string(), "ok".to_string()];
        let result = run(&client, &"aa".repeat(32), &argv, None, None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid stdout_b64"));
    }

    #[tokio::test]
    async fn cancel_with_agent_id_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "cancelled"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = cancel(&client, "req-123", Some(&"aa".repeat(32))).await;
        assert!(
            result.is_ok(),
            "cancel with agent should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn sessions_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = sessions(&client).await;
        assert!(result.is_ok(), "sessions should succeed: {:?}", result);
    }
    #[tokio::test]
    async fn diagnostics_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = diagnostics(&client).await;
        assert!(result.is_ok(), "diagnostics should succeed: {:?}", result);
    }

    #[tokio::test]
    async fn cancel_returns_mock_response() {
        let mock_resp = serde_json::json!({"status": "ok"});
        let (url, _shutdown) = start_mock_server(mock_resp).await;
        let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();
        let result = cancel(&client, "req-123", None::<&str>).await;
        assert!(result.is_ok(), "cancel should succeed: {:?}", result);
    }
}
