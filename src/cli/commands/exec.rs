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
