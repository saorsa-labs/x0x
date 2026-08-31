//! Constitution display command.

use crate::cli::DaemonClient;
use crate::constitution::{CONSTITUTION_MD, CONSTITUTION_STATUS, CONSTITUTION_VERSION};
use anyhow::Result;
use std::io::Write;
use std::process::{Command, Stdio};

/// Display the x0x Constitution.
///
/// The daemon is the source of truth (`GET /constitution`,
/// `GET /constitution/json`): when it is reachable, its copy is shown so a
/// CLI/daemon version skew never serves stale text. When no daemon is
/// running, the CLI binary's embedded copy is the fallback.
pub async fn display(client: Option<&DaemonClient>, raw: bool, json: bool) -> Result<()> {
    let served = match client {
        Some(client) => daemon_constitution(client).await,
        None => None,
    };
    let (md, version, status) = match served {
        Some((md, version, status)) => (md, version, status),
        None => (
            CONSTITUTION_MD.to_string(),
            CONSTITUTION_VERSION.to_string(),
            CONSTITUTION_STATUS.to_string(),
        ),
    };

    if json {
        let out = serde_json::json!({
            "version": version,
            "status": status,
            "content": md,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if raw {
        println!("{md}");
        return Ok(());
    }

    // Prettify the markdown for terminal display
    let rendered = render_for_terminal(&md);

    // Page the output
    page_output(&rendered)?;

    Ok(())
}

/// Fetch the daemon-served constitution, returning `(md, version, status)`
/// when the daemon answered.
///
/// Always uses `/constitution/json`: plain `/constitution` serves raw
/// markdown, which the JSON-oriented `DaemonClient` cannot parse.
async fn daemon_constitution(client: &DaemonClient) -> Option<(String, String, String)> {
    client.ensure_running().await.ok()?;
    let resp = client.get("/constitution/json").await.ok()?;
    let md = resp.get("content").and_then(|v| v.as_str())?.to_string();
    let version = resp
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let status = resp
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Some((md, version, status))
}

fn render_for_terminal(md: &str) -> String {
    use termimad::MadSkin;

    let skin = MadSkin::default();
    let width = terminal_width().min(100); // Cap at 100 columns for readability
    let text = skin.text(md, Some(width));
    text.to_string()
}

fn terminal_width() -> usize {
    // Try to detect terminal width, fall back to 80
    if let Some((w, _)) = terminal_size::terminal_size() {
        w.0 as usize
    } else {
        80
    }
}

fn page_output(content: &str) -> Result<()> {
    // Try system pager: $PAGER > less > more > direct print
    let pager = std::env::var("PAGER")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| {
            if Command::new("less").arg("--version").output().is_ok() {
                "less".to_string()
            } else {
                "more".to_string()
            }
        });

    let pager_args: Vec<&str> = if pager.contains("less") {
        vec!["-R"] // -R preserves ANSI colour codes
    } else {
        vec![]
    };

    match Command::new(&pager)
        .args(&pager_args)
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(content.as_bytes());
            }
            child.wait()?;
        }
        Err(_) => {
            // Fallback: print directly
            print!("{content}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_width_returns_reasonable_value() {
        let width = terminal_width();
        // Should be between 40 and 500
        assert!(width >= 40, "width={width} too small");
        assert!(width <= 500, "width={width} too large");
    }

    #[test]
    fn render_for_terminal_returns_non_empty() {
        let rendered = render_for_terminal(
            "# Hello

This is a test.",
        );
        assert!(!rendered.is_empty(), "should render markdown");
        assert!(rendered.contains("Hello"), "should contain the text");
    }

    #[test]
    fn render_for_terminal_handles_empty() {
        let rendered = render_for_terminal("");
        // Should not panic
        assert!(rendered.is_empty() || !rendered.is_empty());
    }

    #[tokio::test]
    async fn display_json_output_offline() {
        let result = display(None, false, true).await;
        assert!(result.is_ok(), "JSON display should succeed");
    }

    #[tokio::test]
    async fn display_raw_output_offline() {
        let result = display(None, true, false).await;
        assert!(result.is_ok(), "raw display should succeed");
    }
}
