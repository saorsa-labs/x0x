//! `x0x onboard` — teach a non-x0x agent to install x0x and join (#894, R11).
//!
//! The daemon composes the recipe (`GET /onboard`, built by
//! [`crate::onboard`] — the module the handler shares with this command's
//! tests), so REST consumers and the CLI emit the same text. The CLI's own
//! work is presentation: pick the card-delivery query, print the recipe as
//! Markdown or JSON, and in file delivery write the signed card link to the
//! handed-over file instead of printing ~20 KB into the transcript.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::cli::{DaemonClient, OutputFormat};

/// How the inviter's signed card reaches the new agent.
pub enum CardDelivery {
    /// Write the card link to this file; the recipe imports it by file name.
    File(PathBuf),
    /// Embed the card link in the recipe (`--inline-card`).
    Inline,
    /// No card: the new agent looks the inviter up by id (`--no-card`).
    Lookup,
}

/// `x0x onboard` — GET /onboard, print the install-and-join recipe.
pub async fn run(client: &DaemonClient, json: bool, delivery: CardDelivery) -> Result<()> {
    client.ensure_running().await?;
    let (mode, file_path) = match &delivery {
        CardDelivery::File(path) => ("file", Some(path.clone())),
        CardDelivery::Inline => ("inline", None),
        CardDelivery::Lookup => ("lookup", None),
    };
    let mut path = format!("/onboard?card={mode}");
    if let Some(p) = &file_path {
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .context("--card-file must name a file")?;
        // Mirrors the daemon's own check so the refusal happens here,
        // with the flag named, instead of as a bare HTTP 400.
        if let Err(e) = crate::onboard::validate_card_file_name(name) {
            bail!("--card-file: {e}");
        }
        path.push_str(&format!("&card_file={name}"));
    }
    let mut resp = client.get(&path).await?;
    if resp["ok"].as_bool() != Some(true) {
        bail!("daemon refused /onboard: {resp}");
    }

    let mut written_file = None;
    if let (Some(file_path), Some(link)) = (&file_path, resp["card_link"].as_str()) {
        std::fs::write(file_path, format!("{link}\n"))
            .with_context(|| format!("failed to write card to {}", file_path.display()))?;
        let shown = std::fs::canonicalize(file_path).unwrap_or_else(|_| file_path.clone());
        eprintln!(
            "Wrote your signed card to {} — send this file to the new agent with the recipe.",
            shown.display()
        );
        written_file = Some(shown.display().to_string());
    } else if mode == "file" {
        bail!("daemon /onboard response has no card_link");
    }

    if json || matches!(client.format(), OutputFormat::Json) {
        // The ~20 KB link lives in the written file; keep the JSON output
        // paste-sized, exactly like the Markdown recipe.
        if written_file.is_some() {
            if let Some(obj) = resp.as_object_mut() {
                obj.remove("card_link");
            }
        }
        if let (Some(obj), Some(written)) = (resp.as_object_mut(), written_file) {
            obj.insert("card_file".to_string(), serde_json::Value::String(written));
        }
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let recipe = resp["recipe"]
            .as_str()
            .context("daemon /onboard response has no recipe")?;
        print!("{recipe}");
    }
    Ok(())
}
