//! `x0x onboard` — teach a non-x0x agent to install x0x and join (#894, R11).
//!
//! Pure CLI composition: the only daemon call is the existing
//! `GET /agent/card`, which supplies the inviter's agent id and signed card
//! link. The recipe itself is static text built around those two values, so
//! a fresh agent can follow it without reading the full SKILL.md.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::cli::{DaemonClient, OutputFormat};

/// Installer published on `main` (also served at <https://x0x.md>).
const INSTALL_SH_URL: &str =
    "https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh";
/// Where Windows support is tracked; no native steps are invented here.
const WINDOWS_ISSUE_URL: &str = "https://github.com/saorsa-labs/x0x/issues/894";
/// Full reference for anything beyond the first DM.
const SKILL_URL: &str = "https://github.com/saorsa-labs/x0x/blob/main/SKILL.md";

/// How the inviter's signed card reaches the new agent.
///
/// A signed card link is ~20 KB (it carries the ML-DSA-65 public key and
/// signature), which would dwarf the ~450-token recipe, so by default it goes
/// to a file that is handed over out-of-band.
pub enum CardDelivery {
    /// Write the card link to this file; the recipe imports it by file name.
    File(PathBuf),
    /// Embed the card link in the recipe (`--inline-card`).
    Inline,
    /// No card: the new agent looks the inviter up by id (`--no-card`).
    Lookup,
}

/// The card as the recipe refers to it.
enum Card<'a> {
    /// Link embedded in the import command.
    Inline(&'a str),
    /// File name the new agent receives out-of-band.
    File(&'a str),
    /// Discovery by agent id.
    Lookup,
}

/// One step of the recipe: a title, the commands to run, and an optional note.
struct Step {
    title: &'static str,
    commands: Vec<String>,
    note: Option<String>,
}

/// Build the ordered recipe steps for inviter `agent_id`.
///
/// With a card, the new agent imports the inviter's signed card (which
/// carries its public key and addresses). Without it, the new agent looks the
/// inviter up on the network by id instead.
fn steps(agent_id: &str, card: &Card<'_>) -> Vec<Step> {
    let import = match card {
        Card::Inline(link) => Step {
            title: "Import my card (adds me to your contacts)",
            commands: vec![format!("x0x agent import '{link}' --trust known")],
            note: None,
        },
        Card::File(name) => Step {
            title: "Import my card (adds me to your contacts)",
            commands: vec![format!(
                "x0x agent import \"$(cat '{name}')\" --trust known"
            )],
            note: Some(format!(
                "I will send you the file {name} separately; run this in the directory \
                 where you saved it."
            )),
        },
        Card::Lookup => Step {
            title: "Find me and add me to your contacts",
            commands: vec![
                format!("x0x agents find {agent_id}"),
                format!("x0x contacts add {agent_id} --trust known --label inviter"),
            ],
            note: Some(
                "Finding me by id depends on network discovery and may take several \
                 minutes after your daemon starts; repeat `x0x agents find` until it \
                 succeeds. If the DM below returns 404 recipient_key_unavailable, ask me \
                 for my card (`x0x agent card`) and import it with `x0x agent import`."
                    .to_string(),
            ),
        },
    };
    vec![
        Step {
            title: "Install x0xd + x0x (macOS / Linux, x64 or arm64)",
            commands: vec![
                format!("curl -sfLO {INSTALL_SH_URL}"),
                "cat install.sh   # review it first".to_string(),
                "sh install.sh    # installs to ~/.local/bin and starts the daemon".to_string(),
                "export PATH=\"$HOME/.local/bin:$PATH\"".to_string(),
            ],
            note: Some(format!(
                "Ask your human before installing software or starting a background daemon. \
                 Windows: not yet supported natively; see {WINDOWS_ISSUE_URL}"
            )),
        },
        Step {
            title: "Start the daemon (no-op if the installer already started it)",
            commands: vec!["x0x health || x0x start".to_string()],
            note: None,
        },
        import,
        Step {
            title: "DM me back",
            commands: vec![
                format!("x0x direct send {agent_id} \"hello from <your name>\""),
                "x0x direct events   # read replies (streams until Ctrl+C)".to_string(),
            ],
            note: Some(
                "A 409 recipient_ack_semantics_unavailable means my capabilities have not \
                 reached you yet: retry in a minute, or add --no-durable-ack."
                    .to_string(),
            ),
        },
        Step {
            title: "Optional: let me import you",
            commands: vec!["x0x agent card   # send me the x0x://agent/... link".to_string()],
            note: None,
        },
    ]
}

/// Render the recipe as copy-pasteable Markdown for another agent.
fn recipe_text(agent_id: &str, card: &Card<'_>) -> String {
    let mut out = format!(
        "# Join x0x and message me\n\n\
         x0x is a post-quantum agent-to-agent network. I am agent {agent_id}.\n\
         Run these steps in a shell to install x0x, start it, and send me a direct message.\n"
    );
    for (i, step) in steps(agent_id, card).iter().enumerate() {
        out.push_str(&format!("\n## {}. {}\n\n```sh\n", i + 1, step.title));
        for cmd in &step.commands {
            out.push_str(cmd);
            out.push('\n');
        }
        out.push_str("```\n");
        if let Some(note) = &step.note {
            out.push_str(&format!("\n{note}\n"));
        }
    }
    out.push_str(&format!("\nFull reference: {SKILL_URL}\n"));
    out
}

/// Render the recipe as JSON for agents that consume structured output.
///
/// The card link (~20 KB) appears only with `--inline-card`, inside the
/// import command; otherwise `card_file` names where it was written.
fn recipe_json(agent_id: &str, card: &Card<'_>, card_file: Option<&str>) -> serde_json::Value {
    let steps: Vec<serde_json::Value> = steps(agent_id, card)
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "title": s.title,
                "commands": s.commands,
                "note": s.note,
            })
        })
        .collect();
    serde_json::json!({
        "inviter_agent_id": agent_id,
        "card_file": card_file,
        "install_script": INSTALL_SH_URL,
        "windows": format!("not yet supported natively; see {WINDOWS_ISSUE_URL}"),
        "steps": steps,
        "reference": SKILL_URL,
    })
}

/// `x0x onboard` — GET /agent/card, then print the install-and-join recipe.
pub async fn run(client: &DaemonClient, json: bool, delivery: CardDelivery) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/agent/card").await?;
    let agent_id = resp["card"]["agent_id"]
        .as_str()
        .context("daemon /agent/card response has no card.agent_id")?;
    // The id is pasted into shell commands; refuse anything but 64 hex chars.
    if agent_id.len() != 64 || !agent_id.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("daemon returned a malformed agent id: {agent_id:?}");
    }
    let link = match delivery {
        CardDelivery::Lookup => None,
        CardDelivery::File(_) | CardDelivery::Inline => {
            let link = resp["link"]
                .as_str()
                .context("daemon /agent/card response has no link")?;
            // The link may be single-quoted in the recipe; refuse anything
            // that could break out of the quotes.
            if !link.starts_with("x0x://agent/")
                || !link
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '-' | '_'))
            {
                bail!("daemon returned an unexpected card link format");
            }
            Some(link)
        }
    };
    let mut card_file = None;
    let card = match (&delivery, link) {
        (CardDelivery::File(path), Some(link)) => {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .context("--card-file must name a file")?;
            // The name is single-quoted in the recipe's `cat` command.
            if name.contains('\'') {
                bail!("--card-file name must not contain a single quote");
            }
            std::fs::write(path, format!("{link}\n"))
                .with_context(|| format!("failed to write card to {}", path.display()))?;
            let shown = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            eprintln!(
                "Wrote your signed card to {} — send this file to the new agent with the recipe.",
                shown.display()
            );
            card_file = Some(shown.display().to_string());
            Card::File(name)
        }
        (CardDelivery::Inline, Some(link)) => Card::Inline(link),
        _ => Card::Lookup,
    };
    if json || matches!(client.format(), OutputFormat::Json) {
        println!(
            "{}",
            serde_json::to_string_pretty(&recipe_json(agent_id, &card, card_file.as_deref()))?
        );
    } else {
        print!("{}", recipe_text(agent_id, &card));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";
    const LINK: &str = "x0x://agent/eyJhZ2VudF9pZCI6ImFiMTIifQ";
    const FILE: &str = "x0x-invite-card.txt";

    // A fresh agent given only this output must be able to install, start,
    // trust the inviter and DM back (the #894 acceptance path); dropping any
    // of the four steps strands it. The default output must also stay small
    // enough to paste into another agent's context, unlike the ~80 KB
    // SKILL.md: the ~20 KB signed card therefore goes to a file by default
    // and is embedded only on explicit `--inline-card`.
    #[test]
    fn default_recipe_has_all_join_steps_and_fits_context_budget() {
        let text = recipe_text(ID, &Card::File(FILE));
        assert!(text.contains(INSTALL_SH_URL), "install step missing");
        assert!(text.contains("sh install.sh"), "install run missing");
        assert!(text.contains("x0x start"), "start step missing");
        assert!(
            text.contains(&format!("x0x agent import \"$(cat '{FILE}')\"")),
            "card-import step must read the handed-over file"
        );
        assert!(
            text.contains(&format!("x0x direct send {ID}")),
            "DM-back step must target the inviter"
        );
        assert!(text.contains("not yet supported natively"));
        assert!(
            !text.contains("x0x://agent/eyJ"),
            "card must not be inlined"
        );
        assert!(text.len() < 8 * 1024, "recipe is {} bytes", text.len());
    }

    #[test]
    fn inline_and_lookup_variants_keep_every_step() {
        let inline = recipe_text(ID, &Card::Inline(LINK));
        assert!(inline.contains(&format!("x0x agent import '{LINK}'")));
        let lookup = recipe_text(ID, &Card::Lookup);
        assert!(lookup.contains(&format!("x0x contacts add {ID}")));
        // Id lookup is not instant; without saying so a fresh agent gives up
        // after the first failed find.
        assert!(lookup.contains("depends on network discovery"));
        for text in [inline, lookup] {
            assert!(text.contains("sh install.sh"));
            assert!(text.contains("x0x start"));
            assert!(text.contains(&format!("x0x direct send {ID}")));
        }
    }

    #[test]
    fn json_names_card_file_and_inlines_card_only_on_request() {
        let v = recipe_json(ID, &Card::File(FILE), Some("/w/x0x-invite-card.txt"));
        assert_eq!(v["inviter_agent_id"], ID);
        assert_eq!(v["card_file"], "/w/x0x-invite-card.txt");
        assert!(!v.to_string().contains("x0x://agent/eyJ"));
        let cmds: Vec<String> = v["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|s| s["commands"].as_array().cloned().unwrap_or_default())
            .filter_map(|c| c.as_str().map(str::to_string))
            .collect();
        assert!(cmds.iter().any(|c| c.contains("install.sh")));
        assert!(cmds.iter().any(|c| c.contains("x0x start")));
        assert!(cmds.iter().any(|c| c.starts_with("x0x agent import")));
        assert!(cmds.iter().any(|c| c.starts_with("x0x direct send")));
        let inline = recipe_json(ID, &Card::Inline(LINK), None);
        assert!(inline.to_string().contains(LINK));
        assert!(inline["card_file"].is_null());
    }
}
