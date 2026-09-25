//! `x0x onboard` — teach a non-x0x agent to install x0x and join (#894, R11).
//!
//! Pure CLI composition: the only daemon call is the existing
//! `GET /agent/card`, which supplies the inviter's agent id and signed card
//! link. The recipe itself is static text built around those two values, so
//! a fresh agent can follow it without reading the full SKILL.md.

use anyhow::{bail, Context, Result};

use crate::cli::{DaemonClient, OutputFormat};

/// Installer published on `main` (also served at <https://x0x.md>).
const INSTALL_SH_URL: &str =
    "https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh";
/// Where Windows support is tracked; no native steps are invented here.
const WINDOWS_ISSUE_URL: &str = "https://github.com/saorsa-labs/x0x/issues/894";
/// Full reference for anything beyond the first DM.
const SKILL_URL: &str = "https://github.com/saorsa-labs/x0x/blob/main/SKILL.md";

/// One step of the recipe: a title, the commands to run, and an optional note.
struct Step {
    title: &'static str,
    commands: Vec<String>,
    note: Option<String>,
}

/// Build the ordered recipe steps for inviter `agent_id`.
///
/// With `card_link`, the new agent imports the inviter's signed card (which
/// carries its public key and addresses). Without it, the new agent looks the
/// inviter up on the network by id instead.
fn steps(agent_id: &str, card_link: Option<&str>) -> Vec<Step> {
    let import = match card_link {
        Some(link) => Step {
            title: "Import my card (adds me to your contacts)",
            commands: vec![format!("x0x agent import '{link}' --trust known")],
            note: None,
        },
        None => Step {
            title: "Find me and add me to your contacts",
            commands: vec![
                format!("x0x agents find {agent_id}"),
                format!("x0x contacts add {agent_id} --trust known --label inviter"),
            ],
            note: Some("If the DM below returns 404 recipient_key_unavailable, ask me for my card link (`x0x agent card`) and run `x0x agent import '<link>' --trust known`.".to_string()),
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
fn recipe_text(agent_id: &str, card_link: Option<&str>) -> String {
    let mut out = format!(
        "# Join x0x and message me\n\n\
         x0x is a post-quantum agent-to-agent network. I am agent {agent_id}.\n\
         Run these steps in a shell to install x0x, start it, and send me a direct message.\n"
    );
    for (i, step) in steps(agent_id, card_link).iter().enumerate() {
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
/// The card link (~20 KB) appears only inside the import command, never
/// duplicated as a separate field.
fn recipe_json(agent_id: &str, card_link: Option<&str>) -> serde_json::Value {
    let steps: Vec<serde_json::Value> = steps(agent_id, card_link)
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
        "includes_card": card_link.is_some(),
        "install_script": INSTALL_SH_URL,
        "windows": format!("not yet supported natively; see {WINDOWS_ISSUE_URL}"),
        "steps": steps,
        "reference": SKILL_URL,
    })
}

/// `x0x onboard` — GET /agent/card, then print the install-and-join recipe.
pub async fn run(client: &DaemonClient, json: bool, no_card: bool) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/agent/card").await?;
    let agent_id = resp["card"]["agent_id"]
        .as_str()
        .context("daemon /agent/card response has no card.agent_id")?;
    // The id is pasted into shell commands; refuse anything but 64 hex chars.
    if agent_id.len() != 64 || !agent_id.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("daemon returned a malformed agent id: {agent_id:?}");
    }
    let card_link = if no_card {
        None
    } else {
        let link = resp["link"]
            .as_str()
            .context("daemon /agent/card response has no link")?;
        // The link is single-quoted in the recipe; refuse anything that could
        // break out of the quotes.
        if !link.starts_with("x0x://agent/")
            || !link
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '-' | '_'))
        {
            bail!("daemon returned an unexpected card link format");
        }
        Some(link)
    };
    if json || matches!(client.format(), OutputFormat::Json) {
        println!(
            "{}",
            serde_json::to_string_pretty(&recipe_json(agent_id, card_link))?
        );
    } else {
        print!("{}", recipe_text(agent_id, card_link));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";
    const LINK: &str = "x0x://agent/eyJhZ2VudF9pZCI6ImFiMTIifQ";

    // A fresh agent given only this output must be able to install, start,
    // trust the inviter and DM back (the #894 acceptance path); dropping any
    // of the four steps strands it. The recipe body must also stay small
    // enough to paste into another agent's context, unlike the ~80 KB
    // SKILL.md it replaces for onboarding. The budget covers the recipe
    // itself; a real signed card link adds ~20 KB on top (`--no-card` omits it).
    #[test]
    fn recipe_has_all_join_steps_and_fits_context_budget() {
        for card in [Some(LINK), None] {
            let text = recipe_text(ID, card);
            assert!(text.contains(INSTALL_SH_URL), "install step missing");
            assert!(text.contains("sh install.sh"), "install run missing");
            assert!(text.contains("x0x start"), "start step missing");
            assert!(
                text.contains(&format!("x0x direct send {ID}")),
                "DM-back step must target the inviter"
            );
            assert!(text.contains("not yet supported natively"));
            assert!(text.len() < 8 * 1024, "recipe is {} bytes", text.len());
        }
        let with_card = recipe_text(ID, Some(LINK));
        assert!(with_card.contains(&format!("x0x agent import '{LINK}'")));
        let without_card = recipe_text(ID, None);
        assert!(!without_card.contains("x0x://agent/eyJ"));
        assert!(without_card.contains(&format!("x0x contacts add {ID}")));
    }

    #[test]
    fn json_recipe_carries_the_same_steps() {
        let v = recipe_json(ID, Some(LINK));
        assert_eq!(v["inviter_agent_id"], ID);
        assert_eq!(v["includes_card"], true);
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
    }
}
