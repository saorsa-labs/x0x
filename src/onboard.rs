//! Install-and-join onboarding recipe (#894, R11).
//!
//! One recipe builder shared by `GET /onboard` (the daemon) and
//! `x0x onboard` (the CLI), so the REST surface and the CLI can never
//! drift apart. The recipe is static text built around two values from
//! the inviter's daemon — its agent id and signed card link — compact
//! enough (<8 KB) to paste into another agent's context, unlike the
//! ~80 KB SKILL.md.

/// Installer published on `main` (also served at <https://x0x.md>).
pub const INSTALL_SH_URL: &str =
    "https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.sh";
/// Non-interactive Windows installer (binaries, checksum + signed-manifest
/// verification, user PATH; never needs admin).
pub const INSTALL_PS1_URL: &str =
    "https://raw.githubusercontent.com/saorsa-labs/x0x/main/scripts/install.ps1";
/// Full reference for anything beyond the first DM.
pub const SKILL_URL: &str = "https://github.com/saorsa-labs/x0x/blob/main/SKILL.md";

/// How the inviter's signed card reaches the new agent.
///
/// A signed card link is ~20 KB (it carries the ML-DSA-65 public key and
/// signature), which would dwarf the ~450-token recipe, so by default it
/// travels beside the recipe (a handed-over file) rather than inside it.
pub enum Card<'a> {
    /// Link embedded in the import command.
    Inline(&'a str),
    /// File name the new agent receives out-of-band.
    File(&'a str),
    /// Discovery by agent id.
    Lookup,
}

/// One step of the recipe: a title, the commands to run, and an optional note.
pub struct Step {
    /// Human-readable step heading.
    pub title: &'static str,
    /// Copy-pasteable shell commands, in order.
    pub commands: Vec<String>,
    /// Caveat or context the new agent needs for this step.
    pub note: Option<String>,
}

/// The inviter's agent id is pasted into shell commands; refuse anything
/// but 64 hex characters.
pub fn validate_agent_id(agent_id: &str) -> Result<(), String> {
    if agent_id.len() != 64 || !agent_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("malformed agent id: {agent_id:?}"));
    }
    Ok(())
}

/// The card link may be single-quoted in the recipe; refuse anything that
/// could break out of the quotes.
pub fn validate_card_link(link: &str) -> Result<(), String> {
    if !link.starts_with("x0x://agent/")
        || !link
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '-' | '_'))
    {
        return Err("unexpected card link format".to_string());
    }
    Ok(())
}

/// The card file NAME is single-quoted inside the recipe's `cat` command
/// and travels in the `GET /onboard?card_file=` query string, so it must
/// stay a bare, URL-safe file name: ASCII alphanumeric plus `.`, `-`, `_`.
pub fn validate_card_file_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(format!(
            "invalid card file name {name:?}: use only ASCII letters, digits, '.', '-' and '_'"
        ));
    }
    Ok(())
}

/// Build the ordered recipe steps for inviter `agent_id`.
///
/// With a card, the new agent imports the inviter's signed card (which
/// carries its public key and addresses). Without it, the new agent looks the
/// inviter up on the network by id instead.
pub fn steps(agent_id: &str, card: &Card<'_>) -> Vec<Step> {
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
                 Windows (PowerShell): `irm {INSTALL_PS1_URL} | iex` installs the binaries \
                 without starting the daemon; then run `x0xd` yourself."
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
pub fn recipe_text(agent_id: &str, card: &Card<'_>) -> String {
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
/// The card link (~20 KB) appears only inline (inside the import command)
/// when the caller chose that delivery; otherwise `card_file` names where
/// the link travels.
pub fn recipe_json(agent_id: &str, card: &Card<'_>, card_file: Option<&str>) -> serde_json::Value {
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
        "windows": format!("irm {INSTALL_PS1_URL} | iex"),
        "steps": steps,
        "reference": SKILL_URL,
    })
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
    // and is embedded only on explicit inline delivery.
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
        // Windows installs are real now (scripts/install.ps1): the recipe
        // must hand a Windows agent its one-liner, not a dead end.
        assert!(text.contains(INSTALL_PS1_URL), "Windows install missing");
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

    #[test]
    fn validators_accept_real_shapes_and_refuse_shell_breakouts() {
        assert!(validate_agent_id(ID).is_ok());
        assert!(validate_agent_id("ab12").is_err());
        assert!(validate_agent_id(&format!("{}'", &ID[..63])).is_err());
        assert!(validate_card_link(LINK).is_ok());
        assert!(validate_card_link("https://evil/x0x://agent/x").is_err());
        assert!(validate_card_link("x0x://agent/ab'; rm -rf ~").is_err());
        assert!(validate_card_file_name(FILE).is_ok());
        assert!(validate_card_file_name("a'b").is_err());
        assert!(validate_card_file_name("dir/name").is_err());
        assert!(validate_card_file_name("a b.txt").is_err());
        assert!(validate_card_file_name("").is_err());
    }
}
