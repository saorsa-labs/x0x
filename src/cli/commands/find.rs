//! Find agents by 4-word speakable identity.

use crate::cli::{print_value, DaemonClient};
use anyhow::{Context, Result};
use four_word_networking::IdentityEncoder;

/// `x0x find <words...>` — decode identity words and search for matching agents.
pub async fn find(client: &DaemonClient, words: &[String]) -> Result<()> {
    client.ensure_running().await?;

    let encoder = IdentityEncoder::new();

    // Support "word1 word2 word3 word4" (agent) or "word1 word2 word3 word4 @ word5 word6 word7 word8" (full)
    let has_separator = words.iter().any(|w| w == "@");

    // Decode the agent prefix (first 4 words, or first 4 before @)
    let agent_words: String = if has_separator {
        words
            .iter()
            .take_while(|w| w.as_str() != "@")
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        words.iter().take(4).cloned().collect::<Vec<_>>().join(" ")
    };

    let agent_prefix = encoder
        .decode_to_prefix(&agent_words)
        .context("failed to decode identity words — check spelling")?;

    let prefix_hex = hex::encode(agent_prefix);

    eprintln!("Searching for agents matching: {agent_words}");
    eprintln!("Agent ID prefix: 0x{prefix_hex}");

    // Fetch all discovered agents (unfiltered to include expired)
    let resp = client
        .get_query("/agents/discovered", &[("unfiltered", "true")])
        .await?;

    let empty = vec![];
    let agents = resp.as_array().unwrap_or(&empty);

    let mut matches: Vec<serde_json::Value> = Vec::new();
    for agent in agents {
        if let Some(agent_id_hex) = agent.get("agent_id").and_then(|v| v.as_str()) {
            if agent_id_hex.starts_with(&prefix_hex) {
                let mut entry = agent.clone();
                super::identity::inject_identity_words(&mut entry);
                matches.push(entry);
            }
        }
    }

    if matches.is_empty() {
        eprintln!("No agents found matching those words.");
        eprintln!("Try `x0x agents list` to see all discovered agents.");
    } else {
        eprintln!("Found {} matching agent(s):\n", matches.len());
        let result = serde_json::Value::Array(matches);
        print_value(client.format(), &result);
    }

    Ok(())
}
