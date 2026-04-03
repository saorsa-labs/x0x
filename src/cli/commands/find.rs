//! Find agents by 4-word speakable identity.

use crate::cli::{print_value, DaemonClient};
use anyhow::{bail, Context, Result};
use four_word_networking::IdentityEncoder;

/// `x0x find <words...>` — decode identity words and search for matching agents.
pub async fn find(client: &DaemonClient, words: &[String]) -> Result<()> {
    client.ensure_running().await?;

    let encoder = IdentityEncoder::new();

    // Validate input: exactly 4 words, or 4 + "@" + 4 = 9 tokens.
    let has_separator = words.iter().any(|w| w == "@");

    if has_separator {
        if words.len() != 9 {
            bail!(
                "full identity requires exactly 9 tokens: 4 words @ 4 words (got {})",
                words.len()
            );
        }
        if words[4] != "@" {
            bail!(
                "@ separator must be the 5th token (got {:?} at position 5)",
                words[4]
            );
        }
    } else if words.len() != 4 {
        bail!(
            "agent identity requires exactly 4 words (got {}). \
             For full identity use: word1 word2 word3 word4 @ word5 word6 word7 word8",
            words.len()
        );
    }

    // Decode agent prefix (first 4 words).
    let agent_words = words[..4].join(" ");
    let agent_prefix = encoder
        .decode_to_prefix(&agent_words)
        .context("failed to decode agent identity words — check spelling")?;
    let agent_prefix_hex = hex::encode(agent_prefix);

    // Optionally decode user prefix (last 4 words after @).
    let user_prefix_hex = if has_separator {
        let user_words = words[5..9].join(" ");
        let user_prefix = encoder
            .decode_to_prefix(&user_words)
            .context("failed to decode user identity words — check spelling")?;
        Some(hex::encode(user_prefix))
    } else {
        None
    };

    eprintln!("Searching for agents matching: {agent_words}");
    eprintln!("Agent ID prefix: 0x{agent_prefix_hex}");
    if let Some(ref up) = user_prefix_hex {
        eprintln!("User ID prefix:  0x{up}");
    }

    // Fetch all discovered agents (unfiltered to include expired).
    let resp = client
        .get_query("/agents/discovered", &[("unfiltered", "true")])
        .await?;

    let empty = vec![];
    let agents = resp.as_array().unwrap_or(&empty);

    let mut matches: Vec<serde_json::Value> = Vec::new();
    for agent in agents {
        let agent_id_hex = match agent.get("agent_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => continue,
        };

        if !agent_id_hex.starts_with(&agent_prefix_hex) {
            continue;
        }

        // If user words were provided, also filter by user_id prefix.
        if let Some(ref up) = user_prefix_hex {
            let user_match = agent
                .get("user_id")
                .and_then(|v| v.as_str())
                .is_some_and(|uid| uid.starts_with(up.as_str()));
            if !user_match {
                continue;
            }
        }

        let mut entry = agent.clone();
        super::identity::inject_identity_words(&encoder, &mut entry);
        matches.push(entry);
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
