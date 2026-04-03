//! Connect to an agent by 4-word location words.

use crate::cli::{print_value, DaemonClient};
use anyhow::{bail, Context, Result};
use four_word_networking::FourWordAdaptiveEncoder;

/// `x0x connect <words...>` — decode location words to IP:port and connect.
pub async fn connect(client: &DaemonClient, words: &[String]) -> Result<()> {
    if words.len() != 4 {
        bail!(
            "location words require exactly 4 words (got {})",
            words.len()
        );
    }

    client.ensure_running().await?;

    let addr_encoder =
        FourWordAdaptiveEncoder::new().context("failed to initialise address encoder")?;

    let words_str = words.join(" ");
    let addr = addr_encoder
        .decode(&words_str)
        .context("failed to decode location words — check spelling")?;

    eprintln!("Decoded location: {addr}");

    // Search discovered agents for one with a matching address.
    let resp = client
        .get_query("/agents/discovered", &[("unfiltered", "true")])
        .await?;

    let empty = vec![];
    let agents = resp.as_array().unwrap_or(&empty);

    let mut found_agent_id: Option<String> = None;
    for agent in agents {
        let addrs = agent
            .get("addresses")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let matches = addrs.iter().any(|a| a.as_str() == Some(addr.as_str()));
        if matches {
            if let Some(id) = agent.get("agent_id").and_then(|v| v.as_str()) {
                found_agent_id = Some(id.to_string());
                break;
            }
        }
    }

    let agent_id = match found_agent_id {
        Some(id) => id,
        None => {
            bail!(
                "no discovered agent at {addr}. \
                 Make sure the target agent has announced on the gossip network \
                 and appears in `x0x agents list`."
            );
        }
    };

    let id_encoder = four_word_networking::IdentityEncoder::new();
    let identity = id_encoder
        .encode_hex(&agent_id)
        .map(|w| w.to_string())
        .unwrap_or_default();

    eprintln!("Found agent: {identity} ({agent_id})");
    eprintln!("Connecting...");

    let body = serde_json::json!({ "agent_id": agent_id });
    let resp = client.post("/agents/connect", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}
