//! Identity CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;
use four_word_networking::IdentityEncoder;

/// Compute 4-word speakable identity from a hex agent/user ID.
fn identity_words(encoder: &IdentityEncoder, hex_id: &str) -> Option<String> {
    encoder.encode_hex(hex_id).ok().map(|w| w.to_string())
}

/// Inject `identity_words` field into a JSON object next to an `agent_id` field.
pub fn inject_identity_words(encoder: &IdentityEncoder, value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        if let Some(agent_hex) = obj
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            if let Some(words) = identity_words(encoder, &agent_hex) {
                obj.insert(
                    "identity_words".to_string(),
                    serde_json::Value::String(words),
                );
            }
        }
        if let Some(user_hex) = obj
            .get("user_id")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            if let Some(words) = identity_words(encoder, &user_hex) {
                obj.insert("user_words".to_string(), serde_json::Value::String(words));
            }
        }
    }
}

/// `x0x agent` — GET /agent
pub async fn agent(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let mut resp = client.get("/agent").await?;
    let encoder = IdentityEncoder::new();
    inject_identity_words(&encoder, &mut resp);
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agent user-id` — GET /agent/user-id
pub async fn user_id(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/agent/user-id").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x announce` — POST /announce
pub async fn announce(client: &DaemonClient, include_user: bool, consent: bool) -> Result<()> {
    client.ensure_running().await?;
    let body = serde_json::json!({
        "include_user_identity": include_user,
        "human_consent": consent,
    });
    let resp = client.post("/announce", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agent card` — GET /agent/card
pub async fn card(
    client: &DaemonClient,
    display_name: Option<&str>,
    include_groups: bool,
) -> Result<()> {
    client.ensure_running().await?;
    let mut params = Vec::new();
    if let Some(name) = display_name {
        params.push(format!("display_name={name}"));
    }
    if include_groups {
        params.push("include_groups=true".to_string());
    }
    let query = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };
    let resp = client.get(&format!("/agent/card{query}")).await?;

    // Print the link prominently
    if let Some(link) = resp.get("link").and_then(|v| v.as_str()) {
        eprintln!("\nYour shareable identity card:\n");
        eprintln!("  {link}\n");
        eprintln!("Share this link with anyone — they can import it with:");
        eprintln!("  x0x agent import <link>\n");
    }
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x agent import` — POST /agent/card/import
pub async fn import_card(
    client: &DaemonClient,
    card_link: &str,
    trust_level: Option<&str>,
) -> Result<()> {
    client.ensure_running().await?;
    let mut body = serde_json::json!({ "card": card_link });
    if let Some(tl) = trust_level {
        body["trust_level"] = serde_json::Value::String(tl.to_string());
    }
    let resp = client.post("/agent/card/import", &body).await?;
    print_value(client.format(), &resp);
    Ok(())
}
