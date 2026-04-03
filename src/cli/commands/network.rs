//! Network and status CLI commands.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;
use four_word_networking::FourWordAdaptiveEncoder;

/// Inject `location_words` for each address in `external_addrs`.
fn inject_location_words(value: &mut serde_json::Value) {
    let addr_encoder = match FourWordAdaptiveEncoder::new() {
        Ok(e) => e,
        Err(_) => return,
    };

    if let Some(obj) = value.as_object_mut() {
        if let Some(addrs) = obj
            .get("external_addrs")
            .and_then(|v| v.as_array())
            .cloned()
        {
            let location: Vec<serde_json::Value> = addrs
                .iter()
                .filter_map(|a| a.as_str())
                .filter_map(|addr| {
                    addr_encoder.encode(addr).ok().map(|words| {
                        serde_json::json!({
                            "addr": addr,
                            "location_words": words,
                        })
                    })
                })
                .collect();
            if !location.is_empty() {
                obj.insert(
                    "location_words".to_string(),
                    serde_json::Value::Array(location),
                );
            }
        }
    }
}

/// `x0x health` — GET /health
pub async fn health(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/health").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x status` — GET /status
pub async fn status(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let mut resp = client.get("/status").await?;
    let encoder = four_word_networking::IdentityEncoder::new();
    super::identity::inject_identity_words(&encoder, &mut resp);
    inject_location_words(&mut resp);
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x peers` — GET /peers
pub async fn peers(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/peers").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x presence` — GET /presence
pub async fn presence(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/presence").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x network status` — GET /network/status
pub async fn network_status(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/network/status").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x network cache` — GET /network/bootstrap-cache
pub async fn bootstrap_cache(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/network/bootstrap-cache").await?;
    print_value(client.format(), &resp);
    Ok(())
}
