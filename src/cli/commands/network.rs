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

/// `x0x diagnostics connectivity` — GET /diagnostics/connectivity
///
/// Prints the ant-quic NodeStatus snapshot as JSON. Includes UPnP port-mapping
/// state, NAT type, mDNS discovery state, direct vs relayed connection counts,
/// hole-punch success rate, and advertised external addresses. Primary tool
/// for answering "is ant-quic's 100%-connectivity promise holding?".
pub async fn diagnostics_connectivity(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/diagnostics/connectivity").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x diagnostics gossip` — GET /diagnostics/gossip
///
/// Prints PubSub drop-detection counters. Non-zero `decode_to_delivery_drops`
/// means messages reached the local pipeline but failed to hand off to the
/// subscriber channel (buffer full or dropped subscription). Primary tool
/// for the 100%-delivery proof under stress.
pub async fn diagnostics_gossip(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/diagnostics/gossip").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x diagnostics dm` — GET /diagnostics/dm
///
/// Prints direct-message send/receive counters, subscriber fan-out health, and
/// per-peer timing/path state.
pub async fn diagnostics_dm(client: &DaemonClient) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get("/diagnostics/dm").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x peers probe <peer_id>` — POST /peers/:peer_id/probe
///
/// Active liveness probe (ant-quic 0.27.2 #173). Sends a lightweight probe
/// envelope and waits for the remote reader's ACK-v1 reply. Prints measured
/// round-trip time.
pub async fn peers_probe(
    client: &DaemonClient,
    peer_id: &str,
    timeout_ms: Option<u64>,
) -> Result<()> {
    client.ensure_running().await?;
    let path = if let Some(ms) = timeout_ms {
        format!("/peers/{peer_id}/probe?timeout_ms={ms}")
    } else {
        format!("/peers/{peer_id}/probe")
    };
    let resp = client.post_empty(&path).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x peers health <peer_id>` — GET /peers/:peer_id/health
///
/// Connection health snapshot for a peer (ant-quic 0.27.1 #170). Returns
/// lifecycle state, generation, directional activity timestamps, and the
/// most-recent close reason.
pub async fn peers_health(client: &DaemonClient, peer_id: &str) -> Result<()> {
    client.ensure_running().await?;
    let resp = client.get(&format!("/peers/{peer_id}/health")).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x peers events` — GET /peers/events (SSE).
///
/// Streams peer lifecycle transitions (`Established`, `Replaced`, `Closing`,
/// `Closed`, `ReaderExited`) as they occur. Prints each event as a JSON
/// line to stdout. Press Ctrl-C to stop.
pub async fn peers_events(client: &DaemonClient) -> Result<()> {
    use futures::StreamExt as _;
    client.ensure_running().await?;
    let resp = client.get_stream("/peers/events").await?;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| anyhow::anyhow!("stream error: {e}"))?;
        let s = String::from_utf8_lossy(&bytes);
        print!("{s}");
    }
    Ok(())
}
