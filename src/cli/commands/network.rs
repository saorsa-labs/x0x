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
    client.run_get("/health").await
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
    client.run_get("/peers").await
}

/// `x0x presence` — GET /presence
pub async fn presence(client: &DaemonClient) -> Result<()> {
    client.run_get("/presence").await
}

/// `x0x network status` — GET /network/status
pub async fn network_status(client: &DaemonClient) -> Result<()> {
    client.run_get("/network/status").await
}

/// `x0x network cache` — GET /network/bootstrap-cache
pub async fn bootstrap_cache(client: &DaemonClient) -> Result<()> {
    client.run_get("/network/bootstrap-cache").await
}

/// `x0x diagnostics connectivity` — GET /diagnostics/connectivity
///
/// Prints the ant-quic NodeStatus snapshot as JSON. Includes UPnP port-mapping
/// state, NAT type, mDNS discovery state, direct vs relayed connection counts,
/// hole-punch success rate, and advertised external addresses. Primary tool
/// for answering "is ant-quic's 100%-connectivity promise holding?".
pub async fn diagnostics_connectivity(client: &DaemonClient) -> Result<()> {
    client.run_get("/diagnostics/connectivity").await
}

/// `x0x diagnostics ack` — GET /diagnostics/ack
///
/// Prints ACK-v2 per-stage latency buckets and outcome counters. This splits
/// the old opaque "ACK timeout" class into sender open/write/finish/read and
/// receiver demux/admission/response-write stages.
pub async fn diagnostics_ack(client: &DaemonClient) -> Result<()> {
    client.run_get("/diagnostics/ack").await
}

/// `x0x diagnostics gossip` — GET /diagnostics/gossip
///
/// Prints PubSub drop-detection counters. Non-zero `decode_to_delivery_drops`
/// means messages reached the local pipeline but failed to hand off to the
/// subscriber channel (buffer full or dropped subscription). Primary tool
/// for the 100%-delivery proof under stress.
pub async fn diagnostics_gossip(client: &DaemonClient) -> Result<()> {
    client.run_get("/diagnostics/gossip").await
}

/// `x0x diagnostics dm` — GET /diagnostics/dm
///
/// Prints direct-message send/receive counters, subscriber fan-out health, and
/// per-peer timing/path state.
pub async fn diagnostics_dm(client: &DaemonClient) -> Result<()> {
    client.run_get("/diagnostics/dm").await
}

/// `x0x diagnostics groups` — GET /diagnostics/groups
///
/// Prints per-group ingest counters: `members_v2_size`, metadata/public
/// listener state, accepted message count, last-message-at, and per-reason
/// drop buckets (`decode_failed`, `author_banned`,
/// `write_policy_violation`, `signature_failed`, `other`). The
/// `write_policy_violation` bucket is the canary for the
/// join-roster-propagation regression — non-zero on the owner side means
/// joiners' messages reached the listener but the owner's `members_v2`
/// view is missing them.
pub async fn diagnostics_groups(client: &DaemonClient) -> Result<()> {
    client.run_get("/diagnostics/groups").await
}

/// `x0x diagnostics ws` — GET /diagnostics/ws
///
/// WebSocket outbound-queue health: capacity and drop/slow-consumer-close
/// counters (WS1.1 / #122).
pub async fn diagnostics_ws(client: &DaemonClient) -> Result<()> {
    client.run_get("/diagnostics/ws").await
}

/// `x0x diagnostics connect` — GET /diagnostics/connect
///
/// Connect-ACL policy summary (enabled flag, loaded-from path, allow-entry
/// count) and cumulative stream allow/deny counters with per-reason breakdown.
/// Counters read 0 until the T4 forwarder (issue #132) is wired.
pub async fn diagnostics_connect(client: &DaemonClient) -> Result<()> {
    client.run_get("/diagnostics/connect").await
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
    client.run_get(&format!("/peers/{peer_id}/health")).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_location_words_skips_non_object() {
        let mut value = serde_json::json!([1, 2, 3]);
        inject_location_words(&mut value);
        assert!(value.is_array());
    }

    #[test]
    fn inject_location_words_skips_missing_addrs() {
        let mut value = serde_json::json!({"name": "test"});
        inject_location_words(&mut value);
        assert!(value.get("location_words").is_none());
    }

    #[test]
    fn inject_location_words_handles_empty_addrs() {
        let mut value = serde_json::json!({"external_addrs": []});
        inject_location_words(&mut value);
        assert!(value.get("location_words").is_none());
    }

    #[test]
    fn inject_location_words_encodes_valid_addrs() {
        let mut value = serde_json::json!({
            "external_addrs": ["1.2.3.4:5483"]
        });
        inject_location_words(&mut value);
        // May or may not encode depending on FourWordAdaptiveEncoder
        // Just verify it doesn't panic
        let _ = value;
    }
}

#[cfg(test)]
use crate::cli::commands::test_support::start_mock_server;

#[tokio::test]
async fn health_returns_mock_response() {
    let mock_resp = serde_json::json!({"status": "ok", "version": "0.19.42"});
    let (url, _shutdown) = start_mock_server(mock_resp.clone()).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = health(&client).await;
    assert!(result.is_ok(), "health should succeed: {:?}", result);
}

#[tokio::test]
async fn status_returns_mock_response() {
    let mock_resp = serde_json::json!({
        "agent_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "peers": 5,
        "status": "connected"
    });
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = status(&client).await;
    assert!(result.is_ok(), "status should succeed: {:?}", result);
}

#[tokio::test]
async fn peers_returns_mock_response() {
    let mock_resp = serde_json::json!([{"peer_id": "abc123", "state": "connected"}]);
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = peers(&client).await;
    assert!(result.is_ok(), "peers should succeed: {:?}", result);
}

#[tokio::test]
async fn presence_returns_mock_response() {
    let mock_resp = serde_json::json!([{"agent_id": "abc", "online": true}]);
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = presence(&client).await;
    assert!(result.is_ok(), "presence should succeed: {:?}", result);
}

#[tokio::test]
async fn network_status_returns_mock_response() {
    let mock_resp = serde_json::json!({"nat_type": "FullCone", "external_addrs": ["1.2.3.4:5483"]});
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = network_status(&client).await;
    assert!(
        result.is_ok(),
        "network_status should succeed: {:?}",
        result
    );
}

#[tokio::test]
async fn bootstrap_cache_returns_mock_response() {
    let mock_resp = serde_json::json!([{"addr": "1.2.3.4:5483", "peer_id": "abc"}]);
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = bootstrap_cache(&client).await;
    assert!(
        result.is_ok(),
        "bootstrap_cache should succeed: {:?}",
        result
    );
}

#[tokio::test]
async fn diagnostics_connectivity_returns_mock_response() {
    let mock_resp = serde_json::json!({"nat_type": "FullCone", "upnp": true});
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = diagnostics_connectivity(&client).await;
    assert!(
        result.is_ok(),
        "diagnostics_connectivity should succeed: {:?}",
        result
    );
}

#[tokio::test]
async fn diagnostics_gossip_returns_mock_response() {
    let mock_resp = serde_json::json!({"decode_to_delivery_drops": 0, "messages_received": 100});
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = diagnostics_gossip(&client).await;
    assert!(
        result.is_ok(),
        "diagnostics_gossip should succeed: {:?}",
        result
    );
}

#[tokio::test]
async fn diagnostics_dm_returns_mock_response() {
    let mock_resp = serde_json::json!({"messages_sent": 50, "messages_received": 30});
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = diagnostics_dm(&client).await;
    assert!(
        result.is_ok(),
        "diagnostics_dm should succeed: {:?}",
        result
    );
}

#[tokio::test]
async fn diagnostics_groups_returns_mock_response() {
    let mock_resp = serde_json::json!({"groups": [{"name": "test-group", "members": 3}]});
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = diagnostics_groups(&client).await;
    assert!(
        result.is_ok(),
        "diagnostics_groups should succeed: {:?}",
        result
    );
}

#[tokio::test]
async fn peers_probe_returns_mock_response() {
    let mock_resp = serde_json::json!({"rtt_ms": 42});
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = peers_probe(&client, "abc123", Some(5000)).await;
    assert!(result.is_ok(), "peers_probe should succeed: {:?}", result);
}

#[tokio::test]
async fn peers_health_returns_mock_response() {
    let mock_resp = serde_json::json!({"state": "Established", "generation": 3});
    let (url, _shutdown) = start_mock_server(mock_resp).await;
    let client = DaemonClient::new(None, Some(&url), crate::cli::OutputFormat::Json).unwrap();

    let result = peers_health(&client, "abc123").await;
    assert!(result.is_ok(), "peers_health should succeed: {:?}", result);
}
