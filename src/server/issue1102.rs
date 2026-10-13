//! Issue #1102: a raw file offer on a live connection, after the receiver's
//! discovery cache and authenticated-binding registry are emptied.
//!
//! The issue's runtime claim is a hypothesis. This test builds that shape
//! with the test seams: two loopback daemons, a live QUIC connection, then
//! an empty receiver authority (no discovery entry, no binding, no usable
//! relationship evidence). `POST /files/send` must not report success while
//! the offer stays absent from the receiver.

#![cfg(test)]

use super::{serve_with_options, DaemonConfig, ServeOptions};
use crate::dm_capability;
use crate::identity::{AgentId, MachineId};
use crate::DiscoveredAgent;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::time::Duration;

fn daemon_config(root: &std::path::Path, name: &str, plane: &str) -> DaemonConfig {
    let dir = root.join(name);
    let config: DaemonConfig = serde_json::from_value(serde_json::json!({
        "bind_address": "127.0.0.1:0",
        "api_address": "127.0.0.1:0",
        "data_dir": dir.join("data"),
        "identity_dir": dir.join("identity"),
        "bootstrap_peers": [],
        "mdns_enabled": false,
        "port_mapping_enabled": false,
        "network_id": plane,
        "update": {"enabled": false}
    }))
    .expect("loopback daemon config");
    assert!(
        config.resolved_bootstrap_peers().is_empty(),
        "the fixture must not dial fleet seeds"
    );
    assert_eq!(
        config.resolved_network_id().as_deref(),
        Some(plane),
        "both daemons share one private plane"
    );
    config
}

fn serve_options() -> ServeOptions {
    ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    }
}

fn token_for(data_dir: &std::path::Path) -> String {
    std::fs::read_to_string(data_dir.join("api-token"))
        .expect("api-token")
        .trim()
        .to_string()
}

fn authed_client(token: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(25))
        .build()
        .expect("client")
}

fn receiver_card(agent_id: AgentId, machine_id: MachineId, udp: SocketAddr) -> DiscoveredAgent {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    DiscoveredAgent {
        self_name: None,
        cert_digest: None,
        agent_id,
        machine_id,
        user_id: None,
        addresses: vec![udp],
        announced_at: now,
        last_seen: now,
        machine_public_key: Vec::new(),
        nat_type: None,
        can_receive_direct: Some(true),
        is_relay: None,
        is_coordinator: None,
        reachable_via: Vec::new(),
        relay_candidates: Vec::new(),
        cert_not_after: None,
        agent_certificate: None,
        agent_public_key: Vec::new(),
    }
}

fn file_frame_kind(payload: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(payload)
        .ok()
        .and_then(|value| {
            value
                .get("type")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

fn offer_is_pending(body: &Value, filename: &str) -> bool {
    body["transfers"].as_array().is_some_and(|transfers| {
        transfers.iter().any(|transfer| {
            transfer["direction"].as_str() == Some("Receiving")
                && transfer["filename"].as_str() == Some(filename)
                && transfer["status"].as_str() == Some("Pending")
        })
    })
}

async fn post_offer(
    api: SocketAddr,
    token: &str,
    agent_hex: &str,
    filename: &str,
    payload: &[u8],
) -> (u16, String) {
    let sha = hex::encode(Sha256::digest(payload));
    let client = authed_client(token);
    match client
        .post(format!("http://{api}/files/send"))
        .json(&serde_json::json!({
            "agent_id": agent_hex,
            "filename": filename,
            "size": payload.len(),
            "sha256": sha,
            "data_b64": base64::engine::general_purpose::STANDARD.encode(payload),
        }))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status().as_u16();
            let text = response.text().await.unwrap_or_default();
            (status, text)
        }
        Err(error) => (0, error.to_string()),
    }
}

fn send_ok(status: u16, body: &str) -> bool {
    status == 200 && serde_json::from_str::<Value>(body).is_ok_and(|value| value["ok"] == true)
}

fn advertise_file_control(agent: &crate::Agent, peer: AgentId, machine: MachineId) {
    // Keep the gossip inbox off so the live raw path stays the transport.
    // The registry bit is what the file waiter reads.
    let mut capabilities = crate::dm::DmCapabilities::pending();
    capabilities.application_registry = crate::dm::CapabilityRegistry::current();
    assert!(
        agent
            .capability_store()
            .insert(peer, machine, capabilities, dm_capability::now_unix_ms(),),
        "the peer must advertise file_control_ack_v1"
    );
}

fn http_500(status: u16, body: &str) -> bool {
    status == 500 && serde_json::from_str::<Value>(body).is_ok_and(|value| value["ok"] == false)
}

async fn post_accept(api: SocketAddr, token: &str, transfer_id: &str) -> (u16, String) {
    let client = authed_client(token);
    match client
        .post(format!("http://{api}/files/accept/{transfer_id}"))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status().as_u16();
            let text = response.text().await.unwrap_or_default();
            (status, text)
        }
        Err(error) => (0, error.to_string()),
    }
}

async fn sending_offer_status(api: SocketAddr, token: &str, filename: &str) -> String {
    let client = authed_client(token);
    let Ok(response) = client
        .get(format!("http://{api}/files/transfers"))
        .send()
        .await
    else {
        return String::new();
    };
    let text = response.text().await.unwrap_or_default();
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|value| {
            value["transfers"].as_array().and_then(|transfers| {
                transfers.iter().find_map(|transfer| {
                    if transfer["direction"].as_str() == Some("Sending")
                        && transfer["filename"].as_str() == Some(filename)
                    {
                        transfer["status"].as_str().map(str::to_string)
                    } else {
                        None
                    }
                })
            })
        })
        .unwrap_or(text)
}

async fn sending_status(api: SocketAddr, token: &str, transfer_id: &str) -> String {
    let client = authed_client(token);
    let Ok(response) = client
        .get(format!("http://{api}/files/transfers/{transfer_id}"))
        .send()
        .await
    else {
        return String::new();
    };
    let text = response.text().await.unwrap_or_default();
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|value| value["transfer"]["status"].as_str().map(str::to_string))
        .unwrap_or(text)
}

async fn clear_peer_authority(agent: &crate::Agent, peer: AgentId, machine: MachineId) {
    // An in-flight evidence lookup can restore the peer after one clear.
    // Let that lookup land, then clear again immediately before the frame.
    for _ in 0..2 {
        agent.identity_discovery_cache().write().await.clear();
        agent
            .authenticated_machine_bindings_for_testing()
            .write()
            .await
            .clear_for_test();
        agent
            .announced_machine_bindings_for_testing()
            .write()
            .await
            .clear_for_test();
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    agent.identity_discovery_cache().write().await.clear();
    agent
        .authenticated_machine_bindings_for_testing()
        .write()
        .await
        .clear_for_test();
    agent
        .announced_machine_bindings_for_testing()
        .write()
        .await
        .clear_for_test();
    let cache_has_peer = agent
        .identity_discovery_cache()
        .read()
        .await
        .contains_key(&peer);
    let binding = agent
        .authenticated_machine_bindings_for_testing()
        .read()
        .await
        .peek(&peer);
    let evidence_usable = agent
        .peer_evidence()
        .usable(peer, machine, dm_capability::now_unix_ms());
    assert!(
        !cache_has_peer && binding.is_none() && evidence_usable.is_none(),
        "precondition failed: cache={cache_has_peer} binding={} evidence={}",
        binding.is_some(),
        evidence_usable.is_some()
    );
}

async fn verified_flag_of(
    direct: &mut crate::direct::DirectMessageReceiver,
    kind: &str,
    from: AgentId,
) -> Option<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            message = direct.recv() => {
                let message = message?;
                if message.sender == from
                    && file_frame_kind(&message.payload).as_deref() == Some(kind)
                {
                    return Some(message.verified);
                }
            }
        }
    }
}

async fn pending_offer_now(api: SocketAddr, token: &str, filename: &str) -> (bool, String) {
    let client = authed_client(token);
    let Ok(response) = client
        .get(format!("http://{api}/files/transfers"))
        .send()
        .await
    else {
        return (false, String::new());
    };
    let body = response.text().await.unwrap_or_default();
    let seen =
        serde_json::from_str::<Value>(&body).is_ok_and(|value| offer_is_pending(&value, filename));
    (seen, body)
}

async fn pending_offer(api: SocketAddr, token: &str, filename: &str) -> (bool, String) {
    let client = authed_client(token);
    let mut last = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Ok(response) = client
            .get(format!("http://{api}/files/transfers"))
            .send()
            .await
        {
            last = response.text().await.unwrap_or_default();
            if serde_json::from_str::<Value>(&last)
                .is_ok_and(|value| offer_is_pending(&value, filename))
            {
                return (true, last);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (false, last)
}

/// Clear discovery and both binding registries, keep the QUIC connection,
/// and send one raw-capable file offer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1102_raw_offer_from_unverified_sender_is_not_a_silent_success() {
    let root = tempfile::tempdir().expect("tempdir");
    let plane = format!("x0x.test.issue1102.{:032x}", rand::random::<u128>());
    let sender_cfg = daemon_config(root.path(), "sender", &plane);
    let receiver_cfg = daemon_config(root.path(), "receiver", &plane);
    let sender_data = sender_cfg.data_dir.clone();
    let receiver_data = receiver_cfg.data_dir.clone();

    let sender = serve_with_options(sender_cfg, serve_options())
        .await
        .expect("sender serve");
    let receiver = serve_with_options(receiver_cfg, serve_options())
        .await
        .expect("receiver serve");
    let sender_state = sender.test_state.upgrade().expect("sender state");
    let receiver_state = receiver.test_state.upgrade().expect("receiver state");

    let receiver_udp = receiver_state
        .agent
        .network()
        .expect("receiver network")
        .bound_addr()
        .await
        .expect("receiver udp");
    assert!(receiver_udp.ip().is_loopback());
    let receiver_agent = receiver_state.agent.agent_id();
    let receiver_machine = receiver_state.agent.machine_id();
    let sender_agent = sender_state.agent.agent_id();
    let sender_machine = sender_state.agent.machine_id();

    sender_state
        .agent
        .insert_discovered_agent_for_testing(receiver_card(
            receiver_agent,
            receiver_machine,
            receiver_udp,
        ))
        .await;
    sender_state
        .agent
        .network()
        .expect("sender network")
        .connect_addr(receiver_udp)
        .await
        .expect("dial receiver");

    let receiver_peer = ant_quic::PeerId(receiver_machine.0);
    let connected_deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let sender_network = sender_state.agent.network().expect("sender network");
    while !sender_network.is_connected(&receiver_peer).await {
        assert!(
            tokio::time::Instant::now() < connected_deadline,
            "raw connection never came up"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let sender_api = sender.local_addr();
    let receiver_api = receiver.local_addr();
    let sender_token = token_for(&sender_data);
    let receiver_token = token_for(&receiver_data);
    let receiver_hex = hex::encode(receiver_agent.as_bytes());

    let announced_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let known = receiver_state
            .agent
            .identity_discovery_cache()
            .read()
            .await
            .contains_key(&sender_agent);
        if known {
            break;
        }
        assert!(
            tokio::time::Instant::now() < announced_deadline,
            "receiver never learned the sender"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    advertise_file_control(&sender_state.agent, receiver_agent, receiver_machine);
    advertise_file_control(&receiver_state.agent, sender_agent, sender_machine);

    let (warm_status, warm_body) = post_offer(
        sender_api,
        &sender_token,
        &receiver_hex,
        "issue1102-warm.bin",
        b"warm-offer",
    )
    .await;
    let (warm_seen, warm_transfers) =
        pending_offer(receiver_api, &receiver_token, "issue1102-warm.bin").await;
    let warm_ok = send_ok(warm_status, &warm_body) && warm_seen;
    assert!(
        warm_ok,
        "a verified sender must still complete an offer: status={warm_status} body={warm_body} transfers={warm_transfers}"
    );
    let warm_transfer_id = serde_json::from_str::<Value>(&warm_body)
        .ok()
        .and_then(|value| value["transfer_id"].as_str().map(str::to_string))
        .expect("warm transfer id");

    // Accept travels receiver → sender. Empty the sender's authority and keep
    // the QUIC connection. The receiver can still address the sender.
    clear_peer_authority(&sender_state.agent, receiver_agent, receiver_machine).await;
    advertise_file_control(&receiver_state.agent, sender_agent, sender_machine);
    assert!(
        sender_network.is_connected(&receiver_peer).await,
        "clearing sender authority must keep the raw connection"
    );
    let mut sender_direct = sender_state.agent.subscribe_direct();
    let accept_post = post_accept(receiver_api, &receiver_token, &warm_transfer_id);
    let accept_frame_wait = verified_flag_of(&mut sender_direct, "file-accept", receiver_agent);
    let ((accept_status, accept_body), accept_frame) = tokio::join!(accept_post, accept_frame_wait);
    let accept_failed = http_500(accept_status, &accept_body);
    let sender_status = sending_status(sender_api, &sender_token, &warm_transfer_id).await;
    let receiver_status = sending_status(receiver_api, &receiver_token, &warm_transfer_id).await;

    // Offer travels sender → receiver. Put the receiver card back so the
    // sender can address the peer, then empty the receiver's authority.
    sender_state
        .agent
        .insert_discovered_agent_for_testing(receiver_card(
            receiver_agent,
            receiver_machine,
            receiver_udp,
        ))
        .await;
    clear_peer_authority(&receiver_state.agent, sender_agent, sender_machine).await;
    advertise_file_control(&sender_state.agent, receiver_agent, receiver_machine);
    assert!(
        sender_network.is_connected(&receiver_peer).await,
        "clearing receiver authority must keep the raw connection"
    );

    let mut receiver_direct = receiver_state.agent.subscribe_direct();
    let cold_post = post_offer(
        sender_api,
        &sender_token,
        &receiver_hex,
        "issue1102-cold.bin",
        b"cold-offer",
    );
    let offer_frame_wait = verified_flag_of(&mut receiver_direct, "file-offer", sender_agent);
    let ((status, body), offer_frame) = tokio::join!(cold_post, offer_frame_wait);
    let cold_failed = http_500(status, &body);
    let (offer_seen, transfers_body) =
        pending_offer_now(receiver_api, &receiver_token, "issue1102-cold.bin").await;
    let local_offer_status =
        sending_offer_status(sender_api, &sender_token, "issue1102-cold.bin").await;
    let still_connected = sender_network.is_connected(&receiver_peer).await;
    let drops = super::routes::unverified_file_frame_drops();

    let report = serde_json::json!({
        "warm_status": warm_status,
        "warm_seen": warm_seen,
        "accept_status": accept_status,
        "accept_body": accept_body,
        "accept_failed": accept_failed,
        "accept_frame_verified": accept_frame,
        "sender_status": sender_status,
        "receiver_status": receiver_status,
        "status": status,
        "body": body,
        "cold_failed": cold_failed,
        "local_offer_status": local_offer_status,
        "offer_frame_verified": offer_frame,
        "offer_seen": offer_seen,
        "transfers": transfers_body,
        "still_connected": still_connected,
        "unverified_drops": drops,
    });

    let _ = tokio::time::timeout(Duration::from_secs(20), sender.shutdown_and_wait()).await;
    let _ = tokio::time::timeout(Duration::from_secs(20), receiver.shutdown_and_wait()).await;

    assert_eq!(
        accept_frame,
        Some(false),
        "the accept must arrive on the live connection and stay unverified ({report})"
    );
    assert!(
        accept_failed,
        "a dropped accept must return HTTP 500 ({report})"
    );
    assert_eq!(
        sender_status, "Pending",
        "a dropped accept must leave the sending transfer pending ({report})"
    );
    assert_eq!(
        receiver_status, "Pending",
        "a dropped accept must return the receive to pending ({report})"
    );
    assert_eq!(
        offer_frame,
        Some(false),
        "the cold offer must arrive on the live connection and stay unverified ({report})"
    );
    assert!(
        !offer_seen,
        "an unverified offer must not become a pending transfer ({report})"
    );
    assert!(
        cold_failed,
        "a dropped offer must return HTTP 500 ({report})"
    );
    assert_eq!(
        local_offer_status, "Failed",
        "a dropped offer must be Failed on the sender ({report})"
    );
    assert!(
        still_connected,
        "the raw connection must stay up ({report})"
    );
}
