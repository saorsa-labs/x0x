//! Route handlers (`category: "network"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::state::AppState;
use super::super::{api_error, bad_request};
use crate as x0x;
use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Peer entry.
#[derive(Debug, Serialize)]
pub(in crate::server) struct PeerEntry {
    id: String,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/// GET /network/status — NAT traversal diagnostics and connection stats.
pub(in crate::server) async fn network_status(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized");
    };

    let Some(status) = network.node_status().await else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "node not available");
    };

    let nat_type_str = format!("{:?}", status.nat_type);

    // Collect all known addresses: ant-quic observed + local global IPv6.
    // ant-quic currently only reports IPv4 via OBSERVED_ADDRESS frames,
    // so we detect our global IPv6 locally using a UDP socket connect trick
    // (no data sent — the OS routing table resolves our source address).
    let mut all_addrs: Vec<String> = status
        .external_addrs
        .iter()
        .map(|a| a.to_string())
        .collect();
    let mut has_global_address = status.has_global_address;

    let port = status.local_addr.port();

    // Discover global IPv4 address using UDP socket trick.
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                if let std::net::IpAddr::V4(v4) = local.ip() {
                    if !v4.is_loopback() && !v4.is_unspecified() {
                        if !v4.is_private() && !v4.is_link_local() {
                            has_global_address = true;
                        }
                        // Include our locally inferred IPv4 candidate even when it is LAN-only.
                        let addr_str = format!("{v4}:{port}");
                        if !all_addrs.contains(&addr_str) {
                            all_addrs.push(addr_str);
                        }
                    }
                }
            }
        }
    }

    // Discover global IPv6 address using UDP socket trick.
    if let Ok(sock) = std::net::UdpSocket::bind("[::]:0") {
        if sock.connect("[2001:4860:4860::8888]:80").is_ok() {
            if let Ok(local) = sock.local_addr() {
                if let std::net::IpAddr::V6(v6) = local.ip() {
                    let segs = v6.segments();
                    let is_global = (segs[0] & 0xffc0) != 0xfe80  // not link-local
                        && (segs[0] & 0xff00) != 0xfd00           // not ULA
                        && !v6.is_loopback();
                    if is_global {
                        has_global_address = true;
                        let addr_str = format!("[{v6}]:{port}");
                        if !all_addrs.contains(&addr_str) {
                            all_addrs.push(addr_str);
                        }
                    }
                }
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "local_addr": status.local_addr.to_string(),
            "external_addrs": all_addrs,
            "nat_type": nat_type_str,
            "has_global_address": has_global_address,
            "can_receive_direct": status.can_receive_direct,
            "connected_peers": status.connected_peers,
            "direct_connections": status.direct_connections,
            "relayed_connections": status.relayed_connections,
            "hole_punch_success_rate": status.hole_punch_success_rate,
            "is_relaying": status.is_relaying,
            "relay_sessions": status.relay_sessions,
            "is_coordinating": status.is_coordinating,
            "coordination_sessions": status.coordination_sessions,
            "avg_rtt_ms": status.avg_rtt.as_millis() as u64,
            "uptime_secs": status.uptime.as_secs(),
        })),
    )
}

/// GET /peers
pub(in crate::server) async fn peers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.agent.peers().await {
        Ok(peer_list) => {
            let entries: Vec<PeerEntry> = peer_list
                .into_iter()
                .map(|p| PeerEntry {
                    id: hex::encode(p.to_bytes()),
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "peers": entries })),
            )
        }
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
    }
}

/// GET /network/bootstrap-cache — bootstrap peer cache statistics.
pub(in crate::server) async fn bootstrap_cache_stats(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Access bootstrap cache via the network node if available
    match state.agent.network() {
        Some(network) => {
            let connection_count = network.connection_count().await;
            let connected_peers = network.connected_peers().await;
            let peer_addrs: Vec<String> =
                connected_peers.iter().map(|a| format!("{a:?}")).collect();

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "connection_count": connection_count,
                    "connected_peers": peer_addrs
                })),
            )
        }
        None => api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized"),
    }
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn value_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .as_object()
        .and_then(|obj| obj.get(key))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
}

fn augment_pubsub_stage_diagnostics<T>(snapshot: Option<T>) -> serde_json::Value
where
    T: Serialize,
{
    let Ok(mut value) = serde_json::to_value(snapshot) else {
        return serde_json::Value::Null;
    };
    let Some(obj) = value.as_object_mut() else {
        return value;
    };

    if !obj.contains_key("suppressed_peers_by_topic") {
        let mut by_topic: BTreeMap<String, Vec<String>> = BTreeMap::new();
        if let Some(rows) = obj.get("suppressed_peers").and_then(|v| v.as_array()) {
            for row in rows {
                let Some(topic) = value_string_field(row, "topic") else {
                    continue;
                };
                let Some(peer_id) = value_string_field(row, "peer_id") else {
                    continue;
                };
                by_topic.entry(topic).or_default().push(peer_id);
            }
        }
        for peers in by_topic.values_mut() {
            peers.sort();
            peers.dedup();
        }
        obj.insert(
            "suppressed_peers_by_topic".to_string(),
            serde_json::json!(by_topic),
        );
    }

    if !obj.contains_key("peer_scores_by_topic") {
        let mut suppression_by_topic_peer: BTreeMap<(String, String), serde_json::Value> =
            BTreeMap::new();
        if let Some(rows) = obj.get("suppressed_peers").and_then(|v| v.as_array()) {
            for row in rows {
                let Some(topic) = value_string_field(row, "topic") else {
                    continue;
                };
                let Some(peer_id) = value_string_field(row, "peer_id") else {
                    continue;
                };
                suppression_by_topic_peer.insert((topic, peer_id), row.clone());
            }
        }

        let mut by_topic: BTreeMap<String, BTreeMap<String, serde_json::Value>> = BTreeMap::new();
        if let Some(rows) = obj.get("peer_scores").and_then(|v| v.as_array()) {
            for row in rows {
                let Some(topic) = value_string_field(row, "topic") else {
                    continue;
                };
                let Some(peer_id) = value_string_field(row, "peer_id") else {
                    continue;
                };
                let suppressed = suppression_by_topic_peer.get(&(topic.clone(), peer_id.clone()));
                by_topic.entry(topic).or_default().insert(
                    peer_id,
                    serde_json::json!({
                        "role": row.get("role").cloned().unwrap_or(serde_json::Value::Null),
                        "score": row.get("score").cloned().unwrap_or(serde_json::Value::Null),
                        "send_health": row.get("send_health").cloned().unwrap_or(serde_json::Value::Null),
                        "outbound_send_timeouts": row
                            .get("outbound_send_timeouts")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "cooling_events": row
                            .get("cooling_events")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "eager_eligible": row
                            .get("eager_eligible")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "suppression_state": suppressed
                            .and_then(|s| s.get("state"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "recent_timeout_count": suppressed
                            .and_then(|s| s.get("recent_timeout_count"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "cooldown_ms": suppressed
                            .and_then(|s| s.get("cooldown_ms"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "last_cool_at_unix_ms": suppressed
                            .and_then(|s| s.get("last_suppressed_unix_ms"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                    }),
                );
            }
        }
        obj.insert(
            "peer_scores_by_topic".to_string(),
            serde_json::json!(by_topic),
        );
    }

    if !obj.contains_key("admission_state_by_peer") {
        #[derive(Default)]
        struct AdmissionCounts {
            suppressed: usize,
            cooled: usize,
            recovery_probe: usize,
            recovery_ready: usize,
        }

        let mut by_peer: BTreeMap<String, AdmissionCounts> = BTreeMap::new();
        if let Some(rows) = obj.get("suppressed_peers").and_then(|v| v.as_array()) {
            for row in rows {
                let Some(peer_id) = value_string_field(row, "peer_id") else {
                    continue;
                };
                let entry = by_peer.entry(peer_id).or_default();
                entry.suppressed += 1;
                match value_string_field(row, "state").as_deref() {
                    Some("recovery_probe") => entry.recovery_probe += 1,
                    Some("recovery_ready") => entry.recovery_ready += 1,
                    _ => entry.cooled += 1,
                }
            }
        }

        let mut admission: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        for (peer_id, counts) in by_peer {
            let state = if counts.cooled > 0 {
                "cooled"
            } else if counts.recovery_probe > 0 {
                "recovery_probe"
            } else if counts.recovery_ready > 0 {
                "recovery_ready"
            } else {
                "alive"
            };
            admission.insert(
                peer_id,
                serde_json::json!({
                    "state": state,
                    "suppressed_topics_count": counts.suppressed,
                    "cooled_topics_count": counts.cooled,
                    "recovery_probe_topics_count": counts.recovery_probe,
                    "recovery_ready_topics_count": counts.recovery_ready,
                    "priority_queue_depths": {},
                }),
            );
        }
        obj.insert(
            "admission_state_by_peer".to_string(),
            serde_json::json!(admission),
        );
    }

    value
}

/// GET /diagnostics/connectivity — ant-quic NodeStatus snapshot.
///
/// Returns the full connectivity state so we can answer:
/// - Is UPnP port mapping active?
/// - What external addresses have been observed?
/// - What NAT type has ant-quic detected?
/// - Direct vs relayed connection counts, hole-punch success rate, avg RTT.
/// - mDNS browsing/advertising state and discovered peer count.
///
/// This is the primary observability surface for the 100%-connectivity
/// guarantee ant-quic is responsible for.
pub(in crate::server) async fn connectivity_diagnostics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized");
    };

    match network.node_status().await {
        Some(ns) => {
            // X0X-0039: real `data_tx` saturation snapshot from ant-quic 0.27.13.
            let data_tx = network.data_channel_diagnostics().await;
            // X0X-0043: real GSO bundle send snapshot from ant-quic 0.27.13.
            let gso = network.gso_diagnostics().await;
            let connection_pool = network.connection_pool_diagnostics();
            let now = Instant::now();
            let mut per_peer_transport = Vec::new();
            // ADR-0011 §4: accumulate path-quality signals across peers so the
            // transport-environment assessment can spot a constrained-MTU /
            // black-holed path even when only some peers are affected.
            let mut min_observed_mtu: Option<u16> = None;
            let mut lost_plpmtud_probes_total: u64 = 0;
            let mut black_holes_total: u64 = 0;
            for peer_id in network.connected_peers().await {
                let health = network.connection_health(peer_id).await;
                let transport_stats = network.connection_transport_stats(peer_id).await;
                let (
                    connected,
                    generation,
                    reader_task_active,
                    last_sent_ago_ms,
                    last_received_ago_ms,
                    idle_for_ms,
                    close_reason,
                ) = match health {
                    Some(health) => (
                        health.connected,
                        health.generation,
                        health.reader_task_active,
                        health.last_sent_at.map(|instant| {
                            duration_millis_u64(now.saturating_duration_since(instant))
                        }),
                        health.last_received_at.map(|instant| {
                            duration_millis_u64(now.saturating_duration_since(instant))
                        }),
                        health.idle_for.map(duration_millis_u64),
                        health.close_reason.map(|reason| format!("{reason:?}")),
                    ),
                    None => (false, None, None, None, None, None, None),
                };
                let row = match transport_stats {
                    Some(ts) => {
                        if let Some(mtu) = ts.current_mtu {
                            min_observed_mtu = Some(min_observed_mtu.map_or(mtu, |m| m.min(mtu)));
                        }
                        lost_plpmtud_probes_total += ts.lost_plpmtud_probes;
                        black_holes_total += ts.black_holes_detected;
                        serde_json::json!({
                        "peer_id": hex::encode(peer_id.0),
                        "transport": "quic",
                        "stats_available": true,
                        "connected": ts.connected || connected,
                        "generation": ts.generation.or(generation),
                        "reader_task_active": reader_task_active,
                        "rtt_ms": ts.rtt_ms,
                        "udp_tx_bytes": ts.udp_tx_bytes,
                        "udp_rx_bytes": ts.udp_rx_bytes,
                        "udp_tx_datagrams": ts.udp_tx_datagrams,
                        "udp_rx_datagrams": ts.udp_rx_datagrams,
                        "congestion_window": ts.congestion_window,
                        "congestion_events": ts.congestion_events,
                        "lost_packets": ts.lost_packets,
                        "lost_bytes": ts.lost_bytes,
                        "sent_packets": ts.sent_packets,
                        "sent_plpmtud_probes": ts.sent_plpmtud_probes,
                        "lost_plpmtud_probes": ts.lost_plpmtud_probes,
                        "black_holes_detected": ts.black_holes_detected,
                        "packet_loss_rate": ts.packet_loss_rate,
                        "current_mtu": ts.current_mtu,
                        "stream_open_blocked_events": ts.stream_open_blocked_events,
                        "data_blocked_events": ts.data_blocked_events,
                        "stream_data_blocked_events": ts.stream_data_blocked_events,
                        "last_sent_ago_ms": ts.last_sent_ago_ms.or(last_sent_ago_ms),
                        "last_received_ago_ms": ts.last_received_ago_ms.or(last_received_ago_ms),
                        "idle_for_ms": ts.idle_for_ms.or(idle_for_ms),
                        "close_reason": close_reason,
                        })
                    }
                    None => serde_json::json!({
                        "peer_id": hex::encode(peer_id.0),
                        "transport": "quic",
                        "stats_available": false,
                        "connected": connected,
                        "generation": generation,
                        "reader_task_active": reader_task_active,
                        "rtt_ms": null,
                        "udp_tx_bytes": null,
                        "udp_rx_bytes": null,
                        "udp_tx_datagrams": null,
                        "udp_rx_datagrams": null,
                        "congestion_window": null,
                        "congestion_events": null,
                        "lost_packets": null,
                        "lost_bytes": null,
                        "sent_packets": null,
                        "sent_plpmtud_probes": null,
                        "lost_plpmtud_probes": null,
                        "black_holes_detected": null,
                        "packet_loss_rate": null,
                        "current_mtu": null,
                        "stream_open_blocked_events": null,
                        "data_blocked_events": null,
                        "stream_data_blocked_events": null,
                        "last_sent_ago_ms": last_sent_ago_ms,
                        "last_received_ago_ms": last_received_ago_ms,
                        "idle_for_ms": idle_for_ms,
                        "close_reason": close_reason,
                    }),
                };
                per_peer_transport.push(row);
            }
            // ADR-0011 §4: full-tunnel-VPN / constrained-MTU / CGNAT assessment.
            let transport_environment = x0x::connectivity::assess_transport_environment(
                &x0x::connectivity::TransportObservation {
                    external_addrs: ns.external_addrs.clone(),
                    can_receive_direct: Some(ns.can_receive_direct),
                    connected_peers: ns.connected_peers,
                    min_observed_mtu,
                    lost_plpmtud_probes: lost_plpmtud_probes_total,
                    black_holes_detected: black_holes_total,
                },
            );
            let snapshot = serde_json::json!({
                "ok": true,
                "peer_id": hex::encode(ns.peer_id.0),
                "local_addr": ns.local_addr.to_string(),
                "external_addrs": ns.external_addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "nat_type": format!("{:?}", ns.nat_type),
                "can_receive_direct": ns.can_receive_direct,
                "direct_reachability_scope": format!("{:?}", ns.direct_reachability_scope),
                "has_global_address": ns.has_global_address,
                "port_mapping": {
                    "active": ns.port_mapping_active,
                    "external_addr": ns.port_mapping_addr.map(|a| a.to_string()),
                },
                "mdns": {
                    "browsing": ns.mdns_browsing,
                    "advertising": ns.mdns_advertising,
                    "discovered_peers": ns.mdns_discovered_peers,
                },
                "services": {
                    "relay_enabled": ns.relay_service_enabled,
                    "coordinator_enabled": ns.coordinator_service_enabled,
                    "bootstrap_enabled": ns.bootstrap_service_enabled,
                },
                "connections": {
                    "connected_peers": ns.connected_peers,
                    "active": ns.active_connections,
                    "direct": ns.direct_connections,
                    "relayed": ns.relayed_connections,
                    "hole_punch_success_rate": ns.hole_punch_success_rate,
                },
                "per_peer_transport": per_peer_transport,
                "connection_pool": connection_pool,
                "relay": {
                    "is_relaying": ns.is_relaying,
                    "sessions": ns.relay_sessions,
                    "bytes_forwarded": ns.relay_bytes_forwarded,
                },
                "coordinator": {
                    "is_coordinating": ns.is_coordinating,
                    "sessions": ns.coordination_sessions,
                },
                "avg_rtt_ms": ns.avg_rtt.as_millis() as u64,
                "uptime_s": ns.uptime.as_secs(),
                // X0X-0039: `data_tx` channel saturation (ant-quic 0.27.13).
                "data_tx": {
                    "data_tx_depth": data_tx.as_ref().map(|d| d.data_tx_depth),
                    "data_tx_capacity": data_tx.as_ref().map(|d| d.data_tx_capacity),
                    "data_tx_high_water_count": data_tx.as_ref().map(|d| d.data_tx_high_water_count),
                },
                // X0X-0043: GSO bundle send counters (ant-quic 0.27.13). See
                // `docs/debug/gso-bundle-tail-drop-x0x-0030.md` for the
                // Quinn issue #2627 GSO-tail-drop hypothesis under test.
                "gso": {
                    "bundle_send_total": gso.as_ref().map(|g| g.bundle_send_total),
                    "bundle_partial_send": gso.as_ref().map(|g| g.bundle_partial_send),
                },
                // ADR-0011 §4: structured full-tunnel-VPN / constrained-MTU signal.
                "transport_environment": transport_environment,
            });
            (StatusCode::OK, Json(snapshot))
        }
        None => api_error(StatusCode::SERVICE_UNAVAILABLE, "node status unavailable"),
    }
}

/// GET /diagnostics/ack — ACK-v2 per-stage latency and outcome diagnostics.
pub(in crate::server) async fn ack_diagnostics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized");
    };

    match network.ack_diagnostics().await {
        Some(snapshot) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "ack": snapshot,
            })),
        ),
        None => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ACK diagnostics unavailable",
        ),
    }
}

/// GET /diagnostics/gossip — PubSub drop-detection counters.
///
/// The delta between stages proves per-daemon 100% delivery (or surfaces
/// where drops occur). Used by e2e_full_audit / e2e_stress to assert zero
/// drops under load.
pub(in crate::server) async fn gossip_diagnostics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.agent.gossip_stats() {
        Some(snap) => {
            let pubsub_stages =
                augment_pubsub_stage_diagnostics(state.agent.gossip_pubsub_stage_stats());
            let (agents, machines, users) = state.agent.discovery_cache_entry_counts().await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                "ok": true,
                "stats": snap,
                "pubsub_stages": pubsub_stages,
                "dispatcher": state.agent.gossip_dispatch_stats(),
                "recv_pump": state.agent.recv_pump_diagnostics(),
                "discovery_cache_entries": {
                    "agents": agents,
                    "machines": machines,
                    "users": users,
                },
                })),
            )
        }
        None => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "gossip runtime not initialized",
        ),
    }
}

/// GET /diagnostics/groups — per-group ingest diagnostics.
///
/// Mirrors `/diagnostics/dm` and `/diagnostics/exec`. For each
/// locally-known group (or any group with non-zero counters) returns
/// `members_v2_size`, listener-state booleans, and the per-reason
/// drop buckets used by the public-message ingest pipeline. The
/// `messages_dropped_write_policy_violation` bucket is the canary for
/// the join-roster-propagation regression: a non-zero value on the
/// owner side means joiners' messages are reaching the listener but
/// `members_v2` is stale.
pub(in crate::server) async fn groups_diagnostics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let metadata_keys: std::collections::HashSet<String> = state
        .group_metadata_tasks
        .read()
        .await
        .keys()
        .cloned()
        .collect();
    let public_keys: std::collections::HashSet<String> = state
        .public_message_tasks
        .read()
        .await
        .keys()
        .cloned()
        .collect();
    // Snapshot the named_groups under a single read lock to avoid
    // repeatedly contending with the metadata listener under load.
    let groups_view: HashMap<String, x0x::groups::GroupInfo> = {
        let groups = state.named_groups.read().await;
        groups.clone()
    };
    let snap = state
        .groups_diagnostics
        .snapshot(&groups_view, &metadata_keys, &public_keys);
    let treekem_recovery_cache = state.treekem_member_key_packages.diagnostics().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "groups": snap.groups,
            "treekem_recovery_cache": treekem_recovery_cache,
        })),
    )
}

/// GET /diagnostics/dm — direct-message send/receive diagnostics.
pub(in crate::server) async fn dm_diagnostics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let x0x::direct::DmDiagnosticsSnapshot {
        stats,
        per_peer,
        subscriber_count,
        subscriber_capacity,
    } = state.agent.direct_messaging().diagnostics_snapshot();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "stats": stats,
            "per_peer": per_peer,
            "subscriber_count": subscriber_count,
            "subscriber_capacity": subscriber_capacity,
            "capability_store_entries": state.agent.capability_store().len(),
        })),
    )
}

/// Parse a hex `peer_id` path segment into an ant-quic `PeerId` (32 bytes).
fn parse_peer_id(hex_str: &str) -> Result<ant_quic::PeerId, (StatusCode, Json<serde_json::Value>)> {
    let bytes =
        hex::decode(hex_str).map_err(|e| bad_request(format!("invalid hex peer_id: {e}")))?;
    if bytes.len() != 32 {
        return Err(bad_request(format!(
            "peer_id must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ant_quic::PeerId(arr))
}

/// Query for `POST /peers/:peer_id/probe` — optional timeout (default 2s).
#[derive(Debug, serde::Deserialize, Default)]
pub(in crate::server) struct ProbeQuery {
    /// Probe timeout in milliseconds; clamped to `[100, 30000]`.
    timeout_ms: Option<u64>,
}

/// POST /peers/:peer_id/probe — ant-quic 0.27.2 `probe_peer` active liveness.
///
/// Sends a lightweight probe envelope to the peer and waits for the remote
/// reader's ACK-v1 reply. Returns the measured round-trip time. Probe
/// traffic is invisible to the application recv pipeline.
pub(in crate::server) async fn probe_peer_handler(
    State(state): State<Arc<AppState>>,
    Path(peer_hex): Path<String>,
    axum::extract::Query(q): axum::extract::Query<ProbeQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let peer_id = match parse_peer_id(&peer_hex) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized")
            .into_response();
    };
    let timeout_ms = q.timeout_ms.unwrap_or(2_000).clamp(100, 30_000);
    let timeout = std::time::Duration::from_millis(timeout_ms);

    match network.probe_peer(peer_id, timeout).await {
        Some(Ok(rtt)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "rtt_ms": rtt.as_millis() as u64,
                "rtt_us": rtt.as_micros() as u64,
                "timeout_ms": timeout_ms,
            })),
        )
            .into_response(),
        Some(Err(e)) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("probe failed: {e}"),
        )
        .into_response(),
        None => {
            api_error(StatusCode::SERVICE_UNAVAILABLE, "network node not running").into_response()
        }
    }
}

/// GET /peers/:peer_id/health — ant-quic 0.27.1 `connection_health` snapshot.
///
/// Returns the lifecycle state, generation, directional activity timestamps,
/// and most-recent close reason for a peer. The response carries:
///
/// - `health`: opaque Debug rendering of `ConnectionHealth` (legacy, kept
///   for backwards compatibility — older clients substring-matched this).
/// - `snapshot`: structured object new clients should prefer:
///   `{ connected, generation, reader_task_active, last_received_ms_ago,
///   last_sent_ms_ago, idle_ms, close_reason }`. `Instant`-typed fields
///   are converted to elapsed-millisecond deltas so the wire format
///   stays calendar-agnostic.
pub(in crate::server) async fn peer_health_handler(
    State(state): State<Arc<AppState>>,
    Path(peer_hex): Path<String>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let peer_id = match parse_peer_id(&peer_hex) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let Some(network) = state.agent.network() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "network not initialized")
            .into_response();
    };
    match network.connection_health(peer_id).await {
        Some(health) => {
            let now = std::time::Instant::now();
            let snapshot = serde_json::json!({
                "connected": health.connected,
                "generation": health.generation,
                "reader_task_active": health.reader_task_active,
                "last_received_ms_ago": health
                    .last_received_at
                    .map(|t| now.saturating_duration_since(t).as_millis() as u64),
                "last_sent_ms_ago": health
                    .last_sent_at
                    .map(|t| now.saturating_duration_since(t).as_millis() as u64),
                "idle_ms": health.idle_for.map(|d| d.as_millis() as u64),
                "close_reason": health.close_reason.as_ref().map(|r| format!("{r:?}")),
            });
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "peer_id": peer_hex,
                    // `health` is the legacy Debug rendering retained for
                    // backwards compatibility. New clients should consume
                    // `snapshot` (structured fields).
                    "health": format!("{health:?}"),
                    "snapshot": snapshot,
                })),
            )
                .into_response()
        }
        None => {
            api_error(StatusCode::SERVICE_UNAVAILABLE, "network node not running").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for new endpoints
// ---------------------------------------------------------------------------
