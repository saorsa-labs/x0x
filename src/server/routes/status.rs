//! Status/health REST handlers (`category: "status"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::state::AppState;
use crate as x0x;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CONNECTIVITY_GRACE_SECS: u64 = 120;
const STATUS_CONNECTING_GRACE_SECS: u64 = 45;

/// How often the background refresher re-reads the transport peer counts that
/// `/health` serves. Half the watchdog's default 10 s probe interval, so every
/// probe sees a snapshot at most one refresh old.
pub(in crate::server) const HEALTH_SNAPSHOT_REFRESH_SECS: u64 = 5;

/// Cached transport peer counts for the auth-exempt `GET /health` (issue #600).
///
/// `/health` is the one endpoint the API watchdog probes (every 10 s, 3 s
/// timeout, abort after 3 misses). Reading the counts live walks ant-quic's
/// connected-peer table, which can take its `connection_lifecycle` parking_lot
/// **write** lock once per peer — on a tokio worker, and parking_lot parks the
/// OS thread. That is the same lock the gossip event path keeps hot, so under a
/// storm the liveness probe was measuring lock contention, exceeded its 3 s
/// budget, and aborted a perfectly live process 5–12×/hour on mainnet.
///
/// The handler now reads these atomics and nothing else: O(1), lock-free,
/// and independent of the peer table. The traversal moved to a background
/// refresher task in `serve_with_options` (`src/server/mod.rs`), where blocking
/// is survivable. Response shape is unchanged —
/// `/health` is consumed by the VPS fleet monitor, `docs/api-reference.md`,
/// and the #262 zero-peer degraded signal, all of which read these fields.
#[derive(Debug, Default)]
pub(in crate::server) struct HealthSnapshot {
    peers: AtomicUsize,
    send_ready_peers: AtomicUsize,
    /// Connected peers whose link is one-sided (#1419). The refresher
    /// publishes the count. The handler does not walk connection health.
    one_sided_peers: AtomicUsize,
    /// Peer ids from the same refresher store as `one_sided_peers`.
    /// `GET /peers` reads this set so its `link` matches `/health`.
    one_sided_ids: std::sync::Mutex<Vec<[u8; 32]>>,
}

impl HealthSnapshot {
    /// Publish a freshly measured set of counts.
    pub(in crate::server) fn store(
        &self,
        peers: usize,
        send_ready_peers: usize,
        one_sided_peers: usize,
    ) {
        self.peers.store(peers, Ordering::Relaxed);
        self.send_ready_peers
            .store(send_ready_peers, Ordering::Relaxed);
        self.one_sided_peers
            .store(one_sided_peers, Ordering::Relaxed);
    }

    /// Publish counts and the one-sided peer set from one refresher sample.
    pub(in crate::server) fn store_one_sided(
        &self,
        peers: usize,
        send_ready_peers: usize,
        one_sided_ids: &[[u8; 32]],
    ) {
        self.store(peers, send_ready_peers, one_sided_ids.len());
        *self
            .one_sided_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = one_sided_ids.to_vec();
    }

    /// The refresher's stored one-sided peer ids.
    pub(in crate::server) fn one_sided_ids(&self) -> Vec<[u8; 32]> {
        self.one_sided_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Clear the stored set when the node has no network.
    pub(in crate::server) fn clear_one_sided_ids(&self) {
        self.one_sided_ids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// Read the last published counts as `(peers, send_ready_peers, one_sided_peers)`.
    pub(in crate::server) fn load(&self) -> (usize, usize, usize) {
        (
            self.peers.load(Ordering::Relaxed),
            self.send_ready_peers.load(Ordering::Relaxed),
            self.one_sided_peers.load(Ordering::Relaxed),
        )
    }
}

/// Sample one-sided links, store the snapshot, then start a repair task.
///
/// The store runs before the repair is spawned. A re-dial may wait 3 s per
/// peer. This function does not wait, so the next refresher tick can store
/// new peer and send-ready counts (#1419, #600).
pub(in crate::server) async fn publish_one_sided_health(
    network: &Arc<x0x::network::NetworkNode>,
    snapshot: &HealthSnapshot,
    peers: usize,
) {
    let samples = network.connected_link_ages().await;
    let one_sided = x0x::network::one_sided_peer_ids_from(&samples);
    let ids: Vec<[u8; 32]> = one_sided.iter().map(|peer| peer.0).collect();
    let send_ready = network.send_ready_peers().await.len();
    snapshot.store_one_sided(peers, send_ready, &ids);
    network.spawn_one_sided_repair(samples);
}

/// Generic JSON response wrapper.
#[derive(Debug, Serialize)]
pub(in crate::server) struct ApiResponse<T: Serialize> {
    pub(in crate::server) ok: bool,
    #[serde(flatten)]
    pub(in crate::server) data: T,
}

/// Health response.
#[derive(Debug, Serialize)]
pub(in crate::server) struct HealthData {
    status: String,
    version: String,
    peers: usize,
    send_ready_peers: usize,
    uptime_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    degraded_reason: Option<String>,
    /// Structured advisory warnings (never liveness-affecting). ADR-0038
    /// review fix: Home warnings live on AUTHED surfaces only (`GET /home`,
    /// `GET /groups/:id`) — `/health` is auth-exempt and must not leak
    /// Home/owner existence. Reserved (always empty) for future
    /// non-sensitive advisories.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<serde_json::Value>,
    /// GroupCards this process refused at discovery, shard, contact, and
    /// metadata ingress because the signature did not verify (#1224).
    unsigned_group_cards_refused: u64,
}

/// Classify liveness for `GET /health` (issue #262).
///
/// A daemon that has been up past the bootstrap grace window with ZERO peers
/// is not "healthy" — the prod NYC bootstrap sat in exactly that state for
/// 6+ hours (wedged transport, silent socket) while fleet monitoring read
/// `healthy` and stayed quiet. `ok` remains `true` (the process is alive and
/// serving); `status: "degraded"` is the monitorable signal.
fn one_sided_reason(count: usize) -> String {
    let noun = if count == 1 {
        "peer link is"
    } else {
        "peer links are"
    };
    format!(
        "{count} connected {noun} one-sided (one direction idle > {}s while the other direction still has traffic)",
        crate::network::ONE_SIDED_STALE.as_secs()
    )
}

fn classify_health(
    peers: usize,
    send_ready_peers: usize,
    uptime_secs: u64,
    one_sided_peers: usize,
) -> (&'static str, Option<String>) {
    if one_sided_peers > 0 {
        return ("degraded", Some(one_sided_reason(one_sided_peers)));
    }
    if peers == 0 && uptime_secs >= CONNECTIVITY_GRACE_SECS {
        (
            "degraded",
            Some(format!(
                "zero peers for the whole uptime window (>{CONNECTIVITY_GRACE_SECS}s); \
                 transport may be wedged or the network unreachable"
            )),
        )
    } else if peers > 0 && send_ready_peers == 0 && uptime_secs >= CONNECTIVITY_GRACE_SECS {
        (
            "degraded",
            Some(format!(
                "{peers} peers remain in the outer connection table but none are send-ready; \
                 ant-quic has no routable transport winner"
            )),
        )
    } else {
        ("healthy", None)
    }
}

/// Classify the richer `/status` connectivity state from the same transport
/// readiness predicate used by `/health` while preserving its shorter startup
/// state transition from `connecting` to `isolated`.
fn classify_runtime_status(
    peers: usize,
    send_ready_peers: usize,
    uptime_secs: u64,
    has_warnings: bool,
    one_sided_peers: usize,
) -> (&'static str, Option<String>) {
    let (health, degraded_reason) =
        classify_health(peers, send_ready_peers, uptime_secs, one_sided_peers);
    if has_warnings || health == "degraded" {
        ("degraded", degraded_reason)
    } else if send_ready_peers > 0 {
        ("connected", None)
    } else if uptime_secs < STATUS_CONNECTING_GRACE_SECS {
        ("connecting", None)
    } else {
        ("isolated", None)
    }
}

/// Rich runtime status response.
#[derive(Debug, Serialize)]
pub(in crate::server) struct StatusData {
    status: String,
    version: String,
    uptime_secs: u64,
    api_address: String,
    external_addrs: Vec<String>,
    agent_id: String,
    peers: usize,
    send_ready_peers: usize,
    warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Health + status handlers
// ---------------------------------------------------------------------------

/// GET /health
///
/// Deliberately O(1) and lock-free (issue #600): the peer counts come from
/// [`HealthSnapshot`], never from a live peer-table walk. See that type for
/// why the live read made the watchdog abort live daemons.
pub(in crate::server) async fn health(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<HealthData>> {
    let (peers, send_ready_peers, one_sided_peers) = state.health_snapshot.load();
    let uptime_secs = state.start_time.elapsed().as_secs();
    let (status, degraded_reason) =
        classify_health(peers, send_ready_peers, uptime_secs, one_sided_peers);

    Json(ApiResponse {
        ok: true,
        data: HealthData {
            status: status.to_string(),
            version: x0x::VERSION.to_string(),
            peers,
            send_ready_peers,
            uptime_secs,
            degraded_reason,
            warnings: Vec::new(),
            unsigned_group_cards_refused: super::named_groups::unsigned_group_cards_refused(),
        },
    })
}

/// GET /status — rich runtime status with connectivity state machine.
pub(in crate::server) async fn status(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<StatusData>> {
    let uptime_secs = state.start_time.elapsed().as_secs();
    let mut warnings = Vec::new();

    let peers = match state.agent.peers().await {
        Ok(peer_list) => peer_list.len(),
        Err(err) => {
            warnings.push(format!("failed to query peers: {err}"));
            0
        }
    };

    let send_ready_peers = match state.agent.network() {
        Some(network) => network.send_ready_peers().await.len(),
        None => 0,
    };

    // Get external addresses: ant-quic observed + local IPv4/IPv6 discovery.
    let mut external_addrs = Vec::new();
    if let Some(network) = state.agent.network() {
        if let Some(ns) = network.node_status().await {
            external_addrs = ns.external_addrs.iter().map(|a| a.to_string()).collect();

            let port = ns.local_addr.port();

            // Discover global IPv4 via UDP socket trick (no data sent).
            if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
                if sock.connect("8.8.8.8:80").is_ok() {
                    if let Ok(local) = sock.local_addr() {
                        if let std::net::IpAddr::V4(v4) = local.ip() {
                            if !v4.is_loopback() && !v4.is_unspecified() {
                                let addr_str = format!("{v4}:{port}");
                                if !external_addrs.contains(&addr_str) {
                                    external_addrs.push(addr_str);
                                }
                            }
                        }
                    }
                }
            }

            // Discover global IPv6 via UDP socket trick.
            if let Ok(sock) = std::net::UdpSocket::bind("[::]:0") {
                if sock.connect("[2001:4860:4860::8888]:80").is_ok() {
                    if let Ok(local) = sock.local_addr() {
                        if let std::net::IpAddr::V6(v6) = local.ip() {
                            let segs = v6.segments();
                            let is_global = (segs[0] & 0xffc0) != 0xfe80
                                && (segs[0] & 0xff00) != 0xfd00
                                && !v6.is_loopback();
                            if is_global {
                                let addr_str = format!("[{v6}]:{port}");
                                if !external_addrs.contains(&addr_str) {
                                    external_addrs.push(addr_str);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let one_sided_peers = state.health_snapshot.load().2;
    let (connectivity, degraded_reason) = classify_runtime_status(
        peers,
        send_ready_peers,
        uptime_secs,
        !warnings.is_empty(),
        one_sided_peers,
    );
    if let Some(reason) = degraded_reason {
        warnings.push(reason);
    }

    Json(ApiResponse {
        ok: true,
        data: StatusData {
            status: connectivity.to_string(),
            version: x0x::VERSION.to_string(),
            uptime_secs,
            api_address: state.api_address.to_string(),
            external_addrs,
            agent_id: hex::encode(state.agent.agent_id().as_bytes()),
            peers,
            send_ready_peers,
            warnings,
        },
    })
}

/// POST /shutdown — trigger graceful daemon shutdown.
pub(in crate::server) async fn shutdown_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(actor): axum::extract::Extension<
        crate::server::rider_auth::ActorContext,
    >,
) -> impl IntoResponse {
    // Issue #446: daemon lifecycle is an owner act — a 10-minute
    // browser session must not be able to kill the daemon (availability).
    if !actor.is_durable_owner() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "shutdown requires the durable API token (not a session token)"
            })),
        );
    }
    tracing::info!("Shutdown requested via API");
    let _ = state.shutdown_notify.send(true);
    let _ = state.shutdown_tx.send(()).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "message": "shutting down"})),
    )
}

// ---------------------------------------------------------------------------
// Constitution handler
// ---------------------------------------------------------------------------

/// GET /constitution — returns the raw markdown text.
pub(in crate::server) async fn get_constitution() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/markdown; charset=utf-8")],
        x0x::constitution::CONSTITUTION_MD,
    )
}

/// GET /constitution/json — returns structured JSON with version metadata.
pub(in crate::server) async fn get_constitution_json() -> impl IntoResponse {
    Json(serde_json::json!({
        "ok": true,
        "version": x0x::constitution::CONSTITUTION_VERSION,
        "status": x0x::constitution::CONSTITUTION_STATUS,
        "content": x0x::constitution::CONSTITUTION_MD,
    }))
}

#[cfg(test)]
mod tests {
    use super::{classify_health, classify_runtime_status, HealthSnapshot};
    use crate as x0x;

    /// The `health` handler's own source, for the structural guard below.
    /// Matches the `include_str!`-of-route-source convention in
    /// `tests/api_coverage.rs`.
    const STATUS_SOURCE: &str = include_str!("status.rs");

    /// WHY (issue #600): `/health` is what the API watchdog probes every 10 s
    /// with a 3 s budget, aborting the process after 3 misses. Reading peer
    /// counts live walks ant-quic's connected-peer table and can take its
    /// `connection_lifecycle` parking_lot **write** lock once per peer — the
    /// same lock a gossip storm keeps hot — so the probe measured lock
    /// contention instead of liveness and killed live mainnet daemons
    /// 5–12×/hour. `/health` must stay O(1) and touch NO transport state.
    ///
    /// This is a source guard rather than a behavioural test because the
    /// property is "the handler does not call X", which is only observable
    /// under a real storm. It fails the moment someone reintroduces a live
    /// peer read into the handler, which is exactly the regression to catch.
    #[test]
    fn health_handler_never_traverses_the_peer_table() {
        let start = STATUS_SOURCE
            .find("pub(in crate::server) async fn health(")
            .expect("health handler must exist");
        let rest = &STATUS_SOURCE[start..];
        let end = rest
            .find("/// GET /status")
            .expect("health handler must be followed by the /status handler");
        let body = &rest[..end];

        for forbidden in [
            "agent.peers()",
            "send_ready_peers()",
            "network.node_status()",
        ] {
            assert!(
                !body.contains(forbidden),
                "GET /health must not call `{forbidden}` — it is the watchdog's \
                 liveness probe and must not touch ant-quic's peer table \
                 (issue #600). Read from `state.health_snapshot` instead."
            );
        }
        assert!(
            body.contains("state.health_snapshot.load()"),
            "GET /health must serve its peer counts from the cached snapshot"
        );
    }

    /// WHY (issue #600): the cache must be a faithful pass-through, so the
    /// #262 degraded classification keeps working on cached counts. If the
    /// snapshot ever mangled the pair, `/health` would report a transport
    /// state the daemon is not in — to the fleet monitor, silently.
    #[test]
    fn health_snapshot_round_trips_both_counts() {
        let snapshot = HealthSnapshot::default();
        assert_eq!(
            snapshot.load(),
            (0, 0, 0),
            "unprimed snapshot reads as zero"
        );
        snapshot.store(17, 3, 1);
        assert_eq!(snapshot.load(), (17, 3, 1));
        snapshot.store(0, 0, 0);
        assert_eq!(snapshot.load(), (0, 0, 0), "a drop to zero must be visible");
    }

    /// WHY (issue #262): a wedged-transport daemon — up for hours, zero
    /// peers, silent socket — must not read `healthy` to fleet monitoring.
    /// That exact state hid the NYC prod bootstrap outage for 6+ hours.
    #[test]
    fn zero_peers_past_grace_is_degraded() {
        let (status, reason) = classify_health(0, 0, 121, 0);
        assert_eq!(status, "degraded");
        assert!(reason.is_some(), "degraded must carry a reason");
    }

    /// Startup gets a grace window: bootstrap takes seconds-to-a-minute, and
    /// flagging a freshly started daemon would page on every restart.
    #[test]
    fn zero_peers_within_grace_is_still_healthy() {
        let (status, reason) = classify_health(0, 0, 30, 0);
        assert_eq!(status, "healthy");
        assert!(reason.is_none());
    }

    /// Any live peer means the transport works — healthy regardless of age.
    #[test]
    fn connected_daemon_is_healthy() {
        let (status, reason) = classify_health(1, 1, 999_999, 0);
        assert_eq!(status, "healthy");
        assert!(reason.is_none());
    }

    /// An outer-table peer is not evidence that ant-quic still has a routable
    /// transport winner. This exact split produced PeerNotFound storms while
    /// `/health` reported healthy.
    #[test]
    fn outer_peers_without_transport_winner_are_degraded() {
        let (status, reason) = classify_health(17, 0, 2_400, 0);
        assert_eq!(status, "degraded");
        assert!(
            reason
                .as_deref()
                .is_some_and(|value| value.contains("send-ready")),
            "degraded response must name the cross-layer mismatch: {reason:?}"
        );
    }

    /// A partially stale outer table still has a functioning transport when
    /// at least one routable transport winner remains.
    #[test]
    fn at_least_one_transport_winner_is_healthy() {
        let (status, reason) = classify_health(17, 1, 2_400, 0);
        assert_eq!(status, "healthy");
        assert!(reason.is_none());
    }

    /// `/status` must not report `connected` for the stale-outer state which
    /// `/health` classifies as degraded.
    #[test]
    fn runtime_status_degrades_without_a_transport_winner() {
        let (status, reason) = classify_runtime_status(17, 0, 2_400, false, 0);
        assert_eq!(status, "degraded");
        assert!(reason.is_some());
    }

    #[test]
    fn runtime_status_connects_only_with_a_send_ready_peer() {
        let (status, reason) = classify_runtime_status(17, 1, 2_400, false, 0);
        assert_eq!(status, "connected");
        assert!(reason.is_none());
    }

    #[test]
    fn runtime_status_is_connecting_during_transport_grace() {
        let (status, reason) = classify_runtime_status(17, 0, 30, false, 0);
        assert_eq!(status, "connecting");
        assert!(reason.is_none());
    }

    #[test]
    fn runtime_status_preserves_isolated_state_before_degraded_grace() {
        let (status, reason) = classify_runtime_status(0, 0, 60, false, 0);
        assert_eq!(status, "isolated");
        assert!(reason.is_none());
    }

    /// #1419: a mesh that still has send-ready peers is degraded when one
    /// of those links is one-sided. `ok` stays true at the handler; this
    /// is the status the fleet monitor reads.
    #[test]
    fn one_sided_link_is_degraded_while_peers_remain() {
        let (status, reason) = classify_health(4, 4, 2_400, 1);
        assert_eq!(status, "degraded");
        let reason = reason.expect("one-sided degradation carries a reason");
        assert!(
            reason.contains("one-sided"),
            "reason must name the one-sided link: {reason}"
        );
        assert!(
            reason.contains("60s"),
            "reason must name the idle bound: {reason}"
        );
    }

    #[test]
    fn runtime_status_degrades_on_a_one_sided_link() {
        let (status, reason) = classify_runtime_status(4, 4, 2_400, false, 1);
        assert_eq!(status, "degraded");
        assert!(reason.is_some());
    }

    /// #1419: the degraded count is visible while a slow re-dial is still
    /// waiting. Publishing after the repair would leave `/health` healthy
    /// for up to 3 s per peer.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn one_sided_health_is_published_before_the_redial_wait() {
        use std::sync::Arc;
        use std::time::Duration;

        let plane = "issue1419-publish";
        let fabric = x0x::network::sim::SimFabric::new(1419);
        x0x::network::sim::register(plane, &fabric);
        let config = |host: u8| x0x::network::NetworkConfig {
            bind_addr: Some(std::net::SocketAddr::from(([198, 18, 0, host], 5483))),
            network_id: Some(plane.to_string()),
            bootstrap_nodes: Vec::new(),
            mdns_enabled: false,
            port_mapping_enabled: false,
            ..x0x::network::NetworkConfig::default()
        };
        let a = Arc::new(
            x0x::network::NetworkNode::new(config(1), None, None)
                .await
                .unwrap(),
        );
        let b = x0x::network::NetworkNode::new(config(2), None, None)
            .await
            .unwrap();
        let c = x0x::network::NetworkNode::new(config(3), None, None)
            .await
            .unwrap();
        let peer_b = a
            .connect_addr(std::net::SocketAddr::from(([198, 18, 0, 2], 5483)))
            .await
            .unwrap();
        let peer_c = a
            .connect_addr(std::net::SocketAddr::from(([198, 18, 0, 3], 5483)))
            .await
            .unwrap();
        assert_eq!(peer_c, c.peer_id());
        let a_link = a.sim_link_for_test().expect("sim link");
        let b_link = b.sim_link_for_test().expect("sim link");
        let c_link = c.sim_link_for_test().expect("sim link");
        let peer_a = a.peer_id();
        a_link.send(&peer_b, b"\x7fab").unwrap();
        b_link.send(&peer_a, b"\x7fba").unwrap();
        a_link.send(&peer_c, b"\x7fac").unwrap();
        c_link.send(&peer_a, b"\x7fca").unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        tokio::time::sleep(x0x::network::ONE_SIDED_STALE + Duration::from_secs(10)).await;
        b_link.send(&peer_a, b"\x7fba-fresh").unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        a.pause_one_sided_redial_for_test(Duration::from_secs(3));

        let snapshot = Arc::new(HealthSnapshot::default());
        let published = Arc::clone(&snapshot);
        let repair_node = Arc::clone(&a);
        let task = tokio::spawn(async move {
            super::publish_one_sided_health(&repair_node, &published, 2).await;
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            snapshot.load().2,
            1,
            "the degraded count is stored before the re-dial wait finishes"
        );
        assert_eq!(
            snapshot.one_sided_ids(),
            vec![peer_b.0],
            "the stored set is the same peer the count names"
        );
        tokio::time::sleep(Duration::from_secs(4)).await;
        task.await.unwrap();
        a.try_shutdown().await.unwrap();
        b.try_shutdown().await.unwrap();
        c.try_shutdown().await.unwrap();
    }
}
