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
/// The handler now reads these two atomics and nothing else: O(1), lock-free,
/// and independent of the peer table. The traversal moved to a background
/// refresher task in `serve_with_options` (`src/server/mod.rs`), where blocking
/// is survivable. Response shape is unchanged —
/// `/health` is consumed by the VPS fleet monitor, `docs/api-reference.md`,
/// and the #262 zero-peer degraded signal, all of which read these fields.
#[derive(Debug, Default)]
pub(in crate::server) struct HealthSnapshot {
    peers: AtomicUsize,
    send_ready_peers: AtomicUsize,
}

impl HealthSnapshot {
    /// Publish a freshly measured pair of counts.
    pub(in crate::server) fn store(&self, peers: usize, send_ready_peers: usize) {
        self.peers.store(peers, Ordering::Relaxed);
        self.send_ready_peers
            .store(send_ready_peers, Ordering::Relaxed);
    }

    /// Read the last published counts as `(peers, send_ready_peers)`.
    pub(in crate::server) fn load(&self) -> (usize, usize) {
        (
            self.peers.load(Ordering::Relaxed),
            self.send_ready_peers.load(Ordering::Relaxed),
        )
    }
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
}

/// Classify liveness for `GET /health` (issue #262).
///
/// A daemon that has been up past the bootstrap grace window with ZERO peers
/// is not "healthy" — the prod NYC bootstrap sat in exactly that state for
/// 6+ hours (wedged transport, silent socket) while fleet monitoring read
/// `healthy` and stayed quiet. `ok` remains `true` (the process is alive and
/// serving); `status: "degraded"` is the monitorable signal.
fn classify_health(
    peers: usize,
    send_ready_peers: usize,
    uptime_secs: u64,
) -> (&'static str, Option<String>) {
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
) -> (&'static str, Option<String>) {
    let (health, degraded_reason) = classify_health(peers, send_ready_peers, uptime_secs);
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
    let (peers, send_ready_peers) = state.health_snapshot.load();
    let uptime_secs = state.start_time.elapsed().as_secs();
    let (status, degraded_reason) = classify_health(peers, send_ready_peers, uptime_secs);

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

    let (connectivity, degraded_reason) =
        classify_runtime_status(peers, send_ready_peers, uptime_secs, !warnings.is_empty());
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
        assert_eq!(snapshot.load(), (0, 0), "unprimed snapshot reads as zero");
        snapshot.store(17, 3);
        assert_eq!(snapshot.load(), (17, 3));
        snapshot.store(0, 0);
        assert_eq!(snapshot.load(), (0, 0), "a drop to zero must be visible");
    }

    /// WHY (issue #262): a wedged-transport daemon — up for hours, zero
    /// peers, silent socket — must not read `healthy` to fleet monitoring.
    /// That exact state hid the NYC prod bootstrap outage for 6+ hours.
    #[test]
    fn zero_peers_past_grace_is_degraded() {
        let (status, reason) = classify_health(0, 0, 121);
        assert_eq!(status, "degraded");
        assert!(reason.is_some(), "degraded must carry a reason");
    }

    /// Startup gets a grace window: bootstrap takes seconds-to-a-minute, and
    /// flagging a freshly started daemon would page on every restart.
    #[test]
    fn zero_peers_within_grace_is_still_healthy() {
        let (status, reason) = classify_health(0, 0, 30);
        assert_eq!(status, "healthy");
        assert!(reason.is_none());
    }

    /// Any live peer means the transport works — healthy regardless of age.
    #[test]
    fn connected_daemon_is_healthy() {
        let (status, reason) = classify_health(1, 1, 999_999);
        assert_eq!(status, "healthy");
        assert!(reason.is_none());
    }

    /// An outer-table peer is not evidence that ant-quic still has a routable
    /// transport winner. This exact split produced PeerNotFound storms while
    /// `/health` reported healthy.
    #[test]
    fn outer_peers_without_transport_winner_are_degraded() {
        let (status, reason) = classify_health(17, 0, 2_400);
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
        let (status, reason) = classify_health(17, 1, 2_400);
        assert_eq!(status, "healthy");
        assert!(reason.is_none());
    }

    /// `/status` must not report `connected` for the stale-outer state which
    /// `/health` classifies as degraded.
    #[test]
    fn runtime_status_degrades_without_a_transport_winner() {
        let (status, reason) = classify_runtime_status(17, 0, 2_400, false);
        assert_eq!(status, "degraded");
        assert!(reason.is_some());
    }

    #[test]
    fn runtime_status_connects_only_with_a_send_ready_peer() {
        let (status, reason) = classify_runtime_status(17, 1, 2_400, false);
        assert_eq!(status, "connected");
        assert!(reason.is_none());
    }

    #[test]
    fn runtime_status_is_connecting_during_transport_grace() {
        let (status, reason) = classify_runtime_status(17, 0, 30, false);
        assert_eq!(status, "connecting");
        assert!(reason.is_none());
    }

    #[test]
    fn runtime_status_preserves_isolated_state_before_degraded_grace() {
        let (status, reason) = classify_runtime_status(0, 0, 60, false);
        assert_eq!(status, "isolated");
        assert!(reason.is_none());
    }
}
