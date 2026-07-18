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
use std::sync::Arc;

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
    uptime_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    degraded_reason: Option<String>,
}

/// Classify liveness for `GET /health` (issue #262).
///
/// A daemon that has been up past the bootstrap grace window with ZERO peers
/// is not "healthy" — the prod NYC bootstrap sat in exactly that state for
/// 6+ hours (wedged transport, silent socket) while fleet monitoring read
/// `healthy` and stayed quiet. `ok` remains `true` (the process is alive and
/// serving); `status: "degraded"` is the monitorable signal.
fn classify_health(peers: usize, uptime_secs: u64) -> (&'static str, Option<String>) {
    const ZERO_PEER_GRACE_SECS: u64 = 120;
    if peers == 0 && uptime_secs >= ZERO_PEER_GRACE_SECS {
        (
            "degraded",
            Some(format!(
                "zero peers for the whole uptime window (>{ZERO_PEER_GRACE_SECS}s); \
                 transport may be wedged or the network unreachable"
            )),
        )
    } else {
        ("healthy", None)
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
    warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Health + status handlers
// ---------------------------------------------------------------------------

/// GET /health
pub(in crate::server) async fn health(
    State(state): State<Arc<AppState>>,
) -> Json<ApiResponse<HealthData>> {
    let peers = state.agent.peers().await.map(|p| p.len()).unwrap_or(0);
    let uptime_secs = state.start_time.elapsed().as_secs();
    let (status, degraded_reason) = classify_health(peers, uptime_secs);

    Json(ApiResponse {
        ok: true,
        data: HealthData {
            status: status.to_string(),
            version: x0x::VERSION.to_string(),
            peers,
            uptime_secs,
            degraded_reason,
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

    let connectivity = if !warnings.is_empty() {
        "degraded"
    } else if peers > 0 {
        "connected"
    } else if uptime_secs < 45 {
        "connecting"
    } else {
        "isolated"
    }
    .to_string();

    Json(ApiResponse {
        ok: true,
        data: StatusData {
            status: connectivity,
            version: x0x::VERSION.to_string(),
            uptime_secs,
            api_address: state.api_address.to_string(),
            external_addrs,
            agent_id: hex::encode(state.agent.agent_id().as_bytes()),
            peers,
            warnings,
        },
    })
}

/// POST /shutdown — trigger graceful daemon shutdown.
pub(in crate::server) async fn shutdown_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
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
    use super::classify_health;

    /// WHY (issue #262): a wedged-transport daemon — up for hours, zero
    /// peers, silent socket — must not read `healthy` to fleet monitoring.
    /// That exact state hid the NYC prod bootstrap outage for 6+ hours.
    #[test]
    fn zero_peers_past_grace_is_degraded() {
        let (status, reason) = classify_health(0, 121);
        assert_eq!(status, "degraded");
        assert!(reason.is_some(), "degraded must carry a reason");
    }

    /// Startup gets a grace window: bootstrap takes seconds-to-a-minute, and
    /// flagging a freshly started daemon would page on every restart.
    #[test]
    fn zero_peers_within_grace_is_still_healthy() {
        let (status, reason) = classify_health(0, 30);
        assert_eq!(status, "healthy");
        assert!(reason.is_none());
    }

    /// Any live peer means the transport works — healthy regardless of age.
    #[test]
    fn connected_daemon_is_healthy() {
        let (status, reason) = classify_health(1, 999_999);
        assert_eq!(status, "healthy");
        assert!(reason.is_none());
    }
}
