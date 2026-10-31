//! Status/health REST handlers (`category: "status"` in `src/api/mod.rs`).
//!
//! Extracted verbatim from `src/server/mod.rs` as part of the #125 / WS1.4
//! server decomposition. The router registrations stay in the parent module.

use super::super::sse::SseEvent;
use super::super::state::AppState;
use crate as x0x;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub(in crate::server) const CONNECTIVITY_GRACE_SECS: u64 = 120;
const STATUS_CONNECTING_GRACE_SECS: u64 = 45;

/// How often the background refresher re-reads the transport peer counts that
/// `/health` serves. Half the watchdog's default 10 s probe interval, so every
/// probe sees a snapshot at most one refresh old.
pub(in crate::server) const HEALTH_SNAPSHOT_REFRESH_SECS: u64 = 5;

/// Freshness bound for the cached verdict sample (#1380, RC3 review). The
/// refresher's tick awaits transport operations with no deadline, so it can
/// stall — and a stalled refresher freezes every sampled input at its last
/// value. Past three missed refreshes the sample can no longer vouch for
/// health: the overall verdict degrades with a staleness reason (the input
/// badges stay as-of-sample; the live peer counts and delivery-probe
/// results are merged at serve time and stay current).
pub(in crate::server) const VERDICT_SAMPLE_MAX_AGE_SECS: u64 = 3 * HEALTH_SNAPSHOT_REFRESH_SECS;

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
    /// Last M1 verdict sample gathered by the refresher (#1380). Plain
    /// data under a short std mutex — the same pattern as
    /// `one_sided_ids`, and nothing like the per-peer parking_lot walk
    /// that #600 removed from the handler.
    verdict_sample: std::sync::Mutex<super::super::health_verdict::VerdictSample>,
    /// When `verdict_sample` was last stored. `tokio::time::Instant` so
    /// paused-clock tests observe the same freshness bound production
    /// does. `None` until the first refresher tick lands.
    verdict_sample_refreshed_at: std::sync::Mutex<Option<tokio::time::Instant>>,
    /// Delivery-probe results published by the probe task (#1380).
    probes_run: AtomicUsize,
    last_probe_ok: std::sync::atomic::AtomicBool,
    last_probe_latency_ms: AtomicUsize,
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

    /// Publish the refresher's last M1 verdict sample (#1380). Stamping
    /// the store time is part of the publish: the freshness bound below
    /// reads it back at serve time.
    pub(in crate::server) fn store_verdict_sample(
        &self,
        sample: super::super::health_verdict::VerdictSample,
    ) {
        *self
            .verdict_sample
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = sample;
        *self
            .verdict_sample_refreshed_at
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(tokio::time::Instant::now());
    }

    /// Clone the last stored verdict sample. Before the first refresher
    /// tick this is the unsampled baseline (every input `ok`).
    pub(in crate::server) fn verdict_sample(&self) -> super::super::health_verdict::VerdictSample {
        self.verdict_sample
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The sample `GET /health` classifies: the refresher's cached sample
    /// with the live counts, uptime and delivery-probe results merged in
    /// (#1380). RC3 review: probe outcomes are atomics the probe task
    /// records directly, so they must reach the handler without waiting
    /// for the refresher — a stalled refresher cannot hide a newer probe
    /// failure behind the cached copy. The merged sample carries its own
    /// age; `classify` degrades it past
    /// [`VERDICT_SAMPLE_MAX_AGE_SECS`]. A sample that never arrived ages
    /// from process start: the unsampled baseline cannot vouch for
    /// health forever either.
    pub(in crate::server) fn merged_verdict_inputs(
        &self,
        peers: usize,
        send_ready_peers: usize,
        one_sided_peers: usize,
        uptime_secs: u64,
    ) -> super::super::health_verdict::VerdictSample {
        let mut sample = self.verdict_sample();
        sample.peers = peers;
        sample.send_ready_peers = send_ready_peers;
        sample.one_sided_peers = one_sided_peers;
        sample.uptime_secs = uptime_secs;

        let (probes_run, last_probe_ok, last_probe_latency_ms) = self.probe_results();
        sample.probes_run = probes_run;
        sample.last_probe_ok = last_probe_ok;
        sample.last_probe_latency_ms = last_probe_latency_ms;

        let refreshed_at = *self
            .verdict_sample_refreshed_at
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sample.sample_age_secs = Some(match refreshed_at {
            Some(at) => at.elapsed().as_secs(),
            None => uptime_secs,
        });
        sample
    }

    /// Record one delivery-probe outcome (#1380). `latency_ms` is `None`
    /// when the probe failed before a measurable round-trip.
    pub(in crate::server) fn record_probe(&self, ok: bool, latency_ms: Option<u64>) {
        self.probes_run.fetch_add(1, Ordering::Relaxed);
        self.last_probe_ok.store(ok, Ordering::Relaxed);
        // 0 is the "no latency recorded" sentinel, so a real sub-millisecond
        // round-trip clamps up to 1 ms rather than vanishing.
        self.last_probe_latency_ms.store(
            latency_ms.map(|ms| ms.max(1) as usize).unwrap_or(0),
            Ordering::Relaxed,
        );
    }

    /// `(probes_run, last_ok, last_latency_ms)`. `last_ok` and the latency
    /// are `None` until the first probe completes.
    pub(in crate::server) fn probe_results(&self) -> (u64, Option<bool>, Option<u64>) {
        let run = self.probes_run.load(Ordering::Relaxed);
        if run == 0 {
            return (0, None, None);
        }
        let latency = self.last_probe_latency_ms.load(Ordering::Relaxed);
        (
            run as u64,
            Some(self.last_probe_ok.load(Ordering::Relaxed)),
            if latency == 0 {
                None
            } else {
                Some(latency as u64)
            },
        )
    }
}

/// Sample one-sided links, store the snapshot, then start a repair task.
///
/// A both-directions-stale peer is decided by a bounded liveness probe
/// here, so a quiet peer stays up and a broken link is degraded (#1419).
/// The probe wait is bounded by the resolver and happens before the store;
/// the store still runs before the repair is spawned. A re-dial may wait
/// 3 s per peer. This function does not wait for it, so the next refresher
/// tick can store new peer and send-ready counts (#1419, #600).
pub(in crate::server) async fn publish_one_sided_health(
    network: &Arc<x0x::network::NetworkNode>,
    snapshot: &HealthSnapshot,
    peers: usize,
) {
    let samples = network.connected_link_ages().await;
    let one_sided = network.resolve_one_sided_peers(&samples).await;
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
    /// M1 structured verdict `ok|degraded|error` with its ten inputs
    /// (#1380, ADR 0096 §6). Additive: `status`/`degraded_reason` above
    /// keep their exact legacy semantics — the watchdog and the fleet
    /// monitor keep reading those; agents and operators read this.
    verdict: super::super::health_verdict::HealthVerdict,
}

/// Classify liveness for `GET /health` (issue #262). Shared with the M1
/// verdict's peers input (#1380) so the two surfaces can never disagree.
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
        "{count} connected {noun} one-sided (one direction idle > {}s while the other direction still has traffic, \
         or both directions idle > {}s while other peers have traffic and the liveness probe failed)",
        crate::network::ONE_SIDED_STALE.as_secs(),
        crate::network::ONE_SIDED_STALE.as_secs()
    )
}

pub(in crate::server) fn classify_health(
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
    /// True while a corrupt revocation store still waits for a group resync.
    revocation_resync_required: bool,
    warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Health + status handlers
// ---------------------------------------------------------------------------

/// GET /health
///
/// Deliberately O(1) and lock-free (issue #600): the peer counts come from
/// [`HealthSnapshot`], never from a live peer-table walk. See that type for
/// why the live read made the watchdog abort live daemons. The #1380
/// verdict is the same discipline: the handler merges the refresher's
/// cached sample with the live atomics (peer counts, uptime, delivery-probe
/// results and the sample's age) and classifies — no transport state is
/// touched.
///
/// Detail gate (David's ruling of 20 Oct 2026, 01:51 BST, on #1480
/// Finding 3): the node-specific detail inside `verdict.inputs` — disk
/// free/total bytes, `latest_version`, `user_present`, the windowed error
/// count and the windowed publish-failure counts — is served only to
/// loopback callers and to callers presenting a valid owner bearer
/// ([`super::super::auth::has_valid_owner_bearer`], the same check the
/// authenticated routes use). Every caller keeps the verdict itself:
/// `/health` stays auth-exempt (#600) and never answers 401. Loopback is
/// decided from the peer address the accept loop recorded (`ConnectInfo`)
/// via [`x0x::connect::is_loopback`] — proxy headers such as
/// `X-Forwarded-For` are never consulted, and IPv4-mapped IPv6 peers
/// (`::ffff:127.0.0.1`) fail closed as non-loopback.
pub(in crate::server) async fn health(
    State(state): State<Arc<AppState>>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let (peers, send_ready_peers, one_sided_peers) = state.health_snapshot.load();
    let uptime_secs = state.start_time.elapsed().as_secs();
    let (status, degraded_reason) =
        classify_health(peers, send_ready_peers, uptime_secs, one_sided_peers);

    let sample = state.health_snapshot.merged_verdict_inputs(
        peers,
        send_ready_peers,
        one_sided_peers,
        uptime_secs,
    );

    // No ConnectInfo (an embedder serving the router without connect
    // info) fails closed: no peer address, no detail.
    let loopback = connect_info
        .map(|peer| x0x::connect::is_loopback(peer.0.ip()))
        .unwrap_or(false);
    let access = if loopback
        || super::super::auth::has_valid_owner_bearer(&headers, &state.api_token, &state.sessions)
    {
        super::super::health_verdict::DetailAccess::Full
    } else {
        super::super::health_verdict::DetailAccess::Redacted
    };
    let verdict = super::super::health_verdict::classify_with_detail(&sample, access);

    let payload = ApiResponse {
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
            verdict,
        },
    };
    if access == super::super::health_verdict::DetailAccess::Full {
        // Loopback and authenticated callers: the full current payload,
        // byte for byte.
        return Json(payload).into_response();
    }
    // Same payload serialized, then the gated fields removed — see
    // `redact_health_detail`. The payload is a plain derived struct
    // with no fallible parts, so serialization cannot fail today; if a
    // future field ever makes it fallible, this branch fails closed
    // instead of panicking: the bare verdict, with no detail at all.
    let redacted = redacted_health_body(&payload, || bare_health_fallback(&payload));
    Json(redacted).into_response()
}

/// The redacted `/health` branch: serialize the payload and strip the
/// gated detail ([`super::super::health_verdict::redact_health_detail`]),
/// or — when the payload does not serialize — serve `bare()` unchanged.
/// The `Err` arm is the fail-closed root for the one fallible step this
/// branch had: `/health` is auth-exempt (#600), so it must answer, never
/// panic and never 401 (review of ba641b0).
fn redacted_health_body(
    payload: &impl Serialize,
    bare: impl FnOnce() -> serde_json::Value,
) -> serde_json::Value {
    match serde_json::to_value(payload) {
        Ok(mut value) => {
            super::super::health_verdict::redact_health_detail(&mut value);
            value
        }
        Err(_) => bare(),
    }
}

/// The fallback body when a redacted `/health` payload does not
/// serialize: the classification and the legacy liveness fields only —
/// `verdict.inputs` and `verdict.reasons` are absent entirely, so no
/// node detail can pass through this exceptional path. Built from
/// copied `String`/`bool` primitives alone: the fallback itself cannot
/// fail.
fn bare_health_fallback(payload: &ApiResponse<HealthData>) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    body.insert("ok".into(), serde_json::Value::Bool(true));
    body.insert(
        "status".into(),
        serde_json::Value::String(payload.data.status.clone()),
    );
    if let Some(reason) = &payload.data.degraded_reason {
        body.insert(
            "degraded_reason".into(),
            serde_json::Value::String(reason.clone()),
        );
    }
    let mut verdict = serde_json::Map::new();
    verdict.insert(
        "verdict".into(),
        serde_json::Value::String(payload.data.verdict.verdict.to_string()),
    );
    body.insert("verdict".into(), serde_json::Value::Object(verdict));
    serde_json::Value::Object(body)
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

    let (revocation_resync_required, revocation_warning) = {
        let revocations = state.agent.revocation_set();
        let mut revocations = revocations.write().await;
        if let Some(message) = revocations.take_revocation_status_event() {
            let _ = state.broadcast_tx.send(SseEvent {
                event_type: "status".to_string(),
                data: serde_json::json!({
                    "revocation_resync_required": true,
                    "message": message,
                }),
            });
        }
        let required = revocations.revocation_resync_required();
        let sentence = revocations.revocation_status_sentence().to_string();
        (required, sentence)
    };
    if revocation_resync_required {
        warnings.push(revocation_warning);
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
            revocation_resync_required,
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
    use super::{
        classify_health, classify_runtime_status, HealthSnapshot, VERDICT_SAMPLE_MAX_AGE_SECS,
    };
    use crate as x0x;
    use crate::server::health_verdict;

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

    /// WHY (#1380): the verdict is additive JSON only. Every legacy key —
    /// the ones the VPS fleet monitor, `x0x doctor` and the upgrade
    /// handoff's readiness probe parse — must keep its exact name and
    /// semantics, with `verdict` arriving as a new sibling.
    #[test]
    fn health_json_is_additive_over_the_legacy_shape() {
        let (peers, send_ready, one_sided) = (4, 4, 0);
        let uptime = 300_u64;
        let (status, degraded_reason) = classify_health(peers, send_ready, uptime, one_sided);
        let mut sample = health_verdict::VerdictSample::unsampled();
        sample.peers = peers;
        sample.send_ready_peers = send_ready;
        sample.one_sided_peers = one_sided;
        sample.uptime_secs = uptime;
        let data = super::HealthData {
            status: status.to_string(),
            version: x0x::VERSION.to_string(),
            peers,
            send_ready_peers: send_ready,
            uptime_secs: uptime,
            degraded_reason,
            warnings: Vec::new(),
            unsigned_group_cards_refused: 0,
            verdict: health_verdict::classify(&sample),
        };
        let json =
            serde_json::to_value(&super::ApiResponse { ok: true, data }).expect("serializes");
        for legacy_key in [
            "ok",
            "status",
            "version",
            "peers",
            "send_ready_peers",
            "uptime_secs",
        ] {
            assert!(
                json.get(legacy_key).is_some(),
                "legacy key {legacy_key} gone"
            );
        }
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["peers"], 4);
        assert_eq!(json["verdict"]["verdict"], "ok");
        for input in [
            "plane",
            "peers",
            "seed_reachable",
            "send_failure_rate",
            "delivery_probe",
            "recv_pump_shed",
            "disk",
            "log",
            "identity",
            "upgrade",
        ] {
            assert!(
                json["verdict"]["inputs"][input]["state"].is_string(),
                "verdict input {input} missing its state badge"
            );
        }
    }

    /// #1380: the verdict sample is a faithful store/load pass-through, so
    /// the handler serves the refresher's last classification inputs.
    #[test]
    fn health_snapshot_round_trips_the_verdict_sample() {
        let snapshot = HealthSnapshot::default();
        let mut sample = snapshot.verdict_sample();
        assert_eq!(sample.plane, health_verdict::PlaneSample::NotSampled);
        sample.seeds_configured = 2;
        sample.seeds_connected = 1;
        snapshot.store_verdict_sample(sample.clone());
        assert_eq!(snapshot.verdict_sample().seeds_configured, 2);
        assert_eq!(snapshot.verdict_sample().seeds_connected, 1);
    }

    /// RC1 #1380 (P2): the *actual* default snapshot — not an explicitly
    /// constructed `unsampled()` sample — must classify `ok` before the
    /// first refresher tick. At 8646cc84 the derived `Default` left the
    /// identity booleans false, so a never-refreshed snapshot read
    /// `error` ("agent or machine identity missing"). Fails there.
    #[test]
    fn default_health_snapshot_classifies_ok_before_the_first_sample() {
        let verdict = health_verdict::classify(&HealthSnapshot::default().verdict_sample());
        assert_eq!(
            verdict.verdict, "ok",
            "before the first sample is not an error: {:?}",
            verdict.reasons
        );
        assert!(
            verdict.reasons.is_empty(),
            "an unsampled snapshot carries no reasons: {:?}",
            verdict.reasons
        );
    }

    /// #1380: probe recording publishes before the handler reads — a probe
    /// outcome must be visible immediately, and none-yet must read as
    /// `(0, None, None)`.
    #[test]
    fn health_snapshot_records_probe_outcomes() {
        let snapshot = HealthSnapshot::default();
        assert_eq!(snapshot.probe_results(), (0, None, None));
        snapshot.record_probe(true, Some(12));
        snapshot.record_probe(false, None);
        assert_eq!(snapshot.probe_results(), (2, Some(false), None));
        snapshot.record_probe(true, Some(0));
        let (run, ok, latency) = snapshot.probe_results();
        assert_eq!((run, ok), (3, Some(true)));
        assert_eq!(latency, Some(1), "sub-millisecond latency clamps to 1 ms");
    }

    /// RC3 #1380 (P2): a stalled refresher plus a recorded probe failure
    /// must not read healthy. The old handler read probe results only
    /// from the cached verdict sample — frozen at the refresher's last
    /// tick — so once the refresher stalled, later probe failures never
    /// reached `/health` and the stale success vouched forever. The merge
    /// now reads the probe atomics directly and stamps the sample's age.
    /// Fails at 3ecb64c8 (compile: `merged_verdict_inputs` is the fix;
    /// see the RC3 evidence for the runtime demonstration of the old
    /// handler merge returning `ok` in this exact scenario).
    #[tokio::test(start_paused = true)]
    async fn a_stalled_refresher_and_a_recorded_probe_failure_do_not_read_healthy() {
        use std::time::Duration;

        let snapshot = HealthSnapshot::default();
        // Last-known-good: the refresher stored a healthy seeded sample...
        let mut healthy = health_verdict::VerdictSample::unsampled();
        healthy.seeds_configured = 2;
        healthy.seeds_connected = 2;
        snapshot.store_verdict_sample(healthy);
        // ...then stalled (no further stores). The probe task is separate
        // from the refresher and still records: its failure must reach the
        // verdict without waiting for the refresher's next tick.
        tokio::time::advance(Duration::from_secs(VERDICT_SAMPLE_MAX_AGE_SECS + 1)).await;
        snapshot.record_probe(false, None);

        let verdict = health_verdict::classify(&snapshot.merged_verdict_inputs(4, 4, 0, 3_600));
        assert_ne!(
            verdict.verdict, "ok",
            "a stalled refresher must not hide a recorded probe failure: {:?}",
            verdict.reasons
        );
        assert_eq!(
            verdict.inputs.delivery_probe.state, "degraded",
            "the failure is read from the live atomics, not the cached copy"
        );
        assert!(
            matches!(verdict.sample_age_secs, Some(age) if age > VERDICT_SAMPLE_MAX_AGE_SECS),
            "the stale sample's age is reported: {:?}",
            verdict.sample_age_secs
        );
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("background sampler")),
            "staleness itself carries a reason: {:?}",
            verdict.reasons
        );
    }

    /// Control for the RC3 regression above: while the refresher is alive
    /// (a fresh sample), a recorded failure degrades from the probe alone
    /// and a clean snapshot stays `ok` — the freshness bound must not fire
    /// on healthy refreshes.
    #[tokio::test(start_paused = true)]
    async fn a_fresh_sample_degrades_only_from_the_probe_and_a_clean_one_stays_ok() {
        use std::time::Duration;

        let failed = HealthSnapshot::default();
        failed.store_verdict_sample(health_verdict::VerdictSample::unsampled());
        tokio::time::advance(Duration::from_secs(2)).await;
        failed.record_probe(false, None);
        let verdict = health_verdict::classify(&failed.merged_verdict_inputs(4, 4, 0, 600));
        assert_eq!(verdict.verdict, "degraded");
        assert!(
            verdict.reasons.iter().any(|r| r.contains("delivery probe")),
            "the degradation comes from the probe: {:?}",
            verdict.reasons
        );
        assert!(
            !verdict
                .reasons
                .iter()
                .any(|r| r.contains("background sampler")),
            "a 2 s-old sample is fresh: {:?}",
            verdict.reasons
        );

        let clean = HealthSnapshot::default();
        clean.store_verdict_sample(health_verdict::VerdictSample::unsampled());
        tokio::time::advance(Duration::from_secs(2)).await;
        let verdict = health_verdict::classify(&clean.merged_verdict_inputs(4, 4, 0, 600));
        assert_eq!(
            verdict.verdict, "ok",
            "a fresh clean snapshot stays ok: {:?}",
            verdict.reasons
        );
    }

    /// RC3 #1380 (P2): a sample that never arrived (a refresher stalled
    /// from startup) ages from process start — the unsampled baseline
    /// cannot vouch for health forever.
    #[tokio::test(start_paused = true)]
    async fn a_never_refreshed_sample_goes_stale_with_uptime() {
        let snapshot = HealthSnapshot::default();
        // Young uptime: the unsampled baseline keeps the startup contract.
        let fresh = health_verdict::classify(&snapshot.merged_verdict_inputs(2, 2, 0, 5));
        assert_eq!(
            fresh.verdict, "ok",
            "startup before the first refresh is not stale: {:?}",
            fresh.reasons
        );
        // Past the bound with no sample ever stored: stale.
        let stale = health_verdict::classify(&snapshot.merged_verdict_inputs(
            2,
            2,
            0,
            VERDICT_SAMPLE_MAX_AGE_SECS + 1,
        ));
        assert_eq!(stale.verdict, "degraded");
        assert!(stale
            .reasons
            .iter()
            .any(|r| r.contains("background sampler")));
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

    /// #1419, the deferred acceptance case: a link whose two directions
    /// are both stale while other peers flow (the eph `r0481pre-e2e`
    /// shape) is degraded by the publish path, then re-dialled once.
    /// `publish_one_sided_health` resolves the liveness probe before the
    /// store, so the stored count is visible while the re-dial is paused.
    /// The re-dial clears the moved winner, and a later publish leaves the
    /// snapshot healthy again.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn issue1419_both_directions_stale_link_is_published_degraded_then_repaired() {
        use std::sync::Arc;
        use std::time::Duration;

        let plane = "issue1419-both-stale-publish";
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
        fabric
            .supersede_one_sided_for_test(&peer_a, &peer_b)
            .expect("the A-B link exists");
        // B sends nothing after the fault, so both A-B directions go stale
        // together while A-C keeps flowing.
        tokio::time::sleep(x0x::network::ONE_SIDED_STALE + Duration::from_secs(10)).await;
        a_link.send(&peer_c, b"\x7fac2").unwrap();
        c_link.send(&peer_a, b"\x7fca2").unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        // The pause holds the re-dial inside its 3 s bound, short of the
        // bound itself so the dial still completes.
        a.pause_one_sided_redial_for_test(Duration::from_secs(1));

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
            "the both-directions-stale link is degraded before the re-dial wait finishes"
        );
        assert_eq!(
            snapshot.one_sided_ids(),
            vec![peer_b.0],
            "the stored set is the same peer the count names"
        );
        tokio::time::sleep(Duration::from_secs(4)).await;
        task.await.unwrap();
        assert_eq!(
            fabric.one_sided_winner_for_test(&peer_a, &peer_b),
            None,
            "the one bounded re-dial installs a shared winner"
        );
        assert_eq!(
            a.try_connection_generation(&peer_b).unwrap(),
            b.try_connection_generation(&peer_a).unwrap(),
            "both ends agree on that winner"
        );
        // Fresh traffic on the healed link, then one more publish: the
        // stored view returns to healthy.
        a_link.send(&peer_b, b"\x7fhealed-ab").unwrap();
        b_link.send(&peer_a, b"\x7fhealed-ba").unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        super::publish_one_sided_health(&a, &snapshot, 2).await;
        assert_eq!(
            snapshot.load().2,
            0,
            "the healed link leaves the stored degraded set"
        );
        a.try_shutdown().await.unwrap();
        b.try_shutdown().await.unwrap();
        c.try_shutdown().await.unwrap();
    }

    /// `/health` detail gate (David's ruling of 20 Oct 2026, 01:51 BST, on
    /// #1480 Finding 3): the node-specific detail inside `verdict.inputs`
    /// is served to loopback callers and to callers with a valid owner
    /// bearer — the same check the authenticated routes use — and withheld
    /// from everyone else. The verdict itself stays auth-exempt (#600).
    ///
    /// The tests drive the handler through a router, inserting
    /// `ConnectInfo` exactly the way `into_make_service_with_connect_info`
    /// does on the real accept loop, so the gate is tested at the same
    /// seam production uses.
    mod health_detail_gate {
        use super::super::{health, AppState};
        use crate::server::routes::named_groups::tests::secure_endpoint_test_state_at;
        use axum::body::{to_bytes, Body};
        use axum::extract::ConnectInfo;
        use axum::http::Request;
        use axum::routing::get;
        use std::net::{IpAddr, SocketAddr};
        use std::sync::Arc;
        use tower::ServiceExt as _;

        /// The gated detail fields, as JSON-pointer paths into the
        /// flattened `/health` payload. `rate` travels with its counts:
        /// it is the same windowed publish-failure measurement.
        const GATED_DETAIL: &[&str] = &[
            "/verdict/inputs/disk/free_bytes",
            "/verdict/inputs/disk/total_bytes",
            "/verdict/inputs/upgrade/latest_version",
            "/verdict/inputs/identity/user_present",
            "/verdict/inputs/log/errors",
            "/verdict/inputs/send_failure_rate/attempts",
            "/verdict/inputs/send_failure_rate/failed",
            "/verdict/inputs/send_failure_rate/rate",
        ];

        /// Every field that is NOT gated — the verdict itself, its state
        /// badges, the public window constants and neighbouring inputs —
        /// must survive the redaction untouched.
        const UNGATED: &[&str] = &[
            "/verdict/verdict",
            "/verdict/reasons",
            "/verdict/inputs/plane/state",
            "/verdict/inputs/peers/peers",
            "/verdict/inputs/disk/state",
            "/verdict/inputs/log/window_secs",
            "/verdict/inputs/identity/agent",
            "/verdict/inputs/identity/machine",
            "/verdict/inputs/upgrade/update_available",
        ];

        /// Non-loopback test caller (TEST-NET-1, RFC 5737).
        fn remote() -> IpAddr {
            "192.0.2.10".parse().expect("test-net v4 address")
        }

        fn router(state: &Arc<AppState>) -> axum::Router {
            axum::Router::new()
                .route("/health", get(health))
                .with_state(Arc::clone(state))
        }

        /// One `/health` request as seen from `peer`, with an optional
        /// bearer and extra headers. Returns the parsed flattened payload.
        async fn get_health(
            state: &Arc<AppState>,
            peer: IpAddr,
            bearer: Option<&str>,
            extra_headers: &[(&'static str, &str)],
        ) -> serde_json::Value {
            let mut builder =
                Request::get("/health").extension(ConnectInfo(SocketAddr::new(peer, 51714)));
            if let Some(token) = bearer {
                builder = builder.header("authorization", format!("Bearer {token}"));
            }
            for (name, value) in extra_headers {
                builder = builder.header(*name, *value);
            }
            let response = router(state)
                .oneshot(builder.body(Body::empty()).expect("empty body"))
                .await
                .expect("router answers");
            assert_eq!(
                response.status(),
                200,
                "the bare verdict is auth-exempt and never answers 401 (#600)"
            );
            let bytes = to_bytes(response.into_body(), 1 << 20)
                .await
                .expect("response body");
            serde_json::from_slice(&bytes).expect("valid JSON payload")
        }

        /// A network-free AppState: agent keys in a temp dir, no gossip
        /// runtime, no bootstrap — the same inert fixture the profile and
        /// history handler tests use. Every path is explicit (identity
        /// dir, absent user key) so the builder never falls back to the
        /// real `~/.x0x` (#456 test-home guard).
        async fn test_state() -> (Arc<AppState>, tempfile::TempDir) {
            let dir = tempfile::tempdir().expect("temp data dir");
            let agent = Arc::new(
                crate::Agent::builder()
                    .with_identity_dir(dir.path())
                    .with_machine_key(dir.path().join("machine.key"))
                    .with_agent_key(crate::identity::AgentKeypair::generate().expect("agent key"))
                    .with_user_key_path(dir.path().join("user.key"))
                    .with_contact_store_path(dir.path().join("contacts.json"))
                    .with_peer_cache_disabled()
                    .build()
                    .await
                    .expect("agent without a network"),
            );
            let state = secure_endpoint_test_state_at(dir.path(), agent)
                .await
                .expect("test AppState");
            (state, dir)
        }

        /// WHY (the ruling): a non-loopback caller without a token gets
        /// the verdict — `ok`, `status`, the verdict classification and
        /// every non-gated input — but none of the listed detail fields.
        /// Fails on main (8868492), which served every field to every
        /// caller.
        #[tokio::test]
        async fn non_loopback_unauthenticated_gets_the_verdict_without_detail() {
            let (state, _dir) = test_state().await;
            let payload = get_health(&state, remote(), None, &[]).await;
            for path in GATED_DETAIL {
                assert!(
                    payload.pointer(path).is_none(),
                    "{path} must be absent for a non-loopback unauthenticated caller: {payload}"
                );
            }
            for path in UNGATED {
                assert!(
                    payload.pointer(path).is_some(),
                    "{path} is not gated and must stay: {payload}"
                );
            }
        }

        /// WHY (the ruling): the durable API token authenticates a remote
        /// caller — the same bearer the authenticated routes accept.
        #[tokio::test]
        async fn non_loopback_durable_bearer_gets_full_detail() {
            let (state, _dir) = test_state().await;
            let payload = get_health(&state, remote(), Some(&state.api_token), &[]).await;
            for path in GATED_DETAIL {
                assert!(
                    payload.pointer(path).is_some(),
                    "{path} must be present for an authenticated caller: {payload}"
                );
            }
        }

        /// WHY (the ruling): "authenticated" means what the route layer
        /// means — a live session bearer also unlocks the detail.
        #[tokio::test]
        async fn non_loopback_session_bearer_gets_full_detail() {
            let (state, _dir) = test_state().await;
            let token = state.sessions.issue(std::time::Instant::now());
            let payload = get_health(&state, remote(), Some(&token), &[]).await;
            for path in GATED_DETAIL {
                assert!(
                    payload.pointer(path).is_some(),
                    "{path} must be present behind a session bearer: {payload}"
                );
            }
        }

        /// WHY (the ruling): loopback keeps the full detail with no token
        /// at all — the local operator and the loopback-probing watchdog
        /// and CLI see today's payload unchanged.
        #[tokio::test]
        async fn loopback_unauthenticated_gets_full_detail() {
            let (state, _dir) = test_state().await;
            for loopback in ["127.0.0.1", "::1"] {
                let peer: IpAddr = loopback.parse().expect("loopback address");
                let payload = get_health(&state, peer, None, &[]).await;
                for path in GATED_DETAIL {
                    assert!(
                        payload.pointer(path).is_some(),
                        "{path} must be present for a loopback caller ({loopback}): {payload}"
                    );
                }
            }
        }

        /// WHY (the ruling): the loopback decision reads the connection's
        /// own peer address. A proxy header is client-controlled input and
        /// must never turn a remote caller loopback.
        #[tokio::test]
        async fn forwarded_headers_do_not_make_a_remote_caller_loopback() {
            let (state, _dir) = test_state().await;
            let payload = get_health(
                &state,
                remote(),
                None,
                &[("x-forwarded-for", "127.0.0.1"), ("x-real-ip", "127.0.0.1")],
            )
            .await;
            for path in GATED_DETAIL {
                assert!(
                    payload.pointer(path).is_none(),
                    "{path} must stay gated behind a spoofed proxy header: {payload}"
                );
            }
        }

        /// WHY (fail-closed): `::ffff:127.0.0.1` is not loopback under
        /// `connect::is_loopback` — an IPv4-mapped peer is treated as the
        /// remote caller it arrives as.
        #[tokio::test]
        async fn v4_mapped_loopback_peer_fails_closed() {
            let (state, _dir) = test_state().await;
            let peer: IpAddr = "::ffff:127.0.0.1".parse().expect("v4-mapped address");
            let payload = get_health(&state, peer, None, &[]).await;
            for path in GATED_DETAIL {
                assert!(
                    payload.pointer(path).is_none(),
                    "{path} must stay gated for an IPv4-mapped peer: {payload}"
                );
            }
        }

        /// WHY (the ruling): only a VALID bearer unlocks the detail. A
        /// syntactically fine but wrong token leaves the caller gated —
        /// and still answered, never 401.
        #[tokio::test]
        async fn a_wrong_bearer_does_not_unlock_detail() {
            let (state, _dir) = test_state().await;
            let payload = get_health(&state, remote(), Some("not-the-api-token"), &[]).await;
            for path in GATED_DETAIL {
                assert!(
                    payload.pointer(path).is_none(),
                    "{path} must stay gated behind an invalid bearer: {payload}"
                );
            }
        }

        /// WHY (wiring): the gate reads the peer address from
        /// `ConnectInfo`, which only exists because the API server serves
        /// the router through `into_make_service_with_connect_info`. A
        /// bare `axum::serve` would make every read `None` and fail the
        /// gate closed for loopback callers too — silently, since
        /// `/health` keeps answering. Same source-guard convention as the
        /// #600 guard above.
        #[test]
        fn api_server_supplies_connect_info_to_the_router() {
            const SERVER_SOURCE: &str = include_str!("../mod.rs");
            assert!(
                SERVER_SOURCE
                    .contains("into_make_service_with_connect_info::<std::net::SocketAddr>()"),
                "the API server must serve the router with connect info — the /health \
                 detail gate reads the peer address from it (David's 20 Oct 2026 ruling)"
            );
        }

        /// WHY (no panic on the auth-exempt endpoint — both reviews of
        /// ba641b0): the redacted branch's one fallible step, serializing
        /// the payload, must fail closed instead of `expect`. A payload
        /// that cannot serialize serves the bare body unchanged —
        /// answered, never a panic, never a 401.
        #[test]
        fn unserializable_payload_falls_back_to_the_bare_verdict() {
            /// A test-only payload whose serialization always errors —
            /// the `Err` arm of the redaction helper, driven directly.
            struct Unserializable;
            impl serde::Serialize for Unserializable {
                fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                    Err(serde::ser::Error::custom(
                        "test fixture: serialization always fails",
                    ))
                }
            }
            let bare = serde_json::json!({"ok": true, "verdict": {"verdict": "ok"}});
            let body = super::super::redacted_health_body(&Unserializable, || bare.clone());
            assert_eq!(body, bare);
        }

        /// WHY (fail closed): if the redacted branch ever takes the
        /// fallback, the body it serves cannot carry node detail. The
        /// fallback drops `verdict.inputs` and `verdict.reasons`
        /// entirely, so none of the gated values — and nothing else from
        /// the payload — can appear in it.
        #[test]
        fn the_bare_verdict_fallback_cannot_leak_detail() {
            use crate::server::health_verdict::{
                classify_with_detail, DetailAccess, VerdictSample,
            };

            let sample = VerdictSample {
                disk_free_bytes: Some(536870912),
                disk_total_bytes: Some(68719476736),
                send_attempts_window: 100,
                send_failed_window: 75,
                log_errors_window: 77,
                upgrade_latest_version: Some("9.9.9-zcodeleak".to_string()),
                identity_user: true,
                ..VerdictSample::default()
            };
            let payload = super::super::ApiResponse {
                ok: true,
                data: super::super::HealthData {
                    status: "degraded".to_string(),
                    version: "0.0.0-test".to_string(),
                    peers: 3,
                    send_ready_peers: 2,
                    uptime_secs: 4242,
                    degraded_reason: None,
                    warnings: Vec::new(),
                    unsigned_group_cards_refused: 0,
                    verdict: classify_with_detail(&sample, DetailAccess::Full),
                },
            };
            // Control: the payload itself carries every gated value.
            let full = serde_json::to_value(&payload).expect("payload serializes");
            let full_text = full.to_string();
            for probe in ["536870912", "68719476736", "9.9.9-zcodeleak", "4242"] {
                assert!(
                    full_text.contains(probe),
                    "control: {probe} must be in the full payload"
                );
            }

            let bare = super::super::bare_health_fallback(&payload);
            assert!(bare.pointer("/verdict/inputs").is_none(), "{bare}");
            assert!(bare.pointer("/verdict/reasons").is_none(), "{bare}");
            assert_eq!(
                bare.as_object()
                    .expect("fallback is an object")
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["ok", "status", "verdict"],
                "the fallback is exactly the bare verdict: {bare}"
            );
            assert_eq!(
                bare.pointer("/verdict")
                    .and_then(serde_json::Value::as_object)
                    .expect("verdict is an object")
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["verdict"],
                "only the overall classification survives: {bare}"
            );
            let bare_text = bare.to_string();
            for probe in [
                "536870912",
                "68719476736",
                "75",
                "100",
                "77",
                "9.9.9-zcodeleak",
                "user_present",
                "latest_version",
                "inputs",
                "reasons",
                "4242",
                "0.0.0-test",
            ] {
                assert!(
                    !bare_text.contains(probe),
                    "{probe} leaked into the fallback: {bare_text}"
                );
            }
        }
    }
}
