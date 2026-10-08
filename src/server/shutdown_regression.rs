//! Real-socket in-process shutdown regressions (#1262, #1263 part 1, #1269).
//!
//! Every daemon binds loopback only, has no bootstrap peer outside the
//! test, runs with mDNS, port mapping, the peer cache and update checks
//! off, uses a private plane and temporary directories. The tests are
//! `#[ignore]`d and run only inside the approved loopback-only sandbox.
//!
//! - `issue1262_concurrent_embedded_shutdown_*`: concurrent shutdown and
//!   relaunch of three idle or peered daemons.
//! - `issue1262_shutdown_with_dial_in_flight`: a handshake to a silent
//!   peer is in flight at shutdown (an offline seed).
//! - `issue1262_owned_workload_parallel`: the embedder's parallel-test
//!   shape. Knobs for investigation: `X0X_1262_PAIRS`,
//!   `X0X_1262_UPTIME_SECS`, `X0X_1262_STAGGER_MS` (`none` stops a pair
//!   concurrently), `X0X_1262_NO_GROUPS`/`_KV`/`_DM=1`,
//!   `X0X_1262_GROUPS_EVERY_CYCLE=1`, and `RUST_LOG`.
//! - `issue1263_shutdown_with_frozen_peer`: sends blocked on a peer that
//!   stopped reading must not stall network teardown.
//! - `issue1269_group_join_shutdown_releases_owner`: after a peer joins a
//!   named group, both daemons' AppState and Agent must be released when
//!   `shutdown_and_wait` returns, so a same-dir relaunch can reopen
//!   `history.db`.

#![cfg(test)]

use super::{serve_with_options, DaemonConfig, ServeOptions};
use std::net::{TcpListener, UdpSocket};
use std::time::Duration;

async fn concurrent_shutdown_and_relaunch(peered: bool) {
    let root = tempfile::tempdir().expect("isolated daemon directories");
    let plane = format!("x0x.test.shutdown.{}", std::process::id());
    let configs: Vec<DaemonConfig> = (0..3)
        .map(|index| {
            serde_json::from_value(serde_json::json!({
                "bind_address": "127.0.0.1:0",
                "api_address": "127.0.0.1:0",
                "data_dir": root.path().join(format!("daemon-{index}")),
                "identity_dir": root.path().join(format!("identity-{index}")),
                "bootstrap_peers": [],
                "mdns_enabled": false,
                "port_mapping_enabled": false,
                "network_id": plane
            }))
            .expect("loopback-only daemon configuration")
        })
        .collect();

    // The second cycle uses the SAME directories and identities. The old
    // handles must have released their instance locks as well as sockets.
    for cycle in 0..2 {
        let starts = configs.iter().cloned().map(|config| async move {
            serve_with_options(
                config,
                ServeOptions {
                    skip_update_check: true,
                    cli_no_port_mapping: true,
                    cli_disable_peer_cache: true,
                    self_update_enabled: false,
                    ..ServeOptions::default()
                },
            )
            .await
            .expect("serve on fresh or released directories")
        });
        let handles = futures::future::join_all(starts).await;
        let mut addresses = Vec::new();
        let mut networks = Vec::new();
        for handle in &handles {
            let state = handle.test_state.upgrade().expect("live daemon state");
            let network = state.agent.network().expect("real QUIC network").clone();
            let udp = network.bound_addr().await.expect("bound UDP address");
            assert!(udp.ip().is_loopback());
            assert_ne!(udp.port(), 0);
            addresses.push((udp, handle.local_addr()));
            networks.push(network);
        }
        if peered {
            for index in 0..networks.len() {
                networks[index]
                    .connect_addr(addresses[(index + 1) % networks.len()].0)
                    .await
                    .expect("connect loopback daemons");
            }
        }
        // Keep NetworkNode handles alive deliberately: typed shutdown must
        // release the bound socket even when an embedder retains a handle.
        let results = tokio::time::timeout(
            Duration::from_secs(30),
            futures::future::join_all(handles.into_iter().map(|h| h.shutdown_and_wait())),
        )
        .await
        .expect("all concurrent shutdowns complete within 30 seconds");
        for (index, result) in results.into_iter().enumerate() {
            assert!(result.is_ok(), "cycle {cycle}, daemon {index}: {result:?}");
        }
        // Keep all rebound sockets open together: every original address
        // must be free, not merely a single reused ephemeral port.
        let probes: Vec<_> = addresses
            .iter()
            .map(|(udp, tcp)| {
                (
                    UdpSocket::bind(udp).expect("original UDP socket released"),
                    TcpListener::bind(tcp).expect("original API listener released"),
                )
            })
            .collect();
        drop(probes);
        drop(networks);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real sockets: requires the approved loopback-only sandbox"]
async fn issue1262_concurrent_embedded_shutdown_idle() {
    concurrent_shutdown_and_relaunch(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real sockets: requires the approved loopback-only sandbox"]
async fn issue1262_concurrent_embedded_shutdown_peered() {
    concurrent_shutdown_and_relaunch(true).await;
}

// ---------------------------------------------------------------------------
// #1262 reporter-shaped workload: owned daemons (user key, so Home and owner
// sync run), real REST/WS/SSE clients, two peered daemons exchanging pubsub,
// DMs and group/KV traffic, three relaunches of the same identity and data
// dir, and several such pairs alive at once in one process on separate
// runtimes (the `cargo test` shape the embedder runs).
// ---------------------------------------------------------------------------

mod workload {
    use super::super::state::AppState;
    use super::super::{serve_with_options, DaemonConfig, ServeOptions, ServerHandle};
    use base64::Engine as _;
    use std::net::{SocketAddr, TcpListener, UdpSocket};
    use std::path::Path;
    use std::sync::{Arc, Mutex, Weak};
    use std::time::{Duration, Instant};

    const CYCLES: usize = 3;
    const PAIRS: usize = 4;

    fn off(feature: &str) -> bool {
        on(&format!("NO_{feature}"))
    }

    fn on(knob: &str) -> bool {
        std::env::var(format!("X0X_1262_{knob}")).is_ok_and(|v| v == "1")
    }

    fn uptime() -> Duration {
        let secs = std::env::var("X0X_1262_UPTIME_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(12);
        Duration::from_secs(secs)
    }

    /// Deterministic per-(pair, cycle) jitter in `0..max_ms`, varied per
    /// process so repeated runs explore different interleavings.
    fn jitter_ms(index: usize, cycle: usize, max_ms: u64) -> u64 {
        use std::hash::{Hash as _, Hasher as _};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (std::process::id(), index, cycle).hash(&mut hasher);
        hasher.finish() % max_ms.max(1)
    }

    struct Live {
        handle: ServerHandle,
        state: Weak<AppState>,
        base: String,
        token: String,
        agent_hex: String,
        udp: SocketAddr,
        api: SocketAddr,
    }

    fn config(dir: &Path, plane: &str, bootstrap: &[SocketAddr]) -> DaemonConfig {
        let mut config: DaemonConfig = serde_json::from_value(serde_json::json!({
            "bind_address": "127.0.0.1:0",
            "api_address": "127.0.0.1:0",
            "data_dir": dir.join("data"),
            "identity_dir": dir.join("identity"),
            "bootstrap_peers": bootstrap,
            "mdns_enabled": false,
            "port_mapping_enabled": false,
            "network_id": plane
        }))
        .expect("loopback-only daemon configuration");
        config.api_watchdog.enabled = false;
        config
    }

    async fn provision_owner(dir: &Path, user: &crate::identity::UserKeypair) {
        let identity = dir.join("identity");
        tokio::fs::create_dir_all(&identity)
            .await
            .expect("identity dir");
        let bytes = crate::storage::serialize_user_keypair(user).expect("user key bytes");
        crate::storage::write_private_bytes(&identity.join("user.key"), bytes)
            .await
            .expect("user key written");
    }

    async fn start(dir: &Path, plane: &str, bootstrap: &[SocketAddr]) -> Live {
        // A relaunch can race the previous incarnation's stray owners of
        // its data dir (history.db lock). Retry for a bounded time and log
        // every refusal so the run records the hazard.
        let first = Instant::now();
        let handle = loop {
            match serve_with_options(
                config(dir, plane, bootstrap),
                ServeOptions {
                    skip_update_check: true,
                    cli_no_port_mapping: true,
                    cli_disable_peer_cache: true,
                    self_update_enabled: false,
                    ..ServeOptions::default()
                },
            )
            .await
            {
                Ok(handle) => break handle,
                Err(error) if first.elapsed() < Duration::from_secs(60) => {
                    eprintln!(
                        "ISSUE1262 RELAUNCH_REFUSED {} after {:?}: {error:#}",
                        dir.display(),
                        first.elapsed()
                    );
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => panic!("serve never succeeded for {}: {error:#}", dir.display()),
            }
        };
        let state = handle.test_state.upgrade().expect("live daemon state");
        let network = state.agent.network().expect("real QUIC network").clone();
        let udp = network.bound_addr().await.expect("bound UDP address");
        assert!(udp.ip().is_loopback());
        let api = handle.local_addr();
        assert!(api.ip().is_loopback());
        Live {
            base: format!("http://{api}"),
            token: state.api_token.clone(),
            agent_hex: hex::encode(state.agent.agent_id().as_bytes()),
            state: Arc::downgrade(&state),
            handle,
            udp,
            api,
        }
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("loopback HTTP client")
    }

    async fn call(
        http: &reqwest::Client,
        live: &Live,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let key = format!(
            "{method} {}",
            path.split('/')
                .map(|segment| if segment.len() >= 32 { "*" } else { segment })
                .collect::<Vec<_>>()
                .join("/")
        );
        let mut request = http
            .request(method, format!("{}{path}", live.base))
            .bearer_auth(&live.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await;
        let ok = response
            .as_ref()
            .is_ok_and(|response| response.status().is_success());
        {
            let mut tally = TALLY
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = tally.entry(key).or_default();
            if ok {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
        response.ok()?.json::<serde_json::Value>().await.ok()
    }

    /// Per-endpoint `(2xx, other)` counts for the whole run, printed at the
    /// end as evidence of what the workload exercised.
    static TALLY: std::sync::LazyLock<Mutex<std::collections::BTreeMap<String, (u64, u64)>>> =
        std::sync::LazyLock::new(Default::default);

    /// A WebSocket client subscribed to `topic`, left reading until the
    /// daemon closes it.
    async fn ws_client(live: &Live, topic: &str) -> Option<tokio::task::JoinHandle<()>> {
        use futures::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
        let mut request = format!("ws://{}/ws", live.api).into_client_request().ok()?;
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", live.token).parse().ok()?,
        );
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await.ok()?;
        let subscribe = serde_json::json!({ "type": "subscribe", "topics": [topic] }).to_string();
        socket
            .send(tokio_tungstenite::tungstenite::Message::Text(subscribe))
            .await
            .ok()?;
        Some(tokio::spawn(async move {
            while let Some(Ok(_frame)) = socket.next().await {}
        }))
    }

    /// An SSE `/events` reader left open across shutdown.
    fn sse_client(http: &reqwest::Client, live: &Live) -> tokio::task::JoinHandle<()> {
        use futures::StreamExt as _;
        let request = http
            .get(format!("{}/events", live.base))
            .bearer_auth(&live.token)
            .timeout(Duration::from_secs(600));
        tokio::spawn(async move {
            if let Ok(response) = request.send().await {
                let mut body = response.bytes_stream();
                while let Some(Ok(_chunk)) = body.next().await {}
            }
        })
    }

    async fn wait_connected(a: &Live, b: &Live) -> bool {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let (Some(sa), Some(sb)) = (a.state.upgrade(), b.state.upgrade()) else {
                return false;
            };
            let (Some(na), Some(nb)) = (sa.agent.network(), sb.agent.network()) else {
                return false;
            };
            if na.is_connected(&nb.peer_id()).await {
                return true;
            }
            drop((sa, sb));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    async fn traffic(
        http: &reqwest::Client,
        a: &Live,
        b: &Live,
        tag: &str,
        until: Instant,
        groups: bool,
    ) {
        use reqwest::Method;
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
        let topic = format!("x0x.test.1262.{tag}");
        for live in [a, b] {
            for path in [
                "/health",
                "/agent",
                "/home",
                "/peers",
                "/presence",
                "/groups",
            ] {
                let _ = call(http, live, Method::GET, path, None).await;
            }
            let _ = call(
                http,
                live,
                Method::POST,
                "/subscribe",
                Some(serde_json::json!({ "topic": topic })),
            )
            .await;
        }
        let _ = call(
            http,
            a,
            Method::POST,
            "/agents/connect",
            Some(serde_json::json!({ "agent_id": b.agent_hex })),
        )
        .await;
        // Named group A creates, B joins by invite, A sends into it.
        let group = if off("GROUPS") || !groups {
            None
        } else {
            call(
                http,
                a,
                Method::POST,
                "/groups",
                Some(serde_json::json!({ "name": format!("g-{tag}") })),
            )
            .await
            .and_then(|v| v["group_id"].as_str().map(str::to_string))
        };
        if let Some(group) = &group {
            let invite = call(
                http,
                a,
                Method::POST,
                &format!("/groups/{group}/invite"),
                Some(serde_json::json!({ "expiry_secs": 3600 })),
            )
            .await
            .and_then(|v| v["invite_link"].as_str().map(str::to_string));
            if let Some(invite) = invite {
                let _ = call(
                    http,
                    b,
                    Method::POST,
                    "/groups/join",
                    Some(serde_json::json!({ "invite": invite })),
                )
                .await;
            }
            let _ = call(
                http,
                a,
                Method::POST,
                &format!("/groups/{group}/stores"),
                Some(serde_json::json!({ "name": format!("gs-{tag}") })),
            )
            .await;
        }
        let store = if off("KV") {
            None
        } else {
            call(
            http,
            a,
            Method::POST,
            "/stores",
            Some(serde_json::json!({ "name": format!("kv-{tag}"), "topic": format!("{topic}.kv") })),
        )
        .await
        .and_then(|v| v["id"].as_str().map(str::to_string))
        };
        let mut round = 0u64;
        while Instant::now() < until {
            round += 1;
            let _ = call(
                http,
                a,
                Method::POST,
                "/publish",
                Some(serde_json::json!({ "topic": topic, "payload": b64(&format!("a{round}")) })),
            )
            .await;
            let _ = call(
                http,
                b,
                Method::POST,
                "/publish",
                Some(serde_json::json!({ "topic": topic, "payload": b64(&format!("b{round}")) })),
            )
            .await;
            if !off("DM") {
                let _ = call(
                    http,
                    a,
                    Method::POST,
                    "/direct/send",
                    Some(serde_json::json!({ "agent_id": b.agent_hex, "payload": b64("dm-a") })),
                )
                .await;
                let _ = call(
                    http,
                    b,
                    Method::POST,
                    "/direct/send",
                    Some(serde_json::json!({ "agent_id": a.agent_hex, "payload": b64("dm-b") })),
                )
                .await;
            }
            if let Some(group) = &group {
                let _ = call(
                    http,
                    a,
                    Method::POST,
                    &format!("/groups/{group}/send"),
                    Some(serde_json::json!({ "body": format!("hello {round}") })),
                )
                .await;
            }
            if let Some(store) = &store {
                let _ = call(
                    http,
                    a,
                    Method::PUT,
                    &format!("/stores/{store}/k{}", round % 4),
                    Some(serde_json::json!({ "value": b64(&format!("v{round}")) })),
                )
                .await;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Shut `live` down and prove both original addresses rebind. Returns a
    /// failure line, or `None`.
    async fn stop(live: Live, label: &str) -> Option<String> {
        let (udp, api) = (live.udp, live.api);
        let state_weak = live.state.clone();
        let agent_weak = live
            .state
            .upgrade()
            .map(|state| Arc::downgrade(&state.agent))
            .unwrap_or_default();
        let started = Instant::now();
        let result =
            tokio::time::timeout(Duration::from_secs(180), live.handle.shutdown_and_wait()).await;
        let took = started.elapsed();
        let failure = match result {
            Err(_) => Some(format!("{label}: shutdown did not return within 180 s")),
            Ok(Err(error)) => Some(format!("{label}: after {took:?}: {error:#}")),
            Ok(Ok(())) => {
                let udp_ok = UdpSocket::bind(udp).is_ok();
                let tcp_ok = TcpListener::bind(api).is_ok();
                (!udp_ok || !tcp_ok).then(|| {
                    format!(
                        "{label}: Ok after {took:?} but udp_rebind={udp_ok} tcp_rebind={tcp_ok}"
                    )
                })
            }
        };
        eprintln!(
            "ISSUE1262 {label} shutdown took {took:?} result={}",
            failure.as_deref().unwrap_or("ok")
        );
        let release_deadline = Instant::now() + Duration::from_secs(10);
        while (state_weak.strong_count() > 0 || agent_weak.strong_count() > 0)
            && Instant::now() < release_deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        eprintln!(
            "ISSUE1262 {label} after_shutdown+{:?} appstate_strong={} agent_strong={}",
            started.elapsed().saturating_sub(took),
            state_weak.strong_count(),
            agent_weak.strong_count()
        );
        failure
    }

    /// One owned pair. Every daemon in the process shares one plane and
    /// also bootstraps to the process-wide `hub`, so daemons of different
    /// pairs learn each other through gossip membership, as the embedder's
    /// parallel test daemons do through the shared bootstrap network.
    async fn pair(
        root: &Path,
        index: usize,
        plane: &str,
        hub: SocketAddr,
        failures: Arc<Mutex<Vec<String>>>,
    ) {
        let dir_a = root.join(format!("pair{index}-a"));
        let dir_b = root.join(format!("pair{index}-b"));
        let owner_a = crate::identity::UserKeypair::generate().expect("user key");
        provision_owner(&dir_a, &owner_a).await;
        if index.is_multiple_of(2) {
            // Same owner on both machines (owner-sync peers).
            provision_owner(&dir_b, &owner_a).await;
        } else {
            let owner_b = crate::identity::UserKeypair::generate().expect("user key");
            provision_owner(&dir_b, &owner_b).await;
        }
        let http = client();
        for cycle in 0..CYCLES {
            // Desynchronise the pairs' cycles, as independent tests are.
            tokio::time::sleep(Duration::from_millis(jitter_ms(index, cycle, 1500))).await;
            let a = start(&dir_a, plane, &[hub]).await;
            let b = start(&dir_b, plane, &[hub, a.udp]).await;
            let connected = wait_connected(&a, &b).await;
            let tag = format!("{index}-{cycle}");
            let topic = format!("x0x.test.1262.{tag}");
            let ws_a = ws_client(&a, &topic).await;
            let ws_b = ws_client(&b, &topic).await;
            eprintln!(
                "ISSUE1262 pair{index} cycle{cycle} ws_a={} ws_b={}",
                ws_a.is_some(),
                ws_b.is_some()
            );
            let sse_a = sse_client(&http, &a);
            let sse_b = sse_client(&http, &b);
            let until = Instant::now()
                + uptime()
                + Duration::from_millis(jitter_ms(index + 7, cycle, 3000));
            // Groups only in the last cycle by default, as #1262 ran it.
            // Before #1269, a group made the old AppState (and its
            // history.db lock) outlive shutdown, which blocked the relaunch
            // of a later cycle. `X0X_1262_GROUPS_EVERY_CYCLE=1` runs groups
            // in every cycle.
            let groups = cycle + 1 == CYCLES || on("GROUPS_EVERY_CYCLE");
            traffic(&http, &a, &b, &tag, until, groups).await;
            eprintln!("ISSUE1262 pair{index} cycle{cycle} connected={connected} stopping");
            let (label_a, label_b) = (
                format!("pair{index}/cycle{cycle}/a"),
                format!("pair{index}/cycle{cycle}/b"),
            );
            let stagger = match std::env::var("X0X_1262_STAGGER_MS") {
                Ok(v) if v == "none" => None,
                Ok(v) => v.parse::<u64>().ok(),
                Err(_) => Some(jitter_ms(index + 13, cycle, 2500)),
            };
            let (fa, fb) = match stagger {
                // The seed (A) stops first; B keeps running for `ms` (its
                // reconnect dials target a peer that is gone), then stops.
                Some(ms) => {
                    let fa = stop(a, &label_a).await;
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    let fb = stop(b, &label_b).await;
                    (fa, fb)
                }
                None => futures::join!(stop(a, &label_a), stop(b, &label_b)),
            };
            for handle in [ws_a, ws_b].into_iter().flatten() {
                handle.abort();
            }
            sse_a.abort();
            sse_b.abort();
            let mut guard = failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.extend(fa);
            guard.extend(fb);
        }
    }

    fn init_tracing() {
        if std::env::var("RUST_LOG").is_ok() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_writer(std::io::stderr)
                .with_thread_names(true)
                .try_init();
        }
    }

    /// Run [`PAIRS`] pairs at once, each on its own OS thread and runtime.
    pub(super) fn run() {
        init_tracing();
        let pairs = std::env::var("X0X_1262_PAIRS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(PAIRS);
        let root = tempfile::tempdir().expect("isolated daemon directories");
        let failures = Arc::new(Mutex::new(Vec::new()));
        let plane = format!("x0x.test.1262.{}", std::process::id());
        // The hub lives on its own runtime for the whole run and stops last.
        let (hub_addr_tx, hub_addr_rx) = std::sync::mpsc::channel();
        let (hub_stop_tx, hub_stop_rx) = tokio::sync::oneshot::channel::<()>();
        let hub_thread = {
            let dir = root.path().join("hub");
            let plane = plane.clone();
            let failures = Arc::clone(&failures);
            std::thread::Builder::new()
                .name("issue1262-hub".to_string())
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(4)
                        .thread_stack_size(16 * 1024 * 1024)
                        .enable_all()
                        .build()
                        .expect("hub runtime");
                    runtime.block_on(async move {
                        let hub = start(&dir, &plane, &[]).await;
                        let _ = hub_addr_tx.send(hub.udp);
                        let _ = hub_stop_rx.await;
                        let failure = stop(hub, "hub").await;
                        failures
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .extend(failure);
                    });
                })
                .expect("hub thread")
        };
        let hub = hub_addr_rx
            .recv_timeout(Duration::from_secs(120))
            .expect("hub daemon started");
        let threads: Vec<_> = (0..pairs)
            .map(|index| {
                let root = root.path().to_path_buf();
                let failures = Arc::clone(&failures);
                let plane = plane.clone();
                std::thread::Builder::new()
                    .name(format!("issue1262-pair{index}"))
                    .stack_size(16 * 1024 * 1024)
                    .spawn(move || {
                        let runtime = tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(4)
                            .thread_stack_size(16 * 1024 * 1024)
                            .enable_all()
                            .build()
                            .expect("per-pair runtime");
                        runtime.block_on(pair(&root, index, &plane, hub, failures));
                    })
                    .expect("pair thread")
            })
            .collect();
        for thread in threads {
            thread.join().expect("pair thread completed");
        }
        let _ = hub_stop_tx.send(());
        hub_thread.join().expect("hub thread completed");
        let failures = failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for (endpoint, (ok, other)) in TALLY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            eprintln!("ISSUE1262 TALLY {endpoint} ok={ok} other={other}");
        }
        eprintln!("ISSUE1262 SHUTDOWN_FAILURES={}", failures.len());
        for failure in &failures {
            eprintln!("ISSUE1262 FAILURE {failure}");
        }
        assert!(
            failures.is_empty(),
            "{} shutdown failure(s): {failures:#?}",
            failures.len()
        );
    }

    /// How long the Agent and AppState of a stopped daemon may outlive a
    /// successful `shutdown_and_wait` (#1269).
    const GROUP_JOIN_RELEASE_BOUND: Duration = Duration::from_secs(2);

    /// Wait up to [`GROUP_JOIN_RELEASE_BOUND`] for both weak handles to
    /// lose their last strong owner. Returns the final strong counts and
    /// how long the wait took.
    async fn released(
        state: &Weak<AppState>,
        agent: &Weak<crate::Agent>,
    ) -> (usize, usize, Duration) {
        let started = Instant::now();
        let deadline = started + GROUP_JOIN_RELEASE_BOUND;
        while (state.strong_count() > 0 || agent.strong_count() > 0) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (
            state.strong_count(),
            agent.strong_count(),
            started.elapsed(),
        )
    }

    /// #1269: A creates a named group, B joins it by invite, A opens a
    /// group store, then A shuts down. A's AppState and Agent (and with
    /// them the exclusive `history.db` connection) must go when
    /// `shutdown_and_wait` returns, and a relaunch on the same data dir
    /// must succeed at once. The join leaves delayed direct deliveries
    /// (A) and join-attempt polls (B) running; the TreeKEM group store's
    /// protector refers back to A's AppState from A's `kv_stores` (#1250).
    ///
    /// Each daemon runs on its own runtime, as an embedder's daemons do;
    /// the HTTP driver runs on a third.
    pub(super) fn group_join_relaunch() {
        init_tracing();
        let runtime = |name: &str| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name(name)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("daemon runtime")
        };
        let (a_runtime, b_runtime, driver) = (
            runtime("issue1269-a"),
            runtime("issue1269-b"),
            runtime("issue1269-driver"),
        );
        let root = tempfile::tempdir().expect("isolated daemon directories");
        let plane = format!("x0x.test.1269.{}", std::process::id());
        let dir_a = root.path().join("a");
        let dir_b = root.path().join("b");
        let http = client();
        let a = a_runtime.block_on(start(&dir_a, &plane, &[]));
        let b = b_runtime.block_on(start(&dir_b, &plane, &[a.udp]));
        assert!(
            a_runtime.block_on(wait_connected(&a, &b)),
            "A and B connect"
        );
        let group = driver.block_on(async {
            let group = call(
                &http,
                &a,
                reqwest::Method::POST,
                "/groups",
                Some(serde_json::json!({ "name": "g-1269" })),
            )
            .await
            .and_then(|v| v["group_id"].as_str().map(str::to_string))
            .expect("A creates a named group");
            // A group store, opened before the join so that A stops right
            // after it seats B (B's join attempt is then still live). Its
            // handle in A's `kv_stores` holds A's AppState.
            let store = call(
                &http,
                &a,
                reqwest::Method::POST,
                &format!("/groups/{group}/stores"),
                Some(serde_json::json!({ "name": "gs-1269" })),
            )
            .await
            .unwrap_or_default();
            assert_eq!(store["ok"], true, "A creates a group store: {store}");
            // The #1250 shape: the default group is TreeKEM, so the store's
            // TreeKEM protector is what refers back to A's AppState.
            assert_eq!(
                store["ownership"]["policy"], "treekem_encrypted",
                "store: {store}"
            );
            let invite = call(
                &http,
                &a,
                reqwest::Method::POST,
                &format!("/groups/{group}/invite"),
                Some(serde_json::json!({ "expiry_secs": 3600 })),
            )
            .await
            .and_then(|v| v["invite_link"].as_str().map(str::to_string))
            .expect("A mints an invite");
            let joined = call(
                &http,
                &b,
                reqwest::Method::POST,
                "/groups/join",
                Some(serde_json::json!({ "invite": invite })),
            )
            .await;
            eprintln!("ISSUE1269 join response: {joined:?}");
            assert!(joined.is_some(), "B's join request is accepted");
            // The join is complete when A's roster lists B.
            let seated_deadline = Instant::now() + Duration::from_secs(30);
            let mut seated = false;
            while !seated && Instant::now() < seated_deadline {
                seated = call(
                    &http,
                    &a,
                    reqwest::Method::GET,
                    &format!("/groups/{group}/members"),
                    None,
                )
                .await
                .is_some_and(|v| v["members"].to_string().contains(&b.agent_hex));
                if !seated {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            assert!(seated, "A seats B within 30 s");
            group
        });
        eprintln!("ISSUE1269 B seated in group {group}");

        let state_a = a.state.clone();
        let agent_a = a
            .state
            .upgrade()
            .map(|state| Arc::downgrade(&state.agent))
            .expect("live A agent");
        let started = Instant::now();
        let result = a_runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(60), a.handle.shutdown_and_wait()).await
        });
        let took = started.elapsed();
        assert!(
            matches!(result, Ok(Ok(()))),
            "A shutdown_and_wait after {took:?}: {result:?}"
        );
        let (appstate_strong, agent_strong, waited) =
            a_runtime.block_on(released(&state_a, &agent_a));
        eprintln!(
            "ISSUE1269 a shutdown took {took:?}; +{waited:?} appstate_strong={appstate_strong} \
             agent_strong={agent_strong} a_runtime_alive_tasks={}",
            a_runtime.metrics().num_alive_tasks()
        );

        // Relaunch A on the same data and identity dirs. One attempt only:
        // a stray owner of the old Agent still holds `history.db`.
        let relaunch = a_runtime.block_on(serve_with_options(
            config(&dir_a, &plane, &[b.udp]),
            ServeOptions {
                skip_update_check: true,
                cli_no_port_mapping: true,
                cli_disable_peer_cache: true,
                self_update_enabled: false,
                ..ServeOptions::default()
            },
        ));
        let relaunch_error = relaunch.as_ref().err().map(|error| format!("{error:#}"));
        eprintln!("ISSUE1269 a relaunch error={relaunch_error:?}");

        // Stop everything before asserting, so a failure leaks nothing.
        if let Ok(handle) = relaunch {
            let _ = a_runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(60), handle.shutdown_and_wait()).await
            });
        }
        let state_b = b.state.clone();
        let agent_b = b
            .state
            .upgrade()
            .map(|state| Arc::downgrade(&state.agent))
            .expect("live B agent");
        let result_b = b_runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(60), b.handle.shutdown_and_wait()).await
        });
        let (appstate_strong_b, agent_strong_b, waited_b) =
            b_runtime.block_on(released(&state_b, &agent_b));
        eprintln!(
            "ISSUE1269 b result={result_b:?} +{waited_b:?} appstate_strong={appstate_strong_b} \
             agent_strong={agent_strong_b}"
        );

        assert_eq!(
            (appstate_strong, agent_strong),
            (0, 0),
            "A's AppState/Agent outlive shutdown_and_wait by more than {GROUP_JOIN_RELEASE_BOUND:?}"
        );
        assert!(
            relaunch_error.is_none(),
            "same-dir relaunch of A refused: {relaunch_error:?}"
        );
        assert!(matches!(result_b, Ok(Ok(()))), "B shutdown: {result_b:?}");
        assert_eq!(
            (appstate_strong_b, agent_strong_b),
            (0, 0),
            "B's AppState/Agent outlive shutdown_and_wait by more than {GROUP_JOIN_RELEASE_BOUND:?}"
        );
    }

    /// #1263 part 1: B stops reading (a suspended phone or a stalled host)
    /// while it stays connected. A's gossip sends to B (SWIM probes, eager
    /// pushes) then block in ant-quic `open_uni` until B's connection idles
    /// out (30 s). Such a send must not hold up A's network teardown.
    pub(super) fn frozen_peer() {
        init_tracing();
        let root = tempfile::tempdir().expect("isolated daemon directories");
        let plane = format!("x0x.test.1263.{}", std::process::id());
        let runtime = |workers: usize| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .thread_stack_size(16 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("daemon runtime")
        };
        const B_WORKERS: usize = 2;
        let b_runtime = runtime(B_WORKERS);
        let a_runtime = runtime(4);
        let (http_a, http_b) = (client(), client());
        let topic = "x0x.test.1263.frozen";
        let b = b_runtime.block_on(start(&root.path().join("b"), &plane, &[]));
        let a = a_runtime.block_on(start(&root.path().join("a"), &plane, &[b.udp]));
        let subscribe = serde_json::json!({ "topic": topic });
        b_runtime.block_on(call(
            &http_b,
            &b,
            reqwest::Method::POST,
            "/subscribe",
            Some(subscribe.clone()),
        ));
        a_runtime.block_on(async {
            assert!(wait_connected(&a, &b).await, "A and B connect");
            call(
                &http_a,
                &a,
                reqwest::Method::POST,
                "/subscribe",
                Some(subscribe),
            )
            .await;
            tokio::time::sleep(Duration::from_secs(3)).await;
        });

        let network_a = a
            .state
            .upgrade()
            .and_then(|state| state.agent.network().cloned())
            .expect("A network");
        let peer_b = b
            .state
            .upgrade()
            .and_then(|state| state.agent.network().map(|network| network.peer_id()))
            .expect("B peer id");

        // Freeze B: occupy every B worker until one shared deadline, so a
        // sleeper that starts late does not extend the freeze.
        let thaw = Instant::now() + Duration::from_secs(70);
        for _ in 0..B_WORKERS * 2 {
            b_runtime.spawn(async move {
                std::thread::sleep(thaw.saturating_duration_since(Instant::now()));
            });
        }
        std::thread::sleep(Duration::from_millis(500));

        // Fill B's stream credit with sends A cannot complete, so later
        // sends block in ant-quic `open_uni` while A shuts down, well
        // inside B's idle timeout. A transport that holds its node lock
        // across such a send makes teardown wait for that timeout.
        let senders = {
            let network = Arc::clone(&network_a);
            a_runtime.spawn(async move {
                use saorsa_gossip_transport::GossipTransport as _;
                let mut sends = tokio::task::JoinSet::new();
                for _ in 0..320 {
                    let network = Arc::clone(&network);
                    sends.spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(90),
                            network.send_to_peer(
                                saorsa_gossip_types::PeerId::new(peer_b.0),
                                saorsa_gossip_transport::GossipStreamType::Bulk,
                                bytes::Bytes::from_static(&[0u8; 256]),
                            ),
                        )
                        .await;
                    });
                }
                while sends.join_next().await.is_some() {}
            })
        };
        a_runtime.block_on(async { tokio::time::sleep(Duration::from_secs(2)).await });
        let started = Instant::now();
        let failure = a_runtime.block_on(stop(a, "frozen/a"));
        senders.abort();
        drop(network_a);
        a_runtime.block_on(async { tokio::time::sleep(Duration::from_secs(3)).await });
        eprintln!(
            "ISSUE1263 frozen-peer A runtime alive_tasks_after_shutdown={}",
            a_runtime.metrics().num_alive_tasks()
        );
        let took = started.elapsed();
        eprintln!("ISSUE1263 frozen-peer A shutdown took {took:?} failure={failure:?}");

        // Thaw B, then stop it as well.
        std::thread::sleep(thaw.saturating_duration_since(Instant::now()));
        let failure_b = b_runtime.block_on(stop(b, "frozen/b"));
        eprintln!("ISSUE1263 frozen-peer B failure={failure_b:?}");
        if took >= Duration::from_secs(10) {
            eprintln!("ISSUE1262 FAILURE frozen/a: shutdown stalled {took:?}");
        }
        assert!(failure.is_none(), "A shutdown failed: {failure:?}");
        assert!(
            took < Duration::from_secs(10),
            "A shutdown stalled {took:?} behind sends to a frozen peer"
        );
        assert!(failure_b.is_none(), "B shutdown failed: {failure_b:?}");
    }
}

#[test]
#[ignore = "real sockets: requires the approved loopback-only sandbox"]
fn issue1262_owned_workload_parallel() {
    workload::run();
}

#[test]
#[ignore = "real sockets: requires the approved loopback-only sandbox"]
fn issue1263_shutdown_with_frozen_peer() {
    workload::frozen_peer();
}

#[test]
#[ignore = "real sockets: requires the approved loopback-only sandbox"]
fn issue1269_group_join_shutdown_releases_owner() {
    workload::group_join_relaunch();
}

/// #1262/#1263: a daemon whose peer is unreachable (an offline phone, or a
/// peer daemon that already stopped) has an outbound QUIC handshake in
/// flight when it shuts down. The silent peer is a bound loopback UDP
/// socket that never answers, so the dial can neither complete nor fail
/// before shutdown.
async fn shutdown_with_dial_in_flight(uptime: Duration) {
    if std::env::var("RUST_LOG").is_ok() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .try_init();
    }
    let root = tempfile::tempdir().expect("isolated daemon directories");
    let silent = UdpSocket::bind("127.0.0.1:0").expect("silent loopback peer");
    let silent_addr = silent.local_addr().expect("silent peer address");
    let config: DaemonConfig = serde_json::from_value(serde_json::json!({
        "bind_address": "127.0.0.1:0",
        "api_address": "127.0.0.1:0",
        "data_dir": root.path().join("data"),
        "identity_dir": root.path().join("identity"),
        "bootstrap_peers": [silent_addr],
        "mdns_enabled": false,
        "port_mapping_enabled": false,
        "network_id": format!("x0x.test.1262.dial.{}", std::process::id())
    }))
    .expect("loopback-only daemon configuration");
    let handle = serve_with_options(
        config,
        ServeOptions {
            skip_update_check: true,
            cli_no_port_mapping: true,
            cli_disable_peer_cache: true,
            self_update_enabled: false,
            ..ServeOptions::default()
        },
    )
    .await
    .expect("serve");
    let state = handle.test_state.upgrade().expect("live daemon state");
    let udp = state
        .agent
        .network()
        .expect("real QUIC network")
        .bound_addr()
        .await
        .expect("bound UDP address");
    drop(state);
    tokio::time::sleep(uptime).await;
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(120), handle.shutdown_and_wait())
        .await
        .expect("shutdown returns");
    eprintln!(
        "ISSUE1262 dial-in-flight shutdown took {:?} result={result:?}",
        started.elapsed()
    );
    if result.is_err() {
        eprintln!("ISSUE1262 FAILURE dial-in-flight: {result:?}");
    }
    assert!(result.is_ok(), "shutdown with a dial in flight: {result:?}");
    UdpSocket::bind(udp).expect("original UDP socket released");
    drop(silent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real sockets: requires the approved loopback-only sandbox"]
async fn issue1262_shutdown_with_dial_in_flight() {
    shutdown_with_dial_in_flight(Duration::from_secs(3)).await;
}
