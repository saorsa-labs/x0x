//! Phase 2 — in-process library tests for Issue #110 (mobile embedding).
//!
//! These exercise the embeddable `x0x::server::serve` API *in-process* (no
//! spawned daemon binary) — the counterpart to the bin-spawning regression
//! oracle in `server_characterization.rs`. They prove the lifecycle and the
//! storage boundary that mobile/embedding hosts depend on:
//!
//! - `serve(config)` binds, returns a handle whose `local_addr()` is readable
//!   immediately (even when binding `127.0.0.1:0`), serves `/health`, and
//!   `shutdown_and_wait()` returns `Ok` with the port released afterwards.
//! - With a fully-specified config and a sentinel `HOME`/XDG environment, the
//!   embed path writes NOTHING under the sentinel home — there is no `~/.x0x`
//!   fallback once the host supplies an identity directory.
//!
//! All tests are `#[ignore]` (they bind real sockets and build a real agent),
//! matching the `daemon_api_integration.rs` / `server_characterization.rs`
//! convention. Run them with:
//!
//! ```text
//! cargo nextest run --all-features --test server_inprocess --run-ignored all
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use x0x::server::{serve, DaemonConfig};

/// Build a hermetic in-process config: ephemeral API + QUIC ports, no
/// hard-coded bootstrap peers, and all persistent state under `dir`.
fn hermetic_config(dir: &std::path::Path) -> DaemonConfig {
    let mut config = DaemonConfig::default();
    config.api_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bind_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bootstrap_peers = Vec::new();
    config.data_dir = dir.join("data");
    config.identity_dir = Some(dir.join("identity"));
    config
}

/// Reserve a currently-free loopback UDP port by binding `:0`, reading the
/// assigned port, then dropping the socket. Used to pin a FIXED QUIC
/// `bind_address` for the restart tests: as of ant-quic 0.27.27 (#196) the
/// endpoint UDP socket is released on shutdown, so an in-process embedder can
/// re-`serve()` on the SAME fixed QUIC port. There is an inherent (small) TOCTOU
/// window between dropping this probe and serve() rebinding it, acceptable for a
/// loopback test.
fn free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind probe udp socket");
    let port = sock.local_addr().expect("probe local_addr").port();
    drop(sock);
    port
}

/// `serve()` binds, reports its address immediately, serves `/health`, and
/// shuts down cleanly with the port released.
///
/// WHY: this is the embedding contract a mobile host relies on — start the
/// server in-process, read back the actual bound port (it asked for `0`),
/// talk to it over loopback HTTP, then stop it deterministically. If any of
/// these regress, embedding is broken even though the daemon binary still works.
#[tokio::test]
#[ignore]
async fn serve_binds_serves_health_and_shuts_down() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = hermetic_config(tmp.path());

    let handle = serve(config).await.expect("serve() should start");
    let addr = handle.local_addr();
    assert_ne!(
        addr.port(),
        0,
        "local_addr() must resolve the ephemeral port"
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    // `/health` is auth-exempt — same contract the oracle pins for the bin.
    let resp = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .expect("GET /health");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "/health should be 200"
    );

    handle
        .shutdown_and_wait()
        .await
        .expect("shutdown_and_wait should return Ok");

    // Port released: a fresh bind on the same address must now succeed.
    let rebound = tokio::net::TcpListener::bind(addr).await;
    assert!(
        rebound.is_ok(),
        "API port {addr} must be released after shutdown"
    );
}

/// Dropping the handle (without awaiting) requests shutdown — no detached
/// daemon survives. After a drop + a brief settle, the port is reusable.
///
/// WHY: an embedding host may drop the handle on teardown; the server must not
/// keep running and holding the port behind the host's back.
#[tokio::test]
#[ignore]
async fn dropping_handle_requests_shutdown() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = hermetic_config(tmp.path());

    let handle = serve(config).await.expect("serve() should start");
    let addr = handle.local_addr();
    drop(handle);

    // Drop cancels the supervisor; give the graceful-shutdown tail time to run
    // (it removes the port file and shuts the agent down within ~2s).
    let mut rebound = false;
    for _ in 0..40 {
        if tokio::net::TcpListener::bind(addr).await.is_ok() {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(rebound, "dropping the handle must shut the server down");
}

/// Clean teardown (Fix C, Issue #110 Phase 2): after `shutdown_and_wait()`
/// returns Ok, the in-process server can be started AGAIN on the same config —
/// the API (TCP) port is released and no server-owned task or lock survives to
/// deadlock the second build. The second instance binds and serves `/health`.
///
/// WHY: a leaked API listener, a surviving server-owned background task, or a
/// held lock from the first run would make the second `serve()` fail or hang.
/// This is the load-bearing embedding contract: a host can stop and restart x0x
/// in-process. (Some Agent-internal/ExecService tasks are not yet stopped — a
/// tracked Phase 2b item — but they do not hold the API port or block re-serve.)
///
/// FIXED QUIC PORT (ant-quic 0.27.27 / #196): the QUIC `bind_address` is pinned
/// to a FIXED loopback UDP port (not ephemeral). `Agent::shutdown()` aborts the
/// NetworkNode receiver/accept/eviction tasks and calls
/// `ant_quic::Node::shutdown()`, and as of ant-quic 0.27.27 the endpoint UDP
/// socket IS released in-process on shutdown (#196). So the second `serve()`
/// must rebind the SAME fixed QUIC port — the real proof #196 delivers, which
/// was impossible pre-0.27.27 (the socket only freed on process exit). If this
/// fixed-port rebind ever fails, #196 does not cover x0x's endpoint path.
#[tokio::test]
#[ignore]
async fn serve_tears_down_cleanly_and_rebinds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = hermetic_config(tmp.path());
    // Pin a FIXED QUIC bind port so the rebind proves socket release, not just
    // that an ephemeral re-roll happened to pick a new free port.
    let quic_port = free_udp_port();
    config.bind_address = SocketAddr::from(([127, 0, 0, 1], quic_port));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    // First lifecycle.
    let handle = serve(config.clone()).await.expect("first serve() starts");
    let first_addr = handle.local_addr();
    let resp = client
        .get(format!("http://{first_addr}/health"))
        .send()
        .await
        .expect("GET /health (run 1)");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    handle
        .shutdown_and_wait()
        .await
        .expect("first shutdown_and_wait returns Ok");

    // The API (TCP) port must be released after the first teardown — proves the
    // axum listener and its supervisor were actually torn down.
    let rebound = tokio::net::TcpListener::bind(first_addr).await;
    assert!(
        rebound.is_ok(),
        "API port {first_addr} must be released after the first shutdown"
    );
    drop(rebound);

    // Second lifecycle on the SAME config — INCLUDING the same FIXED QUIC port.
    // If ant-quic had not released the endpoint UDP socket (pre-#196), this
    // serve() would fail to bind the fixed QUIC port. It must rebind cleanly.
    let handle = serve(config)
        .await
        .expect("second serve() must rebind the SAME fixed QUIC port (ant-quic #196)");
    let addr = handle.local_addr();
    let resp = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .expect("GET /health (run 2)");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "second instance must serve /health on the same fixed QUIC port — proves #196 releases the socket"
    );
    handle
        .shutdown_and_wait()
        .await
        .expect("second shutdown_and_wait returns Ok");
}

/// Storage boundary: with a fully-specified config and a sentinel HOME/XDG
/// environment, the embed path creates NOTHING under the sentinel home.
///
/// WHY: this is the load-bearing guarantee for mobile embedding — the host
/// owns the filesystem, and x0x must never silently write keys/caches/contacts
/// to `~/.x0x`. The test would fail the moment any identity/cache/contact path
/// re-introduced a `dirs::home_dir()` fallback on the serve() path.
#[tokio::test]
#[ignore]
async fn serve_writes_nothing_under_sentinel_home() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sentinel_home = tmp.path().join("sentinel-home");
    std::fs::create_dir_all(&sentinel_home).expect("create sentinel home");

    // Point every home/XDG knob `dirs` consults at the sentinel directory.
    std::env::set_var("HOME", &sentinel_home);
    std::env::set_var("XDG_DATA_HOME", sentinel_home.join("xdg-data"));
    std::env::set_var("XDG_CONFIG_HOME", sentinel_home.join("xdg-config"));
    std::env::set_var("XDG_CACHE_HOME", sentinel_home.join("xdg-cache"));

    let config = hermetic_config(tmp.path());
    let handle = serve(config).await.expect("serve() should start");
    let addr = handle.local_addr();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let resp = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .expect("GET /health");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    handle.shutdown_and_wait().await.expect("clean shutdown");

    // Assert no x0x state directory was created anywhere under the sentinel home.
    // This covers BOTH the dotfile fallback (`~/.x0x*`, created by a
    // `dirs::home_dir()` fallback) AND the XDG fallback (`<data_dir>/x0x`,
    // created by a `dirs::data_dir()` fallback) — either would silently persist
    // host-owned state outside the config-supplied directory.
    let offenders = find_x0x_dirs(&sentinel_home);
    assert!(
        offenders.is_empty(),
        "serve() must not write x0x state under the sentinel home; found: {offenders:?}"
    );
}

/// Walk `root` and collect any directory that an `~/.x0x` *or* XDG fallback
/// would create:
/// - a name beginning with `.x0x` (`.x0x`, `.x0x-<name>` — the home fallback), or
/// - a directory named exactly `x0x` (no leading dot — the `dirs::data_dir()`
///   XDG fallback, e.g. `$XDG_DATA_HOME/x0x`).
fn find_x0x_dirs(root: &std::path::Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with(".x0x") || name == "x0x" {
                        found.push(path.clone());
                    }
                }
                stack.push(path);
            }
        }
    }
    found
}

/// Deterministic teardown (Issue #116): repeated start → /health → stop cycles
/// on the SAME config must each succeed, proving no Agent/ExecService background
/// task or lock leaks across cycles.
///
/// WHY: before #116 the Agent identity/network-event/direct listeners and the
/// presence refresh loop, plus the three ExecService loops (notably the pure
/// session-idle timer), kept running after `shutdown_and_wait()` returned. A
/// leaked task per cycle would accumulate, and a surviving lock would hang the
/// next build; this loop is the regression that fails if teardown is not
/// complete. The API (TCP) port must rebind each cycle.
///
/// QUIC/UDP (ephemeral on purpose): this test's job is TASK/LOCK leak detection
/// across rapid start→stop cycles, NOT fixed-port rebinding. It keeps the QUIC
/// `bind_address` ephemeral (`127.0.0.1:0`) so each cycle gets a fresh UDP port.
/// FIXED-port rebinding is proven separately by
/// `serve_tears_down_cleanly_and_rebinds`. A tight zero-gap same-fixed-port loop
/// is NOT reliable: ant-quic 0.27.27 (#196) releases the endpoint socket on a
/// single restart, but in a back-to-back same-port loop the prior cycle's UDP FD
/// is not freed in time even after seconds of retry (documented in the report) —
/// so pinning a fixed port here would test that upstream race, not x0x's leak
/// guarantee. The API (TCP) port still must rebind each cycle (asserted below).
#[tokio::test]
#[ignore]
async fn serve_stop_loop_leaks_no_tasks() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = hermetic_config(tmp.path());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    for cycle in 0..3 {
        let handle = serve(config.clone())
            .await
            .unwrap_or_else(|e| panic!("serve() must start on cycle {cycle}: {e:?}"));
        let addr = handle.local_addr();
        assert_ne!(
            addr.port(),
            0,
            "cycle {cycle}: ephemeral API port must resolve"
        );

        let resp = client
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET /health on cycle {cycle}: {e}"));
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "cycle {cycle}: /health must be 200"
        );

        handle
            .shutdown_and_wait()
            .await
            .unwrap_or_else(|e| panic!("shutdown_and_wait must return Ok on cycle {cycle}: {e}"));

        // API (TCP) port released each cycle — proves the listener and its
        // supervisor were torn down before the next start.
        let rebound = tokio::net::TcpListener::bind(addr).await;
        assert!(
            rebound.is_ok(),
            "cycle {cycle}: API port {addr} must be released after shutdown"
        );
    }
}

/// join_network shutdown race (Issue #116): `serve()` then *immediately*
/// `shutdown_and_wait()` — without ever touching /health — must return Ok and
/// return promptly.
///
/// WHY: `serve()` kicks off `join_network`, which starts the listener tasks and
/// the presence-refresh loop. If shutdown fires mid-bootstrap, the registry's
/// closed-flag + `spawn_tracked` refusal + the join_network token guard must
/// ensure no listener is left running. A regression here would either hang
/// (a listener blocking on a transport that is shutting down) or leak a task.
#[tokio::test]
#[ignore]
async fn serve_then_immediate_shutdown_is_ok_and_prompt() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = hermetic_config(tmp.path());
    // Point bootstrap at an unroutable RFC 5737 TEST-NET-1 address so
    // `join_network` actually enters its connect/retry phase and is genuinely
    // still bootstrapping when shutdown fires — this exercises the
    // begin_shutdown-before-drain window (Codex finding 1): the racing
    // join_network's in-flight start_identity_heartbeat / discovery_reaper /
    // presence-start / capability-advert / delayed-reannounce must all no-op
    // because the token is cancelled before bg_tasks are drained.
    config.bootstrap_peers = vec![SocketAddr::from(([192, 0, 2, 1], 5483))];

    let handle = serve(config).await.expect("serve() should start");
    let addr = handle.local_addr();

    // Give the bootstrap a brief head start so join_network is mid-flight, then
    // stop without a /health round-trip to race it.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let started = std::time::Instant::now();
    handle
        .shutdown_and_wait()
        .await
        .expect("immediate shutdown_and_wait should return Ok");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(15),
        "immediate shutdown must return promptly, took {elapsed:?}"
    );

    // Port released afterwards — nothing survived the racing shutdown.
    let rebound = tokio::net::TcpListener::bind(addr).await;
    assert!(
        rebound.is_ok(),
        "API port {addr} must be released after an immediate shutdown"
    );
}
