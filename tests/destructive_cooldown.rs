//! Destructive-cooldown integration tests for the #368 desktop leak fix.
//!
//! PR A (`fix/368-destructive-cooldown`): the gossip transport owns a
//! per-send timeout below saorsa-gossip's adaptive floor, and consecutive
//! timeouts escalate to a connection close by peer-id. These daemon tests
//! prove the two operator-visible properties:
//!
//! 1. a black-holed peer (SIGSTOP — no ACKs, no reads) gets its connection
//!    closed by the escalation, the proof counter increments, the survivor
//!    stays healthy, and the peer is redialled once it resumes;
//! 2. SIGTERM terminates the daemon within the shutdown deadline even with
//!    gossip traffic in flight (#371: saorsa-gossip 0.5.71's IHAVE flusher is
//!    a detached loop with no shutdown handle).
//!
//! All tests are `#[ignore]` — they run real daemons (CI integration job).

use std::future::Future;
use std::process::Command;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::Value;

#[path = "harness/src/cluster.rs"]
mod cluster;

use cluster::{pair, AgentInstance};

const COOLDOWN_WINDOW: Duration = Duration::from_secs(60);

fn kill_signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .args([format!("-{signal}"), pid.to_string()])
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{signal} {pid} failed");
}

fn process_alive(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn publish_burst(alice: &AgentInstance, topic: &str, bytes: usize, rounds: usize) {
    // ~64 KiB base64 payloads: large enough that a stalled peer's QUIC
    // flow-control window saturates within a few rounds.
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(vec![0x5a_u8; bytes]);
    for _ in 0..rounds {
        let resp: Value = alice
            .post(
                "/publish",
                serde_json::json!({ "topic": topic, "payload": payload_b64 }),
            )
            .await
            .json()
            .await
            .unwrap_or_default();
        assert_eq!(resp["ok"], true, "publish: {resp:?}");
    }
}

/// (conns_closed_by_cooldown, streams_reset_on_timeout) — the #368 soak
/// proof counters from GET /diagnostics/gossip.
async fn cooldown_counters(alice: &AgentInstance) -> (u64, u64) {
    let body: Value = alice
        .get("/diagnostics/gossip")
        .await
        .json()
        .await
        .unwrap_or_default();
    let c = &body["send_cooldown"];
    (
        c["conns_closed_by_cooldown"].as_u64().unwrap_or(0),
        c["streams_reset_on_timeout"].as_u64().unwrap_or(0),
    )
}

async fn peer_count(alice: &AgentInstance) -> usize {
    let body: Value = alice.get("/peers").await.json().await.unwrap_or_default();
    body["peers"].as_array().map(Vec::len).unwrap_or(0)
}

/// Why (#368): a peer that stops draining (NAT-stalled in production,
/// SIGSTOP here) pins unbounded send buffers on every retry. The destructive
/// cooldown must close that peer's connection within the escalation window,
/// prove it via `conns_closed_by_cooldown`, keep the survivor healthy, and
/// redial once the peer resumes.
#[tokio::test]
#[ignore]
async fn blackholed_peer_connection_closed_by_cooldown_and_redials_after_resume() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let baseline_peers = peer_count(alice).await;
    assert!(
        baseline_peers >= 1,
        "alice must see bob before the black-hole"
    );

    // Black-hole bob: process frozen — the kernel stops reading the socket
    // and ACKing, so alice's QUIC stream writes stall on flow control.
    kill_signal(bob.pid(), "STOP");

    let deadline = Instant::now() + COOLDOWN_WINDOW;
    let mut closed = 0;
    while Instant::now() < deadline {
        // Keep publishing so consecutive timed-out sends accumulate.
        publish_burst(alice, "x0x.368.blackhole.probe", 64 * 1024, 4).await;
        let (conns_closed, timed_out) = cooldown_counters(alice).await;
        if conns_closed >= 1 {
            closed = conns_closed;
            assert!(
                timed_out >= 2,
                "escalation requires ≥2 timed-out sends: {timed_out}"
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        closed >= 1,
        "destructive cooldown never closed the black-holed peer within {COOLDOWN_WINDOW:?}"
    );

    // Survivor stays healthy.
    let health: Value = alice.get("/health").await.json().await.unwrap_or_default();
    assert_eq!(health["ok"], true, "alice health after cooldown close");

    // Resume bob: the normal redial path must reconnect the pair.
    kill_signal(bob.pid(), "CONT");
    let reconnected = wait_until(COOLDOWN_WINDOW, || async {
        peer_count(alice).await >= baseline_peers
    })
    .await;
    assert!(
        reconnected,
        "alice never redialled bob after resume (baseline {baseline_peers})"
    );

    // And a publish round-trips again.
    publish_burst(alice, "x0x.368.blackhole.resume", 1024, 1).await;
}

/// Why (#371/#368): SIGTERM must terminate the daemon within the shutdown
/// deadline even while gossip is flowing — saorsa-gossip 0.5.71's IHAVE
/// flusher is a detached loop that previously livelocked teardown (13+ min,
/// 100% CPU, RSS +700 MB).
#[tokio::test]
#[ignore]
async fn sigterm_exits_within_deadline_under_gossip_load() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    // Generate gossip traffic both directions so publish/IHAVE state exists
    // at shutdown time.
    publish_burst(alice, "x0x.368.shutdown.load", 16 * 1024, 8).await;
    publish_burst(bob, "x0x.368.shutdown.load", 16 * 1024, 8).await;

    let started = Instant::now();
    kill_signal(alice.pid(), "TERM");

    // x0xd's watchdog deadline is 5s; allow margin for graceful teardown
    // work ahead of it plus scheduling.
    let exit_deadline = Duration::from_secs(10);
    let exited = wait_until(exit_deadline, || async { !process_alive(alice.pid()) }).await;
    assert!(
        exited,
        "alice did not exit within {exit_deadline:?} of SIGTERM (at least {:?} elapsed)",
        started.elapsed()
    );
}

async fn wait_until<F, Fut>(timeout: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
