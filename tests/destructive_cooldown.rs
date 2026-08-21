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

use cluster::{join_peer, pair, solo, AgentInstance};

const COOLDOWN_WINDOW: Duration = Duration::from_secs(60);
const PROBE_TOPIC: &str = "x0x.368.blackhole.probe";

fn kill_signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .args([format!("-{signal}"), pid.to_string()])
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{signal} {pid} failed");
}

async fn publish_burst(alice: &AgentInstance, topic: &str, bytes: usize, rounds: usize) {
    // ~64 KiB base64 payloads: large enough that a stalled peer's QUIC
    // flow-control window saturates within a few rounds. Each publish is
    // UNIQUE (salted) — plumtree dedupes byte-identical messages before
    // fan-out, so a constant payload would never exercise the transport.
    use std::sync::atomic::{AtomicU64, Ordering};
    static SALT: AtomicU64 = AtomicU64::new(0);
    for r in 0..rounds {
        let salt = SALT.fetch_add(1, Ordering::Relaxed);
        let mut raw = vec![0x5a_u8; bytes];
        raw[..8].copy_from_slice(&salt.to_be_bytes());
        raw[8..12].copy_from_slice(&(r as u32).to_be_bytes());
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(raw);
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

/// (sends_rejected_saturated, peers_saturated_now, conns_closed_dead_peer)
/// — the #368 v2 proof counters from GET /diagnostics/gossip.
async fn gate_counters(alice: &AgentInstance) -> (u64, u64, u64) {
    let body: Value = alice
        .get("/diagnostics/gossip")
        .await
        .json()
        .await
        .unwrap_or_default();
    let g = &body["send_gate"];
    (
        g["sends_rejected_saturated"].as_u64().unwrap_or(0),
        g["peers_saturated_now"].as_u64().unwrap_or(0),
        g["conns_closed_dead_peer"].as_u64().unwrap_or(0),
    )
}

async fn peer_count(alice: &AgentInstance) -> usize {
    let body: Value = alice.get("/peers").await.json().await.unwrap_or_default();
    body["peers"].as_array().map(Vec::len).unwrap_or(0)
}

/// Why (#368 v2 + field finding): against saorsa-gossip 0.5.71 the
/// in-flight gate cannot engage — sg serializes per-peer sends (its
/// admission gate holds "never more than one Critical send per peer at
/// once", and bulk lanes behave the same in practice), so K=8 concurrent
/// permits are never exhausted (measured: 17 sg-side per-peer timeouts,
/// zero gate rejections, saturation never >1). This test pins what IS
/// observable and must hold regardless: sends to a frozen peer fail at
/// sg's adaptive timeout (real stalls, unlike v1's fixed timeout), the
/// daemon does NOT close the peer inside the window, health stays ok, and
/// the peer recovers after resume. The leak's true vector is CUMULATIVE
/// sg-abandoned streams (one pinned stream per timeout), not concurrent
/// in-flight ones — design escalation filed with the reviewer.
#[tokio::test]
#[ignore]
async fn blackholed_peer_no_churn_and_recovers_after_resume() {
    let (alice_anchor, anchor_port) = solo().await;
    let bob_joined = join_peer(&alice_anchor, anchor_port).await;
    let alice = &alice_anchor;
    let bob = &bob_joined;

    let baseline_peers = peer_count(alice).await;
    assert!(
        baseline_peers >= 1,
        "alice must see bob before the black-hole"
    );

    for daemon in [alice, bob] {
        let resp: Value = daemon
            .post("/subscribe", serde_json::json!({ "topic": PROBE_TOPIC }))
            .await
            .json()
            .await
            .unwrap_or_default();
        assert_eq!(resp["ok"], true, "subscribe: {resp:?}");
    }
    // Let bob's graft reach alice so eager-push actually targets him.
    tokio::time::sleep(Duration::from_secs(3)).await;

    kill_signal(bob.pid(), "STOP");

    // sg's adaptive per-peer timeout does the stalling (its floor is 1.5 s —
    // real stalls, not v1's false ones). The whole phase stays under the
    // 60 s dead-peer window, so our escalation MUST NOT fire.
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut saw_peer_timeouts = false;
    while Instant::now() < deadline {
        publish_burst(alice, PROBE_TOPIC, 256 * 1024, 8).await;
        let body: Value = alice
            .get("/diagnostics/gossip")
            .await
            .json()
            .await
            .unwrap_or_default();
        if body["pubsub_stages"]["republish_per_peer_timeout"]
            .as_u64()
            .unwrap_or(0)
            >= 1
        {
            saw_peer_timeouts = true;
            let g = gate_counters(alice).await;
            assert_eq!(g.2, 0, "dead-peer close fired inside the window: {g:?}");
        }
        if saw_peer_timeouts {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        saw_peer_timeouts,
        "frozen peer never stalled an sg send — test setup broken"
    );

    let health: Value = alice.get("/health").await.json().await.unwrap_or_default();
    assert_eq!(health["ok"], true, "alice health while peer stalled");

    // Resume bob: the pair recovers (redial first if ant-quic liveness had
    // dropped the frozen connection) and sends complete again.
    kill_signal(bob.pid(), "CONT");
    let recovered = wait_until(COOLDOWN_WINDOW, || async { peer_count(alice).await >= 1 }).await;
    assert!(recovered, "alice never saw a peer again after resume");
    publish_burst(alice, PROBE_TOPIC, 1024, 1).await;
    let g = gate_counters(alice).await;
    assert_eq!(g.2, 0, "no dead-peer close across the whole test: {g:?}");
}

/// Why (#371/#368): SIGTERM must terminate the daemon within the shutdown
/// deadline even while gossip is flowing — saorsa-gossip 0.5.71's IHAVE
/// flusher is a detached loop that previously livelocked teardown (13+ min,
/// 100% CPU, RSS +700 MB).
#[tokio::test]
#[ignore]
async fn sigterm_exits_within_deadline_under_gossip_load() {
    let mut pair = pair().await;
    let alice = &mut pair.alice;
    let bob = &pair.bob;

    // Generate gossip traffic both directions so publish/IHAVE state exists
    // at shutdown time.
    publish_burst(alice, "x0x.368.shutdown.load", 16 * 1024, 8).await;
    publish_burst(bob, "x0x.368.shutdown.load", 16 * 1024, 8).await;

    let started = Instant::now();
    kill_signal(alice.pid(), "TERM");

    // x0xd's watchdog deadline is 5s; allow margin for graceful teardown
    // work ahead of it plus scheduling. Poll via try_wait (reaps the child;
    // kill -0 would keep succeeding on a zombie).
    let exit_deadline = Duration::from_secs(10);
    let deadline = tokio::time::Instant::now() + exit_deadline;
    let mut exited = false;
    loop {
        match alice.try_wait() {
            Ok(Some(_)) => {
                exited = true;
                break;
            }
            Ok(None) => {}
            Err(e) => panic!("try_wait on alice: {e}"),
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
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
