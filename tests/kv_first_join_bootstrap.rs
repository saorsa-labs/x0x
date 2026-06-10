//! Regression test for issue #96 — KvStore first-time late join must
//! bootstrap pre-existing keys.
//!
//! A first-time joiner of a KvStore topic previously received only deltas
//! published *after* it subscribed: keys written before the join never
//! arrived (polled for 10 minutes in the issue repro), even though future
//! writes replicated fine. The fix adds a state-sync side channel — an
//! empty-store joiner requests state, holders respond by republishing
//! their full state as a regular CRDT delta.
//!
//! All tests are `#[ignore]` — they boot real x0xd daemons.
//! Run with: cargo nextest run --test kv_first_join_bootstrap -- --ignored
//! Before running: cargo build --release --bin x0xd

use base64::Engine;
use std::time::{Duration, Instant};

#[path = "harness/src/cluster.rs"]
mod cluster;

fn b64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

#[tokio::test]
#[ignore]
async fn first_time_late_joiner_bootstraps_historical_keys() {
    // True cold first-join (issue #96): alice creates the store and
    // writes a key while bob's daemon DOES NOT EXIST YET. This defeats
    // both fallback paths that can mask the gap on a warm pair — the
    // per-write direct-DM delta delivery (bob is nobody's contact at
    // write time) and short-window gossip cache replay.
    let (alice, alice_bind) = cluster::solo().await;
    let topic = format!("kv-bootstrap-{}", rand::random::<u32>());

    let r = alice
        .post(
            "/stores",
            serde_json::json!({ "name": "party", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates store");
    let r = alice
        .put(
            &format!("/stores/{topic}/party-historical"),
            serde_json::json!({ "value": b64(b"written-before-bob-existed") }),
        )
        .await;
    assert!(r.status().is_success(), "alice writes historical key");

    // Let the write age past the gossip message-cache window (60s in
    // saorsa-gossip-pubsub), then keep the topic busy with fresh writes.
    // Cache pruning is lazy (runs on insert), so on a quiet topic the
    // expired historical delta lingers and anti-entropy can still
    // redeliver it by luck; the fresh inserts force the prune, which is
    // the issue's real-world shape — scenario 3 of #96 observed exactly
    // this (future writes arrived, the historical key never did).
    tokio::time::sleep(Duration::from_secs(70)).await;
    for n in 0..3 {
        let r = alice
            .put(
                &format!("/stores/{topic}/fresh-{n}"),
                serde_json::json!({ "value": b64(b"fresh-write") }),
            )
            .await;
        assert!(r.status().is_success(), "alice fresh write {n}");
    }

    // Only now does bob's daemon boot and connect.
    let bob = cluster::join_peer(&alice, alice_bind).await;

    // Bob joins the store topic for the first time, after the write.
    let r = bob
        .post(&format!("/stores/{topic}/join"), serde_json::json!({}))
        .await;
    assert!(r.status().is_success(), "bob joins store");
    let pair = cluster::AgentPair { alice, bob };

    // The historical key must arrive via the state-sync bootstrap. The
    // requester retries at 1/5/15/30s; allow the full schedule plus
    // propagation slack.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let r = pair.bob.get(&format!("/stores/{topic}/keys")).await;
        let body: serde_json::Value = r.json().await.expect("keys response is json");
        let last_keys = body.to_string();
        let found = body["keys"]
            .as_array()
            .map(|keys| keys.iter().any(|k| k == "party-historical"))
            .unwrap_or(false)
            || last_keys.contains("party-historical");
        if found {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bob never bootstrapped the historical key written before his \
             first join (issue #96); last keys response: {last_keys}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // And the value itself must be readable.
    let r = pair
        .bob
        .get(&format!("/stores/{topic}/party-historical"))
        .await;
    assert!(
        r.status().is_success(),
        "bob reads the bootstrapped historical value"
    );
}

#[tokio::test]
#[ignore]
async fn live_replication_still_works_after_bootstrap_change() {
    // Guard: the state-sync side channel must not disturb the existing
    // join-before-write replication path (issue #96 scenario 1).
    let pair = cluster::pair().await;
    let topic = format!("kv-live-{}", rand::random::<u32>());

    let r = pair
        .alice
        .post(
            "/stores",
            serde_json::json!({ "name": "live", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates store");
    let r = pair
        .bob
        .post(&format!("/stores/{topic}/join"), serde_json::json!({}))
        .await;
    assert!(r.status().is_success(), "bob joins before the write");

    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/party-control"),
            serde_json::json!({ "value": b64(b"live-write") }),
        )
        .await;
    assert!(r.status().is_success(), "alice writes after bob joined");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let r = pair
            .bob
            .get(&format!("/stores/{topic}/party-control"))
            .await;
        if r.status().is_success() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "live replication regressed: bob never saw a write made after he joined"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
