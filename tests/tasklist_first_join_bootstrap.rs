//! Cold-start bootstrap for collaborative task lists.
//!
//! A first-time joiner of a task-list topic previously received only deltas
//! published *after* it subscribed: tasks added before the join never
//! arrived, even though future adds replicated fine. The state-sync side
//! channel (mirrored from the kv-store cold-start, issue #96) closes that
//! gap — an empty-list joiner requests state, holders respond by
//! republishing their full state as a regular CRDT delta whose name/ordering
//! registers merge by vector-clock causality.
//!
//! All tests are `#[ignore]` — they boot real x0xd daemons.
//! Run with: cargo nextest run --test tasklist_first_join_bootstrap -- --ignored
//! Before running: cargo build --release --bin x0xd

use std::time::{Duration, Instant};

#[path = "harness/src/cluster.rs"]
mod cluster;

/// Collect the task titles currently visible on a daemon's task list.
async fn task_titles(node: &cluster::AgentInstance, topic: &str) -> Vec<String> {
    let r = node.get(&format!("/task-lists/{topic}/tasks")).await;
    let body: serde_json::Value = r.json().await.expect("tasks response is json");
    body["tasks"]
        .as_array()
        .map(|tasks| {
            tasks
                .iter()
                .filter_map(|t| t["title"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
#[ignore]
async fn first_time_late_joiner_bootstraps_historical_tasks() {
    // True cold first-join: alice creates the list and adds a task while
    // bob's daemon DOES NOT EXIST YET. This defeats both fallback paths
    // that can mask the gap on a warm pair — per-write direct delivery
    // (bob is unknown at add time) and short-window gossip cache replay.
    let (alice, alice_bind) = cluster::solo().await;
    let topic = format!("tasklist-bootstrap-{}", rand::random::<u32>());

    let r = alice
        .post(
            "/task-lists",
            serde_json::json!({ "name": "sprint", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates task list");
    let r = alice
        .post(
            &format!("/task-lists/{topic}/tasks"),
            serde_json::json!({ "title": "written-before-bob-existed" }),
        )
        .await;
    assert!(r.status().is_success(), "alice adds historical task");

    // Age the add past the gossip message-cache window (60s in
    // saorsa-gossip-pubsub), then force a cache prune with fresh adds so the
    // expired historical delta can't be redelivered by luck — the issue's
    // real-world shape (future adds arrive, the historical task never does).
    tokio::time::sleep(Duration::from_secs(70)).await;
    for n in 0..3 {
        let r = alice
            .post(
                &format!("/task-lists/{topic}/tasks"),
                serde_json::json!({ "title": format!("fresh-{n}") }),
            )
            .await;
        assert!(r.status().is_success(), "alice fresh add {n}");
    }

    // Only now does bob's daemon boot and connect.
    let bob = cluster::join_peer(&alice, alice_bind).await;

    // Bob subscribes to the topic for the first time, after the add. There is
    // no REST "join" for task lists; creating on the same topic subscribes an
    // empty list, which triggers the cold-start StateRequest.
    let r = bob
        .post(
            "/task-lists",
            serde_json::json!({ "name": "sprint", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "bob subscribes to the task list");

    // The historical task must arrive via the state-sync bootstrap. The
    // requester's front burst is 1/5/15/30s with ±20% jitter (issue #238:
    // worst-case cumulative ~61s), and if the mesh forms slowly the first
    // TAIL attempt lands at up to ~97s jittered — allow that envelope plus
    // propagation slack.
    let deadline = Instant::now() + Duration::from_secs(150);
    loop {
        let titles = task_titles(&bob, &topic).await;
        if titles.iter().any(|t| t == "written-before-bob-existed") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bob never bootstrapped the task added before his first join; \
             last titles: {titles:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore]
async fn live_replication_still_works_after_bootstrap_change() {
    // Guard: the state-sync side channel must not disturb the existing
    // join-before-add replication path.
    let pair = cluster::pair().await;
    let topic = format!("tasklist-live-{}", rand::random::<u32>());

    let r = pair
        .alice
        .post(
            "/task-lists",
            serde_json::json!({ "name": "live", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates task list");
    let r = pair
        .bob
        .post(
            "/task-lists",
            serde_json::json!({ "name": "live", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "bob subscribes before the add");

    let r = pair
        .alice
        .post(
            &format!("/task-lists/{topic}/tasks"),
            serde_json::json!({ "title": "live-task" }),
        )
        .await;
    assert!(r.status().is_success(), "alice adds after bob joined");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let titles = task_titles(&pair.bob, &topic).await;
        if titles.iter().any(|t| t == "live-task") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "live replication regressed: bob never saw a task added after he joined"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
