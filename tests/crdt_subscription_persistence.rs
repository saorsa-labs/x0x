//! Regression tests for daemon-restart amnesia: task-list and kv-store
//! registrations must survive an x0xd restart WITHOUT the application
//! re-creating or re-joining them.
//!
//! Before the fix, `AppState.task_lists` / `AppState.kv_stores` were only
//! populated by the REST create/join handlers, so a restarted daemon answered
//! "task list not found" / "store not found" until an explicit re-create.
//! The fix persists a subscription manifest (`crdt-subscriptions.json` in the
//! instance data dir) and rehydrates it after `join_network` by driving the
//! same Agent create/join paths — the empty-replica state-request bootstrap
//! then recovers content (including offline mutations) from peer replicas.
//!
//! All tests are `#[ignore]` — they boot real x0xd daemons.
//! Run with: cargo nextest run --test crdt_subscription_persistence --run-ignored all
//! Before running: cargo build --bin x0xd (or set X0XD_TEST_BINARY)

use base64::Engine;
use std::time::Duration;

#[path = "harness/src/cluster.rs"]
mod cluster;

fn b64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// Poll `path` on `node` until `pred(json)` is true or the deadline passes.
async fn poll_until(
    node: &cluster::AgentInstance,
    path: &str,
    what: &str,
    deadline_secs: u64,
    pred: impl Fn(&serde_json::Value) -> bool,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(deadline_secs);
    let mut last = serde_json::Value::Null;
    loop {
        let resp = node.get(path).await;
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if pred(&json) {
                return;
            }
            last = json;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "{}: {what} not observed within {deadline_secs}s; last response: {last}",
                node.name
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn tasks_contain(json: &serde_json::Value, title: &str) -> bool {
    json["tasks"]
        .as_array()
        .is_some_and(|ts| ts.iter().any(|t| t["title"] == title))
}

/// WHY: this is the defect itself — after a restart, both a joined kv store
/// and a created task list must be answerable via REST (registration AND
/// content) without any re-create/re-join call. Bob is restarted because his
/// config bootstraps to alice, so reconnection is deterministic; alice keeps
/// the authoritative replicas that bob's rehydrated (empty) CRDTs pull state
/// from via the state-request side channel.
#[tokio::test]
#[ignore]
async fn task_list_and_kv_store_survive_daemon_restart() {
    let mut pair = cluster::pair().await;
    let suffix = rand::random::<u32>();
    let list_topic = format!("restart-list-{suffix}");
    let store_topic = format!("restart-store-{suffix}");

    // Alice creates + populates both CRDTs.
    let r = pair
        .alice
        .post(
            "/task-lists",
            serde_json::json!({ "name": "restart-list", "topic": list_topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates task list");
    let r = pair
        .alice
        .post(
            &format!("/task-lists/{list_topic}/tasks"),
            serde_json::json!({ "title": "pre-restart-task" }),
        )
        .await;
    assert!(r.status().is_success(), "alice adds task");
    let r = pair
        .alice
        .post(
            "/stores",
            serde_json::json!({ "name": "restart-store", "topic": store_topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates store");
    let r = pair
        .alice
        .put(
            &format!("/stores/{store_topic}/pre-key"),
            serde_json::json!({ "value": b64(b"pre-restart-value") }),
        )
        .await;
    assert!(r.status().is_success(), "alice puts key");

    // Bob replicates both: joins the store (role "joined") and creates the
    // task list on the same topic (role "created" — the only REST path).
    let r = pair
        .bob
        .post(
            &format!("/stores/{store_topic}/join"),
            serde_json::json!({}),
        )
        .await;
    assert!(r.status().is_success(), "bob joins store");
    let r = pair
        .bob
        .post(
            "/task-lists",
            serde_json::json!({ "name": "restart-list", "topic": list_topic }),
        )
        .await;
    assert!(r.status().is_success(), "bob creates task-list replica");

    // Both registrations must be in bob's persisted manifest.
    let manifest_path = pair.bob.data_dir().join("crdt-subscriptions.json");
    assert!(
        manifest_path.exists(),
        "manifest not written at {}",
        manifest_path.display()
    );

    // Bob converges before the restart (proves replication works at all).
    poll_until(
        &pair.bob,
        &format!("/task-lists/{list_topic}/tasks"),
        "pre-restart task replication",
        120,
        |json| tasks_contain(json, "pre-restart-task"),
    )
    .await;
    poll_until(
        &pair.bob,
        &format!("/stores/{store_topic}/pre-key"),
        "pre-restart key replication",
        120,
        |json| json["value"] == b64(b"pre-restart-value"),
    )
    .await;

    // Restart bob. NO re-create/re-join calls after this point.
    pair.bob.restart().await;

    // Registration and content must come back on their own: the manifest
    // rehydration re-subscribes, and the empty-replica state request pulls
    // the full state from alice.
    poll_until(
        &pair.bob,
        &format!("/task-lists/{list_topic}/tasks"),
        "post-restart task list recovery (no re-create)",
        120,
        |json| tasks_contain(json, "pre-restart-task"),
    )
    .await;
    poll_until(
        &pair.bob,
        &format!("/stores/{store_topic}/pre-key"),
        "post-restart store key recovery (no re-join)",
        120,
        |json| json["value"] == b64(b"pre-restart-value"),
    )
    .await;
}

/// WHY: the point of persisting subscriptions is that mutations made while an
/// instance is DOWN still arrive after it comes back — without the manifest,
/// a restarted daemon has no handle, so the offline delta has nowhere to
/// land and the app sees "task list not found" forever.
#[tokio::test]
#[ignore]
async fn offline_mutation_arrives_after_restart_without_rejoin() {
    let mut pair = cluster::pair().await;
    let suffix = rand::random::<u32>();
    let list_topic = format!("offline-list-{suffix}");

    let r = pair
        .alice
        .post(
            "/task-lists",
            serde_json::json!({ "name": "offline-list", "topic": list_topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates task list");
    let r = pair
        .alice
        .post(
            &format!("/task-lists/{list_topic}/tasks"),
            serde_json::json!({ "title": "task-before-outage" }),
        )
        .await;
    assert!(r.status().is_success(), "alice adds first task");

    // Bob replicates the list and converges.
    let r = pair
        .bob
        .post(
            "/task-lists",
            serde_json::json!({ "name": "offline-list", "topic": list_topic }),
        )
        .await;
    assert!(r.status().is_success(), "bob creates task-list replica");
    poll_until(
        &pair.bob,
        &format!("/task-lists/{list_topic}/tasks"),
        "pre-outage task replication",
        120,
        |json| tasks_contain(json, "task-before-outage"),
    )
    .await;

    // Bob goes down; alice mutates while he is offline.
    pair.bob.stop();
    let r = pair
        .alice
        .post(
            &format!("/task-lists/{list_topic}/tasks"),
            serde_json::json!({ "title": "offline-task" }),
        )
        .await;
    assert!(r.status().is_success(), "alice adds task while bob is down");

    // Bob comes back. NO re-create call — the offline mutation must arrive
    // via manifest rehydration + state-request recovery alone.
    pair.bob.start().await;
    poll_until(
        &pair.bob,
        &format!("/task-lists/{list_topic}/tasks"),
        "offline mutation after restart (no rejoin)",
        120,
        |json| tasks_contain(json, "offline-task") && tasks_contain(json, "task-before-outage"),
    )
    .await;
}
