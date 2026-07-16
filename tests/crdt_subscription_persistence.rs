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

    // Bob replicates both: joins the store anchored on Alice's authoritative
    // owner (role "joined") and creates the task list on the same topic
    // (role "created" — the only REST path). Ownership is anchored ONLY at
    // construction from the out-of-band expected_owner, so Bob's replica
    // accepts Alice's deltas — a None anchor is permanently read-only and
    // rejects them (silent merge_delta rejection), never converging.
    let alice_id = pair.alice.agent_id().await;
    let r = pair
        .bob
        .post(
            &format!("/stores/{store_topic}/join"),
            serde_json::json!({ "expected_owner": alice_id }),
        )
        .await;
    assert!(r.status().is_success(), "bob joins store anchored on alice");
    let r = pair
        .bob
        .post(
            "/task-lists",
            serde_json::json!({ "name": "restart-list", "topic": list_topic }),
        )
        .await;
    assert!(r.status().is_success(), "bob creates task-list replica");

    // Both registrations must be in bob's persisted manifest, and the store
    // join must carry its expected_owner anchor so restart rehydration
    // re-anchors on the same owner — a missing anchor rehydrates read-only
    // and convergence is lost after restart.
    let manifest_path = pair.bob.data_dir().join("crdt-subscriptions.json");
    assert!(
        manifest_path.exists(),
        "manifest not written at {}",
        manifest_path.display()
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("manifest parses as json");
    let store_entry = manifest["entries"]
        .as_array()
        .expect("manifest has entries array")
        .iter()
        .find(|e| e["kind"] == "kv_store" && e["id"] == store_topic)
        .expect("store join persisted in manifest");
    assert_eq!(
        store_entry["expected_owner"].as_str(),
        Some(alice_id.as_str()),
        "manifest anchors store join on alice's owner id"
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

/// WHY (review test 22): at the route level the same store id may be joined and
/// re-joined (the joiner's "re-create") concurrently. The persistence lock in
/// `record()` serialises every durable write and `upsert` collapses same-id
/// entries to one, so the manifest never holds duplicates or half-written
/// state; a failed durable write rolls back the live handle so an un-persisted
/// registration is never acknowledged. Startup rehydration must therefore
/// reproduce a single, anchored, converging store — deterministically,
/// independent of the interleaving that produced it. (The rollback-on-failure
/// half of the invariant is pinned by the unit test
/// `failed_durable_write_rolls_back_and_retries`.)
#[tokio::test]
#[ignore]
async fn concurrent_same_id_join_recreate_rehydrates_deterministically() {
    let mut pair = cluster::pair().await;
    let suffix = rand::random::<u32>();
    let topic = format!("determinism-{suffix}");
    let owner = pair.alice.agent_id().await;

    // Alice is the authoritative owner: she creates the store and seeds a
    // value every joiner must converge on.
    let r = pair
        .alice
        .post(
            "/stores",
            serde_json::json!({ "name": "determinism", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates authoritative store");
    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/seed"),
            serde_json::json!({ "value": b64(b"anchor-value") }),
        )
        .await;
    assert!(r.status().is_success(), "alice seeds store");

    // Fire a storm of concurrent same-id joins at bob (the joiner's create +
    // re-create), all anchored on alice. The persistence lock serialises each
    // `record()`; upsert must collapse them to a single manifest entry no
    // matter how they interleave.
    let join_path = format!("/stores/{topic}/join");
    let join_body = serde_json::json!({ "expected_owner": owner });
    let (r0, r1, r2, r3) = tokio::join!(
        pair.bob.post(&join_path, join_body.clone()),
        pair.bob.post(&join_path, join_body.clone()),
        pair.bob.post(&join_path, join_body.clone()),
        pair.bob.post(&join_path, join_body.clone()),
    );
    // The per-(kind,id) reservation serialises the storm: exactly ONE join
    // wins and installs the handle; every other request sees the handle
    // present and gets 409 CONFLICT — same contract the sibling create test
    // pins. (This assert originally required all four to succeed, which the
    // 409 duplicate-join guard introduced in the same commit made
    // impossible — the #[ignore] suite hid the contradiction.)
    let statuses: Vec<_> = [r0, r1, r2, r3].into_iter().map(|r| r.status()).collect();
    let winners = statuses.iter().filter(|s| s.is_success()).count();
    let conflicts = statuses
        .iter()
        .filter(|s| **s == reqwest::StatusCode::CONFLICT)
        .count();
    assert_eq!(
        (winners, conflicts),
        (1, 3),
        "exactly one concurrent join wins and the rest 409: {statuses:?}"
    );

    // Determinism: exactly ONE kv_store entry for the topic survives in bob's
    // manifest, anchored on alice. A lost update would leave zero or many; a
    // missing dedup would leave duplicates.
    let manifest_path = pair.bob.data_dir().join("crdt-subscriptions.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("manifest parses as json");
    let same_id: Vec<&serde_json::Value> = manifest["entries"]
        .as_array()
        .expect("manifest has entries array")
        .iter()
        .filter(|e| e["kind"] == "kv_store" && e["id"] == topic)
        .collect();
    assert_eq!(same_id.len(), 1, "exactly one manifest entry for the topic");
    assert_eq!(
        same_id[0]["expected_owner"].as_str(),
        Some(owner.as_str()),
        "manifest entry anchored on alice"
    );

    // The anchored replica accepts alice's deltas and converges.
    poll_until(
        &pair.bob,
        &format!("/stores/{topic}/seed"),
        "concurrent-join seed convergence",
        120,
        |json| json["value"] == b64(b"anchor-value"),
    )
    .await;

    // Restart bob. Rehydration replays the single manifest entry and must
    // reproduce the same anchored, converging store — no re-join call.
    pair.bob.restart().await;
    poll_until(
        &pair.bob,
        &format!("/stores/{topic}/seed"),
        "post-restart rehydrate convergence (no re-join)",
        120,
        |json| json["value"] == b64(b"anchor-value"),
    )
    .await;
}

/// WHY (P1 same-ID REST vs REST): two REST creates for the same task-list
/// topic must not both win. The per-`(kind,id)` reservation serializes the
/// whole create → insert-handle → persist transaction, so the first create
/// returns 201 and installs exactly one handle (one sync listener), and every
/// concurrent same-id create sees the handle present and returns 409 CONFLICT
/// — never a duplicate listener, never one request's failure rolling back the
/// other's handle. Asserts the API map (GET /task-lists), the disk manifest,
/// and post-restart rehydrated state all agree on a single entry.
#[tokio::test]
#[ignore]
async fn concurrent_same_id_rest_creates_install_a_single_handle() {
    let mut pair = cluster::pair().await;
    let suffix = rand::random::<u32>();
    let topic = format!("same-id-rest-{suffix}");

    // Alice seeds the list on the shared topic so convergence is observable.
    let r = pair
        .alice
        .post(
            "/task-lists",
            serde_json::json!({ "name": "same-id", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates seed list");
    let r = pair
        .alice
        .post(
            &format!("/task-lists/{topic}/tasks"),
            serde_json::json!({ "title": "seed-task" }),
        )
        .await;
    assert!(r.status().is_success(), "alice seeds task");

    // Fire four concurrent same-id creates at bob. The reservation serializes
    // them: the first installs the handle, the rest observe it and conflict.
    let body = serde_json::json!({ "name": "same-id", "topic": topic });
    let (r0, r1, r2, r3) = tokio::join!(
        pair.bob.post("/task-lists", body.clone()),
        pair.bob.post("/task-lists", body.clone()),
        pair.bob.post("/task-lists", body.clone()),
        pair.bob.post("/task-lists", body.clone()),
    );
    let statuses: Vec<u16> = [r0, r1, r2, r3]
        .iter()
        .map(|r| r.status().as_u16())
        .collect();
    let created = statuses.iter().filter(|&&s| s == 201).count();
    let conflict = statuses.iter().filter(|&&s| s == 409).count();
    assert_eq!(
        created, 1,
        "exactly one same-id create returns 201; got statuses {statuses:?}"
    );
    assert_eq!(
        conflict, 3,
        "the other three same-id creates return 409 CONFLICT"
    );

    // API map agrees: GET /task-lists lists the topic exactly once
    // (one handle ⇒ one listener).
    poll_until(
        &pair.bob,
        "/task-lists",
        "bob lists the created task list exactly once",
        60,
        |json| {
            json["task_lists"]
                .as_array()
                .is_some_and(|a| a.iter().filter(|t| t["id"] == topic).count() == 1)
        },
    )
    .await;

    // Disk manifest agrees: exactly one task_list entry for the topic.
    let manifest_path = pair.bob.data_dir().join("crdt-subscriptions.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("manifest parses as json");
    let n = manifest["entries"]
        .as_array()
        .expect("manifest has entries array")
        .iter()
        .filter(|e| e["kind"] == "task_list" && e["id"] == topic)
        .count();
    assert_eq!(n, 1, "exactly one manifest task_list entry for the topic");

    // One listener ⇒ converges once.
    poll_until(
        &pair.bob,
        &format!("/task-lists/{topic}/tasks"),
        "same-id seed convergence",
        120,
        |json| tasks_contain(json, "seed-task"),
    )
    .await;

    // Post-restart state agrees: rehydration replays the single entry and
    // reproduces a single converging handle — no re-create call.
    pair.bob.restart().await;
    poll_until(
        &pair.bob,
        "/task-lists",
        "post-restart bob lists the task list exactly once",
        60,
        |json| {
            json["task_lists"]
                .as_array()
                .is_some_and(|a| a.iter().filter(|t| t["id"] == topic).count() == 1)
        },
    )
    .await;
    poll_until(
        &pair.bob,
        &format!("/task-lists/{topic}/tasks"),
        "post-restart rehydrate convergence (no re-create)",
        120,
        |json| tasks_contain(json, "seed-task"),
    )
    .await;
}

/// WHY (P1 REST vs rehydrate): rehydration and a REST create for the same
/// `(kind,id)` race on a check-then-create window. Without the shared
/// per-`(kind,id)` reservation both could spawn a long-lived sync listener for
/// the same topic (duplicate listeners) even though only one handle wins the
/// map. With the reservation, one path installs the handle and the other sees
/// it present (REST → 409, rehydrate → AlreadyPresent) — exactly one listener.
/// This fires a REST create at bob the instant he restarts (rehydrate runs in
/// a background task after `join_network`) and asserts the end state has a
/// single manifest entry, a single API-map handle, and clean convergence,
/// independent of which path won.
#[tokio::test]
#[ignore]
async fn rest_create_racing_rehydrate_yields_single_handle() {
    let mut pair = cluster::pair().await;
    let suffix = rand::random::<u32>();
    let topic = format!("rest-vs-rehydrate-{suffix}");

    // Alice seeds the list; bob creates a replica, which is persisted so the
    // restart rehydrates it.
    let r = pair
        .alice
        .post(
            "/task-lists",
            serde_json::json!({ "name": "rvrh", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates seed list");
    let r = pair
        .alice
        .post(
            &format!("/task-lists/{topic}/tasks"),
            serde_json::json!({ "title": "rvrh-task" }),
        )
        .await;
    assert!(r.status().is_success(), "alice seeds task");
    let r = pair
        .bob
        .post(
            "/task-lists",
            serde_json::json!({ "name": "rvrh", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "bob creates persisted replica");
    poll_until(
        &pair.bob,
        &format!("/task-lists/{topic}/tasks"),
        "pre-restart convergence",
        120,
        |json| tasks_contain(json, "rvrh-task"),
    )
    .await;

    // Restart bob. Rehydration runs after join_network in a background task;
    // fire a REST create for the SAME topic immediately, racing rehydrate.
    pair.bob.restart().await;
    let race = pair
        .bob
        .post(
            "/task-lists",
            serde_json::json!({ "name": "rvrh", "topic": topic }),
        )
        .await;
    // Whichever path won is fine: 201 (REST created before rehydrate ran) or
    // 409 (rehydrate already installed the handle). Any other status is a bug.
    let s = race.status().as_u16();
    assert!(
        s == 201 || s == 409,
        "REST create racing rehydrate must be 201 or 409, got {s}"
    );

    // End state: exactly one manifest entry for the topic (no duplicate), and
    // the API map lists it exactly once (one handle ⇒ one listener).
    let manifest_path = pair.bob.data_dir().join("crdt-subscriptions.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("manifest parses as json");
    let n = manifest["entries"]
        .as_array()
        .expect("manifest has entries array")
        .iter()
        .filter(|e| e["kind"] == "task_list" && e["id"] == topic)
        .count();
    assert_eq!(
        n, 1,
        "exactly one manifest entry — REST and rehydrate did not duplicate"
    );
    poll_until(
        &pair.bob,
        "/task-lists",
        "bob lists the task list exactly once after the race",
        60,
        |json| {
            json["task_lists"]
                .as_array()
                .is_some_and(|a| a.iter().filter(|t| t["id"] == topic).count() == 1)
        },
    )
    .await;
    // The single handle converges on alice's content.
    poll_until(
        &pair.bob,
        &format!("/task-lists/{topic}/tasks"),
        "post-race convergence (single listener)",
        120,
        |json| tasks_contain(json, "rvrh-task"),
    )
    .await;
}

// ─── Reconnect-policy: named-node new-port proactive reconnect ──────────────

/// Read a JSON field from `GET /diagnostics/connectivity` on `node`.
async fn connectivity_json(node: &cluster::AgentInstance) -> serde_json::Value {
    node.get("/diagnostics/connectivity")
        .await
        .json::<serde_json::Value>()
        .await
        .expect("connectivity json")
}

/// The node's own QUIC peer id (hex), from `/diagnostics/connectivity`.
async fn node_peer_id(node: &cluster::AgentInstance) -> String {
    connectivity_json(node).await["peer_id"]
        .as_str()
        .expect("peer_id field")
        .to_string()
}

/// The UDP port the node's QUIC transport is bound to, parsed from
/// `local_addr` (e.g. `[::]:53287` or `0.0.0.0:53287`).
async fn local_quic_port(node: &cluster::AgentInstance) -> u16 {
    let addr = connectivity_json(node).await;
    let addr = addr["local_addr"].as_str().expect("local_addr field");
    addr.rsplit_once(':')
        .map(|(_, port)| port)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("could not parse port from local_addr {addr}"))
}

/// Whether the node is advertising itself via mDNS.
async fn mdns_advertising(node: &cluster::AgentInstance) -> bool {
    connectivity_json(node).await["mdns"]["advertising"]
        .as_bool()
        .unwrap_or(false)
}

/// Whether `alice` currently lists `peer_id_hex` (no 0x prefix) among its
/// connected peers.
async fn has_peer(alice: &cluster::AgentInstance, peer_id_hex: &str) -> bool {
    let json = alice.get("/peers").await;
    let peers = json.json::<serde_json::Value>().await.expect("peers json")["peers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    peers
        .iter()
        .any(|p| p["id"].as_str().is_some_and(|id| id == peer_id_hex))
}

/// WHY (review P1 — proactive reconnect): a killed named peer restarted with
/// the SAME MachineId on a FORCED DIFFERENT QUIC port must be proactively
/// re-dialed by the survivor — no manual trigger, no rejoin, no
/// fixed-port/still-running-peer shortcut — with CRDT recovery and
/// transport-path attribution.
///
/// Bob is restarted with NO bootstrap (and `--no-hard-coded-bootstrap`), so he
/// cannot startup-dial alice. The only way the mesh reforms is alice's
/// proactive reconnect, which — post-fix — refreshes bob's mDNS-announced new
/// endpoint on every backoff attempt. Pre-fix the reconnect task snapshotted
/// candidate addresses once and kept dialing bob's dead old port forever.
#[tokio::test]
#[ignore]
async fn killed_named_peer_reconnects_on_new_port_via_proactive_path() {
    let mut pair = cluster::pair().await;
    let suffix = rand::random::<u32>();
    let list_topic = format!("named-restart-{suffix}");

    // Alice creates a task list and adds T1; bob creates a replica on the same
    // topic so his handle is persisted to the manifest (rehydrated on restart).
    assert!(
        pair.alice
            .post(
                "/task-lists",
                serde_json::json!({ "name": "named-restart", "topic": list_topic }),
            )
            .await
            .status()
            .is_success(),
        "alice creates task list"
    );
    assert!(
        pair.alice
            .post(
                &format!("/task-lists/{list_topic}/tasks"),
                serde_json::json!({ "title": "T1-pre-kill" }),
            )
            .await
            .status()
            .is_success(),
        "alice adds T1"
    );
    assert!(
        pair.bob
            .post(
                "/task-lists",
                serde_json::json!({ "name": "named-restart", "topic": list_topic }),
            )
            .await
            .status()
            .is_success(),
        "bob creates task-list replica"
    );
    // Bob converges T1 before the kill (proves replication + bob's handle works).
    poll_until(
        &pair.bob,
        &format!("/task-lists/{list_topic}/tasks"),
        "bob sees T1 before kill",
        120,
        |json| tasks_contain(json, "T1-pre-kill"),
    )
    .await;

    // Capture identity + transport endpoint before the kill.
    let bob_agent_before = pair.bob.agent_id().await;
    let bob_peer_before = node_peer_id(&pair.bob).await;
    let bob_port_before = local_quic_port(&pair.bob).await;

    // Kill bob hard (real transport drop). Alice will detect the dead QUIC
    // connection and schedule a proactive (Transport) reconnect.
    pair.bob.stop();

    // Offline mutation: alice writes T2 while bob is DOWN. It must arrive at
    // bob over the proactive reconnect path after he returns — no rejoin.
    assert!(
        pair.alice
            .post(
                &format!("/task-lists/{list_topic}/tasks"),
                serde_json::json!({ "title": "T2-offline" }),
            )
            .await
            .status()
            .is_success(),
        "alice adds T2 while bob offline"
    );

    // Restart bob on a FORCED NEW QUIC port, same data_dir (same MachineId),
    // NO bootstrap (cannot startup-dial alice).
    let bob_port_after = pair.bob.restart_on_new_quic_port_no_bootstrap().await;

    // (1) Forced different port — no fixed-port shortcut.
    assert_ne!(
        bob_port_after, bob_port_before,
        "bob must restart on a different QUIC port"
    );
    // (2) Same identity across restart (same data_dir ⇒ same machine.key ⇒
    // same MachineId; agent.key persists identically).
    let bob_agent_after = pair.bob.agent_id().await;
    assert_eq!(
        bob_agent_after, bob_agent_before,
        "same agent/machine identity across restart (same MachineId)"
    );
    // (3) Bob actually bound the new port and is advertising via mDNS so alice
    // can rediscover the new endpoint.
    assert_eq!(
        local_quic_port(&pair.bob).await,
        bob_port_after,
        "bob bound the new port"
    );
    assert!(
        mdns_advertising(&pair.bob).await,
        "bob must advertise via mDNS so alice can refresh the endpoint"
    );

    // (4) Transport-path attribution + endpoint refresh: with NO manual
    // trigger or rejoin, alice proactively redials bob. bob had no bootstrap,
    // so he CANNOT have initiated — the connection is alice's proactive
    // reconnect picking up bob's new mDNS-announced port. Poll alice's peer
    // list for bob's peer id (and bob's inbound count rising ≥1 confirms it).
    let reconnect_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let bob_inbound = connectivity_json(&pair.bob).await["connections"]["connected_peers"]
            .as_u64()
            .unwrap_or(0);
        if bob_inbound >= 1 {
            // Bob accepted an inbound connection — alice redialed him.
            break;
        }
        if tokio::time::Instant::now() > reconnect_deadline {
            panic!(
                "alice did not proactively reconnect to bob on the new port \
                 within 120s (bob had no bootstrap, so this is the proactive path)"
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // Confirm from alice's side: she lists bob's peer id. peer_id is stable
    // across restart (same machine.key), so the pre-kill id must reappear.
    let mut alice_sees_bob = false;
    let confirm_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if has_peer(&pair.alice, &bob_peer_before).await {
            alice_sees_bob = true;
            break;
        }
        if tokio::time::Instant::now() > confirm_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // peer_id stability is the expected behaviour; if ant-quic regenerated it,
    // fall back to alice listing any peer (the isolated pair only has bob).
    assert!(
        alice_sees_bob
            || connectivity_json(&pair.alice).await["connections"]["connected_peers"]
                .as_u64()
                .unwrap_or(0)
                >= 1,
        "alice must list bob after the proactive reconnect"
    );

    // (5) CRDT recovery: the offline mutation T2 arrives at bob over the
    // proactive reconnect path — no rejoin call — and T1 is intact.
    poll_until(
        &pair.bob,
        &format!("/task-lists/{list_topic}/tasks"),
        "bob recovers offline mutation T2 over the proactive reconnect path",
        120,
        |json| tasks_contain(json, "T2-offline"),
    )
    .await;
    poll_until(
        &pair.bob,
        &format!("/task-lists/{list_topic}/tasks"),
        "bob still has T1 (state intact)",
        60,
        |json| tasks_contain(json, "T1-pre-kill"),
    )
    .await;
}

/// WHY (issue #238 — rehydration wedge): rehydration must NOT wait for
/// `join_network`'s bootstrap dial schedule. With bob's only bootstrap peer
/// (alice) down, the old daemon sequenced `rehydrate()` AFTER the full ~70s
/// dial schedule (3 rounds × 15s connect timeout + inter-round sleeps), so
/// `GET /stores` stayed empty for 30s+ — including bob's OWN created store,
/// which needs no network at all (it restores from the local snapshot).
/// Rehydration now runs concurrently with join_network: both registrations
/// must be listed — and the own store's key readable — within seconds of the
/// API coming up, while alice is still down.
#[tokio::test]
#[ignore]
async fn own_and_joined_stores_surface_while_bootstrap_peer_is_down() {
    let mut pair = cluster::pair().await;
    let suffix = rand::random::<u32>();
    let own_topic = format!("wedge-own-{suffix}");
    let joined_topic = format!("wedge-joined-{suffix}");

    // Alice creates a store; bob joins it anchored on alice's owner id.
    let r = pair
        .alice
        .post(
            "/stores",
            serde_json::json!({ "name": "wedge-joined", "topic": joined_topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates store");
    let alice_id = pair.alice.agent_id().await;
    let r = pair
        .bob
        .post(
            &format!("/stores/{joined_topic}/join"),
            serde_json::json!({ "expected_owner": alice_id }),
        )
        .await;
    assert!(r.status().is_success(), "bob joins alice's store");

    // Bob creates his OWN store and writes a key (snapshot on bob's disk).
    let r = pair
        .bob
        .post(
            "/stores",
            serde_json::json!({ "name": "wedge-own", "topic": own_topic }),
        )
        .await;
    assert!(r.status().is_success(), "bob creates own store");
    let r = pair
        .bob
        .put(
            &format!("/stores/{own_topic}/mykey"),
            serde_json::json!({ "value": b64(b"mine") }),
        )
        .await;
    assert!(r.status().is_success(), "bob writes own key");

    // Kill BOTH; restart bob only. His sole bootstrap peer (alice) is down,
    // so join_network's dial schedule runs its full ~70s course — which must
    // no longer gate rehydration.
    pair.bob.stop();
    pair.alice.stop();
    pair.bob.start().await;

    // Both stores surface long before the dial schedule could complete.
    // 20s is generous for snapshot restore + subscribe, and far below the
    // ~70s wedge this test regresses against.
    poll_until(
        &pair.bob,
        "/stores",
        "both stores listed with alice down",
        20,
        |json| {
            json["stores"].as_array().is_some_and(|stores| {
                let has = |t: &str| stores.iter().any(|s| s["topic"] == t || s["id"] == t);
                has(&own_topic) && has(&joined_topic)
            })
        },
    )
    .await;

    // Own-store content is local: readable without any peer.
    poll_until(
        &pair.bob,
        &format!("/stores/{own_topic}/mykey"),
        "own key readable from local snapshot with alice down",
        10,
        |json| json["value"] == b64(b"mine"),
    )
    .await;
}

/// WHY (issue #238 — zombie subscription): a joined store that rehydrates
/// while its owner is offline must still converge when the owner returns
/// AFTER the front-loaded state-request schedule (~51s) has exhausted.
/// Before the fix, the requester fired its last request into the void and
/// nothing ever asked again — the owner answers only reactively — so bob's
/// replica stayed permanently empty (>300s observed) and even an explicit
/// re-join (409) could not revive it; only another full restart did.
#[tokio::test]
#[ignore]
async fn joined_store_syncs_after_owner_returns_late() {
    let mut pair = cluster::pair().await;
    let suffix = rand::random::<u32>();
    let store_topic = format!("zombie-{suffix}");

    // Alice creates the store (no keys yet); bob joins anchored on alice.
    let r = pair
        .alice
        .post(
            "/stores",
            serde_json::json!({ "name": "zombie-store", "topic": store_topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates store");
    let alice_id = pair.alice.agent_id().await;
    let r = pair
        .bob
        .post(
            &format!("/stores/{store_topic}/join"),
            serde_json::json!({ "expected_owner": alice_id }),
        )
        .await;
    assert!(r.status().is_success(), "bob joins alice's store");

    // Bob goes down; alice writes k1 while bob is offline; alice goes down.
    pair.bob.stop();
    let r = pair
        .alice
        .put(
            &format!("/stores/{store_topic}/k1"),
            serde_json::json!({ "value": b64(b"offline-write") }),
        )
        .await;
    assert!(r.status().is_success(), "alice writes k1 while bob is down");
    pair.alice.stop();

    // Bob restarts with the owner offline and rehydrates an EMPTY replica;
    // let the entire front-loaded request schedule (~51s) fire into the
    // void — the window in which the old requester died permanently.
    pair.bob.start().await;
    tokio::time::sleep(Duration::from_secs(60)).await;

    // The owner returns. Bob's persistent tail must ask again (next request
    // ≤ the backoff ceiling away) and recover k1 — no re-join, no restart.
    // Deadline covers the worst jittered envelope: a request missed during
    // reconnection pushes recovery to the following tail attempt, and tail
    // delays carry ±20% jitter (a 201s pass was observed against the old
    // 240s bound — round-4 review).
    pair.alice.start().await;
    poll_until(
        &pair.bob,
        &format!("/stores/{store_topic}/k1"),
        "bob recovers k1 after the owner returns late (no re-join/restart)",
        360,
        |json| json["value"] == b64(b"offline-write"),
    )
    .await;
}
