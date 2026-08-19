//! REST surface of `AccessPolicy::SelfKeyed` (issue #340).
//!
//! WHY: an open directory — one topic, many mutually-unknown agents, each
//! writing only the keys prefixed by its own AgentId — must be expressible
//! without a blessed owner. Knowing only the topic is enough to create,
//! join, write, and rehydrate (I4); supplying an `expected_owner` to such a
//! store is a contradiction (the store has no owner for life, I3) and must
//! be a 422, while owner-anchored policies keep requiring the anchor.
//!
//! NOTE on keys: the REST routes address a key as a single path segment
//! (`/stores/:id/:key`), so these tests use the grammar's BARE 64-hex root
//! record (`hex(AgentId)`); suffixed keys (`hex(AgentId)/suffix`) are
//! addressable through the library handle (see the store/lib unit tests).
//!
//! All tests are `#[ignore]` — they boot real x0xd daemons.
//! Run with: cargo nextest run --test kv_self_keyed_rest -- --ignored
//! Before running: cargo build --bin x0xd

use base64::Engine;
use std::time::{Duration, Instant};

#[path = "harness/src/cluster.rs"]
mod cluster;

fn b64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// A syntactically valid 64-hex AgentId prefix (not any real peer).
fn foreign_prefix() -> String {
    "0f".repeat(32)
}

/// Fetch the policy string GET /stores reports for `topic`.
async fn store_policy(node: &cluster::AgentInstance, topic: &str) -> Option<String> {
    let r = node.get("/stores").await;
    if !r.status().is_success() {
        return None;
    }
    let body: serde_json::Value = r.json().await.ok()?;
    body["stores"]
        .as_array()?
        .iter()
        .find(|s| s["topic"] == topic)
        .and_then(|s| s["policy"].as_str().map(str::to_string))
}

#[tokio::test]
#[ignore]
async fn selfkeyed_join_without_expected_owner() {
    let pair = cluster::pair().await;
    let topic = format!("kv-sk-{}", rand::random::<u32>());

    // Create with the self_keyed policy; the response must reflect it, the
    // owner must be null (the store is owner-free for life), and the id must
    // stay the topic string (not the blake3 hex).
    let r = pair
        .alice
        .post(
            "/stores",
            serde_json::json!({ "name": "directory", "topic": topic, "policy": "self_keyed" }),
        )
        .await;
    assert_eq!(r.status().as_u16(), 201, "create self_keyed store");
    let body: serde_json::Value = r.json().await.expect("create body json");
    assert_eq!(body["policy"], "self_keyed");
    assert_eq!(body["id"], topic, "the REST id stays the topic string");
    assert!(
        body["owner"].is_null(),
        "self_keyed store has no owner: {body}"
    );

    // Join WITHOUT expected_owner succeeds (I4).
    let r = pair
        .bob
        .post(
            &format!("/stores/{topic}/join"),
            serde_json::json!({ "policy": "self_keyed" }),
        )
        .await;
    assert_eq!(
        r.status().as_u16(),
        200,
        "self_keyed join needs only the topic"
    );
    let body: serde_json::Value = r.json().await.expect("join body json");
    assert_eq!(body["policy"], "self_keyed");
    assert!(body["owner"].is_null());

    // expected_owner + self_keyed is a contradiction: 422 owner_not_allowed.
    let r = pair
        .bob
        .post(
            &format!("/stores/{topic}-x/join"),
            serde_json::json!({ "policy": "self_keyed", "expected_owner": foreign_prefix() }),
        )
        .await;
    assert_eq!(r.status().as_u16(), 422);
    let body: serde_json::Value = r.json().await.expect("422 body json");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("owner_not_allowed"),
        "422 body names owner_not_allowed; got: {body}"
    );

    // Regression: an owner-anchored join WITHOUT expected_owner is still
    // 422 owner_required (I10 — the fail-closed default is unchanged).
    let r = pair
        .bob
        .post(
            &format!("/stores/{topic}-signed/join"),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(r.status().as_u16(), 422);
    let body: serde_json::Value = r.json().await.expect("422 body json");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("owner_required"),
        "422 body names owner_required; got: {body}"
    );

    // Prefix gating over REST via the grammar's bare root record: alice
    // writes her own namespace, cannot write a foreign one.
    let alice_prefix = pair.alice.agent_id().await;
    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/{alice_prefix}"),
            serde_json::json!({ "value": b64(b"alice") }),
        )
        .await;
    assert!(
        r.status().is_success(),
        "own-prefix put succeeds: {}",
        r.status()
    );
    let foreign_key = foreign_prefix();
    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/{foreign_key}"),
            serde_json::json!({ "value": b64(b"hijack") }),
        )
        .await;
    assert_eq!(
        r.status().as_u16(),
        403,
        "a foreign-prefix put must be 403 Forbidden"
    );
    let r = pair
        .alice
        .get(&format!("/stores/{topic}/{foreign_key}"))
        .await;
    assert_eq!(
        r.status().as_u16(),
        404,
        "the foreign key was never applied"
    );

    // Bob (joined) writes his own namespace too — two publishers, no owner.
    let bob_prefix = pair.bob.agent_id().await;
    let r = pair
        .bob
        .put(
            &format!("/stores/{topic}/{bob_prefix}"),
            serde_json::json!({ "value": b64(b"bob") }),
        )
        .await;
    assert!(r.status().is_success(), "joiner writes its own namespace");

    // Bob eventually sees alice's root record (directory convergence through
    // the existing sync path).
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let r = pair
            .bob
            .get(&format!("/stores/{topic}/{alice_prefix}"))
            .await;
        if r.status().is_success() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bob did not observe alice's key within 60s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore]
async fn selfkeyed_subscription_rehydrate_keeps_policy() {
    let mut pair = cluster::pair().await;
    let topic = format!("kv-sk-restart-{}", rand::random::<u32>());

    // Alice creates; bob joins by topic only; both write their root record.
    let r = pair
        .alice
        .post(
            "/stores",
            serde_json::json!({ "name": "directory", "topic": topic, "policy": "self_keyed" }),
        )
        .await;
    assert_eq!(r.status().as_u16(), 201);
    let r = pair
        .bob
        .post(
            &format!("/stores/{topic}/join"),
            serde_json::json!({ "policy": "self_keyed" }),
        )
        .await;
    assert_eq!(r.status().as_u16(), 200);

    let alice_prefix = pair.alice.agent_id().await;
    let bob_prefix = pair.bob.agent_id().await;
    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/{alice_prefix}"),
            serde_json::json!({ "value": b64(b"alice") }),
        )
        .await;
    assert!(r.status().is_success(), "alice writes her root record");
    let r = pair
        .bob
        .put(
            &format!("/stores/{topic}/{bob_prefix}"),
            serde_json::json!({ "value": b64(b"bob") }),
        )
        .await;
    assert!(r.status().is_success(), "bob writes his root record");

    // Restart both: created and joined self_keyed entries must rehydrate as
    // self_keyed (not Signed) WITHOUT any expected_owner, and stay writable.
    pair.alice.restart().await;
    pair.bob.restart().await;
    for (node, label) in [(&pair.alice, "creator"), (&pair.bob, "joiner")] {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if store_policy(node, &topic).await.as_deref() == Some("self_keyed") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{label} did not rehydrate the self_keyed store within 120s"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    // Still writable after restart (own prefix).
    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/{alice_prefix}"),
            serde_json::json!({ "value": b64(b"alice2") }),
        )
        .await;
    assert!(
        r.status().is_success(),
        "rehydrated creator stays writable in its own namespace"
    );
    let r = pair
        .bob
        .put(
            &format!("/stores/{topic}/{bob_prefix}"),
            serde_json::json!({ "value": b64(b"bob2") }),
        )
        .await;
    assert!(
        r.status().is_success(),
        "rehydrated joiner stays writable in its own namespace"
    );
}
