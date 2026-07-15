//! REST surface of `AccessPolicy::AppendOnly` (tracker-integrity-v2 WP-X).
//!
//! WHY: append-only event logs must be tamper-evident against their own
//! author. The owner can append new keys, but an existing key can never be
//! updated to different content or deleted — even by the owner. The API must
//! surface that as 409 Conflict (not 403: the caller IS authorized to write,
//! the specific mutation is what conflicts with the store's immutability).
//!
//! All tests are `#[ignore]` — they boot a real x0xd daemon.
//! Run with: cargo nextest run --test kv_append_only_rest -- --ignored
//! Before running: cargo build --release --bin x0xd

use base64::Engine;
use std::time::{Duration, Instant};

#[path = "harness/src/cluster.rs"]
mod cluster;

fn b64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// Poll until `key` reads back successfully on `node`, panicking after `secs`.
async fn wait_for_key(node: &cluster::AgentInstance, topic: &str, key: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let r = node.get(&format!("/stores/{topic}/{key}")).await;
        if r.status().is_success() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "key {key} not visible on {topic} within {secs}s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
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
async fn append_only_store_rest_put_conflict_and_delete_conflict() {
    let (node, _bind) = cluster::solo().await;
    let topic = format!("kv-ao-{}", rand::random::<u32>());

    // Create with the append_only policy; the response must reflect it.
    let r = node
        .post(
            "/stores",
            serde_json::json!({ "name": "events", "topic": topic, "policy": "append_only" }),
        )
        .await;
    assert_eq!(r.status().as_u16(), 201, "create append_only store");
    let body: serde_json::Value = r.json().await.expect("create body json");
    assert_eq!(
        body["policy"], "append_only",
        "create response must report the append_only policy"
    );

    // An unsupported policy string must be a 400, not a silent Signed store.
    let r = node
        .post(
            "/stores",
            serde_json::json!({ "name": "x", "topic": format!("{topic}-bad"), "policy": "immutable" }),
        )
        .await;
    assert_eq!(r.status().as_u16(), 400, "unknown policy is rejected");

    // First append succeeds.
    let r = node
        .put(
            &format!("/stores/{topic}/evt-1"),
            serde_json::json!({ "value": b64(b"created") }),
        )
        .await;
    assert!(r.status().is_success(), "owner appends a new key");

    // Re-put with DIFFERENT content: 409 Conflict, value untouched.
    let r = node
        .put(
            &format!("/stores/{topic}/evt-1"),
            serde_json::json!({ "value": b64(b"REWRITTEN") }),
        )
        .await;
    assert_eq!(
        r.status().as_u16(),
        409,
        "owner rewriting an existing key must be 409 Conflict"
    );
    let body: serde_json::Value = r.json().await.expect("409 body json");
    assert_eq!(body["ok"], false);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("immutable key"),
        "409 body names the immutability violation; got: {body}"
    );

    // Re-put with IDENTICAL content: idempotent no-op, accepted (retry-safe).
    let r = node
        .put(
            &format!("/stores/{topic}/evt-1"),
            serde_json::json!({ "value": b64(b"created"), "content_type": "application/octet-stream" }),
        )
        .await;
    assert!(
        r.status().is_success(),
        "byte-identical re-put is an accepted idempotent no-op"
    );

    // DELETE an existing key: 409 Conflict, key retained.
    let r = node.delete(&format!("/stores/{topic}/evt-1")).await;
    assert_eq!(
        r.status().as_u16(),
        409,
        "owner deleting an existing key must be 409 Conflict"
    );

    // The original bytes are still there.
    let r = node.get(&format!("/stores/{topic}/evt-1")).await;
    assert!(r.status().is_success(), "key survives rejected mutations");
    let body: serde_json::Value = r.json().await.expect("get body json");
    assert_eq!(
        body["value"],
        b64(b"created"),
        "original append is retained verbatim"
    );

    // Regression: a default (Signed) store still allows owner update+delete.
    let signed_topic = format!("{topic}-signed");
    let r = node
        .post(
            "/stores",
            serde_json::json!({ "name": "plain", "topic": signed_topic }),
        )
        .await;
    assert_eq!(r.status().as_u16(), 201, "create default Signed store");
    let body: serde_json::Value = r.json().await.expect("create body json");
    assert_eq!(body["policy"], "signed", "default policy is still signed");
    for v in [b"v1".as_slice(), b"v2".as_slice()] {
        let r = node
            .put(
                &format!("/stores/{signed_topic}/k"),
                serde_json::json!({ "value": b64(v) }),
            )
            .await;
        assert!(r.status().is_success(), "Signed store update still works");
    }
    let r = node.delete(&format!("/stores/{signed_topic}/k")).await;
    assert!(r.status().is_success(), "Signed store delete still works");
}

/// WHY (P0-C restart amnesia): an append-only owner or replica must come
/// back from a daemon restart with its state — otherwise the owner forgets
/// key k, accepts its own k=v2 as a fresh append, and signs a rewritten
/// history. State snapshots (`<data_dir>/kv-stores/<id>.bin`) are the fix;
/// this proves them end-to-end through real daemon restarts, including a
/// joiner restarting while the owner is OFFLINE (the data can only come
/// from disk).
#[tokio::test]
#[ignore]
async fn append_only_state_survives_daemon_restart() {
    let mut pair = cluster::pair().await;
    let topic = format!("kv-ao-restart-{}", rand::random::<u32>());

    // Alice creates the append-only store and appends a key.
    let r = pair
        .alice
        .post(
            "/stores",
            serde_json::json!({ "name": "events", "topic": topic, "policy": "append_only" }),
        )
        .await;
    assert_eq!(r.status().as_u16(), 201, "alice creates append_only store");
    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/evt-1"),
            serde_json::json!({ "value": b64(b"created") }),
        )
        .await;
    assert!(r.status().is_success(), "alice appends evt-1");

    // Bob joins anchored on alice and syncs the key (his replica learns the
    // append_only policy from alice's owner-signed checkpoint).
    let alice_id = pair.alice.agent_id().await;
    let r = pair
        .bob
        .post(
            &format!("/stores/{topic}/join"),
            serde_json::json!({ "expected_owner": alice_id }),
        )
        .await;
    assert!(r.status().is_success(), "bob joins");
    wait_for_key(&pair.bob, &topic, "evt-1", 60).await;

    // OWNER RESTART: alice must rehydrate with entries + policy from disk,
    // and still refuse to rewrite her own history.
    pair.alice.restart().await;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if store_policy(&pair.alice, &topic).await.as_deref() == Some("append_only") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "alice did not rehydrate the append_only store within 120s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    wait_for_key(&pair.alice, &topic, "evt-1", 60).await;
    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/evt-1"),
            serde_json::json!({ "value": b64(b"REWRITTEN") }),
        )
        .await;
    assert_eq!(
        r.status().as_u16(),
        409,
        "restarted owner must STILL refuse to rewrite (state restored from snapshot)"
    );
    let r = pair.alice.get(&format!("/stores/{topic}/evt-1")).await;
    let body: serde_json::Value = r.json().await.expect("json");
    assert_eq!(body["value"], b64(b"created"), "original bytes retained");

    // JOINER RESTART WITH OWNER OFFLINE: bob's data + learned append_only
    // policy can only come from his snapshot.
    pair.alice.stop();
    pair.bob.restart().await;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if store_policy(&pair.bob, &topic).await.as_deref() == Some("append_only") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bob did not rehydrate the append_only replica (owner offline) within 120s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    wait_for_key(&pair.bob, &topic, "evt-1", 60).await;
    let r = pair.bob.get(&format!("/stores/{topic}/evt-1")).await;
    let body: serde_json::Value = r.json().await.expect("json");
    assert_eq!(
        body["value"],
        b64(b"created"),
        "joiner restored entry from disk while owner offline"
    );
    // Bob is not the owner: local writes stay 403 (authorization precedes
    // immutability).
    let r = pair
        .bob
        .put(
            &format!("/stores/{topic}/evt-1"),
            serde_json::json!({ "value": b64(b"junk") }),
        )
        .await;
    assert_eq!(r.status().as_u16(), 403, "non-owner writes still 403");
}
