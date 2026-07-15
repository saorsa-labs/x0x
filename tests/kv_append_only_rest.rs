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

#[path = "harness/src/cluster.rs"]
mod cluster;

fn b64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
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
