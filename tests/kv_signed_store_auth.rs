//! Security regression test — a non-owner joiner of a `Signed` KV store
//! must NOT be able to mutate its local replica.
//!
//! Previously a joiner's replica claimed the joiner itself as owner with a
//! permissive policy, so a local PUT via REST returned `200 {"ok":true}` and
//! forked the joiner's replica away from the state authorized peers accept
//! (the creator rejected the joiner's deltas, but the joiner kept its junk).
//!
//! The fix: a joined replica starts with no owner (fail closed, read-only),
//! learns the authoritative owner + policy from an owner-signed announcement
//! on the state-sync side topic, and enforces the same `is_authorized` rule
//! on local writes as on inbound deltas. REST returns 403 for rejected
//! writes.
//!
//! All tests are `#[ignore]` — they boot real x0xd daemons.
//! Run with: cargo nextest run --test kv_signed_store_auth -- --ignored
//! Before running: cargo build --release --bin x0xd

use base64::Engine;
use std::time::{Duration, Instant};

#[path = "harness/src/cluster.rs"]
mod cluster;

fn b64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

/// Poll until `key` is visible in bob's replica, panicking after `deadline`.
async fn wait_for_key(bob: &cluster::AgentInstance, topic: &str, key: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let r = bob.get(&format!("/stores/{topic}/{key}")).await;
        if r.status().is_success() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "key {key} never replicated to the joiner within {secs}s"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore]
async fn joiner_put_on_signed_store_is_403_and_does_not_mutate() {
    let pair = cluster::pair().await;
    let topic = format!("kv-auth-{}", rand::random::<u32>());

    // Alice creates the store (Signed policy, owner = alice) and writes a
    // seed key.
    let r = pair
        .alice
        .post(
            "/stores",
            serde_json::json!({ "name": "authz", "topic": topic }),
        )
        .await;
    assert!(r.status().is_success(), "alice creates store");
    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/seed"),
            serde_json::json!({ "value": b64(b"owner-data") }),
        )
        .await;
    assert!(r.status().is_success(), "alice (owner) writes seed key");

    // Bob joins. His replica must sync the seed key — which also proves he
    // has adopted the authoritative owner, since a replica with an unknown
    // owner rejects all inbound deltas (fail closed).
    let r = pair
        .bob
        .post(&format!("/stores/{topic}/join"), serde_json::json!({}))
        .await;
    assert!(r.status().is_success(), "bob joins store");
    wait_for_key(&pair.bob, &topic, "seed", 60).await;

    // THE DEFECT: bob (non-owner) PUTs into the Signed store. This used to
    // return 200 and mutate his local replica, creating a fork the creator
    // rejects. It must now be a 403 with a distinct error body.
    let r = pair
        .bob
        .put(
            &format!("/stores/{topic}/intruder"),
            serde_json::json!({ "value": b64(b"forked-junk") }),
        )
        .await;
    assert_eq!(
        r.status().as_u16(),
        403,
        "non-owner local PUT on a Signed store must be rejected with 403"
    );
    let body: serde_json::Value = r.json().await.expect("403 body is json");
    assert_eq!(body["ok"], false, "error body must carry ok:false");
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("not authorized") && err.contains("owner is "),
        "403 body must name the policy violation and the true owner; got: {err}"
    );

    // And the local replica must NOT have been mutated.
    let r = pair.bob.get(&format!("/stores/{topic}/intruder")).await;
    assert_eq!(
        r.status().as_u16(),
        404,
        "rejected PUT must not mutate the joiner's local replica"
    );

    // Non-owner DELETE of an existing key must also be rejected without
    // mutating the replica.
    let r = pair.bob.delete(&format!("/stores/{topic}/seed")).await;
    assert_eq!(
        r.status().as_u16(),
        403,
        "non-owner local DELETE on a Signed store must be rejected with 403"
    );
    let r = pair.bob.get(&format!("/stores/{topic}/seed")).await;
    assert!(
        r.status().is_success(),
        "rejected DELETE must not remove the key from the joiner's replica"
    );

    // Creator writes keep working and still replicate to the joiner.
    let r = pair
        .alice
        .put(
            &format!("/stores/{topic}/post-join"),
            serde_json::json!({ "value": b64(b"still-flows") }),
        )
        .await;
    assert!(
        r.status().is_success(),
        "owner writes must keep working unchanged"
    );
    wait_for_key(&pair.bob, &topic, "post-join", 30).await;
}
