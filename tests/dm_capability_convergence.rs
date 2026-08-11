//! Installed-daemon-shaped capability + strict-DM smoke on an isolated plane.
//!
//! Run with:
//! `cargo test --test dm_capability_convergence -- --ignored --nocapture`

#![allow(clippy::expect_used)]

use base64::Engine;

#[path = "harness/src/cluster.rs"]
mod cluster;

async fn strict_send(
    from: &cluster::AgentInstance,
    recipient: &str,
    marker: &[u8],
) -> serde_json::Value {
    let payload = base64::engine::general_purpose::STANDARD.encode(marker);
    let response = from
        .post(
            "/direct/send",
            serde_json::json!({ "agent_id": recipient, "payload": payload }),
        )
        .await;
    let status = response.status();
    let body: serde_json::Value = response.json().await.expect("direct send json");
    assert!(status.is_success(), "strict send failed ({status}): {body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["path"], "gossip_inbox");
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "boots two real x0xd daemons"]
async fn strict_send_converges_bidirectionally_on_isolated_plane() {
    let network_id = format!("capability-convergence-{}", std::process::id());
    let pair = cluster::pair_with_extra_config(&format!("network_id = \"{network_id}\"\n")).await;
    let alice_id = pair.alice.agent_id().await;
    let bob_id = pair.bob.agent_id().await;

    strict_send(&pair.alice, &bob_id, b"isolated strict alice to bob").await;
    strict_send(&pair.bob, &alice_id, b"isolated strict bob to alice").await;
}
