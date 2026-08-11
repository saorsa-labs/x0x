//! Installed-daemon-shaped capability + strict-DM smoke on an isolated plane.
//!
//! Run with:
//! `cargo test --test dm_capability_convergence -- --ignored --nocapture`

#![allow(clippy::expect_used)]

use base64::Engine;
use std::io::{Read, Seek};

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

fn captured_log_path(instance: &cluster::AgentInstance) -> std::path::PathBuf {
    let directory = std::env::var("X0X_TEST_LOG_DIR")
        .expect("X0X_TEST_LOG_DIR is required for capability-flow observability");
    std::path::Path::new(&directory).join(format!("{}.start.log", instance.name))
}

fn captured_log_offset(instance: &cluster::AgentInstance) -> u64 {
    std::fs::metadata(captured_log_path(instance))
        .expect("captured daemon log metadata")
        .len()
}

fn captured_log_suffix(instance: &cluster::AgentInstance, offset: u64) -> String {
    let mut file = std::fs::File::open(captured_log_path(instance)).expect("open captured log");
    file.seek(std::io::SeekFrom::Start(offset))
        .expect("seek captured log");
    let mut suffix = String::new();
    file.read_to_string(&mut suffix).expect("read captured log");
    suffix
}

fn assert_flow_observed(requester_log: &str, responder_log: &str) {
    for marker in [
        "stage=\"capability_refresh_singleflight\"",
        "role=\"started\"",
        "stage=\"capability_refresh_request_published\"",
        "kind=\"targeted_v2\"",
        "stage=\"capability_advert_ingested\"",
        "stage=\"accepted_at_api\"",
        "path=\"gossip_inbox\"",
    ] {
        assert!(
            requester_log.contains(marker),
            "requester log missing {marker}:\n{requester_log}"
        );
    }
    for marker in [
        "stage=\"capability_refresh_request_received\"",
        "kind=\"targeted_v2\"",
        "stage=\"capability_advert_response_published\"",
    ] {
        assert!(
            responder_log.contains(marker),
            "responder log missing {marker}:\n{responder_log}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "boots two real x0xd daemons"]
async fn strict_send_converges_bidirectionally_on_isolated_plane() {
    let network_id = format!("capability-convergence-{}", std::process::id());
    let pair = cluster::pair_with_extra_config(&format!(
        "network_id = \"{network_id}\"\n\
         dm_capability_cache_ttl_secs = 1\n"
    ))
    .await;
    let alice_id = pair.alice.agent_id().await;
    let bob_id = pair.bob.agent_id().await;

    // The pair helper has already completed startup convergence. Let its most
    // recent signed adverts age past the one-second test TTL, then capture log
    // offsets so every asserted stage below belongs to the forced miss.
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    let alice_offset = captured_log_offset(&pair.alice);
    let bob_offset = captured_log_offset(&pair.bob);
    strict_send(&pair.alice, &bob_id, b"isolated strict alice to bob").await;
    assert_flow_observed(
        &captured_log_suffix(&pair.alice, alice_offset),
        &captured_log_suffix(&pair.bob, bob_offset),
    );

    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    let bob_offset = captured_log_offset(&pair.bob);
    let alice_offset = captured_log_offset(&pair.alice);
    strict_send(&pair.bob, &alice_id, b"isolated strict bob to alice").await;
    assert_flow_observed(
        &captured_log_suffix(&pair.bob, bob_offset),
        &captured_log_suffix(&pair.alice, alice_offset),
    );
}
