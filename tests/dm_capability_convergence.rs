//! Installed-daemon-shaped capability + strict-DM smoke on an isolated plane.
//!
//! Run with:
//! `cargo build --bin x0xd && cargo test --test dm_capability_convergence -- --ignored --nocapture`

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

fn captured_log_path(
    log_dir: &std::path::Path,
    instance: &cluster::AgentInstance,
) -> std::path::PathBuf {
    log_dir.join(format!("{}.start.log", instance.name))
}

fn captured_log_offset(log_dir: &std::path::Path, instance: &cluster::AgentInstance) -> u64 {
    std::fs::metadata(captured_log_path(log_dir, instance))
        .expect("captured daemon log metadata")
        .len()
}

fn captured_log_suffix(
    log_dir: &std::path::Path,
    instance: &cluster::AgentInstance,
    offset: u64,
) -> String {
    let mut file =
        std::fs::File::open(captured_log_path(log_dir, instance)).expect("open captured log");
    file.seek(std::io::SeekFrom::Start(offset))
        .expect("seek captured log");
    let mut suffix = String::new();
    file.read_to_string(&mut suffix).expect("read captured log");
    suffix
}

async fn force_next_capability_miss(instance: &cluster::AgentInstance, recipient: &str) {
    let path = format!("/diagnostics/dm/capabilities/{recipient}/force-miss");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let response = instance.post(&path, serde_json::json!({})).await;
        if response.status().is_success() {
            let body: serde_json::Value = response.json().await.expect("force-miss response json");
            assert_eq!(body["next_lookup"], "forced_miss");
            return;
        }
        assert_eq!(
            response.status(),
            reqwest::StatusCode::CONFLICT,
            "force-miss control must be enabled and authenticated"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "recipient capability did not converge before force-miss deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
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
    let log_dir = std::env::temp_dir().join(format!(
        "x0x-capability-forced-miss-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&log_dir).expect("create self-contained daemon log directory");
    let pair = cluster::pair_with_captured_logs(
        &format!(
            "network_id = \"{network_id}\"\n\
         dm_capability_test_controls = true\n"
        ),
        &log_dir,
        "x0x::dm_capability_service=debug,dm.trace=debug,warn",
    )
    .await;
    let alice_id = pair.alice.agent_id().await;
    let bob_id = pair.bob.agent_id().await;

    let unauthenticated = reqwest::Client::new()
        .post(
            pair.alice
                .url(&format!("/diagnostics/dm/capabilities/{bob_id}/force-miss")),
        )
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("unauthenticated force-miss request");
    assert_eq!(
        unauthenticated.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "test control must stay behind daemon bearer authentication"
    );

    // Arm an authenticated one-shot lookup miss only after startup capability
    // convergence. Intervening startup adverts cannot defeat this control: the
    // next exact-recipient lookup consumes the miss and removes that advert.
    force_next_capability_miss(&pair.alice, &bob_id).await;
    let alice_offset = captured_log_offset(&log_dir, &pair.alice);
    let bob_offset = captured_log_offset(&log_dir, &pair.bob);
    strict_send(&pair.alice, &bob_id, b"isolated strict alice to bob").await;
    assert_flow_observed(
        &captured_log_suffix(&log_dir, &pair.alice, alice_offset),
        &captured_log_suffix(&log_dir, &pair.bob, bob_offset),
    );

    force_next_capability_miss(&pair.bob, &alice_id).await;
    let bob_offset = captured_log_offset(&log_dir, &pair.bob);
    let alice_offset = captured_log_offset(&log_dir, &pair.alice);
    strict_send(&pair.bob, &alice_id, b"isolated strict bob to alice").await;
    assert_flow_observed(
        &captured_log_suffix(&log_dir, &pair.bob, bob_offset),
        &captured_log_suffix(&log_dir, &pair.alice, alice_offset),
    );
    eprintln!("capability convergence logs: {}", log_dir.display());
}
