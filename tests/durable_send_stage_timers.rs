//! #336 phase 1: durable-send stage timers must partition wall time.
//!
//! A first durable DM to a new loopback peer is slow today. This test does
//! not cut that latency. It proves the three named stages exist, appear on
//! the timeout 504 body and `/diagnostics/dm`, and sum to daemon wall time
//! so a slow send can name which stage ate the budget.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine;
use reqwest::StatusCode;
use serde_json::Value;
use std::time::{Duration, Instant};

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

/// Matches the bundled client's 30 s observer. Do not raise this.
const DURABLE_SEND_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test]
async fn first_durable_send_stage_timers_sum_to_wall_time() {
    let bob = DaemonFixture::start("dst336-bob").await;
    let bob_client = bob.authed_client(Duration::from_secs(10));
    let bob_status: Value = bob_client
        .get(bob.url("/network/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_quic = rewrite_unspecified_to_loopback(
        bob_status["local_addr"]
            .as_str()
            .expect("network/status.local_addr"),
    );

    let alice = DaemonFixture::start_with_config(
        "dst336-alice",
        &format!("bootstrap_peers = [\"{bob_quic}\"]\n"),
    )
    .await;
    let alice_client = alice.authed_client(DURABLE_SEND_CLIENT_TIMEOUT);

    let alice_card: Value = alice_client
        .get(alice.url("/agent/card"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_card: Value = bob_client
        .get(bob.url("/agent/card"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(alice_client
        .post(alice.url("/agent/card/import"))
        .json(&serde_json::json!({
            "card": bob_card["link"].as_str().unwrap(),
            "trust_level": "Trusted"
        }))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    assert!(bob_client
        .post(bob.url("/agent/card/import"))
        .json(&serde_json::json!({
            "card": alice_card["link"].as_str().unwrap(),
            "trust_level": "Trusted"
        }))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    wait_for_durable_capability(&alice, Duration::from_secs(30)).await;

    let bob_agent_id = {
        let v: Value = bob_client
            .get(bob.url("/agent"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["agent_id"].as_str().unwrap().to_string()
    };

    let payload = base64::engine::general_purpose::STANDARD.encode(b"dst336-first-send");
    let wall = Instant::now();
    let response = alice_client
        .post(alice.url("/direct/send"))
        .json(&serde_json::json!({
            "agent_id": bob_agent_id,
            "payload": payload,
        }))
        .send()
        .await
        .unwrap();
    let wall_ms = u64::try_from(wall.elapsed().as_millis()).unwrap_or(u64::MAX);
    let status = response.status();
    let body: Value = response.json().await.unwrap();

    let stages = if status == StatusCode::GATEWAY_TIMEOUT {
        assert_eq!(
            body["error"], "timeout",
            "504 must keep error=timeout: {body}"
        );
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|d| d.contains("timed out")),
            "504 detail contract must stay: {body}"
        );
        stages_from_timeout_body(&body)
    } else {
        assert_eq!(
            status,
            StatusCode::OK,
            "first durable send must be 200 or 504, got {status}: {body}"
        );
        let diag: Value = alice_client
            .get(alice.url("/diagnostics/dm"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        stages_from_diagnostics(&diag)
    };

    let sum = stages.strict_gate_ms + stages.publish_ms + stages.ack_wait_ms;
    assert!(
        sum.abs_diff(stages.elapsed_ms) <= 25,
        "named stages must partition daemon wall: sum={sum} elapsed={} {:?}",
        stages.elapsed_ms,
        stages
    );
    assert!(
        wall_ms.abs_diff(stages.elapsed_ms) < 2_000,
        "daemon elapsed must track client wall: wall={wall_ms} elapsed={} {:?}",
        stages.elapsed_ms,
        stages
    );
    assert!(
        ["strict_gate_ms", "publish_ms", "ack_wait_ms"].contains(&stages.budget_stage.as_str()),
        "a slow send must name one of the three stages, got {}",
        stages.budget_stage
    );

    let bob_diag: Value = bob_client
        .get(bob.url("/diagnostics/dm"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    if status == StatusCode::OK {
        assert!(
            bob_diag
                .get("last_ack_publish_ms")
                .and_then(Value::as_u64)
                .is_some(),
            "receiver must export last_ack_publish_ms after a durable ACK: {bob_diag}"
        );
    }
}

#[derive(Debug)]
struct ObservedStages {
    strict_gate_ms: u64,
    publish_ms: u64,
    ack_wait_ms: u64,
    elapsed_ms: u64,
    budget_stage: String,
}

fn stages_from_timeout_body(body: &Value) -> ObservedStages {
    ObservedStages {
        strict_gate_ms: required_u64(body, "strict_gate_ms"),
        publish_ms: required_u64(body, "publish_ms"),
        ack_wait_ms: required_u64(body, "ack_wait_ms"),
        elapsed_ms: required_u64(body, "elapsed_ms"),
        budget_stage: body["budget_stage"]
            .as_str()
            .expect("timeout 504 must name budget_stage")
            .to_string(),
    }
}

fn stages_from_diagnostics(diag: &Value) -> ObservedStages {
    let last = diag
        .get("last_durable_send")
        .expect("successful durable send must appear on /diagnostics/dm");
    ObservedStages {
        strict_gate_ms: required_u64(last, "strict_gate_ms"),
        publish_ms: required_u64(last, "publish_ms"),
        ack_wait_ms: required_u64(last, "ack_wait_ms"),
        elapsed_ms: required_u64(last, "elapsed_ms"),
        budget_stage: last["budget_stage"]
            .as_str()
            .expect("diagnostics last_durable_send must name budget_stage")
            .to_string(),
    }
}

fn required_u64(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} must be present on stage-timer export: {value}"))
}

fn rewrite_unspecified_to_loopback(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix("0.0.0.0:") {
        return format!("127.0.0.1:{rest}");
    }
    if let Some(rest) = addr.strip_prefix("[::]:") {
        return format!("127.0.0.1:{rest}");
    }
    if let Some(rest) = addr.strip_prefix("[::1]:") {
        return format!("127.0.0.1:{rest}");
    }
    addr.to_string()
}

async fn wait_for_durable_capability(fixture: &DaemonFixture, deadline: Duration) -> usize {
    let client = fixture.authed_client(Duration::from_secs(5));
    let started = tokio::time::Instant::now();
    let mut polls = 0usize;
    while started.elapsed() < deadline {
        polls += 1;
        if let Ok(resp) = client.get(fixture.url("/diagnostics/dm")).send().await {
            if let Ok(body) = resp.json::<Value>().await {
                if body["capability_store_entries"].as_u64().unwrap_or(0) > 0 {
                    return polls;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "no peer capability advert converged within {deadline:?} ({polls} polls); \
         a durable /direct/send would 409"
    );
}
