//! Round-trip integration tests for the ant-quic 0.27.x peer-lifecycle
//! REST surfaces:
//!
//! - `POST /peers/:peer_id/probe` — `probe_peer` (ant-quic 0.27.2 #173)
//! - `GET /peers/:peer_id/health` — `connection_health` (ant-quic 0.27.1 #170)
//! - `GET /peers/events` (SSE) — `subscribe_all_peer_events` (ant-quic 0.27.1 #171)
//! - `POST /direct/send` with `require_ack_ms` — post-send `probe_peer` liveness confirmation
//!
//! Coverage rationale: `tests/api_coverage.rs` and `tests/parity_cli.rs`
//! verify these endpoints + commands *exist*; `tests/ant_quic_0272_surface.rs`
//! verifies the underlying ant-quic primitives. This file proves the daemon
//! REST handlers actually round-trip with a real second peer attached.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

const STARTUP_SETTLE: Duration = Duration::from_secs(5);

/// Boot bob, read his QUIC bind addr from `/status`, then boot alice with
/// bob as a bootstrap peer. After cross-importing cards as Trusted, both
/// daemons should have a live QUIC connection to each other.
async fn alice_and_bob_connected() -> (DaemonFixture, DaemonFixture, String, String) {
    let bob = DaemonFixture::start("plc-bob").await;
    let bob_client = bob.authed_client(Duration::from_secs(10));

    // Bob's QUIC bind addr is in /network/status as `local_addr`. (The
    // shorter /status endpoint reports api_address + external_addrs, not
    // the bound QUIC socket.)
    let bob_status: Value = bob_client
        .get(bob.url("/network/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_quic = bob_status["local_addr"]
        .as_str()
        .expect("network/status.local_addr")
        .to_string();
    // ant-quic binds dual-stack; rewrite [::]/0.0.0.0 to 127.0.0.1 so alice
    // can dial it on loopback.
    let bob_quic = rewrite_unspecified_to_loopback(&bob_quic);

    let alice = DaemonFixture::start_with_config(
        "plc-alice",
        &format!("bootstrap_peers = [\"{bob_quic}\"]\n"),
    )
    .await;

    // Cross-import cards as Trusted so the trust gate passes.
    let alice_client = alice.authed_client(Duration::from_secs(10));
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
    let alice_link = alice_card["link"].as_str().unwrap().to_string();
    let bob_link = bob_card["link"].as_str().unwrap().to_string();

    let r = alice_client
        .post(alice.url("/agent/card/import"))
        .json(&serde_json::json!({"card": bob_link, "trust_level": "Trusted"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "alice imports bob card");
    let r = bob_client
        .post(bob.url("/agent/card/import"))
        .json(&serde_json::json!({"card": alice_link, "trust_level": "Trusted"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "bob imports alice card");

    // Let the QUIC mesh settle.
    tokio::time::sleep(STARTUP_SETTLE).await;

    let alice_agent: Value = alice_client
        .get(alice.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_agent: Value = bob_client
        .get(bob.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alice_machine = alice_agent["machine_id"].as_str().unwrap().to_string();
    let bob_machine = bob_agent["machine_id"].as_str().unwrap().to_string();

    (alice, bob, alice_machine, bob_machine)
}

fn rewrite_unspecified_to_loopback(addr: &str) -> String {
    // SocketAddr "0.0.0.0:1234" / "[::]:1234" → "127.0.0.1:1234"
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

/// Wait until `/peers` on `fixture` lists `peer_machine`. Returns the elapsed
/// poll count for diagnostics.
async fn wait_for_peer(fixture: &DaemonFixture, peer_machine: &str, deadline: Duration) -> usize {
    let client = fixture.authed_client(Duration::from_secs(5));
    let started = tokio::time::Instant::now();
    let mut polls = 0usize;
    while started.elapsed() < deadline {
        polls += 1;
        if let Ok(resp) = client.get(fixture.url("/peers")).send().await {
            if let Ok(body) = resp.json::<Value>().await {
                if let Some(arr) = body["peers"].as_array() {
                    if arr.iter().any(|p| p["id"].as_str() == Some(peer_machine)) {
                        return polls;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "peer {peer_machine} not visible in /peers within {:?} ({polls} polls)",
        deadline
    );
}

// ---------------------------------------------------------------------------
// /peers/:peer_id/probe — active liveness with finite RTT
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn peer_probe_returns_finite_rtt_against_live_peer() {
    let (alice, _bob, _alice_machine, bob_machine) = alice_and_bob_connected().await;
    wait_for_peer(&alice, &bob_machine, Duration::from_secs(15)).await;

    let client = alice.authed_client(Duration::from_secs(10));
    let r = client
        .post(alice.url(&format!("/peers/{bob_machine}/probe?timeout_ms=3000")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "probe returned non-200");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["ok"], true, "probe ok=false: {body}");

    // Either rtt_ms or rtt_us must be present and non-negative on a healthy
    // localhost link. ant-quic returns sub-millisecond on loopback so rtt_us
    // is the more reliable assertion.
    let has_finite_rtt = body["rtt_ms"].as_u64().map(|v| v < 30_000).unwrap_or(false)
        || body["rtt_us"]
            .as_u64()
            .map(|v| v < 30_000_000)
            .unwrap_or(false);
    assert!(has_finite_rtt, "probe lacked finite rtt: {body}");
    assert_eq!(body["timeout_ms"], 3000);
}

#[tokio::test]
#[ignore]
async fn peer_probe_returns_400_on_invalid_peer_id() {
    let alice = DaemonFixture::start("plc-probe-bad").await;
    let client = alice.authed_client(Duration::from_secs(10));
    // Not 64 hex chars — must be a structured 4xx, not 5xx panic.
    let r = client
        .post(alice.url("/peers/not-a-real-id/probe"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error(), "got {}", r.status());
}

// ---------------------------------------------------------------------------
// /peers/:peer_id/health — connection health snapshot
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn peer_health_snapshot_observable_for_live_peer() {
    let (alice, _bob, _alice_machine, bob_machine) = alice_and_bob_connected().await;
    wait_for_peer(&alice, &bob_machine, Duration::from_secs(15)).await;

    let client = alice.authed_client(Duration::from_secs(10));
    let r = client
        .get(alice.url(&format!("/peers/{bob_machine}/health")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["peer_id"], bob_machine);

    // Structured snapshot is the supported wire shape (v0.19.7+). The
    // `health` Debug string is still emitted for legacy clients but the
    // assertion lives on `snapshot`.
    let snapshot = &body["snapshot"];
    assert_eq!(
        snapshot["connected"], true,
        "snapshot.connected should be true for live peer: {body}"
    );
    assert!(
        snapshot["generation"].as_u64().is_some(),
        "snapshot.generation should be present for live peer: {body}"
    );
    // close_reason is null on a live peer.
    assert!(
        snapshot["close_reason"].is_null(),
        "snapshot.close_reason should be null on a live peer: {body}"
    );

    // Legacy field still present (back-compat).
    assert!(
        body["health"].is_string(),
        "legacy `health` Debug string should still be emitted: {body}"
    );
}

// ---------------------------------------------------------------------------
// /peers/events — SSE lifecycle bus
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn peer_events_sse_emits_established_on_new_connection() {
    // Boot alice first so we can subscribe to her SSE *before* the connection
    // happens. ant-quic's broadcast bus only delivers transitions that occur
    // *after* the receiver subscribes (existing connections are not replayed).
    let alice = DaemonFixture::start("plc-evts-alice").await;
    let alice_token = alice.api_token().to_string();
    let alice_url = alice.url("/peers/events");

    // Open the SSE in a background task; collect raw lines for 12 s.
    let alice_token_clone = alice_token.clone();
    let collector = tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let mut resp = client
            .get(&alice_url)
            .bearer_auth(&alice_token_clone)
            .send()
            .await
            .unwrap();
        let mut acc = String::new();
        let started = tokio::time::Instant::now();
        while started.elapsed() < Duration::from_secs(12) {
            match tokio::time::timeout(Duration::from_millis(500), resp.chunk()).await {
                Ok(Ok(Some(bytes))) => acc.push_str(&String::from_utf8_lossy(&bytes)),
                Ok(Ok(None)) => break, // server closed
                Ok(Err(_)) => break,   // transport error
                Err(_) => continue,    // timeout — keep polling
            }
            if acc.contains("Established") {
                break; // early-exit once we've seen the event we care about
            }
        }
        acc
    });

    // Give the SSE a moment to connect.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Read alice's QUIC bind, then boot bob pointed at her.
    let alice_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let alice_status: Value = alice_client
        .get(alice.url("/network/status"))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alice_quic = rewrite_unspecified_to_loopback(
        alice_status["local_addr"]
            .as_str()
            .expect("network/status.local_addr"),
    );

    let bob = DaemonFixture::start_with_config(
        "plc-evts-bob",
        &format!("bootstrap_peers = [\"{alice_quic}\"]\n"),
    )
    .await;

    // Trust each other so the announce flow doesn't get rejected.
    let bob_client = bob.authed_client(Duration::from_secs(10));
    let alice_card: Value = alice_client
        .get(alice.url("/agent/card"))
        .bearer_auth(&alice_token)
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
    alice_client
        .post(alice.url("/agent/card/import"))
        .bearer_auth(&alice_token)
        .json(&serde_json::json!({
            "card": bob_card["link"].as_str().unwrap(),
            "trust_level": "Trusted",
        }))
        .send()
        .await
        .unwrap();
    bob_client
        .post(bob.url("/agent/card/import"))
        .json(&serde_json::json!({
            "card": alice_card["link"].as_str().unwrap(),
            "trust_level": "Trusted",
        }))
        .send()
        .await
        .unwrap();

    let captured = collector.await.unwrap();
    assert!(
        captured.contains("event: peer-lifecycle"),
        "no peer-lifecycle frame in 12s window: {captured:?}"
    );
    assert!(
        captured.contains("Established"),
        "no Established transition observed in 12s window: {captured:?}"
    );
}

// ---------------------------------------------------------------------------
// /direct/send + require_ack_ms — round-trip ACK probe
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn direct_send_with_require_ack_round_trips_to_live_peer() {
    let (alice, bob, _alice_machine, _bob_machine) = alice_and_bob_connected().await;

    let bob_agent_id = {
        let bob_client = bob.authed_client(Duration::from_secs(5));
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

    let payload = base64::engine::general_purpose::STANDARD.encode(b"plc-ack-test");
    let alice_client = alice.authed_client(Duration::from_secs(10));
    let r = alice_client
        .post(alice.url("/direct/send"))
        .json(&serde_json::json!({
            "agent_id": bob_agent_id,
            "payload": payload,
            "require_ack_ms": 3000,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["ok"], true, "direct/send body: {body}");
    let ack = &body["require_ack"];
    assert_eq!(ack["ok"], true, "require_ack absent or failed: {body}");
    let rtt_ms = ack["rtt_ms"]
        .as_u64()
        .or_else(|| ack["rtt_us"].as_u64().map(|us| us / 1000))
        .expect("require_ack must include rtt_ms or rtt_us");
    assert!(
        rtt_ms < 30_000,
        "require_ack rtt {rtt_ms}ms exceeds 30s ceiling"
    );
}

#[tokio::test]
#[ignore]
async fn direct_send_without_require_ack_omits_ack_block() {
    // Negative coverage: opting out leaves require_ack absent so legacy
    // clients aren't broken by the new field appearing unsolicited.
    let (alice, bob, _alice_machine, _bob_machine) = alice_and_bob_connected().await;

    let bob_agent_id = {
        let bob_client = bob.authed_client(Duration::from_secs(5));
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

    let payload = base64::engine::general_purpose::STANDARD.encode(b"plc-no-ack-test");
    let alice_client = alice.authed_client(Duration::from_secs(10));
    let r = alice_client
        .post(alice.url("/direct/send"))
        .json(&serde_json::json!({
            "agent_id": bob_agent_id,
            "payload": payload,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert!(
        body.get("require_ack").is_none() || body["require_ack"].is_null(),
        "require_ack should be absent when not requested, got: {body}"
    );
}
