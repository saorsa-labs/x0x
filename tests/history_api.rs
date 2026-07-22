//! ADR-0023 Phase 3 — REST/WS history-surface integration tests.
//!
//! `#[ignore]` — these boot real x0xd daemons via the shared cluster
//! harness. Run with: `cargo nextest run --test history_api -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;

#[path = "harness/src/cluster.rs"]
mod cluster;

fn unique_topic() -> String {
    format!("e2e-hist-{}", std::process::id())
}

fn extra_config(topic: &str) -> String {
    format!("[history]\nenabled = true\nrecord_topics = [\"{topic}\"]\n")
}

async fn publish(from: &cluster::AgentInstance, topic: &str, seq: usize) {
    let payload = format!("hist-seq-{seq:04} needle{seq:04}");
    let resp = from
        .post(
            "/publish",
            serde_json::json!({ "topic": topic, "payload": BASE64.encode(payload.as_bytes()) }),
        )
        .await;
    assert!(resp.status().is_success(), "publish {seq} failed");
}

async fn history_count(node: &cluster::AgentInstance, topic: &str) -> usize {
    let resp = node.get(&format!("/history?scope=topic:{topic}")).await;
    if !resp.status().is_success() {
        return 0;
    }
    let v: serde_json::Value = resp.json().await.unwrap_or_default();
    v["count"].as_u64().unwrap_or(0) as usize
}

/// Poll until the recorder has at least `n` rows for the test topic.
async fn wait_for_rows(node: &cluster::AgentInstance, topic: &str, n: usize, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if history_count(node, topic).await >= n {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "recorder never reached {n} rows (have {})",
            history_count(node, topic).await
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// REST surface: list + keyset pagination + search + stats + purge +
/// diagnostics, against a live two-daemon mesh with topic recording on.
#[tokio::test]
#[ignore]
async fn rest_history_list_search_stats_purge_roundtrip() {
    let topic = unique_topic();
    let pair = cluster::pair_with_extra_config(&extra_config(&topic)).await;
    let (alice, bob) = (&pair.alice, &pair.bob);

    // Recording happens on the REST-subscription ingest (local opt-in).
    let resp = bob
        .post("/subscribe", serde_json::json!({ "topic": &topic }))
        .await;
    assert!(resp.status().is_success(), "subscribe failed");
    tokio::time::sleep(Duration::from_secs(2)).await; // gossip sub propagation

    for seq in 0..6 {
        publish(alice, &topic, seq).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    wait_for_rows(bob, &topic, 6, Duration::from_secs(30)).await;

    // Keyset pagination: walk pages of 2, ids strictly descending.
    let mut before_id: Option<i64> = None;
    let mut collected = Vec::new();
    for _page in 0..3 {
        let mut url = format!("/history?scope=topic:{topic}&limit=2");
        if let Some(b) = before_id {
            url.push_str(&format!("&before_id={b}"));
        }
        let v: serde_json::Value = bob.get(&url).await.json().await.expect("page json");
        assert_eq!(v["ok"], true);
        let records = v["records"].as_array().expect("records").clone();
        assert_eq!(records.len(), 2, "expected full page");
        for r in &records {
            let id = r["id"].as_i64().expect("row id");
            if let Some(prev) = collected.last() {
                assert!(id < *prev, "ids must strictly descend across pages");
            }
            collected.push(id);
        }
        before_id = v["next_before_id"].as_i64();
    }
    assert_eq!(collected.len(), 6);

    // FTS search finds exactly the row carrying the distinctive token.
    let v: serde_json::Value = bob
        .get(&format!("/history/search?scope=topic:{topic}&q=needle0003"))
        .await
        .json()
        .await
        .expect("search json");
    assert_eq!(v["ok"], true);
    assert_eq!(v["count"], 1, "search must hit exactly one row: {v}");
    let payload = BASE64
        .decode(v["records"][0]["payload"].as_str().expect("payload"))
        .expect("b64");
    assert!(String::from_utf8_lossy(&payload).contains("hist-seq-0003"));

    // Stats reflect rows + retention bounds.
    let v: serde_json::Value = bob.get("/history/stats").await.json().await.expect("stats");
    assert_eq!(v["ok"], true);
    assert!(v["stats"]["rows"].as_i64().unwrap_or(0) >= 6);
    assert!(v["retention"]["max_bytes"].as_u64().unwrap_or(0) > 0);

    // Diagnostics counters are live.
    let v: serde_json::Value = bob
        .get("/diagnostics/history")
        .await
        .json()
        .await
        .expect("diag");
    assert_eq!(v["enabled"], true);
    assert!(v["written_total"].as_u64().unwrap_or(0) >= 6);

    // Purge is scope-local and complete.
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!(
            "http://{}/history?scope=topic:{topic}",
            bob.api_addr
        ))
        .header("Authorization", format!("Bearer {}", bob.api_token))
        .send()
        .await
        .expect("purge send");
    assert!(resp.status().is_success(), "purge failed");
    let v: serde_json::Value = resp.json().await.expect("purge json");
    assert!(v["removed"].as_u64().unwrap_or(0) >= 6);
    assert_eq!(
        history_count(bob, &topic).await,
        0,
        "scope must be empty after purge"
    );
}

/// The design's dedicated seam test: subscribe-with-backfill DURING active
/// publishing → stored frames, `live` marker, live frames — **no gap, no
/// duplicate** across the marker.
#[tokio::test]
#[ignore]
async fn ws_backfill_then_live_no_gap_no_dup() {
    let topic = unique_topic();
    let pair = cluster::pair_with_extra_config(&extra_config(&topic)).await;
    let (alice, bob) = (&pair.alice, &pair.bob);

    let resp = bob
        .post("/subscribe", serde_json::json!({ "topic": &topic }))
        .await;
    assert!(resp.status().is_success());
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Seed the store with 5 messages before the WS client exists.
    for seq in 0..5 {
        publish(alice, &topic, seq).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    wait_for_rows(bob, &topic, 5, Duration::from_secs(30)).await;

    // Keep publishing concurrently while the WS client backfills.
    let alice_addr = alice.api_addr.clone();
    let alice_token = alice.api_token.clone();
    let pub_topic = topic.clone();
    let publisher = tokio::spawn(async move {
        let client = reqwest::Client::new();
        for seq in 5..15 {
            let payload = format!("hist-seq-{seq:04} needle{seq:04}");
            let _ = client
                .post(format!("http://{alice_addr}/publish"))
                .header("Authorization", format!("Bearer {alice_token}"))
                .json(&serde_json::json!({
                    "topic": pub_topic,
                    "payload": BASE64.encode(payload.as_bytes()),
                }))
                .send()
                .await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    });

    // WS auth accepts session tokens via `?token=`.
    let session = bob.session_token().await;
    let url = format!("ws://{}/ws?token={session}", bob.api_addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("ws connect");
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::json!({
            "type": "subscribe",
            "topics": [&topic],
            "backfill": { "limit": 100 },
        })
        .to_string(),
    ))
    .await
    .expect("send subscribe");

    let mut before_marker: Vec<usize> = Vec::new();
    let mut after_marker: Vec<usize> = Vec::new();
    let mut saw_marker = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    while tokio::time::Instant::now() < deadline {
        let frame = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
        let Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) = frame else {
            continue;
        };
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        match v["type"].as_str() {
            Some("live") if v["topic"].as_str() == Some(topic.as_str()) => saw_marker = true,
            Some("message") if v["topic"].as_str() == Some(topic.as_str()) => {
                let bytes = BASE64
                    .decode(v["payload"].as_str().unwrap_or_default())
                    .unwrap_or_default();
                let text = String::from_utf8_lossy(&bytes).to_string();
                let Some(seq) = text
                    .split("hist-seq-")
                    .nth(1)
                    .and_then(|s| s.get(..4))
                    .and_then(|s| s.parse::<usize>().ok())
                else {
                    continue; // foreign traffic on the topic — not ours
                };
                if saw_marker {
                    after_marker.push(seq);
                } else {
                    before_marker.push(seq);
                }
            }
            _ => {}
        }
        if after_marker.len() >= 6 {
            break;
        }
    }
    publisher.await.expect("publisher");

    assert!(saw_marker, "live marker never arrived");
    assert!(
        before_marker.len() >= 5,
        "backfill must replay the seeded rows, got {before_marker:?}"
    );
    // No duplicate across the marker.
    let mut seen = std::collections::HashSet::new();
    for s in before_marker.iter().chain(after_marker.iter()) {
        assert!(seen.insert(*s), "duplicate seq {s} across the live marker");
    }
    // No gap: everything observed forms a contiguous prefix 0..=max.
    let max = *seen.iter().max().expect("nonempty");
    for s in 0..=max {
        assert!(seen.contains(&s), "gap at seq {s} (observed up to {max})");
    }
    // Backfill frames are stored rows (oldest→newest ordering).
    let sorted: Vec<usize> = {
        let mut v = before_marker.clone();
        v.sort_unstable();
        v
    };
    assert_eq!(sorted, before_marker, "backfill must be oldest→newest");
}

/// Backpressure smoke: a 2,000-message burst neither wedges the daemon nor
/// loses accounting — writes + drops + dedupes are all counted, and a
/// concurrent DM path stays responsive.
#[tokio::test]
#[ignore]
async fn history_backpressure_smoke() {
    let topic = unique_topic();
    let pair = cluster::pair_with_extra_config(&extra_config(&topic)).await;
    let (alice, bob) = (&pair.alice, &pair.bob);

    let resp = bob
        .post("/subscribe", serde_json::json!({ "topic": &topic }))
        .await;
    assert!(resp.status().is_success());
    tokio::time::sleep(Duration::from_secs(2)).await;

    let client = reqwest::Client::new();
    for seq in 0..2000usize {
        let payload = format!("burst-{seq}");
        let _ = client
            .post(format!("http://{}/publish", alice.api_addr))
            .header("Authorization", format!("Bearer {}", alice.api_token))
            .json(&serde_json::json!({
                "topic": &topic,
                "payload": BASE64.encode(payload.as_bytes()),
            }))
            .send()
            .await;
    }

    // Concurrent DM latency must stay sane during the burst tail.
    let bob_agent = {
        let v: serde_json::Value = bob.get("/agent").await.json().await.expect("agent");
        v["agent_id"].as_str().expect("agent_id").to_string()
    };
    let mut worst = Duration::ZERO;
    for i in 0..5 {
        let start = std::time::Instant::now();
        let resp = alice
            .post(
                "/direct/send",
                serde_json::json!({
                    "agent_id": bob_agent,
                    "payload": BASE64.encode(format!("dm-under-burst-{i}").as_bytes()),
                }),
            )
            .await;
        assert!(resp.status().is_success(), "DM under burst failed");
        worst = worst.max(start.elapsed());
    }
    assert!(
        worst < Duration::from_secs(10),
        "DM p_max under burst too slow: {worst:?}"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    let v: serde_json::Value = bob
        .get("/diagnostics/history")
        .await
        .json()
        .await
        .expect("diag");
    assert_eq!(v["enabled"], true);
    let written = v["written_total"].as_u64().unwrap_or(0);
    let dropped = v["dropped_full"].as_u64().unwrap_or(0);
    let dedup = v["dedup_hits"].as_u64().unwrap_or(0);
    assert!(written > 0, "burst must produce writes: {v}");
    // Accounting sanity: everything the recorder saw is in exactly one
    // bucket; gossip loss means the sum may be below 2000, never above
    // (plus the handful of DM/system rows).
    assert!(
        written + dropped + dedup <= 2100,
        "counter sum exceeds published volume: {v}"
    );
}
