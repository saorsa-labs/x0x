//! Issue #310 — public group message fan-out is a race, not a sequence.
//!
//! When direct-unicast fails (timeout or `recipient key material unavailable`)
//! the sender used to burn the ~24s DM retry budget before gossip carry
//! landed (~44s e2e). Gossip topic publish must start without waiting for
//! unicast to finish. These tests inject that unicast failure on ONE daemon
//! and assert the other has the row in < 5s, plus the raced-publish counter.
//!
//! Roster/control events (#333 family) are deliberately not exercised here.
//!
//! All tests are `#[ignore]` — they spawn real x0xd daemons. Run with:
//!   cargo nextest run --test named_group_public_message_race --run-ignored all
//!
//! Before running: cargo build --bin x0xd

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use std::time::{Duration, Instant};

#[path = "harness/src/cluster.rs"]
mod cluster;

use cluster::{pair, pair_with_alice_env, pair_with_bob_env, AgentInstance};

fn authed(d: &AgentInstance) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", d.api_token))
            .expect("auth header value"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(20))
        .build()
        .expect("authed reqwest client")
}

async fn wait_until<F, Fut>(timeout: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn create_public_open_group(d: &AgentInstance, name: &str) -> String {
    let resp: Value = authed(d)
        .post(d.url("/groups"))
        .json(&serde_json::json!({ "name": name, "preset": "public_open" }))
        .send()
        .await
        .expect("POST /groups")
        .json()
        .await
        .expect("create group json");
    assert_eq!(resp["ok"], true, "create group failed: {resp:?}");
    resp["group_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no group_id in create response: {resp:?}"))
        .to_string()
}

async fn send_message(d: &AgentInstance, group_id: &str, body: &str) -> Value {
    authed(d)
        .post(d.url(&format!("/groups/{group_id}/send")))
        .json(&serde_json::json!({ "body": body }))
        .send()
        .await
        .expect("POST /groups/:id/send")
        .json()
        .await
        .expect("send json")
}

async fn get_messages(d: &AgentInstance, group_id: &str) -> Vec<Value> {
    let resp: Value = authed(d)
        .get(d.url(&format!("/groups/{group_id}/messages")))
        .send()
        .await
        .expect("GET /groups/:id/messages")
        .json()
        .await
        .expect("GET messages json");
    resp["messages"].as_array().cloned().unwrap_or_default()
}

async fn gossip_raced_unicast_count(d: &AgentInstance, group_id: &str) -> u64 {
    let resp: Value = authed(d)
        .get(d.url("/diagnostics/groups"))
        .send()
        .await
        .expect("GET /diagnostics/groups")
        .json()
        .await
        .expect("diagnostics json");
    resp["groups"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|g| g["group_id"].as_str() == Some(group_id))
        .and_then(|g| g["public_message_gossip_raced_unicast"].as_u64())
        .unwrap_or(0)
}

async fn bob_joins_via_invite(
    alice: &AgentInstance,
    group_id: &str,
    bob: &AgentInstance,
) -> String {
    let invite_resp: Value = authed(alice)
        .post(alice.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("POST /groups/:id/invite")
        .json()
        .await
        .expect("create invite json");
    assert_eq!(
        invite_resp["ok"], true,
        "create invite failed: {invite_resp:?}"
    );
    let invite_link = invite_resp["invite_link"]
        .as_str()
        .unwrap_or_else(|| panic!("no invite_link in: {invite_resp:?}"))
        .to_string();

    let join_resp: Value = authed(bob)
        .post(bob.url("/groups/join"))
        .json(&serde_json::json!({ "invite": invite_link }))
        .send()
        .await
        .expect("POST /groups/join")
        .json()
        .await
        .expect("bob join json");
    assert_eq!(join_resp["ok"], true, "bob join failed: {join_resp:?}");
    join_resp["group_id"]
        .as_str()
        .unwrap_or(group_id)
        .to_string()
}

async fn wait_for_membership(d: &AgentInstance, group_id: &str, agent_id: &str) -> bool {
    wait_until(Duration::from_secs(30), || async {
        let resp: Value = authed(d)
            .get(d.url(&format!("/groups/{group_id}/members")))
            .send()
            .await
            .expect("GET /groups/:id/members")
            .json()
            .await
            .expect("members json");
        resp["members"].as_array().is_some_and(|arr| {
            arr.iter().any(|m| {
                m["agent_id"].as_str() == Some(agent_id) && m["state"].as_str() == Some("active")
            })
        })
    })
    .await
}

async fn settle_two_member_public_group(
    alice: &AgentInstance,
    bob: &AgentInstance,
    name: &str,
) -> (String, String) {
    let group_id = create_public_open_group(alice, name).await;
    let bob_group_id = bob_joins_via_invite(alice, &group_id, bob).await;
    let bob_id = bob.agent_id().await;
    assert!(
        wait_for_membership(alice, &group_id, &bob_id).await,
        "Alice never saw Bob as an active member; ingest would drop the post"
    );
    assert!(
        wait_for_membership(bob, &bob_group_id, &bob_id).await,
        "Bob's daemon never recognised Bob as active; his send would 403"
    );
    (group_id, bob_group_id)
}

async fn assert_receiver_has_body_within(
    receiver: &AgentInstance,
    group_id: &str,
    body: &str,
    bound: Duration,
) {
    let started = Instant::now();
    let arrived = wait_until(bound, || async {
        get_messages(receiver, group_id)
            .await
            .iter()
            .any(|m| m["body"].as_str() == Some(body))
    })
    .await;
    let elapsed = started.elapsed();
    assert!(
        arrived,
        "receiver missing {body:?} within {bound:?} (elapsed {elapsed:?}); \
         #310 requires gossip carry without the ~24s unicast budget. messages={:?}",
        get_messages(receiver, group_id).await
    );
    assert!(
        elapsed < bound,
        "delivery took {elapsed:?}, which must stay under {bound:?}"
    );
}

/// Injected unicast timeout must not delay gossip: Bob has Alice's row in < 5s
/// and Alice's diagnostics record that gossip started while unicast was still
/// in flight. A sequential unicast-then-gossip path would miss this bound.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn injected_unicast_timeout_delivers_via_gossip_under_five_seconds() {
    let pair = pair_with_alice_env(&[("X0X_TEST_GROUP_PUBLIC_UNICAST_FAIL", "timeout")]).await;
    let (alice, bob) = (&pair.alice, &pair.bob);
    let (group_id, bob_group_id) =
        settle_two_member_public_group(alice, bob, "issue-310-timeout").await;

    let body = format!("timeout-inject-{}", rand::random::<u16>());
    let sent = send_message(alice, &group_id, &body).await;
    assert_eq!(sent["ok"], true, "alice send failed: {sent:?}");
    assert!(
        sent["msg_id"].as_str().is_some_and(|id| id.len() == 64),
        "200 + msg_id contract: {sent:?}"
    );

    assert_receiver_has_body_within(bob, &bob_group_id, &body, Duration::from_secs(5)).await;

    let raced = gossip_raced_unicast_count(alice, &group_id).await;
    assert!(
        raced >= 1,
        "alice must record public_message_gossip_raced_unicast so the test \
         can tell a race from a 24s sequential fallback that later succeeded; \
         counter={raced}"
    );
}

/// `recipient key material unavailable` is non-retryable on this path: skip
/// the 8s+8s retry and let the already-started gossip carry land in < 5s.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn injected_key_unavailable_skips_retry_and_gossips_under_five_seconds() {
    let pair =
        pair_with_alice_env(&[("X0X_TEST_GROUP_PUBLIC_UNICAST_FAIL", "key_unavailable")]).await;
    let (alice, bob) = (&pair.alice, &pair.bob);
    let (group_id, bob_group_id) =
        settle_two_member_public_group(alice, bob, "issue-310-key-unavail").await;

    let body = format!("key-unavail-{}", rand::random::<u16>());
    let sent = send_message(alice, &group_id, &body).await;
    assert_eq!(sent["ok"], true, "alice send failed: {sent:?}");

    assert_receiver_has_body_within(bob, &bob_group_id, &body, Duration::from_secs(5)).await;

    let raced = gossip_raced_unicast_count(alice, &group_id).await;
    assert!(
        raced >= 1,
        "gossip must still start when unicast is classified non-retryable; \
         counter={raced}"
    );
}

/// Healthy unicast is still the low-latency lane: both directions deliver
/// without waiting on a gossip ACK, and we do not force `require_gossip`.
/// This is the no-regression counterpart to the injected-failure tests.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn healthy_unicast_delivers_both_directions_without_gossip_ack_wait() {
    let pair = pair().await;
    let (alice, bob) = (&pair.alice, &pair.bob);
    let (group_id, bob_group_id) =
        settle_two_member_public_group(alice, bob, "issue-310-healthy").await;

    let alice_body = format!("alice-healthy-{}", rand::random::<u16>());
    let alice_sent = send_message(alice, &group_id, &alice_body).await;
    assert_eq!(
        alice_sent["ok"], true,
        "alice healthy send failed: {alice_sent:?}"
    );
    assert_receiver_has_body_within(bob, &bob_group_id, &alice_body, Duration::from_secs(5)).await;

    let bob_body = format!("bob-healthy-{}", rand::random::<u16>());
    let bob_sent = send_message(bob, &bob_group_id, &bob_body).await;
    assert_eq!(
        bob_sent["ok"], true,
        "bob healthy send failed: {bob_sent:?}"
    );
    assert_receiver_has_body_within(alice, &group_id, &bob_body, Duration::from_secs(5)).await;
}

/// Bob-as-sender mirror of the timeout inject: one acceptance-style reverse
/// direction, not a soak. Proves the race is not authority-side only.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn injected_unicast_timeout_reverse_direction_under_five_seconds() {
    let pair = pair_with_bob_env(&[("X0X_TEST_GROUP_PUBLIC_UNICAST_FAIL", "timeout")]).await;
    let (alice, bob) = (&pair.alice, &pair.bob);
    let (group_id, bob_group_id) =
        settle_two_member_public_group(alice, bob, "issue-310-timeout-rev").await;

    let body = format!("timeout-reverse-{}", rand::random::<u16>());
    let sent = send_message(bob, &bob_group_id, &body).await;
    assert_eq!(sent["ok"], true, "bob send failed: {sent:?}");
    assert_receiver_has_body_within(alice, &group_id, &body, Duration::from_secs(5)).await;

    let raced = gossip_raced_unicast_count(bob, &bob_group_id).await;
    assert!(
        raced >= 1,
        "bob must record the raced-gossip counter on reverse send; counter={raced}"
    );
}
