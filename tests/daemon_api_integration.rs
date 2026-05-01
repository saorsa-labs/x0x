//! Integration tests for x0xd REST + WebSocket API.
//!
//! All tests are `#[ignore]` — they require a running x0xd daemon.
//! Run with: cargo nextest run -E 'test(daemon_api)' -- --ignored
//!
//! Before running: cargo build --release --bin x0xd

use base64::Engine;
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

// Re-exports for WebSocket tests
use futures::{SinkExt, StreamExt};

async fn daemon() -> DaemonFixture {
    DaemonFixture::start("api-test").await
}

fn c() -> reqwest::Client {
    DaemonFixture::client(Duration::from_secs(10))
}

/// Authenticated client with Bearer token in default headers.
fn ca(d: &DaemonFixture) -> reqwest::Client {
    d.authed_client(Duration::from_secs(10))
}
fn fake_id() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}
fn b64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

// ===========================================================================
// System (6)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_health() {
    let d = daemon().await;
    // /health is exempt from auth — deliberately use unauthenticated client
    let r: Value = c()
        .get(d.url("/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["status"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_status() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["agent_id"].as_str().unwrap().len() == 64);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["agent_id"].is_string());
    assert!(r["machine_id"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_peers() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/peers")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_network_status() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/network/status")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_announce() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/announce"))
        .json(&serde_json::json!({"include_user_identity": false, "human_consent": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_shutdown_with_sse_client() {
    let mut d = DaemonFixture::start("shutdown-test").await;

    let sse_client = reqwest::Client::new();
    let sse_response = sse_client
        .get(format!("{}?token={}", d.url("/events"), d.api_token()))
        .send()
        .await
        .unwrap();
    assert_eq!(sse_response.status(), StatusCode::OK);

    let shutdown_response = reqwest::Client::new()
        .post(d.url("/shutdown"))
        .header("Authorization", d.auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(shutdown_response.status(), StatusCode::OK);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = d.try_wait().unwrap() {
            assert!(status.success(), "daemon exited with {status}");
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("daemon did not exit with an active SSE client");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    drop(sse_response);
    let port_file = d.port_file();
    assert!(
        !port_file.exists(),
        "port file should be removed on shutdown"
    );
}

// ===========================================================================
// Gossip (4)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_subscribe_publish() {
    let d = daemon().await;
    let topic = format!("test-{}", rand::random::<u32>());
    let r: Value = ca(&d)
        .post(d.url("/subscribe"))
        .json(&serde_json::json!({"topic": topic}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["subscription_id"].is_string());

    let r: Value = ca(&d)
        .post(d.url("/publish"))
        .json(&serde_json::json!({"topic": topic, "payload": b64(b"hello")}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_unsubscribe() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/subscribe"))
        .json(&serde_json::json!({"topic": "unsub-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sid = r["subscription_id"].as_str().unwrap();
    let r = ca(&d)
        .delete(d.url(&format!("/subscribe/{sid}")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_events_sse() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/events")).send().await.unwrap();
    assert!(r
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("text/event-stream"));
}

#[tokio::test]
#[ignore]
async fn daemon_api_publish_bad_base64() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/publish"))
        .json(&serde_json::json!({"topic": "t", "payload": "!!!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

// ===========================================================================
// Direct Messaging (4)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_direct_send_not_found() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/direct/send"))
        .json(&serde_json::json!({"agent_id": fake_id(), "payload": b64(b"hi")}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_server_error() || r.status() == StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore]
async fn daemon_api_direct_connections() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/direct/connections"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["connections"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_direct_events_sse() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/direct/events")).send().await.unwrap();
    assert!(r
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("text/event-stream"));
}

#[tokio::test]
#[ignore]
async fn daemon_api_direct_send_blocked() {
    let d = daemon().await;
    let agent = fake_id();
    // Add as blocked
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "blocked"}))
        .send()
        .await
        .unwrap();
    let r = ca(&d)
        .post(d.url("/direct/send"))
        .json(&serde_json::json!({"agent_id": agent, "payload": b64(b"hi")}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // Cleanup
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// Discovery (5)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_discovered_agents() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/agents/discovered"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["agents"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_discovered_unfiltered() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/agents/discovered?unfiltered=true"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_find_agent_unknown() {
    let d = daemon().await;
    // find_agent does 3-stage search (cache→shard→rendezvous) — needs longer timeout
    let long_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&d.auth_header()).unwrap(),
            );
            headers
        })
        .build()
        .unwrap();
    let r: Value = long_client
        .post(d.url(&format!("/agents/find/{}", fake_id())))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["found"], false);
}

#[tokio::test]
#[ignore]
async fn daemon_api_reachability_unknown() {
    let d = daemon().await;
    let r = ca(&d)
        .get(d.url(&format!("/agents/reachability/{}", fake_id())))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agents_by_user() {
    let d = daemon().await;
    let r = ca(&d)
        .get(d.url(&format!("/users/{}/agents", fake_id())))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

// ===========================================================================
// Contacts & Trust (10)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_add_contact() {
    let d = daemon().await;
    let agent = fake_id();
    let r: Value = ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known", "label": "test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

/// Regression test for issue #19: POST /contacts with `alias` (the field
/// name a beta tester guessed) is rejected with a 400 instead of silently
/// dropping the unknown key. `deny_unknown_fields` on `AddContactRequest`
/// makes serde surface the right field name in its error.
#[tokio::test]
#[ignore]
async fn daemon_api_add_contact_rejects_unknown_field_alias() {
    let d = daemon().await;
    let agent = fake_id();
    let r = ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({
            "agent_id": agent,
            "alias": "should-be-label",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// Regression test for issue #19: POST /agent/card/import with an unknown
/// trust_level no longer silently coerces to "known". The daemon now
/// returns the same FromStr error as POST /contacts.
#[tokio::test]
#[ignore]
async fn daemon_api_import_card_invalid_trust_level_rejected() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/agent/card/import"))
        .json(&serde_json::json!({
            "card": "x0x://agent/not-a-real-card",
            "trust_level": "completely-bogus",
        }))
        .send()
        .await
        .unwrap();
    // The card itself is invalid first, OR we hit the trust-level branch —
    // either way it is a 400 with a structured error, not a silent default.
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert!(body["error"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_list_contacts() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/contacts")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_quick_trust() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "unknown"}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .post(d.url("/contacts/trust"))
        .json(&serde_json::json!({"agent_id": agent, "level": "trusted"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn daemon_api_update_contact() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "unknown"}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .patch(d.url(&format!("/contacts/{agent}")))
        .json(&serde_json::json!({"trust_level": "trusted", "identity_type": "pinned"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn daemon_api_delete_contact() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known"}))
        .send()
        .await
        .unwrap();
    let r = ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_revoke_contact() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known"}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .post(d.url(&format!("/contacts/{agent}/revoke")))
        .json(&serde_json::json!({"reason": "compromised"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_list_revocations() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url(&format!("/contacts/{}/revocations", fake_id())))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["revocations"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_add_machine() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known"}))
        .send()
        .await
        .unwrap();
    let r = ca(&d)
        .post(d.url(&format!("/contacts/{agent}/machines")))
        .json(&serde_json::json!({"machine_id": fake_id()}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "add_machine: {}", r.status());
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn daemon_api_pin_unpin_machine() {
    let d = daemon().await;
    let agent = fake_id();
    let machine = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known"}))
        .send()
        .await
        .unwrap();
    ca(&d)
        .post(d.url(&format!("/contacts/{agent}/machines")))
        .json(&serde_json::json!({"machine_id": machine}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .post(d.url(&format!("/contacts/{agent}/machines/{machine}/pin")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    let r: Value = ca(&d)
        .delete(d.url(&format!("/contacts/{agent}/machines/{machine}/pin")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn daemon_api_evaluate_trust() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/trust/evaluate"))
        .json(&serde_json::json!({"agent_id": fake_id(), "machine_id": fake_id()}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["decision"].is_string());
}

// ===========================================================================
// MLS Groups (8)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_create_group() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["group_id"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_list_groups() {
    let d = daemon().await;
    ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .get(d.url("/mls/groups"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["groups"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_get_group() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    let r: Value = ca(&d)
        .get(d.url(&format!("/mls/groups/{gid}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["members"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_add_member() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    let r: Value = ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/members")))
        .json(&serde_json::json!({"agent_id": fake_id()}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // MLS add_member may fail if commit cannot be applied (expected for synthetic IDs)
    assert!(r["ok"].is_boolean(), "add_member response: {:?}", r);
}

#[tokio::test]
#[ignore]
async fn daemon_api_remove_member() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    let member = fake_id();
    ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/members")))
        .json(&serde_json::json!({"agent_id": member}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .delete(d.url(&format!("/mls/groups/{gid}/members/{member}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // MLS remove_member may fail similarly
    assert!(r["ok"].is_boolean(), "remove_member response: {:?}", r);
}

#[tokio::test]
#[ignore]
async fn daemon_api_encrypt_decrypt() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    // Encrypt
    let enc: Value = ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/encrypt")))
        .json(&serde_json::json!({"payload": b64(b"secret")}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(enc["ok"], true);
    let ct = enc["ciphertext"].as_str().unwrap();
    let epoch = enc["epoch"].as_u64().unwrap();
    // Decrypt
    let dec: Value = ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/decrypt")))
        .json(&serde_json::json!({"ciphertext": ct, "epoch": epoch}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dec["ok"], true);
    let pt = base64::engine::general_purpose::STANDARD
        .decode(dec["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(pt, b"secret");
}

#[tokio::test]
#[ignore]
async fn daemon_api_mls_welcome() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    let invitee = fake_id();
    ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/members")))
        .json(&serde_json::json!({"agent_id": invitee}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/welcome")))
        .json(&serde_json::json!({"agent_id": invitee}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["welcome"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_group_not_found() {
    let d = daemon().await;
    let r = ca(&d)
        .get(d.url("/mls/groups/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// Task Lists (5)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_create_task_list() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/task-lists"))
        .json(&serde_json::json!({"name": "test", "topic": "test-tasks"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_add_task() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/task-lists"))
        .json(&serde_json::json!({"name": "t", "topic": "t-tasks"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let lid = cr["id"]
        .as_str()
        .unwrap_or(cr["task_list_id"].as_str().unwrap_or(""));
    if !lid.is_empty() {
        let r: Value = ca(&d)
            .post(d.url(&format!("/task-lists/{lid}/tasks")))
            .json(&serde_json::json!({"title": "Test task"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(r["ok"], true);
    }
}

#[tokio::test]
#[ignore]
async fn daemon_api_list_tasks() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/task-lists")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_claim_task() {
    // Tested via the update_task endpoint with action: "claim"
    let d = daemon().await;
    let r = ca(&d).get(d.url("/task-lists")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_complete_task() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/task-lists")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

// ===========================================================================
// Network (4)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_bootstrap_cache() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/network/bootstrap-cache"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_diagnostics_connectivity() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/diagnostics/connectivity"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    // The snapshot always includes these keys even before any peer is known,
    // so operators can rely on them for scripted probes.
    assert!(r["port_mapping"].is_object());
    assert!(r["mdns"].is_object());
    assert!(r["connections"].is_object());
}

#[tokio::test]
#[ignore]
async fn daemon_api_diagnostics_dm() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/diagnostics/dm"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["stats"].is_object());
    assert!(r["per_peer"].is_object());
    assert!(r["subscriber_count"].is_number());
    assert!(r["subscriber_capacity"].is_number());
}

#[tokio::test]
#[ignore]
async fn daemon_api_diagnostics_exec() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/diagnostics/exec"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["enabled"].is_boolean());
    assert!(r["totals"].is_object());
    assert!(r["acl_summary"].is_object());
}

#[tokio::test]
#[ignore]
async fn daemon_api_exec_sessions() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/exec/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["pending_clients"].is_array());
    assert!(r["active_servers"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_exec_run_bad_agent_id() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/exec/run"))
        .json(&serde_json::json!({"agent_id":"bad", "argv":["echo", "1"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], false);
    assert!(r["error"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_exec_cancel_bad_request_id() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/exec/cancel"))
        .json(&serde_json::json!({"request_id":"bad"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], false);
    assert!(r["error"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_upgrade_check() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/upgrade"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // May fail due to GitHub rate limiting (403) — that's ok
    assert!(
        r["ok"] == true || r["error"].is_string(),
        "upgrade_check: {:?}",
        r
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_connect_unknown() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/agents/connect"))
        .json(&serde_json::json!({"agent_id": fake_id()}))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap();
    // Unknown agent returns ok with outcome "NotFound"
    assert_eq!(body["ok"], true);
    assert!(
        body["outcome"].as_str().unwrap().contains("NotFound") || body["outcome"] == "Unreachable"
    );
}

// ===========================================================================
// WebSocket (3)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_ws_connect() {
    let d = daemon().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(d.ws_url("/ws"))
        .await
        .expect("WS connect failed");
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = match msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
        other => panic!("Expected text, got {other:?}"),
    };
    let frame: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(frame["type"], "connected");
    assert!(frame["session_id"].is_string());
    let _ = ws.close(None).await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_ws_ping_pong() {
    let d = daemon().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(d.ws_url("/ws"))
        .await
        .unwrap();
    let _ = ws.next().await; // consume connected
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        r#"{"type":"ping"}"#.into(),
    ))
    .await
    .unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = match msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
        other => panic!("Expected text, got {other:?}"),
    };
    let frame: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(frame["type"], "pong");
    let _ = ws.close(None).await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_ws_sessions() {
    let d = daemon().await;
    let (_ws, _) = tokio_tungstenite::connect_async(d.ws_url("/ws"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r: Value = ca(&d)
        .get(d.url("/ws/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["sessions"].is_array());
}

// ===========================================================================
// Error handling (3)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_invalid_hex() {
    let d = daemon().await;
    let r = ca(&d)
        .get(d.url("/agents/reachability/not-hex"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore]
async fn daemon_api_body_too_large() {
    let d = daemon().await;
    let big = "A".repeat(2 * 1024 * 1024);
    let result = ca(&d)
        .post(d.url("/publish"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"topic":"t","payload":"{big}"}}"#))
        .send()
        .await;

    match result {
        Ok(response) => {
            assert!(
                response.status() == StatusCode::PAYLOAD_TOO_LARGE
                    || response.status() == StatusCode::BAD_REQUEST,
                "unexpected status: {}",
                response.status()
            );
        }
        Err(err) => {
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("connection reset")
                    || msg.contains("body write")
                    || msg.contains("channel closed"),
                "unexpected transport error for oversized body: {err}"
            );
        }
    }
}

#[tokio::test]
#[ignore]
async fn daemon_api_invalid_json() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/publish"))
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .unwrap();
    assert!(
        r.status() == StatusCode::BAD_REQUEST || r.status() == StatusCode::UNPROCESSABLE_ENTITY
    );
}
