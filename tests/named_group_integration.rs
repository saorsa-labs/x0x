//! Integration tests for Named Groups (invite/join lifecycle).
//!
//! All tests are `#[ignore]` — they require a running x0xd daemon.
//! Run with: cargo nextest run -E 'test(named_group)' -- --ignored
//!
//! Before running: cargo build --release --bin x0xd

use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

#[path = "harness/src/cluster.rs"]
mod cluster;
#[path = "harness/src/daemon.rs"]
mod daemon;

use cluster::{pair, AgentInstance};
use daemon::DaemonFixture;

async fn daemon() -> DaemonFixture {
    DaemonFixture::start("ng-test").await
}

/// Authenticated client with Bearer token in default headers.
fn authed_client(d: &DaemonFixture) -> reqwest::Client {
    d.authed_client(Duration::from_secs(10))
}

// ===========================================================================
// Helper: create a named group and return (group_id, response_json)
// ===========================================================================

async fn create_group(
    d: &DaemonFixture,
    name: &str,
    description: &str,
    display_name: Option<&str>,
) -> (String, Value) {
    let mut body = serde_json::json!({
        "name": name,
        "description": description,
    });
    if let Some(dn) = display_name {
        body["display_name"] = serde_json::json!(dn);
    }

    let r: Value = authed_client(d)
        .post(d.url("/groups"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let group_id = r["group_id"].as_str().unwrap_or_default().to_string();

    (group_id, r)
}

fn fake_agent_id(fill: u8) -> String {
    hex::encode([fill; 32])
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
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn group_state_hash(d: &AgentInstance, group_id: &str) -> Option<String> {
    let resp = d.get(&format!("/groups/{group_id}/state")).await;
    if !resp.status().is_success() {
        return None;
    }
    let body: Value = resp.json().await.unwrap_or_default();
    body["state_hash"].as_str().map(ToString::to_string)
}

// ===========================================================================
// 1. Create Named Group
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_create() {
    let d = daemon().await;
    let (group_id, r) = create_group(&d, "Alpha Team", "Our first group", Some("Alice")).await;

    assert_eq!(r["ok"], true, "create response: {r:?}");
    assert!(!group_id.is_empty(), "group_id should be non-empty");
    assert_eq!(r["name"], "Alpha Team");
    assert!(r["chat_topic"].is_string(), "chat_topic should be returned");

    // Cleanup
    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 2. List Groups
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_list() {
    let d = daemon().await;
    let (g1, _) = create_group(&d, "List-Group-A", "", None).await;
    let (g2, _) = create_group(&d, "List-Group-B", "", None).await;

    let r: Value = authed_client(&d)
        .get(d.url("/groups"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true);
    let groups = r["groups"].as_array().unwrap();
    assert!(
        groups.len() >= 2,
        "expected at least 2 groups, got {}",
        groups.len()
    );

    let names: Vec<&str> = groups.iter().filter_map(|g| g["name"].as_str()).collect();
    assert!(
        names.contains(&"List-Group-A"),
        "List-Group-A not found in {names:?}"
    );
    assert!(
        names.contains(&"List-Group-B"),
        "List-Group-B not found in {names:?}"
    );

    // Cleanup
    for gid in [&g1, &g2] {
        authed_client(&d)
            .delete(d.url(&format!("/groups/{gid}")))
            .send()
            .await
            .unwrap();
    }
}

// ===========================================================================
// 3. Group Info
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_info() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "Info Group", "detailed info", Some("Creator")).await;

    let r: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true, "get group info: {r:?}");
    assert_eq!(r["name"], "Info Group");
    assert_eq!(r["description"], "detailed info");
    assert!(r["creator"].is_string(), "creator should be present");
    assert!(r["created_at"].is_u64(), "created_at should be a timestamp");
    assert!(r["chat_topic"].is_string(), "chat_topic should be present");
    assert!(
        r["metadata_topic"].is_string(),
        "metadata_topic should be present"
    );
    assert!(r["members"].is_array(), "members should be an array");

    // The creator should appear in members with their display name
    let members = r["members"].as_array().unwrap();
    let creator_member = members.iter().find(|m| m["display_name"] == "Creator");
    assert!(
        creator_member.is_some(),
        "creator 'Creator' not found in members: {members:?}"
    );

    // Cleanup
    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 4. Named-group members endpoint
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_members_endpoint() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "Members Group", "", Some("Creator")).await;

    let r: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}/members")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true, "members response: {r:?}");
    assert!(r["member_count"].as_u64().unwrap_or(0) >= 1);
    let members = r["members"].as_array().unwrap();
    assert!(members.iter().any(|m| m["display_name"] == "Creator"));

    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 5. Add/remove named-group member (local roster semantics)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_add_remove_member_local() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "Roster Group", "", Some("Owner")).await;
    let fake_member = fake_agent_id(0x42);

    let add_r: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/members")))
        .json(&serde_json::json!({
            "agent_id": fake_member,
            "display_name": "Remote Bob"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(add_r["ok"], true, "add member response: {add_r:?}");

    let members_r: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}/members")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let members = members_r["members"].as_array().unwrap();
    assert!(members.iter().any(|m| m["agent_id"] == fake_member));
    assert!(members.iter().any(|m| m["display_name"] == "Remote Bob"));

    let del_r: Value = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}/members/{fake_member}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(del_r["ok"], true, "remove member response: {del_r:?}");

    let members_after: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}/members")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let after = members_after["members"].as_array().unwrap();
    assert!(!after.iter().any(|m| m["agent_id"] == fake_member));

    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 6. Generate Invite
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_generate_invite() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "Invite Group", "", None).await;

    let r: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({"expiry_secs": 3600}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true, "create invite: {r:?}");
    let invite_link = r["invite_link"].as_str().unwrap();
    assert!(
        invite_link.starts_with("x0x://invite/"),
        "invite_link should start with x0x://invite/, got: {invite_link}"
    );
    assert_eq!(r["group_id"], group_id);
    assert_eq!(r["group_name"], "Invite Group");
    assert!(r["expires_at"].is_u64(), "expires_at should be present");

    // Cleanup
    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 5. Join via Invite
// ===========================================================================

/// Since both alice and bob share a single daemon in this test suite,
/// we test the join flow by: (a) creating a group, (b) generating an invite,
/// (c) leaving the group, and (d) joining back via the invite link.
/// This exercises the full invite/join codepath on a single daemon.
#[tokio::test]
#[ignore]
async fn named_group_join_via_invite() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "Join Test Group", "", Some("Alice")).await;

    // Generate invite
    let invite_resp: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({"expiry_secs": 3600}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let invite_link = invite_resp["invite_link"].as_str().unwrap().to_string();

    // Leave the group first so we can rejoin
    let leave_r = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(leave_r.status(), StatusCode::OK);

    // Join via invite
    let join_r: Value = authed_client(&d)
        .post(d.url("/groups/join"))
        .json(&serde_json::json!({
            "invite": invite_link,
            "display_name": "Bob"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(join_r["ok"], true, "join response: {join_r:?}");
    assert_eq!(join_r["group_name"], "Join Test Group");
    assert!(join_r["chat_topic"].is_string());

    // Verify group exists after join
    let info_r: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info_r["ok"], true);

    // Cleanup
    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 6. Display Name
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_display_name() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "Display Name Group", "", None).await;

    // Set display name
    let r: Value = authed_client(&d)
        .put(d.url(&format!("/groups/{group_id}/display-name")))
        .json(&serde_json::json!({"name": "Fancy Alice"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true, "set display name: {r:?}");
    assert_eq!(r["display_name"], "Fancy Alice");

    // Verify via group info
    let info: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let members = info["members"].as_array().unwrap();
    let found = members.iter().any(|m| m["display_name"] == "Fancy Alice");
    assert!(
        found,
        "display name 'Fancy Alice' not found in members: {members:?}"
    );

    // Cleanup
    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 7. Leave Group
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_leave() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "Leave Group", "", None).await;

    // Leave
    let r: Value = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true, "leave response: {r:?}");
    assert_eq!(r["left"], "Leave Group");

    // Verify group is gone
    let info_r = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        info_r.status(),
        StatusCode::NOT_FOUND,
        "group should not exist after leaving"
    );
}

// ===========================================================================
// 8. Rejoin After Leave
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_rejoin_after_leave() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "Rejoin Group", "", Some("Alice")).await;

    // Generate invite before leaving
    let invite_resp: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({"expiry_secs": 3600}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let invite_link = invite_resp["invite_link"].as_str().unwrap().to_string();

    // Leave
    let leave_r: Value = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(leave_r["ok"], true);

    // Verify gone
    let gone_r = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(gone_r.status(), StatusCode::NOT_FOUND);

    // Rejoin via invite
    let join_r: Value = authed_client(&d)
        .post(d.url("/groups/join"))
        .json(&serde_json::json!({
            "invite": invite_link,
            "display_name": "Alice Returned"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(join_r["ok"], true, "rejoin response: {join_r:?}");
    assert_eq!(join_r["group_name"], "Rejoin Group");

    // Verify group info is restored
    let info: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["ok"], true);
    assert_eq!(info["name"], "Rejoin Group");

    let members = info["members"].as_array().unwrap();
    let found = members
        .iter()
        .any(|m| m["display_name"] == "Alice Returned");
    assert!(
        found,
        "'Alice Returned' not in members after rejoin: {members:?}"
    );

    // Cleanup
    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 9. Multiple Members (simulated via display names)
// ===========================================================================

/// On a single daemon we cannot have truly separate agents. Instead, we
/// exercise the member tracking by creating a group, joining via invite
/// multiple times (leave + rejoin with different display names), and
/// verifying the display_names map in group info grows accordingly.
///
/// This tests that the daemon correctly tracks display names set via the
/// PUT /groups/:id/display-name endpoint after successive joins.
#[tokio::test]
#[ignore]
async fn named_group_multiple_display_names() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "Multi-Name Group", "", Some("Alice")).await;

    // Verify initial member
    let info: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["ok"], true);
    let members = info["members"].as_array().unwrap();
    assert!(
        !members.is_empty(),
        "should have at least 1 member after creation"
    );

    // Update display name to "Bob" (simulating a different persona)
    let r: Value = authed_client(&d)
        .put(d.url(&format!("/groups/{group_id}/display-name")))
        .json(&serde_json::json!({"name": "Bob"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);

    // Verify the updated name appears
    let info2: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let members2 = info2["members"].as_array().unwrap();
    let has_bob = members2.iter().any(|m| m["display_name"] == "Bob");
    assert!(has_bob, "Bob should appear in members: {members2:?}");

    // Cleanup
    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 10. Invalid Invite
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_join_invalid_invite() {
    let d = daemon().await;

    // Garbage string
    let r = authed_client(&d)
        .post(d.url("/groups/join"))
        .json(&serde_json::json!({"invite": "this-is-not-a-valid-invite!!!"}))
        .send()
        .await
        .unwrap();

    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "garbage invite should return 400"
    );

    let body: Value = r.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert!(
        body["error"].as_str().unwrap().contains("invalid"),
        "error should mention 'invalid': {:?}",
        body["error"]
    );
}

// ===========================================================================
// 11. Invite for non-existent group returns 404
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_invite_nonexistent() {
    let d = daemon().await;

    let r = authed_client(&d)
        .post(d.url("/groups/nonexistent-group-id/invite"))
        .json(&serde_json::json!({"expiry_secs": 3600}))
        .send()
        .await
        .unwrap();

    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "invite for missing group should return 404"
    );
}

// ===========================================================================
// 12. Get info for non-existent group returns 404
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_info_nonexistent() {
    let d = daemon().await;

    let r = authed_client(&d)
        .get(d.url("/groups/does-not-exist"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "info for missing group should return 404"
    );
}

// ===========================================================================
// 13. Leave non-existent group returns 404
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_leave_nonexistent() {
    let d = daemon().await;

    let r = authed_client(&d)
        .delete(d.url("/groups/does-not-exist"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "leave for missing group should return 404"
    );
}

// ===========================================================================
// 14. Set display name on non-existent group returns 404
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_display_name_nonexistent() {
    let d = daemon().await;

    let r = authed_client(&d)
        .put(d.url("/groups/does-not-exist/display-name"))
        .json(&serde_json::json!({"name": "Nobody"}))
        .send()
        .await
        .unwrap();

    assert_eq!(
        r.status(),
        StatusCode::NOT_FOUND,
        "set display name for missing group should return 404"
    );
}

// ===========================================================================
// 15. Create group with default (no) expiry invite
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_invite_no_expiry() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "No-Expiry Group", "", None).await;

    // Generate invite with expiry_secs = 0 (never expires)
    let r: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({"expiry_secs": 0}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true, "no-expiry invite: {r:?}");
    assert_eq!(
        r["expires_at"], 0,
        "expires_at should be 0 for never-expiring invite"
    );

    // Cleanup
    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 16. Create group without optional fields
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_create_minimal() {
    let d = daemon().await;

    // Minimal: only name required
    let r: Value = authed_client(&d)
        .post(d.url("/groups"))
        .json(&serde_json::json!({"name": "Minimal Group"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true, "minimal create: {r:?}");
    let group_id = r["group_id"].as_str().unwrap();
    assert!(!group_id.is_empty());

    // Cleanup
    authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// 17. Full lifecycle: create -> invite -> leave -> join -> display-name -> leave
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_full_lifecycle() {
    let d = daemon().await;

    // Step 1: Create
    let (group_id, create_r) =
        create_group(&d, "Lifecycle Group", "full test", Some("Creator")).await;
    assert_eq!(create_r["ok"], true);

    // Step 2: Get info
    let info: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["ok"], true);
    assert_eq!(info["name"], "Lifecycle Group");

    // Step 3: Generate invite
    let invite_r: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(invite_r["ok"], true);
    let invite_link = invite_r["invite_link"].as_str().unwrap().to_string();

    // Step 4: Appears in list
    let list_r: Value = authed_client(&d)
        .get(d.url("/groups"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let groups = list_r["groups"].as_array().unwrap();
    let found = groups.iter().any(|g| g["group_id"] == group_id);
    assert!(found, "group should appear in list");

    // Step 5: Leave
    let leave_r: Value = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(leave_r["ok"], true);

    // Step 6: Rejoin via invite
    let join_r: Value = authed_client(&d)
        .post(d.url("/groups/join"))
        .json(&serde_json::json!({
            "invite": invite_link,
            "display_name": "Rejoined"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(join_r["ok"], true);

    // Step 7: Update display name
    let dn_r: Value = authed_client(&d)
        .put(d.url(&format!("/groups/{group_id}/display-name")))
        .json(&serde_json::json!({"name": "Final Name"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dn_r["ok"], true);

    // Step 8: Verify final state
    let final_info: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(final_info["ok"], true);
    let members = final_info["members"].as_array().unwrap();
    let has_final = members.iter().any(|m| m["display_name"] == "Final Name");
    assert!(has_final, "'Final Name' not in members: {members:?}");

    // Step 9: Final leave (cleanup)
    let final_leave: Value = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(final_leave["ok"], true);

    // Step 10: Confirm gone
    let gone = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// 20. Creator removal propagates to removed peer
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_creator_removal_propagates_to_removed_peer() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let alice_create: Value = alice
        .post(
            "/groups",
            serde_json::json!({"name":"Authoritative Removal","display_name":"Alice"}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(alice_create["ok"], true);
    let group_id = alice_create["group_id"].as_str().unwrap().to_string();

    let invite: Value = alice
        .post(&format!("/groups/{group_id}/invite"), serde_json::json!({}))
        .await
        .json()
        .await
        .unwrap();
    let invite_link = invite["invite_link"].as_str().unwrap().to_string();

    let bob_join: Value = bob
        .post(
            "/groups/join",
            serde_json::json!({"invite": invite_link, "display_name": "Bob Local"}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(bob_join["ok"], true);
    let bob_group_id = bob_join["group_id"]
        .as_str()
        .unwrap_or(&group_id)
        .to_string();

    let bob_agent_id = bob.agent_id().await;

    let alice_sees_bob = wait_until(Duration::from_secs(15), || async {
        let info: Value = alice
            .get(&format!("/groups/{group_id}/members"))
            .await
            .json()
            .await
            .unwrap_or_default();
        info["members"]
            .as_array()
            .map(|members| members.iter().any(|m| m["agent_id"] == bob_agent_id))
            .unwrap_or(false)
    })
    .await;
    assert!(
        alice_sees_bob,
        "alice never observed bob's invite join before removal"
    );
    let alice_hash = group_state_hash(alice, &group_id)
        .await
        .expect("alice state hash after bob join");
    let bob_caught_up = wait_until(Duration::from_secs(15), || async {
        group_state_hash(bob, &bob_group_id).await.as_deref() == Some(alice_hash.as_str())
    })
    .await;
    assert!(
        bob_caught_up,
        "bob never applied alice's authoritative member add before removal"
    );

    let remove_resp: Value = alice
        .delete(&format!("/groups/{group_id}/members/{bob_agent_id}"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(remove_resp["ok"], true, "remove response: {remove_resp:?}");

    let removed_seen = wait_until(Duration::from_secs(15), || async {
        let resp = bob.get(&format!("/groups/{bob_group_id}")).await;
        resp.status() == StatusCode::NOT_FOUND
    })
    .await;
    assert!(
        removed_seen,
        "bob never observed creator removal of the space"
    );

    let _ = alice.delete(&format!("/groups/{group_id}")).await;
}

// ===========================================================================
// 22. Invite join preserves genesis creation nonce
// ===========================================================================

#[tokio::test]
#[ignore]
async fn invite_join_preserves_genesis_creation_nonce() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let create: Value = alice
        .post(
            "/groups",
            serde_json::json!({
                "name": "Invite Genesis Parity",
                "description": "invite should preserve genesis creation nonce",
                "display_name": "Alice"
            }),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(create["ok"], true, "create response: {create:?}");
    let group_id = create["group_id"].as_str().unwrap().to_string();

    let alice_state: Value = alice
        .get(&format!("/groups/{group_id}/state"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(alice_state["ok"], true, "alice state: {alice_state:?}");
    let alice_nonce = alice_state["genesis"]["creation_nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let alice_stable = alice_state["genesis"]["group_id"]
        .as_str()
        .unwrap()
        .to_string();

    let invite: Value = alice
        .post(&format!("/groups/{group_id}/invite"), serde_json::json!({}))
        .await
        .json()
        .await
        .unwrap();
    let invite_link = invite["invite_link"].as_str().unwrap().to_string();

    let bob_join: Value = bob
        .post(
            "/groups/join",
            serde_json::json!({"invite": invite_link, "display_name": "Bob"}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(bob_join["ok"], true, "bob join: {bob_join:?}");
    let bob_group_id = bob_join["group_id"].as_str().unwrap().to_string();

    let bob_state: Value = bob
        .get(&format!("/groups/{bob_group_id}/state"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(bob_state["ok"], true, "bob state: {bob_state:?}");
    let bob_nonce = bob_state["genesis"]["creation_nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let bob_stable = bob_state["genesis"]["group_id"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(
        bob_nonce, alice_nonce,
        "invite join must preserve genesis nonce"
    );
    assert_eq!(
        bob_stable, alice_stable,
        "invite join must preserve stable group id"
    );

    let _ = alice.delete(&format!("/groups/{group_id}")).await;
}

// ===========================================================================
// 23. Imported card bootstrap hint is signature-bound
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_import_rejects_tampered_metadata_topic() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let create: Value = alice
        .post(
            "/groups",
            serde_json::json!({
                "name": "Tamper-Proof Import",
                "description": "bootstrap hint must be signed",
                "preset": "public_request_secure"
            }),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(create["ok"], true, "create response: {create:?}");
    let group_id = create["group_id"].as_str().unwrap().to_string();

    let card: Value = alice
        .get(&format!("/groups/cards/{group_id}"))
        .await
        .json()
        .await
        .unwrap();
    assert!(card["signature"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(card["metadata_topic"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));

    let mut tampered = card.clone();
    tampered["metadata_topic"] = serde_json::json!("x0x.group.evil.meta");

    let resp = bob.post("/groups/cards/import", tampered).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false, "import body: {body:?}");
    assert!(body["error"]
        .as_str()
        .unwrap_or_default()
        .contains("invalid signed card"));

    let _ = alice.delete(&format!("/groups/{group_id}")).await;
}

// ===========================================================================
// 21. Creator delete propagates to peers
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_creator_delete_propagates_to_peer() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let alice_create: Value = alice
        .post(
            "/groups",
            serde_json::json!({"name":"Authoritative Delete","display_name":"Alice"}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(alice_create["ok"], true);
    let group_id = alice_create["group_id"].as_str().unwrap().to_string();

    let invite: Value = alice
        .post(&format!("/groups/{group_id}/invite"), serde_json::json!({}))
        .await
        .json()
        .await
        .unwrap();
    let invite_link = invite["invite_link"].as_str().unwrap().to_string();

    let bob_join: Value = bob
        .post(
            "/groups/join",
            serde_json::json!({"invite": invite_link, "display_name": "Bob Local"}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(bob_join["ok"], true);
    let bob_group_id = bob_join["group_id"]
        .as_str()
        .unwrap_or(&group_id)
        .to_string();

    let bob_agent_id = bob.agent_id().await;

    let alice_sees_bob = wait_until(Duration::from_secs(15), || async {
        let info: Value = alice
            .get(&format!("/groups/{group_id}/members"))
            .await
            .json()
            .await
            .unwrap_or_default();
        info["members"]
            .as_array()
            .map(|members| members.iter().any(|m| m["agent_id"] == bob_agent_id))
            .unwrap_or(false)
    })
    .await;
    assert!(
        alice_sees_bob,
        "alice never observed bob's invite join before delete"
    );
    let alice_hash = group_state_hash(alice, &group_id)
        .await
        .expect("alice state hash after bob join");
    let bob_caught_up = wait_until(Duration::from_secs(15), || async {
        group_state_hash(bob, &bob_group_id).await.as_deref() == Some(alice_hash.as_str())
    })
    .await;
    assert!(
        bob_caught_up,
        "bob never applied alice's authoritative member add before delete"
    );

    let delete_resp: Value = alice
        .delete(&format!("/groups/{group_id}"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(delete_resp["ok"], true, "delete response: {delete_resp:?}");

    let deleted_seen = wait_until(Duration::from_secs(15), || async {
        let resp = bob.get(&format!("/groups/{bob_group_id}")).await;
        resp.status() == StatusCode::NOT_FOUND
    })
    .await;
    assert!(
        deleted_seen,
        "bob never observed creator deletion of the space"
    );
}
