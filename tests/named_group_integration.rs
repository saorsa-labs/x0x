//! Integration tests for Named Groups (invite/join lifecycle).
//!
//! All tests are `#[ignore]` — they require a running x0xd daemon.
//! Run with: cargo nextest run -E 'test(named_group)' -- --ignored
//!
//! Before running: cargo build --release --bin x0xd

use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;
use x0x::groups::GroupCard;
use x0x::identity::AgentKeypair;

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

fn agent_hex(kp: &AgentKeypair) -> String {
    hex::encode(kp.agent_id().as_bytes())
}

fn withdrawn_card_from(card: Value, signer: &AgentKeypair) -> Value {
    let mut card: GroupCard = serde_json::from_value(card).expect("group card json");
    card.withdrawn = true;
    card.revision = card.revision.saturating_add(10);
    card.prev_state_hash = Some(card.state_hash.clone());
    card.state_hash = format!("withdrawn-test-{}", card.revision);
    card.issued_at = card.issued_at.saturating_add(10_000);
    card.updated_at = card.issued_at;
    card.expires_at = card.issued_at.saturating_add(60_000);
    card.sign(signer).expect("sign withdrawn test card");
    serde_json::to_value(card).expect("withdrawn card json")
}

fn signed_test_card(
    group_id: &str,
    owner: &AgentKeypair,
    signer: &AgentKeypair,
    revision: u64,
    withdrawn: bool,
) -> Value {
    let now = 10_000 + revision;
    let owner_hex = agent_hex(owner);
    let policy = x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy();
    let mut card = GroupCard {
        group_id: group_id.to_string(),
        name: format!("Stub {group_id}"),
        description: "test stub".to_string(),
        avatar_url: None,
        banner_url: None,
        tags: vec!["withdraw-test".to_string()],
        policy_summary: (&policy).into(),
        owner_agent_id: owner_hex,
        admin_count: 1,
        member_count: 1,
        created_at: now,
        updated_at: now,
        request_access_enabled: true,
        metadata_topic: Some(format!(
            "x0x.group.{}.meta",
            &group_id[..16.min(group_id.len())]
        )),
        revision,
        state_hash: format!("stub-state-{revision}"),
        prev_state_hash: (revision > 1).then(|| format!("stub-state-{}", revision - 1)),
        issued_at: now,
        expires_at: now + 60_000,
        authority_agent_id: String::new(),
        authority_public_key: String::new(),
        withdrawn,
        signature: String::new(),
    };
    card.sign(signer).expect("sign test card");
    serde_json::to_value(card).expect("test card json")
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
    let body = group_state(d, group_id).await?;
    body["state_hash"].as_str().map(ToString::to_string)
}

async fn group_state(d: &AgentInstance, group_id: &str) -> Option<Value> {
    let resp = d.get(&format!("/groups/{group_id}/state")).await;
    if !resp.status().is_success() {
        return None;
    }
    Some(resp.json().await.unwrap_or_default())
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
    // Direct roster add-by-agent_id is a non-secure-plane operation. Since
    // ADR-0012 made `private_secure` (the default preset) secure-by-default
    // TreeKEM — where a direct add correctly requires the target's KeyPackage —
    // this local-roster-semantics test uses a `public_open` (GSS) group, where
    // adding a member by agent_id alone is the valid operation under test.
    let create_r: Value = authed_client(&d)
        .post(d.url("/groups"))
        .json(&serde_json::json!({
            "name": "Roster Group",
            "description": "",
            "display_name": "Owner",
            "preset": "public_open"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = create_r["group_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !group_id.is_empty(),
        "create public_open group: {create_r:?}"
    );
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
/// we test the join flow by: (a) creating a group, (b) proving sole-admin
/// self-leave is rejected, (c) installing a backup admin, (d) generating an
/// invite, (e) leaving as a non-sole-admin, and (f) joining back via the invite.
/// This exercises the full invite/join codepath on a single daemon.
#[tokio::test]
#[ignore]
async fn named_group_join_via_invite() {
    let d = daemon().await;
    // This single-daemon rejoin path needs a local roster backup admin. Use a
    // public_open (GSS) group because direct add-by-agent_id is valid there;
    // private_secure TreeKEM groups require the target's KeyPackage instead.
    let create_r: Value = authed_client(&d)
        .post(d.url("/groups"))
        .json(&serde_json::json!({
            "name": "Join Test Group",
            "description": "",
            "display_name": "Alice",
            "preset": "public_open"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = create_r["group_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !group_id.is_empty(),
        "create public_open group: {create_r:?}"
    );

    // DELETE is pure self-leave; while Alice is the only admin it must be
    // rejected rather than implicitly ending the group.
    let sole_admin_leave = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(sole_admin_leave.status(), StatusCode::CONFLICT);
    let sole_admin_leave_r: Value = sole_admin_leave.json().await.unwrap();
    assert_eq!(
        sole_admin_leave_r["ok"], false,
        "sole-admin leave response: {sole_admin_leave_r:?}"
    );
    assert_eq!(
        sole_admin_leave_r["error"].as_str(),
        Some("a group must always have at least one admin; make another member an admin before leaving"),
        "sole-admin leave response: {sole_admin_leave_r:?}"
    );

    let backup_admin = fake_agent_id(0x44);
    let add_admin_r: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/members")))
        .json(&serde_json::json!({
            "agent_id": backup_admin,
            "display_name": "Backup Admin"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        add_admin_r["ok"], true,
        "add admin response: {add_admin_r:?}"
    );

    let promote_admin: Value = authed_client(&d)
        .patch(d.url(&format!("/groups/{group_id}/members/{backup_admin}/role")))
        .json(&serde_json::json!({ "role": "admin" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        promote_admin["ok"], true,
        "promote admin response: {promote_admin:?}"
    );

    // Generate invite before the successful non-sole-admin self-leave.
    let invite_resp: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({"expiry_secs": 3600}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        invite_resp["ok"], true,
        "create invite response: {invite_resp:?}"
    );
    let invite_link = invite_resp["invite_link"].as_str().unwrap().to_string();

    // Alice can leave once another active admin remains in the roster.
    let leave_resp = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(leave_resp.status(), StatusCode::OK);
    let leave_r: Value = leave_resp.json().await.unwrap();
    assert_eq!(leave_r["ok"], true, "leave response: {leave_r:?}");

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

    // DELETE is pure self-leave. A sole-admin self-leave is rejected rather
    // than implicitly ending the group.
    let leave_resp = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(leave_resp.status(), StatusCode::CONFLICT);
    let r: Value = leave_resp.json().await.unwrap();

    assert_eq!(r["ok"], false, "sole-admin leave response: {r:?}");
    assert_eq!(
        r["error"].as_str(),
        Some("a group must always have at least one admin; make another member an admin before leaving"),
        "sole-admin leave response: {r:?}"
    );

    // Verify the live group remains accessible after the rejected self-leave.
    let info_r = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(info_r.status(), StatusCode::OK);
    let info: Value = info_r.json().await.unwrap();
    assert_eq!(info["ok"], true, "group after rejected leave: {info:?}");
    assert_eq!(info["name"], "Leave Group");

    // Ending the group is explicit delete/withdraw and retains a withdrawn tombstone.
    let delete_r: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/state/withdraw")))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(delete_r["ok"], true, "delete response: {delete_r:?}");

    let state_r: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}/state")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state_r["withdrawn"], true, "withdrawn state: {state_r:?}");
}

// ===========================================================================
// 8. Rejoin After Leave
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_rejoin_after_leave() {
    let d = daemon().await;
    // Uses a public_open (GSS) group: on a non-secure group, rejoin-via-invite
    // restores the joiner into the local roster synchronously. The default
    // private_secure preset is now secure-by-default TreeKEM (ADR-0012), where
    // the join awaits the anchor's authoritative MemberAdded — a different flow
    // than this single-daemon roster-restore test exercises.
    let create_r: Value = authed_client(&d)
        .post(d.url("/groups"))
        .json(&serde_json::json!({
            "name": "Rejoin Group",
            "description": "",
            "display_name": "Alice",
            "preset": "public_open"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = create_r["group_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !group_id.is_empty(),
        "create public_open group: {create_r:?}"
    );

    // DELETE is pure self-leave. A sole-admin self-leave is rejected before the
    // roster changes, so make that behavior explicit before setting up the
    // non-sole-admin leave path exercised by the rejoin flow.
    let sole_admin_leave = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(sole_admin_leave.status(), StatusCode::CONFLICT);
    let sole_admin_leave_r: Value = sole_admin_leave.json().await.unwrap();
    assert_eq!(
        sole_admin_leave_r["ok"], false,
        "sole-admin leave response: {sole_admin_leave_r:?}"
    );
    assert_eq!(
        sole_admin_leave_r["error"].as_str(),
        Some("a group must always have at least one admin; make another member an admin before leaving"),
        "sole-admin leave response: {sole_admin_leave_r:?}"
    );

    let backup_admin = fake_agent_id(0x43);
    let add_admin_r: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/members")))
        .json(&serde_json::json!({
            "agent_id": backup_admin,
            "display_name": "Backup Admin"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        add_admin_r["ok"], true,
        "add admin response: {add_admin_r:?}"
    );

    let promote_admin: Value = authed_client(&d)
        .patch(d.url(&format!("/groups/{group_id}/members/{backup_admin}/role")))
        .json(&serde_json::json!({ "role": "admin" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        promote_admin["ok"], true,
        "promote admin response: {promote_admin:?}"
    );

    // Generate invite before the successful non-sole-admin leave.
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

    // Leave now succeeds because another active admin remains in the roster.
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
// 9. Multiple Members with display names
// ===========================================================================

/// Exercise member tracking with two real daemon identities and verify group
/// info retains distinct display names for both members after an invite join.
#[tokio::test]
#[ignore]
async fn named_group_multiple_display_names() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let alice_agent_id = alice.agent_id().await;
    let bob_agent_id = bob.agent_id().await;

    let create: Value = alice
        .post(
            "/groups",
            serde_json::json!({"name":"Multi-Name Group","display_name":"Alice"}),
        )
        .await
        .json()
        .await
        .unwrap_or_default();
    assert_eq!(create["ok"], true, "create response: {create:?}");
    let group_id = create["group_id"].as_str().unwrap_or_default().to_string();
    assert!(
        !group_id.is_empty(),
        "group_id should be present: {create:?}"
    );

    let invite: Value = alice
        .post(&format!("/groups/{group_id}/invite"), serde_json::json!({}))
        .await
        .json()
        .await
        .unwrap_or_default();
    let invite_link = invite["invite_link"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !invite_link.is_empty(),
        "invite link should be present: {invite:?}"
    );

    let bob_join: Value = bob
        .post(
            "/groups/join",
            serde_json::json!({"invite": invite_link, "display_name": "Bob"}),
        )
        .await
        .json()
        .await
        .unwrap_or_default();
    assert_eq!(bob_join["ok"], true, "join response: {bob_join:?}");
    let bob_group_id = bob_join["group_id"]
        .as_str()
        .unwrap_or(&group_id)
        .to_string();

    let alice_sees_both_names = wait_until(Duration::from_secs(30), || async {
        let info: Value = alice
            .get(&format!("/groups/{group_id}"))
            .await
            .json()
            .await
            .unwrap_or_default();
        info["members"]
            .as_array()
            .map(|members| {
                let has_alice = members
                    .iter()
                    .any(|m| m["agent_id"] == alice_agent_id && m["display_name"] == "Alice");
                let has_bob = members
                    .iter()
                    .any(|m| m["agent_id"] == bob_agent_id && m["display_name"] == "Bob");
                members.len() >= 2 && has_alice && has_bob
            })
            .unwrap_or(false)
    })
    .await;
    assert!(
        alice_sees_both_names,
        "alice never observed distinct Alice and Bob display names"
    );

    let _ = alice.delete(&format!("/groups/{group_id}")).await;
    let _ = bob.delete(&format!("/groups/{bob_group_id}")).await;
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
// 17. Full lifecycle: create -> invite/list -> display-name -> leave rejection -> delete
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
    assert!(!invite_link.is_empty(), "invite link should be returned");

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

    // Step 5: Update display name
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

    // Step 6: Verify display name via group info
    let updated_info: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated_info["ok"], true);
    let members = updated_info["members"].as_array().unwrap();
    let has_final = members.iter().any(|m| m["display_name"] == "Final Name");
    assert!(has_final, "'Final Name' not in members: {members:?}");

    // Step 7: DELETE is now pure self-leave; sole-admin leave is rejected.
    let leave_resp = authed_client(&d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(leave_resp.status(), StatusCode::CONFLICT);
    let leave_r: Value = leave_resp.json().await.unwrap();
    assert_eq!(
        leave_r["ok"], false,
        "sole-admin leave response: {leave_r:?}"
    );
    assert_eq!(
        leave_r["error"].as_str(),
        Some("a group must always have at least one admin; make another member an admin before leaving"),
        "sole-admin leave response: {leave_r:?}"
    );

    // Step 8: Explicit delete/withdraw succeeds and retains a terminality marker.
    let delete_r: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/state/withdraw")))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(delete_r["ok"], true, "delete response: {delete_r:?}");

    let marker_resp = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(marker_resp.status(), StatusCode::OK);
    let marker_info: Value = marker_resp.json().await.unwrap();
    assert_eq!(
        marker_info["ok"], true,
        "withdrawn tombstone: {marker_info:?}"
    );
    assert_eq!(marker_info["group_id"], group_id);

    let state_r: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}/state")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state_r["ok"], true, "withdrawn state: {state_r:?}");
    assert_eq!(state_r["withdrawn"], true, "withdrawn state: {state_r:?}");
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

    let alice_sees_bob = wait_until(Duration::from_secs(30), || async {
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
    let bob_caught_up = wait_until(Duration::from_secs(30), || async {
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

    let removed_seen = wait_until(Duration::from_secs(30), || async {
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
async fn named_group_invite_join_preserves_genesis_creation_nonce() {
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

#[tokio::test]
#[ignore]
async fn withdrawn_card_from_non_admin_does_not_terminate_live_keyed_group() {
    let d = daemon().await;
    let create: Value = authed_client(&d)
        .post(d.url("/groups"))
        .json(&serde_json::json!({
            "name": "Non-admin withdrawn card guard",
            "description": "live keyed group must survive",
            "preset": "public_request_secure"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(create["ok"], true, "create response: {create:?}");
    let group_id = create["group_id"].as_str().unwrap().to_string();
    let card: Value = authed_client(&d)
        .get(d.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let outsider = AgentKeypair::generate().unwrap();
    let withdrawn = withdrawn_card_from(card, &outsider);

    let import = authed_client(&d)
        .post(d.url("/groups/cards/import"))
        .json(&withdrawn)
        .send()
        .await
        .unwrap();
    assert_eq!(import.status(), StatusCode::OK);

    let state: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}/state")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["withdrawn"], false, "state after import: {state:?}");

    let named_groups: Value = serde_json::from_str(
        &tokio::fs::read_to_string(d.data_dir().join("named_groups.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        named_groups[group_id.as_str()]["shared_secret"].is_array(),
        "non-admin withdrawn card must not wipe GSS secret: {named_groups:?}"
    );
}

#[tokio::test]
#[ignore]
async fn withdrawn_card_from_roster_admin_does_not_terminate_live_keyed_group() {
    let d = daemon().await;
    let admin = AgentKeypair::generate().unwrap();
    let admin_hex = agent_hex(&admin);
    let create: Value = authed_client(&d)
        .post(d.url("/groups"))
        .json(&serde_json::json!({
            "name": "Admin withdrawn card guard",
            "description": "live keyed group must require signed terminal commit",
            "preset": "public_request_secure"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(create["ok"], true, "create response: {create:?}");
    let group_id = create["group_id"].as_str().unwrap().to_string();

    let add: Value = authed_client(&d)
        .post(d.url(&format!("/groups/{group_id}/members")))
        .json(&serde_json::json!({ "agent_id": admin_hex, "display_name": "Card Admin" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(add["ok"], true, "add response: {add:?}");
    let promote = authed_client(&d)
        .patch(d.url(&format!("/groups/{group_id}/members/{admin_hex}/role")))
        .json(&serde_json::json!({ "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(promote.status(), StatusCode::OK);

    let card: Value = authed_client(&d)
        .get(d.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let withdrawn = withdrawn_card_from(card, &admin);
    let import = authed_client(&d)
        .post(d.url("/groups/cards/import"))
        .json(&withdrawn)
        .send()
        .await
        .unwrap();
    assert_eq!(import.status(), StatusCode::OK);

    let state: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}/state")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["withdrawn"], false, "state after import: {state:?}");
    let named_groups: Value = serde_json::from_str(
        &tokio::fs::read_to_string(d.data_dir().join("named_groups.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        named_groups[group_id.as_str()]["shared_secret"].is_array(),
        "admin-signed withdrawn card alone must not wipe live GSS secret; signed terminal GroupStateCommit is required: {named_groups:?}"
    );
}

#[tokio::test]
#[ignore]
async fn withdrawn_card_supersedes_keyless_discovery_stub() {
    let d = daemon().await;
    let owner = AgentKeypair::generate().unwrap();
    let outsider = AgentKeypair::generate().unwrap();
    let group_id = "cafe".repeat(16);
    let live_card = signed_test_card(&group_id, &owner, &owner, 1, false);
    let import_live = authed_client(&d)
        .post(d.url("/groups/cards/import"))
        .json(&live_card)
        .send()
        .await
        .unwrap();
    assert_eq!(import_live.status(), StatusCode::OK);

    let withdrawn_card = signed_test_card(&group_id, &owner, &outsider, 2, true);
    let import_withdrawn = authed_client(&d)
        .post(d.url("/groups/cards/import"))
        .json(&withdrawn_card)
        .send()
        .await
        .unwrap();
    assert_eq!(import_withdrawn.status(), StatusCode::OK);

    let state: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}/state")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(state["withdrawn"], true, "stub state: {state:?}");
}

// ===========================================================================
// 21. Admin delete propagates to peers after creator DELETE stays self-leave
// ===========================================================================

#[tokio::test]
#[ignore]
async fn named_group_admin_delete_propagates_to_peer_after_creator_delete_409() {
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
    let alice_state = group_state(alice, &group_id).await;
    assert!(
        alice_state.is_some(),
        "alice state missing after default private_secure create"
    );
    let Some(alice_state) = alice_state else {
        return;
    };
    assert!(
        alice_state["security_binding"]
            .as_str()
            .is_some_and(|binding| binding.starts_with("treekem:")),
        "delete propagation regression must exercise a private_secure TreeKEM group: {alice_state:?}"
    );

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

    let alice_sees_bob = wait_until(Duration::from_secs(30), || async {
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
        "alice never observed bob's invite join before delete checks"
    );
    let alice_hash = group_state_hash(alice, &group_id)
        .await
        .expect("alice state hash after bob join");
    let bob_caught_up = wait_until(Duration::from_secs(30), || async {
        group_state_hash(bob, &bob_group_id).await.as_deref() == Some(alice_hash.as_str())
    })
    .await;
    assert!(
        bob_caught_up,
        "bob never applied alice's authoritative member add before delete checks"
    );

    let delete_resp = alice.delete(&format!("/groups/{group_id}")).await;
    assert_eq!(delete_resp.status(), StatusCode::CONFLICT);
    let delete_body: Value = delete_resp.json().await.unwrap();
    assert_eq!(
        delete_body["error"].as_str(),
        Some("a group must always have at least one admin; make another member an admin before leaving"),
        "creator DELETE must remain pure self-leave: {delete_body:?}"
    );
    assert!(
        group_state(alice, &group_id).await.is_some(),
        "rejected creator DELETE must not remove alice's local group"
    );
    assert!(
        group_state(bob, &bob_group_id).await.is_some(),
        "rejected creator DELETE must not delete bob's group"
    );

    let promote: Value = alice
        .patch(
            &format!("/groups/{group_id}/members/{bob_agent_id}/role"),
            serde_json::json!({ "role": "admin" }),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(promote["ok"], true, "promote response: {promote:?}");

    let promoted_hash = group_state_hash(alice, &group_id)
        .await
        .expect("alice state hash after bob promotion");
    let bob_promoted = wait_until(Duration::from_secs(30), || async {
        let caught_up =
            group_state_hash(bob, &bob_group_id).await.as_deref() == Some(promoted_hash.as_str());
        let members: Value = bob
            .get(&format!("/groups/{bob_group_id}/members"))
            .await
            .json()
            .await
            .unwrap_or_default();
        let has_admin_role = members["members"]
            .as_array()
            .map(|members| {
                members
                    .iter()
                    .any(|m| m["agent_id"] == bob_agent_id && m["role"] == "admin")
            })
            .unwrap_or(false);
        caught_up && has_admin_role
    })
    .await;
    assert!(bob_promoted, "bob never observed his admin promotion");

    let delete: Value = bob
        .post(
            &format!("/groups/{bob_group_id}/state/withdraw"),
            serde_json::json!({}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(delete["ok"], true, "delete response: {delete:?}");

    let bob_withdrawn = group_state(bob, &bob_group_id)
        .await
        .expect("deleting admin should retain terminal state");
    assert_eq!(
        bob_withdrawn["withdrawn"], true,
        "bob state: {bob_withdrawn:?}"
    );
    let bob_encrypt = bob
        .post(
            &format!("/groups/{bob_group_id}/secure/encrypt"),
            serde_json::json!({ "payload_b64": "aGk=" }),
        )
        .await;
    assert_eq!(
        bob_encrypt.status(),
        StatusCode::CONFLICT,
        "deleter authoring must be rejected after withdrawal"
    );
    assert!(
        !tokio::fs::try_exists(
            bob.data_dir()
                .join("treekem")
                .join(format!("{bob_group_id}.snap"))
        )
        .await
        .unwrap_or(false),
        "deleting admin TreeKEM snapshot should be wiped"
    );

    let withdrawn_seen = wait_until(Duration::from_secs(30), || async {
        group_state(alice, &group_id)
            .await
            .is_some_and(|state| state["withdrawn"] == true)
    })
    .await;
    assert!(
        withdrawn_seen,
        "alice never observed non-creator admin delete as retained withdrawn tombstone"
    );
    let alice_encrypt = alice
        .post(
            &format!("/groups/{group_id}/secure/encrypt"),
            serde_json::json!({ "payload_b64": "aGk=" }),
        )
        .await;
    assert_eq!(
        alice_encrypt.status(),
        StatusCode::CONFLICT,
        "recipient authoring must be rejected after withdrawal"
    );
    assert!(
        !tokio::fs::try_exists(
            alice
                .data_dir()
                .join("treekem")
                .join(format!("{group_id}.snap"))
        )
        .await
        .unwrap_or(false),
        "recipient TreeKEM snapshot should be wiped after GroupDeleted"
    );
}

// ===========================================================================
// ADR-0016 R2 — last-admin invariant REST pre-check (exact §3 contract)
// ===========================================================================

/// Why: ADR-0016 fixes this REST contract verbatim — demoting the sole
/// admin-or-higher member (here: the creator/admin demoting itself) must
/// return 409 with exactly the §3 error string, and the roster must be
/// left untouched.
#[tokio::test]
#[ignore]
async fn last_admin_rest_self_demote_returns_409_exact_string() {
    let d = daemon().await;
    let (group_id, _) = create_group(&d, "last-admin-409", "sole admin demote", None).await;
    assert!(!group_id.is_empty());

    let agent: Value = authed_client(&d)
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let self_hex = agent["agent_id"].as_str().expect("agent_id").to_string();

    let resp = authed_client(&d)
        .patch(d.url(&format!("/groups/{group_id}/members/{self_hex}/role")))
        .json(&serde_json::json!({ "role": "member" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"].as_str(),
        Some("a group must always have at least one admin; make another member an admin first")
    );

    // The roster must be unchanged: the creator still holds admin rank.
    let members: Value = authed_client(&d)
        .get(d.url(&format!("/groups/{group_id}/members")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let still_admin = members["members"]
        .as_array()
        .map(|ms| {
            ms.iter()
                .any(|m| m["agent_id"] == self_hex.as_str() && m["role"] == "admin")
        })
        .unwrap_or(false);
    assert!(
        still_admin,
        "roster mutated by a rejected demote: {members}"
    );

    // Re-asserting admin keeps the admin count at 1 and passes.
    let resp = authed_client(&d)
        .patch(d.url(&format!("/groups/{group_id}/members/{self_hex}/role")))
        .json(&serde_json::json!({ "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
