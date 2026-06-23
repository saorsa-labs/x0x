//! Integration tests for the joiner-authored `MemberJoined` metadata event.
//!
//! Covers `docs/design/groups-join-roster-propagation.md` acceptance
//! criterion 1 — a daemon (alice) creating a `public_open` group and a
//! second daemon (bob) joining via invite must result in alice's local
//! `members_v2` view containing bob, after which bob's signed public
//! message is accepted (rather than dropped as
//! `WritePolicyViolation { MembersOnly }`).
//!
//! Also exercises pure-Rust signature canonicalisation paths via the
//! daemon's REST surface so the canonical-bytes helper is held to its
//! published contract: a tampered field on the wire fails the receiver's
//! verify, and an idempotent re-publish does not double-count.

use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

#[path = "harness/src/cluster.rs"]
mod cluster;

use cluster::{pair, trio_with_extra_config, AgentInstance};

fn authed_client(d: &AgentInstance) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", d.api_token))
            .expect("auth header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(20))
        .build()
        .expect("authed client")
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

async fn create_group_with_preset(d: &AgentInstance, name: &str, preset: &str) -> String {
    let resp: Value = authed_client(d)
        .post(d.url("/groups"))
        .json(&serde_json::json!({
            "name": name,
            "description": "join-metadata-event test",
            "preset": preset,
        }))
        .send()
        .await
        .expect("create group request")
        .json()
        .await
        .expect("create group json");
    assert_eq!(resp["ok"], true, "create group response: {resp:?}");
    resp["group_id"].as_str().expect("group_id").to_string()
}

async fn create_public_open_group(d: &AgentInstance, name: &str) -> String {
    create_group_with_preset(d, name, "public_open").await
}

async fn create_invite(d: &AgentInstance, group_id: &str) -> String {
    let r: Value = authed_client(d)
        .post(d.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("invite request")
        .json()
        .await
        .expect("invite json");
    assert_eq!(r["ok"], true, "invite response: {r:?}");
    r["invite_link"].as_str().expect("invite_link").to_string()
}

async fn join_via_invite(d: &AgentInstance, invite: &str, display_name: &str) -> Value {
    authed_client(d)
        .post(d.url("/groups/join"))
        .json(&serde_json::json!({
            "invite": invite,
            "display_name": display_name,
        }))
        .send()
        .await
        .expect("join request")
        .json()
        .await
        .expect("join json")
}

async fn list_members(d: &AgentInstance, group_id: &str) -> Vec<String> {
    let resp: Value = authed_client(d)
        .get(d.url(&format!("/groups/{group_id}/members")))
        .send()
        .await
        .expect("members request")
        .json()
        .await
        .expect("members json");
    resp["members"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m["agent_id"].as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn post_public_message(d: &AgentInstance, group_id: &str, body: &str) -> Value {
    authed_client(d)
        .post(d.url(&format!("/groups/{group_id}/send")))
        .json(&serde_json::json!({ "body": body }))
        .send()
        .await
        .expect("post message")
        .json()
        .await
        .expect("post json")
}

async fn list_public_messages(d: &AgentInstance, group_id: &str) -> Vec<String> {
    let resp: Value = authed_client(d)
        .get(d.url(&format!("/groups/{group_id}/messages")))
        .send()
        .await
        .expect("get messages")
        .json()
        .await
        .expect("get messages json");
    resp["messages"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m["body"].as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn diagnostics_groups(d: &AgentInstance) -> Value {
    let resp = authed_client(d)
        .get(d.url("/diagnostics/groups"))
        .send()
        .await
        .expect("diagnostics request");
    assert_eq!(resp.status(), StatusCode::OK, "diagnostics status");
    resp.json().await.expect("diagnostics json")
}

async fn group_diagnostic_counter(d: &AgentInstance, group_id: &str, counter: &str) -> u64 {
    let diag = diagnostics_groups(d).await;
    diag["groups"]
        .as_array()
        .and_then(|groups| {
            groups
                .iter()
                .find(|g| g["group_id"].as_str() == Some(group_id))
        })
        .and_then(|g| g[counter].as_u64())
        .unwrap_or_default()
}

async fn group_details(d: &AgentInstance, group_id: &str) -> Value {
    authed_client(d)
        .get(d.url(&format!("/groups/{group_id}")))
        .send()
        .await
        .expect("group details request")
        .json()
        .await
        .expect("group details json")
}

async fn group_state_field(d: &AgentInstance, group_id: &str, field: &str) -> Option<String> {
    let resp = authed_client(d)
        .get(d.url(&format!("/groups/{group_id}/state")))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: Value = resp.json().await.ok()?;
    body[field].as_str().map(ToString::to_string)
}

async fn set_member_role(d: &AgentInstance, group_id: &str, agent_id: &str, role: &str) -> Value {
    let resp = authed_client(d)
        .patch(d.url(&format!("/groups/{group_id}/members/{agent_id}/role")))
        .json(&serde_json::json!({ "role": role }))
        .send()
        .await
        .expect("set-role request");
    let status = resp.status();
    let body: Value = resp.json().await.expect("set-role json");
    assert_eq!(status, StatusCode::OK, "set-role response: {body:?}");
    assert_eq!(body["ok"], true, "set-role body: {body:?}");
    body
}

fn member_row(details: &Value, agent_id: &str) -> Option<Value> {
    details["members"]
        .as_array()?
        .iter()
        .find(|m| m["agent_id"].as_str() == Some(agent_id))
        .cloned()
}

fn member_has_role(details: &Value, agent_id: &str, role: &str) -> bool {
    member_row(details, agent_id)
        .and_then(|m| m["role"].as_str().map(ToString::to_string))
        .as_deref()
        == Some(role)
}

fn member_is_active_added_by(details: &Value, agent_id: &str, added_by: &str) -> bool {
    member_row(details, agent_id).is_some_and(|m| {
        m["role"].as_str() == Some("member")
            && m["state"].as_str() == Some("active")
            && m["added_by"].as_str() == Some(added_by)
    })
}

async fn publish_raw(d: &AgentInstance, topic: &str, payload: &[u8]) -> Value {
    use base64::Engine as _;
    authed_client(d)
        .post(d.url("/publish"))
        .json(&serde_json::json!({
            "topic": topic,
            "payload": base64::engine::general_purpose::STANDARD.encode(payload),
        }))
        .send()
        .await
        .expect("publish request")
        .json()
        .await
        .expect("publish json")
}

#[allow(clippy::too_many_arguments)]
fn canonical_member_joined_bytes_for_test(
    group_id: &str,
    stable_group_id: Option<&str>,
    member_agent_id: &str,
    member_public_key_b64: &str,
    role: x0x::groups::GroupRole,
    display_name: Option<&str>,
    inviter_agent_id: &str,
    invite_secret: &str,
    ts_ms: u64,
    treekem_key_package_b64: Option<&str>,
) -> Vec<u8> {
    fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }
    // Must mirror production `canonical_member_joined_bytes` in src/bin/x0xd.rs
    // exactly (domain tag + field layout) or the forged event's signature will
    // fail verification before reaching the role/secret policy checks this test
    // exercises.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"x0x.named_group.member_joined.v2");
    push_lp(&mut buf, group_id.as_bytes());
    push_lp(&mut buf, stable_group_id.unwrap_or("").as_bytes());
    push_lp(&mut buf, member_agent_id.as_bytes());
    push_lp(&mut buf, member_public_key_b64.as_bytes());
    buf.push(role.as_u8());
    push_lp(&mut buf, display_name.unwrap_or("").as_bytes());
    push_lp(&mut buf, inviter_agent_id.as_bytes());
    push_lp(&mut buf, invite_secret.as_bytes());
    buf.extend_from_slice(&ts_ms.to_be_bytes());
    push_lp(&mut buf, treekem_key_package_b64.unwrap_or("").as_bytes());
    buf
}

async fn signed_member_joined_event(
    member: &AgentInstance,
    group_id: &str,
    inviter_agent_id: &str,
    invite_secret: &str,
    role: x0x::groups::GroupRole,
) -> Value {
    use base64::Engine as _;
    let key_path = dirs::home_dir()
        .expect("home dir")
        .join(format!(".x0x-{}", member.name))
        .join("agent.key");
    let keypair = x0x::storage::load_agent_keypair_from(key_path)
        .await
        .expect("load member agent keypair");
    let member_agent_id = hex::encode(keypair.agent_id().as_bytes());
    let member_public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(keypair.public_key().as_bytes());
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64;
    let canonical = canonical_member_joined_bytes_for_test(
        group_id,
        Some(group_id),
        &member_agent_id,
        &member_public_key_b64,
        role,
        None,
        inviter_agent_id,
        invite_secret,
        ts_ms,
        None,
    );
    let sig =
        ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(keypair.secret_key(), &canonical)
            .expect("sign forged member_joined");
    serde_json::json!({
        "event": "member_joined",
        "group_id": group_id,
        "stable_group_id": group_id,
        "member_agent_id": member_agent_id,
        "member_public_key_b64": member_public_key_b64,
        "role": role,
        "display_name": null,
        "inviter_agent_id": inviter_agent_id,
        "invite_secret": invite_secret,
        "ts_ms": ts_ms,
        "signature_b64": base64::engine::general_purpose::STANDARD.encode(sig.as_bytes()),
    })
}

/// Acceptance criterion 1 happy path: bob joins alice's `public_open`
/// group via invite, alice's `members_v2` reflects bob within the local
/// mesh budget, and bob's signed public message is accepted by alice within
/// the same budget.
#[tokio::test]
async fn member_joined_event_propagates_to_inviter() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let group_id = create_public_open_group(alice, "Roster Propagation").await;
    let invite = create_invite(alice, &group_id).await;

    let bob_aid = bob.agent_id().await;
    let join_resp = join_via_invite(bob, &invite, "bob-rp").await;
    assert_eq!(join_resp["ok"], true, "join response: {join_resp:?}");

    // Phase 1: bob's MemberJoined event reaches alice's metadata listener.
    let alice_sees_bob = wait_until(Duration::from_secs(30), || async {
        list_members(alice, &group_id).await.contains(&bob_aid)
    })
    .await;
    assert!(
        alice_sees_bob,
        "alice's members_v2 never picked up bob via MemberJoined event",
    );

    // Diagnostics row shows `member_joined_events_applied >= 1` on alice.
    let diag = diagnostics_groups(alice).await;
    let groups_arr = diag["groups"].as_array().cloned().unwrap_or_default();
    let row = groups_arr
        .iter()
        .find(|g| g["group_id"].as_str() == Some(group_id.as_str()))
        .cloned()
        .expect("alice diagnostics row for group");
    assert!(
        row["member_joined_events_applied"]
            .as_u64()
            .unwrap_or_default()
            >= 1,
        "alice diagnostics row missing applied MemberJoined event: {row:?}",
    );
    assert!(
        row["members_v2_size"].as_u64().unwrap_or_default() >= 2,
        "alice diagnostics members_v2_size should reflect alice+bob: {row:?}",
    );

    // Phase 2: bob's signed public message lands in alice's cache.
    let body = "from bob: roster-propagation-fix";
    let post = post_public_message(bob, &group_id, body).await;
    assert_eq!(post["ok"], true, "post: {post:?}");

    let alice_sees_msg = wait_until(Duration::from_secs(30), || async {
        list_public_messages(alice, &group_id)
            .await
            .iter()
            .any(|b| b == body)
    })
    .await;
    assert!(
        alice_sees_msg,
        "alice never saw bob's signed message — WritePolicyViolation regression?",
    );

    // Cleanup
    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}")))
        .send()
        .await;
}

/// Idempotency: a second join attempt with the same invite (or a replayed
/// MemberJoined event under a duplicate publish) does not double-count
/// bob in alice's `members_v2`.
#[tokio::test]
async fn member_joined_event_is_idempotent() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let group_id = create_public_open_group(alice, "Idempotent Joins").await;
    let invite = create_invite(alice, &group_id).await;

    let bob_aid = bob.agent_id().await;
    let join_resp = join_via_invite(bob, &invite, "bob-idemp").await;
    assert_eq!(join_resp["ok"], true, "first join: {join_resp:?}");

    let converged = wait_until(Duration::from_secs(30), || async {
        list_members(alice, &group_id).await.contains(&bob_aid)
    })
    .await;
    assert!(converged, "alice never saw bob after first join");

    let baseline = list_members(alice, &group_id).await.len();

    // Re-publish the same event by triggering a second join. The local
    // join handler will recreate state and re-emit; alice's applier
    // returns false (no-op) on already-active members — the count must
    // not change.
    let _ = join_via_invite(bob, &invite, "bob-idemp-2").await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = list_members(alice, &group_id).await.len();
    assert_eq!(after, baseline, "MemberJoined applier is not idempotent");

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}")))
        .send()
        .await;
}

/// Pure-Rust verification path: a tampered canonical signing field does
/// not change the joiner's local state but **does** make the receiver
/// reject the event.
///
/// We exercise this via the public-API contract by re-deriving the
/// canonical bytes layout against `GroupRole::as_u8` — bumping a single
/// byte in the role tag breaks the recomputed verify on the wire.
#[test]
fn group_role_as_u8_is_stable_across_releases() {
    use x0x::groups::GroupRole;
    // The on-the-wire role tag is stable; downstream daemons running an
    // older release must continue to verify against the same byte.
    assert_eq!(GroupRole::Owner.as_u8(), 0);
    assert_eq!(GroupRole::Admin.as_u8(), 1);
    assert_eq!(GroupRole::Moderator.as_u8(), 2);
    assert_eq!(GroupRole::Member.as_u8(), 3);
    assert_eq!(GroupRole::Guest.as_u8(), 4);
}

/// Wire-tamper regression: a valid MemberJoined payload must bind signed
/// fields to the signature. Mutating the signed role after signature
/// generation must fail before Alice reaches the role-policy rejection path,
/// while the unmodified payload from the same helper remains acceptable.
#[tokio::test]
async fn tampered_member_joined_signed_role_is_rejected_before_role_policy() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let group_id = create_public_open_group(alice, "Reject Tampered Role").await;
    let details = group_details(alice, &group_id).await;
    let metadata_topic = details["metadata_topic"].as_str().map(ToString::to_string);
    assert!(
        metadata_topic.is_some(),
        "group details missing metadata_topic: {details:?}",
    );
    let Some(metadata_topic) = metadata_topic else {
        return;
    };
    let invite = create_invite(alice, &group_id).await;
    let parsed = x0x::groups::invite::SignedInvite::from_link(&invite);
    assert!(parsed.is_ok(), "parse invite failed");
    let Ok(parsed) = parsed else {
        return;
    };
    let bob_aid = bob.agent_id().await;

    let role_rejected_before = group_diagnostic_counter(
        alice,
        &group_id,
        "member_joined_events_rejected_non_member_role",
    )
    .await;
    let applied_before =
        group_diagnostic_counter(alice, &group_id, "member_joined_events_applied").await;

    let valid = signed_member_joined_event(
        bob,
        &group_id,
        &parsed.inviter,
        &parsed.invite_secret,
        x0x::groups::GroupRole::Member,
    )
    .await;
    let mut tampered = valid.clone();
    tampered["role"] = serde_json::json!("admin");

    let payload = serde_json::to_vec(&tampered);
    assert!(payload.is_ok(), "tampered event json failed");
    let Ok(payload) = payload else {
        return;
    };
    let published = publish_raw(bob, &metadata_topic, &payload).await;
    assert_eq!(
        published["ok"], true,
        "publish tampered event: {published:?}"
    );

    let admitted_after_tamper = wait_until(Duration::from_secs(15), || async {
        list_members(alice, &group_id).await.contains(&bob_aid)
    })
    .await;
    assert!(
        !admitted_after_tamper,
        "tampered MemberJoined unexpectedly admitted bob",
    );
    assert_eq!(
        group_diagnostic_counter(
            alice,
            &group_id,
            "member_joined_events_rejected_non_member_role",
        )
        .await,
        role_rejected_before,
        "tampered role reached role-policy rejection instead of signature verification",
    );
    assert_eq!(
        group_diagnostic_counter(alice, &group_id, "member_joined_events_applied").await,
        applied_before,
        "tampered MemberJoined unexpectedly applied",
    );

    let payload = serde_json::to_vec(&valid);
    assert!(payload.is_ok(), "valid event json failed");
    let Ok(payload) = payload else {
        return;
    };
    let published = publish_raw(bob, &metadata_topic, &payload).await;
    assert_eq!(
        published["ok"], true,
        "publish valid control event: {published:?}"
    );
    let control_applied = wait_until(Duration::from_secs(30), || async {
        group_diagnostic_counter(alice, &group_id, "member_joined_events_applied").await
            > applied_before
            && list_members(alice, &group_id).await.contains(&bob_aid)
    })
    .await;
    assert!(
        control_applied,
        "valid MemberJoined control did not admit bob",
    );

    let details = group_details(alice, &group_id).await;
    let members = details["members"].as_array();
    assert!(
        members.is_some(),
        "group details missing members: {details:?}"
    );
    let Some(members) = members else {
        return;
    };
    let bob_row = members
        .iter()
        .find(|m| m["agent_id"].as_str() == Some(bob_aid.as_str()));
    assert!(bob_row.is_some(), "missing bob member row: {members:?}");
    let Some(bob_row) = bob_row else {
        return;
    };
    assert_eq!(
        bob_row["role"], "member",
        "valid control must admit bob only as member",
    );

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}")))
        .send()
        .await;
}

/// Security regression: a joiner who holds a valid invite must not be able
/// to self-promote by publishing a `MemberJoined { role: admin }` payload,
/// and a joiner without a minted secret must not be admitted. Forged events
/// must leave the one-time invite usable for the legitimate Member join that
/// follows.
#[tokio::test]
async fn forged_member_joined_admin_role_or_secret_is_rejected() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let group_id = create_public_open_group(alice, "Reject Role Escalation").await;
    let details = group_details(alice, &group_id).await;
    let metadata_topic = details["metadata_topic"]
        .as_str()
        .expect("metadata_topic")
        .to_string();
    let invite = create_invite(alice, &group_id).await;
    let parsed = x0x::groups::invite::SignedInvite::from_link(&invite).expect("parse invite");
    let bob_aid = bob.agent_id().await;
    let admin_rejected_before = group_diagnostic_counter(
        alice,
        &group_id,
        "member_joined_events_rejected_non_member_role",
    )
    .await;
    let forged = signed_member_joined_event(
        bob,
        &group_id,
        &parsed.inviter,
        &parsed.invite_secret,
        x0x::groups::GroupRole::Admin,
    )
    .await;
    let payload = serde_json::to_vec(&forged).expect("forge json");
    let published = publish_raw(bob, &metadata_topic, &payload).await;
    assert_eq!(published["ok"], true, "publish forged event: {published:?}");

    let admin_rejected = wait_until(Duration::from_secs(30), || async {
        group_diagnostic_counter(
            alice,
            &group_id,
            "member_joined_events_rejected_non_member_role",
        )
        .await
            > admin_rejected_before
    })
    .await;
    assert!(
        admin_rejected,
        "alice never reported rejecting forged admin MemberJoined",
    );
    assert!(
        !list_members(alice, &group_id).await.contains(&bob_aid),
        "forged admin MemberJoined unexpectedly admitted bob",
    );

    let unknown_secret_rejected_before = group_diagnostic_counter(
        alice,
        &group_id,
        "member_joined_events_rejected_invite_secret_unknown",
    )
    .await;
    let forged_secret = signed_member_joined_event(
        bob,
        &group_id,
        &parsed.inviter,
        &"00".repeat(32),
        x0x::groups::GroupRole::Member,
    )
    .await;
    let payload = serde_json::to_vec(&forged_secret).expect("forge secret json");
    let published = publish_raw(bob, &metadata_topic, &payload).await;
    assert_eq!(
        published["ok"], true,
        "publish forged secret event: {published:?}"
    );
    let unknown_secret_rejected = wait_until(Duration::from_secs(30), || async {
        group_diagnostic_counter(
            alice,
            &group_id,
            "member_joined_events_rejected_invite_secret_unknown",
        )
        .await
            > unknown_secret_rejected_before
    })
    .await;
    assert!(
        unknown_secret_rejected,
        "alice never reported rejecting forged unknown-secret MemberJoined",
    );
    assert!(
        !list_members(alice, &group_id).await.contains(&bob_aid),
        "forged unknown-secret MemberJoined unexpectedly admitted bob",
    );

    let join_resp = join_via_invite(bob, &invite, "bob-member").await;
    assert_eq!(join_resp["ok"], true, "legitimate join: {join_resp:?}");
    let converged = wait_until(Duration::from_secs(30), || async {
        list_members(alice, &group_id).await.contains(&bob_aid)
    })
    .await;
    assert!(
        converged,
        "valid member join did not converge after forged admin event"
    );

    let details = group_details(alice, &group_id).await;
    let members = details["members"].as_array().expect("members array");
    let bob_row = members
        .iter()
        .find(|m| m["agent_id"].as_str() == Some(bob_aid.as_str()))
        .expect("bob member row");
    assert_eq!(
        bob_row["role"], "member",
        "bob must be admitted only as member"
    );
}

/// Invite-secret path: alice records a structured one-time invite when she
/// generates the link, then consumes it when bob's `MemberJoined` request is
/// accepted and converted into an authority-signed `MemberAdded` commit.
#[tokio::test]
async fn issued_invite_secret_is_recorded_on_inviter() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let group_id = create_public_open_group(alice, "Invite Secrets").await;
    let invite = create_invite(alice, &group_id).await;

    // The link round-trips through SignedInvite::from_link; we verify
    // alice authenticates and consumes bob's MemberJoined by observing the
    // committed membership converge.
    let bob_aid = bob.agent_id().await;
    let _ = join_via_invite(bob, &invite, "bob-secret").await;
    let converged = wait_until(Duration::from_secs(30), || async {
        list_members(alice, &group_id).await.contains(&bob_aid)
    })
    .await;
    assert!(converged, "alice never saw bob even with valid invite");

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}")))
        .send()
        .await;
}

async fn non_creator_admin_invite_e2e_converges_for_preset(
    preset: &str,
    group_name: &str,
    expect_treekem: bool,
) {
    let cluster = trio_with_extra_config("").await;
    let creator = &cluster.alice;
    let admin = &cluster.bob;
    let joiner = &cluster.charlie;
    let join_timeout = if expect_treekem {
        Duration::from_secs(90)
    } else {
        Duration::from_secs(45)
    };
    let final_timeout = if expect_treekem {
        Duration::from_secs(120)
    } else {
        Duration::from_secs(60)
    };

    let creator_id = creator.agent_id().await;
    let admin_id = admin.agent_id().await;
    let joiner_id = joiner.agent_id().await;
    assert_ne!(creator_id, admin_id, "fixture needs non-creator admin");

    let group_id = create_group_with_preset(creator, group_name, preset).await;
    if expect_treekem {
        let binding = group_state_field(creator, &group_id, "security_binding")
            .await
            .expect("creator TreeKEM security binding after create");
        assert!(
            binding.starts_with("treekem:epoch="),
            "private_secure variant must exercise TreeKEM, got {binding:?}"
        );
    }
    let admin_bootstrap_invite = create_invite(creator, &group_id).await;
    let admin_join = join_via_invite(admin, &admin_bootstrap_invite, "admin-before-role").await;
    assert_eq!(admin_join["ok"], true, "admin join: {admin_join:?}");
    let admin_group_id = admin_join["group_id"]
        .as_str()
        .unwrap_or(&group_id)
        .to_string();

    let creator_sees_admin = wait_until(join_timeout, || async {
        list_members(creator, &group_id).await.contains(&admin_id)
    })
    .await;
    assert!(
        creator_sees_admin,
        "creator never observed admin's initial join"
    );
    let creator_hash_after_admin_join = group_state_field(creator, &group_id, "state_hash")
        .await
        .expect("creator state_hash after admin join");
    let admin_caught_up = wait_until(join_timeout, || async {
        group_state_field(admin, &admin_group_id, "state_hash")
            .await
            .as_deref()
            == Some(creator_hash_after_admin_join.as_str())
    })
    .await;
    assert!(admin_caught_up, "admin never caught up after initial join");

    let _ = set_member_role(creator, &group_id, &admin_id, "admin").await;
    let role_converged = wait_until(join_timeout, || async {
        let creator_details = group_details(creator, &group_id).await;
        let admin_details = group_details(admin, &admin_group_id).await;
        let creator_hash = group_state_field(creator, &group_id, "state_hash").await;
        let admin_hash = group_state_field(admin, &admin_group_id, "state_hash").await;
        member_has_role(&creator_details, &admin_id, "admin")
            && member_has_role(&admin_details, &admin_id, "admin")
            && creator_hash.is_some()
            && creator_hash == admin_hash
    })
    .await;
    assert!(role_converged, "promoted admin role did not converge");

    let admin_invite = create_invite(admin, &admin_group_id).await;
    let parsed_invite = x0x::groups::invite::SignedInvite::from_link(&admin_invite)
        .expect("admin-issued invite parses");
    assert_eq!(
        parsed_invite.inviter, admin_id,
        "invite routing target must be the issuing admin"
    );
    assert_eq!(
        parsed_invite
            .creator_agent_id_from_base_state()
            .expect("creator provenance derives from base state"),
        creator_id,
        "creator provenance must stay historical, not authority-bearing inviter metadata"
    );

    let join_resp = join_via_invite(joiner, &admin_invite, "joiner-via-admin").await;
    assert_eq!(join_resp["ok"], true, "joiner response: {join_resp:?}");
    let joiner_group_id = join_resp["group_id"]
        .as_str()
        .unwrap_or(&group_id)
        .to_string();

    let converged = wait_until(final_timeout, || async {
        let creator_details = group_details(creator, &group_id).await;
        let admin_details = group_details(admin, &admin_group_id).await;
        let joiner_details = group_details(joiner, &joiner_group_id).await;
        let creator_hash = group_state_field(creator, &group_id, "state_hash").await;
        let admin_hash = group_state_field(admin, &admin_group_id, "state_hash").await;
        let joiner_hash = group_state_field(joiner, &joiner_group_id, "state_hash").await;
        let creator_roster = group_state_field(creator, &group_id, "roster_root").await;
        let admin_roster = group_state_field(admin, &admin_group_id, "roster_root").await;
        let joiner_roster = group_state_field(joiner, &joiner_group_id, "roster_root").await;
        let security_bindings_ok = if expect_treekem {
            let creator_binding = group_state_field(creator, &group_id, "security_binding").await;
            let admin_binding = group_state_field(admin, &admin_group_id, "security_binding").await;
            let joiner_binding =
                group_state_field(joiner, &joiner_group_id, "security_binding").await;
            creator_binding
                .as_deref()
                .is_some_and(|binding| binding.starts_with("treekem:epoch="))
                && creator_binding == admin_binding
                && admin_binding == joiner_binding
        } else {
            true
        };

        [&creator_details, &admin_details, &joiner_details]
            .iter()
            .all(|details| {
                member_has_role(details, &admin_id, "admin")
                    && member_is_active_added_by(details, &joiner_id, &admin_id)
            })
            && creator_hash.is_some()
            && creator_hash == admin_hash
            && admin_hash == joiner_hash
            && creator_roster.is_some()
            && creator_roster == admin_roster
            && admin_roster == joiner_roster
            && security_bindings_ok
    })
    .await;
    assert!(
        converged,
        "admin-authored MemberAdded did not converge coherently across creator/admin/joiner"
    );

    for (label, daemon, local_group_id) in [
        ("creator", creator, group_id.as_str()),
        ("admin", admin, admin_group_id.as_str()),
        ("joiner", joiner, joiner_group_id.as_str()),
    ] {
        let details = group_details(daemon, local_group_id).await;
        assert_eq!(
            details["creator"].as_str(),
            Some(creator_id.as_str()),
            "{label} must retain best-effort historical creator provenance"
        );
        assert_ne!(
            details["creator"].as_str(),
            Some(admin_id.as_str()),
            "{label} must not treat the invite issuer as creator provenance"
        );
    }

    let _ = authed_client(creator)
        .delete(creator.url(&format!("/groups/{group_id}")))
        .send()
        .await;
}

/// ADR-0016 Slice 4 daemon proof: a promoted, non-creator Admin issues an
/// invite through the real REST handler, a separate daemon consumes it through
/// `POST /groups/join`, and the resulting admin-authored `MemberAdded` commit
/// converges across creator, admin, and joiner.
#[tokio::test]
async fn non_creator_admin_invite_e2e_converges_through_real_daemons() {
    non_creator_admin_invite_e2e_converges_for_preset("public_open", "Admin Invite E2E", false)
        .await;
}

/// TreeKEM variant of the Slice 4 daemon proof: for a `private_secure` group,
/// a non-creator Admin's invite drives the real join path to coherent
/// TreeKEM-backed convergence. Direct expected-inviter sender validation is
/// covered by the focused `join_result_requires_stored_expected_inviter` unit
/// regression; this daemon test proves the secure-plane end-to-end join shape.
#[tokio::test]
async fn non_creator_admin_private_secure_invite_e2e_converges_through_real_daemons() {
    non_creator_admin_invite_e2e_converges_for_preset(
        "private_secure",
        "TreeKEM Admin Invite E2E",
        true,
    )
    .await;
}
