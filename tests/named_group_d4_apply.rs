//! Phase D.4 integration tests: state-bearing metadata events must be
//! authority-signed, chain-linked, and converge across daemons.
//!
//! Ignored by default because they require spawning real x0xd daemons.

use reqwest::StatusCode;
use serde_json::Value;
use std::{sync::OnceLock, time::Duration};

#[path = "harness/src/cluster.rs"]
mod cluster;
use cluster::{pair, AgentInstance};

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

static TEST_MUTEX: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn suite_lock() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_MUTEX
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
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

async fn create_group_with_body(d: &AgentInstance, body: Value) -> String {
    let r: Value = authed_client(d)
        .post(d.url("/groups"))
        .json(&body)
        .send()
        .await
        .expect("create group request")
        .json()
        .await
        .expect("create group json");
    assert_eq!(r["ok"], true, "create group response: {r:?}");
    r["group_id"].as_str().unwrap_or_default().to_string()
}

async fn create_group_preset(
    d: &AgentInstance,
    name: &str,
    description: &str,
    preset: &str,
) -> String {
    create_group_with_body(
        d,
        serde_json::json!({
            "name": name,
            "description": description,
            "preset": preset,
        }),
    )
    .await
}

async fn fetch_card(d: &AgentInstance, group_id: &str) -> Value {
    authed_client(d)
        .get(d.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("get card request")
        .json()
        .await
        .expect("get card json")
}

async fn import_card(d: &AgentInstance, card: &Value) -> Value {
    authed_client(d)
        .post(d.url("/groups/cards/import"))
        .json(card)
        .send()
        .await
        .expect("import card request")
        .json()
        .await
        .expect("import card json")
}

async fn agent_card_link(d: &AgentInstance) -> String {
    let card: Value = authed_client(d)
        .get(d.url("/agent/card?include_local_addresses=true"))
        .send()
        .await
        .expect("get agent card request")
        .json()
        .await
        .expect("get agent card json");
    let link = card["link"].as_str().unwrap_or_default().to_string();
    assert!(!link.is_empty(), "agent card missing link: {card:?}");
    link
}

async fn import_agent_card(d: &AgentInstance, link: &str) {
    let resp: Value = authed_client(d)
        .post(d.url("/agent/card/import"))
        .json(&serde_json::json!({
            "card": link,
            "trust_level": "Trusted",
        }))
        .send()
        .await
        .expect("import agent card request")
        .json()
        .await
        .expect("import agent card json");
    assert_eq!(resp["ok"], true, "agent card import failed: {resp:?}");
}

async fn bootstrap_agent_cards(nodes: &[&AgentInstance]) {
    let mut links = Vec::with_capacity(nodes.len());
    for node in nodes {
        links.push(agent_card_link(node).await);
    }
    for (dst_idx, node) in nodes.iter().enumerate() {
        for (src_idx, link) in links.iter().enumerate() {
            if dst_idx != src_idx {
                import_agent_card(node, link).await;
            }
        }
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
}

async fn create_invite(d: &AgentInstance, group_id: &str) -> String {
    let resp = authed_client(d)
        .post(d.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("create invite request");
    assert_eq!(resp.status(), StatusCode::OK, "invite status");
    let r: Value = resp.json().await.expect("invite json");
    r["invite_link"].as_str().unwrap_or_default().to_string()
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

async fn get_state(d: &AgentInstance, group_id: &str) -> Value {
    authed_client(d)
        .get(d.url(&format!("/groups/{group_id}/state")))
        .send()
        .await
        .expect("state request")
        .json()
        .await
        .expect("state json")
}

fn state_commit_keys(state: &Value) -> Option<(&str, u64)> {
    let hash = state["state_hash"]
        .as_str()
        .filter(|hash| !hash.is_empty())?;
    let revision = state["state_revision"].as_u64()?;
    Some((hash, revision))
}

async fn wait_state_match_keys(
    a: &AgentInstance,
    a_group_id: &str,
    b: &AgentInstance,
    b_group_id: &str,
) -> (String, u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let a_state = get_state(a, a_group_id).await;
        let b_state = get_state(b, b_group_id).await;
        let a_keys = state_commit_keys(&a_state);
        let b_keys = state_commit_keys(&b_state);

        if a_state["ok"] == true && b_state["ok"] == true && a_keys.is_some() && a_keys == b_keys {
            if let Some((hash, revision)) = a_keys {
                return (hash.to_string(), revision);
            }
        }

        let timed_out = tokio::time::Instant::now() >= deadline;
        assert!(
            !timed_out,
            "state did not converge within timeout: alice={a_state:?} bob={b_state:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_state_match(a: &AgentInstance, b: &AgentInstance, group_id: &str) -> (String, u64) {
    wait_state_match_keys(a, group_id, b, group_id).await
}

async fn wait_state_available(d: &AgentInstance, group_id: &str) -> Value {
    let ready = wait_until(Duration::from_secs(30), || async {
        let state = get_state(d, group_id).await;
        state["ok"] == true
    })
    .await;
    assert!(ready, "state endpoint did not become available");
    get_state(d, group_id).await
}

async fn get_members(d: &AgentInstance, group_id: &str) -> Value {
    authed_client(d)
        .get(d.url(&format!("/groups/{group_id}/members")))
        .send()
        .await
        .expect("members request")
        .json()
        .await
        .expect("members json")
}

async fn list_requests(d: &AgentInstance, group_id: &str) -> Value {
    authed_client(d)
        .get(d.url(&format!("/groups/{group_id}/requests")))
        .send()
        .await
        .expect("list requests request")
        .json()
        .await
        .expect("list requests json")
}

async fn wait_request_status(
    d: &AgentInstance,
    group_id: &str,
    request_id: &str,
    expected_status: &str,
) {
    let matched = wait_until(Duration::from_secs(30), || async {
        let requests = list_requests(d, group_id).await;
        requests["requests"].as_array().is_some_and(|arr| {
            arr.iter().any(|r| {
                r["request_id"].as_str() == Some(request_id)
                    && r["status"].as_str() == Some(expected_status)
            })
        })
    })
    .await;
    assert!(
        matched,
        "request {request_id} did not reach status {expected_status} on admin view"
    );
}

fn member_state(members: &Value, agent_id: &str) -> Option<String> {
    members["members"].as_array().and_then(|arr| {
        arr.iter()
            .find(|m| m["agent_id"].as_str() == Some(agent_id))
            .and_then(|m| m["state"].as_str())
            .map(ToString::to_string)
    })
}

fn member_role(members: &Value, agent_id: &str) -> Option<String> {
    members["members"].as_array().and_then(|arr| {
        arr.iter()
            .find(|m| m["agent_id"].as_str() == Some(agent_id))
            .and_then(|m| m["role"].as_str())
            .map(ToString::to_string)
    })
}

async fn submit_join_request(d: &AgentInstance, group_id: &str, message: &str) -> Value {
    authed_client(d)
        .post(d.url(&format!("/groups/{group_id}/requests")))
        .json(&serde_json::json!({ "message": message }))
        .send()
        .await
        .expect("submit request")
        .json()
        .await
        .expect("submit request json")
}

async fn d4_stateful_events_converge_via_signed_commits_once() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;
    bootstrap_agent_cards(&[alice, bob]).await;

    // `private_secure` resolves to secure-by-default TreeKEM (ADR-0012). This
    // test exercises D4 signed-commit convergence of stateful metadata/roster
    // events. bob is a real invite-joined member (direct add-by-agent_id is a
    // GSS-only roster op the TreeKEM plane rejects without a KeyPackage).
    let group_id =
        create_group_preset(alice, "D4 Apply", "commit wired metadata", "private_secure").await;
    let invite = create_invite(alice, &group_id).await;
    let join = join_via_invite(bob, &invite, "bob-d4").await;
    assert_eq!(join["ok"], true, "join response: {join:?}");

    let a0 = get_state(alice, &group_id).await;
    assert_eq!(a0["ok"], true, "alice state: {a0:?}");
    let b0 = wait_state_available(bob, &group_id).await;
    assert_eq!(b0["ok"], true, "bob state: {b0:?}");

    // Converge: bob's invite-join produces the owner's authoritative MemberAdded
    // (Commit+Welcome), making bob Active in alice's roster.
    let bob_agent_id = bob.agent_id().await;
    let active = wait_until(Duration::from_secs(90), || async {
        let members = get_members(alice, &group_id).await;
        member_state(&members, &bob_agent_id).as_deref() == Some("active")
    })
    .await;
    assert!(active, "bob did not become active in alice's roster");
    let (_hash0, rev0) = wait_state_match(alice, bob, &group_id).await;

    // Owner-authored metadata edit.
    let resp = authed_client(alice)
        .patch(alice.url(&format!("/groups/{group_id}")))
        .json(&serde_json::json!({
            "name": "D4 Apply Renamed",
            "description": "after metadata patch",
        }))
        .send()
        .await
        .expect("metadata patch request");
    assert_eq!(resp.status(), StatusCode::OK);
    let (_hash1, rev1) = wait_state_match(alice, bob, &group_id).await;
    assert!(rev1 > rev0, "metadata patch should advance revision");

    // Owner-authored policy edit.
    let resp = authed_client(alice)
        .patch(alice.url(&format!("/groups/{group_id}/policy")))
        .json(&serde_json::json!({
            "discoverability": "public_directory",
            "admission": "open_join",
            "confidentiality": "signed_public",
            "read_access": "public",
            "write_access": "members_only",
        }))
        .send()
        .await
        .expect("policy patch request");
    assert_eq!(resp.status(), StatusCode::OK);
    let (_hash2, rev2) = wait_state_match(alice, bob, &group_id).await;
    assert!(rev2 > rev1, "policy patch should advance revision");

    let resp = authed_client(alice)
        .patch(alice.url(&format!("/groups/{group_id}/members/{bob_agent_id}/role")))
        .json(&serde_json::json!({ "role": "admin" }))
        .send()
        .await
        .expect("role patch request");
    assert_eq!(resp.status(), StatusCode::OK);
    let (_hash3, rev3) = wait_state_match(alice, bob, &group_id).await;
    assert!(rev3 > rev2, "role patch should advance revision");
    let bob_members = get_members(bob, &group_id).await;
    assert_eq!(
        member_role(&bob_members, &bob_agent_id).as_deref(),
        Some("admin")
    );

    // NOTE: the GSS-era version of this test added/banned/unbanned/removed a
    // synthetic `charlie` agent here to exercise roster-mutation convergence.
    // On the secure-by-default TreeKEM plane a member cannot be added without a
    // real KeyPackage (and `pair()` provides no third real daemon), so direct
    // roster mutation of a non-existent agent does not apply. TreeKEM ban /
    // epoch-advance convergence is covered by
    // `d4_mls_ban_commit_advances_binding_and_converges`; this test focuses on
    // signed-commit convergence of owner-authored metadata/policy/role events.

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}")))
        .send()
        .await;
}

#[tokio::test]
#[ignore]
async fn d4_stateful_events_converge_via_signed_commits() {
    let _guard = suite_lock().await;
    for attempt in 1..=3 {
        match tokio::spawn(d4_stateful_events_converge_via_signed_commits_once()).await {
            Ok(()) => return,
            Err(err) if attempt < 3 => {
                eprintln!("[d4] stateful-events attempt {attempt} failed: {err}");
            }
            Err(err) => {
                panic!("d4_stateful_events_converge_via_signed_commits failed after retries: {err}")
            }
        }
    }
}

async fn d4_join_request_events_converge_via_signed_commits_once() {
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;
    bootstrap_agent_cards(&[alice, bob]).await;

    let alice_group_id = create_group_preset(
        alice,
        "D4 Requests",
        "request lifecycle commit wiring",
        "public_request_secure",
    )
    .await;
    let card = fetch_card(alice, &alice_group_id).await;
    let bob_group_id = card["group_id"].as_str().unwrap_or_default().to_string();
    assert!(
        !bob_group_id.is_empty(),
        "group card missing stable group_id: {card:?}"
    );

    let imported = import_card(bob, &card).await;
    assert_eq!(imported["ok"], true, "imported stub: {imported:?}");
    let bob_info = authed_client(bob)
        .get(bob.url(&format!("/groups/{bob_group_id}")))
        .send()
        .await
        .expect("bob get stub")
        .json::<Value>()
        .await
        .expect("bob stub json");
    assert_eq!(bob_info["ok"], true, "bob stub info: {bob_info:?}");
    tokio::time::sleep(Duration::from_secs(3)).await;

    let req1 = submit_join_request(bob, &bob_group_id, "first pending request").await;
    assert_eq!(req1["ok"], true, "request1 response: {req1:?}");
    let req1_id = req1["request_id"].as_str().unwrap_or_default().to_string();
    assert!(!req1_id.is_empty(), "request1 id missing");
    wait_request_status(alice, &alice_group_id, &req1_id, "pending").await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let dup = authed_client(bob)
        .post(bob.url(&format!("/groups/{bob_group_id}/requests")))
        .json(&serde_json::json!({ "message": "duplicate" }))
        .send()
        .await
        .expect("duplicate request");
    assert_eq!(dup.status(), StatusCode::CONFLICT);

    let cancel = authed_client(bob)
        .delete(bob.url(&format!("/groups/{bob_group_id}/requests/{req1_id}")))
        .send()
        .await
        .expect("cancel request1");
    assert_eq!(cancel.status(), StatusCode::OK);
    wait_request_status(alice, &alice_group_id, &req1_id, "cancelled").await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let req2 = submit_join_request(bob, &bob_group_id, "please reject me").await;
    assert_eq!(req2["ok"], true, "request2 response: {req2:?}");
    let req2_id = req2["request_id"].as_str().unwrap_or_default().to_string();
    wait_request_status(alice, &alice_group_id, &req2_id, "pending").await;

    let reject = authed_client(alice)
        .post(alice.url(&format!(
            "/groups/{alice_group_id}/requests/{req2_id}/reject"
        )))
        .send()
        .await
        .expect("reject request2");
    assert_eq!(reject.status(), StatusCode::OK);
    wait_request_status(alice, &alice_group_id, &req2_id, "rejected").await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let req3 = submit_join_request(bob, &bob_group_id, "final approval request").await;
    assert_eq!(req3["ok"], true, "request3 response: {req3:?}");
    let req3_id = req3["request_id"].as_str().unwrap_or_default().to_string();
    wait_request_status(alice, &alice_group_id, &req3_id, "pending").await;
    let (_pending_hash, pending_rev) =
        wait_state_match_keys(alice, &alice_group_id, bob, &bob_group_id).await;

    let approve = authed_client(alice)
        .post(alice.url(&format!(
            "/groups/{alice_group_id}/requests/{req3_id}/approve"
        )))
        .send()
        .await
        .expect("approve request3");
    assert_eq!(approve.status(), StatusCode::OK);
    let (approved_hash, approved_rev) =
        wait_state_match_keys(alice, &alice_group_id, bob, &bob_group_id).await;
    assert!(
        !approved_hash.is_empty(),
        "approval should converge on a non-empty state hash"
    );
    assert!(
        approved_rev > pending_rev,
        "approval should advance revision from {pending_rev} to {approved_rev}"
    );
    wait_request_status(alice, &alice_group_id, &req3_id, "approved").await;

    let bob_agent_id = bob.agent_id().await;
    let alice_members = get_members(alice, &alice_group_id).await;
    assert_eq!(
        member_state(&alice_members, &bob_agent_id).as_deref(),
        Some("active")
    );
    let bob_members = get_members(bob, &bob_group_id).await;
    assert_eq!(
        member_state(&bob_members, &bob_agent_id).as_deref(),
        Some("active")
    );

    let post_approval = authed_client(bob)
        .post(bob.url(&format!("/groups/{bob_group_id}/requests")))
        .json(&serde_json::json!({ "message": "should fail after membership" }))
        .send()
        .await
        .expect("post approval request");
    assert_eq!(post_approval.status(), StatusCode::CONFLICT);

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{alice_group_id}")))
        .send()
        .await;
}

#[tokio::test]
#[ignore]
async fn d4_join_request_events_converge_via_signed_commits() {
    let _guard = suite_lock().await;
    for attempt in 1..=3 {
        match tokio::spawn(d4_join_request_events_converge_via_signed_commits_once()).await {
            Ok(()) => return,
            Err(err) if attempt < 3 => {
                eprintln!("[d4] join-request attempt {attempt} failed: {err}");
            }
            Err(err) => panic!(
                "d4_join_request_events_converge_via_signed_commits failed after retries: {err}"
            ),
        }
    }
}

#[tokio::test]
#[ignore]
async fn d4_mls_ban_commit_advances_binding_and_converges() {
    let _guard = suite_lock().await;
    // Use a fresh, OWNED trio (not the `cluster()` `&'static` singleton): the
    // singleton's 3 daemons live for the whole test binary and are never
    // dropped, so they linger on the loopback interface alongside every other
    // d4 test's `pair()` daemons (3 + 2 = 5 concurrent QUIC endpoints). That
    // contention is exactly the dual-stack-loopback hazard documented in
    // `.config/nextest.toml`, and it intermittently stalls `d4_stateful`'s
    // gossip convergence. An owned trio is killed when this test returns.
    let cluster = cluster::trio_with_extra_config("").await;
    let alice = &cluster.alice;
    let bob = &cluster.bob;
    let charlie = &cluster.charlie;
    bootstrap_agent_cards(&[alice, bob, charlie]).await;

    // `private_secure` resolves to secure-by-default TreeKEM (ADR-0012). A ban is
    // a verified TreeKEM removal that advances the group epoch. The owner bans a
    // REAL invite-joined member (KeyPackage exchanged via invite/Welcome), while
    // another non-banned member observes convergence. Per-leaf TreeKEM state hashes
    // differ, so this test checks epoch-bound security bindings + roster state.
    let group_id = create_group_preset(alice, "D4 Ban", "treekem ban path", "private_secure").await;

    let bob_invite = create_invite(alice, &group_id).await;
    let bob_join = join_via_invite(bob, &bob_invite, "bob-ban-observer").await;
    assert_eq!(bob_join["ok"], true, "bob join response: {bob_join:?}");
    let _ = wait_state_available(bob, &group_id).await;

    let charlie_invite = create_invite(alice, &group_id).await;
    let charlie_join = join_via_invite(charlie, &charlie_invite, "charlie-ban-target").await;
    assert_eq!(
        charlie_join["ok"], true,
        "charlie join response: {charlie_join:?}"
    );
    let _ = wait_state_available(charlie, &group_id).await;

    // Converge: the owner's authoritative MemberAdded commits make both real
    // members Active in alice's roster before the ban.
    let bob_agent_id = bob.agent_id().await;
    let charlie_agent_id = charlie.agent_id().await;
    let active = wait_until(Duration::from_secs(90), || async {
        let members = get_members(alice, &group_id).await;
        member_state(&members, &bob_agent_id).as_deref() == Some("active")
            && member_state(&members, &charlie_agent_id).as_deref() == Some("active")
    })
    .await;
    assert!(
        active,
        "bob and charlie did not become active in alice's TreeKEM roster"
    );

    // The group is on the TreeKEM plane before the ban for both owner and
    // non-banned observer.
    let pre = get_state(alice, &group_id).await;
    let pre_binding = pre["security_binding"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        pre_binding.starts_with("treekem:epoch="),
        "pre-ban alice binding should be on the treekem plane, got {pre_binding:?}"
    );
    let bob_pre = get_state(bob, &group_id).await;
    let bob_pre_binding = bob_pre["security_binding"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        bob_pre_binding.starts_with("treekem:epoch="),
        "pre-ban bob binding should be on the treekem plane, got {bob_pre_binding:?}"
    );

    // Ban charlie: verified TreeKEM removal + epoch advance. Bob remains in the
    // group and must observe the removal, proving cross-daemon convergence.
    let resp = authed_client(alice)
        .post(alice.url(&format!("/groups/{group_id}/ban/{charlie_agent_id}")))
        .send()
        .await
        .expect("ban charlie");
    assert_eq!(resp.status(), StatusCode::OK, "ban status");

    // The ban advances the owner's TreeKEM epoch, and charlie converges to
    // `banned` in both the owner and non-banned observer rosters.
    let advanced = wait_until(Duration::from_secs(90), || async {
        let alice_state = get_state(alice, &group_id).await;
        let alice_binding = alice_state["security_binding"].as_str().unwrap_or_default();
        alice_binding.starts_with("treekem:epoch=") && alice_binding != pre_binding
    })
    .await;
    assert!(
        advanced,
        "ban should advance alice's treekem epoch binding from {pre_binding:?}"
    );
    let banned = wait_until(Duration::from_secs(90), || async {
        let alice_members = get_members(alice, &group_id).await;
        let bob_members = get_members(bob, &group_id).await;
        member_state(&alice_members, &charlie_agent_id).as_deref() == Some("banned")
            && member_state(&bob_members, &charlie_agent_id).as_deref() == Some("banned")
    })
    .await;
    assert!(
        banned,
        "charlie should converge to `banned` in alice and bob rosters"
    );

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}")))
        .send()
        .await;
}

/// issue #111: the retained state-commit history endpoint serves applied
/// commits paired with independently-verifiable roster projections, ordered by
/// revision, with working pagination. Members-only (the local owner is a
/// member, so it is served here).
#[tokio::test]
#[ignore = "requires spawning real x0xd daemons"]
async fn state_commits_endpoint_serves_retained_history() {
    let _guard = suite_lock().await;
    let pair = pair().await;
    let alice = &pair.alice;

    let group_id =
        create_group_preset(alice, "Issue111", "retained history", "private_secure").await;

    // Advance the signed chain a few times via owner-authored metadata edits;
    // each distinct edit reseals a new commit.
    for name in ["rev-a", "rev-b", "rev-c"] {
        let resp = authed_client(alice)
            .patch(alice.url(&format!("/groups/{group_id}")))
            .json(&serde_json::json!({ "name": name }))
            .send()
            .await
            .expect("patch group");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "metadata patch should succeed"
        );
    }

    let head = get_state(alice, &group_id).await;
    let head_rev = head["state_revision"].as_u64().expect("head revision");
    assert!(head_rev >= 3, "expected >=3 commits, head at {head_rev}");

    // Full history.
    let body: Value = authed_client(alice)
        .get(alice.url(&format!("/groups/{group_id}/state/commits")))
        .send()
        .await
        .expect("get commits")
        .json()
        .await
        .expect("commits json");
    assert_eq!(body["ok"], true, "commits response: {body:?}");

    let commits = body["commits"].as_array().expect("commits array");
    assert!(
        commits.len() as u64 >= head_rev,
        "retained {} commits but head at {head_rev}",
        commits.len()
    );

    // Each retained entry must self-verify and be strictly revision-ordered.
    let mut prev_rev = 0u64;
    for entry in commits {
        assert_eq!(
            entry["roster_root_verified"], true,
            "retained roster must re-derive the signed roster_root: {entry:?}"
        );
        let rev = entry["commit"]["revision"]
            .as_u64()
            .expect("commit revision");
        assert!(
            rev > prev_rev,
            "commits must be strictly ascending in revision"
        );
        prev_rev = rev;
        assert!(
            entry["roster"].as_object().is_some_and(|r| !r.is_empty()),
            "roster projection should be non-empty (owner present): {entry:?}"
        );
    }

    // Pagination: limit + from_revision cursor must advance across pages.
    let page1: Value = authed_client(alice)
        .get(alice.url(&format!("/groups/{group_id}/state/commits?limit=1")))
        .send()
        .await
        .expect("page1")
        .json()
        .await
        .expect("page1 json");
    assert_eq!(page1["count"], 1, "limit=1 returns one entry: {page1:?}");
    assert_eq!(page1["has_more"], true, "more pages expected: {page1:?}");
    let next = page1["next_from_revision"].as_u64().expect("cursor");
    let page2: Value = authed_client(alice)
        .get(alice.url(&format!(
            "/groups/{group_id}/state/commits?from_revision={next}&limit=1"
        )))
        .send()
        .await
        .expect("page2")
        .json()
        .await
        .expect("page2 json");
    let p1_rev = page1["commits"][0]["commit"]["revision"]
        .as_u64()
        .expect("p1 rev");
    let p2_rev = page2["commits"][0]["commit"]["revision"]
        .as_u64()
        .expect("p2 rev");
    assert!(p2_rev > p1_rev, "cursor must advance past the first page");

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}")))
        .send()
        .await;
}
