//! ADR-0029 threading integration tests — signed public group messages.
//!
//! Daemon-backed REST-level tests covering:
//!
//! 1. Two-daemon threaded round-trip with cross-daemon msg_id stability.
//! 2. Ingest validation: structurally invalid thread fields rejected with 400.
//! 3. Orphan reply: reply to a nonexistent parent is accepted (ADR-0028).
//! 4. Backward-compat wire: non-threaded messages carry no thread keys.
//!
//! All tests are `#[ignore]` — they spawn real x0xd daemons via the cluster
//! harness. Run with:
//!   cargo nextest run --test threading_integration -- --ignored
//!
//! Before running: cargo build --bin x0xd
//!
//! Isolation guarantees (inherited from cluster harness):
//! - `--no-hard-coded-bootstrap` — daemons never dial prod bootstrap nodes.
//! - `[update] enabled = false` — test binaries cannot self-replace via gossip.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

#[path = "harness/src/cluster.rs"]
mod cluster;

use cluster::AgentInstance;

// ── helpers ──────────────────────────────────────────────────────────────────

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

/// Poll `check` every 500 ms until it returns `true` or `timeout` elapses.
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
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Create a `public_open` named group (SignedPublic confidentiality,
/// OpenJoin admission, MembersOnly write). Returns the canonical `group_id`
/// from the create response.
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

/// Call `POST /groups/:id/send`. Returns the raw response so callers can
/// inspect both success bodies and error status codes.
async fn send_message(
    d: &AgentInstance,
    group_id: &str,
    body: &str,
    thread_root: Option<&str>,
    thread_parent: Option<&str>,
) -> reqwest::Response {
    let mut payload = serde_json::json!({ "body": body });
    if let Some(r) = thread_root {
        payload["thread_root"] = serde_json::json!(r);
    }
    if let Some(p) = thread_parent {
        payload["thread_parent"] = serde_json::json!(p);
    }
    authed(d)
        .post(d.url(&format!("/groups/{group_id}/send")))
        .json(&payload)
        .send()
        .await
        .expect("POST /groups/:id/send")
}

/// GET /groups/:id/messages — returns the `messages` array or empty on error.
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

/// GET /groups/:id/messages?thread_root=<id> — thread-scoped view.
async fn get_thread(d: &AgentInstance, group_id: &str, thread_root: &str) -> Vec<Value> {
    let resp: Value = authed(d)
        .get(d.url(&format!(
            "/groups/{group_id}/messages?thread_root={thread_root}"
        )))
        .send()
        .await
        .expect("GET /groups/:id/messages?thread_root=")
        .json()
        .await
        .expect("GET thread messages json");
    resp["messages"].as_array().cloned().unwrap_or_default()
}

/// Alice creates an invite link for `group_id`. Bob uses it to join, becoming
/// an active member. Returns the canonical group_id Bob must use for subsequent
/// API calls (extracted from the join response).
///
/// This is the correct flow for `public_open` groups (OpenJoin admission,
/// MembersOnly write). The invite carries the base state so Bob's daemon
/// creates its local group record without a prior card import.
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

    // The join response contains the canonical group_id Bob must use.
    join_resp["group_id"]
        .as_str()
        .unwrap_or(group_id)
        .to_string()
}

/// Poll `d` until `agent_id` appears as an active member of `group_id`.
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

// ── 1. Two-daemon threaded round-trip ────────────────────────────────────────

/// A sends a root message; B replies with thread_root=thread_parent=root_msg_id
/// (NIP-10 direct-reply semantics). Both daemons converge on the thread via
/// gossip. The ?thread_root= filter returns exactly the two-message thread.
/// Cross-daemon msg_id stability is proven: the BLAKE3(signable_bytes) the
/// sender computes matches what the receiver re-computes from the artifact.
///
/// Why msg_id stability matters: ADR-0029 uses msg_id as the bridge
/// translation key and as the thread anchor. If the id diverges after gossip
/// delivery, thread reconstruction and Nostr bridge mapping both break.
///
/// Why the membership pre-condition matters: `ingest_public_message` on Alice
/// runs `validate_public_message` which enforces MembersOnly write. If Alice
/// does not yet know Bob is a member when his reply arrives via gossip, she
/// drops it with WritePolicyViolation — the test would then time out on the
/// cross-daemon poll. We wait for Alice to see Bob's membership before
/// either party sends messages.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn two_daemon_threaded_round_trip() {
    let pair = cluster::pair().await;
    let (alice, bob) = (&pair.alice, &pair.bob);

    // Alice creates a public_open group (SignedPublic, OpenJoin, MembersOnly write).
    let group_id = create_public_open_group(alice, "adr0029-roundtrip").await;

    // Bob joins via Alice's invite link. This adds Bob to the roster and
    // publishes a MemberJoined commit that Alice's daemon will receive via gossip.
    let bob_group_id = bob_joins_via_invite(alice, &group_id, bob).await;
    let bob_id = bob.agent_id().await;

    // Poll Alice until she knows Bob is an active member. This is a hard
    // pre-condition: ingest_public_message drops messages from non-members
    // under MembersOnly write policy, so we must not send until Alice's
    // roster is current.
    let alice_knows_bob = wait_for_membership(alice, &group_id, &bob_id).await;
    assert!(
        alice_knows_bob,
        "Alice never saw Bob as active member within 30 s; \
         subsequent cross-daemon assertions would be vacuous"
    );

    // Poll Bob's daemon until it recognises Bob himself as an active member.
    // The join handler creates a local stub GroupInfo; Bob's `members_v2` is
    // only marked active after Alice processes the MemberJoined event, publishes
    // an authority-signed MemberAdded commit, and that commit propagates back to
    // Bob via gossip. Without this gate, Bob's own POST /groups/:id/send hits
    // the MembersOnly write check and returns a members-only error.
    let bob_knows_himself = wait_for_membership(bob, &bob_group_id, &bob_id).await;
    assert!(
        bob_knows_himself,
        "Bob's daemon never recognised Bob as active member within 30 s; \
         Bob's send would be rejected by his own MembersOnly write check"
    );

    // Alice sends the root message and captures its msg_id from the response.
    let root_resp: Value = send_message(alice, &group_id, "thread root", None, None)
        .await
        .json()
        .await
        .expect("root send json");
    assert_eq!(root_resp["ok"], true, "root send failed: {root_resp:?}");
    let root_msg_id = root_resp["msg_id"]
        .as_str()
        .unwrap_or_else(|| panic!("POST /send response missing msg_id: {root_resp:?}"))
        .to_string();
    assert_eq!(root_msg_id.len(), 64, "msg_id must be 64 chars");
    assert!(
        root_msg_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "msg_id must be lowercase hex: {root_msg_id}"
    );

    // Bob sends a direct reply. NIP-10: direct reply to root ⇒
    // thread_root == thread_parent == root_msg_id.
    let reply_resp: Value = send_message(
        bob,
        &bob_group_id,
        "thread reply",
        Some(&root_msg_id),
        Some(&root_msg_id),
    )
    .await
    .json()
    .await
    .expect("reply send json");
    assert_eq!(reply_resp["ok"], true, "reply send failed: {reply_resp:?}");
    let reply_msg_id = reply_resp["msg_id"]
        .as_str()
        .unwrap_or_else(|| panic!("POST /send response missing msg_id for reply: {reply_resp:?}"))
        .to_string();

    // Poll Alice until Bob's reply arrives via gossip (cross-daemon delivery).
    let alice_sees_reply = wait_until(Duration::from_secs(30), || async {
        get_messages(alice, &group_id)
            .await
            .iter()
            .any(|m| m["msg_id"].as_str() == Some(reply_msg_id.as_str()))
    })
    .await;
    assert!(
        alice_sees_reply,
        "Alice never received Bob's threaded reply within 30 s"
    );

    // Poll Bob until Alice's root arrives via gossip (cross-daemon delivery).
    let bob_sees_root = wait_until(Duration::from_secs(30), || async {
        get_messages(bob, &bob_group_id)
            .await
            .iter()
            .any(|m| m["msg_id"].as_str() == Some(root_msg_id.as_str()))
    })
    .await;
    assert!(
        bob_sees_root,
        "Bob never received Alice's root message within 30 s"
    );

    // Cross-daemon msg_id stability: the root's id on Bob's read surface must
    // be identical to what Alice's POST response reported. The id is
    // BLAKE3(signable_bytes()) — deterministic from the signed content.
    let bob_msgs = get_messages(bob, &bob_group_id).await;
    let root_on_bob = bob_msgs
        .iter()
        .find(|m| m["msg_id"].as_str() == Some(root_msg_id.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "root message ({root_msg_id}) not in Bob's GET /messages surface; \
                 got: {bob_msgs:?}"
            )
        });
    assert_eq!(
        root_on_bob["msg_id"].as_str(),
        Some(root_msg_id.as_str()),
        "cross-daemon msg_id mismatch: BLAKE3(signable_bytes) must be identical on both sides"
    );

    // Assert thread fields on the reply as Alice sees it after gossip delivery.
    let alice_msgs = get_messages(alice, &group_id).await;
    let reply_on_alice = alice_msgs
        .iter()
        .find(|m| m["msg_id"].as_str() == Some(reply_msg_id.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "reply ({reply_msg_id}) not found on Alice's GET /messages surface; \
                 got: {alice_msgs:?}"
            )
        });
    assert_eq!(
        reply_on_alice["thread_root"].as_str(),
        Some(root_msg_id.as_str()),
        "reply thread_root wrong on Alice's surface"
    );
    assert_eq!(
        reply_on_alice["thread_parent"].as_str(),
        Some(root_msg_id.as_str()),
        "reply thread_parent wrong on Alice's surface"
    );

    // Thread filter on Alice: ?thread_root=<root_msg_id> must return exactly
    // root + reply. Any extra messages indicate filter over-inclusion.
    let thread_alice = get_thread(alice, &group_id, &root_msg_id).await;
    let alice_thread_ids: Vec<&str> = thread_alice
        .iter()
        .filter_map(|m| m["msg_id"].as_str())
        .collect();
    assert!(
        alice_thread_ids.contains(&root_msg_id.as_str()),
        "root missing from Alice's ?thread_root= result: {alice_thread_ids:?}"
    );
    assert!(
        alice_thread_ids.contains(&reply_msg_id.as_str()),
        "reply missing from Alice's ?thread_root= result: {alice_thread_ids:?}"
    );
    assert_eq!(
        thread_alice.len(),
        2,
        "Alice's thread filter should return exactly root + reply \
         (got {} messages): {alice_thread_ids:?}",
        thread_alice.len()
    );

    // Same filter on Bob must agree.
    let thread_bob = get_thread(bob, &bob_group_id, &root_msg_id).await;
    let bob_thread_ids: Vec<&str> = thread_bob
        .iter()
        .filter_map(|m| m["msg_id"].as_str())
        .collect();
    assert!(
        bob_thread_ids.contains(&root_msg_id.as_str()),
        "root missing from Bob's ?thread_root= result: {bob_thread_ids:?}"
    );
    assert!(
        bob_thread_ids.contains(&reply_msg_id.as_str()),
        "reply missing from Bob's ?thread_root= result: {bob_thread_ids:?}"
    );
    assert_eq!(
        thread_bob.len(),
        2,
        "Bob's thread filter should return exactly root + reply \
         (got {} messages): {bob_thread_ids:?}",
        thread_bob.len()
    );
}

// ── 2. Endpoint validation ───────────────────────────────────────────────────

/// Structurally invalid thread fields are rejected with 400 before signing.
///
/// Why: the server must validate thread fields before calling
/// `GroupPublicMessage::sign` so that malformed input never produces a
/// signed artifact with unverifiable thread references. Receivers that
/// re-derive the signing domain from field presence would verify a different
/// byte sequence, permanently rejecting the message.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemon"]
async fn validation_bad_thread_fields_are_400() {
    let (solo, _bind_port) = cluster::solo().await;
    let d = &solo;

    let group_id = create_public_open_group(d, "adr0029-validation").await;
    let valid_hex_64: String = "a".repeat(64);

    // thread_parent present, thread_root absent → parent-requires-root rule.
    let resp = send_message(d, &group_id, "bad", None, Some(&valid_hex_64)).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "thread_parent without thread_root must be 400 \
         (got {})",
        resp.status()
    );

    // thread_root is 63 chars (one short of the required 64).
    let short_hex: String = "a".repeat(63);
    let resp = send_message(d, &group_id, "bad", Some(&short_hex), None).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "63-char thread_root must be 400 (got {})",
        resp.status()
    );

    // thread_root contains uppercase hex (not lowercase).
    let upper_hex: String = "A".repeat(64);
    let resp = send_message(d, &group_id, "bad", Some(&upper_hex), None).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "uppercase thread_root must be 400 (got {})",
        resp.status()
    );
}

// ── 3. Orphan reply ──────────────────────────────────────────────────────────

/// A reply referencing a well-formed but nonexistent parent msg_id is accepted.
///
/// Why: per ADR-0028 and ADR-0029, delivery order and local store completeness
/// are not authorization signals. Gossip history is partial by design — a node
/// that missed the root must still accept and cache replies so that late joiners
/// can reconstruct threads once they receive the root. Gating acceptance on
/// parent existence would create silent availability holes for catching-up nodes.
///
/// The orphan reply must appear in both the unfiltered message list AND the
/// ?thread_root=<phantom> filtered view so clients can reconstruct threads
/// that arrive out of order.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemon"]
async fn orphan_reply_accepted_and_filterable() {
    let (solo, _bind_port) = cluster::solo().await;
    let d = &solo;

    let group_id = create_public_open_group(d, "adr0029-orphan").await;

    // A well-formed 64-char lowercase hex that references no message in the
    // daemon's store. The daemon must not check for parent existence.
    let phantom_root: String = "d".repeat(64);

    let resp = send_message(
        d,
        &group_id,
        "orphan reply",
        Some(&phantom_root),
        Some(&phantom_root),
    )
    .await;
    let status = resp.status();
    let body: Value = resp.json().await.expect("orphan reply json");
    assert_eq!(
        status,
        StatusCode::OK,
        "orphan reply must be accepted (parent existence is not required): \
         got {status} — {body:?}"
    );
    assert_eq!(body["ok"], true, "orphan reply response not ok: {body:?}");
    let sent_msg_id = body["msg_id"]
        .as_str()
        .expect("msg_id in orphan reply response");

    // The reply must appear in the unfiltered message list.
    let msgs = get_messages(d, &group_id).await;
    assert!(
        !msgs.is_empty(),
        "message list is empty after successful orphan reply send"
    );
    assert!(
        msgs.iter()
            .any(|m| m["msg_id"].as_str() == Some(sent_msg_id)),
        "orphan reply ({sent_msg_id}) not found in GET /groups/:id/messages: {msgs:?}"
    );

    // The ?thread_root=<phantom> filter must return the orphan reply even
    // though the root itself is absent — the spec says root included "when
    // known", so absence of the root message is acceptable here.
    let thread = get_thread(d, &group_id, &phantom_root).await;
    assert!(
        !thread.is_empty(),
        "?thread_root=<phantom> returned nothing — \
         orphan replies must be included in the thread filter"
    );
    assert!(
        thread
            .iter()
            .any(|m| m["msg_id"].as_str() == Some(sent_msg_id)),
        "orphan reply ({sent_msg_id}) not found via ?thread_root=<phantom>: {thread:?}"
    );
}

// ── 4. Backward-compat wire check ────────────────────────────────────────────

/// A non-threaded message's JSON in the GET /groups/:id/messages response must
/// contain no `thread_root` or `thread_parent` keys — not null, completely
/// absent — because `GroupPublicMessage` uses `skip_serializing_if = "Option::is_none"`.
///
/// Why: ADR-0029 guarantees that non-threaded messages are wire-identical to
/// v1. Emitting null thread fields would (a) violate that guarantee, (b) trick
/// old consumers into thinking the message is threaded, and (c) waste bytes on
/// every non-threaded message. Clients checking for thread membership must test
/// for key *presence*, not `!= null`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemon"]
async fn non_threaded_message_has_no_thread_keys() {
    let (solo, _bind_port) = cluster::solo().await;
    let d = &solo;

    let group_id = create_public_open_group(d, "adr0029-compat").await;

    let send_resp: Value = send_message(d, &group_id, "plain non-threaded message", None, None)
        .await
        .json()
        .await
        .expect("send json");
    assert_eq!(send_resp["ok"], true, "send failed: {send_resp:?}");
    let msg_id = send_resp["msg_id"]
        .as_str()
        .expect("msg_id in send response");

    let msgs = get_messages(d, &group_id).await;
    let msg = msgs
        .iter()
        .find(|m| m["msg_id"].as_str() == Some(msg_id))
        .unwrap_or_else(|| {
            panic!("sent message ({msg_id}) not found in GET /groups/:id/messages: {msgs:?}")
        });

    // Keys must be completely absent (not present-as-null). This verifies
    // that skip_serializing_if = "Option::is_none" applies end-to-end through
    // the cache, serialisation, and the GET /messages read path.
    let obj = msg.as_object().expect("message item is a JSON object");
    assert!(
        !obj.contains_key("thread_root"),
        "non-threaded message must not carry 'thread_root' key (got: {msg:?})"
    );
    assert!(
        !obj.contains_key("thread_parent"),
        "non-threaded message must not carry 'thread_parent' key (got: {msg:?})"
    );
}
