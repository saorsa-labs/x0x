//! ADR-0040 live proofs: delegation effectiveness, forges rejected,
//! restart re-derivation, and daemon-side mention routing.
//!
//! Ignored by default — these spawn real x0xd daemons (see the harness in
//! `tests/harness/src/cluster.rs`; every config pins `[update] enabled =
//! false`).
//!
//!
//! Coverage markers: `delegation_sendas_positive_and_forges_cross_daemon`,
//! `delegation_survives_restart_via_history`, and
//! `mention_routing_surfaces_ws_event` back the `/groups/:id/delegate` +
//! `/groups/:id/delegations` registry entries in `tests/api_coverage.rs`.

use futures_util::{FutureExt, SinkExt, StreamExt};
use serde_json::Value;
use std::future::Future;
use std::{panic::AssertUnwindSafe, sync::LazyLock, time::Duration};
use tokio_tungstenite::tungstenite::Message;

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

static TEST_MUTEX: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

async fn suite_lock() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_MUTEX.lock().await
}

async fn wait_until<F, Fut>(timeout: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
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

// ───────────────────────── shared setup helpers ──────────────────────────

async fn agent_card_link(d: &AgentInstance) -> String {
    let card: Value = authed_client(d)
        .get(d.url("/agent/card"))
        .send()
        .await
        .expect("agent card request")
        .json()
        .await
        .expect("agent card json");
    card["link"].as_str().unwrap_or_default().to_string()
}

async fn import_agent_card(d: &AgentInstance, card_link: &str) -> Value {
    authed_client(d)
        .post(d.url("/agent/card/import"))
        .json(&serde_json::json!({ "card": card_link, "trust_level": "Trusted" }))
        .send()
        .await
        .expect("agent card import request")
        .json()
        .await
        .expect("agent card import json")
}

async fn connect_to_agent(d: &AgentInstance, agent_id: &str) -> Value {
    authed_client(d)
        .post(d.url("/agents/connect"))
        .json(&serde_json::json!({ "agent_id": agent_id }))
        .send()
        .await
        .expect("agents connect request")
        .json()
        .await
        .expect("agents connect json")
}

async fn peer_count(d: &AgentInstance) -> usize {
    let peers: Value = authed_client(d)
        .get(d.url("/peers"))
        .send()
        .await
        .expect("peers request")
        .json()
        .await
        .expect("peers json");
    peers
        .as_array()
        .or_else(|| peers["peers"].as_array())
        .map_or(0, |entries| entries.len())
}

/// Mesh the pair (cards + connect + wait). Delegation rides DMs and gossip,
/// both of which need the pair to know each other.
async fn mesh_pair(alice: &AgentInstance, bob: &AgentInstance) {
    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let alice_link = agent_card_link(alice).await;
    let bob_link = agent_card_link(bob).await;
    assert_eq!(
        import_agent_card(alice, &bob_link).await["ok"],
        true,
        "alice imports bob card"
    );
    assert_eq!(
        import_agent_card(bob, &alice_link).await["ok"],
        true,
        "bob imports alice card"
    );
    assert_eq!(connect_to_agent(alice, &bob_id).await["ok"], true);
    assert_eq!(connect_to_agent(bob, &alice_id).await["ok"], true);
    let ready = wait_until(Duration::from_secs(20), || async {
        peer_count(alice).await > 0 && peer_count(bob).await > 0
    })
    .await;
    assert!(ready, "pair mesh never formed");
}

/// Create a SignedPublic group on `owner`, patch write policy so members
/// (and only members) may send, and return `(local_group_id, stable_group_id)`
/// as seen by the OWNER.
async fn create_signed_public_group(owner: &AgentInstance, name: &str) -> (String, String) {
    let created: Value = authed_client(owner)
        .post(owner.url("/groups"))
        .json(&serde_json::json!({
            "name": name,
            "description": "adr-0040 delegation proof",
            "preset": "private_secure",
        }))
        .send()
        .await
        .expect("create group request")
        .json()
        .await
        .expect("create group json");
    assert_eq!(created["ok"], true, "create group: {created:?}");
    let local_id = created["group_id"].as_str().unwrap_or_default().to_string();

    let patched: Value = authed_client(owner)
        .patch(owner.url(&format!("/groups/{local_id}/policy")))
        .json(&serde_json::json!({
            "discoverability": "public_directory",
            "admission": "open_join",
            "confidentiality": "signed_public",
            "read_access": "public",
            "write_access": "members_only"
        }))
        .send()
        .await
        .expect("patch policy request")
        .json()
        .await
        .expect("patch policy json");
    assert_eq!(patched["ok"], true, "patch policy: {patched:?}");

    let card: Value = authed_client(owner)
        .get(owner.url(&format!("/groups/cards/{local_id}")))
        .send()
        .await
        .expect("group card request")
        .json()
        .await
        .expect("group card json");
    let stable = card["group_id"].as_str().unwrap_or_default().to_string();
    assert!(!stable.is_empty(), "stable group id: {card:?}");
    (local_id, stable)
}

/// Make `member` an ACTIVE member of the owner's group via the invite +
/// join flow (direct member-add requires a TreeKEM key package only the
/// joining daemon can contribute). Returns when the owner's roster shows
/// the member Active.
async fn join_group(owner: &AgentInstance, member: &AgentInstance, group_id: &str) {
    let invite: Value = authed_client(owner)
        .post(owner.url(&format!("/groups/{group_id}/invite")))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("invite request")
        .json()
        .await
        .expect("invite json");
    assert_eq!(invite["ok"], true, "invite: {invite:?}");
    let link = invite["invite_link"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(!link.is_empty(), "invite link");

    let joined: Value = authed_client(member)
        .post(member.url("/groups/join"))
        .json(&serde_json::json!({ "invite": link, "display_name": "delegate" }))
        .send()
        .await
        .expect("join request")
        .json()
        .await
        .expect("join json");
    assert_eq!(joined["ok"], true, "join: {joined:?}");

    // Wait for the owner's roster to converge on the new Active member.
    let member_id = member.agent_id().await;
    let owner_group = group_id.to_string();
    let converged = wait_until(Duration::from_secs(15), || async {
        let members: Value = authed_client(owner)
            .get(owner.url(&format!("/groups/{owner_group}/members")))
            .send()
            .await
            .expect("members request")
            .json()
            .await
            .expect("members json");
        members["members"].as_array().is_some_and(|ms| {
            ms.iter().any(|m| {
                m["agent_id"]
                    .as_str()
                    .map(|a| a.eq_ignore_ascii_case(&member_id))
                    == Some(true)
                    && m["state"]
                        .as_str()
                        .is_some_and(|st| st.eq_ignore_ascii_case("active"))
            })
        })
    })
    .await;
    assert!(converged, "owner roster never showed the member Active");
}

async fn delegate(
    d: &AgentInstance,
    group_id: &str,
    to_agent_hex: &str,
    scope: &str,
    expiry_ms: u64,
    task: Option<&str>,
    parent: Option<&str>,
) -> reqwest::Response {
    let mut body = serde_json::json!({
        "to_agent": to_agent_hex,
        "scope": scope,
        "expiry_ms": expiry_ms,
    });
    if let Some(task) = task {
        body["task"] = Value::String(task.to_string());
    }
    if let Some(parent) = parent {
        body["parent"] = Value::String(parent.to_string());
    }
    authed_client(d)
        .post(d.url(&format!("/groups/{group_id}/delegate")))
        .json(&body)
        .send()
        .await
        .expect("delegate request")
}

async fn delegations(d: &AgentInstance, group_id: &str) -> Value {
    authed_client(d)
        .get(d.url(&format!("/groups/{group_id}/delegations")))
        .send()
        .await
        .expect("delegations request")
        .json()
        .await
        .expect("delegations json")
}

async fn send_message(d: &AgentInstance, group_id: &str, body: Value) -> reqwest::Response {
    authed_client(d)
        .post(d.url(&format!("/groups/{group_id}/send")))
        .json(&body)
        .send()
        .await
        .expect("send request")
}

async fn get_messages(d: &AgentInstance, group_id: &str) -> Value {
    authed_client(d)
        .get(d.url(&format!("/groups/{group_id}/messages")))
        .send()
        .await
        .expect("get messages request")
        .json()
        .await
        .expect("get messages json")
}

// ─────────────────── 1. send-as + forge rejections ───────────────────────

/// Positive send-as flow plus every REST-exercisable forge from the ADR-0040
/// validation list: expired delegation, non-delegate digest, and depth-3
/// chain — all rejected — while the honest paths (including a task-execute
/// claim under a delegation) succeed. Signed owner-transfer was descoped
/// from v1 (see docs/design/adr-0040-mechanics.md).
#[tokio::test]
#[ignore]
async fn delegation_sendas_positive_and_forges_cross_daemon() {
    let _guard = suite_lock().await;
    let mut pair = pair().await;
    let alice = &mut pair.alice;
    let bob = &pair.bob;
    let proof = AssertUnwindSafe(async {
        mesh_pair(alice, bob).await;
        let (alice_local, stable) = create_signed_public_group(alice, "adr0040-forges").await;
        let bob_id = bob.agent_id().await;
        let alice_id = alice.agent_id().await;

        // Bob must be an active member to receive delegations in-group.
        join_group(alice, bob, &alice_local).await;

        // Warm the listeners so the topic exists before the first publish.
        let warmup = send_message(alice, &alice_local, serde_json::json!({"body": "warmup"})).await;
        assert_eq!(warmup.status(), 200);
        tokio::time::sleep(Duration::from_secs(1)).await;

        // ── positive: alice delegates send_as to bob ──────────────────────
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let delegated = delegate(
            alice,
            &alice_local,
            &bob_id,
            "send_as",
            now + 60_000,
            None,
            None,
        )
        .await;
        assert_eq!(
            delegated.status(),
            200,
            "delegate send_as should succeed: {delegated:?}"
        );
        let delegated_json: Value = delegated.json().await.expect("delegate json");
        assert_eq!(delegated_json["effective"], true, "{delegated_json:?}");
        let digest = delegated_json["delegation_digest"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_eq!(digest.len(), 64, "digest is 64 hex chars");

        // Bob uses it: signs with HIS OWN key, references the digest.
        let sent = send_message(
            bob,
            &alice_local,
            serde_json::json!({
                "body": "sent under alice's authority",
                "delegation_digest": digest,
            }),
        )
        .await;
        assert_eq!(sent.status(), 200, "send-as should succeed: {sent:?}");

        // Alice receives and caches the attributed message (her ingest ran
        // the SAME effectiveness check against her own durable history).
        let body_sent = "sent under alice's authority";
        let received = wait_until(Duration::from_secs(10), || async {
            let msgs = get_messages(alice, &alice_local).await;
            msgs["messages"].as_array().is_some_and(|messages| {
                messages
                    .iter()
                    .any(|m| m["body"].as_str() == Some(body_sent))
            })
        })
        .await;
        assert!(
            received,
            "alice never cached the send-as message (her ingest must have accepted it)"
        );

        // ── forge: alice's OWN digest used by ALICE (not the delegate) ────
        // The delegator cannot "use" the grant it issued — only the delegate
        // may act. Wrong-actor reference: rejected.
        let wrong_actor = send_message(
            alice,
            &alice_local,
            serde_json::json!({
                "body": "alice misusing her own grant",
                "delegation_digest": digest,
            }),
        )
        .await;
        assert_eq!(
            wrong_actor.status(),
            409,
            "non-delegate send-as must be refused: {wrong_actor:?}"
        );

        // ── forge: unknown digest (never committed) ───────────────────────
        let unknown = send_message(
            bob,
            &alice_local,
            serde_json::json!({
                "body": "phantom authority",
                "delegation_digest": "f".repeat(64),
            }),
        )
        .await;
        assert_eq!(
            unknown.status(),
            409,
            "uncommitted delegation digest must be refused: {unknown:?}"
        );

        // ── forge: expired delegation ─────────────────────────────────────
        let short = delegate(
            alice,
            &alice_local,
            &bob_id,
            "send_as",
            now + 2_000,
            None,
            None,
        )
        .await;
        assert_eq!(short.status(), 200, "short-lived delegation issues fine");
        let short_json: Value = short.json().await.expect("short delegate json");
        let short_digest = short_json["delegation_digest"].as_str().unwrap_or_default();
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        let expired_send = send_message(
            bob,
            &alice_local,
            serde_json::json!({
                "body": "too late",
                "delegation_digest": short_digest,
            }),
        )
        .await;
        assert_eq!(
            expired_send.status(),
            409,
            "expired delegation must not authorize: {expired_send:?}"
        );

        // ── forge: depth-3 chain (A→B→C then C tries to re-delegate) ──────
        let ab = delegate(
            alice,
            &alice_local,
            &bob_id,
            "send_as",
            now + 60_000,
            None,
            None,
        )
        .await;
        assert_eq!(ab.status(), 200);
        let ab_json: Value = ab.json().await.expect("ab json");
        let ab_digest = ab_json["delegation_digest"].as_str().unwrap_or_default();
        // Bob re-delegates to alice (depth 2, legal).
        let ba = delegate(
            bob,
            &alice_local,
            &alice_id,
            "send_as",
            now + 60_000,
            None,
            Some(ab_digest),
        )
        .await;
        assert_eq!(ba.status(), 200, "depth-2 re-delegation is legal: {ba:?}");
        let ba_json: Value = ba.json().await.expect("ba json");
        let ba_digest = ba_json["delegation_digest"].as_str().unwrap_or_default();
        // Alice tries to re-delegate the depth-2 grant → cap exceeded.
        let depth3 = delegate(
            alice,
            &alice_local,
            &bob_id,
            "send_as",
            now + 60_000,
            None,
            Some(ba_digest),
        )
        .await;
        assert_eq!(
            depth3.status(),
            409,
            "depth-3 delegation must be refused at the cap: {depth3:?}"
        );

        // ── task-exercise delegation (review r2): claim under authority ──
        // A group-scoped task list, a task_execute delegation from alice
        // to bob for THAT task, and bob claiming it citing the digest.
        // An unknown digest or wrong-task digest must be refused (403).
        let scoped_topic = format!("x0x.group.{stable}.symphony.t{}", rand_val());
        let created_scoped: Value = authed_client(alice)
            .post(alice.url("/task-lists"))
            .json(&serde_json::json!({
                "name": "adr0040-scoped",
                "topic": scoped_topic,
            }))
            .send()
            .await
            .expect("scoped task list create")
            .json()
            .await
            .expect("scoped task list json");
        assert_eq!(created_scoped["ok"], true, "{created_scoped:?}");
        let scoped_task: Value = authed_client(alice)
            .post(alice.url(&format!("/task-lists/{scoped_topic}/tasks")))
            .json(&serde_json::json!({"title": "delegated work"}))
            .send()
            .await
            .expect("scoped add task")
            .json()
            .await
            .expect("scoped add task json");
        assert_eq!(scoped_task["ok"], true, "{scoped_task:?}");
        let scoped_task_id = scoped_task["task_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let te = delegate(
            alice,
            &alice_local,
            &bob_id,
            "task_execute",
            now + 60_000,
            Some(&scoped_task_id),
            None,
        )
        .await;
        assert_eq!(te.status(), 200, "task_execute delegation issues: {te:?}");
        let te_json: Value = te.json().await.expect("te json");
        let te_digest = te_json["delegation_digest"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        // Bob's replica must learn the group-scoped list (same invite-free
        // trick as above: create a list on the same topic, then wait for
        // the late-joiner bootstrap to sync alice's task).
        let bob_scoped: Value = authed_client(bob)
            .post(bob.url("/task-lists"))
            .json(&serde_json::json!({
                "name": "adr0040-scoped-bob",
                "topic": scoped_topic,
            }))
            .send()
            .await
            .expect("bob scoped task list join")
            .json()
            .await
            .expect("bob scoped task list json");
        assert_eq!(bob_scoped["ok"], true, "{bob_scoped:?}");
        let scoped_synced = wait_until(Duration::from_secs(15), || async {
            let tasks: Value = authed_client(bob)
                .get(bob.url(&format!("/task-lists/{scoped_topic}/tasks")))
                .send()
                .await
                .expect("bob scoped tasks read")
                .json()
                .await
                .expect("bob scoped tasks json");
            tasks["tasks"].as_array().is_some_and(|ts| {
                ts.iter()
                    .any(|t| t["id"].as_str() == Some(scoped_task_id.as_str()))
            })
        })
        .await;
        assert!(scoped_synced, "bob's replica never learned the scoped task");

        // Bob claims the task citing the delegation: 200 + authorized_via.
        let claimed = authed_client(bob)
            .patch(bob.url(&format!(
                "/task-lists/{scoped_topic}/tasks/{scoped_task_id}"
            )))
            .json(&serde_json::json!({
                "action": "claim",
                "delegation": te_digest,
            }))
            .send()
            .await
            .expect("delegated claim request");
        assert_eq!(
            claimed.status(),
            200,
            "delegated claim authorized: {claimed:?}"
        );
        let claimed_json: Value = claimed.json().await.expect("claim json");
        assert_eq!(
            claimed_json["authorized_via"]["delegator_agent_id"].as_str(),
            Some(alice_id.as_str()),
            "response carries the delegator attribution"
        );

        // Wrong-task digest: the send_as grant does not target this task.
        let wrong = authed_client(bob)
            .patch(bob.url(&format!(
                "/task-lists/{scoped_topic}/tasks/{scoped_task_id}"
            )))
            .json(&serde_json::json!({
                "action": "complete",
                "delegation": digest, // the send_as grant — wrong scope/task
            }))
            .send()
            .await
            .expect("wrong delegation complete");
        assert_eq!(
            wrong.status(),
            403,
            "wrong-scope delegation must be refused: {wrong:?}"
        );

        // Unknown digest: refused.
        let unknown_d = authed_client(bob)
            .patch(bob.url(&format!(
                "/task-lists/{scoped_topic}/tasks/{scoped_task_id}"
            )))
            .json(&serde_json::json!({
                "action": "complete",
                "delegation": "e".repeat(64),
            }))
            .send()
            .await
            .expect("unknown delegation complete");
        assert_eq!(
            unknown_d.status(),
            403,
            "uncommitted delegation must be refused: {unknown_d:?}"
        );
    })
    .catch_unwind()
    .await;
    drop(pair);
    if let Err(panic) = proof {
        std::panic::resume_unwind(panic);
    }
}

// ─────────────────── 2. restart re-derivation ────────────────────────────

/// Blocker 28's one rule under crash/restart: the delegation was effective
/// because its carrier was durably committed; after the daemon restarts, the
/// registry re-derives the same fact from SQLite history (never from the DM
/// notification, never from memory).
#[tokio::test]
#[ignore]
async fn delegation_survives_restart_via_history() {
    let _guard = suite_lock().await;
    let mut pair = pair().await;
    let alice = &mut pair.alice;
    let bob = &pair.bob;
    let proof = AssertUnwindSafe(async {
        mesh_pair(alice, bob).await;
        let (alice_local, _) = create_signed_public_group(alice, "adr0040-restart").await;
        let bob_id = bob.agent_id().await;
        join_group(alice, bob, &alice_local).await;
        let warmup = send_message(alice, &alice_local, serde_json::json!({"body": "warmup"})).await;
        assert_eq!(warmup.status(), 200);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let delegated = delegate(
            alice,
            &alice_local,
            &bob_id,
            "send_as",
            now + 300_000,
            None,
            None,
        )
        .await;
        assert_eq!(delegated.status(), 200);
        let djson: Value = delegated.json().await.expect("delegate json");
        let digest = djson["delegation_digest"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        // Pre-restart: listed as effective.
        let before = delegations(alice, &alice_local).await;
        assert!(
            before["delegations"].as_array().is_some_and(|ds| ds
                .iter()
                .any(|d| d["delegation_digest"].as_str() == Some(digest.as_str()))),
            "effective before restart: {before:?}"
        );

        // Crash-style restart: same data_dir, same identity, cold memory.
        alice.restart().await;
        // The index is cold — listing must re-derive from durable history.
        let after = delegations(alice, &alice_local).await;
        assert!(
            after["delegations"].as_array().is_some_and(|ds| ds
                .iter()
                .any(|d| d["delegation_digest"].as_str() == Some(digest.as_str()))),
            "delegation survives restart via durable history: {after:?}"
        );

        // And it still WORKS: bob sends-as with the pre-restart digest and
        // the restarted daemon's send gate authorizes it.
        let still_valid = send_message(
            bob,
            &alice_local,
            serde_json::json!({
                "body": "post-restart send-as",
                "delegation_digest": digest,
            }),
        )
        .await;
        assert_eq!(
            still_valid.status(),
            200,
            "send-as authorized against re-derived history: {still_valid:?}"
        );
    })
    .catch_unwind()
    .await;
    drop(pair);
    if let Err(panic) = proof {
        std::panic::resume_unwind(panic);
    }
}

// ─────────────────── 3. daemon-side mention routing ──────────────────────

/// Structured mentions surface as a daemon WS event on the group topic —
/// no GUI string matching involved.
#[tokio::test]
#[ignore]
async fn mention_routing_surfaces_ws_event() {
    let _guard = suite_lock().await;
    let mut pair = pair().await;
    let alice = &mut pair.alice;
    let bob = &pair.bob;
    let proof = AssertUnwindSafe(async {
        mesh_pair(alice, bob).await;
        let (alice_local, stable) = create_signed_public_group(alice, "adr0040-mentions").await;
        let bob_id = bob.agent_id().await;
        let alice_id = alice.agent_id().await;
        join_group(alice, bob, &alice_local).await;
        let warmup = send_message(alice, &alice_local, serde_json::json!({"body": "warmup"})).await;
        assert_eq!(warmup.status(), 200);
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Open a WS on alice and subscribe to the group's public topic.
        // ws_url() mints the short-lived session token (#127 / WS1.6).
        let ws_url = alice.ws_url("/ws").await;
        let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .expect("ws connect");
        let topic = format!("x0x.groups.public.{stable}");
        let sub = serde_json::json!({
            "type": "subscribe",
            "topics": [topic],
        });
        ws.send(Message::Text(sub.to_string()))
            .await
            .expect("subscribe send");
        // Drain until the subscribed ack.
        let mut saw_subscribed = false;
        for _ in 0..25 {
            if let Ok(Some(Ok(Message::Text(text)))) =
                tokio::time::timeout(Duration::from_millis(400), ws.next()).await
            {
                if text.contains("\"subscribed\"") {
                    saw_subscribed = true;
                    break;
                }
            }
        }
        assert!(saw_subscribed, "ws subscription acked");

        // Bob mentions ALICE by structured field (hex AgentId).
        let nonce = format!("mention-{}", rand_val());
        let sent = send_message(
            bob,
            &alice_local,
            serde_json::json!({
                "body": nonce,
                "mentions": [alice_id],
            }),
        )
        .await;
        assert_eq!(sent.status(), 200, "mention send: {sent:?}");

        // Alice's daemon must surface a structured mention WS event naming
        // the local agent — the daemon-side routing replacement for GUI
        // string matching.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut saw_mention = false;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(400), ws.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&text) {
                        if v["type"] == "mention"
                            && v["reason"] == "mention"
                            && v["group_id"] == Value::String(stable.clone())
                        {
                            assert_eq!(
                                v["author_agent_id"].as_str(),
                                Some(bob_id.as_str()),
                                "mention event names the author"
                            );
                            assert!(
                                v["mentions"].as_array().is_some_and(|m| !m.is_empty()),
                                "mention event carries the structured field: {v:?}"
                            );
                            saw_mention = true;
                            break;
                        }
                    }
                }
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => panic!("ws error: {e}"),
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        assert!(saw_mention, "daemon never surfaced the mention event");
        let _ = bob_id;
    })
    .catch_unwind()
    .await;
    drop(pair);
    if let Err(panic) = proof {
        std::panic::resume_unwind(panic);
    }
}

fn rand_val() -> u16 {
    // Cheap uniqueness for message bodies.
    std::process::id() as u16
        ^ (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_millis() as u16)
            .unwrap_or(0))
}
