//! Phase E live proof: positive cross-daemon ModeratedPublic receive.
//!
//! Ignored by default because it spawns real x0xd daemons.

use base64::Engine;
use futures_util::FutureExt;
use serde_json::Value;
use std::{panic::AssertUnwindSafe, sync::OnceLock, time::Duration};

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
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn create_group_preset(
    d: &AgentInstance,
    name: &str,
    description: &str,
    preset: &str,
) -> String {
    let r: Value = authed_client(d)
        .post(d.url("/groups"))
        .json(&serde_json::json!({
            "name": name,
            "description": description,
            "preset": preset,
        }))
        .send()
        .await
        .expect("create group request")
        .json()
        .await
        .expect("create group json");
    assert_eq!(r["ok"], true, "create response: {r:?}");
    r["group_id"].as_str().unwrap_or_default().to_string()
}

async fn patch_group_policy(d: &AgentInstance, group_id: &str, policy: Value) -> Value {
    authed_client(d)
        .patch(d.url(&format!("/groups/{group_id}/policy")))
        .json(&policy)
        .send()
        .await
        .expect("patch group policy request")
        .json()
        .await
        .expect("patch group policy json")
}

async fn get_group_card(d: &AgentInstance, group_id: &str) -> Value {
    authed_client(d)
        .get(d.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("get group card request")
        .json()
        .await
        .expect("get group card json")
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

async fn agent_identity(d: &AgentInstance) -> (String, String) {
    let response = authed_client(d)
        .get(d.url("/agent"))
        .send()
        .await
        .expect("agent identity request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let payload: Value = response.json().await.expect("agent identity json");
    assert_eq!(payload["ok"], true, "agent identity response: {payload:?}");
    let agent_id = payload["agent_id"]
        .as_str()
        .expect("agent identity agent_id")
        .to_string();
    let machine_id = payload["machine_id"]
        .as_str()
        .expect("agent identity machine_id")
        .to_string();
    for (name, value) in [("agent_id", &agent_id), ("machine_id", &machine_id)] {
        assert_eq!(value.len(), 64, "{name} must be 32-byte hex");
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "{name} must be lowercase hex"
        );
    }
    (agent_id, machine_id)
}

async fn wait_for_verified_history(
    d: &AgentInstance,
    stable_group_id: &str,
    canonical_msg_id: &str,
    body: &str,
) -> Value {
    let expected_payload = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
    let expected_scope = format!("group:{stable_group_id}");
    let found = wait_until(Duration::from_secs(12), || async {
        let response = match authed_client(d)
            .get(d.url(&format!("/history?scope=group:{stable_group_id}&limit=50")))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return false,
        };
        if response.status() != reqwest::StatusCode::OK {
            return false;
        }
        let payload: Value = match response.json().await {
            Ok(payload) => payload,
            Err(_) => return false,
        };
        payload["records"].as_array().is_some_and(|records| {
            records.iter().any(|record| {
                record["msg_id"].as_str() == Some(canonical_msg_id)
                    && record["scope"].as_str() == Some(expected_scope.as_str())
                    && record["provenance"].as_str() == Some("VerifiedEnvelope")
                    && record["payload"].as_str() == Some(expected_payload.as_str())
            })
        })
    })
    .await;
    assert!(
        found,
        "verified history row did not arrive for canonical id {canonical_msg_id}"
    );

    let response = authed_client(d)
        .get(d.url(&format!("/history?scope=group:{stable_group_id}&limit=50")))
        .send()
        .await
        .expect("history listing request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let payload: Value = response.json().await.expect("history listing json");
    payload["records"]
        .as_array()
        .and_then(|records| {
            records.iter().find(|record| {
                record["msg_id"].as_str() == Some(canonical_msg_id)
                    && record["scope"].as_str() == Some(expected_scope.as_str())
                    && record["provenance"].as_str() == Some("VerifiedEnvelope")
                    && record["payload"].as_str() == Some(expected_payload.as_str())
            })
        })
        .cloned()
        .expect("verified history row after wait")
}

async fn assert_history_point_lookup(
    d: &AgentInstance,
    stable_group_id: &str,
    canonical_msg_id: &str,
    body: &str,
) {
    let response = authed_client(d)
        .get(d.url(&format!(
            "/history/message/{canonical_msg_id}?scope=group:{stable_group_id}"
        )))
        .send()
        .await
        .expect("history point lookup request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let payload: Value = response.json().await.expect("history point lookup json");
    assert_eq!(payload["ok"], true, "point lookup response: {payload:?}");
    let record = &payload["record"];
    assert_eq!(record["msg_id"], canonical_msg_id);
    assert_eq!(record["scope"], format!("group:{stable_group_id}"));
    assert_eq!(record["provenance"], "VerifiedEnvelope");
    assert_eq!(
        record["payload"],
        base64::engine::general_purpose::STANDARD.encode(body.as_bytes())
    );
}

async fn import_group_card(d: &AgentInstance, card: &Value) -> Value {
    authed_client(d)
        .post(d.url("/groups/cards/import"))
        .json(card)
        .send()
        .await
        .expect("import group card request")
        .json()
        .await
        .expect("import group card json")
}

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

async fn import_agent_card(d: &AgentInstance, card_link: &str, trust_level: &str) -> Value {
    authed_client(d)
        .post(d.url("/agent/card/import"))
        .json(&serde_json::json!({
            "card": card_link,
            "trust_level": trust_level,
        }))
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

async fn delete_group(d: &AgentInstance, group_id: &str) {
    let _ = authed_client(d)
        .delete(d.url(&format!("/groups/{group_id}")))
        .send()
        .await;
}

async fn prove_moderated_public_receive(
    alice: &AgentInstance,
    bob: &AgentInstance,
    local_group_id: &str,
) -> (String, String, String) {
    let policy = patch_group_policy(
        alice,
        local_group_id,
        serde_json::json!({
            "discoverability": "public_directory",
            "admission": "open_join",
            "confidentiality": "signed_public",
            "read_access": "public",
            "write_access": "moderated_public"
        }),
    )
    .await;
    assert_eq!(policy["ok"], true, "policy patch failed: {policy:?}");

    let warmup = authed_client(alice)
        .post(alice.url(&format!("/groups/{local_group_id}/send")))
        .json(&serde_json::json!({"body": "owner warmup", "kind": "chat"}))
        .send()
        .await
        .expect("warmup send request")
        .json::<Value>()
        .await
        .expect("warmup send json");
    assert_eq!(warmup["ok"], true, "warmup send failed: {warmup:?}");

    let card = get_group_card(alice, local_group_id).await;
    let stable_group_id = card["group_id"].as_str().unwrap_or_default().to_string();
    assert!(
        !stable_group_id.is_empty(),
        "group card missing stable group_id: {card:?}"
    );

    let imported = import_group_card(bob, &card).await;
    assert_eq!(imported["ok"], true, "bob import failed: {imported:?}");
    let bob_group_id = imported["group_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        bob_group_id, stable_group_id,
        "bob should address the imported stub by stable group id"
    );

    // Prime alice's listener on the local route. Internally this should subscribe
    // using the stable group id and still resolve the local group correctly.
    let _ = get_messages(alice, local_group_id).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let body = format!("hello moderated {}", rand::random::<u16>());
    let mut received = false;
    let mut canonical_msg_id = String::new();
    for _attempt in 0..3 {
        let sent = authed_client(bob)
            .post(bob.url(&format!("/groups/{bob_group_id}/send")))
            .json(&serde_json::json!({"body": body, "kind": "chat"}))
            .send()
            .await
            .expect("bob moderated send request")
            .json::<Value>()
            .await
            .expect("bob moderated send json");
        assert_eq!(sent["ok"], true, "bob moderated send failed: {sent:?}");
        canonical_msg_id = sent["msg_id"]
            .as_str()
            .expect("moderated send canonical msg_id")
            .to_string();

        received = wait_until(Duration::from_secs(8), || async {
            let msgs = get_messages(alice, local_group_id).await;
            msgs["messages"].as_array().is_some_and(|messages| {
                messages.iter().any(|m| {
                    m["msg_id"].as_str() == Some(canonical_msg_id.as_str())
                        && m["body"].as_str() == Some(body.as_str())
                })
            })
        })
        .await;
        if received {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let final_msgs = get_messages(alice, local_group_id).await;
    assert!(
        received,
        "alice never received bob's moderated_public message: {final_msgs:?}"
    );
    (stable_group_id, canonical_msg_id, body)
}

#[tokio::test]
#[ignore]
async fn e_moderated_public_positive_cross_daemon_receive() {
    let _guard = suite_lock().await;
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let alice_link = agent_card_link(alice).await;
    let bob_link = agent_card_link(bob).await;
    let imported = import_agent_card(alice, &bob_link, "Trusted").await;
    assert_eq!(
        imported["ok"], true,
        "alice agent-card import failed: {imported:?}"
    );
    let imported = import_agent_card(bob, &alice_link, "Trusted").await;
    assert_eq!(
        imported["ok"], true,
        "bob agent-card import failed: {imported:?}"
    );
    let connected = connect_to_agent(alice, &bob_id).await;
    assert_eq!(connected["ok"], true, "alice connect failed: {connected:?}");
    let connected = connect_to_agent(bob, &alice_id).await;
    assert_eq!(connected["ok"], true, "bob connect failed: {connected:?}");
    let mesh_ready = wait_until(Duration::from_secs(20), || async {
        peer_count(alice).await > 0 && peer_count(bob).await > 0
    })
    .await;
    assert!(
        mesh_ready,
        "pair mesh never formed for public-message proof"
    );

    let local_group_id = create_group_preset(
        alice,
        &format!("e-moderated-{}", rand::random::<u16>()),
        "phase-e positive receive proof",
        "private_secure",
    )
    .await;

    let proof = AssertUnwindSafe(prove_moderated_public_receive(alice, bob, &local_group_id))
        .catch_unwind()
        .await;
    delete_group(alice, &local_group_id).await;
    if let Err(panic) = proof {
        std::panic::resume_unwind(panic);
    }
}

/// Issue #321 acceptance seam: an actual VerifiedEnvelope received over the
/// private gossip plane must be discoverable by its sender's canonical id,
/// including after the receiving daemon reopens the same durable store.
/// This remains ignored because it owns real x0xd processes and loopback
/// networking; hosted execution is the runtime acceptance gate.
#[tokio::test]
#[ignore]
async fn e_verified_envelope_history_lookup_survives_restart() {
    let _guard = suite_lock().await;
    let mut pair = pair().await;
    let alice_id = pair.alice.agent_id().await;
    let bob_id = pair.bob.agent_id().await;
    let alice_link = agent_card_link(&pair.alice).await;
    let bob_link = agent_card_link(&pair.bob).await;
    assert_eq!(
        import_agent_card(&pair.alice, &bob_link, "Trusted").await["ok"],
        true
    );
    assert_eq!(
        import_agent_card(&pair.bob, &alice_link, "Trusted").await["ok"],
        true
    );
    assert_eq!(
        connect_to_agent(&pair.alice, &bob_id).await["ok"],
        true,
        "alice connect failed"
    );
    assert_eq!(
        connect_to_agent(&pair.bob, &alice_id).await["ok"],
        true,
        "bob connect failed"
    );
    assert!(
        wait_until(Duration::from_secs(20), || async {
            peer_count(&pair.alice).await > 0 && peer_count(&pair.bob).await > 0
        })
        .await,
        "pair mesh never formed for history restart proof"
    );

    let local_group_id = create_group_preset(
        &pair.alice,
        &format!("e-history-restart-{}", rand::random::<u16>()),
        "issue 321 VerifiedEnvelope restart proof",
        "private_secure",
    )
    .await;
    let (stable_group_id, canonical_msg_id, body) =
        prove_moderated_public_receive(&pair.alice, &pair.bob, &local_group_id).await;
    let before = agent_identity(&pair.alice).await;
    let first =
        wait_for_verified_history(&pair.alice, &stable_group_id, &canonical_msg_id, &body).await;
    assert_history_point_lookup(&pair.alice, &stable_group_id, &canonical_msg_id, &body).await;

    pair.alice.restart().await;
    let after = agent_identity(&pair.alice).await;
    assert_eq!(
        after.0, before.0,
        "restart changed the receiving agent identity"
    );
    assert_eq!(
        after.1, before.1,
        "restart changed the receiving machine identity"
    );
    let second =
        wait_for_verified_history(&pair.alice, &stable_group_id, &canonical_msg_id, &body).await;
    assert_eq!(second, first, "restart changed the durable history row");
    assert_history_point_lookup(&pair.alice, &stable_group_id, &canonical_msg_id, &body).await;

    delete_group(&pair.alice, &local_group_id).await;
}
