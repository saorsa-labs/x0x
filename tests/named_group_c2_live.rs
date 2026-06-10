//! Phase C.2 live proof: shard-delivered PublicDirectory discovery must be
//! visible via the shard-only `/groups/discover/nearby` witness.
//!
//! Ignored by default because it spawns real x0xd daemons.

use serde_json::Value;
use std::{sync::OnceLock, time::Duration};

#[path = "harness/src/cluster.rs"]
mod cluster;
use cluster::{cluster, pair, pair_with_extra_config, AgentInstance};

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

async fn subscribe_shard_key(d: &AgentInstance, kind: &str, key: &str) -> Value {
    authed_client(d)
        .post(d.url("/groups/discover/subscribe"))
        .json(&serde_json::json!({
            "kind": kind,
            "key": key,
        }))
        .send()
        .await
        .expect("subscribe shard request")
        .json()
        .await
        .expect("subscribe shard json")
}

async fn subscribe_name_shard(d: &AgentInstance, key: &str) -> Value {
    subscribe_shard_key(d, "name", key).await
}

async fn list_discovery_subscriptions(d: &AgentInstance) -> Value {
    authed_client(d)
        .get(d.url("/groups/discover/subscriptions"))
        .send()
        .await
        .expect("list subscriptions request")
        .json()
        .await
        .expect("list subscriptions json")
}

async fn nearby_groups(d: &AgentInstance) -> Value {
    authed_client(d)
        .get(d.url("/groups/discover/nearby"))
        .send()
        .await
        .expect("nearby request")
        .json()
        .await
        .expect("nearby json")
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

async fn direct_connections(d: &AgentInstance) -> Value {
    authed_client(d)
        .get(d.url("/direct/connections"))
        .send()
        .await
        .expect("direct connections request")
        .json()
        .await
        .expect("direct connections json")
}

fn direct_has_agent(connections: &Value, agent_id: &str) -> bool {
    connections["connections"].as_array().is_some_and(|peers| {
        peers
            .iter()
            .any(|entry| entry["agent_id"].as_str() == Some(agent_id))
    })
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

async fn get_group_card_response(
    d: &AgentInstance,
    group_id: &str,
) -> (reqwest::StatusCode, Value) {
    let resp = authed_client(d)
        .get(d.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("group card status request");
    let status = resp.status();
    let body = resp.json().await.expect("group card status json");
    (status, body)
}

fn nearby_has_group(nearby: &Value, stable_group_id: &str) -> bool {
    nearby["groups"].as_array().is_some_and(|groups| {
        groups
            .iter()
            .any(|g| g["group_id"].as_str() == Some(stable_group_id))
    })
}

#[tokio::test]
#[ignore]
async fn c2_publicdirectory_discovered_via_shard_only_nearby_witness() {
    let _guard = suite_lock().await;
    let pair = pair().await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let token = format!("c2proof{}", rand::random::<u16>());
    let subscribe = subscribe_name_shard(bob, &token).await;
    assert_eq!(subscribe["ok"], true, "subscribe response: {subscribe:?}");
    assert_eq!(subscribe["kind"].as_str(), Some("name"));

    let local_group_id = create_group_preset(
        alice,
        &format!("{token} public"),
        "c2 shard witness",
        "public_request_secure",
    )
    .await;

    let card = get_group_card(alice, &local_group_id).await;
    let stable_group_id = card["group_id"].as_str().unwrap_or_default().to_string();
    assert!(
        !stable_group_id.is_empty(),
        "group card missing group_id: {card:?}"
    );
    assert_eq!(
        card["policy_summary"]["discoverability"].as_str(),
        Some("public_directory"),
        "card should be PublicDirectory: {card:?}"
    );
    assert!(card["signature"].as_str().is_some_and(|s| !s.is_empty()));

    let matched = wait_until(Duration::from_secs(90), || async {
        let nearby = nearby_groups(bob).await;
        let hit = nearby_has_group(&nearby, &stable_group_id);
        if hit {
            return true;
        }

        let _ = authed_client(alice)
            .post(alice.url(&format!("/groups/{local_group_id}/state/seal")))
            .send()
            .await;
        false
    })
    .await;

    let final_nearby = nearby_groups(bob).await;
    assert!(
        matched,
        "bob never observed alice's PublicDirectory card via shard-only nearby witness: {final_nearby:?}"
    );

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{local_group_id}")))
        .send()
        .await;
}

#[tokio::test]
#[ignore]
async fn c2_late_subscriber_recovers_via_digest_pull_without_republish() {
    let _guard = suite_lock().await;
    let pair = pair_with_extra_config(
        "directory_digest_interval_secs = 5\n\
         group_card_republish_interval_secs = 0",
    )
    .await;
    let alice = &pair.alice;
    let bob = &pair.bob;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let alice_link = agent_card_link(alice).await;
    let bob_link = agent_card_link(bob).await;
    let import = import_agent_card(alice, &bob_link, "Trusted").await;
    assert_eq!(import["ok"], true, "alice imports bob: {import:?}");
    let import = import_agent_card(bob, &alice_link, "Trusted").await;
    assert_eq!(import["ok"], true, "bob imports alice: {import:?}");
    let connect = connect_to_agent(alice, &bob_id).await;
    assert_eq!(connect["ok"], true, "alice connects bob: {connect:?}");
    let connect = connect_to_agent(bob, &alice_id).await;
    assert_eq!(connect["ok"], true, "bob connects alice: {connect:?}");

    let mesh_ready = wait_until(Duration::from_secs(20), || async {
        peer_count(alice).await > 0
            && peer_count(bob).await > 0
            && direct_has_agent(&direct_connections(alice).await, &bob_id)
    })
    .await;
    assert!(mesh_ready, "pair mesh never formed for AE proof");

    let token = format!("c2ae{}", rand::random::<u16>());
    let alice_sub = subscribe_name_shard(alice, &token).await;
    assert_eq!(
        alice_sub["ok"], true,
        "alice subscribe response: {alice_sub:?}"
    );

    let local_group_id = create_group_preset(
        alice,
        &format!("{token} public"),
        "c2 anti-entropy repair",
        "public_request_secure",
    )
    .await;
    let card = get_group_card(alice, &local_group_id).await;
    let stable_group_id = card["group_id"].as_str().unwrap_or_default().to_string();
    assert!(
        !stable_group_id.is_empty(),
        "group card missing group_id: {card:?}"
    );

    // Re-seal BEFORE bob subscribes so he definitely misses the latest direct
    // publish while alice's shard cache and listener already have the card.
    let seal_resp = authed_client(alice)
        .post(alice.url(&format!("/groups/{local_group_id}/state/seal")))
        .send()
        .await
        .expect("alice pre-bob seal")
        .json::<Value>()
        .await
        .expect("alice pre-bob seal json");
    assert_eq!(seal_resp["ok"], true, "seal response: {seal_resp:?}");

    let alice_nearby_ready = wait_until(Duration::from_secs(10), || async {
        nearby_has_group(&nearby_groups(alice).await, &stable_group_id)
    })
    .await;
    assert!(
        alice_nearby_ready,
        "alice never observed her own group in subscribed shard cache"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    let bob_sub = subscribe_name_shard(bob, &token).await;
    assert_eq!(bob_sub["ok"], true, "bob subscribe response: {bob_sub:?}");

    let still_connected = wait_until(Duration::from_secs(10), || async {
        peer_count(alice).await > 0 && peer_count(bob).await > 0
    })
    .await;
    assert!(still_connected, "pair mesh dropped before AE repair window");

    let repaired = nearby_has_group(&nearby_groups(bob).await, &stable_group_id)
        || wait_until(Duration::from_secs(45), || async {
            let nearby = nearby_groups(bob).await;
            nearby_has_group(&nearby, &stable_group_id)
        })
        .await;

    let final_nearby = nearby_groups(bob).await;
    assert!(
        repaired,
        "bob never recovered the group via digest/pull repair: {final_nearby:?}"
    );

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{local_group_id}")))
        .send()
        .await;
}

#[tokio::test]
#[ignore]
async fn c2_listedtocontacts_delivers_only_to_trusted_or_known_contacts() {
    let _guard = suite_lock().await;
    let cluster = cluster().await;
    let alice = &cluster.alice;
    let bob = &cluster.bob;
    let charlie = &cluster.charlie;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let charlie_id = charlie.agent_id().await;

    let alice_link = agent_card_link(alice).await;
    let bob_link = agent_card_link(bob).await;
    let charlie_link = agent_card_link(charlie).await;

    let import = import_agent_card(alice, &bob_link, "Trusted").await;
    assert_eq!(import["ok"], true, "alice imports bob: {import:?}");
    let import = import_agent_card(alice, &charlie_link, "Blocked").await;
    assert_eq!(import["ok"], true, "alice imports charlie: {import:?}");
    let import = import_agent_card(bob, &alice_link, "Trusted").await;
    assert_eq!(import["ok"], true, "bob imports alice: {import:?}");
    let import = import_agent_card(charlie, &alice_link, "Trusted").await;
    assert_eq!(import["ok"], true, "charlie imports alice: {import:?}");

    let resp = connect_to_agent(alice, &bob_id).await;
    assert_eq!(resp["ok"], true, "alice connects bob: {resp:?}");
    let resp = connect_to_agent(bob, &alice_id).await;
    assert_eq!(resp["ok"], true, "bob connects alice: {resp:?}");
    let resp = connect_to_agent(alice, &charlie_id).await;
    assert_eq!(resp["ok"], true, "alice connects charlie: {resp:?}");
    let resp = connect_to_agent(charlie, &alice_id).await;
    assert_eq!(resp["ok"], true, "charlie connects alice: {resp:?}");

    let bob_connected = wait_until(Duration::from_secs(20), || async {
        direct_has_agent(&direct_connections(alice).await, &bob_id)
    })
    .await;
    assert!(
        bob_connected,
        "alice never established a direct session to bob"
    );

    let charlie_connected = wait_until(Duration::from_secs(20), || async {
        direct_has_agent(&direct_connections(alice).await, &charlie_id)
    })
    .await;
    assert!(
        charlie_connected,
        "alice never established a direct session to charlie"
    );

    let local_group_id = create_group_preset(
        alice,
        &format!("c2 ltc {}", rand::random::<u16>()),
        "contact scoped delivery",
        "private_secure",
    )
    .await;
    let policy = patch_group_policy(
        alice,
        &local_group_id,
        serde_json::json!({
            "discoverability": "listed_to_contacts",
            "admission": "invite_only",
            "confidentiality": "mls_encrypted",
            "read_access": "members_only",
            "write_access": "members_only"
        }),
    )
    .await;
    assert_eq!(policy["ok"], true, "ltc policy patch failed: {policy:?}");

    let seal = authed_client(alice)
        .post(alice.url(&format!("/groups/{local_group_id}/state/seal")))
        .send()
        .await
        .expect("ltc seal request")
        .json::<Value>()
        .await
        .expect("ltc seal json");
    assert_eq!(seal["ok"], true, "ltc seal failed: {seal:?}");

    let authority_card = get_group_card(alice, &local_group_id).await;
    let stable_group_id = authority_card["group_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !stable_group_id.is_empty(),
        "alice LTC card missing stable group_id: {authority_card:?}"
    );
    assert_eq!(
        authority_card["policy_summary"]["discoverability"].as_str(),
        Some("listed_to_contacts"),
        "alice LTC card should be listed_to_contacts: {authority_card:?}"
    );

    let bob_received = wait_until(Duration::from_secs(20), || async {
        let (status, _) = get_group_card_response(bob, &stable_group_id).await;
        status == reqwest::StatusCode::OK
    })
    .await;
    let (bob_status, bob_card) = get_group_card_response(bob, &stable_group_id).await;
    assert!(
        bob_received && bob_status == reqwest::StatusCode::OK,
        "bob never received LTC card: status={bob_status} body={bob_card:?}"
    );
    assert_eq!(
        bob_card["policy_summary"]["discoverability"].as_str(),
        Some("listed_to_contacts"),
        "bob received wrong card: {bob_card:?}"
    );

    let charlie_received = wait_until(Duration::from_secs(8), || async {
        let (status, _) = get_group_card_response(charlie, &stable_group_id).await;
        status == reqwest::StatusCode::OK
    })
    .await;
    let (charlie_status, charlie_body) = get_group_card_response(charlie, &stable_group_id).await;
    assert!(
        !charlie_received && charlie_status == reqwest::StatusCode::NOT_FOUND,
        "charlie unexpectedly received LTC card: status={charlie_status} body={charlie_body:?}"
    );

    let bob_nearby = nearby_groups(bob).await;
    assert!(
        !nearby_has_group(&bob_nearby, &stable_group_id),
        "bob should not see LTC group on public nearby: {bob_nearby:?}"
    );
    let charlie_nearby = nearby_groups(charlie).await;
    assert!(
        !nearby_has_group(&charlie_nearby, &stable_group_id),
        "charlie should not see LTC group on public nearby: {charlie_nearby:?}"
    );

    let _ = authed_client(alice)
        .delete(alice.url(&format!("/groups/{local_group_id}")))
        .send()
        .await;
}

#[tokio::test]
#[ignore]
async fn c2_subscriptions_persist_across_restart_and_receive_after_resubscribe() {
    let _guard = suite_lock().await;
    let mut pair = pair_with_extra_config(
        "group_card_republish_interval_secs = 0\n\
         directory_resubscribe_jitter_ms = 500",
    )
    .await;

    let token = format!("c2restart{}", rand::random::<u16>());
    let tag_sub = subscribe_shard_key(&pair.bob, "tag", "unused-restart-tag").await;
    assert_eq!(tag_sub["ok"], true, "tag subscribe failed: {tag_sub:?}");
    let name_sub = subscribe_shard_key(&pair.bob, "name", &token).await;
    assert_eq!(name_sub["ok"], true, "name subscribe failed: {name_sub:?}");

    let local_group_id = create_group_preset(
        &pair.alice,
        &format!("{token} restart proof"),
        "restart persistence witness",
        "public_request_secure",
    )
    .await;
    let authority_card = get_group_card(&pair.alice, &local_group_id).await;
    let stable_group_id = authority_card["group_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !stable_group_id.is_empty(),
        "group card missing stable group_id: {authority_card:?}"
    );

    let id_sub = subscribe_shard_key(&pair.bob, "id", &stable_group_id).await;
    assert_eq!(id_sub["ok"], true, "id subscribe failed: {id_sub:?}");

    let subs = list_discovery_subscriptions(&pair.bob).await;
    assert_eq!(
        subs["count"], 3,
        "bob should have 3 subscriptions: {subs:?}"
    );

    let subscriptions_path = pair.bob.directory_subscriptions_path();
    let persisted = tokio::fs::read(&subscriptions_path)
        .await
        .expect("read subscriptions file before restart");
    let persisted_json: Value =
        serde_json::from_slice(&persisted).expect("parse subscriptions file");
    assert_eq!(
        persisted_json["subscriptions"]
            .as_array()
            .map_or(0, |s| s.len()),
        3,
        "subscription file should contain 3 entries: {persisted_json:?}"
    );

    pair.bob.restart().await;

    let resubscriptions_loaded = wait_until(Duration::from_secs(10), || async {
        list_discovery_subscriptions(&pair.bob).await["count"] == 3
    })
    .await;
    assert!(
        resubscriptions_loaded,
        "bob did not reload 3 subscriptions after restart"
    );

    let mesh_restored = wait_until(Duration::from_secs(20), || async {
        peer_count(&pair.bob).await > 0
    })
    .await;
    assert!(
        mesh_restored,
        "bob did not reconnect to the mesh after restart"
    );

    tokio::time::sleep(Duration::from_secs(2)).await;

    let discovered = if nearby_has_group(&nearby_groups(&pair.bob).await, &stable_group_id) {
        true
    } else {
        let seal = authed_client(&pair.alice)
            .post(
                pair.alice
                    .url(&format!("/groups/{local_group_id}/state/seal")),
            )
            .send()
            .await
            .expect("restart seal request")
            .json::<Value>()
            .await
            .expect("restart seal json");
        assert_eq!(seal["ok"], true, "restart seal failed: {seal:?}");

        wait_until(Duration::from_secs(20), || async {
            let nearby = nearby_groups(&pair.bob).await;
            if nearby_has_group(&nearby, &stable_group_id) {
                return true;
            }
            let _ = authed_client(&pair.alice)
                .post(
                    pair.alice
                        .url(&format!("/groups/{local_group_id}/state/seal")),
                )
                .send()
                .await;
            false
        })
        .await
    };
    let final_nearby = nearby_groups(&pair.bob).await;
    assert!(
        discovered,
        "bob never re-discovered the group after restart resubscribe: {final_nearby:?}"
    );

    let _ = authed_client(&pair.alice)
        .delete(pair.alice.url(&format!("/groups/{local_group_id}")))
        .send()
        .await;
}
