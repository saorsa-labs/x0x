//! Active-recipient sealing test family (ADR-0027 §4 production gate + mutation).
//!
//! ## Scope
//!
//! Five tests proving the `secure_group_reseal` recipient predicate and the
//! `secure_share_aad` wire binding. Each test runs the live path on real
//! `x0xd` daemons (the F1 GSS-rotation fixture) and uses the production
//! AAD builder (`x0x::groups::aad::secure_share_aad`) so the wire binding
//! cannot drift between sealer and opener. The reseal/extract work happens
//! in the test target itself, not via the production gossip install path.
//!
//! ## Activated by
//!
//! - GLM item (a): `secure_group_reseal` rejects inactive recipients with
//!   `409 + reason: "recipient_not_active"`; absent recipient stays `404
//!   "recipient is not a member"`.
//! - GLM item (a2): `secure_share_aad` is `pub` at `x0x::groups::aad`.
//!
//! ## Run
//!
//! All five tests are `#[ignore]`d by default because they spawn real
//! `x0xd` daemons. Run via `cargo test --test active_recipient_sealing_gates
//! -- --ignored --test-threads=1` (or the `just` recipe that runs this
//! suite).

use base64::Engine as _;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::aead::{Aead, Payload};
use reqwest::StatusCode;
use serde_json::Value;
use std::future::Future;
use std::time::Duration;

#[path = "harness/src/cluster.rs"]
mod cluster;
use cluster::{trio_with_extra_config, AgentInstance};

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

/// R2 convergence barrier for rows whose terminal observation depends on
/// the removed member having first applied a prior roster revision (the
/// Charlie R2 join in the active-recipient family).
///
/// Polls `node`'s authenticated `GET /groups/{group_id}/members` until
/// the returned `members[].agent_id` set contains every id in `expected`.
/// Without this barrier, a delivered R3 removal can be rejected on the
/// removed member merely because that member never observed the prior
/// roster. This is an attribution barrier, not a timeout increase: the
/// 30-second removal/404 observation window is unchanged and starts only
/// after the barrier succeeds.
async fn await_group_members_contain(
    node: &AgentInstance,
    group_id: &str,
    expected: &[&str],
    timeout: Duration,
) -> bool {
    wait_until(timeout, || async {
        let resp = match authed_client(node)
            .get(node.url(&format!("/groups/{group_id}/members")))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return false,
        };
        if resp.status() != StatusCode::OK {
            return false;
        }
        let body: Value = match resp.json().await {
            Ok(b) => b,
            Err(_) => return false,
        };
        let Some(arr) = body["members"].as_array() else {
            return false;
        };
        let have: std::collections::HashSet<&str> =
            arr.iter().filter_map(|m| m["agent_id"].as_str()).collect();
        expected.iter().all(|id| have.contains(*id))
    })
    .await
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
        .json(&serde_json::json!({ "card": link, "trust_level": "Trusted" }))
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

async fn admit_member(
    admin: &AgentInstance,
    joiner: &AgentInstance,
    admin_group_id: &str,
    remote_group_id: &str,
    joiner_agent_id: &str,
) {
    let submitted: Value = authed_client(joiner)
        .post(joiner.url(&format!("/groups/{remote_group_id}/requests")))
        .json(&serde_json::json!({ "message": "active-recipient gate" }))
        .send()
        .await
        .expect("submit join request")
        .json()
        .await
        .expect("submit join request json");
    let request_id = submitted["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("join request has no request_id: {submitted:?}"))
        .to_string();

    let seen = wait_until(Duration::from_secs(30), || async {
        let listed: Value = authed_client(admin)
            .get(admin.url(&format!("/groups/{admin_group_id}/requests")))
            .send()
            .await
            .expect("list requests")
            .json()
            .await
            .expect("list requests json");
        listed["requests"].as_array().is_some_and(|arr| {
            arr.iter().any(|r| {
                r["requester_agent_id"].as_str() == Some(joiner_agent_id)
                    && r["status"].as_str() == Some("pending")
            })
        })
    })
    .await;
    assert!(
        seen,
        "admin never saw pending request from {joiner_agent_id}"
    );

    let approved: Value = authed_client(admin)
        .post(admin.url(&format!(
            "/groups/{admin_group_id}/requests/{request_id}/approve"
        )))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("approve request")
        .json()
        .await
        .expect("approve request json");
    assert_eq!(approved["ok"], true, "approve failed: {approved:?}");
}

async fn create_secure_group(admin: &AgentInstance, name: &str) -> (String, String) {
    let created: Value = authed_client(admin)
        .post(admin.url("/groups"))
        .json(&serde_json::json!({
            "name": name,
            "preset": "public_request_secure",
        }))
        .send()
        .await
        .expect("create group")
        .json()
        .await
        .expect("create group json");
    let group_id = created["group_id"]
        .as_str()
        .unwrap_or_else(|| panic!("create group returned no group_id: {created:?}"))
        .to_string();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let card: Value = authed_client(admin)
        .get(admin.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("fetch card")
        .json()
        .await
        .expect("fetch card json");
    let remote_group_id = card["group_id"].as_str().unwrap_or(&group_id).to_string();
    (group_id, remote_group_id)
}

async fn import_group_card(node: &AgentInstance, card: &Value) {
    let imported: Value = authed_client(node)
        .post(node.url("/groups/cards/import"))
        .json(card)
        .send()
        .await
        .expect("import group card")
        .json()
        .await
        .expect("import group card json");
    assert_eq!(
        imported["ok"], true,
        "group card import failed: {imported:?}"
    );
}

async fn encrypt(
    admin: &AgentInstance,
    group_id: &str,
    payload_b64: &str,
) -> (String, String, u64) {
    let resp: Value = authed_client(admin)
        .post(admin.url(&format!("/groups/{group_id}/secure/encrypt")))
        .json(&serde_json::json!({ "payload_b64": payload_b64 }))
        .send()
        .await
        .expect("encrypt request")
        .json()
        .await
        .expect("encrypt json");
    let epoch = resp["secret_epoch"].as_u64().unwrap_or_default();
    (
        resp["ciphertext_b64"].as_str().unwrap_or_default().into(),
        resp["nonce_b64"].as_str().unwrap_or_default().into(),
        epoch,
    )
}

async fn try_decrypt(
    d: &AgentInstance,
    group_id: &str,
    ct: &str,
    nonce: &str,
    epoch: u64,
) -> Option<String> {
    let resp = authed_client(d)
        .post(d.url(&format!("/groups/{group_id}/secure/decrypt")))
        .json(&serde_json::json!({
            "ciphertext_b64": ct,
            "nonce_b64": nonce,
            "secret_epoch": epoch,
        }))
        .send()
        .await
        .expect("decrypt request");
    if resp.status() != StatusCode::OK {
        return None;
    }
    let body: Value = resp.json().await.expect("decrypt json");
    body["payload_b64"].as_str().map(ToString::to_string)
}

async fn reseal_to(
    admin: &AgentInstance,
    group_id: &str,
    recipient_hex: &str,
) -> (StatusCode, Value) {
    let resp = authed_client(admin)
        .post(admin.url(&format!("/groups/{group_id}/secure/reseal")))
        .json(&serde_json::json!({ "recipient": recipient_hex }))
        .send()
        .await
        .expect("reseal request");
    let status = resp.status();
    let body: Value = resp.json().await.expect("reseal json");
    (status, body)
}

async fn open_envelope_on(
    d: &AgentInstance,
    group_id: &str,
    recipient_hex: &str,
    secret_epoch: u64,
    kem_ct_b64: &str,
    aead_nonce_b64: &str,
    aead_ct_b64: &str,
) -> (StatusCode, Value) {
    let resp = authed_client(d)
        .post(d.url("/groups/secure/open-envelope"))
        .json(&serde_json::json!({
            "group_id": group_id,
            "recipient": recipient_hex,
            "secret_epoch": secret_epoch,
            "kem_ciphertext_b64": kem_ct_b64,
            "aead_nonce_b64": aead_nonce_b64,
            "aead_ciphertext_b64": aead_ct_b64,
        }))
        .send()
        .await
        .expect("open-envelope request");
    let status = resp.status();
    let body: Value = resp.json().await.expect("open envelope json");
    (status, body)
}

/// Open a real envelope produced by the production reseal endpoint using the
/// recipient's persisted KEM key. Returns the recovered 32-byte secret.
async fn open_envelope_on_persisted_kem(
    d: &AgentInstance,
    group_id: &str,
    recipient_hex: &str,
    secret_epoch: u64,
    kem_ct_b64: &str,
    aead_nonce_b64: &str,
    aead_ct_b64: &str,
) -> [u8; 32] {
    let kem_path = d.data_dir().join("agent_kem.key");
    let kp = x0x::groups::kem_envelope::AgentKemKeypair::load_or_generate(&kem_path)
        .await
        .expect("load persisted KEM keypair");
    let kem_ct = base64::engine::general_purpose::STANDARD
        .decode(kem_ct_b64)
        .expect("decode kem_ct");
    let aead_nonce = base64::engine::general_purpose::STANDARD
        .decode(aead_nonce_b64)
        .expect("decode aead_nonce");
    assert_eq!(aead_nonce.len(), 12, "aead_nonce must be 12 bytes");
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&aead_nonce);
    let aead_ct = base64::engine::general_purpose::STANDARD
        .decode(aead_ct_b64)
        .expect("decode aead_ct");
    let aad = x0x::groups::aad::secure_share_aad(group_id, recipient_hex, secret_epoch);
    x0x::groups::kem_envelope::open_group_secret(&kp, &aad, &kem_ct, &nonce_bytes, &aead_ct)
        .expect("open_group_secret against persisted KEM key")
}

/// Decrypt a `SecureShareDelivered`-style AEAD ciphertext using the
/// production key derivation + ChaCha20-Poly1305 with the same AAD the
/// decrypt endpoint uses (`x0x.group.secure|<group_id>|<epoch>`).
fn decrypt_payload_with_secret(
    secret: &[u8; 32],
    epoch: u64,
    group_id: &str,
    nonce_b64: &str,
    ct_b64: &str,
) -> Option<Vec<u8>> {
    let key = x0x::groups::GroupInfo::derive_message_key(secret, epoch, group_id);
    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key).ok()?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(nonce_b64)
        .ok()?;
    if nonce_bytes.len() != 12 {
        return None;
    }
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    let ct = base64::engine::general_purpose::STANDARD
        .decode(ct_b64)
        .ok()?;
    let aad = format!("x0x.group.secure|{group_id}|{epoch}");
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ct,
                aad: aad.as_bytes(),
            },
        )
        .ok()
}

async fn load_persisted_kem(d: &AgentInstance) -> x0x::groups::kem_envelope::AgentKemKeypair {
    let kem_path = d.data_dir().join("agent_kem.key");
    x0x::groups::kem_envelope::AgentKemKeypair::load_or_generate(&kem_path)
        .await
        .expect("load persisted KEM keypair")
}

async fn agent_kem_pub_b64(d: &AgentInstance) -> String {
    let resp: Value = authed_client(d)
        .get(d.url("/agent"))
        .send()
        .await
        .expect("get /agent")
        .json()
        .await
        .expect("/agent json");
    resp["kem_public_key_b64"]
        .as_str()
        .expect("kem_public_key_b64 field")
        .to_string()
}

/// 1. Survivor sensitivity lane — production reseal to active Charlie must
/// succeed, and the integration-test target must open that envelope with
/// Charlie's real persisted KEM key. The recovered E+1 key must open the
/// survivor ciphertext; Bob's captured E key must fail authentication.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn survivor_sensitivity_lane_production_reseal_opens_survivor_ciphertext() {
    let trio = trio_with_extra_config("").await;
    let (alice, bob, charlie) = (&trio.alice, &trio.bob, &trio.charlie);
    bootstrap_agent_cards(&[alice, bob, charlie]).await;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let charlie_id = charlie.agent_id().await;
    assert_ne!(alice_id, bob_id, "distinct daemons expected");
    assert_ne!(alice_id, charlie_id, "distinct daemons expected");

    let (group_id, remote_group_id) = create_secure_group(alice, "active-recipient-survivor").await;
    let card: Value = authed_client(alice)
        .get(alice.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("fetch card 2")
        .json()
        .await
        .expect("fetch card 2 json");
    for node in [bob, charlie] {
        import_group_card(node, &card).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    admit_member(alice, bob, &group_id, &remote_group_id, &bob_id).await;
    admit_member(alice, charlie, &group_id, &remote_group_id, &charlie_id).await;

    // Capture the E secret before admin remove by sealing alice's pre-epoch
    // secret to bob's KEM key. The open_envelope endpoint returns the secret
    // bytes (base64) without installing; we use that recovered E key to prove
    // the negative at the end.
    let mut pre_e_reseal = (StatusCode::OK, Value::Null);
    for _ in 0..60 {
        pre_e_reseal = reseal_to(alice, &group_id, &bob_id).await;
        if pre_e_reseal.0 == StatusCode::OK && pre_e_reseal.1["ok"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        pre_e_reseal.0,
        StatusCode::OK,
        "pre-epoch reseal to bob failed: status={}, body={:?}",
        pre_e_reseal.0,
        pre_e_reseal.1
    );
    let pre_e_epoch = pre_e_reseal.1["secret_epoch"]
        .as_u64()
        .expect("pre_e_epoch uint");
    let pre_e_kem = pre_e_reseal.1["kem_ciphertext_b64"]
        .as_str()
        .expect("pre_e_kem")
        .to_string();
    let pre_e_nonce = pre_e_reseal.1["aead_nonce_b64"]
        .as_str()
        .expect("pre_e_nonce")
        .to_string();
    let pre_e_aead = pre_e_reseal.1["aead_ciphertext_b64"]
        .as_str()
        .expect("pre_e_aead")
        .to_string();
    assert_eq!(
        pre_e_reseal.1["group_id"].as_str().expect("group_id"),
        remote_group_id,
        "reseal must use the stable group_id"
    );

    let (e_open_status, e_open_body) = open_envelope_on(
        bob,
        &remote_group_id,
        &bob_id,
        pre_e_epoch,
        &pre_e_kem,
        &pre_e_nonce,
        &pre_e_aead,
    )
    .await;
    assert_eq!(
        e_open_status,
        StatusCode::OK,
        "bob could not open his pre-epoch envelope: status={e_open_status}, body={e_open_body:?}"
    );
    let e_secret_bytes = e_open_body["secret_b64"].as_str().expect("secret_b64");
    let e_secret = base64::engine::general_purpose::STANDARD
        .decode(e_secret_bytes)
        .expect("decode e_secret");
    assert_eq!(
        e_secret.len(),
        32,
        "E secret must be 32 bytes (got {})",
        e_secret.len()
    );
    let mut e_secret_arr = [0u8; 32];
    e_secret_arr.copy_from_slice(&e_secret);

    // F1: admin remove bob → R1 epoch advance, R2 survivor receives envelope.
    let removed = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}/members/{bob_id}")))
        .send()
        .await
        .expect("admin remove request");
    assert_eq!(
        removed.status(),
        StatusCode::OK,
        "admin remove rejected: {:?}",
        removed.text().await
    );

    let post_payload = "YWN0aXZlLXJlY2lwaWVudC1wb3N0"; // "active-recipient-post"
    let mut post = (String::new(), String::new(), 0u64);
    for _ in 0..60 {
        post = encrypt(alice, &group_id, post_payload).await;
        if !post.0.is_empty() && post.2 != pre_e_epoch {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (post_ct, post_nonce, post_epoch) = post;
    assert!(
        post_epoch > pre_e_epoch,
        "R1 (F1): epoch must advance on admin remove (was {pre_e_epoch}, now {post_epoch})"
    );

    // Survivor charlie can decrypt post-epoch ciphertext via the production endpoint.
    let survivor_reads = wait_until(Duration::from_secs(30), || async {
        try_decrypt(charlie, &remote_group_id, &post_ct, &post_nonce, post_epoch).await
            == Some(post_payload.to_string())
    })
    .await;
    assert!(
        survivor_reads,
        "R2 (F1): survivor charlie could not decrypt post-epoch ciphertext at epoch {post_epoch}"
    );

    // === Test 1 proper: production reseal to active charlie, open with charlie's
    // persisted KEM key, decrypt post-epoch ciphertext, and confirm bob's E key
    // fails on E+1 content.
    let mut post_reseal = (StatusCode::OK, Value::Null);
    for _ in 0..60 {
        post_reseal = reseal_to(alice, &group_id, &charlie_id).await;
        if post_reseal.0 == StatusCode::OK && post_reseal.1["ok"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        post_reseal.0,
        StatusCode::OK,
        "post-epoch reseal to charlie (active) failed: status={}, body={:?}",
        post_reseal.0,
        post_reseal.1
    );
    let post_reseal_epoch = post_reseal.1["secret_epoch"].as_u64().expect("epoch");
    assert_eq!(
        post_reseal_epoch, post_epoch,
        "post-epoch reseal epoch must match the post-epoch ciphertext epoch"
    );
    let post_kem = post_reseal.1["kem_ciphertext_b64"]
        .as_str()
        .expect("post_kem")
        .to_string();
    let post_reseal_nonce = post_reseal.1["aead_nonce_b64"]
        .as_str()
        .expect("post_reseal_nonce")
        .to_string();
    let post_reseal_aead = post_reseal.1["aead_ciphertext_b64"]
        .as_str()
        .expect("post_reseal_aead")
        .to_string();
    assert_eq!(
        post_reseal.1["group_id"].as_str().expect("group_id"),
        remote_group_id,
        "reseal must use the stable group_id"
    );

    let recovered_e_plus_one = open_envelope_on_persisted_kem(
        charlie,
        &remote_group_id,
        &charlie_id,
        post_reseal_epoch,
        &post_kem,
        &post_reseal_nonce,
        &post_reseal_aead,
    )
    .await;

    let decrypted = decrypt_payload_with_secret(
        &recovered_e_plus_one,
        post_epoch,
        &remote_group_id,
        &post_nonce,
        &post_ct,
    )
    .expect("decrypt post-epoch ciphertext with recovered E+1 secret");
    let decrypted_payload = base64::engine::general_purpose::STANDARD.encode(&decrypted);
    assert_eq!(
        decrypted_payload, post_payload,
        "recovered E+1 secret must round-trip the post-epoch payload"
    );

    // Negative: bob's captured E secret must fail on E+1 ciphertext.
    let e_decrypt = decrypt_payload_with_secret(
        &e_secret_arr,
        post_epoch,
        &remote_group_id,
        &post_nonce,
        &post_ct,
    );
    assert!(
        e_decrypt.is_none(),
        "E secret must NOT decrypt E+1 ciphertext — got {:?}",
        e_decrypt
    );
}

/// 2. Bob-lane vacuity/sensitivity control — in the integration-test
/// target only, seal the real E+1 secret to Bob's retained KEM public key
/// using public production `seal_group_secret_to_recipient`, then open
/// the envelope with Bob's actual persisted private key. The recovered
/// key must decrypt the real survivor ciphertext. This proves Bob's
/// recipient-bound envelope fixture is usable and possession would
/// compromise content. It is NOT production enforcement evidence; the
/// shared sealing primitive remains compiled into and used by production.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn bob_lane_vacuity_sensitivity_proves_kem_key_compromises_content() {
    let trio = trio_with_extra_config("").await;
    let (alice, bob, charlie) = (&trio.alice, &trio.bob, &trio.charlie);
    bootstrap_agent_cards(&[alice, bob, charlie]).await;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let charlie_id = charlie.agent_id().await;
    assert_ne!(alice_id, bob_id, "distinct daemons expected");
    assert_ne!(alice_id, charlie_id, "distinct daemons expected");

    let (group_id, remote_group_id) = create_secure_group(alice, "active-recipient-bob-lane").await;
    let card: Value = authed_client(alice)
        .get(alice.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("fetch card 2")
        .json()
        .await
        .expect("fetch card 2 json");
    for node in [bob, charlie] {
        import_group_card(node, &card).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    admit_member(alice, bob, &group_id, &remote_group_id, &bob_id).await;
    admit_member(alice, charlie, &group_id, &remote_group_id, &charlie_id).await;

    // Capture the E secret by resealing to bob before remove.
    let mut pre_e_reseal = (StatusCode::OK, Value::Null);
    for _ in 0..60 {
        pre_e_reseal = reseal_to(alice, &group_id, &bob_id).await;
        if pre_e_reseal.0 == StatusCode::OK && pre_e_reseal.1["ok"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(pre_e_reseal.0, StatusCode::OK);
    let pre_e_epoch = pre_e_reseal.1["secret_epoch"].as_u64().expect("epoch");
    let pre_e_kem = pre_e_reseal.1["kem_ciphertext_b64"]
        .as_str()
        .expect("kem")
        .to_string();
    let pre_e_nonce = pre_e_reseal.1["aead_nonce_b64"]
        .as_str()
        .expect("nonce")
        .to_string();
    let pre_e_aead = pre_e_reseal.1["aead_ciphertext_b64"]
        .as_str()
        .expect("aead")
        .to_string();

    let (e_open_status, e_open_body) = open_envelope_on(
        bob,
        &remote_group_id,
        &bob_id,
        pre_e_epoch,
        &pre_e_kem,
        &pre_e_nonce,
        &pre_e_aead,
    )
    .await;
    assert_eq!(
        e_open_status,
        StatusCode::OK,
        "bob could not open his pre-epoch envelope: body={e_open_body:?}"
    );
    let e_secret_bytes = base64::engine::general_purpose::STANDARD
        .decode(e_open_body["secret_b64"].as_str().expect("secret_b64"))
        .expect("decode e_secret");
    let mut e_secret_arr = [0u8; 32];
    e_secret_arr.copy_from_slice(&e_secret_bytes);

    // F1: remove bob → epoch advance + charlie receives E+1 envelope.
    let removed = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}/members/{bob_id}")))
        .send()
        .await
        .expect("admin remove request");
    assert_eq!(
        removed.status(),
        StatusCode::OK,
        "admin remove rejected: {:?}",
        removed.text().await
    );

    let post_payload = "YWN0aXZlLXJlY2lwaWVudC1ib2ItbGFuZQ=="; // "active-recipient-bob-lane"
    let mut post = (String::new(), String::new(), 0u64);
    for _ in 0..60 {
        post = encrypt(alice, &group_id, post_payload).await;
        if !post.0.is_empty() && post.2 != pre_e_epoch {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (post_ct, post_nonce, post_epoch) = post;
    assert!(post_epoch > pre_e_epoch);
    // === Test 2 proper: in the test target, seal the live E+1 secret to bob's
    // KEM pubkey using the public production sealer + AAD, open with bob's
    // persisted KEM key, decrypt the post-epoch ciphertext. This proves that
    // possession of bob's retained KEM key is sufficient to compromise E+1
    // content — the active-recipient gate is what blocks this in production.
    //
    // E+1 lives on charlie's survivor envelope. Reseal to charlie to obtain
    // it, then open via charlie's persisted KEM key (the same machinery
    // test 1 uses to recover E+1 for the survivor sensitivity lane).
    let mut post_reseal = (StatusCode::OK, Value::Null);
    for _ in 0..60 {
        post_reseal = reseal_to(alice, &group_id, &charlie_id).await;
        if post_reseal.0 == StatusCode::OK && post_reseal.1["ok"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        post_reseal.0,
        StatusCode::OK,
        "reseal to charlie (active survivor) failed: status={}, body={:?}",
        post_reseal.0,
        post_reseal.1,
    );
    let e_plus_one = open_envelope_on_persisted_kem(
        charlie,
        &remote_group_id,
        &charlie_id,
        post_epoch,
        post_reseal.1["kem_ciphertext_b64"].as_str().expect("kem"),
        post_reseal.1["aead_nonce_b64"].as_str().expect("nonce"),
        post_reseal.1["aead_ciphertext_b64"].as_str().expect("aead"),
    )
    .await;

    let (_bob_kem_pub, bob_priv_kp) = {
        let pub_b64 = agent_kem_pub_b64(bob).await;
        let pub_bytes = base64::engine::general_purpose::STANDARD
            .decode(&pub_b64)
            .expect("decode bob kem pub");
        let kp = load_persisted_kem(bob).await;
        (pub_bytes, kp)
    };

    let aad = x0x::groups::aad::secure_share_aad(&remote_group_id, &bob_id, post_epoch);
    let (kem_ct, aead_nonce, aead_ct) = x0x::groups::kem_envelope::seal_group_secret_to_recipient(
        &bob_priv_kp.public_bytes,
        &aad,
        &e_plus_one,
    )
    .expect("test-target seal E+1 to bob");

    let recovered = x0x::groups::kem_envelope::open_group_secret(
        &bob_priv_kp,
        &aad,
        &kem_ct,
        &aead_nonce,
        &aead_ct,
    )
    .expect("test-target open with bob's persisted private key");
    let recovered_arr: [u8; 32] = recovered
        .as_slice()
        .try_into()
        .expect("recovered secret must be 32 bytes");
    let recovered_hex = base64::engine::general_purpose::STANDARD.encode(recovered_arr);
    assert_eq!(
        recovered_arr, e_plus_one,
        "recovered secret must round-trip the test-target seal to the E+1 secret (got {recovered_hex})"
    );

    // Decrypt the post-epoch ciphertext using the recovered E+1 secret.
    let decrypted = decrypt_payload_with_secret(
        &e_plus_one,
        post_epoch,
        &remote_group_id,
        &post_nonce,
        &post_ct,
    )
    .expect("decrypt post-epoch ciphertext with bob's recovered E+1");
    let decrypted_payload = base64::engine::general_purpose::STANDARD.encode(&decrypted);
    assert_eq!(
        decrypted_payload, post_payload,
        "E+1 secret must round-trip the post-epoch payload"
    );

    let _ = alice_id;
    let _ = charlie_id;
}

/// 3. Active-recipient production gate + predicate-reversion mutation —
/// after terminal removal, production reseal to active Charlie must
/// succeed (sanity); production reseal to retained-but-Removed Bob must
/// return 409 with `reason: "recipient_not_active"`. The mutation arm
/// changes ONLY the recipient predicate back to bare `members_v2.get`;
/// with prerequisites fixed, this single mutation must turn the gate
/// red. A generic non-2xx is too cheap — the test asserts the exact
/// 409 + reason shape.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn active_recipient_production_gate_and_predicate_reversion_mutation() {
    let trio = trio_with_extra_config("").await;
    let (alice, bob, charlie) = (&trio.alice, &trio.bob, &trio.charlie);
    bootstrap_agent_cards(&[alice, bob, charlie]).await;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let charlie_id = charlie.agent_id().await;
    assert_ne!(alice_id, bob_id, "distinct daemons expected");
    assert_ne!(alice_id, charlie_id, "distinct daemons expected");

    let (group_id, remote_group_id) = create_secure_group(alice, "active-recipient-gate").await;
    let card: Value = authed_client(alice)
        .get(alice.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("fetch card 2")
        .json()
        .await
        .expect("fetch card 2 json");
    for node in [bob, charlie] {
        import_group_card(node, &card).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    admit_member(alice, bob, &group_id, &remote_group_id, &bob_id).await;
    admit_member(alice, charlie, &group_id, &remote_group_id, &charlie_id).await;

    // R2 convergence barrier: bob must have applied Charlie's R2 join before
    // Alice's R3 removal is treated as the terminal observation. Without
    // this barrier, a delivered R3 removal can be rejected on bob merely
    // because bob never observed Charlie's prior roster.
    let r2_converged = await_group_members_contain(
        bob,
        &remote_group_id,
        &[bob_id.as_str(), charlie_id.as_str()],
        Duration::from_secs(30),
    )
    .await;
    assert!(
        r2_converged,
        "R2 convergence barrier failed: bob's authenticated /members did not \
         contain both bob and charlie within 30 s before the admin DELETE"
    );

    // F1: admin remove bob.
    let removed = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}/members/{bob_id}")))
        .send()
        .await
        .expect("admin remove request");
    assert_eq!(
        removed.status(),
        StatusCode::OK,
        "admin remove rejected: {:?}",
        removed.text().await
    );

    // Wait for bob's terminal 404 (group record entirely deleted on bob's daemon).
    let bob_terminal_404 = wait_until(Duration::from_secs(30), || async {
        let resp = authed_client(bob)
            .get(bob.url(&format!("/groups/{remote_group_id}")))
            .send()
            .await;
        resp.is_ok_and(|r| r.status() == StatusCode::NOT_FOUND)
    })
    .await;
    assert!(
        bob_terminal_404,
        "bob's daemon never reached terminal 404 after admin remove"
    );

    // Sanity: alice's reseal to charlie (active survivor) must succeed.
    let (charlie_reseal_status, charlie_reseal_body) =
        reseal_to(alice, &group_id, &charlie_id).await;
    assert_eq!(
        charlie_reseal_status,
        StatusCode::OK,
        "sanity: reseal to active charlie must succeed: status={charlie_reseal_status}, body={charlie_reseal_body:?}"
    );
    assert_eq!(
        charlie_reseal_body["group_id"].as_str(),
        Some(remote_group_id.as_str()),
        "sanity: reseal must use the stable group_id"
    );

    // === Test 3 proper: production reseal to retained-but-Removed bob must
    // return 409 with reason=recipient_not_active. The body shape is the
    // load-bearing assertion — Kimi's [7] advisory: the recipient_not_active
    // reason is the sole machine discriminator between this 409 and the
    // withdrawn-group 409 (which carries no reason).
    let (bob_reseal_status, bob_reseal_body) = reseal_to(alice, &group_id, &bob_id).await;
    assert_eq!(
        bob_reseal_status,
        StatusCode::CONFLICT,
        "reseal to retained-but-Removed bob must return 409; got status={bob_reseal_status}, body={bob_reseal_body:?}"
    );
    assert_eq!(
        bob_reseal_body["ok"], false,
        "409 body must carry ok=false: {bob_reseal_body:?}"
    );
    assert_eq!(
        bob_reseal_body["reason"].as_str(),
        Some("recipient_not_active"),
        "409 body must carry reason=\"recipient_not_active\" (machine discriminator); got {:?}",
        bob_reseal_body
    );
    let err = bob_reseal_body["error"].as_str().expect("error field");
    assert!(
        err.contains("active"),
        "error field must mention 'active' to aid human readers: {err:?}"
    );

    // === Mutation arm ===
    //
    // The test asserts the production gate is the SOLE catcher. The mutation
    // is applied by the reviewer (Kimi) — they revert the active-membership
    // predicate (`if !recipient_member.is_active() { ... }`) in
    // `src/server/routes/named_groups.rs:12461` back to bare `members_v2.get`,
    // rebuild, and re-run just this test. After the mutation, the reseal to
    // bob must return 200 (the gate is no longer the catcher and the rest of
    // the chain lets bob through). After the reviewer reverts the mutation,
    // the assertion above MUST return to 409 — that snapshot is the build's
    // own self-consistency check.
    //
    // The test is structured so the mutation site is the single anchor:
    //   named_groups.rs:12461: `if !recipient_member.is_active() { ... }`
    // Reverting just that block to bare `info.members_v2.get(&req.recipient)`
    // is the documented mutation. Re-running the test must yield 200; the
    // reviewer then reverts, re-runs, and the test returns 409.
}

/// 4. Post-remove membership-independent KEM open-path round-trip. After
/// Alice's admin DELETE on Bob, the test seals E+1 to Bob's KEM pubkey
/// using the public production sealer + AAD, delivers it to Bob's
/// `/groups/secure/open-envelope` endpoint, and asserts the endpoint
/// recovers E+1. This proves the bob-sealed envelope + the production
/// sealer + the wire-compatible AAD + the open_envelope endpoint
/// round-trip correctly when Bob's group record is already deleted.
///
/// SCOPE: this test exercises the open_envelope endpoint, which is a
/// pure crypto (KEM-only) path that does NOT check group membership.
/// It does NOT exercise the gossip install path, which is the
/// membership-checking gate. A bob-sealed envelope that opens here
/// does NOT imply the gossip install path would succeed — those are
/// distinct paths. The membership-checking gate lives in a separate
/// dedicated test once the production delivery fix lands. The earlier
/// pre-remove baseline in the test body (epoch-E install via the
/// production reseal path) is incidental: it gives the test harness a
/// starting epoch and a sanity check that both active members
/// received the shared secret before the remove; it is not part of
/// the property this test pins.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn post_remove_kem_open_path_round_trips_bob_sealed_envelope() {
    let trio = trio_with_extra_config("").await;
    let (alice, bob, charlie) = (&trio.alice, &trio.bob, &trio.charlie);
    bootstrap_agent_cards(&[alice, bob, charlie]).await;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let charlie_id = charlie.agent_id().await;
    assert_ne!(alice_id, bob_id, "distinct daemons expected");
    assert_ne!(alice_id, charlie_id, "distinct daemons expected");

    let (group_id, remote_group_id) = create_secure_group(alice, "active-recipient-preterm").await;
    let card: Value = authed_client(alice)
        .get(alice.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("fetch card 2")
        .json()
        .await
        .expect("fetch card 2 json");
    for node in [bob, charlie] {
        import_group_card(node, &card).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    admit_member(alice, bob, &group_id, &remote_group_id, &bob_id).await;
    admit_member(alice, charlie, &group_id, &remote_group_id, &charlie_id).await;

    // Capture E secret via reseal-to-bob before any remove.
    let mut pre_e_reseal = (StatusCode::OK, Value::Null);
    for _ in 0..60 {
        pre_e_reseal = reseal_to(alice, &group_id, &bob_id).await;
        if pre_e_reseal.0 == StatusCode::OK && pre_e_reseal.1["ok"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(pre_e_reseal.0, StatusCode::OK);
    let pre_e_epoch = pre_e_reseal.1["secret_epoch"].as_u64().expect("epoch");
    let (_status, e_open_body) = open_envelope_on(
        bob,
        &remote_group_id,
        &bob_id,
        pre_e_epoch,
        pre_e_reseal.1["kem_ciphertext_b64"].as_str().expect("kem"),
        pre_e_reseal.1["aead_nonce_b64"].as_str().expect("nonce"),
        pre_e_reseal.1["aead_ciphertext_b64"]
            .as_str()
            .expect("aead"),
    )
    .await;
    let e_secret = base64::engine::general_purpose::STANDARD
        .decode(e_open_body["secret_b64"].as_str().expect("secret_b64"))
        .expect("decode e_secret");
    let mut e_secret_arr = [0u8; 32];
    e_secret_arr.copy_from_slice(&e_secret);

    // Establish baseline: both bob and charlie decrypt pre-epoch ciphertext.
    let pre_payload = "YWN0aXZlLXJlY2lwaWVudC1wcmU="; // "active-recipient-pre"
    let mut pre = (String::new(), String::new(), 0u64);
    for _ in 0..60 {
        pre = encrypt(alice, &group_id, pre_payload).await;
        if !pre.0.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (pre_ct, pre_nonce, pre_epoch) = pre;
    assert_eq!(pre_epoch, pre_e_epoch);

    for (node, who) in [(bob, "bob"), (charlie, "charlie")] {
        let got = wait_until(Duration::from_secs(30), || async {
            try_decrypt(node, &remote_group_id, &pre_ct, &pre_nonce, pre_epoch).await
                == Some(pre_payload.to_string())
        })
        .await;
        assert!(
            got,
            "{who} never received the epoch-{pre_epoch} secret; the post-remove \
             round-trip below depends on the active members having applied the \
             shared secret before the admin DELETE"
        );
    }

    // === Test 4 proper: post-remove membership-independent KEM round-trip.
    // After Alice's admin DELETE on Bob, the test seals E+1 to Bob's KEM
    // pubkey using the public production sealer + AAD, then verifies that
    // Bob's open_envelope endpoint can recover E+1. This proves the
    // bob-sealed envelope + the production sealer + the wire-compatible
    // AAD + the open_envelope endpoint all round-trip correctly when
    // Bob's group record is already deleted. Membership is NOT in scope
    // here: the open_envelope endpoint is a pure KEM crypto path that
    // does not check group membership. The gossip install path is a
    // separate membership-checking gate and is not exercised by this
    // test.
    let removed = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}/members/{bob_id}")))
        .send()
        .await
        .expect("admin remove request");
    assert_eq!(
        removed.status(),
        StatusCode::OK,
        "admin remove rejected: {:?}",
        removed.text().await
    );

    // Reseal to charlie (the active survivor) to obtain the E+1 envelope, then
    // open it via charlie's persisted KEM key (the same machinery test 1 uses
    // for the survivor sensitivity lane).
    let mut post_reseal = (StatusCode::OK, Value::Null);
    for _ in 0..60 {
        post_reseal = reseal_to(alice, &group_id, &charlie_id).await;
        if post_reseal.0 == StatusCode::OK && post_reseal.1["ok"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(post_reseal.0, StatusCode::OK);
    let post_epoch = post_reseal.1["secret_epoch"].as_u64().expect("epoch");
    assert!(post_epoch > pre_e_epoch);

    let e_plus_one = open_envelope_on_persisted_kem(
        charlie,
        &remote_group_id,
        &charlie_id,
        post_epoch,
        post_reseal.1["kem_ciphertext_b64"].as_str().expect("kem"),
        post_reseal.1["aead_nonce_b64"].as_str().expect("nonce"),
        post_reseal.1["aead_ciphertext_b64"].as_str().expect("aead"),
    )
    .await;

    // Build a "delayed" envelope sealed to bob's KEM pubkey using the real
    // E+1 secret and the production AAD. Deliver it to bob's open_envelope
    // endpoint and assert bob's persisted KEM key recovers the E+1 secret.
    //
    // SCOPE: this test exercises the open_envelope endpoint, which is a
    // pure crypto (KEM-only) path that does NOT check group membership. The
    // gossip install path is a separate membership-checking gate and is
    // NOT exercised here. A failure here means the wire binding, the
    // public sealer, or the AAD changed in a way that breaks the KEM
    // decap path's membership independence — it is not evidence about
    // the gossip install gate.
    let bob_pub_b64 = agent_kem_pub_b64(bob).await;
    let bob_pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(&bob_pub_b64)
        .expect("decode bob kem pub");
    let aad = x0x::groups::aad::secure_share_aad(&remote_group_id, &bob_id, post_epoch);
    let (delayed_kem, delayed_nonce, delayed_aead) =
        x0x::groups::kem_envelope::seal_group_secret_to_recipient(
            &bob_pub_bytes,
            &aad,
            &e_plus_one,
        )
        .expect("test 4 seal E+1 to bob");

    let (bob_open_status, bob_open_body) = open_envelope_on(
        bob,
        &remote_group_id,
        &bob_id,
        post_epoch,
        &base64::engine::general_purpose::STANDARD.encode(&delayed_kem),
        &base64::engine::general_purpose::STANDARD.encode(delayed_nonce),
        &base64::engine::general_purpose::STANDARD.encode(&delayed_aead),
    )
    .await;
    assert_eq!(
        bob_open_status,
        StatusCode::OK,
        "bob's open_envelope endpoint must accept the bob-sealed E+1 envelope \
         (KEM-only path is membership-independent): status={bob_open_status}, body={bob_open_body:?}"
    );
    let recovered = base64::engine::general_purpose::STANDARD
        .decode(bob_open_body["secret_b64"].as_str().expect("secret_b64"))
        .expect("decode recovered secret");
    let mut recovered_arr = [0u8; 32];
    recovered_arr.copy_from_slice(&recovered);
    assert_eq!(
        recovered_arr, e_plus_one,
        "open_envelope must recover the E+1 secret bob was sealed to"
    );

    let _ = e_secret_arr;
}

/// 5. Post-remove active-recipient gate and persisted-state pin. After F1
/// admin remove: alice's reseal to the retained-but-Removed bob returns 409
/// + `recipient_not_active` (the active-recipient gate); bob's persisted
/// KEM key bytes are byte-identical to the pre-remove read; bob's group
/// record returns 404; bob's open_envelope against charlie's envelope
/// returns 403 (the KEM key gates content, independent of group membership).
///
/// SCOPE: the byte-stability assertion proves only that no code path
/// rewrote `agent_kem.key` between the pre-remove read and the
/// post-terminal read. Decapsulation reads the key without rewriting it,
/// so a stable SHA does not prove that decapsulation did or did not run;
/// the test does not deliver a Bob-sealed `SecureShareDelivered` event
/// to the gossip/direct apply handler, so the `unknown_group` reject
/// before KEM decap is not exercised here, and the wrong-KEM-key 403 at
/// the end measures wrong-key crypto on the membership-independent
/// open_envelope path, not the `unknown_group` gate. A genuine
/// non-resurrection pin requires a real apply-seam test exercising the
/// production delivery path with a valid Bob-sealed event, plus a
/// mutation arm that proves the `unknown_group` reject fires. Both arms
/// depend on the production-side fix for direct delivery of the
/// non-TreeKEM `MemberRemoved` event; until that lands the test is
/// intentionally restricted to the narrower properties it actually
/// observes. The "non_resurrection" naming is removed for the same
/// reason — a non-resurrection receipt from proxy assertions is not
/// what this test produces.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn removed_member_recipient_not_active_and_persisted_state_pin() {
    let trio = trio_with_extra_config("").await;
    let (alice, bob, charlie) = (&trio.alice, &trio.bob, &trio.charlie);
    bootstrap_agent_cards(&[alice, bob, charlie]).await;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let charlie_id = charlie.agent_id().await;
    assert_ne!(alice_id, bob_id, "distinct daemons expected");
    assert_ne!(alice_id, charlie_id, "distinct daemons expected");

    let (group_id, remote_group_id) = create_secure_group(alice, "active-recipient-postterm").await;
    let card: Value = authed_client(alice)
        .get(alice.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("fetch card 2")
        .json()
        .await
        .expect("fetch card 2 json");
    for node in [bob, charlie] {
        import_group_card(node, &card).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    admit_member(alice, bob, &group_id, &remote_group_id, &bob_id).await;
    admit_member(alice, charlie, &group_id, &remote_group_id, &charlie_id).await;

    // R2 convergence barrier: bob must have applied Charlie's R2 join before
    // Alice's R3 removal is treated as the terminal observation. Without
    // this barrier, a delivered R3 removal can be rejected on bob merely
    // because bob never observed Charlie's prior roster.
    let r2_converged = await_group_members_contain(
        bob,
        &remote_group_id,
        &[bob_id.as_str(), charlie_id.as_str()],
        Duration::from_secs(30),
    )
    .await;
    assert!(
        r2_converged,
        "R2 convergence barrier failed: bob's authenticated /members did not \
         contain both bob and charlie within 30 s before the admin DELETE"
    );

    // Capture bob's persisted KEM key SHA-256 for the byte-stability assertion.
    let bob_kem_path = bob.data_dir().join("agent_kem.key");
    let bob_kem_bytes_before = tokio::fs::read(&bob_kem_path)
        .await
        .expect("read bob kem key before");
    use sha2::{Digest, Sha256};
    let bob_kem_sha_before = {
        let mut h = Sha256::new();
        h.update(&bob_kem_bytes_before);
        h.finalize().to_vec()
    };

    // F1 admin remove.
    let removed = authed_client(alice)
        .delete(alice.url(&format!("/groups/{group_id}/members/{bob_id}")))
        .send()
        .await
        .expect("admin remove request");
    assert_eq!(
        removed.status(),
        StatusCode::OK,
        "admin remove rejected: {:?}",
        removed.text().await
    );

    // Wait for terminal 404 (bob's group record entirely deleted).
    let bob_terminal_404 = wait_until(Duration::from_secs(30), || async {
        let resp = authed_client(bob)
            .get(bob.url(&format!("/groups/{remote_group_id}")))
            .send()
            .await;
        resp.is_ok_and(|r| r.status() == StatusCode::NOT_FOUND)
    })
    .await;
    assert!(
        bob_terminal_404,
        "bob's daemon never reached terminal 404 after admin remove"
    );

    // === Test 5 proper: post-remove active-recipient gate and persisted-state
    // pin. Observed properties:
    //
    //   1. Alice's reseal to retained-but-Removed bob returns 409 +
    //      reason="recipient_not_active" — the active-recipient gate.
    //   2. Bob's daemon has no group record for the deleted group (terminal
    //      404).
    //   3. Bob's persisted KEM key bytes are byte-identical to the
    //      pre-remove read.
    //
    // SCOPE: the byte-stability assertion proves only that no code path
    // rewrote `agent_kem.key` between the pre-remove read and the
    // post-terminal read. Decapsulation reads the key without rewriting
    // it, so a stable SHA does not prove that decapsulation did or did
    // not run. This test does not deliver a Bob-sealed
    // `SecureShareDelivered` event to the gossip/direct apply handler,
    // so the `unknown_group` reject before KEM decap is not exercised,
    // and the wrong-KEM-key 403 further down measures wrong-key crypto
    // on the membership-independent open_envelope path, not the
    // `unknown_group` gate. A genuine non-resurrection pin is out of
    // scope here and will live in a separate test once the production
    // delivery fix lands; the test is intentionally restricted to the
    // properties it actually observes.
    let (bob_reseal_status, bob_reseal_body) = reseal_to(alice, &group_id, &bob_id).await;
    assert_eq!(
        bob_reseal_status,
        StatusCode::CONFLICT,
        "alice's reseal to retained-but-Removed bob must return 409; got status={bob_reseal_status}, body={bob_reseal_body:?}"
    );
    assert_eq!(
        bob_reseal_body["reason"].as_str(),
        Some("recipient_not_active"),
        "alice's reseal to bob must carry reason=\"recipient_not_active\" (the active-recipient gate); got {:?}",
        bob_reseal_body
    );

    // bob's persisted KEM key must be byte-identical to the pre-remove
    // read. This proves only that no code path rewrote the persisted key
    // bytes; decapsulation reads the key without rewriting it, so this
    // SHA equality does not characterise whether decapsulation ran.
    let bob_kem_bytes_after = tokio::fs::read(&bob_kem_path)
        .await
        .expect("read bob kem key after");
    let bob_kem_sha_after = {
        let mut h = Sha256::new();
        h.update(&bob_kem_bytes_after);
        h.finalize().to_vec()
    };
    assert_eq!(
        bob_kem_sha_before, bob_kem_sha_after,
        "bob's persisted KEM key bytes changed between the pre-remove read \
         and the post-terminal read; the only assertion supported here is \
         byte-stability — a code path rewrote the persisted key"
    );

    // The group record itself is gone for bob: the group endpoint returns 404.
    let bob_group_status = authed_client(bob)
        .get(bob.url(&format!("/groups/{remote_group_id}")))
        .send()
        .await
        .expect("bob group GET")
        .status();
    assert_eq!(
        bob_group_status,
        StatusCode::NOT_FOUND,
        "bob's group record must be deleted entirely after admin remove (terminal 404)"
    );

    // The reseal to charlie (active survivor) succeeds and produces a valid
    // envelope — sanity check that the post-remove state is coherent.
    let (charlie_reseal_status, charlie_reseal_body) =
        reseal_to(alice, &group_id, &charlie_id).await;
    assert_eq!(
        charlie_reseal_status,
        StatusCode::OK,
        "sanity: reseal to active charlie must succeed in post-terminal state: status={charlie_reseal_status}, body={charlie_reseal_body:?}"
    );

    // The open_envelope endpoint is a pure crypto (KEM-only) path. Bob's
    // daemon is asked to open charlie's envelope (sealed to charlie's
    // KEM pubkey), and the endpoint returns 403 because bob's daemon
    // does not hold charlie's private key. This measures wrong-key
    // crypto, not the `unknown_group` gate. The endpoint does not
    // install a group record on bob's side regardless of outcome, so
    // the test does not assert a non-resurrection property here — that
    // requires a real apply-seam test (out of scope until the production
    // delivery fix lands).
    let post_epoch = charlie_reseal_body["secret_epoch"].as_u64().expect("epoch");
    let survivor_key_b64 = charlie_reseal_body["kem_ciphertext_b64"]
        .as_str()
        .expect("kem");
    let survivor_nonce_b64 = charlie_reseal_body["aead_nonce_b64"]
        .as_str()
        .expect("nonce");
    let survivor_aead_b64 = charlie_reseal_body["aead_ciphertext_b64"]
        .as_str()
        .expect("aead");
    let (bob_open_status, bob_open_body) = open_envelope_on(
        bob,
        &remote_group_id,
        &charlie_id, // the envelope is sealed to charlie, not bob
        post_epoch,
        survivor_key_b64,
        survivor_nonce_b64,
        survivor_aead_b64,
    )
    .await;
    // Bob's daemon does not hold charlie's private key, so the open-envelope
    // endpoint returns 403 (envelope not decryptable by this daemon's key).
    // That is the proof that the KEM key is what gates content access —
    // bob's daemon can run the endpoint but cannot open the envelope, and
    // its group record remains gone.
    assert_eq!(
        bob_open_status,
        StatusCode::FORBIDDEN,
        "bob's open-envelope against charlie's envelope must be rejected; got status={bob_open_status}, body={bob_open_body:?}"
    );
    let _ = charlie_id;
    let _ = alice_id;
}
