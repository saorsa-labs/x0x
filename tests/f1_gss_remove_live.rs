//! F1 GSS-rotation live gate: the ADMIN REMOVE path must rotate the group
//! shared secret across real daemons.
//!
//! Why this file exists (ADR-0025 observation completeness):
//!
//! The F1 fix (ADR-0010 conformance) landed with unit gates only. The nearest
//! existing live coverage — the `D.2` block in `tests/e2e_named_groups.sh` —
//! exercises the **ban** path (`POST /groups/:id/ban/:agent_id`), which rotated
//! *before* F1. A pre-F1 build passes that block unchanged, so it could never
//! have observed this defect. The defect lived in the **admin remove** path
//! (`DELETE /groups/:id/members/:agent_id`), which removed the member from the
//! roster without rotating the secret, leaving the removed member holding a
//! working key.
//!
//! These assertions were validated against a pre-F1 build (`e301371`, v0.34.3),
//! where R1 and R3 both fail — the removed member decrypts post-removal
//! ciphertext at an unadvanced epoch. That negative run is what gives this gate
//! its power; a gate that passes on the broken build observes nothing.
//!
//! Ignored by default because it spawns real x0xd daemons. Run via
//! `just adr-gates-f1-live`.

use reqwest::StatusCode;
use serde_json::Value;
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
        .json(&serde_json::json!({ "message": "f1 remove-path gate" }))
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

/// Encrypt on the admin daemon, returning (ciphertext_b64, nonce_b64, epoch).
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
    (
        resp["ciphertext_b64"].as_str().unwrap_or_default().into(),
        resp["nonce_b64"].as_str().unwrap_or_default().into(),
        resp["secret_epoch"].as_u64().unwrap_or_default(),
    )
}

/// Attempt a decrypt on `d` and return the full HTTP response (status + body)
/// without collapsing. Used by the phase-aware R3 test to distinguish a
/// pre-terminal 409-with-epoch-mismatch from a terminal 404 (group record
/// deleted) and to fail loudly on any other status the broken pre-F1 build
/// could mask.
async fn try_decrypt_phase(
    d: &AgentInstance,
    group_id: &str,
    ct: &str,
    nonce: &str,
    epoch: u64,
) -> (StatusCode, Value) {
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
    let status = resp.status();
    let body: Value = resp.json().await.expect("decrypt json");
    (status, body)
}

/// Attempt a decrypt on `d`; returns the recovered payload_b64 if the daemon
/// yielded plaintext, `None` for any refusal (409 epoch-mismatch, 403, 424…).
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

/// F1 §2/§2a/§5a — removing a member via the admin-remove endpoint must rotate
/// the GSS secret: the epoch advances, survivors keep reading, and the removed
/// member is locked out of everything published afterwards.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn f1_admin_remove_rotates_gss_secret_live() {
    let trio = trio_with_extra_config("").await;
    let (alice, bob, charlie) = (&trio.alice, &trio.bob, &trio.charlie);
    bootstrap_agent_cards(&[alice, bob, charlie]).await;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let charlie_id = charlie.agent_id().await;
    assert_ne!(alice_id, bob_id, "distinct daemons expected");

    // Admin creates an MlsEncrypted (secure) group.
    let created: Value = authed_client(alice)
        .post(alice.url("/groups"))
        .json(&serde_json::json!({
            "name": "f1-remove-gate",
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
    let card: Value = authed_client(alice)
        .get(alice.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("fetch card")
        .json()
        .await
        .expect("fetch card json");
    let remote_group_id = card["group_id"].as_str().unwrap_or(&group_id).to_string();
    for node in [bob, charlie] {
        let imported: Value = authed_client(node)
            .post(node.url("/groups/cards/import"))
            .json(&card)
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
    tokio::time::sleep(Duration::from_secs(2)).await;

    admit_member(alice, bob, &group_id, &remote_group_id, &bob_id).await;
    admit_member(alice, charlie, &group_id, &remote_group_id, &charlie_id).await;

    // ── Baseline: both members hold the epoch-E secret ───────────────────
    let pre_payload = "ZjEtcHJlLXJlbW92ZQ=="; // "f1-pre-remove"
    let mut pre = (String::new(), String::new(), 0u64);
    for _ in 0..60 {
        pre = encrypt(alice, &group_id, pre_payload).await;
        if !pre.0.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(!pre.0.is_empty(), "admin never produced a group ciphertext");
    let (pre_ct, pre_nonce, pre_epoch) = pre;

    for (node, who) in [(bob, "bob"), (charlie, "charlie")] {
        let got = wait_until(Duration::from_secs(30), || async {
            try_decrypt(node, &remote_group_id, &pre_ct, &pre_nonce, pre_epoch).await
                == Some(pre_payload.to_string())
        })
        .await;
        assert!(
            got,
            "{who} never received the epoch-{pre_epoch} secret; \
             the remove-path assertions below would be vacuous"
        );
    }

    // ── F1: admin removes bob (NOT ban) ──────────────────────────────────
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

    let post_payload = "ZjEtcG9zdC1yZW1vdmU="; // "f1-post-remove"
    let mut post = (String::new(), String::new(), 0u64);
    for _ in 0..60 {
        post = encrypt(alice, &group_id, post_payload).await;
        if !post.0.is_empty() && post.2 != pre_epoch {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (post_ct, post_nonce, post_epoch) = post;

    // R1 — the epoch must advance. This is the assertion a pre-F1 build fails.
    assert!(
        post_epoch > pre_epoch,
        "ADR-0010 violation: secret_epoch did not advance on admin remove \
         (stayed at {pre_epoch}); the removed member's key is still current"
    );

    // R2 — survivors must be re-sealed into the new epoch, not locked out.
    let survivor_reads = wait_until(Duration::from_secs(30), || async {
        try_decrypt(charlie, &remote_group_id, &post_ct, &post_nonce, post_epoch).await
            == Some(post_payload.to_string())
    })
    .await;
    assert!(
        survivor_reads,
        "survivor charlie could not decrypt at epoch {post_epoch}: \
         rotation locked out a retained member"
    );

    // R3 — the removed member must not read anything published after removal.
    let removed_reads = try_decrypt(bob, &remote_group_id, &post_ct, &post_nonce, post_epoch).await;
    assert_ne!(
        removed_reads,
        Some(post_payload.to_string()),
        "confidentiality break: removed member decrypted epoch-{post_epoch} \
         content published after their removal"
    );
    assert!(
        removed_reads.is_none(),
        "removed member's daemon yielded unexpected plaintext: {removed_reads:?}"
    );
}

/// F1 R3 phase-aware rework (ADR-0025 §3 observation completeness).
///
/// The original R3 block in `f1_admin_remove_rotates_gss_secret_live` above
/// collapses every non-200 response into `None`, so 403, 404, 409, 424 and a
/// malformed body all satisfy its `is_none()` assertion. That makes the gate
/// insensitive to the *phase* of the removal: a correctly fast apply that
/// deletes Bob's entire group record produces a 404 from the first request,
/// while a slower apply that leaves the record in place produces a 409
/// (epoch mismatch with `local_epoch < ciphertext_epoch`). Both paths are
/// correct; a 200 is the F1 defect; 403/424/malformed/unmodelled are
/// unmodelled states the gate must not paper over.
///
/// This test re-uses the same fixture as the existing test and asserts the
/// phase transition honestly:
///   - any 200 → red (the F1 defect: Bob decrypts post-removal content);
///   - any 409 with the documented body (parseable JSON, `error ==
///     "epoch mismatch — re-share required"`, `ciphertext_epoch == post_epoch`,
///     `local_epoch < ciphertext_epoch`) → pre-terminal marker, acceptable;
///   - 404 (group not found — Bob's record was deleted by the self-remove
///     apply) → terminal phase marker, acceptable as the first response
///     when the interval is empty and as the transition from 409 otherwise;
///   - 403, 424, malformed, unmodelled → red.
///
/// The bounded window is 30 s — long enough for a deliberate 409 → 404
/// transition, short enough that a stuck `old_epoch` state surfaces as a
/// panic with the offending body rather than a silent hang.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns real x0xd daemons"]
async fn f1_admin_remove_r3_phase_aware_terminal_marker() {
    let trio = trio_with_extra_config("").await;
    let (alice, bob, charlie) = (&trio.alice, &trio.bob, &trio.charlie);
    bootstrap_agent_cards(&[alice, bob, charlie]).await;

    let alice_id = alice.agent_id().await;
    let bob_id = bob.agent_id().await;
    let charlie_id = charlie.agent_id().await;
    assert_ne!(alice_id, bob_id, "distinct daemons expected");

    let created: Value = authed_client(alice)
        .post(alice.url("/groups"))
        .json(&serde_json::json!({
            "name": "f1-r3-phase-aware",
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
    let card: Value = authed_client(alice)
        .get(alice.url(&format!("/groups/cards/{group_id}")))
        .send()
        .await
        .expect("fetch card")
        .json()
        .await
        .expect("fetch card json");
    let remote_group_id = card["group_id"].as_str().unwrap_or(&group_id).to_string();
    for node in [bob, charlie] {
        let imported: Value = authed_client(node)
            .post(node.url("/groups/cards/import"))
            .json(&card)
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
    tokio::time::sleep(Duration::from_secs(2)).await;

    admit_member(alice, bob, &group_id, &remote_group_id, &bob_id).await;
    admit_member(alice, charlie, &group_id, &remote_group_id, &charlie_id).await;

    // Baseline: both members hold the epoch-E secret.
    let pre_payload = "ZjEtcGhhc2UtcHJl"; // "f1-phase-pre"
    let mut pre = (String::new(), String::new(), 0u64);
    for _ in 0..60 {
        pre = encrypt(alice, &group_id, pre_payload).await;
        if !pre.0.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(!pre.0.is_empty(), "admin never produced a group ciphertext");
    let (pre_ct, pre_nonce, pre_epoch) = pre;

    for (node, who) in [(bob, "bob"), (charlie, "charlie")] {
        let got = wait_until(Duration::from_secs(30), || async {
            try_decrypt(node, &remote_group_id, &pre_ct, &pre_nonce, pre_epoch).await
                == Some(pre_payload.to_string())
        })
        .await;
        assert!(
            got,
            "{who} never received the epoch-{pre_epoch} secret; \
             the remove-path assertions below would be vacuous"
        );
    }

    // F1: admin removes bob (NOT ban).
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

    let post_payload = "ZjEtcGhhc2UtcG9zdA=="; // "f1-phase-post"
    let mut post = (String::new(), String::new(), 0u64);
    for _ in 0..60 {
        post = encrypt(alice, &group_id, post_payload).await;
        if !post.0.is_empty() && post.2 != pre_epoch {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (post_ct, post_nonce, post_epoch) = post;

    assert!(
        post_epoch > pre_epoch,
        "ADR-0010 violation: secret_epoch did not advance on admin remove \
         (stayed at {pre_epoch})"
    );

    let survivor_reads = wait_until(Duration::from_secs(30), || async {
        try_decrypt(charlie, &remote_group_id, &post_ct, &post_nonce, post_epoch).await
            == Some(post_payload.to_string())
    })
    .await;
    assert!(
        survivor_reads,
        "survivor charlie could not decrypt at epoch {post_epoch}: \
         rotation locked out a retained member"
    );

    // R3 — phase-aware. Bounded window; expect either a direct 404 (terminal
    // marker; the interval was empty) or a 409 → 404 transition. Anything
    // else is a red that names the offending status and body.
    let phase_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut saw_pre_terminal_409 = false;
    // `terminal_404_seen` is true iff the loop exits via the 404 arm.
    // A panic on deadline or unmodelled status short-circuits, so the only
    // post-loop path is break-from-404. The value is read after the loop as
    // a static sanity check; the initial `false` is reassigned before any
    // read, hence `#[allow(unused_assignments)]`.
    #[allow(unused_assignments)]
    let mut terminal_404_seen = false;
    loop {
        let (status, body) =
            try_decrypt_phase(bob, &remote_group_id, &post_ct, &post_nonce, post_epoch).await;
        match status {
            StatusCode::OK => {
                panic!(
                    "R3 RED: removed member decrypted post-removal content at \
                     epoch {post_epoch}; body={body}"
                );
            }
            StatusCode::CONFLICT => {
                // Pre-terminal marker. Body must be parseable and carry the
                // exact epoch-mismatch shape — any other prose means the
                // predicate slipped.
                let obj = body
                    .as_object()
                    .unwrap_or_else(|| panic!("R3 RED: 409 body is not a JSON object: {body}"));
                assert_eq!(
                    obj.get("error").and_then(Value::as_str),
                    Some("epoch mismatch — re-share required"),
                    "R3 RED: 409 body must carry the epoch-mismatch error, got {body}"
                );
                let local_epoch = obj
                    .get("local_epoch")
                    .and_then(Value::as_u64)
                    .unwrap_or_else(|| panic!("R3 RED: 409 body missing local_epoch, got {body}"));
                let ciphertext_epoch = obj
                    .get("ciphertext_epoch")
                    .and_then(Value::as_u64)
                    .unwrap_or_else(|| {
                        panic!("R3 RED: 409 body missing ciphertext_epoch, got {body}")
                    });
                assert_eq!(
                    ciphertext_epoch, post_epoch,
                    "R3 RED: 409 ciphertext_epoch {ciphertext_epoch} != \
                     requested {post_epoch}; body={body}"
                );
                assert!(
                    local_epoch < post_epoch,
                    "R3 RED: 409 local_epoch {local_epoch} is not < \
                     ciphertext_epoch {post_epoch}; body={body}"
                );
                saw_pre_terminal_409 = true;
            }
            StatusCode::NOT_FOUND => {
                // Terminal phase marker. May be the first response (empty
                // interval) or follow a 409.
                terminal_404_seen = true;
                break;
            }
            other => {
                panic!(
                    "R3 RED: removed member's daemon returned unmodelled \
                     status {other}; body={body}"
                );
            }
        }
        if tokio::time::Instant::now() >= phase_deadline {
            panic!(
                "R3 RED: removed member's daemon never reached terminal 404 \
                 within 30 s; saw_pre_terminal_409={saw_pre_terminal_409}"
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        terminal_404_seen,
        "R3 RED: 404 terminal marker not observed (control flow bug)"
    );
    // saw_pre_terminal_409 is informational only — a prompt correct apply
    // may make the interval empty, so we do not require it to be true. The
    // bounded window + 404 terminal marker are the load-bearing guarantees.
    let _ = saw_pre_terminal_409;
}
