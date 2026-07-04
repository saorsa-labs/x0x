//! Integration tests for key-lifecycle enforcement — issue #130 Step 8.
//!
//! Verifies that:
//!   1. `POST /identity/revoke` accepts a self-revocation of the local agent-id
//!      and returns the signed record.
//!   2. `GET /identity/revocations` returns the record in its list.
//!   3. `POST /identity/revoke` returns 400 when both / neither subject fields
//!      are supplied, or the id hex is malformed.
//!   4. A revocation genuinely DENIES a previously-verified (agent, machine)
//!      binding end-to-end: `GET /agents/:id/machine` goes 200 → 404 after a
//!      self-revocation is applied (`revocation_denies_verified_binding_end_to_end`).
//!
//! All tests are `#[ignore]` — they require `x0xd` to be compiled.
//! Run with: `cargo nextest run -E 'test(revocation)' --all-features -- --ignored`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use std::time::Duration;

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

async fn daemon(prefix: &str) -> DaemonFixture {
    DaemonFixture::start(prefix).await
}

fn ca(d: &DaemonFixture) -> reqwest::Client {
    d.authed_client(Duration::from_secs(10))
}

// ---------------------------------------------------------------------------
// Revocation self-issue + list
// ---------------------------------------------------------------------------

/// POST /identity/revoke — self-revocation of own agent-id succeeds.
#[tokio::test]
#[ignore]
async fn revocation_self_issue_own_agent_id() {
    let d = daemon("revoke-self").await;
    let c = ca(&d);

    // Fetch own agent-id.
    let agent: Value = c
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["agent_id"].as_str().unwrap().to_owned();

    // Issue self-revocation.
    let resp: Value = c
        .post(d.url("/identity/revoke"))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "reason": "test: self-revocation"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["ok"], true, "expected ok: true, got {resp}");
    assert_eq!(resp["subject_kind"], "agent");
    assert_eq!(resp["subject"], agent_id);
    assert!(
        resp["revoked_at"].is_u64(),
        "revoked_at must be a unix timestamp"
    );
    assert_eq!(resp["reason"], "test: self-revocation");
}

/// GET /identity/revocations — issued record appears in the list.
#[tokio::test]
#[ignore]
async fn revocation_list_contains_issued_record() {
    let d = daemon("revoke-list").await;
    let c = ca(&d);

    let agent: Value = c
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["agent_id"].as_str().unwrap().to_owned();

    // Issue a self-revocation of the daemon's own agent-id (valid authority:
    // the /identity/revoke handler signs with the agent keypair, so only the
    // agent-id is self-revocable via the API).
    let revoke = c
        .post(d.url("/identity/revoke"))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "reason": "list test"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), 200, "self-revocation must succeed");

    let list: Value = c
        .get(d.url("/identity/revocations"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let revocations = list["revocations"].as_array().expect("revocations array");
    assert!(
        !revocations.is_empty(),
        "revocations list must be non-empty after issuing a record"
    );
    let found = revocations
        .iter()
        .any(|r| r["subject"] == agent_id && r["subject_kind"] == "agent");
    assert!(
        found,
        "expected agent-id {agent_id} in revocations list; got: {list}"
    );
}

/// POST /identity/revoke — 400 when both fields are set.
#[tokio::test]
#[ignore]
async fn revocation_rejects_both_fields() {
    let d = daemon("revoke-both").await;
    let c = ca(&d);

    let status = c
        .post(d.url("/identity/revoke"))
        .json(&serde_json::json!({
            "agent_id": hex::encode([0u8; 32]),
            "machine_id": hex::encode([1u8; 32]),
        }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 400, "supplying both fields must return 400");
}

/// POST /identity/revoke — 400 when neither field is set.
#[tokio::test]
#[ignore]
async fn revocation_rejects_neither_field() {
    let d = daemon("revoke-none").await;
    let c = ca(&d);

    let status = c
        .post(d.url("/identity/revoke"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 400, "supplying no fields must return 400");
}

/// POST /identity/revoke — 400 when agent_id hex is malformed.
#[tokio::test]
#[ignore]
async fn revocation_rejects_malformed_hex() {
    let d = daemon("revoke-hex").await;
    let c = ca(&d);

    let status = c
        .post(d.url("/identity/revoke"))
        .json(&serde_json::json!({ "agent_id": "not-valid-hex" }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 400, "malformed hex must return 400");
}

// ---------------------------------------------------------------------------
// End-to-end denial through a real daemon (issue #130 acceptance criterion)
// ---------------------------------------------------------------------------

/// A revocation genuinely DENIES a previously-verified (agent, machine)
/// binding, end-to-end through the real daemon HTTP surface.
///
/// This is the #130 acceptance proof: it does not merely assert an API
/// contract, it drives the daemon from "this binding is verified and
/// resolvable" to "this binding is refused" purely by applying a valid
/// revocation.
///
/// Flow (single daemon, self-revocation = valid authority):
///  1. The daemon self-announces, seeding its own signed (agent, machine)
///     binding into the discovery caches.
///  2. `GET /agents/:id/machine` resolves the machine — the binding is live.
///  3. `POST /identity/revoke {agent_id}` self-revokes (authority holds).
///  4. `GET /agents/:id/machine` now returns 404 — the revocation evicted the
///     binding and the verified gate refuses it. Denial is observable.
///
/// Cross-daemon gossip propagation of the same record is exercised by the e2e
/// scripts; the in-daemon enforcement (EP2 verified gate, EP3 DM drop, EP4
/// group gate) is proven by the unit tests in `src/lib.rs`, `src/dm_inbox.rs`,
/// and `src/server/mod.rs`.
#[tokio::test]
#[ignore]
async fn revocation_denies_verified_binding_end_to_end() {
    let d = daemon("revoke-denial").await;
    let c = ca(&d);

    // Own identity.
    let agent: Value = c
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["agent_id"].as_str().unwrap().to_owned();

    // 1. Self-announce so the daemon holds its own verified binding.
    c.post(d.url("/announce"))
        .json(&serde_json::json!({
            "include_user_identity": false,
            "human_consent": false
        }))
        .send()
        .await
        .unwrap();

    // 2. The binding resolves — proof it is verified/live BEFORE revocation.
    let before = c
        .get(d.url(&format!("/agents/{agent_id}/machine")))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(
        before, 200,
        "the self-announced (agent, machine) binding must resolve before revocation"
    );

    // 3. Self-revoke — valid authority (issuer key == subject agent-id).
    let revoke: Value = c
        .post(d.url("/identity/revoke"))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "reason": "e2e denial proof"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(revoke["ok"], true, "self-revocation must succeed: {revoke}");

    // 4. The binding is now DENIED — the revocation evicted it and the gate
    //    refuses it. This is the genuine denial, not an API-contract check.
    let after = c
        .get(d.url(&format!("/agents/{agent_id}/machine")))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(
        after, 404,
        "after revocation the binding must be denied (evicted + gate-closed); got {after}"
    );

    // And the record is durably listed.
    let list: Value = c
        .get(d.url("/identity/revocations"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let found = list["revocations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["subject"] == agent_id && r["subject_kind"] == "agent");
    assert!(
        found,
        "the applied revocation must appear in the list: {list}"
    );
}
