//! Integration tests for x0xd REST + WebSocket API.
//!
//! All tests are `#[ignore]` — they require a running x0xd daemon.
//! Run with: cargo nextest run -E 'test(daemon_api)' -- --ignored
//!
//! Before running: cargo build --release --bin x0xd

use anyhow::{ensure, Context, Result};
use base64::Engine;
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Duration;

#[path = "harness/src/daemon.rs"]
mod daemon;

use daemon::DaemonFixture;

// Re-exports for WebSocket tests
use futures::{SinkExt, StreamExt};

async fn daemon() -> DaemonFixture {
    DaemonFixture::start("api-test").await
}

fn c() -> reqwest::Client {
    DaemonFixture::client(Duration::from_secs(10))
}

/// Authenticated client with Bearer token in default headers.
fn ca(d: &DaemonFixture) -> reqwest::Client {
    d.authed_client(Duration::from_secs(10))
}
fn fake_id() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}
fn b64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

// ===========================================================================
// System (6)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_health() {
    let d = daemon().await;
    // /health is exempt from auth — deliberately use unauthenticated client
    let r: Value = c()
        .get(d.url("/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["status"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_status() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["agent_id"].as_str().unwrap().len() == 64);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["agent_id"].is_string());
    assert!(r["machine_id"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_sign_roundtrip() {
    let d = daemon().await;

    // Sign an arbitrary payload under a mandatory external context.
    let payload = b"the bytes a downstream app would put into an audit record";
    let context = "audit.record.v1";
    let body = serde_json::json!({ "context": context, "payload_b64": b64(payload) });

    let r: Value = ca(&d)
        .post(d.url("/agent/sign"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true);
    assert_eq!(r["algorithm"], "x0x.agent-sign.v2.ml-dsa-65");
    assert_eq!(r["context"], context, "response must echo the context");
    let agent_id_hex = r["agent_id"].as_str().expect("agent_id is a hex string");
    let public_key_b64 = r["public_key_b64"]
        .as_str()
        .expect("public_key_b64 is a base64 string");
    let signature_b64 = r["signature_b64"]
        .as_str()
        .expect("signature_b64 is a base64 string");

    // agent_id matches the agent's hex id.
    let agent_resp: Value = ca(&d)
        .get(d.url("/agent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agent_resp["agent_id"].as_str().unwrap(), agent_id_hex);

    // Signature verifies under the returned public key.
    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .expect("public key decodes from base64");
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .expect("signature decodes from base64");

    let public_key = ant_quic::MlDsaPublicKey::from_bytes(&pk_bytes)
        .expect("public_key_b64 parses as an ML-DSA-65 public key");
    let signature = ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&sig_bytes)
        .expect("signature_b64 parses as an ML-DSA-65 signature");

    // The signature is over the external DST, NOT the raw payload.
    let canonical = x0x::api::agent_signing::assemble_buffer(context, payload);
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&public_key, &canonical, &signature)
        .expect("signature verifies over the domain-separated buffer");
    assert!(
        ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
            &public_key,
            payload,
            &signature
        )
        .is_err(),
        "signature must NOT verify over the raw payload"
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_sign_context_roundtrip_and_mismatch_rejected() {
    let d = daemon().await;

    // Domain-separated signing (issue #133): the signature is over the
    // external DST assembled from `context`, so it verifies only when the
    // verifier supplies the SAME context — a signature issued for one
    // protocol context cannot be replayed as another.
    let payload = b"register envelope bytes";
    let context = "community.jams.pair.v1.register-pop";
    let r: Value = ca(&d)
        .post(d.url("/agent/sign"))
        .json(&serde_json::json!({ "context": context, "payload_b64": b64(payload) }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(r["ok"], true);
    assert_eq!(r["context"], context, "response must echo the context");

    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(r["public_key_b64"].as_str().unwrap())
        .unwrap();
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(r["signature_b64"].as_str().unwrap())
        .unwrap();
    let public_key = ant_quic::MlDsaPublicKey::from_bytes(&pk_bytes).unwrap();
    let signature =
        ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&sig_bytes).unwrap();

    // Verifies over the DST built from the matching context.
    let canonical = x0x::api::agent_signing::assemble_buffer(context, payload);
    ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&public_key, &canonical, &signature)
        .expect("signature verifies over the context's DST");

    // Must NOT verify over the raw payload, nor over a DIFFERENT context's DST.
    assert!(ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
        &public_key,
        payload,
        &signature
    )
    .is_err());
    let other = x0x::api::agent_signing::assemble_buffer("a.different.context.v2", payload);
    assert!(ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(
        &public_key,
        &other,
        &signature
    )
    .is_err());
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_sign_rejects_missing_context() {
    // `context` is required (issue #133): omitting it must never fall back to
    // raw-payload signing — it is rejected with a client error.
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/agent/sign"))
        .json(&serde_json::json!({ "payload_b64": b64(b"x") }))
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_client_error(),
        "missing context must be rejected: {}",
        r.status()
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_sign_rejects_invalid_context() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/agent/sign"))
        .json(&serde_json::json!({ "context": "Has Space!", "payload_b64": b64(b"x") }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "context not matching [a-z0-9._-] must be 400"
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_sign_rejects_internal_context_denylist() {
    // Defense in depth: even though the namespace tag guarantees
    // disjointness, a context naming an internal signing domain is denied.
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/agent/sign"))
        .json(&serde_json::json!({ "context": "announcement", "payload_b64": b64(b"x") }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "internal context must be denied"
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_sign_requires_authentication() {
    // Loopback + bearer-token only (issue #133): an unauthenticated request
    // never produces a signature.
    let d = daemon().await;
    let r = c()
        .post(d.url("/agent/sign"))
        .json(&serde_json::json!({ "context": "test.auth.v1", "payload_b64": b64(b"x") }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_sign_rejects_empty_payload() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/agent/sign"))
        .json(&serde_json::json!({ "context": "test.empty.v1", "payload_b64": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_sign_rejects_invalid_base64() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/agent/sign"))
        .json(
            &serde_json::json!({ "context": "test.badb64.v1", "payload_b64": "@@@not-base64@@@" }),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_sign_rejects_oversize_payload() {
    let d = daemon().await;
    // Just over the 64 KiB cap (issue #133 lowered it from 256 KiB).
    let oversize = vec![0u8; 64 * 1024 + 1];
    let r = ca(&d)
        .post(d.url("/agent/sign"))
        .json(&serde_json::json!({ "context": "test.oversize.v1", "payload_b64": b64(&oversize) }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// ── POST /agent/verify (issue #106) ─────────────────────────────────────

/// Sign `payload` via POST /agent/sign and return (signature_b64, public_key_b64).
async fn sign_via_daemon(d: &DaemonFixture, payload: &[u8], context: &str) -> (String, String) {
    let body = serde_json::json!({ "context": context, "payload_b64": b64(payload) });
    let r: Value = ca(d)
        .post(d.url("/agent/sign"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true, "sign must succeed before verify: {r}");
    (
        r["signature_b64"].as_str().unwrap().to_string(),
        r["public_key_b64"].as_str().unwrap().to_string(),
    )
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_roundtrip() {
    let d = daemon().await;
    let payload = b"audit record bytes read back from storage";
    let (sig, pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;

    let resp = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: Value = resp.json().await.unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["valid"], true);
    assert_eq!(r["algorithm"], "x0x.agent-sign.v2.ml-dsa-65");
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_independent_keypair() {
    // The primary third-party use case: the verifying daemon never authored
    // the signature and holds none of the key material — a record signed by
    // an arbitrary ML-DSA-65 keypair must verify from the supplied bytes alone.
    let d = daemon().await;
    let (public_key, secret_key) =
        ant_quic::crypto::raw_public_keys::pqc::generate_ml_dsa_keypair()
            .expect("keypair generation");
    let payload = b"record authored on a machine this daemon has never seen";
    let context = "third.party.record.v1";
    // Sign the EXTERNAL DST locally (the daemon would assemble the same
    // bytes for this context + payload), then verify via the endpoint.
    let canonical = x0x::api::agent_signing::assemble_buffer(context, payload);
    let signature =
        ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(&secret_key, &canonical)
            .expect("local signing over the DST");

    let r: Value = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": context,
            "payload_b64": b64(payload),
            "signature_b64": b64(signature.as_bytes()),
            "public_key_b64": b64(public_key.as_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(
        r["valid"], true,
        "a signature from a caller-supplied keypair must verify"
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_tampered_payload_is_result_not_error() {
    let d = daemon().await;
    let (sig, pk) = sign_via_daemon(&d, b"the original payload", "test.ctx.v1").await;

    let resp = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(b"the tampered payload"),
            "signature_b64": sig,
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a failed signature check is a result, not an error"
    );
    let r: Value = resp.json().await.unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["valid"], false);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_tampered_signature_is_result_not_error() {
    let d = daemon().await;
    let payload = b"payload whose signature gets corrupted in storage";
    let (sig, pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;

    // Flip one bit mid-signature: still 3309 bytes, so it passes the
    // malformed-input checks and must fail as `valid: false`, not 400.
    let mut sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&sig)
        .unwrap();
    sig_bytes[100] ^= 0x01;

    let resp = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": b64(&sig_bytes),
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: Value = resp.json().await.unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["valid"], false);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_context_mismatch_is_result_not_error() {
    let d = daemon().await;
    let payload = b"register envelope bytes";
    let context = "x0x.test.v1.verify";
    let (sig, pk) = sign_via_daemon(&d, payload, context).await;

    // With the matching context the signature verifies.
    let r: Value = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": context,
            "payload_b64": b64(payload),
            "signature_b64": sig.clone(),
            "public_key_b64": pk.clone(),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["valid"], true);

    // The same signature under a DIFFERENT context must not verify — the DST
    // binds the signature to its context, so a signature for one protocol
    // cannot be replayed as another.
    let r: Value = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "a.different.context.v2",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(
        r["valid"], false,
        "a signature must NOT verify under a mismatched context"
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_accepts_explicit_algorithm() {
    let d = daemon().await;
    let payload = b"payload";
    let (sig, pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;

    let r: Value = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": pk,
            "algorithm": "x0x.agent-sign.v2.ml-dsa-65",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["valid"], true);
}

/// Assert a rejection response: expected status, `ok: false`, and an error
/// string naming the gate that fired.
///
/// The substring assertion is load-bearing: every rejection test sends a
/// request that is fully valid except for the one field under test, so
/// without it a deleted guard could go unnoticed when a *different* check
/// downstream happens to return the same status.
async fn assert_rejection(resp: reqwest::Response, status: StatusCode, needle: &str) {
    assert_eq!(resp.status(), status);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains(needle),
        "error must identify the failing gate: expected substring {needle:?}, got {err:?}"
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_unknown_algorithm() {
    let d = daemon().await;
    // Real signature and key: with the algorithm gate removed this request
    // would verify as 200 valid:true — the silent scheme migration the
    // explicit 400 exists to prevent.
    let payload = b"x";
    let (sig, pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": pk,
            "algorithm": "x0x.agent-sign.v2.something-else",
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "unsupported algorithm").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_null_algorithm() {
    let d = daemon().await;
    // JSON null is a *present* algorithm field, not an omitted one: an
    // `Option<String>` request field would fold it to None and silently
    // accept — this pins the explicit 400 instead.
    let payload = b"x";
    let (sig, pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": pk,
            "algorithm": null,
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "unsupported algorithm").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_requires_auth() {
    let d = daemon().await;
    // Bearer-token like every other endpoint — stateless or not, an
    // unauthenticated carve-out isn't worth the inconsistency (issue #106,
    // maintainer refinement 6).
    let r = c()
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(b"x"),
            "signature_b64": b64(b"sig"),
            "public_key_b64": b64(b"pk"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_accepts_exact_boundary_sizes() {
    let d = daemon().await;
    // Exactly AT the caps must round-trip: the limits reject payloads *over*
    // 64 KiB and contexts *over* 64 chars, not at them.
    let payload = vec![0xA5u8; 64 * 1024];
    let context = "c".repeat(64);
    let (sig, pk) = sign_via_daemon(&d, &payload, &context).await;
    let r: Value = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": context,
            "payload_b64": b64(&payload),
            "signature_b64": sig,
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["valid"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_wrong_key_is_result_not_error() {
    let d = daemon().await;
    // A well-formed 1952-byte key that simply isn't the signer's: that is
    // a verification *result* (valid:false), never malformed input.
    let payload = b"signed by the daemon, checked against a stranger's key";
    let (sig, _pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;
    let (other_pk, _sk) = ant_quic::crypto::raw_public_keys::pqc::generate_ml_dsa_keypair()
        .expect("keypair generation");
    let resp = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": b64(other_pk.as_bytes()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r: Value = resp.json().await.unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["valid"], false);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_invalid_base64_payload() {
    let d = daemon().await;
    let (sig, pk) = sign_via_daemon(&d, b"x", "test.ctx.v1").await;
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": "@@@not-base64@@@",
            "signature_b64": sig,
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "invalid base64 payload").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_invalid_base64_signature() {
    let d = daemon().await;
    let payload = b"x";
    let (_sig, pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": "@@@not-base64@@@",
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "invalid base64 signature").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_invalid_base64_public_key() {
    let d = daemon().await;
    let payload = b"x";
    let (sig, _pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": "@@@not-base64@@@",
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "invalid base64 public key").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_empty_payload() {
    let d = daemon().await;
    let (sig, pk) = sign_via_daemon(&d, b"x", "test.ctx.v1").await;
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": "",
            "signature_b64": sig,
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "payload must be non-empty").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_oversize_payload() {
    let d = daemon().await;
    let (sig, pk) = sign_via_daemon(&d, b"x", "test.ctx.v1").await;
    // Just over the 64 KiB cap — same limit as /agent/sign.
    let oversize = vec![0u8; 64 * 1024 + 1];
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(&oversize),
            "signature_b64": sig,
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(
        r,
        StatusCode::PAYLOAD_TOO_LARGE,
        "exceeds maximum verifiable size",
    )
    .await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_wrong_public_key_length() {
    let d = daemon().await;
    let payload = b"x";
    let (sig, _pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;
    // A 32-byte value is a plausible wrong-key-type paste (e.g. an agent id
    // or an Ed25519 key) — it must be 400, never a confusing valid:false.
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": b64(&[0u8; 32]),
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "public key must be exactly").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_wrong_signature_length() {
    let d = daemon().await;
    let payload = b"x";
    let (_sig, pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;
    // A truncated signature is malformed input, not a failed check.
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "test.ctx.v1",
            "payload_b64": b64(payload),
            "signature_b64": b64(&[0u8; 100]),
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "signature must be exactly").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_invalid_context() {
    // The same context validation as /agent/sign applies to verify: an
    // invalid context is 400, never a `valid: false`.
    let d = daemon().await;
    let payload = b"x";
    let (sig, pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "Has Space!",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "context must match").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_agent_verify_rejects_internal_context() {
    // A denylisted (internal) context is rejected on verify too.
    let d = daemon().await;
    let payload = b"x";
    let (sig, pk) = sign_via_daemon(&d, payload, "test.ctx.v1").await;
    let r = ca(&d)
        .post(d.url("/agent/verify"))
        .json(&serde_json::json!({
            "context": "announcement",
            "payload_b64": b64(payload),
            "signature_b64": sig,
            "public_key_b64": pk,
        }))
        .send()
        .await
        .unwrap();
    assert_rejection(r, StatusCode::BAD_REQUEST, "internal x0x signing domain").await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_peers() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/peers")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_network_status() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/network/status")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_announce() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/announce"))
        .json(&serde_json::json!({"include_user_identity": false, "human_consent": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_shutdown_with_sse_client() {
    let mut d = DaemonFixture::start("shutdown-test").await;

    let sse_client = reqwest::Client::new();
    let session = d.session_token().await;
    let sse_response = sse_client
        .get(format!("{}?token={session}", d.url("/events")))
        .send()
        .await
        .unwrap();
    assert_eq!(sse_response.status(), StatusCode::OK);

    let shutdown_response = reqwest::Client::new()
        .post(d.url("/shutdown"))
        .header("Authorization", d.auth_header())
        .send()
        .await
        .unwrap();
    assert_eq!(shutdown_response.status(), StatusCode::OK);

    // GHA runners are noticeably slower than local — a 5 s deadline flaked
    // intermittently. Bumped to 30 s; observed local shutdown is <1 s.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = d.try_wait().unwrap() {
            assert!(status.success(), "daemon exited with {status}");
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("daemon did not exit with an active SSE client");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    drop(sse_response);
    let port_file = d.port_file();
    assert!(
        !port_file.exists(),
        "port file should be removed on shutdown"
    );
}

// ===========================================================================
// Gossip (4)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_subscribe_publish() {
    let d = daemon().await;
    let topic = format!("test-{}", rand::random::<u32>());
    let r: Value = ca(&d)
        .post(d.url("/subscribe"))
        .json(&serde_json::json!({"topic": topic}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["subscription_id"].is_string());

    let r: Value = ca(&d)
        .post(d.url("/publish"))
        .json(&serde_json::json!({"topic": topic, "payload": b64(b"hello")}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_unsubscribe() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/subscribe"))
        .json(&serde_json::json!({"topic": "unsub-test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sid = r["subscription_id"].as_str().unwrap();
    let r = ca(&d)
        .delete(d.url(&format!("/subscribe/{sid}")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_events_sse() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/events")).send().await.unwrap();
    assert!(r
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("text/event-stream"));
}

#[tokio::test]
#[ignore]
async fn daemon_api_publish_bad_base64() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/publish"))
        .json(&serde_json::json!({"topic": "t", "payload": "!!!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

// ===========================================================================
// Direct Messaging (4)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_direct_send_not_found() -> Result<()> {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/direct/send"))
        .json(&serde_json::json!({"agent_id": fake_id(), "payload": b64(b"hi")}))
        .send()
        .await?;
    let status = r.status();
    let body: Value = r.json().await?;
    ensure!(
        status == StatusCode::NOT_FOUND,
        "unknown direct-send recipient returned {status}: {body:?}"
    );
    ensure!(
        body["ok"].as_bool() == Some(false),
        "unexpected direct-send error body: {body:?}"
    );
    ensure!(
        body["error"].as_str() == Some("recipient_key_unavailable"),
        "unexpected direct-send error body: {body:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn daemon_api_direct_connections() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/direct/connections"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["connections"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_direct_events_sse() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/direct/events")).send().await.unwrap();
    assert!(r
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("text/event-stream"));
}

#[tokio::test]
#[ignore]
async fn daemon_api_direct_send_blocked() {
    let d = daemon().await;
    let agent = fake_id();
    // Add as blocked
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "blocked"}))
        .send()
        .await
        .unwrap();
    let r = ca(&d)
        .post(d.url("/direct/send"))
        .json(&serde_json::json!({"agent_id": agent, "payload": b64(b"hi")}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // Cleanup
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

// ===========================================================================
// Discovery (5)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_discovered_agents() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/agents/discovered"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["agents"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_discovered_unfiltered() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/agents/discovered?unfiltered=true"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_find_agent_unknown() {
    let d = daemon().await;
    // find_agent does 3-stage search (cache→shard→rendezvous) — needs longer timeout
    let long_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&d.auth_header()).unwrap(),
            );
            headers
        })
        .build()
        .unwrap();
    let r: Value = long_client
        .post(d.url(&format!("/agents/find/{}", fake_id())))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert_eq!(r["found"], false);
}

#[tokio::test]
#[ignore]
async fn daemon_api_reachability_unknown() {
    let d = daemon().await;
    let r = ca(&d)
        .get(d.url(&format!("/agents/reachability/{}", fake_id())))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore]
async fn daemon_api_agents_by_user() {
    let d = daemon().await;
    let r = ca(&d)
        .get(d.url(&format!("/users/{}/agents", fake_id())))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

// ===========================================================================
// Contacts & Trust (10)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_add_contact() {
    let d = daemon().await;
    let agent = fake_id();
    let r: Value = ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known", "label": "test"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

/// Regression test for issue #19: POST /contacts with `alias` (the field
/// name a beta tester guessed) is rejected with a 400 instead of silently
/// dropping the unknown key. `deny_unknown_fields` on `AddContactRequest`
/// makes serde surface the right field name in its error.
#[tokio::test]
#[ignore]
async fn daemon_api_add_contact_rejects_unknown_field_alias() {
    let d = daemon().await;
    let agent = fake_id();
    let r = ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({
            "agent_id": agent,
            "alias": "should-be-label",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// Regression test for issue #19: POST /agent/card/import with an unknown
/// trust_level no longer silently coerces to "known". The daemon now
/// returns the same FromStr error as POST /contacts.
#[tokio::test]
#[ignore]
async fn daemon_api_import_card_invalid_trust_level_rejected() -> Result<()> {
    let d = daemon().await;
    let client = ca(&d);
    let card: Value = client
        .get(d.url("/agent/card"))
        .send()
        .await?
        .json()
        .await?;
    let card_link = card["link"]
        .as_str()
        .context("agent card response missing link")?;
    let card_agent_id = card["card"]["agent_id"]
        .as_str()
        .context("agent card response missing card.agent_id")?;

    let r = client
        .post(d.url("/agent/card/import"))
        .json(&serde_json::json!({
            "card": card_link,
            "trust_level": "completely-bogus",
        }))
        .send()
        .await?;
    ensure!(
        r.status() == StatusCode::BAD_REQUEST,
        "expected BAD_REQUEST, got {}",
        r.status()
    );
    let body: Value = r.json().await?;
    ensure!(
        body["ok"].as_bool() == Some(false),
        "unexpected import response: {body:?}"
    );
    let error = body["error"]
        .as_str()
        .context("import response missing error")?;
    ensure!(
        error.contains("invalid trust level: completely-bogus"),
        "unexpected error: {error}"
    );

    // The rejected import must leave the trust surface UNTOUCHED — the card's
    // agent must be ABSENT from `/contacts`. This is the strong invariant
    // issue #142 originally wanted; it was temporarily relaxed to a
    // provenance-based check in #143 because the daemon's background
    // announcement-processing loop registered any OBSERVED agent — including
    // itself on rebroadcast — at `TrustLevel::Unknown`, which raced this
    // assertion. #145 closed that root cause: the announce loop now
    // self-skips (see `register_announced_machine` in lib.rs), so the
    // daemon's own agent (`card_agent_id`, served from `/agent/card`) is
    // never registered as a contact. The strong absence assertion is
    // therefore valid again and is the correct invariant to pin.
    let contacts: Value = client.get(d.url("/contacts")).send().await?.json().await?;
    let contact_entries = contacts["contacts"]
        .as_array()
        .context("contacts response missing contacts array")?;
    let matching: Vec<&Value> = contact_entries
        .iter()
        .filter(|contact| contact["agent_id"].as_str() == Some(card_agent_id))
        .collect();
    ensure!(
        matching.is_empty(),
        "rejected import must leave no contact side-effect for the card agent \
         (announce-loop self-skip via #145 should prevent the daemon's own agent \
         from being registered): {contacts:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn daemon_api_list_contacts() {
    let d = daemon().await;
    let r = ca(&d).get(d.url("/contacts")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_quick_trust() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "unknown"}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .post(d.url("/contacts/trust"))
        .json(&serde_json::json!({"agent_id": agent, "level": "trusted"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn daemon_api_update_contact() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "unknown"}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .patch(d.url(&format!("/contacts/{agent}")))
        .json(&serde_json::json!({"trust_level": "trusted", "identity_type": "pinned"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn daemon_api_delete_contact() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known"}))
        .send()
        .await
        .unwrap();
    let r = ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore]
async fn daemon_api_revoke_contact() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known"}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .post(d.url(&format!("/contacts/{agent}/revoke")))
        .json(&serde_json::json!({"reason": "compromised"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_list_revocations() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url(&format!("/contacts/{}/revocations", fake_id())))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["revocations"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_add_machine() {
    let d = daemon().await;
    let agent = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known"}))
        .send()
        .await
        .unwrap();
    let r = ca(&d)
        .post(d.url(&format!("/contacts/{agent}/machines")))
        .json(&serde_json::json!({"machine_id": fake_id()}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "add_machine: {}", r.status());
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn daemon_api_pin_unpin_machine() {
    let d = daemon().await;
    let agent = fake_id();
    let machine = fake_id();
    ca(&d)
        .post(d.url("/contacts"))
        .json(&serde_json::json!({"agent_id": agent, "trust_level": "known"}))
        .send()
        .await
        .unwrap();
    ca(&d)
        .post(d.url(&format!("/contacts/{agent}/machines")))
        .json(&serde_json::json!({"machine_id": machine}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .post(d.url(&format!("/contacts/{agent}/machines/{machine}/pin")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    let r: Value = ca(&d)
        .delete(d.url(&format!("/contacts/{agent}/machines/{machine}/pin")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    ca(&d)
        .delete(d.url(&format!("/contacts/{agent}")))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn daemon_api_evaluate_trust() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/trust/evaluate"))
        .json(&serde_json::json!({"agent_id": fake_id(), "machine_id": fake_id()}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["decision"].is_string());
}

// ===========================================================================
// MLS Groups (8)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_create_group() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["group_id"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_list_groups() {
    let d = daemon().await;
    ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .get(d.url("/mls/groups"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["groups"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_get_group() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    let r: Value = ca(&d)
        .get(d.url(&format!("/mls/groups/{gid}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["members"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_add_member() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    let r: Value = ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/members")))
        .json(&serde_json::json!({"agent_id": fake_id()}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // MLS add_member may fail if commit cannot be applied (expected for synthetic IDs)
    assert!(r["ok"].is_boolean(), "add_member response: {:?}", r);
}

#[tokio::test]
#[ignore]
async fn daemon_api_remove_member() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    let member = fake_id();
    ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/members")))
        .json(&serde_json::json!({"agent_id": member}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .delete(d.url(&format!("/mls/groups/{gid}/members/{member}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // MLS remove_member may fail similarly
    assert!(r["ok"].is_boolean(), "remove_member response: {:?}", r);
}

#[tokio::test]
#[ignore]
async fn daemon_api_encrypt_decrypt() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    // Encrypt
    let enc: Value = ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/encrypt")))
        .json(&serde_json::json!({"payload": b64(b"secret")}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(enc["ok"], true);
    let ct = enc["ciphertext"].as_str().unwrap();
    let epoch = enc["epoch"].as_u64().unwrap();
    // Decrypt
    let dec: Value = ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/decrypt")))
        .json(&serde_json::json!({"ciphertext": ct, "epoch": epoch}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dec["ok"], true);
    let pt = base64::engine::general_purpose::STANDARD
        .decode(dec["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(pt, b"secret");
}

#[tokio::test]
#[ignore]
async fn daemon_api_mls_welcome() {
    let d = daemon().await;
    let cr: Value = ca(&d)
        .post(d.url("/mls/groups"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = cr["group_id"].as_str().unwrap();
    let invitee = fake_id();
    ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/members")))
        .json(&serde_json::json!({"agent_id": invitee}))
        .send()
        .await
        .unwrap();
    let r: Value = ca(&d)
        .post(d.url(&format!("/mls/groups/{gid}/welcome")))
        .json(&serde_json::json!({"agent_id": invitee}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["welcome"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_group_not_found() {
    let d = daemon().await;
    let r = ca(&d)
        .get(d.url("/mls/groups/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// Task Lists (5)
// ===========================================================================

async fn create_task_list_item(d: &DaemonFixture, title: &str) -> Result<(String, String)> {
    let client = ca(d);
    let topic = format!("task-lifecycle-{}", rand::random::<u32>());

    let create = client
        .post(d.url("/task-lists"))
        .json(&serde_json::json!({"name": "task lifecycle", "topic": topic}))
        .send()
        .await?;
    ensure!(
        create.status() == StatusCode::CREATED,
        "create task list status: {}",
        create.status()
    );

    let create_body: Value = create.json().await?;
    ensure!(
        create_body["ok"].as_bool() == Some(true),
        "create task list response: {create_body:?}"
    );
    let list_id = create_body["id"]
        .as_str()
        .with_context(|| format!("create task list response missing id: {create_body:?}"))?
        .to_string();
    ensure!(!list_id.is_empty(), "create task list id was empty");

    let add = client
        .post(d.url(&format!("/task-lists/{list_id}/tasks")))
        .json(&serde_json::json!({"title": title}))
        .send()
        .await?;
    ensure!(
        add.status() == StatusCode::CREATED,
        "add task status: {}",
        add.status()
    );

    let add_body: Value = add.json().await?;
    ensure!(
        add_body["ok"].as_bool() == Some(true),
        "add task response: {add_body:?}"
    );
    let task_id = add_body["task_id"]
        .as_str()
        .with_context(|| format!("add task response missing task_id: {add_body:?}"))?
        .to_string();
    ensure!(
        task_id.len() == 64,
        "add task response missing 64-char task_id: {add_body:?}"
    );

    Ok((list_id, task_id))
}

async fn list_task_list_items(d: &DaemonFixture, list_id: &str) -> Result<Value> {
    let response = ca(d)
        .get(d.url(&format!("/task-lists/{list_id}/tasks")))
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "list tasks status: {}",
        response.status()
    );

    let body: Value = response.json().await?;
    ensure!(
        body["ok"].as_bool() == Some(true),
        "list tasks response: {body:?}"
    );
    ensure!(body["tasks"].is_array(), "tasks response: {body:?}");
    Ok(body)
}

async fn update_task_item(
    d: &DaemonFixture,
    list_id: &str,
    task_id: &str,
    action: &str,
) -> Result<()> {
    let response = ca(d)
        .patch(d.url(&format!("/task-lists/{list_id}/tasks/{task_id}")))
        .json(&serde_json::json!({"action": action}))
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "update task status: {}",
        response.status()
    );

    let body: Value = response.json().await?;
    ensure!(
        body["ok"].as_bool() == Some(true),
        "update task response: {body:?}"
    );
    Ok(())
}

fn task_state<'a>(body: &'a Value, task_id: &str) -> Option<&'a str> {
    body["tasks"]
        .as_array()
        .and_then(|tasks| {
            tasks
                .iter()
                .find(|task| task["id"].as_str() == Some(task_id))
        })
        .and_then(|task| task["state"].as_str())
}

#[tokio::test]
#[ignore]
async fn daemon_api_create_task_list() -> Result<()> {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/task-lists"))
        .json(&serde_json::json!({
            "name": "test",
            "topic": format!("test-tasks-{}", rand::random::<u32>()),
        }))
        .send()
        .await?;
    ensure!(
        r.status() == StatusCode::CREATED,
        "create task list status: {}",
        r.status()
    );

    let r: Value = r.json().await?;
    ensure!(
        r["ok"].as_bool() == Some(true),
        "create task list response: {r:?}"
    );
    ensure!(r["id"].is_string(), "create task list response: {r:?}");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn daemon_api_add_task() -> Result<()> {
    let d = daemon().await;
    create_task_list_item(&d, "Test task").await?;
    Ok(())
}

#[tokio::test]
#[ignore]
async fn daemon_api_list_tasks() -> Result<()> {
    let d = daemon().await;
    let (list_id, task_id) = create_task_list_item(&d, "List me").await?;

    let r = ca(&d).get(d.url("/task-lists")).send().await?;
    ensure!(
        r.status() == StatusCode::OK,
        "list task lists status: {}",
        r.status()
    );

    let listed = list_task_list_items(&d, &list_id).await?;
    ensure!(
        task_state(&listed, &task_id) == Some("empty"),
        "listed task response: {listed:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn daemon_api_claim_task() -> Result<()> {
    let d = daemon().await;
    let (list_id, task_id) = create_task_list_item(&d, "Claim me").await?;

    update_task_item(&d, &list_id, &task_id, "claim").await?;

    let listed = list_task_list_items(&d, &list_id).await?;
    ensure!(
        task_state(&listed, &task_id).is_some_and(|state| state.starts_with("claimed:")),
        "claimed task response: {listed:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn daemon_api_complete_task() -> Result<()> {
    let d = daemon().await;
    let (list_id, task_id) = create_task_list_item(&d, "Complete me").await?;

    update_task_item(&d, &list_id, &task_id, "claim").await?;
    update_task_item(&d, &list_id, &task_id, "complete").await?;

    let listed = list_task_list_items(&d, &list_id).await?;
    ensure!(
        task_state(&listed, &task_id).is_some_and(|state| state.starts_with("done:")),
        "completed task response: {listed:?}"
    );
    Ok(())
}

// ===========================================================================
// Network (5)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_bootstrap_cache() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/network/bootstrap-cache"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
}

#[tokio::test]
#[ignore]
async fn daemon_api_diagnostics_connectivity() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/diagnostics/connectivity"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    // The snapshot always includes these keys even before any peer is known,
    // so operators can rely on them for scripted probes.
    assert!(r["port_mapping"].is_object());
    assert!(r["mdns"].is_object());
    assert!(r["connections"].is_object());
}

#[tokio::test]
#[ignore]
async fn daemon_api_diagnostics_ack() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/diagnostics/ack"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["ack"].is_object());
    assert!(r["ack"]["generated_at_unix_ms"].is_number());
    assert!(r["ack"]["retention_minutes"].is_number());
    assert!(r["ack"]["peers"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_diagnostics_dm() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/diagnostics/dm"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["stats"].is_object());
    assert!(r["per_peer"].is_object());
    assert!(r["subscriber_count"].is_number());
    assert!(r["subscriber_capacity"].is_number());
}

#[tokio::test]
#[ignore]
async fn daemon_api_diagnostics_ws() {
    // #122 / WS1.1: the bounded WS outbound-queue diagnostics surface.
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/diagnostics/ws"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["ws_outbound_capacity"].is_number());
    assert!(r["ws_outbound_dropped"].is_number());
    assert!(r["ws_slow_consumer_closes"].is_number());
}

#[tokio::test]
#[ignore]
async fn daemon_api_auth_session_exchange() {
    // #127 / WS1.6: durable bearer → short-lived session token.
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/auth/session"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(r["session_token"].is_string());
    let session = r["session_token"].as_str().unwrap();
    assert!(session.len() >= 32, "session token must be opaque");
    assert_eq!(r["expires_in"], 600);

    // The session token must be accepted on a browser-only query-token
    // endpoint (the durable token is NOT — tested separately in the unit
    // auth matrix). Prove it opens /events via ?token=<session>.
    let sse = ca(&d)
        .get(d.url(&format!("/events?token={session}")))
        .send()
        .await
        .unwrap();
    assert!(
        sse.status().is_success(),
        "session token opens SSE: {}",
        sse.status()
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_diagnostics_exec() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/diagnostics/exec"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["enabled"].is_boolean());
    assert!(r["totals"].is_object());
    assert!(r["acl_summary"].is_object());
}

#[tokio::test]
#[ignore]
async fn daemon_api_diagnostics_connect() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/diagnostics/connect"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Connect is Disabled by default (no ACL file at the default path in test env).
    // The snapshot must always carry an acl_summary with enabled=false.
    assert!(r["acl_summary"].is_object());
    assert_eq!(r["acl_summary"]["enabled"], false);
    assert!(r["streams_allowed"].is_number());
    assert!(r["streams_denied"].is_number());
    assert!(r["denial_breakdown"].is_object());
}

#[tokio::test]
#[ignore]
async fn daemon_api_exec_sessions() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/exec/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["pending_clients"].is_array());
    assert!(r["active_servers"].is_array());
}

#[tokio::test]
#[ignore]
async fn daemon_api_exec_run_bad_agent_id() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/exec/run"))
        .json(&serde_json::json!({"agent_id":"bad", "argv":["echo", "1"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], false);
    assert!(r["error"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_exec_cancel_bad_request_id() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .post(d.url("/exec/cancel"))
        .json(&serde_json::json!({"request_id":"bad"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], false);
    assert!(r["error"].is_string());
}

#[tokio::test]
#[ignore]
async fn daemon_api_upgrade_check() {
    let d = daemon().await;
    let r: Value = ca(&d)
        .get(d.url("/upgrade"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // May fail due to GitHub rate limiting (403) — that's ok
    assert!(
        r["ok"] == true || r["error"].is_string(),
        "upgrade_check: {:?}",
        r
    );
}

#[tokio::test]
#[ignore]
async fn daemon_api_connect_unknown() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/agents/connect"))
        .json(&serde_json::json!({"agent_id": fake_id()}))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap();
    // Unknown agent returns ok with outcome "NotFound"
    assert_eq!(body["ok"], true);
    assert!(
        body["outcome"].as_str().unwrap().contains("NotFound") || body["outcome"] == "Unreachable"
    );
}

// ===========================================================================
// WebSocket (3)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_ws_connect() {
    let d = daemon().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(d.ws_url("/ws").await)
        .await
        .expect("WS connect failed");
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = match msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
        other => panic!("Expected text, got {other:?}"),
    };
    let frame: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(frame["type"], "connected");
    assert!(frame["session_id"].is_string());
    let _ = ws.close(None).await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_ws_ping_pong() {
    let d = daemon().await;
    let (mut ws, _) = tokio_tungstenite::connect_async(d.ws_url("/ws").await)
        .await
        .unwrap();
    let _ = ws.next().await; // consume connected
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        r#"{"type":"ping"}"#.into(),
    ))
    .await
    .unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = match msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
        other => panic!("Expected text, got {other:?}"),
    };
    let frame: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(frame["type"], "pong");
    let _ = ws.close(None).await;
}

#[tokio::test]
#[ignore]
async fn daemon_api_ws_sessions() {
    let d = daemon().await;
    let (_ws, _) = tokio_tungstenite::connect_async(d.ws_url("/ws").await)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r: Value = ca(&d)
        .get(d.url("/ws/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["ok"], true);
    assert!(r["sessions"].is_array());
}

// ===========================================================================
// Error handling (3)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn daemon_api_invalid_hex() {
    let d = daemon().await;
    let r = ca(&d)
        .get(d.url("/agents/reachability/not-hex"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore]
async fn daemon_api_body_too_large() {
    let d = daemon().await;
    let big = "A".repeat(2 * 1024 * 1024);
    let result = ca(&d)
        .post(d.url("/publish"))
        .header("content-type", "application/json")
        .body(format!(r#"{{"topic":"t","payload":"{big}"}}"#))
        .send()
        .await;

    match result {
        Ok(response) => {
            assert!(
                response.status() == StatusCode::PAYLOAD_TOO_LARGE
                    || response.status() == StatusCode::BAD_REQUEST,
                "unexpected status: {}",
                response.status()
            );
        }
        Err(err) => {
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("connection reset")
                    || msg.contains("body write")
                    || msg.contains("channel closed"),
                "unexpected transport error for oversized body: {err}"
            );
        }
    }
}

#[tokio::test]
#[ignore]
async fn daemon_api_invalid_json() {
    let d = daemon().await;
    let r = ca(&d)
        .post(d.url("/publish"))
        .header("content-type", "application/json")
        .body("not json")
        .send()
        .await
        .unwrap();
    assert!(
        r.status() == StatusCode::BAD_REQUEST || r.status() == StatusCode::UNPROCESSABLE_ENTITY
    );
}
