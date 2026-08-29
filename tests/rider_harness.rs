//! ADR-0039 agent-harness boundary — integration suite.
//!
//! Runs a real in-process owned daemon (`x0x::server::serve` with a
//! generated owner `user.key`), then exercises the full rider lifecycle:
//!
//! 1. **Scope matrix** — a rider token is `403` on every ungranted verb
//!    (`/agent/sign`, `/exec/run`, `/owner/*`, `/shutdown`, …), `401` with
//!    a bad token, and `200` only on the rider route set.
//! 2. **Issuance → journal → roster** — `POST /owner/agents/issue` lands
//!    a `mode`/`label`/`cert_b64` record in the ADR-0036 journal and
//!    `GET /owner/agents` lists it.
//! 3. **Provenance send** — a rider send to a granted `SignedPublic`
//!    group carries the signed provenance envelope (it verifies and is
//!    covered by `msg_id`), and a rider Home encrypt lands attributed
//!    history in the Home scope.
//! 4. **Revocation** — `DELETE /owner/riders/:id` makes the very next
//!    request `401`; `DELETE /owner/agents/:id` sweeps the agent's
//!    tokens and marks the roster entry revoked.
//! 5. **ACP chain** — a certificate issued over a submitted public key
//!    verifies against `GroupAdmission::OwnerCertified` evidence.
//!
//! Socket-binding tests are `#[ignore]` (repo convention): run with
//! `cargo nextest run --all-features --test rider_harness --run-ignored all`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

/// An owned in-process daemon plus its bearer token and dirs.
struct OwnedDaemon {
    _handle: x0x::server::ServerHandle,
    addr: SocketAddr,
    api_token: String,
    root: PathBuf,
    _dir: tempfile::TempDir,
}

impl OwnedDaemon {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

/// Start an owned daemon: fresh temp identity dir pre-seeded with a
/// generated owner `user.key`, so startup auto-issues the agent
/// certificate and provisions Home (ADR-0038).
async fn owned_daemon() -> OwnedDaemon {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity_dir = dir.path().join("identity");
    tokio::fs::create_dir_all(&identity_dir)
        .await
        .expect("mkdir identity");
    let user_kp = x0x::identity::UserKeypair::generate().expect("owner keypair");
    x0x::storage::save_user_keypair_to(&user_kp, identity_dir.join("user.key"))
        .await
        .expect("save owner key");

    let mut config = x0x::server::DaemonConfig::default();
    config.api_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bind_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bootstrap_peers = Some(Vec::new());
    config.data_dir = dir.path().join("data");
    config.identity_dir = Some(identity_dir.clone());

    let handle = x0x::server::serve(config).await.expect("serve()");
    let addr = handle.local_addr();

    let token_path = dir.path().join("data").join("api-token");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let api_token = loop {
        if let Ok(token) = tokio::fs::read_to_string(&token_path).await {
            let token = token.trim().to_string();
            if !token.is_empty() {
                break token;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "api-token file never appeared"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    OwnedDaemon {
        _handle: handle,
        addr,
        api_token,
        root: dir.path().to_path_buf(),
        _dir: dir,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("client")
}

async fn owner_json(
    d: &OwnedDaemon,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> (reqwest::StatusCode, Value) {
    let mut req = client()
        .request(method, d.url(path))
        .bearer_auth(&d.api_token);
    if let Some(body) = body {
        req = req.json(&body);
    }
    let resp = req.send().await.expect("owner request");
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn rider_json(
    token: &str,
    method: reqwest::Method,
    url: String,
    body: Option<Value>,
) -> (reqwest::StatusCode, Value) {
    let mut req = client().request(method, url).bearer_auth(token);
    if let Some(body) = body {
        req = req.json(&body);
    }
    let resp = req.send().await.expect("rider request");
    let status = resp.status();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// Issue a rider-mode sub-agent + rider token bound to `groups`.
/// Returns `(sub_agent_hex, rider_token)`.
async fn issue_rider(d: &OwnedDaemon, label: &str, groups: Vec<String>) -> (String, String) {
    let kp = x0x::identity::AgentKeypair::generate().expect("sub-agent keypair");
    let public_hex = hex::encode(kp.public_key().as_bytes());
    let (status, body) = owner_json(
        d,
        reqwest::Method::POST,
        "/owner/agents/issue",
        Some(json!({ "agent_public_key": public_hex, "mode": "rider", "label": label })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "issue: {body}");
    let sub_agent_id = body["agent_id"].as_str().expect("agent_id").to_string();

    let (status, body) = owner_json(
        d,
        reqwest::Method::POST,
        "/owner/riders",
        Some(json!({ "sub_agent_id": sub_agent_id, "groups": groups, "label": label })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "rider issue: {body}");
    let token = body["token"].as_str().expect("one-time token").to_string();
    (sub_agent_id, token)
}

/// The stable group id of this daemon's Home.
async fn home_group_id(d: &OwnedDaemon) -> String {
    let (status, body) = owner_json(d, reqwest::Method::GET, "/home", None).await;
    assert_eq!(status, reqwest::StatusCode::OK, "home: {body}");
    body["group_id"]
        .as_str()
        .expect("home group id")
        .to_string()
}

/// 1. Scope matrix: riders are denied every ungranted verb (403) and
/// unknown tokens are 401 — the deny-by-default gate is the middleware,
/// before any handler.
#[tokio::test]
#[ignore]
async fn rider_scope_matrix_ungranted_verbs_forbidden() {
    let d = owned_daemon().await;
    let home = home_group_id(&d).await;
    let (_sub, token) = issue_rider(&d, "scope-matrix", vec![]).await;

    let forbidden: &[(reqwest::Method, &str, Option<Value>)] = &[
        // The signing oracle (gapcheck blocker 21).
        (
            reqwest::Method::POST,
            "/agent/sign",
            Some(json!({ "payload_b64": "aGk=", "context": "x0x-rider-abuse" })),
        ),
        // Remote exec.
        (
            reqwest::Method::POST,
            "/exec/run",
            Some(json!({ "target": "self", "command": "id" })),
        ),
        // Owner/admin surfaces — a rider must never mint riders or read the roster.
        (reqwest::Method::GET, "/owner/agents", None),
        (
            reqwest::Method::POST,
            "/owner/agents/issue",
            Some(json!({ "agent_public_key": "00" })),
        ),
        (reqwest::Method::DELETE, "/owner/agents/abcd", None),
        (reqwest::Method::GET, "/owner/riders", None),
        (
            reqwest::Method::POST,
            "/owner/riders",
            Some(json!({ "sub_agent_id": "00".repeat(32) })),
        ),
        // Control plane.
        (reqwest::Method::POST, "/shutdown", None),
        (
            reqwest::Method::POST,
            "/publish",
            Some(json!({ "topic": "t", "payload_b64": "aGk=" })),
        ),
        (reqwest::Method::POST, "/announce", None),
        (reqwest::Method::GET, "/groups", None),
        (reqwest::Method::GET, "/history/stats", None),
        (reqwest::Method::GET, "/history/search", None),
        (reqwest::Method::GET, "/agent", None),
    ];
    for (method, path, body) in forbidden {
        let (status, resp) = rider_json(&token, method.clone(), d.url(path), body.clone()).await;
        assert_eq!(
            status,
            reqwest::StatusCode::FORBIDDEN,
            "rider {method} {path} must be 403, got {status}: {resp}"
        );
    }

    // Granted surfaces DO answer (possibly with domain errors, but 403 from
    // the route gate is what must never happen).
    let (status, _) = rider_json(
        &token,
        reqwest::Method::GET,
        d.url(&format!("/history?scope=group:{home}&limit=5")),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "rider home history read");

    // Unknown bearer stays a plain 401 — riders are not a side channel for
    // token probing beyond what the owner token already allows.
    let (status, _) = rider_json(
        &"0".repeat(64),
        reqwest::Method::GET,
        d.url("/history?scope=group:x"),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "bad token 401");
}

/// 2. Issuance lands in the ADR-0036 journal (mode + label + retained
/// cert) and the roster lists it; a rider cannot read the roster.
#[tokio::test]
#[ignore]
async fn rider_issuance_journals_and_roster_lists() {
    let d = owned_daemon().await;
    let kp = x0x::identity::AgentKeypair::generate().expect("keypair");
    let (status, body) = owner_json(
        &d,
        reqwest::Method::POST,
        "/owner/agents/issue",
        Some(json!({
            "agent_public_key": hex::encode(kp.public_key().as_bytes()),
            "mode": "rider",
            "label": "ci-agent",
        })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "issue: {body}");
    let agent_id = body["agent_id"].as_str().expect("agent_id").to_string();
    assert_eq!(
        body["mode"].as_str(),
        Some("rider"),
        "response carries the hosting mode"
    );
    assert!(
        !body["certificate"]["storage_b64"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "certificate bytes are returned to the harness"
    );

    // Journal: owner-scoped record with mode/label and retained cert bytes.
    let journal = tokio::fs::read_to_string(d.root.join("identity/owner-cert-journal.jsonl"))
        .await
        .expect("journal file");
    let line = journal
        .lines()
        .rev()
        .find(|line| line.contains(&agent_id))
        .expect("journal line for the issued agent");
    let record: Value = serde_json::from_str(line).expect("journal line is JSON");
    assert_eq!(record["mode"], "rider");
    assert_eq!(record["label"], "ci-agent");
    assert!(!record["cert_b64"].as_str().unwrap_or("").is_empty());

    // Roster lists it with mode/label, journal-backed.
    let (status, body) = owner_json(&d, reqwest::Method::GET, "/owner/agents", None).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let entry = body["agents"]
        .as_array()
        .expect("agents array")
        .iter()
        .find(|entry| entry["agent_id"].as_str() == Some(agent_id.as_str()))
        .expect("roster entry");
    assert_eq!(entry["mode"], "rider");
    assert_eq!(entry["journal_label"], "ci-agent");
    assert_eq!(entry["from_journal"], true, "journal is authoritative");
    assert_eq!(entry["revoked"], false);

    // Anonymous (no owner key) installs refuse issuance with 409 —
    // covered by tests/profile_api.rs for GET; here the owned path is the
    // happy case and malformed keys are rejected:
    let (status, body) = owner_json(
        &d,
        reqwest::Method::POST,
        "/owner/agents/issue",
        Some(json!({ "agent_public_key": "zz", "mode": "rider" })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "bad key: {body}");
    let (status, body) = owner_json(
        &d,
        reqwest::Method::POST,
        "/owner/agents/issue",
        Some(json!({ "agent_public_key": "ab", "mode": "wrong" })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "bad mode: {body}");
}

/// 3. A rider send to a granted SignedPublic group carries the signed
/// provenance envelope (verifiable, covered by msg_id) and a rider Home
/// encrypt lands attributed history in the Home scope.
#[tokio::test]
#[ignore]
async fn rider_send_carries_provenance_and_lands() {
    let d = owned_daemon().await;
    let home = home_group_id(&d).await;

    // A SignedPublic group (PublicOpen preset) the rider will be granted.
    let (status, body) = owner_json(
        &d,
        reqwest::Method::POST,
        "/groups",
        Some(json!({ "name": "rider-target", "preset": "public_open" })),
    )
    .await;
    assert!(status.is_success(), "create group: {body}");
    let group_id = body["group_id"]
        .as_str()
        .expect("stable group id")
        .to_string();

    let (sub_agent, token) = issue_rider(&d, "provenance", vec![group_id.clone()]).await;

    // Review fix #1 (CRITICAL regression): the sub-agent is NOT a
    // member of this MembersOnly group — the rider send must be 403
    // even though the DAEMON (the group creator/admin) is a member.
    // Authorizing against the daemon's role would let a rider emit
    // admin-authored messages; the grant alone must not suffice.
    let (status, _) = rider_json(
        &token,
        reqwest::Method::POST,
        d.url(&format!("/groups/{group_id}/send")),
        Some(json!({ "body": "must be refused" })),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "non-member sub-agent must not send via the daemon's membership"
    );

    // Admit the sub-agent to the roster (OpenJoin admission) — the
    // send is now authorized as the SUB-AGENT and carries provenance.
    let (status, body) = owner_json(
        &d,
        reqwest::Method::POST,
        &format!("/groups/{group_id}/members"),
        Some(json!({ "agent_id": sub_agent })),
    )
    .await;
    assert!(status.is_success(), "add sub-agent member: {body}");

    // Granted send → 200 with msg_id.
    let (status, body) = rider_json(
        &token,
        reqwest::Method::POST,
        d.url(&format!("/groups/{group_id}/send")),
        Some(json!({ "body": "hello from the rider" })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "rider send: {body}");
    let msg_id = body["msg_id"].as_str().expect("msg_id").to_string();

    // The cached message carries provenance AND a verifiable signature —
    // proving the envelope is inside the signed bytes (gapcheck 24).
    let (status, body) = owner_json(
        &d,
        reqwest::Method::GET,
        &format!("/groups/{group_id}/messages"),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "messages: {body}");
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let raw = messages
        .iter()
        .find(|m| m["msg_id"].as_str() == Some(msg_id.as_str()))
        .or_else(|| messages.iter().find(|m| m["rider_provenance"].is_object()))
        .cloned()
        .unwrap_or_else(|| panic!("rider message not in group cache: {body}"));
    assert_eq!(
        raw["rider_provenance"]["sub_agent_id"].as_str(),
        Some(sub_agent.as_str()),
        "provenance names the sub-agent"
    );
    assert_eq!(
        raw["rider_provenance"]["scope"].as_str(),
        Some(group_id.as_str())
    );
    let parsed: x0x::groups::GroupPublicMessage =
        serde_json::from_value(raw).expect("message parses as GroupPublicMessage");
    parsed
        .verify_signature()
        .expect("daemon signature verifies over the provenance-bearing bytes");
    assert_eq!(
        parsed.msg_id(),
        msg_id,
        "msg_id covers the provenance envelope (BLAKE3 over signable bytes)"
    );

    // Ungranted group: a second group the rider has no grant for → 403.
    let (status, body) = owner_json(
        &d,
        reqwest::Method::POST,
        "/groups",
        Some(json!({ "name": "rider-forbidden", "preset": "public_open" })),
    )
    .await;
    assert!(status.is_success(), "second group create: {body}");
    let other_group = body["group_id"]
        .as_str()
        .expect("second group id")
        .to_string();
    let (status, _) = rider_json(
        &token,
        reqwest::Method::POST,
        d.url(&format!("/groups/{other_group}/send")),
        Some(json!({ "body": "nope" })),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "ungranted group send"
    );

    // Home (MlsEncrypted): the rider encrypt surface lands attributed
    // plaintext history in the Home scope.
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::STANDARD.encode(b"rider to home");
    let (status, body) = rider_json(
        &token,
        reqwest::Method::POST,
        d.url(&format!("/groups/{home}/secure/encrypt")),
        Some(json!({ "payload_b64": payload })),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "rider Home encrypt must succeed (Home is always granted): {body}"
    );
    let (status, body) = owner_json(
        &d,
        reqwest::Method::GET,
        &format!("/history?scope=group:{home}&limit=10"),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "home history: {body}");
    let records = body["records"].as_array().cloned().unwrap_or_default();
    assert!(
        records
            .iter()
            .any(|r| r["author_agent"].as_str() == Some(sub_agent.as_str())),
        "Home history row attributed to the sub-agent: {body}"
    );

    // Rider history is bounded to granted scopes: dm scope → 403.
    let (status, _) = rider_json(
        &token,
        reqwest::Method::GET,
        d.url(&format!("/history?scope=dm:{}", "ab".repeat(32))),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "dm scope denied");
}

/// 4. Revocation lifecycle: a revoked token fails on the NEXT request;
/// revoking the sub-agent sweeps its tokens and marks the roster entry.
#[tokio::test]
#[ignore]
async fn rider_revoked_token_fails_on_next_request() {
    let d = owned_daemon().await;
    let home = home_group_id(&d).await;
    let (_sub_agent, token) = issue_rider(&d, "doomed", vec![]).await;

    // Alive: the granted Home history read answers 200.
    let (status, _) = rider_json(
        &token,
        reqwest::Method::GET,
        d.url(&format!("/history?scope=group:{home}")),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "live token works");

    // Revoke the token (owner), then the SAME bearer is 401 immediately.
    let (status, _) = owner_json(&d, reqwest::Method::GET, "/owner/riders", None).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let (status, _) = rider_json(
        &token,
        reqwest::Method::GET,
        d.url(&format!("/history?scope=group:{home}")),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    // token_id 1 is the first issued rider token on this install.
    let (status, body) = owner_json(&d, reqwest::Method::DELETE, "/owner/riders/1", None).await;
    assert_eq!(status, reqwest::StatusCode::OK, "revoke: {body}");
    let (status, _) = rider_json(
        &token,
        reqwest::Method::GET,
        d.url(&format!("/history?scope=group:{home}")),
        None,
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "revoked token 401"
    );
    // Unknown id → 404.
    let (status, _) = owner_json(&d, reqwest::Method::DELETE, "/owner/riders/99", None).await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);

    // Agent-level revocation (ADR-0018 issuer path) sweeps rider tokens
    // and marks the roster entry revoked; new token issuance is refused.
    let (sub2, token2) = issue_rider(&d, "sweep-me", vec![]).await;
    let (status, _) = rider_json(
        &token2,
        reqwest::Method::GET,
        d.url(&format!("/history?scope=group:{home}")),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let (status, body) = owner_json(
        &d,
        reqwest::Method::DELETE,
        &format!("/owner/agents/{sub2}"),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "agent revoke: {body}");
    assert_eq!(body["revoked"], true, "agent revoke response");
    assert_eq!(
        body["rider_tokens_revoked"], 1,
        "agent revoke sweeps rider tokens"
    );
    let (status, _) = rider_json(
        &token2,
        reqwest::Method::GET,
        d.url(&format!("/history?scope=group:{home}")),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "swept token 401");

    let (status, body) = owner_json(&d, reqwest::Method::GET, "/owner/agents", None).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    let entry = body["agents"]
        .as_array()
        .expect("agents")
        .iter()
        .find(|e| e["agent_id"].as_str() == Some(sub2.as_str()))
        .expect("revoked entry still listed (journal is append-only)");
    assert_eq!(entry["revoked"], true, "roster shows revocation");

    let (status, body) = owner_json(
        &d,
        reqwest::Method::POST,
        "/owner/riders",
        Some(json!({ "sub_agent_id": sub2 })),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::CONFLICT,
        "no new rider tokens for a revoked agent: {body}"
    );

    // An unrelated agent id → 404.
    let (status, _) = owner_json(
        &d,
        reqwest::Method::DELETE,
        &format!("/owner/agents/{}", "07".repeat(32)),
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
}

/// Review fix #4: a 10-minute browser session token is a read-only
/// principal. It must NOT mint owner-signed certificates, rider
/// tokens, or revoke anything — those owner-admin acts require the
/// durable API token.
#[tokio::test]
#[ignore]
async fn session_token_cannot_mint_owner_credentials() {
    let d = owned_daemon().await;
    let (status, body) = owner_json(&d, reqwest::Method::POST, "/auth/session", None).await;
    assert_eq!(status, reqwest::StatusCode::OK, "session mint: {body}");
    let session = body["session_token"]
        .as_str()
        .expect("session token")
        .to_string();

    let kp = x0x::identity::AgentKeypair::generate().expect("keypair");
    let admin_acts: &[(reqwest::Method, &str, Option<Value>)] = &[
        (
            reqwest::Method::POST,
            "/owner/agents/issue",
            Some(json!({
                "agent_public_key": hex::encode(kp.public_key().as_bytes()),
                "mode": "rider"
            })),
        ),
        (
            reqwest::Method::POST,
            "/owner/riders",
            Some(json!({ "sub_agent_id": "ab".repeat(32) })),
        ),
        (reqwest::Method::GET, "/owner/riders", None),
        (reqwest::Method::DELETE, "/owner/riders/1", None),
        (
            reqwest::Method::DELETE,
            &format!("/owner/agents/{}", "cd".repeat(32)),
            None,
        ),
    ];
    for (method, path, body) in admin_acts {
        let (status, resp) = rider_json(&session, method.clone(), d.url(path), body.clone()).await;
        assert_eq!(
            status,
            reqwest::StatusCode::FORBIDDEN,
            "session bearer {method} {path} must be 403: {resp}"
        );
    }
    // Read-only owner surfaces remain session-accessible (GUI parity).
    let (status, _) =
        rider_json(&session, reqwest::Method::GET, d.url("/owner/agents"), None).await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "session may read the roster"
    );
}

/// Review fix #1 (CRITICAL): a rider must not inherit the daemon's
/// ADMIN role. In an AdminOnly-write group where the daemon is the
/// creator-admin, a rider whose sub-agent is a plain member (or not a
/// member at all) is 403 — the provenance envelope names the
/// authorization subject and receivers enforce against it.
#[tokio::test]
#[ignore]
async fn rider_cannot_escalate_to_daemon_admin_role() {
    let d = owned_daemon().await;
    let (status, body) = owner_json(
        &d,
        reqwest::Method::POST,
        "/groups",
        Some(json!({
            "name": "admin-only-target",
            "policy": {
                "discoverability": "public_directory",
                "admission": "open_join",
                "confidentiality": "signed_public",
                "read_access": "public",
                "write_access": "admin_only"
            }
        })),
    )
    .await;
    assert!(status.is_success(), "create admin-only group: {body}");
    let group_id = body["group_id"].as_str().expect("group id").to_string();

    let (sub_agent, token) = issue_rider(&d, "escalator", vec![group_id.clone()]).await;

    // Non-member sub-agent: 403 despite the token grant.
    let (status, _) = rider_json(
        &token,
        reqwest::Method::POST,
        d.url(&format!("/groups/{group_id}/send")),
        Some(json!({ "body": "admin voice" })),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "non-member in admin-only group"
    );

    // Plain-member sub-agent: still 403 — AdminOnly needs the
    // sub-agent's OWN admin role, never the daemon's.
    let (status, body) = owner_json(
        &d,
        reqwest::Method::POST,
        &format!("/groups/{group_id}/members"),
        Some(json!({ "agent_id": sub_agent })),
    )
    .await;
    assert!(status.is_success(), "add member: {body}");
    let (status, resp) = rider_json(
        &token,
        reqwest::Method::POST,
        d.url(&format!("/groups/{group_id}/send")),
        Some(json!({ "body": "admin voice" })),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "plain-member sub-agent must not write to an admin-only group: {resp}"
    );

    // The daemon itself (owner bearer) still can — the policy works;
    // only the rider's privilege ceiling changed.
    let (status, resp) = owner_json(
        &d,
        reqwest::Method::POST,
        &format!("/groups/{group_id}/send"),
        Some(json!({ "body": "owner announcement" })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "owner send: {resp}");
}

/// ACP-attached mode: a certificate issued over a submitted public key
/// (the daemon never sees the secret) verifies against the
/// OwnerCertified admission core — the exact chain a Home join presents.
#[test]
fn acp_cert_chain_verifies_against_owner_certified_admission() {
    // WHY: ADR-0039 validation — the harness-key path must be
    // indistinguishable to ADR-0038 admission from any owner-certified
    // agent, while a foreign owner's certificate must NOT chain.
    let owner = x0x::identity::UserKeypair::generate().expect("owner");
    let harness = x0x::identity::AgentKeypair::generate().expect("harness keypair");
    let cert = x0x::identity::AgentCertificate::issue_for_public_key(
        &owner,
        harness.public_key().as_bytes(),
        None,
    )
    .expect("issue over public key only");
    assert!(cert.verify().is_ok(), "cert verifies");
    let agent_hex = hex::encode(harness.agent_id().as_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(
        x0x::groups::owner_cert::verify_cert_against_owner(
            &owner.user_id(),
            &agent_hex,
            &cert,
            false,
            now
        ),
        Ok(()),
        "issued cert chains for OwnerCertified admission"
    );
    // Revocation evidence fails the same check (fail-closed path).
    assert_eq!(
        x0x::groups::owner_cert::verify_cert_against_owner(
            &owner.user_id(),
            &agent_hex,
            &cert,
            true,
            now
        ),
        Err(x0x::groups::owner_cert::OwnerCertFailure::Revoked)
    );
    // A different owner must not accept it.
    let other = x0x::identity::UserKeypair::generate().expect("other owner");
    assert_eq!(
        x0x::groups::owner_cert::verify_cert_against_owner(
            &other.user_id(),
            &agent_hex,
            &cert,
            false,
            now
        ),
        Err(x0x::groups::owner_cert::OwnerCertFailure::NotChainedToOwner)
    );
    // Garbage keys are rejected at issuance (fail closed, blocker 20).
    assert!(
        x0x::identity::AgentCertificate::issue_for_public_key(&owner, &[0u8; 7], None).is_err()
    );
}
