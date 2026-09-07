//! Wiring test for `GET /history/message/:msg_id` (issue #319, ADR-0023
//! completeness): the point-lookup route the tic-tac-toe desktop and the
//! buzz-acp harness were already calling — and receiving 404s from — before
//! it existed.
//!
//! REVERT GUARD: delete the `/history/message/{msg_id}` route registration
//! from `serve_with_options` (src/server/mod.rs) or the
//! `history_message` handler's `get_by_msg_id` call and this test fails:
//! the canonical-id lookup below returns 404/500 instead of the row. The
//! store-level unit surface cannot catch that — this is dispatch wiring.
//!
//! Runs in the default suite: single daemon, loopback only, ephemeral
//! ports, sub-second.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use x0x::server::{serve_with_options, DaemonConfig, ServeOptions, ServerHandle};

use serde_json::Value;

struct Daemon {
    _handle: ServerHandle,
    client: reqwest::Client,
    base: String,
}

impl Daemon {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn post_json(&self, path: &str, body: Value) -> Value {
        self.client
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {path}: {e}"))
            .json()
            .await
            .unwrap_or_else(|e| panic!("POST {path} json: {e}"))
    }

    async fn get_status(&self, path: &str) -> (reqwest::StatusCode, Value) {
        let resp = self
            .client
            .get(self.url(path))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e}"));
        let status = resp.status();
        let body = resp.json().await.unwrap_or(Value::Null);
        (status, body)
    }
}

/// Hermetic single daemon: loopback only, ephemeral ports, empty bootstrap
/// list, all state under `dir`. Mirrors the F2 wiring-test harness.
async fn start_daemon(dir: &Path) -> Daemon {
    let data_dir = dir.join("data");
    tokio::fs::create_dir_all(&data_dir)
        .await
        .expect("create data dir");

    let token = "h9".repeat(32);
    tokio::fs::write(data_dir.join("api-token"), &token)
        .await
        .expect("write api token");

    let mut config = DaemonConfig::default();
    config.api_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bind_address = SocketAddr::from(([127, 0, 0, 1], 0));
    config.bootstrap_peers = Some(Vec::new());
    config.data_dir = data_dir;
    config.identity_dir = Some(dir.join("identity"));

    let options = ServeOptions {
        skip_update_check: true,
        self_update_enabled: false,
        ..ServeOptions::default()
    };
    let handle = serve_with_options(config, options)
        .await
        .expect("serve_with_options should start");
    let base = format!("http://{}", handle.local_addr());

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header"),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client");

    Daemon {
        _handle: handle,
        client,
        base,
    }
}

/// Schema v4 added four columns to every history row. Readers pinned to the
/// released response shape (tic-tac-toe 0.5.2 among them) must see no
/// difference: rows written by today's writers leave the new columns unset,
/// so `/history` keeps exactly the keys it served before, with `thread_root`
/// and `thread_parent` still derived from the signed group artifact.
///
/// REVERT GUARD: leak a new column into `row_json` (src/server/routes/
/// history.rs) or change the derivation and this key-set assertion fails.
#[tokio::test]
async fn history_row_json_shape_unchanged_by_schema_v4() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let daemon = start_daemon(dir.path()).await;

    let created = daemon
        .post_json(
            "/groups",
            serde_json::json!({"name": "shape-guard", "preset": "public_open"}),
        )
        .await;
    assert_eq!(created["ok"], true, "create group: {created:?}");
    let group_id = created["group_id"].as_str().expect("group_id").to_string();

    let sent = daemon
        .post_json(
            &format!("/groups/{group_id}/send"),
            serde_json::json!({"body": "shape guard payload"}),
        )
        .await;
    assert_eq!(sent["ok"], true, "group send: {sent:?}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let record = loop {
        let (status, body) = daemon
            .get_status(&format!("/history?scope=group:{group_id}&limit=10"))
            .await;
        if status == reqwest::StatusCode::OK {
            if let Some(row) = body["records"].as_array().and_then(|rows| rows.first()) {
                break row.clone();
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the group send never produced a durable history row: {body:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let mut keys: Vec<&str> = record
        .as_object()
        .expect("record must be a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "author_agent",
            "author_machine",
            "content_type",
            "direction",
            "id",
            "msg_id",
            "payload",
            "provenance",
            "replace_key",
            "scope",
            "seen_at_ms",
            "sent_at_ms",
            "signed",
            "thread_parent",
            "thread_root",
        ],
        "schema v4 must not change the /history record shape: {record:?}"
    );

    // A rootless group message still reports null ancestry — the dormant
    // columns must not turn into empty strings or defaults.
    assert!(
        record["thread_root"].is_null(),
        "unthreaded row must report null thread_root: {record:?}"
    );
    assert!(
        record["thread_parent"].is_null(),
        "unthreaded row must report null thread_parent: {record:?}"
    );
}

#[tokio::test]
async fn history_message_point_lookup_serves_group_row_by_canonical_id() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let daemon = start_daemon(dir.path()).await;

    // A SignedPublic group message is the simplest durable row with a
    // canonical msg_id exposed on the send response (ADR 0029).
    let created = daemon
        .post_json(
            "/groups",
            serde_json::json!({"name": "point-lookup", "preset": "public_open"}),
        )
        .await;
    assert_eq!(created["ok"], true, "create group: {created:?}");
    let group_id = created["group_id"].as_str().expect("group_id").to_string();

    let sent = daemon
        .post_json(
            &format!("/groups/{group_id}/send"),
            serde_json::json!({"body": "point-lookup wiring payload"}),
        )
        .await;
    assert_eq!(sent["ok"], true, "group send: {sent:?}");
    let msg_id = sent["msg_id"].as_str().expect("send msg_id").to_string();

    // The send response is the canonical ADR-0029 id. The shared local
    // recorder must expose that same id with LocalSend provenance, and the
    // point lookup must return that exact row.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let local_send_record: Value = loop {
        let (status, body) = daemon
            .get_status(&format!("/history?scope=group:{group_id}&limit=10"))
            .await;
        if status == reqwest::StatusCode::OK {
            if let Some(row) = body["records"].as_array().and_then(|rows| {
                rows.iter().find(|row| {
                    row["msg_id"].as_str() == Some(msg_id.as_str())
                        && row["provenance"].as_str() == Some("LocalSend")
                })
            }) {
                break row.clone();
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the group send never produced a durable history row: {body:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    assert_eq!(local_send_record["msg_id"], msg_id);
    assert_eq!(local_send_record["provenance"], "LocalSend");
    let (status, body) = daemon
        .get_status(&format!("/history/message/{msg_id}?scope=group:{group_id}"))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "send-response canonical id must resolve after its LocalSend row is listed: {body:?}"
    );
    assert_eq!(body["ok"], true, "lookup body: {body:?}");
    assert_eq!(body["record"]["msg_id"], msg_id);
    assert_eq!(body["record"]["provenance"], "LocalSend");

    // Unknown-but-well-formed id: clean 404, not 400/500.
    let (status, _) = daemon
        .get_status(&format!("/history/message/{}", "e".repeat(64)))
        .await;
    assert_eq!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "unknown 64-hex msg_id must 404"
    );

    // Malformed id: 400, never a store query.
    let (status, _) = daemon.get_status("/history/message/not-hex").await;
    assert_eq!(
        status,
        reqwest::StatusCode::BAD_REQUEST,
        "malformed msg_id must 400"
    );
}
