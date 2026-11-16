#![cfg(test)]
//! #1094 slice P2: `GET /stores/:id/:key` shows the verified writer of the
//! value it returns, and a rider's write is marked with the rider.

use super::*;
use crate::server::rider_auth::ActorContext;

/// A state whose agent has a loopback-only gossip runtime (a store needs
/// one), with a store open at `topic`.
async fn state_with_store_at(topic: &str) -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("dir");
    let data_dir = dir.path().to_path_buf();
    let agent = Arc::new(
        crate::Agent::builder()
            .with_identity_dir(&data_dir)
            .with_machine_key(data_dir.join("machine.key"))
            .with_agent_key(crate::identity::AgentKeypair::generate().expect("key"))
            .with_agent_cert_path(data_dir.join("agent.cert"))
            .with_peer_cache_disabled()
            .with_contact_store_path(data_dir.join("contacts.json"))
            .with_network_config(crate::network::NetworkConfig {
                bind_addr: Some("127.0.0.1:0".parse().expect("loopback")),
                bootstrap_nodes: Vec::new(),
                mdns_enabled: false,
                port_mapping_enabled: false,
                ..crate::network::NetworkConfig::default()
            })
            .build()
            .await
            .expect("agent"),
    );
    let state =
        crate::server::routes::named_groups::tests::secure_endpoint_test_state_at(&data_dir, agent)
            .await
            .expect("state");
    let handle = state
        .agent
        .create_kv_store("store", topic)
        .await
        .expect("store");
    state
        .kv_stores
        .write()
        .await
        .insert(topic.to_string(), handle);
    (state, dir)
}

async fn state_with_group_store() -> (Arc<AppState>, tempfile::TempDir, String) {
    let (_, topic) = x0x::kv::encrypted::group_store_identity(&"2b".repeat(16), "scratch");
    let (state, dir) = state_with_store_at(&topic).await;
    (state, dir, topic)
}

async fn json_of(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).expect("json"))
}

async fn put(
    state: &Arc<AppState>,
    actor: Option<ActorContext>,
    topic: &str,
    key: &str,
) -> StatusCode {
    put_kv_value(
        actor.map(Extension),
        State(Arc::clone(state)),
        Path((topic.to_string(), key.to_string())),
        Json(PutValueRequest {
            value: BASE64.encode(b"v"),
            content_type: Some("text/plain".to_string()),
        }),
    )
    .await
    .into_response()
    .status()
}

async fn get(state: &Arc<AppState>, topic: &str, key: &str) -> serde_json::Value {
    let (status, body) = json_of(
        get_kv_value(
            State(Arc::clone(state)),
            Path((topic.to_string(), key.to_string())),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// The owner's write reads back with this agent as its verified writer,
/// and the raw mark keys are not in `metadata`.
#[tokio::test]
async fn issue1094_p2_get_shows_the_verified_writer() {
    let (state, _dir, topic) = state_with_group_store().await;
    assert!(put(&state, None, &topic, "note").await.is_success());
    let body = get(&state, &topic, "note").await;
    assert_eq!(
        body["writer"],
        serde_json::json!({
            "verified": true,
            "agent": hex::encode(state.agent.agent_id().as_bytes()),
            "rider": null,
        })
    );
    let metadata = body["metadata"].as_object().expect("metadata");
    assert!(
        metadata
            .keys()
            .all(|k| !k.starts_with(x0x::kv::provenance::WRITER_KEY_PREFIX)),
        "raw mark keys are not shown: {body}"
    );
}

/// A rider's write is marked with its sub-agent id beside this agent.
#[tokio::test]
async fn issue1094_p2_a_rider_write_names_the_rider() {
    let (state, _dir, topic) = state_with_group_store().await;
    let rider = "7c".repeat(32);
    let actor = ActorContext::Rider {
        sub_agent_id: rider.clone(),
        token_id: 1,
        token_hash: "00".repeat(32),
        groups: vec!["2b".repeat(16)],
        scopes: vec!["scratch:read_write".to_string()],
    };
    assert!(put(&state, Some(actor), &topic, "todo").await.is_success());
    let body = get(&state, &topic, "todo").await;
    assert_eq!(body["writer"]["verified"], serde_json::json!(true));
    assert_eq!(body["writer"]["rider"], serde_json::json!(rider));
}

/// Anything but a verified mark is `{"verified": false}`, "writer unknown":
/// here an entry in a store outside `x0x/group/`, which is not marked.
#[tokio::test]
async fn issue1094_p2_an_unmarked_entry_is_writer_unknown() {
    let topic = "app/plain".to_string();
    let (state, _dir) = state_with_store_at(&topic).await;
    assert!(put(&state, None, &topic, "k").await.is_success());
    let body = get(&state, &topic, "k").await;
    assert_eq!(body["writer"], serde_json::json!({ "verified": false }));
    assert_eq!(writer_json(None), serde_json::json!({ "verified": false }));
    let invalid = x0x::kv::provenance::EntryWriter::Invalid { reason: "x" };
    assert_eq!(
        writer_json(Some(&invalid)),
        serde_json::json!({ "verified": false }),
        "invalid is shown as writer unknown, not as tampering"
    );
}

/// Review of #1974: the same bytes rewritten by another writer (here a
/// rider) with another content type. GET pairs the new content type with
/// the new writer: value, content type and writer come from one snapshot.
#[tokio::test]
async fn issue1094_p2_get_pairs_content_type_with_its_writer() {
    let (state, _dir, topic) = state_with_group_store().await;
    assert!(put(&state, None, &topic, "note").await.is_success());
    let rider = "5d".repeat(32);
    let actor = ActorContext::Rider {
        sub_agent_id: rider.clone(),
        token_id: 2,
        token_hash: "11".repeat(32),
        groups: vec!["2b".repeat(16)],
        scopes: vec!["scratch:read_write".to_string()],
    };
    let status = put_kv_value(
        Some(Extension(actor)),
        State(Arc::clone(&state)),
        Path((topic.clone(), "note".to_string())),
        Json(PutValueRequest {
            value: BASE64.encode(b"v"),
            content_type: Some("application/json".to_string()),
        }),
    )
    .await
    .into_response()
    .status();
    assert!(status.is_success(), "{status}");
    let body = get(&state, &topic, "note").await;
    assert_eq!(body["content_type"], serde_json::json!("application/json"));
    assert_eq!(body["writer"]["verified"], serde_json::json!(true));
    assert_eq!(body["writer"]["rider"], serde_json::json!(rider));
}
