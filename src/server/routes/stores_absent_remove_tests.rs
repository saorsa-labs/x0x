#![cfg(test)]
//! #2110 item 3: the owner removes a key its replica does not hold. A
//! removal on the wire names only the key, so the bytes are the ones every
//! receiver already applies.

use super::*;
use x0x::kv::{AccessPolicy, KvStore};

async fn state() -> (Arc<AppState>, tempfile::TempDir) {
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
    (state, dir)
}

async fn open(state: &AppState, topic: &str, policy: AccessPolicy) -> x0x::KvStoreHandle {
    let handle = state
        .agent
        .create_kv_store_with_policy("store", topic, policy)
        .await
        .expect("store");
    state
        .kv_stores
        .write()
        .await
        .insert(topic.to_string(), handle.clone());
    handle
}

async fn delete(
    state: &Arc<AppState>,
    topic: &str,
    key: &str,
    absent: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let (status, Json(body)) = delete_kv_value(
        State(Arc::clone(state)),
        Path((topic.to_string(), key.to_string())),
        Query(DeleteValueQuery {
            absent: absent.map(str::to_string),
        }),
    )
    .await;
    (status, body)
}

#[tokio::test]
async fn delete_of_a_key_this_replica_lacks_is_404_without_the_flag() {
    let (state, _dir) = state().await;
    let handle = open(&state, "absent/404", AccessPolicy::Signed).await;
    let (status, body) = delete(&state, "absent/404", "missing", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "key not found");
    handle.retire_and_drain().await;
}

#[tokio::test]
async fn an_unknown_absent_value_is_400() {
    let (state, _dir) = state().await;
    let handle = open(&state, "absent/400", AccessPolicy::Signed).await;
    let (status, body) = delete(&state, "absent/400", "missing", Some("yes")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    handle.retire_and_drain().await;
}

#[tokio::test]
async fn owner_removes_a_key_it_does_not_hold() {
    let (state, _dir) = state().await;
    let owner = state.agent.agent_id();
    let handle = open(&state, "absent/owner", AccessPolicy::Signed).await;

    let (status, body) = delete(&state, "absent/owner", "k", Some("publish")).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::ACCEPTED,
        "{status} {body}"
    );
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(body["held"], false, "{body}");

    let outcome = handle
        .remove_absent_with_outcome("k")
        .await
        .expect("absent removal");
    assert!(!outcome.held);
    let delta = outcome.delta;
    assert_eq!(delta.removed.len(), 1);
    assert!(
        delta.removed["k"].is_empty(),
        "the removal names only the key"
    );
    assert!(delta.added.is_empty() && delta.updated.is_empty());
    assert!(delta.owner_checkpoint.is_none() && delta.name_update.is_none());
    assert!(delta.allowlist_additions.is_none() && delta.allowlist_removals.is_none());

    // A holder, and a second holder of the same tag that is offline when
    // the removal is published.
    let mut holder = KvStore::new(
        handle.store_id().await,
        "store".to_string(),
        owner,
        AccessPolicy::Signed,
    )
    .expect("holder");
    holder
        .put(
            "k".to_string(),
            b"v".to_vec(),
            "text/plain".to_string(),
            saorsa_gossip_types::PeerId::new([7; 32]),
        )
        .expect("put");
    let mut offline = holder.clone();

    holder
        .merge_delta(&delta, handle.peer_id(), Some(&owner))
        .expect("merge removal");
    assert!(holder.get("k").is_none(), "a holder applies the removal");

    assert!(offline.get("k").is_some());
    offline.merge(&holder).expect("image merge");
    assert!(
        offline.get("k").is_none(),
        "an offline holder loses the key at its next image merge"
    );
    handle.retire_and_drain().await;
}

#[tokio::test]
async fn absent_removal_bytes_match_a_held_removal() {
    let (state, _dir) = state().await;
    let handle = open(&state, "absent/bytes", AccessPolicy::Signed).await;
    handle
        .put("k".to_string(), b"v".to_vec(), "text/plain".to_string())
        .await
        .expect("put");
    let mut held = handle.remove_with_outcome("k").await.expect("held").delta;
    let absent = handle
        .remove_absent_with_outcome("k")
        .await
        .expect("absent")
        .delta;
    held.version = absent.version;
    held.owner_checkpoint = None;
    held.name_update = None;
    assert_eq!(
        bincode::serialize(&held).expect("held bytes"),
        bincode::serialize(&absent).expect("absent bytes"),
        "only the version and the owner checkpoint differ"
    );
    handle.retire_and_drain().await;
}

#[tokio::test]
async fn absent_removal_keeps_the_write_rules() {
    let (state, _dir) = state().await;
    let append_only = open(&state, "absent/ao", AccessPolicy::AppendOnly).await;
    let (status, body) = delete(&state, "absent/ao", "k", Some("publish")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let other = crate::identity::AgentKeypair::generate()
        .expect("key")
        .agent_id();
    let joined = state
        .agent
        .join_kv_store(
            "absent/joined",
            other,
            x0x::kv::store::AnchorChannel::RestParam,
        )
        .await
        .expect("join");
    state
        .kv_stores
        .write()
        .await
        .insert("absent/joined".to_string(), joined.clone());
    let (status, body) = delete(&state, "absent/joined", "k", Some("publish")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    append_only.retire_and_drain().await;
    joined.retire_and_drain().await;
}
