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
    assert_eq!(status, StatusCode::OK, "{body}");
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

    // A replica that holds the key and receives the removal live. Offline
    // holders: `kv::store` tests (group stores heal, plain stores do not).
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
    holder
        .merge_delta(&delta, handle.peer_id(), Some(&owner))
        .expect("merge removal");
    assert!(holder.get("k").is_none(), "a holder applies the removal");
    handle.retire_and_drain().await;
}

#[tokio::test]
async fn absent_removal_changes_nothing_locally() {
    let (state, _dir) = state().await;
    let handle = state
        .agent
        .create_kv_store_persistent(
            "store",
            "absent/local",
            AccessPolicy::Signed,
            &state.kv_store_state_dir,
        )
        .await
        .expect("store");
    handle
        .put("other".to_string(), b"v".to_vec(), "text/plain".to_string())
        .await
        .expect("put");
    let path = crate::kv_snapshot_path(&state.kv_store_state_dir, &handle.store_id().await);
    let snapshot = tokio::fs::read(&path).await.expect("snapshot");
    let version = handle.sync.read().await.current_version();

    let outcome = handle
        .remove_absent_with_outcome("k")
        .await
        .expect("absent removal");
    assert!(!outcome.held);
    assert_eq!(handle.sync.read().await.current_version(), version);
    assert_eq!(tokio::fs::read(&path).await.expect("snapshot"), snapshot);
    handle.retire_and_drain().await;
}

/// `held` is the test `KvStore::remove` applies: an entry this replica
/// holds without a live OR-Set tag is held, removed and persisted.
#[tokio::test]
async fn held_follows_the_entry_that_remove_checks() {
    let (state, _dir) = state().await;
    let handle = open(&state, "absent/ghost", AccessPolicy::Signed).await;
    let version = {
        let mut store = handle.sync.write().await;
        store.entries_mut_for_test().insert(
            "ghost".to_string(),
            x0x::kv::KvEntry::new("ghost".to_string(), b"v".to_vec(), "text/plain".to_string()),
        );
        assert!(store.get("ghost").is_none(), "no live tag");
        store.current_version()
    };
    let (status, body) = delete(&state, "absent/ghost", "ghost", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["held"], true, "{body}");
    let store = handle.sync.read().await;
    assert!(!store.holds_entry("ghost"));
    assert!(store.current_version() > version);
    drop(store);
    handle.retire_and_drain().await;
}

#[tokio::test]
async fn absent_removal_keeps_the_self_keyed_prefix_rule() {
    let (state, _dir) = state().await;
    let topic = "absent/directory";
    let handle = state
        .agent
        .join_self_keyed_kv_store_persistent(topic, &state.kv_store_state_dir)
        .await
        .expect("directory");
    state
        .kv_stores
        .write()
        .await
        .insert(topic.to_string(), handle.clone());
    let own = format!("{}/k", hex::encode(state.agent.agent_id().as_bytes()));
    let foreign = format!("{}/k", "ab".repeat(32));
    let (status, body) = delete(&state, topic, &foreign, Some("publish")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = delete(&state, topic, &own, Some("publish")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["held"], false, "{body}");
    handle.retire_and_drain().await;
}

#[tokio::test]
async fn absent_removal_on_an_encrypted_group_store() {
    let (state, _dir) = state().await;
    let group_key = "a7".repeat(16);
    let mut info = crate::groups::GroupInfo::new(
        "kv-group".to_string(),
        String::new(),
        state.agent.agent_id(),
        group_key.clone(),
    );
    info.migrate_from_v1();
    let _ = info.rotate_shared_secret();
    state
        .named_groups
        .write()
        .await
        .insert(group_key.clone(), info);
    let (code, resp) = create_group_kv_store(
        State(Arc::clone(&state)),
        Path(group_key.clone()),
        Extension(ActorContext::Owner { durable: true }),
        Json(CreateGroupStoreRequest {
            name: "ws".to_string(),
        }),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{resp:?}");
    let topic = resp.0["topic"].as_str().expect("topic").to_string();
    let handle = state
        .kv_stores
        .read()
        .await
        .get(&topic)
        .cloned()
        .expect("handle");
    assert!(handle.is_encrypted().await);
    let (status, body) = delete(&state, &topic, "k", Some("publish")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["held"], false, "{body}");
    let delta = handle
        .remove_absent_with_outcome("k")
        .await
        .expect("absent removal")
        .delta;
    assert!(delta.removed["k"].is_empty());
    assert!(delta.owner_checkpoint.is_none());
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

/// Nothing changed here, the publish failed and a store with no
/// gossip-inbox contact sends no direct message: the removal did nothing,
/// so the reply is 503 with an `error` the CLI prints.
#[tokio::test]
async fn an_absent_removal_that_reaches_no_one_is_503() {
    let (state, _dir) = state().await;
    let handle = open(&state, "absent/503", AccessPolicy::Signed).await;
    handle.sync_fail_next_publish_for_test().await;
    let (status, body) = delete(&state, "absent/503", "k", Some("publish")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["ok"], false, "{body}");
    assert_eq!(body["held"], false, "{body}");
    assert_eq!(body["published"], false, "{body}");
    assert_eq!(body["direct_attempted"], 0, "{body}");
    assert!(
        body["error"].as_str().is_some_and(|e| !e.is_empty()),
        "the CLI prints `error`: {body}"
    );
    assert!(
        body["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "the publish cause is carried: {body}"
    );

    handle
        .put("k".to_string(), b"v".to_vec(), "text/plain".to_string())
        .await
        .expect("put");
    handle.sync_fail_next_publish_for_test().await;
    let (status, body) = delete(&state, "absent/503", "k", Some("publish")).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "a held key is removed here: {body}"
    );
    assert_eq!(body["held"], true, "{body}");
    handle.retire_and_drain().await;
}
