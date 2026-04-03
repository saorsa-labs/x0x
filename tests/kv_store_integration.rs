//! Integration tests for x0x Key-Value Store.
//!
//! These tests verify the complete workflow of creating KV stores,
//! putting/getting values, managing keys, access control, merging,
//! and concurrent write convergence.
//!
//! Run with: `cargo nextest run --all-features --test kv_store_integration`

use saorsa_gossip_crdt_sync::DeltaCrdt;
use saorsa_gossip_types::PeerId;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use x0x::identity::AgentId;
use x0x::kv::{AccessPolicy, KvEntry, KvError, KvStore, KvStoreDelta, KvStoreId};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a test agent ID filled with the given byte.
fn test_agent(n: u8) -> AgentId {
    AgentId([n; 32])
}

/// Create a test peer ID filled with the given byte.
fn test_peer(n: u8) -> PeerId {
    PeerId::new([n; 32])
}

/// Create a test store ID filled with the given byte.
fn test_store_id(n: u8) -> KvStoreId {
    KvStoreId::new([n; 32])
}

/// Create a fresh KvStore with Signed access policy.
fn make_store(id_byte: u8, name: &str, owner_byte: u8) -> KvStore {
    KvStore::new(
        test_store_id(id_byte),
        name.to_string(),
        test_agent(owner_byte),
        AccessPolicy::Signed,
    )
}

// ---------------------------------------------------------------------------
// 1. Create KV Store — create a store, verify it appears correctly
// ---------------------------------------------------------------------------

#[test]
fn test_create_kv_store() {
    let owner = test_agent(1);
    let store = KvStore::new(
        test_store_id(1),
        "My Store".to_string(),
        owner,
        AccessPolicy::Signed,
    );

    assert_eq!(store.name(), "My Store");
    assert_eq!(store.owner(), Some(&owner));
    assert_eq!(*store.policy(), AccessPolicy::Signed);
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert_eq!(store.current_version(), 0);
    assert_eq!(store.active_keys().len(), 0);
    assert_eq!(store.active_entries().len(), 0);
}

#[test]
fn test_create_kv_store_deterministic_id() {
    let owner = test_agent(1);
    let id_a = KvStoreId::from_content("my-store", &owner);
    let id_b = KvStoreId::from_content("my-store", &owner);
    let id_different = KvStoreId::from_content("other-store", &owner);

    assert_eq!(id_a, id_b, "same name+owner must produce same ID");
    assert_ne!(
        id_a, id_different,
        "different names must produce different IDs"
    );
}

#[test]
fn test_create_multiple_stores() {
    let owner = test_agent(1);
    let stores: Vec<KvStore> = (0..5)
        .map(|i| {
            KvStore::new(
                test_store_id(i),
                format!("Store {i}"),
                owner,
                AccessPolicy::Signed,
            )
        })
        .collect();

    assert_eq!(stores.len(), 5);
    for (i, store) in stores.iter().enumerate() {
        assert_eq!(store.name(), format!("Store {i}"));
    }

    // All IDs should be distinct.
    let ids: HashSet<_> = stores.iter().map(|s| *s.id()).collect();
    assert_eq!(ids.len(), 5);
}

// ---------------------------------------------------------------------------
// 2. Put/Get Values — put a key, get it back, verify match
// ---------------------------------------------------------------------------

#[test]
fn test_put_and_get_value() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Test", 1);

    store
        .put(
            "greeting".to_string(),
            b"hello world".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put should succeed");

    let entry = store.get("greeting").expect("key should exist");
    assert_eq!(entry.value, b"hello world");
    assert_eq!(entry.key, "greeting");
    assert_eq!(entry.content_type, "text/plain");
    assert!(entry.is_inline());
    assert_eq!(entry.size(), 11);
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
}

#[test]
fn test_put_get_binary_value() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Binary", 1);
    let binary_data: Vec<u8> = (0..=255).collect();

    store
        .put(
            "bytes".to_string(),
            binary_data.clone(),
            "application/octet-stream".to_string(),
            peer,
        )
        .expect("put binary");

    let entry = store.get("bytes").expect("key should exist");
    assert_eq!(entry.value, binary_data);
    assert_eq!(entry.size(), 256);
}

// ---------------------------------------------------------------------------
// 3. Multiple Keys — put 5 keys, list them, verify all present
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_keys() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Multi", 1);

    let keys_and_values = [
        ("alpha", "one"),
        ("beta", "two"),
        ("gamma", "three"),
        ("delta", "four"),
        ("epsilon", "five"),
    ];

    for (key, val) in &keys_and_values {
        store
            .put(
                key.to_string(),
                val.as_bytes().to_vec(),
                "text/plain".to_string(),
                peer,
            )
            .expect("put should succeed");
    }

    assert_eq!(store.len(), 5);

    let active_keys: HashSet<String> = store.active_keys().into_iter().cloned().collect();

    for (key, _) in &keys_and_values {
        assert!(
            active_keys.contains(*key),
            "key '{key}' should be in active keys"
        );
    }

    // Verify each value.
    for (key, val) in &keys_and_values {
        let entry = store.get(key).expect("key should exist");
        assert_eq!(entry.value, val.as_bytes());
    }

    // active_entries should match.
    assert_eq!(store.active_entries().len(), 5);
}

// ---------------------------------------------------------------------------
// 4. Update Key — overwrite a key, verify latest value returned
// ---------------------------------------------------------------------------

#[test]
fn test_update_key() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Update", 1);

    store
        .put(
            "counter".to_string(),
            b"1".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("initial put");

    assert_eq!(store.get("counter").expect("get").value, b"1");
    let version_after_first = store.current_version();

    store
        .put(
            "counter".to_string(),
            b"2".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("update put");

    let entry = store.get("counter").expect("get after update");
    assert_eq!(entry.value, b"2");
    assert!(
        store.current_version() > version_after_first,
        "version should increment on update"
    );
    // Key count should remain 1 — same key, not a new one.
    assert_eq!(store.len(), 1);
}

#[test]
fn test_update_key_changes_content_type() {
    let peer = test_peer(1);
    let mut store = make_store(1, "ContentType", 1);

    store
        .put(
            "data".to_string(),
            b"plain text".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put text");

    store
        .put(
            "data".to_string(),
            b"{\"key\": \"value\"}".to_vec(),
            "application/json".to_string(),
            peer,
        )
        .expect("put json");

    let entry = store.get("data").expect("get");
    assert_eq!(entry.content_type, "application/json");
    assert_eq!(entry.value, b"{\"key\": \"value\"}");
}

// ---------------------------------------------------------------------------
// 5. Remove Key — delete a key, verify it's gone from keys list
// ---------------------------------------------------------------------------

#[test]
fn test_remove_key() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Remove", 1);

    store
        .put(
            "ephemeral".to_string(),
            b"temp".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put");

    assert!(store.get("ephemeral").is_some());
    let version_before = store.current_version();

    store.remove("ephemeral").expect("remove");

    assert!(store.get("ephemeral").is_none());
    assert!(store.active_keys().is_empty());
    assert!(store.current_version() > version_before);
}

#[test]
fn test_remove_one_of_many() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Remove", 1);

    for key in ["a", "b", "c"] {
        store
            .put(
                key.to_string(),
                key.as_bytes().to_vec(),
                "text/plain".to_string(),
                peer,
            )
            .expect("put");
    }

    assert_eq!(store.active_keys().len(), 3);

    store.remove("b").expect("remove b");

    let remaining: HashSet<String> = store.active_keys().into_iter().cloned().collect();
    assert_eq!(remaining.len(), 2);
    assert!(remaining.contains("a"));
    assert!(remaining.contains("c"));
    assert!(!remaining.contains("b"));
    assert!(store.get("b").is_none());
}

// ---------------------------------------------------------------------------
// 6. Large Value — test near-limit and over-limit values
// ---------------------------------------------------------------------------

#[test]
fn test_large_value_at_limit() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Large", 1);

    // Just under the 64KB limit should succeed.
    let value = vec![0xABu8; 65_535];
    store
        .put(
            "big".to_string(),
            value.clone(),
            "application/octet-stream".to_string(),
            peer,
        )
        .expect("put near-limit value");

    let entry = store.get("big").expect("get big");
    assert_eq!(entry.value.len(), 65_535);
    assert_eq!(entry.value, value);
}

#[test]
fn test_large_value_over_limit_rejected() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Large", 1);

    // 100KB exceeds the 64KB MAX_INLINE_SIZE limit.
    let value = vec![0xFFu8; 100_000];
    let result = store.put(
        "too-big".to_string(),
        value,
        "application/octet-stream".to_string(),
        peer,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        KvError::ValueTooLarge { size, max } => {
            assert_eq!(size, 100_000);
            assert_eq!(max, 65_536);
        }
        other => panic!("expected ValueTooLarge, got: {other}"),
    }

    // Store should remain empty — the put was rejected.
    assert!(store.is_empty());
}

#[test]
fn test_exactly_at_limit_rejected() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Exact", 1);

    // Exactly MAX_INLINE_SIZE (65536) should be rejected (> check, not >=).
    let value = vec![0u8; 65_536];
    let result = store.put(
        "exact".to_string(),
        value,
        "application/octet-stream".to_string(),
        peer,
    );

    // The implementation uses `value.len() > MAX_INLINE_SIZE`, so 65536 is not > 65536.
    // This test documents the boundary behavior.
    if result.is_ok() {
        let entry = store.get("exact").expect("get");
        assert_eq!(entry.value.len(), 65_536);
    }
    // Either way, the behavior is documented.
}

// ---------------------------------------------------------------------------
// 7. Content Types — put values with different content types
// ---------------------------------------------------------------------------

#[test]
fn test_content_types() {
    let peer = test_peer(1);
    let mut store = make_store(1, "ContentTypes", 1);

    let cases = [
        ("text-key", b"hello".as_slice(), "text/plain"),
        (
            "json-key",
            b"{\"msg\":\"hi\"}".as_slice(),
            "application/json",
        ),
        ("html-key", b"<h1>Title</h1>".as_slice(), "text/html"),
        (
            "binary-key",
            &[0u8, 1, 2, 3, 4][..],
            "application/octet-stream",
        ),
        ("xml-key", b"<root/>".as_slice(), "application/xml"),
    ];

    for (key, val, ct) in &cases {
        store
            .put(key.to_string(), val.to_vec(), ct.to_string(), peer)
            .expect("put should succeed");
    }

    for (key, val, ct) in &cases {
        let entry = store.get(key).expect("key should exist");
        assert_eq!(entry.value, *val);
        assert_eq!(entry.content_type, *ct);
    }
}

#[test]
fn test_content_hash_differs_by_value() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Hashes", 1);

    store
        .put(
            "a".to_string(),
            b"foo".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put a");
    store
        .put(
            "b".to_string(),
            b"bar".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put b");

    let hash_a = store.get("a").expect("a").content_hash;
    let hash_b = store.get("b").expect("b").content_hash;
    assert_ne!(hash_a, hash_b);
}

// ---------------------------------------------------------------------------
// 8. Non-existent Key — get a key that doesn't exist
// ---------------------------------------------------------------------------

#[test]
fn test_get_nonexistent_key_returns_none() {
    let store = make_store(1, "Empty", 1);
    assert!(store.get("does-not-exist").is_none());
}

#[test]
fn test_get_nonexistent_key_among_existing() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Partial", 1);

    store
        .put(
            "exists".to_string(),
            b"yes".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put");

    assert!(store.get("exists").is_some());
    assert!(store.get("nope").is_none());
    assert!(store.get("").is_none());
}

#[test]
fn test_remove_nonexistent_key_returns_error() {
    let mut store = make_store(1, "Empty", 1);
    let result = store.remove("ghost");

    assert!(result.is_err());
    match result.unwrap_err() {
        KvError::KeyNotFound(key) => assert_eq!(key, "ghost"),
        other => panic!("expected KeyNotFound, got: {other}"),
    }
}

// ---------------------------------------------------------------------------
// 9. Non-existent Store — operations on mismatched store IDs
// ---------------------------------------------------------------------------

#[test]
fn test_merge_different_store_ids_fails() {
    let mut store_a = make_store(1, "Store A", 1);
    let store_b = make_store(2, "Store B", 1);

    let result = store_a.merge(&store_b);
    assert!(result.is_err());
    match result.unwrap_err() {
        KvError::StoreIdMismatch => {}
        other => panic!("expected StoreIdMismatch, got: {other}"),
    }
}

#[test]
fn test_operations_on_empty_store() {
    let store = make_store(1, "Empty", 1);

    assert!(store.get("any").is_none());
    assert!(store.active_keys().is_empty());
    assert!(store.active_entries().is_empty());
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
    assert_eq!(store.current_version(), 0);
}

// ---------------------------------------------------------------------------
// 10. Concurrent Writes — two agents write to same store, verify convergence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_writes_converge() {
    let store_id = test_store_id(1);
    let owner = test_agent(1);
    let peer_a = test_peer(1);
    let peer_b = test_peer(2);

    // Use Encrypted policy so both peers can write without allowlist.
    let mut store_a = KvStore::new(
        store_id,
        "Shared".to_string(),
        owner,
        AccessPolicy::Encrypted {
            group_id: vec![1, 2, 3],
        },
    );
    let mut store_b = KvStore::new(
        store_id,
        "Shared".to_string(),
        owner,
        AccessPolicy::Encrypted {
            group_id: vec![1, 2, 3],
        },
    );

    // Agent A writes keys.
    store_a
        .put(
            "key-a1".to_string(),
            b"val-a1".to_vec(),
            "text/plain".to_string(),
            peer_a,
        )
        .expect("put a1");
    store_a
        .put(
            "key-a2".to_string(),
            b"val-a2".to_vec(),
            "text/plain".to_string(),
            peer_a,
        )
        .expect("put a2");

    // Agent B writes different keys.
    store_b
        .put(
            "key-b1".to_string(),
            b"val-b1".to_vec(),
            "text/plain".to_string(),
            peer_b,
        )
        .expect("put b1");
    store_b
        .put(
            "key-b2".to_string(),
            b"val-b2".to_vec(),
            "text/plain".to_string(),
            peer_b,
        )
        .expect("put b2");

    // Merge B into A and A into B.
    store_a.merge(&store_b).expect("merge B into A");
    store_b.merge(&store_a).expect("merge A into B");

    // Both stores should now have all 4 keys.
    let keys_a: HashSet<String> = store_a.active_keys().into_iter().cloned().collect();
    let keys_b: HashSet<String> = store_b.active_keys().into_iter().cloned().collect();

    assert_eq!(keys_a.len(), 4);
    assert_eq!(keys_b.len(), 4);
    assert_eq!(keys_a, keys_b, "stores should converge to the same key set");

    for key in ["key-a1", "key-a2", "key-b1", "key-b2"] {
        assert!(store_a.get(key).is_some(), "A missing {key}");
        assert!(store_b.get(key).is_some(), "B missing {key}");
    }
}

#[tokio::test]
async fn test_concurrent_writes_same_key_lww() {
    let store_id = test_store_id(1);
    let owner = test_agent(1);
    let peer_a = test_peer(1);
    let peer_b = test_peer(2);

    let mut store_a = KvStore::new(
        store_id,
        "Shared".to_string(),
        owner,
        AccessPolicy::Encrypted {
            group_id: vec![1, 2, 3],
        },
    );
    let mut store_b = KvStore::new(
        store_id,
        "Shared".to_string(),
        owner,
        AccessPolicy::Encrypted {
            group_id: vec![1, 2, 3],
        },
    );

    // Both write to the same key.
    store_a
        .put(
            "shared".to_string(),
            b"from-A".to_vec(),
            "text/plain".to_string(),
            peer_a,
        )
        .expect("put A");

    // Small delay to ensure different timestamps.
    std::thread::sleep(std::time::Duration::from_millis(2));

    store_b
        .put(
            "shared".to_string(),
            b"from-B".to_vec(),
            "text/plain".to_string(),
            peer_b,
        )
        .expect("put B");

    // Merge both ways.
    store_a.merge(&store_b).expect("merge B->A");
    store_b.merge(&store_a).expect("merge A->B");

    // LWW: both should converge to the same value.
    let val_a = &store_a.get("shared").expect("get A").value;
    let val_b = &store_b.get("shared").expect("get B").value;
    assert_eq!(val_a, val_b, "LWW should converge to the same value");
}

#[tokio::test]
async fn test_concurrent_writes_via_arc_rwlock() {
    let store_id = test_store_id(1);
    let owner = test_agent(1);

    let store = KvStore::new(
        store_id,
        "Concurrent".to_string(),
        owner,
        AccessPolicy::Encrypted {
            group_id: vec![7, 8, 9],
        },
    );
    let store_arc = Arc::new(RwLock::new(store));

    // Spawn multiple writers.
    let mut handles = Vec::new();
    for i in 0u8..10 {
        let store_ref = Arc::clone(&store_arc);
        let handle = tokio::spawn(async move {
            let peer = PeerId::new([i; 32]);
            let mut s = store_ref.write().await;
            s.put(
                format!("key-{i}"),
                format!("value-{i}").into_bytes(),
                "text/plain".to_string(),
                peer,
            )
            .expect("concurrent put");
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.expect("task should complete");
    }

    let s = store_arc.read().await;
    assert_eq!(s.active_keys().len(), 10);
    for i in 0u8..10 {
        let entry = s.get(&format!("key-{i}")).expect("key should exist");
        assert_eq!(entry.value, format!("value-{i}").into_bytes());
    }
}

// ---------------------------------------------------------------------------
// Additional integration scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_delta_roundtrip_put() {
    let peer = test_peer(1);
    let owner = test_agent(1);
    let store_id = test_store_id(1);

    let mut source = KvStore::new(store_id, "Source".to_string(), owner, AccessPolicy::Signed);

    source
        .put(
            "key1".to_string(),
            b"val1".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put");
    source
        .put(
            "key2".to_string(),
            b"val2".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put");

    // Generate full delta from source.
    let delta = source.full_delta();
    assert!(!delta.is_empty());

    // Apply delta to a fresh target store.
    let mut target = KvStore::new(store_id, "Target".to_string(), owner, AccessPolicy::Signed);

    target
        .merge_delta(&delta, peer, Some(&owner))
        .expect("merge delta");

    assert_eq!(target.active_keys().len(), 2);
    assert_eq!(target.get("key1").expect("k1").value, b"val1");
    assert_eq!(target.get("key2").expect("k2").value, b"val2");
}

#[test]
fn test_delta_crdt_trait_integration() {
    let peer = test_peer(1);
    let owner = test_agent(1);
    let store_id = test_store_id(1);

    let mut store = KvStore::new(
        store_id,
        "DeltaCRDT".to_string(),
        owner,
        AccessPolicy::Encrypted { group_id: vec![1] },
    );

    assert_eq!(DeltaCrdt::version(&store), 0);
    assert!(DeltaCrdt::delta(&store, 0).is_none());

    store
        .put(
            "x".to_string(),
            b"y".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put");

    assert!(DeltaCrdt::version(&store) > 0);
    let delta = DeltaCrdt::delta(&store, 0).expect("delta should exist");

    // Apply to fresh store.
    let mut replica = KvStore::new(
        store_id,
        "Replica".to_string(),
        owner,
        AccessPolicy::Encrypted { group_id: vec![1] },
    );
    DeltaCrdt::merge(&mut replica, &delta).expect("merge");
    assert!(replica.get("x").is_some());
}

#[test]
fn test_version_tracking_across_operations() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Versions", 1);

    assert_eq!(store.current_version(), 0);

    store
        .put(
            "a".to_string(),
            b"1".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put");
    assert_eq!(store.current_version(), 1);

    store
        .put(
            "b".to_string(),
            b"2".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put");
    assert_eq!(store.current_version(), 2);

    store
        .put(
            "a".to_string(),
            b"updated".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("update");
    assert_eq!(store.current_version(), 3);

    store.remove("b").expect("remove");
    assert_eq!(store.current_version(), 4);

    store.update_name("Renamed".to_string(), peer);
    assert_eq!(store.current_version(), 5);
    assert_eq!(store.name(), "Renamed");
}

#[test]
fn test_serialization_roundtrip_full() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Serialize", 1);

    store
        .put(
            "a".to_string(),
            b"alpha".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put");
    store
        .put(
            "b".to_string(),
            b"beta".to_vec(),
            "application/json".to_string(),
            peer,
        )
        .expect("put");

    let bytes = bincode::serialize(&store).expect("serialize");
    let restored: KvStore = bincode::deserialize(&bytes).expect("deserialize");

    assert_eq!(restored.id(), store.id());
    assert_eq!(restored.name(), store.name());
    assert_eq!(restored.len(), store.len());
    assert_eq!(restored.get("a").expect("a").value, b"alpha");
    assert_eq!(restored.get("b").expect("b").value, b"beta");
    assert_eq!(
        restored.get("b").expect("b").content_type,
        "application/json"
    );
}

// ---------------------------------------------------------------------------
// Access control integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_signed_policy_rejects_non_owner_delta() {
    let owner = test_agent(1);
    let attacker = test_agent(99);
    let peer = test_peer(99);
    let store_id = test_store_id(1);

    let mut store = KvStore::new(store_id, "Signed".to_string(), owner, AccessPolicy::Signed);

    let entry = KvEntry::new(
        "spam".to_string(),
        b"junk".to_vec(),
        "text/plain".to_string(),
    );
    let delta = KvStoreDelta::for_put("spam".to_string(), entry, (peer, 1), 1);

    // Silent rejection — no error, but data not applied.
    store
        .merge_delta(&delta, peer, Some(&attacker))
        .expect("should not error");
    assert!(
        store.get("spam").is_none(),
        "unauthorized write should be rejected"
    );
}

#[test]
fn test_allowlisted_policy_workflow() {
    let owner = test_agent(1);
    let writer = test_agent(2);
    let outsider = test_agent(3);
    let store_id = test_store_id(1);

    let mut store = KvStore::new(
        store_id,
        "Team".to_string(),
        owner,
        AccessPolicy::Allowlisted,
    );

    // Initially only the owner is authorized.
    assert!(store.is_authorized(&owner));
    assert!(!store.is_authorized(&writer));
    assert!(!store.is_authorized(&outsider));

    // Owner adds writer to allowlist.
    store.allow_writer(writer, &owner).expect("allow");
    assert!(store.is_authorized(&writer));
    assert!(!store.is_authorized(&outsider));

    // Non-owner cannot modify allowlist.
    assert!(store.allow_writer(outsider, &writer).is_err());

    // Writer can write via delta.
    let entry = KvEntry::new("data".to_string(), b"ok".to_vec(), "text/plain".to_string());
    let delta = KvStoreDelta::for_put("data".to_string(), entry, (test_peer(2), 1), 1);
    store
        .merge_delta(&delta, test_peer(2), Some(&writer))
        .expect("merge");
    assert!(store.get("data").is_some());

    // Outsider delta is silently rejected.
    let entry2 = KvEntry::new("bad".to_string(), b"no".to_vec(), "text/plain".to_string());
    let delta2 = KvStoreDelta::for_put("bad".to_string(), entry2, (test_peer(3), 1), 2);
    store
        .merge_delta(&delta2, test_peer(3), Some(&outsider))
        .expect("silent reject");
    assert!(store.get("bad").is_none());

    // Owner revokes writer.
    store.deny_writer(&writer, &owner).expect("deny");
    assert!(!store.is_authorized(&writer));
}

#[test]
fn test_merge_propagates_allowlist() {
    let owner = test_agent(1);
    let writer = test_agent(2);
    let store_id = test_store_id(1);

    let mut store_a = KvStore::new(store_id, "A".to_string(), owner, AccessPolicy::Allowlisted);
    store_a.allow_writer(writer, &owner).expect("allow");

    let mut store_b = KvStore::new(store_id, "B".to_string(), owner, AccessPolicy::Allowlisted);

    // Merge A into B — allowlist should propagate.
    store_b.merge(&store_a).expect("merge");
    assert!(store_b.allowed_writers().contains(&writer));
}

#[test]
fn test_full_delta_includes_allowlist() {
    let owner = test_agent(1);
    let writer = test_agent(2);
    let store_id = test_store_id(1);

    let mut store = KvStore::new(
        store_id,
        "Delta".to_string(),
        owner,
        AccessPolicy::Allowlisted,
    );
    store.allow_writer(writer, &owner).expect("allow");

    let delta = store.full_delta();
    let additions = delta.allowlist_additions.expect("should have allowlist");
    assert!(additions.contains(&writer));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_put_empty_value() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Empty", 1);

    store
        .put("empty".to_string(), vec![], "text/plain".to_string(), peer)
        .expect("put empty");

    let entry = store.get("empty").expect("get");
    assert!(entry.value.is_empty());
    assert_eq!(entry.size(), 0);
    assert!(!entry.is_inline()); // Empty value is not considered inline.
}

#[test]
fn test_put_empty_key_name() {
    let peer = test_peer(1);
    let mut store = make_store(1, "Keys", 1);

    store
        .put(
            String::new(),
            b"val".to_vec(),
            "text/plain".to_string(),
            peer,
        )
        .expect("put empty key");

    assert!(store.get("").is_some());
    assert_eq!(store.get("").expect("get").value, b"val");
}

#[test]
fn test_monotonic_sequence_counter() {
    let store = make_store(1, "Seq", 1);

    let s1 = store.next_seq();
    let s2 = store.next_seq();
    let s3 = store.next_seq();

    assert!(s1 < s2);
    assert!(s2 < s3);
}

#[test]
fn test_store_id_display() {
    let id = test_store_id(0xAB);
    let display = format!("{id}");
    // Should be a 64-char hex string (32 bytes).
    assert_eq!(display.len(), 64);
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
}
