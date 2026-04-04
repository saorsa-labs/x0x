//! Property-based tests for the KV store.

use proptest::prelude::*;
use saorsa_gossip_types::PeerId;
use std::collections::HashMap;
use x0x::identity::AgentId;
use x0x::kv::store::{AccessPolicy, KvStore, KvStoreId};

fn agent(bytes: [u8; 32]) -> AgentId {
    AgentId(bytes)
}

fn peer(bytes: [u8; 32]) -> PeerId {
    PeerId::new(bytes)
}

fn arb_key() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z]{1,4}").unwrap()
}

fn arb_value() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..64)
}

#[derive(Debug, Clone)]
enum KvOp {
    Put(String, Vec<u8>),
    Remove(String),
}

fn arb_op() -> impl Strategy<Value = KvOp> {
    prop_oneof![
        (arb_key(), arb_value()).prop_map(|(k, v)| KvOp::Put(k, v)),
        arb_key().prop_map(KvOp::Remove),
    ]
}

fn make_store(owner: AgentId, policy: AccessPolicy) -> KvStore {
    KvStore::new(
        KvStoreId::from_content("test", &owner),
        "test-store".to_string(),
        owner,
        policy,
    )
}

proptest! {
    #[test]
    fn oracle_consistency(
        owner_bytes in prop::array::uniform32(any::<u8>()),
        ops in prop::collection::vec(arb_op(), 1..30),
    ) {
        let owner = agent(owner_bytes);
        let owner_peer = peer(owner_bytes);
        let mut store = make_store(owner, AccessPolicy::Signed);
        let mut oracle: HashMap<String, Vec<u8>> = HashMap::new();

        for op in &ops {
            match op {
                KvOp::Put(k, v) => {
                    let result = store.put(k.clone(), v.clone(), "application/octet-stream".to_string(), owner_peer);
                    prop_assert!(result.is_ok());
                    oracle.insert(k.clone(), v.clone());
                }
                KvOp::Remove(k) => {
                    let removed = store.remove(k).is_ok();
                    if removed {
                        oracle.remove(k);
                    }
                }
            }
        }

        for (k, v) in &oracle {
            let entry = store.get(k);
            prop_assert!(entry.is_some(), "missing key {k}");
            prop_assert_eq!(&entry.unwrap().value, v);
        }

        let mut store_keys: Vec<String> = store.active_keys().into_iter().cloned().collect();
        store_keys.sort();
        let mut oracle_keys: Vec<String> = oracle.keys().cloned().collect();
        oracle_keys.sort();

        prop_assert_eq!(store_keys, oracle_keys);
        prop_assert_eq!(store.len(), oracle.len());
    }

    #[test]
    fn signed_policy_only_owner_is_authorized(
        owner_bytes in prop::array::uniform32(any::<u8>()),
        other_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(owner_bytes != other_bytes);
        let owner = agent(owner_bytes);
        let other = agent(other_bytes);
        let store = make_store(owner, AccessPolicy::Signed);

        prop_assert!(store.is_authorized(&owner));
        prop_assert!(!store.is_authorized(&other));
    }

    #[test]
    fn allowlisted_grants_listed_and_owner(
        owner_bytes in prop::array::uniform32(any::<u8>()),
        listed_bytes in prop::array::uniform32(any::<u8>()),
        outsider_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(owner_bytes != listed_bytes);
        prop_assume!(owner_bytes != outsider_bytes);
        prop_assume!(listed_bytes != outsider_bytes);

        let owner = agent(owner_bytes);
        let listed = agent(listed_bytes);
        let outsider = agent(outsider_bytes);
        let mut store = make_store(owner, AccessPolicy::Allowlisted);

        let allow_result = store.allow_writer(listed, &owner);
        prop_assert!(allow_result.is_ok());
        prop_assert!(store.is_authorized(&owner));
        prop_assert!(store.is_authorized(&listed));
        prop_assert!(!store.is_authorized(&outsider));
    }

    #[test]
    fn deny_writer_revokes_access(
        owner_bytes in prop::array::uniform32(any::<u8>()),
        writer_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(owner_bytes != writer_bytes);

        let owner = agent(owner_bytes);
        let writer = agent(writer_bytes);
        let mut store = make_store(owner, AccessPolicy::Allowlisted);

        prop_assert!(store.allow_writer(writer, &owner).is_ok());
        prop_assert!(store.is_authorized(&writer));
        prop_assert!(store.deny_writer(&writer, &owner).is_ok());
        prop_assert!(!store.is_authorized(&writer));
    }

    #[test]
    fn active_keys_and_len_stay_in_sync(
        owner_bytes in prop::array::uniform32(any::<u8>()),
        ops in prop::collection::vec(arb_op(), 1..20),
    ) {
        let owner = agent(owner_bytes);
        let owner_peer = peer(owner_bytes);
        let mut store = make_store(owner, AccessPolicy::Signed);

        for op in &ops {
            match op {
                KvOp::Put(k, v) => {
                    let result = store.put(k.clone(), v.clone(), "application/octet-stream".to_string(), owner_peer);
                    prop_assert!(result.is_ok());
                }
                KvOp::Remove(k) => {
                    let _ = store.remove(k);
                }
            }
        }

        prop_assert_eq!(store.active_keys().len(), store.len());
        for key in store.active_keys() {
            prop_assert!(store.get(key).is_some(), "active key {key} missing entry");
        }
    }
}
