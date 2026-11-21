#![cfg(test)]
//! #2110 item 2: the digest beacon carries the declarer's OR-Set digest, so
//! a value-only difference is repaired through the image back-off.

use super::*;
use crate::kv::KvEntry;
use std::cell::Cell;

/// The `StateDigestBeacon` bytes a main-era sender writes (fixture case
/// before #2110).
const MAIN_ERA_BEACON: &str =
    "04000000070707070707070707070707070707070707070707070707070707070707070709000000";

/// `KvSyncMessage` exactly as main encoded it before #2110: what an older
/// receiver decodes into.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
enum MainEraKvSyncMessage {
    StateRequest {
        requester: PeerId,
    },
    OwnerAnnounce {
        owner: AgentId,
        policy: AccessPolicy,
        policy_version: u64,
    },
    StateServed {
        responder: PeerId,
        empty: bool,
        checkpoint_seq: Option<u64>,
    },
    StateServedV2 {
        responder: PeerId,
        digest: [u8; 32],
        entry_count: u32,
    },
    StateDigestBeacon {
        digest: [u8; 32],
        entry_count: u32,
    },
}

#[test]
fn main_era_beacon_decodes_with_no_orset_digest() {
    let bytes = hex::decode(MAIN_ERA_BEACON).expect("hex");
    let msg: KvSyncMessage =
        crate::wire_compat::decode_bincode("KvSyncMessage", &bytes).expect("main-era beacon");
    let KvSyncMessage::StateDigestBeacon {
        digest,
        entry_count,
        orset_digest,
    } = msg
    else {
        panic!("not a beacon: {msg:?}");
    };
    assert_eq!((digest, entry_count, orset_digest), ([7; 32], 9, None));
}

#[test]
fn old_node_reads_a_new_beacon() {
    let bytes = bincode::serialize(&KvSyncMessage::StateDigestBeacon {
        digest: [7; 32],
        entry_count: 9,
        orset_digest: Some([8; 32]),
    })
    .expect("encode");
    assert_eq!(bytes.len(), MAIN_ERA_BEACON.len() / 2 + 33);
    let old: MainEraKvSyncMessage =
        crate::wire_compat::decode_bincode("KvSyncMessage", &bytes).expect("old decoder");
    let MainEraKvSyncMessage::StateDigestBeacon {
        digest,
        entry_count,
    } = old
    else {
        panic!("not a beacon: {old:?}");
    };
    assert_eq!((digest, entry_count), ([7; 32], 9));
}

#[test]
fn beacon_wake_rule() {
    let (a, b, o, p) = ([1; 32], [2; 32], [3; 32], [4; 32]);
    let calls = Cell::new(0);
    let local = |value| {
        let calls = &calls;
        move || {
            calls.set(calls.get() + 1);
            Some(value)
        }
    };
    assert_eq!(
        beacon_wake(a, a, false, Some(o), local(o)),
        BeaconWake::InStep
    );
    assert_eq!(beacon_wake(a, b, true, None, local(o)), BeaconWake::Wake);
    assert_eq!(
        calls.get(),
        0,
        "the OR-Set digest is computed only when needed"
    );
    assert_eq!(
        beacon_wake(a, b, false, None, local(o)),
        BeaconWake::Deferred
    );
    assert_eq!(calls.get(), 0, "an older sender's beacon never needs it");
    assert_eq!(
        beacon_wake(a, b, false, Some(p), local(o)),
        BeaconWake::Deferred
    );
    assert_eq!(
        beacon_wake(a, b, false, Some(o), local(o)),
        BeaconWake::Wake
    );
    assert_eq!(
        beacon_wake(a, b, false, Some(o), || None),
        BeaconWake::Deferred
    );
}

fn store_with(values: &[(&str, &[u8])]) -> KvStore {
    let owner = AgentId([1; 32]);
    let mut store = KvStore::new(
        KvStoreId::new([9; 32]),
        "store".to_string(),
        owner,
        AccessPolicy::Signed,
    )
    .expect("store");
    for (key, value) in values {
        store
            .put(
                (*key).to_string(),
                value.to_vec(),
                "text/plain".to_string(),
                PeerId::new([5; 32]),
            )
            .expect("put");
    }
    store
}

#[test]
fn a_value_only_difference_wakes_through_the_backoff() {
    let author = AgentId([2; 32]);
    let mut local = store_with(&[("k", b"one")]);
    let mut theirs = local.clone();
    theirs.entries_mut_for_test().insert(
        "k".to_string(),
        KvEntry::new("k".to_string(), b"two".to_vec(), "text/plain".to_string()),
    );
    local.refuse_image_source_for_test(author);
    assert!(!local.image_retry_due(&author), "the back-off is active");
    assert_ne!(local.served_digest(), theirs.served_digest());
    assert_eq!(
        local.orset_digest().expect("local"),
        theirs.orset_digest().expect("theirs")
    );
    let wake = |declared: &KvStore| {
        beacon_wake(
            local.served_digest(),
            declared.served_digest(),
            local.image_retry_due(&author),
            Some(declared.orset_digest().expect("declared")),
            || local.orset_digest().ok(),
        )
    };
    assert_eq!(wake(&theirs), BeaconWake::Wake);

    theirs
        .put(
            "extra".to_string(),
            b"x".to_vec(),
            "text/plain".to_string(),
            PeerId::new([6; 32]),
        )
        .expect("put");
    assert_ne!(
        local.orset_digest().expect("local"),
        theirs.orset_digest().expect("theirs")
    );
    assert_eq!(
        wake(&theirs),
        BeaconWake::Deferred,
        "a different OR-Set keeps the back-off"
    );
}

#[test]
fn the_orset_digest_ignores_replica_local_state() {
    let mut local = store_with(&[("k", b"one"), ("gone", b"x")]);
    local.remove("gone").expect("remove");
    let image = local.served_image_for_test();
    assert_eq!(
        local.orset_digest().expect("local"),
        image.orset_digest().expect("served image"),
        "the changelog and version are not part of the digest"
    );
    let mut other_id = store_with(&[("k", b"one"), ("gone", b"x")]);
    other_id.remove("gone").expect("remove");
    assert_eq!(
        local.orset_digest().expect("local"),
        other_id.orset_digest().expect("same state")
    );
}
