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
        BeaconWake::SkipBackoff
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
    assert_eq!(wake(&theirs), BeaconWake::SkipBackoff);

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
    assert!(
        local.take_image_orset_skip(&author),
        "the window's one skip"
    );
    assert!(
        !local.take_image_orset_skip(&author),
        "a second matching beacon in the same window is deferred"
    );
}

#[test]
fn one_orset_skip_per_author_per_window() {
    use crate::kv::image_admission::ImageAdmission;
    let (q, r) = (AgentId([2; 32]), AgentId([3; 32]));
    let mut image = ImageAdmission::default();
    assert!(
        image.take_orset_skip(&q, 0),
        "no refusal: no back-off to skip"
    );
    image.note_refusal(q, 1, 1_000);
    image.note_refusal(r, 1, 1_000);
    assert!(image.take_orset_skip(&q, 2_000));
    assert!(!image.take_orset_skip(&q, 3_000), "used for this window");
    image.note_refusal(q, 1, 4_000);
    assert!(
        !image.take_orset_skip(&q, 5_000),
        "a refusal inside the window does not open a new one"
    );
    assert!(image.take_orset_skip(&r, 5_000), "the bound is per author");
    image.note_refusal(q, 1, 40_000);
    assert!(
        image.take_orset_skip(&q, 41_000),
        "the next window has its own skip"
    );
}

#[test]
fn the_orset_digest_binds_the_domain_tag_and_the_store_id() {
    let local = store_with(&[("k", b"one")]);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"x0x.kv.orset-digest.v1");
    hasher.update(local.id().as_bytes());
    hasher.update(&bincode::serialize(&local.keys_canonical_for_test()).expect("canonical"));
    assert_eq!(
        local.orset_digest().expect("digest"),
        *hasher.finalize().as_bytes()
    );
    let mut moved = KvStore::new(
        KvStoreId::new([10; 32]),
        "store".to_string(),
        AgentId([1; 32]),
        AccessPolicy::Signed,
    )
    .expect("store");
    moved
        .merge(&{
            let mut same = local.clone();
            same.set_id_for_test(KvStoreId::new([10; 32]));
            same
        })
        .expect("same OR-Set under another id");
    assert_eq!(
        bincode::serialize(&moved.keys_canonical_for_test()).expect("moved"),
        bincode::serialize(&local.keys_canonical_for_test()).expect("local"),
        "precondition: the same OR-Set"
    );
    assert_ne!(
        moved.orset_digest().expect("moved"),
        local.orset_digest().expect("local"),
        "the store id is bound"
    );
}

/// Every path that changes the OR-Set moves the cache key, so a cached
/// digest always equals a fresh one.
#[test]
fn the_cached_orset_digest_follows_every_path_that_changes_the_or_set() {
    fn check(store: &KvStore, path: &str) {
        assert_eq!(
            store.orset_digest().expect("cached"),
            store.orset_digest_uncached().expect("fresh"),
            "{path}"
        );
    }
    let owner = AgentId([1; 32]);
    let mut store = store_with(&[("k", b"one")]);
    let mut before = store.orset_digest().expect("first");
    let mut step = |store: &KvStore, path: &str| {
        check(store, path);
        let now = store.orset_digest().expect("now");
        assert_ne!(now, before, "{path} changed the OR-Set");
        before = now;
    };

    store
        .put(
            "a".into(),
            b"1".to_vec(),
            "text/plain".into(),
            PeerId::new([5; 32]),
        )
        .expect("put");
    step(&store, "put");
    store.remove("a").expect("remove");
    step(&store, "remove");

    let entry = KvEntry::new("d".to_string(), b"v".to_vec(), "text/plain".to_string());
    store
        .merge_delta(
            &KvStoreDelta::for_put("d".to_string(), entry, (PeerId::new([6; 32]), 1), 1),
            PeerId::new([6; 32]),
            Some(&owner),
        )
        .expect("delta add");
    step(&store, "delta add");
    let mut removal = KvStoreDelta::new(2);
    removal
        .removed
        .insert("d".to_string(), std::collections::HashSet::new());
    store
        .merge_delta(&removal, PeerId::new([6; 32]), Some(&owner))
        .expect("delta removal");
    step(&store, "delta removal");

    let mut other = store.clone();
    other
        .put(
            "img".into(),
            b"1".to_vec(),
            "text/plain".into(),
            PeerId::new([7; 32]),
        )
        .expect("put");
    store.merge(&other).expect("image merge");
    step(&store, "image merge");

    let cached = store.orset_digest().expect("cached");
    store.settle_loaded();
    check(&store, "settle");
    let loaded: KvStore =
        bincode::deserialize(&bincode::serialize(&store).expect("encode")).expect("load");
    check(&loaded, "load");
    assert_eq!(loaded.orset_digest().expect("loaded"), cached);
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
    let mut replica = store_with(&[("k", b"one"), ("gone", b"x")]);
    replica.remove("gone").expect("remove");
    assert_eq!(
        local.orset_digest().expect("local"),
        replica.orset_digest().expect("same state"),
        "same id and same OR-Set: the same digest"
    );
}

/// The cache on the production group path: a retained-image merge into an
/// encrypted store.
#[test]
fn the_cached_orset_digest_follows_a_group_image_merge() {
    let owner = AgentId([1; 32]);
    let mut info = crate::groups::GroupInfo::new(
        "kv-group".to_string(),
        String::new(),
        owner,
        "ab".repeat(16),
    );
    info.migrate_from_v1();
    let _ = info.rotate_shared_secret();
    let group_id = info.stable_group_id().as_bytes().to_vec();
    let ctx = Arc::new(crate::groups::GssKvSecureContext::from_group(&info).expect("ctx"));
    let mut store = KvStore::new_encrypted(
        KvStoreId::new([11; 32]),
        "Enc".to_string(),
        owner,
        group_id,
        ctx as Arc<dyn crate::kv::encrypted::KvSecureContext>,
    )
    .expect("store");
    store
        .put(
            "k".into(),
            b"1".to_vec(),
            "text/plain".into(),
            PeerId::new([5; 32]),
        )
        .expect("put");
    let before = store.orset_digest().expect("cached");
    let mut other = store.clone();
    other
        .put(
            "img".into(),
            b"1".to_vec(),
            "text/plain".into(),
            PeerId::new([7; 32]),
        )
        .expect("put");
    other.remove("k").expect("remove");
    store
        .merge_group_retained_image(&other.served_image_for_test(), owner, PeerId::new([8; 32]))
        .expect("image merge");
    let after = store.orset_digest().expect("cached");
    assert_ne!(after, before, "the merge changed the OR-Set");
    assert_eq!(after, store.orset_digest_uncached().expect("fresh"));
}
