#![cfg(test)]
//! #2110 item 1: a delta into a group store is measured in O(touched keys).
//! The cached content length is exact after every delta, and a delta over
//! the cheap bound walks no part of the store.

use super::tests::{agent, fill_canonical_to, peer, put_delta, two_writer_group};
use super::*;

fn full_measures() -> u64 {
    FULL_MEASURES.with(std::cell::Cell::get)
}

fn assert_cached_is_exact(s: &KvStore) {
    let cached = s
        .image
        .cached_content(s.version, s.keys.version())
        .expect("a delta merge leaves the content length cached");
    assert_eq!(cached, s.content_len().expect("content"));
    assert_eq!(
        s.retained_image_len().expect("measure"),
        bincode::serialized_size(s).expect("stored")
    );
}

fn snapshots() -> u64 {
    SNAPSHOTS.with(std::cell::Cell::get)
}

/// The pre-check's lower bound on the admission image after `delta`.
fn lowest_image(s: &mut KvStore, delta: &KvStoreDelta) -> i128 {
    let touched: BTreeSet<String> = delta
        .added
        .keys()
        .chain(delta.removed.keys())
        .chain(delta.updated.keys())
        .cloned()
        .collect();
    let touched: Vec<String> = touched.into_iter().collect();
    i128::from(s.content_exact().expect("content"))
        + s.delta_lowest_growth(delta, &touched).expect("lowest")
}

/// Merge `delta` and check that the pre-check's bound was not above the
/// admission image the merge produced.
fn merge_checked(s: &mut KvStore, delta: &KvStoreDelta) {
    let lowest = lowest_image(s, delta);
    s.merge_delta(delta, peer(2), Some(&agent(2)))
        .expect("delta");
    let image = i128::from(s.admission_image_len().expect("image"));
    assert!(lowest <= image, "lowest {lowest} > image {image}");
    assert_cached_is_exact(s);
}

fn entry(key: &str, len: usize, byte: u8, at: u64) -> KvEntry {
    let mut entry = KvEntry::new(key.to_string(), vec![byte; len], "text/plain".to_string());
    entry.updated_at += at;
    entry
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

    /// Local puts and removes, image merges and deltas with adds, removals
    /// (a key in both included), updates, re-added and tombstoned tags: the
    /// cached content length after each delta equals a full measure.
    #[test]
    fn incremental_measure_equals_full_measure(
        ops in proptest::collection::vec(
            (0u8..6, 0u8..5, 0u64..4, 0usize..400),
            1..40,
        )
    ) {
        let keys: Vec<String> = (0..5).map(|i| format!("k{i}")).collect();
        let mut s = two_writer_group(60);
        let mut other = s.clone();
        let mut at = 0u64;
        for (op, key, seq, len) in ops {
            at += 1;
            let key = keys[key as usize].clone();
            match op {
                0 => {
                    s.put(key, vec![b'p'; len], "text/plain".to_string(), peer(1))
                        .expect("put");
                }
                1 => {
                    let _ = s.remove(&key);
                }
                2 => {
                    let delta = KvStoreDelta::for_put(
                        key.clone(),
                        // An odd `seq` sends an entry that loses to the
                        // local one, so the merge keeps the local entry.
                        entry(&key, len, b'd', if seq % 2 == 0 { at + 1_000 } else { 0 }),
                        (peer(2), seq),
                        s.version,
                    );
                    other.merge_delta(&delta, peer(2), Some(&agent(2))).expect("other");
                    merge_checked(&mut s, &delta);
                }
                3 => {
                    let mut delta = KvStoreDelta::new(s.version);
                    delta.removed.insert(key.clone(), HashSet::new());
                    delta.added.insert(
                        key.clone(),
                        (entry(&key, len, b'b', at), (peer(2), seq)),
                    );
                    let next = keys[(keys.iter().position(|k| *k == key).unwrap_or(0) + 1) % 5].clone();
                    delta.removed.insert(next, HashSet::new());
                    merge_checked(&mut s, &delta);
                }
                4 => {
                    let mut delta = KvStoreDelta::new(s.version);
                    delta.updated.insert(key.clone(), entry(&key, len, b'u', at));
                    merge_checked(&mut s, &delta);
                }
                _ => {
                    let _ = other.remove(&key);
                    let image = other.served_image_for_test();
                    s.merge_group_retained_image(&image, agent(2), peer(1))
                        .expect("image");
                }
            }
        }
    }
}

/// A key in both `added` and `removed` of one delta is measured once, and
/// the removal applies after the add, so the key is gone.
#[test]
fn a_key_added_and_removed_in_one_delta_is_measured_once() {
    let mut s = two_writer_group(61);
    s.put(
        "k".to_string(),
        vec![b'v'; 100],
        "text/plain".to_string(),
        peer(1),
    )
    .expect("put");
    s.content_exact().expect("prime");
    let mut delta = KvStoreDelta::new(s.version);
    delta.removed.insert("k".to_string(), HashSet::new());
    delta
        .added
        .insert("k".to_string(), (entry("k", 300, b'n', 9), (peer(2), 7)));
    merge_checked(&mut s, &delta);
    assert!(s.get("k").is_none(), "added, then removed");
}

/// Over-bound deltas, admitted and refused, take no whole-store measure
/// once the content length is cached.
#[test]
fn over_bound_deltas_do_not_walk_the_store() {
    let hard = HARD_IMAGE_LIMIT_BYTES as u64;
    let mut s = two_writer_group(62);
    fill_canonical_to(&mut s, hard - 200_000, "f", peer(1));
    s.content_exact().expect("prime");
    let before = full_measures();
    let mut refused = 0u32;
    let mut admitted = 0u32;
    for i in 0..1_000u64 {
        // A 300 KB entry is over the cheap bound; a 100 KB one also passes
        // the exact measure, until the image fills.
        let len = if i % 2 == 0 { 300_000 } else { 100 };
        let delta = put_delta(&format!("o{i:04}"), len, b'o', (peer(2), 1 + i), s.version);
        match s.merge_delta(&delta, peer(2), Some(&agent(2))) {
            Ok(_) => admitted += 1,
            Err(KvError::StoreFull { .. }) => refused += 1,
            Err(e) => panic!("delta {i}: {e}"),
        }
    }
    assert_eq!(full_measures(), before, "no delta walked the store");
    assert!(
        refused > 0 && admitted > 0,
        "{refused} refused, {admitted} admitted"
    );
    assert_cached_is_exact(&s);
}

/// A store whose admission image is `room` bytes under the hard limit.
/// The pad's value length adds to the image byte for byte.
fn store_with_room(slot: u8, room: u64) -> KvStore {
    let target = HARD_IMAGE_LIMIT_BYTES as u64 - room;
    let mut s = two_writer_group(slot);
    fill_canonical_to(&mut s, target - 70_000, "f", peer(1));
    let pad = |len: u64, version| put_delta("pad", len as usize, b'p', (peer(1), 900_000), version);
    let mut probe = s.clone();
    probe
        .merge_delta(&pad(0, s.version), peer(1), Some(&agent(1)))
        .expect("probe pad");
    let len = target - probe.admission_image_len().expect("image");
    s.merge_delta(&pad(len, s.version), peer(1), Some(&agent(1)))
        .expect("pad");
    assert_eq!(s.admission_image_len().expect("image"), target);
    s
}

/// The pre-check at the boundary: a delta whose merged image is exactly
/// the hard limit is admitted, one byte more is refused before anything
/// is copied or applied.
#[test]
fn the_lower_bound_admits_an_exact_fit_and_refuses_one_byte_over() {
    let hard = HARD_IMAGE_LIMIT_BYTES as u64;
    let room = 300_000;
    let probe = put_delta("new", 0, b'n', (peer(2), 1), 0);
    let mut s = store_with_room(64, room);
    let empty = s.clone().admission_image_len().expect("image");
    let mut measured = s.clone();
    measured
        .merge_delta(&probe, peer(2), Some(&agent(2)))
        .expect("probe");
    let fit = (hard - empty) - (measured.admission_image_len().expect("image") - empty);

    let exact = put_delta("new", fit as usize, b'n', (peer(2), 1), s.version);
    assert_eq!(lowest_image(&mut s, &exact), i128::from(hard));
    let mut admitted = s.clone();
    admitted
        .merge_delta(&exact, peer(2), Some(&agent(2)))
        .expect("an exact fit is admitted");
    assert_eq!(admitted.admission_image_len().expect("image"), hard);

    let over = put_delta("new", fit as usize + 1, b'n', (peer(2), 1), s.version);
    let version = (s.version, s.keys.version());
    let before = snapshots();
    match s.merge_delta(&over, peer(2), Some(&agent(2))) {
        Err(KvError::StoreFull { image, .. }) => assert_eq!(image, hard + 1),
        other => panic!("one byte over: {other:?}"),
    }
    assert_eq!(snapshots(), before, "refused before the set is copied");
    assert_eq!((s.version, s.keys.version()), version, "nothing applied");
    assert!(s.get("new").is_none());
}

/// A delta whose lower bound fits but whose result does not goes through
/// the apply-and-roll-back path, which copies the OR-Set once.
#[test]
fn a_delta_over_only_after_apply_is_rolled_back() {
    let room = 300_000;
    let mut s = store_with_room(65, room);
    let local = s.get("pad").expect("pad").value.len();
    let mut delta = put_delta("pad", local + room as usize, b'q', (peer(2), 5), s.version);
    // Overwriting `pad` may keep the smaller local entry, so the bound
    // counts that and fits; the newer incoming entry wins and does not.
    if let Some((entry, _)) = delta.added.get_mut("pad") {
        entry.updated_at += 1_000_000;
    }
    assert!(lowest_image(&mut s, &delta) <= i128::from(HARD_IMAGE_LIMIT_BYTES as u64));
    let version = (s.version, s.keys.version());
    let before = snapshots();
    assert!(matches!(
        s.merge_delta(&delta, peer(2), Some(&agent(2))),
        Err(KvError::StoreFull { .. })
    ));
    assert_eq!(snapshots(), before + 1);
    assert_eq!((s.version, s.keys.version()), version);
    assert_cached_is_exact(&s);
}

/// The largest delta one frame can carry takes the slow path (its cheap
/// bound is over the limit, its result fits) and is measured from its own
/// keys: one rollback copy and no whole-store measure, for 150 000+ keys.
#[test]
fn a_largest_frame_delta_is_measured_from_its_keys() {
    let hard = HARD_IMAGE_LIMIT_BYTES as u64;
    let room = 300_000;
    let mut s = store_with_room(66, room);
    let limit = crate::network::MAX_MESSAGE_DESERIALIZE_SIZE;
    let mut probe = s.clone();
    probe
        .merge_delta(
            &put_delta("big", 0, b'b', (peer(2), 1), s.version),
            peer(2),
            Some(&agent(2)),
        )
        .expect("probe");
    // One byte under the exact fit: the result fits, and the cheap bound
    // (exact here plus the delta's optional fields) does not.
    let fit = hard - probe.admission_image_len().expect("image") - 1;
    let mut delta = put_delta("big", fit as usize, b'b', (peer(2), 1), s.version);
    let mut size = bincode::serialized_size(&(PeerId::new([2; 32]), &delta)).expect("size");
    let mut i = 0u32;
    loop {
        let key = format!("{i:x}");
        // A removal is the key string and an empty tag set.
        let add = 8 + key.len() as u64 + 8;
        if size + add > limit {
            break;
        }
        size += add;
        delta.removed.insert(key, HashSet::new());
        i += 1;
    }
    assert_eq!(
        bincode::serialized_size(&(PeerId::new([2; 32]), &delta)).expect("size"),
        size
    );
    assert!(
        delta.removed.len() > 150_000,
        "{} removals",
        delta.removed.len()
    );
    let (measures, copies) = (full_measures(), snapshots());
    s.merge_delta(&delta, peer(2), Some(&agent(2)))
        .expect("the result fits");
    assert_eq!(snapshots(), copies + 1, "the slow path ran");
    assert_eq!(full_measures(), measures, "no whole-store measure");
    assert_eq!(s.admission_image_len().expect("image"), hard - 1);
    assert_cached_is_exact(&s);
}

/// The lower bound never refuses a delta that fits: an older, larger entry
/// for a held key loses to the local one, so the merge adds nothing and is
/// admitted even though the incoming entry alone would not fit.
#[test]
fn the_lower_bound_counts_a_losing_incoming_entry_as_the_local_one() {
    let room = 300_000;
    let mut s = store_with_room(67, room);
    let local = s.get("pad").expect("pad").value.len();
    let mut delta = put_delta(
        "pad",
        local + room as usize + 1_000,
        b'o',
        (peer(2), 6),
        s.version,
    );
    if let Some((entry, _)) = delta.added.get_mut("pad") {
        entry.updated_at = 0;
    }
    assert!(lowest_image(&mut s, &delta) <= i128::from(HARD_IMAGE_LIMIT_BYTES as u64));
    s.merge_delta(&delta, peer(2), Some(&agent(2)))
        .expect("the losing entry adds nothing, so the delta fits");
    assert_eq!(s.get("pad").expect("pad").value.len(), local);
    assert_cached_is_exact(&s);
}
