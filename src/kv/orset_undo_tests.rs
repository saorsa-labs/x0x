#![cfg(test)]
//! #2146: a bounded delta that is applied and then refused is rolled back
//! from an OR-Set undo log of its touched keys, not from a copy of the
//! whole OR-Set. The store after the rollback is exactly the store before.

use super::tests::{agent, peer, put_delta, two_writer_group};
use super::*;

fn snapshots() -> u64 {
    SNAPSHOTS.with(std::cell::Cell::get)
}

fn undo_saves() -> u64 {
    DELTA_UNDO_SAVES.with(std::cell::Cell::get)
}

/// A JSON value with every object turned into a key-sorted list of pairs
/// and every array of arrays (a hash set of tags or agent ids) sorted, so
/// the hash-map order of a store does not change its form.
fn normalize(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut pairs: Vec<(String, Value)> =
                map.into_iter().map(|(k, v)| (k, normalize(v))).collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Array(
                pairs
                    .into_iter()
                    .map(|(k, v)| Value::Array(vec![Value::String(k), v]))
                    .collect(),
            )
        }
        Value::Array(items) => {
            let mut items: Vec<Value> = items.into_iter().map(normalize).collect();
            if !items.is_empty() && items.iter().all(Value::is_array) {
                items.sort_by_key(std::string::ToString::to_string);
            }
            Value::Array(items)
        }
        other => other,
    }
}

fn json(value: &impl Serialize) -> serde_json::Value {
    normalize(serde_json::to_value(value).expect("to json"))
}

/// Everything a store persists, in a hash-order-free form: the OR-Set
/// (live tags, tombstones, version, changelog floor and changelog), every
/// entry, the name register (value and clock at the test peers) and every
/// other field. Plus the local sequence counter, which is not persisted.
fn fingerprint(s: &KvStore) -> String {
    let entries: std::collections::BTreeMap<&String, serde_json::Value> =
        s.entries.iter().map(|(k, e)| (k, json(e))).collect();
    let mut writers: Vec<&AgentId> = s.allowed_writers.iter().collect();
    writers.sort_by_key(|a| *a.as_bytes());
    let clock: Vec<u64> = (0..4).map(|n| s.name.clock().get(&peer(n))).collect();
    format!(
        "keys={} entries={entries:?} name={:?}@{clock:?} policy={} owner={:?} writers={writers:?} \
         version={} checkpoint={} cp_seq={} anchor={:?} policy_version={} conflict={:?} \
         endorser={:?} orset_version={} changelog={} seq={}",
        json(&s.keys),
        s.name.get(),
        json(&s.policy),
        s.owner,
        s.version,
        json(&s.latest_checkpoint),
        s.highest_checkpoint_seq,
        s.anchor_channel,
        s.policy_version,
        s.ownership_conflict,
        s.last_history_endorser,
        s.keys.version(),
        s.keys.changelog_len(),
        s.seq_counter.load(std::sync::atomic::Ordering::SeqCst)
    )
}

/// The fingerprint and the cached content length, for a check that a
/// rollback also puts back the derived admission state.
fn full_state(s: &KvStore) -> (String, Option<u64>) {
    (
        fingerprint(s),
        s.image.cached_content(s.version, s.keys.version()),
    )
}

fn touched(delta: &KvStoreDelta) -> Vec<String> {
    delta
        .added
        .keys()
        .chain(delta.removed.keys())
        .chain(delta.updated.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn entry(key: &str, len: usize, byte: u8, at: u64) -> KvEntry {
    let mut entry = KvEntry::new(key.to_string(), vec![byte; len], "text/plain".to_string());
    entry.created_at = 1_000;
    entry.updated_at = 1_000 + at;
    entry
}

/// Apply `delta` in place exactly as the refused branch of
/// `merge_delta_bounded_inner` does, then roll it back.
fn apply_and_roll_back(
    s: &mut KvStore,
    delta: &KvStoreDelta,
    rollback: fn(&mut KvStore, &[String]) -> Rollback,
) {
    let content = s.content_exact().expect("content");
    let touched = touched(delta);
    let orset_before: i128 = touched
        .iter()
        .map(|key| i128::from(s.orset_key_len(key)))
        .sum();
    let snapshot = rollback(s, &touched);
    let mut journal = EntryJournal::default();
    if s.apply_delta_content(delta, Some(&agent(1)), &mut journal)
        .is_ok()
    {
        s.settle_and_measure(content, &touched, orset_before, &mut journal);
    }
    s.rollback(snapshot, journal).expect("rollback");
}

fn by_undo(s: &mut KvStore, touched: &[String]) -> Rollback {
    s.snapshot_for_delta(touched)
}

fn by_copy(s: &mut KvStore, _touched: &[String]) -> Rollback {
    s.snapshot_without_entries()
}

/// One random delta from peer 2: puts that win or lose, re-adds of a
/// tombstoned tag, add-and-remove of one key, removals, updates and
/// allowlist changes.
fn random_delta(
    s: &KvStore,
    keys: &[String],
    op: u8,
    key: usize,
    seq: u64,
    len: usize,
    at: u64,
) -> KvStoreDelta {
    let key = keys[key].clone();
    let next = keys[(keys.iter().position(|k| *k == key).unwrap_or(0) + 1) % keys.len()].clone();
    let mut delta = KvStoreDelta::new(s.version);
    match op {
        0 => {
            let stamp = if seq.is_multiple_of(2) { at + 1_000 } else { 0 };
            delta
                .added
                .insert(key.clone(), (entry(&key, len, b'd', stamp), (peer(2), seq)));
        }
        1 => {
            delta
                .added
                .insert(key.clone(), (entry(&key, len, b'b', at), (peer(2), seq)));
            delta.removed.insert(key, HashSet::new());
            delta.removed.insert(next, HashSet::new());
        }
        2 => {
            delta.removed.insert(key, HashSet::new());
        }
        3 => {
            delta
                .updated
                .insert(key.clone(), entry(&key, len, b'u', at));
        }
        _ => {
            delta.added.insert(
                key.clone(),
                (entry(&key, len, b'n', at), (peer(2), seq + 10)),
            );
            delta.added.insert(
                next.clone(),
                (entry(&next, len / 2, b'm', at), (peer(2), seq + 20)),
            );
            delta.allowlist_removals = Some(vec![agent(2)]);
            delta.allowlist_additions = Some(vec![agent(3)]);
        }
    }
    delta
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

    /// Random stores and random good and bad deltas. A good delta is
    /// merged into the store and into a reference store. A bad delta is
    /// applied in place under the undo log and rolled back; the store is
    /// then exactly as before (tags, tombstones, versions, entries, derived
    /// cached length), and equal to the reference that never saw it. The
    /// same bad delta under the old whole-OR-Set copy gives the same state.
    #[test]
    fn undo_rollback_restores_the_exact_prior_state(
        ops in proptest::collection::vec(
            (0u8..6, 0usize..5, 0u64..4, 0usize..300, proptest::bool::ANY),
            1..40,
        )
    ) {
        let keys: Vec<String> = (0..5).map(|i| format!("k{i}")).collect();
        let mut s = two_writer_group(80);
        let mut reference = s.clone();
        let mut at = 0u64;
        for (op, key, seq, len, bad) in ops {
            at += 1;
            if op == 5 {
                // A local removal, on both replicas.
                let _ = s.remove(&keys[key]);
                let _ = reference.remove(&keys[key]);
                continue;
            }
            let delta = random_delta(&s, &keys, op, key, seq, len, at);
            if bad {
                s.content_exact().expect("content");
                let before = full_state(&s);
                let mut copied = s.clone();
                apply_and_roll_back(&mut s, &delta, by_undo);
                proptest::prop_assert_eq!(&full_state(&s), &before);
                apply_and_roll_back(&mut copied, &delta, by_copy);
                proptest::prop_assert_eq!(full_state(&copied), before);
            } else {
                let kept = s.merge_delta(&delta, peer(2), Some(&agent(1))).is_ok();
                let reference_kept = reference
                    .merge_delta(&delta, peer(2), Some(&agent(1)))
                    .is_ok();
                proptest::prop_assert_eq!(kept, reference_kept);
            }
            proptest::prop_assert_eq!(fingerprint(&s), fingerprint(&reference));
        }
    }
}

/// A store of `keys` small keys plus a pad entry, whose admission image is
/// `room` bytes under the hard limit. The keys go straight into the OR-Set
/// and the entries (a put per key would measure the store each time).
fn many_keys_with_room(slot: u8, keys: u32, room: u64) -> KvStore {
    let mut s = two_writer_group(slot);
    for i in 0..keys {
        let key = format!("m{i:06}");
        s.keys
            .add(key.clone(), (peer(1), u64::from(i) + 1))
            .expect("add");
        s.entries.insert(key.clone(), entry(&key, 16, b'm', 0));
    }
    s.keys.compact(0);
    s.image.invalidate_content();
    let target = HARD_IMAGE_LIMIT_BYTES as u64 - room;
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

/// A delta whose lower bound fits but whose result does not: the newer
/// incoming `pad` entry wins and is `room` bytes too long.
fn over_after_apply(s: &KvStore, room: u64) -> KvStoreDelta {
    let local = s.get("pad").expect("pad").value.len();
    let mut delta = put_delta("pad", local + room as usize, b'q', (peer(2), 5), s.version);
    if let Some((entry, _)) = delta.added.get_mut("pad") {
        entry.updated_at += 1_000_000;
    }
    delta
}

/// The cost proof: in a store of 50 000 keys, a delta of one key that is
/// applied and refused saves one OR-Set element in its undo log and takes
/// no whole-OR-Set copy. The store is exactly as before, its cached length
/// included, and the next delta still fits.
#[test]
fn a_refused_delta_in_a_large_store_saves_only_its_keys() {
    let room = 300_000;
    let mut s = many_keys_with_room(81, 50_000, room);
    let delta = over_after_apply(&s, room);
    let lowest = i128::from(s.content_exact().expect("content"))
        + s.delta_lowest_growth(&delta, &touched(&delta))
            .expect("lowest");
    assert!(
        lowest <= i128::from(HARD_IMAGE_LIMIT_BYTES as u64),
        "passes the pre-check"
    );
    let before = full_state(&s);
    let (copies, saves) = (snapshots(), undo_saves());
    assert!(matches!(
        s.merge_delta(&delta, peer(2), Some(&agent(2))),
        Err(KvError::StoreFull { .. })
    ));
    assert_eq!(snapshots(), copies, "no whole-OR-Set copy");
    assert_eq!(undo_saves(), saves + 1, "one touched key saved");
    assert_eq!(full_state(&s), before, "exactly as before");
    s.merge_delta(
        &put_delta("small", 10, b's', (peer(2), 6), s.version),
        peer(2),
        Some(&agent(2)),
    )
    .expect("a delta that fits is still admitted");
}

/// Every refusal branch of the bounded delta path leaves the store exactly
/// as before: refused by the lower bound (no undo log at all) and refused
/// after the apply (undo log of the touched keys, one removed key and one
/// re-added key included).
#[test]
fn every_refusal_leaves_the_store_unchanged() {
    let room = 300_000;
    let mut s = many_keys_with_room(82, 2_000, room);
    // Lower bound: a new key larger than the room.
    let over = put_delta("new", room as usize + 1, b'n', (peer(2), 1), s.version);
    let before = full_state(&s);
    let (copies, saves) = (snapshots(), undo_saves());
    assert!(matches!(
        s.merge_delta(&over, peer(2), Some(&agent(2))),
        Err(KvError::StoreFull { .. })
    ));
    assert_eq!(
        (snapshots(), undo_saves()),
        (copies, saves),
        "nothing copied or saved"
    );
    assert_eq!(full_state(&s), before);

    // After the apply: a removal, a tombstoned re-add and the winning pad.
    let _ = s.remove("m000001");
    s.content_exact().expect("content");
    // The two removals free room, so the pad grows by more than `room`.
    let mut delta = over_after_apply(&s, room + 10_000);
    delta.removed.insert("m000000".to_string(), HashSet::new());
    delta.added.insert(
        "m000001".to_string(),
        (entry("m000001", 16, b'r', 5), (peer(1), 2)),
    );
    let before = full_state(&s);
    let (copies, saves) = (snapshots(), undo_saves());
    let refused = s.merge_delta(&delta, peer(2), Some(&agent(2)));
    assert!(
        matches!(refused, Err(KvError::StoreFull { .. })),
        "{refused:?}"
    );
    assert_eq!(snapshots(), copies);
    assert_eq!(undo_saves(), saves + 3, "pad, m000000 and m000001");
    assert_eq!(full_state(&s), before);
}

/// Measured cost for the PR (not a pass/fail bound): the old whole-OR-Set
/// copy against the undo log of one key, on 80 000 keys. Run with
/// `--ignored --nocapture`.
#[test]
#[ignore = "timing report only"]
fn report_rollback_state_cost() {
    let mut s = two_writer_group(83);
    for i in 0..80_000u32 {
        let key = format!("m{i:06}");
        s.keys
            .add(key.clone(), (peer(1), u64::from(i) + 1))
            .expect("add");
        s.entries.insert(key.clone(), entry(&key, 16, b'm', 0));
    }
    s.keys.compact(0);
    let rounds = 20u32;
    let start = std::time::Instant::now();
    for _ in 0..rounds {
        let snapshot = s.snapshot_without_entries();
        std::hint::black_box(&snapshot);
    }
    let copy = start.elapsed() / rounds;
    let one = ["m000001".to_string()];
    let start = std::time::Instant::now();
    for _ in 0..rounds {
        let snapshot = s.snapshot_for_delta(&one);
        std::hint::black_box(&snapshot);
    }
    let undo = start.elapsed() / rounds;
    eprintln!("80000 keys: whole-OR-Set copy {copy:?}, undo log of one key {undo:?}");
}
