//! Engine-level tests for ADR 0081: convergence with no delivery gate,
//! panic containment, peer-id uniqueness and the version token.
//!
//! These use only [`super::engine`] and [`super::error`], never a daemon or
//! the network.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::engine::{
    encode_version, EngineRecord, EngineShared, NoteActor, NotesEngine, OsPeerIdSource,
    PeerIdSource, MAX_CONSECUTIVE_FAULTS,
};
use super::error::NoteError;
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

/// Largest update per record in these tests (the store computes the real
/// limit from the inline cap).
const MAX_UPDATE: usize = 60 * 1024;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

fn shared() -> Arc<EngineShared> {
    Arc::new(EngineShared::new(Box::new(OsPeerIdSource), None))
}

async fn open(shared: &Arc<EngineShared>, key: &str) -> Arc<NoteActor> {
    NoteActor::open(
        Arc::clone(shared),
        key.to_string(),
        key.to_string(),
        Vec::new(),
    )
    .await
    .expect("open note")
}

/// Save `text` on `actor` at its current version and import the produced
/// records locally, as the store does after writing them.
async fn save(actor: &NoteActor, text: &str, label: &str, seq: &mut u64) -> Vec<EngineRecord> {
    let _guard = actor.lock_save().await;
    let view = actor.view().await.expect("view");
    let prepared = actor
        .prepare_save(text.to_string(), &view.version, MAX_UPDATE)
        .await
        .expect("prepare save");
    let records: Vec<EngineRecord> = prepared
        .updates
        .into_iter()
        .map(|update| {
            let id = format!("{label}/{seq}");
            *seq += 1;
            EngineRecord {
                id,
                update: Arc::new(update),
            }
        })
        .collect();
    actor.import(records.clone()).await.expect("local import");
    assert_eq!(
        actor.view().await.expect("view").text,
        text,
        "a save must produce exactly the submitted text"
    );
    records
}

/// Unique one-character tokens: a Myers diff can only insert or delete a
/// character that is absent from (or unique in) the other side, so each
/// token maps to exactly one CRDT insert and at most one delete.
fn token(n: u32) -> char {
    char::from_u32(0x4E00 + n).expect("CJK token")
}

/// Record deliveries with duplicates, in a seeded random order.
fn shuffled_with_dups(rng: &mut StdRng, records: &[EngineRecord]) -> Vec<EngineRecord> {
    let mut out: Vec<EngineRecord> = records.to_vec();
    for r in records {
        if rng.gen_bool(0.2) {
            out.push(r.clone());
        }
    }
    out.shuffle(rng);
    out
}

struct Replica {
    actor: Arc<NoteActor>,
    label: String,
    seq: u64,
    /// Records this replica holds (authored or received).
    held: Vec<EngineRecord>,
}

/// Outcome of one simulated run: every final text plus the tokens that must
/// survive.
struct RunResult {
    texts: Vec<String>,
    expected: BTreeSet<char>,
}

/// N replicas edit concurrently for `rounds` rounds, exchanging records
/// only within random partitions (shuffled, 20 % duplicates); then every
/// replica receives every record shuffled, and a fresh observer receives
/// every record in fully reversed order. No delivery gate anywhere.
async fn run_crdt(n: usize, rounds: usize, seed: u64) -> RunResult {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut replicas = Vec::new();
    for i in 0..n {
        let shared = shared();
        replicas.push(Replica {
            actor: open(&shared, &format!("note-{i}")).await,
            label: format!("r{i}"),
            seq: 0,
            held: Vec::new(),
        });
    }
    let mut next_token = 0u32;
    let mut inserted = BTreeSet::new();
    let mut deleted = BTreeSet::new();
    let mut all_records: Vec<EngineRecord> = Vec::new();
    for _ in 0..rounds {
        for replica in &mut replicas {
            let mut chars: Vec<char> = replica
                .actor
                .view()
                .await
                .expect("view")
                .text
                .chars()
                .collect();
            for _ in 0..rng.gen_range(1..=4) {
                if chars.is_empty() || rng.gen_bool(0.65) {
                    let t = token(next_token);
                    next_token += 1;
                    inserted.insert(t);
                    let at = rng.gen_range(0..=chars.len());
                    chars.insert(at, t);
                } else {
                    let at = rng.gen_range(0..chars.len());
                    deleted.insert(chars.remove(at));
                }
            }
            let text: String = chars.into_iter().collect();
            let label = replica.label.clone();
            let records = save(&replica.actor, &text, &label, &mut replica.seq).await;
            replica.held.extend(records.iter().cloned());
            all_records.extend(records);
        }
        // Partition: two random sides; records flow only within a side.
        let mut order: Vec<usize> = (0..n).collect();
        order.shuffle(&mut rng);
        let cut = rng.gen_range(1..=n);
        for side in [&order[..cut], &order[cut..]] {
            let pool: Vec<EngineRecord> = side
                .iter()
                .flat_map(|&i| replicas[i].held.clone())
                .collect();
            for &i in side {
                let delivery = shuffled_with_dups(&mut rng, &pool);
                replicas[i]
                    .actor
                    .import(delivery.clone())
                    .await
                    .expect("partition import");
                replicas[i].held.extend(delivery);
            }
        }
    }
    // Heal: everyone receives everything, shuffled with duplicates.
    for replica in &replicas {
        let delivery = shuffled_with_dups(&mut rng, &all_records);
        replica.actor.import(delivery).await.expect("heal import");
    }
    // A fresh observer gets every record in fully reversed order.
    let observer = open(&shared(), "observer").await;
    let mut reversed = all_records.clone();
    reversed.reverse();
    observer.import(reversed).await.expect("observer import");

    let mut texts = Vec::new();
    for replica in &replicas {
        texts.push(replica.actor.view().await.expect("view").text);
    }
    texts.push(observer.view().await.expect("view").text);
    RunResult {
        texts,
        expected: inserted.difference(&deleted).copied().collect(),
    }
}

/// The ADR's control: the old whole-value LWW path, run through the same
/// concurrent-round shape, must LOSE tokens.
fn run_lww(n: usize, seed: u64) -> RunResult {
    let mut rng = StdRng::seed_from_u64(seed);
    // (stamp, replica) → value; the highest stamp wins everywhere.
    let mut local: Vec<(u64, usize, String)> = (0..n).map(|i| (0, i, String::new())).collect();
    let mut inserted = BTreeSet::new();
    // One concurrent round: every replica inserts from the same base.
    for (i, slot) in local.iter_mut().enumerate() {
        let t = token(u32::try_from(i).expect("small n"));
        inserted.insert(t);
        let mut chars: Vec<char> = slot.2.chars().collect();
        let at = rng.gen_range(0..=chars.len());
        chars.insert(at, t);
        *slot = (1, i, chars.into_iter().collect());
    }
    let winner = local
        .iter()
        .max_by_key(|(stamp, replica, _)| (*stamp, *replica))
        .map(|(_, _, v)| v.clone())
        .unwrap_or_default();
    RunResult {
        texts: vec![winner; n],
        expected: inserted,
    }
}

/// `Err` describes the first violated convergence property.
fn check(result: &RunResult) -> Result<(), String> {
    let first = &result.texts[0];
    for (i, t) in result.texts.iter().enumerate() {
        if t != first {
            return Err(format!("replica {i} diverged: {t:?} vs {first:?}"));
        }
    }
    let present: BTreeSet<char> = first.chars().collect();
    let missing: Vec<char> = result.expected.difference(&present).copied().collect();
    if !missing.is_empty() {
        return Err(format!("lost surviving tokens {missing:?}"));
    }
    let extra: Vec<char> = present.difference(&result.expected).copied().collect();
    if !extra.is_empty() {
        return Err(format!("deleted tokens resurrected {extra:?}"));
    }
    if first.chars().count() != present.len() {
        return Err("a token appears more than once".into());
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    /// ADR 0081 Validation: N ∈ 2..=6 replicas, random concurrent inserts
    /// and deletes, shuffled / duplicated / partitioned delivery plus a fully
    /// reversed observer, and NO delivery gate. All replicas end identical
    /// and every surviving token is present exactly once.
    #[test]
    fn notes_converge_without_a_delivery_gate(n in 2usize..=6, rounds in 1usize..=4, seed in any::<u64>()) {
        let result = runtime().block_on(run_crdt(n, rounds, seed));
        prop_assert!(check(&result).is_ok(), "{:?}", check(&result));
    }
}

/// Ops a single diff-based update emits for `edits` one-character edits
/// over unique-character text, minus `edits` (0 = minimal).
fn extra_ops(options: loro::UpdateOptions, trials: u32) -> i32 {
    let mut rng = StdRng::seed_from_u64(1);
    let mut worst = 0i32;
    for trial in 0..trials {
        let doc = loro::LoroDoc::new();
        let text = doc.get_text(super::engine::TEXT_CONTAINER);
        let mut chars: Vec<char> = (0..rng.gen_range(1..12)).map(token).collect();
        let initial: String = chars.iter().collect();
        text.insert(0, &initial).expect("insert");
        doc.commit();
        let before = doc.oplog_vv().get(&doc.peer_id()).copied().unwrap_or(0);
        let mut edits = 0;
        for k in 0..rng.gen_range(1..4) {
            if rng.gen_bool(0.5) && !chars.is_empty() {
                let at = rng.gen_range(0..chars.len());
                chars.remove(at);
            } else {
                let at = rng.gen_range(0..=chars.len());
                chars.insert(at, token(100 + trial * 10 + k));
            }
            edits += 1;
        }
        let edited: String = chars.iter().collect();
        text.update(&edited, options.clone()).expect("update");
        doc.commit();
        let after = doc.oplog_vv().get(&doc.peer_id()).copied().unwrap_or(0);
        worst = worst.max((after - before) - edits);
    }
    worst
}

/// WHY (R9): a save that re-inserts an unchanged character creates a new op
/// that a concurrent delete of the original cannot remove, so deleted text
/// silently returns. The save path's diff must emit only edited characters.
/// Control: loro's default refined diff is NOT minimal on the same inputs,
/// so this test fails if the save path reverts to the default options.
#[test]
fn save_diff_emits_only_edited_characters() {
    assert_eq!(extra_ops(super::engine::save_diff_options(), 2000), 0);
    assert!(
        extra_ops(loro::UpdateOptions::default(), 2000) > 0,
        "control: the default refined diff re-inserts unchanged characters"
    );
}

/// The seed on which the property test first found resurrected deletes
/// (before `save_diff_options`), kept as a fixed regression case.
#[test]
fn convergence_regression_seed_resurrected_delete() {
    let result = runtime().block_on(run_crdt(6, 2, 18_179_927_475_986_488_634));
    assert!(check(&result).is_ok(), "{:?}", check(&result));
}

/// Control for the property test: whole-value LWW (the old Wiki path) fails
/// the same checker, so the checker can fail.
#[test]
fn lww_control_fails_the_convergence_checker() {
    for n in 2..=6 {
        let result = run_lww(n, 7);
        assert!(
            check(&result).is_err(),
            "LWW must lose a concurrent insert (n = {n})"
        );
    }
}

/// A peer-id source that returns queued values first, then CSPRNG values.
#[derive(Clone, Default)]
struct ScriptedPeers(Arc<Mutex<VecDeque<u64>>>);

impl ScriptedPeers {
    fn push(&self, id: u64) {
        self.0.lock().expect("queue").push_back(id);
    }
}

impl PeerIdSource for ScriptedPeers {
    fn draw(&self) -> u64 {
        if let Some(id) = self.0.lock().expect("queue").pop_front() {
            return id;
        }
        OsPeerIdSource.draw()
    }
}

/// Every (loro_peer, counter) pair a record set uses, via a scratch doc.
fn op_ids(records: &[EngineRecord]) -> Vec<(u64, i32)> {
    let doc = loro::LoroDoc::new();
    for r in records {
        doc.import(&r.update).expect("import for op ids");
    }
    let mut ids = Vec::new();
    for (peer, end) in doc.oplog_vv().iter() {
        for c in 0..*end {
            ids.push((*peer, c));
        }
    }
    ids
}

/// ADR 0081 §4 Validation: open, edit, save, then "kill" the daemon (drop
/// every in-memory object without any shutdown step), restart from the
/// same records and retired-set directory, open and edit — 1,000 times.
/// The RNG returns a colliding id first on every restart: the previous
/// session's id (in the doc's version vector) on even iterations, and an id
/// that was drawn and persisted but never used for an op (only in the
/// retired set) on odd ones. The redraw must reject both.
#[test]
fn peer_ids_are_unique_across_crash_restarts() {
    let rt = runtime();
    let dir = tempfile::tempdir().expect("tempdir");
    rt.block_on(async {
        let mut records: Vec<EngineRecord> = Vec::new();
        let mut seq = 0u64;
        let mut all_sessions: BTreeSet<u64> = BTreeSet::new();
        let mut previous_session: Option<u64> = None;
        let mut unused_session: Option<u64> = None;
        for i in 0..1000u32 {
            let peers = ScriptedPeers::default();
            let collide = if i % 2 == 0 {
                previous_session
            } else {
                unused_session
            };
            if let Some(id) = collide {
                peers.push(id);
            }
            let engine =
                NotesEngine::with_peer_source(Box::new(peers.clone()), Some(dir.path().into()));
            let before = engine.counters().peer_id_redraws;
            let actor = engine
                .get_or_open("store/note", "note", || records.clone())
                .await
                .expect("reopen");
            let session = actor.session_peer().await.expect("peer").expect("session");
            if collide.is_some() {
                assert!(
                    engine.counters().peer_id_redraws > before,
                    "iteration {i}: the colliding draw must be rejected"
                );
            }
            // Distinct from every id in the doc's version vector and every
            // retired id of earlier sessions.
            assert!(all_sessions.insert(session), "iteration {i}: id reused");
            let retired = actor.retired_peers().await.expect("retired");
            assert!(
                retired.contains(&session),
                "session id is persisted before use"
            );
            if i % 2 == 1 {
                // Leave a session that never writes: next odd restart must
                // still refuse its id (it lives only in the retired set).
                let text = format!("{}{}", actor.view().await.expect("v").text, token(i));
                records.extend(save(&actor, &text, "a", &mut seq).await);
                let rotated = actor.rotate_session().await.expect("rotate");
                assert!(all_sessions.insert(rotated));
                unused_session = Some(rotated);
            } else {
                let text = format!("{}{}", actor.view().await.expect("v").text, token(i));
                records.extend(save(&actor, &text, "a", &mut seq).await);
            }
            previous_session = Some(session);
            // "Kill": no clean shutdown, everything is just dropped.
            drop(actor);
            drop(engine);
        }
        let ids = op_ids(&records);
        let unique: BTreeSet<(u64, i32)> = ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "no (loro_peer, counter) pair is shared"
        );
    });
}

/// Colliding draws are redrawn, and a source that only collides fails
/// closed with `PeerIdExhausted` instead of reusing an id.
#[test]
fn exhausted_peer_source_fails_closed() {
    struct Always(u64);
    impl PeerIdSource for Always {
        fn draw(&self) -> u64 {
            self.0
        }
    }
    let rt = runtime();
    rt.block_on(async {
        let result = NoteActor::open(
            Arc::new(EngineShared::new(Box::new(Always(u64::MAX)), None)),
            "k".into(),
            "k".into(),
            Vec::new(),
        )
        .await;
        assert_eq!(result.err(), Some(NoteError::PeerIdExhausted));
    });
}

/// ADR 0081 §7: the version token round-trips; restoring it returns the
/// text of that version; a replica lacking the ops answers
/// `BaseVersionUnknown`; a stale base is refused; garbage is invalid.
#[test]
fn version_token_round_trips_and_restores() {
    let rt = runtime();
    rt.block_on(async {
        let a = open(&shared(), "a").await;
        let mut seq = 0;
        let mut records = save(&a, "alpha", "a", &mut seq).await;
        let v1 = a.view().await.expect("view").version;
        // Round trip of the token itself.
        let bytes = super::engine::decode_version_bytes(&v1).expect("decode");
        let frontiers = loro::Frontiers::decode(&bytes).expect("frontiers");
        assert_eq!(encode_version(&frontiers), v1);
        records.extend(save(&a, "alpha beta", "a", &mut seq).await);
        let v2 = a.view().await.expect("view").version;
        assert_ne!(v1, v2);
        assert_eq!(a.text_at(&v1).await.expect("restore v1"), "alpha");
        assert_eq!(a.text_at(&v2).await.expect("restore v2"), "alpha beta");

        // A replica holding only the first record knows v1, not v2.
        let b = open(&shared(), "b").await;
        b.import(records[..1].to_vec()).await.expect("import");
        assert_eq!(b.text_at(&v1).await.expect("restore on b"), "alpha");
        assert_eq!(b.text_at(&v2).await, Err(NoteError::BaseVersionUnknown));

        // A save against v1 on a, whose head is v2, is stale (the merge
        // path is a later slice).
        let stale = a.prepare_save("x".into(), &v1, MAX_UPDATE).await;
        assert_eq!(stale.err(), Some(NoteError::BaseVersionStale));
        let unknown = b.prepare_save("x".into(), &v2, MAX_UPDATE).await;
        assert_eq!(unknown.err(), Some(NoteError::BaseVersionUnknown));
        assert!(matches!(
            a.text_at("!!not-base64!!").await,
            Err(NoteError::InvalidVersion(_))
        ));
        // Trailing bytes after a valid encoding are refused, not ignored.
        let mut padded = super::engine::decode_version_bytes(&v1).expect("decode");
        padded.extend_from_slice(&[0, 0, 0]);
        let padded =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, padded);
        assert!(matches!(
            a.text_at(&padded).await,
            Err(NoteError::InvalidVersion(_))
        ));
    });
}

/// A save too large for one record splits into several, each within the
/// limit, and a replica that receives them in reverse order converges.
#[test]
fn large_saves_split_into_bounded_records() {
    let rt = runtime();
    rt.block_on(async {
        let a = open(&shared(), "a").await;
        let mut rng = StdRng::seed_from_u64(965);
        let text: String = (0..200_000)
            .map(|_| char::from(rng.gen_range(b'a'..=b'z')))
            .collect();
        let mut seq = 0;
        let mut records = save(&a, &text, "a", &mut seq).await;
        assert!(records.len() > 1, "200 KB must not fit one record");
        assert!(records.iter().all(|r| r.update.len() <= MAX_UPDATE));
        records.reverse();
        let b = open(&shared(), "b").await;
        b.import(records).await.expect("import");
        assert_eq!(b.view().await.expect("view").text, text);
    });
}

/// Malformed-bytes corpus (ADR 0081 §3 Validation). For every input the
/// daemon stays up, the input is refused (decode error) or contained
/// (engine fault → rebuild), the next valid record applies, and a second
/// note on the same engine is unaffected.
#[test]
fn malformed_records_are_contained() {
    let rt = runtime();
    rt.block_on(async {
        let engine_shared = shared();
        let victim = open(&engine_shared, "victim").await;
        let bystander = open(&engine_shared, "bystander").await;
        let mut seq = 0;
        save(&bystander, "untouched", "b", &mut seq).await;

        // A valid source doc producing good records for the victim.
        let author = open(&shared(), "author").await;
        let mut aseq = 0;
        let base = save(&author, "hello", "au", &mut aseq).await;
        victim.import(base.clone()).await.expect("base");
        let good = base[0].update.as_ref().clone();

        let mut rng = StdRng::seed_from_u64(1118);
        let mut corpus: Vec<(String, Vec<u8>)> = Vec::new();
        for len in [0usize, 1, 7, 64, 4096] {
            corpus.push((
                format!("random-{len}"),
                (0..len).map(|_| rng.gen()).collect(),
            ));
        }
        for cut in [1usize, good.len() / 2, good.len().saturating_sub(1)] {
            corpus.push((format!("truncated-{cut}"), good[..cut].to_vec()));
        }
        for bit in [0usize, 8, 40, good.len() * 8 / 2, good.len() * 8 - 1] {
            let mut flipped = good.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            corpus.push((format!("bitflip-{bit}"), flipped));
        }
        // Oversized length prefixes: the loro header followed by maximal
        // varints.
        let mut huge = good[..good.len().min(22)].to_vec();
        huge.extend(std::iter::repeat_n(0xFF, 64));
        corpus.push(("oversized-length".into(), huge));
        // #1118 shape: an update from a different doc that reuses the
        // victim-visible author's peer id with different content.
        let reuse = loro::LoroDoc::new();
        let author_peer = author.session_peer().await.expect("peer").expect("session");
        reuse.set_peer_id(author_peer).expect("peer");
        reuse
            .get_text(super::engine::TEXT_CONTAINER)
            .insert(0, "forged")
            .expect("insert");
        reuse.commit();
        corpus.push((
            "reused-peer-id".into(),
            reuse
                .export(loro::ExportMode::all_updates())
                .expect("export"),
        ));
        // #1068 shape: an update exported from a doc that was loaded from a
        // shallow snapshot of history the victim does not hold.
        let deep = loro::LoroDoc::new();
        deep.get_text(super::engine::TEXT_CONTAINER)
            .insert(0, "deep history")
            .expect("insert");
        deep.commit();
        let shallow_bytes = deep
            .export(loro::ExportMode::shallow_snapshot(&deep.oplog_frontiers()))
            .expect("shallow");
        let shallow = loro::LoroDoc::new();
        shallow.import(&shallow_bytes).expect("load shallow");
        let before = shallow.oplog_vv();
        shallow
            .get_text(super::engine::TEXT_CONTAINER)
            .insert(0, "x")
            .expect("insert");
        shallow.commit();
        corpus.push((
            "shallow-dependent".into(),
            shallow
                .export(loro::ExportMode::updates(&before))
                .expect("export"),
        ));

        for (i, (label, bytes)) in corpus.into_iter().enumerate() {
            let text_before = victim.view().await.expect("view").text;
            let outcome = victim
                .import(vec![EngineRecord {
                    id: format!("bad/{i}"),
                    update: Arc::new(bytes),
                }])
                .await;
            match outcome {
                Ok(_) => {
                    // Malformed bytes are refused or contained; they never
                    // change the text (a flip in a non-semantic header byte
                    // may still import as the same, already-held ops).
                    if !label.starts_with("reused") && !label.starts_with("shallow") {
                        let after = victim.view().await.expect("view").text;
                        assert_eq!(
                            after, text_before,
                            "{label}: malformed bytes changed the text"
                        );
                    }
                }
                Err(NoteError::Degraded { .. }) => {
                    panic!("{label}: one bad record degraded the note")
                }
                Err(other) => panic!("{label}: unexpected {other:?}"),
            }
            // The next valid record still applies.
            let text = format!(
                "{}{}",
                author.view().await.expect("v").text,
                token(i as u32)
            );
            let next = save(&author, &text, "au", &mut aseq).await;
            victim.import(next).await.expect("next valid record");
            let view = victim.view().await.expect("view");
            assert!(!view.degraded, "{label}: victim degraded");
            assert!(
                view.text.contains(token(i as u32)),
                "{label}: next record lost"
            );
        }
        let bystander_view = bystander.view().await.expect("bystander");
        assert_eq!(bystander_view.text, "untouched");
        assert!(!bystander_view.degraded);
    });
}

/// A panicking closure inside the isolation maps to `EngineFault`, the note
/// rebuilds from its records with a fresh peer id, and after
/// `MAX_CONSECUTIVE_FAULTS` faults in a row it is degraded: reads return the
/// last good text and writes are refused.
#[test]
fn panics_become_engine_faults_then_degrade() {
    let rt = runtime();
    rt.block_on(async {
        let engine_shared = shared();
        let actor = open(&engine_shared, "n").await;
        let mut seq = 0;
        save(&actor, "kept", "a", &mut seq).await;
        let first_peer = actor.session_peer().await.expect("peer");
        for round in 1..=MAX_CONSECUTIVE_FAULTS {
            let result: Result<(), NoteError> = actor
                .run_raw_for_test("boom", |_doc| panic!("injected loro panic"))
                .await;
            assert!(
                matches!(result, Err(NoteError::EngineFault { op: "boom", .. })),
                "round {round}: {result:?}"
            );
            let view = actor.view().await.expect("view");
            assert_eq!(view.text, "kept", "rebuilt from records");
            if round < MAX_CONSECUTIVE_FAULTS {
                assert!(!view.degraded);
                let peer = actor.session_peer().await.expect("peer");
                assert_ne!(peer, first_peer, "rebuild draws a fresh peer id");
            } else {
                assert!(view.degraded);
            }
        }
        let counters = engine_shared.counters().snapshot();
        assert_eq!(counters.engine_faults, u64::from(MAX_CONSECUTIVE_FAULTS));
        assert_eq!(counters.degraded_notes, 1);
        assert_eq!(
            counters.quarantined_poisoned_docs + counters.leaked_poisoned_docs,
            u64::from(MAX_CONSECUTIVE_FAULTS),
            "poisoned docs are quarantined, never dropped"
        );
        let view = actor.view().await.expect("view");
        let write = actor
            .prepare_save("new".into(), &view.version, MAX_UPDATE)
            .await;
        assert!(matches!(write, Err(NoteError::Degraded { .. })));
    });
}

/// A panic that escapes into the blocking task maps through
/// `JoinError::is_panic()` to the typed `EngineFault`.
#[test]
fn join_error_panics_map_to_engine_fault() {
    let rt = runtime();
    rt.block_on(async {
        let joined = tokio::task::spawn_blocking(|| -> Result<(), NoteError> {
            panic!("escaped the inner catch")
        })
        .await;
        let mapped = super::engine::map_join_result("escape", "n", joined);
        assert_eq!(
            mapped,
            Err(NoteError::EngineFault {
                note_id: "n".into(),
                op: "escape"
            })
        );
    });
}
