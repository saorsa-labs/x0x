//! Engine-level tests for ADR 0081: convergence with no delivery gate,
//! panic containment, peer-id uniqueness and the version token.
//!
//! These use only [`super::engine`] and [`super::error`], never a daemon or
//! the network.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::engine::{
    encode_version, EngineRecord, EngineShared, NoteActor, NotesEngine, OsPeerIdSource,
    PeerIdSource, LINE_DIFF_THRESHOLD_BYTES, MAX_CONSECUTIVE_FAULTS,
};
use super::error::NoteError;
use super::text_diff::{
    apply_edit_script, edit_script, Budgets, DiffRung, TooLargeToMergeSafely, EXACT_WORK_BUDGET,
    LINE_WORK_BUDGET,
};
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

// ---------------------------------------------------------------------
// #1029: saves above LINE_DIFF_THRESHOLD_BYTES.
// ---------------------------------------------------------------------

/// Unique token `n` for the large-note tests: planes 1 and up (4 UTF-8
/// bytes, never a newline), so about 66 000 of them exceed 256 KiB.
fn big_token(n: u32) -> char {
    char::from_u32(0x1_0000 + n).expect("scalar value")
}

/// One edit of B's save, in base-text character positions.
enum BEdit {
    /// Insert `run` before `base[at]`.
    Insert { at: usize, run: Vec<char> },
    /// Delete `base[from..to]`.
    Delete { from: usize, to: usize },
}

/// A deletes a region of a note above the threshold while B concurrently
/// saves one to three edits elsewhere, mostly on the lines A's region
/// touches.
struct LargeScenario {
    base: String,
    a_text: String,
    b_text: String,
    /// Both saves applied to `base`: the only correct merge.
    expected: String,
    /// Tokens A or B deleted.
    deleted: BTreeSet<char>,
    /// Characters B's save changes (inserted plus deleted).
    b_edited: usize,
}

/// Every edit starts and ends on a token and keeps at least one surviving
/// character between it and any other edit, so exactly one minimal edit
/// script exists for each save and `expected` is the unique correct merge.
fn large_scenario(seed: u64) -> LargeScenario {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut next = 0u32;
    let mut base: Vec<char> = Vec::new();
    let mut bytes = 0;
    while bytes <= LINE_DIFF_THRESHOLD_BYTES + 4096 {
        base.push(big_token(next));
        next += 1;
        bytes += 4;
        if rng.gen_bool(0.15) {
            base.push('\n');
            bytes += 1;
            if rng.gen_bool(0.2) {
                base.push('\n');
                bytes += 1;
            }
        }
    }
    let len = base.len();
    // A: delete base[a0..a1], 1..=300 characters, first and last a token.
    let mut a0 = rng.gen_range(1000..len - 1000);
    while base[a0] == '\n' {
        a0 += 1;
    }
    let mut a1 = (a0 + rng.gen_range(1..=300)).max(a0 + 1);
    while base[a1 - 1] == '\n' {
        a1 -= 1;
    }
    // Reserved closed intervals: an edit plus one neighbour on each side.
    let mut reserved: Vec<(usize, usize)> = vec![(a0 - 1, a1)];
    let free = |reserved: &[(usize, usize)], lo: usize, hi: usize| {
        reserved.iter().all(|&(l, h)| hi < l || lo > h)
    };
    let mut edits = Vec::new();
    for _ in 0..rng.gen_range(1..=3) {
        for _attempt in 0..100 {
            // Mostly on the lines A's region touches, where a whole-line
            // diff re-inserts what A deleted.
            let at = match rng.gen_range(0..4) {
                0 | 1 if rng.gen_bool(0.5) => a0 - rng.gen_range(2..10),
                0 | 1 => a1 + rng.gen_range(2..10),
                2 => rng.gen_range(a0 - 120..a1 + 120),
                _ => rng.gen_range(1..len - 1),
            };
            if rng.gen_bool(0.5) {
                if !free(&reserved, at - 1, at) {
                    continue;
                }
                let mut run = vec![big_token(next)];
                next += 1;
                for _ in 0..rng.gen_range(0..12) {
                    if rng.gen_bool(0.3) {
                        run.push('\n');
                    }
                    run.push(big_token(next));
                    next += 1;
                }
                reserved.push((at - 1, at));
                edits.push(BEdit::Insert { at, run });
            } else {
                let to = (at + rng.gen_range(1..=8)).min(len - 1);
                if base[at..to].contains(&'\n') || !free(&reserved, at - 1, to) {
                    continue;
                }
                reserved.push((at - 1, to));
                edits.push(BEdit::Delete { from: at, to });
            }
            break;
        }
    }
    let mut inserts: Vec<Vec<char>> = vec![Vec::new(); len + 1];
    let mut b_deleted = vec![false; len];
    let mut b_edited = 0;
    for e in &edits {
        match e {
            BEdit::Insert { at, run } => {
                inserts[*at].extend(run);
                b_edited += run.len();
            }
            BEdit::Delete { from, to } => {
                b_deleted[*from..*to].iter_mut().for_each(|d| *d = true);
                b_edited += to - from;
            }
        }
    }
    let (mut a_text, mut b_text, mut expected) = (String::new(), String::new(), String::new());
    let mut deleted = BTreeSet::new();
    for i in 0..=len {
        b_text.extend(&inserts[i]);
        expected.extend(&inserts[i]);
        let Some(&c) = base.get(i) else { break };
        let by_a = (a0..a1).contains(&i);
        if !by_a {
            a_text.push(c);
        }
        if !b_deleted[i] {
            b_text.push(c);
        }
        if by_a || b_deleted[i] {
            if c != '\n' {
                deleted.insert(c);
            }
        } else {
            expected.push(c);
        }
    }
    LargeScenario {
        base: base.into_iter().collect(),
        a_text,
        b_text,
        expected,
        deleted,
        b_edited,
    }
}

/// `Err` names the first way a merged text differs from the only correct
/// merge: deleted text back, a duplicated token or line, or other drift.
fn check_large(s: &LargeScenario, texts: &[String]) -> Result<(), String> {
    for (i, t) in texts.iter().enumerate() {
        if *t == s.expected {
            continue;
        }
        let back = t.chars().filter(|c| s.deleted.contains(c)).count();
        if back > 0 {
            return Err(format!("replica {i}: {back} deleted characters came back"));
        }
        let mut seen = BTreeSet::new();
        if t.chars().filter(|&c| c != '\n').any(|c| !seen.insert(c)) {
            return Err(format!("replica {i}: a character appears twice"));
        }
        let mut lines = BTreeSet::new();
        if t.lines()
            .filter(|l| !l.is_empty())
            .any(|l| !lines.insert(l))
        {
            return Err(format!("replica {i}: a line appears twice"));
        }
        return Err(format!("replica {i} differs from the expected merge"));
    }
    Ok(())
}

/// The scenario through the real save path: engine actors, records
/// exchanged shuffled with duplicates, and a fresh observer that receives
/// every record in reverse order.
async fn run_large_engine(s: &LargeScenario, seed: u64) -> Vec<String> {
    let mut rng = StdRng::seed_from_u64(seed ^ 1029);
    let a = open(&shared(), "a").await;
    let b = open(&shared(), "b").await;
    let (mut seq_a, mut seq_b) = (0, 0);
    let base = save(&a, &s.base, "a", &mut seq_a).await;
    b.import(base.clone()).await.expect("base import");
    let from_a = save(&a, &s.a_text, "a", &mut seq_a).await;
    let from_b = save(&b, &s.b_text, "b", &mut seq_b).await;
    a.import(shuffled_with_dups(&mut rng, &from_b))
        .await
        .expect("a imports b");
    b.import(shuffled_with_dups(&mut rng, &from_a))
        .await
        .expect("b imports a");
    let observer = open(&shared(), "observer").await;
    let mut all: Vec<EngineRecord> = base.into_iter().chain(from_a).chain(from_b).collect();
    all.reverse();
    observer.import(all).await.expect("observer import");
    let mut texts = Vec::new();
    for actor in [&a, &b, &observer] {
        texts.push(actor.view().await.expect("view").text);
    }
    texts
}

/// The scenario on plain loro docs, each save made by `diff`. Returns the
/// merged texts and the ops B's save emitted.
fn run_large_loro(s: &LargeScenario, diff: fn(&loro::LoroText, &str)) -> (Vec<String>, usize) {
    let text = |d: &loro::LoroDoc| d.get_text(super::engine::TEXT_CONTAINER);
    let a = loro::LoroDoc::new();
    a.set_peer_id(1).expect("peer");
    text(&a).insert(0, &s.base).expect("base");
    a.commit();
    let b = loro::LoroDoc::new();
    b.set_peer_id(2).expect("peer");
    b.import(&a.export(loro::ExportMode::all_updates()).expect("export"))
        .expect("import");
    diff(&text(&a), &s.a_text);
    a.commit();
    diff(&text(&b), &s.b_text);
    b.commit();
    let b_ops = b.oplog_vv().get(&2).copied().unwrap_or(0);
    let from_a = a.export(loro::ExportMode::all_updates()).expect("export");
    let from_b = b.export(loro::ExportMode::all_updates()).expect("export");
    a.import(&from_b).expect("import");
    b.import(&from_a).expect("import");
    let texts = vec![text(&a).to_string(), text(&b).to_string()];
    (texts, usize::try_from(b_ops).expect("ops"))
}

fn diff_by_edit_script(text: &loro::LoroText, new: &str) {
    apply_edit_script(text, new, Budgets::DEFAULT).expect("edit script");
}

fn diff_by_line(text: &loro::LoroText, new: &str) {
    text.update_by_line(new, super::engine::save_diff_options())
        .expect("update_by_line");
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    /// #1029: on a note above 256 KiB, A deletes a region while B saves
    /// edits elsewhere, often on the same lines. After every replica
    /// merges, the text is exactly both edits applied: the deleted text is
    /// gone and no character or line appears twice.
    #[test]
    fn large_save_never_resurrects_a_concurrent_delete(seed in any::<u64>()) {
        let s = large_scenario(seed);
        prop_assert!(s.base.len() > LINE_DIFF_THRESHOLD_BYTES);
        let texts = runtime().block_on(run_large_engine(&s, seed));
        prop_assert!(check_large(&s, &texts).is_ok(), "{:?}", check_large(&s, &texts));
    }
}

/// #1029 fixed cases: seeds on which `update_by_line` brings deleted text
/// back (see the control below) converge exactly through the save path.
#[test]
fn large_save_regression_seeds_converge() {
    for seed in [4, 11] {
        let s = large_scenario(seed);
        let texts = runtime().block_on(run_large_engine(&s, seed));
        assert!(
            check_large(&s, &texts).is_ok(),
            "seed {seed}: {:?}",
            check_large(&s, &texts)
        );
    }
}

/// Control for the property test: loro's `update_by_line`, the diff
/// ADR 0081 §8 named for large saves, fails the same checker on the same
/// scenarios (it re-inserts whole changed lines), so the checker can fail.
#[test]
fn update_by_line_control_resurrects_deleted_text() {
    let failures: Vec<u64> = (0..16)
        .filter(|&seed| {
            let s = large_scenario(seed);
            check_large(&s, &run_large_loro(&s, diff_by_line).0).is_err()
        })
        .collect();
    assert!(
        !failures.is_empty(),
        "control: update_by_line must bring deleted text back on some seed"
    );
    assert!(
        failures.contains(&4) && failures.contains(&11),
        "{failures:?}"
    );
}

/// WHY (R9): a large save must emit an op only for a character the user
/// changed; any re-inserted unchanged character is one a concurrent
/// delete cannot remove. Control: `update_by_line` emits many more.
#[test]
fn large_save_emits_only_edited_characters() {
    let mut by_line_extra = 0;
    for seed in 0..16 {
        let s = large_scenario(seed);
        let (texts, ops) = run_large_loro(&s, diff_by_edit_script);
        assert_eq!(ops, s.b_edited, "seed {seed}: extra ops");
        assert!(check_large(&s, &texts).is_ok(), "seed {seed}");
        by_line_extra += run_large_loro(&s, diff_by_line).1 - s.b_edited;
    }
    assert!(
        by_line_extra > 0,
        "control: update_by_line re-inserts lines"
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    /// Whatever the budgets, the edit script either reproduces the new text
    /// or refuses; with the production budgets it never refuses these, and
    /// on the exact rung it replaces nothing whole.
    #[test]
    fn edit_script_reproduces_text_under_any_budget(
        old in "[ab\n\u{e9}\u{4e00}]{0,40}",
        new in "[ab\n\u{e9}\u{4e00}]{0,40}",
        exact in prop_oneof![0u64..64, Just(EXACT_WORK_BUDGET)],
        line in prop_oneof![0u64..64, Just(LINE_WORK_BUDGET)],
    ) {
        let budgets = Budgets { exact, line };
        let Ok(script) = edit_script(&old, &new, budgets) else {
            prop_assert!(budgets != Budgets::DEFAULT, "default budgets refused a tiny edit");
            return Ok(());
        };
        let mut out = old.clone();
        for e in script.edits.iter().rev() {
            out.replace_range(e.old_start..e.old_end, &new[e.new_start..e.new_end]);
        }
        prop_assert_eq!(&out, &new);
        prop_assert!(script.edits.windows(2).all(|w| w[0].old_end <= w[1].old_start));
        if script.rung == DiffRung::Exact {
            prop_assert_eq!(script.replaced_lines, 0);
        }
        let doc = loro::LoroDoc::new();
        let text = doc.get_text(super::engine::TEXT_CONTAINER);
        text.insert(0, &old).expect("insert");
        apply_edit_script(&text, &new, budgets).expect("apply");
        prop_assert_eq!(text.to_string(), new);
    }
}

/// Ladder rung 2's bound: with both budgets spent, a save that changes some
/// lines replaces exactly those lines whole, never an unchanged one and
/// never a region spanning them.
#[test]
fn spent_budgets_replace_only_the_changed_lines() {
    let old: String = (0..50).map(|i| format!("line {i} of the note\n")).collect();
    let mut new = old.clone();
    for i in [3, 4, 5, 20, 41] {
        new = new.replace(&format!("line {i} of"), &format!("LINE {i} of"));
    }
    let exact = edit_script(&old, &new, Budgets::DEFAULT).expect("exact");
    assert_eq!((exact.rung, exact.replaced_lines), (DiffRung::Exact, 0));
    let spent = edit_script(&old, &new, Budgets { exact: 0, line: 0 }).expect("line rung");
    assert_eq!(spent.rung, DiffRung::LinePaired);
    assert_eq!(spent.replaced_lines, 5);
    for e in &spent.edits {
        let replaced = &old[e.old_start..e.old_end];
        assert!(
            replaced.starts_with("line ") && replaced.matches('\n').count() == 1,
            "only one whole changed line per edit: {replaced:?}"
        );
    }
}

/// Ladder rung 3: when neither the character diff nor the line alignment
/// fits the budgets and the line counts differ, there is no safe script,
/// and the diff refuses rather than replacing the region.
#[test]
fn unalignable_save_is_refused_not_replaced() {
    let old: String = (0..40).map(|i| format!("old {i}\n")).collect();
    let new: String = (0..41).map(|i| format!("new {i}\n")).collect();
    let refused = edit_script(&old, &new, Budgets { exact: 0, line: 0 });
    assert_eq!(
        refused,
        Err(TooLargeToMergeSafely {
            old_lines: 40,
            new_lines: 41,
        })
    );
    assert!(edit_script(&old, &new, Budgets::DEFAULT).is_ok());
}

/// A note of `lines` distinct 141-byte ASCII lines (140 + `\n`).
fn codex_note(lines: usize) -> String {
    let mut rng = StdRng::seed_from_u64(1029);
    (0..lines)
        .map(|k| {
            let body: String = (0..133)
                .map(|_| char::from(rng.gen_range(b'a'..=b'z')))
                .collect();
            format!("L{k:05}:{body}\n")
        })
        .collect()
}

/// B's side of Codex's case: one character changed on every line (column
/// 70 becomes `X`, which no old line holds there).
fn change_every_line(base: &str) -> String {
    base.lines()
        .map(|l| format!("{}X{}\n", &l[..70], &l[71..]))
        .collect()
}

/// A region of line `line` that A deletes: `from..to` bytes of the note,
/// clear of column 70, and with no equal character across either edge, so
/// A's minimal script is unique.
fn codex_delete(base: &str, line: usize) -> (usize, usize) {
    let start = line * 141;
    let b = base.as_bytes();
    let mut from = start + 10;
    let mut to = start + 60;
    while b[from - 1] == b[to - 1] || b[from] == b[to] {
        from += 1;
        to -= 1;
    }
    (from, to)
}

/// #1029 review (Codex, P1): 3,000 one-character edits across a 423 KB
/// note (0.7 % changed) while A concurrently deletes 50 characters of
/// line 1,500. The exact rung runs out; before the ladder the whole
/// 422,860-character region was re-inserted and A's delete undone. Now
/// every replica ends with exactly both edits and nothing replaced whole.
#[test]
fn codex_3000_edit_save_keeps_a_concurrent_delete() {
    let base = codex_note(3000);
    assert_eq!(base.len(), 423_000);
    let b_text = change_every_line(&base);
    let (from, to) = codex_delete(&base, 1500);
    let a_text = format!("{}{}", &base[..from], &base[to..]);
    let expected = format!("{}{}", &b_text[..from], &b_text[to..]);
    let deleted = &base[from..to];
    let texts = runtime().block_on(async {
        let a = open(&shared(), "a").await;
        let b = open(&shared(), "b").await;
        let (mut seq_a, mut seq_b) = (0, 0);
        let first = save(&a, &base, "a", &mut seq_a).await;
        b.import(first).await.expect("base import");
        let from_a = save(&a, &a_text, "a", &mut seq_a).await;
        let view = b.view().await.expect("view");
        let prepared = b
            .prepare_save(b_text.clone(), &view.version, MAX_UPDATE)
            .await
            .expect("prepare");
        let report = prepared.large_save.expect("a large save");
        assert_eq!(report.replaced_lines, 0, "{report:?}");
        let from_b: Vec<EngineRecord> = prepared
            .updates
            .into_iter()
            .map(|update| {
                seq_b += 1;
                EngineRecord {
                    id: format!("b/{seq_b}"),
                    update: Arc::new(update),
                }
            })
            .collect();
        b.import(from_b.clone()).await.expect("b local");
        a.import(from_b).await.expect("a imports b");
        b.import(from_a).await.expect("b imports a");
        let mut texts = Vec::new();
        for actor in [&a, &b] {
            texts.push(actor.view().await.expect("view").text);
        }
        texts
    });
    for (i, t) in texts.iter().enumerate() {
        assert!(
            !t.contains(deleted),
            "replica {i}: A's deleted text came back"
        );
        assert!(
            *t == expected,
            "replica {i} differs from the expected merge"
        );
    }
}

/// Rung 3 through the save path: 3,000 changed lines plus one inserted
/// line in one place cannot be aligned within the budgets, so the save is
/// refused with `EditTooLargeToMergeSafely` (422), nothing is applied, and
/// the refusal is counted.
#[test]
fn unmergeable_large_save_fails_closed_with_a_typed_error() {
    let base = codex_note(3000);
    let mut edited = change_every_line(&base);
    edited.insert_str(141 * 1500, "an inserted line\n");
    runtime().block_on(async {
        let shared = shared();
        let a = open(&shared, "a").await;
        let mut seq = 0;
        save(&a, &base, "a", &mut seq).await;
        let view = a.view().await.expect("view");
        let refused = a
            .prepare_save(edited, &view.version, MAX_UPDATE)
            .await
            .expect_err("must refuse");
        assert!(
            matches!(
                refused,
                NoteError::EditTooLargeToMergeSafely {
                    old_lines: 3000,
                    new_lines: 3001
                }
            ),
            "{refused:?}"
        );
        assert_eq!(refused.reason(), "note_edit_too_large_to_merge_safely");
        let after = a.view().await.expect("view");
        assert_eq!(after.text, base, "nothing applied");
        assert_eq!(after.version, view.version);
        let counters = shared.counters().snapshot();
        assert_eq!(counters.large_saves_refused, 1);
        assert_eq!(counters.engine_faults, 0, "a refusal is not a fault");
    });
}

/// Scattered-edit scenario over a >256 KiB note of unique tokens: B changes
/// one token on each of `edits` lines (a contiguous block plus scattered
/// lines, so the exact rung runs out on the block) while A deletes a
/// token-edged region clear of every B edit.
fn scattered_scenario(seed: u64, edits: usize) -> LargeScenario {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut next = 0u32;
    let lines = 3000;
    let mut base_lines: Vec<Vec<char>> = (0..lines)
        .map(|_| {
            (0..rng.gen_range(20..=40))
                .map(|_| {
                    next += 1;
                    big_token(next)
                })
                .collect()
        })
        .collect();
    // B: which lines and which column.
    let block = edits * 3 / 4;
    let block_start = rng.gen_range(0..lines - block);
    let mut changed: BTreeSet<usize> = (block_start..block_start + block).collect();
    while changed.len() < edits {
        changed.insert(rng.gen_range(0..lines));
    }
    let cols: Vec<Option<usize>> = (0..lines)
        .map(|l| {
            changed
                .contains(&l)
                .then(|| rng.gen_range(0..base_lines[l].len()))
        })
        .collect();
    // A: one line's tokens a0..a1, at least one token clear of B's column.
    let mut a_line;
    let (mut a0, mut a1);
    loop {
        a_line = rng.gen_range(0..lines);
        let len = base_lines[a_line].len();
        a0 = rng.gen_range(0..len - 1);
        a1 = rng.gen_range(a0 + 1..=len);
        match cols[a_line] {
            Some(c) if c + 1 >= a0 && c <= a1 => continue,
            _ => break,
        }
    }
    let (mut base, mut a_text, mut b_text, mut expected) =
        (String::new(), String::new(), String::new(), String::new());
    let mut deleted = BTreeSet::new();
    let mut b_edited = 0;
    for (l, tokens) in base_lines.iter_mut().enumerate() {
        for (k, &t) in tokens.iter().enumerate() {
            let by_a = l == a_line && (a0..a1).contains(&k);
            let by_b = cols[l] == Some(k);
            base.push(t);
            if !by_a {
                a_text.push(t);
            }
            if by_b {
                next += 1;
                b_text.push(big_token(next));
                expected.push(big_token(next));
                b_edited += 2;
            } else {
                b_text.push(t);
            }
            if by_a || by_b {
                deleted.insert(t);
            } else {
                expected.push(t);
            }
        }
        for s in [&mut base, &mut a_text, &mut b_text, &mut expected] {
            s.push('\n');
        }
    }
    LargeScenario {
        base,
        a_text,
        b_text,
        expected,
        deleted,
        b_edited,
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 6,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    /// #1029 review: hundreds to thousands of scattered one-character edits
    /// on a note above 256 KiB, with a concurrent delete, through the real
    /// save path. Whatever rung the diff needs, the deleted text never
    /// comes back and every replica ends with exactly both edits.
    #[test]
    fn scattered_edits_never_resurrect_a_concurrent_delete(
        seed in any::<u64>(),
        edits in 200usize..=3000,
    ) {
        let s = scattered_scenario(seed, edits);
        prop_assert!(s.base.len() > LINE_DIFF_THRESHOLD_BYTES);
        let texts = runtime().block_on(run_large_engine(&s, seed));
        prop_assert!(check_large(&s, &texts).is_ok(), "{:?}", check_large(&s, &texts));
    }
}

/// On either rung the scattered scenario stays character-exact:
/// B's save emits one op per changed character and replaces no line.
#[test]
fn scattered_edits_use_the_line_rung_without_replacing_lines() {
    // 3,000 edits (a 2,250-line block) exhaust the exact rung; 1,500 do not.
    for (seed, edits, rung) in [(1, 3000, DiffRung::LinePaired), (2, 1500, DiffRung::Exact)] {
        let s = scattered_scenario(seed, edits);
        let text = loro::LoroDoc::new();
        let root = text.get_text(super::engine::TEXT_CONTAINER);
        root.insert(0, &s.base).expect("base");
        text.commit();
        let before = text.oplog_vv().get(&text.peer_id()).copied().unwrap_or(0);
        let script = apply_edit_script(&root, &s.b_text, Budgets::DEFAULT).expect("apply");
        text.commit();
        let after = text.oplog_vv().get(&text.peer_id()).copied().unwrap_or(0);
        assert_eq!(script.rung, rung, "seed {seed}");
        assert_eq!(script.replaced_lines, 0, "seed {seed}");
        assert_eq!(
            usize::try_from(after - before).expect("ops"),
            s.b_edited,
            "seed {seed}"
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
///
/// Each restart reopens from ONE update carrying the whole history (every
/// op, every peer), so the reopen cost stays linear: re-importing the
/// growing record list one record at a time is quadratic and timed out
/// in CI, where the loro dependency builds without optimisation.
#[test]
fn peer_ids_are_unique_across_crash_restarts() {
    let rt = runtime();
    let dir = tempfile::tempdir().expect("tempdir");
    rt.block_on(async {
        let mut records: Vec<EngineRecord> = Vec::new();
        let history = loro::LoroDoc::new();
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
            let snapshot = history
                .export(loro::ExportMode::all_updates())
                .expect("history export");
            let actor = engine
                .get_or_open("store/note", "note", || {
                    vec![EngineRecord {
                        id: "history".into(),
                        update: Arc::new(snapshot),
                    }]
                })
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
                let saved = save(&actor, &text, "a", &mut seq).await;
                for r in &saved {
                    history.import(&r.update).expect("history import");
                }
                records.extend(saved);
                let rotated = actor.rotate_session().await.expect("rotate");
                assert!(all_sessions.insert(rotated));
                unused_session = Some(rotated);
            } else {
                let text = format!("{}{}", actor.view().await.expect("v").text, token(i));
                let saved = save(&actor, &text, "a", &mut seq).await;
                for r in &saved {
                    history.import(&r.update).expect("history import");
                }
                records.extend(saved);
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
