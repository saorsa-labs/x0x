//! Store-level tests for ADR 0081: the signed-record receiver rule, the
//! per-note cap and store budget, and convergence through the full
//! sign → store → verify → import path with no delivery gate.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::engine::NotesEngine;
use super::error::NoteError;
use super::record::{
    decode_record, encode_record, record_key, sign_record, signing_bytes, NoteUpdateRecordV2,
    RosterEpoch,
};
use super::store::{
    check_budget, entry_cost, EpochVerdict, KvFuture, NoteKv, NotesStore, RosterHistory,
    RosterView, SharedRosterView, NOTE_CAP_BYTES, STORE_BUDGET_BYTES,
};
use crate::identity::{AgentId, AgentKeypair};
use crate::kv::encrypted::AuthorSigning;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// In-memory stand-in for the sealed group store.
#[derive(Default)]
struct MemKv {
    entries: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Retained-image bytes that are not notes entries (other overhead).
    image_base: AtomicU64,
}

const STORE_ID: [u8; 32] = [0x81; 32];

impl MemKv {
    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        self.entries.lock().expect("entries").clone()
    }

    fn insert(&self, key: String, value: Vec<u8>) {
        self.entries.lock().expect("entries").insert(key, value);
    }
}

impl NoteKv for MemKv {
    fn store_id(&self) -> KvFuture<'_, [u8; 32]> {
        Box::pin(async { Ok(STORE_ID) })
    }

    fn entries(&self, prefix: String) -> KvFuture<'_, Vec<(String, Vec<u8>)>> {
        let out = self
            .snapshot()
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .collect();
        Box::pin(async move { Ok(out) })
    }

    fn get(&self, key: String) -> KvFuture<'_, Option<Vec<u8>>> {
        let out = self.snapshot().get(&key).cloned();
        Box::pin(async move { Ok(out) })
    }

    fn put(&self, key: String, value: Vec<u8>, _content_type: &'static str) -> KvFuture<'_, bool> {
        self.insert(key, value);
        Box::pin(async { Ok(true) })
    }

    fn image_len(&self) -> KvFuture<'_, u64> {
        let len = self.image_base.load(Ordering::Relaxed)
            + self
                .snapshot()
                .iter()
                .map(|(k, v)| entry_cost(k, v.len()))
                .sum::<u64>();
        Box::pin(async move { Ok(len) })
    }
}

struct Member {
    signing: AuthorSigning,
    engine: NotesEngine,
    kv: MemKv,
}

impl Member {
    fn new() -> Self {
        let kp = AgentKeypair::generate().expect("keypair");
        Self {
            signing: AuthorSigning::from_keypair(&kp).expect("signing"),
            engine: NotesEngine::new(None),
            kv: MemKv::default(),
        }
    }

    fn id(&self) -> AgentId {
        self.signing.agent_id
    }

    fn store(&self, roster: &SharedRosterView) -> NotesStore<'_, MemKv> {
        NotesStore::new(&self.kv, &self.engine, &self.signing, Arc::clone(roster))
    }

    /// The same member after a daemon restart: same key and store, fresh
    /// in-memory engine (every record is re-verified).
    fn restarted(self) -> Self {
        Self {
            signing: self.signing,
            engine: NotesEngine::new(None),
            kv: self.kv,
        }
    }
}

/// Roster epoch `n` of the test group's state-commit chain.
fn e(n: u8) -> RosterEpoch {
    RosterEpoch {
        revision: u64::from(n),
        state_hash: [n; 32],
    }
}

/// A single-epoch roster (head `e(1)`) whose active members are `ids`.
fn writers(ids: &[AgentId]) -> SharedRosterView {
    Arc::new(RosterHistory::new(e(1), ids.iter().map(|a| a.0)))
}

/// The ADR 0081 "current writer" rule, kept as the CONTROL for the ADR 0082
/// tests: a record is judged against the head roster, whatever its epoch.
struct CurrentWriterOnly(RosterHistory);

impl RosterView for CurrentWriterOnly {
    fn head(&self) -> Option<RosterEpoch> {
        self.0.head()
    }

    fn writer_at(&self, author: &AgentId, _epoch: &RosterEpoch) -> EpochVerdict {
        match self.0.head() {
            Some(head) => self.0.writer_at(author, &head),
            None => EpochVerdict::Unknown,
        }
    }
}

/// A loro update of `text` from a fresh doc: `(loro_peer, update)`.
fn loro_update(text: &str) -> (u64, Vec<u8>) {
    let doc = loro::LoroDoc::new();
    doc.get_text(super::engine::TEXT_CONTAINER)
        .insert(0, text)
        .expect("insert");
    doc.commit();
    (
        doc.peer_id(),
        doc.export(loro::ExportMode::all_updates()).expect("export"),
    )
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

/// Copy every entry of `from` into `to` (a relay or retained serve).
fn replicate(from: &MemKv, to: &MemKv) {
    for (k, v) in from.snapshot() {
        to.insert(k, v);
    }
}

/// ADR 0081 §5 receiver rule, WHY: after a full-state or retained serve the
/// publisher is the serving member, so only a per-record signature binds a
/// record to its author. A record B places under A's key segment — signed
/// by B, or carrying A's public key with B's signature — is refused; A's
/// genuine record relayed by B is accepted.
#[test]
fn forged_author_is_rejected_and_relayed_genuine_record_accepted() {
    runtime().block_on(async {
        let a = Member::new();
        let b = Member::new();
        let c = Member::new();
        let all = writers(&[a.id(), b.id(), c.id()]);
        let note = a.store(&all).create("plan").await.expect("create");
        a.store(&all)
            .save(&note.note_id, "from a", &note.version)
            .await
            .expect("a saves");

        // B relays A's genuine records to C: accepted.
        replicate(&a.kv, &b.kv);
        replicate(&b.kv, &c.kv);
        let read = c.store(&all).read(&note.note_id).await.expect("c reads");
        assert_eq!(read.text, "from a");

        // Forgery 1: B signs a record under A's segment with B's own key.
        let victim_key = record_key(&note.note_id, &a.id().0, 1);
        let (forged_peer, forged_update) = loro_update("FORGED");
        let (_, b_signed) = sign_record(
            &b.signing,
            &STORE_ID,
            &note.note_id,
            1,
            forged_peer,
            e(1),
            forged_update.clone(),
        )
        .expect("sign");
        let mut forged = b_signed.clone();
        forged.author = a.id().0;
        c.kv.insert(victim_key.clone(), encode_record(&forged).expect("encode"));
        let read = c.store(&all).read(&note.note_id).await.expect("read");
        assert_eq!(read.text, "from a", "forgery under B's key must not import");

        // Forgery 2: seq 0 under A's segment carrying A's public key, but
        // signed by B.
        let seq0_key = record_key(&note.note_id, &a.id().0, 0);
        let pk = a.signing.public_key_bytes();
        let message = signing_bytes(
            &STORE_ID,
            &seq0_key,
            &a.id().0,
            0,
            forged_peer,
            &e(1),
            &forged_update,
            &Some(pk.clone()),
        )
        .expect("bytes");
        let forged0 = NoteUpdateRecordV2 {
            author: a.id().0,
            seq: 0,
            loro_peer: forged_peer,
            roster_epoch: 1,
            roster_state_hash: [1; 32],
            update: forged_update.clone(),
            author_pubkey: Some(pk),
            author_sig: b.signing.sign(&message).expect("b signs"),
        };
        let observer = Member::new();
        replicate(&a.kv, &observer.kv);
        observer
            .kv
            .insert(seq0_key, encode_record(&forged0).expect("encode"));
        let read = observer
            .store(&all)
            .read(&note.note_id)
            .await
            .expect("read");
        assert!(
            !read.text.contains("FORGED"),
            "a forged seq-0 record must not import: {:?}",
            read.text
        );

        // Control: the same bytes signed by A itself verify and import.
        let (genuine_key, genuine) = sign_record(
            &a.signing,
            &STORE_ID,
            &note.note_id,
            5,
            forged_peer,
            e(1),
            forged_update,
        )
        .expect("sign");
        let control = Member::new();
        replicate(&a.kv, &control.kv);
        control
            .kv
            .insert(genuine_key, encode_record(&genuine).expect("encode"));
        let read = control.store(&all).read(&note.note_id).await.expect("read");
        assert!(read.text.contains("FORGED"), "A-signed control must import");
    });
}

/// Group history for the ADR 0082 tests: A, B and C are writers at epoch 1;
/// commit 2 removes A. `before_removal` is a replica still at epoch 1;
/// `after_removal` holds both epochs with head 2.
struct RemovalHistory {
    before_removal: SharedRosterView,
    after_removal: SharedRosterView,
    /// The ADR 0081 control: the head (post-removal) roster judges all.
    current_writer_only: SharedRosterView,
}

fn removal_history(a: &Member, b: &Member, c: &Member) -> RemovalHistory {
    let all = [a.id().0, b.id().0, c.id().0];
    let after = RosterHistory::new(e(2), [b.id().0, c.id().0]).with_epoch(e(1), all);
    RemovalHistory {
        before_removal: Arc::new(RosterHistory::new(e(1), all)),
        after_removal: Arc::new(after.clone()),
        current_writer_only: Arc::new(CurrentWriterOnly(after)),
    }
}

/// ADR 0082 (WHY): A's edits made while A was a writer are kept after A is
/// removed — on a replica that first sees them after the removal, and
/// again after that replica restarts (every record re-verified). Control:
/// under the ADR 0081 "current writer" rule the same replica loses them.
#[test]
fn removed_writers_earlier_records_survive_everywhere_including_restart() {
    runtime().block_on(async {
        let (a, b, c) = (Member::new(), Member::new(), Member::new());
        let h = removal_history(&a, &b, &c);
        let note = a
            .store(&h.before_removal)
            .create("n")
            .await
            .expect("create");
        a.store(&h.before_removal)
            .save(&note.note_id, "A wrote this", &note.version)
            .await
            .expect("A saves at epoch 1");
        // A is removed (commit 2); B and C only see A's record afterwards.
        replicate(&a.kv, &b.kv);
        replicate(&a.kv, &c.kv);
        for member in [&b, &c] {
            let read = member
                .store(&h.after_removal)
                .read(&note.note_id)
                .await
                .expect("read");
            assert_eq!(read.text, "A wrote this", "A's earlier save is kept");
        }
        let c = c.restarted();
        let read = c
            .store(&h.after_removal)
            .read(&note.note_id)
            .await
            .expect("read after restart");
        assert_eq!(read.text, "A wrote this", "kept across a restart");

        // Control: the "current writer" rule drops A's history.
        let control = Member::new();
        replicate(&a.kv, &control.kv);
        let read = control
            .store(&h.current_writer_only)
            .read(&note.note_id)
            .await
            .expect("control read");
        assert_eq!(read.text, "", "control: current-writer rule loses A's save");
    });
}

/// ADR 0082 §3: a record A signs under an epoch at which A is no longer an
/// active member is refused. Control: the identical record is accepted by
/// a replica whose roster at that epoch still has A.
#[test]
fn post_removal_record_is_refused() {
    runtime().block_on(async {
        let (a, b, c) = (Member::new(), Member::new(), Member::new());
        let h = removal_history(&a, &b, &c);
        let note = b.store(&h.after_removal).create("n").await.expect("create");
        let (peer, update) = loro_update("AFTER REMOVAL");
        let (key, record) =
            sign_record(&a.signing, &STORE_ID, &note.note_id, 0, peer, e(2), update).expect("sign");
        let bytes = encode_record(&record).expect("encode");
        b.kv.insert(key.clone(), bytes.clone());
        let read = b
            .store(&h.after_removal)
            .read(&note.note_id)
            .await
            .expect("read");
        assert_eq!(read.text, "", "a post-removal record is refused");

        // Control: a replica whose epoch-2 roster (same hash) still lists A.
        let still_member: SharedRosterView = Arc::new(
            RosterHistory::new(e(2), [a.id().0, b.id().0, c.id().0])
                .with_epoch(e(1), [a.id().0, b.id().0, c.id().0]),
        );
        let control = Member::new();
        replicate(&b.kv, &control.kv);
        let read = control
            .store(&still_member)
            .read(&note.note_id)
            .await
            .expect("control read");
        assert_eq!(
            read.text, "AFTER REMOVAL",
            "control: accepted while A is a writer"
        );
    });
}

/// ADR 0082 §4 (WHY): a later edit that builds on a removed writer's
/// earlier text is not held — B's post-removal insert inside A's text
/// applies on every replica. Control: under the "current writer" rule A's
/// record is dropped, so B's dependent edit stays pending and is lost.
#[test]
fn later_edit_depending_on_removed_writers_text_is_not_held() {
    runtime().block_on(async {
        let (a, b, c) = (Member::new(), Member::new(), Member::new());
        let h = removal_history(&a, &b, &c);
        let note = a
            .store(&h.before_removal)
            .create("n")
            .await
            .expect("create");
        a.store(&h.before_removal)
            .save(&note.note_id, "hello", &note.version)
            .await
            .expect("A saves at epoch 1");
        replicate(&a.kv, &b.kv);
        let seen = b
            .store(&h.after_removal)
            .read(&note.note_id)
            .await
            .expect("B reads");
        b.store(&h.after_removal)
            .save(&note.note_id, "helBBlo", &seen.version)
            .await
            .expect("B edits inside A's text at epoch 2");
        replicate(&b.kv, &c.kv);
        let read = c
            .store(&h.after_removal)
            .read(&note.note_id)
            .await
            .expect("C reads");
        assert_eq!(read.text, "helBBlo");

        let control = Member::new();
        replicate(&b.kv, &control.kv);
        let read = control
            .store(&h.current_writer_only)
            .read(&note.note_id)
            .await
            .expect("control read");
        assert!(
            !read.text.contains("BB"),
            "control: B's dependent edit is held when A's record is dropped: {:?}",
            read.text
        );
    });
}

/// ADR 0082 §3: a record naming an epoch this replica has not reached is
/// held — not refused — and accepted once the group state reaches it.
#[test]
fn unknown_epoch_record_is_held_then_accepted() {
    runtime().block_on(async {
        let (a, b, c) = (Member::new(), Member::new(), Member::new());
        let h = removal_history(&a, &b, &c);
        let note = b.store(&h.after_removal).create("n").await.expect("create");
        b.store(&h.after_removal)
            .save(&note.note_id, "from epoch two", &note.version)
            .await
            .expect("B saves at epoch 2");
        replicate(&b.kv, &c.kv);
        // C has not applied commit 2 yet.
        let lagging = c.store(&h.before_removal);
        let actor_key = format!("{}/{}", hex::encode(STORE_ID), note.note_id);
        let read = lagging.read(&note.note_id).await.expect("read");
        assert_eq!(read.text, "", "a future-epoch record is held");
        let actor = c.engine.get(&actor_key).await.expect("actor");
        let report = lagging.sync(&note.note_id, &actor).await.expect("sync");
        assert_eq!(report.held, 1, "held, not refused");
        assert_eq!(report.refused_epoch, 0);
        // Commit 2 arrives.
        let read = c
            .store(&h.after_removal)
            .read(&note.note_id)
            .await
            .expect("read");
        assert_eq!(
            read.text, "from epoch two",
            "accepted once the epoch is known"
        );
    });
}

/// Build a record A signs after removal, backdated to epoch 1: its ops are
/// made on a doc holding `base` records (all of them decoded from `kv`
/// entries whose key starts with `prefix`), inserting `token` at `at`.
fn backdated_record(
    a: &Member,
    kv: &MemKv,
    note_id: &str,
    include_b: &AgentId,
    use_b: bool,
    token: &str,
) -> (String, Vec<u8>) {
    let doc = loro::LoroDoc::new();
    for (key, value) in kv.snapshot() {
        let Some(parsed) = super::record::parse_record_key(&key) else {
            continue;
        };
        if parsed.note_id != note_id || (!use_b && parsed.author == include_b.0) {
            continue;
        }
        let record = decode_record(&value).expect("decode");
        doc.import(&record.update).expect("import");
    }
    let before = doc.oplog_vv();
    let text = doc.get_text(super::engine::TEXT_CONTAINER);
    let at = if use_b {
        // Right after B's post-removal text: depends on B's ops.
        text.to_string().find("BB").map_or(0, |i| i + 2)
    } else {
        0
    };
    text.insert(at, token).expect("insert");
    doc.commit();
    let update = doc
        .export(loro::ExportMode::updates(&before))
        .expect("export");
    let (key, record) = sign_record(
        &a.signing,
        &STORE_ID,
        note_id,
        77,
        doc.peer_id(),
        e(1),
        update,
    )
    .expect("sign");
    (key, encode_record(&record).expect("encode"))
}

/// ADR 0082 §4 backdating: removed A signs a new record claiming epoch 1.
/// When it builds on B's post-removal (epoch-2) text it is refused, because
/// a record's epoch must be at least every epoch it depends on. The same
/// forgery built only on pre-removal text is ACCEPTED: the stated, bounded
/// limit (and the control showing the refusal is the dependency rule).
#[test]
fn backdated_record_is_refused_only_when_it_builds_on_later_epochs() {
    runtime().block_on(async {
        let (a, b, c) = (Member::new(), Member::new(), Member::new());
        let h = removal_history(&a, &b, &c);
        let note = a
            .store(&h.before_removal)
            .create("n")
            .await
            .expect("create");
        a.store(&h.before_removal)
            .save(&note.note_id, "hello", &note.version)
            .await
            .expect("A saves at epoch 1");
        replicate(&a.kv, &b.kv);
        let seen = b
            .store(&h.after_removal)
            .read(&note.note_id)
            .await
            .expect("B reads");
        b.store(&h.after_removal)
            .save(&note.note_id, "helloBB", &seen.version)
            .await
            .expect("B writes at epoch 2");

        // Refused: backdated, but depends on B's epoch-2 ops.
        let (key, value) = backdated_record(&a, &b.kv, &note.note_id, &b.id(), true, "XX");
        let refused = Member::new();
        replicate(&b.kv, &refused.kv);
        refused.kv.insert(key, value);
        let read = refused
            .store(&h.after_removal)
            .read(&note.note_id)
            .await
            .expect("read");
        assert_eq!(
            read.text, "helloBB",
            "backdated edit on later text is refused"
        );

        // Known limit: backdated onto pre-removal text only — accepted.
        let (key, value) = backdated_record(&a, &b.kv, &note.note_id, &b.id(), false, "YY");
        let limit = Member::new();
        replicate(&b.kv, &limit.kv);
        limit.kv.insert(key, value);
        let read = limit
            .store(&h.after_removal)
            .read(&note.note_id)
            .await
            .expect("read");
        assert!(
            read.text.contains("YY") && read.text.contains("BB"),
            "ADR 0082 §4 limit: a backdated edit on pre-removal text is accepted: {:?}",
            read.text
        );
    });
}

/// Budget boundaries (§6): exactly at a limit passes, one byte over fails,
/// and the note check comes first.
#[test]
fn budget_checks_are_exact_at_the_limits() {
    assert!(check_budget(NOTE_CAP_BYTES - 10, 10, 0, 0).is_ok());
    assert!(matches!(
        check_budget(NOTE_CAP_BYTES - 10, 11, 0, 0),
        Err(NoteError::NoteTooLarge { .. })
    ));
    assert!(check_budget(0, 0, STORE_BUDGET_BYTES - 5, 5).is_ok());
    assert!(matches!(
        check_budget(0, 0, STORE_BUDGET_BYTES - 5, 6),
        Err(NoteError::StoreFull {
            current,
            budget: STORE_BUDGET_BYTES,
            ..
        }) if current == STORE_BUDGET_BYTES - 5
    ));
    assert!(matches!(
        check_budget(NOTE_CAP_BYTES, 1, STORE_BUDGET_BYTES, 1),
        Err(NoteError::NoteTooLarge { .. })
    ));
}

/// A write past 4 MiB per note returns `note_too_large` and a write past the
/// 12 MiB store budget returns `notes_store_full`; neither changes the
/// store. A write that fits both succeeds.
#[test]
fn note_cap_and_store_budget_refuse_without_changing_the_store() {
    runtime().block_on(async {
        let a = Member::new();
        let all = writers(&[a.id()]);
        let store = a.store(&all);
        let note = store.create("big").await.expect("create");

        // Fill the note's record bytes to just under the cap with inert
        // entries (never valid records, so they never import).
        let filler = vec![0u8; 64 * 1024 - 1];
        let mut filled = 0u64;
        let mut i = 1000u64;
        // Exactly 1 KiB of headroom: less than one signed record (≥ 3.3 KB
        // of signature alone).
        let target = NOTE_CAP_BYTES - 1024;
        while filled < target {
            let len = (target - filled).min(filler.len() as u64) as usize;
            a.kv.insert(
                record_key(&note.note_id, &[9u8; 32], i),
                filler[..len].to_vec(),
            );
            filled += len as u64;
            i += 1;
        }
        let before = a.kv.snapshot();
        let err = store
            .save(&note.note_id, &"x".repeat(2048), &note.version)
            .await
            .expect_err("over the note cap");
        assert_eq!(err.reason(), "note_too_large");
        assert_eq!(a.kv.snapshot(), before, "a refused write changes nothing");

        // A second note fits its own cap but not the store budget.
        let other = store.create("other").await.expect("create");
        let image = a.kv.image_len().await.expect("image");
        a.kv.image_base
            .store(STORE_BUDGET_BYTES - image - 100, Ordering::Relaxed);
        let before = a.kv.snapshot();
        let err = store
            .save(&other.note_id, "does not fit", &other.version)
            .await
            .expect_err("over the store budget");
        assert_eq!(err.reason(), "notes_store_full");
        assert!(matches!(
            err,
            NoteError::StoreFull {
                budget: STORE_BUDGET_BYTES,
                ..
            }
        ));
        assert_eq!(a.kv.snapshot(), before, "a refused write changes nothing");
        let read = store.read(&other.note_id).await.expect("read");
        assert_eq!(read.text, "", "reads are unaffected");

        // With room again, the same write succeeds.
        a.kv.image_base.store(0, Ordering::Relaxed);
        let saved = store
            .save(&other.note_id, "fits now", &read.version)
            .await
            .expect("fits");
        assert_eq!(saved.note.text, "fits now");
        assert_eq!(saved.records_written, 1, "one record per save");
    });
}

/// A refused save rotates the session, so its counters are never reused
/// with other content by a later save.
#[test]
fn refused_save_rotates_the_session_peer() {
    runtime().block_on(async {
        let a = Member::new();
        let all = writers(&[a.id()]);
        let store = a.store(&all);
        let note = store.create("n").await.expect("create");
        let key = format!("{}/{}", hex::encode(STORE_ID), note.note_id);
        let actor = a.engine.get(&key).await.expect("open actor");
        let first = actor.session_peer().await.expect("peer");
        a.kv.image_base.store(STORE_BUDGET_BYTES, Ordering::Relaxed);
        store
            .save(&note.note_id, "refused", &note.version)
            .await
            .expect_err("over budget");
        let second = actor.session_peer().await.expect("peer");
        assert_ne!(first, second);
    });
}

/// Version semantics at the store: a stale base is 409 `base_version_stale`,
/// a base naming ops this replica lacks is 409 `base_version_unknown`.
#[test]
fn stale_and_unknown_base_versions_are_refused() {
    runtime().block_on(async {
        let a = Member::new();
        let b = Member::new();
        let all = writers(&[a.id(), b.id()]);
        let note = a.store(&all).create("n").await.expect("create");
        let v1 = a
            .store(&all)
            .save(&note.note_id, "one", &note.version)
            .await
            .expect("save")
            .note
            .version;
        let v2 = a
            .store(&all)
            .save(&note.note_id, "one two", &v1)
            .await
            .expect("save")
            .note
            .version;
        let err = a
            .store(&all)
            .save(&note.note_id, "x", &v1)
            .await
            .expect_err("stale");
        assert_eq!(err.reason(), "base_version_stale");
        // B holds only the metadata.
        b.kv.insert(
            super::record::meta_key(&note.note_id),
            a.kv.get(super::record::meta_key(&note.note_id))
                .await
                .expect("get")
                .expect("meta"),
        );
        let err = b
            .store(&all)
            .save(&note.note_id, "x", &v2)
            .await
            .expect_err("unknown");
        assert_eq!(err.reason(), "base_version_unknown");
    });
}

/// Convergence through the full record path: three members save
/// concurrently, their signed records are exchanged between stores in
/// shuffled, duplicated and partitioned order with no gate, and every
/// member ends with the same text holding every surviving token.
#[test]
fn members_converge_through_signed_records_without_a_gate() {
    runtime().block_on(async {
        let mut rng = StdRng::seed_from_u64(0x0081);
        let members: Vec<Member> = (0..3).map(|_| Member::new()).collect();
        let ids: Vec<AgentId> = members.iter().map(Member::id).collect();
        let all = writers(&ids);
        let note = members[0]
            .store(&all)
            .create("shared")
            .await
            .expect("create");
        for m in &members[1..] {
            replicate(&members[0].kv, &m.kv);
        }
        let mut next = 0u32;
        let mut inserted = BTreeSet::new();
        let mut deleted = BTreeSet::new();
        for _round in 0..4 {
            for m in &members {
                let current = m.store(&all).read(&note.note_id).await.expect("read");
                let mut chars: Vec<char> = current.text.chars().collect();
                for _ in 0..rng.gen_range(1..=3) {
                    if chars.is_empty() || rng.gen_bool(0.7) {
                        let t = char::from_u32(0x4E00 + next).expect("token");
                        next += 1;
                        inserted.insert(t);
                        let at = rng.gen_range(0..=chars.len());
                        chars.insert(at, t);
                    } else {
                        let at = rng.gen_range(0..chars.len());
                        deleted.insert(chars.remove(at));
                    }
                }
                let text: String = chars.into_iter().collect();
                m.store(&all)
                    .save(&note.note_id, &text, &current.version)
                    .await
                    .expect("save");
            }
            // Partial, shuffled, duplicated exchange between one random pair.
            let mut order = [0usize, 1, 2];
            order.shuffle(&mut rng);
            let (from, to) = (order[0], order[1]);
            let mut entries: Vec<_> = members[from].kv.snapshot().into_iter().collect();
            let dups: Vec<_> = entries
                .iter()
                .filter(|_| rng.gen_bool(0.2))
                .cloned()
                .collect();
            entries.extend(dups);
            entries.shuffle(&mut rng);
            for (k, v) in entries {
                members[to].kv.insert(k, v);
                // Reading after every single entry is the harshest order.
                members[to]
                    .store(&all)
                    .read(&note.note_id)
                    .await
                    .expect("read");
            }
        }
        // Heal: everyone gets everything, in reverse key order.
        let mut union: Vec<(String, Vec<u8>)> = Vec::new();
        for m in &members {
            union.extend(m.kv.snapshot());
        }
        union.sort();
        union.dedup();
        union.reverse();
        let mut texts = Vec::new();
        for m in &members {
            for (k, v) in &union {
                m.kv.insert(k.clone(), v.clone());
            }
            texts.push(m.store(&all).read(&note.note_id).await.expect("read").text);
        }
        assert!(texts.iter().all(|t| t == &texts[0]), "diverged: {texts:?}");
        let present: BTreeSet<char> = texts[0].chars().collect();
        let expected: BTreeSet<char> = inserted.difference(&deleted).copied().collect();
        assert_eq!(present, expected, "surviving tokens exactly");
    });
}
