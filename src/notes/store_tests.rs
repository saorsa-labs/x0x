//! Store-level tests for ADR 0081: the signed-record receiver rule, the
//! per-note cap and store budget, and convergence through the full
//! sign → store → verify → import path with no delivery gate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::engine::NotesEngine;
use super::error::NoteError;
use super::record::{
    decode_record, encode_record, record_key, record_prefix, sign_record, signing_bytes,
    NoteUpdateRecordV1,
};
use super::store::{
    check_budget, entry_cost, KvFuture, NoteKv, NotesStore, WriterCheck, NOTE_CAP_BYTES,
    STORE_BUDGET_BYTES,
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

    fn store(&self, writers: &WriterCheck) -> NotesStore<'_, MemKv> {
        NotesStore::new(&self.kv, &self.engine, &self.signing, Arc::clone(writers))
    }
}

fn writers(ids: &[AgentId]) -> WriterCheck {
    let set: BTreeSet<[u8; 32]> = ids.iter().map(|a| a.0).collect();
    Arc::new(move |agent: &AgentId| set.contains(&agent.0))
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
        let donor = Member::new();
        let donor_store = donor.store(&all);
        let donor_note = donor_store.create("donor").await.expect("create");
        donor_store
            .save(&donor_note.note_id, "FORGED", &donor_note.version)
            .await
            .expect("donor save");
        let (_, donor_value) = donor
            .kv
            .snapshot()
            .into_iter()
            .find(|(k, _)| k.starts_with(&record_prefix(&donor_note.note_id)))
            .expect("donor record");
        let forged_update = decode_record(&donor_value).expect("decode").update;
        let (_, b_signed) = sign_record(
            &b.signing,
            &STORE_ID,
            &note.note_id,
            1,
            7,
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
            7,
            &forged_update,
            &Some(pk.clone()),
        )
        .expect("bytes");
        let forged0 = NoteUpdateRecordV1 {
            author: a.id().0,
            seq: 0,
            loro_peer: 7,
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
        let (genuine_key, genuine) =
            sign_record(&a.signing, &STORE_ID, &note.note_id, 5, 7, forged_update).expect("sign");
        let control = Member::new();
        replicate(&a.kv, &control.kv);
        control
            .kv
            .insert(genuine_key, encode_record(&genuine).expect("encode"));
        let read = control.store(&all).read(&note.note_id).await.expect("read");
        assert!(read.text.contains("FORGED"), "A-signed control must import");
    });
}

/// A record whose author is not a current writer never reaches loro, and
/// is imported once the author becomes a writer.
#[test]
fn non_writer_records_are_held_until_the_author_is_a_writer() {
    runtime().block_on(async {
        let a = Member::new();
        let reader = Member::new();
        let only_reader = writers(&[reader.id()]);
        let both = writers(&[a.id(), reader.id()]);
        let note = a.store(&both).create("n").await.expect("create");
        a.store(&both)
            .save(&note.note_id, "secret plan", &note.version)
            .await
            .expect("save");
        replicate(&a.kv, &reader.kv);
        let read = reader
            .store(&only_reader)
            .read(&note.note_id)
            .await
            .expect("read");
        assert_eq!(read.text, "", "a non-writer's record must not import");
        let read = reader.store(&both).read(&note.note_id).await.expect("read");
        assert_eq!(read.text, "secret plan");
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
