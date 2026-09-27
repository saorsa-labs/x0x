//! The group `notes` store: note metadata, signed update records, the
//! receiver rule, and the per-note cap and store budget (ADR 0081 §5, §6).
//!
//! The store talks to the sealed group KV store through [`NoteKv`], so the
//! same code runs against a live `KvStoreHandle` and an in-memory map in
//! tests. Records reach loro only after they decode (bounded), their author
//! signature verifies, and their author is a current writer.

use super::engine::{EngineRecord, NoteActor, NoteView, NotesEngine};
use super::error::NoteError;
use super::record::{
    decode_record, encode_record, is_note_id, meta_key, parse_record_key, record_prefix,
    sign_record, verify_record, RecordRejection, MAX_UPDATE_BYTES, RECORD_CONTENT_TYPE,
};
use crate::identity::AgentId;
use crate::kv::encrypted::AuthorSigning;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Per-note cap: the sum of the note's record values (ADR 0075 Q6, §6).
pub const NOTE_CAP_BYTES: u64 = 4 * 1024 * 1024;

/// Store budget: the encoded 0047 retained image of the `notes` store (§6).
pub const STORE_BUDGET_BYTES: u64 = 12 * 1024 * 1024;

/// Conservative per-entry bytes a new KV entry adds to the retained image
/// beyond its key and value (entry fields, content type, OR-Set tag and
/// map overhead). Over-estimating fails closed.
pub const ENTRY_OVERHEAD_ESTIMATE: u64 = 512;

/// The name of the group store that holds notes.
pub const NOTES_STORE_NAME: &str = "notes";

/// Longest accepted note title, in bytes.
pub const MAX_TITLE_BYTES: usize = 512;

/// Content type of a note metadata value.
pub const META_CONTENT_TYPE: &str = "application/json";

/// A boxed future returned by [`NoteKv`].
pub type KvFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, NoteError>> + Send + 'a>>;

/// The KV operations the notes store needs.
pub trait NoteKv: Send + Sync {
    /// The 32-byte store id (bound into every record signature).
    fn store_id(&self) -> KvFuture<'_, [u8; 32]>;
    /// Every active `(key, value)` whose key starts with `prefix`.
    fn entries(&self, prefix: String) -> KvFuture<'_, Vec<(String, Vec<u8>)>>;
    /// One value.
    fn get(&self, key: String) -> KvFuture<'_, Option<Vec<u8>>>;
    /// Write one value; `Ok(true)` when it was also published.
    fn put(&self, key: String, value: Vec<u8>, content_type: &'static str) -> KvFuture<'_, bool>;
    /// The encoded size of the store's retained image.
    fn image_len(&self) -> KvFuture<'_, u64>;
}

/// Note metadata, the LWW value at `n/<note_id>/meta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteMetaV1 {
    /// Note title.
    pub title: String,
    /// Creator agent id, hex.
    pub creator: String,
    /// Creation time, Unix milliseconds.
    pub created_at: u64,
}

/// One entry of `GET /groups/:id/notes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoteSummary {
    /// Note id.
    pub note_id: String,
    /// Title.
    pub title: String,
    /// Creator agent id, hex.
    pub creator: String,
    /// Creation time, Unix milliseconds.
    pub created_at: u64,
}

/// A note as the REST API returns it: `{title, text, version}` plus ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoteDocument {
    /// Note id.
    pub note_id: String,
    /// Title.
    pub title: String,
    /// Text.
    pub text: String,
    /// Version token (base64url `Frontiers`).
    pub version: String,
    /// Whether the note is degraded (writes return 503).
    pub degraded: bool,
}

/// Outcome of a save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SaveOutcome {
    /// The note after the save.
    #[serde(flatten)]
    pub note: NoteDocument,
    /// Records written by this save.
    pub records_written: usize,
    /// Whether every record was also published (else saved locally only).
    pub published: bool,
}

/// What one sync pass did with the store's records.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    /// Records accepted and handed to the engine.
    pub accepted: usize,
    /// Records refused for good (malformed or bad signature).
    pub rejected: usize,
    /// Records held back (author key unknown or author not a writer).
    pub held: usize,
}

/// Whether an agent is a current writer of the group.
pub type WriterCheck = Arc<dyn Fn(&AgentId) -> bool + Send + Sync>;

/// The notes store bound to one group store, one signer and the group's
/// current writer rule.
pub struct NotesStore<'a, K: NoteKv + ?Sized> {
    kv: &'a K,
    engine: &'a NotesEngine,
    signing: &'a AuthorSigning,
    is_writer: WriterCheck,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn record_id(key: &str, value: &[u8]) -> String {
    format!(
        "{key}#{}",
        hex::encode(&blake3::hash(value).as_bytes()[..16])
    )
}

/// Retained-image bytes one new entry is estimated to add.
#[must_use]
pub fn entry_cost(key: &str, value_len: usize) -> u64 {
    (value_len as u64)
        .saturating_add((key.len() as u64).saturating_mul(4))
        .saturating_add(ENTRY_OVERHEAD_ESTIMATE)
}

/// The per-note and per-store checks (§6), in the ADR's order.
///
/// # Errors
///
/// [`NoteError::NoteTooLarge`] or [`NoteError::StoreFull`].
pub fn check_budget(
    note_bytes: u64,
    new_record_bytes: u64,
    image_len: u64,
    new_image_bytes: u64,
) -> Result<(), NoteError> {
    let attempted = note_bytes.saturating_add(new_record_bytes);
    if attempted > NOTE_CAP_BYTES {
        return Err(NoteError::NoteTooLarge {
            current: note_bytes,
            attempted,
            cap: NOTE_CAP_BYTES,
        });
    }
    let projected = image_len.saturating_add(new_image_bytes);
    if projected > STORE_BUDGET_BYTES {
        return Err(NoteError::StoreFull {
            current: image_len,
            projected,
            budget: STORE_BUDGET_BYTES,
        });
    }
    Ok(())
}

/// Verified-or-refused verdict for one candidate record.
enum Verdict {
    Accepted {
        id: String,
        update: Vec<u8>,
        author: AgentId,
    },
    Rejected {
        id: String,
        permanent: bool,
    },
}

impl<'a, K: NoteKv + ?Sized> NotesStore<'a, K> {
    /// Bind the store.
    pub fn new(
        kv: &'a K,
        engine: &'a NotesEngine,
        signing: &'a AuthorSigning,
        is_writer: WriterCheck,
    ) -> Self {
        Self {
            kv,
            engine,
            signing,
            is_writer,
        }
    }

    async fn note_key(&self, note_id: &str) -> Result<String, NoteError> {
        Ok(format!(
            "{}/{note_id}",
            hex::encode(self.kv.store_id().await?)
        ))
    }

    async fn meta(&self, note_id: &str) -> Result<NoteMetaV1, NoteError> {
        if !is_note_id(note_id) {
            return Err(NoteError::NotFound);
        }
        let bytes = self
            .kv
            .get(meta_key(note_id))
            .await?
            .ok_or(NoteError::NotFound)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| NoteError::Store(format!("note metadata is corrupt: {e}")))
    }

    async fn actor(&self, note_id: &str) -> Result<Arc<NoteActor>, NoteError> {
        let key = self.note_key(note_id).await?;
        self.engine.get_or_open(&key, note_id, Vec::new).await
    }

    /// List the notes in the store.
    ///
    /// # Errors
    ///
    /// [`NoteError::Store`] when the store cannot be read.
    pub async fn list(&self) -> Result<Vec<NoteSummary>, NoteError> {
        let mut out = Vec::new();
        for (key, value) in self.kv.entries("n/".to_string()).await? {
            let Some(note_id) = key
                .strip_prefix("n/")
                .and_then(|rest| rest.strip_suffix("/meta"))
            else {
                continue;
            };
            if !is_note_id(note_id) {
                continue;
            }
            let Ok(meta) = serde_json::from_slice::<NoteMetaV1>(&value) else {
                continue;
            };
            out.push(NoteSummary {
                note_id: note_id.to_string(),
                title: meta.title,
                creator: meta.creator,
                created_at: meta.created_at,
            });
        }
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.note_id.cmp(&b.note_id))
        });
        Ok(out)
    }

    /// Create an empty note.
    ///
    /// # Errors
    ///
    /// [`NoteError::InvalidRequest`] for a bad title, or a store error.
    pub async fn create(&self, title: &str) -> Result<NoteDocument, NoteError> {
        let title = title.trim();
        if title.is_empty() || title.len() > MAX_TITLE_BYTES {
            return Err(NoteError::InvalidRequest(format!(
                "title must be 1..={MAX_TITLE_BYTES} bytes"
            )));
        }
        let note_id = {
            use rand::RngCore as _;
            let mut bytes = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            hex::encode(bytes)
        };
        let meta = NoteMetaV1 {
            title: title.to_string(),
            creator: hex::encode(self.signing.agent_id.0),
            created_at: now_ms(),
        };
        let value =
            serde_json::to_vec(&meta).map_err(|e| NoteError::Store(format!("meta encode: {e}")))?;
        let key = meta_key(&note_id);
        let image = self.kv.image_len().await?;
        check_budget(0, 0, image, entry_cost(&key, value.len()))?;
        self.kv.put(key, value, META_CONTENT_TYPE).await?;
        let actor = self.actor(&note_id).await?;
        let view = actor.view().await?;
        Ok(document(note_id, meta.title, view))
    }

    /// Read a note, first importing any new records from the store.
    ///
    /// # Errors
    ///
    /// [`NoteError::NotFound`], a store error, or an engine error.
    pub async fn read(&self, note_id: &str) -> Result<NoteDocument, NoteError> {
        let meta = self.meta(note_id).await?;
        let actor = self.actor(note_id).await?;
        match self.sync(note_id, &actor).await {
            // A degraded note still reads: the last good text (§3).
            Ok(_) | Err(NoteError::Degraded { .. }) => {}
            Err(other) => return Err(other),
        }
        let view = actor.view().await?;
        Ok(document(note_id.to_string(), meta.title, view))
    }

    /// Import every new valid record of `note_id` into its actor.
    ///
    /// # Errors
    ///
    /// A store error, or [`NoteError::Degraded`].
    pub async fn sync(&self, note_id: &str, actor: &NoteActor) -> Result<SyncReport, NoteError> {
        let entries = self.kv.entries(record_prefix(note_id)).await?;
        let known = actor.known_record_ids().await?;
        let (rejected_cache, mut author_keys) =
            actor.with_verify_cache(|cache| (cache.rejected.clone(), cache.author_keys.clone()));
        let mut candidates = Vec::new();
        for (key, value) in entries {
            let id = record_id(&key, &value);
            if known.contains(&id) || rejected_cache.contains(&id) {
                continue;
            }
            candidates.push((key, value, id));
        }
        if candidates.is_empty() {
            return Ok(SyncReport::default());
        }
        // Seq-0 records first: they carry the author keys the rest need.
        candidates.sort_by_key(|(key, _, _)| parse_record_key(key).map_or(u64::MAX, |k| k.seq));
        let store_id = self.kv.store_id().await?;
        let note = note_id.to_string();
        let keys_before = author_keys.clone();
        // Decode and verify off the async runtime, each record isolated.
        let joined = tokio::task::spawn_blocking(move || {
            let mut verdicts = Vec::new();
            for (key, value, id) in candidates {
                let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    verify_candidate(&store_id, &note, &key, &value, &mut author_keys)
                }));
                verdicts.push(match verdict {
                    Ok(Ok((update, author))) => Verdict::Accepted { id, update, author },
                    Ok(Err(rejection)) => Verdict::Rejected {
                        id,
                        permanent: rejection.is_permanent(),
                    },
                    Err(_panic) => Verdict::Rejected {
                        id,
                        permanent: true,
                    },
                });
            }
            (verdicts, author_keys)
        })
        .await;
        let (verdicts, author_keys) = joined.map_err(|_| NoteError::EngineFault {
            note_id: note_id.to_string(),
            op: "verify_records",
        })?;
        let mut report = SyncReport::default();
        let mut accepted = Vec::new();
        let mut permanent = Vec::new();
        for verdict in verdicts {
            match verdict {
                Verdict::Accepted { id, update, author } => {
                    if (self.is_writer)(&author) {
                        accepted.push(EngineRecord {
                            id,
                            update: Arc::new(update),
                        });
                    } else {
                        report.held += 1;
                    }
                }
                Verdict::Rejected {
                    id,
                    permanent: true,
                } => permanent.push(id),
                Verdict::Rejected { .. } => report.held += 1,
            }
        }
        report.rejected = permanent.len();
        report.accepted = accepted.len();
        actor.with_verify_cache(|cache| {
            cache.rejected.extend(permanent);
            for (author, key) in author_keys {
                if !keys_before.contains_key(&author) {
                    cache.author_keys.insert(author, key);
                }
            }
        });
        actor.import(accepted).await?;
        Ok(report)
    }

    /// Save `text` against `base_version` (the note's current version in
    /// this slice): one signed record per save, split across consecutive
    /// seqs only when the update exceeds one record.
    ///
    /// # Errors
    ///
    /// Version errors (409), [`NoteError::NoteTooLarge`] /
    /// [`NoteError::StoreFull`] (413), [`NoteError::Degraded`] (503), or a
    /// store error.
    pub async fn save(
        &self,
        note_id: &str,
        text: &str,
        base_version: &str,
    ) -> Result<SaveOutcome, NoteError> {
        let meta = self.meta(note_id).await?;
        if text.len() as u64 > NOTE_CAP_BYTES {
            return Err(NoteError::NoteTooLarge {
                current: 0,
                attempted: text.len() as u64,
                cap: NOTE_CAP_BYTES,
            });
        }
        let actor = self.actor(note_id).await?;
        let _save = actor.lock_save().await;
        self.sync(note_id, &actor).await?;
        let prepared = actor
            .prepare_save(text.to_string(), base_version, MAX_UPDATE_BYTES)
            .await?;
        if prepared.updates.is_empty() {
            let view = actor.view().await?;
            return Ok(SaveOutcome {
                note: document(note_id.to_string(), meta.title, view),
                records_written: 0,
                published: true,
            });
        }
        match self.write_records(note_id, &actor, prepared).await {
            Ok((records_written, published)) => {
                let view = actor.view().await?;
                Ok(SaveOutcome {
                    note: document(note_id.to_string(), meta.title, view),
                    records_written,
                    published,
                })
            }
            Err(error) => {
                // Counters this save produced must never be reused with other
                // content, even though none (or only some) reached the store.
                let _ = actor.rotate_session().await;
                Err(error)
            }
        }
    }

    async fn write_records(
        &self,
        note_id: &str,
        actor: &NoteActor,
        prepared: super::engine::PreparedSave,
    ) -> Result<(usize, bool), NoteError> {
        let store_id = self.kv.store_id().await?;
        let existing = self.kv.entries(record_prefix(note_id)).await?;
        let me = self.signing.agent_id.0;
        let mut note_bytes = 0u64;
        let mut next_seq = 0u64;
        for (key, value) in &existing {
            note_bytes = note_bytes.saturating_add(value.len() as u64);
            if let Some(parsed) = parse_record_key(key) {
                if parsed.author == me {
                    next_seq = next_seq.max(parsed.seq.saturating_add(1));
                }
            }
        }
        let mut encoded = Vec::with_capacity(prepared.updates.len());
        for (i, update) in prepared.updates.into_iter().enumerate() {
            let seq = next_seq.saturating_add(i as u64);
            let (key, record) = sign_record(
                self.signing,
                &store_id,
                note_id,
                seq,
                prepared.loro_peer,
                update,
            )?;
            let bytes = encode_record(&record)?;
            encoded.push((key, bytes, record.update));
        }
        let new_record_bytes: u64 = encoded.iter().map(|(_, b, _)| b.len() as u64).sum();
        let new_image_bytes: u64 = encoded.iter().map(|(k, b, _)| entry_cost(k, b.len())).sum();
        let image_len = self.kv.image_len().await?;
        check_budget(note_bytes, new_record_bytes, image_len, new_image_bytes)?;
        let mut published = true;
        let mut local = Vec::with_capacity(encoded.len());
        for (key, bytes, update) in encoded {
            if self.kv.get(key.clone()).await?.is_some() {
                return Err(NoteError::SeqConflict(key));
            }
            let id = record_id(&key, &bytes);
            published &= self.kv.put(key, bytes, RECORD_CONTENT_TYPE).await?;
            local.push(EngineRecord {
                id,
                update: Arc::new(update),
            });
        }
        let written = local.len();
        actor.import(local).await?;
        Ok((written, published))
    }
}

/// Decode and verify one candidate. Runs inside `catch_unwind`.
fn verify_candidate(
    store_id: &[u8; 32],
    note_id: &str,
    key: &str,
    value: &[u8],
    author_keys: &mut std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> Result<(Vec<u8>, AgentId), RecordRejection> {
    let parsed = parse_record_key(key)
        .ok_or_else(|| RecordRejection::Malformed("not a record key".into()))?;
    if parsed.note_id != note_id {
        return Err(RecordRejection::Malformed("record of another note".into()));
    }
    let record = decode_record(value).map_err(RecordRejection::Malformed)?;
    let known = author_keys.get(&parsed.author).map(Vec::as_slice);
    let author = verify_record(store_id, key, &record, known)?;
    if let (0, Some(pk)) = (record.seq, record.author_pubkey.as_ref()) {
        author_keys
            .entry(parsed.author)
            .or_insert_with(|| pk.clone());
    }
    Ok((record.update, author))
}

fn document(note_id: String, title: String, view: NoteView) -> NoteDocument {
    NoteDocument {
        note_id,
        title,
        text: view.text,
        version: view.version,
        degraded: view.degraded,
    }
}
