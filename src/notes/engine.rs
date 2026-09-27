//! The loro engine behind one note, with the ADR 0081 containment.
//!
//! - **Isolation (§3).** Every loro call on a note runs through
//!   `NoteActor::run`: inside `tokio::task::spawn_blocking`, with
//!   `std::panic::catch_unwind` inside the closure. A caught panic and a
//!   `JoinError::is_panic()` both become [`NoteError::EngineFault`]. No loro
//!   object leaves the actor; async callers only see owned `String`s and
//!   byte vectors.
//! - **Poisoned docs (§3).** After a fault the doc is never dropped (#1118:
//!   dropping a poisoned doc can abort). It moves into a bounded quarantine;
//!   once that is full it is `mem::forget`-ed and counted. The faulting
//!   record is quarantined and skipped, the note is rebuilt from its other
//!   records into a fresh doc with a fresh peer id, and after
//!   [`MAX_CONSECUTIVE_FAULTS`] faults in a row the note is degraded.
//! - **Peer ids (§4).** A session peer id is drawn from the OS CSPRNG each
//!   time a doc is opened for writing (open, rebuild, and after a failed
//!   save), redrawn while it collides with the doc's `oplog_vv()` or the
//!   note's retired set, persisted to the retired set BEFORE use, and fixed
//!   with `set_peer_id` before any local op.
//! - **Version (§7).** `version` is `Frontiers::encode`, sent as base64url.
//!   Restoring it on a replica that lacks the named ops is
//!   [`NoteError::BaseVersionUnknown`], never a partial text.
//!
//! This file depends only on `std`, `tokio`, `loro`, `rand`, `base64`,
//! `blake3`, `serde`, [`super::error`] and `super::text_diff`, so the
//! containment can be exercised in isolation.

use super::error::NoteError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use loro::{ExportMode, Frontiers, IdSpan, LoroDoc, UpdateOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::mem::ManuallyDrop;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Name of the single text root container of a note doc.
pub const TEXT_CONTAINER: &str = "text";

/// Above this many bytes of text, a save uses the line-first edit script
/// of `super::text_diff` instead of loro's character diff (ADR 0081 §8).
/// Not `LoroText::update_by_line`: it re-inserts whole changed lines, which
/// brings back text a concurrent save deleted (#1029).
pub const LINE_DIFF_THRESHOLD_BYTES: usize = 256 * 1024;

/// Diff options for a save.
///
/// loro's default "refined" diff is not minimal: it can delete and
/// re-insert unchanged characters around an edit. A re-inserted character
/// is a NEW op, so a concurrent delete of the original no longer removes it
/// and deleted text silently comes back (found by the convergence property
/// test). The plain Myers diff emits only the edited characters.
#[must_use]
pub fn save_diff_options() -> UpdateOptions {
    UpdateOptions {
        timeout_ms: None,
        use_refined_diff: false,
    }
}

/// Faults in a row after which a note is degraded (ADR 0081 §3).
pub const MAX_CONSECUTIVE_FAULTS: u32 = 3;

/// Poisoned docs held in the quarantine list before further ones are
/// `mem::forget`-ed.
pub const QUARANTINE_CAPACITY: usize = 8;

/// Total forgotten poisoned docs after which any further fault degrades the
/// faulting note at once instead of rebuilding it, so the leak stays
/// bounded by `QUARANTINE_CAPACITY + MAX_LEAKED_POISONED_DOCS + notes`.
pub const MAX_LEAKED_POISONED_DOCS: u64 = 32;

/// Peer-id draws per session before giving up (only an injected RNG can
/// exhaust this).
pub const MAX_PEER_ID_DRAWS: usize = 64;

/// Source of session peer ids. Production uses [`OsPeerIdSource`]; tests
/// inject a colliding sequence to prove the redraw.
pub trait PeerIdSource: Send + Sync + 'static {
    /// Draw one candidate peer id.
    fn draw(&self) -> u64;
}

/// Draws peer ids from the operating-system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsPeerIdSource;

impl PeerIdSource for OsPeerIdSource {
    fn draw(&self) -> u64 {
        use rand::RngCore as _;
        rand::rngs::OsRng.next_u64()
    }
}

/// Encode a loro `Frontiers` as the REST `version` token (base64url, no
/// padding).
#[must_use]
pub fn encode_version(frontiers: &Frontiers) -> String {
    URL_SAFE_NO_PAD.encode(frontiers.encode())
}

/// Decode the base64url layer of a `version` token. The `Frontiers` decode
/// itself runs inside the isolation.
///
/// # Errors
///
/// [`NoteError::InvalidVersion`] when the token is not base64url or is
/// implausibly long.
pub fn decode_version_bytes(token: &str) -> Result<Vec<u8>, NoteError> {
    if token.len() > MAX_VERSION_TOKEN_LEN {
        return Err(NoteError::InvalidVersion("version token too long".into()));
    }
    URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|e| NoteError::InvalidVersion(e.to_string()))
}

/// The ops one loro update contains and the external ops it depends on
/// (ADR 0082 §4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateOps {
    /// `(peer, start, end)` counter ranges the update contains.
    pub spans: Vec<(u64, i32, i32)>,
    /// External dependencies `(peer, counter)`: ops outside the update that
    /// its changes depend on.
    pub deps: Vec<(u64, i32)>,
}

/// Decode the op spans and external dependencies of a loro update blob.
/// Peer bytes: the decode runs inside `catch_unwind`, and callers run it
/// off the async runtime. Only `Updates`-mode blobs are accepted.
///
/// # Errors
///
/// A description of the decode failure (including a caught panic).
pub fn update_ops(update: &[u8]) -> Result<UpdateOps, String> {
    let meta = catch_unwind(AssertUnwindSafe(|| {
        LoroDoc::decode_import_blob_meta(update, true)
    }))
    .map_err(|_| "update metadata decode panicked".to_string())?
    .map_err(|e| format!("update metadata decode failed: {e}"))?;
    if meta.mode != loro::EncodedBlobMode::Updates {
        return Err(format!("not an updates blob: {}", meta.mode));
    }
    let mut spans = Vec::new();
    for (peer, start) in meta.partial_start_vv.iter() {
        let end = meta.partial_end_vv.get(peer).copied().unwrap_or(*start);
        spans.push((*peer, *start, end));
    }
    spans.sort_unstable();
    let deps = meta
        .start_frontiers
        .iter()
        .map(|id| (id.peer, id.counter))
        .collect();
    Ok(UpdateOps { spans, deps })
}

/// Longest accepted version token (frontiers grow with concurrent heads,
/// not history; 4 KiB is far above any real value).
pub const MAX_VERSION_TOKEN_LEN: usize = 4096;

/// Engine counters surfaced in `/diagnostics/groups` (ADR 0081, Neutral).
#[derive(Debug, Default)]
pub struct EngineCounters {
    engine_faults: AtomicU64,
    quarantined_records: AtomicU64,
    rejected_records: AtomicU64,
    quarantined_poisoned_docs: AtomicU64,
    leaked_poisoned_docs: AtomicU64,
    degraded_notes: AtomicU64,
    peer_id_redraws: AtomicU64,
    sessions_started: AtomicU64,
}

/// A point-in-time copy of [`EngineCounters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct EngineCountersSnapshot {
    /// Caught loro panics (including faults during a rebuild).
    pub engine_faults: u64,
    /// Records skipped for ever because importing them faulted.
    pub quarantined_records: u64,
    /// Records loro refused with an error (no panic).
    pub rejected_records: u64,
    /// Poisoned docs held (never dropped) in the quarantine list.
    pub quarantined_poisoned_docs: u64,
    /// Poisoned docs released with `mem::forget` (a restart reclaims them).
    pub leaked_poisoned_docs: u64,
    /// Notes marked degraded.
    pub degraded_notes: u64,
    /// Peer-id draws rejected because they collided.
    pub peer_id_redraws: u64,
    /// Writing sessions started (one peer id each).
    pub sessions_started: u64,
}

impl EngineCounters {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot every counter.
    #[must_use]
    pub fn snapshot(&self) -> EngineCountersSnapshot {
        EngineCountersSnapshot {
            engine_faults: self.engine_faults.load(Ordering::Relaxed),
            quarantined_records: self.quarantined_records.load(Ordering::Relaxed),
            rejected_records: self.rejected_records.load(Ordering::Relaxed),
            quarantined_poisoned_docs: self.quarantined_poisoned_docs.load(Ordering::Relaxed),
            leaked_poisoned_docs: self.leaked_poisoned_docs.load(Ordering::Relaxed),
            degraded_notes: self.degraded_notes.load(Ordering::Relaxed),
            peer_id_redraws: self.peer_id_redraws.load(Ordering::Relaxed),
            sessions_started: self.sessions_started.load(Ordering::Relaxed),
        }
    }
}

/// Poisoned docs that must never be dropped (#1118).
struct PoisonedDocQuarantine {
    docs: Mutex<Vec<ManuallyDrop<LoroDoc>>>,
}

impl PoisonedDocQuarantine {
    fn admit(&self, doc: LoroDoc, counters: &EngineCounters) {
        let mut docs = self.docs.lock().unwrap_or_else(PoisonError::into_inner);
        if docs.len() < QUARANTINE_CAPACITY {
            docs.push(ManuallyDrop::new(doc));
            EngineCounters::bump(&counters.quarantined_poisoned_docs);
        } else {
            std::mem::forget(doc);
            EngineCounters::bump(&counters.leaked_poisoned_docs);
        }
    }
}

/// State shared by every note actor of one daemon.
pub struct EngineShared {
    counters: EngineCounters,
    quarantine: PoisonedDocQuarantine,
    peer_source: Box<dyn PeerIdSource>,
    retired_dir: Option<PathBuf>,
}

impl std::fmt::Debug for EngineShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineShared")
            .field("counters", &self.counters.snapshot())
            .field("retired_dir", &self.retired_dir)
            .finish_non_exhaustive()
    }
}

impl EngineShared {
    /// Build the shared engine state. `retired_dir` holds each note's
    /// retired peer-id set; `None` keeps it in memory only (tests).
    #[must_use]
    pub fn new(peer_source: Box<dyn PeerIdSource>, retired_dir: Option<PathBuf>) -> Self {
        Self {
            counters: EngineCounters::default(),
            quarantine: PoisonedDocQuarantine {
                docs: Mutex::new(Vec::new()),
            },
            peer_source,
            retired_dir,
        }
    }

    /// The engine counters.
    #[must_use]
    pub fn counters(&self) -> &EngineCounters {
        &self.counters
    }

    fn retired_path(&self, note_key: &str) -> Option<PathBuf> {
        let dir = self.retired_dir.as_ref()?;
        let name = hex_lower(&blake3::hash(note_key.as_bytes()).as_bytes()[..16]);
        Some(dir.join(format!("{name}.peers")))
    }

    fn load_retired(&self, note_key: &str) -> Result<BTreeSet<u64>, NoteError> {
        let Some(path) = self.retired_path(note_key) else {
            return Ok(BTreeSet::new());
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let mut set = BTreeSet::new();
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    let id = u64::from_str_radix(line, 16).map_err(|e| {
                        NoteError::Store(format!("retired peer-id set is corrupt: {e}"))
                    })?;
                    set.insert(id);
                }
                Ok(set)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
            Err(e) => Err(NoteError::Store(format!(
                "cannot read retired peer-id set: {e}"
            ))),
        }
    }

    fn persist_retired(&self, note_key: &str, set: &BTreeSet<u64>) -> Result<(), NoteError> {
        let Some(path) = self.retired_path(note_key) else {
            return Ok(());
        };
        let io =
            |e: std::io::Error| NoteError::Store(format!("cannot persist retired peer ids: {e}"));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let mut body = String::with_capacity(set.len() * 17);
        for id in set {
            body.push_str(&format!("{id:016x}\n"));
        }
        let tmp = path.with_extension("peers.tmp");
        {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&tmp).map_err(io)?;
            file.write_all(body.as_bytes()).map_err(io)?;
            file.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, &path).map_err(io)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A doc created inside an isolated closure. It has no `Drop` of its own:
/// if the closure unwinds, the doc is leaked rather than dropped (it may be
/// poisoned, #1118). [`GuardedDoc::finish`] drops it on the success path.
struct GuardedDoc(ManuallyDrop<LoroDoc>);

impl GuardedDoc {
    fn new(doc: LoroDoc) -> Self {
        Self(ManuallyDrop::new(doc))
    }

    fn finish(self) {
        drop(ManuallyDrop::into_inner(self.0));
    }
}

impl std::ops::Deref for GuardedDoc {
    type Target = LoroDoc;
    fn deref(&self) -> &LoroDoc {
        &self.0
    }
}

/// One verified record handed to the engine: an opaque id (key plus value
/// digest) and the loro update bytes.
#[derive(Debug, Clone)]
pub struct EngineRecord {
    /// Stable identity of the record (key and value digest).
    pub id: String,
    /// The loro update carried by the record.
    pub update: Arc<Vec<u8>>,
}

/// What a batch import did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Records newly imported.
    pub imported: usize,
    /// Records loro refused with an error.
    pub rejected: usize,
    /// Records whose import panicked (now quarantined).
    pub faulted: usize,
}

/// A save prepared on a fork: the loro updates to wrap in records.
#[derive(Debug, Clone)]
pub struct PreparedSave {
    /// The session peer id that produced every update.
    pub loro_peer: u64,
    /// Updates in counter order, each small enough for one record.
    pub updates: Vec<Vec<u8>>,
}

/// The readable state of a note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteView {
    /// The note text (the last good text when degraded).
    pub text: String,
    /// The encoded version token.
    pub version: String,
    /// Whether the note is degraded (writes refused).
    pub degraded: bool,
}

/// The loro state of one note. Only ever touched inside [`NoteActor::run`].
struct NoteEngine {
    note_id: String,
    note_key: String,
    doc: Option<LoroDoc>,
    session_peer: Option<u64>,
    records: BTreeMap<String, Arc<Vec<u8>>>,
    quarantined: BTreeSet<String>,
    rejected: BTreeSet<String>,
    retired: BTreeSet<u64>,
    last_good_text: String,
    last_good_version: String,
    consecutive_faults: u32,
    degraded: bool,
}

impl NoteEngine {
    fn fault(&self, op: &'static str) -> NoteError {
        NoteError::EngineFault {
            note_id: self.note_id.clone(),
            op,
        }
    }

    fn degraded_error(&self) -> NoteError {
        NoteError::Degraded {
            note_id: self.note_id.clone(),
        }
    }

    fn live_doc(&self) -> Result<&LoroDoc, NoteError> {
        if self.degraded {
            return Err(self.degraded_error());
        }
        self.doc.as_ref().ok_or_else(|| self.degraded_error())
    }

    /// Draw, persist and install a fresh session peer id (ADR 0081 §4).
    fn start_session(&mut self, shared: &EngineShared) -> Result<u64, NoteError> {
        let vv = self.live_doc()?.oplog_vv();
        for _ in 0..MAX_PEER_ID_DRAWS {
            let candidate = shared.peer_source.draw();
            if candidate == u64::MAX
                || vv.get(&candidate).is_some()
                || self.retired.contains(&candidate)
            {
                EngineCounters::bump(&shared.counters.peer_id_redraws);
                continue;
            }
            // Durable first: a crash after this point can never hand the
            // same id to a later session.
            let mut next = self.retired.clone();
            next.insert(candidate);
            shared.persist_retired(&self.note_key, &next)?;
            self.retired = next;
            self.live_doc()?
                .set_peer_id(candidate)
                .map_err(|_| self.fault("set_peer_id"))?;
            self.session_peer = Some(candidate);
            EngineCounters::bump(&shared.counters.sessions_started);
            return Ok(candidate);
        }
        Err(NoteError::PeerIdExhausted)
    }

    fn refresh_last_good(&mut self) {
        if let Some(doc) = self.doc.as_ref() {
            self.last_good_text = doc.get_text(TEXT_CONTAINER).to_string();
            self.last_good_version = encode_version(&doc.oplog_frontiers());
        }
    }

    /// Handle a fault: quarantine the doc (and the record, if one caused
    /// it), then rebuild from the remaining records, repeating while the
    /// rebuild itself faults, until the note is healthy or degraded.
    fn recover(&mut self, shared: &EngineShared, mut faulting: Option<String>) {
        loop {
            EngineCounters::bump(&shared.counters.engine_faults);
            if let Some(id) = faulting.take() {
                self.records.remove(&id);
                if self.quarantined.insert(id) {
                    EngineCounters::bump(&shared.counters.quarantined_records);
                }
            }
            if let Some(doc) = self.doc.take() {
                shared.quarantine.admit(doc, &shared.counters);
            }
            self.session_peer = None;
            self.consecutive_faults = self.consecutive_faults.saturating_add(1);
            let leak_budget_spent = shared.counters.leaked_poisoned_docs.load(Ordering::Relaxed)
                >= MAX_LEAKED_POISONED_DOCS;
            if self.consecutive_faults >= MAX_CONSECUTIVE_FAULTS || leak_budget_spent {
                self.mark_degraded(shared);
                return;
            }
            // Rebuild into a fresh doc. It is stored in `self.doc` before any
            // import, so a panic leaves it where the next round quarantines it.
            self.doc = Some(LoroDoc::new());
            let ids: Vec<String> = self.records.keys().cloned().collect();
            for id in ids {
                let Some(update) = self.records.get(&id).cloned() else {
                    continue;
                };
                let Some(doc) = self.doc.as_ref() else {
                    break;
                };
                match catch_unwind(AssertUnwindSafe(|| doc.import(&update))) {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) => {
                        self.records.remove(&id);
                        self.rejected.insert(id);
                        EngineCounters::bump(&shared.counters.rejected_records);
                    }
                    Err(_) => {
                        faulting = Some(id);
                        break;
                    }
                }
            }
            if faulting.is_some() {
                continue;
            }
            let session = catch_unwind(AssertUnwindSafe(|| self.start_session(shared)));
            match session {
                Ok(Ok(_)) => {
                    let refreshed = catch_unwind(AssertUnwindSafe(|| self.refresh_last_good()));
                    if refreshed.is_ok() {
                        return;
                    }
                }
                Ok(Err(_)) => {
                    // No usable peer id (or its persistence failed): this doc
                    // cannot be written safely.
                    self.mark_degraded(shared);
                    return;
                }
                Err(_) => {}
            }
            // start_session or refresh panicked: another round.
        }
    }

    fn mark_degraded(&mut self, shared: &EngineShared) {
        if let Some(doc) = self.doc.take() {
            shared.quarantine.admit(doc, &shared.counters);
        }
        self.session_peer = None;
        if !self.degraded {
            self.degraded = true;
            EngineCounters::bump(&shared.counters.degraded_notes);
        }
    }

    fn import_records(
        &mut self,
        shared: &EngineShared,
        batch: Vec<EngineRecord>,
    ) -> Result<ImportOutcome, NoteError> {
        let mut outcome = ImportOutcome::default();
        for record in batch {
            if self.degraded {
                return Err(self.degraded_error());
            }
            if self.records.contains_key(&record.id)
                || self.quarantined.contains(&record.id)
                || self.rejected.contains(&record.id)
            {
                continue;
            }
            let doc = self.live_doc()?;
            match catch_unwind(AssertUnwindSafe(|| doc.import(&record.update))) {
                Ok(Ok(_status)) => {
                    // Pending (causally early) changes are held by loro
                    // itself; no delivery gate (ADR 0081).
                    self.records.insert(record.id, record.update);
                    outcome.imported += 1;
                    self.consecutive_faults = 0;
                }
                Ok(Err(_)) => {
                    self.rejected.insert(record.id);
                    EngineCounters::bump(&shared.counters.rejected_records);
                    outcome.rejected += 1;
                }
                Err(_) => {
                    outcome.faulted += 1;
                    self.recover(shared, Some(record.id));
                }
            }
        }
        if !self.degraded {
            self.refresh_last_good();
        }
        Ok(outcome)
    }

    fn view(&self) -> NoteView {
        if self.degraded {
            return NoteView {
                text: self.last_good_text.clone(),
                version: self.last_good_version.clone(),
                degraded: true,
            };
        }
        match self.doc.as_ref() {
            Some(doc) => NoteView {
                text: doc.get_text(TEXT_CONTAINER).to_string(),
                version: encode_version(&doc.oplog_frontiers()),
                degraded: false,
            },
            None => NoteView {
                text: self.last_good_text.clone(),
                version: self.last_good_version.clone(),
                degraded: true,
            },
        }
    }

    fn decode_known_frontiers(&self, version: &[u8]) -> Result<Frontiers, NoteError> {
        let frontiers =
            Frontiers::decode(version).map_err(|e| NoteError::InvalidVersion(e.to_string()))?;
        // Only canonical tokens: loro's decode tolerates trailing bytes, so a
        // token that does not re-encode to itself is refused.
        if frontiers.encode() != version {
            return Err(NoteError::InvalidVersion("non-canonical version".into()));
        }
        if self.live_doc()?.frontiers_to_vv(&frontiers).is_none() {
            return Err(NoteError::BaseVersionUnknown);
        }
        Ok(frontiers)
    }

    /// The text at `version` (ADR 0081 §7): `fork_at` on a replica that
    /// holds every op the frontiers name, else `BaseVersionUnknown`.
    fn text_at(&self, version: &[u8]) -> Result<String, NoteError> {
        let frontiers = self.decode_known_frontiers(version)?;
        let fork = GuardedDoc::new(
            self.live_doc()?
                .fork_at(&frontiers)
                .map_err(|_| NoteError::BaseVersionUnknown)?,
        );
        let text = fork.get_text(TEXT_CONTAINER).to_string();
        fork.finish();
        Ok(text)
    }

    /// Prepare a save on a fork of the live doc. Only a save whose
    /// `base_version` is the current version is accepted in this slice.
    fn prepare_save(
        &self,
        text: &str,
        base_version: &[u8],
        max_update_bytes: usize,
    ) -> Result<PreparedSave, NoteError> {
        let doc = self.live_doc()?;
        let peer = self.session_peer.ok_or_else(|| self.degraded_error())?;
        let base = self.decode_known_frontiers(base_version)?;
        if base != doc.oplog_frontiers() {
            return Err(NoteError::BaseVersionStale);
        }
        let fork = GuardedDoc::new(doc.fork());
        fork.set_peer_id(peer)
            .map_err(|_| self.fault("set_peer_id"))?;
        let vv_before = fork.oplog_vv();
        let root = fork.get_text(TEXT_CONTAINER);
        let diffed = if text.len() > LINE_DIFF_THRESHOLD_BYTES {
            root.update_by_line(text, save_diff_options()).is_ok()
        } else {
            root.update(text, save_diff_options()).is_ok()
        };
        if !diffed {
            return Err(self.fault("text_update"));
        }
        fork.commit();
        let vv_after = fork.oplog_vv();
        let start = vv_before.get(&peer).copied().unwrap_or(0);
        let end = vv_after.get(&peer).copied().unwrap_or(0);
        let updates = if end <= start {
            Vec::new()
        } else {
            self.export_chunks(&fork, &vv_before, peer, start, end, max_update_bytes)?
        };
        fork.finish();
        Ok(PreparedSave {
            loro_peer: peer,
            updates,
        })
    }

    /// `export(ExportMode::updates(vv_before))` when it fits one record,
    /// else the same ops split by counter range into records that each fit.
    fn export_chunks(
        &self,
        fork: &LoroDoc,
        vv_before: &loro::VersionVector,
        peer: u64,
        start: i32,
        end: i32,
        max_update_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, NoteError> {
        let whole = fork
            .export(ExportMode::updates(vv_before))
            .map_err(|_| self.fault("export"))?;
        if whole.len() <= max_update_bytes {
            return Ok(vec![whole]);
        }
        let mut out = Vec::new();
        let mut from = start;
        let mut span = end - start;
        while from < end {
            let to = from.saturating_add(span).min(end);
            let bytes = fork
                .export(ExportMode::updates_in_range(vec![IdSpan::new(
                    peer, from, to,
                )]))
                .map_err(|_| self.fault("export"))?;
            if bytes.len() > max_update_bytes {
                if to - from <= 1 {
                    return Err(NoteError::InvalidRequest(
                        "a single edit is larger than one record".into(),
                    ));
                }
                span = ((to - from) / 2).max(1);
                continue;
            }
            out.push(bytes);
            from = to;
        }
        Ok(out)
    }
}

/// Map the result of an isolated blocking task to the typed error: a task
/// that panicked (`JoinError::is_panic()`) or was cancelled is an
/// [`NoteError::EngineFault`].
pub fn map_join_result<T>(
    op: &'static str,
    note_id: &str,
    joined: Result<Result<T, NoteError>, tokio::task::JoinError>,
) -> Result<T, NoteError> {
    match joined {
        Ok(result) => result,
        Err(_join) => Err(NoteError::EngineFault {
            note_id: note_id.to_string(),
            op,
        }),
    }
}

/// One note's actor: the only owner of its loro doc.
pub struct NoteActor {
    inner: Arc<Mutex<NoteEngine>>,
    shared: Arc<EngineShared>,
    /// Serialises whole saves (prepare → write records → import) so two
    /// saves never allocate the same counters.
    save_lock: tokio::sync::Mutex<()>,
    /// Set when a blocking task panicked outside the inner `catch_unwind`;
    /// the next operation recovers the doc first.
    needs_recovery: AtomicBool,
    /// Record-verification cache (no loro objects).
    verify: Mutex<VerifyCache>,
    note_id: String,
}

/// A roster epoch as `(revision, state_hash)` (ADR 0082 §1).
pub type OpEpoch = (u64, [u8; 32]);

/// `(start, end, epoch)`: a counter range of one peer's ops and the epoch
/// of the accepted record that carried them.
pub type OpRange = (i32, i32, OpEpoch);

/// Per-note record-verification state kept by the store layer.
#[derive(Debug, Default)]
pub struct VerifyCache {
    /// Record ids refused for good (malformed or bad signature).
    pub rejected: BTreeSet<String>,
    /// Author → ML-DSA-65 public key from that author's verified seq-0
    /// record of this note.
    pub author_keys: std::collections::HashMap<[u8; 32], Vec<u8>>,
    /// Op ranges of accepted records → the roster epoch
    /// `(revision, state_hash)` they were written under (ADR 0082 §4).
    pub op_index: std::collections::HashMap<u64, Vec<OpRange>>,
}

impl VerifyCache {
    /// The epoch of the accepted record holding op `(peer, counter)`.
    #[must_use]
    pub fn op_epoch(&self, peer: u64, counter: i32) -> Option<OpEpoch> {
        self.op_index.get(&peer).and_then(|ranges| {
            ranges
                .iter()
                .find(|(start, end, _)| *start <= counter && counter < *end)
                .map(|(_, _, epoch)| *epoch)
        })
    }

    /// Record the op ranges of an accepted record.
    pub fn index_ops(&mut self, spans: &[(u64, i32, i32)], epoch: OpEpoch) {
        for (peer, start, end) in spans {
            self.op_index
                .entry(*peer)
                .or_default()
                .push((*start, *end, epoch));
        }
    }
}

impl std::fmt::Debug for NoteActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoteActor")
            .field("note_id", &self.note_id)
            .finish_non_exhaustive()
    }
}

impl NoteActor {
    /// Open a note: load its retired peer ids, import `records` (isolated)
    /// and start a writing session with a fresh peer id.
    ///
    /// # Errors
    ///
    /// [`NoteError::Store`] if the retired set cannot be read; the other
    /// engine errors if opening faults.
    pub async fn open(
        shared: Arc<EngineShared>,
        note_key: String,
        note_id: String,
        records: Vec<EngineRecord>,
    ) -> Result<Arc<Self>, NoteError> {
        let retired = shared.load_retired(&note_key)?;
        let actor = Arc::new(Self {
            inner: Arc::new(Mutex::new(NoteEngine {
                note_id: note_id.clone(),
                note_key,
                doc: None,
                session_peer: None,
                records: BTreeMap::new(),
                quarantined: BTreeSet::new(),
                rejected: BTreeSet::new(),
                retired,
                last_good_text: String::new(),
                last_good_version: String::new(),
                consecutive_faults: 0,
                degraded: false,
            })),
            shared,
            save_lock: tokio::sync::Mutex::new(()),
            needs_recovery: AtomicBool::new(false),
            verify: Mutex::new(VerifyCache::default()),
            note_id,
        });
        actor
            .run("open", move |engine, shared| {
                engine.doc = Some(LoroDoc::new());
                engine.refresh_last_good();
                engine.import_records(shared, records)?;
                if engine.degraded {
                    return Ok(());
                }
                engine.start_session(shared)?;
                Ok(())
            })
            .await?;
        Ok(actor)
    }

    /// The note id this actor owns.
    #[must_use]
    pub fn note_id(&self) -> &str {
        &self.note_id
    }

    /// Run `f` on the record-verification cache (never across an await).
    pub fn with_verify_cache<R>(&self, f: impl FnOnce(&mut VerifyCache) -> R) -> R {
        let mut cache = self.verify.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut cache)
    }

    /// Run `f` on the engine, isolated (ADR 0081 §3).
    async fn run<T, F>(&self, op: &'static str, f: F) -> Result<T, NoteError>
    where
        T: Send + 'static,
        F: FnOnce(&mut NoteEngine, &EngineShared) -> Result<T, NoteError> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let shared = Arc::clone(&self.shared);
        let recover_first = self.needs_recovery.swap(false, Ordering::AcqRel);
        let joined = tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().unwrap_or_else(PoisonError::into_inner);
            let engine = &mut *guard;
            if recover_first && !engine.degraded {
                engine.recover(&shared, None);
            }
            match catch_unwind(AssertUnwindSafe(|| f(engine, &shared))) {
                Ok(result) => result,
                Err(_panic) => {
                    engine.recover(&shared, None);
                    Err(engine.fault(op))
                }
            }
        })
        .await;
        if matches!(&joined, Err(join) if join.is_panic()) {
            // The panic escaped the inner catch (e.g. inside recovery).
            // Count it and recover before the next operation.
            EngineCounters::bump(&self.shared.counters.engine_faults);
            self.needs_recovery.store(true, Ordering::Release);
        }
        map_join_result(op, &self.note_id, joined)
    }

    /// Import verified records (isolated, per record).
    ///
    /// # Errors
    ///
    /// [`NoteError::Degraded`] when the note is degraded.
    pub async fn import(&self, records: Vec<EngineRecord>) -> Result<ImportOutcome, NoteError> {
        if records.is_empty() {
            return Ok(ImportOutcome::default());
        }
        self.run("import", move |engine, shared| {
            engine.import_records(shared, records)
        })
        .await
    }

    /// Whether a record id was already imported, quarantined or rejected.
    pub async fn known_record_ids(&self) -> Result<BTreeSet<String>, NoteError> {
        self.run("known_records", |engine, _| {
            let mut ids: BTreeSet<String> = engine.records.keys().cloned().collect();
            ids.extend(engine.quarantined.iter().cloned());
            ids.extend(engine.rejected.iter().cloned());
            Ok(ids)
        })
        .await
    }

    /// The current text and version (the last good ones when degraded).
    ///
    /// # Errors
    ///
    /// [`NoteError::EngineFault`] if reading faults.
    pub async fn view(&self) -> Result<NoteView, NoteError> {
        self.run("view", |engine, _| Ok(engine.view())).await
    }

    /// The text at an encoded version token (§7).
    ///
    /// # Errors
    ///
    /// [`NoteError::InvalidVersion`], [`NoteError::BaseVersionUnknown`] or
    /// an engine error.
    pub async fn text_at(&self, version: &str) -> Result<String, NoteError> {
        let bytes = decode_version_bytes(version)?;
        self.run("text_at", move |engine, _| engine.text_at(&bytes))
            .await
    }

    /// The session peer id of the live doc (`None` when degraded).
    pub async fn session_peer(&self) -> Result<Option<u64>, NoteError> {
        self.run("session_peer", |engine, _| Ok(engine.session_peer))
            .await
    }

    /// Every peer id this daemon has used for this note.
    pub async fn retired_peers(&self) -> Result<BTreeSet<u64>, NoteError> {
        self.run("retired_peers", |engine, _| Ok(engine.retired.clone()))
            .await
    }

    /// Record-id → update of every imported record (for tests and rebuild
    /// audits).
    pub async fn imported_updates(&self) -> Result<Vec<(String, Arc<Vec<u8>>)>, NoteError> {
        self.run("imported_updates", |engine, _| {
            Ok(engine
                .records
                .iter()
                .map(|(id, u)| (id.clone(), Arc::clone(u)))
                .collect())
        })
        .await
    }

    /// Lock the actor for one whole save.
    pub async fn lock_save(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.save_lock.lock().await
    }

    /// Prepare a save (hold [`Self::lock_save`] across prepare, write and
    /// import).
    ///
    /// # Errors
    ///
    /// Version errors, [`NoteError::Degraded`], or an engine fault.
    pub async fn prepare_save(
        &self,
        text: String,
        base_version: &str,
        max_update_bytes: usize,
    ) -> Result<PreparedSave, NoteError> {
        let base = decode_version_bytes(base_version)?;
        self.run("prepare_save", move |engine, _| {
            engine.prepare_save(&text, &base, max_update_bytes)
        })
        .await
    }

    /// End the current writing session and start a new one with a fresh
    /// peer id. Called after a save that did not complete, so counters a
    /// failed save may have exposed are never reused with other content.
    ///
    /// # Errors
    ///
    /// [`NoteError::PeerIdExhausted`], a persistence error, or degraded.
    pub async fn rotate_session(&self) -> Result<u64, NoteError> {
        self.run("rotate_session", |engine, shared| {
            engine.start_session(shared)
        })
        .await
    }

    /// Run an arbitrary closure inside the isolation — test hook for the
    /// panic-containment corpus.
    #[cfg(test)]
    pub(crate) async fn run_raw_for_test<T, F>(
        &self,
        op: &'static str,
        f: F,
    ) -> Result<T, NoteError>
    where
        T: Send + 'static,
        F: FnOnce(&LoroDoc) -> T + Send + 'static,
    {
        self.run(op, move |engine, _| {
            let doc = engine.live_doc()?;
            Ok(f(doc))
        })
        .await
    }
}

/// Registry of note actors, keyed by `<store>/<note_id>`.
#[derive(Debug)]
pub struct NotesEngine {
    shared: Arc<EngineShared>,
    actors: tokio::sync::Mutex<std::collections::HashMap<String, Arc<NoteActor>>>,
}

impl NotesEngine {
    /// A registry drawing peer ids from the OS CSPRNG and persisting retired
    /// sets under `retired_dir`.
    #[must_use]
    pub fn new(retired_dir: Option<PathBuf>) -> Self {
        Self::with_peer_source(Box::new(OsPeerIdSource), retired_dir)
    }

    /// A registry with an injected peer-id source.
    #[must_use]
    pub fn with_peer_source(
        peer_source: Box<dyn PeerIdSource>,
        retired_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            shared: Arc::new(EngineShared::new(peer_source, retired_dir)),
            actors: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Engine counters.
    #[must_use]
    pub fn counters(&self) -> EngineCountersSnapshot {
        self.shared.counters.snapshot()
    }

    /// The open actor for `note_key`, if any.
    pub async fn get(&self, note_key: &str) -> Option<Arc<NoteActor>> {
        self.actors.lock().await.get(note_key).cloned()
    }

    /// The actor for `note_key`, opening it from `records` when absent.
    ///
    /// # Errors
    ///
    /// As [`NoteActor::open`].
    pub async fn get_or_open(
        &self,
        note_key: &str,
        note_id: &str,
        records: impl FnOnce() -> Vec<EngineRecord>,
    ) -> Result<Arc<NoteActor>, NoteError> {
        let mut actors = self.actors.lock().await;
        if let Some(actor) = actors.get(note_key) {
            return Ok(Arc::clone(actor));
        }
        let actor = NoteActor::open(
            Arc::clone(&self.shared),
            note_key.to_string(),
            note_id.to_string(),
            records(),
        )
        .await?;
        actors.insert(note_key.to_string(), Arc::clone(&actor));
        Ok(actor)
    }

    /// Count of degraded notes among open actors.
    pub async fn open_notes(&self) -> usize {
        self.actors.lock().await.len()
    }
}
