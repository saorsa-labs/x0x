//! Persistence + startup rehydration for CRDT subscriptions (task lists and
//! key-value stores).
//!
//! Fixes daemon-restart amnesia: `AppState.task_lists` / `AppState.kv_stores`
//! were only ever populated by the REST create/join handlers, so a restarted
//! daemon answered "task list not found" / "store not found" until the
//! application explicitly re-created or re-joined. This module persists a
//! small subscription manifest (`crdt-subscriptions.json`, same instance data
//! dir as `directory-subscriptions.json`) whenever a handler registers a
//! task list or store, and rehydrates every entry on startup by driving the
//! SAME `Agent` create/join paths the handlers use — so the gossip topic
//! subscription and the empty-replica state-request bootstrap both happen and
//! mutations made while the daemon was offline are recovered from peers.
//!
//! Design follows the Phase C.2 directory-subscription persistence pattern
//! (`load_directory_subscriptions` / `save_directory_subscriptions` in
//! `src/server/mod.rs`): best-effort JSON on disk, warn-and-continue on any
//! error, never crash startup.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use super::state::AppState;

/// Manifest entry kind for a collaborative task list.
pub(super) const KIND_TASK_LIST: &str = "task_list";
/// Manifest entry kind for a replicated key-value store.
pub(super) const KIND_KV_STORE: &str = "kv_store";
/// Role recorded when this daemon created the task list / store.
pub(super) const ROLE_CREATED: &str = "created";
/// Role recorded when this daemon joined an existing store.
pub(super) const ROLE_JOINED: &str = "joined";

/// One persisted CRDT subscription.
///
/// The schema is deliberately extensible: unknown fields present in the file
/// are captured in `extra` (via `serde(flatten)`) and preserved across
/// load/save cycles, so a future daemon can add fields (e.g. owner/policy
/// info for kv stores) without older builds destroying them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct CrdtSubscriptionEntry {
    /// Entry kind: [`KIND_TASK_LIST`] or [`KIND_KV_STORE`]. Unknown kinds are
    /// kept on disk but skipped (with a warning) at rehydration time.
    pub(super) kind: String,
    /// Registration id used as the `AppState` map key (currently the topic).
    pub(super) id: String,
    /// Human-readable name passed to the create call.
    pub(super) name: String,
    /// Gossip topic the CRDT syncs on.
    pub(super) topic: String,
    /// [`ROLE_CREATED`] or [`ROLE_JOINED`] — selects the create vs join
    /// `Agent` path at rehydration time.
    pub(super) role: String,
    /// Forward-compatibility: unknown fields survive round-trips.
    #[serde(flatten)]
    pub(super) extra: serde_json::Map<String, serde_json::Value>,
}

/// On-disk manifest: the full set of persisted CRDT subscriptions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct CrdtSubscriptionManifest {
    /// All persisted subscriptions, in insertion order.
    #[serde(default)]
    pub(super) entries: Vec<CrdtSubscriptionEntry>,
    /// Forward-compatibility: unknown top-level fields survive round-trips.
    #[serde(flatten)]
    pub(super) extra: serde_json::Map<String, serde_json::Value>,
}

impl CrdtSubscriptionManifest {
    /// Insert `entry`, replacing any existing entry with the same
    /// `(kind, id)`. Returns `true` if the manifest changed.
    ///
    /// Forward-compatibility: when replacing, unknown `extra` fields already
    /// on the existing entry that the incoming entry does not provide are
    /// preserved, so a re-registration by an older handler (or a rollback/
    /// upgrade) cannot delete future schema fields (e.g. owner epoch/policy).
    /// Known fields (`name`, `topic`, `role`) take the incoming value.
    pub(super) fn upsert(&mut self, entry: CrdtSubscriptionEntry) -> bool {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.kind == entry.kind && e.id == entry.id)
        {
            // Incoming `extra` wins for keys it sets; existing-only extra
            // keys (future/unknown fields) are carried forward untouched.
            let mut merged_extra = entry.extra.clone();
            for (k, v) in &existing.extra {
                merged_extra.entry(k.clone()).or_insert_with(|| v.clone());
            }
            let merged = CrdtSubscriptionEntry {
                kind: existing.kind.clone(),
                id: existing.id.clone(),
                name: entry.name,
                topic: entry.topic,
                role: entry.role,
                extra: merged_extra,
            };
            if *existing == merged {
                return false;
            }
            *existing = merged;
        } else {
            self.entries.push(entry);
        }
        true
    }

    /// Remove the entry with the given `(kind, id)`. Returns `true` if an
    /// entry was removed.
    ///
    /// No task-list/store delete or leave REST endpoint exists today (the
    /// endpoint registry in `src/api/mod.rs` only has `DELETE
    /// /stores/:id/:key`, which removes a key, not the store), so production
    /// code has no caller yet — this is the removal half of the manifest API,
    /// ready for when such endpoints land.
    #[allow(dead_code)]
    pub(super) fn remove(&mut self, kind: &str, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| !(e.kind == kind && e.id == id));
        self.entries.len() != before
    }
}

/// Read the manifest from `path` (best-effort).
///
/// A missing file yields an empty manifest silently; an unreadable or
/// corrupt file yields an empty manifest with a warning — startup must never
/// crash on a bad manifest (fail loud in logs, not in process exit).
pub(super) async fn read_manifest(path: &Path) -> CrdtSubscriptionManifest {
    match tokio::fs::read(path).await {
        Ok(bytes) => match serde_json::from_slice::<CrdtSubscriptionManifest>(&bytes) {
            Ok(manifest) => manifest,
            Err(e) => {
                tracing::warn!(
                    "failed to parse CRDT subscription manifest {} (starting empty): {e}",
                    path.display()
                );
                CrdtSubscriptionManifest::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!("no CRDT subscription manifest at {}", path.display());
            CrdtSubscriptionManifest::default()
        }
        Err(e) => {
            tracing::warn!(
                "failed to read CRDT subscription manifest {} (starting empty): {e}",
                path.display()
            );
            CrdtSubscriptionManifest::default()
        }
    }
}

/// Write `manifest` to `path` crash-safely.
///
/// The manifest is serialised, written to a same-directory temp file,
/// `sync_all`'d, and atomically renamed over `path` — mirroring
/// `write_named_groups_json_atomic` in `src/server/mod.rs`. A crash or
/// failure mid-write leaves the previous (good) manifest untouched. Returns
/// `Err` on serialise or write failure so callers (via `record`) can refuse to
/// acknowledge a non-durable registration; unknown/forward-compatible `extra`
/// fields pass through unchanged.
pub(super) async fn write_manifest(
    path: &Path,
    manifest: &CrdtSubscriptionManifest,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    write_manifest_atomic(path, &bytes).await
}

/// Crash-safe single-file write: temp file in the same directory, `sync_all`,
/// then atomic rename. Same pattern as `write_named_groups_json_atomic`. On
/// failure OR task cancellation the temp file is reclaimed by a guard, so a
/// failed/cancelled write leaves no debris and never replaces the last good
/// manifest with a partial file.
async fn write_manifest_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    // #231: reclaim `.tmp` debris left by a process kill/crash mid-write —
    // the TempFile guard cannot run when destructors are skipped. Runs
    // BEFORE we mint our own temp below; age-bounded so a live concurrent
    // writer's temp is never touched.
    sweep_stale_temp_files(path, SystemTime::now());

    // Same directory as the target so the rename is atomic on one filesystem.
    let mut temp_os = path.as_os_str().to_owned();
    temp_os.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let temp_path = PathBuf::from(temp_os);

    // RAII: removes the temp file on drop unless disarmed after a successful
    // rename. Covers both error returns and task cancellation mid-write.
    let mut temp = TempFile::new(temp_path.clone());

    let result = async {
        // Create the temp file SYNCHRONOUSLY (one fast syscall, same pattern
        // as `sync_parent_dir`), not via tokio::fs: the async open dispatches
        // to the blocking pool, and if this future is cancelled while the
        // open is in flight, the file can be created AFTER the TempFile
        // guard's drop already ran its cleanup — orphaned `.tmp` debris.
        // Creating before the first await point means the guard always sees
        // the file; a blocking write still in flight at cancellation goes to
        // the unlinked inode and is freed on close.
        let mut file = {
            let std_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            tokio::fs::File::from_std(std_file)
        };
        file.write_all(bytes).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temp_path, path).await?;
        // Parent-directory fsync is REQUIRED for durable acknowledgement:
        // a rename without a successful dir fsync may not survive power
        // loss. We propagate the error so the caller (via persist_recorded's
        // stage-then-commit) never falsely acknowledges durability. Memory
        // stays at its pre-write state; an identical retry re-stages from old
        // memory and rewrites — the file content is idempotent. The rename
        // itself succeeded (file is at `path`), so the TempFile guard's
        // drop-cleanup harmlessly no-ops (temp no longer exists).
        if let Err(e) = sync_parent_dir(path) {
            tracing::warn!(
                "parent-directory fsync failed for {}: refusing to \
                 acknowledge durability after successful rename ({e})",
                path.display()
            );
            return Err(e);
        }
        Ok::<(), std::io::Error>(())
    }
    .await;

    match result {
        Ok(()) => {
            temp.disarm(); // consumed by the rename
            Ok(())
        }
        Err(e) => Err(e), // guard drops and removes the temp file
    }
}

/// Maximum age of a manifest temp file before it is treated as abandoned
/// debris. A live write holds its temp for only a few milliseconds
/// (create → write → fsync → rename), so 60s is far beyond any legitimate
/// in-flight write — even under heavy blocking-pool scheduling delay —
/// while bounding crash debris lifetime to the next manifest write.
const STALE_TEMP_FILE_MAX_AGE: Duration = Duration::from_secs(60);

/// Best-effort removal of abandoned `.{uuid}.tmp` siblings of `path` older
/// than [`STALE_TEMP_FILE_MAX_AGE`].
///
/// WHY (#231): the [`TempFile`] guard reclaims the temp file on every
/// error/cancellation path, but a process kill (SIGKILL, abort, power loss)
/// mid-write skips ALL destructors, leaking one `.tmp` per crash — and
/// nothing else ever removes those, so they would accumulate forever.
///
/// Crash-safety: temp names are minted with a random UUID per write, and
/// the sweep is AGE-bounded rather than "not ours" — so it cannot remove a
/// temp held by a live concurrent writer in this process, including writers
/// NOT serialised by the persistence lock (see
/// `concurrent_manifest_writes_never_corrupt`). Anything provably younger
/// than the bound — or of unknowable age (metadata/future-mtime errors) —
/// is conservatively kept.
///
/// Synchronous `std::fs`, same pattern as the temp-file create above: one
/// small directory scan before the write's first await. Every failure is
/// logged-and-skipped — hygiene must never fail the actual write.
fn sweep_stale_temp_files(path: &Path, now: SystemTime) {
    let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) else {
        return;
    };
    // Temp names are minted as `{manifest_file_name}.{uuid}.tmp`.
    let prefix = format!("{}.", file_name.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
            continue;
        }
        // Regular files only — never touch a directory or symlink that
        // happens to match the name shape.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        // Keep anything not PROVABLY stale (future mtime → Err → keep).
        let Ok(age) = now.duration_since(modified) else {
            continue;
        };
        if age < STALE_TEMP_FILE_MAX_AGE {
            continue;
        }
        if let Err(e) = std::fs::remove_file(entry.path()) {
            tracing::warn!(
                "failed to remove stale temp file {}: {e}",
                entry.path().display()
            );
        } else {
            tracing::debug!("removed stale temp file {}", entry.path().display());
        }
    }
}

/// RAII guard that removes a temp file on drop unless disarmed (after a
/// successful rename consumes it). Uses blocking `std::fs` because `Drop`
/// cannot await — appropriate for a single-file cleanup.
struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl TempFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// Test-injection flag: when set, `sync_parent_dir` returns a synthetic
// `Err` so tests can verify that a dir-fsync failure propagates as a
// non-acknowledged durable write (the rename succeeds but the caller
// refuses to treat it as durable). Compiled out in release builds.
#[cfg(test)]
thread_local! {
    static INJECT_DIR_FSYNC_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// RAII guard that enables the dir-fsync failure injection for the duration
/// of a test. Drop resets the flag so parallel or subsequent tests are
/// unaffected. Compiled out in release builds.
#[cfg(test)]
pub(super) struct DirFsyncFailureGuard;

#[cfg(test)]
impl DirFsyncFailureGuard {
    /// Enable dir-fsync failure injection. Reset happens automatically on
    /// drop of the returned guard.
    pub(super) fn enable() -> Self {
        INJECT_DIR_FSYNC_FAILURE.with(|c| c.set(true));
        DirFsyncFailureGuard
    }
}

#[cfg(test)]
impl Drop for DirFsyncFailureGuard {
    fn drop(&mut self) {
        INJECT_DIR_FSYNC_FAILURE.with(|c| c.set(false));
    }
}

/// `fsync` of the directory containing `path` so a rename within it is
/// durable across power loss. Returns `Err` on failure — `write_manifest_atomic`
/// propagates this so the caller never falsely acknowledges durability. The
/// rename itself is already committed (file is at `path`); the error means
/// the rename may not survive a power-loss crash. `Ok(())` where directory
/// fsync is unavailable (non-Unix).
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    // Test injection: simulate a dir-fsync failure to verify the caller
    // refuses to acknowledge durability.
    #[cfg(test)]
    if INJECT_DIR_FSYNC_FAILURE.with(|c| c.get()) {
        return Err(std::io::Error::other("injected dir-fsync failure"));
    }
    if let Some(parent) = path.parent() {
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Load the persisted manifest from disk into `state.crdt_subscriptions`.
///
/// Called once during startup, before REST handlers can mutate the set, so a
/// create/join arriving early merges with (rather than clobbers) the
/// persisted entries.
pub(super) async fn load(state: &AppState) {
    let manifest = read_manifest(&state.crdt_subscriptions_path).await;
    let n = manifest.entries.len();
    *state.crdt_subscriptions.write().await = manifest;
    if n > 0 {
        tracing::info!(
            "loaded {n} persisted CRDT subscriptions from {}",
            state.crdt_subscriptions_path.display()
        );
    }
}

/// Record a new/updated subscription in the in-memory manifest and durably
/// persist it to disk. Called by the REST create/join handlers after a
/// successful registration.
///
/// This is a durable transaction (see `persist_recorded`): the manifest is
/// staged in a clone, durably written, and then committed to live memory —
/// only if the write reaches disk. The whole stage → write → commit sequence
/// is serialised by `crdt_subscriptions_persistence_lock`. Returns `Err` if
/// the manifest could not be made durable, so the handler can refuse to
/// acknowledge a non-durable registration. On `Err` or cancellation the
/// in-memory manifest is untouched (it was never mutated), so memory always
/// matches durable state and an identical retry re-stages and re-writes.
pub(super) async fn record(state: &AppState, entry: CrdtSubscriptionEntry) -> std::io::Result<()> {
    persist_recorded(
        &state.crdt_subscriptions,
        &state.crdt_subscriptions_persistence_lock,
        &state.crdt_subscriptions_path,
        entry,
    )
    .await
}

/// Snapshot-and-write core of [`record`], factored out so the durable
/// transaction is unit-testable without a full `AppState`.
///
/// `persistence_lock` serialises the whole stage → durable-write → commit
/// sequence; `manifest` is the live in-memory state; `path` is the on-disk
/// manifest location.
///
/// **Stage-then-commit** (cancellation-safe): the upsert is applied to a
/// *clone* under a read lock; `write_manifest` is awaited on that clone;
/// only after `Ok` is the clone committed to live memory via `write()`.
/// On `Err` — or if the future is dropped (cancelled) during the disk-write
/// await — live memory was never touched, so there is nothing to roll back
/// and nothing diverges from disk. An identical retry sees the entry absent
/// from the (unchanged) live manifest, re-stages, and re-writes — never a
/// silent no-op. The old mutate-then-rollback path is gone: the only
/// cancellable `.await` (the disk write) happens *before* any memory
/// mutation.
async fn persist_recorded(
    manifest: &RwLock<CrdtSubscriptionManifest>,
    persistence_lock: &Mutex<()>,
    path: &Path,
    entry: CrdtSubscriptionEntry,
) -> std::io::Result<()> {
    let _guard = persistence_lock.lock().await;
    // Stage the upsert in a clone — do NOT touch live memory yet. The
    // persistence_lock serialises all recorders, so nothing else mutates
    // `manifest` between this read and the commit write below.
    let staged = {
        let current = manifest.read().await;
        let mut candidate = current.clone();
        if !candidate.upsert(entry) {
            // Already current in memory. Because memory is only ever committed
            // AFTER a durable write succeeds (see commit below), "current in
            // memory" honestly implies "current on disk" — this is a durable
            // no-op.
            return Ok(());
        }
        candidate
    };
    // Durably persist the staged snapshot. If this await returns Err OR is
    // cancelled (future dropped), live memory is untouched — it still matches
    // what is on disk. No rollback is needed because nothing was mutated.
    write_manifest(path, &staged).await?;
    // Commit: the durable write succeeded, so it is now safe to update
    // in-memory state. This write-lock acquisition + store cannot be
    // cancelled in a way that diverges memory from disk (it is a
    // synchronous in-process lock + pointer swap).
    *manifest.write().await = staged;
    Ok(())
}

/// Get-or-create the per-`(kind, id)` reservation lock for a CRDT
/// subscription handle+manifest transaction.
///
/// The caller must `.lock().await` the returned [`Arc`] and hold the guard
/// for the entire create/join → insert-handle → persist-manifest sequence,
/// then drop it. This serialises concurrent same-`(kind,id)` REST requests
/// and REST-vs-rehydrate races so that:
///
/// - a failing transaction removes only its own handle (no other same-ID
///   request could have interleaved an insert under the same reservation);
/// - duplicate long-lived sync listeners cannot be spawned (the loser sees
///   the winner's handle and no-ops).
///
/// Keyed by `"{kind}:{id}"` — the kinds (`task_list`, `kv_store`) are fixed
/// and never contain `:`, so the composite key is unique per pair regardless
/// of what characters appear in `id`.
pub(super) async fn handle_reservation(state: &AppState, kind: &str, id: &str) -> Arc<Mutex<()>> {
    let key = format!("{kind}:{id}");
    let mut locks = state.crdt_handle_locks.write().await;
    // Opportunistic pruning (issue #238 round-2 review): without it every
    // distinct (kind,id) ever requested pins an Arc<Mutex> forever — an
    // unbounded-growth vector for authenticated callers minting unique ids.
    // An entry with strong count 1 is held ONLY by this map: a live guard
    // implies a cloned Arc, and clones are only ever minted under this same
    // write lock, so removal cannot race a concurrent acquisition.
    locks.retain(|k, v| *k == key || Arc::strong_count(v) > 1);
    locks
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Parse a hex-encoded `AgentId` (64 hex chars → 32 bytes) from a manifest
/// `expected_owner` field. Returns `None` if the value is not valid hex or not
/// exactly 32 bytes — the caller treats that as migration-required.
/// Resolve the persisted access policy from a manifest entry's `extra` map.
///
/// - `"append_only"` → `AppendOnly`; `"signed"` → `Signed`.
/// - Absent key → `Signed` (legacy entries predate the policy field and were
///   all created Signed — this is a documented compatibility default, not a
///   downgrade).
/// - Present but unrecognized → `None`: the caller must FAIL CLOSED (skip the
///   rehydration loudly). Mapping garbage to `Signed` would silently strip a
///   possibly-append-only store of its immutability.
fn manifest_policy(
    extra: &serde_json::Map<String, serde_json::Value>,
) -> Option<crate::kv::AccessPolicy> {
    match extra.get("policy") {
        None => Some(crate::kv::AccessPolicy::Signed),
        Some(serde_json::Value::String(s)) if s == "signed" => {
            Some(crate::kv::AccessPolicy::Signed)
        }
        Some(serde_json::Value::String(s)) if s == "append_only" => {
            Some(crate::kv::AccessPolicy::AppendOnly)
        }
        Some(_) => None,
    }
}

fn parse_owner_hex(hex_str: &str) -> Option<crate::identity::AgentId> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() == crate::identity::PEER_ID_LENGTH {
        let mut arr = [0u8; crate::identity::PEER_ID_LENGTH];
        arr.copy_from_slice(&bytes);
        Some(crate::identity::AgentId(arr))
    } else {
        None
    }
}

/// Rehydrate every persisted subscription by driving the same `Agent`
/// create/join paths the REST handlers use.
///
/// Runs concurrently with `join_network` (issue #238) — it must NOT wait for
/// bootstrap: a daemon's own stores restore from local snapshots and joined
/// stores only register subscriptions, so an unreachable bootstrap peer must
/// never delay them. The per-CRDT state-request schedule (front burst plus a
/// persistent while-empty tail) recovers state — including mutations made
/// while this daemon was offline — from peer replicas whenever they become
/// reachable. A failed entry is logged (warn) and skipped, never fatal, and
/// stays in the manifest so the next restart retries it.
///
/// Entries are rehydrated CONCURRENTLY (not sequentially) so that a slow or
/// blocked entry — e.g. a joined KV store whose owner-anchored Signed
/// bootstrap awaits a slow subscription — cannot starve or delay the
/// rehydration of an unrelated entry (e.g. a task list). Each create/join
/// subscribes to its own topic and schedules its own background state-request
/// retry loop; running them concurrently lets every topic's recovery start
/// without waiting on the others. State recovery is per-topic and idempotent,
/// so concurrent rehydration is safe.
pub(super) async fn rehydrate(state: Arc<AppState>) {
    let entries = state.crdt_subscriptions.read().await.entries.clone();
    if entries.is_empty() {
        return;
    }
    let results = futures::future::join_all(
        entries
            .into_iter()
            .map(|entry| rehydrate_one(Arc::clone(&state), entry)),
    )
    .await;
    let (mut restored, mut skipped) = (0usize, 0usize);
    for outcome in results {
        match outcome {
            RehydrateOutcome::Restored => restored += 1,
            RehydrateOutcome::Skipped => skipped += 1,
            RehydrateOutcome::AlreadyPresent => {}
        }
    }
    tracing::info!(restored, skipped, "CRDT subscription rehydration complete");
}

/// Outcome of rehydrating a single manifest entry.
enum RehydrateOutcome {
    /// A new handle was created and inserted.
    Restored,
    /// Rehydration failed or was not applicable (logged); the entry stays in
    /// the manifest for the next restart to retry.
    Skipped,
    /// A live handle already existed (re-created via REST since startup).
    AlreadyPresent,
}

/// Rehydrate a single persisted subscription. See [`rehydrate`] for the
/// concurrency rationale; this preserves the same per-kind/per-role logic and
/// warn-and-skip behaviour as the original sequential loop.
///
/// Acquires the per-`(kind,id)` reservation ([`handle_reservation`]) BEFORE
/// the check-then-create so a concurrent REST create/join for the same
/// `(kind,id)` cannot interleave and spawn a duplicate long-lived sync
/// listener: the loser of the race sees the winner's handle and returns
/// [`RehydrateOutcome::AlreadyPresent`].
async fn rehydrate_one(state: Arc<AppState>, entry: CrdtSubscriptionEntry) -> RehydrateOutcome {
    // Acquire the per-(kind,id) reservation before the check-then-create so
    // a concurrent REST create/join cannot spawn a duplicate listener.
    let reservation = handle_reservation(&state, &entry.kind, &entry.id).await;
    let _guard = reservation.lock().await;

    match entry.kind.as_str() {
        KIND_TASK_LIST => {
            if state.task_lists.read().await.contains_key(&entry.id) {
                return RehydrateOutcome::AlreadyPresent; // re-created via REST since startup
            }
            let result = match entry.role.as_str() {
                ROLE_JOINED => state.agent.join_task_list(&entry.topic).await,
                ROLE_CREATED => {
                    state
                        .agent
                        .create_task_list(&entry.name, &entry.topic)
                        .await
                }
                other => {
                    tracing::warn!(
                        id = %entry.id,
                        role = other,
                        "unknown task-list subscription role — skipping"
                    );
                    return RehydrateOutcome::Skipped;
                }
            };
            match result {
                Ok(handle) => {
                    // Apply group authorization at the CRDT layer so remote
                    // admission rejects nonmember operations for group-scoped
                    // lists. Must run before insertion so the sync listener
                    // starts with the correct authorized set.
                    super::routes::apply_group_authorization(&state, &entry.id, &handle).await;
                    state
                        .task_lists
                        .write()
                        .await
                        .entry(entry.id.clone())
                        .or_insert(handle);
                    RehydrateOutcome::Restored
                }
                Err(e) => {
                    tracing::warn!(
                        id = %entry.id,
                        "failed to rehydrate task list after restart: {e}"
                    );
                    RehydrateOutcome::Skipped
                }
            }
        }
        KIND_KV_STORE => {
            if state.kv_stores.read().await.contains_key(&entry.id) {
                return RehydrateOutcome::AlreadyPresent; // re-created/joined via REST since startup
            }
            let result = match entry.role.as_str() {
                ROLE_JOINED => {
                    // The owner anchor is REQUIRED: a join without it is a
                    // dead replica, not a successful rehydration. A legacy
                    // entry with no stored anchor, or a malformed one, is
                    // migration-required — skip it loudly rather than
                    // creating a read-only handle that can never accept
                    // Signed state.
                    let owner = match entry.extra.get("expected_owner").and_then(|v| v.as_str()) {
                        Some(hex_str) => match parse_owner_hex(hex_str) {
                            Some(id) => id,
                            None => {
                                tracing::warn!(
                                    id = %entry.id,
                                    "stored expected_owner is malformed; \
                                     skipping rehydration (migration_required)"
                                );
                                return RehydrateOutcome::Skipped;
                            }
                        },
                        None => {
                            tracing::warn!(
                                id = %entry.id,
                                "no stored expected_owner for joined store; \
                                 skipping rehydration (migration_required). \
                                 Re-join with an owner anchor to recover."
                            );
                            return RehydrateOutcome::Skipped;
                        }
                    };
                    state
                        .agent
                        .join_kv_store_persistent(
                            &entry.topic,
                            owner,
                            crate::kv::store::AnchorChannel::Persistence,
                            &state.kv_store_state_dir,
                        )
                        .await
                }
                ROLE_CREATED => {
                    // Restore the persisted policy: an append-only store must
                    // never rehydrate as plain Signed (that would silently
                    // drop its immutability guarantees). A malformed policy
                    // string FAILS CLOSED (skip loudly) — defaulting it to
                    // Signed would be a silent downgrade. The state snapshot
                    // (restored inside create_kv_store_persistent) is the
                    // final authority and itself fails closed on conflicts.
                    let policy = match manifest_policy(&entry.extra) {
                        Some(policy) => policy,
                        None => {
                            tracing::warn!(
                                id = %entry.id,
                                "stored kv-store policy is malformed; \
                                 skipping rehydration (migration_required)"
                            );
                            return RehydrateOutcome::Skipped;
                        }
                    };
                    state
                        .agent
                        .create_kv_store_persistent(
                            &entry.name,
                            &entry.topic,
                            policy,
                            &state.kv_store_state_dir,
                        )
                        .await
                }
                other => {
                    tracing::warn!(
                        id = %entry.id,
                        role = other,
                        "unknown kv-store subscription role — skipping"
                    );
                    return RehydrateOutcome::Skipped;
                }
            };
            match result {
                Ok(handle) => {
                    state
                        .kv_stores
                        .write()
                        .await
                        .entry(entry.id.clone())
                        .or_insert(handle);
                    RehydrateOutcome::Restored
                }
                Err(e) => {
                    tracing::warn!(
                        id = %entry.id,
                        "failed to rehydrate kv store after restart: {e}"
                    );
                    RehydrateOutcome::Skipped
                }
            }
        }
        other => {
            tracing::warn!(
                id = %entry.id,
                kind = other,
                "unknown CRDT subscription kind — skipping (kept in manifest)"
            );
            RehydrateOutcome::Skipped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_policy_parses_and_fails_closed() {
        // WHY: a malformed policy string must NEVER silently become Signed —
        // that would strip a possibly-append-only store of its immutability
        // on restart. Absent = legacy Signed (compat default); garbage =
        // None (caller skips loudly).
        let mut extra = serde_json::Map::new();
        assert_eq!(
            manifest_policy(&extra),
            Some(crate::kv::AccessPolicy::Signed),
            "legacy entry without a policy field is Signed"
        );
        extra.insert("policy".into(), serde_json::Value::String("signed".into()));
        assert_eq!(
            manifest_policy(&extra),
            Some(crate::kv::AccessPolicy::Signed)
        );
        extra.insert(
            "policy".into(),
            serde_json::Value::String("append_only".into()),
        );
        assert_eq!(
            manifest_policy(&extra),
            Some(crate::kv::AccessPolicy::AppendOnly)
        );
        extra.insert(
            "policy".into(),
            serde_json::Value::String("immutable".into()),
        );
        assert_eq!(manifest_policy(&extra), None, "garbage fails closed");
        extra.insert("policy".into(), serde_json::Value::Bool(true));
        assert_eq!(manifest_policy(&extra), None, "non-string fails closed");
    }

    fn entry(kind: &str, id: &str, role: &str) -> CrdtSubscriptionEntry {
        CrdtSubscriptionEntry {
            kind: kind.to_string(),
            id: id.to_string(),
            name: format!("{id}-name"),
            topic: id.to_string(),
            role: role.to_string(),
            extra: serde_json::Map::new(),
        }
    }

    /// WHY: the whole fix rests on the manifest surviving a daemon restart —
    /// a save/load round-trip must reproduce exactly what was recorded.
    #[tokio::test]
    async fn manifest_round_trips_through_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");

        let mut manifest = CrdtSubscriptionManifest::default();
        assert!(manifest.upsert(entry(KIND_TASK_LIST, "sprint", ROLE_CREATED)));
        assert!(manifest.upsert(entry(KIND_KV_STORE, "party", ROLE_JOINED)));
        // Re-upserting an identical entry is a no-op (no disk churn).
        assert!(!manifest.upsert(entry(KIND_KV_STORE, "party", ROLE_JOINED)));

        write_manifest(&path, &manifest)
            .await
            .expect("write manifest");
        let loaded = read_manifest(&path).await;
        assert_eq!(loaded, manifest);

        // Remove drops exactly the matching (kind, id) pair.
        let mut loaded = loaded;
        assert!(loaded.remove(KIND_KV_STORE, "party"));
        assert!(!loaded.remove(KIND_KV_STORE, "party"));
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].id, "sprint");

        write_manifest(&path, &loaded)
            .await
            .expect("write manifest");
        assert_eq!(read_manifest(&path).await, loaded);
    }

    /// WHY: upsert must replace, not duplicate, so a re-create after restart
    /// (or a role change) cannot grow the manifest unboundedly.
    #[test]
    fn upsert_replaces_same_kind_and_id() {
        let mut manifest = CrdtSubscriptionManifest::default();
        manifest.upsert(entry(KIND_KV_STORE, "party", ROLE_JOINED));
        manifest.upsert(entry(KIND_KV_STORE, "party", ROLE_CREATED));
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.entries[0].role, ROLE_CREATED);
        // Same id under a different kind is a distinct entry.
        manifest.upsert(entry(KIND_TASK_LIST, "party", ROLE_CREATED));
        assert_eq!(manifest.entries.len(), 2);
    }

    /// WHY: a corrupt manifest must degrade to "no persisted subscriptions"
    /// (fail loud in logs), never crash the daemon at startup.
    #[tokio::test]
    async fn corrupt_manifest_yields_empty_and_does_not_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");
        tokio::fs::write(&path, b"{not json at all")
            .await
            .expect("write corrupt file");
        let loaded = read_manifest(&path).await;
        assert!(loaded.entries.is_empty());

        // Missing file is equally tolerated.
        let missing = dir.path().join("does-not-exist.json");
        assert!(read_manifest(&missing).await.entries.is_empty());
    }

    /// WHY: schema extensibility is a stated requirement — unknown fields
    /// written by a future daemon must be tolerated AND preserved across a
    /// load/save cycle by this build.
    #[tokio::test]
    async fn unknown_fields_are_tolerated_and_preserved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");
        let future_schema = serde_json::json!({
            "schema_version": 2,
            "entries": [{
                "kind": "kv_store",
                "id": "party",
                "name": "party",
                "topic": "party",
                "role": "joined",
                "owner": "abcd1234",
                "policy": { "kind": "signed" }
            }]
        });
        tokio::fs::write(&path, serde_json::to_vec(&future_schema).expect("json"))
            .await
            .expect("write");

        let loaded = read_manifest(&path).await;
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].extra["owner"], "abcd1234");
        assert_eq!(loaded.extra["schema_version"], 2);

        // Round-trip preserves the unknown fields.
        write_manifest(&path, &loaded)
            .await
            .expect("write manifest");
        let reloaded = read_manifest(&path).await;
        assert_eq!(reloaded, loaded);
    }

    /// WHY: crash-safety — concurrent writers must never leave a torn or
    /// corrupt manifest on disk. Each write goes through a same-directory
    /// temp file + `sync_all` + atomic rename, so the final file is always
    /// exactly one of the written manifests (never a blend), and no `.tmp`
    /// debris remains.
    #[tokio::test]
    async fn concurrent_manifest_writes_never_corrupt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");

        let mut written = Vec::new();
        let mut handles = Vec::new();
        for i in 0..32u32 {
            let mut manifest = CrdtSubscriptionManifest::default();
            manifest.upsert(entry(KIND_KV_STORE, &format!("store-{i}"), ROLE_CREATED));
            written.push(manifest.clone());
            let path = path.clone();
            handles.push(tokio::spawn(async move {
                let _ = write_manifest(&path, &manifest).await;
            }));
        }
        for handle in handles {
            handle.await.expect("writer task panicked");
        }

        // The file must parse and equal exactly ONE written manifest — never a
        // torn blend that matches none.
        let loaded = read_manifest(&path).await;
        assert!(
            written.contains(&loaded),
            "concurrent writes corrupted the manifest: {loaded:?}"
        );

        // No temp-file debris left behind by failed/aborted renames.
        let debris = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(debris, 0, "temp-file debris left after concurrent writes");
    }

    /// WHY: a write that fails partway must not replace the last good
    /// manifest — the atomic temp+rename means only a fully-written, fsync'd
    /// file ever reaches the destination path. The old `tokio::fs::write`
    /// could truncate the destination mid-write on a crash.
    #[cfg(unix)]
    #[tokio::test]
    async fn failed_write_leaves_last_good_manifest_intact() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");

        // Establish the last good manifest on disk.
        let mut good = CrdtSubscriptionManifest::default();
        good.upsert(entry(KIND_KV_STORE, "good", ROLE_CREATED));
        write_manifest(&path, &good)
            .await
            .expect("write good manifest");
        assert_eq!(read_manifest(&path).await, good);

        // A strictly newer manifest that WOULD land if the write succeeded.
        let mut newer = CrdtSubscriptionManifest::default();
        newer.upsert(entry(KIND_KV_STORE, "newer", ROLE_CREATED));

        // Make the directory non-writable so the temp file cannot be created.
        let mut perms = tokio::fs::metadata(dir.path())
            .await
            .expect("stat dir")
            .permissions();
        perms.set_mode(0o500);
        tokio::fs::set_permissions(dir.path(), perms)
            .await
            .expect("chmod read-only");

        // Root bypasses Unix permission bits; probe whether the write is
        // actually blocked and only enforce the assertion when it is.
        let probe = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join("__probe__"))
            .await;
        let enforced = probe.is_err();
        if let Ok(file) = probe {
            drop(file);
            let _ = tokio::fs::remove_file(dir.path().join("__probe__")).await;
        }

        if enforced {
            assert!(
                write_manifest(&path, &newer).await.is_err(),
                "blocked write must return Err, not silently succeed"
            );
            assert_eq!(
                read_manifest(&path).await,
                good,
                "failed write replaced the last good manifest"
            );
        }

        // Restore writability so the tempdir can clean up.
        let mut perms = tokio::fs::metadata(dir.path())
            .await
            .expect("stat dir")
            .permissions();
        perms.set_mode(0o700);
        tokio::fs::set_permissions(dir.path(), perms)
            .await
            .expect("chmod restore");
    }

    /// WHY: this is the defect itself — `record()` used to snapshot the
    /// manifest, release the data lock, then write, so a slower OLDER
    /// snapshot could rename over a faster NEWER one (lost update). Now the
    /// persistence lock is held across snapshot + durable write, so every
    /// concurrent record survives to disk.
    #[tokio::test]
    async fn concurrent_records_cannot_regress_disk_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");
        let manifest = Arc::new(RwLock::new(CrdtSubscriptionManifest::default()));
        let lock = Arc::new(Mutex::new(()));

        const N: u32 = 48;
        let mut handles = Vec::new();
        for i in 0..N {
            let (manifest, lock) = (Arc::clone(&manifest), Arc::clone(&lock));
            let path = path.clone();
            handles.push(tokio::spawn(async move {
                persist_recorded(
                    &manifest,
                    &lock,
                    &path,
                    entry(KIND_KV_STORE, &format!("store-{i}"), ROLE_CREATED),
                )
                .await
            }));
        }
        for handle in handles {
            handle
                .await
                .expect("record task panicked")
                .expect("persist_recorded should succeed");
        }

        // No regression: every recorded entry must be present on disk. With
        // the old snapshot-after-unlock code a slower older snapshot would win
        // and silently drop later entries.
        let loaded = read_manifest(&path).await;
        let mut ids: Vec<String> = loaded.entries.iter().map(|e| e.id.clone()).collect();
        ids.sort();
        let mut expected: Vec<String> = (0..N).map(|i| format!("store-{i}")).collect();
        expected.sort();
        assert_eq!(
            ids, expected,
            "lost update: not all concurrent records survived to disk"
        );
    }

    /// WHY (review test 20): a failed durable write must not be acknowledged,
    /// and the rollback must let an identical retry actually re-attempt the
    /// write. Before the fix, `persist_recorded` left the entry in memory
    /// after a failed write, so a retry saw `upsert == false` and skipped
    /// writing — the entry was silently lost from disk forever.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_failure_then_identical_retry() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");
        let manifest = Arc::new(RwLock::new(CrdtSubscriptionManifest::default()));
        let lock = Arc::new(Mutex::new(()));
        let make_entry = || entry(KIND_KV_STORE, "rollback-store", ROLE_CREATED);

        // Make the directory non-writable so the durable write fails.
        let mut perms = tokio::fs::metadata(dir.path())
            .await
            .expect("stat dir")
            .permissions();
        perms.set_mode(0o500);
        tokio::fs::set_permissions(dir.path(), perms)
            .await
            .expect("chmod read-only");

        // Root bypasses permission bits; probe and only enforce when blocked.
        let probe = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join("__probe__"))
            .await;
        let enforced = probe.is_err();
        if let Ok(f) = probe {
            drop(f);
            let _ = tokio::fs::remove_file(dir.path().join("__probe__")).await;
        }

        if enforced {
            // 1. Failed write: must return Err AND roll back the in-memory
            //    upsert so the entry is not retained as if it were durable.
            let result = persist_recorded(&manifest, &lock, &path, make_entry()).await;
            assert!(result.is_err(), "failed durable write must return Err");
            assert!(
                manifest.read().await.entries.is_empty(),
                "in-memory manifest must roll back after a failed durable write"
            );
            assert!(
                read_manifest(&path).await.entries.is_empty(),
                "disk must not contain an entry whose write failed"
            );

            // Restore writability.
            let mut perms = tokio::fs::metadata(dir.path())
                .await
                .expect("stat dir")
                .permissions();
            perms.set_mode(0o700);
            tokio::fs::set_permissions(dir.path(), perms)
                .await
                .expect("chmod restore");

            // 2. Identical retry: because rollback reverted the in-memory
            //    change, the retry re-upserts and actually writes. Without
            //    rollback this would be a silent no-op and disk would stay
            //    empty.
            persist_recorded(&manifest, &lock, &path, make_entry())
                .await
                .expect("retry after removing the failure must succeed");
            let loaded = read_manifest(&path).await;
            assert_eq!(
                loaded.entries.len(),
                1,
                "identical retry after rollback must persist the entry"
            );
            assert_eq!(loaded.entries[0].id, "rollback-store");
        } else {
            // Restore writability for tempdir cleanup even when skipped.
            let mut perms = tokio::fs::metadata(dir.path())
                .await
                .expect("stat dir")
                .permissions();
            perms.set_mode(0o700);
            tokio::fs::set_permissions(dir.path(), perms)
                .await
                .expect("chmod restore");
        }
    }

    /// WHY (review test 21): forward-compatible `extra` fields written by a
    /// future daemon must survive a re-registration by an older handler that
    /// doesn't know about them. Before the fix, `upsert` replaced the whole
    /// entry, deleting any future fields (e.g. owner epoch/policy) on
    /// re-create/re-join — dangerous for rollback/upgrade of the owner anchor.
    #[tokio::test]
    async fn future_fields_survive_upsert_and_rollback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");

        // A "future" entry carrying fields this build doesn't know about.
        let mut future = entry(KIND_KV_STORE, "party", ROLE_CREATED);
        future.extra.insert(
            "owner_epoch".to_string(),
            serde_json::json!({ "epoch": 7, "hash": "deadbeef" }),
        );
        future
            .extra
            .insert("policy_version".to_string(), serde_json::json!(3));
        let mut manifest = CrdtSubscriptionManifest::default();
        assert!(manifest.upsert(future));
        write_manifest(&path, &manifest)
            .await
            .expect("write future manifest");

        // Re-register the same (kind, id) through an "older" handler that only
        // knows `expected_owner` — it does NOT mention the future fields.
        let mut older = entry(KIND_KV_STORE, "party", ROLE_CREATED);
        older
            .extra
            .insert("expected_owner".to_string(), serde_json::json!("abcd1234"));
        // Upsert must MERGE: known fields take the new value; existing-only
        // future extra fields are preserved.
        assert!(
            manifest.upsert(older),
            "re-registration providing a new extra field must change the manifest"
        );
        let merged = &manifest.entries[0];
        assert_eq!(
            merged.extra["expected_owner"],
            serde_json::json!("abcd1234")
        );
        assert_eq!(merged.extra["policy_version"], serde_json::json!(3));
        assert_eq!(merged.extra["owner_epoch"]["epoch"], 7);

        // Round-trip through disk preserves the merged future fields.
        write_manifest(&path, &manifest)
            .await
            .expect("write merged");
        let reloaded = read_manifest(&path).await;
        assert_eq!(
            reloaded.entries[0].extra["expected_owner"],
            serde_json::json!("abcd1234")
        );
        assert_eq!(
            reloaded.entries[0].extra["policy_version"],
            serde_json::json!(3)
        );
        assert_eq!(reloaded.entries[0].extra["owner_epoch"]["epoch"], 7);

        // An identical re-registration (no new info) is a durable no-op: merge
        // yields the same entry, so upsert returns false (no disk churn, future
        // fields still intact).
        let mut older_again = entry(KIND_KV_STORE, "party", ROLE_CREATED);
        older_again
            .extra
            .insert("expected_owner".to_string(), serde_json::json!("abcd1234"));
        assert!(
            !manifest.upsert(older_again),
            "identical re-registration must be a no-op"
        );
    }

    /// WHY (review test 19): deterministic proof that record serializes
    /// through the persistence lock — not timing-based. While the lock is
    /// held, a concurrent recorder can neither snapshot nor write; once
    /// released, it lands its entry. Uses the lock itself as the barrier, so
    /// the outcome is independent of scheduler timing.
    #[tokio::test]
    async fn record_serializes_through_persistence_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");
        let manifest = Arc::new(RwLock::new(CrdtSubscriptionManifest::default()));
        let lock = Arc::new(Mutex::new(()));

        // Hold the persistence lock: a concurrent recorder must NOT be able to
        // snapshot or write until it is released.
        let held = lock.lock().await;
        let recorder = tokio::spawn({
            let (manifest, lock, path) = (Arc::clone(&manifest), Arc::clone(&lock), path.clone());
            async move {
                persist_recorded(
                    &manifest,
                    &lock,
                    &path,
                    entry(KIND_KV_STORE, "blocked", ROLE_CREATED),
                )
                .await
            }
        });
        // Let the scheduler run the recorder up to its lock await.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(
            read_manifest(&path).await.entries.is_empty(),
            "recorder must not write while the persistence lock is held"
        );
        assert!(
            !recorder.is_finished(),
            "recorder must be blocked on the persistence lock"
        );

        // Release the lock; the recorder proceeds and lands its entry.
        drop(held);
        recorder
            .await
            .expect("recorder panicked")
            .expect("persist_recorded should succeed");
        let loaded = read_manifest(&path).await;
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].id, "blocked");
    }

    /// WHY (P1 manifest cancellation hole): `persist_recorded` MUST NOT mutate
    /// live in-memory state before the durable write completes. The old code
    /// upserted into the live manifest, released the data lock, THEN awaited
    /// `write_manifest`; a cancellation (HTTP client disconnect, shutdown, or
    /// task abort) during that await dropped the future before the Err-rollback
    /// ran, leaving the entry in memory but not on disk. An identical retry
    /// then saw `upsert == false` and returned `Ok(())` WITHOUT writing — the
    /// registration was silently lost from disk forever.
    ///
    /// The fix stages the upsert in a clone and commits live memory only after
    /// `write_manifest` returns `Ok`, so a drop at ANY await point (including
    /// the disk write) leaves memory == disk == pre-call state and an identical
    /// retry re-stages and re-writes.
    ///
    /// No sleeps, no wall-clock timing: `biased` select! polls
    /// `persist_recorded` first. It advances synchronously through the
    /// uncontended locks and the in-memory stage until its FIRST blocking
    /// await (the `tokio::fs` disk op, which dispatches to the blocking
    /// pool). At that suspension point the OLD code had already mutated
    /// live memory; the fixed code has not. `yield_now` then wins the
    /// select and drops the future mid-write — exactly the
    /// cancellation-before-rename window.
    ///
    /// One scheduling hazard remains: `tokio::fs` is `spawn_blocking`
    /// underneath, so on a loaded machine the blocking thread can finish
    /// the op BEFORE this task's first poll — persist then completes
    /// without ever suspending and no cancellation happens. Such attempts
    /// prove nothing (not a pass, not a failure), so the scenario retries
    /// with fresh state until a genuine mid-write cancellation is observed,
    /// bounded so a real change in suspension behaviour still fails loudly.
    #[tokio::test]
    async fn cancel_before_rename_leaves_memory_clean_and_retry_writes() {
        let make_entry = || entry(KIND_KV_STORE, "cancel-store", ROLE_CREATED);

        // Drive persist_recorded until it suspends at its first disk await,
        // then cancel (drop) it — the cancellation-before-rename hole.
        let mut observed = None;
        for _ in 0..64 {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("crdt-subscriptions.json");
            let manifest = Arc::new(RwLock::new(CrdtSubscriptionManifest::default()));
            let lock = Arc::new(Mutex::new(()));
            let cancelled = tokio::select! {
                biased;
                // Polled first: runs through the locks + in-memory stage and
                // suspends at the blocking `tokio::fs` write.
                res = persist_recorded(&manifest, &lock, &path, make_entry()) => {
                    // A genuine completion is not the scenario under test;
                    // assert it at least succeeded so the retry stays sound.
                    assert!(res.is_ok(), "if persist completed it must succeed");
                    false
                }
                _ = tokio::task::yield_now() => true,
            };
            if cancelled {
                observed = Some((dir, path, manifest, lock));
                break;
            }
        }
        let Some((dir, path, manifest, lock)) = observed else {
            panic!(
                "no attempt out of 64 was still suspended in its disk write \
                 when cancelled — persist_recorded's first blocking await \
                 has changed and this test no longer exercises the \
                 cancellation-before-rename hole"
            );
        };

        // After cancellation: live memory must be clean — the invariant the
        // fix guarantees unconditionally (memory is only ever committed AFTER
        // a durable write). The OLD code left the entry in memory here.
        assert!(
            manifest.read().await.entries.is_empty(),
            "cancellation mid-write must not leave an un-persisted entry in memory"
        );
        // Disk may land in either honest state: usually empty (cancelled
        // before the rename), but the rename op runs on the blocking pool
        // and is not revoked by dropping the future — if it was already in
        // flight, the fully-written, fsync'd manifest lands even though the
        // caller saw cancellation. That is NOT a durability lie (nothing was
        // acknowledged; memory is behind disk, and the identical retry
        // converges them). A PARTIAL manifest is impossible either way — the
        // rename only ever installs a complete synced file.
        let disk = read_manifest(&path).await;
        assert!(
            disk.entries.is_empty()
                || (disk.entries.len() == 1 && disk.entries[0].id == "cancel-store"),
            "post-cancellation disk must be empty or the complete staged \
             manifest, never a blend: {disk:?}"
        );
        // No temp-file debris from the aborted rename (TempFile guard).
        let debris = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(debris, 0, "cancelled write left temp-file debris");

        // Identical retry: because memory was never advanced, the retry
        // re-stages and actually writes. The OLD code's no-op-on-retry (entry
        // already in memory ⇒ upsert == false ⇒ return Ok without writing)
        // would leave disk empty forever.
        persist_recorded(&manifest, &lock, &path, make_entry())
            .await
            .expect("identical retry after cancellation must persist");
        let loaded = read_manifest(&path).await;
        assert_eq!(loaded.entries.len(), 1, "retry must land the entry on disk");
        assert_eq!(loaded.entries[0].id, "cancel-store");
        assert_eq!(
            manifest.read().await.entries.len(),
            1,
            "memory and disk must agree after retry"
        );
    }

    /// WHY (#231): a process kill (SIGKILL, abort, power loss) mid-write
    /// skips every destructor, so the TempFile guard never runs and one
    /// `.tmp` per crash leaks forever — nothing else ever removes it. The
    /// next manifest write must sweep temp siblings older than
    /// STALE_TEMP_FILE_MAX_AGE.
    #[tokio::test]
    async fn stale_temp_debris_is_swept_on_next_manifest_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");

        // Plant debris exactly as a crashed write would leave it: the same
        // naming scheme write_manifest_atomic mints, mtime far in the past.
        let mut stale_os = path.as_os_str().to_owned();
        stale_os.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let stale_path = PathBuf::from(stale_os);
        let stale = std::fs::File::create(&stale_path).expect("plant stale temp");
        stale
            .set_modified(SystemTime::now() - 2 * STALE_TEMP_FILE_MAX_AGE)
            .expect("backdate mtime");
        drop(stale);

        let mut manifest = CrdtSubscriptionManifest::default();
        manifest.upsert(entry(KIND_KV_STORE, "sweeper", ROLE_CREATED));
        write_manifest(&path, &manifest)
            .await
            .expect("write manifest");

        assert!(
            !stale_path.exists(),
            "stale .tmp debris must be reclaimed by the next manifest write"
        );
        // The write itself still landed correctly and left no debris of its
        // own.
        assert_eq!(read_manifest(&path).await, manifest);
        let debris = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(debris, 0, "fresh write must leave no temp debris");
    }

    /// WHY (#231): the sweep must NEVER remove a temp file a live concurrent
    /// write is using. Production writes are serialised by the persistence
    /// lock, but `write_manifest` itself is not (see
    /// `concurrent_manifest_writes_never_corrupt`), so the sweep is
    /// age-bounded: a temp younger than STALE_TEMP_FILE_MAX_AGE is
    /// definitionally still in flight (a manifest write holds its temp for
    /// milliseconds) and must be left alone.
    #[tokio::test]
    async fn in_flight_temp_of_concurrent_write_is_not_swept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");

        // A fresh temp file is indistinguishable from one a concurrent
        // writer created microseconds ago: same minting scheme, current
        // mtime.
        let mut live_os = path.as_os_str().to_owned();
        live_os.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let live_path = PathBuf::from(live_os);
        std::fs::write(&live_path, b"in-flight partial write").expect("plant live temp");

        let mut manifest = CrdtSubscriptionManifest::default();
        manifest.upsert(entry(KIND_KV_STORE, "writer", ROLE_CREATED));
        write_manifest(&path, &manifest)
            .await
            .expect("write manifest");

        assert!(
            live_path.exists(),
            "a fresh (in-flight) temp file must survive the sweep"
        );
        assert_eq!(read_manifest(&path).await, manifest);
    }

    /// WHY (P1 parent-directory fsync failure → refused durability): a rename
    /// is not durable across power loss until the containing directory is
    /// fsync'd. The OLD `sync_parent_dir` swallowed that error behind a
    /// `let _`, so `persist_recorded` acknowledged a registration as durable
    /// when a power loss could lose the rename. The fix makes a dir-fsync
    /// failure propagate as `Err` from `write_manifest_atomic` →
    /// `persist_recorded`, which (stage-then-commit) refuses to commit live
    /// memory — so a non-durable write is never acknowledged. An identical
    /// retry re-stages from the unchanged memory and rewrites.
    ///
    /// Deterministic via the `DirFsyncFailureGuard` test hook: it forces
    /// `sync_parent_dir` to return a synthetic `Err` for the guard's lifetime
    /// (thread-local, auto-reset on drop), with no filesystem dependency, no
    /// root-bypass, and no permission juggling. Runs on the current-thread
    /// test runtime so the thread-local flag is visible where the future
    /// resumes after the rename await.
    #[cfg(unix)]
    #[tokio::test]
    async fn dir_fsync_failure_refuses_durability_and_leaves_memory_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");
        let manifest = Arc::new(RwLock::new(CrdtSubscriptionManifest::default()));
        let lock = Arc::new(Mutex::new(()));
        let make_entry = || entry(KIND_KV_STORE, "fsync-store", ROLE_CREATED);

        // Inject a dir-fsync failure: the rename succeeds but the parent-dir
        // fsync returns Err, so durability must NOT be acknowledged.
        let _fail = DirFsyncFailureGuard::enable();
        let result = persist_recorded(&manifest, &lock, &path, make_entry()).await;
        assert!(
            result.is_err(),
            "a parent-directory fsync failure must surface as Err, not be \
             acknowledged as durable"
        );
        // Stage-then-commit: live memory was never advanced, so the in-memory
        // manifest does not lie about durability. A "commit-then-fsync"
        // regression would leave the entry committed here while returning Err.
        assert!(
            manifest.read().await.entries.is_empty(),
            "live memory must not commit a write whose dir-fsync failed"
        );

        // Drop the injection: an identical retry re-stages from the (still
        // unchanged) memory and rewrites, now succeeding and committing, so
        // memory and disk converge.
        drop(_fail);
        persist_recorded(&manifest, &lock, &path, make_entry())
            .await
            .expect("retry after removing the fsync failure must persist");
        let loaded = read_manifest(&path).await;
        assert_eq!(loaded.entries.len(), 1, "retry must land the entry on disk");
        assert_eq!(loaded.entries[0].id, "fsync-store");
        assert_eq!(
            manifest.read().await.entries.len(),
            1,
            "memory and disk must agree after retry"
        );
    }

    /// WHY (P1 one-shot failure isolation): a durable-write failure for one
    /// subscription must not clobber a sibling that already committed, and the
    /// failed entry must remain retryable. A regression that rolled back to a
    /// stale/global snapshot, or that committed-then-failed, would lose or
    /// cross-contaminate entries. This pins the invariant across an
    /// interleaving of task create, kv create, and a different-owner kv join
    /// (the manifest-level analog of the route-level mix), with a real one-shot
    /// fs failure injected between them: memory == disk at every step, the
    /// committed sibling survives, and the failed entries retry cleanly.
    #[cfg(unix)]
    #[tokio::test]
    async fn interleaved_failure_does_not_clobber_sibling_entries() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crdt-subscriptions.json");
        let manifest = Arc::new(RwLock::new(CrdtSubscriptionManifest::default()));
        let lock = Arc::new(Mutex::new(()));

        // Root bypasses Unix permission bits; probe and only inject the failure
        // when the permission model is actually enforced.
        let probe = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join("__probe__"))
            .await;
        let enforced = probe.is_err();
        if let Ok(f) = probe {
            drop(f);
            let _ = tokio::fs::remove_file(dir.path().join("__probe__")).await;
        }

        // A: task-list create — commits to memory + disk.
        persist_recorded(
            &manifest,
            &lock,
            &path,
            entry(KIND_TASK_LIST, "alpha", ROLE_CREATED),
        )
        .await
        .expect("A (task create) persists");

        // Different-owner kv join entry: a joined store anchored on a hex owner
        // (64 hex chars ⇒ 32-byte AgentId), the role a public join records.
        let owner_hex = "deadbeef".repeat(8);
        let join_entry = || {
            let mut e = entry(KIND_KV_STORE, "delta", ROLE_JOINED);
            e.extra
                .insert("expected_owner".to_string(), serde_json::json!(owner_hex));
            e
        };

        if enforced {
            let mut perms = tokio::fs::metadata(dir.path())
                .await
                .expect("stat")
                .permissions();
            perms.set_mode(0o500);
            tokio::fs::set_permissions(dir.path(), perms)
                .await
                .expect("chmod read-only");

            // B (kv create) and D (different-owner kv join) both fail: neither
            // may commit, and A must survive in memory AND on disk.
            assert!(
                persist_recorded(
                    &manifest,
                    &lock,
                    &path,
                    entry(KIND_KV_STORE, "beta", ROLE_CREATED)
                )
                .await
                .is_err(),
                "B fails under a read-only directory"
            );
            assert!(
                persist_recorded(&manifest, &lock, &path, join_entry())
                    .await
                    .is_err(),
                "D fails under a read-only directory"
            );
            assert_eq!(
                manifest.read().await.entries.len(),
                1,
                "memory retains only A after failed B/D"
            );
            let disk_after_fail = read_manifest(&path).await;
            assert_eq!(
                disk_after_fail.entries.len(),
                1,
                "disk retains only A after failed B/D"
            );
            assert_eq!(disk_after_fail.entries[0].id, "alpha");

            let mut perms = tokio::fs::metadata(dir.path())
                .await
                .expect("stat")
                .permissions();
            perms.set_mode(0o700);
            tokio::fs::set_permissions(dir.path(), perms)
                .await
                .expect("chmod restore");
        }

        // C: a second task-list create — commits after the failure window.
        persist_recorded(
            &manifest,
            &lock,
            &path,
            entry(KIND_TASK_LIST, "gamma", ROLE_CREATED),
        )
        .await
        .expect("C (task create) persists after restore");

        // Retry B and D — they now succeed; their earlier failure left no trace.
        persist_recorded(
            &manifest,
            &lock,
            &path,
            entry(KIND_KV_STORE, "beta", ROLE_CREATED),
        )
        .await
        .expect("B retry persists");
        persist_recorded(&manifest, &lock, &path, join_entry())
            .await
            .expect("D retry persists");

        // Final invariant: memory == disk, exactly {alpha, beta, delta, gamma},
        // and the join retained its owner anchor through fail + retry.
        let mem = manifest.read().await.clone();
        let disk = read_manifest(&path).await;
        assert_eq!(
            mem, disk,
            "memory and disk must agree after interleaved failures"
        );
        let mut ids: Vec<String> = disk.entries.iter().map(|e| e.id.clone()).collect();
        ids.sort();
        let expected: Vec<String> = ["alpha", "beta", "delta", "gamma"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(ids, expected);
        let joined = disk
            .entries
            .iter()
            .find(|e| e.id == "delta")
            .expect("delta present");
        assert_eq!(joined.role, ROLE_JOINED);
        assert_eq!(joined.extra["expected_owner"], serde_json::json!(owner_hex));
    }
}
