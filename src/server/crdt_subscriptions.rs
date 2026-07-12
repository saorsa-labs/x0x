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

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

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
    pub(super) fn upsert(&mut self, entry: CrdtSubscriptionEntry) -> bool {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.kind == entry.kind && e.id == entry.id)
        {
            if *existing == entry {
                return false;
            }
            *existing = entry;
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

/// Write `manifest` to `path` (best-effort, warns on failure).
pub(super) async fn write_manifest(path: &Path, manifest: &CrdtSubscriptionManifest) {
    match serde_json::to_vec_pretty(manifest) {
        Ok(bytes) => {
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            if let Err(e) = tokio::fs::write(path, &bytes).await {
                tracing::warn!(
                    "failed to persist CRDT subscription manifest to {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => tracing::warn!("failed to serialise CRDT subscription manifest: {e}"),
    }
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

/// Record a new/updated subscription in the in-memory manifest and persist
/// it to disk. Called by the REST create/join handlers after a successful
/// registration.
pub(super) async fn record(state: &AppState, entry: CrdtSubscriptionEntry) {
    let snapshot = {
        let mut manifest = state.crdt_subscriptions.write().await;
        if !manifest.upsert(entry) {
            return;
        }
        manifest.clone()
    };
    write_manifest(&state.crdt_subscriptions_path, &snapshot).await;
}

/// Rehydrate every persisted subscription by driving the same `Agent`
/// create/join paths the REST handlers use.
///
/// Runs after `join_network` returns so the gossip mesh is (re)forming; the
/// per-CRDT empty-replica state-request retry schedule then recovers state —
/// including mutations made while this daemon was offline — from peer
/// replicas. A failed entry is logged (warn) and skipped, never fatal, and
/// stays in the manifest so the next restart retries it.
pub(super) async fn rehydrate(state: Arc<AppState>) {
    let entries = state.crdt_subscriptions.read().await.entries.clone();
    if entries.is_empty() {
        return;
    }
    let (mut restored, mut skipped) = (0usize, 0usize);
    for entry in entries {
        match entry.kind.as_str() {
            KIND_TASK_LIST => {
                if state.task_lists.read().await.contains_key(&entry.id) {
                    continue; // already re-created via REST since startup
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
                        skipped += 1;
                        continue;
                    }
                };
                match result {
                    Ok(handle) => {
                        state
                            .task_lists
                            .write()
                            .await
                            .entry(entry.id.clone())
                            .or_insert(handle);
                        restored += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            id = %entry.id,
                            "failed to rehydrate task list after restart: {e}"
                        );
                        skipped += 1;
                    }
                }
            }
            KIND_KV_STORE => {
                if state.kv_stores.read().await.contains_key(&entry.id) {
                    continue; // already re-created/joined via REST since startup
                }
                let result = match entry.role.as_str() {
                    ROLE_JOINED => state.agent.join_kv_store(&entry.topic).await,
                    ROLE_CREATED => state.agent.create_kv_store(&entry.name, &entry.topic).await,
                    other => {
                        tracing::warn!(
                            id = %entry.id,
                            role = other,
                            "unknown kv-store subscription role — skipping"
                        );
                        skipped += 1;
                        continue;
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
                        restored += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            id = %entry.id,
                            "failed to rehydrate kv store after restart: {e}"
                        );
                        skipped += 1;
                    }
                }
            }
            other => {
                tracing::warn!(
                    id = %entry.id,
                    kind = other,
                    "unknown CRDT subscription kind — skipping (kept in manifest)"
                );
                skipped += 1;
            }
        }
    }
    tracing::info!(restored, skipped, "CRDT subscription rehydration complete");
}

#[cfg(test)]
mod tests {
    use super::*;

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

        write_manifest(&path, &manifest).await;
        let loaded = read_manifest(&path).await;
        assert_eq!(loaded, manifest);

        // Remove drops exactly the matching (kind, id) pair.
        let mut loaded = loaded;
        assert!(loaded.remove(KIND_KV_STORE, "party"));
        assert!(!loaded.remove(KIND_KV_STORE, "party"));
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].id, "sprint");

        write_manifest(&path, &loaded).await;
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
        write_manifest(&path, &loaded).await;
        let reloaded = read_manifest(&path).await;
        assert_eq!(reloaded, loaded);
    }
}
