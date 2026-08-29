//! Delta-CRDT implementation for bandwidth-efficient TaskList synchronization.
//!
//! This module provides delta-based CRDT operations for TaskList, allowing
//! efficient incremental synchronization between peers.
//!
//! ## Delta Strategy
//!
//! Instead of sending the entire TaskList on every sync, we:
//! 1. Track version numbers for each change
//! 2. Generate deltas containing only changes since a given version
//! 3. Apply deltas incrementally
//!
//! This significantly reduces bandwidth usage in collaborative scenarios.

use crate::crdt::{OpAttestation, OwnerTransfer, Result, TaskId, TaskItem, TaskList, TaskListId};
use crate::identity::AgentId;
use saorsa_gossip_crdt_sync::{DeltaCrdt, LwwRegister};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Unique tag for OR-Set elements: (PeerId, sequence_number)
pub type UniqueTag = (PeerId, u64);

/// Delta representing changes to a TaskList.
///
/// Contains only the changes made since a specific version, enabling
/// bandwidth-efficient synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskListDelta {
    /// Tasks that were added (task_id -> (task, unique_tag))
    pub added_tasks: HashMap<TaskId, (TaskItem, UniqueTag)>,

    /// Tasks that were removed (task_id -> set of tags to remove)
    pub removed_tasks: HashMap<TaskId, HashSet<UniqueTag>>,

    /// Updates to existing tasks (task_id -> full task state)
    ///
    /// Note: For simplicity, we currently send the full TaskItem state.
    /// A future optimization could implement TaskItemDelta for finer-grained updates.
    pub task_updates: HashMap<TaskId, TaskItem>,

    /// Update to task ordering, carried as the full LWW register (value +
    /// vector clock) so the receiver resolves it by causality rather than
    /// adopting it unconditionally.
    pub ordering_update: Option<LwwRegister<Vec<TaskId>>>,

    /// Update to list name, carried as the full LWW register (value + vector
    /// clock) so the receiver resolves it by causality.
    pub name_update: Option<LwwRegister<String>>,

    /// Version number of this delta
    pub version: u64,

    /// Ownership transfers (ADR-0040, blocker 27), keyed by task. This is
    /// the delta's ABSOLUTE trailing field with a stream-EOF-tolerant
    /// deserializer: a legacy delta blob (pre-0040, bytes ending after
    /// `version`) decodes with an empty map — TaskItem's own wire shape is
    /// byte-identical to pre-0040, so nothing nested ever misaligns
    /// (review r2 fix). Each entry merges through the ownership admission
    /// gate at apply time. MUST remain the last field.
    #[serde(default, deserialize_with = "deserialize_owner_transfers")]
    pub owner_transfers: HashMap<TaskId, std::collections::BTreeMap<OwnerTransfer, OpAttestation>>,
}

/// Tolerant trailing decode of the ownership map: absent (stream EOF right
/// after `version`) ⇒ empty map, exactly the pre-ADR-0040 observable.
fn deserialize_owner_transfers<'de, D>(
    deserializer: D,
) -> std::result::Result<
    HashMap<TaskId, std::collections::BTreeMap<OwnerTransfer, OpAttestation>>,
    D::Error,
>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Ok(
        HashMap::<TaskId, std::collections::BTreeMap<OwnerTransfer, OpAttestation>>::deserialize(
            deserializer,
        )
        .unwrap_or_default(),
    )
}

impl TaskListDelta {
    /// Create an empty delta at a given version.
    #[must_use]
    pub fn new(version: u64) -> Self {
        Self {
            added_tasks: HashMap::new(),
            removed_tasks: HashMap::new(),
            task_updates: HashMap::new(),
            ordering_update: None,
            name_update: None,
            owner_transfers: HashMap::new(),
            version,
        }
    }

    /// Create a delta for a single add_task operation.
    #[must_use]
    pub fn for_add(task_id: TaskId, task: TaskItem, tag: UniqueTag, version: u64) -> Self {
        let mut delta = Self::new(version);
        if !task.owner_transfers_map().is_empty() {
            delta
                .owner_transfers
                .insert(task_id, task.owner_transfers_map().clone());
        }
        delta.added_tasks.insert(task_id, (task, tag));
        delta
    }

    /// Create a delta for a state change (claim, complete, or ownership
    /// transfer).
    ///
    /// Includes the full TaskItem so receivers can upsert if they
    /// haven't received the add delta yet (out-of-order delivery). The
    /// task's ownership transfers ride the delta-level map (TaskItem's
    /// wire shape carries no ownership — see struct docs).
    #[must_use]
    pub fn for_state_change(task_id: TaskId, full_task: TaskItem, version: u64) -> Self {
        let mut delta = Self::new(version);
        if !full_task.owner_transfers_map().is_empty() {
            delta
                .owner_transfers
                .insert(task_id, full_task.owner_transfers_map().clone());
        }
        delta.task_updates.insert(task_id, full_task);
        delta
    }

    /// Create a delta for a reorder operation.
    ///
    /// Takes the post-reorder ordering register (with its vector clock) so the
    /// change merges by causality on the receiver.
    #[must_use]
    pub fn for_reorder(order_register: LwwRegister<Vec<TaskId>>, version: u64) -> Self {
        let mut delta = Self::new(version);
        delta.ordering_update = Some(order_register);
        delta
    }

    /// Check if this delta is empty (contains no changes).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added_tasks.is_empty()
            && self.removed_tasks.is_empty()
            && self.task_updates.is_empty()
            && self.ordering_update.is_none()
            && self.name_update.is_none()
            && self.owner_transfers.is_empty()
    }

    /// Digest over the full-state content this delta serves, when the delta
    /// is full-state-shaped (issue #240).
    ///
    /// A `TaskList::full_delta` always carries BOTH the ordering and name
    /// registers; incremental deltas carry at most one of them, so `None`
    /// cleanly excludes non-full-state shapes. Callers MUST additionally
    /// require the added-task count to equal the holder's declared
    /// `entry_count` before treating a digest match as a verified full
    /// serve. The digest commits to the carried tasks' RESOLVED observable
    /// fields in sorted task-id order (see
    /// [`TaskItem::hash_resolved_fields`]) — identical to what
    /// [`TaskList::served_digest`] computes over local state, so a receiver
    /// holding exactly the served content produces the same digest.
    pub(crate) fn served_digest(&self, list_id: &TaskListId) -> Option<[u8; 32]> {
        self.ordering_update.as_ref()?;
        self.name_update.as_ref()?;
        let mut h = blake3::Hasher::new();
        h.update(crate::crdt::task_list::SERVED_DIGEST_DOMAIN);
        h.update(list_id.as_bytes());
        let mut ids: Vec<&TaskId> = self.added_tasks.keys().collect();
        ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for id in ids {
            h.update(id.as_bytes());
            self.added_tasks[id].0.hash_resolved_fields(&mut h);
        }
        Some(*h.finalize().as_bytes())
    }
}

/// Extension to TaskList to support delta-based synchronization.
///
/// This implementation adds version tracking and delta generation/merging
/// capabilities to TaskList.
impl TaskList {
    /// Get the current version of this TaskList.
    ///
    /// The version is incremented on each modification. This enables
    /// delta-based synchronization.
    ///
    /// Note: This is a placeholder implementation. A production version
    /// would track the actual version in TaskList's state.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.current_version()
    }

    /// Generate a delta containing the task list's entire current state.
    ///
    /// Mirrors `KvStore::full_delta`: every active task is emitted as an
    /// "added" entry plus the current ordering and name. Receivers apply it
    /// with `merge_delta`, whose upsert/LWW semantics make a full snapshot a
    /// safe superset of any incremental change — this is the producer used to
    /// answer cold-start state requests (see `TaskListSync`). The OR-Set tags
    /// are synthetic because the receiver re-derives membership on merge —
    /// but they must be FRESH per entry (F3, fix-loop): the digest-verified
    /// adopt prunes stale tasks with a local observe-remove, which
    /// tombstones the tags a previous full delta used, and a hardcoded tag
    /// would then be silently rejected on a later serve that re-adds the
    /// task — a permanent re-add deadlock.
    #[must_use]
    pub fn full_delta(&self) -> TaskListDelta {
        let mut delta = TaskListDelta::new(self.version());

        let ordered = self.tasks_ordered();
        for task in &ordered {
            let task_id = *task.id();
            let tag = (PeerId::new([0u8; 32]), self.next_seq());
            if !task.owner_transfers_map().is_empty() {
                delta
                    .owner_transfers
                    .insert(task_id, task.owner_transfers_map().clone());
            }
            delta.added_tasks.insert(task_id, ((*task).clone(), tag));
        }

        // Carry the registers themselves (value + clock) so a cold-start
        // snapshot merges by causality and cannot clobber a newer local
        // ordering/name on an already-populated peer.
        delta.ordering_update = Some(self.ordering_register().clone());
        delta.name_update = Some(self.name_register().clone());

        delta
    }

    /// Merge a delta into this TaskList.
    ///
    /// Applies the changes from the delta according to CRDT semantics:
    /// - Added tasks are merged using OR-Set semantics
    /// - Removed tasks are tombstoned
    /// - Task updates are merged
    /// - Ordering uses LWW semantics
    /// - Name uses LWW semantics
    ///
    /// # Authorship gate (issue #349, Layer A)
    ///
    /// Unauthenticated content fields (added tasks, metadata LWW on
    /// TaskItem, list name, ordering, removes) apply only when `writer` —
    /// the V2-envelope-verified sender (`AgentId`) — is `Some` AND, when
    /// the list has an authorized-member set, is a member of it. Otherwise
    /// they are silently rejected (Ok, KV-style) so unsigned or
    /// non-member deltas cannot attribute create/rename/reassign/reorder/
    /// remove to anyone. Checkbox claim/complete admission is unaffected:
    /// it is gated by `OpAttestation`, so an attested claim on a task the
    /// receiver already holds still converges when content is dropped.
    ///
    /// # Arguments
    ///
    /// * `delta` - The delta to merge
    /// * `peer_id` - OR-Set uniqueness tag source for first-seen upserts.
    ///   NOT an identity: never compared against `writer` (invariant I3).
    /// * `writer` - Envelope-verified sender, if any (`None` for unsigned
    ///   legacy v1 publishes).
    ///
    /// # Returns
    ///
    /// Ok(()) if merge succeeded (including silent content rejection).
    ///
    /// # Errors
    ///
    /// Returns an error if merge operations fail.
    pub fn merge_delta(
        &mut self,
        delta: &TaskListDelta,
        peer_id: PeerId,          // tag only, not identity
        writer: Option<&AgentId>, // envelope-verified sender
    ) -> Result<()> {
        // Capture the resolved observable fingerprint BEFORE applying the
        // delta so the local version advances exactly once iff this merge
        // effectively changes the local snapshot. (Remote claim/complete
        // merges must invalidate a caller's stale local token.)
        //
        // The body uses delta_* helpers that do NOT bump version internally;
        // only commit_revision_if_changed advances it. This ensures an
        // idempotent redelivery (same resolved state) does NOT advance the
        // fence, while a real remote change advances it exactly once.
        //
        // NOTE (composition with the provenance gate): any unauthenticated or
        // forged Claimed/Done element is dropped by the admission gate inside
        // delta_upsert_task / TaskItem::merge — before it can influence
        // resolution. Because this fingerprint wraps the entire merge body, it
        // is computed over post-gate (authenticated) state by construction.
        let before = self.state_fingerprint();

        // Layer A authorship gate (issue #349, I2 + membership): decide ONCE
        // whether unauthenticated content fields may apply. Identity is the
        // envelope-verified `writer` (AgentId) only; `peer_id` and every
        // UniqueTag in the delta are OR-Set tags, never authors (I3).
        let content_allowed = match writer {
            None => false,
            Some(w) => self.is_authorized_content_writer(w),
        };
        if !content_allowed {
            tracing::warn!(
                ?writer,
                list = ?self.id(),
                "dropping unauthenticated content in task-list delta (issue #349)"
            );
        }

        for (task_id, (task, tag)) in &delta.added_tasks {
            // If task doesn't exist, add it (admit runs inside delta_upsert_task).
            // If it exists, merge + filter (admit + membership run inside
            // delta_merge_task / delta_merge_checkbox_only).
            if self.get_task(task_id).is_none() {
                if content_allowed {
                    self.delta_upsert_task(task.clone(), tag.0, tag.1)?;
                }
                // A first-seen task from an unauthenticated add is NOT
                // created: there is no local task to run checkbox admission
                // against, and `created_by` is self-declared payload.
            } else if content_allowed {
                self.delta_merge_task(task_id, task)?;
            } else {
                // Existing task: checkbox + attestations still merge and run
                // the admission gate even when content is dropped.
                self.delta_merge_checkbox_only(task_id, task)?;
            }
        }

        // Apply removed tasks (no version bump; deferred to commit_revision).
        if content_allowed {
            for task_id in delta.removed_tasks.keys() {
                self.delta_remove_task(task_id);
            }
        }

        // Apply task updates (upsert: merge if exists, insert if missing).
        // The upsert is critical for out-of-order delivery — a claim/complete
        // delta may arrive before the corresponding add delta. Since the
        // TaskItem in task_updates contains full state, inserting it directly
        // is safe and preserves the state change. The admission gate runs
        // inside delta_upsert_task / merge.
        for (task_id, updated_task) in &delta.task_updates {
            if self.get_task(task_id).is_some() {
                if content_allowed {
                    self.delta_merge_task(task_id, updated_task)?;
                } else {
                    self.delta_merge_checkbox_only(task_id, updated_task)?;
                }
            } else if content_allowed {
                // Task not yet known — insert it (admit runs inside).
                self.delta_upsert_task(updated_task.clone(), peer_id, 0)?;
            }
        }

        // Ownership transfers (ADR-0040): SELF-AUTHENTICATING ops — like
        // checkbox attestations they apply regardless of the Layer A
        // envelope-writer gate, because each entry carries its own
        // current-owner signature that the admission gate verifies (forged
        // entries are purged, never applied).
        for (task_id, transfers) in &delta.owner_transfers {
            self.delta_apply_owner_transfers(task_id, transfers);
        }

        // Apply ordering update via LWW (vector-clock) merge. The merged
        // ordering may reference task IDs not yet present (out-of-order
        // delivery); tasks_ordered filters those at read time.
        if content_allowed {
            if let Some(order_register) = &delta.ordering_update {
                self.delta_merge_ordering(order_register);
            }

            // Apply name update via LWW (vector-clock) merge.
            if let Some(name_register) = &delta.name_update {
                self.delta_merge_name(name_register);
            }
        }

        // Advance the local revision exactly once iff the resolved observable
        // snapshot changed. Idempotent re-merges (same resolutions) ⇒ no bump.
        self.commit_revision_if_changed(before);
        Ok(())
    }
}

/// Implement DeltaCrdt trait for TaskList.
///
/// This enables TaskList to participate in saorsa-gossip's delta-based
/// synchronization infrastructure.
impl DeltaCrdt for TaskList {
    type Delta = TaskListDelta;

    fn merge(&mut self, delta: &Self::Delta) -> anyhow::Result<()> {
        // No writer identity here — DeltaCrdt::merge is NOT a production
        // untrusted-apply path (issue #349). Pass `None` so no unsigned
        // content applies; the trusted gossip route is TaskListSync, which
        // threads the envelope-verified sender into merge_delta.
        let peer_id = PeerId::new([0u8; 32]);
        self.merge_delta(delta, peer_id, None)
            .map_err(|e| anyhow::anyhow!("Failed to merge delta: {}", e))
    }

    fn delta(&self, since_version: u64) -> Option<Self::Delta> {
        // A full-state delta is a sound conservative answer to "changes since
        // version N": merge_delta is idempotent and LWW/upsert-based, so the
        // receiver converges regardless of how much extra state we include.
        if since_version >= self.version() {
            None
        } else {
            Some(self.full_delta())
        }
    }

    fn version(&self) -> u64 {
        self.version()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::{TaskListId, TaskMetadata};
    use crate::identity::AgentId;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn list_id(n: u8) -> TaskListId {
        TaskListId::new([n; 32])
    }

    fn make_task(id_byte: u8, peer: PeerId) -> TaskItem {
        let agent = agent(1);
        let task_id = TaskId::from_bytes([id_byte; 32]);
        let metadata = TaskMetadata::new(
            format!("Task {}", id_byte),
            format!("Description {}", id_byte),
            128,
            agent,
            1000,
        );
        TaskItem::new(task_id, metadata, peer)
    }

    #[test]
    fn test_empty_delta() {
        let delta = TaskListDelta::new(1);
        assert!(delta.is_empty());
        assert_eq!(delta.version, 1);
    }

    #[test]
    fn test_delta_with_added_task() {
        let mut delta = TaskListDelta::new(2);
        let peer = peer(1);
        let task = make_task(1, peer);
        let task_id = *task.id();
        let tag = (peer, 1);

        delta.added_tasks.insert(task_id, (task, tag));

        assert!(!delta.is_empty());
        assert_eq!(delta.added_tasks.len(), 1);
    }

    #[test]
    fn test_task_list_version() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Test".to_string(), peer);

        let initial_version = list.version();

        // Add a task
        let task = make_task(1, peer);
        list.add_task(task, peer, 1).ok().unwrap();

        let new_version = list.version();
        assert!(new_version > initial_version);
    }

    #[test]
    fn test_delta_generation() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Test".to_string(), peer);

        // Add a task
        let task = make_task(1, peer);
        list.add_task(task, peer, 1).ok().unwrap();

        // A full-state delta carries every active task.
        let delta = list.full_delta();
        assert!(!delta.is_empty());
        assert!(!delta.added_tasks.is_empty());
    }

    #[test]
    fn test_delta_no_changes() {
        let peer = peer(1);
        let id = list_id(1);
        let list = TaskList::new(id, "Test".to_string(), peer);

        let current_version = list.version();

        // Asking the DeltaCrdt trait for changes since the current version
        // yields nothing.
        let delta = DeltaCrdt::delta(&list, current_version);
        assert!(delta.is_none());
    }

    #[test]
    fn test_merge_delta_with_new_task() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);

        let mut list1 = TaskList::new(id, "List 1".to_string(), peer1);
        let mut list2 = TaskList::new(id, "List 2".to_string(), peer2);

        // list2 adds a task
        let task = make_task(1, peer2);
        list2.add_task(task, peer2, 1).ok().unwrap();

        // Generate a full-state delta from list2
        let delta = list2.full_delta();

        // Merge delta into list1 (envelope-verified writer; the payload tag
        // PeerId stays tag-only).
        let result = list1.merge_delta(&delta, peer1, Some(&agent(2)));
        assert!(result.is_ok());

        // list1 should now have the task
        assert_eq!(list1.task_count(), 1);
    }

    #[test]
    fn full_delta_lets_a_late_joiner_converge() {
        // WHY: a peer that subscribes after tasks were already added has no
        // organic deltas to replay. The cold-start path (TaskListSync's
        // StateRequest) answers with `full_delta()`; merging it must reproduce
        // the holder's complete state — every task, the ordering, and the name
        // — or a late joiner would converge to a partial list.
        let holder_peer = peer(1);
        let joiner_peer = peer(2);
        let id = list_id(1);

        let mut holder = TaskList::new(id, "Sprint".to_string(), holder_peer);
        let t1 = make_task(1, holder_peer);
        let t2 = make_task(2, holder_peer);
        let t3 = make_task(3, holder_peer);
        let (id1, id2, id3) = (*t1.id(), *t2.id(), *t3.id());
        holder.add_task(t1, holder_peer, 1).expect("add t1");
        holder.add_task(t2, holder_peer, 2).expect("add t2");
        holder.add_task(t3, holder_peer, 3).expect("add t3");
        holder
            .reorder(vec![id3, id1, id2], holder_peer)
            .expect("reorder");
        holder.update_name("Sprint Backlog".to_string(), holder_peer);

        // Fresh joiner with an empty list applies only the cold-start snapshot.
        let mut joiner = TaskList::new(id, String::new(), joiner_peer);
        let snapshot = holder.full_delta();
        joiner
            .merge_delta(&snapshot, holder_peer, Some(&agent(1)))
            .expect("merge");

        assert_eq!(joiner.task_count(), 3, "all tasks transferred");
        assert_eq!(joiner.name(), "Sprint Backlog", "name transferred");
        let joiner_order: Vec<_> = joiner.tasks_ordered().iter().map(|t| *t.id()).collect();
        let holder_order: Vec<_> = holder.tasks_ordered().iter().map(|t| *t.id()).collect();
        assert_eq!(joiner_order, holder_order, "ordering converged");
    }

    #[test]
    fn test_delta_crdt_trait_merge() {
        // Layer A (issue #349): DeltaCrdt::merge carries no writer identity,
        // so it is NOT an untrusted-apply path — it passes `None` and must
        // apply no unsigned content. The task from list2's delta must NOT
        // land, and the version must not advance on dropped content.
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);

        let mut list1 = TaskList::new(id, "List".to_string(), peer1);
        let mut list2 = TaskList::new(id, "List".to_string(), peer2);

        // list2 adds a task
        let task = make_task(1, peer2);
        list2.add_task(task, peer2, 1).ok().unwrap();

        // Use DeltaCrdt trait
        let delta = DeltaCrdt::delta(&list2, 0).unwrap();
        let result = DeltaCrdt::merge(&mut list1, &delta);
        assert!(result.is_ok());

        // Unsigned content must not apply: no task, no version advance.
        assert_eq!(
            list1.task_count(),
            0,
            "unsigned content must not apply via DeltaCrdt::merge"
        );
        assert_eq!(
            DeltaCrdt::version(&list1),
            0,
            "dropped content must not advance the version"
        );
    }

    #[test]
    fn test_delta_serialization() {
        let delta = TaskListDelta::new(5);

        let serialized = bincode::serialize(&delta).ok().unwrap();
        let deserialized: TaskListDelta = bincode::deserialize(&serialized).ok().unwrap();

        assert_eq!(delta.version, deserialized.version);
        assert_eq!(delta.is_empty(), deserialized.is_empty());
    }

    #[test]
    fn test_merge_delta_with_ordering_update() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Test".to_string(), peer);

        // Add tasks
        let task1 = make_task(1, peer);
        let task2 = make_task(2, peer);
        let id1 = *task1.id();
        let id2 = *task2.id();

        list.add_task(task1, peer, 1).ok().unwrap();
        list.add_task(task2, peer, 2).ok().unwrap();

        // Build an ordering register that causally dominates the local one
        // (a peer that reversed the order on top of the shared history), so
        // the LWW merge adopts it.
        let mut order_register = list.ordering_register().clone();
        order_register.set(vec![id2, id1], peer); // Reversed order, newer clock
        let mut delta = TaskListDelta::new(10);
        delta.ordering_update = Some(order_register);

        // Merge delta
        list.merge_delta(&delta, peer, Some(&agent(1)))
            .ok()
            .unwrap();

        // Verify ordering changed
        let tasks = list.tasks_ordered();
        assert_eq!(tasks[0].id(), &id2);
        assert_eq!(tasks[1].id(), &id1);
    }

    #[test]
    fn stale_name_delta_does_not_clobber_newer_local_name() {
        // WHY: a cold-start responder broadcasts its full state on the main
        // topic, reaching established peers. A peer that renamed the list more
        // recently must not have its name reverted by an older holder's
        // snapshot — the register's vector clock decides the winner.
        let local = peer(1);
        let remote = peer(2);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Original".to_string(), local);

        // `remote` renames the list; capture that register as the "stale" one.
        list.update_name("FromRemote".to_string(), remote);
        let stale = list.name_register().clone();

        // `local` then renames on top — causally newer (its clock includes the
        // remote rename), so a later redelivery of the stale register loses.
        list.update_name("Newest".to_string(), local);

        let mut delta = TaskListDelta::new(7);
        delta.name_update = Some(stale);
        list.merge_delta(&delta, remote, Some(&agent(2)))
            .ok()
            .unwrap();

        assert_eq!(list.name(), "Newest", "stale name must not clobber newer");
    }

    #[test]
    fn test_merge_delta_with_name_update() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Original".to_string(), peer);

        // A peer renames on top of the shared initial state; its register
        // causally dominates ours, so the LWW merge adopts it.
        let mut other = TaskList::new(id, "Original".to_string(), peer);
        other.update_name("Updated".to_string(), peer);
        let mut delta = TaskListDelta::new(5);
        delta.name_update = Some(other.name_register().clone());

        // Merge delta
        list.merge_delta(&delta, peer, Some(&agent(1)))
            .ok()
            .unwrap();

        // Verify name changed
        assert_eq!(list.name(), "Updated");
    }

    #[test]
    fn duplicate_merge_delta_advances_version_once_then_is_idempotent() {
        // P1 fence: the TaskList version IS the local-replica fence token. A
        // real remote change must advance it exactly once; an idempotent
        // re-delivery of an already-resolved delta must NOT advance it (else
        // revision churn would spuriously invalidate callers and satisfy
        // "fence changed" gates with no real change). merge_delta must not
        // bump version inside its sub-operations; only commit_revision_if_changed
        // advances it, iff the resolved snapshot changed.
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "L".to_string(), peer);
        let t1 = make_task(1, peer);
        let t2 = make_task(2, peer);
        let id1 = *t1.id();
        let id2 = *t2.id();
        list.add_task(t1, peer, 1).unwrap();
        list.add_task(t2, peer, 2).unwrap();

        // A remote peer reverses the order on top of the shared history; its
        // register causally dominates ours, so the first merge is a real change.
        let mut order_register = list.ordering_register().clone();
        order_register.set(vec![id2, id1], peer);
        let mut delta = TaskListDelta::new(10);
        delta.ordering_update = Some(order_register);

        let v0 = list.version();
        list.merge_delta(&delta, peer, Some(&agent(1))).unwrap();
        let v1 = list.version();
        assert!(
            v1 > v0,
            "a real remote ordering change must advance the version/fence once"
        );

        // Second identical merge: the ordering is already resolved identically
        // ⇒ the fingerprint is unchanged ⇒ the version MUST NOT advance again.
        list.merge_delta(&delta, peer, Some(&agent(1))).unwrap();
        assert_eq!(
            list.version(),
            v1,
            "duplicate delta must not advance the version/fence again"
        );
        // The two real tasks are still present (no spurious removal).
        assert_eq!(list.task_count(), 2);
    }

    // ------------------------------------------------------------------
    // Layer A authorship gate (issue #349)
    // ------------------------------------------------------------------

    fn signing_for(_n: u8) -> (AgentId, crate::gossip::SigningContext) {
        let kp = crate::identity::AgentKeypair::generate().expect("agent keygen");
        (
            kp.agent_id(),
            crate::gossip::SigningContext::from_keypair(&kp),
        )
    }

    /// Seed a receiver exactly like [`forged_content_delta_template`]'s base
    /// so the delta's LWW registers causally dominate on merge.
    fn seeded_receiver(id: TaskListId, members: Option<AgentId>) -> (TaskList, TaskId, TaskId) {
        let mut list = TaskList::new(id, "Sprint".to_string(), peer(3));
        if let Some(m) = members {
            list.set_authorized_agents(HashSet::from([m]));
        }
        let t0 = make_task(1, peer(3));
        let t0_id = *t0.id();
        list.add_task(t0, peer(3), 1).expect("seed t0");
        (list, t0_id, TaskId::from_bytes([2; 32]))
    }

    /// A delta whose every payload PeerId component equals the victim's
    /// AgentId bytes: an attacker tries to borrow the victim's identity
    /// through the OR-Set tag / LWW-clock namespace.
    fn forged_content_delta(id: TaskListId, t0_id: TaskId) -> TaskListDelta {
        let spoofed = PeerId::new(agent(1).0);
        // Template constructed identically to seeded_receiver so registers
        // cloned from it dominate the receiver's.
        let mut template = TaskList::new(id, "Sprint".to_string(), peer(3));
        template
            .add_task(make_task(1, peer(3)), peer(3), 1)
            .expect("seed t0");

        // New task attributed to the victim (`created_by` = agent(1)).
        let t1 = make_task(2, spoofed);
        let t1_id = *t1.id();
        let mut delta = TaskListDelta::new(5);
        delta.added_tasks.insert(t1_id, (t1, (spoofed, 1)));

        // Forged rename + reorder, clocked by the spoofed peer.
        let mut name_reg = template.name_register().clone();
        name_reg.set("Pwned".to_string(), spoofed);
        delta.name_update = Some(name_reg);
        let mut order_reg = template.ordering_register().clone();
        order_reg.set(vec![t1_id, t0_id], spoofed);
        delta.ordering_update = Some(order_reg);

        // Forged remove of the existing task.
        delta
            .removed_tasks
            .insert(t0_id, HashSet::from([(spoofed, 1)]));
        delta
    }

    #[test]
    fn merge_delta_spoofed_payload_peer_id_is_not_identity() {
        // WHY (issue #349, invariant I3): the payload PeerId is an OR-Set
        // uniqueness tag, never an author. A member (attacker) forging a
        // delta whose payload PeerId EQUALS the victim's AgentId bytes must
        // not borrow the victim's authority: content admission is gated by
        // the envelope-verified writer (AgentId) against the
        // authorized-agents set, never by comparing PeerId bytes to AgentId
        // bytes.
        let id = list_id(1);
        let victim = agent(1);
        let attacker = agent(99);
        let spoofed = PeerId::new(victim.0); // same bytes — must NOT grant identity

        let (mut list, t0_id, t1_id) = seeded_receiver(id, Some(victim));
        let order_before: Vec<_> = list.tasks_ordered().iter().map(|t| *t.id()).collect();
        let delta = forged_content_delta(id, t0_id);

        // The ATTACKER is the verified envelope sender: every content field
        // must be silently dropped (Ok, no error — KV-style reject).
        list.merge_delta(&delta, spoofed, Some(&attacker))
            .expect("silent reject, not an error");
        assert_eq!(list.task_count(), 1, "spoofed add must not create a task");
        assert!(
            list.get_task(&t1_id).is_none(),
            "no task attributed to the victim"
        );
        assert!(
            list.get_task(&t0_id).is_some(),
            "spoofed remove must not delete"
        );
        assert_eq!(list.name(), "Sprint", "spoofed rename must not apply");
        let order_after: Vec<_> = list.tasks_ordered().iter().map(|t| *t.id()).collect();
        assert_eq!(order_after, order_before, "spoofed reorder must not apply");

        // The VICTIM as the verified writer, with a DIFFERENT payload
        // PeerId: the same delta applies — proving the writer AgentId (not
        // the payload PeerId) is the gate.
        let (mut honest, t0_id, t1_id) = seeded_receiver(id, Some(victim));
        honest
            .merge_delta(&delta, peer(7), Some(&victim))
            .expect("honest merge");
        assert!(
            honest.get_task(&t1_id).is_some(),
            "victim's add applies regardless of payload PeerId"
        );
        assert!(
            honest.get_task(&t0_id).is_none(),
            "victim's remove applies regardless of payload PeerId"
        );
        assert_eq!(honest.name(), "Pwned", "victim's rename applies");
    }

    #[test]
    fn merge_delta_anonymous_writer_drops_content_but_admits_attested_claim() {
        // WHY (issue #349, I2): an unsigned (anonymous-sender) delta must
        // not apply ANY unauthenticated content field — add, metadata LWW,
        // name, order, remove — while checkbox admission (gated by
        // OpAttestation, not by the envelope writer) still admits a validly
        // attested claim on a task the receiver already holds.
        let id = list_id(1);
        let p = peer(4);
        let (mut list, t0_id, t1_id) = seeded_receiver(id, None);
        let order_before: Vec<_> = list.tasks_ordered().iter().map(|t| *t.id()).collect();

        // A source task carrying BOTH a validly-attested claim AND a forged
        // title change (no content attestation exists — Layer B is HOLD).
        let (claimer, signing) = signing_for(5);
        let mut claimed = make_task(1, p);
        claimed.claim(id, claimer, p, 42, &signing).expect("attest");
        claimed.update_title("Forged title".to_string(), peer(9));

        let mut delta = forged_content_delta(id, t0_id);
        delta.task_updates.insert(t0_id, claimed);

        list.merge_delta(&delta, peer(9), None)
            .expect("silent reject, not an error");

        // Content dropped: no new task, no remove, no rename, no reorder,
        // no metadata LWW.
        assert_eq!(
            list.task_count(),
            1,
            "anonymous add must not create a task (I2)"
        );
        assert!(list.get_task(&t1_id).is_none(), "no first-seen insert");
        assert!(list.get_task(&t0_id).is_some(), "anonymous remove dropped");
        assert_eq!(list.name(), "Sprint", "anonymous rename dropped");
        let order_after: Vec<_> = list.tasks_ordered().iter().map(|t| *t.id()).collect();
        assert_eq!(order_after, order_before, "anonymous reorder dropped");
        assert_ne!(
            list.get_task(&t0_id).expect("t0").title(),
            "Forged title",
            "anonymous metadata LWW dropped"
        );

        // Checkbox admission still ran for the existing task: the attested
        // claim survives even though every content field was dropped.
        assert!(
            list.get_task(&t0_id)
                .expect("t0")
                .current_state()
                .is_claimed(),
            "attested claim must still be admitted with writer=None"
        );
    }

    #[test]
    fn merge_delta_honest_writer_content_applies() {
        // WHY (issue #349): a verified envelope writer must keep today's
        // apply path — add / name / order / remove all land when the list
        // has no authorized set (Layer A needs no new attestations; Layer B
        // is HOLD).
        let id = list_id(1);
        let (mut list, t0_id, t1_id) = seeded_receiver(id, None);
        let delta = forged_content_delta(id, t0_id);

        list.merge_delta(&delta, peer(7), Some(&agent(1)))
            .expect("honest writer merge");

        assert!(
            list.get_task(&t1_id).is_some(),
            "add applies for a verified writer"
        );
        assert!(
            list.get_task(&t0_id).is_none(),
            "remove applies for a verified writer"
        );
        assert_eq!(list.name(), "Pwned", "rename applies for a verified writer");
        let order: Vec<_> = list.tasks_ordered().iter().map(|t| *t.id()).collect();
        assert_eq!(order, vec![t1_id], "reorder applies for a verified writer");
    }

    #[test]
    fn merge_delta_membership_gates_unauthorized_writer_content() {
        // WHY (issue #349, I8): with an authorized-member set, content from
        // a writer OUTSIDE the set is dropped — "member may edit" — while
        // the same delta from a member applies.
        let id = list_id(1);
        let alice = agent(1);
        let bob = agent(2);

        let (mut list, t0_id, t1_id) = seeded_receiver(id, Some(alice));
        let delta = forged_content_delta(id, t0_id);
        list.merge_delta(&delta, peer(7), Some(&bob))
            .expect("silent reject, not an error");
        assert!(list.get_task(&t1_id).is_none(), "non-member add dropped");
        assert!(list.get_task(&t0_id).is_some(), "non-member remove dropped");
        assert_eq!(list.name(), "Sprint", "non-member rename dropped");

        let (mut member_list, t0_id, t1_id) = seeded_receiver(id, Some(alice));
        member_list
            .merge_delta(&delta, peer(7), Some(&alice))
            .expect("member merge");
        assert!(member_list.get_task(&t1_id).is_some(), "member add applies");
        assert!(
            member_list.get_task(&t0_id).is_none(),
            "member remove applies"
        );
        assert_eq!(member_list.name(), "Pwned", "member rename applies");
    }

    // ── ADR-0040 (review r2): legacy-DELTA byte compatibility ────────────

    /// Pre-0040 wire shapes: TaskItem had NO owner_transfers field and
    /// TaskListDelta had no trailing ownership map. Bincode is positional,
    /// so a tolerant field NESTED inside a delta cannot be told apart from
    /// the next value's bytes — the original trailing-field-on-TaskItem
    /// approach broke legacy-delta decode. The fix moves ownership to the
    /// delta's own trailing map; these tests pin the compat both ways.
    #[test]
    fn legacy_delta_bytes_decode_unchanged() {
        // WHY: an old binary's published (PeerId, TaskListDelta) blob must
        // decode under the new code with full content and empty ownership.
        #[derive(serde::Serialize)]
        struct LegacyTaskItem {
            id: TaskId,
            checkbox: saorsa_gossip_crdt_sync::OrSet<crate::crdt::CheckboxState>,
            title: LwwRegister<String>,
            description: LwwRegister<String>,
            assignee: LwwRegister<Option<AgentId>>,
            priority: LwwRegister<u8>,
            created_by: AgentId,
            created_at: u64,
            attestations: std::collections::BTreeMap<crate::crdt::CheckboxState, OpAttestation>,
        }
        #[derive(serde::Serialize)]
        struct LegacyDelta {
            added_tasks: HashMap<TaskId, (LegacyTaskItem, UniqueTag)>,
            removed_tasks: HashMap<TaskId, HashSet<UniqueTag>>,
            task_updates: HashMap<TaskId, LegacyTaskItem>,
            ordering_update: Option<LwwRegister<Vec<TaskId>>>,
            name_update: Option<LwwRegister<String>>,
            version: u64,
        }

        let task_id = TaskId::from_bytes([7u8; 32]);
        let creator = agent(1);
        let legacy_item = LegacyTaskItem {
            id: task_id,
            checkbox: saorsa_gossip_crdt_sync::OrSet::new(),
            title: LwwRegister::new("Task 7".to_string()),
            description: LwwRegister::new("Description 7".to_string()),
            assignee: LwwRegister::new(None),
            priority: LwwRegister::new(128),
            created_by: creator,
            created_at: 1000,
            attestations: std::collections::BTreeMap::new(),
        };
        let mut added = HashMap::new();
        added.insert(task_id, (legacy_item, (peer(2), 1u64)));
        let legacy = LegacyDelta {
            added_tasks: added,
            removed_tasks: HashMap::new(),
            task_updates: HashMap::new(),
            ordering_update: None,
            name_update: None,
            version: 3,
        };
        let blob = bincode::serialize(&(peer(9), legacy)).expect("legacy blob");

        // Decode with the CURRENT wire codec (same options as
        // gossip::wire::decode_delta: fixint + trailing tolerance).
        use bincode::Options;
        let opts = bincode::options()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(8 * 1024 * 1024);
        let (decoded_peer, decoded): (PeerId, TaskListDelta) =
            opts.deserialize(&blob).expect("legacy delta must decode");
        assert_eq!(decoded_peer, peer(9));
        assert_eq!(decoded.version, 3);
        assert_eq!(decoded.added_tasks.len(), 1, "task content survives");
        assert!(
            decoded.owner_transfers.is_empty(),
            "no ownership on the wire for a legacy delta"
        );
        let restored = decoded
            .added_tasks
            .get(&task_id)
            .map(|(t, _)| t)
            .expect("task present");
        assert_eq!(restored.title(), "Task 7");
        assert_eq!(
            restored.owner(),
            creator,
            "ownership resolves to created_by exactly as pre-0040"
        );
    }

    #[test]
    fn new_delta_carries_ownership_and_merges() {
        // WHY: the delta-level map is not just compat scaffolding — a
        // signed transfer must reach a replica through a real delta and
        // resolve there after the admission gate.
        use crate::gossip::SigningContext;
        let kp = crate::identity::AgentKeypair::generate().expect("keypair");
        let signing = SigningContext::from_keypair(&kp);
        let creator = kp.agent_id();

        let task_id = TaskId::from_bytes([3u8; 32]);
        let mut owned = TaskItem::new(
            task_id,
            TaskMetadata::new("T", "D", 1, creator, 1_000),
            peer(1),
        );
        owned
            .transfer_ownership(
                TaskListId::new([0x5c; 32]),
                creator,
                agent(9),
                5_000,
                &signing,
            )
            .expect("transfer signs");

        let delta = TaskListDelta::for_state_change(task_id, owned, 4);
        assert!(
            delta.owner_transfers.contains_key(&task_id),
            "transfers ride the delta-level map"
        );

        // Wire roundtrip then merge into a fresh replica holding the task.
        let blob = bincode::serialize(&(peer(1), delta)).expect("blob");
        let (_, decoded): (PeerId, TaskListDelta) =
            bincode::deserialize(&blob).expect("new delta decodes");
        // The receiving list's id is the SIGNING SCOPE — scope binding
        // (v2 canonical bytes) must match or the admission gate drops it.
        let mut list = TaskList::new(TaskListId::new([0x5c; 32]), "L".into(), peer(1));
        let fresh = TaskItem::new(
            task_id,
            TaskMetadata::new("T", "D", 1, creator, 1_000),
            peer(1),
        );
        list.add_task(fresh, peer(1), 1).expect("add");
        list.merge_delta(&decoded, peer(2), Some(&creator))
            .expect("merge");
        assert_eq!(
            list.task_owner(&task_id).expect("owner"),
            agent(9),
            "signed transfer converges on the replica via the delta map"
        );
    }
}
