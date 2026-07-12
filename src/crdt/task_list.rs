//! TaskList CRDT for collaborative task management.
//!
//! Implements a distributed task list using:
//! - OR-Set for task membership (adds win over removes)
//! - LWW-Register for task ordering (last write wins)
//! - HashMap for task content storage
//!
//! ## Ordering Strategy
//!
//! Since saorsa-gossip doesn't provide RGA (Replicated Growable Array),
//! we use `LwwRegister<Vec<TaskId>>` for ordering:
//! - On merge, the latest vector clock wins
//! - Tasks in OR-Set but not in ordering vector are appended to the end
//!
//! This provides eventual consistency with deterministic conflict resolution.

use crate::crdt::{CrdtError, Result, TaskId, TaskItem};
use crate::identity::AgentId;
use saorsa_gossip_crdt_sync::{LwwRegister, OrSet};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Task list identifier.
///
/// A 32-byte unique identifier for a task list, typically derived from
/// BLAKE3(list_name || creator || timestamp).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskListId([u8; 32]);

impl TaskListId {
    /// Create a new TaskListId from raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from content (name, creator, timestamp).
    #[must_use]
    pub fn from_content(name: &str, creator: &AgentId, timestamp: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(name.as_bytes());
        hasher.update(creator.as_bytes());
        hasher.update(&timestamp.to_le_bytes());
        let hash = hasher.finalize();
        Self(*hash.as_bytes())
    }

    /// Deterministic id for a task list reached via the gossip `topic`.
    ///
    /// Every replica that creates or joins the same logical list does so via
    /// the same topic, so the id MUST derive from the topic ALONE. It must not
    /// fold in per-node data (e.g. the local agent id) or per-call data (a
    /// name, a timestamp): the id is the attestation `scope` bound into every
    /// claim/complete signature ([`TaskItem::admit`]), so if two replicas
    /// derived different ids their scope-bound attestations would fail to
    /// verify across the wire and claims would never converge.
    #[must_use]
    pub fn from_topic(topic: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"x0x.tasklist.id.v1");
        hasher.update(topic.as_bytes());
        Self(*hasher.finalize().as_bytes())
    }
}

impl std::fmt::Display for TaskListId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// A collaborative task list using CRDTs.
///
/// TaskList combines multiple CRDTs to provide a conflict-free task list:
/// - OR-Set for task membership (which tasks exist)
/// - HashMap for task content (the TaskItem CRDTs)
/// - LWW-Register for ordering (task display order)
/// - LWW-Register for metadata (list name)
fn default_seq_counter() -> Arc<AtomicU64> {
    Arc::new(AtomicU64::new(0))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskList {
    /// Unique identifier for this task list.
    id: TaskListId,

    /// Set of task IDs (OR-Set semantics - adds win).
    tasks: OrSet<TaskId>,

    /// Task content indexed by ID.
    task_data: HashMap<TaskId, TaskItem>,

    /// Task ordering (LWW semantics).
    ///
    /// Contains the ordered list of TaskIds. On merge, the ordering
    /// with the latest vector clock wins. Tasks in the OR-Set but
    /// not in this vector are appended to the end.
    ordering: LwwRegister<Vec<TaskId>>,

    /// List name (LWW semantics).
    name: LwwRegister<String>,

    /// Version counter — incremented on every mutation for accurate
    /// delta-based synchronization.
    #[serde(default)]
    version: u64,

    /// Monotonic sequence counter for generating unique OR-Set tags.
    ///
    /// Shared via `Arc` so clones share the same counter, preventing
    /// tag collisions. Not serialized — remote replicas start their own
    /// counters from 0; uniqueness comes from the `PeerId` component.
    #[serde(skip, default = "default_seq_counter")]
    seq_counter: Arc<AtomicU64>,

    /// Optional authorized-member set for group-scoped lists.
    ///
    /// When set, the admission gate rejects checkbox elements whose attesting
    /// agent is not in this set, applying group authorization at replication
    /// admission (not just at REST). None for non-group-scoped lists — all
    /// validly-attested operations are admitted. Not serialized; set at
    /// runtime by the handle from the group service.
    #[serde(skip, default)]
    authorized_agents: Option<Arc<HashSet<AgentId>>>,
}

impl TaskList {
    /// Create a new empty task list.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this list
    /// * `name` - Human-readable name
    /// * `_peer_id` - Creating peer (for future use)
    ///
    /// # Returns
    ///
    /// A new empty TaskList.
    #[must_use]
    pub fn new(id: TaskListId, name: String, _peer_id: PeerId) -> Self {
        Self {
            id,
            tasks: OrSet::new(),
            task_data: HashMap::new(),
            ordering: LwwRegister::new(Vec::new()),
            name: LwwRegister::new(name),
            version: 0,
            seq_counter: Arc::new(AtomicU64::new(0)),
            authorized_agents: None,
        }
    }

    /// Set the authorized-member set for group-scoped lists.
    ///
    /// When set, the admission gate ([`TaskList::admit_all`] and the merge
    /// paths) drops checkbox elements whose attesting agent is not in this
    /// set. This applies group authorization at replication admission, not
    /// just at REST. Pass an empty set to deny ALL remote claims/completions
    /// (fail-closed for a group with no active members). Call before starting
    /// the sync listener to avoid a race window.
    pub fn set_authorized_agents(&mut self, agents: HashSet<AgentId>) {
        self.authorized_agents = Some(Arc::new(agents));
    }

    /// Clear the authorized-member set (revert to open admission for all
    /// validly-attested operations).
    pub fn clear_authorized_agents(&mut self) {
        self.authorized_agents = None;
    }

    /// Get the current version counter.
    ///
    /// Incremented on every effective local snapshot change — local mutations
    /// (add/remove/claim/complete/reorder/rename) AND remote merges that
    /// change the resolved observable state. A merge that is a no-op (e.g.
    /// re-applying an already-known delta) does NOT bump it. This makes the
    /// counter a correct local-replica fencing token: a caller that captured
    /// `version` before a remote claim merged in observes a mismatch and is
    /// rejected. It is still LOCAL only (per-replica); it is not a distributed
    /// CAS.
    #[must_use]
    pub fn current_version(&self) -> u64 {
        self.version
    }

    /// Deterministic fingerprint of the resolved observable state.
    ///
    /// Hashes the *resolution* of every task (current state, claim/completion
    /// winners, title, description, assignee, priority) plus list ordering and
    /// name, iterated in sorted task-id order. Because it is based on resolved
    /// values (order-independent minima over the OR-Set) and sorted iteration,
    /// it is:
    /// - **deterministic** — identical resolved state yields an identical
    ///   fingerprint; and
    /// - **idempotent-stable** — re-merging an already-known delta leaves the
    ///   resolutions unchanged, so the fingerprint (and thus `version`) does
    ///   not change.
    ///
    /// Used by [`TaskList::merge`] and [`TaskList::merge_delta`] to advance
    /// `version` exactly once per effective local snapshot change. Cost is
    /// O(tasks); task lists are small.
    #[must_use]
    pub(crate) fn state_fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        // Sorted task-id iteration ⇒ deterministic regardless of HashMap
        // randomization.
        let mut ids: Vec<&TaskId> = self.task_data.keys().collect();
        ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for id in &ids {
            let task = &self.task_data[*id];
            hasher.write(id.as_bytes());
            task.title().hash(&mut hasher);
            task.description().hash(&mut hasher);
            task.priority().hash(&mut hasher);
            task.current_state().hash(&mut hasher);
            task.claim_record().hash(&mut hasher);
            task.completion_record().hash(&mut hasher);
            task.assignee().hash(&mut hasher);
        }
        for tid in self.ordering.get() {
            hasher.write(tid.as_bytes());
        }
        hasher.write(self.name.get().as_bytes());
        hasher.finish()
    }

    /// Advance the local revision iff the resolved observable fingerprint has
    /// changed since `before_fingerprint`.
    ///
    /// Idempotent-stable: a merge that leaves the resolutions unchanged (e.g.
    /// re-applying an already-known delta) does not bump `version`, so it
    /// causes no spurious false conflict. This is the single entry point both
    /// [`TaskList::merge`] and [`TaskList::merge_delta`] use to keep the
    /// local-replica fence token honest.
    pub(crate) fn commit_revision_if_changed(&mut self, before_fingerprint: u64) {
        if self.state_fingerprint() != before_fingerprint {
            self.version += 1;
        }
    }

    /// Return the next monotonically-increasing sequence number.
    ///
    /// Used to construct `UniqueTag = (PeerId, seq)` for OR-Set
    /// operations. Guaranteed distinct on this node even when multiple
    /// operations occur within the same millisecond.
    pub fn next_seq(&self) -> u64 {
        self.seq_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Get the task list ID.
    #[must_use]
    pub fn id(&self) -> &TaskListId {
        &self.id
    }

    /// Get the current name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.get()
    }

    /// Add a task to the list.
    ///
    /// # Arguments
    ///
    /// * `task` - The task to add
    /// * `peer_id` - The peer making this change
    /// * `seq` - Sequence number for the operation
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the OR-Set operation fails.
    pub fn add_task(&mut self, task: TaskItem, peer_id: PeerId, seq: u64) -> Result<()> {
        self.add_task_core(task, peer_id, seq)?;
        self.version += 1;
        Ok(())
    }

    /// Core add-task logic (OR-Set add, task_data merge/admit, ordering
    /// append) shared by the public [`add_task`] (local mutation, bumps
    /// version) and the delta-merge path ([`Self::delta_upsert_task`], which
    /// defers the version bump to [`Self::commit_revision_if_changed`]).
    fn add_task_core(&mut self, task: TaskItem, peer_id: PeerId, seq: u64) -> Result<()> {
        let task_id = *task.id();
        // Snapshot scope + authorized set before any mutable borrow of
        // task_data so the admission gate can run without borrow conflicts.
        let scope = self.id;
        let authorized = self.authorized_agents.clone();

        // Add to OR-Set
        let tag = (peer_id, seq);
        self.tasks
            .add(task_id, tag)
            .map_err(|e| CrdtError::Merge(format!("Failed to add task to OR-Set: {}", e)))?;

        // Store or merge task data
        if let Some(existing) = self.task_data.get_mut(&task_id) {
            // Task already exists - merge CRDT state instead of overwriting
            existing.merge(scope, &task)?;
            // Apply group-authorization filter on the merged result so a
            // nonmember's claim/complete arriving via merge is rejected.
            if let Some(members) = &authorized {
                let dropped = existing.filter_unauthorized(members);
                if dropped > 0 {
                    tracing::debug!(dropped, "dropped nonmember elements during merge-add");
                }
            }
        } else {
            // New task — run the fail-closed admission gate before inserting
            // so a first-seen forged/unattested element is purged before it
            // can influence resolution. This closes the first-seen bypass.
            let mut task = task;
            let mut dropped = task.admit(scope);
            if let Some(members) = &authorized {
                dropped += task.filter_unauthorized(members);
            }
            if dropped > 0 {
                tracing::debug!(
                    dropped,
                    "purged unauthenticated/nonmember checkbox elements during first-seen add_task"
                );
            }
            self.task_data.insert(task_id, task);
        }

        // Add to ordering (append to end)
        let mut current_order = self.ordering.get().clone();
        if !current_order.contains(&task_id) {
            current_order.push(task_id);
            self.ordering.set(current_order, peer_id);
        }

        Ok(())
    }

    // ── Delta-merge internal helpers (no version bump) ───────────────────
    //
    // These mirror the public mutators but do NOT advance `self.version`.
    // `merge_delta` wraps the entire body in a fingerprint snapshot and calls
    // `commit_revision_if_changed` exactly once at the end, so the version
    // advances iff the resolved observable state actually changed. If these
    // helpers bumped version internally, an idempotent redelivery would
    // advance the fence despite no effective state change.

    /// Upsert a task during delta merge without bumping version.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn delta_upsert_task(
        &mut self,
        task: TaskItem,
        peer_id: PeerId,
        seq: u64,
    ) -> Result<()> {
        self.add_task_core(task, peer_id, seq)
    }

    /// Remove a task during delta merge without bumping version. No-op if the
    /// task does not exist locally.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn delta_remove_task(&mut self, task_id: &TaskId) {
        if self.task_data.contains_key(task_id) {
            let _ = self.tasks.remove(task_id);
            self.task_data.remove(task_id);
        }
    }

    /// Merge a remote ordering register during delta merge without bumping
    /// version.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn delta_merge_ordering(&mut self, other: &LwwRegister<Vec<TaskId>>) {
        self.ordering.merge(other);
    }

    /// Merge a remote name register during delta merge without bumping version.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn delta_merge_name(&mut self, other: &LwwRegister<String>) {
        self.name.merge(other);
    }

    /// Merge a remote task into an existing local task during delta merge,
    /// then apply the authentication and membership admission gates. Does NOT
    /// bump version (deferred to `commit_revision_if_changed`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn delta_merge_task(&mut self, task_id: &TaskId, other: &TaskItem) -> Result<()> {
        let scope = self.id;
        let authorized = self.authorized_agents.clone();
        if let Some(existing) = self.task_data.get_mut(task_id) {
            existing.merge(scope, other)?;
            if let Some(members) = &authorized {
                let _dropped = existing.filter_unauthorized(members);
            }
        }
        Ok(())
    }

    /// Remove a task from the list.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to remove
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns `CrdtError::TaskNotFound` if the task doesn't exist.
    pub fn remove_task(&mut self, task_id: &TaskId) -> Result<()> {
        if !self.task_data.contains_key(task_id) {
            return Err(CrdtError::TaskNotFound(*task_id));
        }

        // Remove from OR-Set (marks as tombstone)
        self.tasks
            .remove(task_id)
            .map_err(|e| CrdtError::Merge(format!("Failed to remove task from OR-Set: {}", e)))?;

        // Remove from task data
        self.task_data.remove(task_id);

        // Note: We don't remove from ordering vector to preserve order of remaining tasks
        // The ordering will be filtered when tasks_ordered() is called

        self.version += 1;
        Ok(())
    }

    /// Claim a task in the list.
    ///
    /// Delegates to the TaskItem's claim method.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to claim
    /// * `agent_id` - Agent claiming the task
    /// * `peer_id` - Peer making this change
    /// * `seq` - Sequence number
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the task doesn't exist or state transition is invalid.
    pub fn claim_task(
        &mut self,
        task_id: &TaskId,
        agent_id: AgentId,
        peer_id: PeerId,
        seq: u64,
        signing: &crate::gossip::SigningContext,
    ) -> Result<()> {
        let task = self
            .task_data
            .get_mut(task_id)
            .ok_or(CrdtError::TaskNotFound(*task_id))?;

        task.claim(self.id, agent_id, peer_id, seq, signing)?;
        self.version += 1;
        Ok(())
    }

    /// Complete a task in the list.
    ///
    /// Delegates to the TaskItem's complete method.
    ///
    /// # Arguments
    ///
    /// * `task_id` - ID of the task to complete
    /// * `agent_id` - Agent completing the task
    /// * `peer_id` - Peer making this change
    /// * `seq` - Sequence number
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the task doesn't exist or state transition is invalid.
    pub fn complete_task(
        &mut self,
        task_id: &TaskId,
        agent_id: AgentId,
        peer_id: PeerId,
        seq: u64,
        signing: &crate::gossip::SigningContext,
    ) -> Result<()> {
        let task = self
            .task_data
            .get_mut(task_id)
            .ok_or(CrdtError::TaskNotFound(*task_id))?;

        task.complete(self.id, agent_id, peer_id, seq, signing)?;
        self.version += 1;
        Ok(())
    }

    /// Reorder the tasks in the list.
    ///
    /// # Arguments
    ///
    /// * `new_order` - New ordering of task IDs
    /// * `peer_id` - Peer making this change
    ///
    /// # Returns
    ///
    /// Ok(()) if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if any task ID in the new order doesn't exist.
    pub fn reorder(&mut self, new_order: Vec<TaskId>, peer_id: PeerId) -> Result<()> {
        // Validate that all task IDs in the new order exist
        for task_id in &new_order {
            if !self.task_data.contains_key(task_id) {
                return Err(CrdtError::TaskNotFound(*task_id));
            }
        }

        // Update ordering
        self.ordering.set(new_order, peer_id);

        self.version += 1;
        Ok(())
    }

    /// Get tasks in their current order.
    ///
    /// Returns tasks ordered according to the LWW ordering vector.
    /// Tasks in the OR-Set but not in the ordering vector are appended at the end.
    ///
    /// # Returns
    ///
    /// Vector of task references in display order.
    #[must_use]
    pub fn tasks_ordered(&self) -> Vec<&TaskItem> {
        use std::collections::HashSet;

        let current_order = self.ordering.get();
        let or_set_tasks: HashSet<TaskId> = self.tasks.elements().into_iter().copied().collect();
        // Membership set over the ordering vector so the append phase below is
        // O(1) per task instead of an O(n) `Vec::contains` inside the loop.
        let ordered_ids: HashSet<&TaskId> = current_order.iter().collect();

        // Start with tasks in the ordering vector, but only if they're in the OR-Set
        let mut ordered: Vec<&TaskItem> = current_order
            .iter()
            .filter(|id| or_set_tasks.contains(id)) // Filter by OR-Set membership first!
            .filter_map(|id| self.task_data.get(id))
            .collect();

        // Append tasks that are in OR-Set but not in ordering
        for task_id in &or_set_tasks {
            if !ordered_ids.contains(task_id) {
                if let Some(task) = self.task_data.get(task_id) {
                    ordered.push(task);
                }
            }
        }

        ordered
    }

    /// Merge another TaskList into this one.
    ///
    /// Combines OR-Sets, HashMap task data, and LWW registers according to
    /// their respective CRDT semantics.
    ///
    /// # Arguments
    ///
    /// * `other` - The TaskList to merge from
    ///
    /// # Returns
    ///
    /// Ok(()) if merge succeeded.
    ///
    /// # Errors
    ///
    /// Returns an error if the task list IDs don't match.
    pub fn merge(&mut self, other: &TaskList) -> Result<()> {
        // Can only merge lists with the same ID
        if self.id != other.id {
            return Err(CrdtError::Merge(format!(
                "Cannot merge task lists with different IDs: {} != {}",
                self.id, other.id
            )));
        }

        // Capture the resolved observable fingerprint BEFORE merging so the
        // local version advances exactly once iff this merge effectively
        // changes the local snapshot. Without this, a remote claim that
        // merges in would not advance `version` and a caller's stale token
        // would still be accepted — defeating the local-replica fence.
        let before = self.state_fingerprint();
        let scope = self.id;
        let authorized = self.authorized_agents.clone();

        // Merge OR-Set (task membership)
        self.tasks
            .merge_state(&other.tasks)
            .map_err(|e| CrdtError::Merge(format!("Failed to merge task OR-Sets: {}", e)))?;

        // Merge task data (HashMap)
        // For each task in other, either add it or merge it if it exists
        for (task_id, other_task) in &other.task_data {
            if let Some(our_task) = self.task_data.get_mut(task_id) {
                // Merge existing task
                our_task.merge(scope, other_task)?;
                if let Some(members) = &authorized {
                    let _dropped = our_task.filter_unauthorized(members);
                }
            } else {
                // Add new task — run the admission gate so a first-seen
                // forged/unattested element is purged before it can influence
                // resolution.
                let mut new_task = other_task.clone();
                let mut dropped = new_task.admit(scope);
                if let Some(members) = &authorized {
                    dropped += new_task.filter_unauthorized(members);
                }
                if dropped > 0 {
                    tracing::debug!(
                        dropped,
                        "purged unauthenticated/nonmember checkbox elements during first-seen merge"
                    );
                }
                self.task_data.insert(*task_id, new_task);
            }
        }

        // Merge LWW registers (ordering and name)
        self.ordering.merge(&other.ordering);
        self.name.merge(&other.name);

        // Advance the local revision exactly once iff the resolved snapshot
        // changed. Idempotent re-merges leave the fingerprint unchanged ⇒ no
        // bump (fixes spurious false conflicts from repeated full-state
        // merges).
        self.commit_revision_if_changed(before);
        Ok(())
    }

    /// Update the list name.
    ///
    /// # Arguments
    ///
    /// * `name` - New name
    /// * `peer_id` - Peer making this change
    pub fn update_name(&mut self, name: String, peer_id: PeerId) {
        self.name.set(name, peer_id);
        self.version += 1;
    }

    /// The name register, including its vector clock.
    ///
    /// Deltas carry this whole register (not just the value) so receivers can
    /// resolve a remote name change by causality via [`Self::merge_name`].
    #[must_use]
    pub fn name_register(&self) -> &LwwRegister<String> {
        &self.name
    }

    /// The ordering register, including its vector clock.
    #[must_use]
    pub fn ordering_register(&self) -> &LwwRegister<Vec<TaskId>> {
        &self.ordering
    }

    /// Merge a remote name register using LWW (vector-clock) semantics.
    ///
    /// Unlike `update_name`, which records a local edit, this resolves the
    /// winner by causality so a stale delta cannot overwrite a newer local
    /// name. Mirrors what the full-state [`TaskList::merge`] already does.
    pub fn merge_name(&mut self, other: &LwwRegister<String>) {
        self.name.merge(other);
        self.version += 1;
    }

    /// Merge a remote ordering register using LWW (vector-clock) semantics.
    ///
    /// The merged ordering may reference task IDs not yet known locally
    /// (out-of-order delivery); `tasks_ordered` filters those at read time.
    pub fn merge_ordering(&mut self, other: &LwwRegister<Vec<TaskId>>) {
        self.ordering.merge(other);
        self.version += 1;
    }

    /// Run the fail-closed admission gate on every task in this list.
    ///
    /// Drops unauthenticated checkbox elements (missing/malformed/wrong-agent/
    /// attacker signatures) and restores attested elements censored by forged
    /// tombstones. Called after deserializing from persistent storage so a
    /// corrupted/tampered on-disk state cannot bypass the admission gate.
    pub fn admit_all(&mut self) -> usize {
        let scope = self.id;
        let authorized = self.authorized_agents.clone();
        let mut total_dropped = 0usize;
        for task in self.task_data.values_mut() {
            total_dropped += task.admit(scope);
            if let Some(members) = &authorized {
                total_dropped += task.filter_unauthorized(members);
            }
        }
        total_dropped
    }

    /// Get the number of tasks in the list.
    #[must_use]
    pub fn task_count(&self) -> usize {
        self.task_data.len()
    }

    /// Get a specific task by ID.
    #[must_use]
    pub fn get_task(&self, task_id: &TaskId) -> Option<&TaskItem> {
        self.task_data.get(task_id)
    }

    /// Get a mutable reference to a specific task.
    pub fn get_task_mut(&mut self, task_id: &TaskId) -> Option<&mut TaskItem> {
        self.task_data.get_mut(task_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::TaskMetadata;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    /// Real (key-derived) agent identity + matching signing context for a
    /// claim/complete caller. `sign_attestation` self-signs
    /// (`agent_id == signing.agent_id`), so callers cannot use the fixed
    /// `AgentId([n;32])`; the agent id MUST be the keypair's derived id.
    fn signing_for(_n: u8) -> (AgentId, crate::gossip::SigningContext) {
        let kp = crate::identity::AgentKeypair::generate().expect("agent keygen");
        (
            kp.agent_id(),
            crate::gossip::SigningContext::from_keypair(&kp),
        )
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
    fn test_task_list_new() {
        let peer = peer(1);
        let id = list_id(1);
        let list = TaskList::new(id, "My List".to_string(), peer);

        assert_eq!(list.id(), &id);
        assert_eq!(list.name(), "My List");
        assert_eq!(list.task_count(), 0);
        assert!(list.tasks_ordered().is_empty());
    }

    #[test]
    fn test_add_task() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();

        let result = list.add_task(task, peer, 1);
        assert!(result.is_ok());
        assert_eq!(list.task_count(), 1);

        let tasks = list.tasks_ordered();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id(), &task_id);
    }

    #[test]
    fn test_remove_task() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();

        list.add_task(task, peer, 1).ok().unwrap();
        assert_eq!(list.task_count(), 1);

        let result = list.remove_task(&task_id);
        assert!(result.is_ok());
        assert_eq!(list.task_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_task() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task_id = TaskId::from_bytes([99; 32]);
        let result = list.remove_task(&task_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::TaskNotFound(_) => {}
            _ => panic!("Expected TaskNotFound"),
        }
    }

    #[test]
    fn test_claim_task() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();

        list.add_task(task, peer, 1).ok().unwrap();

        let result = list.claim_task(&task_id, agent, peer, 2, &signing);
        assert!(result.is_ok());

        let task = list.get_task(&task_id).unwrap();
        assert!(task.current_state().is_claimed());
    }

    #[test]
    fn test_complete_task() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();

        list.add_task(task, peer, 1).ok().unwrap();
        list.claim_task(&task_id, agent, peer, 2, &signing)
            .ok()
            .unwrap();

        let result = list.complete_task(&task_id, agent, peer, 3, &signing);
        assert!(result.is_ok());

        let task = list.get_task(&task_id).unwrap();
        assert!(task.current_state().is_done());
    }

    #[test]
    fn test_reorder_tasks() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task1 = make_task(1, peer);
        let task2 = make_task(2, peer);
        let task3 = make_task(3, peer);

        let id1 = *task1.id();
        let id2 = *task2.id();
        let id3 = *task3.id();

        list.add_task(task1, peer, 1).ok().unwrap();
        list.add_task(task2, peer, 2).ok().unwrap();
        list.add_task(task3, peer, 3).ok().unwrap();

        // Initial order: 1, 2, 3
        let tasks = list.tasks_ordered();
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0].id(), &id1);
        assert_eq!(tasks[1].id(), &id2);
        assert_eq!(tasks[2].id(), &id3);

        // Reorder to: 3, 1, 2
        let new_order = vec![id3, id1, id2];
        let result = list.reorder(new_order, peer);
        assert!(result.is_ok());

        let tasks = list.tasks_ordered();
        assert_eq!(tasks[0].id(), &id3);
        assert_eq!(tasks[1].id(), &id1);
        assert_eq!(tasks[2].id(), &id2);
    }

    #[test]
    fn test_reorder_with_invalid_task() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        let task_id = *task.id();
        list.add_task(task, peer, 1).ok().unwrap();

        let invalid_id = TaskId::from_bytes([99; 32]);
        let new_order = vec![task_id, invalid_id];

        let result = list.reorder(new_order, peer);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::TaskNotFound(_) => {}
            _ => panic!("Expected TaskNotFound"),
        }
    }

    #[test]
    fn test_merge_task_lists() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);

        let mut list1 = TaskList::new(id, "List 1".to_string(), peer1);
        let mut list2 = TaskList::new(id, "List 2".to_string(), peer2);

        // list1 adds task1
        let task1 = make_task(1, peer1);
        let id1 = *task1.id();
        list1.add_task(task1, peer1, 1).ok().unwrap();

        // list2 adds task2
        let task2 = make_task(2, peer2);
        let id2 = *task2.id();
        list2.add_task(task2, peer2, 1).ok().unwrap();

        // Merge list2 into list1
        let result = list1.merge(&list2);
        assert!(result.is_ok());

        // list1 should now have both tasks
        assert_eq!(list1.task_count(), 2);
        assert!(list1.get_task(&id1).is_some());
        assert!(list1.get_task(&id2).is_some());
    }

    #[test]
    fn test_merge_with_concurrent_task_modifications() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let _agent2 = agent(2);
        let id = list_id(1);

        let mut list1 = TaskList::new(id, "List".to_string(), peer1);
        let mut list2 = TaskList::new(id, "List".to_string(), peer2);

        // Both add the same task
        let task1 = make_task(1, peer1);
        let task2 = make_task(1, peer2);
        let task_id = *task1.id();

        list1.add_task(task1, peer1, 1).ok().unwrap();
        list2.add_task(task2, peer2, 1).ok().unwrap();

        // list1 claims the task
        list1
            .claim_task(&task_id, agent1, peer1, 2, &signing1)
            .ok()
            .unwrap();

        // list2 updates the title
        list2
            .get_task_mut(&task_id)
            .unwrap()
            .update_title("Updated".to_string(), peer2);

        // Merge
        list1.merge(&list2).ok().unwrap();

        // Should have both modifications
        let task = list1.get_task(&task_id).unwrap();
        assert!(task.current_state().is_claimed());
        // Title update depends on vector clock ordering
    }

    // ── Local-fence version invariants (review §3 P0/P1) ────────────────

    #[test]
    fn test_remote_claim_merge_advances_version_invalidating_stale_token() {
        // P0: a remote claim merged in must advance the local version so a
        // caller that captured an earlier version (its local-replica fence
        // token) is rejected. Without this the fence is defeated.
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);

        let mut list_a = TaskList::new(id, "List".to_string(), peer1);
        let mut list_b = TaskList::new(id, "List".to_string(), peer2);

        // Both add the same task.
        let task_a = make_task(1, peer1);
        let task_b = make_task(1, peer2);
        let task_id = *task_a.id();
        list_a.add_task(task_a, peer1, 1).unwrap();
        list_b.add_task(task_b, peer2, 1).unwrap();

        // B reads its snapshot + version (its local fence token).
        let token_b = list_b.current_version();
        assert_eq!(token_b, 1, "version after one local add");
        assert!(!list_b
            .get_task(&task_id)
            .unwrap()
            .current_state()
            .is_claimed());

        // A claims the task (advances A's version, not B's).
        let (agent, signing) = signing_for(1);
        list_a
            .claim_task(&task_id, agent, peer1, 2, &signing)
            .unwrap();

        // B merges A's state. B's resolved snapshot now shows A's claim, and
        // B's version MUST have advanced past `token_b`.
        list_b.merge(&list_a).unwrap();
        assert!(
            list_b
                .get_task(&task_id)
                .unwrap()
                .current_state()
                .is_claimed(),
            "B observed A's claim after merge"
        );
        assert!(
            list_b.current_version() > token_b,
            "remote claim merge must advance the local version (fence invalidated): {} > {}",
            list_b.current_version(),
            token_b
        );
    }

    #[test]
    fn test_merge_delta_remote_claim_advances_version() {
        // P0 via the delta path (the actual inbound gossip route): a state-
        // change delta merged through `merge_delta` must also advance version.
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);
        let mut list_a = TaskList::new(id, "List".to_string(), peer1);
        let mut list_b = TaskList::new(id, "List".to_string(), peer2);
        let task_a = make_task(1, peer1);
        let task_b = make_task(1, peer2);
        let task_id = *task_a.id();
        list_a.add_task(task_a, peer1, 1).unwrap();
        list_b.add_task(task_b, peer2, 1).unwrap();

        let token_b = list_b.current_version();

        // A claims and produces a state-change delta.
        let (agent, signing) = signing_for(1);
        list_a
            .claim_task(&task_id, agent, peer1, 2, &signing)
            .unwrap();
        let claimed_task = list_a.get_task(&task_id).unwrap().clone();
        let delta = crate::crdt::TaskListDelta::for_state_change(
            task_id,
            claimed_task,
            list_a.current_version(),
        );

        // B applies the delta over the gossip path.
        list_b.merge_delta(&delta, peer1).unwrap();
        assert!(
            list_b
                .get_task(&task_id)
                .unwrap()
                .current_state()
                .is_claimed(),
            "delta merge applied the claim"
        );
        assert!(
            list_b.current_version() > token_b,
            "remote state-change delta must advance local version"
        );
    }

    #[test]
    fn test_idempotent_merge_does_not_bump_version() {
        // P1: re-merging an already-known delta leaves the resolved snapshot
        // (and thus the version) unchanged — no spurious false conflicts.
        let peer1 = peer(1);
        let peer2 = peer(2);
        let id = list_id(1);
        let mut list_a = TaskList::new(id, "List".to_string(), peer1);
        let mut list_b = TaskList::new(id, "List".to_string(), peer2);
        let task_a = make_task(1, peer1);
        let task_b = make_task(1, peer2);
        let task_id = *task_a.id();
        list_a.add_task(task_a, peer1, 1).unwrap();
        list_b.add_task(task_b, peer2, 1).unwrap();

        // B claims → its snapshot changes.
        let (agent, signing) = signing_for(1);
        list_b
            .claim_task(&task_id, agent, peer2, 2, &signing)
            .unwrap();

        // First merge brings B's claim into A ⇒ A's version advances once.
        list_a.merge(&list_b).unwrap();
        let v1 = list_a.current_version();
        assert!(v1 > 1, "effective merge (claim) must bump version: {v1}");

        // Second identical merge: A already resolved B's claim ⇒ no change.
        list_a.merge(&list_b).unwrap();
        assert_eq!(
            list_a.current_version(),
            v1,
            "idempotent re-merge must not bump the version"
        );
    }
    #[test]
    fn test_merge_different_list_ids_fails() {
        let peer = peer(1);
        let id1 = list_id(1);
        let id2 = list_id(2);

        let mut list1 = TaskList::new(id1, "List 1".to_string(), peer);
        let list2 = TaskList::new(id2, "List 2".to_string(), peer);

        let result = list1.merge(&list2);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::Merge(_) => {}
            _ => panic!("Expected Merge error"),
        }
    }

    #[test]
    fn test_tasks_ordered_with_removed_tasks() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task1 = make_task(1, peer);
        let task2 = make_task(2, peer);
        let task3 = make_task(3, peer);

        let id1 = *task1.id();
        let id2 = *task2.id();
        let id3 = *task3.id();

        list.add_task(task1, peer, 1).ok().unwrap();
        list.add_task(task2, peer, 2).ok().unwrap();
        list.add_task(task3, peer, 3).ok().unwrap();

        // Remove middle task
        list.remove_task(&id2).ok().unwrap();

        // Should only show task1 and task3
        let tasks = list.tasks_ordered();
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].id(), &id1);
        assert_eq!(tasks[1].id(), &id3);
    }

    #[test]
    fn test_update_name() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "Original".to_string(), peer);

        assert_eq!(list.name(), "Original");

        list.update_name("Updated".to_string(), peer);
        assert_eq!(list.name(), "Updated");
    }

    #[test]
    fn test_task_list_id_from_content() {
        let agent = agent(1);
        let id1 = TaskListId::from_content("My List", &agent, 1000);
        let id2 = TaskListId::from_content("My List", &agent, 1000);

        assert_eq!(id1, id2); // Deterministic

        let id3 = TaskListId::from_content("Different", &agent, 1000);
        assert_ne!(id1, id3); // Different content
    }

    #[test]
    fn from_topic_is_deterministic_and_agent_independent() {
        // Regression guard: every replica that creates or joins a list via the
        // same topic MUST derive the SAME id, regardless of which agent does it
        // — the id is the attestation scope bound into claim/complete
        // signatures, so a per-node id makes cross-replica claims fail to
        // verify and claims never converge. `from_topic` takes no agent/name,
        // so two different agents joining the same topic agree by construction.
        let t = "team-sprint";
        assert_eq!(TaskListId::from_topic(t), TaskListId::from_topic(t));
        assert_ne!(TaskListId::from_topic(t), TaskListId::from_topic("other"));
        // Distinct from the (per-node) content derivation it replaced, so a
        // stale from_content-based replica cannot silently share scope.
        assert_ne!(
            TaskListId::from_topic(t),
            TaskListId::from_content(t, &agent(1), 0)
        );
    }

    #[test]
    fn test_task_list_id_display() {
        let id = TaskListId::new([42u8; 32]);
        let display = format!("{}", id);
        assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let peer = peer(1);
        let id = list_id(1);
        let mut list = TaskList::new(id, "My List".to_string(), peer);

        let task = make_task(1, peer);
        list.add_task(task, peer, 1).ok().unwrap();

        let serialized = bincode::serialize(&list).ok().unwrap();
        let deserialized: TaskList = bincode::deserialize(&serialized).ok().unwrap();

        assert_eq!(list.id(), deserialized.id());
        assert_eq!(list.name(), deserialized.name());
        assert_eq!(list.task_count(), deserialized.task_count());
    }

    #[test]
    fn test_next_seq_starts_at_one() {
        let list = TaskList::new(list_id(99), "seq test".to_string(), peer(1));
        assert_eq!(list.next_seq(), 1);
    }

    #[test]
    fn test_next_seq_is_strictly_monotonic() {
        let list = TaskList::new(list_id(99), "seq test".to_string(), peer(1));
        let mut prev = 0;
        for _ in 0..100 {
            let s = list.next_seq();
            assert!(s > prev, "seq must be strictly increasing");
            prev = s;
        }
    }

    #[test]
    fn test_next_seq_survives_clone() {
        let list = TaskList::new(list_id(99), "seq test".to_string(), peer(1));
        let s1 = list.next_seq();
        let cloned = list.clone();
        let s2 = cloned.next_seq();
        assert_ne!(s1, s2, "clone must share counter via Arc");
        assert_eq!(s2, s1 + 1);
    }

    #[test]
    fn test_seq_counter_resets_after_serde() {
        let list = TaskList::new(list_id(99), "seq test".to_string(), peer(1));
        for _ in 0..10 {
            let _ = list.next_seq();
        }

        let bytes = bincode::serialize(&list).ok().unwrap();
        let restored: TaskList = bincode::deserialize(&bytes).ok().unwrap();
        assert_eq!(
            restored.next_seq(),
            1,
            "deserialized counter must start fresh"
        );
    }

    #[test]
    fn test_rapid_add_tasks_all_survive() {
        let p = peer(1);
        let mut list = TaskList::new(list_id(99), "rapid".to_string(), p);
        for i in 0u8..50 {
            let task = make_task(i, p);
            let seq = list.next_seq();
            list.add_task(task, p, seq).ok().unwrap();
        }
        assert_eq!(
            list.task_count(),
            50,
            "all 50 tasks must survive; duplicate OR-Set tags would drop some"
        );
    }
}
