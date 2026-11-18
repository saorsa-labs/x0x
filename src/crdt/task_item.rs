//! TaskItem CRDT combining OR-Set (checkbox) + LWW-Register (metadata).
//!
//! A TaskItem represents a single task in a collaborative task list. It uses
//! CRDTs from saorsa-gossip to handle concurrent modifications:
//!
//! - **OR-Set** for checkbox state: Allows concurrent claims to coexist
//! - **LWW-Register** for metadata: Last-write-wins semantics for title, description, etc.
//!
//! ## Conflict Resolution
//!
//! - **Concurrent claims**: Both claims are visible in the OR-Set. The earliest
//!   timestamp wins when determining the "current" state.
//! - **Concurrent completes**: First completion wins (earliest timestamp).
//! - **Metadata updates**: Last-write-wins based on vector clocks.
//!
//! ## Example
//!
//! ```ignore
//! use x0x::crdt::{TaskItem, TaskId, TaskMetadata, CheckboxState};
//! use x0x::gossip::SigningContext;
//! use saorsa_gossip_types::PeerId;
//!
//! let peer_id = PeerId::from_bytes([1u8; 32]);
//! let task_id = TaskId::new("Implement feature", &agent_id, 1000);
//! let metadata = TaskMetadata::new("Title", "Description", 128, agent_id, 1000);
//!
//! let mut task = TaskItem::new(task_id, metadata, peer_id);
//!
//! // Claim the task (advisory: a claim records a self-attested candidate in
//! // the OR-Set and does not prevent a concurrent claim by another agent).
//! task.claim(list_id, agent_id, peer_id, 1, &signing)?;
//!
//! // Complete the task
//! task.complete(list_id, agent_id, peer_id, 2, &signing)?;
//! ```

use crate::crdt::{
    purge_unattested_elements, sign_attestation, CheckboxState, CrdtError, OpAttestation, OpKind,
    Result, TaskId, TaskListId, TaskMetadata,
};
use crate::gossip::SigningContext;
use crate::identity::AgentId;
use saorsa_gossip_crdt_sync::{LwwRegister, OrSet};
use saorsa_gossip_types::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// A task item in a collaborative task list.
///
/// TaskItem combines multiple CRDTs to represent a task:
/// - OR-Set for checkbox state (handles concurrent claims)
/// - LWW-Registers for all metadata fields
///
/// This allows multiple agents to collaborate on tasks with automatic
/// conflict resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskItem {
    id: TaskId,

    /// Every `Claimed`/`Done` element carries a matching attestation in
    /// [`TaskItem::attestations`]; [`purge_unattested_elements`] drops any
    /// element whose attestation is missing or fails verification.
    checkbox: OrSet<CheckboxState>,

    title: LwwRegister<String>,

    description: LwwRegister<String>,

    assignee: LwwRegister<Option<AgentId>>,

    priority: LwwRegister<u8>,

    created_by: AgentId,

    created_at: u64,

    /// Per-element operation attestations, keyed by the `CheckboxState` value.
    /// Serialized with the task so they survive delta replication and state sync.
    ///
    /// This is the **trailing** serialized field. bincode (the wire and disk
    /// format) is positional and non-self-describing, so `#[serde(default)]`
    /// alone would not save a blob written without it — a mid-struct absence
    /// misaligns every following field. Kept last with a tolerant deserializer
    /// so a blob whose bytes END before this field (a pre-provenance /
    /// differently-shaped TaskItem at the tail of the stream) decodes to an
    /// empty map instead of an EOF error. An empty map resolves to
    /// `current_state() == Empty`, i.e. no attested elements — fail-closed,
    /// never fail-open. The tolerance is genuine only at stream-EOF: a fieldless
    /// TaskItem nested mid-stream inside a larger bincode value cannot be
    /// recovered positionally. New fields MUST be added after this one.
    #[serde(default, deserialize_with = "deserialize_attestations")]
    attestations: BTreeMap<CheckboxState, OpAttestation>,
}

/// Tolerates the field's absence (a blob from a struct shape without it ends
/// before it). An empty map is the fail-closed default: the admission gate
/// admits nothing on the strength of missing bytes.
fn deserialize_attestations<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<CheckboxState, OpAttestation>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Ok(BTreeMap::<CheckboxState, OpAttestation>::deserialize(deserializer).unwrap_or_default())
}

impl TaskItem {
    /// Create a new TaskItem from metadata.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique task identifier
    /// * `metadata` - Task metadata (title, description, etc.)
    ///
    /// # Returns
    ///
    /// A new TaskItem with Empty checkbox state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let task_id = TaskId::new("Feature X", &agent_id, 1000);
    /// let metadata = TaskMetadata::new("Title", "Desc", 128, agent_id, 1000);
    /// let peer_id = PeerId::from_bytes([1u8; 32]);
    ///
    /// let task = TaskItem::new(task_id, metadata, peer_id);
    /// assert_eq!(task.id(), &task_id);
    /// assert!(task.current_state().is_empty());
    /// ```
    #[must_use]
    pub fn new(id: TaskId, metadata: TaskMetadata, _peer_id: PeerId) -> Self {
        Self {
            id,
            checkbox: OrSet::new(),
            title: LwwRegister::new(metadata.title),
            description: LwwRegister::new(metadata.description),
            assignee: LwwRegister::new(None),
            priority: LwwRegister::new(metadata.priority),
            created_by: metadata.created_by,
            created_at: metadata.created_at,
            attestations: BTreeMap::new(),
        }
    }

    /// Get the task ID.
    #[must_use]
    pub fn id(&self) -> &TaskId {
        &self.id
    }

    /// Get the agent who created this task.
    #[must_use]
    pub fn created_by(&self) -> &AgentId {
        &self.created_by
    }

    /// Get the creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the current title.
    #[must_use]
    pub fn title(&self) -> &str {
        self.title.get()
    }

    /// Get the current description.
    #[must_use]
    pub fn description(&self) -> &str {
        self.description.get()
    }

    /// Get the current assignee.
    #[must_use]
    pub fn assignee(&self) -> Option<&AgentId> {
        self.assignee.get().as_ref()
    }

    /// Get the current priority.
    #[must_use]
    pub fn priority(&self) -> u8 {
        *self.priority.get()
    }

    /// Claim this task.
    ///
    /// **Advisory, non-exclusive.** A successful return records a *candidate*
    /// in the OR-Set; it does NOT grant exclusive ownership and does NOT
    /// prevent another agent (on this or any other replica) from also
    /// claiming. Concurrent claims coexist — see [`TaskItem::claims`] — and
    /// resolve to a single deterministic winner (earliest timestamp, then
    /// lexicographic agent id) observable via [`TaskItem::claim_record`]. That
    /// winner is only stable once all replicas have converged; a strictly
    /// earlier-timestamp candidate arriving via a later merge will displace
    /// it. There is no distributed lock or compare-and-swap here.
    ///
    /// Adds a `Claimed` candidate to the OR-Set. If multiple agents claim
    /// concurrently, all candidates are recorded, and the earliest timestamp
    /// wins as the "current" state.
    ///
    /// Also sets the `assignee` LWW register to the claiming agent, so the
    /// task's assignee is observable without parsing the checkbox state.
    /// Under truly concurrent claims the LWW register may resolve to either
    /// claimer; the authoritative winner is [`TaskItem::claim_record`], which
    /// derives deterministically from the OR-Set.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent claiming this task
    /// * `peer_id` - The peer making this change (for vector clocks)
    /// * `seq` - Sequence number for this operation
    ///
    /// # Returns
    ///
    /// Ok(()) if claimed successfully, or an error if the task is already done.
    ///
    /// # Errors
    ///
    /// Returns `CrdtError::InvalidStateTransition` if attempting to claim
    /// a task that is already in Done state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut task = TaskItem::new(id, metadata, peer_id);
    /// task.claim(list_id, agent_id, peer_id, 1)?;
    /// assert!(task.current_state().is_claimed());
    /// ```
    pub fn claim(
        &mut self,
        scope: TaskListId,
        agent_id: AgentId,
        peer_id: PeerId,
        seq: u64,
        signing: &SigningContext,
    ) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CrdtError::SystemClock(format!("clock before Unix epoch: {e}")))?
            .as_millis() as u64;

        let current = self.current_state();
        if current.is_done() {
            return Err(CrdtError::InvalidStateTransition {
                current,
                attempted: CheckboxState::Claimed {
                    agent_id,
                    timestamp,
                },
            });
        }

        let att = sign_attestation(
            signing,
            OpKind::Claim,
            &scope,
            &self.id,
            &agent_id,
            timestamp,
        )?;

        let claimed_state = CheckboxState::Claimed {
            agent_id,
            timestamp,
        };
        let tag = (peer_id, seq);
        self.checkbox
            .add(claimed_state.clone(), tag)
            .map_err(|e| CrdtError::Merge(format!("Failed to add claimed state: {}", e)))?;
        self.attestations.insert(claimed_state, att);

        self.assignee.set(Some(agent_id), peer_id);

        Ok(())
    }

    /// Complete this task.
    ///
    /// Adds a Done state to the OR-Set. If multiple agents complete concurrently,
    /// the earliest completion wins.
    ///
    /// Also sets the `assignee` LWW register to the completing agent
    /// (mirroring [`TaskItem::claim`]). The authoritative completer is
    /// [`TaskItem::completion_record`], derived from the OR-Set.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent completing this task
    /// * `peer_id` - The peer making this change (for vector clocks)
    /// * `seq` - Sequence number for this operation
    ///
    /// # Returns
    ///
    /// Ok(()) if completed successfully, or an error if invalid transition.
    ///
    /// # Errors
    ///
    /// Returns `CrdtError::InvalidStateTransition` if the task is Empty
    /// (must be claimed first) or already Done.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut task = TaskItem::new(id, metadata, peer_id);
    /// task.claim(list_id, agent_id, peer_id, 1)?;
    /// task.complete(list_id, agent_id, peer_id, 2)?;
    /// assert!(task.current_state().is_done());
    /// ```
    pub fn complete(
        &mut self,
        scope: TaskListId,
        agent_id: AgentId,
        peer_id: PeerId,
        seq: u64,
        signing: &SigningContext,
    ) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CrdtError::SystemClock(format!("clock before Unix epoch: {e}")))?
            .as_millis() as u64;

        let current = self.current_state();

        if current.is_empty() {
            return Err(CrdtError::InvalidStateTransition {
                current,
                attempted: CheckboxState::Done {
                    agent_id,
                    timestamp,
                },
            });
        }

        if current.is_done() {
            return Err(CrdtError::InvalidStateTransition {
                current,
                attempted: CheckboxState::Done {
                    agent_id,
                    timestamp,
                },
            });
        }

        let att = sign_attestation(
            signing,
            OpKind::Complete,
            &scope,
            &self.id,
            &agent_id,
            timestamp,
        )?;

        let done_state = CheckboxState::Done {
            agent_id,
            timestamp,
        };
        let tag = (peer_id, seq);
        self.checkbox
            .add(done_state.clone(), tag)
            .map_err(|e| CrdtError::Merge(format!("Failed to add done state: {}", e)))?;
        self.attestations.insert(done_state, att);

        self.assignee.set(Some(agent_id), peer_id);

        Ok(())
    }

    /// Update the task title.
    ///
    /// Uses LWW semantics - the update with the highest vector clock wins.
    ///
    /// # Arguments
    ///
    /// * `title` - New title
    /// * `peer_id` - The peer making this change
    pub fn update_title(&mut self, title: String, peer_id: PeerId) {
        self.title.set(title, peer_id);
    }

    /// Update the task description.
    ///
    /// Uses LWW semantics - the update with the highest vector clock wins.
    ///
    /// # Arguments
    ///
    /// * `description` - New description
    /// * `peer_id` - The peer making this change
    pub fn update_description(&mut self, description: String, peer_id: PeerId) {
        self.description.set(description, peer_id);
    }

    /// Update the task assignee.
    ///
    /// Uses LWW semantics - the update with the highest vector clock wins.
    ///
    /// # Arguments
    ///
    /// * `assignee` - New assignee (None to unassign)
    /// * `peer_id` - The peer making this change
    pub fn update_assignee(&mut self, assignee: Option<AgentId>, peer_id: PeerId) {
        self.assignee.set(assignee, peer_id);
    }

    /// Update the task priority.
    ///
    /// Uses LWW semantics - the update with the highest vector clock wins.
    ///
    /// # Arguments
    ///
    /// * `priority` - New priority (0-255)
    /// * `peer_id` - The peer making this change
    pub fn update_priority(&mut self, priority: u8, peer_id: PeerId) {
        self.priority.set(priority, peer_id);
    }

    /// Get the current checkbox state.
    ///
    /// Resolves the OR-Set to a single state by taking the maximum
    /// (most progressed state wins: Done > Claimed > Empty).
    ///
    /// # Returns
    ///
    /// - `Empty` if the OR-Set is empty
    /// - `Done` if any Done state exists (task completed)
    /// - `Claimed` if any Claimed state exists (task in progress)
    ///
    /// When multiple states of the same variant exist, the earliest
    /// timestamp wins.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut task = TaskItem::new(id, metadata, peer_id);
    /// assert!(task.current_state().is_empty());
    ///
    /// task.claim(list_id, agent_id, peer_id, 1)?;
    ///
    /// assert!(task.current_state().is_claimed());
    ///
    /// task.complete(list_id, agent_id, peer_id, 2)?;
    /// assert!(task.current_state().is_done());
    /// ```
    #[must_use]
    pub fn current_state(&self) -> CheckboxState {
        // Resolve from the attestation map, not the OR-Set: forged tombstones can
        // hide elements from the OR-Set but cannot censor them here.
        let states: Vec<&CheckboxState> = self.attestations.keys().collect();

        if states.is_empty() {
            return CheckboxState::Empty;
        }

        let done_states: Vec<_> = states.iter().copied().filter(|s| s.is_done()).collect();
        if !done_states.is_empty() {
            return done_states
                .into_iter()
                .min()
                .cloned()
                .unwrap_or(CheckboxState::Empty);
        }

        let claimed_states: Vec<_> = states.iter().copied().filter(|s| s.is_claimed()).collect();
        if !claimed_states.is_empty() {
            return claimed_states
                .into_iter()
                .min()
                .cloned()
                .unwrap_or(CheckboxState::Empty);
        }

        CheckboxState::Empty
    }

    /// The winning claim record, if this task has ever been claimed.
    ///
    /// Resolves the OR-Set's `Claimed` entries to a single deterministic
    /// winner (earliest timestamp, `CheckboxState` ordering as tiebreaker) —
    /// the same resolution [`TaskItem::current_state`] uses. Unlike
    /// `current_state`, the claim record remains available after the task
    /// transitions to Done.
    pub fn claim_record(&self) -> Option<(AgentId, u64)> {
        self.attestations
            .keys()
            .filter(|s| s.is_claimed())
            .min()
            .and_then(|s| match s {
                CheckboxState::Claimed {
                    agent_id,
                    timestamp,
                } => Some((*agent_id, *timestamp)),
                _ => None,
            })
    }

    /// All recorded claim candidates (every `Claimed` OR-Set element).
    ///
    /// Claims are **additive**: every successful local claim appends a distinct
    /// candidate here, regardless of who the deterministic winner is. This
    /// makes the non-exclusive nature of claims observable — a task may carry
    /// many coexisting claimants. Use [`TaskItem::claim_record`] for the
    /// single deterministic winner.
    ///
    /// # Returns
    ///
    /// A `Vec` of `(agent_id, unix_ms_timestamp)` for every observed claim
    /// candidate. Order is unspecified.
    #[must_use]
    pub fn claims(&self) -> Vec<(AgentId, u64)> {
        self.attestations
            .keys()
            .filter_map(|s| match s {
                CheckboxState::Claimed {
                    agent_id,
                    timestamp,
                } => Some((*agent_id, *timestamp)),
                _ => None,
            })
            .collect()
    }

    /// The winning completion record, if this task has been completed.
    ///
    /// Resolves the OR-Set's `Done` entries to a single deterministic winner
    /// (earliest timestamp, `CheckboxState` ordering as tiebreaker).
    ///
    /// # Returns
    ///
    /// `Some((agent_id, timestamp_ms))` for the winning completion, or `None`
    /// if the task is not done.
    #[must_use]
    pub fn completion_record(&self) -> Option<(AgentId, u64)> {
        self.attestations
            .keys()
            .filter(|s| s.is_done())
            .min()
            .and_then(|s| match s {
                CheckboxState::Done {
                    agent_id,
                    timestamp,
                } => Some((*agent_id, *timestamp)),
                _ => None,
            })
    }

    /// Feeds the resolved observable fields into `h` in a canonical
    /// length-delimited encoding, so replicas with identical resolved state hash
    /// identically even when their raw OR-Set elements differ. Deterministic
    /// across platforms and builds: no `Hash` impls, no `HashMap` iteration.
    pub(crate) fn hash_resolved_fields(&self, h: &mut blake3::Hasher) {
        fn lp(h: &mut blake3::Hasher, data: &[u8]) {
            h.update(&(data.len() as u64).to_le_bytes());
            h.update(data);
        }
        fn record(h: &mut blake3::Hasher, rec: Option<(&crate::identity::AgentId, u64)>) {
            match rec {
                Some((agent, ts)) => {
                    h.update(&[1u8]);
                    h.update(agent.as_bytes());
                    h.update(&ts.to_le_bytes());
                }
                None => {
                    h.update(&[0u8]);
                }
            }
        }
        lp(h, self.title().as_bytes());
        lp(h, self.description().as_bytes());
        h.update(&[self.priority()]);
        match self.current_state() {
            CheckboxState::Empty => {
                h.update(&[0u8]);
            }
            CheckboxState::Claimed {
                agent_id,
                timestamp,
            } => {
                h.update(&[1u8]);
                h.update(agent_id.as_bytes());
                h.update(&timestamp.to_le_bytes());
            }
            CheckboxState::Done {
                agent_id,
                timestamp,
            } => {
                h.update(&[2u8]);
                h.update(agent_id.as_bytes());
                h.update(&timestamp.to_le_bytes());
            }
        };
        let claim = self.claim_record();
        record(h, claim.as_ref().map(|(a, t)| (a, *t)));
        let done = self.completion_record();
        record(h, done.as_ref().map(|(a, t)| (a, *t)));
        match self.assignee() {
            Some(agent) => {
                h.update(&[1u8]);
                h.update(agent.as_bytes());
            }
            None => {
                h.update(&[0u8]);
            }
        }
    }

    /// Merge another TaskItem into this one.
    ///
    /// Combines the OR-Sets and LWW-Registers according to their
    /// respective CRDT semantics.
    ///
    /// # Arguments
    ///
    /// * `other` - The TaskItem to merge from
    ///
    /// # Returns
    ///
    /// Ok(()) if merge succeeded, or an error if the task IDs don't match.
    ///
    /// # Errors
    ///
    /// Returns `CrdtError::Merge` if the task IDs differ (can't merge different tasks).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut task1 = TaskItem::new(id, metadata, peer1);
    /// let mut task2 = TaskItem::new(id, metadata, peer2);
    ///
    /// task1.claim(list_id, agent1, peer1, 1)?;
    /// task2.update_title("New title".to_string(), peer2);
    ///
    /// task1.merge(list_id, &task2)?;
    /// // task1 now has both the claim and the title update
    /// ```
    pub fn merge(&mut self, scope: TaskListId, other: &TaskItem) -> Result<()> {
        if self.id != other.id {
            return Err(CrdtError::Merge(format!(
                "Cannot merge tasks with different IDs: {} != {}",
                self.id, other.id
            )));
        }

        self.checkbox
            .merge_state(&other.checkbox)
            .map_err(|e| CrdtError::Merge(format!("Failed to merge checkbox states: {}", e)))?;

        for (state, att) in &other.attestations {
            self.attestations
                .entry(state.clone())
                .or_insert_with(|| att.clone());
        }

        self.title.merge(&other.title);
        self.description.merge(&other.description);
        self.assignee.merge(&other.assignee);
        self.priority.merge(&other.priority);

        // The provenance admission gate runs last, so resolution only ever sees
        // authenticated elements.
        let dropped =
            purge_unattested_elements(&scope, &self.id, &mut self.checkbox, &mut self.attestations);
        if dropped > 0 {
            tracing::debug!(
                dropped,
                "purged unauthenticated task checkbox elements during merge"
            );
        }

        Ok(())
    }

    /// Checkbox-only merge.
    ///
    /// Unions the checkbox OR-Set and the attestation map, then runs the
    /// same provenance admission gate as [`Self::merge`] — WITHOUT merging
    /// the title/description/assignee/priority LWW registers (their clocks
    /// are never even considered). Used by the delta path when the
    /// envelope-verified writer is absent or not an authorized member:
    /// unauthenticated content fields must not land, while an attested
    /// Claimed/Done on an existing task still converges (checkbox admission
    /// is gated by `OpAttestation`, not by the envelope writer).
    ///
    /// # Errors
    ///
    /// Returns an error if the tasks have different IDs or the checkbox
    /// OR-Set merge fails.
    pub fn merge_checkbox_only(&mut self, scope: TaskListId, other: &TaskItem) -> Result<()> {
        if self.id != other.id {
            return Err(CrdtError::Merge(format!(
                "Cannot merge tasks with different IDs: {} != {}",
                self.id, other.id
            )));
        }

        self.checkbox
            .merge_state(&other.checkbox)
            .map_err(|e| CrdtError::Merge(format!("Failed to merge checkbox states: {}", e)))?;

        for (state, att) in &other.attestations {
            self.attestations
                .entry(state.clone())
                .or_insert_with(|| att.clone());
        }

        let dropped =
            purge_unattested_elements(&scope, &self.id, &mut self.checkbox, &mut self.attestations);
        if dropped > 0 {
            tracing::debug!(
                dropped,
                "purged unauthenticated task checkbox elements during checkbox-only merge"
            );
        }

        Ok(())
    }

    /// Fail-closed admission gate: purge every checkbox element and attestation
    /// entry whose attestation is missing or fails verification for `scope`.
    ///
    /// The attestation map is the **authoritative source** for checkbox
    /// resolution — read methods (`current_state`, `claim_record`, etc.)
    /// derive from `attestations.keys()`, not from the OR-Set. A forged
    /// tombstone may hide an element from the OR-Set, but the attested entry
    /// remains in the map and is still visible to resolution. No per-replica
    /// tag is synthesized; the signed `CheckboxState` is the stable op ID.
    ///
    /// This is the **single** admission routine for a `TaskItem`. It MUST be
    /// called before every first insert (when a remote task arrives as a
    /// first-seen element via merge, `merge_delta`, or cold `full_delta`) and
    /// after every merge/full-snapshot/update. [`TaskItem::merge`] calls it
    /// internally as its last step; first-seen insertion paths that bypass
    /// `merge` MUST call this explicitly.
    ///
    /// Returns the number of unauthenticated elements dropped.
    #[must_use]
    pub fn admit(&mut self, scope: TaskListId) -> usize {
        purge_unattested_elements(&scope, &self.id, &mut self.checkbox, &mut self.attestations)
    }

    /// Drop checkbox elements whose attesting agent is not in `authorized`.
    ///
    /// Applies group authorization at CRDT admission: a validly-signed
    /// operation from an agent who is not an authorized member of this list's
    /// group is rejected. This complements the REST-layer membership check —
    /// a remote peer who subscribes to the topic but is not a group member
    /// cannot inject claims/completions even with a valid signature.
    ///
    /// No-op when the element is not a Claimed/Done (Empty is never in the
    /// OR-Set). Returns the count of nonmember elements dropped.
    #[must_use]
    pub fn filter_unauthorized(&mut self, authorized: &HashSet<AgentId>) -> usize {
        // Iterate the attestation map, not the OR-Set, so tombstone-hidden
        // non-member elements are filtered too.
        let attested: Vec<CheckboxState> = self.attestations.keys().cloned().collect();
        let mut dropped = 0usize;
        for state in attested {
            let agent_id = match &state {
                CheckboxState::Claimed { agent_id, .. } | CheckboxState::Done { agent_id, .. } => {
                    *agent_id
                }
                CheckboxState::Empty => continue,
            };
            if !authorized.contains(&agent_id) {
                let _ = self.checkbox.remove(&state);
                self.attestations.remove(&state);
                dropped += 1;
            }
        }
        dropped
    }
}

/// Craft bincode bytes of a `TaskListDelta` containing an unattested
/// first-seen `TaskItem`, for security validation (release oracle / hostile
/// injector).
///
/// The returned bytes are a bincode-serialized `(PeerId, TaskListDelta)` pair
/// ready to publish on the task list's gossip topic. The receiver's admission
/// gate (`TaskItem::admit`) MUST purge the forged element, leaving
/// `current_state() == Empty`.
///
/// The forged `TaskItem` carries a `Claimed { victim, ts: 1 }` element in its
/// checkbox OR-Set with NO matching attestation — the simplest first-seen
/// bypass attack from the independent review.
///
/// # Arguments
///
/// * `victim` - The agent ID being impersonated in the forged claim
/// * `task_id` - The target task ID
/// * `spoof_peer` - The PeerId to use as the delta sender and OR-Set tag
///
/// # Errors
/// Returns [`CrdtError::Serialization`] if the delta cannot be encoded.
pub fn forge_unattested_delta_bytes(
    victim: AgentId,
    task_id: TaskId,
    spoof_peer: PeerId,
) -> Result<Vec<u8>> {
    let metadata =
        crate::crdt::TaskMetadata::new("forged".to_string(), String::new(), 0, victim, 1);
    let mut task = TaskItem::new(task_id, metadata, spoof_peer);
    let forged_state = CheckboxState::Claimed {
        agent_id: victim,
        timestamp: 1,
    };
    let _ = task.checkbox.add(forged_state, (spoof_peer, 1));

    let delta = crate::crdt::TaskListDelta::for_state_change(task_id, task, 0);
    Ok(crate::gossip::wire::encode_delta(spoof_peer, &delta)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    fn signing_for(_n: u8) -> (AgentId, crate::gossip::SigningContext) {
        let kp = crate::identity::AgentKeypair::generate().expect("agent keygen");
        (
            kp.agent_id(),
            crate::gossip::SigningContext::from_keypair(&kp),
        )
    }

    fn make_task(peer: PeerId) -> TaskItem {
        let agent = agent(1);
        let task_id = TaskId::new("Test task", &agent, 1000);
        let metadata = TaskMetadata::new("Test", "Description", 128, agent, 1000);
        TaskItem::new(task_id, metadata, peer)
    }

    fn item_scope() -> crate::crdt::TaskListId {
        crate::crdt::TaskListId::new([0x5c; 32])
    }

    #[test]
    fn test_task_item_new() {
        let peer = peer(1);
        let agent = agent(1);
        let task_id = TaskId::new("Task", &agent, 1000);
        let metadata = TaskMetadata::new("Title", "Desc", 200, agent, 1234567890);

        let task = TaskItem::new(task_id, metadata.clone(), peer);

        assert_eq!(task.id(), &task_id);
        assert_eq!(task.title(), "Title");
        assert_eq!(task.description(), "Desc");
        assert_eq!(task.priority(), 200);
        assert_eq!(task.created_by(), &agent);
        assert_eq!(task.created_at(), 1234567890);
        assert_eq!(task.assignee(), None);
        assert!(task.current_state().is_empty());
    }

    #[test]
    fn test_claim_from_empty() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let mut task = make_task(peer);

        let result = task.claim(item_scope(), agent, peer, 1, &signing);
        assert!(result.is_ok());
        assert!(task.current_state().is_claimed());
        assert_eq!(task.current_state().claimed_by(), Some(&agent));
    }

    #[test]
    fn test_cannot_claim_done_task() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let mut task = make_task(peer);

        task.claim(item_scope(), agent, peer, 1, &signing)
            .ok()
            .unwrap();
        task.complete(item_scope(), agent, peer, 2, &signing)
            .ok()
            .unwrap();

        let result = task.claim(item_scope(), agent, peer, 3, &signing);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::InvalidStateTransition { .. } => {}
            _ => panic!("Expected InvalidStateTransition"),
        }
    }

    #[test]
    fn test_complete_from_claimed() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let mut task = make_task(peer);

        task.claim(item_scope(), agent, peer, 1, &signing)
            .ok()
            .unwrap();
        let result = task.complete(item_scope(), agent, peer, 2, &signing);
        assert!(result.is_ok());
        assert!(task.current_state().is_done());
    }

    #[test]
    fn test_cannot_complete_empty_task() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let mut task = make_task(peer);

        let result = task.complete(item_scope(), agent, peer, 1, &signing);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::InvalidStateTransition { .. } => {}
            _ => panic!("Expected InvalidStateTransition"),
        }
    }

    #[test]
    fn test_cannot_complete_done_task() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let mut task = make_task(peer);

        task.claim(item_scope(), agent, peer, 1, &signing)
            .ok()
            .unwrap();
        task.complete(item_scope(), agent, peer, 2, &signing)
            .ok()
            .unwrap();

        let result = task.complete(item_scope(), agent, peer, 3, &signing);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::InvalidStateTransition { .. } => {}
            _ => panic!("Expected InvalidStateTransition"),
        }
    }

    #[test]
    fn test_concurrent_claims() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);

        let mut task1 = make_task(peer1);
        let mut task2 = make_task(peer1);

        task1
            .claim(item_scope(), agent1, peer1, 100, &signing1)
            .ok()
            .unwrap();
        task2
            .claim(item_scope(), agent2, peer2, 200, &signing2)
            .ok()
            .unwrap();

        task1.merge(item_scope(), &task2).ok().unwrap();

        let state = task1.current_state();
        assert!(state.is_claimed());
        assert!(state.claimed_by().is_some());
        assert!(state.timestamp().unwrap() > 1_000_000_000_000);
    }

    #[test]
    fn test_concurrent_completes() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);

        let mut task1 = make_task(peer1);
        let mut task2 = make_task(peer1);

        task1
            .claim(item_scope(), agent1, peer1, 50, &signing1)
            .ok()
            .unwrap();
        task2
            .claim(item_scope(), agent1, peer1, 50, &signing1)
            .ok()
            .unwrap();

        task1
            .complete(item_scope(), agent1, peer1, 100, &signing1)
            .ok()
            .unwrap();
        task2
            .complete(item_scope(), agent2, peer2, 200, &signing2)
            .ok()
            .unwrap();

        task1.merge(item_scope(), &task2).ok().unwrap();

        let state = task1.current_state();
        assert!(state.is_done());
        assert!(state.claimed_by().is_some());
        assert!(state.timestamp().unwrap() > 1_000_000_000_000);
    }

    #[test]
    fn test_claims_accessor_empty_then_populated() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let mut task = make_task(peer);

        assert!(task.claims().is_empty(), "no candidates before any claim");

        task.claim(item_scope(), agent, peer, 1, &signing)
            .expect("claim");
        let claims = task.claims();
        assert_eq!(claims.len(), 1, "one candidate after a single claim");
        assert_eq!(claims[0].0, agent);
        assert!(claims[0].1 > 1_000_000_000_000, "candidate carries Unix ms");
    }

    #[test]
    fn test_claim_is_advisory_claiming_already_claimed_succeeds() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);
        let mut task = make_task(peer1);

        task.claim(item_scope(), agent1, peer1, 1, &signing1)
            .expect("first claim");
        task.claim(item_scope(), agent2, peer2, 2, &signing2)
            .expect("second concurrent claim");

        assert_eq!(
            task.claims().len(),
            2,
            "both candidates coexist (advisory, non-exclusive)"
        );
    }

    #[test]
    fn test_concurrent_same_version_claims_coexist_with_single_winner() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);

        let mut replica_a = make_task(peer1);
        let mut replica_b = make_task(peer1);

        replica_a
            .claim(item_scope(), agent1, peer1, 10, &signing1)
            .expect("replica A claims");
        replica_b
            .claim(item_scope(), agent2, peer2, 20, &signing2)
            .expect("replica B claims");
        assert_eq!(replica_a.claims().len(), 1);
        assert_eq!(replica_b.claims().len(), 1);

        replica_a.merge(item_scope(), &replica_b).expect("merge");

        let merged_claims = replica_a.claims();
        assert_eq!(
            merged_claims.len(),
            2,
            "both candidates survive merge: {merged_claims:?}"
        );

        let winner = replica_a
            .claim_record()
            .expect("deterministic winner exists post-merge");
        let min_ts = merged_claims.iter().map(|(_, t)| *t).min().unwrap();
        assert_eq!(winner.1, min_ts, "winner has the earliest timestamp");
        let agents: Vec<_> = merged_claims.iter().map(|(a, _)| *a).collect();
        assert!(
            agents.contains(&winner.0),
            "winner must be one of the recorded candidates: {winner:?}"
        );
        assert!(replica_a.current_state().is_claimed());

        replica_b
            .merge(item_scope(), &replica_a)
            .expect("reverse merge");
        assert_eq!(
            replica_b.claim_record(),
            Some(winner),
            "both replicas converge to the same deterministic winner"
        );
    }

    #[test]
    fn test_earlier_timestamp_candidate_via_merge_displaces_winner() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);

        let mut replica_a = make_task(peer1);
        replica_a
            .claim(item_scope(), agent1, peer1, 1, &signing1)
            .expect("earliest claim");
        let first_winner = replica_a.claim_record().expect("winner after first claim");

        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut replica_b = make_task(peer1);
        replica_b
            .claim(item_scope(), agent2, peer2, 2, &signing2)
            .expect("later claim");

        replica_a
            .merge(item_scope(), &replica_b)
            .expect("merge later claim");
        let resolved = replica_a.claim_record().expect("winner after merge");
        assert_eq!(
            resolved, first_winner,
            "earlier-ts winner is stable against a later (greater-ts) candidate"
        );
        assert_eq!(replica_a.claims().len(), 2);
    }

    #[test]
    fn test_update_title() {
        let peer = peer(1);
        let mut task = make_task(peer);

        assert_eq!(task.title(), "Test");

        task.update_title("New Title".to_string(), peer);
        assert_eq!(task.title(), "New Title");
    }

    #[test]
    fn test_update_description() {
        let peer = peer(1);
        let mut task = make_task(peer);

        assert_eq!(task.description(), "Description");

        task.update_description("New Description".to_string(), peer);
        assert_eq!(task.description(), "New Description");
    }

    #[test]
    fn test_update_assignee() {
        let peer = peer(1);
        let agent = agent(42);
        let mut task = make_task(peer);

        assert_eq!(task.assignee(), None);

        task.update_assignee(Some(agent), peer);
        assert_eq!(task.assignee(), Some(&agent));

        task.update_assignee(None, peer);
        assert_eq!(task.assignee(), None);
    }

    #[test]
    fn test_update_priority() {
        let peer = peer(1);
        let mut task = make_task(peer);

        assert_eq!(task.priority(), 128);

        task.update_priority(255, peer);
        assert_eq!(task.priority(), 255);
    }

    #[test]
    fn test_metadata_lww_semantics() {
        let peer1 = peer(1);
        let peer2 = peer(2);

        let mut task1 = make_task(peer1);
        let mut task2 = make_task(peer1);

        task1.update_title("Title from peer1".to_string(), peer1);

        task2.update_title("Title from peer2".to_string(), peer2);

        task1.merge(item_scope(), &task2).ok().unwrap();

        assert!(
            task1.title() == "Title from peer1" || task1.title() == "Title from peer2",
            "LWW should pick one of the concurrent updates"
        );
    }

    #[test]
    fn test_merge_is_idempotent() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);

        let mut task1 = make_task(peer);
        let mut task2 = make_task(peer);

        task1
            .claim(item_scope(), agent, peer, 100, &signing)
            .ok()
            .unwrap();
        task1.update_title("Title".to_string(), peer);

        task2.merge(item_scope(), &task1).ok().unwrap();
        let state_after_first = task2.current_state();
        let title_after_first = task2.title().to_string();

        task2.merge(item_scope(), &task1).ok().unwrap();
        let state_after_second = task2.current_state();
        let title_after_second = task2.title().to_string();

        assert_eq!(state_after_first, state_after_second);
        assert_eq!(title_after_first, title_after_second);
    }

    #[test]
    fn test_merge_is_commutative() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let _agent2 = agent(2);

        let mut task_a = make_task(peer1);
        let mut task_b = make_task(peer1);

        task_a
            .claim(item_scope(), agent1, peer1, 100, &signing1)
            .ok()
            .unwrap();
        task_b.update_title("New Title".to_string(), peer2);

        let mut result1 = task_a.clone();
        result1.merge(item_scope(), &task_b).ok().unwrap();

        let mut result2 = task_b.clone();
        result2.merge(item_scope(), &task_a).ok().unwrap();

        assert_eq!(result1.current_state(), result2.current_state());
        assert_eq!(result1.title(), result2.title());
    }

    #[test]
    fn test_merge_different_task_ids_fails() {
        let peer = peer(1);
        let agent1 = agent(1);
        let agent2 = agent(2);

        let task_id1 = TaskId::new("Task 1", &agent1, 1000);
        let task_id2 = TaskId::new("Task 2", &agent2, 2000);

        let metadata1 = TaskMetadata::new("Task 1", "Desc", 128, agent1, 1000);
        let metadata2 = TaskMetadata::new("Task 2", "Desc", 128, agent2, 2000);

        let mut task1 = TaskItem::new(task_id1, metadata1, peer);
        let task2 = TaskItem::new(task_id2, metadata2, peer);

        let result = task1.merge(item_scope(), &task2);
        assert!(result.is_err());
        match result.unwrap_err() {
            CrdtError::Merge(_) => {}
            _ => panic!("Expected Merge error"),
        }
    }

    #[test]
    fn claim_populates_assignee_register() {
        let peer = peer(1);
        let (claimer, signing) = signing_for(7);
        let mut task = make_task(peer);
        assert_eq!(task.assignee(), None, "precondition: unassigned");

        task.claim(item_scope(), claimer, peer, 1, &signing)
            .ok()
            .unwrap();

        assert_eq!(
            task.assignee(),
            Some(&claimer),
            "claim must set the assignee register — clients read assignee, not Display strings"
        );
        let (by, at) = task.claim_record().expect("claim record exists");
        assert_eq!(by, claimer);
        assert!(at > 1_000_000_000_000, "claimed_at is Unix ms");
    }

    #[test]
    fn concurrent_claims_converge_to_same_winner_on_both_replicas() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);

        let mut replica_a = make_task(peer1);
        let mut replica_b = make_task(peer1);

        replica_a
            .claim(item_scope(), agent1, peer1, 100, &signing1)
            .ok()
            .unwrap();
        replica_b
            .claim(item_scope(), agent2, peer2, 200, &signing2)
            .ok()
            .unwrap();

        let a_before = replica_a.clone();
        replica_a.merge(item_scope(), &replica_b).ok().unwrap();
        replica_b.merge(item_scope(), &a_before).ok().unwrap();

        let (winner_a, ts_a) = replica_a.claim_record().expect("winner on A");
        let (winner_b, ts_b) = replica_b.claim_record().expect("winner on B");
        assert_eq!(winner_a, winner_b, "replicas disagree on claim winner");
        assert_eq!(ts_a, ts_b);

        let state = replica_a.current_state();
        assert_eq!(state.claimed_by(), Some(&winner_a));
    }

    #[test]
    fn complete_sets_completion_record_and_assignee() {
        let peer = peer(1);
        let (claimer, signing_claim) = signing_for(1);
        let (completer, signing_complete) = signing_for(2);
        let mut task = make_task(peer);

        task.claim(item_scope(), claimer, peer, 1, &signing_claim)
            .ok()
            .unwrap();
        task.complete(item_scope(), completer, peer, 2, &signing_complete)
            .ok()
            .unwrap();

        let (done_by, done_at) = task.completion_record().expect("completion record");
        assert_eq!(done_by, completer);
        assert!(done_at > 1_000_000_000_000, "completed_at is Unix ms");
        assert_eq!(
            task.assignee(),
            Some(&completer),
            "complete mirrors the completer into the assignee register"
        );
        let (claimed_by, _) = task.claim_record().expect("claim record survives Done");
        assert_eq!(claimed_by, claimer);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let peer = peer(1);
        let (agent, signing) = signing_for(42);
        let mut task = make_task(peer);

        task.claim(item_scope(), agent, peer, 100, &signing)
            .ok()
            .unwrap();
        task.update_title("Serialized Task".to_string(), peer);
        task.update_priority(200, peer);

        let serialized = bincode::serialize(&task).ok().unwrap();
        let deserialized: TaskItem = bincode::deserialize(&serialized).ok().unwrap();

        assert_eq!(task.id(), deserialized.id());
        assert_eq!(task.title(), deserialized.title());
        assert_eq!(task.priority(), deserialized.priority());
        assert_eq!(task.current_state(), deserialized.current_state());
    }

    #[test]
    fn legacy_taskitem_without_attestations_decodes() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let mut task = make_task(peer);
        task.claim(item_scope(), agent, peer, 1, &signing)
            .expect("claim");
        task.update_title("Legacy".to_string(), peer);

        #[derive(Serialize)]
        struct LegacyTaskItemV0 {
            id: TaskId,
            checkbox: OrSet<CheckboxState>,
            title: LwwRegister<String>,
            description: LwwRegister<String>,
            assignee: LwwRegister<Option<AgentId>>,
            priority: LwwRegister<u8>,
            created_by: AgentId,
            created_at: u64,
        }
        let legacy = LegacyTaskItemV0 {
            id: task.id,
            checkbox: task.checkbox.clone(),
            title: task.title.clone(),
            description: task.description.clone(),
            assignee: task.assignee.clone(),
            priority: task.priority.clone(),
            created_by: task.created_by,
            created_at: task.created_at,
        };

        let bytes = bincode::serialize(&legacy).expect("serialize legacy shape");
        let restored: TaskItem = bincode::deserialize(&bytes)
            .expect("legacy TaskItem (no attestations bytes) must decode");

        assert!(
            restored.attestations.is_empty(),
            "absent trailing field decodes to an empty attestation map"
        );
        assert_eq!(restored.id(), task.id());
        assert_eq!(restored.title(), "Legacy");
        assert_eq!(restored.description(), task.description());
        assert_eq!(restored.priority(), task.priority());
        assert_eq!(restored.created_by(), task.created_by());
        assert_eq!(restored.created_at(), task.created_at());
        assert!(
            restored.current_state().is_empty(),
            "no attestation ⇒ fail-closed Empty even though the OR-Set carries a claim element"
        );
    }

    #[test]
    fn taskitem_roundtrip_preserves_populated_attestations() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let mut task = make_task(peer);
        task.claim(item_scope(), agent, peer, 1, &signing)
            .expect("claim");
        task.complete(item_scope(), agent, peer, 2, &signing)
            .expect("complete");
        task.update_title("Roundtrip".to_string(), peer);
        assert!(
            !task.attestations.is_empty(),
            "precondition: a claim + complete populate the attestation map"
        );

        let bytes = bincode::serialize(&task).expect("serialize");
        let restored: TaskItem = bincode::deserialize(&bytes).expect("deserialize");

        assert_eq!(
            restored.attestations, task.attestations,
            "populated attestation map survives the round-trip"
        );
        assert_eq!(restored.id(), task.id());
        assert_eq!(restored.title(), task.title());
        assert_eq!(restored.current_state(), task.current_state());
        assert!(
            restored.current_state().is_done(),
            "attested Done state resolves after round-trip"
        );
    }

    #[test]
    fn merge_drops_unattested_claim_element_before_resolution() {
        let (agent_a, signing_a) = signing_for(1);
        let peer = peer(1);
        let mut legit = make_task(peer);
        legit
            .claim(item_scope(), agent_a, peer, 1, &signing_a)
            .expect("legit claim");
        let legit_ts = legit.claim_record().expect("winner exists").1;
        assert!(legit_ts > 1_000_000_000_000, "legit claim carries Unix-ms");

        let mut rogue = make_task(peer);
        let forged = CheckboxState::Claimed {
            agent_id: agent_a,
            timestamp: 1,
        };
        rogue
            .checkbox
            .add(forged.clone(), (peer, 999))
            .expect("add forged element");

        legit.merge(item_scope(), &rogue).expect("merge");

        assert_eq!(
            legit.claims().len(),
            1,
            "forged unattested element purged on merge"
        );
        let winner = legit.claim_record().expect("attested winner survives");
        assert_eq!(winner.0, agent_a);
        assert_eq!(
            winner.1, legit_ts,
            "resolution uses the attested claim, not the forged ts=1 element"
        );
    }

    #[test]
    fn merge_drops_claim_whose_attestation_was_signed_by_an_attacker() {
        let (victim, victim_signing) = signing_for(1);
        let (_attacker, attacker_signing) = signing_for(2);
        let peer = peer(1);

        let mut legit = make_task(peer);
        legit
            .claim(item_scope(), victim, peer, 1, &victim_signing)
            .expect("victim claim");
        let legit_winner = legit.claim_record().expect("winner");

        let mut rogue = make_task(peer);
        let forged_state = CheckboxState::Claimed {
            agent_id: victim,
            timestamp: 1,
        };
        rogue
            .checkbox
            .add(forged_state.clone(), (peer, 7))
            .expect("add");
        let msg =
            crate::crdt::canonical_op_bytes(OpKind::Claim, &item_scope(), legit.id(), &victim, 1);
        let sig = attacker_signing.sign(&msg).expect("attacker sign");
        rogue.attestations.insert(
            forged_state,
            OpAttestation {
                author_agent_id: victim,
                author_public_key: attacker_signing.public_key_bytes.clone(),
                signature: sig,
            },
        );

        legit.merge(item_scope(), &rogue).expect("merge");

        assert_eq!(
            legit.claims().len(),
            1,
            "attacker-attested impersonation element purged on merge"
        );
        assert_eq!(
            legit.claim_record().expect("winner"),
            legit_winner,
            "victim's attested claim wins; impersonation rejected"
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum BadAttestation {
        Missing,
        MalformedKey,
        AttackerKey,
        WrongAgent,
    }

    fn task_with_forged_claim(
        task_id: TaskId,
        victim: AgentId,
        ts: u64,
        mode: BadAttestation,
    ) -> TaskItem {
        let scope = crate::crdt::TaskListId::new([1u8; 32]);
        let p = peer(1);
        let metadata = TaskMetadata::new("forged", "d", 1, victim, 0);
        let mut task = TaskItem::new(task_id, metadata, p);
        let elem = CheckboxState::Claimed {
            agent_id: victim,
            timestamp: ts,
        };
        task.checkbox
            .add(elem.clone(), (p, 9001))
            .expect("add forged element");
        match mode {
            BadAttestation::Missing => {
                // No attestation entry at all — the unattested injection shape.
            }
            BadAttestation::MalformedKey => {
                task.attestations.insert(
                    elem,
                    OpAttestation {
                        author_agent_id: victim,
                        author_public_key: vec![0u8; 5],
                        signature: vec![0u8; 16],
                    },
                );
            }
            BadAttestation::AttackerKey => {
                let (_, atk_signing) = signing_for(8);
                let msg =
                    crate::crdt::canonical_op_bytes(OpKind::Claim, &scope, &task_id, &victim, ts);
                let sig = atk_signing.sign(&msg).expect("attacker sign");
                task.attestations.insert(
                    elem,
                    OpAttestation {
                        author_agent_id: victim,
                        author_public_key: atk_signing.public_key_bytes.clone(),
                        signature: sig,
                    },
                );
            }
            BadAttestation::WrongAgent => {
                let (other, other_signing) = signing_for(9);
                let att = crate::crdt::sign_attestation(
                    &other_signing,
                    OpKind::Claim,
                    &scope,
                    &task_id,
                    &other,
                    ts,
                )
                .expect("self-sign as other");
                task.attestations.insert(elem, att);
            }
        }
        task
    }

    #[test]
    fn first_seen_unattested_claim_via_full_list_merge_is_purged() {
        let id = crate::crdt::TaskListId::new([1u8; 32]);
        let task_id = TaskId::from_bytes([7u8; 32]);
        let victim = agent(9);

        let mut hostile = crate::crdt::TaskList::new(id, "L".to_string(), peer(1));
        let forged = task_with_forged_claim(task_id, victim, 1, BadAttestation::Missing);
        hostile.add_task(forged, peer(1), 1).unwrap();

        let mut receiver = crate::crdt::TaskList::new(id, "L".to_string(), peer(2));
        receiver.merge(&hostile).unwrap();

        let t = receiver.get_task(&task_id).expect("task admitted");
        assert!(
            t.current_state().is_empty(),
            "forged first-seen claim purged"
        );
        assert!(
            t.claim_record().is_none(),
            "no claim_record for a purged element"
        );
        assert!(t.claims().is_empty(), "no surviving claim candidates");
    }

    #[test]
    fn first_seen_unattested_claim_via_added_tasks_delta_is_purged() {
        let id = crate::crdt::TaskListId::new([1u8; 32]);
        let task_id = TaskId::from_bytes([7u8; 32]);
        let victim = agent(9);

        let forged = task_with_forged_claim(task_id, victim, 1, BadAttestation::Missing);
        let mut delta = crate::crdt::TaskListDelta::new(1);
        delta.added_tasks.insert(task_id, (forged, (peer(1), 1)));

        let mut receiver = crate::crdt::TaskList::new(id, "L".to_string(), peer(2));
        receiver
            .merge_delta(&delta, peer(1), Some(&agent(1)))
            .unwrap();

        let t = receiver.get_task(&task_id).expect("task admitted");
        assert!(
            t.current_state().is_empty(),
            "added-tasks forged claim purged"
        );
        assert!(t.claim_record().is_none());
    }

    #[test]
    fn first_seen_unattested_claim_via_out_of_order_update_is_purged() {
        let id = crate::crdt::TaskListId::new([1u8; 32]);
        let task_id = TaskId::from_bytes([7u8; 32]);
        let victim = agent(9);

        let forged = task_with_forged_claim(task_id, victim, 1, BadAttestation::Missing);
        let mut delta = crate::crdt::TaskListDelta::new(1);
        delta.task_updates.insert(task_id, forged);

        let mut receiver = crate::crdt::TaskList::new(id, "L".to_string(), peer(2));
        receiver
            .merge_delta(&delta, peer(3), Some(&agent(1)))
            .unwrap();

        let t = receiver
            .get_task(&task_id)
            .expect("task admitted via upsert");
        assert!(
            t.current_state().is_empty(),
            "out-of-order forged claim purged"
        );
        assert!(t.claim_record().is_none());
    }

    #[test]
    fn first_seen_unattested_claim_via_cold_full_delta_is_purged() {
        let id = crate::crdt::TaskListId::new([1u8; 32]);
        let task_id = TaskId::from_bytes([7u8; 32]);
        let victim = agent(9);

        let mut holder = crate::crdt::TaskList::new(id, "L".to_string(), peer(1));
        let forged = task_with_forged_claim(task_id, victim, 1, BadAttestation::Missing);
        holder.add_task(forged, peer(1), 1).unwrap();
        let snapshot = holder.full_delta();

        let mut joiner = crate::crdt::TaskList::new(id, String::new(), peer(2));
        joiner
            .merge_delta(&snapshot, peer(1), Some(&agent(1)))
            .unwrap();

        let t = joiner.get_task(&task_id).expect("task transferred");
        assert!(
            t.current_state().is_empty(),
            "cold-start forged claim purged"
        );
        assert!(t.claim_record().is_none());
    }

    #[test]
    fn first_seen_admission_drops_every_bad_attestation_mode() {
        let id = crate::crdt::TaskListId::new([1u8; 32]);
        let task_id = TaskId::from_bytes([7u8; 32]);
        let victim = agent(9);

        let modes = [
            BadAttestation::Missing,
            BadAttestation::MalformedKey,
            BadAttestation::AttackerKey,
            BadAttestation::WrongAgent,
        ];
        for mode in modes {
            let forged = task_with_forged_claim(task_id, victim, 1, mode);
            let mut delta = crate::crdt::TaskListDelta::new(1);
            delta.added_tasks.insert(task_id, (forged, (peer(1), 1)));

            let mut receiver = crate::crdt::TaskList::new(id, "L".to_string(), peer(2));
            receiver
                .merge_delta(&delta, peer(1), Some(&agent(1)))
                .unwrap();

            let t = receiver
                .get_task(&task_id)
                .expect("task admitted (purge-keeps-task semantics)");
            assert!(
                t.current_state().is_empty(),
                "{mode:?}: forged claim must be purged, got {:?}",
                t.current_state()
            );
            assert!(t.claim_record().is_none(), "{mode:?}: no claim_record");
            assert!(t.claims().is_empty(), "{mode:?}: no surviving candidates");
        }
    }

    #[test]
    fn validly_attested_first_seen_claim_converges_via_delta() {
        let id = crate::crdt::TaskListId::new([1u8; 32]);
        let p = peer(1);
        let (claimer, signing) = signing_for(5);

        let task_id = TaskId::from_bytes([7u8; 32]);
        let metadata = TaskMetadata::new("real", "d", 1, claimer, 0);
        let mut task = TaskItem::new(task_id, metadata, p);
        task.claim(id, claimer, p, 1, &signing)
            .expect("legit claim");
        let claimed_ts = task.claim_record().expect("claim recorded").1;

        let mut delta = crate::crdt::TaskListDelta::new(1);
        delta.added_tasks.insert(task_id, (task, (p, 1)));

        let mut receiver = crate::crdt::TaskList::new(id, "L".to_string(), peer(2));
        receiver.merge_delta(&delta, p, Some(&agent(1))).unwrap();

        let t = receiver.get_task(&task_id).expect("valid task admitted");
        assert!(
            t.current_state().is_claimed(),
            "valid first-seen claim resolves"
        );
        let (by, ts) = t.claim_record().expect("claim_record present");
        assert_eq!(by, claimer, "valid claimant is the winner");
        assert_eq!(ts, claimed_ts, "claim timestamp preserved across admission");
    }

    #[test]
    fn forged_tombstone_does_not_censor_an_attested_claim() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);

        let mut task = make_task(peer);
        task.claim(item_scope(), agent, peer, 1, &signing)
            .expect("legit claim");
        let claim = task.claim_record().expect("claim recorded before attack");

        let claimed_state = CheckboxState::Claimed {
            agent_id: claim.0,
            timestamp: claim.1,
        };
        let _ = task.checkbox.remove(&claimed_state);

        let _dropped = task.admit(item_scope());

        assert_eq!(
            task.claim_record(),
            Some(claim),
            "an attested claim survives a forged tombstone"
        );
        assert!(
            task.current_state().is_claimed(),
            "current_state still reflects the attested claim after a forged tombstone"
        );
    }

    #[test]
    fn valid_signature_nonmember_is_dropped_by_filter_unauthorized() {
        let peer = peer(1);
        let (member, member_signing) = signing_for(1);
        let (outsider, outsider_signing) = signing_for(2);

        let mut task_m = make_task(peer);
        task_m
            .claim(item_scope(), member, peer, 1, &member_signing)
            .expect("member claim");
        let mut task_o = make_task(peer);
        task_o
            .claim(item_scope(), outsider, peer, 1, &outsider_signing)
            .expect("outsider claim");

        let mut authorized = HashSet::<AgentId>::new();
        authorized.insert(member);

        let dropped_m = task_m.filter_unauthorized(&authorized);
        assert_eq!(dropped_m, 0, "member's valid claim is authorized");
        assert!(task_m.claim_record().is_some(), "member claim survives");

        let dropped_o = task_o.filter_unauthorized(&authorized);
        assert_eq!(dropped_o, 1, "valid-signature nonmember is dropped");
        assert!(
            task_o.claim_record().is_none(),
            "outsider claim removed despite a valid signature"
        );
        assert!(
            task_o.current_state().is_empty(),
            "nonmember's claim did not survive admission"
        );
    }

    #[test]
    fn admission_converges_identically_in_both_merge_orders() {
        let peer = peer(1);
        let (agent_id, signing) = signing_for(1);
        let task_id = TaskId::from_bytes([7u8; 32]);

        let metadata = TaskMetadata::new("t", "d", 1, agent_id, 0);
        let mut honest = TaskItem::new(task_id, metadata, peer);
        honest
            .claim(item_scope(), agent_id, peer, 1, &signing)
            .expect("honest claim");
        let honest_winner = honest.claim_record().expect("winner");

        let hostile = task_with_forged_claim(task_id, agent(9), 1, BadAttestation::Missing);

        let mut order1 = honest.clone();
        order1
            .merge(item_scope(), &hostile)
            .expect("merge hostile into honest");
        let mut order2 = hostile.clone();
        order2
            .merge(item_scope(), &honest)
            .expect("merge honest into hostile");

        assert_eq!(
            order1.claim_record(),
            Some(honest_winner),
            "order1 keeps the attested winner"
        );
        assert_eq!(
            order2.claim_record(),
            Some(honest_winner),
            "order2 keeps the attested winner"
        );
        assert_eq!(order1.claims().len(), 1, "forged element purged in order1");
        assert_eq!(order2.claims().len(), 1, "forged element purged in order2");
    }
}
