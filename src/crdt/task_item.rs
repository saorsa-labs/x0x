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
    chain_head, key_owner_chain, purge_unattested_elements, purge_unverified_owner_transfers,
    resolve_owner, sign_attestation, sign_owner_transfer, CheckboxState, CrdtError, OpAttestation,
    OpKind, OwnerTransfer, Result, TaskId, TaskListId, TaskMetadata,
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
    /// Unique identifier for this task.
    id: TaskId,

    /// Checkbox state using OR-Set semantics.
    ///
    /// Allows concurrent claims to coexist. The "current" state is
    /// determined by taking the minimum (earliest timestamp wins). Every
    /// `Claimed`/`Done` element here carries a matching attestation in
    /// [`TaskItem::attestations`]; the provenance admission gate
    /// ([`purge_unattested_elements`]) keeps this invariant pure by dropping
    /// any element whose attestation is missing or fails verification.
    checkbox: OrSet<CheckboxState>,

    /// Task title (LWW semantics).
    title: LwwRegister<String>,

    /// Task description (LWW semantics).
    description: LwwRegister<String>,

    /// Assigned agent (LWW semantics).
    ///
    /// None means unassigned. Some(agent_id) means assigned to that agent.
    assignee: LwwRegister<Option<AgentId>>,

    /// Task priority (LWW semantics).
    ///
    /// 0-255, where higher values = higher priority.
    priority: LwwRegister<u8>,

    /// The agent who created this task (immutable).
    created_by: AgentId,

    /// When this task was created (immutable, Unix milliseconds).
    created_at: u64,

    /// Per-element operation attestations, keyed by the `CheckboxState` value.
    ///
    /// Each `Claimed`/`Done` element in `checkbox` MUST have an entry here that
    /// [`crate::crdt::verify_attestation`]s against the element's
    /// `(kind, agent_id, timestamp)`. Serialized with the task so attestations
    /// survive delta replication and historical (`full_delta`) state sync.
    /// Merged as a union (same key ⇒ content-addressed identical attestation).
    ///
    /// This is the first of the **trailing** serialized fields. bincode (the
    /// wire and disk format) is positional and non-self-describing, so
    /// `#[serde(default)]` alone would not save a blob written without it —
    /// a mid-struct absence misaligns every following field. Kept trailing
    /// with a tolerant deserializer so a blob whose bytes END before this
    /// field (a pre-provenance / differently-shaped TaskItem at the tail of
    /// the stream) decodes to an empty map instead of an EOF error. An
    /// empty map resolves to `current_state() == Empty`, i.e. no attested
    /// elements — fail-closed, never fail-open. The tolerance is genuine
    /// only at stream-EOF: a fieldless TaskItem nested mid-stream inside a
    /// larger bincode value cannot be recovered positionally. New fields
    /// MUST be added after this one.
    #[serde(default, deserialize_with = "deserialize_attestations")]
    attestations: BTreeMap<CheckboxState, OpAttestation>,

    /// Per-operation ownership-transfer attestations (ADR-0040, blocker 27),
    /// keyed by the transfer operation itself.
    ///
    /// Ownership is a chain rooted at [`TaskItem::created_by`]; every entry
    /// MUST carry an [`OpAttestation`] signed by the transfer's `from`
    /// agent's own ML-DSA-65 key ([`crate::crdt::verify_owner_transfer`]).
    /// Unsigned or wrong-signer transfers are dropped at admission
    /// ([`crate::crdt::purge_unverified_owner_transfers`]) and can never
    /// influence [`TaskItem::owner`]. Claiming does NOT touch this map —
    /// a claim is an advisory candidate, not an ownership change.
    ///
    /// WIRE FORMAT (review r2): this field is NOT serialized on TaskItem.
    /// As a trailing tolerant field it only decoded at stream EOF — nested
    /// inside a `TaskListDelta`, a legacy delta's following bytes would
    /// misalign (broken legacy-delta decode). Ownership instead rides the
    /// DELTA as its own trailing EOF-tolerant map
    /// (`TaskListDelta::owner_transfers`), keeping TaskItem bytes identical
    /// to the pre-0040 shape so legacy deltas decode unchanged. In-memory
    /// merge paths union it through the admission gate as usual.
    #[serde(skip)]
    owner_chain: crate::crdt::provenance::OwnerChain,
}

/// Deserialize the trailing per-element attestation map, tolerating its
/// absence. A blob written by a struct shape lacking this field (e.g. a
/// pre-provenance TaskItem) simply ends before it; bincode would then hit EOF.
/// This mirrors the KvStoreDelta `owner_checkpoint` pattern: decode the value
/// if present, otherwise (EOF or any malformed value) yield an empty map. An
/// empty attestation map is the fail-closed default — the provenance admission
/// gate treats it as "no attested elements", so nothing is admitted on the
/// strength of missing bytes.
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
    /// * `peer_id` - The peer creating this task (for vector clocks)
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
            owner_chain: BTreeMap::new(),
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
        // Generate Unix timestamp for conflict resolution (globally comparable)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CrdtError::SystemClock(format!("clock before Unix epoch: {e}")))?
            .as_millis() as u64;

        // Check current state - can't claim if already done
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

        // Provenance: self-sign the operation so receivers can authenticate
        // the claimant. sign_attestation requires agent_id == signing.agent_id
        // (you can only claim as yourself); any mismatch is a hard error.
        let att = sign_attestation(
            signing,
            OpKind::Claim,
            &scope,
            &self.id,
            &agent_id,
            timestamp,
        )?;

        // Add the claimed state to the OR-Set with Unix timestamp for LWW
        let claimed_state = CheckboxState::Claimed {
            agent_id,
            timestamp, // Unix timestamp in milliseconds (globally comparable)
        };
        let tag = (peer_id, seq); // seq used for OR-Set uniqueness
        self.checkbox
            .add(claimed_state.clone(), tag)
            .map_err(|e| CrdtError::Merge(format!("Failed to add claimed state: {}", e)))?;
        self.attestations.insert(claimed_state, att);

        // Mirror the claim into the assignee LWW register so the assignee is
        // directly observable (same timestamp source as update_assignee: the
        // register's own vector clock keyed by peer_id).
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
        // Generate Unix timestamp for conflict resolution (globally comparable)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CrdtError::SystemClock(format!("clock before Unix epoch: {e}")))?
            .as_millis() as u64;

        // Check current state
        let current = self.current_state();

        // Can't complete if empty (must claim first) or already done
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

        // Provenance: self-sign the completion (agent_id == signing.agent_id).
        let att = sign_attestation(
            signing,
            OpKind::Complete,
            &scope,
            &self.id,
            &agent_id,
            timestamp,
        )?;

        // Add the done state to the OR-Set with Unix timestamp for LWW
        let done_state = CheckboxState::Done {
            agent_id,
            timestamp, // Unix timestamp in milliseconds (globally comparable)
        };
        let tag = (peer_id, seq); // seq used for OR-Set uniqueness
        self.checkbox
            .add(done_state.clone(), tag)
            .map_err(|e| CrdtError::Merge(format!("Failed to add done state: {}", e)))?;
        self.attestations.insert(done_state, att);

        // Mirror the completion into the assignee LWW register (see claim).
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

    /// Transfer ownership of this task to another agent (ADR-0040).
    ///
    /// The transfer is recorded as a signed [`OwnerTransfer`] operation
    /// attested by `from`'s OWN ML-DSA-65 key — the caller must hold that
    /// key (`signing.agent_id == from`), which is what makes ownership
    /// transfer cryptographic rather than a UI convention. `from` should be
    /// the current resolved owner ([`TaskItem::owner`]); a transfer signed
    /// by anyone else is inert at resolution time (see [`resolve_owner`]).
    ///
    /// Claiming does NOT transfer ownership — [`TaskItem::claim`] records an
    /// advisory candidate only. Ownership starts at `created_by` and changes
    /// exclusively through this signed chain.
    ///
    /// # Errors
    ///
    /// Returns [`CrdtError::Gossip`] if `from != signing.agent_id` (the
    /// caller tried to transfer a task they do not own) or signing fails.
    pub fn transfer_ownership(
        &mut self,
        scope: TaskListId,
        from: AgentId,
        to: AgentId,
        timestamp_ms: u64,
        signing: &SigningContext,
    ) -> Result<()> {
        // HASH CHAIN (review r4): the new edge extends the CURRENT chain
        // head — the signer commits to the exact position being superseded,
        // which is what makes backdating structurally detectable.
        let supersedes = chain_head(self.created_by, &self.owner_chain);
        let transfer = OwnerTransfer {
            from,
            to,
            timestamp_ms,
            supersedes,
        };
        let att = sign_owner_transfer(signing, &scope, &self.id, &transfer)?;
        let digest = crate::crdt::owner_transfer_digest(&scope, &self.id, &transfer);
        self.owner_chain.insert(digest, (transfer, att));
        Ok(())
    }

    /// The resolved owner of this task.
    ///
    /// Deterministic pure function of the verified transfer set: starts at
    /// `created_by` and advances along signature-valid transfers signed by
    /// each intermediate owner (see [`resolve_owner`]). Concurrent transfers
    /// by the same owner resolve to the `(timestamp, to)`-maximum, so every
    /// replica converges on the same owner without coordination.
    #[must_use]
    pub fn owner(&self) -> AgentId {
        resolve_owner(self.created_by, &self.owner_chain)
    }

    /// All recorded ownership-transfer operations (verified survivors only
    /// after admission). Order is unspecified.
    #[must_use]
    pub fn owner_transfers(&self) -> Vec<(OwnerTransfer, OpAttestation)> {
        self.owner_chain
            .values()
            .map(|(t, a)| (*t, a.clone()))
            .collect()
    }

    /// Crate-internal view of the ownership-transfer map (delta wiring:
    /// `TaskListDelta::for_add`/`for_state_change` lift it to the
    /// delta-level trailing field).
    pub(crate) fn owner_wire_map(&self) -> BTreeMap<OwnerTransfer, OpAttestation> {
        self.owner_chain.values().cloned().collect()
    }

    /// Union a remote ownership-transfer map into this task and run the
    /// ownership admission gate (delta wiring — TaskItem's wire shape
    /// carries no ownership; it rides `TaskListDelta::owner_transfers`).
    pub(crate) fn ingest_owner_transfers(
        &mut self,
        scope: TaskListId,
        transfers: &BTreeMap<OwnerTransfer, OpAttestation>,
    ) {
        let incoming = key_owner_chain(&scope, &self.id, transfers);
        for (digest, entry) in incoming {
            self.owner_chain.entry(digest).or_insert(entry);
        }
        let dropped = purge_unverified_owner_transfers(&scope, &self.id, &mut self.owner_chain);
        if dropped > 0 {
            tracing::debug!(
                dropped,
                "purged unverified owner transfers during delta apply"
            );
        }
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
        // Derive from the attestation map — the authoritative source for
        // checkbox resolution. The OR-Set is a delivery transport; forged
        // tombstones may hide elements from it but cannot censor them here.
        // After admission (purge), every entry in attestations is
        // cryptographically valid for this list's scope.
        let states: Vec<&CheckboxState> = self.attestations.keys().collect();

        if states.is_empty() {
            return CheckboxState::Empty;
        }

        // Priority: Done > Claimed > Empty
        // Within same variant, earliest timestamp wins

        // First check for any Done states
        let done_states: Vec<_> = states.iter().copied().filter(|s| s.is_done()).collect();
        if !done_states.is_empty() {
            return done_states
                .into_iter()
                .min()
                .cloned()
                .unwrap_or(CheckboxState::Empty);
        }

        // Then check for any Claimed states
        let claimed_states: Vec<_> = states.iter().copied().filter(|s| s.is_claimed()).collect();
        if !claimed_states.is_empty() {
            return claimed_states
                .into_iter()
                .min()
                .cloned()
                .unwrap_or(CheckboxState::Empty);
        }

        // Otherwise empty
        CheckboxState::Empty
    }

    /// The winning claim record, if this task has ever been claimed.
    ///
    /// Resolves the OR-Set's `Claimed` entries to a single deterministic
    /// winner (earliest timestamp, `CheckboxState` ordering as tiebreaker) —
    /// the same resolution [`TaskItem::current_state`] uses. Unlike
    /// `current_state`, the claim record remains available after the task
    /// transitions to Done.
    ///
    /// # Returns
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

    /// Feed this task's RESOLVED observable fields into `h` in a canonical
    /// length-delimited encoding (issue #240 served-state digest).
    ///
    /// Covers exactly the fields [`TaskList::state_fingerprint`] resolves —
    /// title, description, priority, current checkbox state, claim and
    /// completion winners, assignee — so two replicas with identical
    /// RESOLVED state hash identically even when their raw OR-Set element
    /// sets differ (e.g. after one of them compacted a delivery). Every
    /// variable-length field is length-prefixed (64-bit LE) so the encoding
    /// is unambiguous; options carry a 1-byte presence tag; enum variants a
    /// 1-byte discriminant. Deterministic across platforms and builds: no
    /// `Hash` impls, no HashMap iteration.
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
        // Resolved owner (ADR-0040): two replicas converge on the same
        // signed transfer chain ⇒ identical resolved owner bytes.
        h.update(&[1u8]);
        h.update(self.owner().as_bytes());
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
        // Can only merge tasks with the same ID
        if self.id != other.id {
            return Err(CrdtError::Merge(format!(
                "Cannot merge tasks with different IDs: {} != {}",
                self.id, other.id
            )));
        }

        // Merge OR-Set (checkbox states)
        self.checkbox
            .merge_state(&other.checkbox)
            .map_err(|e| CrdtError::Merge(format!("Failed to merge checkbox states: {}", e)))?;

        // Union attestations (same CheckboxState key ⇒ content-addressed
        // identical attestation, so union is idempotent).
        for (state, att) in &other.attestations {
            self.attestations
                .entry(state.clone())
                .or_insert_with(|| att.clone());
        }

        // Merge LWW-Registers (metadata)
        self.title.merge(&other.title);
        self.description.merge(&other.description);
        self.assignee.merge(&other.assignee);
        self.priority.merge(&other.priority);

        // created_by and created_at are immutable, no merge needed

        // Union ownership transfers (same OwnerTransfer key ⇒
        // content-addressed identical attestation, union is idempotent).
        for (digest, entry) in &other.owner_chain {
            self.owner_chain.entry(*digest).or_insert(entry.clone());
        }

        // Provenance admission gate (LAST step): drop every checkbox element
        // whose attestation is missing or fails verification. Keeps the OR-Set
        // invariant-pure (every element authenticated) so resolution operates
        // only over authenticated state; a forged/unattested element shipped in
        // a delta or full_delta is dropped before it can influence resolution.
        let mut dropped =
            purge_unattested_elements(&scope, &self.id, &mut self.checkbox, &mut self.attestations);
        // Ownership admission gate: drop transfers whose attestation is not a
        // valid signature by their own `from` agent (ADR-0040 blocker 27).
        // Unsigned or wrong-signer transfers shipped in a delta die here.
        dropped += purge_unverified_owner_transfers(&scope, &self.id, &mut self.owner_chain);
        if dropped > 0 {
            tracing::debug!(
                dropped,
                "purged unauthenticated checkbox/ownership elements during merge"
            );
        }

        Ok(())
    }

    /// Checkbox-only merge (issue #349, Layer A).
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
        for (digest, entry) in &other.owner_chain {
            self.owner_chain.entry(*digest).or_insert(entry.clone());
        }

        let mut dropped =
            purge_unattested_elements(&scope, &self.id, &mut self.checkbox, &mut self.attestations);
        dropped += purge_unverified_owner_transfers(&scope, &self.id, &mut self.owner_chain);
        if dropped > 0 {
            tracing::debug!(
                dropped,
                "purged unauthenticated checkbox/ownership elements during checkbox-only merge"
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
    pub fn admit(&mut self, scope: TaskListId) -> usize {
        purge_unattested_elements(&scope, &self.id, &mut self.checkbox, &mut self.attestations)
            + purge_unverified_owner_transfers(&scope, &self.id, &mut self.owner_chain)
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
        // Iterate the attestation map (authoritative source), not the OR-Set,
        // so tombstone-hidden nonmember elements are also filtered.
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
        // Ownership transfers (ADR-0040): a transfer touching a nonmember
        // (either side) is dropped, so removing a member reverts ownership to
        // the last fully-authorized holder — membership revocation auto-expires
        // authority that flowed through the removed agent.
        let nonmember: Vec<[u8; 32]> = self
            .owner_chain
            .iter()
            .filter(|(_, (t, _))| !authorized.contains(&t.from) || !authorized.contains(&t.to))
            .map(|(d, _)| *d)
            .collect();
        dropped += nonmember.len();
        for key in nonmember {
            self.owner_chain.remove(&key);
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
#[must_use]
pub fn forge_unattested_delta_bytes(
    victim: AgentId,
    task_id: TaskId,
    spoof_peer: PeerId,
) -> Vec<u8> {
    let metadata =
        crate::crdt::TaskMetadata::new("forged".to_string(), String::new(), 0, victim, 1);
    let mut task = TaskItem::new(task_id, metadata, spoof_peer);
    // Inject the forged element directly into the checkbox OR-Set without
    // an attestation — simulating a hostile publisher.
    let forged_state = CheckboxState::Claimed {
        agent_id: victim,
        timestamp: 1,
    };
    let _ = task.checkbox.add(forged_state, (spoof_peer, 1));
    // Deliberately do NOT add an attestation — this is the attack.

    let delta = crate::crdt::TaskListDelta::for_state_change(task_id, task, 0);
    crate::gossip::wire::encode_delta(spoof_peer, &delta)
        .expect("encode_delta must not fail for a well-formed delta")
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

    fn make_task(peer: PeerId) -> TaskItem {
        let agent = agent(1);
        let task_id = TaskId::new("Test task", &agent, 1000);
        let metadata = TaskMetadata::new("Test", "Description", 128, agent, 1000);
        TaskItem::new(task_id, metadata, peer)
    }

    /// Arbitrary list scope for TaskItem-level unit tests. `claim`/`complete`/
    /// `merge` now bind a `TaskListId` into the signed canonical bytes; the
    /// value is irrelevant at the item level, only that it is consistent
    /// within a test.
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

        // Claim and complete
        task.claim(item_scope(), agent, peer, 1, &signing)
            .ok()
            .unwrap();
        task.complete(item_scope(), agent, peer, 2, &signing)
            .ok()
            .unwrap();

        // Try to claim again
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

        // Try to complete again
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

        // Concurrent claims (timestamps generated internally using SystemTime)
        task1
            .claim(item_scope(), agent1, peer1, 100, &signing1)
            .ok()
            .unwrap();
        task2
            .claim(item_scope(), agent2, peer2, 200, &signing2)
            .ok()
            .unwrap();

        // Merge
        task1.merge(item_scope(), &task2).ok().unwrap();

        // One of the claims wins (deterministically based on Unix timestamp + agent_id tiebreaker)
        let state = task1.current_state();
        assert!(state.is_claimed());
        assert!(state.claimed_by().is_some());
        // Timestamp is Unix time in milliseconds (reasonable range check)
        assert!(state.timestamp().unwrap() > 1_000_000_000_000); // After year 2001
    }

    #[test]
    fn test_concurrent_completes() {
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);

        let mut task1 = make_task(peer1);
        let mut task2 = make_task(peer1);

        // Both claim (timestamps generated internally using SystemTime)
        task1
            .claim(item_scope(), agent1, peer1, 50, &signing1)
            .ok()
            .unwrap();
        task2
            .claim(item_scope(), agent1, peer1, 50, &signing1)
            .ok()
            .unwrap();

        // Concurrent completes (timestamps generated internally)
        task1
            .complete(item_scope(), agent1, peer1, 100, &signing1)
            .ok()
            .unwrap();
        task2
            .complete(item_scope(), agent2, peer2, 200, &signing2)
            .ok()
            .unwrap();

        // Merge
        task1.merge(item_scope(), &task2).ok().unwrap();

        // One of the completes wins (deterministically based on Unix timestamp + agent_id)
        let state = task1.current_state();
        assert!(state.is_done());
        assert!(state.claimed_by().is_some());
        // Timestamp is Unix time in milliseconds (reasonable range check)
        assert!(state.timestamp().unwrap() > 1_000_000_000_000); // After year 2001
    }

    // ── Honest (advisory) claim semantics ───────────────────────────────
    //
    // A claim is NOT a mutex. These tests pin the three honesty invariants
    // the claim contract depends on:
    //   1. Additivity — claiming an already-claimed task succeeds (no mutual
    //      exclusion); the only hard reject is Done.
    //   2. Coexistence — concurrent claims from different replicas both
    //      survive a merge, observable via `claims()` (>1 candidate).
    //   3. Deterministic resolution — all replicas converge to ONE winner via
    //      `claim_record()` (earliest timestamp, then lexicographic agent id).
    // Together they prove two replicas at the "same version" can never be
    // misread as a single globally-accepted exclusive claim.

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
        // No mutual exclusion: a second agent may claim a task the first
        // agent already claimed. Both candidates coexist. (Only Done rejects.)
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);
        let mut task = make_task(peer1);

        task.claim(item_scope(), agent1, peer1, 1, &signing1)
            .expect("first claim");
        // A concurrent claim by a different agent does NOT error — it records
        // a second candidate rather than excluding the second claimer.
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
        // Two replicas at the "same version" (neither knows of the other)
        // each commit a local claim. Neither is a globally-accepted exclusive
        // claim: after merge BOTH candidates are present, yet there is exactly
        // one deterministic winner observable via `claim_record()`.
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);

        let mut replica_a = make_task(peer1);
        let mut replica_b = make_task(peer1); // same task id as replica_a

        // Each replica commits a local claim, unaware of the other.
        replica_a
            .claim(item_scope(), agent1, peer1, 10, &signing1)
            .expect("replica A claims");
        replica_b
            .claim(item_scope(), agent2, peer2, 20, &signing2)
            .expect("replica B claims");
        // Before merge each replica sees only its own candidate.
        assert_eq!(replica_a.claims().len(), 1);
        assert_eq!(replica_b.claims().len(), 1);

        // Convergence.
        replica_a.merge(item_scope(), &replica_b).expect("merge");

        // After merge BOTH candidates are present — proof the two same-version
        // commits were not a single exclusive claim.
        let merged_claims = replica_a.claims();
        assert_eq!(
            merged_claims.len(),
            2,
            "both candidates survive merge: {merged_claims:?}"
        );

        // Exactly one deterministic winner, and it is the earliest-timestamp
        // candidate (independent of which agent's wall clock ran first).
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
        // current_state agrees with claim_record's winner.
        assert!(replica_a.current_state().is_claimed());

        // Convergence is symmetric: the other replica resolves identically.
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
        // Monotone re-resolution: once a candidate exists, a strictly-earlier-
        // timestamp candidate arriving via a later merge displaces the winner.
        // (The resolved winner timestamp is monotone non-increasing.) Because
        // `claim()` derives timestamps from the wall clock, we force ordering
        // by claiming in sequence: the first claim gets the earliest ts and
        // remains the winner after a later claim merges in.
        let peer1 = peer(1);
        let peer2 = peer(2);
        let (agent1, signing1) = signing_for(1);
        let (agent2, signing2) = signing_for(2);

        let mut replica_a = make_task(peer1);
        replica_a
            .claim(item_scope(), agent1, peer1, 1, &signing1)
            .expect("earliest claim");
        let first_winner = replica_a.claim_record().expect("winner after first claim");

        // A later claim on a divergent replica (wall clock has advanced, so
        // its ts is strictly greater) must NOT displace the existing winner.
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
        // Both candidates still coexist — the later claimer was recorded, not
        // excluded; it simply did not win.
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

        // task1 updates title
        task1.update_title("Title from peer1".to_string(), peer1);

        // task2 updates title later (higher vector clock)
        task2.update_title("Title from peer2".to_string(), peer2);

        // Merge - LWW should pick the later update
        task1.merge(item_scope(), &task2).ok().unwrap();

        // The exact winner depends on vector clock implementation
        // Both values are valid depending on clock ordering
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

        // Merge again (idempotent)
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

        // Make different changes
        task_a
            .claim(item_scope(), agent1, peer1, 100, &signing1)
            .ok()
            .unwrap();
        task_b.update_title("New Title".to_string(), peer2);

        // Merge A <- B
        let mut result1 = task_a.clone();
        result1.merge(item_scope(), &task_b).ok().unwrap();

        // Merge B <- A
        let mut result2 = task_b.clone();
        result2.merge(item_scope(), &task_a).ok().unwrap();

        // Both should converge to the same state
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

    // ── Structured claim/completion semantics (task-claim API fix) ─────────
    //
    // WHY: the REST API used to return bare {"ok":true} on claim and the
    // assignee register stayed None forever — ownership was only recoverable
    // by parsing the Display string "claimed:<hex>". These tests pin the
    // contract that claim/complete populate the assignee register and that
    // the OR-Set winner (claim_record) is deterministic across replicas.

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

        // Two agents claim "successfully" on their own replicas.
        replica_a
            .claim(item_scope(), agent1, peer1, 100, &signing1)
            .ok()
            .unwrap();
        replica_b
            .claim(item_scope(), agent2, peer2, 200, &signing2)
            .ok()
            .unwrap();

        // Full state exchange (order differs per replica).
        let a_before = replica_a.clone();
        replica_a.merge(item_scope(), &replica_b).ok().unwrap();
        replica_b.merge(item_scope(), &a_before).ok().unwrap();

        // Both replicas must agree on a SINGLE winner — this is the CAS-free
        // conflict signal: exactly one agent owns the task after convergence.
        let (winner_a, ts_a) = replica_a.claim_record().expect("winner on A");
        let (winner_b, ts_b) = replica_b.claim_record().expect("winner on B");
        assert_eq!(winner_a, winner_b, "replicas disagree on claim winner");
        assert_eq!(ts_a, ts_b);

        // And claimed_by derived from current_state matches that winner.
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
        // The original claim record survives the transition to Done.
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

    // ── bincode wire/disk compatibility: attestations is a TRAILING field ────
    //
    // WHY: `attestations` was originally inserted mid-struct (field #3, between
    // `checkbox` and `title`) with only `#[serde(default)]`. bincode is
    // positional and non-self-describing — `#[serde(default)]` does nothing for
    // it — so a blob written by any struct shape lacking that exact field at
    // that exact position (a pre-provenance TaskItem, or an older peer/disk
    // record) misaligns at field #3 and the WHOLE decode errors with EOF.
    // Because TaskItem is nested in TaskListDelta maps, one bad item fails the
    // entire delta and a persisted TaskList cannot load. The fix moves
    // `attestations` to the LAST serialized field with a tolerant deserializer,
    // so a blob that simply ends before it decodes to an empty map.
    //
    // This test reconstructs the EXACT pre-wave byte layout via a local
    // `LegacyTaskItemV0` (the v0.30.1 field order, no `attestations`). If the
    // field were ever moved back mid-struct, or lost its tolerant deserializer,
    // this decode fails — that is the whole point of the test.

    #[test]
    fn legacy_taskitem_without_attestations_decodes() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);
        let mut task = make_task(peer);
        // A real claim so the checkbox OR-Set and LWW registers are non-trivial.
        task.claim(item_scope(), agent, peer, 1, &signing)
            .expect("claim");
        task.update_title("Legacy".to_string(), peer);

        // Mirror the pre-provenance-wave TaskItem field layout exactly (see
        // `git show b573441:src/crdt/task_item.rs`): the 8 fields in declaration
        // order, with NO `attestations`. bincode is positional, so serializing
        // this is byte-identical to what a pre-wave node wrote for this task.
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

        // The trailing field defaults to an empty map instead of erroring.
        assert!(
            restored.attestations.is_empty(),
            "absent trailing field decodes to an empty attestation map"
        );
        // Every other field survives intact (proves alignment, not just non-error).
        assert_eq!(restored.id(), task.id());
        assert_eq!(restored.title(), "Legacy");
        assert_eq!(restored.description(), task.description());
        assert_eq!(restored.priority(), task.priority());
        assert_eq!(restored.created_by(), task.created_by());
        assert_eq!(restored.created_at(), task.created_at());
        // Resolution is fail-closed: with an empty attestation map (the
        // authoritative source), a legacy claim element in the OR-Set does NOT
        // resolve — the task reads Empty rather than admitting an unattested op.
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

        // The populated trailing map round-trips byte-for-byte.
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

    // ── Provenance admission gate: integration into TaskItem::merge ──────────
    //
    // The crypto-level gate (provenance.rs) is unit-tested in isolation.
    // These tests pin that the gate runs as the LAST step of `merge`, so a
    // forged / unattested Claimed element arriving via a remote merge is
    // dropped BEFORE it can influence resolution — the strict-cutover
    // invariant (legacy/forged unattested elements are dropped, not tolerated).

    #[test]
    fn merge_drops_unattested_claim_element_before_resolution() {
        // A legitimate, self-signed claim.
        let (agent_a, signing_a) = signing_for(1);
        let peer = peer(1);
        let mut legit = make_task(peer);
        legit
            .claim(item_scope(), agent_a, peer, 1, &signing_a)
            .expect("legit claim");
        let legit_ts = legit.claim_record().expect("winner exists").1;
        assert!(legit_ts > 1_000_000_000_000, "legit claim carries Unix-ms");

        // A rogue replica fabricates a Claimed element with timestamp 1
        // (which would WIN earliest-ts resolution if it survived) but
        // attaches NO attestation — the v0.30.1 unattested / injection shape.
        let mut rogue = make_task(peer); // identical task id
        let forged = CheckboxState::Claimed {
            agent_id: agent_a,
            timestamp: 1,
        };
        rogue
            .checkbox
            .add(forged.clone(), (peer, 999))
            .expect("add forged element");
        // Deliberately NO attestation entry for `forged`.

        // Merge rogue → legit. The gate must drop the forged element.
        legit.merge(item_scope(), &rogue).expect("merge");

        // Only the attested claim survives; the forged ts=1 element did NOT
        // steal the claim.
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
        // Impersonation via merge: the element claims `victim`, but the
        // attestation was produced by an attacker's key
        // (derived(attacker) != victim) → the gate drops it even though an
        // attestation entry EXISTS, so the forged claim cannot steal the task.
        let (victim, victim_signing) = signing_for(1);
        let (_attacker, attacker_signing) = signing_for(2);
        let peer = peer(1);

        // Legit victim claim.
        let mut legit = make_task(peer);
        legit
            .claim(item_scope(), victim, peer, 1, &victim_signing)
            .expect("victim claim");
        let legit_winner = legit.claim_record().expect("winner");

        // Rogue replica injects an impersonating element: claims `victim` at
        // ts=1 (earlier, to try to win) but attested by the attacker's key.
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

        // Merge rogue → legit: the forged (attacker-attested) element is dropped.
        legit.merge(item_scope(), &rogue).expect("merge");

        // Only the victim's legitimately-attested claim survives.
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
    // ── P0: first-seen TaskItem admission across every insertion path ──────
    //
    // WHY: `TaskItem::merge` runs the provenance gate as its last step, so a
    // forged/unattested Claimed element is dropped when it arrives via a MERGE
    // (proven above). But a FIRST-SEEN task used to bypass merge entirely:
    // full-list `TaskList::merge` cloned the unknown task in directly,
    // `merge_delta`'s `added_tasks`/`task_updates` inserted via `add_task`,
    // and a cold `full_delta` snapshot flowed through the same paths. A hostile
    // publisher could make `Claimed { victim, ts: 1 }` a receiver's first
    // observation and, under earliest-timestamp-wins resolution, steal the
    // claim. The fix routes every first-seen insertion through the same
    // fail-closed admission routine as merge.
    //
    // These tests live in THIS module (not task_list's) because forging a
    // TaskItem with a bare/unattested checkbox element requires private access
    // to `checkbox`/`attestations` — the public `claim()` always self-signs
    // correctly and cannot produce the attack shape.
    //
    // Semantics asserted (matching the existing merge-path gate): admission
    // PURGES unattested elements and keeps the task, so a forged-only
    // first-seen task lands with `current_state() == Empty`.

    #[derive(Debug, Clone, Copy)]
    enum BadAttestation {
        Missing,
        MalformedKey,
        AttackerKey,
        WrongAgent,
    }

    /// Build a TaskItem for `task_id` whose only checkbox element is
    /// `Claimed { victim, ts }`, with the attestation in the chosen mode. White-
    /// box: pokes private `checkbox`/`attestations` directly so the element is
    /// exactly what a hostile publisher ships — never produced by `claim()`.
    /// `ts` is intentionally small (1) so the forged element would WIN
    /// earliest-timestamp resolution if it survived.
    fn task_with_forged_claim(
        task_id: TaskId,
        victim: AgentId,
        ts: u64,
        mode: BadAttestation,
    ) -> TaskItem {
        // Scope under which the forged signature is produced. Every admission
        // test uses list id [1u8;32]; the scope must match the receiver's so
        // the forged signature is well-formed for that list — it then rejects
        // via the agent binding (attacker key / wrong agent), not the scope.
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
                        author_public_key: vec![0u8; 5], // not a valid ML-DSA key
                        signature: vec![0u8; 16],
                    },
                );
            }
            BadAttestation::AttackerKey => {
                // Attacker signs the victim's canonical bytes with the
                // attacker's own key, then tags the attestation as the victim.
                // derived(attacker key) != victim ⇒ rejected.
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
                // A different valid agent self-attests correctly, but the
                // element claims `victim` ⇒ author_agent_id != element agent_id.
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
        // Full-list path: a hostile replica's only task carries an unattested
        // Claimed{ts:1}. A clean receiver that merges the whole list must purge
        // the forged element — it must not become the resolved claim.
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
        // Live delta path (the actual gossip route): an added_tasks delta
        // carries a first-seen task with an unattested Claimed{ts:1}.
        let id = crate::crdt::TaskListId::new([1u8; 32]);
        let task_id = TaskId::from_bytes([7u8; 32]);
        let victim = agent(9);

        let forged = task_with_forged_claim(task_id, victim, 1, BadAttestation::Missing);
        let mut delta = crate::crdt::TaskListDelta::new(1);
        delta.added_tasks.insert(task_id, (forged, (peer(1), 1)));

        let mut receiver = crate::crdt::TaskList::new(id, "L".to_string(), peer(2));
        // Layer A (issue #349): a writer is required for the first-seen add
        // itself; the forged CLAIM inside it must still be purged.
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
        // Out-of-order delivery: a claim/complete delta arrives BEFORE the add
        // delta, so `task_updates` upserts a task the receiver has never seen.
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
        // Cold start: a holder answers a StateRequest with full_delta(). If the
        // holder's task carries a forged element, the joiner's merge_delta must
        // purge it before it can influence resolution.
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
        // The first-seen invariant must hold for EVERY way an attestation can
        // be invalid, not just "missing". None may let Claimed{ts:1} steal the
        // claim when shipped first-seen via an added_tasks delta.
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
        // Positive contract — admission must not OVER-reject. A genuinely
        // self-attested claim shipped first-seen via a delta MUST survive and
        // resolve, so valid relayed history still converges end to end. (This
        // is the teeth check for the purge tests above: the gate rejects
        // forged elements specifically, not every first-seen task.)
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

    // ── P1: forged-tombstone anti-censorship ───────────────────────────────
    //
    // WHY: a hostile participant could try to censor an authenticated claim by
    // shipping a tombstone that removes its checkbox element. Checkbox elements
    // are append-only (no legitimate removal), so any tombstone is forged. The
    // read methods treat the attestation map as authoritative, so an attested
    // claim remains observable via `claim_record()` even after the element is
    // tombstoned out of the checkbox. Admission re-establishes visibility.

    #[test]
    fn forged_tombstone_does_not_censor_an_attested_claim() {
        let peer = peer(1);
        let (agent, signing) = signing_for(1);

        let mut task = make_task(peer);
        task.claim(item_scope(), agent, peer, 1, &signing)
            .expect("legit claim");
        let claim = task.claim_record().expect("claim recorded before attack");

        // Hostile: forge a tombstone on the attested checkbox element.
        let claimed_state = CheckboxState::Claimed {
            agent_id: claim.0,
            timestamp: claim.1,
        };
        let _ = task.checkbox.remove(&claimed_state);

        // Admission runs the gate; the attested element is NOT dropped (its
        // attestation verifies for this scope) and remains observable.
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

    // ── P1: group-membership authorization at CRDT admission ──────────────
    //
    // WHY: provenance authenticates the SIGNER, not group membership. Without
    // a membership check at admission, a remote peer subscribed to a group-
    // scoped topic (but not a member) could inject validly-signed claims.
    // `filter_unauthorized` drops checkbox elements whose agent is not in the
    // authorized set — a valid-signature nonmember is rejected at the CRDT
    // layer, complementing the REST membership check.

    #[test]
    fn valid_signature_nonmember_is_dropped_by_filter_unauthorized() {
        let peer = peer(1);
        let (member, member_signing) = signing_for(1);
        let (outsider, outsider_signing) = signing_for(2);

        // Two tasks (same id), each validly claimed by a different agent.
        let mut task_m = make_task(peer);
        task_m
            .claim(item_scope(), member, peer, 1, &member_signing)
            .expect("member claim");
        let mut task_o = make_task(peer);
        task_o
            .claim(item_scope(), outsider, peer, 1, &outsider_signing)
            .expect("outsider claim");

        // Authorized set contains ONLY the member.
        let mut authorized = HashSet::<AgentId>::new();
        authorized.insert(member);

        // The member's valid claim survives; the outsider's is dropped even
        // though its signature is cryptographically valid.
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

    // ── P1: admission is order-independent (both merge orders converge) ────

    #[test]
    fn admission_converges_identically_in_both_merge_orders() {
        // A replica holding a validly-attested claim and one carrying a forged
        // unattested Claimed{ts:1} must converge to the SAME safe state
        // regardless of merge direction — only the attested claim survives in
        // both, so the gate is order-independent and valid relayed history
        // converges.
        let peer = peer(1);
        let (agent_id, signing) = signing_for(1);
        let task_id = TaskId::from_bytes([7u8; 32]);

        // honest: a real, self-attested claim under the same task id.
        let metadata = TaskMetadata::new("t", "d", 1, agent_id, 0);
        let mut honest = TaskItem::new(task_id, metadata, peer);
        honest
            .claim(item_scope(), agent_id, peer, 1, &signing)
            .expect("honest claim");
        let honest_winner = honest.claim_record().expect("winner");

        // hostile: forged unattested Claimed{ts:1} (would win earliest-ts if it
        // survived the gate).
        let hostile = task_with_forged_claim(task_id, agent(9), 1, BadAttestation::Missing);

        // Order 1: honest absorbs hostile.
        let mut order1 = honest.clone();
        order1
            .merge(item_scope(), &hostile)
            .expect("merge hostile into honest");
        // Order 2: hostile absorbs honest.
        let mut order2 = hostile.clone();
        order2
            .merge(item_scope(), &honest)
            .expect("merge honest into hostile");

        // Both directions keep exactly the attested claim; the forged element is
        // purged and never steals the claim in either order.
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

    // ── Ownership (ADR-0040, blocker 27) ────────────────────────────────────

    /// Task with a REAL creator keypair, so `created_by` has a matching
    /// signing context (ownership is rooted at the creator).
    fn owned_task(creator: &AgentId) -> TaskItem {
        let task_id = TaskId::new("owned", creator, 1000);
        let metadata = TaskMetadata::new("T", "D", 1, *creator, 1000);
        TaskItem::new(task_id, metadata, peer(1))
    }

    #[test]
    fn owner_starts_at_creator_and_claim_does_not_transfer() {
        // WHY: ADR-0040 makes claiming advisory — a claim must NOT imply
        // ownership. If a claim flipped the owner, any member could seize
        // tasks without the owner's signature.
        let (creator, _creator_signing) = signing_for(1);
        let (claimer, claimer_signing) = signing_for(2);
        let mut task = owned_task(&creator);
        assert_eq!(task.owner(), creator, "owner starts at created_by");

        task.claim(item_scope(), claimer, peer(2), 1, &claimer_signing)
            .expect("claim");
        assert_eq!(
            task.owner(),
            creator,
            "claiming does not transfer ownership"
        );
        assert_eq!(
            task.assignee(),
            Some(&claimer),
            "assignee is still advisory metadata"
        );
    }

    #[test]
    fn owner_signed_transfer_resolves() {
        // WHY: the happy path — the current owner signs, the chain advances.
        let (creator, creator_signing) = signing_for(1);
        let (bob, _) = signing_for(2);
        let mut task = owned_task(&creator);
        task.transfer_ownership(item_scope(), creator, bob, 5_000, &creator_signing)
            .expect("creator transfers");
        assert_eq!(task.owner(), bob, "signed transfer advances the chain");
    }

    #[test]
    fn transfer_by_non_owner_is_rejected_at_signing() {
        // WHY: blocker 25/27 — B must never be able to produce a transfer
        // signed as A. The API refuses to sign a transfer whose `from` is not
        // the local key holder, so no A-keyed signature ever exists from B.
        let (creator, _creator_signing) = signing_for(1);
        let (mallory, mallory_signing) = signing_for(2);
        let mut task = owned_task(&creator);
        let err = task.transfer_ownership(item_scope(), creator, mallory, 1, &mallory_signing);
        assert!(err.is_err(), "signing as another agent must hard-fail");
        assert_eq!(task.owner(), creator);
    }

    #[test]
    fn non_owner_validly_signed_transfer_is_inert() {
        // WHY: a member CAN validly sign {from: self, to: other} while not
        // being the owner. Signature-valid but chain-orphaned: it must never
        // influence resolution, or ownership could be stolen by any member.
        let (creator, _creator_signing) = signing_for(1);
        let (mallory, mallory_signing) = signing_for(2);
        let (puppet, _) = signing_for(3);
        let mut task = owned_task(&creator);
        // Mallory legitimately signs her own transfer op (from == mallory).
        task.transfer_ownership(item_scope(), mallory, puppet, 1, &mallory_signing)
            .expect("self-signed op records");
        assert_eq!(
            task.owner(),
            creator,
            "orphan transfer must not resolve: mallory is not the owner"
        );
    }

    #[test]
    fn forged_transfer_is_purged_at_admission() {
        // WHY: an attacker may craft a delta whose transfer op claims
        // from=victim but carries the attacker's key/signature. The
        // admission gate drops it before resolution — fail-closed.
        let (creator, creator_signing) = signing_for(1);
        let (mallory, mallory_signing) = signing_for(2);
        let mut honest = owned_task(&creator);
        honest
            .transfer_ownership(item_scope(), creator, mallory, 10, &creator_signing)
            .expect("creator legitimately transfers to mallory");

        let mut hostile = owned_task(&creator);
        // Mallory signs a second transfer op {from: mallory, to: mallory2}
        // but we tamper the attested author so verification fails.
        let (mallory2, _) = signing_for(3);
        hostile
            .transfer_ownership(item_scope(), mallory, mallory2, 20, &mallory_signing)
            .expect("recorded");
        // Corrupt: relabel the attestation author as the creator while the
        // key still hashes to mallory ⇒ derived != author_agent_id.
        for (_, att) in hostile.owner_chain.values_mut() {
            att.author_agent_id = creator;
        }

        honest.merge(item_scope(), &hostile).expect("merge");
        assert_eq!(
            honest.owner_transfers().len(),
            1,
            "only the creator-signed transfer survives; the tampered one is purged"
        );
        assert_eq!(honest.owner(), mallory, "legitimate chain still resolves");
    }

    #[test]
    fn chained_transfer_converges_in_both_merge_orders() {
        // WHY (hash chain, review r4): to extend the chain a signer MUST
        // reference the current head — a transfer signed against a STALE
        // head (B signing B→C before learning A→B, so it points at
        // Genesis where the owner is A, not B) is VOID FOREVER, even after
        // its prefix arrives. That is the security property: pre-signed
        // transfers at positions the signer no longer holds must never
        // activate retroactively (the same class as backdating). Both
        // merge orders must converge on the honest chain.
        let (a, a_signing) = signing_for(1);
        let (b, b_signing) = signing_for(2);
        let (c, _) = signing_for(3);
        let mut first = owned_task(&a);
        first
            .transfer_ownership(item_scope(), a, b, 100, &a_signing)
            .expect("a→b");
        let mut second = owned_task(&a);
        second
            .transfer_ownership(item_scope(), b, c, 200, &b_signing)
            .expect("b signs against a stale head (void edge)");
        // The stale-head edge is inert on its own.
        assert_eq!(second.owner(), a, "stale-head chain does not resolve alone");

        let mut order1 = first.clone();
        order1.merge(item_scope(), &second).expect("merge");
        let mut order2 = second.clone();
        order2.merge(item_scope(), &first).expect("merge");
        assert_eq!(order1.owner(), b, "order1 keeps the honest chain head");
        assert_eq!(order2.owner(), b, "order2 converges identically");

        // The LEGITIMATE continuation: B, now holding the converged chain,
        // transfers onward — its edge references the real head and walks.
        order1
            .transfer_ownership(item_scope(), b, c, 300, &b_signing)
            .expect("b→c from the converged head");
        assert_eq!(order1.owner(), c, "head-referencing continuation resolves");
    }

    #[test]
    fn concurrent_owner_transfers_resolve_deterministically() {
        // WHY (hash chain, review r4): the owner may sign two conflicting
        // transfers (A→B, A→C), both legitimately extending Genesis (each
        // replica signed against the head it saw). Replicas holding the
        // union must agree on ONE owner: the fork resolves by LOWEST EDGE
        // DIGEST — signer-independent, so neither timestamp nor signing
        // order can bias it. The test asserts CONVERGENCE (both merge
        // directions, same owner) rather than a specific winner.
        let (a, a_signing) = signing_for(1);
        let (b, _) = signing_for(2);
        let (c, _) = signing_for(3);
        let mut with_b = owned_task(&a);
        with_b
            .transfer_ownership(item_scope(), a, b, 500, &a_signing)
            .expect("a→b (later ts — irrelevant under the chain)");
        let mut with_c = owned_task(&a);
        with_c
            .transfer_ownership(item_scope(), a, c, 100, &a_signing)
            .expect("a→c (earlier ts — irrelevant under the chain)");

        with_b.merge(item_scope(), &with_c).expect("merge");
        with_c.merge(item_scope(), &with_b).expect("merge");
        assert_ne!(b, c, "fixtures must differ");
        assert_eq!(
            with_b.owner(),
            with_c.owner(),
            "both replicas converge on the same fork winner (lowest edge digest)"
        );
    }

    #[test]
    fn equivocating_owner_converges_identically_across_replicas() {
        // REVIEW r5: A signs A→B and A→M, both at Genesis (equivocation).
        // Replicas that received the edges in EITHER order — or hold only
        // one until the merge — must resolve the SAME deterministic winner
        // (lowest TO-agent identity), so ownership never forks across the
        // mesh. A non-owner's edge (C→M at Genesis) stays inadmissible.
        let (a, a_signing) = signing_for(1);
        let (b, _) = signing_for(2);
        let (m, _) = signing_for(9);
        let (c, c_signing) = signing_for(3);

        let mut replica1 = owned_task(&a);
        replica1
            .transfer_ownership(item_scope(), a, b, 100, &a_signing)
            .expect("a→b first on replica1");
        replica1
            .transfer_ownership(item_scope(), a, m, 50, &a_signing)
            .expect("then a→m (fork at genesis — void at the head)");
        let mut replica2 = owned_task(&a);
        replica2
            .transfer_ownership(item_scope(), a, m, 50, &a_signing)
            .expect("a→m first on replica2");
        replica2
            .transfer_ownership(item_scope(), a, b, 100, &a_signing)
            .expect("then a→b (fork at genesis)");

        // Both replicas converge to the same owner after merging views.
        replica1.merge(item_scope(), &replica2).expect("merge");
        replica2.merge(item_scope(), &replica1).expect("merge");
        assert_eq!(
            replica1.owner(),
            replica2.owner(),
            "equivocation resolves identically on every replica"
        );
        // And a non-owner's concurrent edge never participates.
        let mut replica3 = replica1.clone();
        replica3
            .transfer_ownership(item_scope(), c, m, 999, &c_signing)
            .expect("c signs although it never owned");
        assert_eq!(replica3.owner(), replica1.owner());
        // creator(a) is the starting point; the deterministic winner is
        // whichever of b/m has the lower AgentId bytes.
        let expected = if b.as_bytes() < m.as_bytes() { b } else { m };
        assert_eq!(replica1.owner(), expected);
    }

    #[test]
    fn former_owner_transfer_is_inadmissible() {
        // REVIEW r3 (critical): after A→B@100 makes B the owner, A is a
        // FORMER owner. A's own key can still sign A→M@200 — signature
        // valid, signer==from — but at ts=200 the running owner (folded
        // from strictly-earlier admissible edges) is B, not A, so the edge
        // is inadmissible and ownership must stay with B. This kills the
        // former-owner root-edge takeover.
        let (a, a_signing) = signing_for(1);
        let (b, _) = signing_for(2);
        let (mallory, _) = signing_for(3);
        let mut task = owned_task(&a);
        task.transfer_ownership(item_scope(), a, b, 100, &a_signing)
            .expect("a→b");
        // A (former owner) signs a NEWER root edge to mallory.
        task.transfer_ownership(item_scope(), a, mallory, 200, &a_signing)
            .expect("a signs as former owner (signature is valid)");
        assert_eq!(
            task.owner(),
            b,
            "former-owner edge at a later timestamp must be inadmissible"
        );

        // Same attack arriving via a REMOTE delta map (ingest path) — the
        // identical fold resolves it, no writer-gate reliance.
        let mut remote = owned_task(&a);
        remote
            .transfer_ownership(item_scope(), a, b, 100, &a_signing)
            .expect("a→b on remote");
        remote
            .transfer_ownership(item_scope(), a, mallory, 200, &a_signing)
            .expect("forged-later edge on remote");
        let mut local = owned_task(&a);
        local.ingest_owner_transfers(item_scope(), &remote.owner_wire_map());
        assert_eq!(
            local.owner(),
            b,
            "remote-carried former-owner edge is inadmissible on every path"
        );
    }

    #[test]
    fn membership_removal_reverts_ownership_over_removed_agent() {
        // WHY (ADR-0040): revoking an agent's membership must auto-expire
        // authority that flowed through it. Transfers touching a nonmember
        // are dropped, so ownership falls back to the last authorized holder.
        let (a, a_signing) = signing_for(1);
        let (b, b_signing) = signing_for(2);
        let (c, _) = signing_for(3);
        let mut task = owned_task(&a);
        task.transfer_ownership(item_scope(), a, b, 100, &a_signing)
            .expect("a→b");
        task.transfer_ownership(item_scope(), b, c, 200, &b_signing)
            .expect("b→c");
        assert_eq!(task.owner(), c);

        let mut authorized = HashSet::new();
        authorized.insert(a);
        // b removed from the group; c remains.
        authorized.insert(c);
        let dropped = task.filter_unauthorized(&authorized);
        assert!(dropped >= 1, "transfers touching b are dropped");
        assert_eq!(
            task.owner(),
            a,
            "ownership reverts to last authorized holder"
        );
    }

    #[test]
    fn legacy_taskitem_without_owner_transfers_decodes() {
        // WHY: wire/disk compatibility — blobs written before ADR-0040 lack
        // the trailing owner_transfers field entirely; they must decode
        // unchanged with ownership resolving to created_by (blocker 27's
        // "legacy deltas without the field decode unchanged").
        let (creator, _) = signing_for(1);
        let task = owned_task(&creator);

        // Serialize the pre-0040 9-field shape by stripping the trailing map.
        #[derive(serde::Serialize)]
        struct LegacyTaskItemPre0040<'a> {
            id: &'a TaskId,
            checkbox: &'a OrSet<CheckboxState>,
            title: &'a LwwRegister<String>,
            description: &'a LwwRegister<String>,
            assignee: &'a LwwRegister<Option<AgentId>>,
            priority: &'a LwwRegister<u8>,
            created_by: &'a AgentId,
            created_at: &'a u64,
            attestations: &'a BTreeMap<CheckboxState, OpAttestation>,
        }
        let legacy = LegacyTaskItemPre0040 {
            id: &task.id,
            checkbox: &task.checkbox,
            title: &task.title,
            description: &task.description,
            assignee: &task.assignee,
            priority: &task.priority,
            created_by: &task.created_by,
            created_at: &task.created_at,
            attestations: &task.attestations,
        };
        let bytes = bincode::serialize(&legacy).expect("serialize legacy shape");
        let decoded: TaskItem = bincode::deserialize(&bytes).expect("legacy blob decodes");
        assert_eq!(decoded.owner(), creator);
        assert!(decoded.owner_transfers().is_empty());
        assert_eq!(decoded.title(), task.title());
    }
}
