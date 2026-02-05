# Phase 1.4: CRDT Task Lists - Implementation Plan

**Phase**: 1.4
**Name**: CRDT Task Lists
**Status**: Planning Complete
**Created**: 2026-02-05
**Estimated Tasks**: 10

---

## Overview

Build the collaborative task list system using saorsa-gossip's CRDT engine. This phase creates the distributed data structures needed for agents to collaborate on shared task lists with proper conflict resolution.

**Key Technologies:**
- `saorsa-gossip-crdt-sync`: OR-Set, LWW-Register, Delta-CRDTs, Anti-Entropy
- Checkbox state machine: Empty → Claimed → Done
- Delta synchronization for bandwidth efficiency
- Gossip pub/sub integration for real-time updates

---

## Task Breakdown

### Task 1: Define CRDT Task List Error Types
**File**: `src/crdt/error.rs`

Define error types specific to CRDT task list operations:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CrdtError {
    #[error("task not found: {0}")]
    TaskNotFound(TaskId),

    #[error("invalid state transition: {current:?} -> {attempted:?}")]
    InvalidStateTransition { current: CheckboxState, attempted: CheckboxState },

    #[error("task already claimed by {0}")]
    AlreadyClaimed(AgentId),

    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("CRDT merge error: {0}")]
    Merge(String),

    #[error("gossip error: {0}")]
    Gossip(String),
}

pub type Result<T> = std::result::Result<T, CrdtError>;
```

**Requirements:**
- Use `thiserror` for error derivation
- No unwrap/expect
- Clear error messages for debugging

**Tests**: Unit tests for error creation and Display formatting

---

### Task 2: Implement CheckboxState Type
**File**: `src/crdt/checkbox.rs`

Implement the checkbox state machine for task items:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckboxState {
    Empty,
    Claimed { agent_id: AgentId, timestamp: u64 },
    Done { agent_id: AgentId, timestamp: u64 },
}

impl CheckboxState {
    pub fn claim(agent_id: AgentId, timestamp: u64) -> Result<Self>;
    pub fn complete(agent_id: AgentId, timestamp: u64) -> Result<Self>;
    pub fn is_empty(&self) -> bool;
    pub fn is_claimed(&self) -> bool;
    pub fn is_done(&self) -> bool;
    pub fn claimed_by(&self) -> Option<&AgentId>;
}
```

**State Machine:**
- `Empty -> Claimed`: OK
- `Claimed -> Done`: OK (same or different agent)
- `Done -> *`: Immutable (error on transition)
- `Empty -> Done`: Error (must claim first)
- `Claimed -> Claimed`: Error (already claimed)

**Requirements:**
- Proper error handling for invalid transitions
- Timestamp tracking for conflict resolution
- Implement Ord for deterministic tiebreaking

**Tests**:
- Valid transitions (empty→claimed, claimed→done)
- Invalid transitions return errors
- Conflict resolution (concurrent claims)

---

### Task 3: Implement TaskId and TaskMetadata
**File**: `src/crdt/task.rs`

Define task identifier and metadata types:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId([u8; 32]); // BLAKE3 hash

impl TaskId {
    pub fn new(content: &str, creator: &AgentId, timestamp: u64) -> Self;
    pub fn as_bytes(&self) -> &[u8; 32];
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMetadata {
    pub title: String,
    pub description: String,
    pub priority: u8, // 0-255
    pub created_by: AgentId,
    pub created_at: u64,
    pub tags: Vec<String>,
}
```

**Requirements:**
- TaskId derived from BLAKE3(title || creator || timestamp) for content-addressing
- Implement Display for TaskId (hex format)
- TaskMetadata uses owned Strings (no lifetimes)

**Tests**:
- TaskId generation is deterministic
- TaskId Display shows hex format
- TaskMetadata serialization round-trips

---

### Task 4: Implement TaskItem CRDT
**File**: `src/crdt/task_item.rs`

Combine OR-Set (checkbox) + LWW-Register (metadata):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskItem {
    id: TaskId,
    checkbox: OrSet<CheckboxState>, // OR-Set for concurrent state changes
    title: LwwRegister<String>,
    description: LwwRegister<String>,
    assignee: LwwRegister<Option<AgentId>>,
    priority: LwwRegister<u8>,
    created_by: AgentId,
    created_at: u64,
}

impl TaskItem {
    pub fn new(id: TaskId, metadata: TaskMetadata, peer_id: PeerId) -> Self;
    pub fn claim(&mut self, agent_id: AgentId, peer_id: PeerId, seq: u64) -> Result<()>;
    pub fn complete(&mut self, agent_id: AgentId, peer_id: PeerId, seq: u64) -> Result<()>;
    pub fn update_title(&mut self, title: String, peer_id: PeerId);
    pub fn current_state(&self) -> CheckboxState;
    pub fn merge(&mut self, other: &TaskItem) -> Result<()>;
}
```

**Requirements:**
- Use OrSet for checkbox to handle concurrent claims
- Use LwwRegister for all metadata fields
- Proper error handling for state transitions
- Merge operation combines both OR-Set and LWW semantics

**Tests**:
- Concurrent claims resolve correctly (both see claimed)
- First to complete wins
- Metadata updates use LWW semantics
- Merge is idempotent and commutative

---

### Task 5: Implement TaskList CRDT with Ordered Storage
**File**: `src/crdt/task_list.rs`

Since saorsa-gossip doesn't provide RGA, use OrSet + ordering metadata:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskList {
    id: TaskListId,
    tasks: OrSet<TaskId>, // OR-Set of task IDs
    task_data: HashMap<TaskId, TaskItem>, // Task content
    ordering: LwwRegister<Vec<TaskId>>, // LWW for ordering
    name: LwwRegister<String>,
    version: u64,
    changelog: HashMap<u64, TaskListDelta>,
}

impl TaskList {
    pub fn new(id: TaskListId, name: String, peer_id: PeerId) -> Self;
    pub fn add_task(&mut self, task: TaskItem, peer_id: PeerId, seq: u64) -> Result<()>;
    pub fn remove_task(&mut self, task_id: &TaskId) -> Result<()>;
    pub fn claim_task(&mut self, task_id: &TaskId, agent_id: AgentId, peer_id: PeerId, seq: u64) -> Result<()>;
    pub fn complete_task(&mut self, task_id: &TaskId, agent_id: AgentId, peer_id: PeerId, seq: u64) -> Result<()>;
    pub fn reorder(&mut self, new_order: Vec<TaskId>, peer_id: PeerId) -> Result<()>;
    pub fn tasks_ordered(&self) -> Vec<&TaskItem>;
    pub fn merge(&mut self, other: &TaskList) -> Result<()>;
}
```

**Ordering Strategy:**
- Use LwwRegister<Vec<TaskId>> for task ordering
- On merge, take ordering from latest vector clock
- If tasks in OR-Set but not in ordering vector, append to end

**Requirements:**
- OR-Set semantics for task membership (add wins)
- LWW semantics for ordering and metadata
- Proper state validation
- No panic on missing tasks (return errors)

**Tests**:
- Add/remove tasks works correctly
- Claim/complete operations delegate to TaskItem
- Reordering updates LWW register
- Merge combines task sets and resolves ordering conflicts
- Concurrent adds from different peers converge

---

### Task 6: Implement Delta-CRDT for TaskList
**File**: `src/crdt/delta.rs`

Implement DeltaCrdt trait for bandwidth-efficient sync:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskListDelta {
    pub added_tasks: HashMap<TaskId, (TaskItem, UniqueTag)>,
    pub removed_tasks: HashMap<TaskId, HashSet<UniqueTag>>,
    pub task_updates: HashMap<TaskId, TaskItemDelta>,
    pub ordering_update: Option<(Vec<TaskId>, VectorClock)>,
    pub name_update: Option<(String, VectorClock)>,
    pub version: u64,
}

impl DeltaCrdt for TaskList {
    type Delta = TaskListDelta;

    fn merge(&mut self, delta: &Self::Delta) -> Result<()>;
    fn delta(&self, since_version: u64) -> Option<Self::Delta>;
    fn version(&self) -> u64;
}
```

**Requirements:**
- Track changes in changelog (version -> delta)
- Generate minimal deltas containing only changes since version
- Apply deltas correctly (OR-Set + LWW semantics)
- Implement changelog compaction (keep last N versions)

**Tests**:
- Delta generation includes only changed tasks
- Delta merge updates version correctly
- Changelog compaction prevents unbounded growth
- Delta round-trip preserves state

---

### Task 7: Integrate Anti-Entropy for TaskList Sync
**File**: `src/crdt/sync.rs`

Use saorsa-gossip's AntiEntropyManager for automatic sync:

```rust
pub struct TaskListSync {
    task_list: Arc<RwLock<TaskList>>,
    anti_entropy: AntiEntropyManager<TaskList>,
    gossip_runtime: Arc<GossipRuntime>,
    topic: String,
}

impl TaskListSync {
    pub async fn new(
        task_list: TaskList,
        gossip_runtime: Arc<GossipRuntime>,
        topic: String,
        sync_interval_secs: u64,
    ) -> Result<Self>;

    pub async fn start(&self) -> Result<()>;
    pub async fn stop(&self) -> Result<()>;
    pub async fn apply_remote_delta(&self, peer_id: PeerId, delta: TaskListDelta) -> Result<()>;
}
```

**Requirements:**
- Wrap TaskList in Arc<RwLock<>> for concurrent access
- Use AntiEntropyManager for periodic sync
- Publish deltas to gossip topic
- Subscribe to topic and apply received deltas
- No unwrap in async code paths

**Tests**:
- Start/stop lifecycle
- Delta publishing to gossip topic
- Delta reception and application
- Multi-peer synchronization

---

### Task 8: Add TaskList API to Agent
**File**: `src/lib.rs`

Extend Agent with TaskList operations:

```rust
impl Agent {
    /// Create a new task list bound to a topic
    pub async fn create_task_list(&self, name: &str, topic: &str) -> Result<TaskListHandle>;

    /// Join an existing task list by topic
    pub async fn join_task_list(&self, topic: &str) -> Result<TaskListHandle>;
}

/// Handle for interacting with a task list
pub struct TaskListHandle {
    sync: Arc<TaskListSync>,
}

impl TaskListHandle {
    pub async fn add_task(&self, title: String, description: String) -> Result<TaskId>;
    pub async fn claim_task(&self, task_id: TaskId) -> Result<()>;
    pub async fn complete_task(&self, task_id: TaskId) -> Result<()>;
    pub async fn list_tasks(&self) -> Result<Vec<TaskSnapshot>>;
    pub async fn reorder(&self, task_ids: Vec<TaskId>) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct TaskSnapshot {
    pub id: TaskId,
    pub title: String,
    pub description: String,
    pub state: CheckboxState,
    pub assignee: Option<AgentId>,
    pub priority: u8,
}
```

**Requirements:**
- TaskListHandle provides safe concurrent access
- All operations return Results (no panics)
- TaskSnapshot is a read-only view (no CRDT internals exposed)
- Integration with existing Agent identity (machine_id for PeerId, agent_id for ownership)

**Tests**:
- Create and join task lists
- Add tasks to list
- Claim and complete tasks
- List tasks in order
- Reorder tasks

---

### Task 9: Implement Persistence for TaskList
**File**: `src/crdt/persistence.rs`

Local storage for offline operation:

```rust
pub struct TaskListStorage {
    storage_path: PathBuf,
}

impl TaskListStorage {
    pub fn new(storage_path: PathBuf) -> Self;
    pub async fn save_task_list(&self, list_id: &TaskListId, task_list: &TaskList) -> Result<()>;
    pub async fn load_task_list(&self, list_id: &TaskListId) -> Result<TaskList>;
    pub async fn list_task_lists(&self) -> Result<Vec<TaskListId>>;
    pub async fn delete_task_list(&self, list_id: &TaskListId) -> Result<()>;
}
```

**Storage Format:**
- Store as bincode-serialized files in `~/.x0x/task_lists/<list_id>.bin`
- Atomic writes (write to temp file, rename)
- Proper error handling for I/O failures

**Requirements:**
- Create storage directory if it doesn't exist
- No unwrap on I/O operations
- Graceful handling of corrupted files (return error, don't panic)

**Tests**:
- Save and load round-trip
- List all task lists
- Delete task list
- Atomic write (no partial writes on crash)
- Corrupted file handling

---

### Task 10: Write Integration Tests for CRDT Task Lists
**File**: `tests/crdt_integration.rs`

Comprehensive integration tests covering:

```rust
#[tokio::test]
async fn test_task_list_concurrent_operations() {
    // Two agents, one task list
    // Agent A adds task, Agent B claims it, Agent A completes it
    // Verify convergence
}

#[tokio::test]
async fn test_task_list_conflict_resolution() {
    // Concurrent claims on same task
    // Verify OR-Set semantics (both see claimed)
    // First to complete wins
}

#[tokio::test]
async fn test_task_list_ordering_conflicts() {
    // Two agents reorder task list concurrently
    // Verify LWW semantics for ordering
}

#[tokio::test]
async fn test_task_list_delta_sync() {
    // Agent A offline, makes changes
    // Agent A reconnects, delta sync with Agent B
    // Verify anti-entropy reconciliation
}

#[tokio::test]
async fn test_task_list_persistence() {
    // Create task list, make changes, save
    // Load from storage
    // Verify state matches
}

#[tokio::test]
async fn test_task_list_multi_agent_collaboration() {
    // 3+ agents collaborating on shared task list
    // Add, claim, complete, reorder operations
    // Verify eventual consistency
}
```

**Property-Based Tests** (using `proptest`):
- CRDT operations are commutative
- CRDT operations are idempotent
- Merge always converges

**Requirements:**
- Zero test failures
- No unwrap in test setup (use `?` and proper error propagation)
- Tests run in parallel (no shared global state)

---

## Module Structure

Create new module in `src/`:

```
src/crdt/
├── mod.rs          // Module declarations and re-exports
├── error.rs        // Task 1: CrdtError type
├── checkbox.rs     // Task 2: CheckboxState
├── task.rs         // Task 3: TaskId and TaskMetadata
├── task_item.rs    // Task 4: TaskItem CRDT
├── task_list.rs    // Task 5: TaskList CRDT
├── delta.rs        // Task 6: Delta-CRDT implementation
├── sync.rs         // Task 7: Anti-entropy sync
└── persistence.rs  // Task 9: Storage
```

Update `src/lib.rs`:
```rust
pub mod crdt;
pub use crdt::{TaskListHandle, TaskSnapshot, TaskId, CheckboxState};
```

---

## Dependencies

Add to `Cargo.toml` (if not already present):

```toml
[dependencies]
saorsa-gossip-crdt-sync = { path = "../saorsa-gossip/crates/crdt-sync" }
```

Already present:
- `blake3`, `bincode`, `serde`, `tokio`, `saorsa-gossip-types`

---

## Success Criteria

- [ ] Zero compilation errors across all targets
- [ ] Zero compilation warnings (cargo clippy passes)
- [ ] Zero test failures (all unit + integration tests pass)
- [ ] No `.unwrap()` or `.expect()` in production code (tests OK)
- [ ] Agent can create and join task lists
- [ ] Multiple agents can collaborate on shared task list
- [ ] Concurrent operations resolve correctly (OR-Set + LWW)
- [ ] Delta synchronization reduces bandwidth usage
- [ ] Anti-entropy repairs partitions
- [ ] Task lists persist across agent restarts
- [ ] Documentation complete for all public APIs

---

## Task Execution Order

**TDD Approach** (tests before implementation):

1. Task 1 (errors) - Foundation
2. Task 2 (checkbox) - State machine
3. Task 3 (task metadata) - Data types
4. Task 4 (task item CRDT) - Core CRDT
5. Task 5 (task list CRDT) - Collection CRDT
6. Task 6 (delta) - Bandwidth optimization
7. Task 7 (anti-entropy) - Automatic sync
8. Task 9 (persistence) - Offline support
9. Task 8 (Agent API) - Public interface
10. Task 10 (integration tests) - End-to-end validation

---

## Notes

- **RGA Not Available**: saorsa-gossip-crdt-sync doesn't provide RGA (Replicated Growable Array). We use OrSet + LwwRegister<Vec<TaskId>> for ordering instead. This gives us eventual consistency with LWW conflict resolution for ordering.

- **Checkbox as OR-Set**: Using OR-Set for checkbox state allows multiple concurrent claims to be visible. The "first to complete" wins the Done state. This is correct for collaborative task management.

- **TaskId Content-Addressing**: Using BLAKE3(title || creator || timestamp) ensures unique task IDs while making them reproducible from task content.

- **No Panic Policy**: All error paths return `Result`. The only acceptable panics are in tests for assertion failures.

---

**Plan Created**: 2026-02-05
**Total Tasks**: 10
**Estimated Completion**: Phase 1.4 complete after all tasks pass review
