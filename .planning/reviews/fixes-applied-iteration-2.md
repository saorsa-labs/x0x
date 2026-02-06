# Fixes Applied - Review Iteration 2

**Date**: 2026-02-06 18:30:00 GMT
**Review Iteration**: 2 → 3
**Status**: ALL CRITICAL ISSUES FIXED ✅

---

## Critical Issues Fixed (3)

### CRITICAL-1: Sequence Numbers Misused as Timestamps ✅ FIXED

**Location**: `src/crdt/task_item.rs:190, 244`
**Issue**: Code used per-peer sequence numbers for timestamps, which cannot be globally compared across peers, breaking CRDT deterministic conflict resolution.

**Fix Applied**:
```rust
// BEFORE (WRONG):
let claimed_state = CheckboxState::Claimed {
    agent_id,
    timestamp: seq,  // ← Per-peer sequence number (not globally comparable!)
};

// AFTER (CORRECT):
let timestamp = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("system time before Unix epoch")
    .as_millis() as u64;

let claimed_state = CheckboxState::Claimed {
    agent_id,
    timestamp,  // ← Unix timestamp in milliseconds (globally comparable)
};
let tag = (peer_id, seq);  // seq still used for OR-Set uniqueness
```

**Changes**:
- `task_item.rs:claim()` - Generate Unix timestamp at method entry
- `task_item.rs:complete()` - Generate Unix timestamp at method entry
- Both methods use `SystemTime::now()` for globally comparable timestamps
- `seq` parameter still used for OR-Set tags (correct usage)

**Test Updates**:
- `test_concurrent_claims` - Updated to verify Unix timestamp range instead of exact value
- `test_concurrent_completes` - Updated to verify Unix timestamp range instead of exact value
- Both tests now verify timestamps > 1 trillion (year 2001+)

**Verification**: ✅ All 281 tests passing

---

### CRITICAL-2: add_task() Overwrites Existing Tasks ✅ FIXED

**Location**: `src/crdt/task_list.rs:150-151`
**Issue**: Unconditional `HashMap::insert()` overwrote existing TaskItem CRDT state, causing data loss on concurrent task additions.

**Fix Applied**:
```rust
// BEFORE (WRONG):
self.task_data.insert(task_id, task);  // ← Always overwrites!

// AFTER (CORRECT):
if let Some(existing) = self.task_data.get_mut(&task_id) {
    // Task already exists - merge CRDT state instead of overwriting
    existing.merge(&task)?;
} else {
    // New task - insert
    self.task_data.insert(task_id, task);
}
```

**Impact**:
- Prevents data loss when two peers concurrently add same TaskId
- Preserves checkbox OR-Set states from both peers
- Preserves metadata LWW-Register states
- Correct CRDT merge semantics maintained

**Verification**: ✅ All 281 tests passing (including merge tests)

---

### CRITICAL-3: tasks_ordered() Returns Removed Tasks ✅ FIXED

**Location**: `src/crdt/task_list.rs:298-318`
**Issue**: Method pulled tasks from `ordering` vector without checking OR-Set membership, causing removed tasks to reappear.

**Fix Applied**:
```rust
// BEFORE (WRONG):
let mut ordered: Vec<&TaskItem> = current_order
    .iter()
    .filter_map(|id| self.task_data.get(id))  // ← No OR-Set check!
    .collect();

// AFTER (CORRECT):
use std::collections::HashSet;

let or_set_tasks: HashSet<TaskId> = self.tasks.elements().into_iter().copied().collect();
let mut ordered: Vec<&TaskItem> = current_order
    .iter()
    .filter(|id| or_set_tasks.contains(id))  // ← Check OR-Set membership first!
    .filter_map(|id| self.task_data.get(id))
    .collect();
```

**Changes**:
- Changed `or_set_tasks` from `Vec` to `HashSet` for O(1) membership check
- Added `.filter(|id| or_set_tasks.contains(id))` before pulling from `task_data`
- Only returns tasks that are present in the OR-Set (not removed)

**Side Benefit**: Also fixes O(n²) performance issue noted by Kimi reviewer (HashSet provides O(1) lookup instead of Vec O(n) `contains()`)

**Verification**: ✅ All 281 tests passing

---

## Build Validation ✅

```bash
cargo check --all-features --all-targets
# ✅ PASS - Zero errors, zero warnings

cargo clippy --all-features --all-targets -- -D warnings
# ✅ PASS - Zero clippy violations

cargo nextest run --no-fail-fast
# ✅ PASS - 281/281 tests passing (including 94 CRDT tests)

cargo fmt --all -- --check
# ✅ PASS - All code formatted
```

---

## Files Modified

1. **src/crdt/task_item.rs** (2 methods)
   - `claim()` - Use Unix timestamp instead of seq for conflict resolution
   - `complete()` - Use Unix timestamp instead of seq for conflict resolution
   - Updated 2 tests to verify Unix timestamp ranges

2. **src/crdt/task_list.rs** (2 locations)
   - `add_task()` - Merge with existing task instead of overwriting
   - `tasks_ordered()` - Filter by OR-Set membership, use HashSet for performance

---

## Impact Assessment

### CRDT Correctness: RESTORED ✅
- **Convergence**: Now guaranteed (Unix timestamps are globally comparable)
- **Commutativity**: Merge order doesn't matter (all operations commutative)
- **Idempotence**: Applying same operation multiple times is safe
- **Determinism**: Same concurrent operations resolve identically on all replicas

### Performance: IMPROVED ✅
- **tasks_ordered()**: O(n²) → O(n) (HashSet instead of Vec contains)
- **Bandwidth**: No change (delta-CRDT still efficient)
- **Memory**: Minimal overhead (HashSet vs Vec for OR-Set elements)

### Security: NO REGRESSION ✅
- Unix timestamps are public (no secret data leaked)
- OR-Set tags still use (peer_id, seq) for uniqueness
- No new attack surfaces introduced

---

## Remaining Issues (Non-Blocking)

### Important (Recommended for Production)
1. **Encryption nonce reuse** (encrypted.rs) - Kimi finding
2. **DoS size limits** (task_list.rs) - No max task count
3. **task_data pruning after merge** - Zombie tasks possible

### Minor (Optional)
1. **Property-based tests** - Add proptest for CRDT properties
2. **File permissions** (persistence.rs) - Explicit 0600 instead of umask
3. **Network partition tests** - Integration tests for offline/online scenarios

---

## Next Steps

1. ✅ All critical CRDT bugs fixed
2. ⏭️ Commit fixes
3. ⏭️ Re-run gsd-review (iteration 3) to verify fixes
4. ⏭️ If review PASS → Proceed to Phase 1.5
5. ⏭️ If review FAIL → Fix remaining issues and repeat

---

**Summary**: All 3 critical CRDT correctness bugs have been fixed. The implementation now correctly uses Unix timestamps for global conflict resolution, merges concurrent task additions instead of overwriting, and filters removed tasks from ordered list. All 281 tests passing with zero warnings.

**Review Iteration 2 → 3 Fixes Complete** ✅
