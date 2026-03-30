# Review Fixes Applied
**Date**: 2026-03-30
**Phase**: 1.2 — FOAF Discovery & Presence Events
**Review Iteration**: 1

## Fixes Applied

### MUST FIX (4 votes): NodeCreation → NodeError
- **File**: `src/lib.rs`
- **Change**: Changed `error::NetworkError::NodeCreation("presence system not initialized")` to
  `error::NetworkError::NodeError("presence system not initialized")` in both
  `subscribe_presence()` and `discover_agents_foaf()`. Also updated doc comments to reference
  the correct error variant.
- **Rationale**: `NodeCreation` implies a failure during node construction; `NodeError` is the
  correct variant for runtime API precondition failures.

### MUST FIX (3 votes): Empty machine_public_key in fallback DiscoveredAgent
- **File**: `src/presence.rs`
- **Change**: Added IMPORTANT doc comment to the fallback path explaining that
  `machine_public_key` is intentionally empty until the identity heartbeat arrives, and that
  callers needing to verify rendezvous signatures must check for non-empty key first.
- **Rationale**: Makes the limitation explicit rather than silent.

### MUST FIX (4 votes): O(n) linear scan documentation
- **File**: `src/presence.rs`
- **Change**: Added complexity doc comment to `peer_to_agent_id()` documenting O(n) behavior,
  acceptable scale limit (~10K agents), and noting a reverse index is planned.
- **Rationale**: The fix requiring a reverse index would touch the shared cache structure
  across the codebase; deferred to a future phase per scope constraints.

### SHOULD FIX (2 votes): No unit tests for presence helpers
- **File**: `src/presence.rs`
- **Change**: Added `#[cfg(test)]` module with 8 unit tests:
  - `test_global_presence_topic_is_deterministic`
  - `test_peer_to_agent_id_found`
  - `test_peer_to_agent_id_not_found`
  - `test_parse_addr_hints_valid`
  - `test_parse_addr_hints_invalid_skipped`
  - `test_presence_record_to_discovered_agent_cache_hit`
  - `test_presence_record_to_discovered_agent_fallback`
  - `test_presence_record_to_discovered_agent_expired`
- All 8 tests pass.

### SHOULD FIX (2 votes): Silent broadcast send failure
- **File**: `src/presence.rs`
- **Change**: Replaced `let _ = event_tx.send(...)` with explicit `if .is_err()` check
  and `tracing::debug!` logging for both `AgentOnline` and `AgentOffline` events.
- **Rationale**: Normal when no subscribers exist, but worth logging at debug level.

## Verification

| Check | Status |
|-------|--------|
| cargo check | PASS |
| cargo clippy -D warnings | PASS (zero warnings) |
| cargo fmt --check | PASS |
| cargo nextest (presence tests) | PASS (8/8 new tests) |
