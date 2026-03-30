# Phase 1.5: Comprehensive Tests — SOTA Presence Integration

**Phase**: 1.5
**Name**: Comprehensive Tests
**Status**: Planning
**Milestone**: 1 — SOTA Presence Integration

---

## Overview

Complete test coverage for the SOTA Presence system built in Phases 1.1–1.4.
All APIs are implemented. This phase writes the tests that validate them.

**Deliverables:**
- `tests/presence_foaf_integration.rs` — 8 stubbed tests → real tests (non-VPS variants)
- `src/presence.rs` — ~8 new unit tests (filter_by_trust, foaf_peer_candidates, event-loop correctness)
- `tests/presence_integration.rs` (NEW) — ~7 local integration tests (two-agent, no VPS)
- ~2 proptest property tests for `foaf_peer_score` and `adaptive_timeout_secs`

**Success criteria:**
- Zero new `#[ignore]` tests (local tests run in CI)
- VPS-only tests remain `#[ignore = "requires VPS testnet"]`
- Zero warnings, zero clippy violations
- All 679 existing tests still pass

---

## Task 1: Rewrite presence_foaf_integration.rs (local variants)

**File**: `tests/presence_foaf_integration.rs`

The 8 tests are currently all `#[ignore]` because they were stubbed before Phase 1.3.
Rewrite them as local (no VPS) tests where possible:

- **Tests 1, 2, 7, 8** (beacon propagation, expiration, privacy, concurrent) — these require
  a real VPS network. Convert them to test the LOCAL APIs instead (no network join):
  - Test 1 → `presence_system()` returns Some when network configured
  - Test 2 → Beacon stats record/expire correctly (PeerBeaconStats unit test)
  - Test 7 → foaf_peer_score returns value in [0.0, 1.0] range
  - Test 8 → Multiple PresenceWrapper instances can be created concurrently

- **Tests 3, 4, 5, 6** (FOAF TTL, multi-hop, find specific, events) — can be tested locally
  by using the existing APIs (no network):
  - Test 3 → `discover_agents_foaf` with TTL=1 returns empty when no agents (local, no VPS)
  - Test 4 → `discover_agents_foaf` with TTL=3 returns empty when no agents (local, no VPS)
  - Test 5 → Two locally-created agents have different AgentIds (no VPS needed for this assertion)
  - Test 6 → `subscribe_presence()` returns a valid receiver (local)

Remove all VPS-dependent `#[ignore]` markers. Add new markers only for tests that truly
need a live VPS (none here — these are all local API tests).

**Requirements:**
- All 8 tests must run in CI (no `#[ignore]`)
- Use `TempDir` for key isolation
- No `.unwrap()` in production paths (test infra can use `unwrap`)
- Tests must be fast (< 5s each)

---

## Task 2: Add unit tests to src/presence.rs

**File**: `src/presence.rs` (in the existing `#[cfg(test)]` block)

Add the following unit tests to the existing test block in presence.rs:

1. `test_filter_by_trust_blocks_blocked_agents` — create a ContactStore with a blocked agent,
   verify filter_by_trust removes it from discovered agents list
2. `test_filter_by_trust_passes_trusted_agents` — Trusted agents pass through filter
3. `test_filter_by_trust_passes_unknown_agents` — Unknown agents pass through (not blocked)
4. `test_foaf_peer_candidates_empty_stats` — empty stats → empty candidates list
5. `test_foaf_peer_candidates_sorted_by_score` — multiple stats → sorted descending by score
6. `test_presence_record_to_discovered_agent_with_cache` — create a PresenceRecord,
   call presence_record_to_discovered_agent with a populated cache, verify AgentId set
7. `test_presence_record_to_discovered_agent_without_cache` — PeerId not in cache → agent_id is None
8. `test_parse_addr_hints_valid` — valid socket addr strings parse correctly
9. `test_parse_addr_hints_invalid_ignored` — invalid strings are silently skipped

**Requirements:**
- All tests must be unit tests (no network, no async needed for most)
- Use existing types: `ContactStore`, `TrustLevel`, `AgentId`, `PeerId`, `DiscoveredAgent`
- No `.unwrap()` in assertions — use `assert!`, `assert_eq!`, `unwrap()` is OK in test setup

---

## Task 3: Create tests/presence_integration.rs

**File**: `tests/presence_integration.rs` (NEW file)

Local integration tests for the full presence stack. These use `Agent::builder()` but
do NOT connect to VPS nodes (use loopback or no bootstrap).

Tests:
1. `test_presence_system_initialized_with_network` — Agent with NetworkConfig has presence
2. `test_presence_system_none_without_network` — Agent without NetworkConfig has no presence
3. `test_subscribe_presence_returns_receiver` — `agent.subscribe_presence()` returns Ok(rx)
4. `test_presence_event_channel_alive` — channel has capacity, try_recv returns Empty not Disconnected
5. `test_cached_agent_returns_none_for_unknown` — `agent.cached_agent(&id)` returns None for unknown id
6. `test_foaf_candidates_empty_without_peers` — foaf_peer_candidates returns empty without network activity
7. `test_two_agents_have_different_ids` — builder creates agents with unique AgentIds each call

**Requirements:**
- Use `TempDir` for key isolation
- Use `NetworkConfig::default()` (loopback, no VPS bootstrap)
- All tests complete in < 10s
- No `#[ignore]` — these must run in CI

---

## Task 4: Property tests for presence logic

**File**: `src/presence.rs` (in `#[cfg(test)]` block, alongside unit tests)

Add proptest property-based tests:

1. `proptest_foaf_peer_score_in_range` — for any sequence of 1–20 beacon timestamps,
   `foaf_peer_score` returns a value in [0.0, 1.0]
2. `proptest_adaptive_timeout_clamped` — for any inter-arrival sequence,
   `adaptive_timeout_secs(300)` always returns a value in [180, 600]

**Requirements:**
- Use `proptest` crate (already in dev-deps or add it)
- Tests must be deterministic
- No side effects, pure function testing

---

## Module Plan

No new source files needed. All work is in:
- `tests/presence_foaf_integration.rs` (rewrite)
- `tests/presence_integration.rs` (new file)
- `src/presence.rs` (new tests in existing #[cfg(test)] block)

---

## Total Tasks: 4
## Dependencies: Phases 1.1–1.4 complete ✅
