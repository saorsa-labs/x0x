# Phase 3.2: Integration Testing

**Milestone**: 3 (VPS Testnet & Production Release)
**Phase**: 3.2
**Status**: In Progress
**Created**: 2026-02-06

## Overview

Phase 3.2 validates ALL work from Milestones 1, 2, and 3.1 through comprehensive integration testing across the global VPS testnet. This phase ensures production readiness by testing real-world scenarios: NAT traversal, network partitions, CRDT convergence, presence/FOAF discovery, cross-language interop, security, and scale.

## Infrastructure

**6 Global VPS Nodes** (all healthy from Phase 3.1):
- saorsa-2: 142.93.199.50:12000 (NYC)
- saorsa-3: 147.182.234.192:12000 (SFO)
- saorsa-6: 65.21.157.229:12000 (Helsinki)
- saorsa-7: 116.203.101.172:12000 (Nuremberg)
- saorsa-8: 149.28.156.231:12000 (Singapore)
- saorsa-9: 45.77.176.184:12000 (Tokyo)

## Quality Requirements

- 100% test pass rate (all tests must succeed)
- Zero compilation errors/warnings
- Tests must be reproducible
- Performance benchmarks must have clear metrics
- Security tests must validate all threat models
- Cross-language interop verified (Rust, Node.js, Python)

---

## Tasks

### Task 1: NAT Traversal Verification Tests

**Goal**: Verify QUIC hole punching works across global VPS nodes behind different NAT configurations.

**Implementation** (~80 lines):
- Create `tests/nat_traversal_integration.rs`
- Test direct connections between VPS pairs (all 15 combinations)
- Test connections from local machine (behind NAT) to VPS nodes
- Test symmetric NAT scenarios with MASQUE relay fallback
- Verify external address discovery works correctly
- Measure hole punch success rate and latency

**Test Scenarios**:
1. NYC ↔ SFO (both public IPs) - should be instant
2. Local (NAT) → NYC (public) - should hole punch
3. Local (NAT) → SFO (public) - should hole punch
4. Symmetric NAT → VPS - should use MASQUE relay
5. Connection pool stability over 5 minutes

**Acceptance Criteria**:
- All VPS-to-VPS connections succeed (100% success rate)
- NAT → public connections succeed (>95% success rate)
- Symmetric NAT uses relay fallback correctly
- Connection latency < 200ms for local region pairs
- Zero connection timeouts

**Dependencies**: None

---

### Task 2: CRDT Convergence Tests - Concurrent Operations

**Goal**: Verify task list CRDTs converge correctly under concurrent operations from multiple agents.

**Implementation** (~100 lines):
- Create `tests/crdt_convergence_concurrent.rs`
- Spawn 10 agents, all connected to same task list topic
- Each agent performs concurrent operations:
  - Add tasks (OR-Set additions)
  - Claim tasks (OR-Set state transitions)
  - Update metadata (LWW-Register updates)
  - Complete tasks (OR-Set state transitions)
- Wait for gossip propagation (5-10 seconds)
- Verify all agents converge to identical state

**Test Scenarios**:
1. Concurrent add_task() - all tasks should merge
2. Concurrent claim_task() on same task - OR-Set semantics
3. Concurrent metadata updates - LWW wins (latest timestamp)
4. Concurrent complete_task() - both see completion
5. Mixed operations - add/claim/complete/update all at once

**Acceptance Criteria**:
- All agents see identical task list after convergence
- OR-Set semantics preserved (no duplicates)
- LWW semantics preserved (latest wins)
- RGA ordering consistent across replicas
- Convergence time < 10 seconds for 10 agents

**Dependencies**: Task 1 (network connectivity verified)

---

### Task 3: CRDT Convergence Tests - Network Partitions

**Goal**: Verify CRDTs repair correctly after network partitions and message loss.

**Implementation** (~90 lines):
- Create `tests/crdt_partition_tolerance.rs`
- Create 2 groups of agents (Group A: 3 agents, Group B: 3 agents)
- Partition network - block gossip between groups for 30 seconds
- Each group performs independent operations during partition
- Restore network connectivity
- Verify anti-entropy repairs and state converges

**Test Scenarios**:
1. Simple partition - add tasks on both sides, verify merge
2. Conflicting claims - both groups claim same task
3. Conflicting updates - both groups update same task metadata
4. Asymmetric partition - one group sees partial updates
5. Multiple partition/repair cycles

**Acceptance Criteria**:
- CRDTs converge after partition repair (100% success)
- Anti-entropy detects missed messages via IBLT
- No data loss after partition repair
- Conflict resolution follows CRDT semantics
- Convergence time < 30 seconds post-repair

**Dependencies**: Task 2 (concurrent convergence verified)

---

### Task 4: Presence & FOAF Discovery Tests

**Goal**: Verify presence beacons and FOAF discovery work across the VPS mesh.

**Implementation** (~80 lines):
- Create `tests/presence_foaf_integration.rs`
- Spawn agents on different VPS nodes
- Test presence beacon propagation (15min TTL)
- Test FOAF queries with TTL=3, fanout=3
- Verify agents discover each other within 3 hops
- Test beacon expiration and offline detection

**Test Scenarios**:
1. Agent A online → beacon visible to VPS mesh
2. Agent B queries FOAF for Agent A → finds within 3 hops
3. Agent A goes offline → beacon expires after 15min
4. FOAF query with TTL=1 → only immediate neighbors
5. FOAF query with TTL=3 → up to 3 hops

**Acceptance Criteria**:
- Presence beacons propagate to all VPS nodes (< 5 seconds)
- FOAF queries find agents within TTL hops (100% success)
- Beacon expiration works (offline detection within 15min)
- Privacy preserved - no full path visibility
- Query latency < 2 seconds for 3-hop discovery

**Dependencies**: Task 1 (network connectivity verified)

---

### Task 5: Rendezvous Shard Discovery Tests

**Goal**: Verify rendezvous sharding for global agent findability.

**Implementation** (~70 lines):
- Create `tests/rendezvous_integration.rs`
- Test shard assignment: `ShardId = BLAKE3("saorsa-rendezvous" || agent_id) & 0xFFFF`
- Verify agents advertise to correct shard coordinators
- Test agent lookup via shard query
- Verify coordinator adverts (ML-DSA signed, 24h TTL)
- Test failover when coordinator goes offline

**Test Scenarios**:
1. Agent registers to shard → coordinator stores entry
2. Query by AgentId → correct shard returns result
3. Multiple coordinators for same shard → consistent results
4. Coordinator goes offline → failover to backup
5. Shard load balancing across 65,536 shards

**Acceptance Criteria**:
- Shard assignment deterministic and collision-resistant
- Agent findability via shard query (100% success)
- Coordinator adverts propagate globally (< 10 seconds)
- Failover works when coordinator offline
- Query latency < 1 second for shard lookup

**Dependencies**: Task 4 (presence system verified)

---

### Task 6: Scale Testing Framework

**Goal**: Build infrastructure to simulate 100+ agents and measure performance.

**Implementation** (~120 lines):
- Create `tests/scale_test_framework.rs`
- Build agent simulator: spawn 100 lightweight agents
- Configure agents to connect to VPS testnet
- Implement metrics collection:
  - Message propagation latency (p50, p95, p99)
  - Bandwidth usage per agent (up/down)
  - Memory usage per agent
  - Connection success rate
  - CRDT convergence time
- Generate load: 10 msg/sec per agent = 1000 msg/sec total
- Run for 5 minutes, collect metrics, generate report

**Metrics to Track**:
- Latency: Message propagation time (gossip)
- Throughput: Messages/sec sustained
- Bandwidth: Bytes/sec per agent
- Memory: MB per agent
- CPU: % usage per agent
- Convergence: Seconds to reach consistency

**Acceptance Criteria**:
- Framework supports 100+ simulated agents
- Metrics collection automated and exportable
- Test runs for 5+ minutes without crashes
- Report generated with statistical summaries
- Baseline established for future regression testing

**Dependencies**: Tasks 1-5 (all systems verified functional)

---

### Task 7: Scale Test Execution & Analysis

**Goal**: Run scale test and analyze results against performance targets.

**Implementation** (~60 lines):
- Use framework from Task 6
- Run 100-agent test for 10 minutes
- Analyze results against targets:
  - p95 latency < 500ms
  - Throughput > 500 msg/sec
  - Memory < 50MB per agent
  - Bandwidth < 100KB/s per agent
  - Convergence < 30 seconds
- Generate performance report with graphs
- Document any bottlenecks or issues

**Performance Targets**:
| Metric | Target | Threshold |
|--------|--------|-----------|
| p95 latency | < 500ms | < 1000ms |
| Throughput | > 500 msg/s | > 250 msg/s |
| Memory/agent | < 50MB | < 100MB |
| Bandwidth/agent | < 100KB/s | < 200KB/s |
| Convergence | < 30s | < 60s |

**Acceptance Criteria**:
- All metrics meet targets or documented exceptions
- Performance report generated with recommendations
- No crashes or panics during 10min run
- Network remains stable under load
- Bottlenecks identified and documented

**Dependencies**: Task 6 (framework built)

---

### Task 8: Property-Based CRDT Tests

**Goal**: Use proptest to verify CRDT invariants hold for all possible operation sequences.

**Implementation** (~100 lines):
- Create `tests/crdt_properties_proptest.rs`
- Add proptest dependency to dev-dependencies
- Define property tests:
  - **Commutativity**: `op1; op2 == op2; op1` for all ops
  - **Associativity**: `(op1; op2); op3 == op1; (op2; op3)`
  - **Idempotence**: `op; op == op` for all ops
  - **Convergence**: All replicas reach same state
  - **Monotonicity**: Operations never decrease set size (OR-Set)
- Generate random operation sequences (add/claim/complete/update)
- Verify invariants hold after applying operations

**Properties to Test**:
1. OR-Set commutativity: add/remove order doesn't matter
2. LWW-Register convergence: latest timestamp wins
3. RGA ordering: insertions preserve causal order
4. TaskList convergence: independent ops commute
5. State merge idempotence: merge(S, S) = S

**Acceptance Criteria**:
- All property tests pass with 1000+ random inputs
- No counterexamples found by proptest
- Regression files committed for reproducibility
- CRDT semantics formally verified
- Zero panics or unexpected errors

**Dependencies**: Task 3 (CRDT convergence verified manually)

---

### Task 9: Cross-Language Interop Tests

**Goal**: Verify Rust, Node.js, and Python SDKs interoperate on same network.

**Implementation** (~90 lines):
- Create `tests/cross_language_interop.rs` (coordinator)
- Create `bindings/nodejs/tests/interop.test.js` (Node.js)
- Create `bindings/python/tests/test_interop.py` (Python)
- Test scenario:
  1. Rust agent creates task list, adds task
  2. Node.js agent subscribes to task list topic
  3. Python agent claims the task
  4. Rust agent verifies claim propagated
  5. Node.js agent completes the task
  6. All agents see completed state

**Test Coverage**:
- Identity compatibility (ML-DSA keys, PeerId derivation)
- Network messages (JSON serialization, bincode for binary)
- CRDT operations (add/claim/complete)
- Event system (subscribe/publish)
- Presence beacons (all languages see each other)

**Acceptance Criteria**:
- All three languages connect to same VPS network
- Task list operations propagate across languages
- Message serialization compatible (JSON + bincode)
- Events delivered to all language subscribers
- Zero type mismatches or serialization errors

**Dependencies**: Phase 2.1 (Node.js bindings), Phase 2.2 (Python bindings)

---

### Task 10: Security Validation Tests

**Goal**: Verify signature validation, replay prevention, and MLS encryption work correctly.

**Implementation** (~100 lines):
- Create `tests/security_validation.rs`
- Test ML-DSA-65 signature verification:
  - Valid signatures accepted
  - Invalid signatures rejected
  - Tampered messages rejected
- Test replay attack prevention:
  - Message IDs (BLAKE3) cached
  - Duplicate messages ignored
  - Cache expires after 5 minutes
- Test MLS group encryption:
  - Only group members can decrypt
  - Forward secrecy verified (old keys don't work)
  - Post-compromise security (new epoch after member leave)

**Security Tests**:
1. Message signature validation (positive + negative)
2. PeerId verification (detect key substitution)
3. Replay attack prevention (message deduplication)
4. MLS encryption (confidentiality)
5. MLS forward secrecy (key rotation)
6. MLS post-compromise security (member removal)

**Acceptance Criteria**:
- All signature verifications work correctly (100%)
- Replay attacks blocked (duplicate msg ignored)
- MLS encryption protects confidentiality
- Forward secrecy verified (old keys invalid)
- Post-compromise security verified (new epoch)
- Zero security bypasses or vulnerabilities

**Dependencies**: Phase 1.5 (MLS integration)

---

### Task 11: Performance Benchmarking

**Goal**: Establish performance baselines for future regression testing.

**Implementation** (~80 lines):
- Create `benches/core_operations.rs` (using criterion)
- Add criterion to dev-dependencies
- Benchmark critical operations:
  - Agent creation (key generation)
  - Task list operations (add/claim/complete)
  - Message signing/verification (ML-DSA-65)
  - Message serialization (JSON + bincode)
  - CRDT merge operations
  - Gossip message propagation (local)
- Run benchmarks, save baselines
- Document results in `.planning/benchmarks.md`

**Benchmarks**:
| Operation | Target | Baseline |
|-----------|--------|----------|
| Agent creation | < 100ms | TBD |
| add_task() | < 1ms | TBD |
| ML-DSA sign | < 5ms | TBD |
| ML-DSA verify | < 3ms | TBD |
| JSON serialize | < 100μs | TBD |
| CRDT merge | < 10ms | TBD |

**Acceptance Criteria**:
- All benchmarks run successfully
- Baseline metrics documented
- Criterion generates HTML reports
- No performance regressions vs expectations
- Benchmarks integrated into CI/CD

**Dependencies**: None (can run in parallel with other tasks)

---

### Task 12: Test Automation & Reporting

**Goal**: Automate test execution and generate comprehensive test report.

**Implementation** (~70 lines):
- Create `scripts/run_integration_tests.sh`
- Automate test execution sequence:
  1. Check VPS node health (all 6 must be up)
  2. Run unit tests: `cargo nextest run --lib`
  3. Run integration tests: `cargo nextest run --test '*'`
  4. Run cross-language tests: Node.js + Python
  5. Run benchmarks: `cargo bench`
  6. Collect results and generate report
- Create `.planning/TEST_REPORT.md` template
- Populate report with:
  - Test summary (pass/fail counts)
  - Performance metrics from scale tests
  - Benchmark baselines
  - Known issues or exceptions
  - Recommendations for Phase 3.3

**Test Report Sections**:
1. Executive Summary
2. Infrastructure Status (6 VPS nodes)
3. Test Results by Category (NAT, CRDT, presence, scale, security)
4. Performance Metrics (latency, throughput, memory)
5. Cross-Language Interop Status
6. Security Validation Results
7. Known Issues & Mitigations
8. Recommendations for Phase 3.3

**Acceptance Criteria**:
- Automation script runs end-to-end without manual intervention
- All tests execute in correct order
- Report auto-generated with all metrics
- Report format is markdown and human-readable
- Script returns exit code 0 on success, 1 on failure

**Dependencies**: Tasks 1-11 (all tests implemented)

---

## Success Criteria

**Phase Complete When**:
- All 12 tasks completed
- 100% test pass rate (zero failures)
- Zero compilation errors/warnings
- Performance targets met (latency, throughput, memory)
- Security tests pass (signature, replay, MLS)
- Cross-language interop verified
- Test report generated with recommendations
- STATE.json updated to "phase_complete"

**Deliverables**:
- 12 test files (~1000 lines total)
- Performance benchmarks with baselines
- Cross-language interop verification
- Automation script for CI/CD
- Comprehensive test report (`.planning/TEST_REPORT.md`)

**Quality Gates**:
- cargo nextest run → 100% pass
- cargo clippy → zero warnings
- cargo fmt --check → zero changes
- Benchmarks → meet targets
- VPS testnet → all 6 nodes healthy

---

## Task Execution Order

```
Task 1 (NAT) ──┬──> Task 2 (CRDT concurrent) ──> Task 3 (CRDT partition)
               │                                            │
               ├──> Task 4 (Presence/FOAF) ──> Task 5 (Rendezvous)
               │                                            │
               └────────────────┬───────────────────────────┘
                                │
                                ├──> Task 6 (Scale framework) ──> Task 7 (Scale execution)
                                │
                                ├──> Task 8 (Property tests)
                                │
                                ├──> Task 9 (Cross-language)
                                │
                                ├──> Task 10 (Security)
                                │
                                ├──> Task 11 (Benchmarks)
                                │
                                └──> Task 12 (Automation & Report)
```

**Critical Path**: Task 1 → Task 2 → Task 3 → Task 6 → Task 7 → Task 12

**Parallelizable**: Tasks 8, 9, 10, 11 can run after Task 3 completes.

---

## Notes

- All tests must be reproducible (use fixed seeds for randomness)
- VPS nodes are production infrastructure - monitor resource usage
- Clean up test artifacts (task lists, connections) after each test
- Document any flaky tests or intermittent failures
- Use `#[ignore]` for long-running tests (>60 seconds)
- Tag tests with `#[cfg(feature = "vps-integration")]` for CI control
