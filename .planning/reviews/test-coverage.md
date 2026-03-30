# Test Coverage Review
**Date**: Mon 30 Mar 2026 10:40:22 BST

## Test files
announcement_test.rs
bootstrap_cache_integration.rs
comprehensive_integration.rs
connectivity_test.rs
constitution_integration.rs
crdt_convergence_concurrent.rs
crdt_integration.rs
crdt_partition_tolerance.rs
daemon_api_integration.rs
direct_messaging_integration.rs
file_transfer_integration.rs
gossip_cache_adapter_integration.rs
identity_announcement_integration.rs
identity_integration.rs
identity_unification_test.rs
mls_integration.rs
nat_traversal_integration.rs
network_integration.rs
network_timeout.rs
presence_foaf_integration.rs
presence_wiring_test.rs
rendezvous_integration.rs
scale_testing.rs
trust_evaluation_test.rs
upgrade_integration.rs
vps_e2e_integration.rs

## New code test coverage
New APIs added in Phase 1.2:
  - Agent::subscribe_presence()  — no dedicated test
  - Agent::discover_agents_foaf() — no dedicated test
  - Agent::discover_agent_by_id() — no dedicated test
  - presence::peer_to_agent_id() — no dedicated test
  - presence::presence_record_to_discovered_agent() — no dedicated test
  - PresenceWrapper::start_event_loop() — no dedicated test

  Note: tests/presence_foaf_integration.rs has 8 tests but ALL are #[ignore]
  (awaiting VPS testnet — by design per CLAUDE.md)

## Existing test counts
Unit tests in src/: 365
Integration test files: 26

## Findings
- [IMPORTANT] No unit tests for peer_to_agent_id(), presence_record_to_discovered_agent() helper functions
- [IMPORTANT] No unit test for start_event_loop() idempotency (double-call should be no-op)
- [MINOR] discover_agents_foaf() and discover_agent_by_id() untested without network
- [OK] Integration tests in presence_foaf_integration.rs exist but are correctly ignored (VPS dependency)

## Grade: B
