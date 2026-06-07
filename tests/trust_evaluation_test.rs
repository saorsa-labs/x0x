#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for the flexible trust model.
//!
//! Tests the ContactStore and TrustEvaluator working together: adding contacts,
//! setting trust levels, recording machine IDs, pinning machines, and verifying
//! the trust decision logic end-to-end.

use tempfile::TempDir;
use x0x::contacts::{Contact, ContactStore, IdentityType, MachineRecord, TrustLevel};
use x0x::identity::{AgentId, AgentKeypair, MachineId, MachineKeypair};
use x0x::trust::{TrustContext, TrustDecision, TrustEvaluator};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fresh_agent_id() -> AgentId {
    AgentKeypair::generate().unwrap().agent_id()
}

fn fresh_machine_id() -> MachineId {
    MachineKeypair::generate().unwrap().machine_id()
}

fn empty_store(dir: &TempDir) -> ContactStore {
    ContactStore::new(dir.path().join("contacts.json"))
}

fn store_with(dir: &TempDir, trust: TrustLevel, id_type: IdentityType) -> (ContactStore, AgentId) {
    let mut store = empty_store(dir);
    let aid = fresh_agent_id();
    store.add(Contact {
        agent_id: aid,
        trust_level: trust,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: id_type,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    (store, aid)
}

// ---------------------------------------------------------------------------
// Test 1: Unknown agent → Unknown decision
// ---------------------------------------------------------------------------

#[test]
fn unknown_agent_yields_unknown_decision() {
    let dir = TempDir::new().unwrap();
    let store = empty_store(&dir);
    let evaluator = TrustEvaluator::new(&store);
    let decision = evaluator.evaluate(&TrustContext {
        agent_id: &fresh_agent_id(),
        machine_id: &fresh_machine_id(),
    });
    assert_eq!(decision, TrustDecision::Unknown);
}

// ---------------------------------------------------------------------------
// Test 2: Blocked agent → RejectBlocked
// ---------------------------------------------------------------------------

#[test]
fn blocked_agent_yields_reject_blocked() {
    let dir = TempDir::new().unwrap();
    let (store, aid) = store_with(&dir, TrustLevel::Blocked, IdentityType::Anonymous);
    let evaluator = TrustEvaluator::new(&store);
    let decision = evaluator.evaluate(&TrustContext {
        agent_id: &aid,
        machine_id: &fresh_machine_id(),
    });
    assert_eq!(decision, TrustDecision::RejectBlocked);
}

// ---------------------------------------------------------------------------
// Test 3: Trusted agent (non-pinned) → Accept
// ---------------------------------------------------------------------------

#[test]
fn trusted_non_pinned_agent_yields_accept() {
    let dir = TempDir::new().unwrap();
    let (store, aid) = store_with(&dir, TrustLevel::Trusted, IdentityType::Trusted);
    let evaluator = TrustEvaluator::new(&store);
    let decision = evaluator.evaluate(&TrustContext {
        agent_id: &aid,
        machine_id: &fresh_machine_id(),
    });
    assert_eq!(decision, TrustDecision::Accept);
}

// ---------------------------------------------------------------------------
// Test 4: Known agent → AcceptWithFlag
// ---------------------------------------------------------------------------

#[test]
fn known_agent_yields_accept_with_flag() {
    let dir = TempDir::new().unwrap();
    let (store, aid) = store_with(&dir, TrustLevel::Known, IdentityType::Known);
    let evaluator = TrustEvaluator::new(&store);
    let decision = evaluator.evaluate(&TrustContext {
        agent_id: &aid,
        machine_id: &fresh_machine_id(),
    });
    assert_eq!(decision, TrustDecision::AcceptWithFlag);
}

// ---------------------------------------------------------------------------
// Test 5: Pinned agent with correct machine → Accept
// ---------------------------------------------------------------------------

#[test]
fn pinned_agent_correct_machine_yields_accept() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();
    let mid = fresh_machine_id();

    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid, Some("laptop".into())));
    store.pin_machine(&aid, &mid);

    let evaluator = TrustEvaluator::new(&store);
    let decision = evaluator.evaluate(&TrustContext {
        agent_id: &aid,
        machine_id: &mid,
    });
    assert_eq!(decision, TrustDecision::Accept);
}

// ---------------------------------------------------------------------------
// Test 6: Pinned agent with wrong machine → RejectMachineMismatch
// ---------------------------------------------------------------------------

#[test]
fn pinned_agent_wrong_machine_yields_reject_mismatch() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();
    let mid = fresh_machine_id();
    let other_mid = fresh_machine_id();

    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid, None));
    store.pin_machine(&aid, &mid);

    let evaluator = TrustEvaluator::new(&store);
    let decision = evaluator.evaluate(&TrustContext {
        agent_id: &aid,
        machine_id: &other_mid,
    });
    assert_eq!(decision, TrustDecision::RejectMachineMismatch);
}

// ---------------------------------------------------------------------------
// Test 7: Blocked check happens before machine pinning
// ---------------------------------------------------------------------------

#[test]
fn blocked_takes_priority_over_machine_mismatch() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();
    let mid = fresh_machine_id();
    let other_mid = fresh_machine_id();

    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Blocked,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid, None));
    store.pin_machine(&aid, &mid);

    let evaluator = TrustEvaluator::new(&store);
    let decision = evaluator.evaluate(&TrustContext {
        agent_id: &aid,
        machine_id: &other_mid, // wrong machine, but also blocked
    });
    assert_eq!(
        decision,
        TrustDecision::RejectBlocked,
        "blocked must take priority over machine mismatch"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Unpin a machine removes pinning constraint
// ---------------------------------------------------------------------------

#[test]
fn unpin_machine_removes_constraint() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();
    let mid = fresh_machine_id();

    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid, None));
    store.pin_machine(&aid, &mid);
    store.unpin_machine(&aid, &mid);

    // After unpinning, identity_type should no longer be Pinned
    // so any machine should be accepted based on trust level alone
    let evaluator = TrustEvaluator::new(&store);
    let different_mid = fresh_machine_id();
    let decision = evaluator.evaluate(&TrustContext {
        agent_id: &aid,
        machine_id: &different_mid,
    });
    // Should be Accept (Trusted level) since pinning was removed
    assert_eq!(
        decision,
        TrustDecision::Accept,
        "after unpinning, trust level should govern"
    );
}

// ---------------------------------------------------------------------------
// Test 9: Multiple machines, one pinned
// ---------------------------------------------------------------------------

#[test]
fn multiple_machines_only_one_pinned() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();
    let mid1 = fresh_machine_id();
    let mid2 = fresh_machine_id();

    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid1, Some("desktop".into())));
    store.add_machine(&aid, MachineRecord::new(mid2, Some("laptop".into())));
    // Only pin mid1
    store.pin_machine(&aid, &mid1);

    let evaluator = TrustEvaluator::new(&store);

    // mid1 is pinned → Accept
    assert_eq!(
        evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid1,
        }),
        TrustDecision::Accept
    );

    // mid2 is in the machine list but NOT pinned → RejectMachineMismatch
    // (because identity_type is now Pinned but mid2 doesn't have pinned: true)
    assert_eq!(
        evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid2,
        }),
        TrustDecision::RejectMachineMismatch
    );
}

// ---------------------------------------------------------------------------
// Test 10: set_trust updates trust level of existing contact
// ---------------------------------------------------------------------------

#[test]
fn set_trust_updates_existing_contact() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();

    // Start with Unknown
    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Unknown,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });

    {
        let evaluator = TrustEvaluator::new(&store);
        assert_eq!(
            evaluator.evaluate(&TrustContext {
                agent_id: &aid,
                machine_id: &fresh_machine_id(),
            }),
            TrustDecision::Unknown
        );
    }

    // Upgrade to Trusted
    store.set_trust(&aid, TrustLevel::Trusted);

    {
        let evaluator = TrustEvaluator::new(&store);
        assert_eq!(
            evaluator.evaluate(&TrustContext {
                agent_id: &aid,
                machine_id: &fresh_machine_id(),
            }),
            TrustDecision::Accept
        );
    }

    // Downgrade to Blocked
    store.set_trust(&aid, TrustLevel::Blocked);

    {
        let evaluator = TrustEvaluator::new(&store);
        assert_eq!(
            evaluator.evaluate(&TrustContext {
                agent_id: &aid,
                machine_id: &fresh_machine_id(),
            }),
            TrustDecision::RejectBlocked
        );
    }
}

// ---------------------------------------------------------------------------
// Test 11: ContactStore machines() accessor
// ---------------------------------------------------------------------------

#[test]
fn machines_accessor_returns_correct_records() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();
    let mid1 = fresh_machine_id();
    let mid2 = fresh_machine_id();

    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Known,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid1, None));
    store.add_machine(&aid, MachineRecord::new(mid2, Some("server".into())));

    let machines = store.machines(&aid);
    assert_eq!(machines.len(), 2);
    assert!(machines.iter().any(|m| m.machine_id == mid1));
    assert!(machines.iter().any(|m| m.machine_id == mid2));
}

// ---------------------------------------------------------------------------
// Test 12: remove_machine removes the correct record
// ---------------------------------------------------------------------------

#[test]
fn remove_machine_removes_correct_record() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();
    let mid1 = fresh_machine_id();
    let mid2 = fresh_machine_id();

    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid1, None));
    store.add_machine(&aid, MachineRecord::new(mid2, None));

    assert_eq!(store.machines(&aid).len(), 2);
    store.remove_machine(&aid, &mid1);
    assert_eq!(store.machines(&aid).len(), 1);
    assert_eq!(store.machines(&aid)[0].machine_id, mid2);
}

// ---------------------------------------------------------------------------
// Test 13: Removing the only pinned machine removes the pinning constraint
// ---------------------------------------------------------------------------

#[test]
fn remove_only_pinned_machine_removes_constraint() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();
    let mid = fresh_machine_id();

    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid, None));
    store.pin_machine(&aid, &mid);

    assert!(store.remove_machine(&aid, &mid));
    assert!(store.machines(&aid).is_empty());
    assert_eq!(
        store.get(&aid).map(|contact| contact.identity_type),
        Some(IdentityType::Known)
    );

    let evaluator = TrustEvaluator::new(&store);
    assert_eq!(
        evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &fresh_machine_id(),
        }),
        TrustDecision::Accept
    );
}

// ---------------------------------------------------------------------------
// Test 14: Removing one pinned machine keeps remaining pins constrained
// ---------------------------------------------------------------------------

#[test]
fn remove_one_pinned_machine_keeps_remaining_pin() {
    let dir = TempDir::new().unwrap();
    let mut store = empty_store(&dir);
    let aid = fresh_agent_id();
    let mid1 = fresh_machine_id();
    let mid2 = fresh_machine_id();

    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Trusted,
        label: None,
        added_at: 0,
        last_seen: None,
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid1, Some("desktop".into())));
    store.add_machine(&aid, MachineRecord::new(mid2, Some("laptop".into())));
    store.pin_machine(&aid, &mid1);
    store.pin_machine(&aid, &mid2);

    assert!(store.remove_machine(&aid, &mid1));
    let machines = store.machines(&aid);
    assert_eq!(machines.len(), 1);
    assert_eq!(machines[0].machine_id, mid2);
    assert!(machines[0].pinned);
    assert_eq!(
        store.get(&aid).map(|contact| contact.identity_type),
        Some(IdentityType::Pinned)
    );

    let evaluator = TrustEvaluator::new(&store);
    assert_eq!(
        evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid2,
        }),
        TrustDecision::Accept
    );
    assert_eq!(
        evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid1,
        }),
        TrustDecision::RejectMachineMismatch
    );
}

// ---------------------------------------------------------------------------
// Test 15: ContactStore in-memory state round-trip
// ---------------------------------------------------------------------------

#[test]
fn contact_store_in_memory_state_round_trip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("contacts.json");
    let aid = fresh_agent_id();
    let mid = fresh_machine_id();

    let mut store = ContactStore::new(path);

    // Add a trusted, pinned contact
    store.add(Contact {
        agent_id: aid,
        trust_level: TrustLevel::Trusted,
        label: Some("Alice".into()),
        added_at: 1_000,
        last_seen: Some(2_000),
        identity_type: IdentityType::Anonymous,
        machines: Vec::new(),
        dm_capabilities: None,
    });
    store.add_machine(&aid, MachineRecord::new(mid, Some("workstation".into())));
    store.pin_machine(&aid, &mid);

    // Verify in-memory state
    let contact = store.get(&aid).expect("contact should be present");
    assert_eq!(contact.trust_level, TrustLevel::Trusted);
    assert_eq!(contact.label.as_deref(), Some("Alice"));
    let machines = store.machines(&aid);
    assert_eq!(machines.len(), 1);
    assert_eq!(machines[0].machine_id, mid);
    assert!(machines[0].pinned, "machine should be pinned");
    assert_eq!(machines[0].label.as_deref(), Some("workstation"));
}
