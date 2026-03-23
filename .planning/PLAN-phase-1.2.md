# Phase 1.2 Plan: Flexible Trust Model

## Overview

Extend the contact/trust system so that trust is evaluated per
`(identity, machine)` pair with optional machine pinning. This enables
scenarios such as "trust this agent only when it runs on a specific
machine" or "I know this identity but haven't pinned a machine yet".

## Goal

- Add `MachineRecord` to track known machines per contact
- Add `IdentityType` enum (Anonymous, Known, Trusted, Pinned)
- Create `src/trust.rs` with `TrustEvaluator` that scores `(AgentId, MachineId)` pairs
- Update `ContactStore` to store machine records
- Update identity listener to use `TrustEvaluator`
- Expose new trust/contact fields through x0xd REST API
- All tests green, zero warnings

## Files

- `src/contacts.rs` — extend with MachineRecord, IdentityType, new ContactStore methods
- `src/trust.rs` — new: TrustEvaluator, TrustDecision, TrustContext
- `src/lib.rs` — expose trust module; use TrustEvaluator in identity listener
- `src/bin/x0xd.rs` — REST API: GET /contacts/:id/machines, POST /contacts/:id/machines, DELETE /contacts/:id/machines/:mid

---

## Tasks

### Task 1: Add IdentityType and MachineRecord to contacts.rs

**Files**: `src/contacts.rs`

**Description**:
Add two new types to the contacts module:

```rust
/// How strongly we identify and constrain this contact's machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityType {
    /// No machine information — agent is trusted regardless of machine.
    Anonymous,
    /// Machine seen but not pinned — accepted from any known machine.
    Known,
    /// Trusted identity; accepted from any trusted machine.
    Trusted,
    /// Pinned to specific machine(s) — only those machine_ids are accepted.
    Pinned,
}

/// A record of a known machine for a contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineRecord {
    /// Machine identity (SHA-256 of ML-DSA-65 public key).
    pub machine_id: crate::identity::MachineId,
    /// Human-readable label for this machine.
    pub label: Option<String>,
    /// Unix timestamp when first seen.
    pub first_seen: u64,
    /// Unix timestamp when last seen.
    pub last_seen: u64,
    /// Whether to reject messages from other machines for this contact.
    pub pinned: bool,
}
```

Extend `Contact` with:
```rust
pub identity_type: IdentityType,
pub machines: Vec<MachineRecord>,
```

Add `ContactStore` methods:
- `add_machine(agent_id, MachineRecord) -> bool` (true if new)
- `remove_machine(agent_id, machine_id) -> bool`
- `machines(agent_id) -> &[MachineRecord]`
- `pin_machine(agent_id, machine_id) -> bool`
- `unpin_machine(agent_id, machine_id) -> bool`

Update existing tests; add new unit tests for machine record operations.

**Estimated Lines**: ~120

---

### Task 2: Create src/trust.rs — TrustEvaluator

**Files**: `src/trust.rs` (new)

**Description**:
Create a `TrustEvaluator` that makes trust decisions for `(AgentId, MachineId)` pairs based on the `ContactStore`.

```rust
/// The outcome of a trust evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    /// Accept the message — identity and machine are trusted.
    Accept,
    /// Accept but flag — identity known, machine not pinned.
    AcceptWithFlag,
    /// Reject — machine pinning violated.
    RejectMachineMismatch,
    /// Reject — identity is blocked.
    RejectBlocked,
    /// Unknown sender — deliver with Unknown tag.
    Unknown,
}

/// Context for a trust evaluation.
pub struct TrustContext<'a> {
    pub agent_id: &'a crate::identity::AgentId,
    pub machine_id: &'a crate::identity::MachineId,
}

/// Evaluates trust for (identity, machine) pairs.
pub struct TrustEvaluator<'a> {
    store: &'a crate::contacts::ContactStore,
}

impl<'a> TrustEvaluator<'a> {
    pub fn new(store: &'a crate::contacts::ContactStore) -> Self;
    pub fn evaluate(&self, ctx: &TrustContext<'_>) -> TrustDecision;
}
```

Logic:
1. If blocked → `RejectBlocked`
2. If `IdentityType::Pinned` and machine not in pinned list → `RejectMachineMismatch`
3. If `IdentityType::Pinned` and machine matches → `Accept`
4. If `TrustLevel::Trusted` and machine is known → `Accept`
5. If `TrustLevel::Known` → `AcceptWithFlag`
6. If `TrustLevel::Unknown` → `Unknown`

Add comprehensive unit tests directly in the file.

**Estimated Lines**: ~130

---

### Task 3: Expose trust module in lib.rs

**Files**: `src/lib.rs`

**Description**:
- Add `pub mod trust;` declaration
- Import `trust::TrustEvaluator` and `trust::TrustDecision`
- Update identity listener (the gossip subscription that processes `IdentityAnnouncement`) to use `TrustEvaluator`:
  - Extract `machine_id` from announcement
  - Call `evaluator.evaluate(&TrustContext { agent_id, machine_id })`
  - If `RejectBlocked` or `RejectMachineMismatch` → skip announcement
  - If `Unknown` or `AcceptWithFlag` → insert into cache but add flag
- Add `machine_record` update: call `contact_store.add_machine()` whenever a valid announcement is received
- Update `Agent` struct to hold `Arc<RwLock<ContactStore>>` (replacing any direct field or making it accessible)

This requires `Agent` to carry a contact store. If one isn't present already, add:
```rust
contact_store: std::sync::Arc<tokio::sync::RwLock<crate::contacts::ContactStore>>,
```
and initialise in `AgentBuilder`.

**Estimated Lines**: ~80

---

### Task 4: Update x0xd REST API for machine records

**Files**: `src/bin/x0xd.rs`

**Description**:
Add three new REST endpoints for machine record management:

```
GET    /contacts/:agent_id/machines
       → 200 JSON array of MachineRecord

POST   /contacts/:agent_id/machines
       body: { "machine_id": "<hex>", "label": "...", "pinned": false }
       → 201 Created with MachineRecord

DELETE /contacts/:agent_id/machines/:machine_id
       → 204 No Content
```

Also update existing `PATCH /contacts/:agent_id` to accept optional `identity_type` field.

Add Axum handlers, register routes in `build_router()`.

**Estimated Lines**: ~100

---

### Task 5: Update serialization and persistence

**Files**: `src/contacts.rs`

**Description**:
The `ContactsFile` serialization format must be backward-compatible — existing files without `machines` or `identity_type` must load without error.

- Add `#[serde(default)]` to both new fields on `Contact`
- Add default implementations: `IdentityType::default() = Anonymous`
- Add `MachineRecord::new(machine_id, label) -> Self` convenience constructor
- Ensure the `save()` / `load()` cycle round-trips correctly

Write a persistence test that saves contacts with machine records and reloads them.

**Estimated Lines**: ~50

---

### Task 6: Integration test — trust evaluation round-trip

**Files**: `src/trust.rs` (existing tests), `src/contacts.rs` (existing tests)

**Description**:
Add an integration-level test that exercises the full flow:
1. Create a `ContactStore` with a trusted contact
2. Add a `MachineRecord` with `pinned: true`
3. Construct `TrustEvaluator` from the store
4. Evaluate — expect `Accept` for the pinned machine
5. Evaluate with a different machine_id — expect `RejectMachineMismatch`
6. Set contact to `Blocked`, evaluate — expect `RejectBlocked`
7. Evaluate an unknown agent — expect `Unknown`

Add the test in `src/trust.rs` under `#[cfg(test)]`.

**Estimated Lines**: ~60

---

## Summary

| Task | File(s) | Lines | Status |
|------|---------|-------|--------|
| 1 | contacts.rs | ~120 | TODO |
| 2 | trust.rs (new) | ~130 | TODO |
| 3 | lib.rs | ~80 | TODO |
| 4 | x0xd.rs | ~100 | TODO |
| 5 | contacts.rs | ~50 | TODO |
| 6 | trust.rs | ~60 | TODO |

**Total Tasks**: 6
**Total Estimated Lines**: ~540
