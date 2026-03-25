//! Trust evaluation for (identity, machine) pairs.
//!
//! The `TrustEvaluator` combines an agent's trust level with its
//! identity type and machine records to produce a `TrustDecision`.
//!
//! # Machine Pinning
//!
//! When an agent's identity type is `Pinned`, only messages
//! originating from machine IDs that appear in the contact's machine list with
//! `pinned: true` are accepted. Any other machine identity results in
//! `TrustDecision::RejectMachineMismatch`.
//!
//! # Trust Decision Flow
//!
//! ```text
//! blocked?       → RejectBlocked
//! pinned + wrong machine → RejectMachineMismatch
//! pinned + right machine → Accept
//! Trusted level  → Accept
//! Known level    → AcceptWithFlag
//! Unknown level  → Unknown
//! ```
//!
//! # Example
//!
//! ```rust
//! use x0x::trust::{TrustContext, TrustDecision, TrustEvaluator};
//! use x0x::contacts::ContactStore;
//! use std::path::PathBuf;
//!
//! let store = ContactStore::new(PathBuf::from("/tmp/test-contacts.json"));
//! let evaluator = TrustEvaluator::new(&store);
//! ```

use crate::contacts::{ContactStore, IdentityType, TrustLevel};
use crate::identity::{AgentId, MachineId};

/// The outcome of a trust evaluation for a `(AgentId, MachineId)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    /// Accept the message — identity and machine are trusted.
    Accept,
    /// Accept but flag — identity is known/trusted, but machine is not pinned
    /// (or we have no machine constraint for this contact).
    AcceptWithFlag,
    /// Reject — the contact is pinned to specific machines and this one is not in the list.
    RejectMachineMismatch,
    /// Reject — the identity is explicitly blocked.
    RejectBlocked,
    /// Unknown sender — deliver with an unknown tag; the consumer decides.
    Unknown,
}

impl std::fmt::Display for TrustDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::AcceptWithFlag => write!(f, "accept_with_flag"),
            Self::RejectMachineMismatch => write!(f, "reject_machine_mismatch"),
            Self::RejectBlocked => write!(f, "reject_blocked"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Context for a trust evaluation.
///
/// Carries the agent and machine identities extracted from an incoming
/// [`crate::IdentityAnnouncement`] or message.
#[derive(Debug, Clone, Copy)]
pub struct TrustContext<'a> {
    /// The portable agent identity of the sender.
    pub agent_id: &'a AgentId,
    /// The machine identity of the sending daemon.
    pub machine_id: &'a MachineId,
}

/// Evaluates trust for `(AgentId, MachineId)` pairs against a `ContactStore`.
///
/// The evaluator is cheap to construct — it borrows the store for the duration
/// of the evaluation.
pub struct TrustEvaluator<'a> {
    store: &'a ContactStore,
}

impl<'a> TrustEvaluator<'a> {
    /// Create a new evaluator backed by the given contact store.
    #[must_use]
    pub fn new(store: &'a ContactStore) -> Self {
        Self { store }
    }

    /// Evaluate trust for the given `(agent_id, machine_id)` pair.
    ///
    /// # Decision Rules
    ///
    /// 1. If the agent is blocked → [`TrustDecision::RejectBlocked`]
    /// 2. If `IdentityType::Pinned` and machine is NOT in the pinned list
    ///    → [`TrustDecision::RejectMachineMismatch`]
    /// 3. If `IdentityType::Pinned` and machine IS in the pinned list
    ///    → [`TrustDecision::Accept`]
    /// 4. If `TrustLevel::Trusted` → [`TrustDecision::Accept`]
    /// 5. If `TrustLevel::Known` → [`TrustDecision::AcceptWithFlag`]
    /// 6. Agent not in contact store → [`TrustDecision::Unknown`]
    pub fn evaluate(&self, ctx: &TrustContext<'_>) -> TrustDecision {
        let contact = match self.store.get(ctx.agent_id) {
            Some(c) => c,
            None => return TrustDecision::Unknown,
        };

        // Rule 1: blocked
        if contact.trust_level == TrustLevel::Blocked {
            return TrustDecision::RejectBlocked;
        }

        // Rules 2-3: machine pinning
        if contact.identity_type == IdentityType::Pinned {
            let is_pinned_machine = contact
                .machines
                .iter()
                .any(|m| m.machine_id == *ctx.machine_id && m.pinned);

            if is_pinned_machine {
                return TrustDecision::Accept;
            } else {
                return TrustDecision::RejectMachineMismatch;
            }
        }

        // Rule 4: trusted
        if contact.trust_level == TrustLevel::Trusted {
            return TrustDecision::Accept;
        }

        // Rule 5: known
        if contact.trust_level == TrustLevel::Known {
            return TrustDecision::AcceptWithFlag;
        }

        // Rule 6: unknown trust level (shouldn't reach here since Unknown is default,
        // but handle it for completeness)
        TrustDecision::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::{Contact, ContactStore, IdentityType, MachineRecord, TrustLevel};
    use crate::identity::{AgentKeypair, MachineKeypair};

    fn agent_id() -> AgentId {
        AgentKeypair::generate().expect("keygen").agent_id()
    }

    fn machine_id() -> MachineId {
        MachineKeypair::generate().expect("keygen").machine_id()
    }

    fn store_with_contact(trust: TrustLevel, id_type: IdentityType) -> (ContactStore, AgentId) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));
        let aid = agent_id();
        store.add(Contact {
            agent_id: aid,
            trust_level: trust,
            label: None,
            added_at: 0,
            last_seen: None,
            identity_type: id_type,
            machines: Vec::new(),
        });
        (store, aid)
    }

    // ── basic trust level tests ────────────────────────────────────────────

    #[test]
    fn unknown_agent_returns_unknown() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = ContactStore::new(dir.path().join("contacts.json"));
        let evaluator = TrustEvaluator::new(&store);
        let aid = agent_id();
        let mid = machine_id();
        let decision = evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid,
        });
        assert_eq!(decision, TrustDecision::Unknown);
    }

    #[test]
    fn blocked_agent_returns_reject_blocked() {
        let (store, aid) = store_with_contact(TrustLevel::Blocked, IdentityType::Anonymous);
        let evaluator = TrustEvaluator::new(&store);
        let mid = machine_id();
        let decision = evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid,
        });
        assert_eq!(decision, TrustDecision::RejectBlocked);
    }

    #[test]
    fn trusted_non_pinned_returns_accept() {
        let (store, aid) = store_with_contact(TrustLevel::Trusted, IdentityType::Trusted);
        let evaluator = TrustEvaluator::new(&store);
        let mid = machine_id();
        let decision = evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid,
        });
        assert_eq!(decision, TrustDecision::Accept);
    }

    #[test]
    fn known_agent_returns_accept_with_flag() {
        let (store, aid) = store_with_contact(TrustLevel::Known, IdentityType::Known);
        let evaluator = TrustEvaluator::new(&store);
        let mid = machine_id();
        let decision = evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid,
        });
        assert_eq!(decision, TrustDecision::AcceptWithFlag);
    }

    #[test]
    fn unknown_trust_level_returns_unknown() {
        let (store, aid) = store_with_contact(TrustLevel::Unknown, IdentityType::Anonymous);
        let evaluator = TrustEvaluator::new(&store);
        let mid = machine_id();
        let decision = evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid,
        });
        assert_eq!(decision, TrustDecision::Unknown);
    }

    // ── machine pinning tests ─────────────────────────────────────────────

    #[test]
    fn pinned_correct_machine_returns_accept() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));
        let aid = agent_id();
        let mid = machine_id();

        store.add(Contact {
            agent_id: aid,
            trust_level: TrustLevel::Trusted,
            label: None,
            added_at: 0,
            last_seen: None,
            identity_type: IdentityType::Anonymous,
            machines: Vec::new(),
        });
        store.add_machine(&aid, MachineRecord::new(mid, None));
        store.pin_machine(&aid, &mid);

        let evaluator = TrustEvaluator::new(&store);
        let decision = evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &mid,
        });
        assert_eq!(decision, TrustDecision::Accept);
    }

    #[test]
    fn pinned_wrong_machine_returns_reject_mismatch() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));
        let aid = agent_id();
        let mid = machine_id();
        let other_mid = machine_id();

        store.add(Contact {
            agent_id: aid,
            trust_level: TrustLevel::Trusted,
            label: None,
            added_at: 0,
            last_seen: None,
            identity_type: IdentityType::Anonymous,
            machines: Vec::new(),
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

    #[test]
    fn blocked_pinned_agent_returns_reject_blocked_not_machine_mismatch() {
        // Blocked check happens before machine pinning check
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));
        let aid = agent_id();
        let mid = machine_id();
        let other_mid = machine_id();

        store.add(Contact {
            agent_id: aid,
            trust_level: TrustLevel::Blocked,
            label: None,
            added_at: 0,
            last_seen: None,
            identity_type: IdentityType::Anonymous,
            machines: Vec::new(),
        });
        store.add_machine(&aid, MachineRecord::new(mid, None));
        store.pin_machine(&aid, &mid);

        let evaluator = TrustEvaluator::new(&store);
        // Even though machine doesn't match, blocked takes priority
        let decision = evaluator.evaluate(&TrustContext {
            agent_id: &aid,
            machine_id: &other_mid,
        });
        assert_eq!(decision, TrustDecision::RejectBlocked);
    }

    // ── integration round-trip ────────────────────────────────────────────

    #[test]
    fn full_trust_round_trip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));
        let aid = agent_id();
        let mid = machine_id();
        let other_mid = machine_id();

        // 1. Add trusted contact
        store.set_trust(&aid, TrustLevel::Trusted);

        // 2. Add machine record with pinned: true
        store.add_machine(&aid, MachineRecord::new(mid, Some("laptop".into())));
        store.pin_machine(&aid, &mid);

        let evaluator = TrustEvaluator::new(&store);

        // 3. Evaluate — expect Accept for the pinned machine
        assert_eq!(
            evaluator.evaluate(&TrustContext {
                agent_id: &aid,
                machine_id: &mid,
            }),
            TrustDecision::Accept
        );

        // 4. Evaluate with a different machine — expect RejectMachineMismatch
        assert_eq!(
            evaluator.evaluate(&TrustContext {
                agent_id: &aid,
                machine_id: &other_mid,
            }),
            TrustDecision::RejectMachineMismatch
        );

        // 5. Block the contact and re-evaluate — expect RejectBlocked
        store.set_trust(&aid, TrustLevel::Blocked);
        let evaluator = TrustEvaluator::new(&store);
        assert_eq!(
            evaluator.evaluate(&TrustContext {
                agent_id: &aid,
                machine_id: &mid,
            }),
            TrustDecision::RejectBlocked
        );

        // 6. Evaluate an entirely unknown agent — expect Unknown
        let unknown_aid = agent_id();
        let unknown_mid = machine_id();
        let evaluator = TrustEvaluator::new(&store);
        assert_eq!(
            evaluator.evaluate(&TrustContext {
                agent_id: &unknown_aid,
                machine_id: &unknown_mid,
            }),
            TrustDecision::Unknown
        );
    }

    #[test]
    fn trust_decision_display() {
        assert_eq!(TrustDecision::Accept.to_string(), "accept");
        assert_eq!(
            TrustDecision::AcceptWithFlag.to_string(),
            "accept_with_flag"
        );
        assert_eq!(
            TrustDecision::RejectMachineMismatch.to_string(),
            "reject_machine_mismatch"
        );
        assert_eq!(TrustDecision::RejectBlocked.to_string(), "reject_blocked");
        assert_eq!(TrustDecision::Unknown.to_string(), "unknown");
    }
}
