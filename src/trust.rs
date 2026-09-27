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
//! owner-trusted  → Accept          (ADR-0070 §1; only via `with_owner_trust`)
//! Trusted level  → Accept
//! Known level    → AcceptWithFlag
//! Unknown level  → Unknown
//! ```
//!
//! # Owner trust (ADR-0070 §1)
//!
//! The evaluator does not decide owner trust itself — that needs the
//! agent's certificate, the owner device set and the revocation set (see
//! [`crate::owner_trust`]). A caller that has established owner trust for
//! the pair passes it in with
//! [`TrustEvaluator::with_owner_trust`](crate::trust::TrustEvaluator::with_owner_trust).
//! Owner trust sits after the explicit denials (`Blocked`, machine-pin mismatch)
//! and before the contact-level rules, so it can never override a denial.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
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

impl TrustDecision {
    /// Apply the ADR-0070 §1 owner-trust input to a contact-derived decision.
    ///
    /// Owner trust ranks after revocation, `Blocked` and machine-pin
    /// mismatch, and before the contact-level rules: an owner-trusted pair
    /// yields [`TrustDecision::Accept`] where the contact rules gave
    /// [`TrustDecision::Unknown`] or [`TrustDecision::AcceptWithFlag`]. The
    /// two rejections are returned unchanged — owner trust never overrides an
    /// explicit local denial.
    #[must_use]
    pub fn with_owner_trust(self, owner_trusted: bool) -> Self {
        match self {
            Self::Unknown | Self::AcceptWithFlag if owner_trusted => Self::Accept,
            other => other,
        }
    }
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
    owner_trusted: bool,
}

impl<'a> TrustEvaluator<'a> {
    /// Create a new evaluator backed by the given contact store.
    #[must_use]
    pub fn new(store: &'a ContactStore) -> Self {
        Self {
            store,
            owner_trusted: false,
        }
    }

    /// Supply the ADR-0070 §1 owner-trust input for the pair being evaluated.
    ///
    /// `owner_trusted` must only be `true` when the caller has verified the
    /// pair against the local owner (see [`crate::owner_trust`]). It raises
    /// `Unknown`/`AcceptWithFlag` to `Accept` and never overrides `Blocked`
    /// or a machine-pin mismatch.
    #[must_use]
    pub fn with_owner_trust(mut self, owner_trusted: bool) -> Self {
        self.owner_trusted = owner_trusted;
        self
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
    /// 4. If owner-trusted ([`Self::with_owner_trust`]) → [`TrustDecision::Accept`]
    /// 5. If `TrustLevel::Trusted` → [`TrustDecision::Accept`]
    /// 6. If `TrustLevel::Known` → [`TrustDecision::AcceptWithFlag`]
    /// 7. Agent not in contact store → [`TrustDecision::Unknown`]
    pub fn evaluate(&self, ctx: &TrustContext<'_>) -> TrustDecision {
        self.evaluate_contact_rules(ctx)
            .with_owner_trust(self.owner_trusted)
    }

    /// The contact-store rules alone (1–3 and 5–7 of [`Self::evaluate`]).
    fn evaluate_contact_rules(&self, ctx: &TrustContext<'_>) -> TrustDecision {
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

        // Rule 5: trusted
        if contact.trust_level == TrustLevel::Trusted {
            return TrustDecision::Accept;
        }

        // Rule 6: known
        if contact.trust_level == TrustLevel::Known {
            return TrustDecision::AcceptWithFlag;
        }

        // Rule 7: unknown trust level (shouldn't reach here since Unknown is default,
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
            dm_capabilities: None,
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
            dm_capabilities: None,
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
            dm_capabilities: None,
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

    // ── ADR-0070 §1 owner trust ordering ──────────────────────────────────

    #[test]
    fn owner_trust_accepts_an_agent_with_no_contact_entry() {
        // WHY: R3 — an owner's own agents must be trusted with no contact
        // edits; without the owner input the same pair stays Unknown.
        let dir = tempfile::tempdir().expect("tmpdir");
        let store = ContactStore::new(dir.path().join("contacts.json"));
        let aid = agent_id();
        let mid = machine_id();
        let ctx = TrustContext {
            agent_id: &aid,
            machine_id: &mid,
        };
        assert_eq!(
            TrustEvaluator::new(&store).evaluate(&ctx),
            TrustDecision::Unknown
        );
        assert_eq!(
            TrustEvaluator::new(&store)
                .with_owner_trust(true)
                .evaluate(&ctx),
            TrustDecision::Accept
        );
    }

    #[test]
    fn owner_trust_ranks_before_contact_rules() {
        // WHY: ADR-0070 orders owner trust before the existing contact rules,
        // so a Known contact that is also owner-trusted is a full Accept.
        let (store, aid) = store_with_contact(TrustLevel::Known, IdentityType::Known);
        let mid = machine_id();
        let ctx = TrustContext {
            agent_id: &aid,
            machine_id: &mid,
        };
        assert_eq!(
            TrustEvaluator::new(&store)
                .with_owner_trust(true)
                .evaluate(&ctx),
            TrustDecision::Accept
        );
    }

    #[test]
    fn blocked_beats_owner_trust() {
        // WHY: an explicit local denial always wins over owner trust. If the
        // owner input were checked before Blocked this would return Accept.
        let (store, aid) = store_with_contact(TrustLevel::Blocked, IdentityType::Anonymous);
        let mid = machine_id();
        assert_eq!(
            TrustEvaluator::new(&store)
                .with_owner_trust(true)
                .evaluate(&TrustContext {
                    agent_id: &aid,
                    machine_id: &mid,
                }),
            TrustDecision::RejectBlocked
        );
    }

    #[test]
    fn machine_pin_mismatch_beats_owner_trust() {
        // WHY: a contact pinned to other machines is an explicit denial for
        // this machine; owner trust must not reopen it.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut store = ContactStore::new(dir.path().join("contacts.json"));
        let aid = agent_id();
        let pinned = machine_id();
        let other = machine_id();
        store.set_trust(&aid, TrustLevel::Trusted);
        store.add_machine(&aid, MachineRecord::new(pinned, None));
        store.pin_machine(&aid, &pinned);
        assert_eq!(
            TrustEvaluator::new(&store)
                .with_owner_trust(true)
                .evaluate(&TrustContext {
                    agent_id: &aid,
                    machine_id: &other,
                }),
            TrustDecision::RejectMachineMismatch
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
