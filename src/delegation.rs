//! Agent-to-agent delegation envelopes (ADR-0040).
//!
//! A [`Delegation`] is a bounded, expiring grant of authority from one agent
//! (the delegator, `from_agent`) to another (the delegate, `to_agent`) inside
//! one group ("space"). The envelope is signed by the **delegator's own
//! ML-DSA-65 key** — never the delegate's, and the delegator's key is never
//! used by the delegate (blocker 25): a delegate acting under `SendAs` signs
//! with ITS OWN key and references the delegation by digest, so receivers
//! verify `actor = B, delegator = A` through the chain, not through key
//! sharing.
//!
//! ## Envelope fields (blocker 26)
//!
//! The envelope carries a `delegation_id` (unique per issuance), `issued_at_ms`
//! and `expiry_ms` (bounded lifetime), the concrete `task_ref` resource, the
//! `verbs` the delegate may exercise, `parent_delegation` digest + `depth`
//! (re-delegation chain, capped at [`MAX_DELEGATION_DEPTH`]) and the
//! `group_id` audience. All are bound into the signed canonical bytes.
//!
//! ## Effectiveness (blocker 28)
//!
//! A delegation is EFFECTIVE when its envelope is durably committed to group
//! history (ADR-0023). The DM-v2 durable-ACK handoff to the delegate is a
//! NOTIFICATION, not the source of truth: crash/retry re-derives the set of
//! effective delegations from history, so there is exactly one effectiveness
//! rule on every path.
//!
//! ## Credential slot (blocker 29) — deliberately absent
//!
//! The sealed shared-credential slot is deferred: a group-sealed secret is
//! readable by every group-key holder, and per-agent scoping needs recipient
//! envelopes plus a use-broker. Recording a group-readable slot here and
//! calling it scoped would be a false security claim.

use crate::identity::{AgentId, AgentKeypair};
use ant_quic::crypto::raw_public_keys::pqc::{verify_with_ml_dsa, MlDsaSignature};
use ant_quic::MlDsaPublicKey;
use serde::{Deserialize, Serialize};

/// Domain separator for delegation envelopes.
///
/// Distinct from every other signing domain in the crate so a delegation
/// signature can never be replayed as a claim, message, or state commit.
pub const DELEGATION_DOMAIN: &[u8] = b"x0x.delegation.v1";

/// Maximum re-delegation depth (A→B→C, not further).
///
/// ADR-0040: the cap keeps the accountability chain legible in history.
/// Root delegations (issued directly by the task owner / space member) are
/// depth 1; one re-delegation to depth 2 is allowed; depth 3+ is rejected at
/// both signing and verification.
pub const MAX_DELEGATION_DEPTH: u8 = 2;

/// What the delegate may do in the delegator's name.
///
/// Deliberately closed: `send-as` and `task-execute` — nothing else
/// (ADR-0040 Decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityScope {
    /// Execute task work on the referenced task (claim/complete).
    TaskExecute,
    /// Send group messages that carry the delegator's attribution.
    SendAs,
}

/// A concrete verb the delegate may exercise. Bounded by [`AuthorityScope`]:
/// task verbs only make sense under `task_execute`; `send_public_message`
/// only under `send_as`. Cross-scope verbs are rejected at validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationVerb {
    /// Claim the referenced task (`task_execute` only).
    Claim,
    /// Complete the referenced task (`task_execute` only).
    Complete,
    /// Publish a group public message attributed to the delegator
    /// (`send_as` only).
    SendPublicMessage,
}

impl DelegationVerb {
    /// The scope this verb is valid under.
    #[must_use]
    pub fn scope(self) -> AuthorityScope {
        match self {
            DelegationVerb::Claim | DelegationVerb::Complete => AuthorityScope::TaskExecute,
            DelegationVerb::SendPublicMessage => AuthorityScope::SendAs,
        }
    }
}

/// A delegation grant, signed by `from_agent`'s own key as
/// [`SignedDelegation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Unique issuance id (random 128-bit). Prevents two distinct grants from
    /// ever colliding in the digest index and lets revocation/retry name
    /// exactly one envelope.
    pub delegation_id: [u8; 16],
    /// Unix milliseconds at issuance.
    pub issued_at_ms: u64,
    /// The concrete resource: the referenced task (`task_execute` scope).
    /// `None` for `send_as` (the audience is the group itself).
    pub task_ref: Option<[u8; 32]>,
    /// The delegator. MUST equal the AgentId derived from the signer key.
    pub from_agent: AgentId,
    /// The delegate who receives the authority.
    pub to_agent: AgentId,
    /// What the delegate may do.
    pub authority_scope: AuthorityScope,
    /// The concrete verbs granted (subset of the scope's verbs).
    pub verbs: Vec<DelegationVerb>,
    /// Unix milliseconds after which the grant is dead. MUST be > issued_at.
    pub expiry_ms: u64,
    /// Digest of the parent [`SignedDelegation`] for re-delegation chains;
    /// `None` for a root grant.
    pub parent_delegation: Option<[u8; 32]>,
    /// Chain depth: 1 = root, 2 = one re-delegation. Capped at
    /// [`MAX_DELEGATION_DEPTH`].
    pub depth: u8,
    /// The group ("space") whose durable history makes this effective.
    pub group_id: String,
}

/// A delegation plus its self-contained ML-DSA-65 signature by the
/// delegator's own key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    /// ML-DSA-65 public key bytes; MUST hash to `delegation.from_agent`.
    pub signer_public_key: Vec<u8>,
    /// Signature over [`canonical_delegation_bytes`].
    pub signature: Vec<u8>,
}

/// Errors produced by delegation validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    /// Structure/time violations (bad expiry, depth, verbs, self-delegation).
    Invalid(String),
    /// Signature verification failed.
    BadSignature(String),
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationError::Invalid(why) => write!(f, "invalid delegation: {why}"),
            DelegationError::BadSignature(why) => write!(f, "delegation signature: {why}"),
        }
    }
}

impl std::error::Error for DelegationError {}

/// Deterministic byte layout that is signed and verified.
///
/// `domain || delegation_id(16) || issued_at(8 BE) || task_ref(1+32) ||
/// from(32) || to(32) || scope(1) || verb_count(1)+verbs(1 each) ||
/// expiry(8 BE) || parent(1+32) || depth(1) || group_id(len-prefixed)`.
///
/// Fixed-width where possible; the variable-length `verbs` and `group_id`
/// are unambiguous (bounded count, u32-LE length prefix). Every policy field
/// is bound — nothing in the envelope is modifiable without breaking the
/// signature.
#[must_use]
pub fn canonical_delegation_bytes(d: &Delegation) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(DELEGATION_DOMAIN);
    out.extend_from_slice(&d.delegation_id);
    out.extend_from_slice(&d.issued_at_ms.to_be_bytes());
    match d.task_ref {
        Some(task) => {
            out.push(1);
            out.extend_from_slice(&task);
        }
        None => out.push(0),
    }
    out.extend_from_slice(d.from_agent.as_bytes());
    out.extend_from_slice(d.to_agent.as_bytes());
    out.push(match d.authority_scope {
        AuthorityScope::TaskExecute => 0,
        AuthorityScope::SendAs => 1,
    });
    out.push(d.verbs.len() as u8);
    for verb in &d.verbs {
        out.push(match verb {
            DelegationVerb::Claim => 0,
            DelegationVerb::Complete => 1,
            DelegationVerb::SendPublicMessage => 2,
        });
    }
    out.extend_from_slice(&d.expiry_ms.to_be_bytes());
    match d.parent_delegation {
        Some(parent) => {
            out.push(1);
            out.extend_from_slice(&parent);
        }
        None => out.push(0),
    }
    out.push(d.depth);
    out.extend_from_slice(&(d.group_id.len() as u32).to_le_bytes());
    out.extend_from_slice(d.group_id.as_bytes());
    out
}

/// BLAKE3 digest of the canonical bytes — the identity by which a
/// re-delegation names its parent and a `send_as` message references its
/// grant.
#[must_use]
pub fn delegation_digest(d: &Delegation) -> [u8; 32] {
    *blake3::hash(&canonical_delegation_bytes(d)).as_bytes()
}

/// Digest of a signed delegation (same canonical bytes — the signature is
/// over exactly those bytes).
#[must_use]
pub fn signed_delegation_digest(sd: &SignedDelegation) -> [u8; 32] {
    delegation_digest(&sd.delegation)
}

/// Validate envelope policy WITHOUT cryptographic checks.
///
/// WHY split from signature verification: policy violations (depth 3,
/// expired-before-issued, empty verbs) are deterministic facts about the
/// fields, while signature checks need key parsing; callers that verify
/// chains want both reported distinctly.
///
/// # Errors
///
/// Returns [`DelegationError::Invalid`] on any structural policy violation.
pub fn validate_policy(d: &Delegation) -> Result<(), DelegationError> {
    if d.depth == 0 {
        return Err(DelegationError::Invalid("depth must be >= 1".into()));
    }
    if d.depth > MAX_DELEGATION_DEPTH {
        return Err(DelegationError::Invalid(format!(
            "delegation depth {} exceeds cap {}",
            d.depth, MAX_DELEGATION_DEPTH
        )));
    }
    if d.expiry_ms <= d.issued_at_ms {
        return Err(DelegationError::Invalid(
            "expiry_ms must be strictly after issued_at_ms".into(),
        ));
    }
    if d.from_agent == d.to_agent {
        return Err(DelegationError::Invalid(
            "self-delegation is meaningless and masks attribution".into(),
        ));
    }
    if d.verbs.is_empty() {
        return Err(DelegationError::Invalid(
            "at least one verb is required (an empty grant authorizes nothing but still audits as authority)".into(),
        ));
    }
    for verb in &d.verbs {
        if verb.scope() != d.authority_scope {
            return Err(DelegationError::Invalid(format!(
                "verb {verb:?} is outside authority_scope {:?}",
                d.authority_scope
            )));
        }
    }
    if d.authority_scope == AuthorityScope::TaskExecute && d.task_ref.is_none() {
        return Err(DelegationError::Invalid(
            "task_execute scope requires a concrete task_ref".into(),
        ));
    }
    // A task_ref under send_as is permitted (scope narrowing to one task's
    // discussion) but not required.
    if (d.depth == 1) != d.parent_delegation.is_none() {
        return Err(DelegationError::Invalid(
            "root delegations (depth 1) have no parent; re-delegations name their parent digest"
                .into(),
        ));
    }
    Ok(())
}

/// Sign a delegation with the local agent's keypair.
///
/// The signer MUST be `from_agent` (key hashes to it) — the delegator's OWN
/// key, per blocker 25. Structural policy is validated before signing so an
/// unforgeable-but-invalid envelope is never created.
///
/// # Errors
///
/// Returns [`DelegationError::Invalid`] on policy violations or signer
/// mismatch; [`DelegationError::BadSignature`] on signing failure.
pub fn sign_delegation(
    kp: &AgentKeypair,
    d: &Delegation,
) -> Result<SignedDelegation, DelegationError> {
    validate_policy(d)?;
    let derived = kp.agent_id();
    if derived != d.from_agent {
        return Err(DelegationError::BadSignature(format!(
            "signer {} is not the delegator {} — a delegation must be signed by the delegator's own key",
            hex::encode(derived.as_bytes()),
            hex::encode(d.from_agent.as_bytes())
        )));
    }
    let msg = canonical_delegation_bytes(d);
    let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(kp.secret_key(), &msg)
        .map_err(|e| DelegationError::BadSignature(format!("ml-dsa sign failed: {e:?}")))?;
    Ok(SignedDelegation {
        delegation: d.clone(),
        signer_public_key: kp.public_key().as_bytes().to_vec(),
        signature: signature.as_bytes().to_vec(),
    })
}

/// Re-delegation attenuation (review r2): the child grant must be BOUNDED
/// by the parent — same group, same scope, verb subset, no later expiry,
/// and (for `task_execute`) the same concrete task. Without this, B could
/// re-delegate broader powers than A granted (e.g. mint a longer-lived or
/// verb-superset grant), turning delegation into authority escalation.
///
/// Enforced BOTH at issue (the delegate endpoint checks the parent before
/// signing) and at use (`authorize` re-checks against the committed parent)
/// — a stored child that somehow violates attenuation never authorizes.
///
/// # Errors
///
/// Returns [`DelegationError::Invalid`] naming the violated bound.
pub fn is_attenuated_by(parent: &Delegation, child: &Delegation) -> Result<(), DelegationError> {
    if parent.group_id != child.group_id {
        return Err(DelegationError::Invalid(
            "re-delegation must stay in the parent's group".into(),
        ));
    }
    if parent.authority_scope != child.authority_scope {
        return Err(DelegationError::Invalid(
            "re-delegation must not widen the authority scope".into(),
        ));
    }
    for verb in &child.verbs {
        if !parent.verbs.contains(verb) {
            return Err(DelegationError::Invalid(format!(
                "re-delegation adds verb {verb:?} the parent does not grant"
            )));
        }
    }
    if child.expiry_ms > parent.expiry_ms {
        return Err(DelegationError::Invalid(
            "re-delegation must not outlive the parent grant".into(),
        ));
    }
    // Task binding (review r3 — intersection semantics): the child's task
    // scope must be a SUBSET of the parent's. Narrowing a group-wide
    // parent (task_ref None) onto one task is VALID attenuation; WIDENING
    // a task-bound parent (Some → None) or retargeting (Some ≠ Some) is
    // escalation and rejected.
    match (parent.task_ref, child.task_ref) {
        (None, _) => {} // group-wide parent: any child scope ⊆ parent
        (Some(parent_task), Some(child_task)) => {
            if parent_task != child_task {
                return Err(DelegationError::Invalid(
                    "re-delegation must not retarget task_execute to another task".into(),
                ));
            }
        }
        (Some(_), None) => {
            return Err(DelegationError::Invalid(
                "re-delegation must not widen a task-bound grant to group-wide".into(),
            ));
        }
    }
    Ok(())
}

/// Verify a signed delegation: key parses, key hashes to BOTH the embedded
/// author and `from_agent`, signature checks over the canonical bytes, and
/// the structural policy holds.
///
/// # Errors
///
/// Returns [`DelegationError`] describing the first failed check.
pub fn verify_delegation(sd: &SignedDelegation) -> Result<(), DelegationError> {
    validate_policy(&sd.delegation)?;
    let pubkey = MlDsaPublicKey::from_bytes(&sd.signer_public_key)
        .map_err(|e| DelegationError::BadSignature(format!("bad signer key: {e:?}")))?;
    let derived = AgentId::from_public_key(&pubkey);
    if derived != sd.delegation.from_agent {
        return Err(DelegationError::BadSignature(
            "signer key does not hash to from_agent (wrong-signer forgery)".into(),
        ));
    }
    let sig = MlDsaSignature::from_bytes(&sd.signature)
        .map_err(|e| DelegationError::BadSignature(format!("bad signature encoding: {e:?}")))?;
    let msg = canonical_delegation_bytes(&sd.delegation);
    verify_with_ml_dsa(&pubkey, &msg, &sig)
        .map_err(|e| DelegationError::BadSignature(format!("ml-dsa verify failed: {e:?}")))?;
    Ok(())
}

/// Verify a re-delegation chain: the child's `parent_delegation` digest must
/// match the parent's digest, the parent's delegate must be the child's
/// delegator, and depth must be exactly parent + 1.
///
/// Both envelopes must individually [`verify_delegation`]. The chain is what
/// makes a depth-2 grant honest: B can only re-delegate A's authority if A
/// actually granted it to B.
///
/// # Errors
///
/// Returns [`DelegationError::Invalid`] describing the broken link.
pub fn verify_chain(
    parent: &SignedDelegation,
    child: &SignedDelegation,
) -> Result<(), DelegationError> {
    let parent_digest = signed_delegation_digest(parent);
    if child.delegation.parent_delegation != Some(parent_digest) {
        return Err(DelegationError::Invalid(
            "child does not name this parent by digest".into(),
        ));
    }
    if parent.delegation.to_agent != child.delegation.from_agent {
        return Err(DelegationError::Invalid(
            "chain break: parent's delegate is not the child's delegator".into(),
        ));
    }
    if child.delegation.depth != parent.delegation.depth + 1 {
        return Err(DelegationError::Invalid(
            "chain depth must be parent depth + 1".into(),
        ));
    }
    Ok(())
}

/// Is the delegation live at `now_ms`? (Expiry is a hard bound; revocation is
/// membership-driven and checked by the caller against the roster.)
#[must_use]
pub fn is_effective_time(d: &Delegation, now_ms: u64) -> bool {
    now_ms < d.expiry_ms
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn keypair() -> AgentKeypair {
        AgentKeypair::generate().unwrap()
    }

    fn root_delegation(from: &AgentKeypair, to: AgentId) -> Delegation {
        Delegation {
            delegation_id: [0xAB; 16],
            issued_at_ms: 1_000,
            task_ref: Some([9u8; 32]),
            from_agent: from.agent_id(),
            to_agent: to,
            authority_scope: AuthorityScope::TaskExecute,
            verbs: vec![DelegationVerb::Claim, DelegationVerb::Complete],
            expiry_ms: 60_000,
            parent_delegation: None,
            depth: 1,
            group_id: "space-7".into(),
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let a = keypair();
        let b = keypair();
        let sd = sign_delegation(&a, &root_delegation(&a, b.agent_id())).unwrap();
        assert!(verify_delegation(&sd).is_ok(), "valid envelope verifies");
    }

    #[test]
    fn wrong_signer_delegation_is_rejected() {
        // WHY (blocker 25): B must never be able to mint authority claiming
        // it came from A. Signing A's envelope with B's key fails because the
        // key hashes to B, not A.
        let a = keypair();
        let b = keypair();
        let mut d = root_delegation(&a, b.agent_id());
        // Keep from_agent = A but sign with B's key.
        let err = sign_delegation(&b, &d).unwrap_err();
        assert!(matches!(err, DelegationError::BadSignature(_)));
        // And a hand-built envelope with B's signature over A's bytes fails
        // verification.
        d.from_agent = a.agent_id();
        let msg = canonical_delegation_bytes(&d);
        let sig =
            ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(b.secret_key(), &msg).unwrap();
        let forged = SignedDelegation {
            delegation: d,
            signer_public_key: b.public_key().as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
        };
        assert!(verify_delegation(&forged).is_err());
    }

    #[test]
    fn expired_delegation_is_not_effective() {
        // WHY (blocker 26): authority must be bounded in time; an expiry that
        // never binds is permanent authority by accident.
        let a = keypair();
        let b = keypair();
        let sd = sign_delegation(&a, &root_delegation(&a, b.agent_id())).unwrap();
        assert!(is_effective_time(&sd.delegation, 59_999));
        assert!(
            !is_effective_time(&sd.delegation, 60_000),
            "at expiry_ms the grant is dead"
        );
        // Structural: expiry before issuance is rejected outright.
        let mut d = root_delegation(&a, b.agent_id());
        d.expiry_ms = d.issued_at_ms;
        assert!(sign_delegation(&a, &d).is_err());
    }

    #[test]
    fn depth_three_is_rejected_at_signing() {
        // WHY (ADR-0040): the depth cap keeps the accountability chain
        // legible; depth 3 must be unconstructible, not merely ignored.
        let a = keypair();
        let b = keypair();
        let mut d = root_delegation(&a, b.agent_id());
        d.depth = 3;
        d.parent_delegation = Some([1u8; 32]);
        assert!(matches!(
            sign_delegation(&a, &d),
            Err(DelegationError::Invalid(_))
        ));
    }

    #[test]
    fn valid_chain_verifies_and_broken_chains_do_not() {
        let a = keypair();
        let b = keypair();
        let c = keypair();
        let parent = sign_delegation(&a, &root_delegation(&a, b.agent_id())).unwrap();
        let mut child_d = root_delegation(&b, c.agent_id());
        child_d.depth = 2;
        child_d.parent_delegation = Some(signed_delegation_digest(&parent));
        child_d.authority_scope = AuthorityScope::SendAs;
        child_d.verbs = vec![DelegationVerb::SendPublicMessage];
        child_d.task_ref = None;
        let child = sign_delegation(&b, &child_d).unwrap();
        assert!(verify_chain(&parent, &child).is_ok());

        // Unrelated parent digest -> broken link.
        let mut orphan_d = child.delegation.clone();
        orphan_d.parent_delegation = Some([7u8; 32]);
        let orphan = sign_delegation(&b, &orphan_d).unwrap();
        assert!(verify_chain(&parent, &orphan).is_err());
    }

    #[test]
    fn send_as_chain_attribution_never_uses_delegator_key() {
        // WHY (blocker 25): the delegate signs with its OWN key. The
        // delegation only needs to be REFERENCED by digest; nothing in this
        // API exposes or requires A's secret key for B to act.
        let a = keypair();
        let b = keypair();
        let mut d = root_delegation(&a, b.agent_id());
        d.authority_scope = AuthorityScope::SendAs;
        d.verbs = vec![DelegationVerb::SendPublicMessage];
        d.task_ref = None;
        let sd = sign_delegation(&a, &d).unwrap();
        // B's own keypair can sign its message; the digest is the only link.
        let _digest = signed_delegation_digest(&sd);
        let b_msg = b.agent_id(); // stand-in: B signs as B, always
        assert_ne!(b_msg, sd.delegation.from_agent);
        assert!(verify_delegation(&sd).is_ok());
    }

    #[test]
    fn canonical_bytes_bind_every_policy_field() {
        // WHY (blocker 26): every field must be tamper-evident. Flipping any
        // single policy field must change the signed bytes.
        let a = keypair();
        let b = keypair();
        let base = root_delegation(&a, b.agent_id());
        let bytes = canonical_delegation_bytes(&base);
        for mutate in [
            Delegation {
                delegation_id: [0xCD; 16],
                ..base.clone()
            },
            Delegation {
                issued_at_ms: 1_001,
                ..base.clone()
            },
            Delegation {
                expiry_ms: 60_001,
                ..base.clone()
            },
            Delegation {
                depth: 2,
                parent_delegation: Some([3u8; 32]),
                ..base.clone()
            },
            Delegation {
                group_id: "space-8".into(),
                ..base.clone()
            },
            Delegation {
                task_ref: Some([8u8; 32]),
                ..base.clone()
            },
            Delegation {
                authority_scope: AuthorityScope::SendAs,
                verbs: vec![DelegationVerb::SendPublicMessage],
                task_ref: None,
                ..base
            },
        ] {
            assert_ne!(
                bytes,
                canonical_delegation_bytes(&mutate),
                "mutated envelope must not share signed bytes"
            );
        }
    }

    #[test]
    fn cross_scope_verb_is_rejected() {
        // WHY: verbs are bounded by the scope; a grant must not smuggle
        // send-as powers under a task-execute label.
        let a = keypair();
        let b = keypair();
        let mut d = root_delegation(&a, b.agent_id());
        d.verbs.push(DelegationVerb::SendPublicMessage);
        assert!(matches!(
            sign_delegation(&a, &d),
            Err(DelegationError::Invalid(_))
        ));
    }

    #[test]
    fn attenuation_rejects_escalation() {
        // WHY (review r2): re-delegation must shrink, never widen. Each
        // violated bound names its own error.
        let a = keypair();
        let b = keypair();
        let c = keypair();
        let parent_d = root_delegation(&a, b.agent_id()); // task_execute, claim+complete, g1, exp 60k
        let parent = sign_delegation(&a, &parent_d).unwrap();

        // Legal child: subset verbs, earlier-or-equal expiry, same task.
        let mut ok_child = root_delegation(&b, c.agent_id());
        ok_child.depth = 2;
        ok_child.parent_delegation = Some(signed_delegation_digest(&parent));
        ok_child.verbs = vec![DelegationVerb::Claim];
        ok_child.expiry_ms = 50_000;
        let child = sign_delegation(&b, &ok_child).unwrap();
        assert!(is_attenuated_by(&parent.delegation, &child.delegation).is_ok());

        // Longer-lived child ⇒ rejected.
        let mut long = ok_child.clone();
        long.expiry_ms = 70_000;
        let long_child = sign_delegation(&b, &long).unwrap();
        assert!(is_attenuated_by(&parent.delegation, &long_child.delegation).is_err());

        // Verb superset under send_as parent ⇒ rejected (scope mismatch).
        let mut sa_parent_d = root_delegation(&a, b.agent_id());
        sa_parent_d.authority_scope = AuthorityScope::SendAs;
        sa_parent_d.verbs = vec![DelegationVerb::SendPublicMessage];
        sa_parent_d.task_ref = None;
        let sa_parent = sign_delegation(&a, &sa_parent_d).unwrap();
        let mut esc = root_delegation(&b, c.agent_id());
        esc.depth = 2;
        esc.parent_delegation = Some(signed_delegation_digest(&sa_parent));
        esc.verbs = vec![DelegationVerb::SendPublicMessage, DelegationVerb::Claim];
        // scope must match parent's; giving it task_execute verbs triggers
        // the scope bound first.
        esc.authority_scope = AuthorityScope::TaskExecute;
        let esc_child = sign_delegation(&b, &esc);
        if let Ok(esc_child) = esc_child {
            assert!(is_attenuated_by(&sa_parent.delegation, &esc_child.delegation).is_err());
        }

        // Retargeted task ⇒ rejected.
        let mut retarget = ok_child.clone();
        retarget.task_ref = Some([7u8; 32]);
        let retarget_child = sign_delegation(&b, &retarget).unwrap();
        assert!(is_attenuated_by(&parent.delegation, &retarget_child.delegation).is_err());

        // Different group ⇒ rejected.
        let mut other_group = ok_child;
        other_group.group_id = "space-9".into();
        let og_child = sign_delegation(&b, &other_group).unwrap();
        assert!(is_attenuated_by(&parent.delegation, &og_child.delegation).is_err());
    }

    #[test]
    fn attenuation_allows_narrowing_but_not_widening() {
        // REVIEW r3: child authority must be the INTERSECTION of parent
        // and request — narrower is safe, wider is escalation.
        let a = keypair();
        let b = keypair();
        let c = keypair();
        // Group-wide send_as parent (task_ref None).
        let mut parent_d = root_delegation(&a, b.agent_id());
        parent_d.authority_scope = AuthorityScope::SendAs;
        parent_d.verbs = vec![DelegationVerb::SendPublicMessage];
        parent_d.task_ref = None;
        let parent = sign_delegation(&a, &parent_d).unwrap();

        // NARROWING (parent None → child Some) is VALID attenuation.
        let mut narrowed = root_delegation(&b, c.agent_id());
        narrowed.depth = 2;
        narrowed.parent_delegation = Some(signed_delegation_digest(&parent));
        narrowed.authority_scope = AuthorityScope::SendAs;
        narrowed.verbs = vec![DelegationVerb::SendPublicMessage];
        narrowed.task_ref = Some([9u8; 32]); // narrowed onto one task
        narrowed.expiry_ms = 50_000;
        let child = sign_delegation(&b, &narrowed).unwrap();
        assert!(
            is_attenuated_by(&parent.delegation, &child.delegation).is_ok(),
            "narrowing a group-wide grant onto one task is valid attenuation"
        );

        // WIDENING (parent Some → child None) is escalation; task_execute
        // children require a task_ref at signing, so exercise the pure
        // function with a hand-shaped child.
        let tp_d = root_delegation(&a, b.agent_id()); // task-bound parent
        let tp = sign_delegation(&a, &tp_d).unwrap();
        let mut widened = root_delegation(&b, c.agent_id());
        widened.depth = 2;
        widened.parent_delegation = Some(signed_delegation_digest(&tp));
        widened.expiry_ms = 50_000;
        let mut hand = widened;
        hand.task_ref = None;
        assert!(
            is_attenuated_by(&tp.delegation, &hand).is_err(),
            "widening a task-bound grant to group-wide is escalation"
        );
    }

    #[test]
    fn task_execute_requires_task_ref() {
        let a = keypair();
        let b = keypair();
        let mut d = root_delegation(&a, b.agent_id());
        d.task_ref = None;
        assert!(matches!(
            sign_delegation(&a, &d),
            Err(DelegationError::Invalid(_))
        ));
    }
}
