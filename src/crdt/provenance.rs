//! Authenticated operation provenance for task claims/completions.
//!
//! Without this module, the inner `TaskItem` claimant `AgentId` carried in a
//! [`crate::crdt::TaskListDelta`] is self-asserted data: any mesh peer that can
//! publish to the task-list topic can inject a `Claimed{victim, ts=1}` element
//! and, under earliest-timestamp-wins resolution, steal every claim by
//! impersonation. The signed outer transport sender is discarded at the merge
//! boundary and may be a relay (not the author), so it cannot be the trust root.
//!
//! This module supplies the trust root: every `Claimed`/`Done` element that
//! enters a `TaskItem`'s checkbox OR-Set must carry an [`OpAttestation`] signed
//! by the ML-DSA-65 secret key whose public key hashes to the element's
//! `agent_id` (`AgentId::from_public_key`). This is the exact "derived ==
//! claimed" binding already used for forward attestations, group cards, and
//! revocations elsewhere in the crate — no new cryptography.
//!
//! ## Layout
//!
//! - [`OpAttestation`] / [`OpKind`]: the attestation data carried alongside the
//!   element (serialized within `TaskItem`, so it survives `full_delta`
//!   historical state sync).
//! - [`canonical_op_bytes`]: the deterministic, fixed-width byte layout that is
//!   both signed and verified. Both ends MUST agree byte-for-byte.
//! - [`sign_attestation`]: produce an attestation using a [`SigningContext`]
//!   (the local agent's key material). Called by the handle on claim/complete.
//! - [`verify_attestation`]: self-contained verification — parse the public key,
//!   require `from_public_key == author_agent_id == element agent_id`, and
//!   verify the signature over [`canonical_op_bytes`]. Used by the admission
//!   gate.
//! - [`purge_unattested_elements`]: the admission gate. Drops every checkbox
//!   element whose attestation is missing or fails verification, so the OR-Set
//!   is kept invariant-pure (every element is authenticated) and resolution
//!   (`current_state` / `claim_record` / `completion_record`) operates only over
//!   authenticated state.
//!
//! ## Non-goals (documented, not silently "fixed")
//!
//! Provenance defeats *impersonation*. It does NOT provide exactly-once
//! execution, mutual exclusion under partition, or anti-squatting (an attacker
//! signing under their own valid key with `ts=1` is authenticated and wins their
//! own claim early — a fairness/liveness concern, out of scope here).

use crate::crdt::{CheckboxState, CrdtError, Result, TaskId, TaskListId};
use crate::gossip::SigningContext;
use crate::identity::AgentId;
use ant_quic::crypto::raw_public_keys::pqc::{verify_with_ml_dsa, MlDsaSignature};
use ant_quic::MlDsaPublicKey;
use saorsa_gossip_crdt_sync::OrSet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain separator for claim attestations.
///
/// Prevents a claim signature being replayed as a completion (or as any other
/// signed context in the crate). Pinned at v2 (binds list/topic scope); a
/// layout change bumps the suffix so old attestations fail verification rather
/// than silently re-binding.
pub const CLAIM_DOMAIN: &[u8] = b"x0x.task.claim.v2";

/// Domain separator for completion attestations. See [`CLAIM_DOMAIN`].
pub const COMPLETE_DOMAIN: &[u8] = b"x0x.task.complete.v2";

/// The kind of operation an attestation covers. Determines the domain separator
/// in [`canonical_op_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpKind {
    /// A task claim (`Empty`/`Claimed` → `Claimed`).
    Claim,
    /// A task completion (`Claimed` → `Done`).
    Complete,
}

impl OpKind {
    /// The domain-separator bytes for this operation kind.
    #[must_use]
    pub fn domain(self) -> &'static [u8] {
        match self {
            OpKind::Claim => CLAIM_DOMAIN,
            OpKind::Complete => COMPLETE_DOMAIN,
        }
    }
}

/// A self-contained attestation that `author_agent_id` authorized an operation.
///
/// Carried alongside the corresponding `Claimed`/`Done` checkbox element so it
/// survives delta replication and historical state sync. Verification
/// ([`verify_attestation`]) needs only this struct plus the element's fields —
/// it is independent of the transport signer, so a relayed operation verifies
/// exactly like a direct one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpAttestation {
    /// The agent asserting the operation. MUST equal
    /// `AgentId::from_public_key(author_public_key)` and the element's
    /// `agent_id`; checked at verification.
    pub author_agent_id: AgentId,
    /// ML-DSA-65 public key bytes whose hash equals [`author_agent_id`].
    pub author_public_key: Vec<u8>,
    /// ML-DSA-65 signature over [`canonical_op_bytes`] under the matching
    /// secret key.
    pub signature: Vec<u8>,
}

/// Deterministic, fixed-width byte layout that is both signed and verified.
///
/// Layout: `domain || scope (32) || task_id (32) || agent_id (32) || timestamp_ms (8, BE)`.
///
/// All fields are fixed-width, so the encoding is unambiguous and
/// cross-replica stable. The `peer_id`/`seq` OR-Set tag is intentionally NOT
/// included: the attestation binds the *operation* (who claimed/completed which
/// task at what time), not the delivery channel, so an attestation can be keyed
/// by its `CheckboxState` value rather than by an OR-Set tag (which the OR-Set
/// does not expose after `merge_state`).
///
/// **Scope binding (v2):** the list/topic scope (`TaskListId`, 32 bytes) is
/// mixed into the signed bytes. A valid attestation signed for list A fails
/// verification when checked against list B's scope, preventing cross-list
/// replay of a valid claim into a different task list that happens to share the
/// same `TaskId`.
#[must_use]
pub fn canonical_op_bytes(
    kind: OpKind,
    scope: &TaskListId,
    task_id: &TaskId,
    agent_id: &AgentId,
    timestamp_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(kind.domain().len() + 32 + 32 + 32 + 8);
    out.extend_from_slice(kind.domain());
    out.extend_from_slice(scope.as_bytes());
    out.extend_from_slice(task_id.as_bytes());
    out.extend_from_slice(agent_id.as_bytes());
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out
}

/// Produce an attestation for an operation using the local agent's key material.
///
/// `agent_id` MUST be the local agent (equal to `signing.agent_id`); claims and
/// completions are self-signed. The returned attestation's `author_agent_id` is
/// the signing context's agent id and its public key is the context's public
/// key, so the binding `from_public_key == author_agent_id` holds by
/// construction.
///
/// # Errors
///
/// Returns [`CrdtError::Gossip`] if signing fails, or if `agent_id` does not
/// match the signing context's agent (a misuse indicating the caller tried to
/// attest as a different agent).
pub fn sign_attestation(
    signing: &SigningContext,
    kind: OpKind,
    scope: &TaskListId,
    task_id: &TaskId,
    agent_id: &AgentId,
    timestamp_ms: u64,
) -> Result<OpAttestation> {
    // Claims/completions are self-signed: only attest as the key holder.
    if *agent_id != signing.agent_id {
        return Err(CrdtError::Gossip(format!(
            "attestation agent_id mismatch: element claims {} but signing context is {}",
            hex::encode(agent_id.as_bytes()),
            hex::encode(signing.agent_id.as_bytes())
        )));
    }
    let msg = canonical_op_bytes(kind, scope, task_id, agent_id, timestamp_ms);
    let signature = signing
        .sign(&msg)
        .map_err(|e| CrdtError::Gossip(format!("attestation sign failed: {e:?}")))?;
    Ok(OpAttestation {
        author_agent_id: signing.agent_id,
        author_public_key: signing.public_key_bytes.clone(),
        signature,
    })
}

/// Verify an attestation against an operation's fields.
///
/// Returns `true` only if ALL hold:
/// 1. `author_public_key` parses as a valid ML-DSA-65 key,
/// 2. `AgentId::from_public_key(author_public_key)` equals both
///    `att.author_agent_id` and the element's `agent_id`,
/// 3. `signature` verifies over [`canonical_op_bytes`] under that key.
///
/// Any failure (forged agent id, bad signature, malformed key) returns `false`.
/// This function never panics.
#[must_use]
pub fn verify_attestation(
    att: &OpAttestation,
    kind: OpKind,
    scope: &TaskListId,
    task_id: &TaskId,
    agent_id: &AgentId,
    timestamp_ms: u64,
) -> bool {
    let Ok(pubkey) = MlDsaPublicKey::from_bytes(&att.author_public_key) else {
        return false;
    };
    // Binding: the key must hash to BOTH the attestation's claimed author and
    // the element's claimant agent_id. If either differs, the operation is
    // forged (impersonation) and is rejected.
    let derived = AgentId::from_public_key(&pubkey);
    if derived != att.author_agent_id || derived != *agent_id {
        return false;
    }
    let Ok(sig) = MlDsaSignature::from_bytes(&att.signature) else {
        return false;
    };
    let msg = canonical_op_bytes(kind, scope, task_id, agent_id, timestamp_ms);
    verify_with_ml_dsa(&pubkey, &msg, &sig).is_ok()
}

/// If `state` is a Claimed/Done element, return its `(kind, agent_id, ts)` so
/// the gate can look up and verify its attestation. `Empty` is never added to
/// the OR-Set, so it maps to `None`.
#[must_use]
fn provenance_fields(state: &CheckboxState) -> Option<(OpKind, AgentId, u64)> {
    match state {
        CheckboxState::Claimed {
            agent_id,
            timestamp,
        } => Some((OpKind::Claim, *agent_id, *timestamp)),
        CheckboxState::Done {
            agent_id,
            timestamp,
        } => Some((OpKind::Complete, *agent_id, *timestamp)),
        CheckboxState::Empty => None,
    }
}

/// The admission gate: drop every checkbox element and attestation entry that
/// lacks a valid attestation for `scope`.
///
/// # Authentication (two passes)
///
/// 1. **Visible-element pass:** for each `Claimed`/`Done` element currently
///    visible in `checkbox`, require a matching attestation that
///    [`verify_attestation`]s. Drop forged/unattested elements from both the
///    OR-Set and the attestation map.
///
/// 2. **Attestation-map pass:** for every entry in `attestations` (including
///    those hidden by forged tombstones), verify the attestation. Drop entries
///    that fail verification. This ensures the attestation map — which is the
///    **authoritative source** for checkbox resolution (see
///    [`crate::crdt::TaskItem::current_state`]) — contains only authenticated
///    operations.
///
/// # Tombstone defense (no tag synthesis)
///
/// Checkbox elements (`Claimed`/`Done`) are append-only — no legitimate code
/// path removes one. The attestation map is the source of truth for resolution;
/// read methods derive state from `attestations.keys()`, NOT from
/// `checkbox.elements()`. A forged tombstone may hide an element from the
/// OR-Set, but the element remains in the attestation map and is still visible
/// to resolution. No per-replica tag is synthesized — the signed
/// `CheckboxState` (agent + timestamp + kind) IS the stable operation ID,
/// preserved verbatim on relay and immune to tombstone censorship.
///
/// Returns the number of unauthenticated elements/entries dropped.
#[must_use]
pub fn purge_unattested_elements(
    scope: &TaskListId,
    task_id: &TaskId,
    checkbox: &mut OrSet<CheckboxState>,
    attestations: &mut BTreeMap<CheckboxState, OpAttestation>,
) -> usize {
    let mut dropped = 0usize;

    // Pass 1: drop visible OR-Set elements without valid attestations.
    let elements: Vec<CheckboxState> = checkbox.elements().into_iter().cloned().collect();
    for state in elements {
        let Some((kind, agent_id, ts)) = provenance_fields(&state) else {
            continue;
        };
        let authenticated = attestations
            .get(&state)
            .is_some_and(|att| verify_attestation(att, kind, scope, task_id, &agent_id, ts));
        if !authenticated {
            let _ = checkbox.remove(&state);
            attestations.remove(&state);
            dropped += 1;
        }
    }

    // Pass 2: verify every attestation entry (including tombstone-hidden ones).
    // The attestation map is authoritative for resolution; every entry must be
    // cryptographically valid for this scope.
    let attested: Vec<CheckboxState> = attestations.keys().cloned().collect();
    for state in attested {
        let Some((kind, agent_id, ts)) = provenance_fields(&state) else {
            continue;
        };
        let authenticated = attestations
            .get(&state)
            .is_some_and(|att| verify_attestation(att, kind, scope, task_id, &agent_id, ts));
        if !authenticated {
            let _ = checkbox.remove(&state);
            attestations.remove(&state);
            dropped += 1;
        }
    }

    dropped
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::identity::AgentKeypair;

    fn fresh_signing() -> (SigningContext, AgentId) {
        let kp = AgentKeypair::generate().unwrap();
        let aid = kp.agent_id();
        (SigningContext::from_keypair(&kp), aid)
    }

    fn task_id_for(agent: &AgentId) -> TaskId {
        TaskId::new("provenance-test", agent, 1)
    }

    /// Fixed list scope for provenance unit tests (the v2 canonical bytes bind
    /// a `TaskListId`; the value is irrelevant to these crypto-level checks).
    fn scope() -> TaskListId {
        TaskListId::new([0x5c; 32])
    }

    // ── canonical_op_bytes: determinism & separation ─────────────────────────

    #[test]
    fn canonical_bytes_are_deterministic() {
        let (_, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let a = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &aid, 1000);
        let b = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &aid, 1000);
        assert_eq!(a, b, "identical inputs must produce identical bytes");
    }

    #[test]
    fn canonical_bytes_separate_claim_from_complete() {
        let (_, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let claim = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &aid, 1000);
        let complete = canonical_op_bytes(OpKind::Complete, &scope(), &tid, &aid, 1000);
        assert_ne!(
            claim, complete,
            "claim and complete domains must not collide"
        );
    }

    #[test]
    fn canonical_bytes_bind_timestamp_and_task_and_agent() {
        let (_, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let base = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &aid, 1000);
        assert_ne!(
            base,
            canonical_op_bytes(OpKind::Claim, &scope(), &tid, &aid, 1001),
            "timestamp must be bound"
        );
        let other_task = TaskId::new("other-task", &aid, 9);
        assert_ne!(
            base,
            canonical_op_bytes(OpKind::Claim, &scope(), &other_task, &aid, 1000),
            "task_id must be bound"
        );
        let (_, other_agent) = fresh_signing();
        assert_ne!(
            base,
            canonical_op_bytes(OpKind::Claim, &scope(), &tid, &other_agent, 1000),
            "agent_id must be bound"
        );
    }

    // ── sign / verify roundtrip ──────────────────────────────────────────────

    #[test]
    fn sign_then_verify_roundtrips_true() {
        let (signing, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let att = sign_attestation(&signing, OpKind::Claim, &scope(), &tid, &aid, 5000).unwrap();
        assert!(
            verify_attestation(&att, OpKind::Claim, &scope(), &tid, &aid, 5000),
            "a validly-signed attestation must verify"
        );
    }

    // ── impersonation: forged agent_id ───────────────────────────────────────

    #[test]
    fn forged_claimant_agent_id_is_rejected() {
        // Attacker signs the victim's canonical bytes with the attacker's own
        // key, but tags the attestation as the victim. The derived agent
        // (attacker) must not equal the claimed victim agent_id → rejected.
        let (attacker_signing, attacker) = fresh_signing();
        let (_, victim) = fresh_signing();
        let tid = task_id_for(&victim);
        let msg = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &victim, 1);
        let signature = attacker_signing.sign(&msg).unwrap();
        let forged = OpAttestation {
            author_agent_id: victim, // self-asserted victim
            author_public_key: attacker_signing.public_key_bytes.clone(), // attacker's key
            signature,
        };
        assert!(
            !verify_attestation(&forged, OpKind::Claim, &scope(), &tid, &victim, 1),
            "an attacker's key must not verify against a victim agent_id"
        );
        // Sanity: the attacker's key DOES hash to the attacker, not the victim.
        assert_ne!(attacker, victim);
    }

    #[test]
    fn sign_attestation_refuses_to_attest_as_another_agent() {
        let (signing, _) = fresh_signing();
        let (_, other) = fresh_signing();
        let tid = task_id_for(&other);
        let res = sign_attestation(&signing, OpKind::Claim, &scope(), &tid, &other, 1);
        assert!(
            res.is_err(),
            "sign_attestation must refuse to attest as a non-local agent"
        );
    }

    // ── forged signature / wrong key ─────────────────────────────────────────

    #[test]
    fn forged_signature_is_rejected() {
        let (signing, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let mut att = sign_attestation(&signing, OpKind::Claim, &scope(), &tid, &aid, 7).unwrap();
        // Flip a signature byte.
        att.signature[0] ^= 0xff;
        assert!(
            !verify_attestation(&att, OpKind::Claim, &scope(), &tid, &aid, 7),
            "a tampered signature must not verify"
        );
    }

    #[test]
    fn malformed_public_key_is_rejected() {
        let (signing, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let mut att =
            sign_attestation(&signing, OpKind::Complete, &scope(), &tid, &aid, 9).unwrap();
        att.author_public_key = vec![0u8; 7]; // garbage
        assert!(
            !verify_attestation(&att, OpKind::Complete, &scope(), &tid, &aid, 9),
            "a malformed public key must not verify"
        );
    }

    #[test]
    fn wrong_task_id_does_not_verify() {
        // A valid attestation for task A must not verify against task B
        // (no cross-task signature replay).
        let (signing, aid) = fresh_signing();
        let tid_a = TaskId::new("task-a", &aid, 1);
        let tid_b = TaskId::new("task-b", &aid, 1);
        let att = sign_attestation(&signing, OpKind::Claim, &scope(), &tid_a, &aid, 100).unwrap();
        assert!(
            verify_attestation(&att, OpKind::Claim, &scope(), &tid_a, &aid, 100),
            "original task must verify"
        );
        assert!(
            !verify_attestation(&att, OpKind::Claim, &scope(), &tid_b, &aid, 100),
            "attestation must not transfer to a different task"
        );
    }

    #[test]
    fn wrong_timestamp_does_not_verify() {
        let (signing, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let att = sign_attestation(&signing, OpKind::Claim, &scope(), &tid, &aid, 100).unwrap();
        assert!(
            !verify_attestation(&att, OpKind::Claim, &scope(), &tid, &aid, 999),
            "a different timestamp must not verify"
        );
    }

    // ── purge_unattested_elements: the admission gate ────────────────────────

    fn claimed(agent: &AgentId, ts: u64) -> CheckboxState {
        CheckboxState::Claimed {
            agent_id: *agent,
            timestamp: ts,
        }
    }

    fn peer_tag(n: u8) -> (saorsa_gossip_types::PeerId, u64) {
        (saorsa_gossip_types::PeerId::new([n; 32]), n as u64)
    }

    #[test]
    fn purge_drops_unattested_keeps_attested() {
        let (signing, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let (_, rogue) = fresh_signing();

        // A legitimately-attested claim by `aid`.
        let good = claimed(&aid, 10);
        let good_att = sign_attestation(&signing, OpKind::Claim, &scope(), &tid, &aid, 10).unwrap();

        // A claim element with NO attestation at all (simulates a legacy /
        // unattested remote element that must be dropped under strict cutover).
        let unattested = claimed(&rogue, 5);

        let mut checkbox = OrSet::<CheckboxState>::new();
        checkbox.add(good.clone(), peer_tag(1)).unwrap();
        checkbox.add(unattested.clone(), peer_tag(2)).unwrap();

        let mut attestations = BTreeMap::new();
        attestations.insert(good.clone(), good_att);
        // No entry for `unattested`.

        let dropped = purge_unattested_elements(&scope(), &tid, &mut checkbox, &mut attestations);

        assert_eq!(dropped, 1, "exactly the unattested element is dropped");
        let remaining: Vec<CheckboxState> = checkbox.elements().into_iter().cloned().collect();
        assert!(remaining.contains(&good), "attested element survives");
        assert!(
            !remaining.contains(&unattested),
            "unattested element is purged"
        );
        assert!(attestations.contains_key(&good), "good attestation kept");
        assert!(
            !attestations.contains_key(&unattested),
            "orphaned attestation removed"
        );
    }

    #[test]
    fn purge_drops_element_whose_attestation_fails_verification() {
        // Element claims `victim`, but the attestation was produced by an
        // attacker's key (impersonation): derived(attacker key) != victim →
        // the gate drops it even though an attestation entry exists.
        let (attacker_signing, _) = fresh_signing();
        let (_, victim) = fresh_signing();
        let tid = task_id_for(&victim);

        let forged_element = claimed(&victim, 10);
        let msg = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &victim, 10);
        let signature = attacker_signing.sign(&msg).unwrap();
        let bad_att = OpAttestation {
            author_agent_id: victim,
            author_public_key: attacker_signing.public_key_bytes.clone(),
            signature,
        };

        let mut checkbox = OrSet::<CheckboxState>::new();
        checkbox.add(forged_element.clone(), peer_tag(9)).unwrap();
        let mut attestations = BTreeMap::new();
        attestations.insert(forged_element.clone(), bad_att);

        let dropped = purge_unattested_elements(&scope(), &tid, &mut checkbox, &mut attestations);
        assert_eq!(dropped, 1, "forged-attestation element is dropped");
        assert!(
            checkbox.elements().is_empty(),
            "no element survives a fully-forged set"
        );
    }

    // ── P1: scope binding prevents cross-list replay ───────────────────────
    //
    // WHY: without the list scope in the signed bytes, a validly-attested
    // claim for list A could be replayed into list B (which happens to share
    // the same TaskId) and verify there — letting a participant of one list
    // inject state into another. The v2 canonical bytes mix the TaskListId in,
    // so an attestation verifies only in its home list.

    #[test]
    fn scope_is_bound_into_canonical_bytes() {
        // The canonical bytes differ when only the scope differs — the
        // TaskListId is mixed into the signed payload, not just the domain.
        let (_, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let scope_a = TaskListId::new([0xAA; 32]);
        let scope_b = TaskListId::new([0xBB; 32]);
        assert_ne!(
            canonical_op_bytes(OpKind::Claim, &scope_a, &tid, &aid, 1000),
            canonical_op_bytes(OpKind::Claim, &scope_b, &tid, &aid, 1000),
            "different list scopes must produce different canonical bytes"
        );
    }

    #[test]
    fn cross_list_replay_of_a_valid_claim_is_rejected() {
        // A claim validly attested for list A verifies in A but NOT in list B,
        // so it cannot be replayed into a different task list sharing the same
        // TaskId. The scope mismatch fails verification before the element can
        // influence resolution.
        let (signing, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let scope_a = TaskListId::new([0xAA; 32]);
        let scope_b = TaskListId::new([0xBB; 32]);

        let att = sign_attestation(&signing, OpKind::Claim, &scope_a, &tid, &aid, 1000).unwrap();
        assert!(
            verify_attestation(&att, OpKind::Claim, &scope_a, &tid, &aid, 1000),
            "attestation verifies in its home list"
        );
        assert!(
            !verify_attestation(&att, OpKind::Claim, &scope_b, &tid, &aid, 1000),
            "a list-A attestation must not verify in list B (cross-list replay blocked)"
        );
    }

    #[test]
    fn purge_drops_element_attested_for_a_different_scope() {
        // End-to-end at the admission gate: an element whose attestation is
        // valid for scope_A, checked under scope_B, is purged — cross-list
        // replay is rejected at admission, not only at the crypto predicate.
        let (signing, aid) = fresh_signing();
        let tid = task_id_for(&aid);
        let scope_a = TaskListId::new([0xAA; 32]);
        let scope_b = TaskListId::new([0xBB; 32]);

        let elem = claimed(&aid, 100);
        let att = sign_attestation(&signing, OpKind::Claim, &scope_a, &tid, &aid, 100).unwrap();

        let mut checkbox = OrSet::<CheckboxState>::new();
        checkbox.add(elem.clone(), peer_tag(1)).unwrap();
        let mut attestations = BTreeMap::new();
        attestations.insert(elem.clone(), att);

        // Purge under scope_B: the scope-A attestation fails verification AND
        // its attestation entry is removed, so the tombstone defense does not
        // restore it.
        let dropped = purge_unattested_elements(&scope_b, &tid, &mut checkbox, &mut attestations);
        assert_eq!(dropped, 1, "cross-scope element is purged at admission");
        assert!(
            checkbox.elements().is_empty(),
            "no cross-scope element survives admission"
        );
        assert!(
            attestations.is_empty(),
            "cross-scope attestation entry is removed (not restored)"
        );
    }
}
