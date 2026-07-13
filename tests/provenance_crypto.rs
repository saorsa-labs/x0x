//! Integration-level verification of the task-claim provenance crypto core.
//!
//! Rationale: the in-crate `#[cfg(test)]` module in `src/crdt/provenance.rs`
//! cannot execute until the lib *test* binary links, which is currently blocked
//! by an in-flight `claim_task` signature migration elsewhere. This file is an
//! *integration* test: it links against the non-test lib (which compiles
//! warning-clean) and exercises the public provenance API against the REAL
//! ML-DSA-65 implementation, independent of the lib-test modules.
//!
//! Covers the security-critical binding: a claim/complete attestation verifies
//! only when signed by the ML-DSA-65 secret key whose public key hashes to the
//! claimed `agent_id`. Impersonation, tampered signatures, malformed keys, and
//! cross-task/cross-timestamp replay are all rejected.

#![allow(clippy::unwrap_used)]

use x0x::crdt::provenance::{
    canonical_op_bytes, sign_attestation, verify_attestation, OpAttestation, OpKind,
};
use x0x::crdt::{TaskId, TaskListId};
use x0x::gossip::SigningContext;
use x0x::identity::{AgentId, AgentKeypair};

/// Build a fresh signing context + its derived agent id.
fn fresh_signing() -> (SigningContext, AgentId) {
    let kp = AgentKeypair::generate().unwrap();
    let aid = kp.agent_id();
    (SigningContext::from_keypair(&kp), aid)
}

fn task_id_for(agent: &AgentId) -> TaskId {
    TaskId::new("provenance-integration", agent, 1)
}

fn scope() -> TaskListId {
    TaskListId::new([0xAA; 32])
}

// ── canonical_op_bytes: determinism & domain separation ─────────────────────

#[test]
fn canonical_bytes_are_deterministic_and_domain_separated() {
    let (_, aid) = fresh_signing();
    let tid = task_id_for(&aid);
    let a = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &aid, 1000);
    let b = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &aid, 1000);
    assert_eq!(a, b, "identical inputs ⇒ identical bytes");

    // Claim and complete domains must not collide (no cross-context replay).
    let claim = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &aid, 1000);
    let complete = canonical_op_bytes(OpKind::Complete, &scope(), &tid, &aid, 1000);
    assert_ne!(claim, complete);

    // Every field is bound.
    assert_ne!(
        a,
        canonical_op_bytes(OpKind::Claim, &scope(), &tid, &aid, 1001)
    ); // ts
    let other_task = TaskId::new("other", &aid, 9);
    assert_ne!(
        a,
        canonical_op_bytes(OpKind::Claim, &scope(), &other_task, &aid, 1000)
    ); // task
    let (_, other_agent) = fresh_signing();
    assert_ne!(
        a,
        canonical_op_bytes(OpKind::Claim, &scope(), &tid, &other_agent, 1000)
    ); // agent
}

// ── sign / verify roundtrip ─────────────────────────────────────────────────

#[test]
fn validly_signed_attestation_verifies() {
    let (signing, aid) = fresh_signing();
    let tid = task_id_for(&aid);
    let att = sign_attestation(&signing, OpKind::Claim, &scope(), &tid, &aid, 5000).unwrap();
    assert!(
        verify_attestation(&att, OpKind::Claim, &scope(), &tid, &aid, 5000),
        "a validly-signed attestation must verify"
    );
    // Completion attestation verifies too.
    let comp = sign_attestation(&signing, OpKind::Complete, &scope(), &tid, &aid, 6000).unwrap();
    assert!(verify_attestation(
        &comp,
        OpKind::Complete,
        &scope(),
        &tid,
        &aid,
        6000,
    ));
}

// ── impersonation: forged claimant agent_id ─────────────────────────────────

#[test]
fn attacker_key_cannot_attest_as_victim() {
    // The attacker signs the victim's canonical bytes with the attacker's own
    // key, then self-asserts the victim as the author. The derived agent
    // (attacker) must not equal the claimed victim agent_id ⇒ rejected.
    let (attacker_signing, attacker) = fresh_signing();
    let (_, victim) = fresh_signing();
    assert_ne!(attacker, victim, "fixtures must be distinct agents");
    let tid = task_id_for(&victim);
    let msg = canonical_op_bytes(OpKind::Claim, &scope(), &tid, &victim, 1);
    let signature = attacker_signing.sign(&msg).unwrap();
    let forged = OpAttestation {
        author_agent_id: victim,
        author_public_key: attacker_signing.public_key_bytes.clone(),
        signature,
    };
    assert!(
        !verify_attestation(&forged, OpKind::Claim, &scope(), &tid, &victim, 1),
        "an attacker's key must not verify against a victim agent_id"
    );
}

#[test]
fn sign_attestation_refuses_to_attest_as_a_non_local_agent() {
    let (signing, _) = fresh_signing();
    let (_, other) = fresh_signing();
    let tid = task_id_for(&other);
    let res = sign_attestation(&signing, OpKind::Claim, &scope(), &tid, &other, 1);
    assert!(
        res.is_err(),
        "sign_attestation must refuse to attest as a non-local agent"
    );
}

// ── forged signature / malformed key ────────────────────────────────────────

#[test]
fn tampered_signature_is_rejected() {
    let (signing, aid) = fresh_signing();
    let tid = task_id_for(&aid);
    let mut att = sign_attestation(&signing, OpKind::Claim, &scope(), &tid, &aid, 7).unwrap();
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
    let mut att = sign_attestation(&signing, OpKind::Complete, &scope(), &tid, &aid, 9).unwrap();
    att.author_public_key = vec![0u8; 7]; // garbage
    assert!(
        !verify_attestation(&att, OpKind::Complete, &scope(), &tid, &aid, 9),
        "a malformed public key must not verify"
    );
}

// ── no cross-task / cross-timestamp replay ───────────────────────────────────

#[test]
fn attestation_does_not_transfer_across_task_or_timestamp() {
    let (signing, aid) = fresh_signing();
    let tid_a = TaskId::new("task-a", &aid, 1);
    let tid_b = TaskId::new("task-b", &aid, 1);
    let att = sign_attestation(&signing, OpKind::Claim, &scope(), &tid_a, &aid, 100).unwrap();
    assert!(verify_attestation(
        &att,
        OpKind::Claim,
        &scope(),
        &tid_a,
        &aid,
        100
    ));
    assert!(
        !verify_attestation(&att, OpKind::Claim, &scope(), &tid_b, &aid, 100),
        "attestation must not transfer to a different task"
    );
    assert!(
        !verify_attestation(&att, OpKind::Claim, &scope(), &tid_a, &aid, 999),
        "attestation must not transfer to a different timestamp"
    );
    assert!(
        !verify_attestation(&att, OpKind::Complete, &scope(), &tid_a, &aid, 100),
        "a claim attestation must not verify as a completion"
    );
}
