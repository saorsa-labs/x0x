//! Key/identity revocation records and the local grow-only revocation set
//! (issue #130).
//!
//! A [`RevocationRecord`](crate::revocation::RevocationRecord) is a signed, self-authenticating statement that a
//! specific agent or machine identity is revoked. Records are gossiped across
//! the network and enforced at every trust gate (see the enforcement points in
//! `lib.rs`, `dm_inbox.rs`, and `server/mod.rs`). Presence of a *valid*
//! revocation always fails **closed**.
//!
//! # Who may revoke — exactly two rules
//!
//! Both are verifiable from the record alone plus (for issuer-revocation) a
//! certificate already known for the subject; neither needs any trust state:
//!
//! 1. **Self-revocation** — the issuer key *is* the subject: the SHA-256 of
//!    `issuer_public_key` equals the revoked `AgentId`/`MachineId`. Always
//!    valid; an attacker "revoking" a stolen key only helps the victim.
//! 2. **Issuer-revocation** — for an `Agent` subject, the issuer key is the
//!    user key that signed that agent's [`AgentCertificate`](crate::identity::AgentCertificate). The user who
//!    vouched for an agent may un-vouch it.
//!
//! There is **no third-party revocation** and **no un-revocation**: the set is
//! grow-only (a G-Set), which removes the entire replay/rollback class —
//! replaying a revocation is idempotent and there is no "restore" message to
//! replay. Records are de-duplicated by the BLAKE3 hash of their canonical
//! bytes.

use std::collections::{HashMap, HashSet};

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};
use ant_quic::derive_peer_id_from_public_key;
use serde::{Deserialize, Serialize};

use crate::error::IdentityError;
use crate::identity::{AgentCertificate, AgentId, MachineId};

/// Domain-separation prefix for the bytes a revocation signs over.
const REVOCATION_MSG_PREFIX: &[u8] = b"x0x-revocation-v1";

/// Magic marker prefixing the on-disk revocation set file.
const REVOCATIONS_FILE_MAGIC: &[u8; 4] = b"X0XR";

/// The identity a revocation record targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevokedSubject {
    /// A portable agent identity.
    Agent(AgentId),
    /// A hardware-pinned machine identity.
    Machine(MachineId),
}

impl RevokedSubject {
    /// Domain tag byte distinguishing the subject kind in signed bytes.
    fn tag(&self) -> u8 {
        match self {
            RevokedSubject::Agent(_) => 0x01,
            RevokedSubject::Machine(_) => 0x02,
        }
    }

    /// The raw 32-byte identifier of the subject.
    fn id_bytes(&self) -> &[u8; 32] {
        match self {
            RevokedSubject::Agent(id) => id.as_bytes(),
            RevokedSubject::Machine(id) => id.as_bytes(),
        }
    }
}

/// A signed, self-authenticating revocation of an agent or machine identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// The identity being revoked.
    pub subject: RevokedSubject,
    /// The revoker's ML-DSA-65 public key bytes.
    pub issuer_public_key: Vec<u8>,
    /// Unix timestamp when the revocation was issued (informational only).
    pub revoked_at: u64,
    /// Optional human-readable reason.
    pub reason: Option<String>,
    /// ML-DSA-65 signature over the canonical message.
    pub signature: Vec<u8>,
}

impl RevocationRecord {
    /// Canonical bytes signed by a revocation:
    /// `prefix || subject_tag || subject_id || issuer_pubkey || revoked_at ||
    /// reason_len || reason`.
    ///
    /// `reason` is length-prefixed so two records that differ only by where a
    /// field boundary falls cannot collide.
    fn canonical_message(
        subject: &RevokedSubject,
        issuer_public_key: &[u8],
        revoked_at: u64,
        reason: &Option<String>,
    ) -> Vec<u8> {
        let reason_bytes = reason.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        let mut msg = Vec::with_capacity(
            REVOCATION_MSG_PREFIX.len()
                + 1
                + 32
                + issuer_public_key.len()
                + 8
                + 8
                + reason_bytes.len(),
        );
        msg.extend_from_slice(REVOCATION_MSG_PREFIX);
        msg.push(subject.tag());
        msg.extend_from_slice(subject.id_bytes());
        msg.extend_from_slice(issuer_public_key);
        msg.extend_from_slice(&revoked_at.to_le_bytes());
        msg.extend_from_slice(&(reason_bytes.len() as u64).to_le_bytes());
        msg.extend_from_slice(reason_bytes);
        msg
    }

    /// Sign a new revocation record.
    ///
    /// The caller supplies the issuer's public key bytes and secret key. For a
    /// **self-revocation**, pass the keypair whose id equals `subject`; for an
    /// **issuer-revocation**, pass the user keypair that signed the subject
    /// agent's certificate. Authority is (re-)checked in
    /// [`verify_authority`](Self::verify_authority) on receipt.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::CertificateVerification`] if signing fails.
    pub fn sign(
        subject: RevokedSubject,
        issuer_public_key: &MlDsaPublicKey,
        issuer_secret_key: &MlDsaSecretKey,
        revoked_at: u64,
        reason: Option<String>,
    ) -> Result<Self, IdentityError> {
        let issuer_pub_bytes = issuer_public_key.as_bytes().to_vec();
        let message = Self::canonical_message(&subject, &issuer_pub_bytes, revoked_at, &reason);
        let signature = sign_with_ml_dsa(issuer_secret_key, &message).map_err(|e| {
            IdentityError::CertificateVerification(format!("revocation signing failed: {e:?}"))
        })?;
        Ok(Self {
            subject,
            issuer_public_key: issuer_pub_bytes,
            revoked_at,
            reason,
            signature: signature.as_bytes().to_vec(),
        })
    }

    /// Verify the signature and the authority of this record.
    ///
    /// `subject_cert` is a certificate known for the subject agent (from the
    /// discovery cache or the same gossip batch), used only to check
    /// issuer-revocation authority; pass `None` if none is known. The
    /// signature is always checked first, so a forged record is rejected even
    /// when a certificate is supplied.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] if the signature is invalid or the
    /// issuer is neither the subject (self) nor the certifying user (issuer).
    pub fn verify_authority(
        &self,
        subject_cert: Option<&AgentCertificate>,
    ) -> Result<(), IdentityError> {
        // 1. Signature check — the record must be authentic before its claimed
        //    authority means anything.
        let issuer_pubkey = MlDsaPublicKey::from_bytes(&self.issuer_public_key)
            .map_err(|_| IdentityError::Revocation("invalid issuer public key".to_string()))?;
        let signature = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|e| IdentityError::Revocation(format!("invalid signature format: {e:?}")))?;
        let message = Self::canonical_message(
            &self.subject,
            &self.issuer_public_key,
            self.revoked_at,
            &self.reason,
        );
        verify_with_ml_dsa(&issuer_pubkey, &message, &signature)
            .map_err(|e| IdentityError::Revocation(format!("bad signature: {e:?}")))?;

        // 2. Self-revocation: the issuer key hashes to the subject id.
        let issuer_id = derive_peer_id_from_public_key(&issuer_pubkey).0;
        if &issuer_id == self.subject.id_bytes() {
            return Ok(());
        }

        // 3. Issuer-revocation (Agent subjects only): the issuer key is the
        //    user key that signed the subject agent's certificate.
        if let RevokedSubject::Agent(subject_agent) = &self.subject {
            if let Some(cert) = subject_cert {
                let cert_binds_subject = cert
                    .agent_id()
                    .map(|a| a == *subject_agent)
                    .unwrap_or(false);
                let cert_is_valid = cert.verify().is_ok();
                let issuer_is_certifier = cert
                    .user_id()
                    .map(|u| u.as_bytes() == &issuer_id)
                    .unwrap_or(false);
                if cert_binds_subject && cert_is_valid && issuer_is_certifier {
                    return Ok(());
                }
            }
        }

        Err(IdentityError::Revocation(
            "issuer is neither the subject nor the certifying user".to_string(),
        ))
    }

    /// BLAKE3 hash of the canonical (signed) message, used for de-duplication.
    ///
    /// Two records for the same `(subject, issuer, revoked_at, reason)` hash
    /// identically, so merging is idempotent.
    #[must_use]
    pub fn record_hash(&self) -> [u8; 32] {
        let message = Self::canonical_message(
            &self.subject,
            &self.issuer_public_key,
            self.revoked_at,
            &self.reason,
        );
        *blake3::hash(&message).as_bytes()
    }
}

/// In-memory grow-only set of verified revocations.
///
/// Maintains `HashSet`s of revoked agent/machine ids for O(1) gate checks plus
/// a hash-keyed map of the full records for rebroadcast. Records are only ever
/// added; there is no removal (no un-revocation).
#[derive(Debug, Default, Clone)]
pub struct RevocationSet {
    revoked_agents: HashSet<AgentId>,
    revoked_machines: HashSet<MachineId>,
    records_by_hash: HashMap<[u8; 32], RevocationRecord>,
}

impl RevocationSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an agent id is revoked.
    #[must_use]
    pub fn is_agent_revoked(&self, id: &AgentId) -> bool {
        self.revoked_agents.contains(id)
    }

    /// Whether a machine id is revoked.
    #[must_use]
    pub fn is_machine_revoked(&self, id: &MachineId) -> bool {
        self.revoked_machines.contains(id)
    }

    /// Number of distinct records held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records_by_hash.len()
    }

    /// Whether the set holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records_by_hash.is_empty()
    }

    /// Whether a record (by canonical hash) is already known.
    #[must_use]
    pub fn contains_hash(&self, hash: &[u8; 32]) -> bool {
        self.records_by_hash.contains_key(hash)
    }

    /// Insert an already-verified record. Returns `true` if it was new.
    ///
    /// Callers MUST verify authority via
    /// [`RevocationRecord::verify_authority`] before inserting; this method
    /// performs no cryptographic checks so that loading a locally-persisted,
    /// previously-verified set stays cheap.
    pub fn insert_verified(&mut self, record: RevocationRecord) -> bool {
        let hash = record.record_hash();
        if self.records_by_hash.contains_key(&hash) {
            return false;
        }
        match &record.subject {
            RevokedSubject::Agent(id) => {
                self.revoked_agents.insert(*id);
            }
            RevokedSubject::Machine(id) => {
                self.revoked_machines.insert(*id);
            }
        }
        self.records_by_hash.insert(hash, record);
        true
    }

    /// All held records (order unspecified), for rebroadcast/anti-entropy.
    #[must_use]
    pub fn all_records(&self) -> Vec<RevocationRecord> {
        self.records_by_hash.values().cloned().collect()
    }

    /// Encode the set for on-disk persistence: `X0XR` magic + bincode of the
    /// record list.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let records: Vec<&RevocationRecord> = self.records_by_hash.values().collect();
        let body = bincode::serialize(&records)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut out = Vec::with_capacity(REVOCATIONS_FILE_MAGIC.len() + body.len());
        out.extend_from_slice(REVOCATIONS_FILE_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a set previously written by [`to_bytes`](Self::to_bytes).
    ///
    /// Records are inserted without re-verifying signatures — they were
    /// verified before this daemon persisted them. An empty or magic-less
    /// input yields an empty set (forward-compatible with a missing file).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] if the body is present but
    /// malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        if bytes.len() < REVOCATIONS_FILE_MAGIC.len()
            || &bytes[..REVOCATIONS_FILE_MAGIC.len()] != REVOCATIONS_FILE_MAGIC
        {
            return Err(IdentityError::Serialization(
                "revocation file missing X0XR magic".to_string(),
            ));
        }
        let records: Vec<RevocationRecord> =
            bincode::deserialize(&bytes[REVOCATIONS_FILE_MAGIC.len()..])
                .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut set = Self::new();
        for record in records {
            set.insert_verified(record);
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::identity::{AgentKeypair, MachineKeypair, UserKeypair};

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn revocation_self_signed_verifies() {
        // An agent revoking its own id is always authoritative: the issuer key
        // hashes to the subject. This is the "revoke a stolen key" path and
        // must never require external state.
        let agent = AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            agent.public_key(),
            agent.secret_key(),
            now(),
            Some("compromised".to_string()),
        )
        .unwrap();
        record
            .verify_authority(None)
            .expect("self-revocation must verify with no certificate");
    }

    #[test]
    fn revocation_machine_self_signed_verifies() {
        let machine = MachineKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Machine(machine.machine_id()),
            machine.public_key(),
            machine.secret_key(),
            now(),
            None,
        )
        .unwrap();
        record
            .verify_authority(None)
            .expect("machine self-revocation must verify");
    }

    #[test]
    fn revocation_user_signed_for_certified_agent_verifies() {
        // The user who certified an agent may revoke it. Authority is proven by
        // the agent's certificate binding agent->user and the issuer being that
        // user key.
        let user = UserKeypair::generate().unwrap();
        let agent = AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user, &agent).unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            user.public_key(),
            user.secret_key(),
            now(),
            None,
        )
        .unwrap();
        record
            .verify_authority(Some(&cert))
            .expect("issuer (certifying user) revocation must verify");
    }

    #[test]
    fn revocation_user_without_cert_rejected() {
        // Without the certificate proving the agent->user binding, a user key
        // has no authority over the agent — fail closed.
        let user = UserKeypair::generate().unwrap();
        let agent = AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            user.public_key(),
            user.secret_key(),
            now(),
            None,
        )
        .unwrap();
        assert!(
            record.verify_authority(None).is_err(),
            "issuer-revocation without the binding certificate must be rejected"
        );
    }

    #[test]
    fn revocation_unrelated_key_rejected() {
        // A third party (neither the subject nor its certifier) cannot revoke,
        // even with a validly-signed record. This is the core no-third-party
        // property.
        let user = UserKeypair::generate().unwrap();
        let agent = AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user, &agent).unwrap();
        let attacker = UserKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            attacker.public_key(),
            attacker.secret_key(),
            now(),
            None,
        )
        .unwrap();
        assert!(
            record.verify_authority(Some(&cert)).is_err(),
            "an unrelated key must not be able to revoke, even with the cert"
        );
    }

    #[test]
    fn revocation_forged_signature_rejected() {
        // Tampering the record after signing must fail the signature check
        // before authority is ever considered.
        let agent = AgentKeypair::generate().unwrap();
        let mut record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            agent.public_key(),
            agent.secret_key(),
            now(),
            None,
        )
        .unwrap();
        record.revoked_at = record.revoked_at.wrapping_add(1);
        assert!(
            record.verify_authority(None).is_err(),
            "a tampered record must fail the signature check"
        );
    }

    #[test]
    fn revocation_set_merge_grow_only_idempotent() {
        // Merging the same record twice is a no-op; the set only grows. This is
        // what makes gossip replay harmless.
        let agent = AgentKeypair::generate().unwrap();
        let record = RevocationRecord::sign(
            RevokedSubject::Agent(agent.agent_id()),
            agent.public_key(),
            agent.secret_key(),
            now(),
            None,
        )
        .unwrap();
        let mut set = RevocationSet::new();
        assert!(set.insert_verified(record.clone()), "first insert is new");
        assert!(
            !set.insert_verified(record.clone()),
            "re-inserting the same record must be idempotent"
        );
        assert_eq!(set.len(), 1);
        assert!(set.is_agent_revoked(&agent.agent_id()));
        assert!(!set.is_machine_revoked(&MachineKeypair::generate().unwrap().machine_id()));
    }

    #[test]
    fn revocation_set_persists_and_reloads() {
        // The on-disk round-trip preserves the gate state — a daemon restart
        // must not forget revocations it learned.
        let agent = AgentKeypair::generate().unwrap();
        let machine = MachineKeypair::generate().unwrap();
        let mut set = RevocationSet::new();
        set.insert_verified(
            RevocationRecord::sign(
                RevokedSubject::Agent(agent.agent_id()),
                agent.public_key(),
                agent.secret_key(),
                now(),
                None,
            )
            .unwrap(),
        );
        set.insert_verified(
            RevocationRecord::sign(
                RevokedSubject::Machine(machine.machine_id()),
                machine.public_key(),
                machine.secret_key(),
                now(),
                None,
            )
            .unwrap(),
        );
        let bytes = set.to_bytes().unwrap();
        let reloaded = RevocationSet::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.is_agent_revoked(&agent.agent_id()));
        assert!(reloaded.is_machine_revoked(&machine.machine_id()));
    }

    #[test]
    fn revocation_set_from_empty_is_empty() {
        assert!(RevocationSet::from_bytes(&[]).unwrap().is_empty());
    }
}
