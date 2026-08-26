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

    /// Whether this is a self-revocation — the issuer key hashes to the subject
    /// id.
    ///
    /// A self-revocation re-verifies from the record alone (no certificate
    /// needed); an issuer-revocation requires the subject agent's certificate.
    /// A malformed issuer key yields `false` (it will fail verification anyway).
    #[must_use]
    pub fn is_self_revocation(&self) -> bool {
        match MlDsaPublicKey::from_bytes(&self.issuer_public_key) {
            Ok(pk) => &derive_peer_id_from_public_key(&pk).0 == self.subject.id_bytes(),
            Err(_) => false,
        }
    }

    /// Hex-encoded subject identifier (32 bytes → 64 hex chars).
    ///
    /// Convenience for REST responses — avoids exposing raw `[u8; 32]` in JSON.
    #[must_use]
    pub fn subject_hex(&self) -> String {
        hex::encode(self.subject.id_bytes())
    }

    /// Human-readable subject kind: `"agent"` or `"machine"`.
    #[must_use]
    pub fn subject_kind(&self) -> &'static str {
        match &self.subject {
            RevokedSubject::Agent(_) => "agent",
            RevokedSubject::Machine(_) => "machine",
        }
    }

    /// SHA-256 of the issuer public key bytes, for compact display in REST
    /// responses.  This is deterministic given the issuer keypair and matches
    /// the AgentId/MachineId derivation when the issuer is self-revoking.
    #[must_use]
    pub fn issuer_public_key_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.issuer_public_key);
        hasher.finalize().into()
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

/// A revocation record plus the subject certificate (if any) that authorizes
/// it, as stored on disk.
///
/// `subject_cert` is `Some` only for **issuer-revocations**, where the record
/// is authorized by the user key that signed the subject agent's certificate:
/// that certificate is required to re-verify authority on load. Self-revocations
/// carry `None` (they re-verify from the record alone). Persisting the cert is
/// what lets [`RevocationSet::from_bytes`] re-check authority — so a
/// tampered/forged `revocations.bin` cannot inject an unverified revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRevocation {
    record: RevocationRecord,
    subject_cert: Option<AgentCertificate>,
}

/// In-memory grow-only set of verified revocations.
///
/// Maintains `HashSet`s of revoked agent/machine ids for O(1) gate checks plus
/// a hash-keyed map of the full records for rebroadcast. Records are only ever
/// added; there is no removal (no un-revocation).
///
/// Every record in the set has passed [`RevocationRecord::verify_authority`] —
/// both on first receipt and again when reloaded from disk. Insertion therefore
/// only happens through [`verify_and_insert`](Self::verify_and_insert); the
/// crate-internal raw insert performs no crypto and must only ever be handed a
/// record that was just verified.
#[derive(Debug, Default, Clone)]
pub struct RevocationSet {
    revoked_agents: HashSet<AgentId>,
    revoked_machines: HashSet<MachineId>,
    records_by_hash: HashMap<[u8; 32], PersistedRevocation>,
    /// Monotonic change counter — incremented on every insert or expiry.
    /// Publishers compare this to decide whether the set changed since
    /// their last full broadcast (the on-change piggyback gate), avoiding
    /// a full `all_records` comparison per heartbeat.
    change_generation: u64,
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

    /// Verify a record's authority, then insert it. Returns `true` if it was
    /// newly added, `false` if already present (idempotent).
    ///
    /// This is the ONLY way a record enters the set. `subject_cert` supplies
    /// the subject agent's certificate for issuer-revocations (pass `None` for
    /// self-revocations, or when no certificate is known — issuer-revocations
    /// then fail closed). The validating certificate is retained so the record
    /// re-verifies on a later [`from_bytes`](Self::from_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] if the record's signature is
    /// invalid or the issuer lacks authority over the subject.
    pub fn verify_and_insert(
        &mut self,
        record: RevocationRecord,
        subject_cert: Option<&AgentCertificate>,
    ) -> Result<bool, IdentityError> {
        record.verify_authority(subject_cert)?;
        // Retain the certificate only when it was actually needed to prove
        // authority (issuer-revocation). Self-revocations re-verify without it.
        let retained_cert = if record.is_self_revocation() {
            None
        } else {
            subject_cert.cloned()
        };
        Ok(self.insert_verified(PersistedRevocation {
            record,
            subject_cert: retained_cert,
        }))
    }

    /// Raw insert of an already-verified record. Performs NO cryptographic
    /// checks — it is module-private and reachable ONLY through
    /// [`verify_and_insert`](Self::verify_and_insert), which is the sole path a
    /// record can enter the set. Returns `true` if new.
    /// Monotonic generation counter — changes on every insert or expiry.
    /// The heartbeat piggyback compares generations: unchanged set ⇒ skip
    /// the publish (except the periodic fallback).
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.change_generation
    }

    /// Drop records older than `ttl_secs`. Returns the number expired.
    ///
    /// A revocation older than the TTL with no renewal is already moot:
    /// revocations target currently-known agents, and a record that old
    /// means nobody has seen the agent (or the issuer) for months. The
    /// 2026-07 stale testnet records (2 records, 19 KB each heartbeat) are
    /// the motivating case — they cost 222 KB/s fleet-wide on a topic
    /// that should be silent.
    pub fn expire_records_older_than(&mut self, ttl_secs: u64, now_unix: u64) -> usize {
        let cutoff = now_unix.saturating_sub(ttl_secs);
        let expired: Vec<[u8; 32]> = self
            .records_by_hash
            .iter()
            .filter(|(_, persisted)| persisted.record.revoked_at < cutoff)
            .map(|(hash, _)| *hash)
            .collect();
        if expired.is_empty() {
            return 0;
        }
        for hash in &expired {
            if let Some(persisted) = self.records_by_hash.remove(hash) {
                match &persisted.record.subject {
                    RevokedSubject::Agent(id) => {
                        self.revoked_agents.remove(id);
                    }
                    RevokedSubject::Machine(id) => {
                        self.revoked_machines.remove(id);
                    }
                }
            }
        }
        self.change_generation = self.change_generation.saturating_add(1);
        expired.len()
    }

    fn insert_verified(&mut self, persisted: PersistedRevocation) -> bool {
        let hash = persisted.record.record_hash();
        if self.records_by_hash.contains_key(&hash) {
            return false;
        }
        match &persisted.record.subject {
            RevokedSubject::Agent(id) => {
                self.revoked_agents.insert(*id);
            }
            RevokedSubject::Machine(id) => {
                self.revoked_machines.insert(*id);
            }
        }
        self.records_by_hash.insert(hash, persisted);
        self.change_generation = self.change_generation.saturating_add(1);
        true
    }

    /// All held records (order unspecified), for rebroadcast/anti-entropy.
    #[must_use]
    pub fn all_records(&self) -> Vec<RevocationRecord> {
        self.records_by_hash
            .values()
            .map(|p| p.record.clone())
            .collect()
    }

    /// Encode the set for on-disk persistence: `X0XR` magic + bincode of the
    /// record list (each record carrying the certificate that authorizes it,
    /// where applicable).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let records: Vec<&PersistedRevocation> = self.records_by_hash.values().collect();
        let body = bincode::serialize(&records)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut out = Vec::with_capacity(REVOCATIONS_FILE_MAGIC.len() + body.len());
        out.extend_from_slice(REVOCATIONS_FILE_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a set previously written by [`to_bytes`](Self::to_bytes),
    /// **re-verifying every record's authority on load**.
    ///
    /// The on-disk file is untrusted input: a record that fails re-verification
    /// (forged signature, or an issuer-revocation whose persisted certificate
    /// no longer authorizes it) is silently dropped rather than trusted, so a
    /// tampered `revocations.bin` cannot inject an unverified revocation.
    /// Legitimately-verified records — including issuer-revocations, whose
    /// authorizing certificate is persisted alongside them — are preserved.
    ///
    /// An empty input yields an empty set (a missing file is not an error).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] if the magic is missing or the
    /// body is malformed.
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
        let persisted: Vec<PersistedRevocation> =
            bincode::deserialize(&bytes[REVOCATIONS_FILE_MAGIC.len()..])
                .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut set = Self::new();
        for entry in persisted {
            // Re-verify authority against the persisted certificate. A record
            // that no longer verifies is dropped (not present in the set) —
            // this is the load-path enforcement of the authority model.
            let _ = set.verify_and_insert(entry.record, entry.subject_cert.as_ref());
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    mod revocation_cadence {
        use super::super::*;
        use crate::identity::AgentKeypair;

        /// Build a self-signed revocation record for an agent at the given
        /// timestamp. Self-revocations require no subject certificate.
        fn self_revocation(agent_kp: &AgentKeypair, revoked_at: u64) -> RevocationRecord {
            RevocationRecord::sign(
                RevokedSubject::Agent(agent_kp.agent_id()),
                agent_kp.public_key(),
                agent_kp.secret_key(),
                revoked_at,
                None,
            )
            .expect("self-revocation signs")
        }

        /// #380 cadence: the TTL expiry kills the 2 stale July testnet
        /// records that cost 222 KB/s fleet-wide on the revocation topic.
        #[test]
        fn ttl_expires_stale_records_and_unrevokes_subject() {
            let kp = AgentKeypair::generate().expect("agent keypair");
            let mut set = RevocationSet::new();
            let now = 1_800_000_000u64;

            let stale = self_revocation(&kp, now - 91 * 24 * 3600);
            set.verify_and_insert(stale, None)
                .expect("stale record verifies");
            assert!(set.is_agent_revoked(&kp.agent_id()));

            let expired = set.expire_records_older_than(90 * 24 * 3600, now);
            assert_eq!(expired, 1, "the 91-day-old record must expire");
            assert!(
                !set.is_agent_revoked(&kp.agent_id()),
                "the expired subject is no longer revoked"
            );
            assert!(set.all_records().is_empty());
        }

        /// #380 cadence: fresh records survive the TTL.
        #[test]
        fn ttl_keeps_fresh_records() {
            let kp = AgentKeypair::generate().expect("agent keypair");
            let mut set = RevocationSet::new();
            let now = 1_800_000_000u64;

            let fresh = self_revocation(&kp, now - 24 * 3600);
            set.verify_and_insert(fresh, None).expect("fresh verifies");

            let expired = set.expire_records_older_than(90 * 24 * 3600, now);
            assert_eq!(expired, 0);
            assert!(set.is_agent_revoked(&kp.agent_id()));
        }

        /// #380 cadence: the change generation advances on insert AND on
        /// expiry — the on-change piggyback key.
        #[test]
        fn generation_advances_on_insert_and_expiry() {
            let kp = AgentKeypair::generate().expect("agent keypair");
            let mut set = RevocationSet::new();
            let now = 1_800_000_000u64;
            let gen0 = set.generation();

            let stale = self_revocation(&kp, now - 91 * 24 * 3600);
            set.verify_and_insert(stale, None).expect("verifies");
            let gen1 = set.generation();
            assert!(gen1 > gen0, "insert must advance the generation");

            set.expire_records_older_than(90 * 24 * 3600, now);
            let gen2 = set.generation();
            assert!(gen2 > gen1, "expiry must advance the generation");

            // No-op: neither insert nor expiry fires.
            set.expire_records_older_than(90 * 24 * 3600, now);
            assert_eq!(set.generation(), gen2, "no-change must not advance");
        }
    }
}
