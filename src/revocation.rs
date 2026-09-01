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

/// Magic marker prefixing the ADR-0043 ad-hoc binding-record file
/// (`revocations-v2.bin`).
const REVOCATIONS_FILE_MAGIC_V2: &[u8; 4] = b"X0R2";

/// An `(agent, machine, move_epoch)` pairing retired by an ADR-0043 move
/// (or an ad-hoc owner revocation of the same pairing). Revokes the PAIR —
/// never the whole machine, never co-resident agents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentMachineBinding {
    /// The portable agent identity whose binding is retired.
    pub agent: AgentId,
    /// The machine the agent may no longer sign from.
    pub machine: MachineId,
    /// The move that retired the binding (orders tombstones against
    /// placement records).
    pub move_epoch: u64,
}

/// The identity a revocation record targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevokedSubject {
    /// A portable agent identity.
    Agent(AgentId),
    /// A hardware-pinned machine identity.
    Machine(MachineId),
    /// An ADR-0043 agent↔machine binding: the agent may keep existing,
    /// the machine may keep hosting other agents, but THIS pairing is
    /// permanently dead. Owner-key issued only (self-revocation is
    /// structurally impossible — the issuer key hashes to one 32-byte id,
    /// the subject carries two ids plus an epoch).
    AgentMachineBinding(AgentMachineBinding),
}

impl From<AgentMachineBinding> for RevokedSubject {
    fn from(binding: AgentMachineBinding) -> Self {
        RevokedSubject::AgentMachineBinding(binding)
    }
}

impl RevokedSubject {
    /// Domain tag byte distinguishing the subject kind in signed bytes.
    fn tag(&self) -> u8 {
        match self {
            RevokedSubject::Agent(_) => 0x01,
            RevokedSubject::Machine(_) => 0x02,
            RevokedSubject::AgentMachineBinding(_) => 0x03,
        }
    }

    /// The raw 32-byte identifier of the subject (Agent/Machine subjects).
    /// Binding subjects carry TWO ids plus an epoch — see
    /// [`Self::binding_subject_bytes`].
    fn id_bytes(&self) -> &[u8; 32] {
        match self {
            RevokedSubject::Agent(id) => id.as_bytes(),
            RevokedSubject::Machine(id) => id.as_bytes(),
            RevokedSubject::AgentMachineBinding(_) => {
                // Unreachable in canonical construction: canonical_message
                // dispatches bindings to binding_subject_bytes. The empty slice
                // keeps callers that only match Agent/Machine total.
                static EMPTY: [u8; 32] = [0u8; 32];
                &EMPTY
            }
        }
    }

    /// Fixed-width subject bytes of a binding: `agent ‖ machine ‖
    /// epoch_le` — no boundary ambiguity (the §7.1 canonical form).
    fn binding_subject_bytes(&self) -> Option<Vec<u8>> {
        match self {
            RevokedSubject::AgentMachineBinding(binding) => {
                let mut out = Vec::with_capacity(32 + 32 + 8);
                out.extend_from_slice(binding.agent.as_bytes());
                out.extend_from_slice(binding.machine.as_bytes());
                out.extend_from_slice(&binding.move_epoch.to_le_bytes());
                Some(out)
            }
            _ => None,
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
    /// field boundary falls cannot collide. Binding subjects use the §7.1
    /// fixed-width form `prefix ‖ 0x03 ‖ agent ‖ machine ‖ epoch_le`.
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
                + 72
                + issuer_public_key.len()
                + 8
                + 8
                + reason_bytes.len(),
        );
        msg.extend_from_slice(REVOCATION_MSG_PREFIX);
        msg.push(subject.tag());
        if let Some(binding_bytes) = subject.binding_subject_bytes() {
            // §7.1: `prefix ‖ 0x03 ‖ agent ‖ machine ‖ epoch_le` — fixed
            // widths, no boundary ambiguity.
            msg.extend_from_slice(&binding_bytes);
        } else {
            msg.extend_from_slice(subject.id_bytes());
        }
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
        //    Binding subjects never take this path (no single subject id).
        let issuer_id = derive_peer_id_from_public_key(&issuer_pubkey).0;
        if !matches!(self.subject, RevokedSubject::AgentMachineBinding(_))
            && &issuer_id == self.subject.id_bytes()
        {
            return Ok(());
        }

        // 3. Issuer-revocation: the issuer key is the user key that signed
        //    the subject agent's certificate. For a BINDING subject
        //    (ADR-0043 §7.2) this is the ONLY legal authority path —
        //    self-revocation is structurally unreachable (the subject
        //    carries two ids plus an epoch, not one 32-byte id), so the
        //    certificate is REQUIRED, never optional.
        let subject_agent = match &self.subject {
            RevokedSubject::Agent(agent) => Some(*agent),
            RevokedSubject::AgentMachineBinding(binding) => Some(binding.agent),
            RevokedSubject::Machine(_) => None,
        };
        if let Some(subject_agent) = subject_agent {
            if let Some(cert) = subject_cert {
                let cert_binds_subject =
                    cert.agent_id().map(|a| a == subject_agent).unwrap_or(false);
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

    /// Whether this is a self-revocation — the issuer key hashes to the
    /// subject id.
    ///
    /// A self-revocation re-verifies from the record alone (no certificate
    /// needed); an issuer-revocation requires the subject agent's certificate.
    /// A malformed issuer key yields `false` (it will fail verification anyway).
    #[must_use]
    pub fn is_self_revocation(&self) -> bool {
        match (
            &self.subject,
            MlDsaPublicKey::from_bytes(&self.issuer_public_key),
        ) {
            // Bindings have no single subject id — never self-revocable.
            (RevokedSubject::AgentMachineBinding(_), _) => false,
            (_, Ok(pk)) => &derive_peer_id_from_public_key(&pk).0 == self.subject.id_bytes(),
            (_, Err(_)) => false,
        }
    }

    /// Hex-encoded subject identifier (32 bytes → 64 hex chars).
    ///
    /// Convenience for REST responses — avoids exposing raw `[u8; 32]` in
    /// JSON. A binding subject surfaces its AGENT id (the pairing's primary
    /// identity; the machine rides in the record's REST view separately).
    #[must_use]
    pub fn subject_hex(&self) -> String {
        match &self.subject {
            RevokedSubject::AgentMachineBinding(binding) => hex::encode(binding.agent.as_bytes()),
            _ => hex::encode(self.subject.id_bytes()),
        }
    }

    /// Human-readable subject kind: `"agent"`, `"machine"`, or `"binding"`.
    #[must_use]
    pub fn subject_kind(&self) -> &'static str {
        match &self.subject {
            RevokedSubject::Agent(_) => "agent",
            RevokedSubject::Machine(_) => "machine",
            RevokedSubject::AgentMachineBinding(_) => "binding",
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
    /// ADR-0043 tombstone epochs from ad-hoc binding `RevocationRecord`s
    /// (`x0x.revocation.v2` carrier). Grow-only; never TTL-swept.
    binding_epochs: HashMap<(AgentId, MachineId), u64>,
    /// ADR-0043 tombstone epochs unioned from VERIFIED
    /// `ActivationBundle.retired_bindings` sets (owner-covered by the
    /// bundle signature — not standalone records). Grow-only, order-
    /// independent; never TTL-swept. Both maps feed
    /// [`Self::is_binding_revoked`].
    bundle_retired_epochs: HashMap<(AgentId, MachineId), u64>,
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

    /// Whether an `(agent, machine)` binding is retired (ADR-0043 check
    /// **B**): the grow-only union of bundle `retired_bindings` and ad-hoc
    /// v2 tombstones.
    #[must_use]
    pub fn is_binding_revoked(&self, agent: &AgentId, machine: &MachineId) -> bool {
        let key = (*agent, *machine);
        self.binding_epochs.contains_key(&key) || self.bundle_retired_epochs.contains_key(&key)
    }

    /// Highest epoch of any tombstone for the agent across both carriers,
    /// ordering placement records against tombstones (§9 check **P**).
    #[must_use]
    pub fn max_revoked_binding_epoch(&self, agent: &AgentId) -> Option<u64> {
        let from_records = self
            .binding_epochs
            .iter()
            .filter(|((a, _), _)| a == agent)
            .map(|(_, epoch)| *epoch)
            .max();
        let from_bundles = self
            .bundle_retired_epochs
            .iter()
            .filter(|((a, _), _)| a == agent)
            .map(|(_, epoch)| *epoch)
            .max();
        from_records.max(from_bundles)
    }

    /// Union a VERIFIED `ActivationBundle`'s cumulative `retired_bindings`
    /// into the grow-only tombstone set (order-independent; the entries are
    /// owner-covered by the bundle's signature, not standalone records).
    /// Returns `true` when anything new was added.
    ///
    /// # Security
    ///
    /// Callers MUST have passed the bundle through
    /// [`crate::key_move::verify_bundle_mesh`] first — this method performs
    /// no cryptography.
    pub fn union_bundle_retired(&mut self, bindings: &[AgentMachineBinding]) -> bool {
        let mut changed = false;
        for binding in bindings {
            let key = (binding.agent, binding.machine);
            let entry = self.bundle_retired_epochs.entry(key).or_insert(0);
            if *entry < binding.move_epoch {
                *entry = binding.move_epoch;
                changed = true;
            }
        }
        if changed {
            self.change_generation = self.change_generation.saturating_add(1);
        }
        changed
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
            // ADR-0043 §7.3: binding tombstones are PERMANENT — a retired
            // binding must never resurrect, so the TTL sweep skips them.
            .filter(|(_, persisted)| {
                persisted.record.revoked_at < cutoff
                    && !matches!(
                        persisted.record.subject,
                        RevokedSubject::AgentMachineBinding(_)
                    )
            })
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
                    // Bindings never reach the expired list (filter
                    // above); arm kept total for exhaustiveness.
                    RevokedSubject::AgentMachineBinding(binding) => {
                        self.binding_epochs
                            .remove(&(binding.agent, binding.machine));
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
            RevokedSubject::AgentMachineBinding(binding) => {
                // Keep the highest epoch per pairing — the grow-only
                // tombstone set orders placement records (§9 P).
                let key = (binding.agent, binding.machine);
                let entry = self.binding_epochs.entry(key).or_insert(0);
                *entry = (*entry).max(binding.move_epoch);
            }
        }
        self.records_by_hash.insert(hash, persisted);
        self.change_generation = self.change_generation.saturating_add(1);
        true
    }

    /// All held records for the V1 wire (`Agent`/`Machine` subjects only,
    /// order unspecified), for rebroadcast/anti-entropy.
    ///
    /// ADR-0043 §7.4: the v1 batch is one whole `Vec<RevocationRecord>`
    /// that legacy peers deserialize in full — an unknown `0x03` variant
    /// would poison every co-resident record for old peers, so the v1
    /// publication filters to legacy subjects and stays byte-identical.
    #[must_use]
    pub fn all_records(&self) -> Vec<RevocationRecord> {
        self.records_by_hash
            .values()
            .filter(|p| !matches!(p.record.subject, RevokedSubject::AgentMachineBinding(_)))
            .map(|p| p.record.clone())
            .collect()
    }

    /// All held binding-subject records (ad-hoc tombstones) for the
    /// `x0x.revocation.v2` carrier and the `revocations-v2.bin` store.
    #[must_use]
    pub fn binding_records(&self) -> Vec<RevocationRecord> {
        self.records_by_hash
            .values()
            .filter(|p| matches!(p.record.subject, RevokedSubject::AgentMachineBinding(_)))
            .map(|p| p.record.clone())
            .collect()
    }

    /// Encode the V1 set for on-disk persistence: `X0XR` magic + bincode of
    /// the legacy-subject (`Agent`/`Machine`) record list, each record
    /// carrying the certificate that authorizes it. Binding tombstones
    /// persist via [`Self::to_bytes_v2`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let records: Vec<&PersistedRevocation> = self
            .records_by_hash
            .values()
            .filter(|p| !matches!(p.record.subject, RevokedSubject::AgentMachineBinding(_)))
            .collect();
        let body = bincode::serialize(&records)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut out = Vec::with_capacity(REVOCATIONS_FILE_MAGIC.len() + body.len());
        out.extend_from_slice(REVOCATIONS_FILE_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Encode the ADR-0043 ad-hoc binding records for
    /// `revocations-v2.bin`: `X0R2` magic + bincode of the persisted
    /// entries (cert included — issuer authority re-verifies on load).
    /// Bundle-unioned tombstones are re-derived from `move-bundles.bin`
    /// on load and are NOT duplicated here.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn to_bytes_v2(&self) -> Result<Vec<u8>, IdentityError> {
        let records: Vec<&PersistedRevocation> = self
            .records_by_hash
            .values()
            .filter(|p| matches!(p.record.subject, RevokedSubject::AgentMachineBinding(_)))
            .collect();
        let body = bincode::serialize(&records)
            .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut out = Vec::with_capacity(REVOCATIONS_FILE_MAGIC_V2.len() + body.len());
        out.extend_from_slice(REVOCATIONS_FILE_MAGIC_V2);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a `revocations-v2.bin` previously written by
    /// [`to_bytes_v2`](Self::to_bytes_v2), re-verifying every record's
    /// authority on load. Merge into the main set with
    /// [`merge_v2`](Self::merge_v2) — the returned set holds only the
    /// binding records.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] if the magic is missing or
    /// the body is malformed. Empty input yields an empty set.
    pub fn from_bytes_v2(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        if bytes.len() < REVOCATIONS_FILE_MAGIC_V2.len()
            || &bytes[..REVOCATIONS_FILE_MAGIC_V2.len()] != REVOCATIONS_FILE_MAGIC_V2
        {
            return Err(IdentityError::Serialization(
                "revocation v2 file missing X0R2 magic".to_string(),
            ));
        }
        let persisted: Vec<PersistedRevocation> =
            bincode::deserialize(&bytes[REVOCATIONS_FILE_MAGIC_V2.len()..])
                .map_err(|e| IdentityError::Serialization(e.to_string()))?;
        let mut set = Self::new();
        for entry in persisted {
            // Fail-closed load path: an entry that no longer verifies is
            // dropped, never trusted.
            let _ = set.verify_and_insert(entry.record, entry.subject_cert.as_ref());
        }
        Ok(set)
    }

    /// Merge a decoded v2 set into this one (grow-only union).
    pub fn merge_v2(&mut self, other: Self) {
        for ((agent, machine), epoch) in other.binding_epochs {
            let key = (agent, machine);
            let entry = self.binding_epochs.entry(key).or_insert(0);
            *entry = (*entry).max(epoch);
        }
        for (hash, persisted) in other.records_by_hash {
            self.records_by_hash.entry(hash).or_insert(persisted);
        }
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]

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
        assert!(
            set.verify_and_insert(record.clone(), None).unwrap(),
            "first insert is new"
        );
        assert!(
            !set.verify_and_insert(record.clone(), None).unwrap(),
            "re-inserting the same record must be idempotent"
        );
        assert_eq!(set.len(), 1);
        assert!(set.is_agent_revoked(&agent.agent_id()));
        assert!(!set.is_machine_revoked(&MachineKeypair::generate().unwrap().machine_id()));
    }

    #[test]
    fn revocation_set_persists_and_reloads() {
        // The on-disk round-trip preserves the gate state — a daemon restart
        // must not forget revocations it learned. Includes an issuer-revocation
        // (cert persisted alongside) so the reload re-verifies it via that cert.
        let agent = AgentKeypair::generate().unwrap();
        let machine = MachineKeypair::generate().unwrap();
        let user = UserKeypair::generate().unwrap();
        let issued_agent = AgentKeypair::generate().unwrap();
        let cert = AgentCertificate::issue(&user, &issued_agent).unwrap();
        let mut set = RevocationSet::new();
        // self-revocation (agent)
        set.verify_and_insert(
            RevocationRecord::sign(
                RevokedSubject::Agent(agent.agent_id()),
                agent.public_key(),
                agent.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            None,
        )
        .unwrap();
        // self-revocation (machine)
        set.verify_and_insert(
            RevocationRecord::sign(
                RevokedSubject::Machine(machine.machine_id()),
                machine.public_key(),
                machine.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            None,
        )
        .unwrap();
        // issuer-revocation (user revokes a certified agent)
        set.verify_and_insert(
            RevocationRecord::sign(
                RevokedSubject::Agent(issued_agent.agent_id()),
                user.public_key(),
                user.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            Some(&cert),
        )
        .unwrap();
        let bytes = set.to_bytes().unwrap();
        let reloaded = RevocationSet::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded.len(), 3, "all three records must survive reload");
        assert!(reloaded.is_agent_revoked(&agent.agent_id()));
        assert!(reloaded.is_machine_revoked(&machine.machine_id()));
        assert!(
            reloaded.is_agent_revoked(&issued_agent.agent_id()),
            "issuer-revocation must re-verify on load via its persisted cert"
        );
    }

    #[test]
    fn revocation_set_from_bytes_rejects_forged_and_unrelated_records() {
        // SECURITY: revocations.bin is untrusted input. A record whose signature
        // is forged (tampered after signing) and an issuer-revocation whose
        // persisted cert does not authorize it must both be DROPPED on load,
        // while a legitimately-signed self-revocation and a properly-certified
        // issuer-revocation must survive. This pins load-path authority
        // enforcement — without it a tampered file would inject revocations.
        let good_agent = AgentKeypair::generate().unwrap();
        let user = UserKeypair::generate().unwrap();
        let issued_agent = AgentKeypair::generate().unwrap();
        let good_cert = AgentCertificate::issue(&user, &issued_agent).unwrap();

        // Legit self-revocation.
        let good_self = PersistedRevocation {
            record: RevocationRecord::sign(
                RevokedSubject::Agent(good_agent.agent_id()),
                good_agent.public_key(),
                good_agent.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            subject_cert: None,
        };

        // Legit issuer-revocation, cert persisted alongside.
        let good_issuer = PersistedRevocation {
            record: RevocationRecord::sign(
                RevokedSubject::Agent(issued_agent.agent_id()),
                user.public_key(),
                user.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            subject_cert: Some(good_cert.clone()),
        };

        // Forged: a validly-signed self-revocation tampered after signing.
        let forged_agent = AgentKeypair::generate().unwrap();
        let mut forged_record = RevocationRecord::sign(
            RevokedSubject::Agent(forged_agent.agent_id()),
            forged_agent.public_key(),
            forged_agent.secret_key(),
            now(),
            None,
        )
        .unwrap();
        forged_record.revoked_at = forged_record.revoked_at.wrapping_add(1);
        let forged = PersistedRevocation {
            record: forged_record,
            subject_cert: None,
        };

        // Unrelated issuer: a third party's key with a cert that does not bind
        // them to the subject.
        let attacker = UserKeypair::generate().unwrap();
        let victim_agent = AgentKeypair::generate().unwrap();
        let unrelated = PersistedRevocation {
            record: RevocationRecord::sign(
                RevokedSubject::Agent(victim_agent.agent_id()),
                attacker.public_key(),
                attacker.secret_key(),
                now(),
                None,
            )
            .unwrap(),
            // Attach a real cert, but it certifies issued_agent (not the
            // victim) and is signed by `user` (not the attacker).
            subject_cert: Some(good_cert),
        };

        // Craft the on-disk bytes directly (bypassing verify_and_insert) to
        // simulate a tampered file.
        let entries = vec![good_self, good_issuer, forged, unrelated];
        let mut bytes = REVOCATIONS_FILE_MAGIC.to_vec();
        bytes.extend_from_slice(&bincode::serialize(&entries).unwrap());

        let loaded = RevocationSet::from_bytes(&bytes).unwrap();
        assert_eq!(
            loaded.len(),
            2,
            "only the two authoritative records may survive load"
        );
        assert!(
            loaded.is_agent_revoked(&good_agent.agent_id()),
            "legit self-revocation must survive"
        );
        assert!(
            loaded.is_agent_revoked(&issued_agent.agent_id()),
            "legit issuer-revocation (with cert) must survive"
        );
        assert!(
            !loaded.is_agent_revoked(&forged_agent.agent_id()),
            "forged record must be rejected on load"
        );
        assert!(
            !loaded.is_agent_revoked(&victim_agent.agent_id()),
            "unrelated-issuer record must be rejected on load"
        );
    }

    #[test]
    fn revocation_set_from_empty_is_empty() {
        assert!(RevocationSet::from_bytes(&[]).unwrap().is_empty());
    }
    /// ADR-0043 §7: binding-revocation authority matrix, carrier split,
    /// and permanence. The WHY: only the owner key may retire a pairing —
    /// not the moving agent, not either machine, not a third user — and a
    /// retired binding must never resurrect via TTL or a v1 round-trip.
    #[test]
    fn binding_revocation_authority_matrix_and_carriers() {
        use crate::identity::{AgentKeypair, UserKeypair};

        let owner = UserKeypair::generate().unwrap();
        let agent_kp = AgentKeypair::generate().unwrap();
        let cert = crate::identity::AgentCertificate::issue(&owner, &agent_kp).unwrap();
        let machine = crate::identity::MachineId([7u8; 32]);
        let binding = AgentMachineBinding {
            agent: agent_kp.agent_id(),
            machine,
            move_epoch: 3,
        };

        // Owner-key issued with the cert: accepted.
        let record = RevocationRecord::sign(
            RevokedSubject::AgentMachineBinding(binding.clone()),
            owner.public_key(),
            owner.secret_key(),
            1_000,
            Some("stolen machine".into()),
        )
        .unwrap();
        assert!(record.verify_authority(Some(&cert)).is_ok());
        // Without the cert: fail-closed (issuer authority unverifiable).
        assert!(record.verify_authority(None).is_err());
        assert!(!record.is_self_revocation());
        assert_eq!(record.subject_kind(), "binding");

        // The moving agent's own key cannot issue it.
        let agent_issued = RevocationRecord::sign(
            RevokedSubject::AgentMachineBinding(binding.clone()),
            agent_kp.public_key(),
            agent_kp.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        assert!(agent_issued.verify_authority(Some(&cert)).is_err());

        // A third user cannot issue it.
        let stranger = UserKeypair::generate().unwrap();
        let stranger_issued = RevocationRecord::sign(
            RevokedSubject::AgentMachineBinding(binding.clone()),
            stranger.public_key(),
            stranger.secret_key(),
            1_000,
            None,
        )
        .unwrap();
        assert!(stranger_issued.verify_authority(Some(&cert)).is_err());

        // Insert → check B → v1 wire excludes it, v2 round-trips it →
        // TTL sweep NEVER expires it.
        let mut set = RevocationSet::new();
        assert!(set.verify_and_insert(record.clone(), Some(&cert)).unwrap());
        assert!(set.is_binding_revoked(&binding.agent, &machine));
        assert_eq!(set.max_revoked_binding_epoch(&binding.agent), Some(3));
        assert!(
            set.all_records().is_empty(),
            "v1 wire must never carry the 0x03 variant (§7.4)"
        );
        assert_eq!(set.binding_records().len(), 1);

        let v2 = set.to_bytes_v2().unwrap();
        let loaded = RevocationSet::from_bytes_v2(&v2).unwrap();
        assert!(loaded.is_binding_revoked(&binding.agent, &machine));
        let mut merged = RevocationSet::new();
        merged.merge_v2(loaded);
        assert!(merged.is_binding_revoked(&binding.agent, &machine));

        // Permanence: a sweep far past any TTL keeps the tombstone.
        let expired = set.expire_records_older_than(60, 10_000_000);
        assert_eq!(expired, 0);
        assert!(set.is_binding_revoked(&binding.agent, &machine));

        // Bundle-unioned tombstones (no standalone record) feed the same
        // check and never expire.
        let mut set2 = RevocationSet::new();
        assert!(set2.union_bundle_retired(&[
            binding.clone(),
            AgentMachineBinding {
                agent: binding.agent,
                machine: crate::identity::MachineId([8u8; 32]),
                move_epoch: 1,
            }
        ]));
        assert!(set2.is_binding_revoked(&binding.agent, &machine));
        assert_eq!(set2.max_revoked_binding_epoch(&binding.agent), Some(3));
        assert!(set2.binding_records().is_empty());
        assert!(set2.expire_records_older_than(0, u64::MAX) == 0);
        assert!(set2.is_binding_revoked(&binding.agent, &machine));
    }

    /// HS-A review fixture gap (seam check 2026-08-30, concern 2 / MINOR-4):
    /// the X0R2 carrier is isolated on its own topic and file today, but
    /// nothing pinned the bincode shape of `PersistedRevocation` carrying a
    /// `RevokedSubject::AgentMachineBinding` (variant 2 of the file era,
    /// enum tag 0x03). A future field INSERTED into `PersistedRevocation`,
    /// `RevocationRecord`, or before the existing `RevokedSubject` variants
    /// would silently break every older v2 decoder. Pin the exact bytes.
    #[test]
    fn revocations_v2_file_bytes_match_frozen_vector() {
        let record = RevocationRecord {
            subject: RevokedSubject::AgentMachineBinding(AgentMachineBinding {
                agent: AgentId([0xA1; 32]),
                machine: MachineId([0xA2; 32]),
                move_epoch: 7,
            }),
            issuer_public_key: vec![0xB1; 4],
            revoked_at: 1_700_000_321,
            reason: Some("key-move".to_string()),
            signature: vec![0xC1; 4],
        };
        let mut set = RevocationSet::new();
        assert!(set.insert_verified(PersistedRevocation {
            record,
            subject_cert: None,
        }));

        let bytes = set.to_bytes_v2().expect("encode v2 file");
        println!(
            "X0R2_FROZEN_HEX={}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        const FROZEN_X0R2_HEX: &str = "58305232010000000000000002000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a207000000000000000400000000000000b1b1b1b141f25365000000000108000000000000006b65792d6d6f76650400000000000000c1c1c1c100";
        let frozen = hex::decode(FROZEN_X0R2_HEX).expect("frozen hex");
        assert_eq!(
            bytes, frozen,
            "X0R2 file bytes must stay byte-identical (append-only fields/variants)"
        );
        // The pinned vector itself decodes as a v2 set (the record fails
        // authority re-verification by construction — fake keys — so the
        // decoded set is empty; the shape pin above is the contract).
        let decoded = RevocationSet::from_bytes_v2(&frozen).expect("decode v2 file");
        assert!(decoded.is_empty());
    }
}
