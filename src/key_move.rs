//! ADR-0043 agent key-move protocol: the per-agent signed move log, the
//! total fold, participant/mesh verification rules, the export envelope,
//! and the derived placement ledger.
//!
//! # One durable record; everything else derived
//!
//! The signed per-agent log (`ChainedRecord`s) is the only durable move
//! state. It folds **totally** — for every legal shape (initial mint,
//! mid-move, post-activation, post-abort) — to `MoveFold` carrying
//! `custodian`, `retired_bindings`, `placement`, and `phase`. Key
//! possession is a gate INPUT, not log state:
//!
//! ```text
//! may_sign(M, A)    = holds_key(M, A) ∧ custodian(A) == M
//! quiesced(M, A)    = holds_key(M, A) ∧ (phase == MidMove{from: M} ∨ RetirePending{from: M})
//! quarantined(M, A) = holds_key(M, A) ∧ phase == MidMove{to: M}
//! ```
//!
//! No ordered mutations exist to crash between; replay is idempotent;
//! partial application is impossible by construction.
//!
//! # Two verification rules, one derivation (§3.3)
//!
//! **Participants** (source/target/owner) hold the full log and accept a
//! record iff signatures verify AND `prev` equals their head (CAS) AND the
//! kind is a legal successor. **Mesh peers** never see pre-activation
//! records; they accept a carried `MoveRecord::ActivationBundle` on
//! whole-record owner signature + cross-field coherence + placement-epoch
//! monotonicity, while its cumulative tombstones union in unconditionally.
//!
//! # Enforcement (§9)
//!
//! Two checks wherever an `(agent, machine)` pairing is known:
//! **B** — [`RevocationSet::is_binding_revoked`](crate::revocation::RevocationSet::is_binding_revoked); and
//! **P** — a cached placement record at epoch ≥ the highest revoked
//! binding epoch whose pin is a DIFFERENT machine denies the pairing.
//! Absent evidence fails open (ADR-0043 §9.3).

use std::collections::{HashMap, HashSet};

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};
use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};
use crate::groups::kem_envelope::{open_sealed_bytes, seal_bytes_to_recipient, AgentKemKeypair};
use crate::identity::{AgentCertificate, AgentId, MachineId};
use crate::revocation::{AgentMachineBinding, RevocationSet};

/// Domain-separation prefix for the bytes an owner signature covers over a
/// chained move record (mirrors `REVOCATION_MSG_PREFIX`).
pub const MOVE_MSG_PREFIX: &[u8] = b"x0x-agent-move.v1";

/// Domain-separation prefix for the bytes an owner signature covers over a
/// placement record (ADR-0043 §8.1).
pub const PLACEMENT_MSG_PREFIX: &[u8] = b"x0x-placement.v1";

/// Magic marker for the participant move-log file (`moves.bin`).
const MOVES_FILE_MAGIC: &[u8; 4] = b"X0XM";
/// Magic marker for the mesh bundle store (`move-bundles.bin`).
const BUNDLES_FILE_MAGIC: &[u8; 4] = b"X0MB";
/// Magic marker for the placement-record cache (`placement-blobs.bin`).
const PLACEMENTS_FILE_MAGIC: &[u8; 4] = b"X0PB";

/// Genesis `prev` value — the first record of every per-agent log.
pub const GENESIS_PREV: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Placement (§8)
// ---------------------------------------------------------------------------

/// Where an agent's key is authorized to live (ADR-0037/0043).
///
/// `Roaming` names **no** machine: a roamer's per-machine authorization is
/// exactly the derived tombstone set; `Pinned(MachineId)` carries the pin
/// compared at enforcement gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Placement {
    /// The agent's key lives on exactly this machine.
    Pinned(MachineId),
    /// The agent may sign from any machine whose binding is not retired.
    Roaming,
}

impl Placement {
    /// The pin target, when pinned.
    #[must_use]
    pub fn pinned_machine(&self) -> Option<MachineId> {
        match self {
            Placement::Pinned(m) => Some(*m),
            Placement::Roaming => None,
        }
    }

    /// Wire-friendly kind tag for REST views.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Placement::Pinned(_) => "pinned",
            Placement::Roaming => "roaming",
        }
    }
}

/// Owner-signed statement of an agent's current placement (ADR-0043 §8.1).
///
/// `owner_public_key` must equal the issuer of the agent's
/// [`AgentCertificate`] — coherence clause 2/4 of the mesh rule checks
/// exactly that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRecord {
    pub agent_id: AgentId,
    /// Owner (user) ML-DSA-65 public key — the certificate issuer.
    pub owner_public_key: Vec<u8>,
    pub placement: Placement,
    /// Epoch of the move that produced this record (0 = mint).
    pub placement_epoch: u64,
    pub issued_at: u64,
    /// Owner ML-DSA-65 signature over [`PLACEMENT_MSG_PREFIX`] ‖ unsigned
    /// fields.
    pub signature: Vec<u8>,
}

impl PlacementRecord {
    fn canonical_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(
            PLACEMENT_MSG_PREFIX.len() + 32 + 8 + self.owner_public_key.len() + 1 + 32 + 8 + 8,
        );
        msg.extend_from_slice(PLACEMENT_MSG_PREFIX);
        msg.extend_from_slice(self.agent_id.as_bytes());
        msg.extend_from_slice(&(self.owner_public_key.len() as u64).to_le_bytes());
        msg.extend_from_slice(&self.owner_public_key);
        match self.placement {
            Placement::Pinned(machine) => {
                msg.push(0x01);
                msg.extend_from_slice(machine.as_bytes());
            }
            Placement::Roaming => msg.push(0x02),
        }
        msg.extend_from_slice(&self.placement_epoch.to_le_bytes());
        msg.extend_from_slice(&self.issued_at.to_le_bytes());
        msg
    }

    /// BLAKE3 of the canonical bytes — the digest machines advertise on
    /// `MachineAnnouncementV3.placement_digests` and blob-v2 keys on.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_message()).as_bytes()
    }

    /// Sign a placement record with the owner (user) key.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::CertificateVerification`] on signing
    /// failure.
    pub fn sign(
        agent_id: AgentId,
        owner_public_key: &[u8],
        placement: Placement,
        placement_epoch: u64,
        issued_at: u64,
        owner_secret: &MlDsaSecretKey,
    ) -> Result<Self> {
        let unsigned = Self {
            agent_id,
            owner_public_key: owner_public_key.to_vec(),
            placement,
            placement_epoch,
            issued_at,
            signature: Vec::new(),
        };
        let message = unsigned.canonical_message();
        let signature = sign_with_ml_dsa(owner_secret, &message).map_err(|e| {
            IdentityError::CertificateVerification(format!("placement signing failed: {e:?}"))
        })?;
        Ok(Self {
            signature: signature.as_bytes().to_vec(),
            ..unsigned
        })
    }

    /// Verify the owner signature over the canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] on a bad key or signature.
    pub fn verify(&self) -> std::result::Result<(), IdentityError> {
        let owner = MlDsaPublicKey::from_bytes(&self.owner_public_key)
            .map_err(|e| IdentityError::Revocation(format!("invalid owner public key: {e:?}")))?;
        let signature = MlDsaSignature::from_bytes(&self.signature).map_err(|e| {
            IdentityError::Revocation(format!("invalid placement signature: {e:?}"))
        })?;
        verify_with_ml_dsa(&owner, &self.canonical_message(), &signature).map_err(|e| {
            IdentityError::Revocation(format!("placement signature verification failed: {e:?}"))
        })
    }

    /// Coherence against the certificate that binds the agent to this
    /// owner: the record's owner key must BE the certificate issuer.
    /// A forged record pinning someone else's agent fails here.
    #[must_use]
    pub fn owner_matches_cert(&self, cert: &AgentCertificate) -> bool {
        cert.agent_id().is_ok_and(|a| a == self.agent_id)
            && self.owner_public_key.as_slice() == cert.user_public_key_bytes()
    }
}

// ---------------------------------------------------------------------------
// Move records (§3.1)
// ---------------------------------------------------------------------------

/// Owner-signed authorization for exactly one move (ADR-0043 §3.1).
///
/// Contains **no envelope digest** — the dependency graph is acyclic: the
/// authorization never names the envelope; the receipt commits to both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveAuthorization {
    pub agent_id: AgentId,
    pub move_epoch: u64,
    pub from_machine: MachineId,
    pub to_machine: MachineId,
    /// Placement outcome of this move (`Pinned(to_machine)` or `Roaming`).
    pub placement: Placement,
    pub issued_at: u64,
}

impl MoveAuthorization {
    /// Canonical bytes — the AAD of the export envelope and the preimage
    /// of `auth_hash`. Fixed-width fields; no owner key inside (the owner
    /// key is on the enclosing [`ChainedRecord`]).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(MOVE_MSG_PREFIX.len() + 32 + 8 + 32 + 32 + 1 + 32 + 8);
        msg.extend_from_slice(MOVE_MSG_PREFIX);
        msg.extend_from_slice(self.agent_id.as_bytes());
        msg.extend_from_slice(&self.move_epoch.to_le_bytes());
        msg.extend_from_slice(self.from_machine.as_bytes());
        msg.extend_from_slice(self.to_machine.as_bytes());
        match self.placement {
            Placement::Pinned(machine) => {
                msg.push(0x01);
                msg.extend_from_slice(machine.as_bytes());
            }
            Placement::Roaming => msg.push(0x02),
        }
        msg.extend_from_slice(&self.issued_at.to_le_bytes());
        msg
    }

    /// BLAKE3 of the canonical bytes — the `auth_hash` receipts and aborts
    /// reference.
    #[must_use]
    pub fn auth_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

/// One record of a per-agent move log. Machine countersignatures live
/// inside the receipt variants; the owner signature lives on the
/// [`ChainedRecord`]. The `ActivationBundle` variant deliberately carries
/// its full self-contained payload (embedded authorization + cumulative
/// tombstones + placement record + certificate — §7.5 r4-2: mesh coherence
/// checks reference in-record fields ONLY); records append at ceremony
/// cadence, never in hot loops, so the size difference is accepted
/// (same call as `named_groups.rs`'s variant allow).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveRecord {
    /// Genesis: owner-signed epoch-0 placement + initial custodian (§8.2).
    PlacementMint {
        agent_id: AgentId,
        placement: Placement,
        custodian_machine: MachineId,
        issued_at: u64,
    },
    /// Owner-signed; authorizes ONE move; contains no envelope digest.
    MoveAuthorization(MoveAuthorization),
    /// Source-machine-signed commit to the sealed ciphertext. The machine
    /// public key rides in-record (self-authenticating: its derived
    /// `MachineId` must equal the authorization's `from_machine`).
    ExportReceipt {
        auth_hash: [u8; 32],
        envelope_digest: [u8; 32],
        sealed_at: u64,
        machine_public_key: Vec<u8>,
        machine_signature: Vec<u8>,
    },
    /// Target-machine-signed statement that the key material arrived.
    ImportReceipt {
        auth_hash: [u8; 32],
        imported_at: u64,
        machine_public_key: Vec<u8>,
        machine_signature: Vec<u8>,
    },
    /// Owner-signed COMMIT-terminator. SELF-CONTAINED: the canonical
    /// authorization rides inside (mesh coherence checks reference
    /// in-record fields only); `retired_bindings` is CUMULATIVE across all
    /// committed moves (grow-only at the owner).
    ActivationBundle {
        authorization: MoveAuthorization,
        retired_bindings: Vec<AgentMachineBinding>,
        placement_record: PlacementRecord,
        agent_certificate: AgentCertificate,
    },
    /// Source-machine-signed bookkeeping after commitment; changes no
    /// derived security state.
    RetireReceipt {
        auth_hash: [u8; 32],
        retired_at: u64,
        machine_public_key: Vec<u8>,
        machine_signature: Vec<u8>,
    },
    /// Owner-signed ROLLBACK-terminator — legal from any pre-activation
    /// head; burns the move epoch.
    AbortRecord { auth_hash: [u8; 32], reason: String },
}

impl MoveRecord {
    /// Kind tag byte in the chained signed message.
    fn kind_tag(&self) -> u8 {
        match self {
            MoveRecord::PlacementMint { .. } => 0x01,
            MoveRecord::MoveAuthorization(_) => 0x02,
            MoveRecord::ExportReceipt { .. } => 0x03,
            MoveRecord::ImportReceipt { .. } => 0x04,
            MoveRecord::ActivationBundle { .. } => 0x05,
            MoveRecord::RetireReceipt { .. } => 0x06,
            MoveRecord::AbortRecord { .. } => 0x07,
        }
    }

    /// The authorization hash this record references, when any.
    #[must_use]
    pub fn auth_hash(&self) -> Option<[u8; 32]> {
        match self {
            MoveRecord::MoveAuthorization(auth) => Some(auth.auth_hash()),
            MoveRecord::ExportReceipt { auth_hash, .. }
            | MoveRecord::ImportReceipt { auth_hash, .. }
            | MoveRecord::RetireReceipt { auth_hash, .. }
            | MoveRecord::AbortRecord { auth_hash, .. } => Some(*auth_hash),
            MoveRecord::PlacementMint { .. } | MoveRecord::ActivationBundle { .. } => None,
        }
    }

    /// Human-readable kind for REST/log views.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            MoveRecord::PlacementMint { .. } => "placement_mint",
            MoveRecord::MoveAuthorization(_) => "move_authorization",
            MoveRecord::ExportReceipt { .. } => "export_receipt",
            MoveRecord::ImportReceipt { .. } => "import_receipt",
            MoveRecord::ActivationBundle { .. } => "activation_bundle",
            MoveRecord::RetireReceipt { .. } => "retire_receipt",
            MoveRecord::AbortRecord { .. } => "abort_record",
        }
    }

    /// Canonical bytes a machine countersignature covers for the receipt
    /// variants.
    fn receipt_message(&self) -> Option<Vec<u8>> {
        let (auth_hash, stamp, tag) = match self {
            MoveRecord::ExportReceipt {
                auth_hash,
                sealed_at,
                ..
            } => (*auth_hash, *sealed_at, b"export"),
            MoveRecord::ImportReceipt {
                auth_hash,
                imported_at,
                ..
            } => (*auth_hash, *imported_at, b"import"),
            MoveRecord::RetireReceipt {
                auth_hash,
                retired_at,
                ..
            } => (*auth_hash, *retired_at, b"retire"),
            _ => return None,
        };
        let mut msg = Vec::with_capacity(MOVE_MSG_PREFIX.len() + 8 + 32 + 8);
        msg.extend_from_slice(MOVE_MSG_PREFIX);
        msg.extend_from_slice(tag);
        msg.extend_from_slice(&auth_hash);
        msg.extend_from_slice(&stamp.to_le_bytes());
        Some(msg)
    }
}

/// One append to a per-agent move log: the record plus its chain link and
/// the owner (user) signature covering
/// `MOVE_MSG_PREFIX ‖ prev ‖ kind_tag ‖ owner_pubkey ‖ variant-bytes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainedRecord {
    /// Hash of the previous record's signed message (genesis: all-zero).
    pub prev: [u8; 32],
    pub record: MoveRecord,
    /// Owner ML-DSA-65 public key bytes (the certificate issuer).
    pub owner_public_key: Vec<u8>,
    pub owner_signature: Vec<u8>,
}

impl ChainedRecord {
    /// The exact bytes the owner signature (and the chain hash) cover.
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let variant = bincode::serialize(&self.record).unwrap_or_default();
        let mut msg = Vec::with_capacity(
            MOVE_MSG_PREFIX.len() + 32 + 1 + 8 + self.owner_public_key.len() + variant.len(),
        );
        msg.extend_from_slice(MOVE_MSG_PREFIX);
        msg.extend_from_slice(&self.prev);
        msg.push(self.record.kind_tag());
        msg.extend_from_slice(&(self.owner_public_key.len() as u64).to_le_bytes());
        msg.extend_from_slice(&self.owner_public_key);
        msg.extend_from_slice(&variant);
        msg
    }

    /// BLAKE3 of the signed message — the `prev` of any successor and the
    /// digest blob-v2's `Bundle` kind fetches historical bundles by.
    #[must_use]
    pub fn record_hash(&self) -> [u8; 32] {
        *blake3::hash(&self.signed_message()).as_bytes()
    }

    /// Append a new owner-signed record to `prev`.
    ///
    /// `owner_public_key`/`owner_secret` are the OWNER (user) keypair —
    /// only the owner key authorizes irreversible steps (ADR-0043 driver
    /// 3).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::CertificateVerification`] on signing
    /// failure.
    pub fn sign(
        prev: [u8; 32],
        record: MoveRecord,
        owner_public_key: &[u8],
        owner_secret: &MlDsaSecretKey,
    ) -> Result<Self> {
        let unsigned = Self {
            prev,
            record,
            owner_public_key: owner_public_key.to_vec(),
            owner_signature: Vec::new(),
        };
        let message = unsigned.signed_message();
        let signature = sign_with_ml_dsa(owner_secret, &message).map_err(|e| {
            IdentityError::CertificateVerification(format!("move-record signing failed: {e:?}"))
        })?;
        Ok(Self {
            owner_signature: signature.as_bytes().to_vec(),
            ..unsigned
        })
    }

    /// Verify the owner signature over the signed message.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] when the key or signature is
    /// invalid.
    pub fn verify_owner_signature(&self) -> std::result::Result<(), IdentityError> {
        let owner = MlDsaPublicKey::from_bytes(&self.owner_public_key)
            .map_err(|e| IdentityError::Revocation(format!("invalid owner public key: {e:?}")))?;
        let signature = MlDsaSignature::from_bytes(&self.owner_signature)
            .map_err(|e| IdentityError::Revocation(format!("invalid owner signature: {e:?}")))?;
        verify_with_ml_dsa(&owner, &self.signed_message(), &signature).map_err(|e| {
            IdentityError::Revocation(format!("move-record signature verification failed: {e:?}"))
        })
    }

    /// Verify the in-record machine countersignature of a receipt variant
    /// against the machine the authorization names (`expected_machine`).
    fn verify_machine_countersignature(
        &self,
        expected_machine: &MachineId,
    ) -> std::result::Result<(), IdentityError> {
        let (public_key, signature) = match &self.record {
            MoveRecord::ExportReceipt {
                machine_public_key,
                machine_signature,
                ..
            }
            | MoveRecord::ImportReceipt {
                machine_public_key,
                machine_signature,
                ..
            }
            | MoveRecord::RetireReceipt {
                machine_public_key,
                machine_signature,
                ..
            } => (machine_public_key, machine_signature),
            _ => {
                return Err(IdentityError::Revocation(
                    "machine countersignature requested for a non-receipt record".to_string(),
                ));
            }
        };
        let machine_pub = MlDsaPublicKey::from_bytes(public_key)
            .map_err(|e| IdentityError::Revocation(format!("invalid machine public key: {e:?}")))?;
        if &MachineId::from_public_key(&machine_pub) != expected_machine {
            return Err(IdentityError::Revocation(
                "receipt countersigned by a machine other than the one the authorization names"
                    .to_string(),
            ));
        }
        let message = self
            .record
            .receipt_message()
            .ok_or_else(|| IdentityError::Revocation("receipt message unavailable".to_string()))?;
        let machine_sig = MlDsaSignature::from_bytes(signature)
            .map_err(|e| IdentityError::Revocation(format!("invalid machine signature: {e:?}")))?;
        verify_with_ml_dsa(&machine_pub, &message, &machine_sig).map_err(|e| {
            IdentityError::Revocation(format!("machine countersignature failed: {e:?}"))
        })
    }
}

/// Sign a receipt variant's machine countersignature (source/target
/// machine key over the receipt message).
///
/// # Errors
///
/// Returns [`IdentityError::CertificateVerification`] on signing failure,
/// or [`IdentityError::Revocation`] when `record` is not a receipt.
pub fn sign_machine_receipt(
    record: &MoveRecord,
    machine_secret: &MlDsaSecretKey,
) -> Result<Vec<u8>> {
    let message = record
        .receipt_message()
        .ok_or_else(|| IdentityError::Revocation("not a receipt record".to_string()))?;
    let signature = sign_with_ml_dsa(machine_secret, &message).map_err(|e| {
        IdentityError::CertificateVerification(format!("receipt signing failed: {e:?}"))
    })?;
    Ok(signature.as_bytes().to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MovePhase {
    /// No move in flight, no retire pending.
    Idle,
    /// Authorization/export/import seen, no terminator yet — nobody may
    /// sign (`custodian` = ⊥).
    MidMove { from: MachineId, to: MachineId },
    /// Activation bundle seen, retire receipt not — the source is
    /// quiesced, the target is the custodian.
    RetirePending { from: MachineId },
}

/// The total fold of one agent's move log (ADR-0043 §3.2). Defined for
/// every legal log shape; never undefined. The default (no log) is an
/// Idle fold with no custodian — callers treat "no log" fail-open
/// separately (pre-0043 agents keep signing through their local key).
#[derive(Debug, Clone, PartialEq)]
pub struct MoveFold {
    /// Who is authorized to sign as the agent. `None` during a transfer
    /// (zero live signers), exactly one machine otherwise.
    pub custodian: Option<MachineId>,
    /// Grow-only union of every retired `(agent, machine, epoch)` binding.
    pub retired_bindings: HashSet<AgentMachineBinding>,
    /// Current placement + the epoch that produced it.
    pub placement: Option<(Placement, u64)>,
    pub phase: MovePhase,
}

impl Default for MoveFold {
    fn default() -> Self {
        Self {
            custodian: None,
            retired_bindings: HashSet::new(),
            placement: None,
            phase: MovePhase::Idle,
        }
    }
}

impl MoveFold {
    /// `may_sign = holds_key ∧ custodian == machine` — key possession is
    /// an INPUT, not log state.
    #[must_use]
    pub fn may_sign(&self, machine: &MachineId, holds_key: bool) -> bool {
        holds_key && self.custodian.as_ref() == Some(machine)
    }

    /// Source-side quiesce label: the machine holds the key but a move is
    /// in flight FROM it (or it is retire-pending after activation).
    #[must_use]
    pub fn quiesced(&self, machine: &MachineId, holds_key: bool) -> bool {
        holds_key
            && match self.phase {
                MovePhase::MidMove { from, .. } | MovePhase::RetirePending { from } => {
                    &from == machine
                }
                MovePhase::Idle => false,
            }
    }

    /// Target-side quarantine label: the machine holds the (imported) key
    /// but the move has not been activated.
    #[must_use]
    pub fn quarantined(&self, machine: &MachineId, holds_key: bool) -> bool {
        holds_key && matches!(self.phase, MovePhase::MidMove { to, .. } if &to == machine)
    }
}

/// Fold a per-agent record sequence by kind rules — pure, no crypto.
///
/// Total by cases on each record kind, applied in order (§3.2): the mint
/// seeds custodian+placement; an active (unterminated) move sets
/// `custodian = ⊥` and `MidMove`; an `ActivationBundle` transfers custody,
/// unions the cumulative tombstones and updates placement; an
/// `AbortRecord` restores the aborted move's `from_machine`; a
/// `RetireReceipt` is bookkeeping and changes nothing.
#[must_use]
pub fn fold_records(records: &[ChainedRecord]) -> MoveFold {
    let mut out = MoveFold::default();
    let mut active: Option<MoveAuthorization> = None;
    for chained in records {
        match &chained.record {
            MoveRecord::PlacementMint {
                placement,
                custodian_machine,
                ..
            } => {
                out.custodian = Some(*custodian_machine);
                out.placement = Some((*placement, 0));
                out.phase = MovePhase::Idle;
                active = None;
            }
            MoveRecord::MoveAuthorization(auth) => {
                // Owner authorized a move: custody lapses for the transfer
                // duration — ZERO live signers.
                out.custodian = None;
                out.phase = MovePhase::MidMove {
                    from: auth.from_machine,
                    to: auth.to_machine,
                };
                active = Some(auth.clone());
            }
            MoveRecord::ExportReceipt { .. } | MoveRecord::ImportReceipt { .. } => {
                // Still mid-move; custodian stays ⊥ (identical bytes fold
                // identically — replay-idempotent).
            }
            MoveRecord::ActivationBundle {
                authorization,
                retired_bindings,
                placement_record,
                ..
            } => {
                out.custodian = Some(authorization.to_machine);
                for binding in retired_bindings {
                    out.retired_bindings.insert(binding.clone());
                }
                out.placement =
                    Some((placement_record.placement, placement_record.placement_epoch));
                out.phase = MovePhase::RetirePending {
                    from: authorization.from_machine,
                };
                active = None;
            }
            MoveRecord::RetireReceipt { .. } => {
                // Bookkeeping after commitment: all values unchanged, phase
                // returns to Idle (the source's key deletion makes
                // holds_key false there; the custodian keeps signing).
                out.phase = MovePhase::Idle;
            }
            MoveRecord::AbortRecord { auth_hash, .. } => {
                // Rollback: restore custody to the aborted move's source.
                if let Some(auth) = &active {
                    if auth.auth_hash() == *auth_hash {
                        out.custodian = Some(auth.from_machine);
                    }
                }
                out.phase = MovePhase::Idle;
                active = None;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Participant rule (§3.3) — chain verification
// ---------------------------------------------------------------------------

/// Whether `next`'s kind is a legal successor of `prev`'s (§5.1).
#[must_use]
pub fn is_legal_successor(prev: &MoveRecord, next: &MoveRecord) -> bool {
    use MoveRecord::{
        AbortRecord, ActivationBundle, ExportReceipt, ImportReceipt, MoveAuthorization,
        PlacementMint, RetireReceipt,
    };
    matches!(
        (prev, next),
        (PlacementMint { .. }, MoveAuthorization(_))
            | (MoveAuthorization(_), ExportReceipt { .. })
            | (MoveAuthorization(_), AbortRecord { .. })
            | (ExportReceipt { .. }, ImportReceipt { .. })
            | (ExportReceipt { .. }, AbortRecord { .. })
            | (ImportReceipt { .. }, ActivationBundle { .. })
            | (ImportReceipt { .. }, AbortRecord { .. })
            | (ActivationBundle { .. }, RetireReceipt { .. })
            | (ActivationBundle { .. }, MoveAuthorization(_))
            | (RetireReceipt { .. }, MoveAuthorization(_))
            | (AbortRecord { .. }, MoveAuthorization(_))
    )
}

/// Verify a whole per-agent log under the participant rule: every owner
/// signature valid, `prev` links intact (CAS — a fork challenger is
/// rejected here; first-valid is kept by the caller), kinds legal
/// successors, and the per-variant semantic bindings (receipt `auth_hash`
/// ↔ active authorization, embedded-authorization equality, epoch
/// increments, machine countersignatures).
///
/// `expected_owner` (when supplied) pins the owner public key — the
/// daemon's own user key for agents it certifies.
///
/// # Errors
///
/// Returns [`IdentityError::Revocation`] describing the first violated
/// clause.
pub fn verify_chain(
    records: &[ChainedRecord],
    expected_owner: Option<&MlDsaPublicKey>,
) -> std::result::Result<(), IdentityError> {
    let mut head: [u8; 32] = GENESIS_PREV;
    let mut placement_epoch: u64 = 0;
    let mut active: Option<MoveAuthorization> = None;
    let mut last_bundle: Option<MoveAuthorization> = None;
    let mut owner_key: Option<Vec<u8>> = None;

    for (index, chained) in records.iter().enumerate() {
        // (1) CAS: prev must equal the head hash.
        if chained.prev != head {
            return Err(IdentityError::Revocation(format!(
                "record {index}: prev {} is not the head {} — fork or out-of-order append",
                hex::encode(chained.prev),
                hex::encode(head)
            )));
        }
        // (2) Owner signature + stable owner identity across the chain.
        chained.verify_owner_signature()?;
        if let Some(expected) = expected_owner {
            if chained.owner_public_key.as_slice() != expected.as_bytes() {
                return Err(IdentityError::Revocation(format!(
                    "record {index}: owner key is not the expected owner"
                )));
            }
        }
        if let Some(seen) = &owner_key {
            if seen != &chained.owner_public_key {
                return Err(IdentityError::Revocation(format!(
                    "record {index}: owner key changed mid-chain"
                )));
            }
        } else {
            owner_key = Some(chained.owner_public_key.clone());
        }
        // (3) Kind legality.
        if index > 0 {
            let prev_record = &records[index - 1].record;
            if !is_legal_successor(prev_record, &chained.record) {
                return Err(IdentityError::Revocation(format!(
                    "record {index}: {} is not a legal successor of {}",
                    chained.record.kind(),
                    prev_record.kind()
                )));
            }
        } else if !matches!(chained.record, MoveRecord::PlacementMint { .. }) {
            return Err(IdentityError::Revocation(
                "first record of a move log must be a PlacementMint".to_string(),
            ));
        }
        // (4) Per-variant semantics.
        match &chained.record {
            MoveRecord::PlacementMint { .. } => {
                placement_epoch = 0;
            }
            MoveRecord::MoveAuthorization(auth) => {
                if auth.move_epoch != placement_epoch + 1 {
                    return Err(IdentityError::Revocation(format!(
                        "move epoch {} does not succeed placement epoch {placement_epoch}",
                        auth.move_epoch
                    )));
                }
                // The source of a new move must be the CURRENT custodian
                // (the fold of everything before this record).
                let before = fold_records(&records[..index]);
                if before.custodian != Some(auth.from_machine) {
                    return Err(IdentityError::Revocation(format!(
                        "move epoch {}: from_machine is not the current custodian",
                        auth.move_epoch
                    )));
                }
                if active.is_some() {
                    return Err(IdentityError::Revocation(
                        "move authorized while another move is active".to_string(),
                    ));
                }
                active = Some(auth.clone());
            }
            MoveRecord::ExportReceipt { auth_hash, .. } => {
                let auth = active.as_ref().ok_or_else(|| {
                    IdentityError::Revocation(
                        "export receipt with no active authorization".to_string(),
                    )
                })?;
                if auth.auth_hash() != *auth_hash {
                    return Err(IdentityError::Revocation(
                        "export receipt does not reference the active authorization".to_string(),
                    ));
                }
                chained.verify_machine_countersignature(&auth.from_machine)?;
            }
            MoveRecord::ImportReceipt { auth_hash, .. } => {
                let auth = active.as_ref().ok_or_else(|| {
                    IdentityError::Revocation(
                        "import receipt with no active authorization".to_string(),
                    )
                })?;
                if auth.auth_hash() != *auth_hash {
                    return Err(IdentityError::Revocation(
                        "import receipt does not reference the active authorization".to_string(),
                    ));
                }
                chained.verify_machine_countersignature(&auth.to_machine)?;
            }
            MoveRecord::ActivationBundle { authorization, .. } => {
                let auth = active.as_ref().ok_or_else(|| {
                    IdentityError::Revocation(
                        "activation bundle with no active authorization".to_string(),
                    )
                })?;
                // Participants additionally check the embedded
                // authorization equals their log's record (§7.5).
                if auth != authorization {
                    return Err(IdentityError::Revocation(
                        "activation bundle embeds a foreign authorization".to_string(),
                    ));
                }
                verify_bundle_coherence_chained(chained)?;
                placement_epoch = authorization.move_epoch;
                last_bundle = Some(authorization.clone());
                active = None;
            }
            MoveRecord::RetireReceipt { auth_hash, .. } => {
                let bundle_auth = last_bundle.as_ref().ok_or_else(|| {
                    IdentityError::Revocation("retire receipt with no committed bundle".to_string())
                })?;
                if bundle_auth.auth_hash() != *auth_hash {
                    return Err(IdentityError::Revocation(
                        "retire receipt does not reference the committed move".to_string(),
                    ));
                }
                chained.verify_machine_countersignature(&bundle_auth.from_machine)?;
            }
            MoveRecord::AbortRecord { auth_hash, .. } => {
                let auth = active.as_ref().ok_or_else(|| {
                    IdentityError::Revocation(
                        "abort record with no active authorization".to_string(),
                    )
                })?;
                if auth.auth_hash() != *auth_hash {
                    return Err(IdentityError::Revocation(
                        "abort record does not reference the active authorization".to_string(),
                    ));
                }
                // The epoch is burned: every future record must chain past
                // this one (CAS + successor rules make it
                // un-re-extendable).
                active = None;
            }
        }
        head = chained.record_hash();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-field coherence + mesh rule (§7.5)
// ---------------------------------------------------------------------------

/// Cross-field coherence of one chained `ActivationBundle`, checked as a
/// unit against the EMBEDDED authorization (r3 c / r4 2) — the form used
/// by BOTH the participant rule and the mesh rule, because clause 2's
/// owner-signer equality needs the CHAINED record's owner key. A record
/// failing any clause is dropped whole; there is no partially accepted
/// bundle because there is no application step — only store-if-coherent.
///
/// Clauses (§7.5):
/// 1. owner signature over the whole chained record verifies;
/// 2. `agent_certificate.verify()` ∧ cert agent == auth agent ∧ the
///    certificate's issuer (user key) == the record's owner signer;
/// 3. `retired_bindings` non-empty, contains this move's tombstone
///    `(auth.agent, auth.from_machine, auth.move_epoch)`, and every entry
///    belongs to the same agent;
/// 4. `placement_record` names the same agent + owner, its epoch equals
///    the move epoch, and it verifies;
/// 5. a pinned move may only pin to its target, and the placement record
///    matches the declared placement.
///
/// # Errors
///
/// Returns [`IdentityError::Revocation`] naming the violated clause.
pub fn verify_bundle_coherence_chained(
    chained: &ChainedRecord,
) -> std::result::Result<(), IdentityError> {
    let MoveRecord::ActivationBundle {
        authorization,
        retired_bindings,
        placement_record,
        agent_certificate,
    } = &chained.record
    else {
        return Err(IdentityError::Revocation(
            "coherence check requires an ActivationBundle".to_string(),
        ));
    };
    // Clause 1.
    chained.verify_owner_signature()?;
    // Clause 2.
    agent_certificate
        .verify()
        .map_err(|e| IdentityError::Revocation(format!("bundle certificate invalid: {e}")))?;
    let cert_agent = agent_certificate.agent_id().map_err(|e| {
        IdentityError::Revocation(format!("bundle certificate agent id unreadable: {e}"))
    })?;
    if cert_agent != authorization.agent_id {
        return Err(IdentityError::Revocation(
            "bundle certificate belongs to a different agent (swapped cert)".to_string(),
        ));
    }
    if agent_certificate.user_public_key_bytes() != chained.owner_public_key.as_slice() {
        return Err(IdentityError::Revocation(
            "bundle certificate issuer is not the record's owner signer".to_string(),
        ));
    }
    // Clause 3.
    if retired_bindings.is_empty() {
        return Err(IdentityError::Revocation(
            "bundle retires no bindings".to_string(),
        ));
    }
    let this_move = AgentMachineBinding {
        agent: authorization.agent_id,
        machine: authorization.from_machine,
        move_epoch: authorization.move_epoch,
    };
    if !retired_bindings.contains(&this_move) {
        return Err(IdentityError::Revocation(
            "bundle's cumulative retired set omits this move's tombstone".to_string(),
        ));
    }
    for binding in retired_bindings {
        if binding.agent != authorization.agent_id {
            return Err(IdentityError::Revocation(
                "bundle retires a binding of a foreign agent".to_string(),
            ));
        }
    }
    // Clause 4.
    if placement_record.agent_id != authorization.agent_id {
        return Err(IdentityError::Revocation(
            "placement record names a foreign agent".to_string(),
        ));
    }
    if placement_record.owner_public_key != chained.owner_public_key {
        return Err(IdentityError::Revocation(
            "placement record issuer is not the record's owner signer".to_string(),
        ));
    }
    if placement_record.placement_epoch != authorization.move_epoch {
        return Err(IdentityError::Revocation(
            "placement epoch does not match the move epoch".to_string(),
        ));
    }
    placement_record.verify().map_err(|e| {
        IdentityError::Revocation(format!("placement record signature invalid: {e}"))
    })?;
    // Clause 5.
    match authorization.placement {
        Placement::Pinned(pin) => {
            if pin != authorization.to_machine {
                return Err(IdentityError::Revocation(
                    "authorization pins to a machine other than the move target".to_string(),
                ));
            }
            if placement_record.placement != Placement::Pinned(authorization.to_machine) {
                return Err(IdentityError::Revocation(
                    "placement record pin does not match the declared placement".to_string(),
                ));
            }
        }
        Placement::Roaming => {
            if placement_record.placement != Placement::Roaming {
                return Err(IdentityError::Revocation(
                    "placement record is pinned but the authorization declares roaming".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// What a mesh-verified bundle contributes to the derived state.
#[derive(Debug, Clone)]
pub struct MeshAcceptance {
    /// `Some` when the bundle's placement record advances the peer's view.
    pub placement: Option<PlacementRecord>,
    /// The cumulative tombstone set — unions in regardless of epoch.
    pub tombstones: Vec<AgentMachineBinding>,
    /// The move epoch of the accepted bundle (audit view).
    pub move_epoch: u64,
}

/// The mesh rule for one carried `ActivationBundle` (§3.3): whole-record
/// owner signature + cross-field coherence + placement-epoch monotonicity.
///
/// Tombstones union in UNCONDITIONALLY (order-independent, r4-3): the
/// returned acceptance always carries the bundle's cumulative set; the
/// placement update is `Some` only when the epoch advances (equal epoch +
/// identical digest is a replay no-op; a lower epoch's PLACEMENT is stale
/// but its tombstones still merge).
///
/// # Errors
///
/// Returns [`IdentityError::Revocation`] on any failed clause.
pub fn verify_bundle_mesh(
    chained: &ChainedRecord,
    current_placement: Option<&PlacementRecord>,
) -> std::result::Result<MeshAcceptance, IdentityError> {
    let MoveRecord::ActivationBundle {
        authorization,
        retired_bindings,
        placement_record,
        ..
    } = &chained.record
    else {
        return Err(IdentityError::Revocation(
            "mesh rule requires an ActivationBundle".to_string(),
        ));
    };
    verify_bundle_coherence_chained(chained)?;
    let placement_update = match current_placement {
        None => Some(()),
        Some(current) => {
            if placement_record.placement_epoch > current.placement_epoch {
                Some(())
            } else {
                None // equal-digest replay no-op OR stale placement
            }
        }
    };
    Ok(MeshAcceptance {
        placement: placement_update.map(|()| placement_record.clone()),
        tombstones: retired_bindings.clone(),
        move_epoch: authorization.move_epoch,
    })
}

// ---------------------------------------------------------------------------
// Export envelope (§4)
// ---------------------------------------------------------------------------

/// The sealed export envelope: the serialized agent keypair under the
/// target machine's ML-KEM-768 key, AAD-bound to the move authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEnvelope {
    pub kem_ciphertext: Vec<u8>,
    pub aead_nonce: [u8; 12],
    pub aead_ciphertext: Vec<u8>,
}

impl ExportEnvelope {
    /// `blake3(kem_ct ‖ nonce ‖ aead_ct)` — committed only in the
    /// `ExportReceipt`, never in the authorization (§3.1 acyclicity).
    #[must_use]
    pub fn envelope_digest(&self) -> [u8; 32] {
        let mut buf =
            Vec::with_capacity(self.kem_ciphertext.len() + 12 + self.aead_ciphertext.len());
        buf.extend_from_slice(&self.kem_ciphertext);
        buf.extend_from_slice(&self.aead_nonce);
        buf.extend_from_slice(&self.aead_ciphertext);
        *blake3::hash(&buf).as_bytes()
    }

    /// Seal `keypair_bytes` to the target machine's enrolled KEM public
    /// key, AAD-bound to the authorization's canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on KEM/AEAD failure.
    pub fn seal(
        target_machine_kem_public: &[u8],
        authorization: &MoveAuthorization,
        keypair_bytes: &[u8],
    ) -> Result<Self> {
        let aad = authorization.canonical_bytes();
        let (kem_ct, nonce, aead_ct) =
            seal_bytes_to_recipient(target_machine_kem_public, &aad, keypair_bytes)?;
        Ok(Self {
            kem_ciphertext: kem_ct,
            aead_nonce: nonce,
            aead_ciphertext: aead_ct,
        })
    }

    /// Unwrap on the target machine. Cross-move replay, re-targeting, and
    /// envelope substitution all fail the AEAD tag (the AAD is the exact
    /// authorization bytes).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] when this machine is not
    /// the recipient or the AAD/ciphertext was substituted.
    pub fn open(
        &self,
        machine_kem: &AgentKemKeypair,
        authorization: &MoveAuthorization,
    ) -> Result<Vec<u8>> {
        let aad = authorization.canonical_bytes();
        open_sealed_bytes(
            machine_kem,
            &aad,
            &self.kem_ciphertext,
            &self.aead_nonce,
            &self.aead_ciphertext,
        )
    }
}

/// The operator-carried transfer bundle: everything the target needs to
/// import, and everything the owner needs to activate (§5.4 —
/// pre-activation records are NOT mesh-replicated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferBundle {
    /// The owner-signed `MoveAuthorization` chained record.
    pub authorization: ChainedRecord,
    /// The source's `ExportReceipt`, once sealed.
    pub export_receipt: Option<ChainedRecord>,
    /// The sealed key envelope, once sealed.
    pub envelope: Option<ExportEnvelope>,
}

// ---------------------------------------------------------------------------
// Enforcement (§9)
// ---------------------------------------------------------------------------

/// Why an `(agent, machine)` pairing was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingDenial {
    /// Check B: the binding was retired by a committed/ad-hoc tombstone.
    BindingRevoked,
    /// Check P: a current placement record pins the agent elsewhere.
    PlacementPinned { pinned_to: MachineId },
}

/// Evaluate checks B and P for one pairing against the derived state.
///
/// B reads the grow-only tombstone union (bundle `retired_bindings` +
/// ad-hoc v2 records). P applies only when a placement record is cached
/// at an epoch ≥ the highest revoked binding epoch — the coherent
/// activation case (equal epochs) enforces; strictly older records are
/// stale; an absent record fails open (§9.3).
#[must_use]
pub fn enforce_pairing(
    revoked: &RevocationSet,
    placements: &HashMap<AgentId, PlacementRecord>,
    agent: &AgentId,
    machine: &MachineId,
) -> Option<PairingDenial> {
    if revoked.is_binding_revoked(agent, machine) {
        return Some(PairingDenial::BindingRevoked);
    }
    let record = placements.get(agent)?;
    let max_epoch = revoked.max_revoked_binding_epoch(agent).unwrap_or(0);
    if record.placement_epoch >= max_epoch {
        if let Placement::Pinned(pin) = record.placement {
            if &pin != machine {
                return Some(PairingDenial::PlacementPinned { pinned_to: pin });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// MoveState — logs, bundles, placements (§5.4)
// ---------------------------------------------------------------------------

/// The full ADR-0043 derived state one daemon holds: participant logs for
/// agents it has a role in, mesh-verified activation bundles, and the
/// placement-record cache every gate reads.
#[derive(Debug, Default)]
pub struct MoveState {
    /// Per-agent participant logs (`moves.bin`).
    logs: HashMap<AgentId, Vec<ChainedRecord>>,
    /// Latest mesh-verified bundle per agent (`move-bundles.bin`) —
    /// tombstones live in the shared [`RevocationSet`].
    bundles: HashMap<AgentId, ChainedRecord>,
    /// Current owner-verified placement record per agent
    /// (`placement-blobs.bin`); mint records enter here too.
    placements: HashMap<AgentId, PlacementRecord>,
}

impl MoveState {
    /// Empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The participant log of one agent (empty slice when absent).
    #[must_use]
    pub fn log(&self, agent: &AgentId) -> &[ChainedRecord] {
        self.logs.get(agent).map_or(&[], Vec::as_slice)
    }

    /// Head hash of one agent's log (genesis when no log).
    #[must_use]
    pub fn head_hash(&self, agent: &AgentId) -> [u8; 32] {
        self.logs
            .get(agent)
            .and_then(|records| records.last())
            .map_or(GENESIS_PREV, ChainedRecord::record_hash)
    }

    /// The fold of one agent's participant log (the mint defaults when no
    /// log exists yet — total by construction).
    #[must_use]
    pub fn fold(&self, agent: &AgentId) -> MoveFold {
        fold_records(self.log(agent))
    }

    /// Append a record to an agent's participant log under the CAS rule:
    /// a record already in the log is an idempotent no-op; otherwise
    /// `record.prev` must equal the current head and the extended chain
    /// must verify. Forks (two records claiming one `prev`) keep
    /// first-valid and the challenger is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] when the CAS fails or the
    /// extended chain does not verify.
    pub fn append(
        &mut self,
        agent: &AgentId,
        record: ChainedRecord,
        expected_owner: Option<&MlDsaPublicKey>,
    ) -> std::result::Result<bool, IdentityError> {
        // Idempotent replay: a record already in the log changes nothing
        // (identical bytes → identical fold).
        if self
            .log(agent)
            .iter()
            .any(|r| r.record_hash() == record.record_hash())
        {
            return Ok(false);
        }
        let head = self.head_hash(agent);
        if record.prev != head {
            return Err(IdentityError::Revocation(format!(
                "append prev {} ≠ head {} — fork rejected (first-valid kept)",
                hex::encode(record.prev),
                hex::encode(head)
            )));
        }
        let extended: Vec<ChainedRecord> = self
            .log(agent)
            .iter()
            .cloned()
            .chain(std::iter::once(record))
            .collect();
        verify_chain(&extended, expected_owner)?;
        self.logs.insert(*agent, extended);
        Ok(true)
    }

    /// Ingest a carried bundle under the MESH rule: verify, union the
    /// cumulative tombstones into the shared revocation set
    /// (order-independent), and advance the placement view when the epoch
    /// does. Returns whether anything changed.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] when the bundle fails the
    /// mesh rule; the state is untouched in that case.
    pub fn ingest_bundle(
        &mut self,
        agent: &AgentId,
        chained: &ChainedRecord,
        revoked: &mut RevocationSet,
    ) -> std::result::Result<bool, IdentityError> {
        let acceptance = verify_bundle_mesh(chained, self.placements.get(agent))?;
        let mut changed = revoked.union_bundle_retired(&acceptance.tombstones);
        if let Some(placement) = acceptance.placement {
            if self.placements.get(agent) != Some(&placement) {
                self.placements.insert(*agent, placement);
                changed = true;
            }
        }
        let bundle_epoch = self
            .bundles
            .get(agent)
            .and_then(|c| match &c.record {
                MoveRecord::ActivationBundle { authorization, .. } => {
                    Some(authorization.move_epoch)
                }
                _ => None,
            })
            .unwrap_or(0);
        if acceptance.move_epoch >= bundle_epoch && self.bundles.get(agent) != Some(chained) {
            self.bundles.insert(*agent, chained.clone());
            changed = true;
        }
        Ok(changed)
    }

    /// Cache an owner-verified placement record (mint or fetched via
    /// blob-v2). Mesh-rule epoch monotonicity: strictly older records are
    /// ignored; equal-digest replays are no-ops.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Revocation`] when the record's signature
    /// does not verify.
    pub fn cache_placement(
        &mut self,
        record: PlacementRecord,
    ) -> std::result::Result<bool, IdentityError> {
        record.verify()?;
        match self.placements.get(&record.agent_id) {
            Some(current) if current.placement_epoch > record.placement_epoch => Ok(false),
            Some(current)
                if current.placement_epoch == record.placement_epoch
                    && current.digest() == record.digest() =>
            {
                Ok(false)
            }
            _ => {
                self.placements.insert(record.agent_id, record);
                Ok(true)
            }
        }
    }

    /// Read-only placement view shared by the enforcement gates.
    #[must_use]
    pub fn placement_view(&self) -> &HashMap<AgentId, PlacementRecord> {
        &self.placements
    }

    /// The placement record of one agent, when cached.
    #[must_use]
    pub fn placement(&self, agent: &AgentId) -> Option<&PlacementRecord> {
        self.placements.get(agent)
    }

    /// The latest mesh-verified bundle of one agent, when held.
    #[must_use]
    pub fn bundle(&self, agent: &AgentId) -> Option<&ChainedRecord> {
        self.bundles.get(agent)
    }

    /// All agents this daemon holds ANY move state for (REST view).
    #[must_use]
    pub fn known_agents(&self) -> Vec<AgentId> {
        let mut agents: HashSet<AgentId> = self.logs.keys().copied().collect();
        agents.extend(self.bundles.keys().copied());
        agents.extend(self.placements.keys().copied());
        let mut out: Vec<AgentId> = agents.into_iter().collect();
        out.sort_by_key(|a| a.0);
        out
    }

    /// Encode the participant logs for `moves.bin`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn logs_to_bytes(&self) -> Result<Vec<u8>> {
        let list: Vec<(&AgentId, &Vec<ChainedRecord>)> = self.logs.iter().collect();
        let body = bincode::serialize(&list)
            .map_err(|e| IdentityError::Serialization(format!("moves.bin encode: {e}")))?;
        let mut out = Vec::with_capacity(MOVES_FILE_MAGIC.len() + body.len());
        out.extend_from_slice(MOVES_FILE_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode `moves.bin`, re-verifying every chain on load (untrusted
    /// disk; a log that fails verification is dropped whole — fail-closed,
    /// never silently trusted).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on malformed input.
    pub fn logs_from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut state = Self::new();
        if bytes.is_empty() {
            return Ok(state);
        }
        if bytes.len() < MOVES_FILE_MAGIC.len()
            || &bytes[..MOVES_FILE_MAGIC.len()] != MOVES_FILE_MAGIC
        {
            return Err(IdentityError::Serialization(
                "moves.bin missing X0XM magic".to_string(),
            ));
        }
        let list: Vec<(AgentId, Vec<ChainedRecord>)> =
            bincode::deserialize(&bytes[MOVES_FILE_MAGIC.len()..])
                .map_err(|e| IdentityError::Serialization(format!("moves.bin decode: {e}")))?;
        for (agent, records) in list {
            if verify_chain(&records, None).is_ok() {
                state.logs.insert(agent, records);
            } else {
                tracing::warn!(
                    agent = %hex::encode(agent.as_bytes()),
                    "moves.bin: dropping unverified log on load"
                );
            }
        }
        Ok(state)
    }

    /// Encode the mesh bundle store for `move-bundles.bin`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn bundles_to_bytes(&self) -> Result<Vec<u8>> {
        let list: Vec<(&AgentId, &ChainedRecord)> = self.bundles.iter().collect();
        let body = bincode::serialize(&list)
            .map_err(|e| IdentityError::Serialization(format!("move-bundles.bin encode: {e}")))?;
        let mut out = Vec::with_capacity(BUNDLES_FILE_MAGIC.len() + body.len());
        out.extend_from_slice(BUNDLES_FILE_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode `move-bundles.bin`, re-verifying every bundle under the
    /// coherence rule on load and re-unioning its cumulative tombstones.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on malformed input.
    pub fn bundles_from_bytes(bytes: &[u8], revoked: &mut RevocationSet) -> Result<Self> {
        let mut state = Self::new();
        if bytes.is_empty() {
            return Ok(state);
        }
        if bytes.len() < BUNDLES_FILE_MAGIC.len()
            || &bytes[..BUNDLES_FILE_MAGIC.len()] != BUNDLES_FILE_MAGIC
        {
            return Err(IdentityError::Serialization(
                "move-bundles.bin missing X0MB magic".to_string(),
            ));
        }
        let list: Vec<(AgentId, ChainedRecord)> =
            bincode::deserialize(&bytes[BUNDLES_FILE_MAGIC.len()..]).map_err(|e| {
                IdentityError::Serialization(format!("move-bundles.bin decode: {e}"))
            })?;
        for (agent, chained) in list {
            if verify_bundle_coherence_chained(&chained).is_ok() {
                if let MoveRecord::ActivationBundle {
                    retired_bindings,
                    placement_record,
                    ..
                } = &chained.record
                {
                    let _ = revoked.union_bundle_retired(retired_bindings);
                    if state
                        .placements
                        .get(&agent)
                        .is_none_or(|cur| cur.placement_epoch <= placement_record.placement_epoch)
                    {
                        state.placements.insert(agent, placement_record.clone());
                    }
                }
                state.bundles.insert(agent, chained);
            } else {
                tracing::warn!(
                    agent = %hex::encode(agent.as_bytes()),
                    "move-bundles.bin: dropping incoherent bundle on load"
                );
            }
        }
        Ok(state)
    }

    /// Encode the placement cache for `placement-blobs.bin`.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on encode failure.
    pub fn placements_to_bytes(&self) -> Result<Vec<u8>> {
        let list: Vec<&PlacementRecord> = self.placements.values().collect();
        let body = bincode::serialize(&list).map_err(|e| {
            IdentityError::Serialization(format!("placement-blobs.bin encode: {e}"))
        })?;
        let mut out = Vec::with_capacity(PLACEMENTS_FILE_MAGIC.len() + body.len());
        out.extend_from_slice(PLACEMENTS_FILE_MAGIC);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode `placement-blobs.bin`, re-verifying every record's owner
    /// signature on load.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Serialization`] on malformed input.
    pub fn placements_from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut state = Self::new();
        if bytes.is_empty() {
            return Ok(state);
        }
        if bytes.len() < PLACEMENTS_FILE_MAGIC.len()
            || &bytes[..PLACEMENTS_FILE_MAGIC.len()] != PLACEMENTS_FILE_MAGIC
        {
            return Err(IdentityError::Serialization(
                "placement-blobs.bin missing X0PB magic".to_string(),
            ));
        }
        let list: Vec<PlacementRecord> =
            bincode::deserialize(&bytes[PLACEMENTS_FILE_MAGIC.len()..]).map_err(|e| {
                IdentityError::Serialization(format!("placement-blobs.bin decode: {e}"))
            })?;
        for record in list {
            if record.verify().is_ok() {
                let _ = state.cache_placement(record);
            } else {
                tracing::warn!(
                    agent = %hex::encode(record.agent_id.as_bytes()),
                    "placement-blobs.bin: dropping unverified placement on load"
                );
            }
        }
        Ok(state)
    }

    /// Merge a loaded companion store into this state (the three files
    /// load into one state). Placement entries merge under epoch
    /// monotonicity; logs/bundles keep the richer side.
    pub fn merge_loaded(&mut self, other: Self) {
        for (agent, records) in other.logs {
            let entry = self.logs.entry(agent).or_default();
            if records.len() > entry.len() {
                *entry = records;
            }
        }
        for (agent, chained) in other.bundles {
            self.bundles.entry(agent).or_insert(chained);
        }
        for (agent, record) in other.placements {
            match self.placements.get(&agent) {
                Some(current) if current.placement_epoch >= record.placement_epoch => {}
                _ => {
                    self.placements.insert(agent, record);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::identity::{AgentKeypair, UserKeypair};

    struct Fixture {
        owner: UserKeypair,
        source_machine: crate::identity::MachineKeypair,
        target_machine: crate::identity::MachineKeypair,
        agent: AgentKeypair,
        target_kem: AgentKemKeypair,
        cert: AgentCertificate,
    }

    impl Fixture {
        fn new() -> Self {
            let owner = UserKeypair::generate().unwrap();
            let source_machine = crate::identity::MachineKeypair::generate().unwrap();
            let target_machine = crate::identity::MachineKeypair::generate().unwrap();
            let agent = AgentKeypair::generate().unwrap();
            let target_kem = AgentKemKeypair::generate().unwrap();
            let cert =
                AgentCertificate::issue_for_public_key(&owner, agent.public_key().as_bytes(), None)
                    .unwrap();
            Self {
                owner,
                source_machine,
                target_machine,
                agent,
                target_kem,
                cert,
            }
        }

        fn owner_pk(&self) -> &[u8] {
            self.owner.public_key().as_bytes()
        }

        fn mint(&self, placement: Placement) -> ChainedRecord {
            ChainedRecord::sign(
                GENESIS_PREV,
                MoveRecord::PlacementMint {
                    agent_id: self.agent.agent_id(),
                    placement,
                    custodian_machine: self.source_machine.machine_id(),
                    issued_at: 1,
                },
                self.owner_pk(),
                self.owner.secret_key(),
            )
            .unwrap()
        }

        fn auth_record(
            &self,
            epoch: u64,
            from: MachineId,
            to: MachineId,
            placement: Placement,
        ) -> ChainedRecord {
            ChainedRecord::sign(
                [0u8; 32], // caller re-signs against the live head via `chain`
                MoveRecord::MoveAuthorization(MoveAuthorization {
                    agent_id: self.agent.agent_id(),
                    move_epoch: epoch,
                    from_machine: from,
                    to_machine: to,
                    placement,
                    issued_at: 2,
                }),
                self.owner_pk(),
                self.owner.secret_key(),
            )
            .unwrap()
        }

        /// Re-sign a record's variant against the given `prev` (test
        /// convenience — production always signs against the live head).
        fn chain(&self, prev: [u8; 32], record: &ChainedRecord) -> ChainedRecord {
            ChainedRecord::sign(
                prev,
                record.record.clone(),
                self.owner_pk(),
                self.owner.secret_key(),
            )
            .unwrap()
        }

        fn export_receipt(
            &self,
            auth: &MoveAuthorization,
            envelope_digest: [u8; 32],
        ) -> ChainedRecord {
            let inner = MoveRecord::ExportReceipt {
                auth_hash: auth.auth_hash(),
                envelope_digest,
                sealed_at: 3,
                machine_public_key: self.source_machine.public_key().as_bytes().to_vec(),
                machine_signature: Vec::new(),
            };
            let sig = sign_machine_receipt(&inner, self.source_machine.secret_key()).unwrap();
            ChainedRecord {
                prev: [0u8; 32],
                record: MoveRecord::ExportReceipt {
                    auth_hash: auth.auth_hash(),
                    envelope_digest,
                    sealed_at: 3,
                    machine_public_key: self.source_machine.public_key().as_bytes().to_vec(),
                    machine_signature: sig,
                },
                owner_public_key: self.owner_pk().to_vec(),
                owner_signature: Vec::new(),
            }
        }

        fn import_receipt(&self, auth: &MoveAuthorization) -> ChainedRecord {
            let inner = MoveRecord::ImportReceipt {
                auth_hash: auth.auth_hash(),
                imported_at: 4,
                machine_public_key: self.target_machine.public_key().as_bytes().to_vec(),
                machine_signature: Vec::new(),
            };
            let sig = sign_machine_receipt(&inner, self.target_machine.secret_key()).unwrap();
            ChainedRecord {
                prev: [0u8; 32],
                record: MoveRecord::ImportReceipt {
                    auth_hash: auth.auth_hash(),
                    imported_at: 4,
                    machine_public_key: self.target_machine.public_key().as_bytes().to_vec(),
                    machine_signature: sig,
                },
                owner_public_key: self.owner_pk().to_vec(),
                owner_signature: Vec::new(),
            }
        }

        fn bundle(
            &self,
            auth: &MoveAuthorization,
            retired: Vec<AgentMachineBinding>,
        ) -> ChainedRecord {
            let placement_record = PlacementRecord::sign(
                auth.agent_id,
                self.owner_pk(),
                auth.placement,
                auth.move_epoch,
                5,
                self.owner.secret_key(),
            )
            .unwrap();
            ChainedRecord {
                prev: [0u8; 32],
                record: MoveRecord::ActivationBundle {
                    authorization: auth.clone(),
                    retired_bindings: retired,
                    placement_record,
                    agent_certificate: self.cert.clone(),
                },
                owner_public_key: self.owner_pk().to_vec(),
                owner_signature: Vec::new(),
            }
        }
    }

    /// Assemble + verify a full ceremony chain, returning the records.
    ///
    /// The MOVE placement must be a legal outcome of moving to the target
    /// (clause 5: pin ≠ target refuses) — `Pinned(target)` or `Roaming`.
    /// The MINT pins to the source (epoch 0, pre-move state).
    fn ceremony(fx: &Fixture, move_placement: Placement) -> Vec<ChainedRecord> {
        let mint_placement = Placement::Pinned(fx.source_machine.machine_id());
        let mint = fx.mint(mint_placement);
        let auth_draft = fx.auth_record(
            1,
            fx.source_machine.machine_id(),
            fx.target_machine.machine_id(),
            move_placement,
        );
        let auth_record = fx.chain(mint.record_hash(), &auth_draft);
        let auth = match &auth_record.record {
            MoveRecord::MoveAuthorization(a) => a.clone(),
            _ => unreachable!(),
        };
        let env = ExportEnvelope::seal(&fx.target_kem.public_bytes, &auth, b"agent-key").unwrap();
        let export = fx.chain(
            auth_record.record_hash(),
            &fx.export_receipt(&auth, env.envelope_digest()),
        );
        let import = fx.chain(export.record_hash(), &fx.import_receipt(&auth));
        let retired = vec![AgentMachineBinding {
            agent: auth.agent_id,
            machine: auth.from_machine,
            move_epoch: auth.move_epoch,
        }];
        let bundle = fx.chain(import.record_hash(), &fx.bundle(&auth, retired));
        let records = vec![mint, auth_record, export, import, bundle];
        verify_chain(&records, None).unwrap();
        records
    }

    #[test]
    fn fold_is_total_across_every_legal_shape() {
        let fx = Fixture::new();
        let pinned = Placement::Pinned(fx.source_machine.machine_id());

        // Shape 1: mint only — the initial custodian signs.
        let mint = fx.mint(pinned);
        let f = fold_records(&[mint]);
        assert_eq!(f.custodian, Some(fx.source_machine.machine_id()));
        assert_eq!(f.placement, Some((pinned, 0)));
        assert_eq!(f.phase, MovePhase::Idle);
        assert!(f.may_sign(&fx.source_machine.machine_id(), true));
        assert!(!f.may_sign(&fx.source_machine.machine_id(), false));

        let records = ceremony(&fx, Placement::Pinned(fx.target_machine.machine_id()));

        // Shape 2: mid-move (auth seen, no terminator) — NOBODY signs.
        let mid = fold_records(&records[..2]);
        assert_eq!(mid.custodian, None);
        assert!(matches!(mid.phase, MovePhase::MidMove { .. }));
        assert!(!mid.may_sign(&fx.source_machine.machine_id(), true));
        assert!(!mid.may_sign(&fx.target_machine.machine_id(), true));
        assert!(mid.quiesced(&fx.source_machine.machine_id(), true));
        assert!(!mid.quarantined(&fx.source_machine.machine_id(), true));
        // Placement/retired unchanged during transfer.
        assert_eq!(mid.placement, Some((pinned, 0)));
        assert!(mid.retired_bindings.is_empty());

        // Shape 2b: import seen — target holds but is quarantined.
        let quarantined = fold_records(&records[..4]);
        assert_eq!(quarantined.custodian, None);
        assert!(quarantined.quarantined(&fx.target_machine.machine_id(), true));
        assert!(quarantined.quiesced(&fx.source_machine.machine_id(), true));

        // Shape 3: post-activation — the TARGET is the sole signer; the
        // source is quiesced (holds a dead key).
        let activated = fold_records(&records);
        assert_eq!(activated.custodian, Some(fx.target_machine.machine_id()));
        assert_eq!(
            activated.placement,
            Some((Placement::Pinned(fx.target_machine.machine_id()), 1))
        );
        assert!(activated.may_sign(&fx.target_machine.machine_id(), true));
        assert!(!activated.may_sign(&fx.source_machine.machine_id(), true));
        assert!(activated.quiesced(&fx.source_machine.machine_id(), true));
        assert!(matches!(activated.phase, MovePhase::RetirePending { .. }));
        assert_eq!(
            activated.retired_bindings.iter().next().map(|b| b.machine),
            Some(fx.source_machine.machine_id())
        );

        // Shape 4: post-abort — the source is restored. Abort is legal
        // from any pre-activation head; here straight from the auth.
        let auth = match &records[1].record {
            MoveRecord::MoveAuthorization(a) => a.clone(),
            _ => unreachable!(),
        };
        let abort = ChainedRecord::sign(
            records[1].record_hash(),
            MoveRecord::AbortRecord {
                auth_hash: auth.auth_hash(),
                reason: "test".into(),
            },
            fx.owner_pk(),
            fx.owner.secret_key(),
        )
        .unwrap();
        let aborted = fold_records(&[records[0].clone(), records[1].clone(), abort]);
        assert_eq!(aborted.custodian, Some(fx.source_machine.machine_id()));
        assert!(aborted.may_sign(&fx.source_machine.machine_id(), true));
        assert_eq!(aborted.phase, MovePhase::Idle);
        // Retired bindings and placement untouched by rollback.
        assert!(aborted.retired_bindings.is_empty());
        assert_eq!(aborted.placement, Some((pinned, 0)));

        // Shape 5: post-retire — bookkeeping changes nothing; custodian
        // (target) keeps signing.
        let retire_inner = MoveRecord::RetireReceipt {
            auth_hash: auth.auth_hash(),
            retired_at: 6,
            machine_public_key: fx.source_machine.public_key().as_bytes().to_vec(),
            machine_signature: Vec::new(),
        };
        let sig = sign_machine_receipt(&retire_inner, fx.source_machine.secret_key()).unwrap();
        let retire = ChainedRecord::sign(
            records[4].record_hash(),
            MoveRecord::RetireReceipt {
                auth_hash: auth.auth_hash(),
                retired_at: 6,
                machine_public_key: fx.source_machine.public_key().as_bytes().to_vec(),
                machine_signature: sig,
            },
            fx.owner_pk(),
            fx.owner.secret_key(),
        )
        .unwrap();
        let retired_fold = fold_records(&[records.clone(), vec![retire]].concat());
        assert_eq!(retired_fold.custodian, Some(fx.target_machine.machine_id()));
        assert_eq!(retired_fold.phase, MovePhase::Idle);
    }

    #[test]
    fn at_most_one_live_signer_at_every_instant() {
        // The signer invariant: zero during transfer, exactly one after
        // completion or abort — custodian is single-valued at every legal
        // log shape and the gate conjoins it with key possession.
        let fx = Fixture::new();
        let records = ceremony(&fx, Placement::Roaming);
        let source = fx.source_machine.machine_id();
        let target = fx.target_machine.machine_id();
        for prefix in 0..records.len() {
            let f = fold_records(&records[..=prefix]);
            let signers = f
                .custodian
                .map(|c| usize::from(c == source) + usize::from(c == target))
                .unwrap_or(0);
            assert!(signers <= 1, "prefix {prefix}: {signers} live signers");
        }
        let done = fold_records(&records);
        assert_eq!(done.custodian, Some(target));
    }

    #[test]
    fn participant_cas_rejects_forks_and_accepts_replays() {
        let fx = Fixture::new();
        let records = ceremony(&fx, Placement::Roaming);
        let mut state = MoveState::new();
        let agent = fx.agent.agent_id();
        for r in &records {
            assert!(state.append(&agent, r.clone(), None).unwrap());
        }
        // Replay of ANY already-stored record: idempotent no-op.
        for r in &records {
            assert!(!state.append(&agent, r.clone(), None).unwrap());
        }
        // Fork: a DIFFERENT record claiming an old prev while the head
        // has advanced — CAS rejects, first-valid kept. (Re-signing the
        // identical variant against the identical prev reproduces the
        // identical record — deterministic ML-DSA — and is a replay
        // no-op, not a fork.)
        let auth = match &records[1].record {
            MoveRecord::MoveAuthorization(a) => a.clone(),
            _ => unreachable!(),
        };
        let fork = fx.chain(
            records[3].record_hash(),
            &ChainedRecord {
                prev: [0u8; 32],
                record: MoveRecord::AbortRecord {
                    auth_hash: auth.auth_hash(),
                    reason: "fork challenger".into(),
                },
                owner_public_key: fx.owner_pk().to_vec(),
                owner_signature: Vec::new(),
            },
        );
        assert!(state.append(&agent, fork, None).is_err());
        assert_eq!(state.log(&agent).len(), 5);
    }

    #[test]
    fn participant_rule_rejects_illegal_successors_and_bad_epochs() {
        let fx = Fixture::new();
        let records = ceremony(&fx, Placement::Roaming);
        // Import directly after auth (skipping export) is illegal.
        let bad = [records[0].clone(), records[1].clone(), records[3].clone()];
        assert!(verify_chain(&bad, None).is_err());

        // A move whose from_machine is not the custodian is rejected.
        let stranger = crate::identity::MachineKeypair::generate().unwrap();
        let bad_auth = fx.chain(
            records[0].record_hash(),
            &fx.auth_record(
                1,
                stranger.machine_id(),
                fx.target_machine.machine_id(),
                Placement::Roaming,
            ),
        );
        assert!(verify_chain(&[records[0].clone(), bad_auth], None).is_err());

        // A second move may chain from the committed bundle (epoch 2).
        let auth2 = fx.chain(
            records[4].record_hash(),
            &fx.auth_record(
                2,
                fx.target_machine.machine_id(),
                fx.source_machine.machine_id(),
                Placement::Roaming,
            ),
        );
        let mut records2 = records.clone();
        records2.push(auth2);
        assert!(verify_chain(&records2, None).is_ok());

        // Wrong owner key pinned: the whole chain is rejected.
        let stranger_owner = UserKeypair::generate().unwrap();
        let foreign = ChainedRecord::sign(
            GENESIS_PREV,
            records[0].record.clone(),
            stranger_owner.public_key().as_bytes(),
            stranger_owner.secret_key(),
        )
        .unwrap();
        let expected = fx.owner.public_key();
        assert!(verify_chain(&[foreign], Some(expected)).is_err());
    }

    #[test]
    fn mesh_rule_epoch_monotonicity_and_order_independent_tombstones() {
        let fx = Fixture::new();
        let records = ceremony(&fx, Placement::Roaming);
        let agent = fx.agent.agent_id();
        let bundle1 = records[4].clone();

        // Epoch 2 bundle. The owner builds CUMULATIVE sets, but mesh peers
        // do NOT check supersetness (§7.5 clause 3 note — they may lack
        // earlier bundles and must accept out-of-order arrivals), so a
        // peer may first see an epoch-2 bundle carrying only its own
        // tombstone — coherent, accepted, epoch-1 binding NOT yet known.
        let auth2_inner = MoveAuthorization {
            agent_id: agent,
            move_epoch: 2,
            from_machine: fx.target_machine.machine_id(),
            to_machine: fx.source_machine.machine_id(),
            placement: Placement::Roaming,
            issued_at: 8,
        };
        let epoch2_only = vec![AgentMachineBinding {
            agent,
            machine: fx.target_machine.machine_id(),
            move_epoch: 2,
        }];
        let bundle2 = fx.chain([0u8; 32], &fx.bundle(&auth2_inner, epoch2_only));

        // A peer fed epoch 2 FIRST: placement at 2, only epoch-2's
        // tombstone known — no head needed, no error.
        let mut revoked = RevocationSet::new();
        let mut state = MoveState::new();
        assert!(state.ingest_bundle(&agent, &bundle2, &mut revoked).unwrap());
        assert!(!revoked.is_binding_revoked(&agent, &fx.source_machine.machine_id()));
        assert!(revoked.is_binding_revoked(&agent, &fx.target_machine.machine_id()));
        assert_eq!(revoked.max_revoked_binding_epoch(&agent), Some(2));
        assert_eq!(state.placement(&agent).map(|p| p.placement_epoch), Some(2));

        // Late epoch-1 bundle (r4-3): its PLACEMENT is stale (epoch 1 <
        // 2) but its tombstone unions in REGARDLESS of epoch — the peer
        // now enforces epoch 1's retired binding too, in any arrival
        // order.
        assert!(state.ingest_bundle(&agent, &bundle1, &mut revoked).unwrap());
        assert!(revoked.is_binding_revoked(&agent, &fx.source_machine.machine_id()));
        assert_eq!(state.placement(&agent).map(|p| p.placement_epoch), Some(2));
    }

    #[test]
    fn coherence_drops_each_clause_violation_whole() {
        let fx = Fixture::new();
        let records = ceremony(&fx, Placement::Roaming);
        let auth = match &records[1].record {
            MoveRecord::MoveAuthorization(a) => a.clone(),
            _ => unreachable!(),
        };
        let agent = fx.agent.agent_id();
        let this_tombstone = vec![AgentMachineBinding {
            agent,
            machine: auth.from_machine,
            move_epoch: 1,
        }];

        // Baseline: coherent bundle passes.
        assert!(verify_bundle_coherence_chained(&records[4]).is_ok());

        // Swapped certificate (cert of a different agent, same owner).
        let other_agent = AgentKeypair::generate().unwrap();
        let other_cert = AgentCertificate::issue_for_public_key(
            &fx.owner,
            other_agent.public_key().as_bytes(),
            None,
        )
        .unwrap();
        let mut swapped = fx.bundle(&auth, this_tombstone.clone());
        if let MoveRecord::ActivationBundle {
            agent_certificate, ..
        } = &mut swapped.record
        {
            *agent_certificate = other_cert;
        }
        let swapped = fx.chain([0u8; 32], &swapped);
        assert!(verify_bundle_coherence_chained(&swapped).is_err());

        // Mismatched epoch (placement epoch ≠ move epoch).
        let mut bad_epoch = fx.bundle(&auth, this_tombstone.clone());
        if let MoveRecord::ActivationBundle {
            placement_record, ..
        } = &mut bad_epoch.record
        {
            placement_record.placement_epoch = 99;
        }
        let bad_epoch = fx.chain([0u8; 32], &bad_epoch);
        assert!(verify_bundle_coherence_chained(&bad_epoch).is_err());

        // Non-cumulative set: missing this move's tombstone.
        let empty_retired = fx.chain([0u8; 32], &fx.bundle(&auth, vec![]));
        assert!(verify_bundle_coherence_chained(&empty_retired).is_err());

        // Pin ≠ target.
        let pin_auth = MoveAuthorization {
            agent_id: auth.agent_id,
            move_epoch: 1,
            from_machine: auth.from_machine,
            to_machine: auth.to_machine,
            placement: Placement::Pinned(fx.source_machine.machine_id()), // ≠ to_machine
            issued_at: 2,
        };
        let pin_mismatch = fx.chain([0u8; 32], &fx.bundle(&pin_auth, this_tombstone.clone()));
        assert!(verify_bundle_coherence_chained(&pin_mismatch).is_err());

        // Foreign placement payload (placement record of another agent).
        let mut foreign = fx.bundle(&auth, this_tombstone);
        if let MoveRecord::ActivationBundle {
            placement_record, ..
        } = &mut foreign.record
        {
            placement_record.agent_id = other_agent.agent_id();
        }
        let foreign = fx.chain([0u8; 32], &foreign);
        assert!(verify_bundle_coherence_chained(&foreign).is_err());
    }

    #[test]
    fn export_envelope_is_bound_to_its_authorization() {
        let fx = Fixture::new();
        let auth = MoveAuthorization {
            agent_id: fx.agent.agent_id(),
            move_epoch: 1,
            from_machine: fx.source_machine.machine_id(),
            to_machine: fx.target_machine.machine_id(),
            placement: Placement::Roaming,
            issued_at: 2,
        };
        let (pub_bytes, sec_bytes) = fx.agent.to_bytes();
        // Export payload: length-prefixed public ‖ secret.
        let mut payload = Vec::with_capacity(8 + pub_bytes.len() + sec_bytes.len());
        payload.extend_from_slice(&(pub_bytes.len() as u64).to_le_bytes());
        payload.extend_from_slice(&pub_bytes);
        payload.extend_from_slice(&sec_bytes);

        let env = ExportEnvelope::seal(&fx.target_kem.public_bytes, &auth, &payload).unwrap();
        // Target unwraps and the keypair round-trips.
        let opened = env.open(&fx.target_kem, &auth).unwrap();
        assert_eq!(opened, payload);
        let reopened = AgentKeypair::from_bytes(&pub_bytes, &sec_bytes).unwrap();
        assert_eq!(reopened.agent_id(), fx.agent.agent_id());

        // The same envelope under a DIFFERENT authorization (other move /
        // other epoch) fails the AEAD tag — acyclicity + AAD binding.
        let other = MoveAuthorization {
            move_epoch: 2,
            ..auth.clone()
        };
        assert!(env.open(&fx.target_kem, &other).is_err());
        // A different machine cannot unwrap.
        let stranger_kem = AgentKemKeypair::generate().unwrap();
        assert!(env.open(&stranger_kem, &auth).is_err());
    }

    #[test]
    fn enforcement_b_and_p() {
        let fx = Fixture::new();
        let agent = fx.agent.agent_id();
        let source = fx.source_machine.machine_id();
        let target = fx.target_machine.machine_id();

        let mut revoked = RevocationSet::new();
        let mut placements = HashMap::new();

        // Absent evidence fails open (§9.3).
        assert!(enforce_pairing(&revoked, &placements, &agent, &source).is_none());

        // B: tombstone denies the pairing; any other machine passes.
        revoked.union_bundle_retired(&[AgentMachineBinding {
            agent,
            machine: source,
            move_epoch: 1,
        }]);
        assert_eq!(
            enforce_pairing(&revoked, &placements, &agent, &source),
            Some(PairingDenial::BindingRevoked)
        );
        assert!(enforce_pairing(&revoked, &placements, &agent, &target).is_none());

        // P: pinned-to-target record at an epoch ≥ the tombstone denies
        // the stale source pairing (coherent equal-epoch activation).
        let record = PlacementRecord::sign(
            agent,
            fx.owner_pk(),
            Placement::Pinned(target),
            1,
            5,
            fx.owner.secret_key(),
        )
        .unwrap();
        placements.insert(agent, record);
        // For the REVOKED source pairing, B fires first (check order:
        // B before P — a tombstone is stronger evidence than a pin).
        assert_eq!(
            enforce_pairing(&revoked, &placements, &agent, &source),
            Some(PairingDenial::BindingRevoked)
        );
        // P proper: a THIRD machine (binding not revoked) is denied by
        // the pin — a pinned agent announcing from a non-pinned machine.
        let stranger_machine = MachineId([9u8; 32]);
        assert_eq!(
            enforce_pairing(&revoked, &placements, &agent, &stranger_machine),
            Some(PairingDenial::PlacementPinned { pinned_to: target })
        );
        assert!(enforce_pairing(&revoked, &placements, &agent, &target).is_none());

        // A strictly OLDER placement record is stale — no P denial.
        let stale = PlacementRecord::sign(
            agent,
            fx.owner_pk(),
            Placement::Pinned(source),
            0,
            5,
            fx.owner.secret_key(),
        )
        .unwrap();
        let mut stale_view = HashMap::new();
        stale_view.insert(agent, stale);
        assert!(enforce_pairing(&revoked, &stale_view, &agent, &target).is_none());

        // Roaming placement never denies by P.
        let roaming = PlacementRecord::sign(
            agent,
            fx.owner_pk(),
            Placement::Roaming,
            2,
            6,
            fx.owner.secret_key(),
        )
        .unwrap();
        let mut roaming_view = HashMap::new();
        roaming_view.insert(agent, roaming);
        // Roaming never denies by P (a roamer's per-machine authorization
        // is exactly the tombstone set — B is the only check).
        assert!(enforce_pairing(&revoked, &roaming_view, &agent, &target).is_none());
    }

    #[test]
    fn move_state_persistence_roundtrip() {
        let fx = Fixture::new();
        let agent = fx.agent.agent_id();
        let records = ceremony(&fx, Placement::Roaming);
        let mut state = MoveState::new();
        for r in &records {
            state.append(&agent, r.clone(), None).unwrap();
        }
        let mut revoked = RevocationSet::new();
        state
            .ingest_bundle(&agent, &records[4], &mut revoked)
            .unwrap();

        let logs_bytes = state.logs_to_bytes().unwrap();
        let bundles_bytes = state.bundles_to_bytes().unwrap();
        let placements_bytes = state.placements_to_bytes().unwrap();
        let mut loaded = MoveState::logs_from_bytes(&logs_bytes).unwrap();
        let mut revoked2 = RevocationSet::new();
        let bundles_state = MoveState::bundles_from_bytes(&bundles_bytes, &mut revoked2).unwrap();
        let placements_state = MoveState::placements_from_bytes(&placements_bytes).unwrap();
        loaded.merge_loaded(bundles_state);
        loaded.merge_loaded(placements_state);

        assert_eq!(loaded.log(&agent).len(), 5);
        assert_eq!(loaded.fold(&agent), state.fold(&agent));
        assert!(loaded.placement(&agent).is_some());
        assert!(revoked2.is_binding_revoked(&agent, &fx.source_machine.machine_id()));

        // Torn/corrupt magic fails closed.
        assert!(MoveState::logs_from_bytes(b"garbage").is_err());
        assert!(MoveState::bundles_from_bytes(b"garbage", &mut RevocationSet::new()).is_err());
        assert!(MoveState::placements_from_bytes(b"garbage").is_err());
    }

    #[test]
    fn placement_record_verify_rejects_forgery() {
        let fx = Fixture::new();
        let agent = fx.agent.agent_id();
        let record = PlacementRecord::sign(
            agent,
            fx.owner_pk(),
            Placement::Roaming,
            0,
            1,
            fx.owner.secret_key(),
        )
        .unwrap();
        assert!(record.verify().is_ok());
        // Forged equal-epoch pin by a DIFFERENT owner: the signature is
        // internally valid but the issuer is not the cert issuer.
        let attacker = UserKeypair::generate().unwrap();
        let forged = PlacementRecord::sign(
            agent,
            attacker.public_key().as_bytes(),
            Placement::Pinned(fx.target_machine.machine_id()),
            1,
            2,
            attacker.secret_key(),
        )
        .unwrap();
        assert!(forged.verify().is_ok());
        assert!(!forged.owner_matches_cert(&fx.cert));
    }

    #[test]
    fn legal_successor_table() {
        use MoveRecord::{
            AbortRecord as AbortRec, ActivationBundle as BundleRec, ExportReceipt as ExportRec,
            ImportReceipt as ImportRec, MoveAuthorization as AuthRec, PlacementMint as MintRec,
            RetireReceipt as RetireRec,
        };
        let agent = AgentId([1; 32]);
        let m1 = MachineId([2; 32]);
        let m2 = MachineId([3; 32]);
        let auth_inner = super::MoveAuthorization {
            agent_id: agent,
            move_epoch: 1,
            from_machine: m1,
            to_machine: m2,
            placement: Placement::Roaming,
            issued_at: 0,
        };
        let mint = MintRec {
            agent_id: agent,
            placement: Placement::Roaming,
            custodian_machine: m1,
            issued_at: 0,
        };
        let auth = AuthRec(auth_inner.clone());
        let export = ExportRec {
            auth_hash: [0; 32],
            envelope_digest: [0; 32],
            sealed_at: 0,
            machine_public_key: vec![],
            machine_signature: vec![],
        };
        let import = ImportRec {
            auth_hash: [0; 32],
            imported_at: 0,
            machine_public_key: vec![],
            machine_signature: vec![],
        };
        let retire = RetireRec {
            auth_hash: [0; 32],
            retired_at: 0,
            machine_public_key: vec![],
            machine_signature: vec![],
        };
        let abort = AbortRec {
            auth_hash: [0; 32],
            reason: String::new(),
        };
        let bundle = BundleRec {
            authorization: auth_inner,
            retired_bindings: vec![],
            placement_record: PlacementRecord {
                agent_id: agent,
                owner_public_key: vec![],
                placement: Placement::Roaming,
                placement_epoch: 1,
                issued_at: 0,
                signature: vec![],
            },
            agent_certificate: AgentCertificate::issue(
                &UserKeypair::generate().unwrap(),
                &AgentKeypair::generate().unwrap(),
            )
            .unwrap(),
        };
        assert!(is_legal_successor(&mint, &auth));
        assert!(is_legal_successor(&auth, &export));
        assert!(is_legal_successor(&auth, &abort));
        assert!(is_legal_successor(&export, &import));
        assert!(is_legal_successor(&export, &abort));
        assert!(is_legal_successor(&import, &bundle));
        assert!(is_legal_successor(&import, &abort));
        assert!(is_legal_successor(&bundle, &retire));
        assert!(is_legal_successor(&bundle, &auth));
        assert!(is_legal_successor(&retire, &auth));
        assert!(is_legal_successor(&abort, &auth));
        // Illegal: skip steps / go backwards / abort a committed move.
        assert!(!is_legal_successor(&mint, &export));
        assert!(!is_legal_successor(&auth, &import));
        assert!(!is_legal_successor(&import, &export));
        assert!(!is_legal_successor(&mint, &abort));
        assert!(!is_legal_successor(&mint, &bundle));
        assert!(!is_legal_successor(&bundle, &abort));
        assert!(!is_legal_successor(&export, &retire));
    }
}
