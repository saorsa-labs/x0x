//! ADR-0064 (Decision §1/§1a): the pre-mutation owner mandate for
//! invite-derived seatings on owner-axis (OwnerCertified / Home) groups.
//!
//! The mandate is the ADMISSION OWNER's USER-key signature over a preimage
//! whose every member is deterministically known BEFORE the seating
//! authority mutates TreeKEM or persists: the authority clones its live
//! [`GroupInfo`](crate::groups::GroupInfo), applies the seat-write it is
//! about to perform, and derives the roster root over that clone (the
//! ACTUAL current roster — never the possibly-stale invite projection; the
//! r2 `{owner, A, B, joiner}` sequence is exactly the case the invite
//! projection gets wrong). The post-mutation terminal binding stays
//! two-phase: the mandate is pre-mutation intent, and the existing
//! post-mutation head attestation remains the terminal CAS confirmation.
//!
//! Persistence/wire shape (mixed-fleet safety, #451): a plain struct whose
//! every field is `#[serde(default)]`, carried as an OPTIONAL field on the
//! `MemberAdded` metadata event. Old binaries ignore the unknown JSON key
//! and nodes without the owner key simply omit it — no wire enum grows a
//! variant.

use crate::groups::state_commit::GroupStateCommit;
use crate::groups::GroupInfo;
use crate::identity::UserId;
use ant_quic::crypto::raw_public_keys::pqc::{sign_with_ml_dsa, verify_with_ml_dsa};
use ant_quic::MlDsaPublicKey;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Wire-format version of the mandate preimage (ADR-0064 §1a fixes the
/// domain string to `v2`; there is no v1 on the wire).
pub const OWNER_MANDATE_VERSION: u8 = 2;

/// Domain prefix for the canonical mandate preimage.
const OWNER_MANDATE_DOMAIN: &[u8] = b"x0x.owner-mandate.v2\0";

const B64_STD: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// ADR-0064 §1a: the owner signs the BLAKE3 digest of the canonical
/// preimage (domain-separated, length-stable per field class).
fn mandate_digest(canonical: &[u8]) -> [u8; 32] {
    *blake3::hash(canonical).as_bytes()
}

/// The signed statement by the admission owner (owner USER key) that a
/// specific authority agent may seat a specific joiner, bound to the group
/// stable id, the authority agent id, the roster root at issuance (the
/// post-add root over the authority's CURRENT roster), the state
/// revision/hash the mandate is anchored to (`expected_terminal_revision`
/// chains from `parent_state_hash`), an `issued_at_ms`, and the declared
/// TreeKEM epoch the terminal event must carry.
///
/// Receivers verify it on an ISOLATED clone (see
/// [`OwnerMandate::verify_against_terminal`]): the mandate's
/// `roster_root_after_add` must equal BOTH the receiver's own re-derived
/// candidate root AND the terminal commit's signed `roster_root`
/// (triple-equality), and the anchor revision/parent hash must match the
/// terminal commit exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerMandate {
    /// Preimage version; must be [`OWNER_MANDATE_VERSION`].
    #[serde(default)]
    pub version: u8,
    /// The group's stable id (`GroupGenesis::group_id`).
    #[serde(default)]
    pub stable_group_id: String,
    /// The revision the terminal commit will carry
    /// (`authority.state_revision + 1` at mint time).
    #[serde(default)]
    pub expected_terminal_revision: u64,
    /// The authority's current head `state_hash` (the terminal commit's
    /// `prev_state_hash`).
    #[serde(default)]
    pub parent_state_hash: String,
    /// Roster root over the authority's CURRENT roster + the seat-write
    /// (NOT the invite projection).
    #[serde(default)]
    pub roster_root_after_add: String,
    /// `compute_policy_hash` over the authority's current policy.
    #[serde(default)]
    pub policy_hash: String,
    /// `compute_public_meta_hash` over the authority's current meta.
    #[serde(default)]
    pub public_meta_hash: String,
    /// TreeKEM epoch the terminal `MemberAdded` will carry (`0` when the
    /// plane has no TreeKEM epoch to bind).
    #[serde(default)]
    pub declared_epoch: u64,
    /// Hex agent id of the joiner being seated.
    #[serde(default)]
    pub joiner_agent_id: String,
    /// BLAKE3-256 hex over the invite secret (binds the mandate to the
    /// one specific invite whose consumption produced the seat).
    #[serde(default)]
    pub invite_secret_hash: String,
    /// BLAKE3-256 hex of the `AgentCertificate` the joiner was admitted
    /// under (empty when the group has no owner axis — mandates are never
    /// minted for those).
    #[serde(default)]
    pub admission_cert_digest: String,
    /// Hex agent id of the AUTHORITY agent performing the seat-write —
    /// the mandate is per-authority, never group-level.
    #[serde(default)]
    pub authority_agent_id: String,
    /// Unix ms at mint (observability; covered by the signature).
    #[serde(default)]
    pub issued_at_ms: u64,
    /// Base64 ML-DSA-65 signature by the owner USER key over the BLAKE3
    /// digest of the canonical preimage.
    #[serde(default)]
    pub signature_b64: String,
}

/// Verification failure reasons (typed so diagnostics and tests can
/// distinguish WHICH binding broke).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OwnerMandateError {
    #[error("owner key does not match the policy's admission owner")]
    OwnerKeyMismatch,
    #[error("mandate version {0} is not {OWNER_MANDATE_VERSION}")]
    UnsupportedVersion(u8),
    #[error("mandate is not for this group's stable id")]
    GroupBindingMismatch,
    #[error("roster root triple-equality failed (mandate/candidate/terminal)")]
    RosterRootMismatch,
    #[error("mandate revision {got} does not match terminal revision {expected}")]
    RevisionMismatch { got: u64, expected: u64 },
    #[error("mandate parent hash does not match the terminal commit's prev_state_hash")]
    ParentHashMismatch,
    #[error("mandate authority {0} is not the event's actor")]
    AuthorityMismatch(String),
    #[error("mandate joiner {0} is not the event's joiner")]
    JoinerMismatch(String),
    #[error("mandate policy hash does not match the terminal commit")]
    PolicyHashMismatch,
    #[error("mandate public-meta hash does not match the terminal commit")]
    MetaHashMismatch,
    #[error("mandate declared epoch {declared} does not match the event's treekem epoch")]
    EpochMismatch { declared: u64 },
    #[error("mandate admission-cert digest does not match the committed certificate")]
    AdmissionDigestMismatch,
    #[error("mandate signature fails verification under the owner key")]
    SignatureInvalid,
}

impl OwnerMandate {
    /// Canonical, domain-separated preimage bytes — every bound field in a
    /// fixed order with NUL separators between variable-length fields
    /// (same style as the `HeadAttestation` canonical bytes).
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(OWNER_MANDATE_DOMAIN);
        buf.push(self.version);
        buf.push(0);
        buf.extend_from_slice(self.stable_group_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.expected_terminal_revision.to_le_bytes());
        buf.extend_from_slice(self.parent_state_hash.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.roster_root_after_add.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.policy_hash.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.public_meta_hash.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.declared_epoch.to_le_bytes());
        buf.extend_from_slice(self.joiner_agent_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.invite_secret_hash.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.admission_cert_digest.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.authority_agent_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.issued_at_ms.to_le_bytes());
        buf
    }

    /// Mint a mandate. Every input MUST be derived from the authority's
    /// pre-mutation clone with the seat-write already applied (see the
    /// module docs); this function performs no derivation of its own so
    /// the mint point stays an explicit property of the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        stable_group_id: &str,
        expected_terminal_revision: u64,
        parent_state_hash: &str,
        roster_root_after_add: &str,
        policy_hash: &str,
        public_meta_hash: &str,
        declared_epoch: u64,
        joiner_agent_id: &str,
        invite_secret_hash: &str,
        admission_cert_digest: &str,
        authority_agent_id: &str,
        issued_at_ms: u64,
        owner_kp: &crate::identity::UserKeypair,
    ) -> Result<Self, String> {
        let mut mandate = Self {
            version: OWNER_MANDATE_VERSION,
            stable_group_id: stable_group_id.to_string(),
            expected_terminal_revision,
            parent_state_hash: parent_state_hash.to_string(),
            roster_root_after_add: roster_root_after_add.to_string(),
            policy_hash: policy_hash.to_string(),
            public_meta_hash: public_meta_hash.to_string(),
            declared_epoch,
            joiner_agent_id: joiner_agent_id.to_string(),
            invite_secret_hash: invite_secret_hash.to_string(),
            admission_cert_digest: admission_cert_digest.to_string(),
            authority_agent_id: authority_agent_id.to_string(),
            issued_at_ms,
            signature_b64: String::new(),
        };
        let digest = mandate_digest(&mandate.canonical_bytes());
        let sig = sign_with_ml_dsa(owner_kp.secret_key(), &digest)
            .map_err(|e| format!("owner mandate sign: {e:?}"))?;
        mandate.signature_b64 = B64_STD.encode(sig.as_bytes());
        Ok(mandate)
    }

    /// Verify the mandate on an ISOLATED clone (`candidate` — the
    /// receiver's throwaway `GroupInfo` with the SAME seat-write applied)
    /// against the terminal commit and the event's identity fields.
    ///
    /// Checks, in order: the owner key IS the policy's admission owner;
    /// the version; the stable-id binding (mandate == candidate ==
    /// terminal); the ROSTER-ROOT TRIPLE-EQUALITY (mandate ==
    /// `compute_roster_root(candidate)` == `terminal.roster_root`); the
    /// anchor revision/parent-hash; the authority-agent and joiner
    /// bindings; the policy/meta hashes against the terminal; the
    /// declared epoch against the event's `treekem_epoch` (only when the
    /// event carries one — GSS-plane events have no epoch to bind); the
    /// admission-cert digest (when the receiver holds the committed
    /// certificate); and finally the ML-DSA signature under the owner
    /// USER key.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_against_terminal(
        &self,
        owner_public_key: &MlDsaPublicKey,
        expected_owner: &UserId,
        candidate: &GroupInfo,
        terminal: &GroupStateCommit,
        authority_agent_id: &str,
        joiner_agent_id: &str,
        event_epoch: Option<u64>,
        admission_cert_digest: Option<&str>,
    ) -> Result<(), OwnerMandateError> {
        if &UserId::from_public_key(owner_public_key) != expected_owner {
            return Err(OwnerMandateError::OwnerKeyMismatch);
        }
        if self.version != OWNER_MANDATE_VERSION {
            return Err(OwnerMandateError::UnsupportedVersion(self.version));
        }
        if self.stable_group_id != candidate.stable_group_id()
            || self.stable_group_id != terminal.group_id
        {
            return Err(OwnerMandateError::GroupBindingMismatch);
        }
        // R2 triple-equality: the receiver re-derives the candidate root
        // on its own clone and requires mandate == candidate == terminal.
        let candidate_root =
            crate::groups::state_commit::compute_roster_root(&candidate.members_v2);
        if self.roster_root_after_add != candidate_root || candidate_root != terminal.roster_root {
            return Err(OwnerMandateError::RosterRootMismatch);
        }
        if self.expected_terminal_revision != terminal.revision {
            return Err(OwnerMandateError::RevisionMismatch {
                got: self.expected_terminal_revision,
                expected: terminal.revision,
            });
        }
        if terminal.prev_state_hash.as_deref() != Some(self.parent_state_hash.as_str()) {
            return Err(OwnerMandateError::ParentHashMismatch);
        }
        if !self
            .authority_agent_id
            .eq_ignore_ascii_case(authority_agent_id)
        {
            return Err(OwnerMandateError::AuthorityMismatch(
                self.authority_agent_id.clone(),
            ));
        }
        if !self.joiner_agent_id.eq_ignore_ascii_case(joiner_agent_id) {
            return Err(OwnerMandateError::JoinerMismatch(
                self.joiner_agent_id.clone(),
            ));
        }
        if self.policy_hash != terminal.policy_hash {
            return Err(OwnerMandateError::MetaHashMismatch);
        }
        if event_epoch.is_some_and(|epoch| epoch != self.declared_epoch) {
            return Err(OwnerMandateError::EpochMismatch {
                declared: self.declared_epoch,
            });
        }
        if admission_cert_digest.is_some_and(|digest| digest != self.admission_cert_digest) {
            return Err(OwnerMandateError::AdmissionDigestMismatch);
        }
        let Ok(sig_bytes) = B64_STD.decode(&self.signature_b64) else {
            return Err(OwnerMandateError::SignatureInvalid);
        };
        let Ok(sig) =
            ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&sig_bytes)
        else {
            return Err(OwnerMandateError::SignatureInvalid);
        };
        let digest = mandate_digest(&self.canonical_bytes());
        if verify_with_ml_dsa(owner_public_key, &digest, &sig).is_err() {
            return Err(OwnerMandateError::SignatureInvalid);
        }
        Ok(())
    }
}

/// ADR-0064 §1b capability state for ONE authority agent. An ABSENT map
/// entry is the `Unknown` state (never observed capability from that
/// agent — the keyless tier); a present entry records the FIRST time this
/// agent proved it holds the owner USER key (a verified mandate or an
/// owner-countersigned InviteV4 minted by its install). Slice 2 only
/// records; the grace/`Refusing` derivation lands with slice 3 and reads
/// `first_seen_ms` — no persisted enum grows a variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateCapabilityState {
    /// Unix ms of the first capability observation from this agent.
    #[serde(default)]
    pub first_seen_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_are_deterministic_and_field_sensitive() {
        // WHY: every bound field must feed the signed preimage — a field
        // that does not influence the bytes cannot influence the
        // signature, and flipping it would be unobservable.
        let a = mandate_fixture();
        let b = mandate_fixture();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        for mutated in mandate_field_flips(&a) {
            assert_ne!(
                a.canonical_bytes(),
                mutated.canonical_bytes(),
                "flip must change the canonical preimage"
            );
        }
    }

    #[test]
    fn serde_defaults_decode_an_empty_object() {
        // WHY (#451 mixed-fleet hazard): an old/new record that omits
        // every field must still decode — unknown or absent keys can
        // never brick a peer.
        let decoded: OwnerMandate = serde_json::from_str("{}").expect("empty object decodes");
        assert_eq!(decoded, OwnerMandate::default_like());
        let round: OwnerMandate =
            serde_json::from_str(&serde_json::to_string(&mandate_fixture()).unwrap()).unwrap();
        assert_eq!(round, mandate_fixture());
    }

    fn mandate_fixture() -> OwnerMandate {
        OwnerMandate {
            version: OWNER_MANDATE_VERSION,
            stable_group_id: "ab".repeat(32),
            expected_terminal_revision: 7,
            parent_state_hash: "cd".repeat(32),
            roster_root_after_add: "ef".repeat(32),
            policy_hash: "12".repeat(32),
            public_meta_hash: "34".repeat(32),
            declared_epoch: 3,
            joiner_agent_id: "56".repeat(32),
            invite_secret_hash: "78".repeat(32),
            admission_cert_digest: "9a".repeat(32),
            authority_agent_id: "bc".repeat(32),
            issued_at_ms: 1_755_000_000_000,
            signature_b64: String::new(),
        }
    }

    /// One flip per BOUND PREIMAGE field (keeps the tamper matrix in
    /// lockstep with the struct definition — a new preimage field must be
    /// added here or the field-sensitivity test fails). The
    /// `signature_b64` OUTPUT is not a preimage member by construction
    /// (it cannot sign itself); flipping it is covered by the
    /// verify-tamper suite in the server tests.
    fn mandate_field_flips(m: &OwnerMandate) -> Vec<OwnerMandate> {
        let mut out = Vec::new();
        let mut flip_version = m.clone();
        flip_version.version = OWNER_MANDATE_VERSION + 1;
        out.push(flip_version);
        let mut flip_group = m.clone();
        flip_group.stable_group_id = m.stable_group_id.clone() + "x";
        out.push(flip_group);
        let mut flip_rev = m.clone();
        flip_rev.expected_terminal_revision = m.expected_terminal_revision + 1;
        out.push(flip_rev);
        let mut flip_parent = m.clone();
        flip_parent.parent_state_hash = m.parent_state_hash.clone() + "x";
        out.push(flip_parent);
        let mut flip_root = m.clone();
        flip_root.roster_root_after_add = m.roster_root_after_add.clone() + "x";
        out.push(flip_root);
        let mut flip_policy = m.clone();
        flip_policy.policy_hash = m.policy_hash.clone() + "x";
        out.push(flip_policy);
        let mut flip_meta = m.clone();
        flip_meta.public_meta_hash = m.public_meta_hash.clone() + "x";
        out.push(flip_meta);
        let mut flip_epoch = m.clone();
        flip_epoch.declared_epoch = m.declared_epoch + 1;
        out.push(flip_epoch);
        let mut flip_joiner = m.clone();
        flip_joiner.joiner_agent_id = m.joiner_agent_id.clone() + "x";
        out.push(flip_joiner);
        let mut flip_secret = m.clone();
        flip_secret.invite_secret_hash = m.invite_secret_hash.clone() + "x";
        out.push(flip_secret);
        let mut flip_cert = m.clone();
        flip_cert.admission_cert_digest = m.admission_cert_digest.clone() + "x";
        out.push(flip_cert);
        let mut flip_authority = m.clone();
        flip_authority.authority_agent_id = m.authority_agent_id.clone() + "x";
        out.push(flip_authority);
        let mut flip_issued = m.clone();
        flip_issued.issued_at_ms = m.issued_at_ms + 1;
        out.push(flip_issued);
        out
    }

    impl OwnerMandate {
        fn default_like() -> Self {
            Self {
                version: 0,
                stable_group_id: String::new(),
                expected_terminal_revision: 0,
                parent_state_hash: String::new(),
                roster_root_after_add: String::new(),
                policy_hash: String::new(),
                public_meta_hash: String::new(),
                declared_epoch: 0,
                joiner_agent_id: String::new(),
                invite_secret_hash: String::new(),
                admission_cert_digest: String::new(),
                authority_agent_id: String::new(),
                issued_at_ms: 0,
                signature_b64: String::new(),
            }
        }
    }
}
