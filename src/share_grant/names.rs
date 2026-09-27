//! Grant-carried owner and machine names (ADR-0079 §1).
//!
//! A `ShareGrant` is strict positional bincode with a fixed signature
//! layout, so names cannot be appended to it without breaking every old
//! verifier. Instead the owner install sends a second typed DM,
//! `x0x-sharegrant-v2\0` ‖ bincode of [`ShareGrantEnvelopeV2`]:
//!
//! - `grant`: the unchanged v1 [`ShareGrant`], with its v1 signature;
//! - `names`: [`GrantNames`] — the owner's `owner_name` and the names of
//!   the owner's machines that host the shared agents;
//! - `names_signature`: the owner **user** key's ML-DSA-65 signature over
//!   [`GrantNames::signed_bytes`], which binds the names to
//!   `SHA-256(grant.signed_bytes())`, so names cannot be moved to another
//!   grant or attributed to another user.
//!
//! The receiver verifies the grant by the unchanged v1 rules, then the names
//! signature under `grant.owner_public_key`; either failure refuses the
//! whole envelope. The grant is stored byte-identical to a v1 delivery, so a
//! v1 and a v2 copy of one `grant_id` are an idempotent `Duplicate`.
//!
//! The envelope goes only to grantee agents that advertise the signed
//! `share_grant_names` capability extension
//! ([`crate::dm_capability::ShareGrantNamesExtension`]); shared-agent
//! daemons, which enforce the grant, and every other recipient get v1
//! ([`choose_grant_envelope`]).

use std::collections::BTreeSet;

use ant_quic::crypto::raw_public_keys::pqc::{
    sign_with_ml_dsa, verify_with_ml_dsa, MlDsaPublicKey, MlDsaSignature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{strict_decode, ShareGrant, ShareGrantError, MAX_GRANT_AGENTS, MAX_SHARE_GRANT_BYTES};
use crate::identity::{AgentId, MachineId, UserId, UserKeypair};

/// Versioned, NUL-terminated DM prefix of a names-carrying grant delivery.
pub const SHARE_GRANT_V2_DM_PREFIX: &[u8] = b"x0x-sharegrant-v2\0";

/// Decode bound for a v2 envelope body (ADR-0079: the worst case is about
/// 22 KiB; v1's 32 KiB bound is raised for this prefix only).
pub const MAX_SHARE_GRANT_V2_BYTES: usize = 48 * 1024;

/// Longest owner or machine name, in UTF-8 bytes (as
/// `SelfProfile::validate_name`).
pub const MAX_GRANT_NAME_BYTES: usize = 128;

/// Most machine entries in one names section (= [`MAX_GRANT_AGENTS`]).
pub const MAX_GRANT_MACHINE_NAMES: usize = MAX_GRANT_AGENTS;

/// Domain separation for the names signature.
const NAMES_SIG_DOMAIN: &[u8] = b"x0x-sharegrant-names-v1";

/// One named machine of the owner that hosts at least one shared agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantMachineName {
    /// The machine.
    pub machine_id: MachineId,
    /// Its synced ADR-0036 `machine_name`.
    pub machine_name: String,
}

/// The names section of a v2 grant envelope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantNames {
    /// The owner's ADR-0036 `human_name`, trimmed.
    pub owner_name: Option<String>,
    /// Sorted by `machine_id`, unique, at most [`MAX_GRANT_MACHINE_NAMES`].
    pub machines: Vec<GrantMachineName>,
}

/// Validate one owner or machine name: already trimmed, 1–128 UTF-8 bytes,
/// no control characters.
///
/// # Errors
/// [`ShareGrantError::Invalid`] naming the rule broken.
pub fn validate_grant_name(field: &str, name: &str) -> Result<(), ShareGrantError> {
    let invalid = |m: String| Err(ShareGrantError::Invalid(m));
    if name.is_empty() {
        return invalid(format!("{field} must not be empty"));
    }
    if name.trim() != name {
        return invalid(format!("{field} must be trimmed"));
    }
    if name.len() > MAX_GRANT_NAME_BYTES {
        return invalid(format!("{field} exceeds {MAX_GRANT_NAME_BYTES} bytes"));
    }
    if name.chars().any(char::is_control) {
        return invalid(format!("{field} must not contain control characters"));
    }
    Ok(())
}

impl GrantNames {
    /// Whether the section carries nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.owner_name.is_none() && self.machines.is_empty()
    }

    /// Structural checks: name rules, at most [`MAX_GRANT_MACHINE_NAMES`]
    /// entries, ids sorted and unique.
    ///
    /// # Errors
    /// [`ShareGrantError::Invalid`].
    pub fn validate(&self) -> Result<(), ShareGrantError> {
        if let Some(owner_name) = &self.owner_name {
            validate_grant_name("owner_name", owner_name)?;
        }
        if self.machines.len() > MAX_GRANT_MACHINE_NAMES {
            return Err(ShareGrantError::Invalid("too many machine names".into()));
        }
        if self
            .machines
            .windows(2)
            .any(|w| w[0].machine_id.0 >= w[1].machine_id.0)
        {
            return Err(ShareGrantError::Invalid(
                "machine names must be sorted by id and unique".into(),
            ));
        }
        for machine in &self.machines {
            validate_grant_name("machine_name", &machine.machine_name)?;
        }
        Ok(())
    }

    /// The bytes the owner signs: `"x0x-sharegrant-names-v1" ‖
    /// SHA-256(grant.signed_bytes()) ‖ owner_name ‖ machines`, with a
    /// presence tag for `owner_name`, `u32` little-endian length prefixes
    /// and counts, and fixed-width 32-byte machine ids. No two distinct
    /// (grant, names) pairs share an encoding.
    #[must_use]
    pub fn signed_bytes(&self, grant: &ShareGrant) -> Vec<u8> {
        let digest = Sha256::digest(grant.signed_bytes());
        let mut out = Vec::with_capacity(
            NAMES_SIG_DOMAIN.len() + 32 + 5 + MAX_GRANT_NAME_BYTES + 4 + self.machines.len() * 164,
        );
        out.extend_from_slice(NAMES_SIG_DOMAIN);
        out.extend_from_slice(&digest);
        match &self.owner_name {
            None => out.push(0),
            Some(name) => {
                out.push(1);
                push_str(&mut out, name);
            }
        }
        out.extend_from_slice(&(self.machines.len() as u32).to_le_bytes());
        for machine in &self.machines {
            out.extend_from_slice(machine.machine_id.as_bytes());
            push_str(&mut out, &machine.machine_name);
        }
        out
    }
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// A names section with the owner's signature over it (bound to one grant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGrantNames {
    /// The names.
    pub names: GrantNames,
    /// ML-DSA-65 signature by the grant's owner key over
    /// [`GrantNames::signed_bytes`].
    pub names_signature: Vec<u8>,
}

impl SignedGrantNames {
    /// Sign `names` for `grant` with the grant's owner key.
    ///
    /// # Errors
    /// `Invalid` when `owner_key` is not the grant's owner or the names are
    /// out of bounds; `BadSignature` when signing fails.
    pub fn sign(
        owner_key: &UserKeypair,
        grant: &ShareGrant,
        names: GrantNames,
    ) -> Result<Self, ShareGrantError> {
        if owner_key.user_id() != grant.owner {
            return Err(ShareGrantError::Invalid(
                "names must be signed by the grant's owner".into(),
            ));
        }
        names.validate()?;
        let signature = sign_with_ml_dsa(owner_key.secret_key(), &names.signed_bytes(grant))
            .map_err(|e| ShareGrantError::BadSignature(format!("signing names failed: {e:?}")))?;
        Ok(Self {
            names,
            names_signature: signature.as_bytes().to_vec(),
        })
    }

    /// Verify the section against `grant`: bounds, the grant's owner key
    /// hashes to `grant.owner`, and the signature verifies over
    /// [`GrantNames::signed_bytes`] for exactly this grant.
    ///
    /// # Errors
    /// `Invalid` or `BadSignature`.
    pub fn verify(&self, grant: &ShareGrant) -> Result<(), ShareGrantError> {
        self.names.validate()?;
        let key = MlDsaPublicKey::from_bytes(&grant.owner_public_key)
            .map_err(|_| ShareGrantError::BadSignature("invalid owner public key".into()))?;
        if UserId::from_public_key(&key) != grant.owner {
            return Err(ShareGrantError::BadSignature(
                "owner public key does not match owner".into(),
            ));
        }
        let signature = MlDsaSignature::from_bytes(&self.names_signature)
            .map_err(|e| ShareGrantError::BadSignature(format!("names signature format: {e:?}")))?;
        verify_with_ml_dsa(&key, &self.names.signed_bytes(grant), &signature)
            .map_err(|e| ShareGrantError::BadSignature(format!("names signature: {e:?}")))
    }
}

/// The v2 wire envelope: the unchanged v1 grant, the names section and the
/// names signature, in this order (strict positional bincode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareGrantEnvelopeV2 {
    /// The unchanged v1 grant, with its v1 signature.
    pub grant: ShareGrant,
    /// The names section.
    pub names: GrantNames,
    /// The owner's signature over the names section.
    pub names_signature: Vec<u8>,
}

impl ShareGrantEnvelopeV2 {
    /// Assemble an envelope from a grant and its signed names.
    #[must_use]
    pub fn new(grant: &ShareGrant, signed: &SignedGrantNames) -> Self {
        Self {
            grant: grant.clone(),
            names: signed.names.clone(),
            names_signature: signed.names_signature.clone(),
        }
    }

    /// The signed names section.
    #[must_use]
    pub fn signed_names(&self) -> SignedGrantNames {
        SignedGrantNames {
            names: self.names.clone(),
            names_signature: self.names_signature.clone(),
        }
    }

    /// Typed DM payload: `SHARE_GRANT_V2_DM_PREFIX ‖ bincode(envelope)`.
    ///
    /// # Errors
    /// [`ShareGrantError::Malformed`] on encode failure.
    pub fn to_dm_payload(&self) -> Result<Vec<u8>, ShareGrantError> {
        let body = bincode::serialize(self)
            .map_err(|e| ShareGrantError::Malformed(format!("encode: {e}")))?;
        let mut out = Vec::with_capacity(SHARE_GRANT_V2_DM_PREFIX.len() + body.len());
        out.extend_from_slice(SHARE_GRANT_V2_DM_PREFIX);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Strictly decode a v2 payload: the prefix, the 48 KiB body bound, a
    /// canonical bincode body (re-encoding must reproduce it exactly), and
    /// the inner grant within v1's own bound. Verification is a separate
    /// step ([`Self::verify`]).
    ///
    /// # Errors
    /// [`ShareGrantError::Malformed`].
    pub fn from_dm_payload(payload: &[u8]) -> Result<Self, ShareGrantError> {
        let body = payload
            .strip_prefix(SHARE_GRANT_V2_DM_PREFIX)
            .ok_or_else(|| ShareGrantError::Malformed("missing v2 prefix".into()))?;
        if body.len() > MAX_SHARE_GRANT_V2_BYTES {
            return Err(ShareGrantError::Malformed("oversized".into()));
        }
        let envelope: Self = strict_decode(body, MAX_SHARE_GRANT_V2_BYTES as u64)
            .map_err(|e| ShareGrantError::Malformed(format!("decode: {e}")))?;
        let canonical = bincode::serialize(&envelope)
            .map_err(|e| ShareGrantError::Malformed(format!("re-encode: {e}")))?;
        if canonical != body {
            return Err(ShareGrantError::Malformed("non-canonical encoding".into()));
        }
        let grant_len = bincode::serialized_size(&envelope.grant)
            .map_err(|e| ShareGrantError::Malformed(format!("grant size: {e}")))?;
        if grant_len > MAX_SHARE_GRANT_BYTES as u64 {
            return Err(ShareGrantError::Malformed("inner grant oversized".into()));
        }
        Ok(envelope)
    }

    /// Verify the grant by the unchanged v1 rules, then the names signature
    /// under the grant's owner key. Any names failure refuses the whole
    /// envelope as `Malformed`.
    ///
    /// # Errors
    /// The grant's own [`ShareGrant::verify`] error, or `Malformed` for the
    /// names section.
    pub fn verify(&self) -> Result<(), ShareGrantError> {
        self.grant.verify()?;
        self.signed_names()
            .verify(&self.grant)
            .map_err(|e| ShareGrantError::Malformed(format!("names section: {e}")))
    }
}

/// Which envelope one delivery uses. Recorded in the redelivery outbox so a
/// retry resends the exact same bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantEnvelope {
    /// `x0x-sharegrant-v1\0` ‖ grant.
    #[default]
    V1,
    /// `x0x-sharegrant-v2\0` ‖ grant ‖ these signed names.
    V2(SignedGrantNames),
}

impl GrantEnvelope {
    /// `"v1"` or `"v2"` (REST view).
    #[must_use]
    pub fn version_str(&self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2(_) => "v2",
        }
    }
}

/// Decode either delivery form: a v1 grant, or a v2 envelope whose grant
/// and names both verify. Returns the grant and, for v2, its names.
///
/// # Errors
/// Any decode or verification error; the whole delivery is refused.
pub fn decode_grant_delivery(
    payload: &[u8],
) -> Result<(ShareGrant, Option<GrantNames>), ShareGrantError> {
    if payload.starts_with(SHARE_GRANT_V2_DM_PREFIX) {
        let envelope = ShareGrantEnvelopeV2::from_dm_payload(payload)?;
        envelope.verify()?;
        Ok((envelope.grant, Some(envelope.names)))
    } else {
        Ok((ShareGrant::from_dm_payload(payload)?, None))
    }
}

/// Which envelope `recipient` gets (ADR-0079 §1 "Who gets v2"): v2 only
/// when names are included, the recipient is a grantee agent, it is NOT
/// one of the shared agents (their daemons enforce the grant and always get
/// v1), and it advertises the signed `share_grant_names` extension.
#[must_use]
pub fn choose_grant_envelope(
    grant: &ShareGrant,
    recipient: &AgentId,
    is_grantee_agent: bool,
    advertises_names: bool,
    names: Option<&SignedGrantNames>,
) -> GrantEnvelope {
    match names {
        Some(signed)
            if is_grantee_agent && advertises_names && !grant.agents.contains(recipient) =>
        {
            GrantEnvelope::V2(signed.clone())
        }
        _ => GrantEnvelope::V1,
    }
}

/// One contact, as the ADR-0079 §2 contact gate sees it.
#[derive(Debug, Clone)]
pub struct ContactObservation {
    /// The contact agent.
    pub agent: AgentId,
    /// Its local trust level.
    pub trust: crate::contacts::TrustLevel,
    /// Its cached certificate, if any.
    pub certificate: Option<crate::identity::AgentCertificate>,
    /// Whether the agent is revoked.
    pub revoked: bool,
}

/// ADR-0079 §2 contact gate: a grant owner is a Known/Trusted contact when
/// at least one `Known` or `Trusted` contact agent has a valid, unexpired,
/// unrevoked certificate chaining to `owner`. A `Blocked` contact certified
/// by `owner` vetoes (fail closed). Anyone else is a stranger: their name
/// defaults are only suggestions.
#[must_use]
pub fn owner_contact_gate(owner: &UserId, contacts: &[ContactObservation], now_unix: u64) -> bool {
    use crate::contacts::TrustLevel;
    let mut vouched = false;
    for contact in contacts {
        let certified = contact.certificate.as_ref().is_some_and(|cert| {
            crate::owner_trust::certificate_chains_to_owner(
                owner,
                &contact.agent,
                cert,
                contact.revoked,
                now_unix,
            )
        });
        if !certified {
            continue;
        }
        match contact.trust {
            TrustLevel::Blocked => return false,
            TrustLevel::Known | TrustLevel::Trusted => vouched = true,
            TrustLevel::Unknown => {}
        }
    }
    vouched
}

/// Build the names section an owner install sends with `grant`
/// (ADR-0079 §1). `owner_name` is the owner's `human_name`; it is trimmed
/// and dropped when it breaks the name rules. `named_machines` are
/// `(machine, synced machine_name)` pairs; a machine is listed only when it
/// is in `enrolled` (a current ADR-0041 enrollment by this owner) and in
/// `hosting` (it hosts at least one of `grant.agents`). Names that break the
/// rules are skipped, ids are sorted and unique, and at most
/// [`MAX_GRANT_MACHINE_NAMES`] are kept. `None` when nothing remains.
#[must_use]
pub fn build_grant_names(
    owner_name: Option<&str>,
    named_machines: &[(MachineId, String)],
    enrolled: &BTreeSet<[u8; 32]>,
    hosting: &BTreeSet<[u8; 32]>,
) -> Option<GrantNames> {
    let owner_name = owner_name
        .map(str::trim)
        .filter(|name| validate_grant_name("owner_name", name).is_ok())
        .map(str::to_string);
    let mut machines: std::collections::BTreeMap<[u8; 32], String> =
        std::collections::BTreeMap::new();
    for (machine, name) in named_machines {
        let name = name.trim();
        if !enrolled.contains(&machine.0)
            || !hosting.contains(&machine.0)
            || validate_grant_name("machine_name", name).is_err()
        {
            continue;
        }
        machines
            .entry(machine.0)
            .or_insert_with(|| name.to_string());
    }
    let names = GrantNames {
        owner_name,
        machines: machines
            .into_iter()
            .take(MAX_GRANT_MACHINE_NAMES)
            .map(|(id, machine_name)| GrantMachineName {
                machine_id: MachineId(id),
                machine_name,
            })
            .collect(),
    };
    (!names.is_empty()).then_some(names)
}
