//! Group policy axes and presets.
//!
//! Every named group has a `GroupPolicy` composed of independent axes:
//! discoverability, admission, confidentiality, read access, write access.
//! Presets (`private_secure`, `public_request_secure`, `public_open`,
//! `public_announce`) bundle these axes into well-known configurations.

use crate::identity::UserId;
use serde::{Deserialize, Serialize};

/// Controls whether a group is visible to non-members.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupDiscoverability {
    /// Not listed anywhere; only members know the group exists.
    #[default]
    Hidden,
    /// Visible to contacts only (not broadcast publicly).
    ListedToContacts,
    /// Published to the public directory / gossip index.
    PublicDirectory,
}

/// Controls how new members are admitted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupAdmission {
    /// Admin must issue an invite link.
    #[default]
    InviteOnly,
    /// Anyone discovering the group may submit a join request.
    RequestAccess,
    /// Anyone may join without approval.
    OpenJoin,
    /// ADR-0038: only agents presenting a valid, unexpired
    /// `AgentCertificate` chaining to `owner` may be admitted. Verified at
    /// invite-accept and re-verified at every state-commit seal; admin role
    /// is inert for admission here (an admin invite cannot admit an
    /// uncertified agent).
    ///
    /// Serde compatibility: this variant is APPENDED, so the bincode variant
    /// indices of `invite_only`/`request_access`/`open_join` (0/1/2) are
    /// unchanged and every stored legacy policy decodes byte-identically.
    /// Nodes running pre-ADR-0038 code fail to decode the unknown variant
    /// and reject the policy (fail-closed: an old node drops the card or
    /// invite carrying it rather than silently downgrading the group to a
    /// weaker admission axis).
    OwnerCertified(
        /// Owner whose user key must have signed the joiner's certificate.
        #[serde(with = "crate::identity::user_id_hex")]
        UserId,
    ),
}

impl GroupAdmission {
    /// The owner whose `AgentCertificate` chain certifies admission when
    /// this axis is [`GroupAdmission::OwnerCertified`] (ADR-0038).
    #[must_use]
    pub fn owner_certified_user_id(&self) -> Option<&UserId> {
        match self {
            Self::OwnerCertified(owner) => Some(owner),
            _ => None,
        }
    }
}

/// Controls how group content is cryptographically protected.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupConfidentiality {
    /// MLS end-to-end encryption; only members decrypt.
    #[default]
    MlsEncrypted,
    /// Signed but readable plaintext; anyone can read.
    SignedPublic,
}

/// Controls who can read group content.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupReadAccess {
    /// Only active members can read.
    #[default]
    MembersOnly,
    /// Anyone can read.
    Public,
}

/// Controls who can write content to the group.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupWriteAccess {
    /// Only active members can write.
    #[default]
    MembersOnly,
    /// Anyone can write, subject to moderation.
    ModeratedPublic,
    /// Only admins/owner can write (announcement channel).
    AdminOnly,
}

/// Complete policy for a named group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPolicy {
    pub discoverability: GroupDiscoverability,
    pub admission: GroupAdmission,
    pub confidentiality: GroupConfidentiality,
    pub read_access: GroupReadAccess,
    pub write_access: GroupWriteAccess,
}

impl Default for GroupPolicy {
    fn default() -> Self {
        GroupPolicyPreset::PrivateSecure.to_policy()
    }
}

/// Named preset bundle for common policy shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPolicyPreset {
    /// Hidden, invite-only, MLS-encrypted, members-only read/write. Default.
    PrivateSecure,
    /// Public directory listing + request access + MLS-encrypted content.
    PublicRequestSecure,
    /// Public directory, open join, signed-public, members-only write.
    PublicOpen,
    /// Public directory, open join, signed-public, admin-only write (announce channel).
    PublicAnnounce,
}

impl GroupPolicyPreset {
    /// Convert a preset into a concrete policy.
    #[must_use]
    pub fn to_policy(self) -> GroupPolicy {
        match self {
            Self::PrivateSecure => GroupPolicy {
                discoverability: GroupDiscoverability::Hidden,
                admission: GroupAdmission::InviteOnly,
                confidentiality: GroupConfidentiality::MlsEncrypted,
                read_access: GroupReadAccess::MembersOnly,
                write_access: GroupWriteAccess::MembersOnly,
            },
            Self::PublicRequestSecure => GroupPolicy {
                discoverability: GroupDiscoverability::PublicDirectory,
                admission: GroupAdmission::RequestAccess,
                confidentiality: GroupConfidentiality::MlsEncrypted,
                read_access: GroupReadAccess::MembersOnly,
                write_access: GroupWriteAccess::MembersOnly,
            },
            Self::PublicOpen => GroupPolicy {
                discoverability: GroupDiscoverability::PublicDirectory,
                admission: GroupAdmission::OpenJoin,
                confidentiality: GroupConfidentiality::SignedPublic,
                read_access: GroupReadAccess::Public,
                write_access: GroupWriteAccess::MembersOnly,
            },
            Self::PublicAnnounce => GroupPolicy {
                discoverability: GroupDiscoverability::PublicDirectory,
                admission: GroupAdmission::OpenJoin,
                confidentiality: GroupConfidentiality::SignedPublic,
                read_access: GroupReadAccess::Public,
                write_access: GroupWriteAccess::AdminOnly,
            },
        }
    }

    /// Parse a preset name (case-insensitive, snake_case or kebab-case).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().replace('-', "_").as_str() {
            "private_secure" => Some(Self::PrivateSecure),
            "public_request_secure" => Some(Self::PublicRequestSecure),
            "public_open" => Some(Self::PublicOpen),
            "public_announce" => Some(Self::PublicAnnounce),
            _ => None,
        }
    }
}

/// Full policy summary published in discoverable group cards.
///
/// Carries all five policy axes so a non-member importing the card can
/// reconstruct exact behaviour without silently defaulting to private-like
/// semantics. This is the minimum a joiner/importer needs to honour the
/// group's stated read/write rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPolicySummary {
    pub discoverability: GroupDiscoverability,
    pub admission: GroupAdmission,
    pub confidentiality: GroupConfidentiality,
    #[serde(default)]
    pub read_access: GroupReadAccess,
    #[serde(default)]
    pub write_access: GroupWriteAccess,
}

impl From<&GroupPolicy> for GroupPolicySummary {
    fn from(p: &GroupPolicy) -> Self {
        Self {
            discoverability: p.discoverability,
            admission: p.admission,
            confidentiality: p.confidentiality,
            read_access: p.read_access,
            write_access: p.write_access,
        }
    }
}

impl From<&GroupPolicySummary> for GroupPolicy {
    fn from(s: &GroupPolicySummary) -> Self {
        Self {
            discoverability: s.discoverability,
            admission: s.admission,
            confidentiality: s.confidentiality,
            read_access: s.read_access,
            write_access: s.write_access,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_secure_defaults() {
        let p = GroupPolicyPreset::PrivateSecure.to_policy();
        assert_eq!(p.discoverability, GroupDiscoverability::Hidden);
        assert_eq!(p.admission, GroupAdmission::InviteOnly);
        assert_eq!(p.confidentiality, GroupConfidentiality::MlsEncrypted);
        assert_eq!(p.read_access, GroupReadAccess::MembersOnly);
        assert_eq!(p.write_access, GroupWriteAccess::MembersOnly);
    }

    #[test]
    fn public_request_secure_preset() {
        let p = GroupPolicyPreset::PublicRequestSecure.to_policy();
        assert_eq!(p.discoverability, GroupDiscoverability::PublicDirectory);
        assert_eq!(p.admission, GroupAdmission::RequestAccess);
        assert_eq!(p.confidentiality, GroupConfidentiality::MlsEncrypted);
    }

    #[test]
    fn public_announce_preset() {
        let p = GroupPolicyPreset::PublicAnnounce.to_policy();
        assert_eq!(p.discoverability, GroupDiscoverability::PublicDirectory);
        assert_eq!(p.write_access, GroupWriteAccess::AdminOnly);
    }

    #[test]
    fn default_policy_is_private_secure() {
        let default = GroupPolicy::default();
        let preset = GroupPolicyPreset::PrivateSecure.to_policy();
        assert_eq!(default, preset);
    }

    #[test]
    fn preset_name_parsing() {
        assert_eq!(
            GroupPolicyPreset::from_name("private_secure"),
            Some(GroupPolicyPreset::PrivateSecure)
        );
        assert_eq!(
            GroupPolicyPreset::from_name("PRIVATE-SECURE"),
            Some(GroupPolicyPreset::PrivateSecure)
        );
        assert_eq!(
            GroupPolicyPreset::from_name("public_request_secure"),
            Some(GroupPolicyPreset::PublicRequestSecure)
        );
        assert_eq!(GroupPolicyPreset::from_name("nonsense"), None);
    }

    /// The pre-ADR-0038 admission axis, replicated exactly as an old node
    /// knows it. Used to prove the forward-compat failure mode: an old node
    /// receiving an `owner_certified` policy must ERROR (fail closed), not
    /// silently fall back to a weaker axis.
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum LegacyAdmission {
        InviteOnly,
        RequestAccess,
        OpenJoin,
    }

    #[test]
    fn legacy_admission_json_bytes_decode_unchanged() {
        // WHY ADR-0038 compat: stored policies are JSON; every legacy value
        // must round-trip byte-identically so an upgraded daemon reopening
        // an old store observes exactly the policy it saved.
        for (json, expected) in [
            ("\"invite_only\"", GroupAdmission::InviteOnly),
            ("\"request_access\"", GroupAdmission::RequestAccess),
            ("\"open_join\"", GroupAdmission::OpenJoin),
        ] {
            let decoded: GroupAdmission =
                serde_json::from_str(json).unwrap_or_else(|e| panic!("{json} must decode: {e}"));
            assert_eq!(decoded, expected);
            assert_eq!(
                serde_json::to_string(&decoded).expect("re-encode"),
                json,
                "legacy variant must re-encode to identical bytes"
            );
        }
    }

    #[test]
    fn legacy_admission_bincode_variant_indices_unchanged() {
        // WHY ADR-0038 compat: positional formats (bincode) encode variants
        // by declaration index. `OwnerCertified` is APPENDED, so the legacy
        // indices 0/1/2 — and therefore every legacy bincode payload — must
        // be exactly what they were before the new variant existed. New
        // bytes for old variants would partition the fleet.
        assert_eq!(
            bincode::serialize(&GroupAdmission::InviteOnly).expect("bincode invite_only"),
            vec![0, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&GroupAdmission::RequestAccess).expect("bincode request_access"),
            vec![1, 0, 0, 0]
        );
        assert_eq!(
            bincode::serialize(&GroupAdmission::OpenJoin).expect("bincode open_join"),
            vec![2, 0, 0, 0]
        );
    }

    #[test]
    fn owner_certified_json_is_hex_and_round_trips() {
        // WHY: the owner UserId rides in persisted policy JSON and the CLI;
        // hex (not a 32-number array) keeps it readable and copy-pasteable,
        // and the round-trip must preserve the exact bytes of the id.
        let owner = UserId([0xAB; 32]);
        let admission = GroupAdmission::OwnerCertified(owner);
        let json = serde_json::to_string(&admission).expect("serialize");
        assert_eq!(
            json,
            format!("{{\"owner_certified\":\"{}\"}}", "ab".repeat(32))
        );
        let decoded: GroupAdmission = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, admission);
        assert_eq!(admission.owner_certified_user_id(), Some(&owner));

        // Full policy round-trip (the actual stored shape).
        let policy = GroupPolicy {
            admission,
            ..GroupPolicy::default()
        };
        let value = serde_json::to_value(&policy).expect("policy to value");
        assert_eq!(
            value["admission"]["owner_certified"],
            serde_json::json!("ab".repeat(32))
        );
        let back: GroupPolicy = serde_json::from_value(value).expect("policy from value");
        assert_eq!(back, policy);
        // Summary (cards) carries the same axis losslessly.
        let summary = crate::groups::GroupPolicySummary::from(&policy);
        let restored: GroupPolicy = crate::groups::GroupPolicy::from(&summary);
        assert_eq!(restored.admission, admission);
    }

    #[test]
    fn legacy_admission_rejects_unknown_owner_certified_variant() {
        // WHY (documented old-node behavior): a pre-ADR-0038 node that
        // receives a card/invite carrying `owner_certified` fails to decode
        // the admission axis and drops the object — fail-closed. This test
        // pins that the failure is a decode ERROR naming the unknown
        // variant, never a silent downgrade to invite-only/open-join.
        let json = serde_json::to_string(&GroupAdmission::OwnerCertified(UserId([1; 32])))
            .expect("serialize");
        let err = serde_json::from_str::<LegacyAdmission>(&json)
            .expect_err("old decoder must reject owner_certified");
        assert!(
            err.to_string().contains("owner_certified"),
            "error must name the unknown variant: {err}"
        );
    }

    #[test]
    fn other_admission_axes_have_no_owner() {
        // WHY: `owner_certified_user_id()` gates every enforcement site;
        // a legacy axis returning Some() would wrongly drag cert checks
        // into non-OwnerCertified groups (or worse, skip them).
        assert_eq!(GroupAdmission::InviteOnly.owner_certified_user_id(), None);
        assert_eq!(
            GroupAdmission::RequestAccess.owner_certified_user_id(),
            None
        );
        assert_eq!(GroupAdmission::OpenJoin.owner_certified_user_id(), None);
    }

    #[test]
    fn summary_from_policy() {
        let p = GroupPolicyPreset::PublicRequestSecure.to_policy();
        let s: GroupPolicySummary = (&p).into();
        assert_eq!(s.admission, GroupAdmission::RequestAccess);
    }
}
