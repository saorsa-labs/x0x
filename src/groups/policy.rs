//! Group policy axes and presets.
//!
//! Every named group has a `GroupPolicy` composed of independent axes:
//! discoverability, admission, confidentiality, read access, write access.
//! Presets (`private_secure`, `public_request_secure`, `public_open`,
//! `public_announce`) bundle these axes into well-known configurations.

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

    #[test]
    fn summary_from_policy() {
        let p = GroupPolicyPreset::PublicRequestSecure.to_policy();
        let s: GroupPolicySummary = (&p).into();
        assert_eq!(s.admission, GroupAdmission::RequestAccess);
    }
}
