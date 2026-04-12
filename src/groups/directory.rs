//! Discoverable group cards.

use crate::groups::policy::GroupPolicySummary;
use serde::{Deserialize, Serialize};

/// Public-facing card for a discoverable group.
///
/// Contains the information a non-member needs to decide whether to request
/// access. Does NOT include private content, roster, or encrypted data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupCard {
    pub group_id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub banner_url: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub policy_summary: GroupPolicySummary,
    pub owner_agent_id: String,
    pub admin_count: u32,
    pub member_count: u32,
    pub created_at: u64,
    pub updated_at: u64,
    pub request_access_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::policy::{
        GroupAdmission, GroupConfidentiality, GroupDiscoverability, GroupReadAccess,
        GroupWriteAccess,
    };

    #[test]
    fn card_roundtrip() {
        let summary = GroupPolicySummary {
            discoverability: GroupDiscoverability::PublicDirectory,
            admission: GroupAdmission::RequestAccess,
            confidentiality: GroupConfidentiality::MlsEncrypted,
            read_access: GroupReadAccess::MembersOnly,
            write_access: GroupWriteAccess::MembersOnly,
        };
        let c = GroupCard {
            group_id: "abcd".into(),
            name: "Test".into(),
            description: "desc".into(),
            avatar_url: None,
            banner_url: None,
            tags: vec!["rust".into()],
            policy_summary: summary,
            owner_agent_id: "ff".repeat(32),
            admin_count: 1,
            member_count: 5,
            created_at: 0,
            updated_at: 0,
            request_access_enabled: true,
        };
        let json = serde_json::to_string(&c).unwrap();
        let c2: GroupCard = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }
}
