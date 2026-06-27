//! Group member roles, state, and records.

use serde::{Deserialize, Serialize};

/// Role of a member within a group.
///
/// New role assignments use the flat ADR-0016 model: `Admin` is the full
/// group authority role and `Member` is the ordinary participant role.
/// `Owner`, `Moderator`, and `Guest` remain parseable for legacy rosters but
/// are not assignable by current APIs. Privilege ordering is kept stable for
/// legacy evaluation and hashing: Owner > Admin > Moderator > Member > Guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole {
    Owner,
    Admin,
    Moderator,
    Member,
    Guest,
}

impl GroupRole {
    /// Exact ADR-0016 §3 error when a caller tries to assign legacy `owner`.
    pub const OWNER_ASSIGNMENT_ERROR: &'static str =
        "'owner' is a legacy role and cannot be assigned; valid roles: 'admin', 'member'";

    /// Numeric rank: higher means more privileged.
    fn rank(self) -> u8 {
        match self {
            Self::Owner => 4,
            Self::Admin => 3,
            Self::Moderator => 2,
            Self::Member => 1,
            Self::Guest => 0,
        }
    }

    /// Stable on-the-wire encoding of the role as a single byte.
    ///
    /// Used by canonical signing helpers (e.g. `MemberJoined` event) so the
    /// signing payload is independent of `serde` enum representation choices.
    /// Values must remain stable across releases.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Admin => 1,
            Self::Moderator => 2,
            Self::Member => 3,
            Self::Guest => 4,
        }
    }

    /// Returns true iff this role's privilege is at least `minimum`.
    #[must_use]
    pub fn at_least(self, minimum: Self) -> bool {
        self.rank() >= minimum.rank()
    }

    /// Returns true iff this role has strictly more privilege than `other`.
    #[must_use]
    pub fn outranks(self, other: Self) -> bool {
        self.rank() > other.rank()
    }

    /// Returns true iff this role has strictly less privilege than `other`.
    #[must_use]
    pub fn rank_below(self, other: Self) -> bool {
        self.rank() < other.rank()
    }

    /// Parse a role name (case-insensitive snake_case).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "moderator" => Some(Self::Moderator),
            "member" => Some(Self::Member),
            "guest" => Some(Self::Guest),
            _ => None,
        }
    }

    /// Parse a role name for **new assignments**.
    ///
    /// This deliberately accepts exactly the current ADR-0016 assignment
    /// vocabulary (`admin`, `member`) while [`Self::from_name`] continues to
    /// parse every stored legacy role name for deserialization and migration.
    pub fn assignable_from_name(name: &str) -> Result<Self, String> {
        match name {
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            "owner" => Err(Self::OWNER_ASSIGNMENT_ERROR.to_string()),
            other
                if other.eq_ignore_ascii_case("admin") || other.eq_ignore_ascii_case("member") =>
            {
                Err(format!(
                    "role names are case-sensitive; use '{}'",
                    other.to_ascii_lowercase()
                ))
            }
            other => Err(format!(
                "role '{other}' is reserved and cannot be assigned; valid roles: 'admin', 'member'"
            )),
        }
    }
}

/// Membership state for a `GroupMember` record.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupMemberState {
    #[default]
    Active,
    Pending,
    Removed,
    Banned,
}

/// A single member entry in a group roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    /// Agent ID as lowercase hex.
    pub agent_id: String,
    /// Optional linked user ID (hex).
    #[serde(default)]
    pub user_id: Option<String>,
    pub role: GroupRole,
    pub state: GroupMemberState,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Unix milliseconds when this member was first added.
    pub joined_at: u64,
    /// Unix milliseconds of the last state/role change.
    pub updated_at: u64,
    /// Agent hex that added this member (None for the initial admin seed).
    #[serde(default)]
    pub added_by: Option<String>,
    /// Agent hex that removed/banned this member.
    #[serde(default)]
    pub removed_by: Option<String>,
    /// Base64 of the member's ML-KEM-768 public key, published by them in
    /// `GET /agent` and in `JoinRequestCreated`. Required to seal
    /// `SecureShareDelivered` envelopes to this member. `None` indicates
    /// we haven't learned the key yet (e.g. a legacy v2 roster from before
    /// Phase D.2).
    #[serde(default)]
    pub kem_public_key_b64: Option<String>,
    /// Base64 TreeKEM KeyPackage used to bind this roster entry to its ratchet
    /// tree leaf. Required for verified TreeKEM removals; absent for legacy GSS
    /// members and old pre-Phase-3 rosters.
    #[serde(default)]
    pub treekem_key_package_b64: Option<String>,
}

impl GroupMember {
    /// Create the initial Admin record for a new group.
    #[must_use]
    pub fn new_admin(agent_id_hex: String, display_name: Option<String>, now_ms: u64) -> Self {
        Self {
            agent_id: agent_id_hex,
            user_id: None,
            role: GroupRole::Admin,
            state: GroupMemberState::Active,
            display_name,
            joined_at: now_ms,
            updated_at: now_ms,
            added_by: None,
            removed_by: None,
            kem_public_key_b64: None,
            treekem_key_package_b64: None,
        }
    }

    /// Create a legacy Owner record for historical fixtures and migrations
    /// that must preserve already-stored role vocabulary.
    #[must_use]
    pub fn new_owner(agent_id_hex: String, display_name: Option<String>, now_ms: u64) -> Self {
        Self {
            agent_id: agent_id_hex,
            user_id: None,
            role: GroupRole::Owner,
            state: GroupMemberState::Active,
            display_name,
            joined_at: now_ms,
            updated_at: now_ms,
            added_by: None,
            removed_by: None,
            kem_public_key_b64: None,
            treekem_key_package_b64: None,
        }
    }

    /// Create a regular Member record.
    #[must_use]
    pub fn new_member(
        agent_id_hex: String,
        display_name: Option<String>,
        added_by: Option<String>,
        now_ms: u64,
    ) -> Self {
        Self {
            agent_id: agent_id_hex,
            user_id: None,
            role: GroupRole::Member,
            state: GroupMemberState::Active,
            display_name,
            joined_at: now_ms,
            updated_at: now_ms,
            added_by,
            removed_by: None,
            kem_public_key_b64: None,
            treekem_key_package_b64: None,
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == GroupMemberState::Active
    }

    #[must_use]
    pub fn is_banned(&self) -> bool {
        self.state == GroupMemberState::Banned
    }

    #[must_use]
    pub fn is_removed(&self) -> bool {
        self.state == GroupMemberState::Removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_rank_ordering() {
        assert!(GroupRole::Owner.outranks(GroupRole::Admin));
        assert!(GroupRole::Admin.outranks(GroupRole::Moderator));
        assert!(GroupRole::Moderator.outranks(GroupRole::Member));
        assert!(GroupRole::Member.outranks(GroupRole::Guest));
    }

    #[test]
    fn role_at_least() {
        assert!(GroupRole::Owner.at_least(GroupRole::Admin));
        assert!(GroupRole::Admin.at_least(GroupRole::Admin));
        assert!(!GroupRole::Member.at_least(GroupRole::Admin));
    }

    #[test]
    fn role_from_name() {
        assert_eq!(GroupRole::from_name("admin"), Some(GroupRole::Admin));
        assert_eq!(GroupRole::from_name("OWNER"), Some(GroupRole::Owner));
        assert_eq!(
            GroupRole::from_name("moderator"),
            Some(GroupRole::Moderator)
        );
        assert_eq!(GroupRole::from_name("guest"), Some(GroupRole::Guest));
        assert_eq!(GroupRole::from_name("bogus"), None);
    }

    #[test]
    fn role_assignment_accepts_only_admin_and_member_with_exact_errors() {
        assert_eq!(
            GroupRole::assignable_from_name("admin"),
            Ok(GroupRole::Admin)
        );
        assert_eq!(
            GroupRole::assignable_from_name("member"),
            Ok(GroupRole::Member)
        );
        assert_eq!(
            GroupRole::assignable_from_name("owner").unwrap_err(),
            "'owner' is a legacy role and cannot be assigned; valid roles: 'admin', 'member'"
        );
        assert_eq!(
            GroupRole::assignable_from_name("moderator").unwrap_err(),
            "role 'moderator' is reserved and cannot be assigned; valid roles: 'admin', 'member'"
        );
        assert_eq!(
            GroupRole::assignable_from_name("guest").unwrap_err(),
            "role 'guest' is reserved and cannot be assigned; valid roles: 'admin', 'member'"
        );
    }

    #[test]
    fn role_assignment_is_exact_lowercase_vocabulary() {
        // A mis-cased *valid* role name is right-intent/wrong-casing, so it must
        // get a case-sensitivity hint rather than the generic "reserved" error
        // that genuinely-unknown roles (e.g. "moderator") receive — otherwise a
        // caller typing "ADMIN" is misdirected toward thinking admin is reserved.
        assert_eq!(
            GroupRole::assignable_from_name("ADMIN").unwrap_err(),
            "role names are case-sensitive; use 'admin'"
        );
        assert_eq!(
            GroupRole::assignable_from_name("Member").unwrap_err(),
            "role names are case-sensitive; use 'member'"
        );
    }

    #[test]
    fn new_owner_is_active_owner() {
        let m = GroupMember::new_owner("ff".repeat(32), None, 100);
        assert_eq!(m.role, GroupRole::Owner);
        assert!(m.is_active());
        assert_eq!(m.joined_at, 100);
    }

    #[test]
    fn new_admin_is_active_admin() {
        let m = GroupMember::new_admin("ff".repeat(32), None, 100);
        assert_eq!(m.role, GroupRole::Admin);
        assert!(m.is_active());
        assert_eq!(m.joined_at, 100);
    }

    #[test]
    fn new_member_is_plain_member() {
        let m = GroupMember::new_member("aa".repeat(32), Some("Alice".into()), None, 200);
        assert_eq!(m.role, GroupRole::Member);
        assert!(m.is_active());
        assert_eq!(m.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn banned_flag() {
        let mut m = GroupMember::new_member("aa".repeat(32), None, None, 0);
        m.state = GroupMemberState::Banned;
        assert!(m.is_banned());
        assert!(!m.is_active());
    }
}
