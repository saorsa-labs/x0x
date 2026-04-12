//! Join request records for groups with `admission == RequestAccess`.

use crate::groups::member::GroupRole;
use serde::{Deserialize, Serialize};

/// Current state of a join request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinRequestStatus {
    Pending,
    Approved,
    Rejected,
    Cancelled,
}

/// A single join request submitted by an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    /// UUID v4 hex.
    pub request_id: String,
    /// Group this request targets (mls_group_id hex).
    pub group_id: String,
    /// Requester agent ID as hex.
    pub requester_agent_id: String,
    /// Optional linked user ID (hex).
    #[serde(default)]
    pub requester_user_id: Option<String>,
    /// Role the requester is asking for (usually `Member`).
    pub requested_role: GroupRole,
    /// Optional free-text justification.
    #[serde(default)]
    pub message: Option<String>,
    /// Unix milliseconds when the request was submitted.
    pub created_at: u64,
    /// Unix milliseconds when an admin reviewed (approved/rejected) the request.
    #[serde(default)]
    pub reviewed_at: Option<u64>,
    /// Hex agent ID of the reviewing admin.
    #[serde(default)]
    pub reviewed_by: Option<String>,
    pub status: JoinRequestStatus,
}

impl JoinRequest {
    /// Create a new pending request.
    #[must_use]
    pub fn new(
        group_id: String,
        requester_agent_id: String,
        message: Option<String>,
        now_ms: u64,
    ) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().simple().to_string(),
            group_id,
            requester_agent_id,
            requester_user_id: None,
            requested_role: GroupRole::Member,
            message,
            created_at: now_ms,
            reviewed_at: None,
            reviewed_by: None,
            status: JoinRequestStatus::Pending,
        }
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status == JoinRequestStatus::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_request_is_pending() {
        let r = JoinRequest::new("g1".into(), "a1".into(), Some("hi".into()), 100);
        assert!(r.is_pending());
        assert_eq!(r.created_at, 100);
        assert_eq!(r.requested_role, GroupRole::Member);
        assert_eq!(r.request_id.len(), 32); // simple UUID = 32 hex chars
    }

    #[test]
    fn roundtrip_serialization() {
        let r = JoinRequest::new("g1".into(), "a1".into(), None, 42);
        let s = serde_json::to_string(&r).unwrap();
        let r2: JoinRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(r, r2);
    }
}
