#![allow(missing_docs)]

use crate::contacts::TrustLevel;
use crate::identity::AgentId;
use crate::mls::{MlsGroup, MlsWelcome};
use crate::types::GroupId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A pending invite received from another agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvite {
    /// The Welcome message to accept/reject.
    pub welcome: MlsWelcome,
    /// Authenticated sender AgentId (from V2 signed gossip message).
    pub sender: AgentId,
    /// Whether the gossip V2 signature was verified.
    pub verified: bool,
    /// Trust level of sender from local contact store.
    pub trust_level: Option<TrustLevel>,
    /// Unix timestamp when the invite was received.
    pub received_at: u64,
}

/// Summary of a group (returned from create/accept/list operations).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSummary {
    /// The hashed GroupId for API/indexing use.
    pub group_id: GroupId,
    /// Human-readable group name.
    pub name: String,
    /// Number of known members in this group.
    pub known_members: usize,
    /// The known member AgentIds.
    pub member_ids: Vec<AgentId>,
}

/// Summary of a pending invite (returned from list_pending_invites).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInviteSummary {
    /// The group this invite is for.
    pub group_id: GroupId,
    /// Who sent the invite (authenticated via V2 signing).
    pub sender: AgentId,
    /// Whether the V2 signature was verified.
    pub verified: bool,
    /// Trust level of the sender.
    pub trust_level: Option<TrustLevel>,
    /// When the invite was received.
    pub received_at: u64,
}

/// Shared group state for the Agent.
///
/// This is wrapped in `Arc<RwLock<>>` for concurrent access from the
/// background invite listener and API handlers.
#[derive(Debug, Default)]
pub struct GroupState {
    /// Active groups the agent is a member of.
    pub groups: HashMap<GroupId, MlsGroup>,
    /// Group names (separate from MlsGroup since MlsGroup doesn't have a name field).
    pub group_names: HashMap<GroupId, String>,
    /// Pending invites keyed by (GroupId, sender AgentId).
    pub pending_invites: HashMap<(GroupId, AgentId), PendingInvite>,
}
