//! High-level group management for x0x.
//!
//! A Group ties together:
//! - An MLS group (encryption, membership)
//! - A KvStore (group metadata, display names, settings)
//! - Gossip topics (chat rooms, notifications)
//! - CRDT task lists (kanban boards)
//!
//! Groups are the primary collaboration primitive for agents and humans.

pub mod card;
pub mod invite;

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata for a group, stored in the group's KvStore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Human-readable group name.
    pub name: String,
    /// Optional description.
    pub description: String,
    /// The agent that created this group.
    pub creator: AgentId,
    /// Unix milliseconds when the group was created.
    pub created_at: u64,
    /// MLS group ID (hex-encoded).
    pub mls_group_id: String,
    /// KvStore topic for group metadata.
    pub metadata_topic: String,
    /// Gossip topic prefix for chat rooms (e.g., `group/{id}/chat/`).
    pub chat_topic_prefix: String,
    /// Display names for members (agent_id_hex -> display name).
    pub display_names: HashMap<String, String>,
}

impl GroupInfo {
    /// Create a new `GroupInfo`.
    #[must_use]
    pub fn new(name: String, description: String, creator: AgentId, mls_group_id: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let metadata_topic = format!("x0x.group.{}.meta", &mls_group_id[..16]);
        let chat_topic_prefix = format!("x0x.group.{}.chat", &mls_group_id[..16]);

        Self {
            name,
            description,
            creator,
            created_at: now,
            mls_group_id,
            metadata_topic,
            chat_topic_prefix,
            display_names: HashMap::new(),
        }
    }

    /// Set a display name for a member.
    pub fn set_display_name(&mut self, agent_id_hex: String, name: String) {
        self.display_names.insert(agent_id_hex, name);
    }

    /// Get a member's display name, falling back to truncated agent ID.
    #[must_use]
    pub fn display_name(&self, agent_id_hex: &str) -> String {
        self.display_names
            .get(agent_id_hex)
            .cloned()
            .unwrap_or_else(|| {
                if agent_id_hex.len() >= 8 {
                    format!("{}…", &agent_id_hex[..8])
                } else {
                    agent_id_hex.to_string()
                }
            })
    }

    /// Get the default chat topic for the group ("general" room).
    #[must_use]
    pub fn general_chat_topic(&self) -> String {
        format!("{}/general", self.chat_topic_prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    #[test]
    fn test_group_info_new() {
        let info = GroupInfo::new(
            "Test Group".to_string(),
            "A test".to_string(),
            agent(1),
            "aabb".repeat(8),
        );
        assert_eq!(info.name, "Test Group");
        assert!(info.created_at > 0);
        assert!(info.metadata_topic.starts_with("x0x.group."));
        assert!(info.chat_topic_prefix.starts_with("x0x.group."));
    }

    #[test]
    fn test_display_name() {
        let mut info = GroupInfo::new(
            "Test".to_string(),
            String::new(),
            agent(1),
            "aabb".repeat(8),
        );

        let agent_hex = hex::encode([1u8; 32]);

        // Before setting — falls back to truncated ID
        let name = info.display_name(&agent_hex);
        assert!(name.ends_with('…'));
        assert_eq!(name.chars().count(), 9); // 8 chars + ellipsis (char count, not byte count)

        // After setting
        info.set_display_name(agent_hex.clone(), "Alice".to_string());
        assert_eq!(info.display_name(&agent_hex), "Alice");
    }

    #[test]
    fn test_general_chat_topic() {
        let info = GroupInfo::new(
            "Test".to_string(),
            String::new(),
            agent(1),
            "aabb".repeat(8),
        );
        assert!(info.general_chat_topic().ends_with("/general"));
    }

    #[test]
    fn test_serialization() {
        let info = GroupInfo::new(
            "Test".to_string(),
            "desc".to_string(),
            agent(1),
            "aabb".repeat(8),
        );
        let json = serde_json::to_string(&info).expect("serialize");
        let restored: GroupInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(info.name, restored.name);
        assert_eq!(info.mls_group_id, restored.mls_group_id);
    }
}
