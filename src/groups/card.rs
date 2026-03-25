//! Shareable identity cards for x0x agents.
//!
//! An `AgentCard` is a portable, shareable representation of an agent's
//! identity. It can be encoded as a `x0x://agent/<base64url>` link and
//! shared via email, chat, QR code, or any out-of-band channel.
//!
//! When imported, the card adds the agent to the local contact store
//! so they can be discovered, trusted, and communicated with.

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};

/// A shareable identity card for an x0x agent.
///
/// Contains everything someone needs to find and trust you on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Human-readable display name (e.g., "David", "alice-bot").
    pub display_name: String,

    /// Agent ID (hex-encoded, 64 chars).
    pub agent_id: String,

    /// Machine ID (hex-encoded, 64 chars). The ant-quic raw public key hash.
    pub machine_id: String,

    /// User ID (hex-encoded, 64 chars). Only present if the agent has a
    /// human identity and chose to include it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Network addresses where this agent can be reached (IP:port).
    /// May be empty if the agent hasn't announced yet.
    #[serde(default)]
    pub addresses: Vec<String>,

    /// Groups this agent belongs to, with invite links.
    /// Allows one-click "add me AND join my groups".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<CardGroup>,

    /// KvStore topics this agent wants to share.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stores: Vec<CardStore>,

    /// Unix seconds when this card was generated.
    pub created_at: u64,
}

/// A group reference inside an agent card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardGroup {
    /// Group name.
    pub name: String,
    /// Invite link (`x0x://invite/...`).
    pub invite_link: String,
}

/// A store reference inside an agent card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardStore {
    /// Store name.
    pub name: String,
    /// Gossip topic for the store.
    pub topic: String,
}

impl AgentCard {
    /// Create a new agent card.
    #[must_use]
    pub fn new(display_name: String, agent_id: &AgentId, machine_id: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            display_name,
            agent_id: hex::encode(agent_id.as_bytes()),
            machine_id: machine_id.to_string(),
            user_id: None,
            addresses: Vec::new(),
            groups: Vec::new(),
            stores: Vec::new(),
            created_at: now,
        }
    }

    /// Encode this card as a shareable link.
    ///
    /// Format: `x0x://agent/<base64url(json)>`
    #[must_use]
    pub fn to_link(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
        format!("x0x://agent/{b64}")
    }

    /// Parse a card from a link string.
    ///
    /// Accepts `x0x://agent/<base64>` or raw base64.
    ///
    /// # Errors
    ///
    /// Returns an error if the link is malformed.
    pub fn from_link(link: &str) -> std::result::Result<Self, String> {
        let b64 = link.strip_prefix("x0x://agent/").unwrap_or(link).trim();

        use base64::Engine;
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("invalid base64: {e}"))?;

        let json_str = String::from_utf8(json_bytes).map_err(|e| format!("invalid UTF-8: {e}"))?;

        serde_json::from_str(&json_str).map_err(|e| format!("invalid card JSON: {e}"))
    }

    /// Get a short display string for this card.
    #[must_use]
    pub fn short_display(&self) -> String {
        let id_short = if self.agent_id.len() >= 8 {
            &self.agent_id[..8]
        } else {
            &self.agent_id
        };
        format!("{} ({}…)", self.display_name, id_short)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    #[test]
    fn test_new_card() {
        let card = AgentCard::new("David".to_string(), &agent(1), &hex::encode([2u8; 32]));
        assert_eq!(card.display_name, "David");
        assert_eq!(card.agent_id.len(), 64);
        assert_eq!(card.machine_id.len(), 64);
        assert!(card.user_id.is_none());
        assert!(card.addresses.is_empty());
        assert!(card.groups.is_empty());
        assert!(card.created_at > 0);
    }

    #[test]
    fn test_link_roundtrip() {
        let mut card = AgentCard::new("Alice".to_string(), &agent(1), &hex::encode([2u8; 32]));
        card.user_id = Some(hex::encode([3u8; 32]));
        card.addresses = vec!["1.2.3.4:5483".to_string()];
        card.groups.push(CardGroup {
            name: "Team".to_string(),
            invite_link: "x0x://invite/abc123".to_string(),
        });
        card.stores.push(CardStore {
            name: "Shared".to_string(),
            topic: "shared-kv".to_string(),
        });

        let link = card.to_link();
        assert!(link.starts_with("x0x://agent/"));

        let restored = AgentCard::from_link(&link).expect("parse");
        assert_eq!(card.display_name, restored.display_name);
        assert_eq!(card.agent_id, restored.agent_id);
        assert_eq!(card.machine_id, restored.machine_id);
        assert_eq!(card.user_id, restored.user_id);
        assert_eq!(card.addresses, restored.addresses);
        assert_eq!(card.groups.len(), 1);
        assert_eq!(card.stores.len(), 1);
    }

    #[test]
    fn test_from_link_raw_base64() {
        let card = AgentCard::new("Bob".to_string(), &agent(5), &hex::encode([6u8; 32]));
        let link = card.to_link();
        let raw = link.strip_prefix("x0x://agent/").expect("prefix");
        let restored = AgentCard::from_link(raw).expect("parse raw");
        assert_eq!(card.agent_id, restored.agent_id);
    }

    #[test]
    fn test_from_link_invalid() {
        assert!(AgentCard::from_link("garbage!!!").is_err());
    }

    #[test]
    fn test_short_display() {
        let card = AgentCard::new("David".to_string(), &agent(1), &hex::encode([2u8; 32]));
        let display = card.short_display();
        assert!(display.starts_with("David ("));
        assert!(display.contains('…'));
    }

    #[test]
    fn test_minimal_card_no_optional_fields() {
        let card = AgentCard::new("Minimal".to_string(), &agent(1), &hex::encode([2u8; 32]));
        let json = serde_json::to_string(&card).expect("serialize");
        // user_id, groups, stores should NOT appear in JSON when empty
        assert!(!json.contains("user_id"));
        assert!(!json.contains("groups"));
        assert!(!json.contains("stores"));
    }
}
