//! Signed invite tokens for group membership.
//!
//! Invite tokens are one-time links that allow one agent to join a group.
//! Today admission is authenticated by the invite secret + join handshake;
//! the inviter records the secret locally, enforces expiry/role caps, consumes
//! it on first successful use, then publishes an authority-signed membership
//! commit. The `signature` field is retained as future-facing/vestigial
//! metadata and is not currently enforced on the wire.

use crate::groups::policy::GroupPolicy;
use crate::identity::AgentId;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default invite expiry: 7 days in seconds.
pub const DEFAULT_EXPIRY_SECS: u64 = 7 * 24 * 60 * 60;

/// A signed invite token for joining a group.
///
/// Tokens are serialized to base64url for sharing via email, chat, QR codes, etc.
/// Each token is accepted at most once by the inviter that minted it.
/// The format is: `x0x://invite/<base64url(json(SignedInvite))>`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInvite {
    /// MLS group ID (hex-encoded).
    pub group_id: String,
    /// Stable D.3 group_id, if known.
    #[serde(default)]
    pub stable_group_id: Option<String>,
    /// Authority-created timestamp for the group.
    #[serde(default)]
    pub group_created_at: Option<u64>,
    /// Human-readable group name.
    pub group_name: String,
    /// Human-readable group description.
    #[serde(default)]
    pub group_description: Option<String>,
    /// Full policy snapshot used to seed the joiner's local GroupInfo.
    #[serde(default)]
    pub policy: Option<GroupPolicy>,
    /// Authority genesis nonce so invite-joined peers reconstruct the same
    /// `GroupGenesis` payload, not just the same stable group id.
    #[serde(default)]
    pub genesis_creation_nonce: Option<String>,
    /// Agent ID of the inviter (hex-encoded).
    pub inviter: String,
    /// One-time invite secret (32 bytes, hex-encoded).
    /// Used to authenticate the join handshake and consumed by the inviter
    /// when it publishes the authoritative membership commit.
    pub invite_secret: String,
    /// Unix seconds when this invite was created.
    pub created_at: u64,
    /// Unix seconds when this invite expires (0 = never).
    pub expires_at: u64,
    /// Optional future-facing ML-DSA-65 signature over the invite fields
    /// (hex-encoded). Currently not validated by the join flow.
    pub signature: String,
}

impl SignedInvite {
    /// Create a new invite (without signature — call `sign()` separately).
    ///
    /// # Arguments
    ///
    /// * `group_id` - MLS group ID (hex).
    /// * `group_name` - Human-readable group name.
    /// * `inviter` - Inviter's agent ID.
    /// * `expiry_secs` - Seconds until expiry (0 = never).
    #[must_use]
    pub fn new(group_id: String, group_name: String, inviter: &AgentId, expiry_secs: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate random invite secret
        let mut secret_bytes = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut secret_bytes);

        let expires_at = if expiry_secs > 0 {
            now + expiry_secs
        } else {
            0
        };

        Self {
            group_id,
            stable_group_id: None,
            group_created_at: None,
            group_name,
            group_description: None,
            policy: None,
            genesis_creation_nonce: None,
            inviter: hex::encode(inviter.as_bytes()),
            invite_secret: hex::encode(secret_bytes),
            created_at: now,
            expires_at,
            signature: String::new(),
        }
    }

    /// Get the canonical bytes that would be signed if invite signatures are
    /// enforced in the future.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"x0x.invite.v2|");
        data.extend_from_slice(self.group_id.as_bytes());
        data.extend_from_slice(self.stable_group_id.as_deref().unwrap_or("").as_bytes());
        data.extend_from_slice(&self.group_created_at.unwrap_or_default().to_le_bytes());
        data.extend_from_slice(self.group_name.as_bytes());
        data.extend_from_slice(self.group_description.as_deref().unwrap_or("").as_bytes());
        let policy_json = serde_json::to_vec(&self.policy).unwrap_or_default();
        data.extend_from_slice(&policy_json);
        data.extend_from_slice(
            self.genesis_creation_nonce
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        data.extend_from_slice(self.inviter.as_bytes());
        data.extend_from_slice(self.invite_secret.as_bytes());
        data.extend_from_slice(&self.created_at.to_le_bytes());
        data.extend_from_slice(&self.expires_at.to_le_bytes());
        data
    }

    /// Check if this invite has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false; // Never expires
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// Check if the signature field is populated.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }

    /// Encode this invite as a shareable link.
    ///
    /// Format: `x0x://invite/<base64url(json)>`
    #[must_use]
    pub fn to_link(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
        format!("x0x://invite/{b64}")
    }

    /// Parse an invite from a link string.
    ///
    /// Accepts both `x0x://invite/<base64>` and raw `<base64>` formats.
    ///
    /// # Errors
    ///
    /// Returns an error if the link is malformed or the invite can't be deserialized.
    pub fn from_link(link: &str) -> std::result::Result<Self, String> {
        let b64 = link.strip_prefix("x0x://invite/").unwrap_or(link).trim();

        use base64::Engine;
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| format!("invalid base64: {e}"))?;

        let json_str = String::from_utf8(json_bytes).map_err(|e| format!("invalid UTF-8: {e}"))?;

        serde_json::from_str(&json_str).map_err(|e| format!("invalid invite JSON: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    #[test]
    fn test_create_invite() {
        let invite = SignedInvite::new(
            "aabb".repeat(8),
            "Test Group".to_string(),
            &agent(1),
            DEFAULT_EXPIRY_SECS,
        );

        assert_eq!(invite.group_name, "Test Group");
        assert!(!invite.invite_secret.is_empty());
        assert_eq!(invite.invite_secret.len(), 64); // 32 bytes hex
        assert!(invite.created_at > 0);
        assert!(invite.expires_at > invite.created_at);
        assert!(!invite.is_expired());
        assert!(!invite.is_signed());
    }

    #[test]
    fn test_invite_no_expiry() {
        let invite = SignedInvite::new("aabb".repeat(8), "Forever Group".to_string(), &agent(1), 0);
        assert_eq!(invite.expires_at, 0);
        assert!(!invite.is_expired());
    }

    #[test]
    fn test_invite_expired() {
        let mut invite = SignedInvite::new("aabb".repeat(8), "Old Group".to_string(), &agent(1), 1);
        // Force expiry in the past
        invite.expires_at = 1000;
        assert!(invite.is_expired());
    }

    #[test]
    fn test_signable_bytes_deterministic() {
        let mut invite1 = SignedInvite::new("aabb".repeat(8), "Test".to_string(), &agent(1), 3600);
        let mut invite2 = invite1.clone();

        // Same fields → same signable bytes
        invite1.invite_secret = "aa".repeat(32);
        invite2.invite_secret = "aa".repeat(32);
        invite1.created_at = 1000;
        invite2.created_at = 1000;
        invite1.expires_at = 2000;
        invite2.expires_at = 2000;

        assert_eq!(invite1.signable_bytes(), invite2.signable_bytes());
    }

    #[test]
    fn test_link_roundtrip() {
        let invite = SignedInvite::new(
            "aabb".repeat(8),
            "Test Group".to_string(),
            &agent(1),
            DEFAULT_EXPIRY_SECS,
        );

        let link = invite.to_link();
        assert!(link.starts_with("x0x://invite/"));

        let restored = SignedInvite::from_link(&link).expect("parse link");
        assert_eq!(invite.group_id, restored.group_id);
        assert_eq!(invite.group_name, restored.group_name);
        assert_eq!(invite.inviter, restored.inviter);
        assert_eq!(invite.invite_secret, restored.invite_secret);
    }

    #[test]
    fn test_from_link_raw_base64() {
        let invite = SignedInvite::new("aabb".repeat(8), "Test".to_string(), &agent(1), 0);

        let link = invite.to_link();
        // Strip the prefix — should still parse
        let raw = link.strip_prefix("x0x://invite/").expect("prefix");
        let restored = SignedInvite::from_link(raw).expect("parse raw");
        assert_eq!(invite.group_id, restored.group_id);
    }

    #[test]
    fn test_from_link_invalid() {
        let result = SignedInvite::from_link("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_json_serialization() {
        let invite = SignedInvite::new("aabb".repeat(8), "Test".to_string(), &agent(1), 3600);
        let json = serde_json::to_string(&invite).expect("serialize");
        let restored: SignedInvite = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(invite.group_id, restored.group_id);
    }

    #[test]
    fn test_optional_metadata_roundtrip() {
        let mut invite = SignedInvite::new("aabb".repeat(8), "Test".to_string(), &agent(1), 3600);
        invite.stable_group_id = Some("bb".repeat(32));
        invite.group_created_at = Some(1_234_567);
        invite.group_description = Some("desc".to_string());
        invite.policy = Some(GroupPolicy::default());
        invite.genesis_creation_nonce = Some("cc".repeat(32));

        let json = serde_json::to_string(&invite).expect("serialize metadata invite");
        let restored: SignedInvite =
            serde_json::from_str(&json).expect("deserialize metadata invite");
        assert_eq!(invite.stable_group_id, restored.stable_group_id);
        assert_eq!(invite.group_created_at, restored.group_created_at);
        assert_eq!(invite.group_description, restored.group_description);
        assert_eq!(invite.policy, restored.policy);
        assert_eq!(
            invite.genesis_creation_nonce,
            restored.genesis_creation_nonce
        );
    }
}
