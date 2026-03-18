#![allow(missing_docs)]
//! Shared types for x0x.
//!
//! This module provides common types that span multiple subsystems.
//! Identity-specific types (MachineId, AgentId, UserId) live in
//! [`crate::identity`]; this module holds types that don't belong
//! to a single layer.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Group identifier derived from SHA-256 hash of MLS group_id bytes.
///
/// MLS group IDs are variable-length `Vec<u8>`. GroupId normalizes this to a
/// fixed 32-byte SHA-256 hash for use as HashMap keys, API identifiers, and
/// stable comparison. This is consistent with how AgentId and MachineId work
/// (both are SHA-256 hashes of public keys).
///
/// **Important:** Raw MLS `group_id` bytes must be used in cryptographic contexts
/// (MlsGroupContext, EncryptedTaskListDelta envelopes, AAD). GroupId is only for
/// app-facing indexing, API identity, and HashMap keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId([u8; 32]);

impl GroupId {
    /// Create a GroupId by SHA-256 hashing the raw MLS group_id bytes.
    ///
    /// MLS group IDs are variable-length; this normalizes them to a fixed
    /// 32-byte identifier suitable for indexing and display.
    #[inline]
    pub fn from_mls_group_id(bytes: &[u8]) -> Self {
        let hash = Sha256::digest(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        Self(out)
    }

    /// Get the raw 32-byte representation.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to `Vec<u8>`.
    #[inline]
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Full hex encoding of all 32 bytes (for REST route parameters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from a hex string (for REST route parameter deserialization).
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is not exactly 64 characters or
    /// contains invalid hex digits.
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex_str)?;
        let mut out = [0u8; 32];
        if bytes.len() != 32 {
            // hex::decode succeeded but wrong length — use InvalidStringLength
            return Err(hex::FromHexError::InvalidStringLength);
        }
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupId(0x{})", hex::encode(&self.0[..8]))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_group_id_from_mls_group_id() {
        let input = b"some-mls-group-id-bytes";
        let id1 = GroupId::from_mls_group_id(input);
        let id2 = GroupId::from_mls_group_id(input);
        assert_eq!(id1, id2, "same input must produce the same GroupId");
    }

    #[test]
    fn test_group_id_different_inputs() {
        let id1 = GroupId::from_mls_group_id(b"group-alpha");
        let id2 = GroupId::from_mls_group_id(b"group-beta");
        assert_ne!(id1, id2, "different inputs must produce different GroupIds");
    }

    #[test]
    fn test_group_id_display() {
        let id = GroupId::from_mls_group_id(b"display-test");
        let display = format!("{}", id);
        assert!(
            display.starts_with("GroupId(0x"),
            "display should start with GroupId(0x, got: {}",
            display
        );
        // "GroupId(0x" = 10 chars, 8 bytes = 16 hex chars, ")" = 1 char → 27 total
        assert_eq!(
            display.len(),
            "GroupId(0x)".len() + 16,
            "display length mismatch: {}",
            display
        );
    }

    #[test]
    fn test_group_id_hex_roundtrip() {
        let id = GroupId::from_mls_group_id(b"hex-roundtrip-test");
        let hex_str = id.to_hex();
        let restored = GroupId::from_hex(&hex_str).unwrap();
        assert_eq!(id, restored, "hex roundtrip must preserve GroupId");
    }

    #[test]
    fn test_group_id_serde_roundtrip() {
        let id = GroupId::from_mls_group_id(b"serde-roundtrip-test");
        let encoded = bincode::serialize(&id).unwrap();
        let decoded: GroupId = bincode::deserialize(&encoded).unwrap();
        assert_eq!(id, decoded, "serde roundtrip must preserve GroupId");
    }
}
