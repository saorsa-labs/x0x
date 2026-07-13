//! Error types for KvStore operations.

use crate::identity::AgentId;

/// Result type for KvStore operations.
pub type Result<T> = std::result::Result<T, KvError>;

/// Errors that can occur during KvStore operations.
#[derive(Debug, thiserror::Error)]
pub enum KvError {
    /// Key not found in the store.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Value exceeds the maximum inline size.
    #[error("value too large: {size} bytes exceeds maximum {max} bytes")]
    ValueTooLarge {
        /// The actual size.
        size: usize,
        /// The maximum allowed size.
        max: usize,
    },

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    /// CRDT merge operation failed.
    #[error("merge error: {0}")]
    Merge(String),

    /// Gossip layer error.
    #[error("gossip error: {0}")]
    Gossip(String),

    /// I/O error during persistence.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Store IDs do not match during merge.
    #[error("store ID mismatch: cannot merge stores with different IDs")]
    StoreIdMismatch,

    /// Unauthorized write attempt.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// The store has no anchored owner.
    ///
    /// Ownership is established ONLY at construction from trusted out-of-band
    /// input (the creator, or an explicit `expected_owner` at join). A replica
    /// that joined without an anchor has no owner and is permanently read-only
    /// by design — the protocol never derives ownership from an untrusted
    /// network announce, so there is no silent path from `None` to `Some`.
    /// Policy-restricted writes (and the local-write counterpart) fail closed.
    #[error("store owner unknown: no anchored owner — store is read-only; supply expected_owner at join")]
    OwnerUnknown,

    /// The established owner disagrees with a received ownership announcement.
    ///
    /// Ownership is immutable once anchored. An announce whose claimed owner
    /// differs from the anchored owner is a conflict (possible takeover
    /// attempt or genuine misconfiguration): it is rejected, the anchored
    /// owner is unchanged, and the conflict is surfaced for auditability.
    #[error("ownership conflict: anchored owner {anchored} != announced owner {claimed}")]
    OwnershipConflict {
        /// The anchored (construction-time) owner.
        anchored: AgentId,
        /// The conflicting owner claimed by the announce.
        claimed: AgentId,
    },

    /// An ownership announcement is not a valid basis for establishing or
    /// refreshing ownership.
    ///
    /// Covers: a sender that does not match the claimed owner (third-party
    /// assignment), an attempt to establish ownership on a store that has none
    /// (first-self-capture guard — ownership is construction-only), and a
    /// stale/replayed policy refresh. The store state is unchanged.
    #[error("invalid ownership token: {0}")]
    OwnerTokenInvalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_key_not_found() {
        let error = KvError::KeyNotFound("mykey".to_string());
        assert!(format!("{error}").contains("key not found"));
        assert!(format!("{error}").contains("mykey"));
    }

    #[test]
    fn test_error_display_value_too_large() {
        let error = KvError::ValueTooLarge {
            size: 100_000,
            max: 65_536,
        };
        let display = format!("{error}");
        assert!(display.contains("100000"));
        assert!(display.contains("65536"));
    }

    #[test]
    fn test_error_display_merge() {
        let error = KvError::Merge("conflict".to_string());
        assert!(format!("{error}").contains("merge error"));
    }

    #[test]
    fn test_error_display_gossip() {
        let error = KvError::Gossip("timeout".to_string());
        assert!(format!("{error}").contains("gossip error"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let kv_err: KvError = io_err.into();
        assert!(format!("{kv_err}").contains("I/O error"));
    }
}
