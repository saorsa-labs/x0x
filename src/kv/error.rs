//! Error types for KvStore operations.

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
