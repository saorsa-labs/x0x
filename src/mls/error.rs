//! MLS error types for group encryption operations.

use thiserror::Error;

/// Errors that can occur during MLS operations.
#[derive(Debug, Error)]
pub enum MlsError {
    /// Group with the specified ID was not found.
    #[error("group not found: {0}")]
    GroupNotFound(String),

    /// The specified member is not in the group.
    #[error("member not in group: {0}")]
    MemberNotInGroup(String),

    /// Invalid key material provided.
    #[error("invalid key material")]
    InvalidKeyMaterial,

    /// Epoch mismatch between current and received.
    #[error("epoch mismatch: current {current}, received {received}")]
    EpochMismatch {
        /// Current epoch number.
        current: u64,
        /// Received epoch number.
        received: u64,
    },

    /// Encryption operation failed.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// Decryption operation failed.
    #[error("decryption error: {0}")]
    DecryptionError(String),

    /// General MLS operation failed.
    #[error("MLS operation failed: {0}")]
    MlsOperation(String),
}

/// Type alias for Results using MlsError.
pub type Result<T> = std::result::Result<T, MlsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_not_found_display() {
        let err = MlsError::GroupNotFound("test-group".to_string());
        assert_eq!(err.to_string(), "group not found: test-group");
    }

    #[test]
    fn test_member_not_in_group_display() {
        let err = MlsError::MemberNotInGroup("agent-123".to_string());
        assert_eq!(err.to_string(), "member not in group: agent-123");
    }

    #[test]
    fn test_invalid_key_material_display() {
        let err = MlsError::InvalidKeyMaterial;
        assert_eq!(err.to_string(), "invalid key material");
    }

    #[test]
    fn test_epoch_mismatch_display() {
        let err = MlsError::EpochMismatch {
            current: 5,
            received: 3,
        };
        assert_eq!(err.to_string(), "epoch mismatch: current 5, received 3");
    }

    #[test]
    fn test_encryption_error_display() {
        let err = MlsError::EncryptionError("cipher init failed".to_string());
        assert_eq!(err.to_string(), "encryption error: cipher init failed");
    }

    #[test]
    fn test_decryption_error_display() {
        let err = MlsError::DecryptionError("authentication failed".to_string());
        assert_eq!(err.to_string(), "decryption error: authentication failed");
    }

    #[test]
    fn test_mls_operation_display() {
        let err = MlsError::MlsOperation("commit validation failed".to_string());
        assert_eq!(
            err.to_string(),
            "MLS operation failed: commit validation failed"
        );
    }

    #[test]
    fn test_result_type_alias() {
        let success: Result<i32> = Ok(42);
        assert!(success.is_ok());

        let failure: Result<i32> = Err(MlsError::InvalidKeyMaterial);
        assert!(failure.is_err());
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MlsError>();
    }
}
