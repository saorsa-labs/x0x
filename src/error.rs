//! Error types for x0x identity operations.
//!
//! All identity operations use a Result type based on the [`crate::error::IdentityError`] enum,
//! providing comprehensive error handling without panics or unwraps in production code.

use thiserror::Error;

/// Comprehensive error type for all x0x identity operations.
///
/// This enum covers all possible failure modes in identity management:
/// - Cryptographic key generation failures
/// - Invalid key material
/// - PeerId verification mismatches
/// - Persistent storage I/O errors
/// - Serialization/deserialization failures
///
/// # Examples
///
/// ```ignore
/// use x0x::error::{IdentityError, Result};
///
/// fn example() -> Result<()> {
///     // Operations return Result<T>
///     Err(IdentityError::KeyGeneration("RNG failed".to_string()))
/// }
/// ```
#[derive(Error, Debug)]
pub enum IdentityError {
    /// Key generation failed (e.g., RNG failure, hardware error).
    #[error("failed to generate keypair: {0}")]
    KeyGeneration(String),

    /// Public key validation failed.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Secret key validation failed.
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// PeerId verification failed - public key doesn't match the stored PeerId.
    /// This indicates a key substitution attack or corruption.
    #[error("PeerId verification failed")]
    PeerIdMismatch,

    /// Persistent storage I/O error.
    /// Wraps std::io::Error for file operations on keypairs.
    #[error("key storage error: {0}")]
    Storage(#[from] std::io::Error),

    /// Serialization or deserialization of keypairs failed.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Standard Result type for x0x identity operations.
///
/// All async and sync identity functions return `Result<T>` which is an alias for
/// `std::result::Result<T, IdentityError>`.
///
/// # Examples
///
/// ```ignore
/// use x0x::identity::MachineKeypair;
/// use x0x::error::Result;
///
/// fn create_identity() -> Result<MachineKeypair> {
///     MachineKeypair::generate()
/// }
/// ```
pub type Result<T> = std::result::Result<T, IdentityError>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_key_generation_error_display() {
        let err = IdentityError::KeyGeneration("RNG failed".to_string());
        assert_eq!(err.to_string(), "failed to generate keypair: RNG failed");
    }

    #[test]
    fn test_invalid_public_key_error_display() {
        let err = IdentityError::InvalidPublicKey("size mismatch".to_string());
        assert_eq!(err.to_string(), "invalid public key: size mismatch");
    }

    #[test]
    fn test_invalid_secret_key_error_display() {
        let err = IdentityError::InvalidSecretKey("corrupted".to_string());
        assert_eq!(err.to_string(), "invalid secret key: corrupted");
    }

    #[test]
    fn test_peer_id_mismatch_error_display() {
        let err = IdentityError::PeerIdMismatch;
        assert_eq!(err.to_string(), "PeerId verification failed");
    }

    #[test]
    fn test_serialization_error_display() {
        let err = IdentityError::Serialization("invalid bincode".to_string());
        assert_eq!(err.to_string(), "serialization error: invalid bincode");
    }

    #[test]
    fn test_result_type_ok() {
        let result: Result<i32> = Ok(42);
        match result {
            Ok(val) => assert_eq!(val, 42),
            Err(_) => panic!("expected Ok variant"),
        }
    }

    #[test]
    fn test_result_type_err() {
        let result: Result<i32> = Err(IdentityError::KeyGeneration("test".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let id_err: IdentityError = io_err.into();
        assert!(matches!(id_err, IdentityError::Storage(_)));
    }

    #[test]
    fn test_error_debug() {
        let err = IdentityError::KeyGeneration("test failure".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("KeyGeneration"));
    }
}
