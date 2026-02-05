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

/// Network-specific error types.
///
/// This enum covers all possible failure modes in network operations:
/// - Node creation and configuration failures
/// - Connection establishment and lifecycle management
/// - Peer discovery and cache operations
/// - NAT traversal and address discovery
/// - Stream multiplexing and data transfer
/// - Security and validation failures
/// - Resource exhaustion and limits
///
/// # Examples
///
/// ```ignore
/// use x0x::error::{NetworkError, NetworkResult};
///
/// async fn connect_to_network() -> NetworkResult<()> {
///     Err(NetworkError::ConnectionTimeout {
///         peer_id: [0u8; 32],
///         timeout: std::time::Duration::from_secs(30),
///     })
/// }
/// ```
#[derive(Error, Debug)]
pub enum NetworkError {
    /// Network node creation failed.
    #[error("failed to create network node: {0}")]
    NodeCreation(String),

    /// Connection to a peer failed with specific reason.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection attempt timed out.
    #[error("connection timeout to peer {peer_id:?} after {timeout:?}")]
    ConnectionTimeout {
        /// The peer ID we were trying to connect to.
        peer_id: [u8; 32],
        /// How long we waited before giving up.
        timeout: std::time::Duration,
    },

    /// Already connected to this peer.
    #[error("already connected to peer {0:?}")]
    AlreadyConnected([u8; 32]),

    /// Not connected to this peer.
    #[error("not connected to peer {0:?}")]
    NotConnected([u8; 32]),

    /// Connection was closed.
    #[error("connection closed to peer {0:?}")]
    ConnectionClosed([u8; 32]),

    /// Connection was reset by peer.
    #[error("connection reset by peer {0:?}")]
    ConnectionReset([u8; 32]),

    /// Peer not found in cache or network.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Peer cache I/O error.
    #[error("cache error: {0}")]
    CacheError(String),

    /// NAT traversal operation failed.
    #[error("NAT traversal failed: {0}")]
    NatTraversalFailed(String),

    /// Address discovery operation failed.
    #[error("address discovery failed: {0}")]
    AddressDiscoveryFailed(String),

    /// Stream operation failed.
    #[error("stream error: {0}")]
    StreamError(String),

    /// Event broadcasting failed.
    #[error("event broadcast error: {0}")]
    BroadcastError(String),

    /// Authentication failed for a peer.
    #[error("authentication failed for peer {peer_id:?}: {reason}")]
    AuthenticationFailed {
        /// The peer ID that failed authentication.
        peer_id: [u8; 32],
        /// Why authentication failed.
        reason: String,
    },

    /// Protocol violation detected.
    #[error("protocol violation from peer {peer_id:?}: {violation}")]
    ProtocolViolation {
        /// The peer that violated the protocol.
        peer_id: [u8; 32],
        /// What was violated.
        violation: String,
    },

    /// Invalid peer ID format.
    #[error("invalid peer ID: {0}")]
    InvalidPeerId(String),

    /// Maximum connections reached.
    #[error("maximum connections reached: {current} >= {limit}")]
    MaxConnectionsReached {
        /// Current number of connections.
        current: u32,
        /// Configured maximum.
        limit: u32,
    },

    /// Message too large.
    #[error("message too large: {size} bytes exceeds limit of {limit}")]
    MessageTooLarge {
        /// Actual message size.
        size: usize,
        /// Maximum allowed size.
        limit: usize,
    },

    /// Channel closed unexpectedly.
    #[error("channel closed: {0}")]
    ChannelClosed(String),

    /// Invalid bootstrap node address.
    #[error("invalid bootstrap node address: {0}")]
    InvalidBootstrapNode(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Node error from underlying ant-quic.
    #[error("node error: {0}")]
    NodeError(String),

    /// Connection error from underlying ant-quic.
    #[error("connection error: {0}")]
    ConnectionError(String),
}

/// Standard Result type for x0x network operations.
///
/// All async and sync network functions return `NetworkResult<T>` which is an alias for
/// `std::result::Result<T, NetworkError>`.
///
/// # Examples
///
/// ```ignore
/// use x0x::error::NetworkResult;
/// use x0x::network::NetworkNode;
///
/// async fn create_node() -> NetworkResult<NetworkNode> {
///     NetworkNode::new(config).await
/// }
/// ```
pub type NetworkResult<T> = std::result::Result<T, NetworkError>;

#[cfg(test)]
mod network_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_node_creation_error_display() {
        let err = NetworkError::NodeCreation("binding failed".to_string());
        assert_eq!(
            err.to_string(),
            "failed to create network node: binding failed"
        );
    }

    #[test]
    fn test_connection_failed_error_display() {
        let err = NetworkError::ConnectionFailed("timeout".to_string());
        assert_eq!(err.to_string(), "connection failed: timeout");
    }

    #[test]
    fn test_connection_timeout_error_display() {
        let err = NetworkError::ConnectionTimeout {
            peer_id: [1u8; 32],
            timeout: Duration::from_secs(30),
        };
        assert!(err.to_string().contains("connection timeout"));
        assert!(err.to_string().contains("30s"));
    }

    #[test]
    fn test_already_connected_error_display() {
        let err = NetworkError::AlreadyConnected([2u8; 32]);
        assert!(err.to_string().contains("already connected"));
    }

    #[test]
    fn test_not_connected_error_display() {
        let err = NetworkError::NotConnected([3u8; 32]);
        assert!(err.to_string().contains("not connected"));
    }

    #[test]
    fn test_connection_closed_error_display() {
        let err = NetworkError::ConnectionClosed([4u8; 32]);
        assert!(err.to_string().contains("connection closed"));
    }

    #[test]
    fn test_connection_reset_error_display() {
        let err = NetworkError::ConnectionReset([5u8; 32]);
        assert!(err.to_string().contains("connection reset"));
    }

    #[test]
    fn test_peer_not_found_error_display() {
        let err = NetworkError::PeerNotFound("unknown peer".to_string());
        assert_eq!(err.to_string(), "peer not found: unknown peer");
    }

    #[test]
    fn test_cache_error_display() {
        let err = NetworkError::CacheError("serialization failed".to_string());
        assert_eq!(err.to_string(), "cache error: serialization failed");
    }

    #[test]
    fn test_nat_traversal_failed_error_display() {
        let err = NetworkError::NatTraversalFailed("hole punching failed".to_string());
        assert_eq!(
            err.to_string(),
            "NAT traversal failed: hole punching failed"
        );
    }

    #[test]
    fn test_address_discovery_failed_error_display() {
        let err = NetworkError::AddressDiscoveryFailed("no interfaces found".to_string());
        assert_eq!(
            err.to_string(),
            "address discovery failed: no interfaces found"
        );
    }

    #[test]
    fn test_stream_error_display() {
        let err = NetworkError::StreamError("stream closed".to_string());
        assert_eq!(err.to_string(), "stream error: stream closed");
    }

    #[test]
    fn test_broadcast_error_display() {
        let err = NetworkError::BroadcastError("receiver dropped".to_string());
        assert_eq!(err.to_string(), "event broadcast error: receiver dropped");
    }

    #[test]
    fn test_authentication_failed_error_display() {
        let err = NetworkError::AuthenticationFailed {
            peer_id: [6u8; 32],
            reason: "invalid signature".to_string(),
        };
        assert!(err.to_string().contains("authentication failed"));
        assert!(err.to_string().contains("invalid signature"));
    }

    #[test]
    fn test_protocol_violation_error_display() {
        let err = NetworkError::ProtocolViolation {
            peer_id: [7u8; 32],
            violation: "invalid message format".to_string(),
        };
        assert!(err.to_string().contains("protocol violation"));
        assert!(err.to_string().contains("invalid message format"));
    }

    #[test]
    fn test_invalid_peer_id_error_display() {
        let err = NetworkError::InvalidPeerId("wrong length".to_string());
        assert_eq!(err.to_string(), "invalid peer ID: wrong length");
    }

    #[test]
    fn test_max_connections_reached_error_display() {
        let err = NetworkError::MaxConnectionsReached {
            current: 100,
            limit: 100,
        };
        assert!(err.to_string().contains("maximum connections reached"));
        assert!(err.to_string().contains("100"));
    }

    #[test]
    fn test_message_too_large_error_display() {
        let err = NetworkError::MessageTooLarge {
            size: 1024 * 1024,
            limit: 1024,
        };
        assert!(err.to_string().contains("message too large"));
        assert!(err.to_string().contains("1048576"));
        assert!(err.to_string().contains("1024"));
    }

    #[test]
    fn test_channel_closed_error_display() {
        let err = NetworkError::ChannelClosed("sender dropped".to_string());
        assert_eq!(err.to_string(), "channel closed: sender dropped");
    }

    #[test]
    fn test_network_result_type_ok() {
        let result: NetworkResult<i32> = Ok(42);
        match result {
            Ok(val) => assert_eq!(val, 42),
            Err(_) => panic!("expected Ok variant"),
        }
    }

    #[test]
    fn test_network_result_type_err() {
        let result: NetworkResult<i32> = Err(NetworkError::NodeCreation("test".to_string()));
        assert!(result.is_err());
    }
}
