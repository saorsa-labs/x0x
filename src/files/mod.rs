//! File transfer protocol for agent-to-agent file sharing.
//!
//! Transfers use direct messaging (QUIC streams) with chunked transfer
//! and SHA-256 integrity verification. Only accepted from trusted contacts
//! by default.

use serde::{Deserialize, Serialize};

/// Default chunk size: 32 KiB raw.
///
/// Sized to fit every chunk inside a single DM envelope. Each chunk's
/// wire form is base64(payload) + JSON wrapper (`transfer_id` +
/// `chunk_index` + `sha256` + a few fields) — 32768 bytes base64-encodes
/// to ~43 691 bytes which, with the JSON wrapper and DM overhead, still
/// fits under `crate::dm::MAX_PAYLOAD_BYTES` (49 152). Using 64 KiB
/// previously caused `envelope construction failed: payload exceeds
/// MAX_PAYLOAD_BYTES (87481 > 49152)` and aborted every file transfer
/// on chunk 0 — see proofs/full-20260421-193705/ for the regression.
pub const DEFAULT_CHUNK_SIZE: usize = 32768;

/// Maximum file transfer size: 1 GB.
pub const MAX_TRANSFER_SIZE: u64 = 1_073_741_824;

/// A file transfer offer sent to initiate transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOffer {
    /// Unique transfer ID.
    pub transfer_id: String,
    /// Original filename.
    pub filename: String,
    /// File size in bytes.
    pub size: u64,
    /// SHA-256 hash of the complete file.
    pub sha256: String,
    /// Chunk size in bytes.
    pub chunk_size: usize,
    /// Total number of chunks.
    pub total_chunks: u64,
}

/// A single file chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    /// Transfer ID this chunk belongs to.
    pub transfer_id: String,
    /// Chunk sequence number (0-indexed).
    pub sequence: u64,
    /// Base64-encoded chunk data.
    pub data: String,
}

/// Completion message sent after all chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileComplete {
    /// Transfer ID.
    pub transfer_id: String,
    /// SHA-256 hash (for verification).
    pub sha256: String,
}

/// Transfer direction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferDirection {
    /// Sending a file.
    Sending,
    /// Receiving a file.
    Receiving,
}

/// Transfer status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferStatus {
    /// Offer sent/received, waiting for acceptance.
    Pending,
    /// Transfer in progress.
    InProgress,
    /// Transfer complete and verified.
    Complete,
    /// Transfer failed.
    Failed,
    /// Transfer rejected by receiver.
    Rejected,
}

/// Tracks state of a file transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferState {
    /// Unique transfer ID.
    pub transfer_id: String,
    /// Direction (sending or receiving).
    pub direction: TransferDirection,
    /// Remote agent ID.
    pub remote_agent_id: String,
    /// Filename.
    pub filename: String,
    /// Total size in bytes.
    pub total_size: u64,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Current status.
    pub status: TransferStatus,
    /// SHA-256 hash of the file.
    pub sha256: String,
    /// Error message if failed.
    pub error: Option<String>,
    /// Timestamp when transfer started (unix seconds).
    pub started_at: u64,
    /// Timestamp when transfer started (unix milliseconds).
    #[serde(default)]
    pub started_at_unix_ms: u64,
    /// Timestamp when transfer reached a terminal state (unix milliseconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at_unix_ms: Option<u64>,
    /// Local file path (sender side only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    /// Output path for received file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
    /// Chunk size used for this transfer.
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,
    /// Total number of chunks.
    #[serde(default)]
    pub total_chunks: u64,
}

/// Default chunk size for serde deserialization.
fn default_chunk_size() -> usize {
    DEFAULT_CHUNK_SIZE
}

/// File transfer message types (sent over direct messaging).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FileMessage {
    /// Offer to send a file.
    #[serde(rename = "file-offer")]
    Offer(FileOffer),
    /// A chunk of file data.
    #[serde(rename = "file-chunk")]
    Chunk(FileChunk),
    /// Transfer complete.
    #[serde(rename = "file-complete")]
    Complete(FileComplete),
    /// Accept a transfer offer.
    #[serde(rename = "file-accept")]
    Accept {
        /// Transfer ID to accept.
        transfer_id: String,
    },
    /// Reject a transfer offer.
    #[serde(rename = "file-reject")]
    Reject {
        /// Transfer ID to reject.
        transfer_id: String,
        /// Reason for rejection.
        reason: String,
    },
    /// Acknowledge that a chunk was received and persisted to disk.
    ///
    /// Sent by the receiver after each successful chunk write. The sender
    /// waits for this before sending the next chunk, which throttles the
    /// sender to the receiver's actual disk + decode rate and prevents a
    /// `subscribe_direct` subscriber queue from filling and being dropped.
    #[serde(rename = "file-chunk-ack")]
    ChunkAck {
        /// Transfer ID this ack belongs to.
        transfer_id: String,
        /// Highest contiguous chunk sequence number successfully persisted.
        sequence: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn default_chunk_size_value() {
        assert_eq!(default_chunk_size(), DEFAULT_CHUNK_SIZE);
        assert_eq!(DEFAULT_CHUNK_SIZE, 32768);
    }

    #[test]
    fn max_transfer_size_value() {
        assert_eq!(MAX_TRANSFER_SIZE, 1_073_741_824);
    }

    #[test]
    fn file_offer_roundtrip() {
        let offer = FileOffer {
            transfer_id: "transfer-123".to_string(),
            filename: "test.txt".to_string(),
            size: 1024,
            sha256: "abc123".to_string(),
            chunk_size: 32768,
            total_chunks: 1,
        };
        let json = serde_json::to_string(&offer).unwrap();
        let decoded: FileOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.transfer_id, "transfer-123");
        assert_eq!(decoded.filename, "test.txt");
        assert_eq!(decoded.size, 1024);
    }

    #[test]
    fn file_chunk_roundtrip() {
        let chunk = FileChunk {
            transfer_id: "transfer-123".to_string(),
            sequence: 0,
            data: base64::engine::general_purpose::STANDARD.encode(b"hello world"),
        };
        let json = serde_json::to_string(&chunk).unwrap();
        let decoded: FileChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.transfer_id, "transfer-123");
        assert_eq!(decoded.sequence, 0);
    }

    #[test]
    fn file_complete_roundtrip() {
        let complete = FileComplete {
            transfer_id: "transfer-123".to_string(),
            sha256: "abc123".to_string(),
        };
        let json = serde_json::to_string(&complete).unwrap();
        let decoded: FileComplete = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.transfer_id, "transfer-123");
    }

    #[test]
    fn transfer_direction_display() {
        assert_eq!(TransferDirection::Sending as u8, 0);
        assert_eq!(TransferDirection::Receiving as u8, 1);
    }

    #[test]
    fn transfer_status_variants() {
        assert_eq!(TransferStatus::Pending as u8, 0);
        assert_eq!(TransferStatus::InProgress as u8, 1);
        assert_eq!(TransferStatus::Complete as u8, 2);
        assert_eq!(TransferStatus::Failed as u8, 3);
        assert_eq!(TransferStatus::Rejected as u8, 4);
    }

    #[test]
    fn transfer_state_roundtrip() {
        let state = TransferState {
            transfer_id: "transfer-123".to_string(),
            direction: TransferDirection::Sending,
            remote_agent_id: "agent-456".to_string(),
            filename: "test.txt".to_string(),
            total_size: 1024,
            bytes_transferred: 512,
            status: TransferStatus::InProgress,
            sha256: "abc123".to_string(),
            error: None,
            started_at: 1000,
            started_at_unix_ms: 1_000_000,
            completed_at_unix_ms: None,
            source_path: Some("/tmp/test.txt".to_string()),
            output_path: None,
            chunk_size: 32768,
            total_chunks: 1,
        };
        let json = serde_json::to_string(&state).unwrap();
        let decoded: TransferState = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.transfer_id, "transfer-123");
        assert_eq!(decoded.direction, TransferDirection::Sending);
        assert_eq!(decoded.status, TransferStatus::InProgress);
        assert_eq!(decoded.chunk_size, 32768);
    }

    #[test]
    fn file_message_offer_roundtrip() {
        let offer = FileOffer {
            transfer_id: "t1".to_string(),
            filename: "f.txt".to_string(),
            size: 100,
            sha256: "hash".to_string(),
            chunk_size: 32768,
            total_chunks: 1,
        };
        let msg = FileMessage::Offer(offer);
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: FileMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, FileMessage::Offer(_)));
    }

    #[test]
    fn file_message_accept_roundtrip() {
        let msg = FileMessage::Accept {
            transfer_id: "t1".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: FileMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, FileMessage::Accept { .. }));
    }

    #[test]
    fn file_message_reject_roundtrip() {
        let msg = FileMessage::Reject {
            transfer_id: "t1".to_string(),
            reason: "too big".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: FileMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, FileMessage::Reject { .. }));
    }

    #[test]
    fn file_message_chunk_ack_roundtrip() {
        let msg = FileMessage::ChunkAck {
            transfer_id: "t1".to_string(),
            sequence: 5,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: FileMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, FileMessage::ChunkAck { .. }));
    }
}
