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
}
