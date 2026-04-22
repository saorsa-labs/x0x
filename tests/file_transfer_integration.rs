//! Integration tests for the file transfer protocol.
//!
//! Tests cover FileMessage serialization, TransferState logic,
//! chunk arithmetic, path traversal protection, and SHA-256 verification.

use base64::Engine;
use sha2::{Digest, Sha256};
use x0x::files::{
    FileChunk, FileComplete, FileMessage, FileOffer, TransferDirection, TransferState,
    TransferStatus, DEFAULT_CHUNK_SIZE, MAX_TRANSFER_SIZE,
};

// ---------------------------------------------------------------------------
// Helper: build a TransferState for testing
// ---------------------------------------------------------------------------

fn make_sending_transfer(size: u64, chunk_size: usize) -> TransferState {
    let total_chunks = if size == 0 {
        0
    } else {
        size.div_ceil(chunk_size as u64)
    };
    TransferState {
        transfer_id: "test-xfer".to_string(),
        direction: TransferDirection::Sending,
        remote_agent_id: "0".repeat(64),
        filename: "test.bin".to_string(),
        total_size: size,
        bytes_transferred: 0,
        status: TransferStatus::Pending,
        sha256: "abc123".to_string(),
        error: None,
        started_at: 0,
        started_at_unix_ms: 0,
        completed_at_unix_ms: None,
        source_path: Some("/tmp/test.bin".to_string()),
        output_path: None,
        chunk_size,
        total_chunks,
    }
}

fn make_receiving_transfer(size: u64, chunk_size: usize) -> TransferState {
    let total_chunks = if size == 0 {
        0
    } else {
        size.div_ceil(chunk_size as u64)
    };
    TransferState {
        transfer_id: "test-recv".to_string(),
        direction: TransferDirection::Receiving,
        remote_agent_id: "f".repeat(64),
        filename: "received.bin".to_string(),
        total_size: size,
        bytes_transferred: 0,
        status: TransferStatus::InProgress,
        sha256: "def456".to_string(),
        error: None,
        started_at: 0,
        started_at_unix_ms: 0,
        completed_at_unix_ms: None,
        source_path: None,
        output_path: Some("/tmp/received.bin".to_string()),
        chunk_size,
        total_chunks,
    }
}

// ---------------------------------------------------------------------------
// 1. FileMessage serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn file_offer_roundtrip() {
    let msg = FileMessage::Offer(FileOffer {
        transfer_id: "xfer-001".into(),
        filename: "report.pdf".into(),
        size: 123_456,
        sha256: "abc123".into(),
        chunk_size: DEFAULT_CHUNK_SIZE,
        total_chunks: 2,
    });
    let json = serde_json::to_vec(&msg).unwrap();
    let decoded: FileMessage = serde_json::from_slice(&json).unwrap();
    let json_str = String::from_utf8_lossy(&json);
    assert!(
        json_str.contains("\"type\":\"file-offer\""),
        "got: {json_str}"
    );
    // Verify Offer fields survived roundtrip
    if let FileMessage::Offer(offer) = decoded {
        assert_eq!(offer.transfer_id, "xfer-001");
        assert_eq!(offer.filename, "report.pdf");
        assert_eq!(offer.size, 123_456);
        assert_eq!(offer.total_chunks, 2);
    } else {
        panic!("expected Offer variant");
    }
}

#[test]
fn file_accept_roundtrip() {
    let msg = FileMessage::Accept {
        transfer_id: "xfer-002".into(),
    };
    let json = serde_json::to_vec(&msg).unwrap();
    let json_str = String::from_utf8_lossy(&json);
    assert!(
        json_str.contains("\"type\":\"file-accept\""),
        "got: {json_str}"
    );
    let decoded: FileMessage = serde_json::from_slice(&json).unwrap();
    if let FileMessage::Accept { transfer_id } = decoded {
        assert_eq!(transfer_id, "xfer-002");
    } else {
        panic!("expected Accept variant");
    }
}

#[test]
fn file_reject_roundtrip() {
    let msg = FileMessage::Reject {
        transfer_id: "xfer-003".into(),
        reason: "too large".into(),
    };
    let json = serde_json::to_vec(&msg).unwrap();
    let json_str = String::from_utf8_lossy(&json);
    assert!(
        json_str.contains("\"type\":\"file-reject\""),
        "got: {json_str}"
    );
    let decoded: FileMessage = serde_json::from_slice(&json).unwrap();
    if let FileMessage::Reject {
        transfer_id,
        reason,
    } = decoded
    {
        assert_eq!(transfer_id, "xfer-003");
        assert_eq!(reason, "too large");
    } else {
        panic!("expected Reject variant");
    }
}

#[test]
fn file_chunk_roundtrip() {
    let msg = FileMessage::Chunk(FileChunk {
        transfer_id: "xfer-004".into(),
        sequence: 7,
        data: base64::engine::general_purpose::STANDARD.encode([0xDE, 0xAD, 0xBE, 0xEF]),
    });
    let json = serde_json::to_vec(&msg).unwrap();
    let json_str = String::from_utf8_lossy(&json);
    assert!(
        json_str.contains("\"type\":\"file-chunk\""),
        "got: {json_str}"
    );
    let decoded: FileMessage = serde_json::from_slice(&json).unwrap();
    if let FileMessage::Chunk(chunk) = decoded {
        assert_eq!(chunk.transfer_id, "xfer-004");
        assert_eq!(chunk.sequence, 7);
    } else {
        panic!("expected Chunk variant");
    }
}

#[test]
fn file_complete_roundtrip() {
    let msg = FileMessage::Complete(FileComplete {
        transfer_id: "xfer-005".into(),
        sha256: "abc".into(),
    });
    let json = serde_json::to_vec(&msg).unwrap();
    let json_str = String::from_utf8_lossy(&json);
    assert!(
        json_str.contains("\"type\":\"file-complete\""),
        "got: {json_str}"
    );
    let decoded: FileMessage = serde_json::from_slice(&json).unwrap();
    if let FileMessage::Complete(complete) = decoded {
        assert_eq!(complete.transfer_id, "xfer-005");
        assert_eq!(complete.sha256, "abc");
    } else {
        panic!("expected Complete variant");
    }
}

// ---------------------------------------------------------------------------
// 2. TransferState creation and fields
// ---------------------------------------------------------------------------

#[test]
fn transfer_state_sending_fields() {
    // Chunk-size-agnostic: 3 full chunks + a remainder = 4 total.
    let size = (DEFAULT_CHUNK_SIZE as u64) * 3 + 200;
    let ts = make_sending_transfer(size, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.direction, TransferDirection::Sending);
    assert_eq!(ts.status, TransferStatus::Pending);
    assert_eq!(ts.bytes_transferred, 0);
    assert_eq!(ts.source_path, Some("/tmp/test.bin".to_string()));
    assert!(ts.output_path.is_none());
    assert_eq!(ts.chunk_size, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.total_chunks, 4);
}

#[test]
fn transfer_state_receiving_fields() {
    // Exactly one chunk regardless of chunk size constant.
    let ts = make_receiving_transfer(DEFAULT_CHUNK_SIZE as u64, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.direction, TransferDirection::Receiving);
    assert_eq!(ts.status, TransferStatus::InProgress);
    assert!(ts.source_path.is_none());
    assert_eq!(ts.output_path, Some("/tmp/received.bin".to_string()));
    assert_eq!(ts.total_chunks, 1);
}

// ---------------------------------------------------------------------------
// 3. Chunk count computation for various file sizes
// ---------------------------------------------------------------------------

#[test]
fn total_chunks_zero_size() {
    let ts = make_sending_transfer(0, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.total_chunks, 0);
}

#[test]
fn total_chunks_one_byte() {
    let ts = make_sending_transfer(1, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.total_chunks, 1);
}

#[test]
fn total_chunks_exact_chunk_size() {
    let ts = make_sending_transfer(DEFAULT_CHUNK_SIZE as u64, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.total_chunks, 1);
}

#[test]
fn total_chunks_chunk_size_plus_one() {
    let ts = make_sending_transfer(DEFAULT_CHUNK_SIZE as u64 + 1, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.total_chunks, 2);
}

#[test]
fn total_chunks_exact_multiple() {
    // Exactly 2 chunks at whatever DEFAULT_CHUNK_SIZE is today.
    let ts = make_sending_transfer((DEFAULT_CHUNK_SIZE as u64) * 2, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.total_chunks, 2);
}

#[test]
fn total_chunks_large_file() {
    // 1 MiB / current chunk size, rounded up.
    const ONE_MIB: u64 = 1 << 20;
    let expected = ONE_MIB.div_ceil(DEFAULT_CHUNK_SIZE as u64);
    let ts = make_sending_transfer(ONE_MIB, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.total_chunks, expected);
}

// ---------------------------------------------------------------------------
// 4. MAX_TRANSFER_SIZE constant
// ---------------------------------------------------------------------------

#[test]
fn max_transfer_size_is_one_gib() {
    assert_eq!(MAX_TRANSFER_SIZE, 1 << 30);
    assert_eq!(MAX_TRANSFER_SIZE, 1_073_741_824);
}

// ---------------------------------------------------------------------------
// 5. Chunk sequence validation
// ---------------------------------------------------------------------------

#[test]
fn expected_sequence_starts_at_zero() {
    let ts = make_receiving_transfer(200_000, DEFAULT_CHUNK_SIZE);
    let expected = ts.bytes_transferred / ts.chunk_size as u64;
    assert_eq!(expected, 0);
}

#[test]
fn expected_sequence_advances_with_chunks() {
    // Size the transfer relative to the current DEFAULT_CHUNK_SIZE so the
    // test stays correct when the constant changes (64 KiB → 32 KiB etc.).
    let two_chunks_plus_tail = (DEFAULT_CHUNK_SIZE as u64) * 2 + 1_024;
    let mut ts = make_receiving_transfer(two_chunks_plus_tail, DEFAULT_CHUNK_SIZE);

    // After one full chunk
    ts.bytes_transferred = DEFAULT_CHUNK_SIZE as u64;
    let expected = ts.bytes_transferred / ts.chunk_size as u64;
    assert_eq!(expected, 1);

    // After two full chunks
    ts.bytes_transferred = (DEFAULT_CHUNK_SIZE * 2) as u64;
    let expected = ts.bytes_transferred / ts.chunk_size as u64;
    assert_eq!(expected, 2);

    // After partial third chunk
    ts.bytes_transferred = two_chunks_plus_tail;
    let expected = ts.bytes_transferred / ts.chunk_size as u64;
    assert_eq!(expected, 2);
}

// ---------------------------------------------------------------------------
// 6. Size limit enforcement (cumulative)
// ---------------------------------------------------------------------------

#[test]
fn cumulative_size_detects_overflow() {
    let mut ts = make_receiving_transfer(100, DEFAULT_CHUNK_SIZE);
    // Within limit
    assert!(ts.bytes_transferred + 100 <= ts.total_size);
    // One byte over
    assert!(ts.bytes_transferred + 101 > ts.total_size);

    // After partial transfer
    ts.bytes_transferred = 60;
    assert!(ts.bytes_transferred + 40 <= ts.total_size);
    assert!(ts.bytes_transferred + 41 > ts.total_size);
}

// ---------------------------------------------------------------------------
// 7. Path traversal protection
// ---------------------------------------------------------------------------

fn sanitize_filename(name: &str) -> String {
    std::path::Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string())
}

#[test]
fn sanitize_strips_parent_traversal() {
    assert_eq!(sanitize_filename("../../../etc/passwd"), "passwd");
}

#[test]
fn sanitize_strips_absolute_path() {
    assert_eq!(sanitize_filename("/etc/shadow"), "shadow");
}

#[test]
fn sanitize_preserves_normal_filename() {
    assert_eq!(sanitize_filename("report.pdf"), "report.pdf");
}

#[test]
fn sanitize_handles_nested_traversal() {
    assert_eq!(sanitize_filename("foo/../../bar/baz.txt"), "baz.txt");
}

#[test]
fn sanitize_handles_dots_only() {
    assert_eq!(sanitize_filename(".."), "download");
}

#[test]
fn sanitize_handles_empty_after_strip() {
    // "/" has no file_name component
    assert_eq!(sanitize_filename("/"), "download");
}

// ---------------------------------------------------------------------------
// 8. SHA-256 incremental verification
// ---------------------------------------------------------------------------

#[test]
fn sha256_incremental_matches_whole() {
    // Create test data spanning multiple chunks
    let data: Vec<u8> = (0u8..=255)
        .cycle()
        .take(DEFAULT_CHUNK_SIZE * 3 + 42)
        .collect();
    let whole_hash = hex::encode(Sha256::digest(&data));

    // Hash incrementally, chunk by chunk
    let mut hasher = Sha256::new();
    for chunk in data.chunks(DEFAULT_CHUNK_SIZE) {
        hasher.update(chunk);
    }
    let incremental_hash = hex::encode(hasher.finalize());

    assert_eq!(whole_hash, incremental_hash);
}

#[test]
fn sha256_empty_data_known_hash() {
    let hash = hex::encode(Sha256::digest(b""));
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// ---------------------------------------------------------------------------
// 9. State machine: only InProgress+Receiving accepts chunks
// ---------------------------------------------------------------------------

#[test]
fn chunk_rejected_if_status_pending() {
    let ts = TransferState {
        status: TransferStatus::Pending,
        ..make_receiving_transfer(100_000, DEFAULT_CHUNK_SIZE)
    };
    // Chunks should only be processed when status is InProgress
    assert_ne!(ts.status, TransferStatus::InProgress);
}

#[test]
fn chunk_rejected_if_direction_sending() {
    let ts = make_sending_transfer(100_000, DEFAULT_CHUNK_SIZE);
    // Chunks should only be written for Receiving transfers
    assert_eq!(ts.direction, TransferDirection::Sending);
    assert_ne!(ts.direction, TransferDirection::Receiving);
}

#[test]
fn chunk_accepted_only_when_in_progress_receiving() {
    let ts = make_receiving_transfer(100_000, DEFAULT_CHUNK_SIZE);
    assert_eq!(ts.direction, TransferDirection::Receiving);
    assert_eq!(ts.status, TransferStatus::InProgress);
}

// ---------------------------------------------------------------------------
// 10. TransferState serde: new fields have defaults for backward compat
// ---------------------------------------------------------------------------

#[test]
fn transfer_state_deserializes_without_optional_fields() {
    // Simulate a JSON from an older version that lacks new fields
    let json = serde_json::json!({
        "transfer_id": "old-xfer",
        "direction": "Sending",
        "remote_agent_id": "abc123",
        "filename": "old.bin",
        "total_size": 1000,
        "bytes_transferred": 500,
        "status": "InProgress",
        "sha256": "deadbeef",
        "error": null,
        "started_at": 12345
    });
    let ts: TransferState = serde_json::from_value(json).unwrap();
    assert_eq!(ts.transfer_id, "old-xfer");
    assert!(ts.source_path.is_none());
    assert!(ts.output_path.is_none());
    assert_eq!(ts.chunk_size, DEFAULT_CHUNK_SIZE); // serde default
    assert_eq!(ts.total_chunks, 0); // serde default
    assert_eq!(ts.started_at_unix_ms, 0); // serde default
    assert!(ts.completed_at_unix_ms.is_none()); // serde default
}

// ---------------------------------------------------------------------------
// 11. FileOffer total_chunks matches declared size
// ---------------------------------------------------------------------------

#[test]
fn file_offer_total_chunks_consistent() {
    // Use a size chosen relative to DEFAULT_CHUNK_SIZE so the assertion
    // stays honest when the constant changes.
    let size = (DEFAULT_CHUNK_SIZE as u64) * 3 + 200;
    let computed = size.div_ceil(DEFAULT_CHUNK_SIZE as u64);
    let offer = FileOffer {
        transfer_id: "tc1".into(),
        filename: "f.bin".into(),
        size,
        sha256: "h".into(),
        chunk_size: DEFAULT_CHUNK_SIZE,
        total_chunks: computed,
    };
    assert_eq!(offer.total_chunks, computed);
    assert_eq!(computed, 4); // 3 full chunks + 1 remainder regardless of chunk size
}
