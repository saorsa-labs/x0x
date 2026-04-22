//! Property-based tests for file transfer types and size math.

use proptest::prelude::*;
use x0x::files::{
    FileOffer, TransferDirection, TransferState, TransferStatus, DEFAULT_CHUNK_SIZE,
    MAX_TRANSFER_SIZE,
};

fn chunk_count(size: u64, chunk_size: usize) -> u64 {
    if size == 0 {
        0
    } else {
        1 + (size - 1) / chunk_size as u64
    }
}

fn last_chunk_size(size: u64, chunk_size: usize) -> usize {
    if size == 0 {
        0
    } else {
        let remainder = (size % chunk_size as u64) as usize;
        if remainder == 0 {
            chunk_size
        } else {
            remainder
        }
    }
}

proptest! {
    #[test]
    fn chunk_count_is_ceil_div(size in 0u64..10_000_000) {
        let expected = if size == 0 {
            0
        } else {
            size.div_ceil(DEFAULT_CHUNK_SIZE as u64)
        };
        prop_assert_eq!(chunk_count(size, DEFAULT_CHUNK_SIZE), expected);
    }

    #[test]
    fn last_chunk_le_chunk_size(size in 1u64..10_000_000) {
        let last = last_chunk_size(size, DEFAULT_CHUNK_SIZE);
        prop_assert!(last <= DEFAULT_CHUNK_SIZE && last > 0);
    }

    #[test]
    fn chunk_sizes_sum_to_total(size in 1u64..10_000_000) {
        let total_chunks = chunk_count(size, DEFAULT_CHUNK_SIZE);
        let last = last_chunk_size(size, DEFAULT_CHUNK_SIZE) as u64;
        let full_chunks = total_chunks.saturating_sub(1);
        prop_assert_eq!(full_chunks * DEFAULT_CHUNK_SIZE as u64 + last, size);
    }

    #[test]
    fn file_offer_serde_roundtrip(
        filename in prop::string::string_regex("[a-zA-Z0-9._-]{1,32}").unwrap(),
        size in 0u64..1_000_000,
        sha in prop::array::uniform32(any::<u8>()),
    ) {
        let offer = FileOffer {
            transfer_id: "transfer-1".into(),
            filename,
            size,
            sha256: hex::encode(sha),
            chunk_size: DEFAULT_CHUNK_SIZE,
            total_chunks: chunk_count(size, DEFAULT_CHUNK_SIZE),
        };
        let json = serde_json::to_string(&offer).unwrap();
        let parsed: FileOffer = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(parsed.transfer_id, offer.transfer_id);
        prop_assert_eq!(parsed.size, offer.size);
        prop_assert_eq!(parsed.sha256, offer.sha256);
        prop_assert_eq!(parsed.total_chunks, offer.total_chunks);
    }

    #[test]
    fn transfer_state_defaults_chunk_size_on_deserialize(total_size in 0u64..1_000_000) {
        let value = serde_json::json!({
            "transfer_id": "transfer-1",
            "direction": "Sending",
            "remote_agent_id": "abcd",
            "filename": "file.bin",
            "total_size": total_size,
            "bytes_transferred": 0,
            "status": "Pending",
            "sha256": "deadbeef",
            "error": null,
            "started_at": 0
        });

        let state: TransferState = serde_json::from_value(value).unwrap();
        prop_assert_eq!(state.chunk_size, DEFAULT_CHUNK_SIZE);
        prop_assert_eq!(state.total_chunks, 0);
        prop_assert_eq!(state.started_at_unix_ms, 0);
        prop_assert_eq!(state.completed_at_unix_ms, None);
        prop_assert_eq!(state.direction, TransferDirection::Sending);
        prop_assert_eq!(state.status, TransferStatus::Pending);
    }
}

#[test]
fn max_transfer_size_is_at_least_one_chunk() {
    assert!(MAX_TRANSFER_SIZE >= DEFAULT_CHUNK_SIZE as u64);
}

#[test]
fn sha256_deterministic() {
    use sha2::{Digest, Sha256};

    let data = b"x0x-files";
    let first = Sha256::digest(data);
    let second = Sha256::digest(data);
    assert_eq!(first.as_slice(), second.as_slice());
}
