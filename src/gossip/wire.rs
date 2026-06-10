//! Shared wire codec for the `(PeerId, Delta)` envelope used by CRDT gossip sync.
//!
//! The task-list and kv-store sync loops both publish and receive deltas as a
//! bincode-encoded `(sender_peer_id, delta)` tuple. Keeping the encode/decode
//! options in one place means the on-wire format cannot silently fork between
//! the two stacks.

use bincode::Options;
use saorsa_gossip_types::PeerId;
use serde::{de::DeserializeOwned, Serialize};

/// The single source of truth for the encoding of the `(PeerId, Delta)`
/// envelope: fixint, trailing-byte tolerant. Both the encode and decode paths
/// derive from this so the format cannot fork between them — the decode side
/// additionally bounds the input size (see [`decode_delta`]). Fixint matches
/// the legacy inline `bincode::serialize`, so existing peers and persisted
/// payloads stay compatible.
fn envelope_opts() -> impl Options {
    bincode::options()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

/// Serialize a `(sender, delta)` pair for publication on a CRDT sync topic.
pub(crate) fn encode_delta<D: Serialize>(
    sender: PeerId,
    delta: &D,
) -> Result<Vec<u8>, bincode::Error> {
    envelope_opts().serialize(&(sender, delta))
}

/// Decode a `(sender, delta)` pair received on a CRDT sync topic.
///
/// Adds a hard size limit on top of [`envelope_opts`] so an oversized inbound
/// payload is rejected rather than allocated.
pub(crate) fn decode_delta<D: DeserializeOwned>(
    payload: &[u8],
) -> Result<(PeerId, D), bincode::Error> {
    envelope_opts()
        .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
        .deserialize::<(PeerId, D)>(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Sample {
        a: u64,
        b: String,
    }

    fn peer(n: u8) -> PeerId {
        PeerId::new([n; 32])
    }

    #[test]
    fn round_trips_sender_and_delta() {
        let delta = Sample {
            a: 42,
            b: "hello".to_string(),
        };
        let bytes = encode_delta(peer(7), &delta).expect("encode");
        let (sender, decoded): (PeerId, Sample) = decode_delta(&bytes).expect("decode");
        assert_eq!(sender, peer(7));
        assert_eq!(decoded, delta);
    }

    #[test]
    fn encode_matches_legacy_inline_serialization() {
        // The helper must produce bytes identical to the previous inline
        // `bincode::serialize(&(peer, delta))` call so existing peers and
        // persisted payloads stay compatible.
        let delta = Sample {
            a: 9,
            b: "x".to_string(),
        };
        let helper = encode_delta(peer(3), &delta).expect("encode");
        let inline = bincode::serialize(&(peer(3), &delta)).expect("inline");
        assert_eq!(helper, inline);
    }
}
