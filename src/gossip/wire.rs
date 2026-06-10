//! Shared wire codec for the `(PeerId, Delta)` envelope used by CRDT gossip sync.
//!
//! The task-list and kv-store sync loops both publish and receive deltas as a
//! bincode-encoded `(sender_peer_id, delta)` tuple. Keeping the encode/decode
//! options in one place means the on-wire format cannot silently fork between
//! the two stacks.

use saorsa_gossip_types::PeerId;
use serde::{de::DeserializeOwned, Serialize};

/// Serialize a `(sender, delta)` pair for publication on a CRDT sync topic.
///
/// Uses `bincode::serialize` (fixint encoding), matching the decode side in
/// [`decode_delta`].
pub(crate) fn encode_delta<D: Serialize>(
    sender: PeerId,
    delta: &D,
) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(&(sender, delta))
}

/// Decode a `(sender, delta)` pair received on a CRDT sync topic.
///
/// Fixint encoding with a hard size limit, tolerating trailing bytes — the
/// single definition of the inbound delta envelope shared by every CRDT sync
/// loop.
pub(crate) fn decode_delta<D: DeserializeOwned>(
    payload: &[u8],
) -> Result<(PeerId, D), bincode::Error> {
    use bincode::Options;
    bincode::options()
        .with_fixint_encoding()
        .with_limit(crate::network::MAX_MESSAGE_DESERIALIZE_SIZE)
        .allow_trailing_bytes()
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
