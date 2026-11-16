//! Per-entry writer mark (#1094 slice P1, A10 amendment of 16 Nov 2026).
//!
//! A store record's verified author is not the writer of every entry it
//! carries: retained images and full state serves relay co-writers'
//! entries. So the writer signs each entry it writes, and the mark rides
//! inside the entry, in reserved [`KvEntry::metadata`] keys:
//!
//! - [`WRITER_KEY`]: base64 of the writer agent's ML-DSA-65 public key (the
//!   agent id is its SHA-256, so a reader needs no other lookup);
//! - [`WRITER_SIG_KEY`]: base64 of the ML-DSA-65 signature over
//!   [`signed_bytes`];
//! - [`WRITER_RIDER_KEY`] (optional): the label of the rider that wrote
//!   through the agent, at most [`MAX_RIDER_LABEL_BYTES`].
//!
//! `metadata` is already part of the encoded entry, of its merge and of the
//! store's content digests, so an older peer stores, merges and relays the
//! mark unchanged: no new wire field, no storage migration and no
//! capability bit. An older peer's own write carries no mark, and a reader
//! then sees [`EntryWriter::Unsigned`].

use std::collections::HashMap;

use base64::Engine as _;

use super::entry::KvEntry;
use super::store::{lp_bytes as lp, KvStoreId};
use crate::identity::AgentId;

/// Reserved metadata prefix of the writer mark.
pub const WRITER_KEY_PREFIX: &str = "x0x.writer.";

/// Metadata key: base64 of the writer agent's ML-DSA-65 public key.
pub const WRITER_KEY: &str = "x0x.writer.pk.v1";

/// Metadata key: base64 of the writer's signature.
pub const WRITER_SIG_KEY: &str = "x0x.writer.sig.v1";

/// Metadata key: label of the rider that wrote through the agent.
pub const WRITER_RIDER_KEY: &str = "x0x.writer.rider.v1";

/// Longest rider label a mark carries; a longer label is cut at a
/// character boundary.
pub const MAX_RIDER_LABEL_BYTES: usize = 64;

/// Domain separation for the signed bytes.
const DOMAIN: &[u8] = b"x0x.kv.entry-writer.v1\0";

/// Who wrote an entry, as far as its mark shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryWriter {
    /// The mark verifies: `agent` signed this entry's current content, in
    /// this store, with `rider` when a rider wrote through it.
    Verified {
        /// The writer agent.
        agent: AgentId,
        /// The rider that wrote through the agent, if any.
        rider: Option<String>,
    },
    /// The entry carries no mark (an older writer, or a store whose writes
    /// are not marked).
    Unsigned,
    /// The entry carries a mark that does not verify for its current
    /// content in this store; `reason` says why.
    Invalid {
        /// Why the mark does not verify.
        reason: &'static str,
    },
}

fn is_mark_key(key: &str) -> bool {
    key.starts_with(WRITER_KEY_PREFIX)
}

/// The bytes the writer signs: the store id, the key, the content hash,
/// the content type, `updated_at`, the rider label, and every metadata
/// pair outside the mark, sorted. `created_at` is left out because a merge
/// keeps the earliest one, so it can change under the mark.
#[must_use]
pub fn signed_bytes(store_id: &KvStoreId, entry: &KvEntry, rider: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(DOMAIN);
    lp(&mut buf, store_id.as_bytes());
    lp(&mut buf, entry.key.as_bytes());
    lp(&mut buf, &entry.content_hash);
    lp(&mut buf, entry.content_type.as_bytes());
    buf.extend_from_slice(&entry.updated_at.to_le_bytes());
    lp(&mut buf, rider.unwrap_or_default().as_bytes());
    let mut other: Vec<_> = entry
        .metadata
        .iter()
        .filter(|(key, _)| !is_mark_key(key))
        .collect();
    other.sort();
    buf.extend_from_slice(&(other.len() as u64).to_le_bytes());
    for (key, value) in other {
        lp(&mut buf, key.as_bytes());
        lp(&mut buf, value.as_bytes());
    }
    buf
}

/// Remove any writer mark from `metadata`.
pub fn strip(metadata: &mut HashMap<String, String>) {
    metadata.retain(|key, _| !is_mark_key(key));
}

/// `label` cut to [`MAX_RIDER_LABEL_BYTES`] at a character boundary.
fn bounded_rider(label: &str) -> &str {
    let mut end = label.len().min(MAX_RIDER_LABEL_BYTES);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    &label[..end]
}

/// Mark `entry` as written by the holder of `public_key` / `secret_key`,
/// replacing any earlier mark.
///
/// # Errors
///
/// Returns an error when signing fails.
pub fn mark(
    entry: &mut KvEntry,
    store_id: &KvStoreId,
    public_key: &ant_quic::MlDsaPublicKey,
    secret_key: &ant_quic::MlDsaSecretKey,
    rider: Option<&str>,
) -> std::result::Result<(), String> {
    strip(&mut entry.metadata);
    let rider = rider.map(bounded_rider).filter(|label| !label.is_empty());
    let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        secret_key,
        &signed_bytes(store_id, entry, rider),
    )
    .map_err(|e| format!("entry writer signature failed: {e:?}"))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    entry
        .metadata
        .insert(WRITER_KEY.to_string(), b64.encode(public_key.as_bytes()));
    entry
        .metadata
        .insert(WRITER_SIG_KEY.to_string(), b64.encode(signature.as_bytes()));
    if let Some(rider) = rider {
        entry
            .metadata
            .insert(WRITER_RIDER_KEY.to_string(), rider.to_string());
    }
    Ok(())
}

/// Who wrote `entry` in the store `store_id`, by its mark.
#[must_use]
pub fn verify(store_id: &KvStoreId, entry: &KvEntry) -> EntryWriter {
    let (Some(pk), Some(sig)) = (
        entry.metadata.get(WRITER_KEY),
        entry.metadata.get(WRITER_SIG_KEY),
    ) else {
        if entry.metadata.keys().any(|key| is_mark_key(key)) {
            return EntryWriter::Invalid {
                reason: "incomplete writer mark",
            };
        }
        return EntryWriter::Unsigned;
    };
    if *blake3::hash(&entry.value).as_bytes() != entry.content_hash {
        return EntryWriter::Invalid {
            reason: "content hash does not match the value",
        };
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let Some(public_key) = b64
        .decode(pk)
        .ok()
        .and_then(|bytes| ant_quic::MlDsaPublicKey::from_bytes(&bytes).ok())
    else {
        return EntryWriter::Invalid {
            reason: "malformed writer public key",
        };
    };
    let Some(signature) = b64.decode(sig).ok().and_then(|bytes| {
        ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&bytes).ok()
    }) else {
        return EntryWriter::Invalid {
            reason: "malformed writer signature",
        };
    };
    let rider = entry.metadata.get(WRITER_RIDER_KEY).cloned();
    if rider
        .as_deref()
        .is_some_and(|label| label.is_empty() || label.len() > MAX_RIDER_LABEL_BYTES)
    {
        return EntryWriter::Invalid {
            reason: "malformed rider label",
        };
    }
    let message = signed_bytes(store_id, entry, rider.as_deref());
    if ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&public_key, &message, &signature)
        .is_err()
    {
        return EntryWriter::Invalid {
            reason: "writer signature does not verify",
        };
    }
    EntryWriter::Verified {
        agent: AgentId::from_public_key(&public_key),
        rider,
    }
}

#[cfg(test)]
#[path = "provenance_tests.rs"]
mod tests;
