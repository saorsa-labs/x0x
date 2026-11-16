//! Per-entry writer mark (#1094 slice P1, A10 amendment of 16 Nov 2026).
//!
//! A store record's verified author is not the writer of every entry it
//! carries: retained images and full state serves relay co-writers'
//! entries. So the writer signs each entry it writes, and the mark rides
//! inside the entry, in reserved [`KvEntry::metadata`] keys:
//!
//! - [`WRITER_AGENT_KEY`]: the writer's agent id, hex;
//! - [`WRITER_SIG_KEY`]: base64 of the ML-DSA-65 signature over
//!   [`signed_bytes`];
//! - [`WRITER_FOR_KEY`]: `<updated_at>:<content hash hex>`, the version the
//!   mark was made for, so a later rewrite by a writer that does not mark
//!   reads [`EntryWriter::Unsigned`], not [`EntryWriter::Invalid`];
//! - [`WRITER_RIDER_KEY`] (optional): the label of the rider that wrote
//!   through the agent, at most [`MAX_RIDER_LABEL_BYTES`].
//!
//! The public key is not in the entry (review of #1963: about 2.6 KB per
//! entry). A reader resolves it from [`known_agent_key`]: keys proved by a
//! verified signed gossip message or by this process's own agents. A key
//! not known here reads [`EntryWriter::Unverified`], never `Verified`.
//!
//! `metadata` is already part of the encoded entry, of its merge and of the
//! store's content digests, so an older peer stores, merges and relays the
//! mark unchanged: no new wire field, no storage migration and no
//! capability bit.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use base64::Engine as _;

use super::entry::KvEntry;
use super::store::{lp_bytes as lp, KvStoreId};
use crate::identity::AgentId;

/// Reserved metadata prefix of the writer mark.
pub const WRITER_KEY_PREFIX: &str = "x0x.writer.";

/// Metadata key: the writer's agent id, hex.
pub const WRITER_AGENT_KEY: &str = "x0x.writer.agent.v1";

/// Metadata key: base64 of the writer's signature.
pub const WRITER_SIG_KEY: &str = "x0x.writer.sig.v1";

/// Metadata key: `<updated_at>:<content hash hex>` the mark was made for.
pub const WRITER_FOR_KEY: &str = "x0x.writer.for.v1";

/// Metadata key: label of the rider that wrote through the agent.
pub const WRITER_RIDER_KEY: &str = "x0x.writer.rider.v1";

/// Longest rider label a mark carries; a longer label is cut at a
/// character boundary.
pub const MAX_RIDER_LABEL_BYTES: usize = 64;

/// Domain separation for the signed bytes.
const DOMAIN: &[u8] = b"x0x.kv.entry-writer.v2\0";

/// Agent keys [`known_agent_key`] keeps; the oldest is dropped first.
const KNOWN_AGENT_KEYS_CAP: usize = 8192;

/// Who wrote an entry, as far as its mark shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryWriter {
    /// The mark verifies: `agent` signed this entry's current content, under
    /// this key, in this store, with `rider` when a rider wrote through it.
    Verified {
        /// The writer agent.
        agent: AgentId,
        /// The rider that wrote through the agent, if any.
        rider: Option<String>,
    },
    /// The mark names `agent`, but this daemon does not know that agent's
    /// public key, so the mark cannot be checked.
    Unverified {
        /// The agent the mark names.
        agent: AgentId,
    },
    /// The entry carries no mark for its current content: an older writer,
    /// a store whose writes are not marked, or a rewrite after the mark.
    Unsigned,
    /// The entry carries a mark that does not verify for its current
    /// content, key and store; `reason` says why.
    Invalid {
        /// Why the mark does not verify.
        reason: &'static str,
    },
}

impl EntryWriter {
    /// Merge rank on an exact tie (review of #1963): a verified mark beats
    /// an unverifiable or absent one, which beats an invalid one.
    #[must_use]
    pub(crate) fn tie_rank(&self) -> u8 {
        match self {
            Self::Verified { .. } => 2,
            Self::Unverified { .. } | Self::Unsigned => 1,
            Self::Invalid { .. } => 0,
        }
    }
}

struct KnownKeys {
    keys: HashMap<AgentId, ant_quic::MlDsaPublicKey>,
    order: VecDeque<AgentId>,
}

static KNOWN_KEYS: Mutex<Option<KnownKeys>> = Mutex::new(None);

/// Remember `public_key` as its agent's key. Keys are self-authenticating
/// (the agent id is the key's SHA-256), so any verified source may add one.
pub fn note_agent_key(public_key: &ant_quic::MlDsaPublicKey) {
    let agent = AgentId::from_public_key(public_key);
    let mut guard = KNOWN_KEYS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let known = guard.get_or_insert_with(|| KnownKeys {
        keys: HashMap::new(),
        order: VecDeque::new(),
    });
    if known.keys.contains_key(&agent) {
        return;
    }
    if known.keys.len() >= KNOWN_AGENT_KEYS_CAP {
        if let Some(oldest) = known.order.pop_front() {
            known.keys.remove(&oldest);
        }
    }
    known.keys.insert(agent, public_key.clone());
    known.order.push_back(agent);
}

/// The public key of `agent`, when a verified source proved it here.
#[must_use]
pub fn known_agent_key(agent: &AgentId) -> Option<ant_quic::MlDsaPublicKey> {
    KNOWN_KEYS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|known| known.keys.get(agent).cloned())
}

fn is_mark_key(key: &str) -> bool {
    key.starts_with(WRITER_KEY_PREFIX)
}

fn version_tag(entry: &KvEntry) -> String {
    format!("{}:{}", entry.updated_at, hex::encode(entry.content_hash))
}

/// The bytes the writer signs: the store id, the key, the writer agent,
/// the content hash, the content type, `updated_at`, the rider label, and
/// every metadata pair outside the mark, sorted. `created_at` is left out
/// because a merge keeps the earliest one, so it can change under the mark.
#[must_use]
pub fn signed_bytes(
    store_id: &KvStoreId,
    key: &str,
    agent: &AgentId,
    entry: &KvEntry,
    rider: Option<&str>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(DOMAIN);
    lp(&mut buf, store_id.as_bytes());
    lp(&mut buf, key.as_bytes());
    lp(&mut buf, agent.as_bytes());
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
/// replacing any earlier mark. The key is the entry's own key.
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
    note_agent_key(public_key);
    let agent = AgentId::from_public_key(public_key);
    let rider = rider.map(bounded_rider).filter(|label| !label.is_empty());
    let signature = ant_quic::crypto::raw_public_keys::pqc::sign_with_ml_dsa(
        secret_key,
        &signed_bytes(store_id, &entry.key, &agent, entry, rider),
    )
    .map_err(|e| format!("entry writer signature failed: {e:?}"))?;
    entry
        .metadata
        .insert(WRITER_AGENT_KEY.to_string(), hex::encode(agent.as_bytes()));
    entry.metadata.insert(
        WRITER_SIG_KEY.to_string(),
        base64::engine::general_purpose::STANDARD.encode(signature.as_bytes()),
    );
    entry
        .metadata
        .insert(WRITER_FOR_KEY.to_string(), version_tag(entry));
    if let Some(rider) = rider {
        entry
            .metadata
            .insert(WRITER_RIDER_KEY.to_string(), rider.to_string());
    }
    Ok(())
}

/// Who wrote `entry`, held under map key `key` in the store `store_id`, by
/// its mark, with keys from [`known_agent_key`].
#[must_use]
pub fn verify(store_id: &KvStoreId, key: &str, entry: &KvEntry) -> EntryWriter {
    verify_with(store_id, key, entry, known_agent_key)
}

/// [`verify`] with an explicit key lookup.
#[must_use]
pub fn verify_with(
    store_id: &KvStoreId,
    key: &str,
    entry: &KvEntry,
    lookup: impl Fn(&AgentId) -> Option<ant_quic::MlDsaPublicKey>,
) -> EntryWriter {
    if !entry.metadata.keys().any(|k| is_mark_key(k)) {
        return EntryWriter::Unsigned;
    }
    let invalid = |reason| EntryWriter::Invalid { reason };
    if key != entry.key {
        return invalid("the entry is not under its own key");
    }
    // A mark made for another version: the entry was rewritten by a writer
    // that does not mark (an older peer keeps the metadata).
    match entry.metadata.get(WRITER_FOR_KEY) {
        Some(tag) if *tag == version_tag(entry) => {}
        Some(_) => return EntryWriter::Unsigned,
        None => return invalid("incomplete writer mark"),
    }
    let (Some(agent_hex), Some(sig)) = (
        entry.metadata.get(WRITER_AGENT_KEY),
        entry.metadata.get(WRITER_SIG_KEY),
    ) else {
        return invalid("incomplete writer mark");
    };
    if *blake3::hash(&entry.value).as_bytes() != entry.content_hash {
        return invalid("content hash does not match the value");
    }
    let Some(agent) = hex::decode(agent_hex)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(AgentId)
    else {
        return invalid("malformed writer agent id");
    };
    let Some(signature) = base64::engine::general_purpose::STANDARD
        .decode(sig)
        .ok()
        .and_then(|bytes| {
            ant_quic::crypto::raw_public_keys::pqc::MlDsaSignature::from_bytes(&bytes).ok()
        })
    else {
        return invalid("malformed writer signature");
    };
    let rider = entry.metadata.get(WRITER_RIDER_KEY).cloned();
    if rider
        .as_deref()
        .is_some_and(|label| label.is_empty() || label.len() > MAX_RIDER_LABEL_BYTES)
    {
        return invalid("malformed rider label");
    }
    let Some(public_key) = lookup(&agent) else {
        return EntryWriter::Unverified { agent };
    };
    let message = signed_bytes(store_id, key, &agent, entry, rider.as_deref());
    if ant_quic::crypto::raw_public_keys::pqc::verify_with_ml_dsa(&public_key, &message, &signature)
        .is_err()
    {
        return invalid("writer signature does not verify");
    }
    EntryWriter::Verified { agent, rider }
}

#[cfg(test)]
#[path = "provenance_tests.rs"]
mod tests;
